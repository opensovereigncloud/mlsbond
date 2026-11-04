//! The MLS side of mlsbond: a host's identity, its VNI groups, and the Security Association key
//! material derived from them.

use std::collections::BTreeMap;

use anyhow::{Result, anyhow};
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use tls_codec::{Deserialize as _, Serialize as _};

use crate::prefix::HostPrefix;

/// The one MLS ciphersuite of mlsbond. Moving to another one is a change here plus a regroup.
pub const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

/// Exporter label of Security Association key material.
const EXPORTER_LABEL: &str = "mlsbond sa";

/// How many past epochs a member can still decrypt Ready and Switched of, which a peer may have
/// encrypted before it processed the latest commits.
const MAX_PAST_EPOCHS: usize = 16;

/// The key and salt of one Security Association (AES-256-GCM).
#[derive(Clone, PartialEq, Eq)]
pub struct KeyMaterial {
    pub key: [u8; 32],
    pub salt: [u8; 4],
}

impl std::fmt::Debug for KeyMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("KeyMaterial(..)")
    }
}

/// The exporter context of the Security Association from src to dst: vni ‖ epoch ‖ src ‖ dst, the
/// prefixes in direction order.
fn sa_context(vni: u32, epoch: u64, src: HostPrefix, dst: HostPrefix) -> Vec<u8> {
    let mut ctx = Vec::with_capacity(4 + 8 + 16 + 16);
    ctx.extend_from_slice(&vni.to_be_bytes());
    ctx.extend_from_slice(&epoch.to_be_bytes());
    ctx.extend_from_slice(&src.underlay().octets());
    ctx.extend_from_slice(&dst.underlay().octets());
    ctx
}

/// Derives the key material of the Security Association from src to dst in the group's current
/// epoch.
pub fn derive_sa(group: &MlsGroup, provider: &OpenMlsRustCrypto, vni: u32, src: HostPrefix, dst: HostPrefix) -> Result<KeyMaterial> {
    let ctx = sa_context(vni, group.epoch().as_u64(), src, dst);
    let out = group.export_secret(provider.crypto(), EXPORTER_LABEL, &ctx, 36).map_err(|e| anyhow!("MLS exporter: {e:?}"))?;
    let mut km = KeyMaterial { key: [0; 32], salt: [0; 4] };
    km.key.copy_from_slice(&out[..32]);
    km.salt.copy_from_slice(&out[32..]);
    Ok(km)
}

/// Picks an ingress SPI: a random value from 256 upwards for which `used` is false.
pub fn pick_spi(used: impl Fn(u32) -> bool, mut random: impl FnMut() -> u32) -> u32 {
    loop {
        let spi = random();
        if spi >= 256 && !used(spi) {
            return spi;
        }
    }
}

/// A host's MLS identity: its signature key and a BasicCredential holding its host prefix. It
/// lives in memory only.
pub struct Identity {
    pub provider: OpenMlsRustCrypto,
    pub signer: SignatureKeyPair,
    pub credential: CredentialWithKey,
    pub prefix: HostPrefix,
}

impl Identity {
    pub fn new(prefix: HostPrefix) -> Result<Identity> {
        let provider = OpenMlsRustCrypto::default();
        let signer = SignatureKeyPair::new(CIPHERSUITE.signature_algorithm()).map_err(|e| anyhow!("signature key: {e:?}"))?;
        signer.store(provider.storage()).map_err(|e| anyhow!("storing signature key: {e:?}"))?;
        let credential =
            CredentialWithKey { credential: BasicCredential::new(prefix.to_string().into_bytes()).into(), signature_key: signer.public().into() };
        Ok(Identity { provider, signer, credential, prefix })
    }

    /// A fresh single-use key package, MLSMessage encoded.
    pub fn key_package(&self) -> Result<Vec<u8>> {
        let bundle = KeyPackage::builder()
            .build(CIPHERSUITE, &self.provider, &self.signer, self.credential.clone())
            .map_err(|e| anyhow!("key package: {e:?}"))?;
        let msg: MlsMessageOut = bundle.key_package().clone().into();
        Ok(msg.tls_serialize_detached()?)
    }

    pub fn create_group(&self) -> Result<MlsGroup> {
        let config =
            MlsGroupCreateConfig::builder().ciphersuite(CIPHERSUITE).use_ratchet_tree_extension(true).max_past_epochs(MAX_PAST_EPOCHS).build();
        let id = GroupId::from_slice(&rand::random::<[u8; 16]>());
        MlsGroup::new_with_group_id(&self.provider, &self.signer, &config, id, self.credential.clone()).map_err(|e| anyhow!("creating group: {e:?}"))
    }

    /// Joins a group from a Welcome (MLSMessage encoded).
    pub fn join(&self, welcome: &[u8]) -> Result<MlsGroup> {
        let msg = MlsMessageIn::tls_deserialize_exact(welcome)?;
        let MlsMessageBodyIn::Welcome(welcome) = msg.extract() else {
            return Err(anyhow!("not a Welcome"));
        };
        let config = MlsGroupJoinConfig::builder().use_ratchet_tree_extension(true).max_past_epochs(MAX_PAST_EPOCHS).build();
        StagedWelcome::new_from_welcome(&self.provider, &config, welcome, None)
            .map_err(|e| anyhow!("Welcome: {e:?}"))?
            .into_group(&self.provider)
            .map_err(|e| anyhow!("Welcome: {e:?}"))
    }
}

/// Validates a key package (MLSMessage encoded) uploaded by another host.
pub fn parse_key_package(provider: &OpenMlsRustCrypto, bytes: &[u8]) -> Result<KeyPackage> {
    let msg = MlsMessageIn::tls_deserialize_exact(bytes)?;
    match msg.extract() {
        MlsMessageBodyIn::KeyPackage(kp) => kp.validate(provider.crypto(), ProtocolVersion::Mls10).map_err(|e| anyhow!("invalid key package: {e:?}")),
        _ => Err(anyhow!("not a key package")),
    }
}

/// The host prefix a credential holds.
pub fn credential_prefix(credential: &Credential) -> Option<HostPrefix> {
    let basic = BasicCredential::try_from(credential.clone()).ok()?;
    std::str::from_utf8(basic.identity()).ok()?.parse().ok()
}

/// The members of a group: host prefix -> (leaf index, signature key). A new signature key under
/// the same host prefix is a new leaf: a host that restarted or rejoined.
pub fn members(group: &MlsGroup) -> BTreeMap<HostPrefix, (LeafNodeIndex, Vec<u8>)> {
    group.members().filter_map(|m| Some((credential_prefix(&m.credential)?, (m.index, m.signature_key)))).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prefix(s: &str) -> HostPrefix {
        s.parse().unwrap()
    }

    /// A two-member group: returns both members' identities and groups.
    fn pair() -> ((Identity, MlsGroup), (Identity, MlsGroup)) {
        let a = Identity::new(prefix("fd00:a::/64")).unwrap();
        let b = Identity::new(prefix("fd00:b::/64")).unwrap();
        let mut ga = a.create_group().unwrap();
        let kp = parse_key_package(&a.provider, &b.key_package().unwrap()).unwrap();
        let (_, welcome, _) = ga.add_members(&a.provider, &a.signer, &[kp]).unwrap();
        ga.merge_pending_commit(&a.provider).unwrap();
        let gb = b.join(&welcome.tls_serialize_detached().unwrap()).unwrap();
        ((a, ga), (b, gb))
    }

    #[test]
    fn both_ends_derive_the_same_key_material() {
        let ((a, ga), (b, gb)) = pair();
        let (pa, pb) = (a.prefix, b.prefix);
        assert_eq!(derive_sa(&ga, &a.provider, 7, pa, pb).unwrap(), derive_sa(&gb, &b.provider, 7, pa, pb).unwrap());
        assert_eq!(derive_sa(&ga, &a.provider, 7, pb, pa).unwrap(), derive_sa(&gb, &b.provider, 7, pb, pa).unwrap());
    }

    #[test]
    fn direction_order_matters() {
        let ((a, ga), (b, _)) = pair();
        let ab = derive_sa(&ga, &a.provider, 7, a.prefix, b.prefix).unwrap();
        let ba = derive_sa(&ga, &a.provider, 7, b.prefix, a.prefix).unwrap();
        assert_ne!(ab.key, ba.key);
        assert_ne!(ab.salt, ba.salt);
    }

    #[test]
    fn vni_and_epoch_matter() {
        let ((a, mut ga), (b, _)) = pair();
        let first = derive_sa(&ga, &a.provider, 7, a.prefix, b.prefix).unwrap();
        assert_ne!(first, derive_sa(&ga, &a.provider, 8, a.prefix, b.prefix).unwrap());
        ga.self_update(&a.provider, &a.signer, LeafNodeParameters::default()).unwrap();
        ga.merge_pending_commit(&a.provider).unwrap();
        assert_ne!(first, derive_sa(&ga, &a.provider, 7, a.prefix, b.prefix).unwrap());
    }

    #[test]
    fn spis_are_from_256_upwards() {
        let mut values = vec![0, 1, 255, 256].into_iter();
        assert_eq!(pick_spi(|_| false, || values.next().unwrap()), 256);
    }

    #[test]
    fn spis_in_use_are_skipped() {
        let mut values = vec![300, 301, 300, 302].into_iter();
        assert_eq!(pick_spi(|spi| spi == 300 || spi == 301, || values.next().unwrap()), 302);
    }

    #[test]
    fn credentials_hold_the_host_prefix() {
        let ((a, ga), (b, _)) = pair();
        let m = members(&ga);
        assert_eq!(m.keys().copied().collect::<Vec<_>>(), vec![a.prefix, b.prefix]);
    }
}
