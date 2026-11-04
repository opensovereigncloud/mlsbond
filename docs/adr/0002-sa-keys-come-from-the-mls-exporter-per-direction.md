# Security Association keys come from the MLS exporter, per direction; the receiver picks the SPI

Status: accepted

Every host derives the key and salt of each Security Association itself from the epoch's MLS
exporter, with the two host prefixes in direction order:

```
MLS-Exporter("mlsbond sa", vni ‖ epoch ‖ src_prefix ‖ dst_prefix, 36)
  → key (32 bytes) ‖ salt (4 bytes)
```

The wire SPI is not derived. The receiving host picks it at random from the values 256 and up that
none of its ingress Security Associations uses, and tells the sender in its `Ready` (ADR 0004), as
RFC 4301 section 4.1 and IKEv2 have the receiver choose its inbound SPI. AES-256-GCM, extended
sequence numbers on, and an anti-replay window of 64 on ingress are fixed parameters.

This replaces IEP-25's derivation (salt = `HMAC(group_key, VNI:PrefixA:PrefixB:Epoch)` and
SPI = `Sum32` of the same string, with the prefixes sorted), which has two flaws:

- **Nonce reuse.** Sorting makes A→B and B→A share key, salt and SPI. Both directions count
  their sequence numbers from 1 and the AES-GCM nonce is `salt ‖ seq`, so packet *n* in each
  direction is encrypted under the same nonce, which reveals the GHASH key and the XOR of the
  plaintexts.
- **The SPI reveals the VNI.** `Sum32` over public inputs lets anyone on the fabric, who sees
  both prefixes, search the 2²⁴ VNIs for the one matching the SPI. dpservice separated the wire
  SPI from the VNI to avoid exactly that.

## Considered Options

- **Deriving the SPI from the exporter as well.** Hides the VNI just as well, but nobody chooses
  the value, so collisions cannot be avoided, only made rare: on dpservice between the same two
  hosts, where one leaves the pair stuck. A Linux XFRM receiver looks inbound states up by
  destination address and SPI, so it would also need a packet mark set from the outer source /64
  to tell senders apart. With SPIs the receiver picks, unique among its own ingress Security
  Associations, neither is needed.
- **Deriving with a retry counter** that the receiver announces on collision. The same message flow
  as picking the SPI, with more to get wrong.
