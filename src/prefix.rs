//! Host prefixes: the underlay /64 identifying a host.

use std::fmt;
use std::net::Ipv6Addr;
use std::str::FromStr;

/// The underlay /64 of a host, kept as its network address.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct HostPrefix(Ipv6Addr);

impl HostPrefix {
    pub const MIN: HostPrefix = HostPrefix(Ipv6Addr::UNSPECIFIED);
    pub const MAX: HostPrefix = HostPrefix(Ipv6Addr::new(0xffff, 0xffff, 0xffff, 0xffff, 0, 0, 0, 0));

    /// The network address of the prefix: the underlay address in Security Associations.
    pub fn underlay(&self) -> Ipv6Addr {
        self.0
    }

    pub fn from_underlay(addr: Ipv6Addr) -> Option<HostPrefix> {
        let p = HostPrefix(addr);
        (p.masked() == addr).then_some(p)
    }

    pub fn from_underlay_bytes(bytes: &[u8]) -> Option<HostPrefix> {
        let bytes: [u8; 16] = bytes.try_into().ok()?;
        Self::from_underlay(Ipv6Addr::from(bytes))
    }

    fn masked(&self) -> Ipv6Addr {
        Ipv6Addr::from(self.0.to_bits() & !((1u128 << 64) - 1))
    }
}

impl FromStr for HostPrefix {
    type Err = String;

    /// Parses "addr/64" whose host bits are zero.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let err = || format!("{s:?} is not an IPv6 /64 prefix");
        let (addr, len) = s.split_once('/').ok_or_else(err)?;
        let addr: Ipv6Addr = addr.parse().map_err(|_| err())?;
        if len != "64" {
            return Err(err());
        }
        HostPrefix::from_underlay(addr).ok_or_else(err)
    }
}

impl fmt::Display for HostPrefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/64", self.0)
    }
}
