//! 1:1 prefix translation (NETMAP). One [`Mapping`] generates the nftables
//! NETMAP rules, the dnsmasq `alias=` line, client routes and Headscale ACL
//! addresses; operators never write the translation twice.

use std::net::Ipv4Addr;

use ipnet::Ipv4Net;

/// A real prefix and the virtual prefix clients see it under. Host bits are preserved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Mapping {
    real: Ipv4Net,
    virt: Ipv4Net,
}

impl Mapping {
    /// Both prefixes must have the same length. Prefixes are normalised
    /// (`trunc`) so `192.168.1.5/24` means `192.168.1.0/24`.
    pub fn new(real: Ipv4Net, virt: Ipv4Net) -> crate::Result<Self> {
        if real.prefix_len() != virt.prefix_len() {
            return Err(crate::Error::Malformed {
                what: "mapping",
                detail: format!(
                    "{real} and {virt} have different prefix lengths ({} vs {})",
                    real.prefix_len(),
                    virt.prefix_len()
                ),
            });
        }
        Ok(Mapping {
            real: real.trunc(),
            virt: virt.trunc(),
        })
    }

    pub fn real(&self) -> Ipv4Net {
        self.real
    }
    pub fn virt(&self) -> Ipv4Net {
        self.virt
    }
    /// Dotted-quad netmask, as dnsmasq's `alias=` wants it.
    pub fn netmask(&self) -> Ipv4Addr {
        self.real.netmask()
    }

    fn host_mask(&self) -> u32 {
        !u32::from(self.real.netmask())
    }

    /// Real → virtual, if `addr` is inside the real prefix.
    pub fn to_virtual(&self, addr: Ipv4Addr) -> Option<Ipv4Addr> {
        self.real.contains(&addr).then(|| {
            Ipv4Addr::from((u32::from(self.virt.network())) | (u32::from(addr) & self.host_mask()))
        })
    }

    /// Virtual → real, if `addr` is inside the virtual prefix.
    pub fn to_real(&self, addr: Ipv4Addr) -> Option<Ipv4Addr> {
        self.virt.contains(&addr).then(|| {
            Ipv4Addr::from((u32::from(self.real.network())) | (u32::from(addr) & self.host_mask()))
        })
    }

    /// Translate a real sub-prefix (e.g. a /32 host) into virtual space.
    pub fn net_to_virtual(&self, net: Ipv4Net) -> Option<Ipv4Net> {
        if !self.real.contains(&net) {
            return None;
        }
        let addr = self.to_virtual(net.addr())?;
        Ipv4Net::new(addr, net.prefix_len()).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn home() -> Mapping {
        Mapping::new(
            "192.168.1.0/24".parse().unwrap(),
            "198.18.1.0/24".parse().unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn preserves_host_bits() {
        let m = home();
        assert_eq!(
            m.to_virtual("192.168.1.5".parse().unwrap()),
            Some("198.18.1.5".parse().unwrap())
        );
        assert_eq!(
            m.to_real("198.18.1.1".parse().unwrap()),
            Some("192.168.1.1".parse().unwrap())
        );
        assert_eq!(m.to_virtual("10.0.0.1".parse().unwrap()), None);
        assert_eq!(m.to_real("192.168.1.5".parse().unwrap()), None);
        assert_eq!(m.netmask(), Ipv4Addr::new(255, 255, 255, 0));
    }

    #[test]
    fn rejects_prefix_mismatch() {
        assert!(Mapping::new(
            "192.168.1.0/24".parse().unwrap(),
            "198.18.1.0/25".parse().unwrap()
        )
        .is_err());
    }

    #[test]
    fn translates_sub_prefixes() {
        let m = home();
        assert_eq!(
            m.net_to_virtual("192.168.1.5/32".parse().unwrap()),
            Some("198.18.1.5/32".parse().unwrap())
        );
        assert_eq!(
            m.net_to_virtual("192.168.1.128/25".parse().unwrap()),
            Some("198.18.1.128/25".parse().unwrap())
        );
        assert_eq!(m.net_to_virtual("192.168.0.0/16".parse().unwrap()), None);
    }

    proptest! {
        /// real → virtual → real is the identity for every address in any prefix.
        #[test]
        fn round_trips(real_base in any::<u32>(), virt_base in any::<u32>(), prefix in 0u8..=32, host in any::<u32>()) {
            let real = Ipv4Net::new(Ipv4Addr::from(real_base), prefix).unwrap();
            let virt = Ipv4Net::new(Ipv4Addr::from(virt_base), prefix).unwrap();
            let m = Mapping::new(real, virt).unwrap();
            let host_mask = !u32::from(real.netmask());
            let addr = Ipv4Addr::from((u32::from(real.network())) | (host & host_mask));
            let v = m.to_virtual(addr).unwrap();
            prop_assert!(m.virt().contains(&v));
            prop_assert_eq!(m.to_real(v), Some(addr));
            prop_assert_eq!(u32::from(v) & host_mask, u32::from(addr) & host_mask);
        }
    }
}
