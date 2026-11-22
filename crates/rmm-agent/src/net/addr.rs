//! IPv4 blocks, which addresses the agent will probe, and the machine's own subnets.

use std::net::{IpAddr, Ipv4Addr};

/// An IPv4 block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    pub base: u32,
    pub prefix: u8,
}

impl Cidr {
    pub fn parse(s: &str) -> Option<Cidr> {
        let s = s.trim();
        let (ip, prefix) = match s.split_once('/') {
            Some((ip, p)) => (ip, p.parse::<u8>().ok()?),
            None => (s, 32),
        };
        if prefix > 32 {
            return None;
        }
        let ip: Ipv4Addr = ip.parse().ok()?;
        Some(Cidr { base: u32::from(ip) & mask(prefix), prefix })
    }

    /// Addresses in the block that can be hosts: not the network and broadcast addresses of
    /// anything wider than a /31.
    pub fn size(&self) -> u64 {
        let all = 1u64 << (32 - u32::from(self.prefix));
        if self.prefix >= 31 { all } else { all - 2 }
    }

    pub fn hosts(&self) -> impl Iterator<Item = Ipv4Addr> + use<> {
        let (first, count) = if self.prefix >= 31 { (self.base, self.size()) } else { (self.base + 1, self.size()) };
        (0..count).map(move |i| Ipv4Addr::from(first + i as u32))
    }

    #[cfg(test)]
    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        u32::from(ip) & mask(self.prefix) == self.base
    }
}

impl std::fmt::Display for Cidr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", Ipv4Addr::from(self.base), self.prefix)
    }
}

fn mask(prefix: u8) -> u32 {
    if prefix == 0 { 0 } else { u32::MAX << (32 - u32::from(prefix)) }
}

/// Addresses a scan may probe: the private ranges (RFC 1918), shared address space (RFC 6598)
/// and link-local. An agent is never a way to scan the internet.
pub fn scannable(ip: Ipv4Addr) -> bool {
    ip.is_private() || ip.is_link_local() || (ip.octets()[0] == 100 && (ip.octets()[1] & 0xc0) == 64)
}

/// Where a device may be polled: the above, the machine itself, and unique-local IPv6.
pub fn pollable(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => scannable(v4) || v4.is_loopback(),
        IpAddr::V6(v6) => v6.is_loopback() || (v6.segments()[0] & 0xfe00) == 0xfc00 || (v6.segments()[0] & 0xffc0) == 0xfe80,
    }
}

/// The blocks to scan when none are given: each IPv4 network the machine is on, narrowed to
/// at most a /22 around its own address (a /8 isn't something to sweep by default).
pub fn local_subnets(nets: &[(Ipv4Addr, u8)]) -> Vec<Cidr> {
    let mut out: Vec<Cidr> = Vec::new();
    for &(ip, prefix) in nets {
        if !scannable(ip) || prefix >= 32 {
            continue;
        }
        let prefix = prefix.max(22);
        let c = Cidr { base: u32::from(ip) & mask(prefix), prefix };
        if !out.contains(&c) {
            out.push(c);
        }
    }
    out
}

/// `aa:bb:cc:dd:ee:ff` in lower case from `aa-bb-...` or `AA:BB:...`; `None` for anything else
/// and for the all-zero and broadcast addresses.
pub fn normalize_mac(s: &str) -> Option<String> {
    let parts: Vec<&str> = s.trim().split([':', '-']).collect();
    if parts.len() != 6 || parts.iter().any(|p| p.is_empty() || p.len() > 2 || !p.bytes().all(|b| b.is_ascii_hexdigit())) {
        return None;
    }
    let bytes: Vec<u8> = parts.iter().map(|p| u8::from_str_radix(p, 16).ok()).collect::<Option<_>>()?;
    if bytes.iter().all(|b| *b == 0) || bytes.iter().all(|b| *b == 0xff) {
        return None;
    }
    Some(bytes.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_parse_and_enumerate() {
        let c = Cidr::parse("192.168.1.77/24").unwrap();
        assert_eq!((c.to_string(), c.size()), ("192.168.1.0/24".to_string(), 254));
        let hosts: Vec<_> = c.hosts().collect();
        assert_eq!((hosts[0], *hosts.last().unwrap()), (Ipv4Addr::new(192, 168, 1, 1), Ipv4Addr::new(192, 168, 1, 254)));
        assert_eq!(Cidr::parse("10.0.0.5").unwrap().hosts().collect::<Vec<_>>(), [Ipv4Addr::new(10, 0, 0, 5)]);
        assert_eq!(Cidr::parse("10.0.0.0/31").unwrap().hosts().count(), 2);
        assert_eq!(Cidr::parse("0.0.0.0/0").unwrap().size(), (1u64 << 32) - 2);
        assert!(c.contains(Ipv4Addr::new(192, 168, 1, 200)) && !c.contains(Ipv4Addr::new(192, 168, 2, 1)));
        for bad in ["", "10.0.0.0/33", "10.0.0/24", "a.b.c.d", "10.0.0.0/x"] {
            assert!(Cidr::parse(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn only_private_space_is_scanned() {
        for ok in ["10.1.2.3", "172.16.0.1", "172.31.255.1", "192.168.0.9", "100.64.0.1", "100.127.0.1", "169.254.1.1"] {
            assert!(scannable(ok.parse().unwrap()), "{ok}");
        }
        for no in ["8.8.8.8", "172.32.0.1", "100.128.0.1", "127.0.0.1", "0.0.0.0", "224.0.0.1", "255.255.255.255", "1.1.1.1"] {
            assert!(!scannable(no.parse().unwrap()), "{no}");
        }
        assert!(pollable("127.0.0.1".parse().unwrap()) && pollable("fd00::1".parse().unwrap()) && pollable("10.0.0.1".parse().unwrap()));
        assert!(!pollable("8.8.8.8".parse().unwrap()) && !pollable("2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn default_subnets_are_narrow_and_private() {
        let nets = [
            (Ipv4Addr::new(10, 20, 30, 40), 8),
            (Ipv4Addr::new(192, 168, 1, 5), 24),
            (Ipv4Addr::new(192, 168, 1, 6), 24),
            (Ipv4Addr::new(127, 0, 0, 1), 8),
            (Ipv4Addr::new(8, 8, 8, 8), 24),
            (Ipv4Addr::new(172, 17, 0, 1), 32),
        ];
        let s: Vec<String> = local_subnets(&nets).iter().map(Cidr::to_string).collect();
        assert_eq!(s, ["10.20.28.0/22", "192.168.1.0/24"]);
    }

    #[test]
    fn macs_are_normalised() {
        assert_eq!(normalize_mac("AA-BB-CC-0D-0E-0F").as_deref(), Some("aa:bb:cc:0d:0e:0f"));
        assert_eq!(normalize_mac("a:b:c:d:e:f").as_deref(), Some("0a:0b:0c:0d:0e:0f"), "macOS drops leading zeros");
        for bad in ["", "00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff", "aa:bb:cc:dd:ee", "gg:bb:cc:dd:ee:ff", "aabbccddeeff"] {
            assert_eq!(normalize_mac(bad), None, "{bad}");
        }
    }
}
