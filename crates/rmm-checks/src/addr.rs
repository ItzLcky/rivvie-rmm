//! Address classes, for the rule that a check run by the server may only reach the public
//! internet: loopback, private, link-local, cloud metadata and other special-purpose ranges are
//! refused after the name is resolved (and on every redirect), so a monitor can't be pointed at
//! the server's own network.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    Public,
    Loopback,
    /// RFC 1918, carrier-grade NAT (100.64/10), IPv6 unique local (fc00::/7).
    Private,
    /// 169.254/16, fe80::/10.
    LinkLocal,
    /// Cloud instance metadata: 169.254.169.254, fd00:ec2::254, 100.100.100.200 (Alibaba).
    Metadata,
    /// Unspecified, broadcast, multicast, documentation, benchmarking and reserved ranges.
    Special,
}

impl Class {
    pub fn describe(self) -> &'static str {
        match self {
            Class::Public => "a public address",
            Class::Loopback => "a loopback address",
            Class::Private => "a private address",
            Class::LinkLocal => "a link-local address",
            Class::Metadata => "a cloud metadata address",
            Class::Special => "a reserved address",
        }
    }
}

fn v4(ip: Ipv4Addr) -> Class {
    let o = ip.octets();
    if ip == Ipv4Addr::new(169, 254, 169, 254) || ip == Ipv4Addr::new(100, 100, 100, 200) {
        return Class::Metadata;
    }
    if ip.is_loopback() {
        Class::Loopback
    } else if ip.is_private() || (o[0] == 100 && (o[1] & 0xc0) == 64) {
        Class::Private
    } else if ip.is_link_local() {
        Class::LinkLocal
    } else if ip.is_unspecified()
        || ip.is_broadcast()
        || ip.is_multicast()
        || ip.is_documentation()
        || o[0] == 0
        || o[0] >= 240
        || (o[0] == 192 && o[1] == 0 && o[2] == 0)
        || (o[0] == 198 && (o[1] & 0xfe) == 18)
    {
        Class::Special
    } else {
        Class::Public
    }
}

fn v6(ip: Ipv6Addr) -> Class {
    if let Some(m) = ip.to_ipv4_mapped() {
        return v4(m);
    }
    let s = ip.segments();
    if ip == Ipv6Addr::new(0xfd00, 0xec2, 0, 0, 0, 0, 0, 0x254) {
        Class::Metadata
    } else if ip.is_loopback() {
        Class::Loopback
    } else if (s[0] & 0xfe00) == 0xfc00 {
        Class::Private
    } else if (s[0] & 0xffc0) == 0xfe80 {
        Class::LinkLocal
    } else if ip.is_unspecified() || ip.is_multicast() || (s[0] == 0x2001 && s[1] == 0x0db8) || (s[0] == 0x64 && s[1] == 0xff9b) || s[0] == 0x0100 {
        // Unspecified, multicast, documentation, NAT64 (it reaches IPv4 space we can't see), discard.
        Class::Special
    } else {
        Class::Public
    }
}

pub fn classify(ip: IpAddr) -> Class {
    match ip {
        IpAddr::V4(a) => v4(a),
        IpAddr::V6(a) => v6(a),
    }
}

/// A [`crate::Guard`] that only lets public addresses through.
pub fn public_only(ip: IpAddr) -> Result<(), String> {
    match classify(ip) {
        Class::Public => Ok(()),
        c => Err(format!("{ip} is {}, which checks run by the server may not reach", c.describe())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(s: &str) -> Class {
        classify(s.parse().unwrap())
    }

    #[test]
    fn address_classes() {
        assert_eq!(c("8.8.8.8"), Class::Public);
        assert_eq!(c("2606:4700::1111"), Class::Public);
        for s in ["127.0.0.1", "127.255.0.9", "::1"] {
            assert_eq!(c(s), Class::Loopback, "{s}");
        }
        for s in ["10.1.2.3", "172.16.0.1", "172.31.255.255", "192.168.1.1", "100.64.0.1", "100.127.255.254", "fd12::1", "fc00::1"] {
            assert_eq!(c(s), Class::Private, "{s}");
        }
        assert_eq!(c("172.32.0.1"), Class::Public);
        assert_eq!(c("100.128.0.1"), Class::Public);
        for s in ["169.254.1.1", "fe80::1"] {
            assert_eq!(c(s), Class::LinkLocal, "{s}");
        }
        for s in ["169.254.169.254", "fd00:ec2::254", "100.100.100.200", "::ffff:169.254.169.254"] {
            assert_eq!(c(s), Class::Metadata, "{s}");
        }
        for s in ["0.0.0.0", "255.255.255.255", "224.0.0.1", "192.0.2.1", "198.18.0.1", "240.0.0.1", "::", "ff02::1", "2001:db8::1", "64:ff9b::1.2.3.4"] {
            assert_eq!(c(s), Class::Special, "{s}");
        }
        // An IPv4-mapped address is judged as the IPv4 address it is.
        assert_eq!(c("::ffff:10.0.0.1"), Class::Private);
        assert_eq!(c("::ffff:8.8.4.4"), Class::Public);
        assert!(public_only("1.1.1.1".parse().unwrap()).is_ok());
        assert!(public_only("127.0.0.1".parse().unwrap()).unwrap_err().contains("loopback"));
    }
}
