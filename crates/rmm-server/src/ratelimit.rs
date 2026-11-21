//! Brute-force protection for sign-in and enrollment.
//!
//! Token buckets keyed by client IP (and, for sign-in, also by email). Only failures take a
//! token, so a site rolling out hundreds of agents from one NAT address, or a busy office
//! signing in, is never throttled; an attacker guessing passwords or tokens runs dry quickly.
//!
//! Behind a reverse proxy every request comes from the proxy's address, so the client IP is
//! taken from `X-Forwarded-For`, but only when the direct peer is in `RMM_TRUSTED_PROXIES`.
//! Otherwise anyone could pick their own rate-limit key by sending that header.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use axum::extract::{ConnectInfo, FromRequestParts};
use axum::http::request::Parts;

use crate::state::AppState;

pub struct Limiter {
    capacity: f64,
    /// Tokens regained per second.
    refill: f64,
    buckets: Mutex<HashMap<String, Bucket>>,
}

struct Bucket {
    tokens: f64,
    at: Instant,
}

impl Limiter {
    /// `capacity` failures in a burst, then one more every `every`.
    pub fn new(capacity: u32, every: Duration) -> Self {
        Self { capacity: capacity as f64, refill: 1.0 / every.as_secs_f64(), buckets: Mutex::default() }
    }

    fn level(&self, b: &Bucket, now: Instant) -> f64 {
        (b.tokens + now.duration_since(b.at).as_secs_f64() * self.refill).min(self.capacity)
    }

    /// `Err(retry_after)` when `key` has no attempts left.
    pub fn check(&self, key: &str) -> Result<(), Duration> {
        let now = Instant::now();
        let buckets = self.buckets.lock().unwrap_or_else(|e| e.into_inner());
        match buckets.get(key) {
            Some(b) => {
                let level = self.level(b, now);
                if level >= 1.0 { Ok(()) } else { Err(Duration::from_secs_f64((1.0 - level) / self.refill).max(Duration::from_secs(1))) }
            }
            None => Ok(()),
        }
    }

    /// Record a failure against `key`.
    pub fn fail(&self, key: &str) {
        let now = Instant::now();
        let mut buckets = self.buckets.lock().unwrap_or_else(|e| e.into_inner());
        let level = buckets.get(key).map_or(self.capacity, |b| self.level(b, now));
        buckets.insert(key.to_string(), Bucket { tokens: (level - 1.0).max(0.0), at: now });
    }

    /// Check and spend one token: for limits on every use rather than on failures.
    pub fn take(&self, key: &str) -> Result<(), Duration> {
        self.check(key)?;
        self.fail(key);
        Ok(())
    }

    /// Forget buckets that have refilled completely; they behave like absent ones.
    pub fn prune(&self) {
        let now = Instant::now();
        let mut buckets = self.buckets.lock().unwrap_or_else(|e| e.into_inner());
        buckets.retain(|_, b| self.level(b, now) < self.capacity);
    }
}

pub struct Limits {
    /// Failed sign-ins (bad password or 2FA code) per client IP.
    pub login_ip: Limiter,
    /// Failed sign-ins per account, so a botnet can't spread guesses over many IPs.
    pub login_account: Limiter,
    /// Bad enrollment tokens per client IP (agent socket and token-authorized downloads).
    pub enroll_ip: Limiter,
    /// Vault password reveals and TOTP codes per user. Unlike the others every request takes
    /// a token (see [`Limiter::take`]): a stolen session can't page through a vault quickly.
    pub vault_reveal: Limiter,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            login_ip: Limiter::new(10, Duration::from_secs(30)),
            login_account: Limiter::new(20, Duration::from_secs(90)),
            enroll_ip: Limiter::new(20, Duration::from_secs(15)),
            // 60 per 5 minutes.
            vault_reveal: Limiter::new(60, Duration::from_secs(5)),
        }
    }
}

impl Limits {
    pub fn prune(&self) {
        self.login_ip.prune();
        self.login_account.prune();
        self.enroll_ip.prune();
        self.vault_reveal.prune();
    }
}

/// An IPv4/IPv6 network in CIDR notation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    net: IpAddr,
    bits: u8,
}

impl Cidr {
    pub fn parse(s: &str) -> Option<Self> {
        let (addr, bits) = match s.split_once('/') {
            Some((a, b)) => (a, Some(b.parse::<u8>().ok()?)),
            None => (s, None),
        };
        let net: IpAddr = addr.parse().ok()?;
        let max = if net.is_ipv4() { 32 } else { 128 };
        let bits = bits.unwrap_or(max);
        (bits <= max).then_some(Self { net, bits })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        let ip = canonical(ip);
        match (self.net, ip) {
            (IpAddr::V4(n), IpAddr::V4(i)) => {
                let mask = if self.bits == 0 { 0 } else { u32::MAX << (32 - self.bits) };
                u32::from(n) & mask == u32::from(i) & mask
            }
            (IpAddr::V6(n), IpAddr::V6(i)) => {
                let mask = if self.bits == 0 { 0 } else { u128::MAX << (128 - self.bits) };
                u128::from(n) & mask == u128::from(i) & mask
            }
            _ => false,
        }
    }
}

/// `::ffff:10.0.0.1` (a v4 peer on a dual-stack socket) compares as `10.0.0.1`.
fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        v4 => v4,
    }
}

/// Parses `RMM_TRUSTED_PROXIES`: comma-separated CIDRs or addresses. `private` expands to
/// loopback plus the RFC 1918 and IPv6 unique-local ranges (a proxy on the same host or in
/// the same Docker network).
pub fn parse_trusted(spec: &str) -> Result<Vec<Cidr>, String> {
    let mut out = Vec::new();
    for item in spec.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        if item.eq_ignore_ascii_case("private") {
            for c in ["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "::1/128", "fc00::/7"] {
                out.push(Cidr::parse(c).expect("valid"));
            }
        } else {
            out.push(Cidr::parse(item).ok_or_else(|| format!("RMM_TRUSTED_PROXIES: invalid address or CIDR '{item}'"))?);
        }
    }
    Ok(out)
}

/// The address a request really came from. Walks `X-Forwarded-For` right to left past
/// trusted proxies; the first untrusted hop is the client. Entries left of it were
/// supplied by the client and are ignored.
pub fn client_ip(peer: IpAddr, forwarded_for: &[&str], trusted: &[Cidr]) -> IpAddr {
    let peer = canonical(peer);
    if !trusted.iter().any(|c| c.contains(peer)) {
        return peer;
    }
    let hops = forwarded_for.iter().rev().flat_map(|h| h.rsplit(',')).map(str::trim);
    let mut last = peer;
    for hop in hops {
        let Ok(ip) = hop.parse::<IpAddr>().map(canonical) else { return last };
        if !trusted.iter().any(|c| c.contains(ip)) {
            return ip;
        }
        last = ip;
    }
    last
}

/// Extractor for the client IP as computed by [`client_ip`].
pub struct ClientIp(pub IpAddr);

impl FromRequestParts<std::sync::Arc<AppState>> for ClientIp {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, st: &std::sync::Arc<AppState>) -> Result<Self, Self::Rejection> {
        let peer = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|c| c.0.ip())
            .unwrap_or(IpAddr::from([0, 0, 0, 0]));
        let xff: Vec<&str> = parts.headers.get_all("x-forwarded-for").iter().filter_map(|v| v.to_str().ok()).collect();
        Ok(ClientIp(client_ip(peer, &xff, &st.cfg.trusted_proxies)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn bucket_blocks_after_capacity_failures() {
        let l = Limiter::new(3, Duration::from_secs(60));
        for _ in 0..3 {
            assert!(l.check("a").is_ok());
            l.fail("a");
        }
        let wait = l.check("a").unwrap_err();
        assert!(wait > Duration::from_secs(50) && wait <= Duration::from_secs(60), "{wait:?}");
        assert!(l.check("b").is_ok(), "keys are independent");
    }

    #[test]
    fn take_spends_on_success() {
        let l = Limiter::new(2, Duration::from_secs(60));
        assert!(l.take("u").is_ok() && l.take("u").is_ok());
        assert!(l.take("u").is_err());
        assert!(Limits::default().vault_reveal.capacity == 60.0);
    }

    #[test]
    fn bucket_refills() {
        let l = Limiter::new(1, Duration::from_millis(20));
        l.fail("a");
        assert!(l.check("a").is_err());
        std::thread::sleep(Duration::from_millis(30));
        assert!(l.check("a").is_ok());
        l.prune();
        assert!(l.buckets.lock().unwrap().is_empty());
    }

    #[test]
    fn cidr_matching() {
        let c = Cidr::parse("172.16.0.0/12").unwrap();
        assert!(c.contains(ip("172.20.1.2")));
        assert!(!c.contains(ip("172.32.0.1")));
        assert!(c.contains(ip("::ffff:172.20.1.2")));
        assert!(Cidr::parse("fc00::/7").unwrap().contains(ip("fd12::1")));
        assert!(Cidr::parse("10.0.0.1").unwrap().contains(ip("10.0.0.1")));
        assert!(Cidr::parse("10.0.0.0/33").is_none());
        assert!(Cidr::parse("0.0.0.0/0").unwrap().contains(ip("8.8.8.8")));
    }

    #[test]
    fn forwarded_for_only_from_trusted_proxies() {
        let trusted = parse_trusted("private").unwrap();
        // Direct connection from the internet: the header is the client's own claim.
        assert_eq!(client_ip(ip("203.0.113.9"), &["1.2.3.4"], &trusted), ip("203.0.113.9"));
        // Via a trusted proxy: the proxy appended the real client.
        assert_eq!(client_ip(ip("172.18.0.3"), &["203.0.113.9"], &trusted), ip("203.0.113.9"));
        // A spoofed entry to the left of the real one is skipped.
        assert_eq!(client_ip(ip("172.18.0.3"), &["6.6.6.6, 203.0.113.9"], &trusted), ip("203.0.113.9"));
        assert_eq!(client_ip(ip("172.18.0.3"), &["6.6.6.6", "203.0.113.9"], &trusted), ip("203.0.113.9"));
        // Chained trusted proxies.
        assert_eq!(client_ip(ip("127.0.0.1"), &["203.0.113.9, 10.0.0.2"], &trusted), ip("203.0.113.9"));
        // No header, or garbage: fall back to the last trusted hop.
        assert_eq!(client_ip(ip("172.18.0.3"), &[], &trusted), ip("172.18.0.3"));
        assert_eq!(client_ip(ip("172.18.0.3"), &["nonsense"], &trusted), ip("172.18.0.3"));
        // Nothing trusted (the default): the peer, always.
        assert_eq!(client_ip(ip("172.18.0.3"), &["203.0.113.9"], &[]), ip("172.18.0.3"));
        assert!(parse_trusted("10.0.0.0/8, bogus").is_err());
    }
}
