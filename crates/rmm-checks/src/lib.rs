//! Small network checks for uptime monitoring: ICMP echo, TCP connect, an HTTP/1.1 GET or
//! HEAD, a TLS handshake that reads the server's certificate, and DNS lookups.
//!
//! No HTTP framework and no X.509 library: the HTTP client is a few hundred lines over
//! `tokio-rustls` (the TLS stack the agent already has), and certificates are read with the BER
//! reader of `rmm-snmp`. The agent runs these for the checks the server sends it
//! (`rmm_proto::checks`); the server links the same code for the checks it runs itself, which is
//! why every check that connects somewhere takes an address [`Guard`].
//!
//! Nothing here returns a response body: only status codes, latency, whether a keyword was found,
//! and certificate fields.

pub mod addr;
pub mod dns;
pub mod http;
pub mod ping;
pub mod tcp;
pub mod tls;
pub mod x509;

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

/// Decides whether a check may connect to an address, after the name was resolved (and again
/// on every redirect). The agent allows everything (reaching private space is its purpose); a
/// server-run check refuses loopback, private, link-local and metadata addresses ([`addr`]).
pub type Guard = fn(IpAddr) -> Result<(), String>;

/// Allows every address.
pub fn allow_all(_: IpAddr) -> Result<(), String> {
    Ok(())
}

/// Resolves `host` (a name or an address literal) and returns the addresses the guard allows,
/// in the resolver's order. An error says why there is nothing to connect to.
pub async fn resolve(host: &str, port: u16, guard: Guard, timeout: Duration) -> Result<Vec<SocketAddr>, String> {
    let host = host.trim_matches(['[', ']']);
    if host.is_empty() {
        return Err("no host".into());
    }
    let addrs: Vec<SocketAddr> = if let Ok(ip) = host.parse::<IpAddr>() {
        vec![SocketAddr::new(ip, port)]
    } else {
        match tokio::time::timeout(timeout, tokio::net::lookup_host((host, port))).await {
            Err(_) => return Err(format!("resolving {host} timed out")),
            Ok(Err(e)) => return Err(format!("cannot resolve {host}: {e}")),
            Ok(Ok(a)) => a.collect(),
        }
    };
    if addrs.is_empty() {
        return Err(format!("{host} has no addresses"));
    }
    let mut refused = None;
    let allowed: Vec<SocketAddr> = addrs
        .into_iter()
        .filter(|a| match guard(a.ip()) {
            Ok(()) => true,
            Err(e) => {
                refused.get_or_insert(e);
                false
            }
        })
        .collect();
    match (allowed.is_empty(), refused) {
        (true, Some(e)) => Err(e),
        _ => Ok(allowed),
    }
}

/// Milliseconds, saturating.
pub(crate) fn millis(d: Duration) -> u32 {
    d.as_millis().min(u128::from(u32::MAX)) as u32
}
