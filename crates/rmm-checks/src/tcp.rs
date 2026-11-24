//! TCP connect: the port answers (a handshake completes) within the timeout.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use tokio::net::TcpStream;

use crate::Guard;

/// Connects to the first address of `host` that accepts, trying each in turn. Returns the time
/// the successful handshake took and the address.
pub async fn connect(host: &str, port: u16, guard: Guard, timeout: Duration) -> Result<(u32, SocketAddr), String> {
    let deadline = Instant::now() + timeout;
    let addrs = crate::resolve(host, port, guard, timeout).await?;
    let (stream, ms) = connect_any(&addrs, deadline).await?;
    let peer = stream.peer_addr().map_err(|e| e.to_string())?;
    Ok((ms, peer))
}

/// The first of `addrs` that accepts before `deadline`, and how long its handshake took.
pub(crate) async fn connect_any(addrs: &[SocketAddr], deadline: Instant) -> Result<(TcpStream, u32), String> {
    let mut last = String::from("no address to connect to");
    for a in addrs {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err("timed out".into());
        }
        let started = Instant::now();
        match tokio::time::timeout(left, TcpStream::connect(a)).await {
            Ok(Ok(s)) => {
                let _ = s.set_nodelay(true);
                return Ok((s, crate::millis(started.elapsed())));
            }
            Ok(Err(e)) => last = format!("{a}: {}", describe(&e)),
            Err(_) => last = format!("{a}: timed out"),
        }
    }
    Err(last)
}

pub(crate) fn describe(e: &std::io::Error) -> String {
    match e.kind() {
        std::io::ErrorKind::ConnectionRefused => "connection refused".into(),
        std::io::ErrorKind::TimedOut => "timed out".into(),
        _ => e.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn open_and_closed_ports() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let (ms, peer) = connect("127.0.0.1", port, crate::allow_all, Duration::from_secs(2)).await.unwrap();
        assert!(ms < 2000 && peer.port() == port);
        drop(l);
        let e = connect("127.0.0.1", port, crate::allow_all, Duration::from_secs(10)).await.unwrap_err();
        assert!(e.contains("refused"), "{e}");
        let e = connect("127.0.0.1", port, crate::addr::public_only, Duration::from_secs(2)).await.unwrap_err();
        assert!(e.contains("loopback"), "the guard sees the address: {e}");
    }
}
