//! ICMP echo without a raw socket.
//!
//! - **Linux and macOS**: an ICMP *datagram* socket. Linux allows it when the process's group is
//!   in `net.ipv4.ping_group_range` (or it holds CAP_NET_RAW, as the agent does as root); macOS
//!   allows it for everyone. The kernel fills in the header's identifier and checksum.
//! - **Windows**: `IcmpSendEcho` from the IP Helper API, which needs no privileges (IPv4 only).
//!
//! [`sweep`] (many hosts, one echo each, for network discovery) is Linux-only, as it always was:
//! elsewhere discovery relies on TCP and the neighbour table.

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use crate::Guard;

/// Hosts that answered an echo, with the round trip in milliseconds.
pub async fn sweep(targets: Vec<Ipv4Addr>) -> Vec<(Ipv4Addr, u32)> {
    #[cfg(target_os = "linux")]
    {
        unix::sweep(targets).await
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = targets;
        Vec::new()
    }
}

/// Echoes `host` up to `tries` times (stopping at the first answer); the round trip in ms.
pub async fn echo(host: &str, guard: Guard, timeout: Duration, tries: u32) -> Result<u32, String> {
    let addrs = crate::resolve(host, 0, guard, timeout).await?;
    let ip = addrs[0].ip();
    let per = (timeout / tries.max(1)).max(Duration::from_millis(200));
    let mut last = String::from("no reply");
    for seq in 0..tries.max(1) {
        match echo_once(ip, seq as u16, per).await {
            Ok(ms) => return Ok(ms),
            Err(e) => last = e,
        }
    }
    Err(last)
}

async fn echo_once(ip: IpAddr, seq: u16, timeout: Duration) -> Result<u32, String> {
    #[cfg(unix)]
    {
        unix::echo(ip, seq, timeout).await
    }
    #[cfg(windows)]
    {
        let _ = seq;
        let IpAddr::V4(v4) = ip else { return Err("ping over IPv6 isn't supported on Windows yet".into()) };
        tokio::task::spawn_blocking(move || windows::echo(v4, timeout)).await.map_err(|e| e.to_string())?
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (ip, seq, timeout);
        Err("ping isn't supported on this system".into())
    }
}

#[cfg(unix)]
mod unix {
    use std::net::{IpAddr, SocketAddr};
    use std::os::fd::FromRawFd;
    use std::time::{Duration, Instant};

    use tokio::net::UdpSocket;

    pub(super) fn socket(v6: bool) -> std::io::Result<UdpSocket> {
        let (domain, proto) = if v6 { (libc::AF_INET6, libc::IPPROTO_ICMPV6) } else { (libc::AF_INET, libc::IPPROTO_ICMP) };
        // SAFETY: a plain socket(2) call; the descriptor is wrapped (and closed) by UdpSocket.
        let fd = unsafe { libc::socket(domain, libc::SOCK_DGRAM, proto) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: `fd` is a fresh, open descriptor that nothing else owns.
        let s = unsafe { std::net::UdpSocket::from_raw_fd(fd) };
        // SAFETY: fcntl on the descriptor we own.
        unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
        s.set_nonblocking(true)?;
        UdpSocket::from_std(s)
    }

    /// The ICMP message in a datagram: macOS hands IPv4 replies over with their IP header.
    fn icmp_part(buf: &[u8]) -> &[u8] {
        if buf.first().is_some_and(|b| b >> 4 == 4) {
            let ihl = usize::from(buf[0] & 0x0f) * 4;
            if buf.len() > ihl + 8 {
                return &buf[ihl..];
            }
        }
        buf
    }

    pub(super) async fn echo(ip: IpAddr, seq: u16, timeout: Duration) -> Result<u32, String> {
        let v6 = ip.is_ipv6();
        let sock = socket(v6).map_err(|e| {
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                "this machine doesn't allow ICMP for the agent (net.ipv4.ping_group_range)".to_string()
            } else {
                format!("cannot open an ICMP socket: {e}")
            }
        })?;
        let (request, reply) = if v6 { (128u8, 129u8) } else { (8u8, 0u8) };
        let mut pkt = [0u8; 16];
        pkt[0] = request;
        pkt[6..8].copy_from_slice(&seq.to_be_bytes());
        pkt[8..].copy_from_slice(b"rmm-ping");
        let started = Instant::now();
        sock.send_to(&pkt, SocketAddr::new(ip, 0)).await.map_err(|e| format!("sending the echo: {e}"))?;
        let deadline = tokio::time::Instant::now() + timeout;
        let mut buf = [0u8; 1500];
        loop {
            let (n, from) = match tokio::time::timeout_at(deadline, sock.recv_from(&mut buf)).await {
                Err(_) => return Err("no reply".into()),
                Ok(Err(e)) => return Err(format!("receiving: {e}")),
                Ok(Ok(r)) => r,
            };
            let m = icmp_part(&buf[..n]);
            if from.ip() == ip && m.len() >= 8 && m[0] == reply && m[6..8] == seq.to_be_bytes() {
                return Ok(crate::millis(started.elapsed()));
            }
            // Type 3 (unreachable) about our packet ends it early.
            if from.ip() != ip && m.first() == Some(&3) {
                return Err("destination unreachable".into());
            }
        }
    }

    #[cfg(target_os = "linux")]
    pub(super) async fn sweep(targets: Vec<std::net::Ipv4Addr>) -> Vec<(std::net::Ipv4Addr, u32)> {
        use std::collections::HashMap;
        use std::net::Ipv4Addr;
        use std::sync::{Arc, Mutex};

        let Ok(sock) = socket(false) else { return Vec::new() };
        let sock = Arc::new(sock);
        let sent: Arc<Mutex<HashMap<Ipv4Addr, Instant>>> = Arc::default();
        let sender = {
            let (sock, sent) = (sock.clone(), sent.clone());
            tokio::spawn(async move {
                for (i, ip) in targets.iter().enumerate() {
                    // Echo request: type 8, code 0, checksum and id filled in by the kernel, sequence, 8 bytes of payload.
                    let mut pkt = [0u8; 16];
                    pkt[0] = 8;
                    pkt[6..8].copy_from_slice(&(i as u16).to_be_bytes());
                    pkt[8..].copy_from_slice(b"rmm-scan");
                    sent.lock().unwrap().insert(*ip, Instant::now());
                    let _ = sock.send_to(&pkt, SocketAddr::new(IpAddr::V4(*ip), 0)).await;
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            })
        };
        let mut alive: HashMap<Ipv4Addr, u32> = HashMap::new();
        let mut buf = [0u8; 1500];
        let mut stop_at: Option<Instant> = None;
        loop {
            if stop_at.is_none() && sender.is_finished() {
                stop_at = Some(Instant::now() + Duration::from_millis(1500));
            }
            if stop_at.is_some_and(|t| Instant::now() >= t) {
                break;
            }
            let Ok(Ok((n, from))) = tokio::time::timeout(Duration::from_millis(100), sock.recv_from(&mut buf)).await else { continue };
            // The datagram socket delivers the ICMP message itself: type 0 is an echo reply.
            if n >= 8
                && buf[0] == 0
                && let IpAddr::V4(ip) = from.ip()
                && let Some(t) = sent.lock().unwrap().get(&ip)
            {
                alive.entry(ip).or_insert_with(|| t.elapsed().as_millis() as u32);
            }
        }
        let mut out: Vec<_> = alive.into_iter().collect();
        out.sort();
        out
    }
}

#[cfg(windows)]
mod windows {
    use std::net::Ipv4Addr;
    use std::time::Duration;

    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::NetworkManagement::IpHelper::{ICMP_ECHO_REPLY, IcmpCloseHandle, IcmpCreateFile, IcmpSendEcho};

    struct Handle(HANDLE);

    impl Drop for Handle {
        fn drop(&mut self) {
            // SAFETY: the handle came from IcmpCreateFile and is closed once.
            let _ = unsafe { IcmpCloseHandle(self.0) };
        }
    }

    pub(super) fn echo(ip: Ipv4Addr, timeout: Duration) -> Result<u32, String> {
        // SAFETY: no arguments; the handle is closed by `Handle`.
        let h = Handle(unsafe { IcmpCreateFile() }.map_err(|e| format!("IcmpCreateFile: {e}"))?);
        let payload = *b"rmm-ping";
        // A reply buffer must hold one ICMP_ECHO_REPLY, the payload and 8 bytes for an ICMP error.
        let mut reply = vec![0u8; std::mem::size_of::<ICMP_ECHO_REPLY>() + payload.len() + 8 + 64];
        // The address in network byte order, as the API wants it.
        let dest = u32::from_ne_bytes(ip.octets());
        // SAFETY: the buffers outlive the call and their sizes are passed alongside.
        let n = unsafe {
            IcmpSendEcho(
                h.0,
                dest,
                payload.as_ptr().cast(),
                payload.len() as u16,
                None,
                reply.as_mut_ptr().cast(),
                reply.len() as u32,
                timeout.as_millis().clamp(1, u128::from(u32::MAX)) as u32,
            )
        };
        if n == 0 {
            return Err("no reply".into());
        }
        // SAFETY: on success the buffer starts with an ICMP_ECHO_REPLY; read it unaligned.
        let r: ICMP_ECHO_REPLY = unsafe { std::ptr::read_unaligned(reply.as_ptr().cast()) };
        if r.Status != 0 {
            return Err(format!("ICMP status {}", r.Status));
        }
        Ok(r.RoundTripTime)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn loopback_answers_where_icmp_is_allowed() {
        match echo("127.0.0.1", crate::allow_all, Duration::from_secs(2), 2).await {
            Ok(ms) => assert!(ms < 2000),
            // A CI box whose ping_group_range leaves us out: the reason is said.
            Err(e) => assert!(e.contains("ICMP"), "{e}"),
        }
        assert!(echo("127.0.0.1", crate::addr::public_only, Duration::from_secs(1), 1).await.unwrap_err().contains("loopback"));
    }
}
