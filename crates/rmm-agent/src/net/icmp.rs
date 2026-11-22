//! ICMP echo without a raw socket. Linux lets ordinary processes open an ICMP *datagram*
//! socket when their group is in `net.ipv4.ping_group_range` (or they hold CAP_NET_RAW, as the
//! agent does as root): the kernel builds the packet's header and checksum and routes replies
//! back to the socket. Where that isn't allowed, or on other systems, the sweep simply has no
//! ICMP results and relies on TCP and the neighbour table.

use std::net::Ipv4Addr;

/// Hosts that answered an echo, with the round trip in milliseconds.
pub async fn sweep(targets: Vec<Ipv4Addr>) -> Vec<(Ipv4Addr, u32)> {
    #[cfg(target_os = "linux")]
    {
        linux::sweep(targets).await
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = targets;
        Vec::new()
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::os::fd::FromRawFd;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use tokio::net::UdpSocket;

    fn socket() -> std::io::Result<std::net::UdpSocket> {
        // SAFETY: a plain socket(2) call; the descriptor is wrapped (and closed) by UdpSocket.
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC, libc::IPPROTO_ICMP) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: `fd` is a fresh, open, owned descriptor.
        Ok(unsafe { std::net::UdpSocket::from_raw_fd(fd) })
    }

    pub async fn sweep(targets: Vec<Ipv4Addr>) -> Vec<(Ipv4Addr, u32)> {
        let Ok(std_sock) = socket() else { return Vec::new() };
        let Ok(sock) = UdpSocket::from_std(std_sock) else { return Vec::new() };
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
