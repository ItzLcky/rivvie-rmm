//! Wake-on-LAN: magic packets sent for the server ([`rmm_proto::ServerMsg::WakeOnLan`]).
//!
//! A magic packet is six `FF` bytes and then the target's MAC address sixteen times. It goes
//! to UDP ports 9 and 7, three times, to `255.255.255.255` and to the directed broadcast of
//! every IPv4 interface the machine has (the interface whose subnet holds one of the target's
//! last addresses first, since that is the one most likely to reach it).
//!
//! `RMM_WOL_FAKE=<addr:port>` sends every packet to that address instead (tests).

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use rmm_proto::AgentMsg;
use rmm_proto::net::{MAX_WOL_TARGETS, WolTarget};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::{info, warn};
use uuid::Uuid;

use super::addr::{Cidr, normalize_mac};

const PORTS: [u16; 2] = [9, 7];
const REPEAT: usize = 3;
const GAP: Duration = Duration::from_millis(100);

/// The 102-byte magic packet for `mac` (`aa:bb:...`, already normalised).
pub fn magic_packet(mac: &str) -> Option<[u8; 102]> {
    let mac = normalize_mac(mac)?;
    let bytes: Vec<u8> = mac.split(':').map(|p| u8::from_str_radix(p, 16).ok()).collect::<Option<_>>()?;
    let mut out = [0xffu8; 102];
    for i in 0..16 {
        out[6 + i * 6..12 + i * 6].copy_from_slice(&bytes);
    }
    Some(out)
}

/// Broadcast addresses to send to, best first: the directed broadcast of each interface
/// whose subnet holds one of `last_ip`, then those of the other interfaces, then
/// `255.255.255.255`. Loopback is left out.
pub fn destinations(own: &[(Ipv4Addr, u8)], last_ip: &[String]) -> Vec<Ipv4Addr> {
    let targets: Vec<Ipv4Addr> =
        last_ip.iter().filter_map(|s| s.split('/').next().and_then(|ip| ip.trim().parse().ok())).collect();
    let mut near = Vec::new();
    let mut far = Vec::new();
    for &(ip, prefix) in own {
        if ip.is_loopback() || ip.is_unspecified() || prefix == 0 || prefix >= 31 {
            continue;
        }
        let Some(c) = Cidr::parse(&format!("{ip}/{prefix}")) else { continue };
        let bcast = Ipv4Addr::from(c.base | (u32::MAX >> prefix));
        let list = if targets.iter().any(|t| Cidr::parse(&format!("{t}/{prefix}")).is_some_and(|tc| tc.base == c.base)) {
            &mut near
        } else {
            &mut far
        };
        if !list.contains(&bcast) {
            list.push(bcast);
        }
    }
    far.retain(|b| !near.contains(b));
    near.extend(far);
    near.push(Ipv4Addr::BROADCAST);
    near
}

/// Sends the packets and answers the server.
pub async fn wake(request_id: Uuid, mut targets: Vec<WolTarget>, tx: mpsc::Sender<AgentMsg>) {
    targets.truncate(MAX_WOL_TARGETS);
    let (sent, error) = match send_all(&targets).await {
        Ok(n) => (n, None),
        Err(e) => (0, Some(e)),
    };
    info!(%request_id, targets = targets.len(), sent, "wake-on-LAN packets sent");
    let _ = tx.send(AgentMsg::WakeOnLanResult { request_id, sent, error }).await;
}

async fn send_all(targets: &[WolTarget]) -> Result<u32, String> {
    let fake: Option<SocketAddr> = std::env::var("RMM_WOL_FAKE").ok().and_then(|s| s.parse().ok());
    let sock = UdpSocket::bind(if fake.is_some_and(|a| a.ip().is_loopback()) { "127.0.0.1:0" } else { "0.0.0.0:0" })
        .await
        .map_err(|e| format!("can't open a UDP socket: {e}"))?;
    sock.set_broadcast(true).map_err(|e| format!("can't enable broadcast: {e}"))?;
    let own: Vec<(Ipv4Addr, u8)> = super::scan::own_interfaces().into_iter().map(|(ip, p, _)| (ip, p)).collect();
    // Packets and where each goes, worked out once; then three rounds over all of them.
    let mut plan: Vec<([u8; 102], Vec<SocketAddr>)> = Vec::new();
    for t in targets {
        let Some(packet) = magic_packet(&t.mac) else {
            warn!(mac = %t.mac, "not a MAC address; nothing sent");
            continue;
        };
        let dests = match fake {
            Some(a) => vec![a],
            None => destinations(&own, &t.last_ip)
                .into_iter()
                .flat_map(|ip| PORTS.iter().map(move |p| SocketAddr::from((ip, *p))))
                .collect(),
        };
        plan.push((packet, dests));
    }
    let mut went = vec![false; plan.len()];
    for round in 0..REPEAT {
        if round > 0 {
            tokio::time::sleep(GAP).await;
        }
        for (i, (packet, dests)) in plan.iter().enumerate() {
            for d in dests {
                match sock.send_to(packet, d).await {
                    Ok(_) => went[i] = true,
                    // Some interfaces refuse broadcasts (no route, down): the others may still work.
                    Err(e) => tracing::debug!(%d, "wake-on-LAN send failed: {e}"),
                }
            }
        }
    }
    let sent = went.iter().filter(|w| **w).count() as u32;
    if sent == 0 && !plan.is_empty() {
        return Err("no packet could be sent (no interface allows broadcasts)".into());
    }
    Ok(sent)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_magic_packet_is_six_ff_and_sixteen_macs() {
        let p = magic_packet("AA-BB-CC-00-11-22").unwrap();
        assert_eq!(&p[..6], &[0xff; 6]);
        for i in 0..16 {
            assert_eq!(&p[6 + i * 6..12 + i * 6], &[0xaa, 0xbb, 0xcc, 0x00, 0x11, 0x22]);
        }
        assert!(magic_packet("00:00:00:00:00:00").is_none() && magic_packet("nope").is_none());
    }

    #[test]
    fn the_targets_subnet_goes_first() {
        let own = [(Ipv4Addr::new(127, 0, 0, 1), 8), (Ipv4Addr::new(10, 1, 0, 4), 16), (Ipv4Addr::new(192, 168, 7, 20), 24)];
        assert_eq!(
            destinations(&own, &["192.168.7.99/24".into()]),
            [Ipv4Addr::new(192, 168, 7, 255), Ipv4Addr::new(10, 1, 255, 255), Ipv4Addr::BROADCAST]
        );
        assert_eq!(destinations(&own, &[]), [Ipv4Addr::new(10, 1, 255, 255), Ipv4Addr::new(192, 168, 7, 255), Ipv4Addr::BROADCAST]);
        assert_eq!(destinations(&[], &["10.0.0.1".into()]), [Ipv4Addr::BROADCAST]);
    }

    #[tokio::test]
    async fn packets_reach_the_fake_address() {
        let rx = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        // The env var is read per call; set it only for this test's address.
        // SAFETY: no other test in this binary reads or writes RMM_WOL_FAKE.
        unsafe { std::env::set_var("RMM_WOL_FAKE", rx.local_addr().unwrap().to_string()) };
        let (tx, mut out) = mpsc::channel(1);
        wake(Uuid::nil(), vec![WolTarget { mac: "aa:bb:cc:00:11:22".into(), last_ip: vec![] }, WolTarget { mac: "bad".into(), last_ip: vec![] }], tx).await;
        match out.recv().await.unwrap() {
            AgentMsg::WakeOnLanResult { sent, error, .. } => assert_eq!((sent, error), (1, None)),
            other => panic!("{other:?}"),
        }
        let mut buf = [0u8; 200];
        let n = rx.recv(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], &magic_packet("aa:bb:cc:00:11:22").unwrap());
    }
}
