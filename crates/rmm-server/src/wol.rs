//! Wake-on-LAN (docs/design/wake-on-lan.md): an online agent on the same site sends the magic
//! packets for an offline one.
//!
//! [`wake`] works out, for each device, the MAC addresses to wake (from its last inventory)
//! and which agent sends them: the site's designated network agent when it's online, else any
//! online agent of the site that can, preferring one on the same subnet. Each sender gets one
//! [`ServerMsg::WakeOnLan`] with all of its targets.
//!
//! The patch scheduler calls [`wake`] for devices whose patch window is about to open
//! ([`crate::patches::scheduler_tick`]).

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use rmm_proto::ServerMsg;
use rmm_proto::net::{self, WolTarget};
use serde::Serialize;
use tokio::sync::oneshot;
use tracing::{info, warn};
use uuid::Uuid;

use crate::state::AppState;

/// How long to wait for a sender to say it sent the packets.
const ANSWER_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// Packets went out through another agent.
    Sent,
    /// The inventory has no usable MAC address (never reported, or only virtual interfaces).
    NoMac,
    /// No online agent of the site can send them.
    NoSender,
    /// The device is online already: nothing to do.
    Online,
}

#[derive(Debug, Clone, Serialize)]
pub struct Woken {
    pub agent_id: Uuid,
    pub outcome: Outcome,
    /// The agent that sent the packets.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sender_id: Option<Uuid>,
    /// What the sender reported when it couldn't send.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// MAC prefixes of virtual adapters (hypervisors, containers): waking one of those wakes
/// nothing, so they are never a target.
const VIRTUAL_PREFIXES: &[&str] = &[
    "00:05:69", "00:0c:29", "00:1c:14", "00:50:56", // VMware
    "08:00:27", "0a:00:27", // VirtualBox
    "00:15:5d", // Hyper-V
    "52:54:00", // QEMU/KVM
    "00:16:3e", // Xen
    "00:1c:42", // Parallels
    "02:42:",   // Docker bridges and veths
];

/// One interface of an agent's inventory.
#[derive(Debug, Clone)]
struct Iface {
    mac: Option<String>,
    /// `(address, prefix)` of its IPv4 networks.
    nets: Vec<(Ipv4Addr, u8)>,
    addrs: Vec<String>,
}

fn interfaces(inventory: Option<&serde_json::Value>) -> Vec<Iface> {
    let Some(list) = inventory.and_then(|i| i.get("network")).and_then(|n| n.as_array()) else { return Vec::new() };
    list.iter()
        .map(|n| {
            let addrs: Vec<String> = n
                .get("addrs")
                .and_then(|a| a.as_array())
                .map(|a| a.iter().filter_map(|s| s.as_str().map(String::from)).collect())
                .unwrap_or_default();
            let nets = addrs.iter().filter_map(|a| parse_net(a)).collect();
            let name = n.get("name").and_then(|s| s.as_str()).unwrap_or("");
            let mac = n.get("mac").and_then(|s| s.as_str()).and_then(|m| wakeable_mac(name, m));
            Iface { mac, nets, addrs }
        })
        .collect()
}

fn parse_net(s: &str) -> Option<(Ipv4Addr, u8)> {
    let (ip, prefix) = s.split_once('/').unwrap_or((s, "32"));
    Some((ip.trim().parse().ok()?, prefix.trim().parse().ok().filter(|p| *p <= 32)?))
}

/// The MAC of an interface worth waking, normalised; `None` for loopback, all-zero, broadcast,
/// multicast and virtual adapters.
pub fn wakeable_mac(name: &str, mac: &str) -> Option<String> {
    let lname = name.to_ascii_lowercase();
    if lname == "lo" || lname.starts_with("loopback") || lname.starts_with("docker") || lname.starts_with("veth") || lname.starts_with("virbr") {
        return None;
    }
    let m = crate::netmon::normalize_mac(mac)?;
    let first = u8::from_str_radix(&m[..2], 16).ok()?;
    if first & 1 == 1 || VIRTUAL_PREFIXES.iter().any(|p| m.starts_with(p)) {
        return None;
    }
    Some(m)
}

/// What to send for one device: its MACs, each with that interface's last addresses.
fn targets_of(ifaces: &[Iface]) -> Vec<WolTarget> {
    let mut out: Vec<WolTarget> = Vec::new();
    for i in ifaces {
        let Some(mac) = &i.mac else { continue };
        if !out.iter().any(|t| &t.mac == mac) {
            let last_ip = i.addrs.iter().filter(|a| parse_net(a).is_some()).cloned().collect();
            out.push(WolTarget { mac: mac.clone(), last_ip });
        }
    }
    out
}

fn same_subnet(a: &[(Ipv4Addr, u8)], b: &[(Ipv4Addr, u8)]) -> bool {
    a.iter().any(|&(ip, p)| {
        if ip.is_loopback() || p == 0 {
            return false;
        }
        let mask = u32::MAX << (32 - u32::from(p.min(32)));
        b.iter().any(|&(other, _)| !other.is_loopback() && u32::from(ip) & mask == u32::from(other) & mask)
    })
}

/// A possible sender: an online agent of the site that has the capability.
#[derive(Debug, Clone)]
pub struct Candidate {
    pub id: Uuid,
    nets: Vec<(Ipv4Addr, u8)>,
}

/// Who sends for a device with these networks: the designated agent when it's a candidate,
/// else a candidate on the same subnet, else any candidate.
fn choose<'a>(designated: Option<Uuid>, candidates: &'a [Candidate], target: &[(Ipv4Addr, u8)]) -> Option<&'a Candidate> {
    if let Some(d) = designated.and_then(|d| candidates.iter().find(|c| c.id == d)) {
        return Some(d);
    }
    candidates.iter().find(|c| same_subnet(&c.nets, target)).or_else(|| candidates.first())
}

type Answer = (u32, Option<String>);
/// Requests waiting for their answer: request id → (the agent asked, where the answer goes).
type Pending = Mutex<HashMap<Uuid, (Uuid, oneshot::Sender<Answer>)>>;

fn pending() -> &'static Pending {
    static P: OnceLock<Pending> = OnceLock::new();
    P.get_or_init(Default::default)
}

/// An agent's [`rmm_proto::AgentMsg::WakeOnLanResult`].
pub fn complete(from_agent: Uuid, request_id: Uuid, sent: u32, error: Option<String>) {
    let mut p = pending().lock().unwrap();
    if p.get(&request_id).is_some_and(|(a, _)| *a == from_agent)
        && let Some((_, tx)) = p.remove(&request_id)
    {
        let _ = tx.send((sent, error));
    }
}

/// Sends one request and waits for the answer. `Err` when the sender is gone or said nothing.
async fn ask(st: &AppState, sender: Uuid, targets: Vec<WolTarget>) -> Result<Answer, String> {
    let request_id = Uuid::new_v4();
    let (tx, rx) = oneshot::channel();
    pending().lock().unwrap().insert(request_id, (sender, tx));
    if !st.hub.send(sender, ServerMsg::WakeOnLan { request_id, targets }).await {
        pending().lock().unwrap().remove(&request_id);
        return Err("the sending agent went offline".into());
    }
    let res = tokio::time::timeout(ANSWER_TIMEOUT, rx).await;
    pending().lock().unwrap().remove(&request_id);
    match res {
        Ok(Ok(a)) => Ok(a),
        Ok(Err(_)) => Err("the sending agent disconnected".into()),
        Err(_) => Err("the sending agent didn't answer".into()),
    }
}

/// An offline device to wake: its id, what to send, and its networks (to pick a sender).
type Device = (Uuid, Vec<WolTarget>, Vec<(Ipv4Addr, u8)>);

#[derive(sqlx::FromRow)]
struct Row {
    id: Uuid,
    site_id: Uuid,
    inventory: Option<serde_json::Value>,
}

/// Wakes these devices (the caller has checked the user may see them). One result per id
/// that exists, in no particular order. Sets `agents.wol_sent_at` on those packets went out for.
pub async fn wake(st: &AppState, agent_ids: &[Uuid], by: Option<Uuid>) -> anyhow::Result<Vec<Woken>> {
    let rows: Vec<Row> = sqlx::query_as("SELECT id, site_id, inventory FROM agents WHERE id = ANY($1)").bind(agent_ids).fetch_all(&st.db).await?;
    let mut out = Vec::with_capacity(rows.len());
    // Offline devices with something to wake, by site.
    let mut by_site: HashMap<Uuid, Vec<Device>> = HashMap::new();
    for r in rows {
        if st.hub.is_online(r.id) {
            out.push(Woken { agent_id: r.id, outcome: Outcome::Online, sender_id: None, error: None });
            continue;
        }
        let ifaces = interfaces(r.inventory.as_ref());
        let targets = targets_of(&ifaces);
        if targets.is_empty() {
            out.push(Woken { agent_id: r.id, outcome: Outcome::NoMac, sender_id: None, error: None });
            continue;
        }
        let nets = ifaces.iter().filter(|i| i.mac.is_some()).flat_map(|i| i.nets.iter().copied()).collect();
        by_site.entry(r.site_id).or_default().push((r.id, targets, nets));
    }
    // Per sender: the devices it wakes and the packets it sends.
    let mut plan: HashMap<Uuid, (Vec<Uuid>, Vec<WolTarget>)> = HashMap::new();
    for (site_id, devices) in by_site {
        let designated: Option<Uuid> = sqlx::query_scalar("SELECT agent_id FROM site_network WHERE site_id = $1")
            .bind(site_id)
            .fetch_optional(&st.db)
            .await?
            .flatten();
        let others: Vec<(Uuid, Option<serde_json::Value>)> =
            sqlx::query_as("SELECT id, inventory FROM agents WHERE site_id = $1 AND $2 = ANY(capabilities) ORDER BY hostname, id")
                .bind(site_id)
                .bind(net::WOL_CAPABILITY)
                .fetch_all(&st.db)
                .await?;
        let candidates: Vec<Candidate> = others
            .into_iter()
            .filter(|(id, _)| st.hub.is_online(*id))
            .map(|(id, inv)| Candidate { id, nets: interfaces(inv.as_ref()).into_iter().flat_map(|i| i.nets).collect() })
            .collect();
        for (id, targets, nets) in devices {
            match choose(designated, &candidates, &nets) {
                Some(c) => {
                    let e = plan.entry(c.id).or_default();
                    e.0.push(id);
                    e.1.extend(targets);
                }
                None => out.push(Woken { agent_id: id, outcome: Outcome::NoSender, sender_id: None, error: None }),
            }
        }
    }
    let asks = plan.into_iter().map(|(sender, (devices, mut targets))| async move {
        targets.truncate(net::MAX_WOL_TARGETS);
        let answer = ask(st, sender, targets).await;
        (sender, devices, answer)
    });
    let mut sent_ids = Vec::new();
    for (sender, devices, answer) in futures_util::future::join_all(asks).await {
        let error = match answer {
            Ok((n, err)) if n > 0 || err.is_none() => None,
            Ok((_, err)) => err,
            Err(e) => Some(e),
        };
        if let Some(e) = &error {
            warn!(%sender, "wake-on-LAN failed: {e}");
        } else {
            sent_ids.extend(devices.iter().copied());
        }
        for d in devices {
            let outcome = if error.is_none() { Outcome::Sent } else { Outcome::NoSender };
            out.push(Woken { agent_id: d, outcome, sender_id: Some(sender), error: error.clone() });
        }
    }
    if !sent_ids.is_empty() {
        sqlx::query("UPDATE agents SET wol_sent_at = now() WHERE id = ANY($1)").bind(&sent_ids).execute(&st.db).await?;
    }
    info!(asked = agent_ids.len(), sent = sent_ids.len(), by = ?by, "wake-on-LAN");
    Ok(out)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn only_real_adapters_are_woken() {
        assert_eq!(wakeable_mac("eth0", "AA-BB-CC-00-11-22").as_deref(), Some("aa:bb:cc:00:11:22"));
        for (name, mac) in [
            ("lo", "aa:bb:cc:00:11:22"),
            ("eth0", "00:00:00:00:00:00"),
            ("eth0", "ff:ff:ff:ff:ff:ff"),
            ("eth0", "01:00:5e:00:00:01"),
            ("eth0", "00:50:56:aa:bb:cc"),
            ("vEthernet", "00:15:5d:01:02:03"),
            ("docker0", "aa:bb:cc:00:11:22"),
            ("br-x", "02:42:ac:11:00:02"),
            ("eth0", "not a mac"),
        ] {
            assert_eq!(wakeable_mac(name, mac), None, "{name} {mac}");
        }
    }

    #[test]
    fn targets_come_from_the_inventory() {
        let inv = json!({ "network": [
            { "name": "lo", "mac": "00:00:00:00:00:00", "addrs": ["127.0.0.1/8"] },
            { "name": "eth0", "mac": "aa:bb:cc:00:11:22", "addrs": ["192.168.7.20/24", "fe80::1/64"] },
            { "name": "eth0.5", "mac": "aa:bb:cc:00:11:22", "addrs": ["10.5.0.2/16"] },
            { "name": "docker0", "mac": "02:42:00:00:00:01", "addrs": ["172.17.0.1/16"] },
        ]});
        let t = targets_of(&interfaces(Some(&inv)));
        assert_eq!(t, [WolTarget { mac: "aa:bb:cc:00:11:22".into(), last_ip: vec!["192.168.7.20/24".into()] }]);
        assert!(targets_of(&interfaces(None)).is_empty());
        assert!(targets_of(&interfaces(Some(&json!({ "network": "x" })))).is_empty());
    }

    #[test]
    fn the_designated_agent_sends_else_one_on_the_same_subnet() {
        let a = Candidate { id: Uuid::from_u128(1), nets: vec![(Ipv4Addr::new(10, 0, 0, 5), 24)] };
        let b = Candidate { id: Uuid::from_u128(2), nets: vec![(Ipv4Addr::new(192, 168, 7, 3), 24)] };
        let cands = [a.clone(), b.clone()];
        let target = [(Ipv4Addr::new(192, 168, 7, 99), 24)];
        assert_eq!(choose(Some(a.id), &cands, &target).unwrap().id, a.id, "designated wins");
        assert_eq!(choose(None, &cands, &target).unwrap().id, b.id, "same subnet");
        assert_eq!(choose(Some(Uuid::from_u128(9)), &cands, &target).unwrap().id, b.id, "designated offline");
        assert_eq!(choose(None, &cands, &[(Ipv4Addr::new(172, 16, 0, 1), 16)]).unwrap().id, a.id, "anyone");
        assert!(choose(Some(a.id), &[], &target).is_none());
        assert!(!same_subnet(&[(Ipv4Addr::LOCALHOST, 8)], &[(Ipv4Addr::LOCALHOST, 8)]));
    }
}
