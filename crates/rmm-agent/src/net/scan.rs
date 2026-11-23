//! The sweep: which addresses answer, who they are, what they offer.
//!
//! Liveness comes from three sources, none of which needs more than ordinary rights: an ICMP
//! echo over an unprivileged datagram socket (Linux), a TCP connection attempt (an answer or a
//! refusal both mean someone is there) and the neighbour table, which the attempts fill in
//! for hosts on the same subnet. A host that only shows up in the table still counts.
//!
//! Everything is bounded: [`CONCURRENCY`] probes in flight, [`PACE`] between starting two, and
//! [`rmm_proto::net::MAX_SCAN_HOSTS`] addresses.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rmm_proto::net::{Host, MAX_SCAN_HOSTS, SCAN_PORTS, ScanSpec, SnmpIdent, SnmpProfile};
use tokio::net::TcpStream;
use tokio::sync::{Mutex, Semaphore};

use super::addr::{Cidr, local_subnets, normalize_mac, scannable};
use super::{arp, dns, poll};

/// Probes in flight at once.
const CONCURRENCY: usize = 128;
/// The least time between starting two connection attempts: at most about 1,000 a second.
const PACE: Duration = Duration::from_millis(1);
const CONNECT_TIMEOUT: Duration = Duration::from_millis(600);
/// Ports tried to find out whether a host is there at all.
const LIVENESS_PORTS: &[u16] = &[443, 80, 22, 445, 135, 3389];
/// A scan that takes longer than this stops and reports what it has.
const MAX_DURATION: Duration = Duration::from_secs(600);

pub struct Outcome {
    pub subnets: Vec<String>,
    pub scanned: u32,
    pub hosts: Vec<Host>,
    pub error: Option<String>,
}

/// Spaces out the starts of probes.
struct Pacer(Mutex<Instant>);

impl Pacer {
    async fn wait(&self) {
        let at = {
            let mut next = self.0.lock().await;
            let at = (*next).max(Instant::now());
            *next = at + PACE;
            at
        };
        tokio::time::sleep_until(tokio::time::Instant::from_std(at)).await;
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Reach {
    /// A connection opened.
    Open,
    /// Refused or reset: a host is there, with nothing on that port.
    Closed,
    /// Nothing came back.
    Silent,
}

async fn connect(ip: Ipv4Addr, port: u16) -> Reach {
    match tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(SocketAddr::new(IpAddr::V4(ip), port))).await {
        Ok(Ok(_)) => Reach::Open,
        Ok(Err(e)) if matches!(e.kind(), std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::ConnectionReset) => Reach::Closed,
        _ => Reach::Silent,
    }
}

#[derive(Default)]
struct Seen {
    methods: Vec<&'static str>,
    rtt_ms: Option<u32>,
}

/// This machine's IPv4 networks and MAC addresses.
pub fn own_interfaces() -> Vec<(Ipv4Addr, u8, Option<String>)> {
    let Ok(nets) = sysinfo::Networks::new_with_refreshed_list() else { return Vec::new() };
    let mut out = Vec::new();
    for (_, n) in &nets {
        let mac = normalize_mac(&n.mac_address().to_string());
        for ip in n.ip_networks() {
            if let IpAddr::V4(v4) = ip.addr {
                out.push((v4, ip.prefix, mac.clone()));
            }
        }
    }
    out
}

/// Runs a scan. `allow_loopback` is for tests only: the scan never leaves private space otherwise.
pub async fn run(spec: &ScanSpec, allow_loopback: bool) -> Outcome {
    let started = Instant::now();
    let own = own_interfaces();
    let mut error = None;

    // Which blocks.
    let mut blocks: Vec<Cidr> = Vec::new();
    if spec.subnets.is_empty() {
        let nets: Vec<(Ipv4Addr, u8)> = own.iter().map(|(ip, p, _)| (*ip, *p)).collect();
        blocks = local_subnets(&nets);
        if blocks.is_empty() {
            return Outcome { subnets: vec![], scanned: 0, hosts: vec![], error: Some("this machine has no private IPv4 network to scan".into()) };
        }
    } else {
        for s in &spec.subnets {
            match Cidr::parse(s) {
                Some(c) => blocks.push(c),
                None => return Outcome { subnets: vec![], scanned: 0, hosts: vec![], error: Some(format!("{s:?} isn't an IPv4 block like 192.168.1.0/24")) },
            }
        }
    }
    let max = spec.max_hosts.clamp(1, MAX_SCAN_HOSTS) as usize;
    let mut targets: Vec<Ipv4Addr> = Vec::new();
    let mut seen_ip = HashSet::new();
    'blocks: for b in &blocks {
        for ip in b.hosts() {
            if !(scannable(ip) || (allow_loopback && ip.is_loopback())) || !seen_ip.insert(ip) {
                continue;
            }
            if targets.len() >= max {
                error = Some(format!("the blocks hold more than {max} addresses; the rest weren't scanned"));
                break 'blocks;
            }
            targets.push(ip);
        }
    }
    let subnets: Vec<String> = blocks.iter().map(Cidr::to_string).collect();

    // Phase 1: who is there.
    let mut seen: BTreeMap<Ipv4Addr, Seen> = BTreeMap::new();
    let icmp = tokio::spawn(super::icmp::sweep(targets.clone()));
    let pacer = Arc::new(Pacer(Mutex::new(Instant::now())));
    let sem = Arc::new(Semaphore::new(CONCURRENCY));
    let mut tasks = tokio::task::JoinSet::new();
    for &ip in &targets {
        let (pacer, sem) = (pacer.clone(), sem.clone());
        tasks.spawn(async move {
            let _permit = sem.acquire_owned().await.ok()?;
            for &port in LIVENESS_PORTS {
                pacer.wait().await;
                let t = Instant::now();
                if connect(ip, port).await != Reach::Silent {
                    return Some((ip, t.elapsed().as_millis() as u32));
                }
            }
            None
        });
    }
    while let Some(r) = tasks.join_next().await {
        if started.elapsed() > MAX_DURATION {
            error = Some("the scan took too long and was stopped; this is what it found so far".into());
            tasks.abort_all();
            break;
        }
        if let Ok(Some((ip, rtt))) = r {
            let s = seen.entry(ip).or_default();
            s.methods.push("tcp");
            s.rtt_ms = Some(rtt);
        }
    }
    for (ip, rtt) in icmp.await.unwrap_or_default() {
        let s = seen.entry(ip).or_default();
        s.methods.insert(0, "icmp");
        s.rtt_ms = Some(s.rtt_ms.map_or(rtt, |r| r.min(rtt)));
    }
    // The neighbour table, after the probes have filled it.
    let target_set: HashSet<Ipv4Addr> = targets.iter().copied().collect();
    let mut macs: HashMap<Ipv4Addr, String> = HashMap::new();
    for (ip, mac) in arp::read() {
        if target_set.contains(&ip) {
            macs.insert(ip, mac);
            let s = seen.entry(ip).or_default();
            if !s.methods.contains(&"arp") {
                s.methods.push("arp");
            }
        }
    }
    // The machine itself is a host of its own subnets, with a MAC the table doesn't show.
    for (ip, _, mac) in &own {
        if target_set.contains(ip) {
            let s = seen.entry(*ip).or_default();
            s.methods.push("local");
            if let Some(m) = mac {
                macs.insert(*ip, m.clone());
            }
        }
    }

    // Phase 2: what each one is.
    let mdns = if spec.names { tokio::spawn(dns::mdns_browse(Duration::from_millis(1500))) } else { tokio::spawn(async { HashMap::new() }) };
    let servers = Arc::new(if spec.names { dns::nameservers() } else { Vec::new() });
    let profiles = Arc::new(spec.profiles.clone());
    let sem = Arc::new(Semaphore::new(CONCURRENCY / 2));
    let mut tasks = tokio::task::JoinSet::new();
    for ip in seen.keys().copied() {
        let (sem, pacer, servers, profiles) = (sem.clone(), pacer.clone(), servers.clone(), profiles.clone());
        let names = spec.names;
        tasks.spawn(async move {
            let _permit = sem.acquire_owned().await.ok()?;
            let mut ports = Vec::new();
            let mut checks = tokio::task::JoinSet::new();
            for &port in SCAN_PORTS {
                pacer.wait().await;
                checks.spawn(async move { (port, connect(ip, port).await) });
            }
            while let Some(Ok((port, r))) = checks.join_next().await {
                if r == Reach::Open {
                    ports.push(port);
                }
            }
            ports.sort_unstable();
            let hostname = if names {
                let mut name = None;
                for s in servers.iter() {
                    if let Some(n) = dns::ptr_lookup(*s, ip, Duration::from_millis(700), false).await {
                        name = Some(n);
                        break;
                    }
                }
                name
            } else {
                None
            };
            // Ask the host itself for its mDNS name when the group browse doesn't.
            let unicast_mdns =
                if names { dns::ptr_lookup(SocketAddr::new(IpAddr::V4(ip), 5353), ip, Duration::from_millis(400), true).await } else { None };
            let snmp = ident(ip, &profiles).await;
            Some((ip, ports, hostname, unicast_mdns, snmp))
        });
    }
    /// Open ports, reverse-DNS name, mDNS name and SNMP identity of one host.
    type Detail = (Vec<u16>, Option<String>, Option<String>, Option<SnmpIdent>);
    let mut details: HashMap<Ipv4Addr, Detail> = HashMap::new();
    while let Some(r) = tasks.join_next().await {
        if let Ok(Some((ip, ports, host, mdns, snmp))) = r {
            details.insert(ip, (ports, host, mdns, snmp));
        }
    }
    let group_names = mdns.await.unwrap_or_default();

    let hosts = seen
        .into_iter()
        .map(|(ip, s)| {
            let (open_ports, hostname, unicast, snmp) = details.remove(&ip).unwrap_or_default();
            let mut methods: Vec<String> = s.methods.iter().map(|m| m.to_string()).collect();
            if snmp.is_some() {
                methods.push("snmp".into());
            }
            Host {
                ip: ip.to_string(),
                mac: macs.get(&ip).cloned(),
                hostname,
                mdns_name: group_names.get(&ip).cloned().or(unicast),
                methods,
                open_ports,
                snmp,
                rtt_ms: s.rtt_ms,
            }
        })
        .collect();
    Outcome { subnets, scanned: targets.len() as u32, hosts, error }
}

/// Tries each credential profile for the system group; the first that answers wins.
async fn ident(ip: Ipv4Addr, profiles: &[SnmpProfile]) -> Option<SnmpIdent> {
    for p in profiles {
        if let Some(sys) = poll::identify(IpAddr::V4(ip), p.port, &p.creds).await {
            return Some(SnmpIdent { profile_id: p.id, sys });
        }
    }
    None
}
