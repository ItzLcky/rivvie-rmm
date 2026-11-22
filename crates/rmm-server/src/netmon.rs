//! Network discovery and SNMP monitoring, server side (docs/design/network.md).
//!
//! Each site has one designated agent ([`crate::api::network`] sets it). This module asks it
//! to scan ([`start_scan`]) and to read the site's monitored devices ([`run`]), and stores
//! what it answers ([`ingest_scan`], [`ingest_poll`]): discovered hosts matched to the
//! agents we manage, device state, interface rates and the samples the charts and alerts
//! ([`crate::netalerts`]) work from.
//!
//! Credentials stay sealed in the database (`net_credentials`); they leave it only inside a
//! request to the one agent that reads that site, never in an API response.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use rmm_proto::net::{self, PollResult, PollTarget, ScanSpec, SnmpCreds, SnmpProfile};
use rmm_proto::ServerMsg;
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::Row;
use tracing::{info, warn};
use uuid::Uuid;

use crate::hub::Event;
use crate::state::AppState;

const TICK: Duration = Duration::from_secs(10);
/// A poll the agent hasn't answered after this long is given up on.
const POLL_TIMEOUT: Duration = Duration::from_secs(240);
/// A scan has this long: the agent stops itself after ten minutes.
const SCAN_TIMEOUT_MINUTES: i64 = 15;
/// Counters are only turned into rates over at least this long.
const MIN_RATE_SECS: f64 = 5.0;

// ---------------------------------------------------------------------------
// Credentials
// ---------------------------------------------------------------------------

/// A `net_credentials` row.
#[derive(sqlx::FromRow)]
pub struct CredRow {
    pub id: Uuid,
    pub name: String,
    pub version: String,
    pub username: String,
    pub auth_proto: Option<String>,
    pub priv_proto: Option<String>,
    pub context: String,
    pub secret: Vec<u8>,
    pub secret_sealed: bool,
}

#[derive(Deserialize, Default)]
struct Secret {
    #[serde(default)]
    community: String,
    #[serde(default)]
    auth_secret: Option<String>,
    #[serde(default)]
    priv_secret: Option<String>,
}

pub const CRED_COLUMNS: &str = "id, name, version, username, auth_proto, priv_proto, context, secret, secret_sealed";

impl CredRow {
    /// The credentials as the agent takes them, with the secret opened. `None` if it can't be
    /// (sealed and the server has no key, or the wrong one).
    pub fn open(&self, key: Option<&crate::crypto::DataKey>) -> Option<SnmpCreds> {
        let plain = crate::crypto::load(key, &self.secret, self.secret_sealed)?;
        let s: Secret = serde_json::from_slice(&plain).ok()?;
        Some(if self.version == "v2c" {
            SnmpCreds::V2c { community: s.community }
        } else {
            SnmpCreds::V3 {
                user: self.username.clone(),
                auth_proto: self.auth_proto.clone(),
                auth_secret: self.auth_proto.as_ref().and(s.auth_secret),
                priv_proto: self.priv_proto.clone(),
                priv_secret: self.priv_proto.as_ref().and(s.priv_secret),
                context: self.context.clone(),
            }
        })
    }
}

/// The JSON that is sealed into `net_credentials.secret`.
pub fn secret_json(community: Option<&str>, auth_secret: Option<&str>, priv_secret: Option<&str>) -> Vec<u8> {
    json!({ "community": community.unwrap_or(""), "auth_secret": auth_secret, "priv_secret": priv_secret }).to_string().into_bytes()
}

async fn credential(st: &AppState, id: Uuid) -> sqlx::Result<Option<CredRow>> {
    sqlx::query_as(sqlx::AssertSqlSafe(format!("SELECT {CRED_COLUMNS} FROM net_credentials WHERE id = $1"))).bind(id).fetch_optional(&st.db).await
}

// ---------------------------------------------------------------------------
// Addresses
// ---------------------------------------------------------------------------

/// A block of addresses, for validation: `a.b.c.d/p`, private space only.
pub fn valid_subnet(s: &str) -> Result<String, String> {
    let (ip, p) = s.trim().split_once('/').unwrap_or((s.trim(), "32"));
    let ip: std::net::Ipv4Addr = ip.parse().map_err(|_| format!("{s:?} isn't an IPv4 block like 192.168.1.0/24"))?;
    let p: u32 = p.parse().ok().filter(|p| *p <= 32).ok_or_else(|| format!("{s:?} has a bad prefix length"))?;
    if !private_v4(ip) {
        return Err(format!("{s:?} isn't private address space (10/8, 172.16/12, 192.168/16, 100.64/10, 169.254/16): agents don't scan the internet"));
    }
    if p < 20 {
        return Err(format!("{s:?} is too large: at most 4096 addresses (a /20)"));
    }
    Ok(format!("{ip}/{p}"))
}

pub fn private_v4(ip: std::net::Ipv4Addr) -> bool {
    ip.is_private() || ip.is_link_local() || (ip.octets()[0] == 100 && (ip.octets()[1] & 0xc0) == 64)
}

/// Where a device may be read: private space, this machine, unique-local IPv6.
pub fn valid_device_host(s: &str) -> Result<String, String> {
    let ip: std::net::IpAddr = s.trim().trim_matches(['[', ']']).parse().map_err(|_| format!("{s:?} isn't an IP address"))?;
    let ok = match ip {
        std::net::IpAddr::V4(v4) => private_v4(v4) || v4.is_loopback(),
        std::net::IpAddr::V6(v6) => v6.is_loopback() || (v6.segments()[0] & 0xfe00) == 0xfc00 || (v6.segments()[0] & 0xffc0) == 0xfe80,
    };
    if !ok {
        return Err(format!("{ip} isn't private address space: devices are only read on the local network"));
    }
    Ok(ip.to_string())
}

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

// ---------------------------------------------------------------------------
// What is it
// ---------------------------------------------------------------------------

pub struct Facts<'a> {
    pub object_id: &'a str,
    pub descr: &'a str,
    pub ports: &'a [i32],
    pub vendor: Option<&'a str>,
}

/// A guess at what a host is, from what it says and what it offers. Good enough to sort a
/// list; people correct it when they add the device.
pub fn guess_kind(f: &Facts) -> &'static str {
    let d = f.descr.to_lowercase();
    let v = f.vendor.unwrap_or("").to_lowercase();
    let has = |words: &[&str]| words.iter().any(|w| d.contains(w) || v.contains(w));
    let port = |p: i32| f.ports.contains(&p);
    if has(&["laserjet", "officejet", "printer", "bizhub", "imagerunner", "workcentre", "ecosys", "mfp", "lexmark", "ricoh", "kyocera"]) || port(9100) || port(631) || port(515) {
        return "printer";
    }
    if has(&["fortigate", "fortinet", "pfsense", "opnsense", "sonicwall", "palo alto", "watchguard", "checkpoint", "check point", "sophos", "firewall", "adaptive security"]) {
        return "firewall";
    }
    if has(&["access point", "wireless", "unifi ap", "u6-", "uap", "aruba ap", "cambium", "ruckus"]) {
        return "ap";
    }
    if has(&["ups", "apc ", "eaton", "powerware", "cyberpower"]) && !has(&["groups"]) {
        return "ups";
    }
    if has(&["switch", "catalyst", "procurve", "aruba", "edgeswitch", "netgear", "dell networking", "powerconnect", "juniper ex", "tp-link", "d-link", "zyxel"]) {
        return "switch";
    }
    if has(&["router", "routeros", "mikrotik", "edgerouter", "vyos", "ubiquiti", "cisco ios"]) {
        return "router";
    }
    if has(&["synology", "qnap", "diskstation", "readynas", "nas"]) {
        return "nas";
    }
    if d.contains("windows") || port(3389) || port(135) || port(445) && !port(22) {
        return "windows";
    }
    if d.contains("linux") || port(22) {
        return "linux";
    }
    if f.object_id.starts_with("1.3.6.1.4.1.9.") {
        return "switch";
    }
    "other"
}

/// What to do about an unmanaged host that might take an agent.
pub fn deploy_hint(kind: &str, ports: &[i32]) -> Value {
    let has = |p: i32| ports.contains(&p);
    let os = match kind {
        "windows" => "windows",
        "linux" | "nas" => "linux",
        _ if has(3389) || has(445) || has(135) => "windows",
        _ if has(22) => "linux",
        _ => "unknown",
    };
    let mut ways = Vec::new();
    if os == "windows" {
        if has(3389) {
            ways.push(json!({ "via": "rdp", "port": 3389, "text": "Remote Desktop in, download the MSI for the site's token and run it." }));
        }
        if has(5985) {
            ways.push(json!({ "via": "winrm", "port": 5985, "text": "Push the MSI over WinRM." }));
        }
        if has(445) {
            ways.push(json!({ "via": "smb", "port": 445, "text": "Copy the MSI to the admin share and run it with a remote tool." }));
        }
    }
    if os == "linux" && has(22) {
        ways.push(json!({ "via": "ssh", "port": 22, "text": "SSH in and install the .deb or .rpm for the site's token." }));
    }
    let manageable = os != "unknown" && !matches!(kind, "printer" | "switch" | "router" | "firewall" | "ap" | "ups");
    json!({ "os": os, "manageable": manageable, "ways": ways })
}

// ---------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------

/// Asks the site's designated agent for a scan. Returns the scan's id, or why not.
pub async fn start_scan(st: &AppState, site_id: Uuid, by: Option<Uuid>) -> Result<Uuid, String> {
    let row: Option<(Option<Uuid>, Vec<String>, Vec<Uuid>)> =
        sqlx::query_as("SELECT agent_id, subnets, credential_ids FROM site_network WHERE site_id = $1")
            .bind(site_id)
            .fetch_optional(&st.db)
            .await
            .map_err(|e| e.to_string())?;
    let Some((Some(agent_id), subnets, cred_ids)) = row else {
        return Err("pick the agent that scans this site first".into());
    };
    let capable: bool = sqlx::query_scalar("SELECT $2 = ANY(capabilities) FROM agents WHERE id = $1 AND site_id = $3")
        .bind(agent_id)
        .bind(net::CAPABILITY)
        .bind(site_id)
        .fetch_optional(&st.db)
        .await
        .map_err(|e| e.to_string())?
        .unwrap_or(false);
    if !capable {
        return Err("the designated agent is too old for network scans: update it".into());
    }
    if !st.hub.is_online(agent_id) {
        return Err("the designated agent is offline".into());
    }
    let running: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM discovery_scans WHERE site_id = $1 AND status = 'running' AND created_at > now() - make_interval(mins => $2::int))",
    )
    .bind(site_id)
    .bind(SCAN_TIMEOUT_MINUTES as i32)
    .fetch_one(&st.db)
    .await
    .map_err(|e| e.to_string())?;
    if running {
        return Err("a scan is already running".into());
    }
    let mut profiles = Vec::new();
    for id in cred_ids {
        if let Some(c) = credential(st, id).await.map_err(|e| e.to_string())? {
            match c.open(st.cfg.data_key.as_ref()) {
                Some(creds) => profiles.push(SnmpProfile { id: c.id, creds, port: net::default_port() }),
                None => warn!(credential = %c.id, "can't open SNMP credentials for a scan (is RMM_DATA_KEY right?)"),
            }
        }
    }
    let scan_id = Uuid::new_v4();
    sqlx::query("INSERT INTO discovery_scans (id, site_id, agent_id, subnets, requested_by) VALUES ($1, $2, $3, $4, $5)")
        .bind(scan_id)
        .bind(site_id)
        .bind(agent_id)
        .bind(&subnets)
        .bind(by)
        .execute(&st.db)
        .await
        .map_err(|e| e.to_string())?;
    let spec = ScanSpec { subnets, max_hosts: net::MAX_SCAN_HOSTS, profiles, names: true };
    if !st.hub.send(agent_id, ServerMsg::NetScan { scan_id, spec }).await {
        sqlx::query("UPDATE discovery_scans SET status = 'failed', error = 'the agent went offline', finished_at = now() WHERE id = $1")
            .bind(scan_id)
            .execute(&st.db)
            .await
            .ok();
        return Err("the designated agent is offline".into());
    }
    info!(%site_id, %scan_id, %agent_id, "network scan requested");
    Ok(scan_id)
}

#[derive(sqlx::FromRow)]
struct Known {
    id: Uuid,
    ip: String,
    mac: Option<String>,
}

/// The agents of a client, by MAC and by (site, IP), for telling a discovered host from a managed one.
struct AgentIndex {
    by_mac: HashMap<String, Uuid>,
    by_ip: HashMap<(Uuid, String), Uuid>,
}

async fn agent_index(st: &AppState, client_id: Uuid) -> sqlx::Result<AgentIndex> {
    let macs: Vec<(Uuid, Option<String>)> = sqlx::query_as(
        "SELECT a.id, n ->> 'mac'
           FROM agents a JOIN sites s ON s.id = a.site_id,
                jsonb_array_elements(CASE WHEN jsonb_typeof(a.inventory -> 'network') = 'array' THEN a.inventory -> 'network' ELSE '[]'::jsonb END) n
          WHERE s.client_id = $1",
    )
    .bind(client_id)
    .fetch_all(&st.db)
    .await?;
    let ips: Vec<(Uuid, Uuid, String)> = sqlx::query_as(
        "SELECT t.agent_id, a.site_id, t.term FROM agent_search_terms t JOIN agents a ON a.id = t.agent_id JOIN sites s ON s.id = a.site_id
          WHERE s.client_id = $1 AND t.kind = 'ip'",
    )
    .bind(client_id)
    .fetch_all(&st.db)
    .await?;
    Ok(AgentIndex {
        by_mac: macs.into_iter().filter_map(|(id, m)| Some((normalize_mac(&m?)?, id))).collect(),
        // Inventory addresses are `ip/prefix`.
        by_ip: ips.into_iter().map(|(id, site, t)| ((site, t.split('/').next().unwrap_or("").to_string()), id)).collect(),
    })
}

/// A scan finished. Only the agent the scan was given to may answer it, once.
pub async fn ingest_scan(
    st: &Arc<AppState>,
    agent_id: Uuid,
    scan_id: Uuid,
    subnets: Vec<String>,
    scanned: u32,
    hosts: Vec<net::Host>,
    error: Option<String>,
) -> anyhow::Result<()> {
    let row: Option<(Uuid, Uuid)> = sqlx::query_as(
        "SELECT sc.site_id, s.client_id FROM discovery_scans sc JOIN sites s ON s.id = sc.site_id
          WHERE sc.id = $1 AND sc.agent_id = $2 AND sc.status = 'running'",
    )
    .bind(scan_id)
    .bind(agent_id)
    .fetch_optional(&st.db)
    .await?;
    let Some((site_id, client_id)) = row else {
        warn!(%agent_id, %scan_id, "a scan result nobody asked this agent for");
        return Ok(());
    };
    // A scan that found nothing and says why: failed. One that says why but found hosts: partial, kept.
    let failed = error.is_some() && hosts.is_empty();
    let index = agent_index(st, client_id).await?;
    let known: Vec<Known> = sqlx::query_as("SELECT id, ip, mac FROM discovered_devices WHERE site_id = $1").bind(site_id).fetch_all(&st.db).await?;
    let mut by_mac: HashMap<&str, Uuid> = HashMap::new();
    let mut by_ip: HashMap<&str, Uuid> = HashMap::new();
    for k in &known {
        match &k.mac {
            Some(m) => {
                by_mac.insert(m, k.id);
            }
            None => {
                by_ip.insert(&k.ip, k.id);
            }
        }
    }
    let creds: HashSet<Uuid> = sqlx::query_scalar("SELECT id FROM net_credentials WHERE client_id = $1").bind(client_id).fetch_all(&st.db).await?.into_iter().collect();

    let mut new_hosts = 0;
    let mut tx = st.db.begin().await?;
    for h in hosts.iter().take(net::MAX_SCAN_HOSTS as usize) {
        let Ok(ip) = h.ip.parse::<std::net::Ipv4Addr>() else { continue };
        if !private_v4(ip) {
            continue;
        }
        let mac = h.mac.as_deref().and_then(normalize_mac);
        let vendor = mac.as_deref().and_then(crate::oui::vendor);
        let ports: Vec<i32> = h.open_ports.iter().map(|p| i32::from(*p)).collect();
        let sys = h.snmp.as_ref().map(|s| &s.sys);
        let kind = guess_kind(&Facts {
            object_id: sys.map_or("", |s| &s.object_id),
            descr: sys.map_or("", |s| &s.descr),
            ports: &ports,
            vendor,
        });
        let matched = mac
            .as_deref()
            .and_then(|m| index.by_mac.get(m))
            .or_else(|| index.by_ip.get(&(site_id, h.ip.clone())))
            .copied();
        // The same host: by MAC; else (no MAC seen) by IP, or the row that has this IP and no MAC yet.
        let existing = mac.as_deref().and_then(|m| by_mac.get(m).copied()).or_else(|| by_ip.get(h.ip.as_str()).copied());
        let cred = h.snmp.as_ref().map(|s| s.profile_id).filter(|c| creds.contains(c));
        let name = |v: &Option<String>| v.as_deref().map(|s| s.chars().take(255).collect::<String>());
        let trim = |s: &str| Some(s.chars().take(512).collect::<String>()).filter(|s| !s.is_empty());
        let methods: Vec<String> = h.methods.iter().take(8).cloned().collect();
        if let Some(id) = existing {
            sqlx::query(
                "UPDATE discovered_devices SET ip = $2, mac = coalesce($3, mac), hostname = coalesce($4, hostname), mdns_name = coalesce($5, mdns_name),
                        vendor = coalesce($6, vendor), sys_name = coalesce($7, sys_name), sys_descr = coalesce($8, sys_descr),
                        sys_object_id = coalesce($9, sys_object_id), sys_location = coalesce($10, sys_location), credential_id = coalesce($11, credential_id),
                        open_ports = $12, methods = $13, kind = CASE WHEN status = 'unmanaged' THEN $14 ELSE kind END, agent_id = $15, online = true,
                        rtt_ms = $16, last_seen_at = now(), last_scan_id = $17
                  WHERE id = $1",
            )
            .bind(id)
            .bind(&h.ip)
            .bind(&mac)
            .bind(name(&h.hostname))
            .bind(name(&h.mdns_name))
            .bind(vendor)
            .bind(sys.and_then(|s| trim(&s.name)))
            .bind(sys.and_then(|s| trim(&s.descr)))
            .bind(sys.and_then(|s| trim(&s.object_id)))
            .bind(sys.and_then(|s| trim(&s.location)))
            .bind(cred)
            .bind(&ports)
            .bind(&methods)
            .bind(kind)
            .bind(matched)
            .bind(h.rtt_ms.map(|r| r as i32))
            .bind(scan_id)
            .execute(&mut *tx)
            .await?;
        } else {
            new_hosts += 1;
            sqlx::query(
                "INSERT INTO discovered_devices (id, site_id, ip, mac, hostname, mdns_name, vendor, sys_name, sys_descr, sys_object_id, sys_location,
                                                 credential_id, open_ports, methods, kind, agent_id, rtt_ms, last_scan_id)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)",
            )
            .bind(Uuid::new_v4())
            .bind(site_id)
            .bind(&h.ip)
            .bind(&mac)
            .bind(name(&h.hostname))
            .bind(name(&h.mdns_name))
            .bind(vendor)
            .bind(sys.and_then(|s| trim(&s.name)))
            .bind(sys.and_then(|s| trim(&s.descr)))
            .bind(sys.and_then(|s| trim(&s.object_id)))
            .bind(sys.and_then(|s| trim(&s.location)))
            .bind(cred)
            .bind(&ports)
            .bind(&methods)
            .bind(kind)
            .bind(matched)
            .bind(h.rtt_ms.map(|r| r as i32))
            .bind(scan_id)
            .execute(&mut *tx)
            .await?;
        }
    }
    // Hosts in the scanned blocks that this scan didn't see are offline now. Hosts elsewhere weren't looked for.
    if !failed && !subnets.is_empty() {
        sqlx::query(
            "UPDATE discovered_devices SET online = false
              WHERE site_id = $1 AND online AND last_scan_id IS DISTINCT FROM $2 AND ip::inet <<= ANY($3::cidr[])",
        )
        .bind(site_id)
        .bind(scan_id)
        .bind(&subnets)
        .execute(&mut *tx)
        .await?;
    }
    sqlx::query(
        "UPDATE discovery_scans SET status = $2, scanned = $3, found = $4, new_hosts = $5, error = $6, subnets = $7, finished_at = now() WHERE id = $1",
    )
    .bind(scan_id)
    .bind(if failed { "failed" } else { "done" })
    .bind(scanned as i32)
    .bind(hosts.len() as i32)
    .bind(new_hosts)
    .bind(error.as_deref().map(|e| e.chars().take(500).collect::<String>()))
    .bind(&subnets)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    info!(%site_id, %scan_id, found = hosts.len(), new_hosts, "network scan stored");
    st.hub.publish(Event::Network { site_id, client_id });
    Ok(())
}

// ---------------------------------------------------------------------------
// Polling
// ---------------------------------------------------------------------------

struct Inflight {
    agent_id: Uuid,
    site_id: Uuid,
    devices: Vec<Uuid>,
    at: Instant,
}

fn inflight() -> &'static Mutex<HashMap<Uuid, Inflight>> {
    static M: OnceLock<Mutex<HashMap<Uuid, Inflight>>> = OnceLock::new();
    M.get_or_init(Default::default)
}

pub async fn run(st: Arc<AppState>) {
    let mut tick = tokio::time::interval(TICK);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        if let Err(e) = dispatch(&st).await {
            warn!("network monitoring: {e:#}");
        }
        if let Err(e) = scan_schedule(&st).await {
            warn!("network discovery schedule: {e:#}");
        }
    }
}

#[derive(sqlx::FromRow)]
struct Due {
    id: Uuid,
    site_id: Uuid,
    agent_id: Uuid,
    host: String,
    port: i32,
    kind: String,
    credential_id: Uuid,
}

async fn dispatch(st: &Arc<AppState>) -> anyhow::Result<()> {
    // Polls the agent never answered: its devices stay as they were, with a note.
    let expired: Vec<Inflight> = {
        let mut m = inflight().lock().unwrap();
        let ids: Vec<Uuid> = m.iter().filter(|(_, f)| f.at.elapsed() > POLL_TIMEOUT).map(|(k, _)| *k).collect();
        ids.into_iter().filter_map(|k| m.remove(&k)).collect()
    };
    for f in expired {
        warn!(agent = %f.agent_id, devices = f.devices.len(), "an SNMP poll went unanswered");
        sqlx::query("UPDATE net_devices SET last_error = 'the agent didn''t answer' WHERE id = ANY($1)").bind(&f.devices).execute(&st.db).await?;
    }
    let busy: HashSet<Uuid> = inflight().lock().unwrap().values().map(|f| f.site_id).collect();
    let due: Vec<Due> = sqlx::query_as(
        "SELECT d.id, d.site_id, sn.agent_id, d.host, d.port, d.kind, d.credential_id
           FROM net_devices d JOIN site_network sn ON sn.site_id = d.site_id
          WHERE d.enabled AND sn.agent_id IS NOT NULL
            AND (d.last_poll_at IS NULL OR d.last_poll_at + make_interval(secs => coalesce(d.poll_secs, sn.poll_secs)) <= now())
          ORDER BY d.last_poll_at NULLS FIRST
          LIMIT 1000",
    )
    .fetch_all(&st.db)
    .await?;
    let mut by_site: HashMap<Uuid, Vec<Due>> = HashMap::new();
    for d in due {
        by_site.entry(d.site_id).or_default().push(d);
    }
    for (site_id, mut devices) in by_site {
        if busy.contains(&site_id) {
            continue;
        }
        let agent_id = devices[0].agent_id;
        if !st.hub.is_online(agent_id) {
            continue;
        }
        let capable: bool =
            sqlx::query_scalar("SELECT $2 = ANY(capabilities) FROM agents WHERE id = $1").bind(agent_id).bind(net::CAPABILITY).fetch_one(&st.db).await?;
        if !capable {
            continue;
        }
        devices.truncate(net::MAX_POLL_TARGETS);
        let mut targets = Vec::new();
        let mut sent_ids = Vec::new();
        let mut creds: HashMap<Uuid, Option<SnmpCreds>> = HashMap::new();
        for d in &devices {
            if let std::collections::hash_map::Entry::Vacant(slot) = creds.entry(d.credential_id) {
                slot.insert(credential(st, d.credential_id).await?.and_then(|c| c.open(st.cfg.data_key.as_ref())));
            }
            let Some(Some(c)) = creds.get(&d.credential_id) else {
                sqlx::query("UPDATE net_devices SET last_error = 'the SNMP credentials can''t be opened (wrong RMM_DATA_KEY?)', last_poll_at = now() WHERE id = $1")
                    .bind(d.id)
                    .execute(&st.db)
                    .await?;
                continue;
            };
            targets.push(PollTarget {
                device_id: d.id,
                host: d.host.clone(),
                port: d.port as u16,
                creds: c.clone(),
                supplies: matches!(d.kind.as_str(), "printer" | "other" | "mfp"),
            });
            sent_ids.push(d.id);
        }
        if targets.is_empty() {
            continue;
        }
        let poll_id = Uuid::new_v4();
        sqlx::query("UPDATE net_devices SET last_poll_at = now() WHERE id = ANY($1)").bind(&sent_ids).execute(&st.db).await?;
        inflight().lock().unwrap().insert(poll_id, Inflight { agent_id, site_id, devices: sent_ids, at: Instant::now() });
        if !st.hub.send(agent_id, ServerMsg::SnmpPoll { poll_id, targets }).await {
            inflight().lock().unwrap().remove(&poll_id);
        }
    }
    Ok(())
}

/// Starts the scans that sites asked to have on a schedule, and gives up on ones that never finished.
async fn scan_schedule(st: &Arc<AppState>) -> anyhow::Result<()> {
    sqlx::query(
        "UPDATE discovery_scans SET status = 'failed', error = 'the agent never answered', finished_at = now()
          WHERE status = 'running' AND created_at < now() - make_interval(mins => $1::int)",
    )
    .bind(SCAN_TIMEOUT_MINUTES as i32)
    .execute(&st.db)
    .await?;
    let due: Vec<Uuid> = sqlx::query_scalar(
        "SELECT sn.site_id FROM site_network sn
          WHERE sn.agent_id IS NOT NULL AND sn.discovery_hours > 0
            AND NOT EXISTS (SELECT 1 FROM discovery_scans sc WHERE sc.site_id = sn.site_id AND sc.created_at > now() - make_interval(hours => sn.discovery_hours))",
    )
    .fetch_all(&st.db)
    .await?;
    for site_id in due {
        if let Err(e) = start_scan(st, site_id, None).await {
            // The agent being offline is the usual reason, and the next tick tries again.
            tracing::debug!(%site_id, "scheduled scan not started: {e}");
        }
    }
    Ok(())
}

/// Polls one monitored device's site now, ahead of schedule.
pub async fn poll_now(st: &AppState, device_id: Uuid) -> sqlx::Result<()> {
    sqlx::query("UPDATE net_devices SET last_poll_at = NULL WHERE id = $1").bind(device_id).execute(&st.db).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Poll results
// ---------------------------------------------------------------------------

#[derive(sqlx::FromRow)]
struct IfRow {
    if_index: i32,
    oper_status: i16,
    monitored: bool,
    monitored_manual: bool,
    last_in_octets: Option<i64>,
    last_out_octets: Option<i64>,
    last_hc: bool,
    last_at: Option<DateTime<Utc>>,
}

/// bits per second from two counter readings. `None` when there's nothing to say: no earlier
/// reading, too little time, or the counter was reset (the device restarted).
pub fn rate_bps(prev: i64, cur: i64, hc: bool, secs: f64, rebooted: bool) -> Option<i64> {
    if secs < MIN_RATE_SECS || rebooted {
        return None;
    }
    let delta = if cur >= prev {
        cur - prev
    } else if !hc && prev > (u32::MAX as i64) / 2 && prev <= u32::MAX as i64 {
        // A 32-bit counter wrapped once.
        cur + (u32::MAX as i64 + 1) - prev
    } else {
        return None;
    };
    Some(((delta as f64) * 8.0 / secs) as i64)
}

/// Whether an interface should be watched without being asked: real ports, not loopbacks and tunnels.
pub fn worth_monitoring(if_type: i32, name: &str) -> bool {
    // 24 softwareLoopback, 131 tunnel, 53 propVirtual, 135/136 vlan sub-interfaces, 1 other.
    !matches!(if_type, 24 | 131 | 1 | 135 | 136) && !name.to_lowercase().starts_with("lo")
}

/// The agent answered a poll.
pub async fn ingest_poll(st: &Arc<AppState>, agent_id: Uuid, poll_id: Uuid, results: Vec<PollResult>) {
    let Some(f) = inflight().lock().unwrap().remove(&poll_id) else {
        warn!(%agent_id, %poll_id, "an SNMP poll result nobody asked for (or that came too late)");
        return;
    };
    if f.agent_id != agent_id {
        warn!(%agent_id, %poll_id, "an SNMP poll result from another agent");
        return;
    }
    let asked: HashSet<Uuid> = f.devices.iter().copied().collect();
    for r in results {
        // Only devices that were in the request, so an agent can't write another site's data.
        if !asked.contains(&r.device_id) {
            continue;
        }
        let id = r.device_id;
        if let Err(e) = ingest_one(st, agent_id, f.site_id, r).await {
            warn!(device = %id, "storing an SNMP reading: {e:#}");
        }
    }
}

async fn ingest_one(st: &Arc<AppState>, agent_id: Uuid, site_id: Uuid, r: PollResult) -> anyhow::Result<()> {
    if r.error.as_deref() == Some(net::AGENT_BUSY) {
        // Not read at all this time; try again soon.
        sqlx::query("UPDATE net_devices SET last_poll_at = NULL WHERE id = $1").bind(r.device_id).execute(&st.db).await?;
        return Ok(());
    }
    let mut tx = st.db.begin().await?;
    let prev: Option<(String, bool, Option<i64>)> =
        sqlx::query_as("SELECT state, enabled, uptime_secs FROM net_devices WHERE id = $1 AND site_id = $2 FOR UPDATE")
            .bind(r.device_id)
            .bind(site_id)
            .fetch_optional(&mut *tx)
            .await?;
    let Some((prev_state, enabled, prev_uptime)) = prev else { return Ok(()) };
    if !enabled {
        return Ok(());
    }
    let now = Utc::now();
    if r.ok {
        let sys = r.sys.clone().unwrap_or_default();
        let nz = |s: &str| Some(s.to_string()).filter(|s| !s.is_empty());
        sqlx::query(
            "UPDATE net_devices SET state = 'up', state_since = CASE WHEN state = 'up' THEN state_since ELSE now() END, last_ok_at = now(),
                    last_error = $2, rtt_ms = $3, uptime_secs = $4, cpu_percent = $5, mem_used = $6, mem_total = $7,
                    storage = $8, supplies = $9, sys_descr = coalesce($10, sys_descr), sys_name = coalesce($11, sys_name),
                    sys_object_id = coalesce($12, sys_object_id), sys_location = coalesce($13, sys_location)
              WHERE id = $1",
        )
        .bind(r.device_id)
        .bind(r.error.as_deref().map(|e| e.chars().take(500).collect::<String>()))
        .bind(r.rtt_ms.map(|v| v as i32))
        .bind(r.uptime_secs.map(|v| v as i64))
        .bind(r.cpu_percent)
        .bind(r.mem_used.map(|v| v as i64))
        .bind(r.mem_total.map(|v| v as i64))
        .bind(serde_json::to_value(&r.storage)?)
        .bind(serde_json::to_value(&r.supplies)?)
        .bind(nz(&sys.descr))
        .bind(nz(&sys.name))
        .bind(nz(&sys.object_id))
        .bind(nz(&sys.location))
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "INSERT INTO net_device_metrics (device_id, ts, reachable, rtt_ms, uptime_secs, cpu_percent, mem_used, mem_total)
             VALUES ($1, $2, true, $3, $4, $5, $6, $7) ON CONFLICT DO NOTHING",
        )
        .bind(r.device_id)
        .bind(now)
        .bind(r.rtt_ms.map(|v| v as i32))
        .bind(r.uptime_secs.map(|v| v as i64))
        .bind(r.cpu_percent)
        .bind(r.mem_used.map(|v| v as i64))
        .bind(r.mem_total.map(|v| v as i64))
        .execute(&mut *tx)
        .await?;
        let rebooted = matches!((prev_uptime, r.uptime_secs), (Some(p), Some(c)) if (c as i64) + 5 < p);
        store_interfaces(&mut tx, &r, now, rebooted).await?;
    } else {
        sqlx::query(
            "UPDATE net_devices SET state = 'down', state_since = CASE WHEN state = 'down' THEN state_since ELSE now() END, last_error = $2 WHERE id = $1",
        )
        .bind(r.device_id)
        .bind(r.error.as_deref().unwrap_or("no answer").chars().take(500).collect::<String>())
        .execute(&mut *tx)
        .await?;
        sqlx::query("INSERT INTO net_device_metrics (device_id, ts, reachable) VALUES ($1, $2, false) ON CONFLICT DO NOTHING")
            .bind(r.device_id)
            .bind(now)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    let client_id: Uuid = sqlx::query_scalar("SELECT client_id FROM sites WHERE id = $1").bind(site_id).fetch_one(&st.db).await?;
    st.hub.publish(Event::Network { site_id, client_id });
    if prev_state != (if r.ok { "up" } else { "down" }) {
        info!(device = %r.device_id, from = %prev_state, up = r.ok, "network device state changed");
    }
    crate::netalerts::evaluate(st, agent_id, r.device_id).await;
    Ok(())
}

async fn store_interfaces(tx: &mut sqlx::PgConnection, r: &PollResult, now: DateTime<Utc>, rebooted: bool) -> anyhow::Result<()> {
    if r.interfaces.is_empty() {
        return Ok(());
    }
    let existing: Vec<IfRow> = sqlx::query_as(
        "SELECT if_index, oper_status, monitored, monitored_manual, last_in_octets, last_out_octets, last_hc, last_at
           FROM net_interfaces WHERE device_id = $1",
    )
    .bind(r.device_id)
    .fetch_all(&mut *tx)
    .await?;
    let by_index: HashMap<i32, &IfRow> = existing.iter().map(|e| (e.if_index, e)).collect();
    let mut seen: Vec<i32> = Vec::new();
    for i in r.interfaces.iter().take(net::MAX_INTERFACES) {
        let idx = i.index as i32;
        seen.push(idx);
        let prev = by_index.get(&idx);
        let (in_o, out_o) = (i.in_octets.min(i64::MAX as u64) as i64, i.out_octets.min(i64::MAX as u64) as i64);
        let (mut in_bps, mut out_bps) = (None, None);
        if let Some(p) = prev
            && let (Some(pi), Some(po), Some(at)) = (p.last_in_octets, p.last_out_octets, p.last_at)
            && p.last_hc == i.hc
        {
            let secs = (now - at).num_milliseconds() as f64 / 1000.0;
            in_bps = rate_bps(pi, in_o, i.hc, secs, rebooted);
            out_bps = rate_bps(po, out_o, i.hc, secs, rebooted);
        }
        let util = match (in_bps, out_bps, i.speed_bps) {
            (Some(a), Some(b), s) if s > 0 => Some(((a.max(b) as f64) * 100.0 / s as f64).min(100.0) as f32),
            _ => None,
        };
        let oper = i.oper_status as i16;
        let changed = prev.is_none_or(|p| p.oper_status != oper);
        let monitored_manual = prev.is_some_and(|p| p.monitored_manual);
        let monitored = if monitored_manual {
            prev.is_some_and(|p| p.monitored)
        } else {
            prev.is_some_and(|p| p.monitored) || (oper == 1 && worth_monitoring(i.if_type, &i.name))
        };
        sqlx::query(
            "INSERT INTO net_interfaces (device_id, if_index, name, descr, alias, if_type, speed_bps, admin_status, oper_status, status_since, monitored,
                                         in_bps, out_bps, util_pct, in_errors, out_errors, in_discards, out_discards,
                                         last_in_octets, last_out_octets, last_hc, last_at, last_uptime)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, now(), $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22)
             ON CONFLICT (device_id, if_index) DO UPDATE SET
                 name = EXCLUDED.name, descr = EXCLUDED.descr, alias = EXCLUDED.alias, if_type = EXCLUDED.if_type, speed_bps = EXCLUDED.speed_bps,
                 admin_status = EXCLUDED.admin_status, oper_status = EXCLUDED.oper_status,
                 status_since = CASE WHEN $23 THEN now() ELSE net_interfaces.status_since END, monitored = EXCLUDED.monitored,
                 in_bps = EXCLUDED.in_bps, out_bps = EXCLUDED.out_bps, util_pct = EXCLUDED.util_pct, in_errors = EXCLUDED.in_errors,
                 out_errors = EXCLUDED.out_errors, in_discards = EXCLUDED.in_discards, out_discards = EXCLUDED.out_discards,
                 last_in_octets = EXCLUDED.last_in_octets, last_out_octets = EXCLUDED.last_out_octets, last_hc = EXCLUDED.last_hc,
                 last_at = EXCLUDED.last_at, last_uptime = EXCLUDED.last_uptime",
        )
        .bind(r.device_id)
        .bind(idx)
        .bind(&i.name)
        .bind(&i.descr)
        .bind(&i.alias)
        .bind(i.if_type)
        .bind(i.speed_bps.min(i64::MAX as u64) as i64)
        .bind(i.admin_status as i16)
        .bind(oper)
        .bind(monitored)
        .bind(in_bps)
        .bind(out_bps)
        .bind(util)
        .bind(i.in_errors.min(i64::MAX as u64) as i64)
        .bind(i.out_errors.min(i64::MAX as u64) as i64)
        .bind(i.in_discards.min(i64::MAX as u64) as i64)
        .bind(i.out_discards.min(i64::MAX as u64) as i64)
        .bind(in_o)
        .bind(out_o)
        .bind(i.hc)
        .bind(now)
        .bind(r.uptime_secs.map(|v| v as i64))
        .bind(changed)
        .execute(&mut *tx)
        .await?;
        if monitored {
            sqlx::query(
                "INSERT INTO net_interface_metrics (device_id, if_index, ts, oper_status, in_bps, out_bps, util_pct, in_errors, out_errors)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) ON CONFLICT DO NOTHING",
            )
            .bind(r.device_id)
            .bind(idx)
            .bind(now)
            .bind(oper)
            .bind(in_bps)
            .bind(out_bps)
            .bind(util)
            .bind(i.in_errors.min(i64::MAX as u64) as i64)
            .bind(i.out_errors.min(i64::MAX as u64) as i64)
            .execute(&mut *tx)
            .await?;
        }
    }
    // Interfaces the device no longer has (renumbered after a restart, removed modules).
    sqlx::query("DELETE FROM net_interfaces WHERE device_id = $1 AND NOT (if_index = ANY($2))").bind(r.device_id).bind(&seen).execute(&mut *tx).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Rollups and retention
// ---------------------------------------------------------------------------

/// Rolls the last few complete hours of samples up (idempotent; late samples are folded in).
pub async fn rollup(db: &sqlx::PgPool) -> sqlx::Result<()> {
    sqlx::query(
        "INSERT INTO net_device_metrics_hourly (device_id, hour, samples, reachable, rtt_avg, rtt_max, cpu_avg, cpu_max, mem_used_avg, mem_total)
         SELECT device_id, date_trunc('hour', ts), count(*), count(*) FILTER (WHERE reachable), avg(rtt_ms), max(rtt_ms), avg(cpu_percent), max(cpu_percent),
                avg(mem_used)::bigint, max(mem_total)
           FROM net_device_metrics
          WHERE ts >= date_trunc('hour', now()) - interval '3 hours' AND ts < date_trunc('hour', now())
          GROUP BY 1, 2
         ON CONFLICT (device_id, hour) DO UPDATE SET samples = EXCLUDED.samples, reachable = EXCLUDED.reachable, rtt_avg = EXCLUDED.rtt_avg,
                rtt_max = EXCLUDED.rtt_max, cpu_avg = EXCLUDED.cpu_avg, cpu_max = EXCLUDED.cpu_max, mem_used_avg = EXCLUDED.mem_used_avg,
                mem_total = EXCLUDED.mem_total",
    )
    .execute(db)
    .await?;
    sqlx::query(
        "INSERT INTO net_interface_metrics_hourly (device_id, if_index, hour, samples, up_samples, in_bps_avg, in_bps_max, out_bps_avg, out_bps_max, util_max, errors)
         SELECT device_id, if_index, date_trunc('hour', ts), count(*), count(*) FILTER (WHERE oper_status = 1), avg(in_bps)::bigint, max(in_bps),
                avg(out_bps)::bigint, max(out_bps), max(util_pct), coalesce(max(in_errors + out_errors) - min(in_errors + out_errors), 0)
           FROM net_interface_metrics
          WHERE ts >= date_trunc('hour', now()) - interval '3 hours' AND ts < date_trunc('hour', now())
          GROUP BY 1, 2, 3
         ON CONFLICT (device_id, if_index, hour) DO UPDATE SET samples = EXCLUDED.samples, up_samples = EXCLUDED.up_samples,
                in_bps_avg = EXCLUDED.in_bps_avg, in_bps_max = EXCLUDED.in_bps_max, out_bps_avg = EXCLUDED.out_bps_avg,
                out_bps_max = EXCLUDED.out_bps_max, util_max = EXCLUDED.util_max, errors = EXCLUDED.errors",
    )
    .execute(db)
    .await?;
    Ok(())
}

/// Raw samples for `raw_days`, rollups for `retention_days`; old scans and hosts that haven't been seen for a year.
pub async fn prune(db: &sqlx::PgPool, raw_days: i32, retention_days: i32) -> sqlx::Result<()> {
    for sql in [
        "DELETE FROM net_device_metrics WHERE ts < now() - make_interval(days => $1)",
        "DELETE FROM net_interface_metrics WHERE ts < now() - make_interval(days => $1)",
    ] {
        sqlx::query(sql).bind(raw_days).execute(db).await?;
    }
    for sql in [
        "DELETE FROM net_device_metrics_hourly WHERE hour < now() - make_interval(days => $1)",
        "DELETE FROM net_interface_metrics_hourly WHERE hour < now() - make_interval(days => $1)",
    ] {
        sqlx::query(sql).bind(retention_days).execute(db).await?;
    }
    sqlx::query("DELETE FROM discovery_scans WHERE created_at < now() - interval '90 days'").execute(db).await?;
    sqlx::query("DELETE FROM discovered_devices WHERE last_seen_at < now() - interval '365 days' AND status <> 'known' AND net_device_id IS NULL").execute(db).await?;
    Ok(())
}

/// What the `/network/summary` and dashboards count.
pub async fn counts(db: &sqlx::PgPool, scope: Option<&[Uuid]>) -> sqlx::Result<Value> {
    let r = sqlx::query(
        "SELECT (SELECT count(*) FROM discovered_devices d JOIN sites s ON s.id = d.site_id
                  WHERE ($1::uuid[] IS NULL OR s.client_id = ANY($1)) AND d.status = 'unmanaged' AND d.agent_id IS NULL AND d.net_device_id IS NULL AND d.online) AS unmanaged,
                (SELECT count(*) FROM net_devices d JOIN sites s ON s.id = d.site_id WHERE ($1::uuid[] IS NULL OR s.client_id = ANY($1))) AS devices,
                (SELECT count(*) FROM net_devices d JOIN sites s ON s.id = d.site_id WHERE ($1::uuid[] IS NULL OR s.client_id = ANY($1)) AND d.enabled AND d.state = 'down') AS down",
    )
    .bind(scope)
    .fetch_one(db)
    .await?;
    Ok(json!({ "unmanaged": r.get::<i64, _>("unmanaged"), "devices": r.get::<i64, _>("devices"), "down": r.get::<i64, _>("down") }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counter_rates_handle_wraps_and_resets() {
        // 1 MB in 10 seconds is 800 kbit/s.
        assert_eq!(rate_bps(0, 1_000_000, true, 10.0, false), Some(800_000));
        // A 32-bit counter that wrapped once.
        assert_eq!(rate_bps(u32::MAX as i64 - 99, 100, false, 10.0, false), Some(160));
        // A 64-bit counter going backwards is a reset, not a wrap.
        assert_eq!(rate_bps(5_000_000_000, 100, true, 10.0, false), None);
        // A small 32-bit counter going backwards is a reset too.
        assert_eq!(rate_bps(1000, 10, false, 10.0, false), None);
        assert_eq!(rate_bps(0, 100, true, 1.0, false), None, "too little time between readings");
        assert_eq!(rate_bps(0, 100, true, 10.0, true), None, "the device restarted");
    }

    #[test]
    fn blocks_and_hosts_are_private_only() {
        assert_eq!(valid_subnet("192.168.1.77/24").unwrap(), "192.168.1.77/24");
        assert_eq!(valid_subnet("10.1.0.0/20").unwrap(), "10.1.0.0/20");
        for bad in ["8.8.8.0/24", "10.0.0.0/8", "10.0.0.0/19", "192.168.1.0/33", "nope", "172.32.0.0/24"] {
            assert!(valid_subnet(bad).is_err(), "{bad}");
        }
        assert_eq!(valid_device_host("10.0.0.2").unwrap(), "10.0.0.2");
        assert!(valid_device_host("127.0.0.1").is_ok() && valid_device_host("fd00::1").is_ok() && valid_device_host("[fd00::1]").is_ok());
        assert!(valid_device_host("8.8.8.8").is_err() && valid_device_host("switch.example.com").is_err());
    }

    #[test]
    fn hosts_are_sorted_into_kinds() {
        let k = |descr: &str, ports: &[i32], vendor: Option<&str>| guess_kind(&Facts { object_id: "", descr, ports, vendor });
        assert_eq!(k("HP ETHERNET MULTI-ENVIRONMENT,ROM none,JETDIRECT", &[9100], None), "printer");
        assert_eq!(k("Cisco IOS Software, Catalyst L3 Switch", &[22], None), "switch");
        assert_eq!(k("FortiGate-60F v7.2", &[443], None), "firewall");
        assert_eq!(k("Linux fileserver 6.1 x86_64", &[22, 445], None), "linux");
        assert_eq!(k("", &[135, 445, 3389], None), "windows");
        assert_eq!(k("", &[22], None), "linux");
        assert_eq!(k("", &[80], None), "other");
        assert_eq!(k("Synology DiskStation", &[5000], None), "nas");
        assert_eq!(k("", &[], Some("Hewlett Packard printer division")), "printer");
        assert_eq!(k("UniFi AP-AC-Pro", &[], None), "ap");
    }

    #[test]
    fn deploy_hints_follow_the_open_ports() {
        let h = deploy_hint("windows", &[135, 445, 3389]);
        assert_eq!((h["os"].as_str(), h["manageable"].as_bool()), (Some("windows"), Some(true)));
        assert!(h["ways"].as_array().unwrap().iter().any(|w| w["via"] == "rdp"));
        let h = deploy_hint("linux", &[22]);
        assert_eq!(h["ways"][0]["via"], "ssh");
        assert_eq!(deploy_hint("printer", &[9100])["manageable"], false);
        assert_eq!(deploy_hint("other", &[])["os"], "unknown");
    }

    #[test]
    fn interfaces_worth_watching() {
        assert!(worth_monitoring(6, "GigabitEthernet0/1") && worth_monitoring(117, "ge-0/0/1"));
        assert!(!worth_monitoring(24, "lo") && !worth_monitoring(6, "Loopback0") && !worth_monitoring(131, "tun0"));
    }

    #[test]
    fn secrets_roundtrip_through_sealing() {
        let key = crate::crypto::DataKey::from_bytes([3u8; 32]);
        let (bytes, sealed) = crate::crypto::store(Some(&key), &secret_json(None, Some("auth-pass-1"), Some("priv-pass-1")));
        assert!(sealed && !bytes.windows(11).any(|w| w == b"auth-pass-1"));
        let row = CredRow {
            id: Uuid::nil(),
            name: "x".into(),
            version: "v3".into(),
            username: "monitor".into(),
            auth_proto: Some("sha1".into()),
            priv_proto: None,
            context: String::new(),
            secret: bytes,
            secret_sealed: sealed,
        };
        match row.open(Some(&key)).unwrap() {
            SnmpCreds::V3 { user, auth_secret, priv_secret, priv_proto, .. } => {
                assert_eq!((user.as_str(), auth_secret.as_deref(), priv_secret, priv_proto), ("monitor", Some("auth-pass-1"), None, None), "no privacy protocol, no privacy secret");
            }
            other => panic!("{other:?}"),
        }
        assert!(row.open(None).is_none(), "sealed without a key can't be opened");
        assert!(row.open(Some(&crate::crypto::DataKey::from_bytes([4u8; 32]))).is_none());
    }
}
