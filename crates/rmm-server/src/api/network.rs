//! Network discovery and SNMP monitoring: a site's network settings (which agent scans and
//! reads), scans, the hosts they found, monitored devices with their interfaces and history,
//! and the SNMP credentials per client. See [`crate::netmon`] and docs/design/network.md.
//!
//! Credentials are write-only: nothing here returns a community string or passphrase.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, Query, State};
use chrono::{DateTime, Duration, Utc};
use rmm_proto::net;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::AssertSqlSafe;
use uuid::Uuid;

use crate::auth::{self, Role, User};
use crate::error::{ApiError, ApiResult};
use crate::netmon;
use crate::state::AppState;

const KINDS: &[&str] = &["switch", "router", "firewall", "ap", "printer", "ups", "nas", "server", "windows", "linux", "other"];

fn clean(s: &str, what: &str, max: usize) -> ApiResult<String> {
    let s = s.trim();
    if s.is_empty() || s.chars().count() > max {
        return Err(ApiError::BadRequest(format!("{what} must be 1-{max} characters")));
    }
    Ok(s.to_string())
}

fn kind(s: Option<&str>) -> ApiResult<String> {
    match s.map(str::trim).filter(|k| !k.is_empty()) {
        None => Ok("other".into()),
        Some(k) if KINDS.contains(&k) => Ok(k.into()),
        Some(k) => Err(ApiError::BadRequest(format!("unknown kind {k:?}: {}", KINDS.join(", ")))),
    }
}

async fn device_client(st: &AppState, u: &User, id: Uuid) -> ApiResult<(Uuid, Uuid)> {
    let row: Option<(Uuid, Uuid)> =
        sqlx::query_as("SELECT d.site_id, s.client_id FROM net_devices d JOIN sites s ON s.id = d.site_id WHERE d.id = $1").bind(id).fetch_optional(&st.db).await?;
    row.filter(|(_, c)| u.can_see_client(*c)).ok_or(ApiError::NotFound("device"))
}

async fn discovered_client(st: &AppState, u: &User, id: Uuid) -> ApiResult<(Uuid, Uuid)> {
    let row: Option<(Uuid, Uuid)> =
        sqlx::query_as("SELECT d.site_id, s.client_id FROM discovered_devices d JOIN sites s ON s.id = d.site_id WHERE d.id = $1").bind(id).fetch_optional(&st.db).await?;
    row.filter(|(_, c)| u.can_see_client(*c)).ok_or(ApiError::NotFound("discovered device"))
}

async fn credential_client(st: &AppState, u: &User, id: Uuid) -> ApiResult<Uuid> {
    let c: Option<Uuid> = sqlx::query_scalar("SELECT client_id FROM net_credentials WHERE id = $1").bind(id).fetch_optional(&st.db).await?;
    c.filter(|c| u.can_see_client(*c)).ok_or(ApiError::NotFound("credentials"))
}

// ---------------------------------------------------------------------------
// Site settings
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct Candidate {
    id: Uuid,
    hostname: String,
    online: bool,
    /// Runs this version of the network features.
    capable: bool,
}

#[derive(Serialize, sqlx::FromRow)]
pub struct ScanRow {
    id: Uuid,
    status: String,
    subnets: Vec<String>,
    scanned: i32,
    found: i32,
    new_hosts: i32,
    error: Option<String>,
    requested_by_name: Option<String>,
    created_at: DateTime<Utc>,
    finished_at: Option<DateTime<Utc>>,
}

const SCAN_SELECT: &str = "SELECT sc.id, sc.status, sc.subnets, sc.scanned, sc.found, sc.new_hosts, sc.error, u.name AS requested_by_name, sc.created_at, sc.finished_at
  FROM discovery_scans sc LEFT JOIN users u ON u.id = sc.requested_by";

#[derive(Serialize)]
pub struct SiteNetwork {
    site_id: Uuid,
    site_name: String,
    client_id: Uuid,
    agent_id: Option<Uuid>,
    agent_hostname: Option<String>,
    agent_online: bool,
    agent_capable: bool,
    subnets: Vec<String>,
    discovery_hours: i32,
    credential_ids: Vec<Uuid>,
    poll_secs: i32,
    candidates: Vec<Candidate>,
    last_scan: Option<ScanRow>,
    devices: i64,
}

pub async fn site_settings(State(st): State<Arc<AppState>>, u: User, Path(site_id): Path<Uuid>) -> ApiResult<Json<SiteNetwork>> {
    let client_id = super::access::site(&st, &u, site_id).await?;
    let site_name: String = sqlx::query_scalar("SELECT name FROM sites WHERE id = $1").bind(site_id).fetch_one(&st.db).await?;
    type Row = (Option<Uuid>, Vec<String>, i32, Vec<Uuid>, i32);
    let row: Option<Row> = sqlx::query_as("SELECT agent_id, subnets, discovery_hours, credential_ids, poll_secs FROM site_network WHERE site_id = $1")
        .bind(site_id)
        .fetch_optional(&st.db)
        .await?;
    let (agent_id, subnets, discovery_hours, credential_ids, poll_secs) = row.unwrap_or((None, vec![], 0, vec![], 300));
    let agents: Vec<(Uuid, String, bool, bool)> = sqlx::query_as(
        "SELECT id, hostname, online, $2 = ANY(capabilities) FROM agents WHERE site_id = $1 ORDER BY lower(hostname)",
    )
    .bind(site_id)
    .bind(net::CAPABILITY)
    .fetch_all(&st.db)
    .await?;
    let chosen = agents.iter().find(|a| Some(a.0) == agent_id);
    let last_scan: Option<ScanRow> = sqlx::query_as(AssertSqlSafe(format!("{SCAN_SELECT} WHERE sc.site_id = $1 ORDER BY sc.created_at DESC LIMIT 1")))
        .bind(site_id)
        .fetch_optional(&st.db)
        .await?;
    let devices: i64 = sqlx::query_scalar("SELECT count(*) FROM net_devices WHERE site_id = $1").bind(site_id).fetch_one(&st.db).await?;
    Ok(Json(SiteNetwork {
        site_id,
        site_name,
        client_id,
        agent_id,
        agent_hostname: chosen.map(|a| a.1.clone()),
        agent_online: chosen.is_some_and(|a| a.2),
        agent_capable: chosen.is_some_and(|a| a.3),
        subnets,
        discovery_hours,
        credential_ids,
        poll_secs,
        candidates: agents.into_iter().map(|(id, hostname, online, capable)| Candidate { id, hostname, online, capable }).collect(),
        last_scan,
        devices,
    }))
}

#[derive(Deserialize)]
pub struct SiteNetworkIn {
    /// The agent that scans and reads. `null` turns the site's network features off.
    agent_id: Option<Uuid>,
    #[serde(default)]
    subnets: Vec<String>,
    #[serde(default)]
    discovery_hours: i32,
    #[serde(default)]
    credential_ids: Vec<Uuid>,
    #[serde(default = "default_poll")]
    poll_secs: i32,
}

fn default_poll() -> i32 {
    300
}

pub async fn update_settings(State(st): State<Arc<AppState>>, u: User, Path(site_id): Path<Uuid>, Json(b): Json<SiteNetworkIn>) -> ApiResult<Json<Value>> {
    u.require(Role::Technician)?;
    let client_id = super::access::site(&st, &u, site_id).await?;
    if !(0..=720).contains(&b.discovery_hours) {
        return Err(ApiError::BadRequest("scan every 0 (only when asked) to 720 hours".into()));
    }
    if !(60..=3600).contains(&b.poll_secs) {
        return Err(ApiError::BadRequest("read devices every 60 to 3600 seconds".into()));
    }
    if b.subnets.len() > 16 {
        return Err(ApiError::BadRequest("at most 16 subnets".into()));
    }
    let subnets: Vec<String> = b.subnets.iter().map(|s| netmon::valid_subnet(s)).collect::<Result<_, _>>().map_err(ApiError::BadRequest)?;
    let total: u64 = subnets.iter().map(|s| 1u64 << (32 - s.rsplit('/').next().and_then(|p| p.parse::<u32>().ok()).unwrap_or(32))).sum();
    if total > u64::from(net::MAX_SCAN_HOSTS) {
        return Err(ApiError::BadRequest(format!("the subnets hold {total} addresses; at most {} are scanned at once", net::MAX_SCAN_HOSTS)));
    }
    if b.credential_ids.len() > 8 {
        return Err(ApiError::BadRequest("at most 8 credential sets are tried on each host".into()));
    }
    let own: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM net_credentials WHERE client_id = $1 AND id = ANY($2)").bind(client_id).bind(&b.credential_ids).fetch_all(&st.db).await?;
    if own.len() != b.credential_ids.iter().collect::<std::collections::HashSet<_>>().len() {
        return Err(ApiError::BadRequest("those credentials belong to another client".into()));
    }
    if let Some(a) = b.agent_id {
        let capable: Option<bool> = sqlx::query_scalar("SELECT $3 = ANY(capabilities) FROM agents WHERE id = $1 AND site_id = $2")
            .bind(a)
            .bind(site_id)
            .bind(net::CAPABILITY)
            .fetch_optional(&st.db)
            .await?;
        match capable {
            None => return Err(ApiError::BadRequest("the agent must belong to this site".into())),
            Some(false) => return Err(ApiError::BadRequest("that agent is too old for network scans (or hasn't connected since it was updated)".into())),
            Some(true) => {}
        }
    }
    let mut tx = st.db.begin().await?;
    let before: Option<Uuid> = sqlx::query_scalar("SELECT agent_id FROM site_network WHERE site_id = $1 FOR UPDATE").bind(site_id).fetch_optional(&mut *tx).await?.flatten();
    sqlx::query(
        "INSERT INTO site_network (site_id, agent_id, subnets, discovery_hours, credential_ids, poll_secs, updated_by, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, now())
         ON CONFLICT (site_id) DO UPDATE SET agent_id = EXCLUDED.agent_id, subnets = EXCLUDED.subnets, discovery_hours = EXCLUDED.discovery_hours,
                credential_ids = EXCLUDED.credential_ids, poll_secs = EXCLUDED.poll_secs, updated_by = EXCLUDED.updated_by, updated_at = now()",
    )
    .bind(site_id)
    .bind(b.agent_id)
    .bind(&subnets)
    .bind(b.discovery_hours)
    .bind(&b.credential_ids)
    .bind(b.poll_secs)
    .bind(u.id)
    .execute(&mut *tx)
    .await?;
    if before != b.agent_id {
        // The devices follow the agent: their open alerts belong to whoever reads them now, and they're read again at once.
        if let Some(a) = b.agent_id {
            sqlx::query("UPDATE alerts SET agent_id = $2 WHERE device_id IN (SELECT id FROM net_devices WHERE site_id = $1)").bind(site_id).bind(a).execute(&mut *tx).await?;
        }
        sqlx::query("UPDATE net_devices SET last_poll_at = NULL, state = CASE WHEN state = 'down' THEN 'unknown' ELSE state END WHERE site_id = $1").bind(site_id).execute(&mut *tx).await?;
    }
    tx.commit().await?;
    if before != b.agent_id {
        // Uptime monitors that use the site's designated agent move with it.
        crate::checks::push_soon(&st, Some(before.into_iter().chain(b.agent_id).collect()));
    }
    auth::audit(&st.db, Some(u.id), "network.settings", Some(("site", site_id)), json!({ "agent_id": b.agent_id, "subnets": subnets, "discovery_hours": b.discovery_hours, "poll_secs": b.poll_secs })).await;
    Ok(Json(json!({ "ok": true })))
}

pub async fn scan(State(st): State<Arc<AppState>>, u: User, Path(site_id): Path<Uuid>) -> ApiResult<Json<Value>> {
    u.require(Role::Technician)?;
    super::access::site(&st, &u, site_id).await?;
    let id = netmon::start_scan(&st, site_id, Some(u.id)).await.map_err(ApiError::Conflict)?;
    auth::audit(&st.db, Some(u.id), "network.scan", Some(("site", site_id)), json!({ "scan_id": id })).await;
    Ok(Json(json!({ "id": id })))
}

pub async fn scans(State(st): State<Arc<AppState>>, u: User, Path(site_id): Path<Uuid>) -> ApiResult<Json<Vec<ScanRow>>> {
    super::access::site(&st, &u, site_id).await?;
    Ok(Json(sqlx::query_as(AssertSqlSafe(format!("{SCAN_SELECT} WHERE sc.site_id = $1 ORDER BY sc.created_at DESC LIMIT 20"))).bind(site_id).fetch_all(&st.db).await?))
}

#[derive(Deserialize)]
pub struct ScopeQuery {
    client_id: Option<Uuid>,
}

pub async fn summary(State(st): State<Arc<AppState>>, u: User, Query(q): Query<ScopeQuery>) -> ApiResult<Json<Value>> {
    let scope: Option<Vec<Uuid>> = match q.client_id {
        Some(c) => {
            super::access::client(&u, c)?;
            Some(vec![c])
        }
        None => u.scope().map(<[Uuid]>::to_vec),
    };
    Ok(Json(netmon::counts(&st.db, scope.as_deref()).await?))
}

// ---------------------------------------------------------------------------
// Discovered devices
// ---------------------------------------------------------------------------

#[derive(Serialize, sqlx::FromRow)]
pub struct Discovered {
    id: Uuid,
    site_id: Uuid,
    site_name: String,
    client_id: Uuid,
    client_name: String,
    ip: String,
    mac: Option<String>,
    hostname: Option<String>,
    mdns_name: Option<String>,
    vendor: Option<String>,
    sys_name: Option<String>,
    sys_descr: Option<String>,
    sys_object_id: Option<String>,
    sys_location: Option<String>,
    credential_id: Option<Uuid>,
    open_ports: Vec<i32>,
    methods: Vec<String>,
    kind: String,
    status: String,
    note: String,
    agent_id: Option<Uuid>,
    agent_hostname: Option<String>,
    net_device_id: Option<Uuid>,
    online: bool,
    rtt_ms: Option<i32>,
    first_seen_at: DateTime<Utc>,
    last_seen_at: DateTime<Utc>,
    /// managed (an agent), monitored (read over SNMP), ignored, known, or unmanaged.
    state: String,
    /// The best name we have for it.
    name: String,
}

const DISCOVERED_SELECT: &str = "SELECT * FROM (
  SELECT d.id, d.site_id, s.name AS site_name, s.client_id, c.name AS client_name, d.ip, d.mac, d.hostname, d.mdns_name, d.vendor, d.sys_name, d.sys_descr,
         d.sys_object_id, d.sys_location, d.credential_id, d.open_ports, d.methods, d.kind, d.status, d.note, d.agent_id, a.hostname AS agent_hostname,
         d.net_device_id, d.online, d.rtt_ms, d.first_seen_at, d.last_seen_at,
         CASE WHEN d.agent_id IS NOT NULL THEN 'managed' WHEN d.net_device_id IS NOT NULL THEN 'monitored' ELSE d.status END AS state,
         coalesce(d.hostname, d.mdns_name, d.sys_name, a.hostname, d.ip) AS name
    FROM discovered_devices d JOIN sites s ON s.id = d.site_id JOIN clients c ON c.id = s.client_id LEFT JOIN agents a ON a.id = d.agent_id
   WHERE ($1::uuid[] IS NULL OR s.client_id = ANY($1)) AND ($2::uuid IS NULL OR s.client_id = $2) AND ($3::uuid IS NULL OR d.site_id = $3)
) x";

#[derive(Deserialize)]
pub struct DiscoveredQuery {
    client_id: Option<Uuid>,
    site_id: Option<Uuid>,
    /// `unmanaged` (default), `managed`, `monitored`, `ignored`, `known` or `all`.
    state: Option<String>,
    q: Option<String>,
    /// Only hosts seen in the latest scan (or only those that weren't).
    online: Option<bool>,
    limit: Option<i64>,
}

pub async fn list_discovered(State(st): State<Arc<AppState>>, u: User, Query(q): Query<DiscoveredQuery>) -> ApiResult<Json<Vec<Discovered>>> {
    if let Some(c) = q.client_id {
        super::access::client(&u, c)?;
    }
    let state = q.state.as_deref().unwrap_or("unmanaged");
    if !matches!(state, "unmanaged" | "managed" | "monitored" | "ignored" | "known" | "all") {
        return Err(ApiError::BadRequest("state: unmanaged, managed, monitored, ignored, known or all".into()));
    }
    let pat = q.q.as_deref().map(str::trim).filter(|s| !s.is_empty()).map(|s| format!("%{}%", s.replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_")));
    let rows: Vec<Discovered> = sqlx::query_as(AssertSqlSafe(format!(
        "{DISCOVERED_SELECT} WHERE ($4 = 'all' OR x.state = $4) AND ($5::boolean IS NULL OR x.online = $5)
            AND ($6::text IS NULL OR x.name ILIKE $6 OR x.ip ILIKE $6 OR x.mac ILIKE $6 OR x.vendor ILIKE $6 OR x.sys_descr ILIKE $6 OR x.note ILIKE $6)
          ORDER BY x.online DESC, x.last_seen_at DESC, x.ip LIMIT $7"
    )))
    .bind(u.scope())
    .bind(q.client_id)
    .bind(q.site_id)
    .bind(state)
    .bind(q.online)
    .bind(pat)
    .bind(q.limit.unwrap_or(500).clamp(1, 2000))
    .fetch_all(&st.db)
    .await?;
    Ok(Json(rows))
}

#[derive(Deserialize)]
pub struct DiscoveredPatch {
    /// `unmanaged`, `ignored` or `known`.
    status: Option<String>,
    note: Option<String>,
    kind: Option<String>,
}

fn status(s: &str) -> ApiResult<&str> {
    match s {
        "unmanaged" | "ignored" | "known" => Ok(s),
        _ => Err(ApiError::BadRequest("status: unmanaged, ignored or known".into())),
    }
}

pub async fn update_discovered(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>, Json(b): Json<DiscoveredPatch>) -> ApiResult<Json<Value>> {
    u.require(Role::Technician)?;
    discovered_client(&st, &u, id).await?;
    let st_new = b.status.as_deref().map(status).transpose()?;
    let note = b.note.as_deref().map(|n| n.trim().chars().take(500).collect::<String>());
    let kind = b.kind.as_deref().map(|k| self::kind(Some(k))).transpose()?;
    sqlx::query("UPDATE discovered_devices SET status = coalesce($2, status), note = coalesce($3, note), kind = coalesce($4, kind) WHERE id = $1")
        .bind(id)
        .bind(st_new)
        .bind(note)
        .bind(kind)
        .execute(&st.db)
        .await?;
    auth::audit(&st.db, Some(u.id), "network.discovered_update", Some(("discovered_device", id)), json!({ "status": b.status })).await;
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
pub struct Bulk {
    ids: Vec<Uuid>,
    status: String,
    note: Option<String>,
}

pub async fn bulk_discovered(State(st): State<Arc<AppState>>, u: User, Json(b): Json<Bulk>) -> ApiResult<Json<Value>> {
    u.require(Role::Technician)?;
    status(&b.status)?;
    if b.ids.is_empty() || b.ids.len() > 1000 {
        return Err(ApiError::BadRequest("pick 1 to 1000 devices".into()));
    }
    let note = b.note.as_deref().map(|n| n.trim().chars().take(500).collect::<String>());
    let n = sqlx::query(
        "UPDATE discovered_devices d SET status = $2, note = coalesce($3, note)
           FROM sites s WHERE s.id = d.site_id AND d.id = ANY($1) AND ($4::uuid[] IS NULL OR s.client_id = ANY($4))",
    )
    .bind(&b.ids)
    .bind(&b.status)
    .bind(note)
    .bind(u.scope())
    .execute(&st.db)
    .await?
    .rows_affected();
    auth::audit(&st.db, Some(u.id), "network.discovered_bulk", None, json!({ "status": b.status, "count": n })).await;
    Ok(Json(json!({ "updated": n })))
}

pub async fn deploy_hint(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    let (site_id, client_id) = discovered_client(&st, &u, id).await?;
    let (kind, ports, ip): (String, Vec<i32>, String) =
        sqlx::query_as("SELECT kind, open_ports, ip FROM discovered_devices WHERE id = $1").bind(id).fetch_one(&st.db).await?;
    let mut hint = netmon::deploy_hint(&kind, &ports);
    hint["ip"] = json!(ip);
    hint["site_id"] = json!(site_id);
    hint["client_id"] = json!(client_id);
    Ok(Json(hint))
}

#[derive(Deserialize, Default)]
pub struct MonitorIn {
    name: Option<String>,
    credential_id: Option<Uuid>,
    kind: Option<String>,
}

/// Starts reading a discovered host over SNMP.
pub async fn monitor_discovered(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>, Json(b): Json<MonitorIn>) -> ApiResult<Json<Value>> {
    u.require(Role::Technician)?;
    let (site_id, client_id) = discovered_client(&st, &u, id).await?;
    /// ip, mac, vendor, sys_name, sys_descr, hostname, credential_id, kind, net_device_id
    type Found = (String, Option<String>, Option<String>, Option<String>, Option<String>, Option<String>, Option<Uuid>, String, Option<Uuid>);
    let d: Found = sqlx::query_as(
        "SELECT ip, mac, vendor, sys_name, sys_descr, hostname, credential_id, kind, net_device_id FROM discovered_devices WHERE id = $1",
    )
    .bind(id)
    .fetch_one(&st.db)
    .await?;
    if d.8.is_some() {
        return Err(ApiError::Conflict("already monitored".into()));
    }
    let cred = b.credential_id.or(d.6).ok_or_else(|| ApiError::BadRequest("pick the SNMP credentials to read it with".into()))?;
    if credential_client(&st, &u, cred).await? != client_id {
        return Err(ApiError::BadRequest("those credentials belong to another client".into()));
    }
    let name = match b.name.as_deref().map(str::trim).filter(|n| !n.is_empty()) {
        Some(n) => clean(n, "name", 100)?,
        None => d.3.clone().or(d.5.clone()).unwrap_or_else(|| d.0.clone()).chars().take(100).collect(),
    };
    let kind = b.kind.as_deref().map(|k| self::kind(Some(k))).transpose()?.unwrap_or(d.7);
    let device_id = Uuid::new_v4();
    let mut tx = st.db.begin().await?;
    sqlx::query(
        "INSERT INTO net_devices (id, site_id, name, host, credential_id, kind, sys_descr, sys_name, vendor, mac, created_by)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
    )
    .bind(device_id)
    .bind(site_id)
    .bind(&name)
    .bind(&d.0)
    .bind(cred)
    .bind(&kind)
    .bind(&d.4)
    .bind(&d.3)
    .bind(&d.2)
    .bind(&d.1)
    .bind(u.id)
    .execute(&mut *tx)
    .await?;
    sqlx::query("UPDATE discovered_devices SET net_device_id = $2, credential_id = $3 WHERE id = $1").bind(id).bind(device_id).bind(cred).execute(&mut *tx).await?;
    tx.commit().await?;
    auth::audit(&st.db, Some(u.id), "network.device_create", Some(("net_device", device_id)), json!({ "name": name, "host": d.0, "from_discovered": id })).await;
    Ok(Json(json!({ "id": device_id })))
}

// ---------------------------------------------------------------------------
// Devices
// ---------------------------------------------------------------------------

#[derive(Serialize, sqlx::FromRow)]
pub struct DeviceRow {
    id: Uuid,
    site_id: Uuid,
    site_name: String,
    client_id: Uuid,
    client_name: String,
    name: String,
    host: String,
    port: i32,
    credential_id: Uuid,
    credential_name: String,
    kind: String,
    enabled: bool,
    poll_secs: Option<i32>,
    sys_descr: Option<String>,
    sys_name: Option<String>,
    sys_object_id: Option<String>,
    sys_location: Option<String>,
    vendor: Option<String>,
    mac: Option<String>,
    state: String,
    state_since: DateTime<Utc>,
    last_poll_at: Option<DateTime<Utc>>,
    last_ok_at: Option<DateTime<Utc>>,
    last_error: Option<String>,
    rtt_ms: Option<i32>,
    uptime_secs: Option<i64>,
    cpu_percent: Option<f32>,
    mem_used: Option<i64>,
    mem_total: Option<i64>,
    storage: Value,
    supplies: Value,
    created_at: DateTime<Utc>,
    /// The agent that reads it, and whether it is connected.
    agent_id: Option<Uuid>,
    agent_hostname: Option<String>,
    agent_online: bool,
    open_alerts: i64,
    interfaces: i64,
    interfaces_up: i64,
}

const DEVICE_SELECT: &str = "SELECT * FROM (
  SELECT d.id, d.site_id, s.name AS site_name, s.client_id, c.name AS client_name, d.name, d.host, d.port, d.credential_id, cr.name AS credential_name,
         d.kind, d.enabled, d.poll_secs, d.sys_descr, d.sys_name, d.sys_object_id, d.sys_location, d.vendor, d.mac, d.state, d.state_since, d.last_poll_at,
         d.last_ok_at, d.last_error, d.rtt_ms, d.uptime_secs, d.cpu_percent, d.mem_used, d.mem_total, d.storage, d.supplies, d.created_at,
         sn.agent_id, a.hostname AS agent_hostname, coalesce(a.online, false) AS agent_online,
         (SELECT count(*) FROM alerts al WHERE al.device_id = d.id AND al.resolved_at IS NULL) AS open_alerts,
         (SELECT count(*) FROM net_interfaces i WHERE i.device_id = d.id) AS interfaces,
         (SELECT count(*) FROM net_interfaces i WHERE i.device_id = d.id AND i.oper_status = 1) AS interfaces_up
    FROM net_devices d JOIN sites s ON s.id = d.site_id JOIN clients c ON c.id = s.client_id JOIN net_credentials cr ON cr.id = d.credential_id
         LEFT JOIN site_network sn ON sn.site_id = d.site_id LEFT JOIN agents a ON a.id = sn.agent_id
   WHERE ($1::uuid[] IS NULL OR s.client_id = ANY($1)) AND ($2::uuid IS NULL OR s.client_id = $2) AND ($3::uuid IS NULL OR d.site_id = $3)
) x";

#[derive(Deserialize)]
pub struct DeviceQuery {
    client_id: Option<Uuid>,
    site_id: Option<Uuid>,
    /// `up`, `down` or `unknown`.
    state: Option<String>,
    kind: Option<String>,
    q: Option<String>,
}

pub async fn list_devices(State(st): State<Arc<AppState>>, u: User, Query(q): Query<DeviceQuery>) -> ApiResult<Json<Vec<DeviceRow>>> {
    if let Some(c) = q.client_id {
        super::access::client(&u, c)?;
    }
    let pat = q.q.as_deref().map(str::trim).filter(|s| !s.is_empty()).map(|s| format!("%{}%", s.replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_")));
    let rows: Vec<DeviceRow> = sqlx::query_as(AssertSqlSafe(format!(
        "{DEVICE_SELECT} WHERE ($4::text IS NULL OR x.state = $4) AND ($5::text IS NULL OR x.kind = $5)
            AND ($6::text IS NULL OR x.name ILIKE $6 OR x.host ILIKE $6 OR x.sys_descr ILIKE $6 OR x.sys_name ILIKE $6 OR x.vendor ILIKE $6)
          ORDER BY CASE x.state WHEN 'down' THEN 0 WHEN 'unknown' THEN 1 ELSE 2 END, lower(x.name) LIMIT 2000"
    )))
    .bind(u.scope())
    .bind(q.client_id)
    .bind(q.site_id)
    .bind(q.state)
    .bind(q.kind)
    .bind(pat)
    .fetch_all(&st.db)
    .await?;
    Ok(Json(rows))
}

#[derive(Serialize, sqlx::FromRow)]
pub struct InterfaceRow {
    if_index: i32,
    name: String,
    descr: String,
    alias: String,
    if_type: i32,
    speed_bps: i64,
    admin_status: i16,
    oper_status: i16,
    status_since: DateTime<Utc>,
    monitored: bool,
    in_bps: Option<i64>,
    out_bps: Option<i64>,
    util_pct: Option<f32>,
    in_errors: i64,
    out_errors: i64,
    in_discards: i64,
    out_discards: i64,
    last_at: Option<DateTime<Utc>>,
}

#[derive(Serialize)]
pub struct DeviceDetail {
    #[serde(flatten)]
    device: DeviceRow,
    interfaces: Vec<InterfaceRow>,
    alerts: Vec<Value>,
}

pub async fn get_device(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    device_client(&st, &u, id).await?;
    let mut rows: Vec<DeviceRow> = sqlx::query_as(AssertSqlSafe(format!("{DEVICE_SELECT} WHERE x.id = $4"))).bind(u.scope()).bind(None::<Uuid>).bind(None::<Uuid>).bind(id).fetch_all(&st.db).await?;
    let device = rows.pop().ok_or(ApiError::NotFound("device"))?;
    let interfaces: Vec<InterfaceRow> = sqlx::query_as(
        "SELECT if_index, name, descr, alias, if_type, speed_bps, admin_status, oper_status, status_since, monitored, in_bps, out_bps, util_pct,
                in_errors, out_errors, in_discards, out_discards, last_at
           FROM net_interfaces WHERE device_id = $1 ORDER BY if_index",
    )
    .bind(id)
    .fetch_all(&st.db)
    .await?;
    /// id, title, severity, kind, opened_at, acknowledged_at
    type OpenAlert = (Uuid, String, String, String, DateTime<Utc>, Option<DateTime<Utc>>);
    let alerts: Vec<OpenAlert> = sqlx::query_as(
        "SELECT id, title, severity, kind, opened_at, acknowledged_at FROM alerts WHERE device_id = $1 AND resolved_at IS NULL ORDER BY opened_at DESC LIMIT 50",
    )
    .bind(id)
    .fetch_all(&st.db)
    .await?;
    let alerts = alerts
        .into_iter()
        .map(|(id, title, severity, kind, opened_at, ack)| json!({ "id": id, "title": title, "severity": severity, "kind": kind, "opened_at": opened_at, "acknowledged_at": ack }))
        .collect();
    Ok(Json(serde_json::to_value(DeviceDetail { device, interfaces, alerts }).map_err(anyhow::Error::from)?))
}

#[derive(Deserialize)]
pub struct DeviceIn {
    site_id: Option<Uuid>,
    name: Option<String>,
    host: Option<String>,
    port: Option<i32>,
    credential_id: Option<Uuid>,
    kind: Option<String>,
    enabled: Option<bool>,
    /// 60-3600; `0` for the site's interval.
    poll_secs: Option<i32>,
}

pub async fn create_device(State(st): State<Arc<AppState>>, u: User, Json(b): Json<DeviceIn>) -> ApiResult<Json<Value>> {
    u.require(Role::Technician)?;
    let site_id = b.site_id.ok_or_else(|| ApiError::BadRequest("pick a site".into()))?;
    let client_id = super::access::site(&st, &u, site_id).await?;
    let name = clean(b.name.as_deref().unwrap_or(""), "name", 100)?;
    let host = netmon::valid_device_host(b.host.as_deref().unwrap_or("")).map_err(ApiError::BadRequest)?;
    let port = b.port.unwrap_or(161);
    if !(1..=65535).contains(&port) {
        return Err(ApiError::BadRequest("port must be 1-65535".into()));
    }
    let cred = b.credential_id.ok_or_else(|| ApiError::BadRequest("pick the SNMP credentials".into()))?;
    if credential_client(&st, &u, cred).await? != client_id {
        return Err(ApiError::BadRequest("those credentials belong to another client".into()));
    }
    let poll = b.poll_secs.filter(|p| *p != 0);
    if poll.is_some_and(|p| !(60..=3600).contains(&p)) {
        return Err(ApiError::BadRequest("read the device every 60 to 3600 seconds".into()));
    }
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO net_devices (id, site_id, name, host, port, credential_id, kind, poll_secs, created_by) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)")
        .bind(id)
        .bind(site_id)
        .bind(&name)
        .bind(&host)
        .bind(port)
        .bind(cred)
        .bind(kind(b.kind.as_deref())?)
        .bind(poll)
        .bind(u.id)
        .execute(&st.db)
        .await?;
    auth::audit(&st.db, Some(u.id), "network.device_create", Some(("net_device", id)), json!({ "name": name, "host": host })).await;
    Ok(Json(json!({ "id": id })))
}

pub async fn update_device(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>, Json(b): Json<DeviceIn>) -> ApiResult<Json<Value>> {
    u.require(Role::Technician)?;
    let (_, client_id) = device_client(&st, &u, id).await?;
    let name = b.name.as_deref().map(|n| clean(n, "name", 100)).transpose()?;
    let host = b.host.as_deref().map(netmon::valid_device_host).transpose().map_err(ApiError::BadRequest)?;
    if b.port.is_some_and(|p| !(1..=65535).contains(&p)) {
        return Err(ApiError::BadRequest("port must be 1-65535".into()));
    }
    if let Some(c) = b.credential_id
        && credential_client(&st, &u, c).await? != client_id
    {
        return Err(ApiError::BadRequest("those credentials belong to another client".into()));
    }
    if b.poll_secs.is_some_and(|p| p != 0 && !(60..=3600).contains(&p)) {
        return Err(ApiError::BadRequest("read the device every 60 to 3600 seconds".into()));
    }
    let kind = b.kind.as_deref().map(|k| self::kind(Some(k))).transpose()?;
    sqlx::query(
        "UPDATE net_devices SET name = coalesce($2, name), host = coalesce($3, host), port = coalesce($4, port), credential_id = coalesce($5, credential_id),
                kind = coalesce($6, kind), enabled = coalesce($7, enabled), poll_secs = CASE WHEN $8::int IS NULL THEN poll_secs WHEN $8 = 0 THEN NULL ELSE $8 END,
                last_poll_at = CASE WHEN $3 IS NOT NULL OR $4 IS NOT NULL OR $5 IS NOT NULL THEN NULL ELSE last_poll_at END
          WHERE id = $1",
    )
    .bind(id)
    .bind(name)
    .bind(host)
    .bind(b.port)
    .bind(b.credential_id)
    .bind(kind)
    .bind(b.enabled)
    .bind(b.poll_secs)
    .execute(&st.db)
    .await?;
    if b.enabled == Some(false) {
        crate::netalerts::close_device(&st, id).await;
    }
    auth::audit(&st.db, Some(u.id), "network.device_update", Some(("net_device", id)), json!({ "enabled": b.enabled })).await;
    Ok(Json(json!({ "ok": true })))
}

pub async fn remove_device(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    u.require(Role::Technician)?;
    device_client(&st, &u, id).await?;
    crate::netalerts::close_device(&st, id).await;
    sqlx::query("DELETE FROM net_devices WHERE id = $1").bind(id).execute(&st.db).await?;
    auth::audit(&st.db, Some(u.id), "network.device_delete", Some(("net_device", id)), json!({})).await;
    Ok(Json(json!({ "ok": true })))
}

pub async fn poll_now(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    u.require(Role::Technician)?;
    device_client(&st, &u, id).await?;
    netmon::poll_now(&st, id).await?;
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
pub struct InterfaceIn {
    monitored: bool,
}

pub async fn set_interface(State(st): State<Arc<AppState>>, u: User, Path((id, idx)): Path<(Uuid, i32)>, Json(b): Json<InterfaceIn>) -> ApiResult<Json<Value>> {
    u.require(Role::Technician)?;
    device_client(&st, &u, id).await?;
    let n = sqlx::query("UPDATE net_interfaces SET monitored = $3, monitored_manual = true WHERE device_id = $1 AND if_index = $2")
        .bind(id)
        .bind(idx)
        .bind(b.monitored)
        .execute(&st.db)
        .await?
        .rows_affected();
    if n == 0 {
        return Err(ApiError::NotFound("interface"));
    }
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
pub struct HoursQuery {
    hours: Option<i64>,
}

#[derive(Serialize, sqlx::FromRow)]
pub struct DevicePoint {
    ts: DateTime<Utc>,
    /// Percent of readings in the bucket that were answered.
    reachable_pct: f64,
    rtt_ms: Option<f64>,
    cpu_percent: Option<f64>,
    mem_used: Option<i64>,
    mem_total: Option<i64>,
}

pub async fn device_metrics(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>, Query(q): Query<HoursQuery>) -> ApiResult<Json<Vec<DevicePoint>>> {
    device_client(&st, &u, id).await?;
    let hours = q.hours.unwrap_or(24).clamp(1, 24 * 366);
    let bucket = ((hours * 3600) / 500).max(60);
    let sql = if hours <= 48 {
        "SELECT to_timestamp(floor(extract(epoch FROM ts) / $3) * $3) AS ts, (100.0 * avg(CASE WHEN reachable THEN 1 ELSE 0 END))::float8 AS reachable_pct,
                avg(rtt_ms)::float8 AS rtt_ms, avg(cpu_percent)::float8 AS cpu_percent, avg(mem_used)::bigint AS mem_used, max(mem_total) AS mem_total
           FROM net_device_metrics WHERE device_id = $1 AND ts > $2 GROUP BY 1 ORDER BY 1"
    } else {
        "SELECT to_timestamp(floor(extract(epoch FROM hour) / $3) * $3) AS ts, (100.0 * sum(reachable) / nullif(sum(samples), 0))::float8 AS reachable_pct,
                avg(rtt_avg)::float8 AS rtt_ms, avg(cpu_avg)::float8 AS cpu_percent, avg(mem_used_avg)::bigint AS mem_used, max(mem_total) AS mem_total
           FROM net_device_metrics_hourly WHERE device_id = $1 AND hour > $2 GROUP BY 1 ORDER BY 1"
    };
    let bucket = if hours <= 48 { bucket } else { bucket.max(3600) / 3600 * 3600 };
    Ok(Json(sqlx::query_as(sql).bind(id).bind(Utc::now() - Duration::hours(hours)).bind(bucket as f64).fetch_all(&st.db).await?))
}

#[derive(Serialize, sqlx::FromRow)]
pub struct InterfacePoint {
    ts: DateTime<Utc>,
    in_bps: Option<i64>,
    out_bps: Option<i64>,
    util_pct: Option<f64>,
    /// Percent of readings in the bucket with the interface up.
    up_pct: f64,
}

pub async fn interface_metrics(
    State(st): State<Arc<AppState>>,
    u: User,
    Path((id, idx)): Path<(Uuid, i32)>,
    Query(q): Query<HoursQuery>,
) -> ApiResult<Json<Vec<InterfacePoint>>> {
    device_client(&st, &u, id).await?;
    let hours = q.hours.unwrap_or(24).clamp(1, 24 * 366);
    let bucket = ((hours * 3600) / 500).max(60);
    let sql = if hours <= 48 {
        "SELECT to_timestamp(floor(extract(epoch FROM ts) / $4) * $4) AS ts, avg(in_bps)::bigint AS in_bps, avg(out_bps)::bigint AS out_bps,
                avg(util_pct)::float8 AS util_pct, (100.0 * avg(CASE WHEN oper_status = 1 THEN 1 ELSE 0 END))::float8 AS up_pct
           FROM net_interface_metrics WHERE device_id = $1 AND if_index = $2 AND ts > $3 GROUP BY 1 ORDER BY 1"
    } else {
        "SELECT to_timestamp(floor(extract(epoch FROM hour) / $4) * $4) AS ts, avg(in_bps_avg)::bigint AS in_bps, avg(out_bps_avg)::bigint AS out_bps,
                avg(util_max)::float8 AS util_pct, (100.0 * sum(up_samples) / nullif(sum(samples), 0))::float8 AS up_pct
           FROM net_interface_metrics_hourly WHERE device_id = $1 AND if_index = $2 AND hour > $3 GROUP BY 1 ORDER BY 1"
    };
    let bucket = if hours <= 48 { bucket } else { bucket.max(3600) / 3600 * 3600 };
    Ok(Json(sqlx::query_as(sql).bind(id).bind(idx).bind(Utc::now() - Duration::hours(hours)).bind(bucket as f64).fetch_all(&st.db).await?))
}

// ---------------------------------------------------------------------------
// Credentials
// ---------------------------------------------------------------------------

#[derive(Serialize, sqlx::FromRow)]
pub struct CredOut {
    id: Uuid,
    client_id: Uuid,
    name: String,
    version: String,
    username: String,
    auth_proto: Option<String>,
    priv_proto: Option<String>,
    context: String,
    /// Sites and devices use it.
    devices: i64,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

const CRED_SELECT: &str = "SELECT c.id, c.client_id, c.name, c.version, c.username, c.auth_proto, c.priv_proto, c.context,
       (SELECT count(*) FROM net_devices d WHERE d.credential_id = c.id) AS devices, c.created_at, c.updated_at FROM net_credentials c";

pub async fn list_credentials(State(st): State<Arc<AppState>>, u: User, Path(client_id): Path<Uuid>) -> ApiResult<Json<Vec<CredOut>>> {
    super::access::client(&u, client_id)?;
    Ok(Json(sqlx::query_as(AssertSqlSafe(format!("{CRED_SELECT} WHERE c.client_id = $1 ORDER BY lower(c.name)"))).bind(client_id).fetch_all(&st.db).await?))
}

#[derive(Deserialize)]
pub struct CredIn {
    name: Option<String>,
    /// `v2c` or `v3`.
    version: Option<String>,
    community: Option<String>,
    username: Option<String>,
    auth_proto: Option<String>,
    auth_secret: Option<String>,
    priv_proto: Option<String>,
    priv_secret: Option<String>,
    context: Option<String>,
}

const AUTH: &[&str] = &["md5", "sha1", "sha224", "sha256", "sha384", "sha512"];
const PRIV: &[&str] = &["des", "aes128"];

/// A full set of credentials, checked the way the agent will.
struct Checked {
    version: String,
    username: String,
    auth_proto: Option<String>,
    priv_proto: Option<String>,
    context: String,
    community: Option<String>,
    auth_secret: Option<String>,
    priv_secret: Option<String>,
}

fn check(c: &Checked) -> ApiResult<()> {
    let bad = |m: &str| Err(ApiError::BadRequest(m.into()));
    if c.version == "v2c" {
        return match c.community.as_deref() {
            Some(s) if !s.is_empty() && s.len() <= 255 => Ok(()),
            _ => bad("the community string must be 1-255 characters"),
        };
    }
    if c.username.is_empty() || c.username.len() > 32 {
        return bad("the SNMPv3 user name must be 1-32 characters");
    }
    for (proto, secret, what) in [(&c.auth_proto, &c.auth_secret, "authentication"), (&c.priv_proto, &c.priv_secret, "privacy")] {
        match (proto, secret) {
            (Some(_), Some(s)) if s.len() < 8 || s.len() > 255 => return bad(&format!("the {what} passphrase must be 8-255 characters")),
            (Some(_), None) | (None, Some(_)) => return bad(&format!("the {what} protocol and passphrase go together")),
            _ => {}
        }
    }
    if c.priv_proto.is_some() && c.auth_proto.is_none() {
        return bad("privacy needs authentication");
    }
    Ok(())
}

pub async fn create_credential(State(st): State<Arc<AppState>>, u: User, Path(client_id): Path<Uuid>, Json(b): Json<CredIn>) -> ApiResult<Json<Value>> {
    u.require(Role::Technician)?;
    super::access::client(&u, client_id)?;
    let name = clean(b.name.as_deref().unwrap_or(""), "name", 100)?;
    let version = b.version.clone().unwrap_or_else(|| "v2c".into());
    if !matches!(version.as_str(), "v2c" | "v3") {
        return Err(ApiError::BadRequest("version: v2c or v3".into()));
    }
    let nonempty = |s: &Option<String>| s.clone().filter(|s| !s.is_empty());
    let c = Checked {
        username: if version == "v3" { b.username.clone().unwrap_or_default().trim().to_string() } else { String::new() },
        auth_proto: if version == "v3" { nonempty(&b.auth_proto) } else { None },
        priv_proto: if version == "v3" { nonempty(&b.priv_proto) } else { None },
        context: if version == "v3" { b.context.clone().unwrap_or_default().chars().take(64).collect() } else { String::new() },
        community: if version == "v2c" { b.community.clone() } else { None },
        auth_secret: if version == "v3" { nonempty(&b.auth_secret) } else { None },
        priv_secret: if version == "v3" { nonempty(&b.priv_secret) } else { None },
        version,
    };
    check(&c)?;
    if c.auth_proto.as_deref().is_some_and(|p| !AUTH.contains(&p)) || c.priv_proto.as_deref().is_some_and(|p| !PRIV.contains(&p)) {
        return Err(ApiError::BadRequest(format!("authentication: {}; privacy: {}", AUTH.join(", "), PRIV.join(", "))));
    }
    let (secret, sealed) = crate::crypto::store(st.cfg.data_key.as_ref(), &netmon::secret_json(c.community.as_deref(), c.auth_secret.as_deref(), c.priv_secret.as_deref()));
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO net_credentials (id, client_id, name, version, username, auth_proto, priv_proto, context, secret, secret_sealed, created_by)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
    )
    .bind(id)
    .bind(client_id)
    .bind(&name)
    .bind(&c.version)
    .bind(&c.username)
    .bind(&c.auth_proto)
    .bind(&c.priv_proto)
    .bind(&c.context)
    .bind(secret)
    .bind(sealed)
    .bind(u.id)
    .execute(&st.db)
    .await?;
    auth::audit(&st.db, Some(u.id), "network.credential_create", Some(("net_credential", id)), json!({ "name": name, "version": c.version })).await;
    Ok(Json(json!({ "id": id })))
}

/// Changes what is sent; a secret left out stays as it is.
pub async fn update_credential(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>, Json(b): Json<CredIn>) -> ApiResult<Json<Value>> {
    u.require(Role::Technician)?;
    credential_client(&st, &u, id).await?;
    let row: netmon::CredRow = sqlx::query_as(AssertSqlSafe(format!("SELECT {} FROM net_credentials WHERE id = $1", netmon::CRED_COLUMNS))).bind(id).fetch_one(&st.db).await?;
    let old = crate::crypto::load(st.cfg.data_key.as_ref(), &row.secret, row.secret_sealed)
        .and_then(|p| serde_json::from_slice::<Value>(&p).ok())
        .ok_or_else(|| ApiError::Conflict("the stored secret can't be opened (wrong RMM_DATA_KEY?); create the credentials again".into()))?;
    let old_s = |k: &str| old[k].as_str().map(str::to_string).filter(|s| !s.is_empty());
    let given = |s: &Option<String>| s.clone().filter(|s| !s.is_empty());
    let v3 = row.version == "v3";
    // A protocol set to "" removes it (and its passphrase); a missing field stays.
    let auth_proto = match &b.auth_proto {
        Some(p) if p.is_empty() => None,
        Some(p) => Some(p.clone()),
        None => row.auth_proto.clone(),
    };
    let priv_proto = match &b.priv_proto {
        Some(p) if p.is_empty() => None,
        Some(p) => Some(p.clone()),
        None => row.priv_proto.clone(),
    };
    let c = Checked {
        version: row.version.clone(),
        username: if v3 { b.username.as_deref().map(|s| s.trim().to_string()).unwrap_or(row.username.clone()) } else { String::new() },
        context: if v3 { b.context.clone().map(|c| c.chars().take(64).collect()).unwrap_or(row.context.clone()) } else { String::new() },
        community: if v3 { None } else { given(&b.community).or(old_s("community")) },
        auth_secret: if v3 && auth_proto.is_some() { given(&b.auth_secret).or(old_s("auth_secret")) } else { None },
        priv_secret: if v3 && priv_proto.is_some() { given(&b.priv_secret).or(old_s("priv_secret")) } else { None },
        auth_proto: if v3 { auth_proto } else { None },
        priv_proto: if v3 { priv_proto } else { None },
    };
    check(&c)?;
    if c.auth_proto.as_deref().is_some_and(|p| !AUTH.contains(&p)) || c.priv_proto.as_deref().is_some_and(|p| !PRIV.contains(&p)) {
        return Err(ApiError::BadRequest(format!("authentication: {}; privacy: {}", AUTH.join(", "), PRIV.join(", "))));
    }
    let name = match &b.name {
        Some(n) => clean(n, "name", 100)?,
        None => row.name.clone(),
    };
    let (secret, sealed) = crate::crypto::store(st.cfg.data_key.as_ref(), &netmon::secret_json(c.community.as_deref(), c.auth_secret.as_deref(), c.priv_secret.as_deref()));
    sqlx::query(
        "UPDATE net_credentials SET name = $2, username = $3, auth_proto = $4, priv_proto = $5, context = $6, secret = $7, secret_sealed = $8, updated_at = now() WHERE id = $1",
    )
    .bind(id)
    .bind(&name)
    .bind(&c.username)
    .bind(&c.auth_proto)
    .bind(&c.priv_proto)
    .bind(&c.context)
    .bind(secret)
    .bind(sealed)
    .execute(&st.db)
    .await?;
    // Devices are read again with the new credentials at once.
    sqlx::query("UPDATE net_devices SET last_poll_at = NULL WHERE credential_id = $1").bind(id).execute(&st.db).await?;
    auth::audit(&st.db, Some(u.id), "network.credential_update", Some(("net_credential", id)), json!({ "name": name })).await;
    Ok(Json(json!({ "ok": true })))
}

pub async fn remove_credential(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    u.require(Role::Technician)?;
    credential_client(&st, &u, id).await?;
    let used: i64 = sqlx::query_scalar("SELECT count(*) FROM net_devices WHERE credential_id = $1").bind(id).fetch_one(&st.db).await?;
    if used > 0 {
        return Err(ApiError::Conflict(format!("{used} monitored device(s) are read with these credentials; change them first")));
    }
    sqlx::query("UPDATE site_network SET credential_ids = array_remove(credential_ids, $1) WHERE $1 = ANY(credential_ids)").bind(id).execute(&st.db).await?;
    sqlx::query("DELETE FROM net_credentials WHERE id = $1").bind(id).execute(&st.db).await?;
    auth::audit(&st.db, Some(u.id), "network.credential_delete", Some(("net_credential", id)), json!({})).await;
    Ok(Json(json!({ "ok": true })))
}
