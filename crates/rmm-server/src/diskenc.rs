//! Disk encryption status and BitLocker recovery-key escrow (docs/design/disk-encryption.md).
//!
//! Agents report their fixed volumes ([`ingest_report`]); the server keeps them in
//! `disk_volumes`, then, where the device's `disk_encryption` policy says to escrow, **pulls**
//! each BitLocker recovery password it doesn't hold yet ([`request_keys`]) and stores it in the
//! client's vault through [`crate::vault::put_managed`] (kind `disk_recovery`, reference
//! `<agent>:<volume>`, the protector id as the username). A key is accepted only from the agent
//! that was asked, for a request still pending ([`ingest_key`]).
//!
//! `disk_encryption` alert items open one alert per volume (key `vol:<id>`) for an unencrypted
//! volume, protection suspended past a grace period, and (BitLocker) a recovery password that
//! isn't escrowed.

use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use rmm_proto::ServerMsg;
use rmm_proto::diskenc::{CAPABILITY, MAX_VOLUMES, ProtectorOp, Report, Status};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::sync::oneshot;
use tracing::{info, warn};
use uuid::Uuid;

use crate::alerts::{Policy, Rule, clear, fire, policies_for};
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;
use crate::vault::{self, Managed, ManagedKind, Source};

/// A key request (or a protector change) not answered within this is forgotten; the next report
/// asks again.
const PENDING_FOR: Duration = Duration::from_secs(120);
/// How long [`rotate`] waits for the agent.
const ROTATE_WAIT: Duration = Duration::from_secs(90);
/// A failed "add a recovery password" isn't retried for this long (Group Policy may forbid it).
const ADD_RETRY: Duration = Duration::from_secs(24 * 3600);

// ---------------------------------------------------------------------------
// The alert rule
// ---------------------------------------------------------------------------

fn os() -> String {
    "os".into()
}

fn yes() -> bool {
    true
}

fn day() -> i32 {
    24
}

/// `disk_encryption` alert params.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DiskEncryptionRule {
    /// `os` (the system volume) or `all_fixed`.
    #[serde(default = "os")]
    pub volumes: String,
    /// BitLocker volumes whose recovery password isn't in the vault.
    #[serde(default = "yes")]
    pub require_escrow: bool,
    /// Protection may be suspended this long (updates suspend it for a restart) before it alerts.
    #[serde(default = "day")]
    pub grace_hours: i32,
}

impl Default for DiskEncryptionRule {
    fn default() -> Self {
        DiskEncryptionRule { volumes: os(), require_escrow: true, grace_hours: 24 }
    }
}

pub fn validate(r: &DiskEncryptionRule) -> Result<(), String> {
    if !["os", "all_fixed"].contains(&r.volumes.as_str()) {
        return Err("volumes is os or all_fixed".into());
    }
    if !(0..=720).contains(&r.grace_hours) {
        return Err("the grace period is 0-720 hours".into());
    }
    Ok(())
}

/// A volume as the alert logic sees it.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Vol {
    pub volume_id: String,
    pub kind: String,
    pub role: String,
    pub status: String,
    pub recovery_protector_id: Option<String>,
    pub escrowed_protector_id: Option<String>,
    pub escrow_error: Option<String>,
    pub suspended_since: Option<DateTime<Utc>>,
}

impl Vol {
    fn escrowed(&self) -> bool {
        self.recovery_protector_id.is_some() && self.recovery_protector_id == self.escrowed_protector_id
    }
}

/// What a rule finds: `(key, title, details)`, one per volume at most. `pending` holds volumes
/// whose key is being fetched right now (not a finding yet).
pub fn findings(r: &DiskEncryptionRule, vols: &[Vol], pending: &[String], now: DateTime<Utc>) -> Vec<(String, String, Value)> {
    let mut out = Vec::new();
    for v in vols.iter().filter(|v| r.volumes == "all_fixed" || v.role == "os") {
        let key = format!("vol:{}", v.volume_id);
        let details = |finding: &str| json!({ "volume": v.volume_id, "finding": finding, "status": v.status, "kind": v.kind, "error": v.escrow_error });
        match v.status.as_str() {
            "unencrypted" => out.push((key, format!("{} isn't encrypted", v.volume_id), details("unencrypted"))),
            "suspended" if v.suspended_since.is_some_and(|t| t <= now - chrono::Duration::hours(i64::from(r.grace_hours))) => {
                out.push((key, format!("Encryption of {} has been suspended for more than {} hours", v.volume_id, r.grace_hours), details("suspended")));
            }
            "encrypted" | "encrypting" | "suspended"
                if r.require_escrow && v.kind == "bitlocker" && !v.escrowed() && !pending.contains(&v.volume_id) =>
            {
                let title = if v.recovery_protector_id.is_none() {
                    format!("{} has no BitLocker recovery password to escrow", v.volume_id)
                } else {
                    format!("The BitLocker recovery password of {} isn't escrowed", v.volume_id)
                };
                out.push((key, title, details("not_escrowed")));
            }
            _ => {}
        }
    }
    out
}

async fn volumes(st: &AppState, agent_id: Uuid) -> sqlx::Result<Vec<Vol>> {
    sqlx::query_as(
        "SELECT volume_id, kind, role, status, recovery_protector_id, escrowed_protector_id, escrow_error, suspended_since
           FROM disk_volumes WHERE agent_id = $1 ORDER BY role <> 'os', volume_id",
    )
    .bind(agent_id)
    .fetch_all(&st.db)
    .await
}

async fn check(st: &AppState, p: &Policy, agent_id: Uuid, vols: &[Vol]) -> sqlx::Result<()> {
    let Some(Rule::DiskEncryption(r)) = p.rule() else { return Ok(()) };
    let found = findings(&r, vols, &pending_volumes(agent_id), Utc::now());
    let keep: Vec<String> = found.iter().map(|f| f.0.clone()).collect();
    for (key, title, details) in found {
        fire(st, p, agent_id, &key, &title, details, 0).await?;
    }
    clear(st, p, agent_id, None, &keep).await
}

/// Re-checks the agent's `disk_encryption` items against its stored volumes.
pub async fn recheck_agent(st: &AppState, agent_id: Uuid) {
    let res: sqlx::Result<()> = async {
        let policies = policies_for(st, agent_id, "disk_encryption").await?;
        if policies.is_empty() {
            return Ok(());
        }
        let reported: bool = sqlx::query_scalar("SELECT diskenc_at IS NOT NULL FROM agents WHERE id = $1").bind(agent_id).fetch_optional(&st.db).await?.unwrap_or(false);
        if !reported {
            return Ok(());
        }
        let vols = volumes(st, agent_id).await?;
        for p in &policies {
            check(st, p, agent_id, &vols).await?;
        }
        Ok(())
    }
    .await;
    if let Err(e) = res {
        warn!(%agent_id, "re-checking disk encryption alerts: {e}");
    }
}

pub async fn recheck_item(st: &AppState, item_id: Uuid) {
    let rows: sqlx::Result<Vec<Uuid>> = sqlx::query_scalar(
        "SELECT ap.agent_id FROM agent_policy ap WHERE ap.item_id = $1 AND ap.module = 'alert' AND ap.enabled AND ap.config ->> 'kind' = 'disk_encryption'",
    )
    .bind(item_id)
    .fetch_all(&st.db)
    .await;
    for agent_id in rows.unwrap_or_default() {
        recheck_agent(st, agent_id).await;
    }
}

// ---------------------------------------------------------------------------
// Requests in flight
// ---------------------------------------------------------------------------

struct PendingKey {
    agent_id: Uuid,
    volume_id: String,
    protector_id: String,
    at: Instant,
}

struct PendingOp {
    agent_id: Uuid,
    volume_id: String,
    op: ProtectorOp,
    at: Instant,
    done: Option<oneshot::Sender<(bool, String)>>,
}

static KEYS: LazyLock<Mutex<HashMap<Uuid, PendingKey>>> = LazyLock::new(Default::default);
static OPS: LazyLock<Mutex<HashMap<Uuid, PendingOp>>> = LazyLock::new(Default::default);
/// When a recovery password was last added to `(agent, volume)` by policy, so a refusal isn't
/// retried on every report.
static ADDED: LazyLock<Mutex<HashMap<(Uuid, String), Instant>>> = LazyLock::new(Default::default);

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn expire() {
    lock(&KEYS).retain(|_, p| p.at.elapsed() < PENDING_FOR);
    lock(&OPS).retain(|_, p| p.at.elapsed() < PENDING_FOR.max(ROTATE_WAIT));
}

fn pending_volumes(agent_id: Uuid) -> Vec<String> {
    expire();
    let mut v: Vec<String> = lock(&KEYS).values().filter(|p| p.agent_id == agent_id).map(|p| p.volume_id.clone()).collect();
    v.extend(lock(&OPS).values().filter(|p| p.agent_id == agent_id).map(|p| p.volume_id.clone()));
    v
}

// ---------------------------------------------------------------------------
// Reports and keys
// ---------------------------------------------------------------------------

fn clip(s: &str, n: usize) -> String {
    s.chars().filter(|c| !c.is_control()).take(n).collect()
}

/// `encrypted` (every volume), `none` (no volume), `partial`; None without volumes.
pub fn summary(statuses: &[Status]) -> Option<&'static str> {
    if statuses.is_empty() {
        return None;
    }
    let enc = statuses.iter().filter(|s| **s == Status::Encrypted).count();
    let plain = statuses.iter().filter(|s| **s == Status::Unencrypted).count();
    Some(if enc == statuses.len() {
        "encrypted"
    } else if plain == statuses.len() {
        "none"
    } else {
        "partial"
    })
}

pub async fn ingest_report(st: &AppState, agent_id: Uuid, client_id: Uuid, mut report: Report) -> anyhow::Result<()> {
    report.volumes.truncate(MAX_VOLUMES);
    let mut seen = std::collections::HashSet::new();
    report.volumes.retain(|v| !v.volume_id.trim().is_empty() && v.volume_id.len() <= 200 && seen.insert(v.volume_id.clone()));
    let mut tx = st.db.begin().await?;
    let ids: Vec<String> = report.volumes.iter().map(|v| v.volume_id.clone()).collect();
    for v in &report.volumes {
        let protectors: Vec<String> = v.protectors.iter().take(20).map(|p| clip(p, 40)).collect();
        sqlx::query(
            "INSERT INTO disk_volumes (agent_id, volume_id, mount, device, kind, role, status, percent, method, protectors, protection_on, locked,
                                       recovery_protector_id, suspended_since, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, CASE WHEN $7 = 'suspended' THEN now() END, now())
             ON CONFLICT (agent_id, volume_id) DO UPDATE SET mount = EXCLUDED.mount, device = EXCLUDED.device, kind = EXCLUDED.kind,
                    role = EXCLUDED.role, status = EXCLUDED.status, percent = EXCLUDED.percent, method = EXCLUDED.method,
                    protectors = EXCLUDED.protectors, protection_on = EXCLUDED.protection_on, locked = EXCLUDED.locked,
                    recovery_protector_id = EXCLUDED.recovery_protector_id,
                    suspended_since = CASE WHEN EXCLUDED.status = 'suspended' THEN coalesce(disk_volumes.suspended_since, now()) END,
                    updated_at = now()",
        )
        .bind(agent_id)
        .bind(&v.volume_id)
        .bind(clip(&v.mount, 500))
        .bind(clip(&v.device, 500))
        .bind(v.kind.as_str())
        .bind(v.role.as_str())
        .bind(v.status.as_str())
        .bind(v.percent.map(|p| p.clamp(0.0, 100.0)))
        .bind(v.method.as_deref().map(|m| clip(m, 60)))
        .bind(&protectors)
        .bind(v.protection_on)
        .bind(v.locked)
        .bind(v.recovery_protector_id.as_deref().map(|p| clip(p, 100)))
        .execute(&mut *tx)
        .await?;
    }
    // Volumes that disappeared (a disk removed, BitLocker turned off and the drive formatted).
    // Their escrowed keys stay in the vault.
    sqlx::query("DELETE FROM disk_volumes WHERE agent_id = $1 AND NOT (volume_id = ANY($2))").bind(agent_id).bind(&ids).execute(&mut *tx).await?;
    let statuses: Vec<Status> = report.volumes.iter().map(|v| v.status).collect();
    sqlx::query("UPDATE agents SET diskenc_at = now(), diskenc_error = $2, tpm = $3, diskenc_status = $4 WHERE id = $1")
        .bind(agent_id)
        .bind(report.error.as_deref().map(|e| clip(e, 1000)))
        .bind(report.tpm.as_ref().map(|t| serde_json::to_value(t).unwrap_or(Value::Null)))
        .bind(summary(&statuses))
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    request_keys(st, agent_id).await?;
    recheck_agent(st, agent_id).await;
    st.hub.publish(crate::hub::Event::Security { agent_id, client_id });
    Ok(())
}

/// Asks the agent for each recovery password the vault doesn't hold yet, and adds a recovery
/// password where the policy says to and a BitLocker volume has none. Nothing without
/// `RMM_DATA_KEY`: a key that can't be stored isn't fetched.
pub async fn request_keys(st: &AppState, agent_id: Uuid) -> sqlx::Result<()> {
    let policy = crate::policy::disk_encryption(st, agent_id).await?;
    if st.cfg.data_key.is_none() || !(policy.escrow_recovery_keys || policy.add_recovery_protector) {
        return Ok(());
    }
    let capable: bool = sqlx::query_scalar("SELECT $2 = ANY(capabilities) FROM agents WHERE id = $1")
        .bind(agent_id)
        .bind(CAPABILITY)
        .fetch_optional(&st.db)
        .await?
        .unwrap_or(false);
    if !capable {
        return Ok(());
    }
    let rows: Vec<(String, String, Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT volume_id, status, recovery_protector_id, escrowed_protector_id FROM disk_volumes
          WHERE agent_id = $1 AND kind = 'bitlocker' AND status IN ('encrypted', 'encrypting', 'suspended')",
    )
    .bind(agent_id)
    .fetch_all(&st.db)
    .await?;
    expire();
    for (volume_id, _status, recovery, escrowed) in rows {
        match recovery {
            Some(pid) if policy.escrow_recovery_keys && Some(&pid) != escrowed.as_ref() => {
                let asked = lock(&KEYS).values().any(|p| p.agent_id == agent_id && p.volume_id == volume_id && p.protector_id == pid);
                if asked {
                    continue;
                }
                let request_id = Uuid::new_v4();
                lock(&KEYS).insert(request_id, PendingKey { agent_id, volume_id: volume_id.clone(), protector_id: pid.clone(), at: Instant::now() });
                if !st.hub.send(agent_id, ServerMsg::DiskRecoveryRequest { request_id, volume_id, protector_id: pid }).await {
                    lock(&KEYS).remove(&request_id);
                }
            }
            None if policy.add_recovery_protector => {
                let key = (agent_id, volume_id.clone());
                let recent = lock(&ADDED).get(&key).is_some_and(|t| t.elapsed() < ADD_RETRY);
                if recent || lock(&OPS).values().any(|p| p.agent_id == agent_id && p.volume_id == volume_id) {
                    continue;
                }
                lock(&ADDED).insert(key, Instant::now());
                let request_id = Uuid::new_v4();
                lock(&OPS).insert(request_id, PendingOp { agent_id, volume_id: volume_id.clone(), op: ProtectorOp::AddRecovery, at: Instant::now(), done: None });
                info!(%agent_id, volume = %volume_id, "adding a BitLocker recovery password (policy)");
                if !st.hub.send(agent_id, ServerMsg::DiskProtector { request_id, volume_id, op: ProtectorOp::AddRecovery }).await {
                    lock(&OPS).remove(&request_id);
                }
            }
            _ => {}
        }
    }
    Ok(())
}

/// The agent's answer to a key request. Anything that doesn't match a pending request of this
/// agent (another agent, a replay, a request that timed out) is dropped.
pub async fn ingest_key(st: &AppState, agent_id: Uuid, request_id: Uuid, volume_id: String, protector_id: String, key: Option<String>, error: Option<String>) -> anyhow::Result<()> {
    let pending = {
        let mut keys = lock(&KEYS);
        match keys.get(&request_id) {
            Some(p) if p.agent_id == agent_id && p.volume_id == volume_id && p.protector_id == protector_id => keys.remove(&request_id),
            _ => None,
        }
    };
    if pending.is_none() {
        warn!(%agent_id, %request_id, volume = %volume_id, "recovery key for no pending request of this agent; ignored");
        return Ok(());
    }
    match key.map(|k| k.trim().to_string()).filter(|k| !k.is_empty() && k.len() <= vault::PASSWORD_MAX) {
        Some(key) => {
            let (client_id, hostname): (Uuid, String) =
                sqlx::query_as("SELECT s.client_id, a.hostname FROM agents a JOIN sites s ON s.id = a.site_id WHERE a.id = $1").bind(agent_id).fetch_one(&st.db).await?;
            let m = Managed {
                kind: ManagedKind::DiskRecovery,
                agent_id: Some(agent_id),
                reference: format!("{agent_id}:{volume_id}"),
                name: clip(&format!("BitLocker recovery: {hostname} {volume_id}"), 200),
                username: clip(&protector_id, 200),
                state: Some("escrowed".into()),
                ..Default::default()
            };
            match vault::put_managed(st, client_id, m, &key, Source::system("diskenc")).await {
                Ok(item) => {
                    sqlx::query(
                        "UPDATE disk_volumes SET escrowed_protector_id = $3, escrowed_at = now(), vault_item_id = $4, escrow_error = NULL
                          WHERE agent_id = $1 AND volume_id = $2",
                    )
                    .bind(agent_id)
                    .bind(&volume_id)
                    .bind(&protector_id)
                    .bind(item)
                    .execute(&st.db)
                    .await?;
                    crate::auth::audit(&st.db, None, "diskenc.escrow", Some(("agent", agent_id)), json!({ "volume": volume_id, "protector_id": protector_id, "vault_item_id": item }))
                        .await;
                    info!(%agent_id, volume = %volume_id, "recovery password escrowed");
                }
                Err(e) => set_escrow_error(st, agent_id, &volume_id, &e.to_string()).await?,
            }
        }
        None => set_escrow_error(st, agent_id, &volume_id, error.as_deref().unwrap_or("the agent sent no key")).await?,
    }
    recheck_agent(st, agent_id).await;
    if let Ok(client_id) = sqlx::query_scalar::<_, Uuid>("SELECT s.client_id FROM agents a JOIN sites s ON s.id = a.site_id WHERE a.id = $1").bind(agent_id).fetch_one(&st.db).await {
        st.hub.publish(crate::hub::Event::Security { agent_id, client_id });
    }
    Ok(())
}

async fn set_escrow_error(st: &AppState, agent_id: Uuid, volume_id: &str, e: &str) -> sqlx::Result<()> {
    warn!(%agent_id, volume = %volume_id, "recovery password not escrowed: {e}");
    sqlx::query("UPDATE disk_volumes SET escrow_error = $3 WHERE agent_id = $1 AND volume_id = $2")
        .bind(agent_id)
        .bind(volume_id)
        .bind(clip(e, 500))
        .execute(&st.db)
        .await?;
    Ok(())
}

/// The agent's answer to a protector change.
pub async fn ingest_protector_result(st: &AppState, agent_id: Uuid, request_id: Uuid, ok: bool, message: String) {
    let op = {
        let mut ops = lock(&OPS);
        match ops.get(&request_id) {
            Some(p) if p.agent_id == agent_id => ops.remove(&request_id),
            _ => None,
        }
    };
    let Some(mut op) = op else {
        warn!(%agent_id, %request_id, "protector result for no pending request; ignored");
        return;
    };
    let message = clip(&message, 1000);
    if op.op == ProtectorOp::AddRecovery && op.done.is_none() {
        crate::auth::audit(&st.db, None, "diskenc.add_protector", Some(("agent", agent_id)), json!({ "volume": op.volume_id, "ok": ok, "message": message })).await;
        if !ok {
            let _ = set_escrow_error(st, agent_id, &op.volume_id, &format!("adding a recovery password failed: {message}")).await;
            recheck_agent(st, agent_id).await;
        }
    }
    if let Some(done) = op.done.take() {
        let _ = done.send((ok, message));
    }
}

/// Asks the agent to report now.
pub async fn refresh(st: &AppState, agent_id: Uuid) -> ApiResult<()> {
    capable(st, agent_id).await?;
    if !st.hub.send(agent_id, ServerMsg::DiskEncryptionRefresh).await {
        return Err(ApiError::Conflict("the agent is offline".into()));
    }
    Ok(())
}

async fn capable(st: &AppState, agent_id: Uuid) -> ApiResult<()> {
    let (online, capable): (bool, bool) = sqlx::query_as("SELECT online, $2 = ANY(capabilities) FROM agents WHERE id = $1")
        .bind(agent_id)
        .bind(CAPABILITY)
        .fetch_optional(&st.db)
        .await?
        .ok_or(ApiError::NotFound("agent"))?;
    if !online {
        return Err(ApiError::Conflict("the agent is offline".into()));
    }
    if !capable {
        return Err(ApiError::Conflict("the agent is too old to report disk encryption; update it".into()));
    }
    Ok(())
}

/// Replaces a BitLocker volume's recovery password and waits for the agent's answer. The new
/// password is escrowed from the report that follows.
pub async fn rotate(st: &Arc<AppState>, agent_id: Uuid, volume_id: &str) -> ApiResult<String> {
    capable(st, agent_id).await?;
    if st.cfg.data_key.is_none() {
        return Err(ApiError::Conflict(format!("rotating a recovery password needs somewhere to keep the new one: {}", vault::NEEDS_KEY)));
    }
    let row: Option<(String, String, Option<String>)> =
        sqlx::query_as("SELECT kind, status, recovery_protector_id FROM disk_volumes WHERE agent_id = $1 AND volume_id = $2")
            .bind(agent_id)
            .bind(volume_id)
            .fetch_optional(&st.db)
            .await?;
    let Some((kind, status, recovery)) = row else { return Err(ApiError::NotFound("volume")) };
    if kind != "bitlocker" || !["encrypted", "encrypting", "suspended"].contains(&status.as_str()) {
        return Err(ApiError::Conflict("only a BitLocker-encrypted volume has a recovery password to rotate".into()));
    }
    let op = if recovery.is_some() { ProtectorOp::RotateRecovery } else { ProtectorOp::AddRecovery };
    expire();
    if lock(&OPS).values().any(|p| p.agent_id == agent_id && p.volume_id == volume_id) {
        return Err(ApiError::Conflict("a change to this volume's recovery password is already running".into()));
    }
    let (done, wait) = oneshot::channel();
    let request_id = Uuid::new_v4();
    lock(&OPS).insert(request_id, PendingOp { agent_id, volume_id: volume_id.to_string(), op, at: Instant::now(), done: Some(done) });
    if !st.hub.send(agent_id, ServerMsg::DiskProtector { request_id, volume_id: volume_id.to_string(), op }).await {
        lock(&OPS).remove(&request_id);
        return Err(ApiError::Conflict("the agent is offline".into()));
    }
    match tokio::time::timeout(ROTATE_WAIT, wait).await {
        Ok(Ok((true, message))) => Ok(message),
        Ok(Ok((false, message))) => Err(ApiError::Conflict(format!("the agent couldn't change the recovery password: {message}"))),
        _ => {
            lock(&OPS).remove(&request_id);
            Err(ApiError::Conflict("the agent didn't answer in time; check the volume again shortly".into()))
        }
    }
}

/// Every minute: forget unanswered requests, and re-check agents whose suspension may have
/// passed its grace period since they last reported.
pub async fn run(st: Arc<AppState>) {
    let mut tick = tokio::time::interval(Duration::from_secs(60));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        expire();
        let agents: Vec<Uuid> = sqlx::query_scalar("SELECT DISTINCT agent_id FROM disk_volumes WHERE status = 'suspended' OR (kind = 'bitlocker' AND escrowed_protector_id IS DISTINCT FROM recovery_protector_id)")
            .fetch_all(&st.db)
            .await
            .unwrap_or_default();
        for a in agents {
            recheck_agent(&st, a).await;
        }
    }
}

/// After a policy change: escrow what the new policy asks for.
pub async fn policy_changed(st: &AppState, agents: Option<&[Uuid]>) {
    let list: Vec<Uuid> = match agents {
        Some(a) => a.to_vec(),
        None => sqlx::query_scalar("SELECT DISTINCT agent_id FROM disk_volumes WHERE kind = 'bitlocker'").fetch_all(&st.db).await.unwrap_or_default(),
    };
    for a in list {
        if st.hub.is_online(a)
            && let Err(e) = request_keys(st, a).await
        {
            warn!(agent_id = %a, "requesting recovery keys: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vol(id: &str, role: &str, kind: &str, status: &str, rec: Option<&str>, esc: Option<&str>, suspended_hours: Option<i64>) -> Vol {
        Vol {
            volume_id: id.into(),
            kind: kind.into(),
            role: role.into(),
            status: status.into(),
            recovery_protector_id: rec.map(String::from),
            escrowed_protector_id: esc.map(String::from),
            escrow_error: None,
            suspended_since: suspended_hours.map(|h| Utc::now() - chrono::Duration::hours(h)),
        }
    }

    fn keys(f: Vec<(String, String, Value)>) -> Vec<(String, String)> {
        f.into_iter().map(|f| (f.0, f.2["finding"].as_str().unwrap().to_string())).collect()
    }

    #[test]
    fn findings_per_volume() {
        let now = Utc::now();
        let vols = [
            vol("C:", "os", "bitlocker", "encrypted", Some("{A}"), Some("{A}"), None),
            vol("D:", "data", "none", "unencrypted", None, None, None),
            vol("E:", "data", "bitlocker", "suspended", Some("{E}"), Some("{E}"), Some(2)),
            vol("F:", "data", "bitlocker", "suspended", Some("{F}"), Some("{F}"), Some(30)),
            vol("G:", "data", "bitlocker", "encrypting", Some("{G2}"), Some("{G1}"), None),
            vol("H:", "data", "bitlocker", "encrypted", None, None, None),
            vol("/home", "data", "luks", "encrypted", None, None, None),
        ];
        let all = DiskEncryptionRule { volumes: "all_fixed".into(), ..Default::default() };
        assert_eq!(
            keys(findings(&all, &vols, &[], now)),
            [
                ("vol:D:".to_string(), "unencrypted".to_string()),
                ("vol:F:".into(), "suspended".into()),
                ("vol:G:".into(), "not_escrowed".into()),
                ("vol:H:".into(), "not_escrowed".into()),
            ],
            "E: is within its grace period; LUKS has no escrow"
        );
        assert!(findings(&DiskEncryptionRule::default(), &vols, &[], now).is_empty(), "only the OS volume, which is fine");
        let no_escrow = DiskEncryptionRule { require_escrow: false, ..all.clone() };
        assert_eq!(keys(findings(&no_escrow, &vols, &[], now)).len(), 2);
        assert_eq!(keys(findings(&all, &vols, &["G:".into(), "H:".into()], now)).len(), 2, "a key being fetched isn't a finding yet");
        let bare = [vol("C:", "os", "none", "unencrypted", None, None, None)];
        let f = findings(&DiskEncryptionRule::default(), &bare, &[], now);
        assert_eq!(f[0].1, "C: isn't encrypted");
        assert!(validate(&DiskEncryptionRule { volumes: "usb".into(), ..Default::default() }).is_err());
        assert!(validate(&DiskEncryptionRule { grace_hours: 1000, ..Default::default() }).is_err());
    }

    #[test]
    fn summaries() {
        use Status::*;
        assert_eq!(summary(&[]), None);
        assert_eq!(summary(&[Encrypted, Encrypted]), Some("encrypted"));
        assert_eq!(summary(&[Unencrypted]), Some("none"));
        assert_eq!(summary(&[Encrypted, Unencrypted]), Some("partial"));
        assert_eq!(summary(&[Suspended]), Some("partial"));
    }

    #[test]
    fn keys_only_from_the_agent_that_was_asked() {
        let (a, b, req) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        lock(&KEYS).insert(req, PendingKey { agent_id: a, volume_id: "C:".into(), protector_id: "{P}".into(), at: Instant::now() });
        assert_eq!(pending_volumes(a), ["C:"]);
        assert!(pending_volumes(b).is_empty());
        lock(&KEYS).remove(&req);
    }
}
