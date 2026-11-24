//! Local admin password rotation (docs/design/local-admin.md).
//!
//! One managed local account per device. The server generates the password and **stores it
//! before the agent sets it**:
//!
//! 1. [`crate::vault::put_managed`] (kind `local_admin`, reference = the agent id, state
//!    `pending`): the previous password moves to the item's history;
//! 2. [`ServerMsg::LocalAdminSet`];
//! 3. on `ok` the item's state becomes `current` and the next rotation is scheduled.
//!
//! A lost reply or a failure leaves the item `pending` with the previous password in its
//! history, so nobody is locked out, and a retry sends the same pending password again instead
//! of making a new one. Nothing is queued for an offline agent: [`tick`] (every minute, and when
//! an agent connects) sends what is due to agents that are online.
//!
//! `local_admin_state.status`: `ok`, `pending` (sent, no answer yet), `failed` (retried with
//! backoff), `unsupported` and `conflict` (retried daily, in case the device changed).

use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use rmm_proto::ServerMsg;
use rmm_proto::localadmin::{CAPABILITY, Outcome, Secret};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tracing::{info, warn};
use uuid::Uuid;

use crate::alerts::{Policy, Rule, clear, fire, policies_for};
use crate::error::{ApiError, ApiResult};
use crate::policy::LocalAdminConfig;
use crate::state::AppState;
use crate::vault::{self, Managed, ManagedKind, Source};

pub const MIN_LENGTH: i32 = 14;
pub const MAX_LENGTH: i32 = 64;
/// A set without an answer for this long is sent again (same password).
const ANSWER_SECS: i64 = 120;
/// A failed set is retried after this many minutes times the attempts so far, up to an hour.
const RETRY_MINUTES: i64 = 5;

// ---------------------------------------------------------------------------
// Passwords
// ---------------------------------------------------------------------------

/// No look-alikes (I, l, 1, O, 0), nothing a shell or CSV quotes (`'"\$` and space), no `:`
/// (`chpasswd`'s separator).
const UPPER: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ";
const LOWER: &[u8] = b"abcdefghijkmnpqrstuvwxyz";
const DIGITS: &[u8] = b"23456789";
const SYMBOLS: &[u8] = b"!#%+-=?@^_*.,";

/// A uniform index below `n`, from the OS CSPRNG (rejection sampling: no modulo bias).
fn below(n: usize) -> usize {
    let n = n as u32;
    let zone = u32::MAX - (u32::MAX % n);
    loop {
        let mut b = [0u8; 4];
        getrandom::fill(&mut b).expect("OS RNG unavailable");
        let v = u32::from_le_bytes(b);
        if v < zone {
            return (v % n) as usize;
        }
    }
}

/// A password of `length` characters (clamped to 14-64) with at least one upper-case letter,
/// lower-case letter, digit and symbol, which satisfies Windows' default complexity rule.
pub fn generate(length: usize) -> String {
    let length = length.clamp(MIN_LENGTH as usize, MAX_LENGTH as usize);
    let all: Vec<u8> = [UPPER, LOWER, DIGITS, SYMBOLS].concat();
    let mut out: Vec<u8> = [UPPER, LOWER, DIGITS, SYMBOLS].iter().map(|class| class[below(class.len())]).collect();
    while out.len() < length {
        out.push(all[below(all.len())]);
    }
    // Fisher-Yates, so the guaranteed characters aren't always first.
    for i in (1..out.len()).rev() {
        out.swap(i, below(i + 1));
    }
    String::from_utf8(out).expect("ASCII")
}

// ---------------------------------------------------------------------------
// The alert rule
// ---------------------------------------------------------------------------

fn seven() -> i32 {
    7
}

/// `local_admin` alert params: the rotation failed, conflicts with Windows LAPS, or is this many
/// days overdue.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LocalAdminRule {
    #[serde(default = "seven")]
    pub overdue_days: i32,
}

impl Default for LocalAdminRule {
    fn default() -> Self {
        LocalAdminRule { overdue_days: 7 }
    }
}

pub fn validate(r: &LocalAdminRule) -> Result<(), String> {
    if !(1..=365).contains(&r.overdue_days) {
        return Err("overdue days must be 1-365".into());
    }
    Ok(())
}

#[derive(Debug, Clone, sqlx::FromRow, Serialize)]
pub struct State {
    pub agent_id: Uuid,
    pub account: String,
    pub vault_item_id: Option<Uuid>,
    pub status: String,
    pub rotated_at: Option<DateTime<Utc>>,
    pub next_rotate_at: Option<DateTime<Utc>>,
    pub rotate_reason: Option<String>,
    pub attempts: i32,
    #[serde(skip)]
    pub request_id: Option<Uuid>,
    pub sent_at: Option<DateTime<Utc>>,
    pub last_error: Option<String>,
    pub updated_at: DateTime<Utc>,
}

const STATE_COLS: &str = "agent_id, account, vault_item_id, status, rotated_at, next_rotate_at, rotate_reason, attempts, request_id, sent_at, last_error, updated_at";

/// What a rule finds about a device's rotation (one alert per device, key `""`).
pub fn finding(r: &LocalAdminRule, enabled: bool, s: Option<&State>, now: DateTime<Utc>) -> Option<(String, Value)> {
    let s = s.filter(|_| enabled)?;
    let details = json!({ "status": s.status, "account": s.account, "error": s.last_error, "rotated_at": s.rotated_at, "next_rotate_at": s.next_rotate_at });
    match s.status.as_str() {
        "failed" => Some((format!("Rotating the {} password failed", s.account), details)),
        "conflict" => Some((format!("Windows LAPS also manages {}", s.account), details)),
        "unsupported" => None,
        _ => {
            let due = s.next_rotate_at.or(s.sent_at)?;
            (due < now - chrono::Duration::days(i64::from(r.overdue_days)))
                .then(|| (format!("The {} password is more than {} days overdue for rotation", s.account, r.overdue_days), details))
        }
    }
}

async fn state(st: &AppState, agent_id: Uuid) -> sqlx::Result<Option<State>> {
    sqlx::query_as(sqlx::AssertSqlSafe(format!("SELECT {STATE_COLS} FROM local_admin_state WHERE agent_id = $1")))
        .bind(agent_id)
        .fetch_optional(&st.db)
        .await
}

async fn check(st: &AppState, p: &Policy, agent_id: Uuid, enabled: bool, s: Option<&State>) -> sqlx::Result<()> {
    let Some(Rule::LocalAdmin(r)) = p.rule() else { return Ok(()) };
    match finding(&r, enabled, s, Utc::now()) {
        Some((title, details)) => fire(st, p, agent_id, "", &title, details, 0).await,
        None => clear(st, p, agent_id, None, &[]).await,
    }
}

pub async fn recheck_agent(st: &AppState, agent_id: Uuid) {
    let res: sqlx::Result<()> = async {
        let policies = policies_for(st, agent_id, "local_admin").await?;
        if policies.is_empty() {
            return Ok(());
        }
        let cfg = crate::policy::local_admin(st, agent_id).await?;
        let s = state(st, agent_id).await?;
        for p in &policies {
            check(st, p, agent_id, cfg.enabled, s.as_ref()).await?;
        }
        Ok(())
    }
    .await;
    if let Err(e) = res {
        warn!(%agent_id, "re-checking local admin alerts: {e}");
    }
}

pub async fn recheck_item(st: &AppState, item_id: Uuid) {
    let rows: sqlx::Result<Vec<Uuid>> = sqlx::query_scalar(
        "SELECT ap.agent_id FROM agent_policy ap WHERE ap.item_id = $1 AND ap.module = 'alert' AND ap.enabled AND ap.config ->> 'kind' = 'local_admin'",
    )
    .bind(item_id)
    .fetch_all(&st.db)
    .await;
    for agent_id in rows.unwrap_or_default() {
        recheck_agent(st, agent_id).await;
    }
}

// ---------------------------------------------------------------------------
// Rotation
// ---------------------------------------------------------------------------

async fn publish(st: &AppState, agent_id: Uuid) {
    if let Ok(client_id) = sqlx::query_scalar::<_, Uuid>("SELECT s.client_id FROM agents a JOIN sites s ON s.id = a.site_id WHERE a.id = $1").bind(agent_id).fetch_one(&st.db).await {
        st.hub.publish(crate::hub::Event::Security { agent_id, client_id });
    }
}

/// Starts a rotation (`reason`: first, schedule, reveal, manual): a new password stored as
/// `pending`, or the pending one again if the last rotation never finished, then sent.
pub async fn start(st: &AppState, agent_id: Uuid, cfg: &LocalAdminConfig, reason: &str, by: Option<Uuid>) -> ApiResult<()> {
    let master = st.cfg.data_key.as_ref().ok_or_else(|| ApiError::Conflict(vault::NEEDS_KEY.into()))?;
    let (client_id, hostname): (Uuid, String) =
        sqlx::query_as("SELECT s.client_id, a.hostname FROM agents a JOIN sites s ON s.id = a.site_id WHERE a.id = $1")
            .bind(agent_id)
            .fetch_optional(&st.db)
            .await?
            .ok_or(ApiError::NotFound("agent"))?;
    let cur = state(st, agent_id).await?;
    // The pending password of a rotation that never finished, for the same account: reuse it.
    let mut reuse: Option<(Uuid, String)> = None;
    if let Some(s) = cur.as_ref().filter(|s| s.account == cfg.account)
        && let Some(item) = s.vault_item_id
    {
        let managed: Option<Option<String>> =
            sqlx::query_scalar("SELECT managed_state FROM vault_items WHERE id = $1 AND managed_kind = 'local_admin'").bind(item).fetch_optional(&st.db).await?;
        if managed.flatten().as_deref() == Some("pending")
            && let Some(pw) = vault::read_password(&st.db, master, client_id, item).await?
        {
            reuse = Some((item, pw));
        }
    }
    let reused = reuse.is_some();
    let item = match reuse {
        Some((item, _)) => item,
        None => {
            let password = generate(cfg.length as usize);
            let m = Managed {
                kind: ManagedKind::LocalAdmin,
                agent_id: Some(agent_id),
                reference: agent_id.to_string(),
                name: format!("Local admin: {hostname}").chars().take(200).collect(),
                username: cfg.account.clone(),
                state: Some("pending".into()),
                ..Default::default()
            };
            let source = match by {
                Some(u) => Source::user("local_admin", u),
                None => Source::system("local_admin"),
            };
            vault::put_managed(st, client_id, m, &password, source).await?
        }
    };
    sqlx::query(
        "INSERT INTO local_admin_state (agent_id, account, vault_item_id, status, rotate_reason, attempts, updated_at)
         VALUES ($1, $2, $3, 'pending', $4, 0, now())
         ON CONFLICT (agent_id) DO UPDATE SET account = EXCLUDED.account, vault_item_id = EXCLUDED.vault_item_id, status = 'pending',
                rotate_reason = EXCLUDED.rotate_reason, attempts = CASE WHEN $5 THEN local_admin_state.attempts ELSE 0 END,
                request_id = NULL, sent_at = NULL, updated_at = now()",
    )
    .bind(agent_id)
    .bind(&cfg.account)
    .bind(item)
    .bind(reason)
    .bind(reused)
    .execute(&st.db)
    .await?;
    // A retry of the same password isn't a new rotation.
    if !reused || by.is_some() {
        crate::auth::audit(&st.db, by, "local_admin.rotate", Some(("agent", agent_id)), json!({ "trigger": reason, "account": cfg.account, "vault_item_id": item, "retry": reused })).await;
    }
    send(st, agent_id, cfg).await
}

/// Sends the pending password (again). The agent must be online and able to.
async fn send(st: &AppState, agent_id: Uuid, cfg: &LocalAdminConfig) -> ApiResult<()> {
    let master = st.cfg.data_key.as_ref().ok_or_else(|| ApiError::Conflict(vault::NEEDS_KEY.into()))?;
    let s = state(st, agent_id).await?.ok_or(ApiError::NotFound("local admin state"))?;
    let item = s.vault_item_id.ok_or_else(|| ApiError::Conflict("the managed credential was deleted; rotate to make a new one".into()))?;
    let client_id: Uuid = sqlx::query_scalar("SELECT s.client_id FROM agents a JOIN sites s ON s.id = a.site_id WHERE a.id = $1").bind(agent_id).fetch_one(&st.db).await?;
    let password = vault::read_password(&st.db, master, client_id, item).await?.ok_or_else(|| ApiError::Conflict("the managed credential has no password".into()))?;
    let request_id = Uuid::new_v4();
    sqlx::query("UPDATE local_admin_state SET request_id = $2, sent_at = now(), attempts = attempts + 1, status = 'pending', updated_at = now() WHERE agent_id = $1")
        .bind(agent_id)
        .bind(request_id)
        .execute(&st.db)
        .await?;
    let msg = ServerMsg::LocalAdminSet { request_id, account: s.account.clone(), password: Secret(password), create: cfg.create };
    if !st.hub.send(agent_id, msg).await {
        // Tried again when it reconnects.
        sqlx::query("UPDATE local_admin_state SET sent_at = NULL WHERE agent_id = $1").bind(agent_id).execute(&st.db).await?;
        return Err(ApiError::Conflict("the agent is offline; the rotation runs when it reconnects".into()));
    }
    info!(%agent_id, account = %s.account, attempt = s.attempts + 1, "local admin password sent");
    publish(st, agent_id).await;
    Ok(())
}

/// The agent's answer. Only the answer to the set in flight counts.
pub async fn ingest_result(st: &AppState, agent_id: Uuid, request_id: Uuid, ok: bool, created: bool, status: Outcome, message: String) -> anyhow::Result<()> {
    let Some(s) = state(st, agent_id).await? else { return Ok(()) };
    if s.request_id != Some(request_id) {
        warn!(%agent_id, %request_id, "local admin result for another request; ignored");
        return Ok(());
    }
    let cfg = crate::policy::local_admin(st, agent_id).await?;
    let message: String = message.chars().filter(|c| !c.is_control()).take(500).collect();
    let client_id: Uuid = sqlx::query_scalar("SELECT s.client_id FROM agents a JOIN sites s ON s.id = a.site_id WHERE a.id = $1").bind(agent_id).fetch_one(&st.db).await?;
    if ok {
        if let Some(item) = s.vault_item_id
            && let Err(e) = vault::set_managed_state(&st.db, client_id, item, "current").await
        {
            warn!(%agent_id, "marking the local admin password current: {e}");
        }
        sqlx::query(
            "UPDATE local_admin_state SET status = 'ok', rotated_at = now(), next_rotate_at = now() + make_interval(days => $2), attempts = 0,
                    request_id = NULL, last_error = NULL, updated_at = now() WHERE agent_id = $1",
        )
        .bind(agent_id)
        .bind(cfg.rotate_days.max(1))
        .execute(&st.db)
        .await?;
        info!(%agent_id, account = %s.account, created, "local admin password rotated");
    } else {
        // The item stays `pending`: the next try sends the same password.
        let (st_name, retry_minutes) = match status {
            Outcome::Unsupported => ("unsupported", 24 * 60),
            Outcome::Conflict => ("conflict", 24 * 60),
            _ => ("failed", (RETRY_MINUTES * i64::from(s.attempts.max(1))).min(60)),
        };
        sqlx::query(
            "UPDATE local_admin_state SET status = $2, last_error = $3, request_id = NULL, next_rotate_at = now() + make_interval(mins => $4), updated_at = now()
              WHERE agent_id = $1",
        )
        .bind(agent_id)
        .bind(st_name)
        .bind(&message)
        .bind(retry_minutes as i32)
        .execute(&st.db)
        .await?;
        warn!(%agent_id, account = %s.account, status = st_name, "local admin rotation failed: {message}");
    }
    crate::auth::audit(
        &st.db,
        None,
        "local_admin.result",
        Some(("agent", agent_id)),
        json!({ "ok": ok, "created": created, "status": status.as_str(), "account": s.account, "message": message, "trigger": s.rotate_reason }),
    )
    .await;
    recheck_agent(st, agent_id).await;
    publish(st, agent_id).await;
    Ok(())
}

/// Someone revealed a managed local admin password: rotate it `rotate_after_reveal_hours` later.
pub async fn revealed(st: &AppState, item_id: Uuid) {
    let res: sqlx::Result<()> = async {
        let agent: Option<Uuid> = sqlx::query_scalar("SELECT agent_id FROM local_admin_state WHERE vault_item_id = $1").bind(item_id).fetch_optional(&st.db).await?;
        let Some(agent_id) = agent else { return Ok(()) };
        let cfg = crate::policy::local_admin(st, agent_id).await?;
        if !cfg.enabled || cfg.rotate_after_reveal_hours == 0 {
            return Ok(());
        }
        sqlx::query(
            "UPDATE local_admin_state SET next_rotate_at = least(coalesce(next_rotate_at, 'infinity'), now() + make_interval(hours => $2)),
                    rotate_reason = 'reveal', updated_at = now()
              WHERE agent_id = $1 AND status = 'ok'",
        )
        .bind(agent_id)
        .bind(cfg.rotate_after_reveal_hours)
        .execute(&st.db)
        .await?;
        Ok(())
    }
    .await;
    if let Err(e) = res {
        warn!(item = %item_id, "scheduling a rotation after a reveal: {e}");
    }
}

/// What one agent needs now, if anything: `(start a rotation with this reason | resend)`.
#[derive(Debug, PartialEq, Eq)]
pub enum Due {
    Start(&'static str),
    Resend,
}

pub fn due(cfg: &LocalAdminConfig, s: Option<&State>, now: DateTime<Utc>) -> Option<Due> {
    if !cfg.enabled {
        return None;
    }
    let Some(s) = s else { return Some(Due::Start("first")) };
    if s.account != cfg.account {
        return Some(Due::Start("first"));
    }
    let at = |t: Option<DateTime<Utc>>| t.is_none_or(|t| t <= now);
    match s.status.as_str() {
        // Sent and not answered (or never sent: the agent was offline).
        "pending" => s.sent_at.is_none_or(|t| t <= now - chrono::Duration::seconds(ANSWER_SECS)).then_some(Due::Resend),
        "failed" | "unsupported" | "conflict" => at(s.next_rotate_at).then_some(Due::Resend),
        _ => at(s.next_rotate_at).then(|| Due::Start(if s.rotate_reason.as_deref() == Some("reveal") { "reveal" } else { "schedule" })),
    }
}

/// Agents whose rotation is being worked on right now: the tick, a connect and a policy change
/// must not both start one (two passwords, the first one lost).
static BUSY: std::sync::LazyLock<std::sync::Mutex<std::collections::HashSet<Uuid>>> = std::sync::LazyLock::new(Default::default);

struct Claim(Uuid);

impl Claim {
    fn take(agent_id: Uuid) -> Option<Claim> {
        BUSY.lock().unwrap_or_else(|e| e.into_inner()).insert(agent_id).then_some(Claim(agent_id))
    }
}

impl Drop for Claim {
    fn drop(&mut self) {
        BUSY.lock().unwrap_or_else(|e| e.into_inner()).remove(&self.0);
    }
}

/// Acts on one agent if something is due. Errors are recorded on its state.
pub async fn tick_agent(st: &AppState, agent_id: Uuid) {
    let Some(_claim) = Claim::take(agent_id) else { return };
    let res: ApiResult<()> = async {
        let cfg = crate::policy::local_admin(st, agent_id).await?;
        let s = state(st, agent_id).await?;
        match due(&cfg, s.as_ref(), Utc::now()) {
            None => Ok(()),
            Some(Due::Start(reason)) => start(st, agent_id, &cfg, reason, None).await,
            // A retry: the pending password if the item is still pending, else (an `ok` item
            // after a manual change elsewhere) a new rotation.
            Some(Due::Resend) => start(st, agent_id, &cfg, s.and_then(|s| s.rotate_reason).as_deref().map(reason_str).unwrap_or("schedule"), None).await,
        }
    }
    .await;
    if let Err(e) = res {
        if matches!(&e, ApiError::Conflict(m) if m.contains("offline")) {
            return;
        }
        let msg = e.to_string();
        warn!(%agent_id, "local admin rotation: {msg}");
        let _ = sqlx::query("UPDATE local_admin_state SET last_error = $2, updated_at = now() WHERE agent_id = $1")
            .bind(agent_id)
            .bind(msg.chars().take(500).collect::<String>())
            .execute(&st.db)
            .await;
    }
}

fn reason_str(r: &str) -> &'static str {
    match r {
        "first" => "first",
        "reveal" => "reveal",
        "manual" => "manual",
        _ => "schedule",
    }
}

/// Online agents that can rotate, whose policy is on.
async fn candidates(st: &AppState) -> sqlx::Result<Vec<Uuid>> {
    sqlx::query_scalar(
        "SELECT a.id FROM agents a JOIN policy_effective e ON e.set_id = a.policy_set_id AND e.item_id = $1
          WHERE a.online AND $2 = ANY(a.capabilities) AND e.enabled AND (e.config ->> 'enabled')::boolean",
    )
    .bind(crate::policy::LOCAL_ADMIN_ITEM)
    .bind(CAPABILITY)
    .fetch_all(&st.db)
    .await
}

/// One pass: rotations due on online agents, and the alerts time alone opens (overdue).
pub async fn tick(st: &AppState) {
    if st.cfg.data_key.is_none() {
        return;
    }
    match candidates(st).await {
        Ok(agents) => {
            for a in agents {
                tick_agent(st, a).await;
            }
        }
        Err(e) => warn!("local admin rotation: {e}"),
    }
    let watch: Vec<Uuid> = sqlx::query_scalar(
        "SELECT agent_id FROM local_admin_state WHERE status IN ('failed', 'conflict') OR next_rotate_at < now() - interval '1 day'
         UNION SELECT agent_id FROM alerts WHERE kind = 'local_admin' AND resolved_at IS NULL",
    )
    .fetch_all(&st.db)
    .await
    .unwrap_or_default();
    for a in watch {
        recheck_agent(st, a).await;
    }
}

/// An agent connected: rotate now if something is due.
pub async fn on_connect(st: &Arc<AppState>, agent_id: Uuid, capabilities: &[String]) {
    if st.cfg.data_key.is_none() || !capabilities.iter().any(|c| c == CAPABILITY) {
        return;
    }
    let st = st.clone();
    tokio::spawn(async move {
        // After the connection is registered, so the set can be delivered.
        tokio::time::sleep(Duration::from_millis(500)).await;
        tick_agent(&st, agent_id).await;
    });
}

/// After a policy change: start what the new policy asks for at once.
pub async fn policy_changed(st: &AppState, agents: Option<&[Uuid]>) {
    let list = match candidates(st).await {
        Ok(l) => l,
        Err(e) => return warn!("local admin after a policy change: {e}"),
    };
    for a in list.into_iter().filter(|a| agents.is_none_or(|l| l.contains(a))) {
        tick_agent(st, a).await;
    }
    if let Some(l) = agents {
        for a in l {
            recheck_agent(st, *a).await;
        }
    }
}

/// Every `RMM_LOCALADMIN_TICK_SECS` (default 60).
pub async fn run(st: Arc<AppState>) {
    let secs = std::env::var("RMM_LOCALADMIN_TICK_SECS").ok().and_then(|v| v.trim().parse::<u64>().ok()).unwrap_or(60).clamp(1, 3600);
    let mut tick_every = tokio::time::interval(Duration::from_secs(secs));
    tick_every.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick_every.tick().await;
        tick(&st).await;
    }
}

/// A manual rotation (`POST /agents/{id}/local-admin/rotate`).
pub async fn rotate_now(st: &AppState, agent_id: Uuid, by: Uuid) -> ApiResult<()> {
    let cfg = crate::policy::local_admin(st, agent_id).await?;
    if !cfg.enabled {
        return Err(ApiError::Conflict("local admin rotation is off in this device's policy".into()));
    }
    let capable: bool = sqlx::query_scalar("SELECT $2 = ANY(capabilities) FROM agents WHERE id = $1").bind(agent_id).bind(CAPABILITY).fetch_one(&st.db).await?;
    if !capable {
        return Err(ApiError::Conflict("the agent is too old to rotate its local admin password; update it".into()));
    }
    if !st.hub.is_online(agent_id) {
        return Err(ApiError::Conflict("the agent is offline".into()));
    }
    let _claim = Claim::take(agent_id).ok_or_else(|| ApiError::Conflict("a rotation is being started already".into()))?;
    start(st, agent_id, &cfg, "manual", Some(by)).await
}

/// `GET /agents/{id}/local-admin`: the policy and the state.
pub async fn view(st: &AppState, agent_id: Uuid) -> ApiResult<Value> {
    let cfg = crate::policy::local_admin(st, agent_id).await?;
    let s = state(st, agent_id).await?;
    let managed_state: Option<String> = match s.as_ref().and_then(|s| s.vault_item_id) {
        Some(item) => sqlx::query_scalar("SELECT managed_state FROM vault_items WHERE id = $1").bind(item).fetch_optional(&st.db).await?.flatten(),
        None => None,
    };
    Ok(json!({ "policy": cfg, "state": s, "managed_state": managed_state, "needs_data_key": st.cfg.data_key.is_none() }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passwords() {
        for len in [14usize, 20, 64] {
            let p = generate(len);
            assert_eq!(p.len(), len);
            assert!(p.bytes().any(|c| UPPER.contains(&c)) && p.bytes().any(|c| LOWER.contains(&c)));
            assert!(p.bytes().any(|c| DIGITS.contains(&c)) && p.bytes().any(|c| SYMBOLS.contains(&c)));
            assert!(!p.contains([':', ' ', '"', '\'', '\\', '$', 'l', 'I', 'O', '0', '1']));
        }
        assert_eq!(generate(3).len(), 14, "clamped");
        assert_ne!(generate(20), generate(20));
        // Every class position is used over many draws (no stuck shuffle).
        let firsts: std::collections::HashSet<u8> = (0..400).map(|_| generate(14).as_bytes()[0]).collect();
        assert!(firsts.len() > 20);
    }

    fn st(status: &str, next_in_hours: Option<i64>, sent_secs_ago: Option<i64>, reason: Option<&str>) -> State {
        let now = Utc::now();
        State {
            agent_id: Uuid::nil(),
            account: "rmmadmin".into(),
            vault_item_id: Some(Uuid::nil()),
            status: status.into(),
            rotated_at: None,
            next_rotate_at: next_in_hours.map(|h| now + chrono::Duration::hours(h)),
            rotate_reason: reason.map(String::from),
            attempts: 1,
            request_id: None,
            sent_at: sent_secs_ago.map(|s| now - chrono::Duration::seconds(s)),
            last_error: None,
            updated_at: now,
        }
    }

    #[test]
    fn state_machine() {
        let now = Utc::now();
        let on = LocalAdminConfig { enabled: true, ..Default::default() };
        assert_eq!(due(&LocalAdminConfig::default(), None, now), None, "off by default");
        assert_eq!(due(&on, None, now), Some(Due::Start("first")));
        // pending → answered in time: nothing; lost reply: resend the same password.
        assert_eq!(due(&on, Some(&st("pending", None, Some(10), Some("first"))), now), None);
        assert_eq!(due(&on, Some(&st("pending", None, Some(600), Some("first"))), now), Some(Due::Resend));
        assert_eq!(due(&on, Some(&st("pending", None, None, Some("first"))), now), Some(Due::Resend), "never delivered");
        // failed → retried (with the pending password) once its backoff passed.
        assert_eq!(due(&on, Some(&st("failed", Some(1), None, None)), now), None);
        assert_eq!(due(&on, Some(&st("failed", Some(-1), None, None)), now), Some(Due::Resend));
        // ok → on schedule, or sooner after a reveal.
        assert_eq!(due(&on, Some(&st("ok", Some(24), None, None)), now), None);
        assert_eq!(due(&on, Some(&st("ok", Some(-1), None, Some("first"))), now), Some(Due::Start("schedule")));
        assert_eq!(due(&on, Some(&st("ok", Some(-1), None, Some("reveal"))), now), Some(Due::Start("reveal")));
        // A different account in the policy starts over.
        let other = LocalAdminConfig { account: "itadmin".into(), ..on.clone() };
        assert_eq!(due(&other, Some(&st("ok", Some(24), None, None)), now), Some(Due::Start("first")));
    }

    #[test]
    fn alert_findings() {
        let now = Utc::now();
        let r = LocalAdminRule::default();
        assert!(finding(&r, true, Some(&st("failed", None, None, None)), now).is_some());
        assert!(finding(&r, true, Some(&st("conflict", None, None, None)), now).unwrap().0.contains("Windows LAPS"));
        assert!(finding(&r, true, Some(&st("unsupported", None, None, None)), now).is_none());
        assert!(finding(&r, true, Some(&st("ok", Some(-24 * 6), None, None)), now).is_none(), "six days late is within seven");
        assert!(finding(&r, true, Some(&st("ok", Some(-24 * 8), None, None)), now).is_some());
        assert!(finding(&r, false, Some(&st("failed", None, None, None)), now).is_none(), "the policy is off");
        assert!(finding(&r, true, None, now).is_none());
        assert!(validate(&LocalAdminRule { overdue_days: 0 }).is_err());
    }
}
