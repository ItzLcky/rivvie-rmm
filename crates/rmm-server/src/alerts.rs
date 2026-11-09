//! Alert engine.
//!
//! Policies ([`Rule`]) are checked two ways:
//! - **Polled** every `RMM_ALERT_EVAL_SECS` (offline, CPU, memory, disk). Each check is one
//!   set-based `INSERT ... SELECT` that opens alerts and one `UPDATE` that resolves them.
//! - **Event-driven** as agents report (a job finishes, the service list changes, a log
//!   watcher matches) and when an agent reconnects (offline alerts clear at once).
//!
//! An alert is unique per (policy, agent, key) while unresolved, so re-checks refresh the
//! open alert instead of opening another. Opening and clearing queue notifications
//! ([`crate::notify`]) and push a live event to dashboards.

use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use rmm_proto::{LogEntry, LogLevel, LogWatcher, ServerMsg, ServiceInfo, ServiceState, StartMode};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::AssertSqlSafe;
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::hub::Event;
use crate::state::AppState;

// ---------------------------------------------------------------------------
// Policies
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Threshold {
    /// Percent.
    pub threshold: f64,
    /// The value must stay at or above the threshold for this long.
    pub minutes: i32,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ServiceRule {
    /// Names to watch. `*` matches anything; `nginx` also matches `nginx.service`.
    #[serde(default)]
    pub services: Vec<String>,
    /// Also watch every service set to start automatically.
    #[serde(default)]
    pub auto_only: bool,
    /// Never alert on these (same matching as `services`).
    #[serde(default)]
    pub exclude: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LogRule {
    #[serde(default)]
    pub channels: Vec<String>,
    #[serde(default)]
    pub sources: Vec<String>,
    #[serde(default)]
    pub event_ids: Vec<u32>,
    pub min_level: LogLevel,
    #[serde(default)]
    pub pattern: Option<String>,
}

/// What a policy checks: `kind` and `params` columns together.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "params", rename_all = "snake_case")]
pub enum Rule {
    Offline { minutes: i32 },
    Cpu(Threshold),
    Memory(Threshold),
    Disk(Threshold),
    Service(ServiceRule),
    JobFailed {
        #[serde(default)]
        script_id: Option<Uuid>,
    },
    Log(LogRule),
}

impl Rule {
    pub fn parse(kind: &str, params: &Value) -> Result<Rule, String> {
        serde_json::from_value(json!({ "kind": kind, "params": params })).map_err(|e| format!("invalid {kind} policy: {e}"))
    }

    pub fn kind(&self) -> &'static str {
        match self {
            Rule::Offline { .. } => "offline",
            Rule::Cpu(_) => "cpu",
            Rule::Memory(_) => "memory",
            Rule::Disk(_) => "disk",
            Rule::Service(_) => "service",
            Rule::JobFailed { .. } => "job_failed",
            Rule::Log(_) => "log",
        }
    }

    pub fn params(&self) -> Value {
        serde_json::to_value(self).ok().and_then(|mut v| v.get_mut("params").map(Value::take)).unwrap_or(json!({}))
    }

    pub fn validate(&self) -> Result<(), String> {
        let list = |l: &[String], what: &str| -> Result<(), String> {
            if l.len() > 100 || l.iter().any(|s| s.trim().is_empty() || s.len() > 256) {
                return Err(format!("{what}: up to 100 non-empty names of at most 256 characters"));
            }
            Ok(())
        };
        match self {
            Rule::Offline { minutes } if !(1..=10080).contains(minutes) => Err("offline minutes must be 1-10080".into()),
            Rule::Cpu(t) | Rule::Memory(t) | Rule::Disk(t) if !(1.0..=100.0).contains(&t.threshold) => {
                Err("threshold must be 1-100 percent".into())
            }
            Rule::Cpu(t) | Rule::Memory(t) | Rule::Disk(t) if !(1..=1440).contains(&t.minutes) => Err("minutes must be 1-1440".into()),
            Rule::Service(s) => {
                if s.services.is_empty() && !s.auto_only {
                    return Err("pick services to watch, or watch every automatic service".into());
                }
                list(&s.services, "services")?;
                list(&s.exclude, "exclude")
            }
            Rule::Log(l) => {
                list(&l.channels, "channels")?;
                list(&l.sources, "sources")?;
                if l.event_ids.len() > 100 {
                    return Err("at most 100 event ids".into());
                }
                if let Some(p) = l.pattern.as_deref().filter(|p| !p.is_empty()) {
                    if p.len() > 1000 {
                        return Err("pattern must be at most 1000 characters".into());
                    }
                    regex_lite::Regex::new(p).map_err(|e| format!("invalid pattern: {e}"))?;
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Policy {
    pub id: Uuid,
    pub name: String,
    pub kind: String,
    pub params: Value,
    pub severity: String,
    pub client_id: Option<Uuid>,
    pub site_id: Option<Uuid>,
    pub os_family: Option<String>,
    pub channel_ids: Vec<Uuid>,
    pub notify_resolved: bool,
}

pub const POLICY_COLS: &str = "p.id, p.name, p.kind, p.params, p.severity, p.client_id, p.site_id, p.os_family, p.channel_ids, p.notify_resolved";

impl Policy {
    fn rule(&self) -> Option<Rule> {
        Rule::parse(&self.kind, &self.params).inspect_err(|e| warn!(policy = %self.id, "{e}")).ok()
    }

    fn covers(&self, client_id: Uuid, site_id: Uuid, os: &str) -> bool {
        self.client_id.is_none_or(|c| c == client_id)
            && self.site_id.is_none_or(|s| s == site_id)
            && self.os_family.as_deref().is_none_or(|o| o == os)
    }
}

/// `$n` client, `$n+1` site, `$n+2` OS: the agents (`a`, site `s`) a policy covers.
fn scope_sql(n: usize) -> String {
    format!(
        "(${n}::uuid IS NULL OR s.client_id = ${n}) AND (${m}::uuid IS NULL OR a.site_id = ${m}) AND (${o}::text IS NULL OR a.os_family = ${o})",
        m = n + 1,
        o = n + 2
    )
}

/// Enabled policies of one kind that cover this agent.
async fn policies_for(st: &AppState, agent_id: Uuid, kind: &str) -> sqlx::Result<Vec<Policy>> {
    sqlx::query_as(AssertSqlSafe(format!(
        "SELECT {POLICY_COLS} FROM alert_policies p, agents a JOIN sites s ON s.id = a.site_id
          WHERE a.id = $1 AND p.enabled AND p.kind = $2
            AND (p.client_id IS NULL OR p.client_id = s.client_id) AND (p.site_id IS NULL OR p.site_id = a.site_id)
            AND (p.os_family IS NULL OR p.os_family = a.os_family)"
    )))
    .bind(agent_id)
    .bind(kind)
    .fetch_all(&st.db)
    .await
}

/// The policy, if it exists and is enabled.
pub async fn load_policy(st: &AppState, id: Uuid) -> sqlx::Result<Option<Policy>> {
    sqlx::query_as(AssertSqlSafe(format!("SELECT {POLICY_COLS} FROM alert_policies p WHERE p.id = $1 AND p.enabled")))
        .bind(id)
        .fetch_optional(&st.db)
        .await
}

// ---------------------------------------------------------------------------
// Opening and resolving
// ---------------------------------------------------------------------------

/// Announces alerts that just opened or resolved: live events, and notifications unless
/// `notify` is false.
async fn announce(st: &AppState, ids: &[Uuid], event: &'static str, channels: &[Uuid], notify: bool) {
    if ids.is_empty() {
        return;
    }
    let rows: Vec<(Uuid, Uuid, Uuid)> = match sqlx::query_as(
        "SELECT al.id, al.agent_id, s.client_id FROM alerts al JOIN agents a ON a.id = al.agent_id JOIN sites s ON s.id = a.site_id
          WHERE al.id = ANY($1)",
    )
    .bind(ids)
    .fetch_all(&st.db)
    .await
    {
        Ok(r) => r,
        Err(e) => return warn!("announcing alerts: {e}"),
    };
    let state = if event == "opened" { "open" } else { "resolved" };
    for (id, agent_id, client_id) in rows {
        st.hub.publish(Event::Alert { id, agent_id, client_id, state: state.into() });
        if notify {
            crate::notify::enqueue(st, id, event, channels).await;
        }
        // Tickets follow the alert even when notifications are off.
        if event == "opened" {
            crate::tickets::alert_opened(st, id).await;
        } else {
            crate::tickets::alert_resolved(st, id).await;
        }
    }
    if notify && !channels.is_empty() {
        st.notify_wake.notify_one();
    }
}

/// Opens (or refreshes) the alert for (policy, agent, key). `bump` adds to its occurrence
/// count when it was already open.
async fn fire(st: &AppState, p: &Policy, agent_id: Uuid, key: &str, title: &str, details: Value, bump: i32) -> sqlx::Result<()> {
    let (id, inserted): (Uuid, bool) = sqlx::query_as(
        "INSERT INTO alerts (id, policy_id, agent_id, key, kind, severity, title, details, occurrences)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, greatest($9, 1))
         ON CONFLICT (policy_id, agent_id, key) WHERE resolved_at IS NULL
         DO UPDATE SET last_seen_at = now(), title = EXCLUDED.title, details = EXCLUDED.details,
                       occurrences = alerts.occurrences + $9
         RETURNING id, (xmax = 0)",
    )
    .bind(Uuid::new_v4())
    .bind(p.id)
    .bind(agent_id)
    .bind(key)
    .bind(&p.kind)
    .bind(&p.severity)
    .bind(title)
    .bind(details)
    .bind(bump)
    .fetch_one(&st.db)
    .await?;
    if inserted {
        info!(alert = %id, policy = %p.name, %agent_id, key, "alert opened");
        announce(st, &[id], "opened", &p.channel_ids, true).await;
    } else if bump > 0 {
        // Occurrence count changed: let open lists redraw.
        if let Ok(client_id) = client_of(st, agent_id).await {
            st.hub.publish(Event::Alert { id, agent_id, client_id, state: "open".into() });
        }
    }
    Ok(())
}

async fn client_of(st: &AppState, agent_id: Uuid) -> sqlx::Result<Uuid> {
    sqlx::query_scalar("SELECT s.client_id FROM agents a JOIN sites s ON s.id = a.site_id WHERE a.id = $1")
        .bind(agent_id)
        .fetch_one(&st.db)
        .await
}

/// Resolves the policy's open alerts on this agent whose key is in `keys` (all keys if None),
/// except those in `keep`.
async fn clear(st: &AppState, p: &Policy, agent_id: Uuid, keys: Option<&[String]>, keep: &[String]) -> sqlx::Result<()> {
    let ids: Vec<Uuid> = sqlx::query_scalar(
        "UPDATE alerts SET resolved_at = now(), resolution = 'cleared'
          WHERE policy_id = $1 AND agent_id = $2 AND resolved_at IS NULL
            AND ($3::text[] IS NULL OR key = ANY($3)) AND NOT (key = ANY($4))
          RETURNING id",
    )
    .bind(p.id)
    .bind(agent_id)
    .bind(keys)
    .bind(keep)
    .fetch_all(&st.db)
    .await?;
    announce(st, &ids, "resolved", &p.channel_ids, p.notify_resolved).await;
    Ok(())
}

/// A policy was edited, disabled or deleted: close its alerts on agents it no longer covers
/// (all of them if it's gone or disabled), quietly, then re-check what can be re-checked now.
pub async fn policy_changed(st: &Arc<AppState>, policy_id: Uuid) {
    let res: sqlx::Result<Vec<Uuid>> = sqlx::query_scalar(AssertSqlSafe(format!(
        "UPDATE alerts al SET resolved_at = now(), resolution = 'policy'
          WHERE al.policy_id = $1 AND al.resolved_at IS NULL
            AND NOT EXISTS (SELECT 1 FROM alert_policies p, agents a JOIN sites s ON s.id = a.site_id
                             WHERE p.id = $1 AND p.enabled AND a.id = al.agent_id
                               AND {})
          RETURNING al.id",
        scope_sql_policy()
    )))
    .bind(policy_id)
    .fetch_all(&st.db)
    .await;
    match res {
        Ok(ids) => announce(st, &ids, "resolved", &[], false).await,
        Err(e) => warn!(policy = %policy_id, "closing alerts of a changed policy: {e}"),
    }
    // None: disabled or deleted, and it may have been a log policy.
    match load_policy(st, policy_id).await.ok().flatten().as_ref().map(|p| p.kind.as_str()) {
        Some("service") => {
            let st = st.clone();
            tokio::spawn(async move { recheck_services(&st, policy_id).await });
        }
        Some("log") | None => push_watchers(st).await,
        _ => {}
    }
}

/// The policy `p`'s scope against agent `a` / site `s`, without binds.
fn scope_sql_policy() -> &'static str {
    "(p.client_id IS NULL OR p.client_id = s.client_id) AND (p.site_id IS NULL OR p.site_id = a.site_id)
     AND (p.os_family IS NULL OR p.os_family = a.os_family)"
}

// ---------------------------------------------------------------------------
// Polled checks
// ---------------------------------------------------------------------------

pub async fn run(st: Arc<AppState>) {
    let every = Duration::from_secs(st.cfg.alert_eval_secs.max(5).into());
    let mut tick = tokio::time::interval(every);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        if let Err(e) = evaluate(&st).await {
            warn!("alert evaluation: {e}");
        }
    }
}

async fn evaluate(st: &AppState) -> sqlx::Result<()> {
    let policies: Vec<Policy> = sqlx::query_as(AssertSqlSafe(format!(
        "SELECT {POLICY_COLS} FROM alert_policies p WHERE p.enabled AND p.kind IN ('offline', 'cpu', 'memory', 'disk')"
    )))
    .fetch_all(&st.db)
    .await?;
    for p in &policies {
        let res = match p.rule() {
            Some(Rule::Offline { minutes }) => check_offline(st, p, minutes).await,
            Some(Rule::Cpu(t)) => check_threshold(st, p, "m.cpu_percent", "CPU", &t).await,
            Some(Rule::Memory(t)) => check_threshold(st, p, "100.0 * m.mem_used / nullif(m.mem_total, 0)", "Memory", &t).await,
            Some(Rule::Disk(t)) => check_threshold(st, p, "m.disk_max_pct", "Disk", &t).await,
            _ => Ok(()),
        };
        if let Err(e) = res {
            warn!(policy = %p.id, "checking {}: {e}", p.name);
        }
    }
    Ok(())
}

async fn check_offline(st: &AppState, p: &Policy, minutes: i32) -> sqlx::Result<()> {
    // Count from when this server started too: after downtime, agents need a moment to
    // reconnect, and their last_seen_at is old through no fault of their own.
    let opened: Vec<Uuid> = sqlx::query_scalar(AssertSqlSafe(format!(
        "INSERT INTO alerts (id, policy_id, agent_id, key, kind, severity, title, details)
         SELECT gen_random_uuid(), $1, a.id, '', 'offline', $2, format('Offline for more than %s minutes', $3::int),
                jsonb_build_object('last_seen_at', a.last_seen_at, 'minutes', $3::int)
           FROM agents a JOIN sites s ON s.id = a.site_id
          WHERE NOT a.online AND {}
            AND greatest(coalesce(a.last_seen_at, a.enrolled_at), $4) < now() - make_interval(mins => $3)
         ON CONFLICT (policy_id, agent_id, key) WHERE resolved_at IS NULL DO NOTHING
         RETURNING id",
        scope_sql(5)
    )))
    .bind(p.id)
    .bind(&p.severity)
    .bind(minutes)
    .bind(st.started_at)
    .bind(p.client_id)
    .bind(p.site_id)
    .bind(&p.os_family)
    .fetch_all(&st.db)
    .await?;
    announce(st, &opened, "opened", &p.channel_ids, true).await;

    let cleared: Vec<Uuid> = sqlx::query_scalar(AssertSqlSafe(format!(
        "UPDATE alerts al SET resolved_at = now(), resolution = 'cleared'
          WHERE al.policy_id = $1 AND al.resolved_at IS NULL
            AND NOT EXISTS (SELECT 1 FROM agents a JOIN sites s ON s.id = a.site_id WHERE a.id = al.agent_id AND NOT a.online AND {})
          RETURNING al.id",
        scope_sql(2)
    )))
    .bind(p.id)
    .bind(p.client_id)
    .bind(p.site_id)
    .bind(&p.os_family)
    .fetch_all(&st.db)
    .await?;
    announce(st, &cleared, "resolved", &p.channel_ids, p.notify_resolved).await;
    Ok(())
}

/// Opens when every sample in the last `minutes` is at or above the threshold (and the
/// samples span the window); clears when the last few minutes are all below it.
async fn check_threshold(st: &AppState, p: &Policy, expr: &str, label: &str, t: &Threshold) -> sqlx::Result<()> {
    // Allow for heartbeat spacing at the start of the window.
    let slack_secs = (t.minutes * 30).min(90);
    let opened: Vec<(Uuid, bool)> = sqlx::query_as(AssertSqlSafe(format!(
        "WITH w AS (
            SELECT m.agent_id, min({expr}) AS lo, avg({expr}) AS av, min(m.ts) AS first
              FROM agent_metrics m JOIN agents a ON a.id = m.agent_id JOIN sites s ON s.id = a.site_id
             WHERE m.ts > now() - make_interval(mins => $3) AND a.online AND {scope}
             GROUP BY 1)
         INSERT INTO alerts (id, policy_id, agent_id, key, kind, severity, title, details)
         SELECT gen_random_uuid(), $1, w.agent_id, '', $6, $2,
                format('%s at or above %s%% for %s minutes', $5::text, round($4::numeric, 1), $3::int),
                jsonb_build_object('value', round(w.av::numeric, 1), 'threshold', $4::float8, 'minutes', $3::int)
           FROM w
          WHERE w.lo >= $4 AND w.first <= now() - make_interval(mins => $3) + make_interval(secs => $7)
         ON CONFLICT (policy_id, agent_id, key) WHERE resolved_at IS NULL
         DO UPDATE SET last_seen_at = now(), details = EXCLUDED.details
         RETURNING id, (xmax = 0)",
        scope = scope_sql(8),
    )))
    .bind(p.id)
    .bind(&p.severity)
    .bind(t.minutes)
    .bind(t.threshold)
    .bind(label)
    .bind(&p.kind)
    .bind(slack_secs as f64)
    .bind(p.client_id)
    .bind(p.site_id)
    .bind(&p.os_family)
    .fetch_all(&st.db)
    .await?;
    let opened: Vec<Uuid> = opened.into_iter().filter(|(_, new)| *new).map(|(id, _)| id).collect();
    announce(st, &opened, "opened", &p.channel_ids, true).await;

    let cleared: Vec<Uuid> = sqlx::query_scalar(AssertSqlSafe(format!(
        "UPDATE alerts al SET resolved_at = now(), resolution = 'cleared'
          WHERE al.policy_id = $1 AND al.resolved_at IS NULL
            AND (NOT EXISTS (SELECT 1 FROM agents a JOIN sites s ON s.id = a.site_id WHERE a.id = al.agent_id AND {scope})
                 OR (SELECT max({expr}) FROM agent_metrics m
                      WHERE m.agent_id = al.agent_id AND m.ts > now() - make_interval(mins => least($2, 5))) < $3)
          RETURNING al.id",
        scope = scope_sql(4),
    )))
    .bind(p.id)
    .bind(t.minutes)
    .bind(t.threshold)
    .bind(p.client_id)
    .bind(p.site_id)
    .bind(&p.os_family)
    .fetch_all(&st.db)
    .await?;
    announce(st, &cleared, "resolved", &p.channel_ids, p.notify_resolved).await;
    Ok(())
}

// ---------------------------------------------------------------------------
// Event-driven checks
// ---------------------------------------------------------------------------

/// The agent reconnected: its offline alerts clear now rather than at the next check.
pub async fn agent_online(st: &AppState, agent_id: Uuid) {
    let res: sqlx::Result<()> = async {
        for p in policies_for(st, agent_id, "offline").await? {
            clear(st, &p, agent_id, None, &[]).await?;
        }
        // Policies that stopped covering the agent still own alerts on it.
        let stale: Vec<(Uuid, Vec<Uuid>, bool)> = sqlx::query_as(
            "UPDATE alerts al SET resolved_at = now(), resolution = 'cleared'
               FROM alert_policies p
              WHERE p.id = al.policy_id AND al.agent_id = $1 AND al.kind = 'offline' AND al.resolved_at IS NULL
              RETURNING al.id, p.channel_ids, p.notify_resolved",
        )
        .bind(agent_id)
        .fetch_all(&st.db)
        .await?;
        for (id, channels, notify) in stale {
            announce(st, &[id], "resolved", &channels, notify).await;
        }
        Ok(())
    }
    .await;
    if let Err(e) = res {
        warn!(%agent_id, "clearing offline alerts: {e}");
    }
}

/// A job finished (`status` as stored). Failures open an alert per script; the next success
/// of the same script clears it.
pub async fn job_finished(st: &AppState, agent_id: Uuid, job_id: Uuid, status: &str) {
    let res: sqlx::Result<()> = async {
        let policies = policies_for(st, agent_id, "job_failed").await?;
        if policies.is_empty() {
            return Ok(());
        }
        let (script_id, script_name, exit_code, interpreter): (Option<Uuid>, Option<String>, Option<i32>, String) = sqlx::query_as(
            "SELECT j.script_id, sc.name, j.exit_code, j.interpreter FROM jobs j LEFT JOIN scripts sc ON sc.id = j.script_id WHERE j.id = $1",
        )
        .bind(job_id)
        .fetch_one(&st.db)
        .await?;
        let key = script_id.map(|s| s.to_string()).unwrap_or_else(|| "adhoc".into());
        let failed = crate::api::JOB_FAILED.contains(&status);
        for p in &policies {
            let Some(Rule::JobFailed { script_id: want }) = p.rule() else { continue };
            if want.is_some_and(|w| Some(w) != script_id) {
                continue;
            }
            if failed {
                let name = script_name.clone().unwrap_or_else(|| format!("ad-hoc {interpreter}"));
                let title = format!("Job failed: {name}");
                let details = json!({ "job_id": job_id, "status": status, "exit_code": exit_code, "script": name });
                fire(st, p, agent_id, &key, &title, details, 1).await?;
            } else if status == "succeeded" {
                clear(st, p, agent_id, Some(std::slice::from_ref(&key)), &[]).await?;
            }
        }
        Ok(())
    }
    .await;
    if let Err(e) = res {
        warn!(%agent_id, %job_id, "job alert: {e}");
    }
}

/// `pattern` against `name`, case-insensitively. `*` matches any run of characters, and a
/// pattern without a dot also matches `<pattern>.service`.
pub fn service_matches(pattern: &str, name: &str) -> bool {
    fn glob(p: &[u8], s: &[u8]) -> bool {
        match (p.first(), s.first()) {
            (None, None) => true,
            (Some(b'*'), _) => glob(&p[1..], s) || (!s.is_empty() && glob(p, &s[1..])),
            (Some(a), Some(b)) if a.eq_ignore_ascii_case(b) => glob(&p[1..], &s[1..]),
            _ => false,
        }
    }
    let (p, n) = (pattern.trim().as_bytes(), name.as_bytes());
    glob(p, n) || (!pattern.contains('.') && name.strip_suffix(".service").is_some_and(|base| glob(p, base.as_bytes())))
}

/// The watched services that are down: `(name, title, details)`.
pub fn down_services(rule: &ServiceRule, services: &[ServiceInfo]) -> Vec<(String, String, Value)> {
    services
        .iter()
        .filter(|s| {
            let watched = (rule.auto_only && s.start_mode == StartMode::Auto) || rule.services.iter().any(|p| service_matches(p, &s.name));
            watched
                && !rule.exclude.iter().any(|p| service_matches(p, &s.name))
                && matches!(s.state, ServiceState::Stopped | ServiceState::Failed)
        })
        .map(|s| {
            let label = if s.display_name.is_empty() { s.name.clone() } else { s.display_name.clone() };
            let verb = if s.state == ServiceState::Failed { "failed" } else { "stopped" };
            (
                s.name.clone(),
                format!("Service {verb}: {label}"),
                json!({ "service": s.name, "display_name": s.display_name, "state": s.state.as_str() }),
            )
        })
        .collect()
}

async fn check_services(st: &AppState, p: &Policy, agent_id: Uuid, services: &[ServiceInfo]) -> sqlx::Result<()> {
    let Some(Rule::Service(rule)) = p.rule() else { return Ok(()) };
    let down = down_services(&rule, services);
    let keep: Vec<String> = down.iter().map(|d| d.0.clone()).collect();
    for (key, title, details) in down {
        fire(st, p, agent_id, &key, &title, details, 0).await?;
    }
    clear(st, p, agent_id, None, &keep).await
}

/// The agent reported its services (only sent when something changed).
pub async fn services_reported(st: &AppState, agent_id: Uuid, services: &[ServiceInfo]) {
    let res: sqlx::Result<()> = async {
        for p in policies_for(st, agent_id, "service").await? {
            check_services(st, &p, agent_id, services).await?;
        }
        Ok(())
    }
    .await;
    if let Err(e) = res {
        warn!(%agent_id, "service alerts: {e}");
    }
}

/// A service policy changed: check it against every covered agent's last report.
async fn recheck_services(st: &AppState, policy_id: Uuid) {
    let Ok(Some(p)) = load_policy(st, policy_id).await else { return };
    let rows: sqlx::Result<Vec<(Uuid, Value)>> = sqlx::query_as(AssertSqlSafe(format!(
        "SELECT a.id, a.services FROM agents a JOIN sites s ON s.id = a.site_id WHERE a.services IS NOT NULL AND {}",
        scope_sql(1)
    )))
    .bind(p.client_id)
    .bind(p.site_id)
    .bind(&p.os_family)
    .fetch_all(&st.db)
    .await;
    for (agent_id, services) in rows.unwrap_or_default() {
        let services: Vec<ServiceInfo> = serde_json::from_value(services).unwrap_or_default();
        if let Err(e) = check_services(st, &p, agent_id, &services).await {
            warn!(%agent_id, "service alerts: {e}");
        }
    }
}

/// Log entries matched the watcher of policy `policy_id`.
pub async fn log_matched(st: &AppState, agent_id: Uuid, policy_id: Uuid, entries: Vec<LogEntry>, suppressed: u32) {
    let res: sqlx::Result<()> = async {
        // The agent may still run a watcher for a policy that was just changed or removed.
        let Some(p) = policies_for(st, agent_id, "log").await?.into_iter().find(|p| p.id == policy_id) else {
            debug!(%agent_id, %policy_id, "log match for a policy that no longer covers this agent");
            return Ok(());
        };
        let entries: Vec<LogEntry> = entries.into_iter().take(100).collect();
        let total = entries.len() as i32 + suppressed.min(i32::MAX as u32) as i32;
        if total == 0 {
            return Ok(());
        }
        let last = entries.last();
        let details = json!({
            "source": last.map(|e| e.source.as_str()),
            "event_id": last.and_then(|e| e.event_id),
            "level": last.map(|e| e.level.as_str()),
            "message": last.map(|e| e.message.chars().take(1000).collect::<String>()),
            "suppressed": suppressed,
        });
        fire(st, &p, agent_id, "", &format!("Log match: {}", p.name), details, total).await?;
        let alert_id: Option<Uuid> =
            sqlx::query_scalar("SELECT id FROM alerts WHERE policy_id = $1 AND agent_id = $2 AND key = '' AND resolved_at IS NULL")
                .bind(p.id)
                .bind(agent_id)
                .fetch_optional(&st.db)
                .await?;
        for e in &entries {
            sqlx::query(
                "INSERT INTO log_events (agent_id, policy_id, alert_id, ts, level, source, event_id, message)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
            )
            .bind(agent_id)
            .bind(p.id)
            .bind(alert_id)
            .bind(e.ts.min(Utc::now()))
            .bind(e.level.as_str())
            .bind(e.source.chars().take(256).collect::<String>())
            .bind(e.event_id.map(|i| i as i32))
            .bind(e.message.chars().take(rmm_proto::LOG_MESSAGE_MAX).collect::<String>())
            .execute(&st.db)
            .await?;
        }
        Ok(())
    }
    .await;
    if let Err(e) = res {
        warn!(%agent_id, "log alert: {e}");
    }
}

// ---------------------------------------------------------------------------
// Log watcher distribution
// ---------------------------------------------------------------------------

fn watcher(p: &Policy) -> Option<LogWatcher> {
    let Some(Rule::Log(l)) = p.rule() else { return None };
    Some(LogWatcher {
        id: p.id,
        channels: l.channels,
        sources: l.sources,
        event_ids: l.event_ids,
        min_level: l.min_level,
        pattern: l.pattern.filter(|p| !p.is_empty()),
    })
}

/// The watchers an agent should run.
pub async fn watchers_for(st: &AppState, agent_id: Uuid) -> Vec<LogWatcher> {
    match policies_for(st, agent_id, "log").await {
        Ok(ps) => ps.iter().filter_map(watcher).collect(),
        Err(e) => {
            warn!(%agent_id, "loading log watchers: {e}");
            vec![]
        }
    }
}

/// Re-sends every online agent its watcher set (after a log policy changed).
pub async fn push_watchers(st: &AppState) {
    let res: sqlx::Result<()> = async {
        let policies: Vec<Policy> =
            sqlx::query_as(AssertSqlSafe(format!("SELECT {POLICY_COLS} FROM alert_policies p WHERE p.enabled AND p.kind = 'log'")))
                .fetch_all(&st.db)
                .await?;
        let agents: Vec<(Uuid, Uuid, Uuid, String)> = sqlx::query_as(
            "SELECT a.id, s.client_id, a.site_id, a.os_family FROM agents a JOIN sites s ON s.id = a.site_id WHERE a.online",
        )
        .fetch_all(&st.db)
        .await?;
        for (agent_id, client_id, site_id, os) in agents {
            let watchers = policies.iter().filter(|p| p.covers(client_id, site_id, &os)).filter_map(watcher).collect();
            st.hub.send(agent_id, ServerMsg::Watchers { watchers }).await;
        }
        Ok(())
    }
    .await;
    if let Err(e) = res {
        warn!("pushing log watchers: {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn svc(name: &str, state: ServiceState, start_mode: StartMode) -> ServiceInfo {
        ServiceInfo { name: name.into(), display_name: String::new(), state, start_mode }
    }

    #[test]
    fn rules_round_trip_and_validate() {
        let r = Rule::parse("cpu", &json!({ "threshold": 90, "minutes": 10 })).unwrap();
        assert_eq!(r, Rule::Cpu(Threshold { threshold: 90.0, minutes: 10 }));
        assert_eq!(r.params(), json!({ "threshold": 90.0, "minutes": 10 }));
        assert!(Rule::parse("cpu", &json!({ "threshold": 90 })).is_err());
        assert!(Rule::parse("nope", &json!({})).is_err());
        assert!(Rule::Cpu(Threshold { threshold: 150.0, minutes: 5 }).validate().is_err());
        assert!(Rule::Service(ServiceRule::default()).validate().is_err());
        let log = Rule::parse("log", &json!({ "min_level": "error", "pattern": "(" })).unwrap();
        assert!(log.validate().is_err(), "bad regex is rejected");
        assert_eq!(Rule::parse("job_failed", &json!({})).unwrap(), Rule::JobFailed { script_id: None });
    }

    #[test]
    fn service_patterns() {
        assert!(service_matches("nginx", "nginx.service"));
        assert!(service_matches("NGINX.service", "nginx.service"));
        assert!(service_matches("php*-fpm", "php8.2-fpm.service"));
        assert!(service_matches("Spool*", "Spooler"));
        assert!(!service_matches("nginx", "nginx-debug.service"));
        assert!(!service_matches("ssh", "sshd.service"));
    }

    #[test]
    fn down_services_respects_auto_and_exclude() {
        let list = [
            svc("nginx.service", ServiceState::Failed, StartMode::Auto),
            svc("cron.service", ServiceState::Running, StartMode::Auto),
            svc("backup.service", ServiceState::Stopped, StartMode::Auto),
            svc("manual.service", ServiceState::Stopped, StartMode::Manual),
            svc("starting.service", ServiceState::Starting, StartMode::Auto),
        ];
        let rule = ServiceRule { auto_only: true, exclude: vec!["backup".into()], ..Default::default() };
        let down: Vec<String> = down_services(&rule, &list).into_iter().map(|d| d.0).collect();
        assert_eq!(down, ["nginx.service"]);
        let rule = ServiceRule { services: vec!["manual".into(), "cron".into()], ..Default::default() };
        let down = down_services(&rule, &list);
        assert_eq!(down.len(), 1);
        assert_eq!(down[0].1, "Service stopped: manual.service");
    }
}
