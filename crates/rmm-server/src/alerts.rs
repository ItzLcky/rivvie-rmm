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

use chrono::{DateTime, Utc};
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

/// Which detections raise alerts.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreatAlerts {
    Off,
    /// One alert per active threat, cleared when the product deals with it.
    #[default]
    Active,
    /// Every new detection, even one the product already quarantined or blocked. These
    /// stay open until someone resolves them.
    Any,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SecurityRule {
    /// No antivirus product is enabled.
    #[serde(default)]
    pub unprotected: bool,
    /// Products are enabled but none scans files as they're opened.
    #[serde(default)]
    pub realtime_off: bool,
    /// Every enabled product's signatures are older than this. None = don't check.
    #[serde(default)]
    pub signature_max_age_hours: Option<i32>,
    #[serde(default)]
    pub threats: ThreatAlerts,
    /// The policy runs our sensor here, but it isn't running (crashed, keeps restarting, or
    /// was stopped).
    #[serde(default)]
    pub sensor_down: bool,
    /// The agent is online but hasn't reported its protection state for this long.
    #[serde(default)]
    pub stale_hours: Option<i32>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PatchRule {
    /// Updates whose last install failed (and that nobody declined since).
    #[serde(default = "yes")]
    pub failed: bool,
    /// A restart has been pending for this long. None = don't check.
    #[serde(default)]
    pub reboot_hours: Option<i32>,
}

fn yes() -> bool {
    true
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
    Security(SecurityRule),
    Patch(PatchRule),
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
            Rule::Security(_) => "security",
            Rule::Patch(_) => "patch",
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
            Rule::Security(r) => {
                if r.signature_max_age_hours.is_some_and(|h| !(1..=8760).contains(&h)) {
                    return Err("signature age must be 1-8760 hours".into());
                }
                if r.stale_hours.is_some_and(|h| !(2..=168).contains(&h)) {
                    return Err("the reporting limit must be 2-168 hours".into());
                }
                if !r.unprotected
                    && !r.realtime_off
                    && r.signature_max_age_hours.is_none()
                    && r.threats == ThreatAlerts::Off
                    && !r.sensor_down
                    && r.stale_hours.is_none()
                {
                    return Err("pick at least one thing to alert on".into());
                }
                Ok(())
            }
            Rule::Patch(r) => {
                if r.reboot_hours.is_some_and(|h| !(1..=8760).contains(&h)) {
                    return Err("restart pending must be 1-8760 hours".into());
                }
                if !r.failed && r.reboot_hours.is_none() {
                    return Err("pick at least one thing to alert on".into());
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
    pub excluded_agents: Vec<Uuid>,
}

pub const POLICY_COLS: &str =
    "p.id, p.name, p.kind, p.params, p.severity, p.client_id, p.site_id, p.os_family, p.channel_ids, p.notify_resolved, p.excluded_agents";

impl Policy {
    fn rule(&self) -> Option<Rule> {
        Rule::parse(&self.kind, &self.params).inspect_err(|e| warn!(policy = %self.id, "{e}")).ok()
    }

    fn covers(&self, agent_id: Uuid, client_id: Uuid, site_id: Uuid, os: &str) -> bool {
        !self.excluded_agents.contains(&agent_id)
            && self.client_id.is_none_or(|c| c == client_id)
            && self.site_id.is_none_or(|s| s == site_id)
            && self.os_family.as_deref().is_none_or(|o| o == os)
    }
}

/// `$n` client, `$n+1` site, `$n+2` OS, `$n+3` excluded agents: the agents (`a`, site `s`)
/// a policy covers.
fn scope_sql(n: usize) -> String {
    format!(
        "(${n}::uuid IS NULL OR s.client_id = ${n}) AND (${m}::uuid IS NULL OR a.site_id = ${m}) AND (${o}::text IS NULL OR a.os_family = ${o})
         AND NOT (a.id = ANY(${x}::uuid[]))",
        m = n + 1,
        o = n + 2,
        x = n + 3
    )
}

/// Enabled policies of one kind that cover this agent.
async fn policies_for(st: &AppState, agent_id: Uuid, kind: &str) -> sqlx::Result<Vec<Policy>> {
    sqlx::query_as(AssertSqlSafe(format!(
        "SELECT {POLICY_COLS} FROM alert_policies p, agents a JOIN sites s ON s.id = a.site_id
          WHERE a.id = $1 AND p.enabled AND p.kind = $2
            AND (p.client_id IS NULL OR p.client_id = s.client_id) AND (p.site_id IS NULL OR p.site_id = a.site_id)
            AND (p.os_family IS NULL OR p.os_family = a.os_family) AND NOT (a.id = ANY(p.excluded_agents))"
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
/// `notify` is false. Alerts held back by a mute (`suppressed`) only get the live event: they
/// are announced properly if they're still open when the mute ends ([`unsuppress`]).
async fn announce(st: &AppState, ids: &[Uuid], event: &'static str, channels: &[Uuid], notify: bool) {
    if ids.is_empty() {
        return;
    }
    let rows: Vec<(Uuid, Uuid, Uuid, bool)> = match sqlx::query_as(
        "SELECT al.id, al.agent_id, s.client_id, al.suppressed FROM alerts al JOIN agents a ON a.id = al.agent_id
           JOIN sites s ON s.id = a.site_id
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
    let mut woke = false;
    for (id, agent_id, client_id, suppressed) in rows {
        st.hub.publish(Event::Alert { id, agent_id, client_id, state: state.into() });
        if suppressed {
            continue;
        }
        if notify {
            crate::notify::enqueue(st, id, event, channels).await;
            woke |= !channels.is_empty();
        }
        // Tickets follow the alert even when notifications are off.
        if event == "opened" {
            crate::tickets::alert_opened(st, id).await;
        } else {
            crate::tickets::alert_resolved(st, id).await;
        }
    }
    if woke {
        st.notify_wake.notify_one();
    }
}

/// Alerts held back by a mute that has ended and are still open: announce them now.
pub async fn unsuppress(st: &AppState) -> sqlx::Result<()> {
    let rows: Vec<(Uuid, Option<Uuid>)> = sqlx::query_as(
        "UPDATE alerts SET suppressed = false, last_notified_at = now()
          WHERE suppressed AND resolved_at IS NULL AND NOT agent_muted(agent_id, now())
          RETURNING id, policy_id",
    )
    .fetch_all(&st.db)
    .await?;
    for (id, policy_id) in rows {
        let channels = match policy_id {
            Some(pid) => sqlx::query_scalar("SELECT channel_ids FROM alert_policies WHERE id = $1")
                .bind(pid)
                .fetch_optional(&st.db)
                .await?
                .unwrap_or_default(),
            None => vec![],
        };
        info!(alert = %id, "mute ended with the alert still open");
        announce(st, &[id], "opened", &channels, true).await;
    }
    Ok(())
}

/// Open, unacknowledged alerts whose policy asks for reminders: notify again.
async fn remind(st: &AppState) -> sqlx::Result<()> {
    let rows: Vec<(Uuid, Vec<Uuid>)> = sqlx::query_as(
        "UPDATE alerts al SET last_notified_at = now()
           FROM alert_policies p
          WHERE p.id = al.policy_id AND p.renotify_minutes IS NOT NULL AND p.enabled
            AND al.resolved_at IS NULL AND al.acknowledged_at IS NULL AND NOT al.suppressed
            AND coalesce(al.last_notified_at, al.opened_at) < now() - make_interval(mins => p.renotify_minutes)
            AND NOT agent_muted(al.agent_id, now())
          RETURNING al.id, p.channel_ids",
    )
    .fetch_all(&st.db)
    .await?;
    let mut woke = false;
    for (id, channels) in &rows {
        crate::notify::enqueue(st, *id, "reminder", channels).await;
        woke |= !channels.is_empty();
    }
    if woke {
        st.notify_wake.notify_one();
    }
    Ok(())
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
        Some("security") => {
            let st = st.clone();
            tokio::spawn(async move { recheck_security(&st, policy_id).await });
        }
        Some("patch") => {
            let st = st.clone();
            tokio::spawn(async move { recheck_patches(&st, policy_id).await });
        }
        Some("log") | None => push_watchers(st).await,
        _ => {}
    }
}

/// The policy `p`'s scope against agent `a` / site `s`, without binds.
fn scope_sql_policy() -> &'static str {
    "(p.client_id IS NULL OR p.client_id = s.client_id) AND (p.site_id IS NULL OR p.site_id = a.site_id)
     AND (p.os_family IS NULL OR p.os_family = a.os_family) AND NOT (a.id = ANY(p.excluded_agents))"
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
        "SELECT {POLICY_COLS} FROM alert_policies p WHERE p.enabled AND p.kind IN ('offline', 'cpu', 'memory', 'disk', 'security', 'patch')"
    )))
    .fetch_all(&st.db)
    .await?;
    for p in &policies {
        let res = match p.rule() {
            Some(Rule::Offline { minutes }) => check_offline(st, p, minutes).await,
            Some(Rule::Cpu(t)) => check_threshold(st, p, "m.cpu_percent", "CPU", &t).await,
            Some(Rule::Memory(t)) => check_threshold(st, p, "100.0 * m.mem_used / nullif(m.mem_total, 0)", "Memory", &t).await,
            Some(Rule::Disk(t)) => check_threshold(st, p, "m.disk_max_pct", "Disk", &t).await,
            Some(Rule::Security(r)) => {
                // Signatures age, and reports stop, without the agent sending anything new.
                let mut res = Ok(());
                if let Some(h) = r.signature_max_age_hours {
                    res = check_signatures(st, p, h).await;
                }
                if let (Ok(()), Some(h)) = (&res, r.stale_hours) {
                    res = check_stale_security(st, p, h).await;
                }
                res
            }
            Some(Rule::Patch(PatchRule { reboot_hours: Some(h), .. })) => check_reboot(st, p, h).await,
            _ => Ok(()),
        };
        if let Err(e) = res {
            warn!(policy = %p.id, "checking {}: {e}", p.name);
        }
    }
    unsuppress(st).await?;
    remind(st).await
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
    .bind(&p.excluded_agents)
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
    .bind(&p.excluded_agents)
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
    .bind(&p.excluded_agents)
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
    .bind(&p.excluded_agents)
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
    .bind(&p.excluded_agents)
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
// Endpoint protection
// ---------------------------------------------------------------------------

/// A product as the security checks see it (a `security_products` row).
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ProductState {
    pub name: String,
    pub enabled: Option<bool>,
    pub realtime: Option<bool>,
    pub signatures_updated_at: Option<DateTime<Utc>>,
    pub signatures_current: Option<bool>,
}

/// A `security_detections` row.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct DetectionState {
    pub id: Uuid,
    pub product: String,
    pub name: String,
    pub severity: String,
    pub status: String,
    pub resources: Vec<String>,
    pub detected_at: Option<DateTime<Utc>>,
}

/// When an agent last reported its protection state, for the "stopped reporting" check.
#[derive(Debug, Clone, Default)]
pub struct Reporting {
    pub online: bool,
    pub reported_at: Option<DateTime<Utc>>,
    /// When its connection started: a fresh connection gets time to report.
    pub connected_at: Option<DateTime<Utc>>,
}

impl Reporting {
    /// The last report (if any) when it's older than `hours` on an online agent.
    pub fn stale_since(&self, hours: i32, now: DateTime<Utc>) -> Option<Option<DateTime<Utc>>> {
        let latest = self.reported_at.max(self.connected_at)?;
        (self.online && latest < now - chrono::Duration::hours(hours.into())).then_some(self.reported_at)
    }
}

/// Up-to-date signatures, as SQL on `sp` (security_products) with the age in hours at `$n`.
/// Products without a date go by Security Center's verdict, else count as current.
fn fresh_sql(n: usize) -> String {
    format!("coalesce(sp.signatures_updated_at > now() - make_interval(hours => ${n}), sp.signatures_current, true)")
}

fn fresh(p: &ProductState, max_age_hours: i32, now: DateTime<Utc>) -> bool {
    match (p.signatures_updated_at, p.signatures_current) {
        (Some(t), _) => t > now - chrono::Duration::hours(max_age_hours.into()),
        (None, Some(current)) => current,
        (None, None) => true,
    }
}

/// What a security policy finds on one agent: `(key, title, details)`. `new` are
/// detections first seen in the report being checked.
#[allow(clippy::too_many_arguments)]
pub fn security_findings(
    rule: &SecurityRule,
    products: &[ProductState],
    detections: &[DetectionState],
    new: &[Uuid],
    sensor: Option<&Value>,
    reporting: &Reporting,
    now: DateTime<Utc>,
) -> Vec<(String, String, Value)> {
    let enabled: Vec<&ProductState> = products.iter().filter(|p| p.enabled == Some(true)).collect();
    let all_names: Vec<&str> = products.iter().map(|p| p.name.as_str()).collect();
    let mut out = Vec::new();
    if let Some(h) = rule.stale_hours
        && let Some(since) = reporting.stale_since(h, now)
    {
        out.push(("stale".into(), "Protection state not reported".into(), json!({ "last_report": since, "hours": h })));
    }
    if rule.unprotected && enabled.is_empty() {
        out.push(("unprotected".into(), "No active antivirus".into(), json!({ "products": all_names })));
    }
    if rule.realtime_off && !enabled.is_empty() && enabled.iter().all(|p| p.realtime == Some(false)) {
        let names: Vec<&str> = enabled.iter().map(|p| p.name.as_str()).collect();
        out.push(("realtime".into(), "Real-time protection is off".into(), json!({ "products": names })));
    }
    if let Some(h) = rule.signature_max_age_hours
        && !enabled.is_empty()
        && !enabled.iter().any(|p| fresh(p, h, now))
    {
        let newest = enabled.iter().filter_map(|p| p.signatures_updated_at).max();
        out.push(("signatures".into(), "Antivirus signatures out of date".into(), json!({ "newest": newest, "max_age_hours": h })));
    }
    if rule.sensor_down
        && let Some(s) = sensor
        && s.get("enabled").and_then(Value::as_bool) == Some(true)
    {
        let running = s.get("running").and_then(Value::as_bool) == Some(true);
        let restarts = s.get("restarts").and_then(Value::as_u64).unwrap_or(0);
        if !running || restarts >= 3 {
            let title = if running { "Sensor keeps restarting" } else { "Sensor not running" };
            out.push(("sensor".into(), title.into(), json!({ "restarts": restarts, "error": s.get("error") })));
        }
    }
    for d in detections {
        let active = d.status == "active";
        let recent_new = new.contains(&d.id) && d.detected_at.is_none_or(|t| now - t < chrono::Duration::hours(24));
        let raise = match rule.threats {
            ThreatAlerts::Off => false,
            ThreatAlerts::Active => active,
            ThreatAlerts::Any => active || recent_new,
        };
        if !raise {
            continue;
        }
        let verb = match d.status.as_str() {
            "quarantined" => "quarantined",
            "removed" => "removed",
            "blocked" => "blocked",
            "allowed" => "allowed",
            _ => "detected",
        };
        out.push((
            format!("threat:{}", d.id),
            format!("Threat {verb}: {}", d.name),
            json!({
                "detection_id": d.id, "product": d.product, "name": d.name, "severity": d.severity,
                "status": d.status, "resources": d.resources.iter().take(5).collect::<Vec<_>>(),
            }),
        ));
    }
    out
}

async fn check_security(st: &AppState, p: &Policy, agent_id: Uuid, new: &[Uuid]) -> sqlx::Result<()> {
    let Some(Rule::Security(rule)) = p.rule() else { return Ok(()) };
    let reported: bool = sqlx::query_scalar("SELECT security_at IS NOT NULL FROM agents WHERE id = $1")
        .bind(agent_id)
        .fetch_optional(&st.db)
        .await?
        .unwrap_or(false);
    if !reported {
        return Ok(());
    }
    let products: Vec<ProductState> = sqlx::query_as(
        "SELECT name, enabled, realtime, signatures_updated_at, signatures_current FROM security_products WHERE agent_id = $1",
    )
    .bind(agent_id)
    .fetch_all(&st.db)
    .await?;
    let detections: Vec<DetectionState> = sqlx::query_as(
        "SELECT id, product, name, severity, status, resources, detected_at FROM security_detections
          WHERE agent_id = $1 AND NOT audit AND ((resolved_at IS NULL AND status = 'active') OR id = ANY($2))",
    )
    .bind(agent_id)
    .bind(new)
    .fetch_all(&st.db)
    .await?;
    type Row = (Option<Value>, bool, Option<DateTime<Utc>>, Option<DateTime<Utc>>);
    let (sensor, online, reported_at, connected_at): Row =
        sqlx::query_as("SELECT sensor, online, security_at, connected_at FROM agents WHERE id = $1").bind(agent_id).fetch_one(&st.db).await?;
    let reporting = Reporting { online, reported_at, connected_at };
    let findings = security_findings(&rule, &products, &detections, new, sensor.as_ref(), &reporting, Utc::now());
    let keep: Vec<String> = findings.iter().map(|f| f.0.clone()).collect();
    for (key, title, details) in findings {
        fire(st, p, agent_id, &key, &title, details, 0).await?;
    }
    // Whatever no longer holds clears. Under `any`, threat alerts wait for a person.
    let ids: Vec<Uuid> = sqlx::query_scalar(
        "UPDATE alerts SET resolved_at = now(), resolution = 'cleared'
          WHERE policy_id = $1 AND agent_id = $2 AND resolved_at IS NULL AND NOT (key = ANY($3))
            AND ($4 OR key NOT LIKE 'threat:%')
          RETURNING id",
    )
    .bind(p.id)
    .bind(agent_id)
    .bind(&keep)
    .bind(rule.threats != ThreatAlerts::Any)
    .fetch_all(&st.db)
    .await?;
    announce(st, &ids, "resolved", &p.channel_ids, p.notify_resolved).await;
    Ok(())
}

/// The agent reported its protection state; `new` are detections seen for the first time.
pub async fn security_reported(st: &AppState, agent_id: Uuid, new: &[Uuid]) {
    let res: sqlx::Result<()> = async {
        for p in policies_for(st, agent_id, "security").await? {
            check_security(st, &p, agent_id, new).await?;
        }
        Ok(())
    }
    .await;
    if let Err(e) = res {
        warn!(%agent_id, "security alerts: {e}");
    }
}

/// A security policy changed: check it against every covered agent's last report.
async fn recheck_security(st: &AppState, policy_id: Uuid) {
    let Ok(Some(p)) = load_policy(st, policy_id).await else { return };
    let agents: sqlx::Result<Vec<Uuid>> = sqlx::query_scalar(AssertSqlSafe(format!(
        "SELECT a.id FROM agents a JOIN sites s ON s.id = a.site_id WHERE a.security_at IS NOT NULL AND {}",
        scope_sql(1)
    )))
    .bind(p.client_id)
    .bind(p.site_id)
    .bind(&p.os_family)
    .bind(&p.excluded_agents)
    .fetch_all(&st.db)
    .await;
    for agent_id in agents.unwrap_or_default() {
        if let Err(e) = check_security(st, &p, agent_id, &[]).await {
            warn!(%agent_id, "security alerts: {e}");
        }
    }
}

/// Polled: signatures go stale without the agent reporting anything new.
async fn check_signatures(st: &AppState, p: &Policy, hours: i32) -> sqlx::Result<()> {
    let stale = |n: usize| {
        format!(
            "EXISTS (SELECT 1 FROM security_products sp WHERE sp.agent_id = a.id AND sp.enabled)
             AND NOT EXISTS (SELECT 1 FROM security_products sp WHERE sp.agent_id = a.id AND sp.enabled AND {})",
            fresh_sql(n)
        )
    };
    let opened: Vec<Uuid> = sqlx::query_scalar(AssertSqlSafe(format!(
        "INSERT INTO alerts (id, policy_id, agent_id, key, kind, severity, title, details)
         SELECT gen_random_uuid(), $1, a.id, 'signatures', 'security', $2, 'Antivirus signatures out of date',
                jsonb_build_object('newest', (SELECT max(sp.signatures_updated_at) FROM security_products sp WHERE sp.agent_id = a.id AND sp.enabled),
                                   'max_age_hours', $3::int)
           FROM agents a JOIN sites s ON s.id = a.site_id
          WHERE a.security_at IS NOT NULL AND {} AND {}
         ON CONFLICT (policy_id, agent_id, key) WHERE resolved_at IS NULL DO NOTHING
         RETURNING id",
        scope_sql(4),
        stale(3)
    )))
    .bind(p.id)
    .bind(&p.severity)
    .bind(hours)
    .bind(p.client_id)
    .bind(p.site_id)
    .bind(&p.os_family)
    .bind(&p.excluded_agents)
    .fetch_all(&st.db)
    .await?;
    announce(st, &opened, "opened", &p.channel_ids, true).await;

    let cleared: Vec<Uuid> = sqlx::query_scalar(AssertSqlSafe(format!(
        "UPDATE alerts al SET resolved_at = now(), resolution = 'cleared'
          WHERE al.policy_id = $1 AND al.key = 'signatures' AND al.resolved_at IS NULL
            AND NOT EXISTS (SELECT 1 FROM agents a JOIN sites s ON s.id = a.site_id WHERE a.id = al.agent_id AND {} AND {})
          RETURNING al.id",
        scope_sql(3),
        stale(2)
    )))
    .bind(p.id)
    .bind(hours)
    .bind(p.client_id)
    .bind(p.site_id)
    .bind(&p.os_family)
    .bind(&p.excluded_agents)
    .fetch_all(&st.db)
    .await?;
    announce(st, &cleared, "resolved", &p.channel_ids, p.notify_resolved).await;
    Ok(())
}

/// Polled: an online agent that has gone `hours` without reporting its protection state
/// (counting from when it connected: every connection starts with a report).
async fn check_stale_security(st: &AppState, p: &Policy, hours: i32) -> sqlx::Result<()> {
    let stale = |n: usize| {
        format!(
            "a.online AND ${cap} = ANY(a.capabilities)
             AND greatest(a.security_at, a.connected_at) < now() - make_interval(hours => ${n})",
            cap = n + 1
        )
    };
    let opened: Vec<Uuid> = sqlx::query_scalar(AssertSqlSafe(format!(
        "INSERT INTO alerts (id, policy_id, agent_id, key, kind, severity, title, details)
         SELECT gen_random_uuid(), $1, a.id, 'stale', 'security', $2, 'Protection state not reported',
                jsonb_build_object('last_report', a.security_at, 'hours', $3::int)
           FROM agents a JOIN sites s ON s.id = a.site_id
          WHERE {} AND {}
         ON CONFLICT (policy_id, agent_id, key) WHERE resolved_at IS NULL DO NOTHING
         RETURNING id",
        stale(3),
        scope_sql(5)
    )))
    .bind(p.id)
    .bind(&p.severity)
    .bind(hours)
    .bind(rmm_proto::security::CAPABILITY)
    .bind(p.client_id)
    .bind(p.site_id)
    .bind(&p.os_family)
    .bind(&p.excluded_agents)
    .fetch_all(&st.db)
    .await?;
    announce(st, &opened, "opened", &p.channel_ids, true).await;

    let cleared: Vec<Uuid> = sqlx::query_scalar(AssertSqlSafe(format!(
        "UPDATE alerts al SET resolved_at = now(), resolution = 'cleared'
          WHERE al.policy_id = $1 AND al.key = 'stale' AND al.resolved_at IS NULL
            AND NOT EXISTS (SELECT 1 FROM agents a JOIN sites s ON s.id = a.site_id WHERE a.id = al.agent_id AND {} AND {})
          RETURNING al.id",
        stale(2),
        scope_sql(4)
    )))
    .bind(p.id)
    .bind(hours)
    .bind(rmm_proto::security::CAPABILITY)
    .bind(p.client_id)
    .bind(p.site_id)
    .bind(&p.os_family)
    .bind(&p.excluded_agents)
    .fetch_all(&st.db)
    .await?;
    announce(st, &cleared, "resolved", &p.channel_ids, p.notify_resolved).await;
    Ok(())
}

// ---------------------------------------------------------------------------
// Patches
// ---------------------------------------------------------------------------

/// Updates on this agent whose last install failed, and nobody declined since.
const FAILED_PATCHES: &str = "p.state = 'failed' AND p.approval <> 'declined'";

/// What a patch policy finds on one agent: `(key, title, details)`.
async fn patch_findings(st: &AppState, rule: &PatchRule, agent_id: Uuid) -> sqlx::Result<Vec<(String, String, Value)>> {
    let mut out = Vec::new();
    if rule.failed {
        let failed: Vec<(String, Option<String>)> = sqlx::query_as(AssertSqlSafe(format!(
            "SELECT p.title, p.last_error FROM patches p WHERE p.agent_id = $1 AND {FAILED_PATCHES} ORDER BY p.title"
        )))
        .bind(agent_id)
        .fetch_all(&st.db)
        .await?;
        if !failed.is_empty() {
            let title = match failed.len() {
                1 => format!("Update failed to install: {}", failed[0].0),
                n => format!("{n} updates failed to install"),
            };
            let updates: Vec<&str> = failed.iter().take(10).map(|f| f.0.as_str()).collect();
            out.push(("failed".into(), title, json!({ "updates": updates, "count": failed.len(), "error": failed[0].1 })));
        }
    }
    if let Some(h) = rule.reboot_hours {
        let since: Option<DateTime<Utc>> =
            sqlx::query_scalar("SELECT reboot_pending_since FROM agents WHERE id = $1 AND reboot_pending").bind(agent_id).fetch_optional(&st.db).await?.flatten();
        if let Some(t) = since.filter(|t| *t < Utc::now() - chrono::Duration::hours(h.into())) {
            out.push(("reboot".into(), "Restart pending to finish updates".into(), json!({ "since": t, "hours": h })));
        }
    }
    Ok(out)
}

async fn check_patches(st: &AppState, p: &Policy, agent_id: Uuid) -> sqlx::Result<()> {
    let Some(Rule::Patch(rule)) = p.rule() else { return Ok(()) };
    let findings = patch_findings(st, &rule, agent_id).await?;
    let keep: Vec<String> = findings.iter().map(|f| f.0.clone()).collect();
    for (key, title, details) in findings {
        fire(st, p, agent_id, &key, &title, details, 0).await?;
    }
    clear(st, p, agent_id, None, &keep).await
}

/// The agent's patch state changed (a scan, an install's result).
pub async fn patches_changed(st: &AppState, agent_id: Uuid) {
    let res: sqlx::Result<()> = async {
        for p in policies_for(st, agent_id, "patch").await? {
            check_patches(st, &p, agent_id).await?;
        }
        Ok(())
    }
    .await;
    if let Err(e) = res {
        warn!(%agent_id, "patch alerts: {e}");
    }
}

/// A patch policy changed: check every covered agent that has scanned.
async fn recheck_patches(st: &AppState, policy_id: Uuid) {
    let Ok(Some(p)) = load_policy(st, policy_id).await else { return };
    let agents: sqlx::Result<Vec<Uuid>> = sqlx::query_scalar(AssertSqlSafe(format!(
        "SELECT a.id FROM agents a JOIN sites s ON s.id = a.site_id WHERE a.patch_scanned_at IS NOT NULL AND {}",
        scope_sql(1)
    )))
    .bind(p.client_id)
    .bind(p.site_id)
    .bind(&p.os_family)
    .bind(&p.excluded_agents)
    .fetch_all(&st.db)
    .await;
    for agent_id in agents.unwrap_or_default() {
        if let Err(e) = check_patches(st, &p, agent_id).await {
            warn!(%agent_id, "patch alerts: {e}");
        }
    }
}

/// Polled: restarts that have been pending too long (they age without any new report).
async fn check_reboot(st: &AppState, p: &Policy, hours: i32) -> sqlx::Result<()> {
    let opened: Vec<Uuid> = sqlx::query_scalar(AssertSqlSafe(format!(
        "INSERT INTO alerts (id, policy_id, agent_id, key, kind, severity, title, details)
         SELECT gen_random_uuid(), $1, a.id, 'reboot', 'patch', $2, 'Restart pending to finish updates',
                jsonb_build_object('since', a.reboot_pending_since, 'hours', $3::int)
           FROM agents a JOIN sites s ON s.id = a.site_id
          WHERE a.reboot_pending AND a.reboot_pending_since < now() - make_interval(hours => $3) AND {}
         ON CONFLICT (policy_id, agent_id, key) WHERE resolved_at IS NULL DO NOTHING
         RETURNING id",
        scope_sql(4)
    )))
    .bind(p.id)
    .bind(&p.severity)
    .bind(hours)
    .bind(p.client_id)
    .bind(p.site_id)
    .bind(&p.os_family)
    .bind(&p.excluded_agents)
    .fetch_all(&st.db)
    .await?;
    announce(st, &opened, "opened", &p.channel_ids, true).await;
    // Clearing happens as agents report (a scan after the restart), in `patches_changed`.
    Ok(())
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
            let watchers = policies.iter().filter(|p| p.covers(agent_id, client_id, site_id, &os)).filter_map(watcher).collect();
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
    fn security_rule_parses_and_finds() {
        let r = Rule::parse("security", &json!({ "unprotected": true, "signature_max_age_hours": 72 })).unwrap();
        let Rule::Security(rule) = &r else { panic!() };
        assert_eq!(rule.threats, ThreatAlerts::Active, "threats default to active");
        assert!(r.validate().is_ok());
        assert!(Rule::parse("security", &json!({ "threats": "off" })).unwrap().validate().is_err(), "nothing to alert on");
        assert!(Rule::parse("security", &json!({ "signature_max_age_hours": 0 })).unwrap().validate().is_err());

        let now = Utc::now();
        let r0 = Reporting::default();
        let product = |name: &str, enabled, realtime, age_h: Option<i64>| ProductState {
            name: name.into(),
            enabled: Some(enabled),
            realtime: Some(realtime),
            signatures_updated_at: age_h.map(|h| now - chrono::Duration::hours(h)),
            signatures_current: None,
        };
        let all = SecurityRule {
            unprotected: true,
            realtime_off: true,
            signature_max_age_hours: Some(72),
            threats: ThreatAlerts::Active,
            sensor_down: false,
            stale_hours: None,
        };
        let keys = |f: Vec<(String, String, Value)>| f.into_iter().map(|f| f.0).collect::<Vec<_>>();
        assert!(keys(security_findings(&all, &[product("Defender", true, true, Some(2))], &[], &[], None, &r0, now)).is_empty());
        assert_eq!(keys(security_findings(&all, &[product("Defender", false, false, Some(2))], &[], &[], None, &r0, now)), ["unprotected"]);
        assert_eq!(keys(security_findings(&all, &[], &[], &[], None, &r0, now)), ["unprotected"], "nothing installed at all");
        assert_eq!(keys(security_findings(&all, &[product("ClamAV", true, false, Some(100))], &[], &[], None, &r0, now)), ["realtime", "signatures"]);
        // One product with fresh signatures is enough; a disabled one doesn't count.
        let two = [product("ClamAV", true, false, Some(100)), product("Other", true, true, Some(1)), product("Off", false, false, Some(1))];
        assert!(keys(security_findings(&all, &two, &[], &[], None, &r0, now)).is_empty());
        // Security Center's verdict stands in for a missing date.
        let mut sc = product("Sophos", true, true, None);
        sc.signatures_current = Some(false);
        assert_eq!(keys(security_findings(&all, &[sc], &[], &[], None, &r0, now)), ["signatures"]);

        let det = |status: &str, hours_ago: i64| DetectionState {
            id: Uuid::new_v4(),
            product: "defender".into(),
            name: "EICAR".into(),
            severity: "severe".into(),
            status: status.into(),
            resources: vec!["C:\\eicar.com".into()],
            detected_at: Some(now - chrono::Duration::hours(hours_ago)),
        };
        let (active, quarantined, old) = (det("active", 1), det("quarantined", 1), det("quarantined", 48));
        let ds = [active.clone(), quarantined.clone(), old.clone()];
        let new = [active.id, quarantined.id, old.id];
        let ok = [product("Defender", true, true, Some(1))];
        let f = security_findings(&all, &ok, &ds, &new, None, &r0, now);
        assert_eq!(keys(f.clone()), [format!("threat:{}", active.id)]);
        assert_eq!(f[0].1, "Threat detected: EICAR");
        let any = SecurityRule { threats: ThreatAlerts::Any, ..all.clone() };
        let f = security_findings(&any, &ok, &ds, &new, None, &r0, now);
        assert_eq!(keys(f.clone()), [format!("threat:{}", active.id), format!("threat:{}", quarantined.id)], "old history doesn't alert");
        assert_eq!(f[1].1, "Threat quarantined: EICAR");
        assert!(keys(security_findings(&any, &ok, &ds, &[], None, &r0, now)).len() == 1, "only new detections, apart from active ones");
        let off = SecurityRule { threats: ThreatAlerts::Off, ..all.clone() };
        assert!(keys(security_findings(&off, &ok, &ds, &new, None, &r0, now)).is_empty());
        let sd = SecurityRule { sensor_down: true, ..all };
        let down = json!({ "enabled": true, "running": false, "restarts": 1 });
        assert_eq!(keys(security_findings(&sd, &ok, &[], &[], Some(&down), &r0, now)), ["sensor"]);
        let flapping = json!({ "enabled": true, "running": true, "restarts": 4 });
        assert_eq!(security_findings(&sd, &ok, &[], &[], Some(&flapping), &r0, now)[0].1, "Sensor keeps restarting");
        let off_by_policy = json!({ "enabled": false, "running": false, "restarts": 0 });
        assert!(keys(security_findings(&sd, &ok, &[], &[], Some(&off_by_policy), &r0, now)).is_empty());
    }

    #[test]
    fn stale_reports() {
        let now = Utc::now();
        let h = |n: i64| Some(now - chrono::Duration::hours(n));
        let r = |online, reported_at, connected_at| Reporting { online, reported_at, connected_at };
        assert_eq!(r(true, h(30), h(40)).stale_since(24, now), Some(h(30)), "old report, long connection");
        assert_eq!(r(true, h(30), h(2)).stale_since(24, now), None, "just reconnected: gets time to report");
        assert_eq!(r(false, h(30), h(40)).stale_since(24, now), None, "offline is the offline policy's business");
        assert_eq!(r(true, None, h(30)).stale_since(24, now), Some(None), "never reported");
        assert_eq!(r(true, None, None).stale_since(24, now), None);
        let rule = SecurityRule {
            unprotected: false,
            realtime_off: false,
            signature_max_age_hours: None,
            threats: ThreatAlerts::Off,
            sensor_down: false,
            stale_hours: Some(24),
        };
        assert!(Rule::Security(rule.clone()).validate().is_ok(), "stale alone is something to alert on");
        assert!(Rule::Security(SecurityRule { stale_hours: Some(1), ..rule.clone() }).validate().is_err());
        let f = security_findings(&rule, &[], &[], &[], None, &r(true, h(30), h(40)), now);
        assert_eq!(f.iter().map(|f| f.0.as_str()).collect::<Vec<_>>(), ["stale"]);
    }

    #[test]
    fn patch_rules() {
        assert_eq!(Rule::parse("patch", &json!({})).unwrap(), Rule::Patch(PatchRule { failed: true, reboot_hours: None }));
        assert!(Rule::parse("patch", &json!({ "failed": false })).unwrap().validate().is_err(), "nothing to alert on");
        assert!(Rule::parse("patch", &json!({ "failed": false, "reboot_hours": 48 })).unwrap().validate().is_ok());
        assert!(Rule::parse("patch", &json!({ "reboot_hours": 0 })).unwrap().validate().is_err());
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
