//! Automation policies (docs/design/automations.md): `automation` items of the policy sets run
//! a saved script when something happens on a device (it enrolls, comes back after being
//! offline, an alert of some kind opens, a patch install leaves a restart pending), or once on
//! every device the item reaches.
//!
//! Every run is a row of `automation_runs`, which is both the history on the agent's page and
//! the state of the once-per-device automations: `enrollment` and `run_once` have a unique row
//! per (item, agent), so they cannot run twice however often the event is delivered or the
//! worker ticks.
//!
//! A run passes three gates before it starts (all in the transaction that records it, under an
//! advisory lock per item, so two events can't both take the last slot):
//!
//! - cooldown (event triggers): the device already ran this automation within
//!   `cooldown_minutes`; the run is recorded as skipped.
//! - maintenance window (`respect_window`): outside the site's window the run waits.
//! - rate (`max_runs_per_hour`, per automation): event runs over the limit are skipped;
//!   enrollment and run-once runs wait for the next slot, so none is lost.
//!
//! A worker ([`run`]) ticks every [`TICK`]: it syncs run states from their jobs, starts
//! run-once runs for devices that have none yet (including devices that joined later), starts
//! waiting runs when their gates open, retries failed runs, and expires event runs that waited
//! more than a day. Retries and run-once runs of an automation that stopped applying are
//! dropped.

use std::sync::LazyLock;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use sqlx::PgConnection;
use tracing::{info, warn};
use uuid::Uuid;

use crate::policy::{AutomationConfig, Trigger};
use crate::state::AppState;

const TICK: Duration = Duration::from_secs(15);
/// Run-once devices started per tick (the rest follow on the next ticks).
const BATCH: i64 = 200;
/// Event runs that wait longer than this for their window are dropped: the event is stale.
const EXPIRE_HOURS: i32 = 24;

/// For this long after the server starts, an agent's offline time is counted from the start:
/// the server can't know the agent was really offline while it was down itself, and a
/// restart must not set off every `agent_online` automation at once.
static RESTART_GRACE: LazyLock<chrono::Duration> = LazyLock::new(|| {
    let minutes = std::env::var("RMM_AUTOMATION_RESTART_GRACE_MINUTES").ok().and_then(|v| v.parse::<i64>().ok()).unwrap_or(10);
    chrono::Duration::minutes(minutes.clamp(0, 1440))
});

fn config(v: Value) -> Option<AutomationConfig> {
    serde_json::from_value(v).ok()
}

/// How long an agent that connects now at `now` was offline, given when it was last seen and
/// when the server started (see [`RESTART_GRACE`]).
pub fn offline_for(last_seen: DateTime<Utc>, now: DateTime<Utc>, server_started: DateTime<Utc>, grace: chrono::Duration) -> chrono::Duration {
    let from = if now - server_started < grace { last_seen.max(server_started) } else { last_seen };
    (now - from).max(chrono::Duration::zero())
}

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

/// An agent has connected. `first` is its first connection ever; `last_seen` is when it was
/// last heard from before this connection.
pub async fn on_connect(st: &AppState, agent_id: Uuid, first: bool, last_seen: Option<DateTime<Utc>>) {
    if first {
        fire(st, agent_id, Trigger::Enrollment, Event::default(), json!({})).await;
    } else if let Some(seen) = last_seen {
        let now = Utc::now();
        let away = offline_for(seen, now, st.started_at, *RESTART_GRACE);
        fire(
            st,
            agent_id,
            Trigger::AgentOnline,
            Event { offline_minutes: Some(away.num_minutes()), ..Default::default() },
            json!({ "offline_minutes": away.num_minutes(), "last_seen_at": seen }),
        )
        .await;
    }
}

/// An alert opened (and wasn't held back by a mute) on an agent.
pub async fn alert_opened(st: &AppState, alert_id: Uuid) {
    let row: sqlx::Result<Option<(Uuid, String, String)>> =
        sqlx::query_as("SELECT agent_id, kind, title FROM alerts WHERE id = $1").bind(alert_id).fetch_optional(&st.db).await;
    match row {
        Ok(Some((agent_id, kind, title))) => {
            fire(st, agent_id, Trigger::AlertOpened, Event { alert_kind: Some(kind.clone()), ..Default::default() }, json!({ "alert_id": alert_id, "alert_kind": kind, "title": title }))
                .await
        }
        Ok(None) => {}
        Err(e) => warn!(alert = %alert_id, "automations for an opened alert: {e}"),
    }
}

/// A patch install finished and the machine still needs a restart.
pub async fn patch_reboot_pending(st: &AppState, agent_id: Uuid, patch_run: Uuid) {
    fire(st, agent_id, Trigger::PatchRebootPending, Event::default(), json!({ "patch_run_id": patch_run })).await;
}

/// What an event says, for the automations that match on it.
#[derive(Default)]
pub struct Event {
    offline_minutes: Option<i64>,
    alert_kind: Option<String>,
}

impl Event {
    fn matches(&self, c: &AutomationConfig) -> bool {
        match c.trigger {
            Trigger::AgentOnline => self.offline_minutes.is_some_and(|m| m >= c.offline_minutes.unwrap_or(i32::MAX) as i64),
            Trigger::AlertOpened => self.alert_kind.is_some() && self.alert_kind == c.alert_kind,
            _ => true,
        }
    }
}

/// The one entry point of events: starts every enabled automation of `trigger` that applies to
/// the agent (its set's items, inside their limits) and matches the event. A trigger on custom
/// field or tag changes calls this too, with its own [`Trigger`].
pub async fn fire(st: &AppState, agent_id: Uuid, trigger: Trigger, event: Event, context: Value) {
    let items: sqlx::Result<Vec<(Uuid, Value)>> = sqlx::query_as(
        "SELECT item_id, config FROM agent_policy WHERE agent_id = $1 AND module = 'automation' AND enabled AND config ->> 'trigger' = $2",
    )
    .bind(agent_id)
    .bind(trigger.as_str())
    .fetch_all(&st.db)
    .await;
    let items = match items {
        Ok(i) => i,
        Err(e) => return warn!(%agent_id, trigger = trigger.as_str(), "finding automations: {e}"),
    };
    for (item, cfg) in items {
        let Some(cfg) = config(cfg) else { continue };
        if !event.matches(&cfg) {
            continue;
        }
        if let Err(e) = admit(st, item, agent_id, &cfg, trigger, context.clone()).await {
            warn!(%item, %agent_id, trigger = trigger.as_str(), "automation: {e:#}");
        }
    }
}

/// A job finished (or was given up on): bring its run up to date.
pub async fn job_finished(st: &AppState, job_id: Uuid) {
    if let Err(e) = sync_jobs(st, Some(job_id)).await {
        warn!(%job_id, "updating automation runs: {e}");
    }
}

// ---------------------------------------------------------------------------
// Admission
// ---------------------------------------------------------------------------

enum Gate {
    Go,
    Wait(&'static str),
    Skip(&'static str),
}

async fn in_window(db: &mut PgConnection, agent: Uuid) -> sqlx::Result<bool> {
    sqlx::query_scalar(
        "SELECT in_maintenance_window(s.maint_days, s.maint_start, s.maint_minutes, s.maint_tz, now())
           FROM agents a JOIN sites s ON s.id = a.site_id WHERE a.id = $1",
    )
    .bind(agent)
    .fetch_one(db)
    .await
}

/// Runs of this automation started in the last hour.
async fn started_last_hour(db: &mut PgConnection, item: Uuid) -> sqlx::Result<i64> {
    sqlx::query_scalar("SELECT count(*) FROM automation_runs WHERE item_id = $1 AND started_at > now() - interval '1 hour'")
        .bind(item)
        .fetch_one(db)
        .await
}

/// Serializes decisions about one automation: the budget check and the insert are one step.
async fn lock_item(db: &mut PgConnection, item: Uuid) -> sqlx::Result<()> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 7))").bind(item.to_string()).execute(db).await?;
    Ok(())
}

async fn gate(db: &mut PgConnection, item: Uuid, agent: Uuid, c: &AutomationConfig) -> sqlx::Result<Gate> {
    if c.respect_window && !in_window(db, agent).await? {
        return Ok(Gate::Wait("maintenance_window"));
    }
    if started_last_hour(db, item).await? >= c.max_runs_per_hour as i64 {
        return Ok(if c.trigger.once_per_device() { Gate::Wait("rate_limited") } else { Gate::Skip("rate_limited") });
    }
    Ok(Gate::Go)
}

/// Decides what happens to an event for one device and records it; starts the run if it may.
async fn admit(st: &AppState, item: Uuid, agent: Uuid, c: &AutomationConfig, trigger: Trigger, context: Value) -> anyhow::Result<()> {
    let mut tx = st.db.begin().await?;
    lock_item(&mut tx, item).await?;
    if trigger.once_per_device() {
        let done: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM automation_runs WHERE item_id = $1 AND agent_id = $2)")
            .bind(item)
            .bind(agent)
            .fetch_one(&mut *tx)
            .await?;
        if done {
            return Ok(());
        }
    }
    let verdict = if !trigger.once_per_device()
        && c.cooldown_minutes > 0
        && sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS (SELECT 1 FROM automation_runs WHERE item_id = $1 AND agent_id = $2 AND status <> 'skipped'
                             AND created_at > now() - make_interval(mins => $3))",
        )
        .bind(item)
        .bind(agent)
        .bind(c.cooldown_minutes)
        .fetch_one(&mut *tx)
        .await?
    {
        Gate::Skip("cooldown")
    } else {
        gate(&mut tx, item, agent, c).await?
    };
    let (status, reason) = match verdict {
        Gate::Go => ("pending", None),
        Gate::Wait(r) => ("waiting", Some(r)),
        Gate::Skip(r) => ("skipped", Some(r)),
    };
    // A device that trips a gate again and again leaves one skipped row an hour, not one per event.
    let inserted: Option<Uuid> = sqlx::query_scalar(
        "INSERT INTO automation_runs (item_id, agent_id, trigger, status, reason, context, started_at, finished_at)
         SELECT $1::uuid, $2::uuid, $3::text, $4::text, $5::text, $6::jsonb, CASE WHEN $4 = 'pending' THEN now() END, CASE WHEN $4 = 'skipped' THEN now() END
          WHERE $4 <> 'skipped' OR NOT EXISTS (SELECT 1 FROM automation_runs WHERE item_id = $1 AND agent_id = $2 AND status = 'skipped'
                                                 AND reason = $5 AND created_at > now() - interval '1 hour')
         ON CONFLICT DO NOTHING
         RETURNING id",
    )
    .bind(item)
    .bind(agent)
    .bind(trigger.as_str())
    .bind(status)
    .bind(reason)
    .bind(&context)
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    if let (Some(run), "pending") = (inserted, status) {
        launch(st, run).await?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Running
// ---------------------------------------------------------------------------

/// Creates the run's job and sends it. The run is `pending` and has no job yet (or a failed
/// attempt's, when it is a retry).
async fn launch(st: &AppState, run_id: Uuid) -> anyhow::Result<()> {
    #[allow(clippy::type_complexity)]
    let row: Option<(Uuid, Uuid, Option<Value>, Uuid, i32)> = sqlx::query_as(
        "SELECT r.item_id, r.agent_id, ap.config, s.client_id, r.attempts
           FROM automation_runs r JOIN agents a ON a.id = r.agent_id JOIN sites s ON s.id = a.site_id
           LEFT JOIN agent_policy ap ON ap.agent_id = r.agent_id AND ap.item_id = r.item_id AND ap.enabled
          WHERE r.id = $1 AND r.status = 'pending'",
    )
    .bind(run_id)
    .fetch_optional(&st.db)
    .await?;
    let Some((item, agent_id, cfg, client_id, attempts)) = row else { return Ok(()) };
    let Some(c) = cfg.and_then(config) else {
        return end(st, run_id, "skipped", "no_longer_applies").await;
    };
    let script: Option<(String, String, i32, Option<Uuid>)> =
        sqlx::query_as("SELECT interpreter, body, timeout_secs, client_id FROM scripts WHERE id = $1").bind(c.script_id).fetch_optional(&st.db).await?;
    let Some((interp, body, script_timeout, script_client)) = script else {
        return end(st, run_id, "failed", "script_missing").await;
    };
    // A client's own script only runs on that client's agents.
    if script_client.is_some_and(|sc| sc != client_id) {
        return end(st, run_id, "failed", "script_other_client").await;
    }
    let Some(interpreter) = crate::agent_ws::parse_interpreter(&interp) else {
        return end(st, run_id, "failed", "script_unavailable").await;
    };
    let timeout = c.timeout_secs.unwrap_or(script_timeout).clamp(1, 86400);
    let job_id = Uuid::new_v4();
    let mut tx = st.db.begin().await?;
    // The job's schedule_id is the item: the jobs lists name the automation, and the job
    // retention (`retain_days`) applies.
    sqlx::query(
        "INSERT INTO jobs (id, agent_id, script_id, interpreter, body, args, timeout_secs, schedule_id)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(job_id)
    .bind(agent_id)
    .bind(c.script_id)
    .bind(&interp)
    .bind(&body)
    .bind(json!(c.args))
    .bind(timeout)
    .bind(item)
    .execute(&mut *tx)
    .await?;
    let claimed = sqlx::query(
        "UPDATE automation_runs SET job_id = $2, attempts = attempts + 1, started_at = now(), finished_at = NULL
          WHERE id = $1 AND status = 'pending'",
    )
    .bind(run_id)
    .bind(job_id)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if claimed == 0 {
        return Ok(());
    }
    tx.commit().await?;
    let job = rmm_proto::ScriptJob { job_id, interpreter, script: body, args: c.args, timeout_secs: timeout as u32 };
    let status = crate::api::deliver_job(st, agent_id, client_id, job).await.map_err(|e| anyhow::anyhow!("{e}"))?;
    info!(%item, %agent_id, %job_id, attempt = attempts + 1, status, "automation started");
    Ok(())
}

async fn end(st: &AppState, run_id: Uuid, status: &str, reason: &str) -> anyhow::Result<()> {
    sqlx::query("UPDATE automation_runs SET status = $2, reason = $3, finished_at = now() WHERE id = $1 AND status = 'pending'")
        .bind(run_id)
        .bind(status)
        .bind(reason)
        .execute(&st.db)
        .await?;
    Ok(())
}

/// Moves pending runs to the outcome of their jobs (one job, or all that are final).
async fn sync_jobs(st: &AppState, job: Option<Uuid>) -> sqlx::Result<u64> {
    let n = sqlx::query(
        "UPDATE automation_runs r
            SET status = CASE WHEN j.status = 'succeeded' THEN 'succeeded' ELSE 'failed' END,
                reason = CASE WHEN j.status = 'succeeded' THEN NULL ELSE j.status END,
                finished_at = coalesce(j.finished_at, now())
           FROM jobs j
          WHERE j.id = r.job_id AND r.status = 'pending' AND j.status NOT IN ('queued', 'sent') AND ($1::uuid IS NULL OR j.id = $1)",
    )
    .bind(job)
    .execute(&st.db)
    .await?
    .rows_affected();
    Ok(n)
}

pub async fn run(st: std::sync::Arc<AppState>) {
    LazyLock::force(&RESTART_GRACE);
    let mut tick = tokio::time::interval(TICK);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        if let Err(e) = work(&st).await {
            warn!("automations: {e:#}");
        }
    }
}

/// One pass of the worker; public so tests can run it without waiting for the timer.
pub async fn work(st: &AppState) -> anyhow::Result<()> {
    sync_jobs(st, None).await?;
    orphans(st).await?;
    expire(st).await?;
    start_run_once(st).await?;
    start_waiting(st).await?;
    retry_failed(st).await?;
    Ok(())
}

/// Runs marked pending whose job was never created (the server stopped in between).
async fn orphans(st: &AppState) -> anyhow::Result<()> {
    let ids: Vec<Uuid> = sqlx::query_scalar(
        "SELECT id FROM automation_runs WHERE status = 'pending' AND job_id IS NULL AND started_at < now() - interval '1 minute' LIMIT 100",
    )
    .fetch_all(&st.db)
    .await?;
    for id in ids {
        launch(st, id).await?;
    }
    Ok(())
}

async fn expire(st: &AppState) -> sqlx::Result<()> {
    sqlx::query(
        "UPDATE automation_runs SET status = 'skipped', reason = 'expired', finished_at = now()
          WHERE status = 'waiting' AND trigger NOT IN ('enrollment', 'run_once') AND created_at < now() - make_interval(hours => $1)",
    )
    .bind(EXPIRE_HOURS)
    .execute(&st.db)
    .await?;
    // A run-once automation that is switched off or no longer reaches the device leaves
    // nothing waiting for it.
    sqlx::query(
        "UPDATE automation_runs r SET status = 'skipped', reason = 'no_longer_applies', finished_at = now()
          WHERE r.status = 'waiting' AND NOT EXISTS (SELECT 1 FROM agent_policy ap WHERE ap.agent_id = r.agent_id AND ap.item_id = r.item_id AND ap.enabled)",
    )
    .execute(&st.db)
    .await?;
    Ok(())
}

/// Devices an enabled run-once automation reaches that have no run of it yet: a new device, a
/// device that moved into the set, an automation just created. Their run is recorded (so it
/// is never started twice) and started, within the automation's hourly budget.
async fn start_run_once(st: &AppState) -> anyhow::Result<()> {
    let due: Vec<(Uuid, Uuid, Value)> = sqlx::query_as(
        "SELECT i.id, a.id, e.config
           FROM policy_items i
           JOIN policy_effective e ON e.item_id = i.id AND e.enabled AND e.config ->> 'trigger' = 'run_once'
           JOIN agents a ON a.policy_set_id = e.set_id
           JOIN sites s ON s.id = a.site_id
          WHERE i.module = 'automation'
            AND (i.client_id IS NULL OR i.client_id = s.client_id) AND (i.site_id IS NULL OR i.site_id = a.site_id)
            AND NOT (a.id = ANY(i.excluded_agents))
            AND NOT EXISTS (SELECT 1 FROM automation_runs r WHERE r.item_id = i.id AND r.agent_id = a.id)
          ORDER BY i.id, a.enrolled_at
          LIMIT $1",
    )
    .bind(BATCH)
    .fetch_all(&st.db)
    .await?;
    for (item, agent, cfg) in due {
        let Some(c) = config(cfg) else { continue };
        if let Err(e) = admit(st, item, agent, &c, Trigger::RunOnce, json!({})).await {
            warn!(%item, %agent, "run-once automation: {e:#}");
        }
    }
    Ok(())
}

/// Waiting runs whose gates are open now.
async fn start_waiting(st: &AppState) -> anyhow::Result<()> {
    let waiting: Vec<(Uuid, Uuid, Uuid, Value)> = sqlx::query_as(
        "SELECT r.id, r.item_id, r.agent_id, ap.config
           FROM automation_runs r JOIN agent_policy ap ON ap.agent_id = r.agent_id AND ap.item_id = r.item_id AND ap.enabled
          WHERE r.status = 'waiting' ORDER BY r.created_at LIMIT $1",
    )
    .bind(BATCH)
    .fetch_all(&st.db)
    .await?;
    for (run, item, agent, cfg) in waiting {
        let Some(c) = config(cfg) else { continue };
        if claim(st, run, item, agent, &c, "waiting").await? {
            launch(st, run).await?;
        }
    }
    Ok(())
}

/// Failed runs of automations that retry, once their wait is over.
async fn retry_failed(st: &AppState) -> anyhow::Result<()> {
    let failed: Vec<(Uuid, Uuid, Uuid, Value)> = sqlx::query_as(
        "SELECT r.id, r.item_id, r.agent_id, ap.config
           FROM automation_runs r JOIN agent_policy ap ON ap.agent_id = r.agent_id AND ap.item_id = r.item_id AND ap.enabled
          WHERE r.status = 'failed' AND r.trigger IN ('enrollment', 'run_once') AND r.reason IS DISTINCT FROM 'cancelled'
            AND (ap.config ->> 'retry_failed')::boolean AND r.attempts < (ap.config ->> 'max_attempts')::int
            AND r.finished_at < now() - make_interval(mins => (ap.config ->> 'retry_minutes')::int)
          ORDER BY r.finished_at LIMIT $1",
    )
    .bind(BATCH)
    .fetch_all(&st.db)
    .await?;
    for (run, item, agent, cfg) in failed {
        let Some(c) = config(cfg) else { continue };
        if claim(st, run, item, agent, &c, "failed").await? {
            launch(st, run).await?;
        }
    }
    Ok(())
}

/// Moves a `waiting` or `failed` run to `pending` if its gates are open and the automation's
/// hourly budget has room. Returns whether it did.
async fn claim(st: &AppState, run: Uuid, item: Uuid, agent: Uuid, c: &AutomationConfig, from: &str) -> sqlx::Result<bool> {
    let mut tx = st.db.begin().await?;
    lock_item(&mut tx, item).await?;
    if !matches!(gate(&mut tx, item, agent, c).await?, Gate::Go) {
        return Ok(false);
    }
    let n = sqlx::query(
        "UPDATE automation_runs SET status = 'pending', reason = NULL, job_id = NULL, started_at = now(), finished_at = NULL
          WHERE id = $1 AND status = $2",
    )
    .bind(run)
    .bind(from)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    tx.commit().await?;
    Ok(n == 1)
}

/// Housekeeping: forget event runs older than their automation's `retain_days`. Runs of
/// `enrollment` and `run_once` are the record that the script ran and stay.
pub async fn prune(db: &sqlx::PgPool) -> sqlx::Result<u64> {
    Ok(sqlx::query(
        "DELETE FROM automation_runs r USING policy_items i
          WHERE i.id = r.item_id AND r.trigger NOT IN ('enrollment', 'run_once') AND r.status NOT IN ('waiting', 'pending')
            AND coalesce(r.finished_at, r.created_at) < now() - make_interval(days => coalesce((i.config ->> 'retain_days')::int, 30))",
    )
    .execute(db)
    .await?
    .rows_affected())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn at(h: u32, m: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 1, 15, h, m, 0).unwrap()
    }

    #[test]
    fn offline_time_is_counted_from_the_server_start_just_after_it() {
        let grace = chrono::Duration::minutes(10);
        // Server up since 12:00, the agent last seen at 10:00 (while we were down): at 12:03
        // we only know it has been gone 3 minutes.
        assert_eq!(offline_for(at(10, 0), at(12, 3), at(12, 0), grace).num_minutes(), 3);
        // Long after the start the whole gap counts.
        assert_eq!(offline_for(at(10, 0), at(12, 30), at(12, 0), grace).num_minutes(), 150);
        // Seen after the server started: always the real gap.
        assert_eq!(offline_for(at(12, 1), at(12, 5), at(12, 0), grace).num_minutes(), 4);
        // No grace configured: the real gap, always.
        assert_eq!(offline_for(at(10, 0), at(12, 3), at(12, 0), chrono::Duration::zero()).num_minutes(), 123);
        // A clock that ran backwards never gives a negative time.
        assert_eq!(offline_for(at(13, 0), at(12, 0), at(11, 0), grace), chrono::Duration::zero());
    }

    fn cfg(v: Value) -> AutomationConfig {
        let mut base = json!({ "script_id": Uuid::nil() });
        base.as_object_mut().unwrap().extend(v.as_object().unwrap().clone());
        serde_json::from_value(base).unwrap()
    }

    #[test]
    fn events_match_their_automations() {
        let online = cfg(json!({ "trigger": "agent_online", "offline_minutes": 30 }));
        let away = |m| Event { offline_minutes: Some(m), ..Default::default() };
        assert!(away(30).matches(&online) && away(500).matches(&online));
        assert!(!away(29).matches(&online));
        assert!(!Event::default().matches(&online));
        let alert = cfg(json!({ "trigger": "alert_opened", "alert_kind": "disk" }));
        let kind = |k: &str| Event { alert_kind: Some(k.into()), ..Default::default() };
        assert!(kind("disk").matches(&alert));
        assert!(!kind("cpu").matches(&alert) && !Event::default().matches(&alert));
        assert!(Event::default().matches(&cfg(json!({ "trigger": "enrollment" }))));
    }
}
