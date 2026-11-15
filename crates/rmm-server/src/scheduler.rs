//! Scheduled scripts: cron expressions evaluated in the schedule's time zone.
//!
//! Every [`TICK`], due schedules are claimed (`FOR UPDATE SKIP LOCKED`, so a second server
//! process would never double-run one), moved to their next time, and run: one job per
//! targeted agent. An agent that still has a queued or running job from the same schedule is
//! skipped, so an offline machine collects one pending run, not one per tick. A server that
//! was down runs each missed schedule once on start, then resumes the normal cadence.

use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use rmm_proto::ScriptJob;
use tracing::{info, warn};
use uuid::Uuid;

use crate::state::AppState;

const TICK: Duration = Duration::from_secs(15);

/// Parses a 5-field cron expression (or `@hourly`, `@daily`, `@weekly`, `@monthly`,
/// `@yearly`) and a time zone, returning the next run strictly after `after`.
pub fn next_run(cron: &str, timezone: &str, after: DateTime<Utc>) -> Result<DateTime<Utc>, String> {
    let cron = cron.trim();
    if !cron.starts_with('@') && cron.split_whitespace().count() != 5 {
        return Err("use 5 fields: minute hour day-of-month month day-of-week".into());
    }
    if cron.eq_ignore_ascii_case("@reboot") {
        return Err("@reboot isn't supported".into());
    }
    let parsed = croner::Cron::from_str(cron).map_err(|e| format!("invalid cron expression: {e}"))?;
    let tz = chrono_tz::Tz::from_str(timezone.trim()).map_err(|_| format!("unknown time zone {timezone:?}"))?;
    parsed
        .find_next_occurrence(&after.with_timezone(&tz), false)
        .map(|t| t.with_timezone(&Utc))
        .map_err(|e| format!("no upcoming run: {e}"))
}

pub async fn run(st: Arc<AppState>) {
    let mut tick = tokio::time::interval(TICK);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        let work = async {
            match claim_due(&st).await {
                Ok(due) => {
                    for id in due {
                        if let Err(e) = run_schedule(&st, id, None).await {
                            warn!(schedule = %id, "scheduled run failed: {e}");
                        }
                    }
                }
                Err(e) => warn!("scheduler: {e}"),
            }
        };
        crate::metrics::M.scheduler_tick.time(work).await;
    }
}

/// Moves every due schedule to its next run and returns their ids.
async fn claim_due(st: &AppState) -> sqlx::Result<Vec<Uuid>> {
    let mut tx = st.db.begin().await?;
    let due: Vec<(Uuid, String, String)> = sqlx::query_as(
        "SELECT id, cron, timezone FROM schedules WHERE enabled AND next_run_at <= now() ORDER BY next_run_at FOR UPDATE SKIP LOCKED",
    )
    .fetch_all(&mut *tx)
    .await?;
    let now = Utc::now();
    let mut ids = Vec::with_capacity(due.len());
    for (id, cron, tz) in due {
        // Computed from now, not from the missed time: missed runs collapse into this one.
        let next = next_run(&cron, &tz, now).inspect_err(|e| warn!(schedule = %id, "{e}; disabling")).ok();
        sqlx::query("UPDATE schedules SET next_run_at = $2, last_run_at = now(), enabled = enabled AND $2 IS NOT NULL WHERE id = $1")
            .bind(id)
            .bind(next)
            .execute(&mut *tx)
            .await?;
        ids.push(id);
    }
    tx.commit().await?;
    Ok(ids)
}

#[derive(Debug, Default, serde::Serialize)]
pub struct RunResult {
    pub queued: usize,
    pub sent: usize,
    /// Agents still busy with (or waiting for) this schedule's previous run.
    pub skipped: usize,
}

/// Starts one run of a schedule now. `by` is the user who pressed Run now, if any.
pub async fn run_schedule(st: &AppState, id: Uuid, by: Option<Uuid>) -> anyhow::Result<RunResult> {
    #[allow(clippy::type_complexity)]
    let (client_id, site_id, os_family, script_id, args, timeout, interp, body, script_timeout, script_client, name): (
        Option<Uuid>,
        Option<Uuid>,
        Option<String>,
        Uuid,
        serde_json::Value,
        Option<i32>,
        String,
        String,
        i32,
        Option<Uuid>,
        String,
    ) = sqlx::query_as(
        "SELECT sc.client_id, sc.site_id, sc.os_family, sc.script_id, sc.args, sc.timeout_secs,
                s.interpreter, s.body, s.timeout_secs, s.client_id, sc.name
           FROM schedules sc JOIN scripts s ON s.id = sc.script_id WHERE sc.id = $1",
    )
    .bind(id)
    .fetch_one(&st.db)
    .await?;
    let interpreter =
        crate::agent_ws::parse_interpreter(&interp).ok_or_else(|| anyhow::anyhow!("script has unknown interpreter {interp}"))?;
    let timeout = timeout.unwrap_or(script_timeout).clamp(1, 86400);
    let arg_list: Vec<String> = serde_json::from_value(args.clone()).unwrap_or_default();

    // A client's own script only ever runs on that client's agents.
    let targets: Vec<(Uuid, Uuid, bool)> = sqlx::query_as(
        "SELECT a.id, s.client_id,
                EXISTS (SELECT 1 FROM jobs j WHERE j.agent_id = a.id AND j.schedule_id = $5 AND j.status IN ('queued', 'sent'))
           FROM agents a JOIN sites s ON s.id = a.site_id
          WHERE ($1::uuid IS NULL OR s.client_id = $1) AND ($2::uuid IS NULL OR a.site_id = $2)
            AND ($3::text IS NULL OR a.os_family = $3) AND ($4::uuid IS NULL OR s.client_id = $4)",
    )
    .bind(client_id)
    .bind(site_id)
    .bind(&os_family)
    .bind(script_client)
    .bind(id)
    .fetch_all(&st.db)
    .await?;

    let mut result = RunResult::default();
    for (agent_id, agent_client, busy) in targets {
        if busy {
            result.skipped += 1;
            continue;
        }
        let job_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO jobs (id, agent_id, script_id, interpreter, body, args, timeout_secs, created_by, schedule_id)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        )
        .bind(job_id)
        .bind(agent_id)
        .bind(script_id)
        .bind(&interp)
        .bind(&body)
        .bind(&args)
        .bind(timeout)
        .bind(by)
        .bind(id)
        .execute(&st.db)
        .await?;
        let job = ScriptJob { job_id, interpreter, script: body.clone(), args: arg_list.clone(), timeout_secs: timeout as u32 };
        match crate::api::deliver_job(st, agent_id, agent_client, job).await? {
            "sent" => result.sent += 1,
            _ => result.queued += 1,
        }
    }
    info!(schedule = %id, %name, sent = result.sent, queued = result.queued, skipped = result.skipped, "schedule ran");
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn next_run_honours_time_zone_and_rejects_junk() {
        let after = Utc.with_ymd_and_hms(2026, 1, 15, 12, 0, 0).unwrap();
        // 02:30 every day in New York (UTC-5 in January) is 07:30 UTC.
        assert_eq!(next_run("30 2 * * *", "America/New_York", after).unwrap(), Utc.with_ymd_and_hms(2026, 1, 16, 7, 30, 0).unwrap());
        assert_eq!(next_run("*/15 * * * *", "UTC", after).unwrap(), Utc.with_ymd_and_hms(2026, 1, 15, 12, 15, 0).unwrap());
        assert_eq!(next_run("@daily", "UTC", after).unwrap(), Utc.with_ymd_and_hms(2026, 1, 16, 0, 0, 0).unwrap());
        // Mondays at 09:00; 2026-01-15 is a Thursday.
        assert_eq!(next_run("0 9 * * 1", "UTC", after).unwrap(), Utc.with_ymd_and_hms(2026, 1, 19, 9, 0, 0).unwrap());
        assert!(next_run("* * * * * *", "UTC", after).is_err(), "no per-second schedules");
        assert!(next_run("61 * * * *", "UTC", after).is_err());
        assert!(next_run("0 0 * * *", "Mars/Olympus", after).is_err());
        assert!(next_run("@reboot", "UTC", after).is_err());
    }
}
