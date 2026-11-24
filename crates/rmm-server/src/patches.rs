//! Patch management, server side: storing scans and install results, applying approval
//! policies, and the scheduler that requests scans and starts automatic installs.
//!
//! An update's lifecycle on one agent (`patches.state`): a scan lists it (`missing`); a run
//! includes it (`installing`); the result marks it `installed` or `failed`; the rescan the
//! agent sends after every install is authoritative (anything it still lists is `missing`
//! or stays `failed`, anything it doesn't is `installed`).
//!
//! Approvals: the patch policy of the agent's policy set (the `agent_patch_policy` view over
//! `policy_effective`) approves by severity or category. A person's decision
//! (`approval_manual`) is kept when policies change.

use std::sync::Arc;
use std::time::Duration;

use rmm_proto::ServerMsg;
use rmm_proto::patch::{PatchOutcome, PatchStage, PatchUpdate, RebootPolicy};
use tokio::sync::mpsc;
use tracing::{info, warn};
use uuid::Uuid;

use crate::hub::Event;
use crate::state::AppState;

/// Scans no answer came back for are asked again after this long.
const SCAN_RETRY_MINUTES: i32 = 60;
/// An agent gets at most this many scan requests per scheduler tick, fleet-wide.
const SCANS_PER_TICK: i64 = 50;
/// A sent install with no result after this long is given up on.
const RUN_TIMEOUT_HOURS: i32 = 6;

/// Updates eligible to install automatically, as an SQL condition on `p` (patches) and `pol`
/// (agent_patch_policy). Failed updates are retried automatically up to three times.
pub const ELIGIBLE: &str = "p.approval = 'approved' AND p.state IN ('missing', 'failed') AND p.fail_count < 3
     AND (p.approval_manual OR p.first_seen_at <= now() - make_interval(days => pol.deferral_days))";

fn publish(st: &AppState, agent_id: Uuid, client_id: Uuid) {
    st.hub.publish(Event::Patches { agent_id, client_id });
}

async fn client_of(st: &AppState, agent_id: Uuid) -> sqlx::Result<Option<Uuid>> {
    sqlx::query_scalar("SELECT s.client_id FROM agents a JOIN sites s ON s.id = a.site_id WHERE a.id = $1")
        .bind(agent_id)
        .fetch_optional(&st.db)
        .await
}

/// A freshly authenticated agent: record what it supports, settle the installs it no longer
/// holds, send queued installs, and ask for a scan if the last one is stale.
pub async fn on_connect(
    st: &AppState,
    agent_id: Uuid,
    client_id: Uuid,
    capabilities: &[String],
    held_runs: &[Uuid],
    tx: &mpsc::Sender<ServerMsg>,
) -> anyhow::Result<()> {
    sqlx::query("UPDATE agents SET capabilities = $2 WHERE id = $1").bind(agent_id).bind(capabilities).execute(&st.db).await?;
    if !capabilities.iter().any(|c| c == rmm_proto::patch::CAPABILITY) {
        return Ok(());
    }
    let lost = mark_lost(st, agent_id, Some(held_runs)).await?;
    let sent = dispatch_queued(st, agent_id, tx).await?;
    // Stale, never scanned, or an install finished since (the machine may have rebooted to
    // complete it, and the post-install rescan may not reflect that).
    let stale: bool = sqlx::query_scalar(
        "SELECT patch_scanned_at IS NULL OR patch_scanned_at < now() - make_interval(hours => $2)
             OR EXISTS (SELECT 1 FROM patch_runs r WHERE r.agent_id = a.id AND r.finished_at > a.patch_scanned_at AND r.rebooting)
           FROM agents a WHERE id = $1",
    )
    .bind(agent_id)
    .bind(st.cfg.patch_scan_hours as i32)
    .fetch_one(&st.db)
    .await?;
    if stale {
        request_scan(st, agent_id, tx).await?;
    }
    if lost > 0 || sent > 0 {
        publish(st, agent_id, client_id);
    }
    Ok(())
}

/// Sends a scan request and notes it.
async fn request_scan(st: &AppState, agent_id: Uuid, tx: &mpsc::Sender<ServerMsg>) -> sqlx::Result<bool> {
    if tx.send(ServerMsg::PatchScan { request_id: Uuid::new_v4() }).await.is_err() {
        return Ok(false);
    }
    sqlx::query("UPDATE agents SET patch_scan_requested_at = now() WHERE id = $1").bind(agent_id).execute(&st.db).await?;
    Ok(true)
}

/// Asks online, patch-capable agents for a scan now. Returns how many were asked.
pub async fn scan_now(st: &AppState, agent_ids: &[Uuid]) -> sqlx::Result<usize> {
    let capable: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM agents WHERE id = ANY($1) AND $2 = ANY(capabilities)")
        .bind(agent_ids)
        .bind(rmm_proto::patch::CAPABILITY)
        .fetch_all(&st.db)
        .await?;
    let mut n = 0;
    for id in capable {
        if st.hub.send(id, ServerMsg::PatchScan { request_id: Uuid::new_v4() }).await {
            sqlx::query("UPDATE agents SET patch_scan_requested_at = now() WHERE id = $1").bind(id).execute(&st.db).await?;
            n += 1;
            if let Some(c) = client_of(st, id).await? {
                publish(st, id, c);
            }
        }
    }
    Ok(n)
}

/// Installs the agent can't report on any more become `lost`: those it didn't list when it
/// reconnected (`held`), or (with `held` None) those sent too long ago. Their updates go back
/// to `missing`.
pub async fn mark_lost(st: &AppState, agent_id: Uuid, held: Option<&[Uuid]>) -> sqlx::Result<u64> {
    let ids: Vec<Uuid> = sqlx::query_scalar(
        "UPDATE patch_runs SET status = 'lost', finished_at = now(),
                error = coalesce(error, 'the agent stopped reporting on this install (it restarted, or the result was lost)')
          WHERE agent_id = $1 AND status = 'sent'
            AND CASE WHEN $2::uuid[] IS NULL THEN sent_at < now() - make_interval(hours => $3) ELSE NOT (id = ANY($2)) END
          RETURNING id",
    )
    .bind(agent_id)
    .bind(held)
    .bind(RUN_TIMEOUT_HOURS)
    .fetch_all(&st.db)
    .await?;
    if !ids.is_empty() {
        settle_installing(st, agent_id).await?;
        info!(%agent_id, runs = ids.len(), "patch installs lost");
    }
    Ok(ids.len() as u64)
}

/// Updates marked `installing` without a live run go back to `missing`.
async fn settle_installing(st: &AppState, agent_id: Uuid) -> sqlx::Result<()> {
    sqlx::query(
        "UPDATE patches p SET state = 'missing'
          WHERE p.agent_id = $1 AND p.state = 'installing'
            AND NOT EXISTS (SELECT 1 FROM patch_runs r WHERE r.agent_id = p.agent_id AND r.status = 'sent' AND p.update_id = ANY(r.update_ids))",
    )
    .bind(agent_id)
    .execute(&st.db)
    .await?;
    Ok(())
}

/// Sends this agent's queued installs (oldest first). Returns how many.
async fn dispatch_queued(st: &AppState, agent_id: Uuid, tx: &mpsc::Sender<ServerMsg>) -> sqlx::Result<usize> {
    let rows: Vec<(Uuid, Vec<String>, String)> = sqlx::query_as(
        "UPDATE patch_runs SET status = 'sent', sent_at = now()
          WHERE agent_id = $1 AND status = 'queued'
          RETURNING id, update_ids, reboot_policy",
    )
    .bind(agent_id)
    .fetch_all(&st.db)
    .await?;
    let n = rows.len();
    for (run_id, ids, reboot) in rows {
        mark_installing(st, agent_id, &ids).await?;
        let reboot_policy = RebootPolicy::parse(&reboot).unwrap_or_default();
        let _ = tx.send(ServerMsg::PatchInstall { run_id, ids, reboot_policy }).await;
    }
    Ok(n)
}

async fn mark_installing(st: &AppState, agent_id: Uuid, ids: &[String]) -> sqlx::Result<()> {
    sqlx::query("UPDATE patches SET state = 'installing' WHERE agent_id = $1 AND update_id = ANY($2) AND state <> 'installed'")
        .bind(agent_id)
        .bind(ids)
        .execute(&st.db)
        .await?;
    Ok(())
}

pub enum Trigger {
    Manual(Uuid),
    Policy,
}

/// Creates an install and sends it if the agent is online (else it waits for the agent).
/// Returns the run id and whether it was sent.
pub async fn start_run(
    st: &AppState,
    agent_id: Uuid,
    update_ids: &[String],
    reboot: RebootPolicy,
    trigger: Trigger,
) -> sqlx::Result<(Uuid, bool)> {
    let run_id = Uuid::new_v4();
    let (kind, by) = match trigger {
        Trigger::Manual(u) => ("manual", Some(u)),
        Trigger::Policy => ("policy", None),
    };
    sqlx::query("INSERT INTO patch_runs (id, agent_id, update_ids, reboot_policy, trigger, created_by) VALUES ($1, $2, $3, $4, $5, $6)")
        .bind(run_id)
        .bind(agent_id)
        .bind(update_ids)
        .bind(reboot.as_str())
        .bind(kind)
        .bind(by)
        .execute(&st.db)
        .await?;
    let mut sent = false;
    if st.hub.is_online(agent_id) {
        // Claim it first, so a reconnect running dispatch_queued can't send it twice.
        let claimed = sqlx::query("UPDATE patch_runs SET status = 'sent', sent_at = now() WHERE id = $1 AND status = 'queued'")
            .bind(run_id)
            .execute(&st.db)
            .await?
            .rows_affected()
            == 1;
        if claimed {
            let msg = ServerMsg::PatchInstall { run_id, ids: update_ids.to_vec(), reboot_policy: reboot };
            if st.hub.send(agent_id, msg).await {
                mark_installing(st, agent_id, update_ids).await?;
                sent = true;
            } else {
                sqlx::query("UPDATE patch_runs SET status = 'queued', sent_at = NULL WHERE id = $1").bind(run_id).execute(&st.db).await?;
            }
        }
    }
    if let Some(c) = client_of(st, agent_id).await? {
        publish(st, agent_id, c);
    }
    Ok((run_id, sent))
}

/// Stores a scan. A failed scan keeps the previous list (it's still the best information).
#[allow(clippy::too_many_arguments)]
pub async fn ingest_scan(
    st: &AppState,
    agent_id: Uuid,
    client_id: Uuid,
    provider: &str,
    all_or_nothing: bool,
    error: Option<String>,
    updates: &[PatchUpdate],
    reboot_pending: bool,
) -> anyhow::Result<()> {
    let mut tx = st.db.begin().await?;
    let error = error.map(|e| e.chars().take(8000).collect::<String>());
    sqlx::query(
        "UPDATE agents SET patch_provider = $2, patch_all_or_nothing = $3, patch_scan_error = $4, reboot_pending = $5,
                reboot_pending_since = CASE WHEN $5 THEN coalesce(reboot_pending_since, now()) END,
                patch_scanned_at = CASE WHEN $4::text IS NULL THEN now() ELSE patch_scanned_at END,
                patch_scan_requested_at = NULL
          WHERE id = $1",
    )
    .bind(agent_id)
    .bind(provider)
    .bind(all_or_nothing)
    .bind(&error)
    .bind(reboot_pending)
    .execute(&mut *tx)
    .await?;
    if error.is_none() {
        // Dedupe: the primary key is (agent, id), and a buggy scan mustn't abort the upsert.
        let mut seen = std::collections::HashSet::new();
        let updates: Vec<&PatchUpdate> = updates.iter().filter(|u| !u.id.is_empty() && seen.insert(u.id.as_str())).take(5000).collect();
        let col = |f: fn(&PatchUpdate) -> Option<String>| updates.iter().map(|u| f(u)).collect::<Vec<_>>();
        let ids = col(|u| Some(u.id.chars().take(500).collect()));
        let titles = col(|u| Some(u.title.chars().take(1000).collect()));
        let kbs = col(|u| u.kb.clone());
        let sevs = col(|u| u.severity.map(|s| s.as_str().to_string()));
        let cats = col(|u| Some(u.category.as_str().to_string()));
        let versions = col(|u| u.version.clone());
        let currents = col(|u| u.current_version.clone());
        let sizes: Vec<Option<i64>> = updates.iter().map(|u| u.size.map(|s| s.min(i64::MAX as u64) as i64)).collect();
        let reboots: Vec<bool> = updates.iter().map(|u| u.requires_reboot).collect();
        sqlx::query(
            "INSERT INTO patches AS p (agent_id, update_id, title, kb, severity, category, size, requires_reboot, version, current_version)
             SELECT $1, * FROM unnest($2::text[], $3::text[], $4::text[], $5::text[], $6::text[], $7::bigint[], $8::bool[], $9::text[], $10::text[])
             ON CONFLICT (agent_id, update_id) DO UPDATE
                SET title = EXCLUDED.title, kb = EXCLUDED.kb, severity = EXCLUDED.severity, category = EXCLUDED.category,
                    size = EXCLUDED.size, requires_reboot = EXCLUDED.requires_reboot, current_version = EXCLUDED.current_version,
                    version = EXCLUDED.version, last_seen_at = now(),
                    -- Still offered: not installed after all. A failure stays visible until it works.
                    state = CASE WHEN p.state = 'failed' THEN 'failed' ELSE 'missing' END,
                    installed_at = NULL,
                    -- A newer version is a new attempt.
                    fail_count = CASE WHEN p.version IS DISTINCT FROM EXCLUDED.version THEN 0 ELSE p.fail_count END",
        )
        .bind(agent_id)
        .bind(&ids)
        .bind(&titles)
        .bind(&kbs)
        .bind(&sevs)
        .bind(&cats)
        .bind(&sizes)
        .bind(&reboots)
        .bind(&versions)
        .bind(&currents)
        .execute(&mut *tx)
        .await?;
        // Gone from the scan: installed (by us, by a person, or superseded).
        sqlx::query(
            "UPDATE patches SET state = 'installed', installed_at = coalesce(installed_at, now()), last_error = NULL
              WHERE agent_id = $1 AND state <> 'installed' AND NOT (update_id = ANY($2))",
        )
        .bind(agent_id)
        .bind(&ids)
        .execute(&mut *tx)
        .await?;
    }
    // In the same transaction, so nobody sees new updates before the policy has judged them.
    apply_policies(&mut tx, Some(&[agent_id])).await?;
    tx.commit().await?;
    publish(st, agent_id, client_id);
    crate::alerts::patches_changed(st, agent_id).await;
    Ok(())
}

pub async fn ingest_progress(
    st: &AppState,
    agent_id: Uuid,
    client_id: Uuid,
    run_id: Uuid,
    stage: PatchStage,
    message: Option<String>,
    percent: Option<u8>,
) -> sqlx::Result<()> {
    let n = sqlx::query(
        "UPDATE patch_runs SET stage = $3, progress = $4, percent = coalesce($5, percent)
          WHERE id = $1 AND agent_id = $2 AND status = 'sent'",
    )
    .bind(run_id)
    .bind(agent_id)
    .bind(stage.as_str())
    .bind(message.map(|m| m.chars().take(500).collect::<String>()))
    .bind(percent.map(|p| p.min(100) as i16))
    .execute(&st.db)
    .await?
    .rows_affected();
    if n > 0 {
        publish(st, agent_id, client_id);
    }
    Ok(())
}

/// Stores an install's result (idempotent: resends after reconnects change nothing).
pub async fn ingest_result(st: &AppState, agent_id: Uuid, client_id: Uuid, o: &PatchOutcome) -> anyhow::Result<()> {
    let ok = o.succeeded();
    let status = if o.error.is_none() && ok == o.results.len() && ok > 0 {
        "succeeded"
    } else if ok > 0 {
        "partial"
    } else {
        "failed"
    };
    let mut tx = st.db.begin().await?;
    // `lost` too: the reaper may have given up on an install that then reported.
    let updated: Option<String> = sqlx::query_scalar(
        "UPDATE patch_runs SET status = $3, error = $4, results = $5, reboot_required = $6, rebooting = $7, output = $8,
                duration_ms = $9, finished_at = now(), stage = NULL, percent = NULL
          WHERE id = $1 AND agent_id = $2 AND status IN ('sent', 'lost')
          RETURNING trigger",
    )
    .bind(o.run_id)
    .bind(agent_id)
    .bind(status)
    .bind(&o.error)
    .bind(serde_json::to_value(&o.results)?)
    .bind(o.reboot_required)
    .bind(o.rebooting)
    .bind(rmm_proto::patch::tail(&o.output, rmm_proto::patch::OUTPUT_MAX))
    .bind(o.duration_ms as i64)
    .fetch_optional(&mut *tx)
    .await?;
    if updated.is_some() {
        for r in &o.results {
            if r.ok {
                sqlx::query(
                    "UPDATE patches SET state = 'installed', installed_at = now(), last_error = NULL, fail_count = 0
                      WHERE agent_id = $1 AND update_id = $2",
                )
                .bind(agent_id)
                .bind(&r.id)
                .execute(&mut *tx)
                .await?;
            } else {
                sqlx::query(
                    "UPDATE patches SET state = 'failed', fail_count = fail_count + 1, last_error = $3
                      WHERE agent_id = $1 AND update_id = $2",
                )
                .bind(agent_id)
                .bind(&r.id)
                .bind(r.message.as_deref().or(o.error.as_deref()).map(|m| m.chars().take(2000).collect::<String>()))
                .execute(&mut *tx)
                .await?;
            }
        }
        if o.reboot_required {
            sqlx::query("UPDATE agents SET reboot_pending = true, reboot_pending_since = coalesce(reboot_pending_since, now()) WHERE id = $1")
                .bind(agent_id)
                .execute(&mut *tx)
                .await?;
        }
    }
    tx.commit().await?;
    if updated.is_some() {
        settle_installing(st, agent_id).await?;
        info!(%agent_id, run = %o.run_id, status, ok, requested = o.results.len(), rebooting = o.rebooting, "patch install finished");
        crate::auth::audit(
            &st.db,
            None,
            "agent.patch_result",
            Some(("agent", agent_id)),
            serde_json::json!({ "run_id": o.run_id, "status": status, "installed": ok, "requested": o.results.len(),
                                "error": o.error, "rebooting": o.rebooting }),
        )
        .await;
        publish(st, agent_id, client_id);
        crate::alerts::patches_changed(st, agent_id).await;
        // Restarting by itself needs no help; a machine that still waits for one does.
        if o.reboot_required && !o.rebooting {
            crate::automation::patch_reboot_pending(st, agent_id, o.run_id).await;
        }
    }
    Ok(())
}

/// Re-evaluates approvals for these agents (all agents with None): standing decisions a
/// person made for a scope ([`STANDING`]) first, then the approval policy. Decisions made on
/// one agent's row are left alone.
pub async fn apply_policies(db: &mut sqlx::PgConnection, agent_ids: Option<&[Uuid]>) -> sqlx::Result<u64> {
    let standing = sqlx::query(sqlx::AssertSqlSafe(format!(
        "UPDATE patches p
            SET approval = m.decision, approval_manual = true, approved_by = m.decided_by,
                approved_at = CASE WHEN m.decision = 'approved' THEN m.decided_at END
           FROM (SELECT p2.agent_id, p2.update_id, d.*
                   FROM patches p2 JOIN agents a ON a.id = p2.agent_id JOIN sites s ON s.id = a.site_id
                   CROSS JOIN LATERAL ({STANDING}) d
                  WHERE NOT p2.approval_manual AND ($1::uuid[] IS NULL OR p2.agent_id = ANY($1))) m
          WHERE p.agent_id = m.agent_id AND p.update_id = m.update_id"
    )))
    .bind(agent_ids)
    .execute(&mut *db)
    .await?
    .rows_affected();
    let by_policy = sqlx::query(
        "UPDATE patches p
            SET approval = m.approval,
                approved_at = CASE WHEN m.approval = 'approved' THEN coalesce(p.approved_at, now()) END,
                approved_by = NULL
           FROM (SELECT p2.agent_id, p2.update_id,
                        CASE WHEN p2.category = ANY(pol.auto_approve_categories) OR p2.severity = ANY(pol.auto_approve_severities)
                             THEN 'approved' ELSE 'pending' END AS approval
                   FROM patches p2 JOIN agent_patch_policy pol ON pol.agent_id = p2.agent_id
                  WHERE NOT p2.approval_manual AND ($1::uuid[] IS NULL OR p2.agent_id = ANY($1))) m
          WHERE p.agent_id = m.agent_id AND p.update_id = m.update_id AND p.approval IS DISTINCT FROM m.approval",
    )
    .bind(agent_ids)
    .execute(&mut *db)
    .await?
    .rows_affected();
    Ok(standing + by_policy)
}

/// The standing decision (`patch_approvals`) for update `p2.update_id` on agent `a` (site `s`):
/// the site's, else the client's, else the MSP-wide one.
pub const STANDING: &str = "SELECT pa.decision, pa.decided_by, pa.decided_at FROM patch_approvals pa
          WHERE pa.update_id = p2.update_id
            AND (pa.site_id = s.id OR (pa.client_id = s.client_id AND pa.site_id IS NULL) OR (pa.client_id IS NULL AND pa.site_id IS NULL))
          ORDER BY (pa.site_id IS NOT NULL) DESC, (pa.client_id IS NOT NULL) DESC LIMIT 1";

/// Every minute: request stale scans, start automatic installs, give up on silent installs.
pub async fn scheduler(st: Arc<AppState>) {
    let mut tick = tokio::time::interval(Duration::from_secs(60));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        if let Err(e) = scheduler_tick(&st).await {
            warn!("patch scheduler: {e:#}");
        }
    }
}

pub async fn scheduler_tick(st: &AppState) -> anyhow::Result<()> {
    // Installs that never reported.
    let silent: Vec<Uuid> = sqlx::query_scalar(
        "SELECT DISTINCT agent_id FROM patch_runs WHERE status = 'sent' AND sent_at < now() - make_interval(hours => $1)",
    )
    .bind(RUN_TIMEOUT_HOURS)
    .fetch_all(&st.db)
    .await?;
    for agent_id in silent {
        mark_lost(st, agent_id, None).await?;
    }
    sqlx::query(
        "UPDATE patch_runs SET status = 'expired', finished_at = now()
          WHERE status = 'queued' AND created_at < now() - make_interval(days => $1)",
    )
    .bind(st.cfg.job_queue_days as i32)
    .execute(&st.db)
    .await?;

    // Stale scans, oldest first, a batch at a time.
    let due: Vec<Uuid> = sqlx::query_scalar(
        "SELECT id FROM agents
          WHERE online AND $1 = ANY(capabilities)
            AND (patch_scanned_at IS NULL OR patch_scanned_at < now() - make_interval(hours => $2))
            AND (patch_scan_requested_at IS NULL OR patch_scan_requested_at < now() - make_interval(mins => $3))
          ORDER BY patch_scanned_at NULLS FIRST LIMIT $4",
    )
    .bind(rmm_proto::patch::CAPABILITY)
    .bind(st.cfg.patch_scan_hours as i32)
    .bind(SCAN_RETRY_MINUTES)
    .bind(SCANS_PER_TICK)
    .fetch_all(&st.db)
    .await?;
    for id in due {
        if st.hub.send(id, ServerMsg::PatchScan { request_id: Uuid::new_v4() }).await {
            sqlx::query("UPDATE agents SET patch_scan_requested_at = now() WHERE id = $1").bind(id).execute(&st.db).await?;
        }
    }

    // Automatic installs: online agents whose policy installs automatically, inside its window
    // (the policy's own, else the site's), with nothing in flight and something eligible. All-or-nothing agents
    // (pacman) only when everything they'd install is eligible.
    let sql = format!(
        "SELECT a.id, pol.reboot_policy, array_agg(p.update_id ORDER BY p.update_id)
           FROM agents a
           JOIN sites s ON s.id = a.site_id
           JOIN agent_patch_policy pol ON pol.agent_id = a.id
           JOIN patches p ON p.agent_id = a.id
          WHERE a.online AND $1 = ANY(a.capabilities) AND pol.auto_install AND a.patch_scan_error IS NULL
            AND in_maintenance_window(pol.maint_days, pol.maint_start, pol.maint_minutes, pol.maint_tz, now())
            AND NOT EXISTS (SELECT 1 FROM patch_runs r WHERE r.agent_id = a.id
                             AND (r.status IN ('queued', 'sent') OR (r.trigger = 'policy' AND r.created_at > now() - interval '30 minutes')))
            AND {ELIGIBLE}
            AND (NOT a.patch_all_or_nothing OR NOT EXISTS (
                    SELECT 1 FROM patches p WHERE p.agent_id = a.id AND p.state IN ('missing', 'failed') AND NOT ({ELIGIBLE})))
          GROUP BY a.id, pol.reboot_policy
          LIMIT 200"
    );
    let due: Vec<(Uuid, String, Vec<String>)> =
        sqlx::query_as(sqlx::AssertSqlSafe(sql)).bind(rmm_proto::patch::CAPABILITY).fetch_all(&st.db).await?;
    for (agent_id, reboot, ids) in due {
        let reboot = RebootPolicy::parse(&reboot).unwrap_or_default();
        let (run_id, sent) = start_run(st, agent_id, &ids, reboot, Trigger::Policy).await?;
        info!(%agent_id, %run_id, updates = ids.len(), sent, "automatic patch install");
    }
    wake_before_window(st).await?;
    Ok(())
}

/// A device is woken before a patch window at most this often, so one that never wakes
/// isn't sent packets every minute.
pub const WAKE_EVERY_HOURS: i32 = 12;

/// Wake-on-LAN before a patch window (the patch policy's `wake_before_minutes`): offline
/// devices that install automatically, have something eligible to install, and whose window
/// opens within that many minutes (or is open now), unless they were woken in the last
/// [`WAKE_EVERY_HOURS`].
pub async fn wake_before_window(st: &AppState) -> anyhow::Result<()> {
    let sql = format!(
        "SELECT a.id FROM agents a
           JOIN agent_patch_policy pol ON pol.agent_id = a.id
           JOIN policy_effective e ON e.set_id = a.policy_set_id AND e.item_id = pol.id
          WHERE NOT a.online AND pol.auto_install AND cardinality(pol.maint_days) > 0
            AND coalesce((e.config ->> 'wake_before_minutes')::int, 0) > 0
            AND (a.wol_sent_at IS NULL OR a.wol_sent_at < now() - make_interval(hours => $1))
            AND (in_maintenance_window(pol.maint_days, pol.maint_start, pol.maint_minutes, pol.maint_tz, now())
                 OR next_maintenance_window(pol.maint_days, pol.maint_start, pol.maint_tz, now())
                    <= now() + make_interval(mins => (e.config ->> 'wake_before_minutes')::int))
            AND EXISTS (SELECT 1 FROM patches p WHERE p.agent_id = a.id AND {ELIGIBLE})
          LIMIT 1000"
    );
    let due: Vec<Uuid> = sqlx::query_scalar(sqlx::AssertSqlSafe(sql)).bind(WAKE_EVERY_HOURS).fetch_all(&st.db).await?;
    if due.is_empty() {
        return Ok(());
    }
    let woken = crate::wol::wake(st, &due, None).await?;
    // Tried, whatever came of it: a device with no MAC or no sender waits as long as one that
    // was sent packets.
    sqlx::query("UPDATE agents SET wol_sent_at = now() WHERE id = ANY($1)")
        .bind(&due)
        .execute(&st.db)
        .await?;
    let sent = woken.iter().filter(|w| w.outcome == crate::wol::Outcome::Sent).count();
    info!(devices = due.len(), sent, "woke devices before their patch window");
    Ok(())
}

/// Housekeeping: forget installed updates and old runs.
pub async fn prune(db: &sqlx::PgPool) -> sqlx::Result<u64> {
    let a = sqlx::query("DELETE FROM patches WHERE state = 'installed' AND installed_at < now() - interval '90 days'").execute(db).await?;
    let b = sqlx::query("DELETE FROM patch_runs WHERE finished_at < now() - interval '180 days'").execute(db).await?;
    Ok(a.rows_affected() + b.rows_affected())
}
