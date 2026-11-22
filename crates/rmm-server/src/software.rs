//! Software deployment, server side (docs/design/software.md): the catalog as agents see it,
//! storing scans and run results, running installs ad hoc and as desired state from the
//! `software` policy module, and the scheduler that asks for scans and enforces the policies.
//!
//! A run is one install, upgrade or removal of one package on one agent (`software_runs`,
//! shaped like `patch_runs`: queued until the agent is online, `sent`, then a final status).
//! `software_state` holds what the agent's last scan found per package; enforcement compares
//! it with what the agent's policies ask for ([`decide`]) and starts at most one run per agent
//! at a time. Failures back off exponentially, so a package that can't be installed isn't
//! retried every minute.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use rmm_proto::ServerMsg;
use rmm_proto::patch::PatchStage;
use rmm_proto::software::{Installer, InstallerKind, Op, Outcome, Package, Status, compare_versions};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};
use uuid::Uuid;

use crate::hub::Event;
use crate::state::AppState;

/// A scan asked for and not answered is asked again after this long.
const SCAN_RETRY_MINUTES: i32 = 60;
/// An agent gets at most this many scan requests per scheduler tick, fleet-wide.
const SCANS_PER_TICK: i64 = 50;
/// A sent run with no result after this long is given up on.
const RUN_TIMEOUT_HOURS: i32 = 6;
/// Packages in one scan request.
const SCAN_PACKAGES_MAX: i64 = 2000;

fn publish(st: &AppState, agent_id: Uuid, client_id: Uuid) {
    st.hub.publish(Event::Software { agent_id, client_id });
}

async fn client_of(st: &AppState, agent_id: Uuid) -> sqlx::Result<Option<Uuid>> {
    sqlx::query_scalar("SELECT s.client_id FROM agents a JOIN sites s ON s.id = a.site_id WHERE a.id = $1").bind(agent_id).fetch_optional(&st.db).await
}

// ---------------------------------------------------------------------------
// Desired state
// ---------------------------------------------------------------------------

/// What a `software` policy item asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Want {
    /// Installed (at the pinned version, if there is one).
    Present,
    /// Installed, and upgraded whenever a newer version is on offer.
    Latest,
    Absent,
}

impl Want {
    fn rank(self) -> u8 {
        match self {
            Want::Present => 0,
            Want::Latest => 1,
            Want::Absent => 2,
        }
    }
}

/// What a scan found, for [`decide`].
#[derive(Debug, Clone, Copy, Default)]
pub struct Facts<'a> {
    pub installed: Option<&'a str>,
    pub available: Option<&'a str>,
    pub ignored: Option<&'a str>,
    pub pin: Option<&'a str>,
    /// Upgrades only start inside the policy's window (installs and removals don't wait).
    pub in_window: bool,
}

/// What to do about one package on one agent, if anything.
pub fn decide(want: Want, f: Facts) -> Option<Op> {
    // Installed, but the provider couldn't say which version: leave it be.
    let known = f.installed.filter(|v| *v != "unknown");
    match (want, f.installed) {
        (Want::Absent, Some(_)) => Some(Op::Uninstall),
        (Want::Absent, None) => None,
        (_, None) => Some(Op::Install),
        (_, Some(_)) => {
            if let (Some(pin), Some(have)) = (f.pin, known) {
                // A pin is a floor: older than it is brought up; newer isn't taken back down.
                return compare_versions(have, pin).is_lt().then_some(Op::Upgrade);
            }
            if want == Want::Latest && f.pin.is_none() && f.in_window && f.available.is_some() && f.available != f.ignored {
                return Some(Op::Upgrade);
            }
            None
        }
    }
}

/// Whether the agent meets what a policy asks of one package (for display; enforcement uses
/// [`decide`]).
pub fn compliant(want: Want, f: Facts) -> bool {
    decide(want, f).is_none() && !(want == Want::Latest && f.pin.is_none() && f.available.is_some() && f.available != f.ignored)
}

/// Several policy items can name one package on one agent; the strictest wins (absent beats
/// latest beats present).
pub fn strictest(wants: impl IntoIterator<Item = Want>) -> Option<Want> {
    wants.into_iter().max_by_key(|w| w.rank())
}

// ---------------------------------------------------------------------------
// The catalog as agents see it
// ---------------------------------------------------------------------------

#[derive(sqlx::FromRow, Clone)]
pub struct PackageRow {
    pub id: Uuid,
    pub client_id: Option<Uuid>,
    pub name: String,
    pub description: String,
    pub publisher: Option<String>,
    pub winget_id: Option<String>,
    pub choco_id: Option<String>,
    pub apt_name: Option<String>,
    pub dnf_name: Option<String>,
    pub version: Option<String>,
    pub installer_key: Option<String>,
    pub installer_name: Option<String>,
    pub installer_size: Option<i64>,
    pub installer_sha256: Option<String>,
    pub installer_kind: Option<String>,
    pub silent_args: String,
    pub uninstall_cmd: Option<String>,
    pub product_code: Option<String>,
    pub detect_name: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

pub const PACKAGE_COLS: &str = "p.id, p.client_id, p.name, p.description, p.publisher, p.winget_id, p.choco_id, p.apt_name, p.dnf_name, p.version,
    p.installer_key, p.installer_name, p.installer_size, p.installer_sha256, p.installer_kind, p.silent_args, p.uninstall_cmd, p.product_code,
    p.detect_name, p.created_at, p.updated_at";

impl PackageRow {
    pub fn to_proto(&self) -> Package {
        let installer = match (&self.installer_key, &self.installer_sha256, self.installer_kind.as_deref().and_then(InstallerKind::parse)) {
            (Some(_), Some(sha), Some(kind)) => Some(Installer {
                kind,
                size: self.installer_size.unwrap_or(0).max(0) as u64,
                sha256: sha.clone(),
                silent_args: self.silent_args.clone(),
                uninstall_cmd: self.uninstall_cmd.clone(),
                product_code: self.product_code.clone(),
                detect_name: self.detect_name.clone(),
            }),
            _ => None,
        };
        Package {
            id: self.id,
            name: self.name.clone(),
            version: self.version.clone(),
            winget: self.winget_id.clone(),
            choco: self.choco_id.clone(),
            apt: self.apt_name.clone(),
            dnf: self.dnf_name.clone(),
            installer,
        }
    }
}

/// Whether an agent running `os_family` has a way to handle the package.
pub fn usable_on(p: &PackageRow, os_family: &str) -> bool {
    match os_family {
        "windows" => p.winget_id.is_some() || p.choco_id.is_some() || p.installer_key.is_some(),
        "linux" => p.apt_name.is_some() || p.dnf_name.is_some(),
        _ => false,
    }
}

pub async fn load_package(st: &AppState, id: Uuid) -> sqlx::Result<Option<PackageRow>> {
    sqlx::query_as(sqlx::AssertSqlSafe(format!("SELECT {PACKAGE_COLS} FROM software_packages p WHERE p.id = $1"))).bind(id).fetch_optional(&st.db).await
}

/// The catalog packages an agent can use: MSP-wide and its client's, with a way to handle them
/// on its OS.
async fn packages_for(st: &AppState, agent_id: Uuid) -> sqlx::Result<Vec<Package>> {
    let rows: Vec<PackageRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT {PACKAGE_COLS} FROM software_packages p, agents a JOIN sites s ON s.id = a.site_id
          WHERE a.id = $1 AND (p.client_id IS NULL OR p.client_id = s.client_id)
            AND CASE a.os_family
                  WHEN 'windows' THEN p.winget_id IS NOT NULL OR p.choco_id IS NOT NULL OR p.installer_key IS NOT NULL
                  WHEN 'linux' THEN p.apt_name IS NOT NULL OR p.dnf_name IS NOT NULL
                  ELSE false END
          ORDER BY p.name LIMIT {SCAN_PACKAGES_MAX}"
    )))
    .bind(agent_id)
    .fetch_all(&st.db)
    .await?;
    Ok(rows.iter().map(PackageRow::to_proto).collect())
}

// ---------------------------------------------------------------------------
// Connecting, scanning
// ---------------------------------------------------------------------------

fn capable(capabilities: &[String]) -> bool {
    capabilities.iter().any(|c| c == rmm_proto::software::CAPABILITY)
}

/// A freshly authenticated agent: settle the runs it no longer holds, send queued ones, and
/// ask for a scan if the last is stale.
pub async fn on_connect(st: &AppState, agent_id: Uuid, client_id: Uuid, capabilities: &[String], held_runs: &[Uuid]) -> anyhow::Result<()> {
    if !capable(capabilities) {
        return Ok(());
    }
    let lost = mark_lost(st, agent_id, Some(held_runs)).await?;
    let sent = dispatch_queued(st, agent_id).await?;
    let stale: bool = sqlx::query_scalar(
        "SELECT NOT EXISTS (SELECT 1 FROM software_agent_status s WHERE s.agent_id = $1 AND s.scanned_at > now() - make_interval(hours => $2))",
    )
    .bind(agent_id)
    .bind(st.cfg.patch_scan_hours as i32)
    .fetch_one(&st.db)
    .await?;
    if stale {
        request_scan(st, agent_id).await?;
    } else {
        // Nothing to learn, but the device may have joined a policy set while it was away.
        evaluate(st, Some(&[agent_id])).await?;
    }
    if lost > 0 || sent > 0 {
        publish(st, agent_id, client_id);
    }
    Ok(())
}

/// Asks the agent for a scan of every catalog package it can use. Returns whether it was sent.
pub async fn request_scan(st: &AppState, agent_id: Uuid) -> sqlx::Result<bool> {
    let packages = packages_for(st, agent_id).await?;
    if !st.hub.send(agent_id, ServerMsg::SoftwareScan { request_id: Uuid::new_v4(), packages }).await {
        return Ok(false);
    }
    sqlx::query(
        "INSERT INTO software_agent_status (agent_id, requested_at) VALUES ($1, now())
         ON CONFLICT (agent_id) DO UPDATE SET requested_at = now()",
    )
    .bind(agent_id)
    .execute(&st.db)
    .await?;
    Ok(true)
}

/// Scans these agents now (those online and able). Returns how many were asked.
pub async fn scan_now(st: &AppState, agent_ids: &[Uuid]) -> sqlx::Result<usize> {
    let capable: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM agents WHERE id = ANY($1) AND online AND $2 = ANY(capabilities)")
        .bind(agent_ids)
        .bind(rmm_proto::software::CAPABILITY)
        .fetch_all(&st.db)
        .await?;
    let mut n = 0;
    for id in capable {
        if request_scan(st, id).await? {
            n += 1;
            if let Some(c) = client_of(st, id).await? {
                publish(st, id, c);
            }
        }
    }
    Ok(n)
}

/// Stores a scan: one row per package reported (packages it didn't mention keep what they
/// had). A failed scan changes nothing but the agent's status.
pub async fn ingest_scan(st: &AppState, agent_id: Uuid, client_id: Uuid, providers: Vec<String>, error: Option<String>, items: &[Status]) -> anyhow::Result<()> {
    let error = error.map(|e| e.chars().take(8000).collect::<String>());
    let mut tx = st.db.begin().await?;
    sqlx::query(
        "INSERT INTO software_agent_status (agent_id, providers, scanned_at, requested_at, error)
         VALUES ($1, $2, CASE WHEN $3::text IS NULL THEN now() END, NULL, $3)
         ON CONFLICT (agent_id) DO UPDATE
            SET providers = EXCLUDED.providers, requested_at = NULL, error = EXCLUDED.error,
                scanned_at = CASE WHEN EXCLUDED.error IS NULL THEN now() ELSE software_agent_status.scanned_at END",
    )
    .bind(agent_id)
    .bind(&providers)
    .bind(&error)
    .execute(&mut *tx)
    .await?;
    if !items.is_empty() {
        let mut seen = std::collections::HashSet::new();
        let items: Vec<&Status> = items.iter().filter(|s| seen.insert(s.package_id)).take(SCAN_PACKAGES_MAX as usize).collect();
        let clip = |s: &Option<String>| s.as_ref().map(|v| v.chars().take(200).collect::<String>());
        let ids: Vec<Uuid> = items.iter().map(|s| s.package_id).collect();
        let installed: Vec<Option<String>> = items.iter().map(|s| clip(&s.installed)).collect();
        let available: Vec<Option<String>> = items.iter().map(|s| clip(&s.available)).collect();
        let provider: Vec<Option<String>> = items.iter().map(|s| clip(&s.provider)).collect();
        // Packages deleted from the catalog since the request are skipped by the join.
        sqlx::query(
            "INSERT INTO software_state AS st (agent_id, package_id, installed_version, available_version, provider, checked_at)
             SELECT $1, u.id, u.installed, u.available, u.provider, now()
               FROM unnest($2::uuid[], $3::text[], $4::text[], $5::text[]) AS u(id, installed, available, provider)
               JOIN software_packages p ON p.id = u.id
             ON CONFLICT (agent_id, package_id) DO UPDATE
                SET installed_version = EXCLUDED.installed_version, available_version = EXCLUDED.available_version,
                    provider = EXCLUDED.provider, checked_at = now()",
        )
        .bind(agent_id)
        .bind(&ids)
        .bind(&installed)
        .bind(&available)
        .bind(&provider)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    publish(st, agent_id, client_id);
    evaluate(st, Some(&[agent_id])).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Runs
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
pub enum Trigger {
    Manual(Uuid),
    /// Started by enforcement of this policy item.
    Policy(Uuid),
}

/// Creates a run and sends it if the agent is online (else it waits for the agent). Returns the
/// run id and whether it was sent.
pub async fn start_run(st: &AppState, agent_id: Uuid, pkg: &PackageRow, op: Op, trigger: Trigger, bootstrap_choco: bool) -> sqlx::Result<(Uuid, bool)> {
    let run_id = Uuid::new_v4();
    let (kind, by, item) = match trigger {
        Trigger::Manual(u) => ("manual", Some(u), None),
        Trigger::Policy(i) => ("policy", None, Some(i)),
    };
    let from: Option<String> = sqlx::query_scalar("SELECT installed_version FROM software_state WHERE agent_id = $1 AND package_id = $2")
        .bind(agent_id)
        .bind(pkg.id)
        .fetch_optional(&st.db)
        .await?
        .flatten();
    sqlx::query(
        "INSERT INTO software_runs (id, agent_id, package_id, package_name, op, trigger, policy_item_id, created_by, bootstrap_choco, from_version)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
    )
    .bind(run_id)
    .bind(agent_id)
    .bind(pkg.id)
    .bind(&pkg.name)
    .bind(op.as_str())
    .bind(kind)
    .bind(item)
    .bind(by)
    .bind(bootstrap_choco)
    .bind(from)
    .execute(&st.db)
    .await?;
    if kind == "policy" {
        sqlx::query("UPDATE software_state SET last_attempt_at = now() WHERE agent_id = $1 AND package_id = $2").bind(agent_id).bind(pkg.id).execute(&st.db).await?;
    }
    let mut sent = false;
    if st.hub.is_online(agent_id) {
        // Claim it first, so a reconnect running dispatch_queued can't send it twice.
        let claimed = sqlx::query("UPDATE software_runs SET status = 'sent', sent_at = now() WHERE id = $1 AND status = 'queued'")
            .bind(run_id)
            .execute(&st.db)
            .await?
            .rows_affected()
            == 1;
        if claimed {
            let msg = ServerMsg::SoftwareRun { run_id, op, package: pkg.to_proto(), bootstrap_choco };
            if st.hub.send(agent_id, msg).await {
                sent = true;
            } else {
                sqlx::query("UPDATE software_runs SET status = 'queued', sent_at = NULL WHERE id = $1").bind(run_id).execute(&st.db).await?;
            }
        }
    }
    if let Some(c) = client_of(st, agent_id).await? {
        publish(st, agent_id, c);
    }
    Ok((run_id, sent))
}

/// Sends this agent's queued runs, oldest first. Returns how many.
async fn dispatch_queued(st: &AppState, agent_id: Uuid) -> sqlx::Result<usize> {
    let rows: Vec<(Uuid, Option<Uuid>, String, bool)> = sqlx::query_as(
        "UPDATE software_runs SET status = 'sent', sent_at = now()
          WHERE agent_id = $1 AND status = 'queued' RETURNING id, package_id, op, bootstrap_choco",
    )
    .bind(agent_id)
    .fetch_all(&st.db)
    .await?;
    let mut sent = 0;
    for (run_id, package_id, op, bootstrap_choco) in rows {
        let pkg = match package_id {
            Some(id) => load_package(st, id).await?,
            None => None,
        };
        let (Some(pkg), Some(op)) = (pkg, Op::parse(&op)) else {
            sqlx::query("UPDATE software_runs SET status = 'cancelled', finished_at = now(), error = 'the package was deleted from the catalog' WHERE id = $1").bind(run_id).execute(&st.db).await?;
            continue;
        };
        if st.hub.send(agent_id, ServerMsg::SoftwareRun { run_id, op, package: pkg.to_proto(), bootstrap_choco }).await {
            sent += 1;
        } else {
            sqlx::query("UPDATE software_runs SET status = 'queued', sent_at = NULL WHERE id = $1").bind(run_id).execute(&st.db).await?;
        }
    }
    Ok(sent)
}

/// Runs the agent can't report on any more become `lost`: those it didn't list when it
/// reconnected (`held`), or (with `held` None) those sent too long ago.
pub async fn mark_lost(st: &AppState, agent_id: Uuid, held: Option<&[Uuid]>) -> sqlx::Result<u64> {
    let n = sqlx::query(
        "UPDATE software_runs SET status = 'lost', finished_at = now(),
                error = coalesce(error, 'the agent stopped reporting on this run (it restarted, or the result was lost)')
          WHERE agent_id = $1 AND status = 'sent'
            AND CASE WHEN $2::uuid[] IS NULL THEN sent_at < now() - make_interval(hours => $3) ELSE NOT (id = ANY($2)) END",
    )
    .bind(agent_id)
    .bind(held)
    .bind(RUN_TIMEOUT_HOURS)
    .execute(&st.db)
    .await?
    .rows_affected();
    if n > 0 {
        info!(%agent_id, runs = n, "software runs lost");
    }
    Ok(n)
}

pub async fn ingest_progress(st: &AppState, agent_id: Uuid, client_id: Uuid, run_id: Uuid, stage: PatchStage, message: Option<String>) -> sqlx::Result<()> {
    let n = sqlx::query("UPDATE software_runs SET stage = $3, progress = $4 WHERE id = $1 AND agent_id = $2 AND status = 'sent'")
        .bind(run_id)
        .bind(agent_id)
        .bind(stage.as_str())
        .bind(message.map(|m| m.chars().take(500).collect::<String>()))
        .execute(&st.db)
        .await?
        .rows_affected();
    if n > 0 {
        publish(st, agent_id, client_id);
    }
    Ok(())
}

/// Stores a run's result (idempotent: resends after reconnects change nothing).
pub async fn ingest_result(st: &AppState, agent_id: Uuid, client_id: Uuid, o: &Outcome) -> anyhow::Result<()> {
    let status = if o.ok { "succeeded" } else { "failed" };
    let error = (!o.ok).then(|| o.message.clone().unwrap_or_else(|| "failed".into())).map(|m| m.chars().take(4000).collect::<String>());
    let mut tx = st.db.begin().await?;
    // `lost` too: the reaper may have given up on a run that then reported.
    let row: Option<(Option<Uuid>, String, String)> = sqlx::query_as(
        "UPDATE software_runs SET status = $3, error = $4, provider = $5, to_version = $6, reboot_required = $7, output = $8,
                duration_ms = $9, finished_at = now(), stage = NULL, progress = coalesce(progress, $10)
          WHERE id = $1 AND agent_id = $2 AND status IN ('sent', 'lost')
          RETURNING package_id, trigger, op",
    )
    .bind(o.run_id)
    .bind(agent_id)
    .bind(status)
    .bind(&error)
    .bind(&o.provider)
    .bind(&o.installed_version)
    .bind(o.reboot_required)
    .bind(rmm_proto::patch::tail(&o.output, rmm_proto::software::OUTPUT_MAX))
    .bind(o.duration_ms as i64)
    .bind(o.ok.then(|| o.message.clone()).flatten())
    .fetch_optional(&mut *tx)
    .await?;
    let Some((package_id, trigger, op)) = row else {
        tx.commit().await?;
        return Ok(());
    };
    if let Some(package_id) = package_id {
        if o.ok {
            // What the agent verified after the run is the state now; waiting for its rescan
            // would let enforcement see the old one and start the run again.
            sqlx::query(
                "UPDATE software_state SET installed_version = $3, checked_at = now(), fail_count = 0, last_error = NULL,
                        available_version = CASE WHEN $3::text IS NULL OR available_version = $3 THEN NULL ELSE available_version END
                  WHERE agent_id = $1 AND package_id = $2",
            )
            .bind(agent_id)
            .bind(package_id)
            .bind(&o.installed_version)
            .execute(&mut *tx)
            .await?;
        } else {
            // Only runs enforcement started count toward backing off; a technician's retry is theirs.
            sqlx::query(
                "UPDATE software_state SET fail_count = fail_count + CASE WHEN $3 = 'policy' THEN 1 ELSE 0 END, last_error = $4
                  WHERE agent_id = $1 AND package_id = $2",
            )
            .bind(agent_id)
            .bind(package_id)
            .bind(&trigger)
            .bind(&error)
            .execute(&mut *tx)
            .await?;
        }
    }
    if o.reboot_required {
        sqlx::query("UPDATE agents SET reboot_pending = true, reboot_pending_since = coalesce(reboot_pending_since, now()) WHERE id = $1").bind(agent_id).execute(&mut *tx).await?;
    }
    tx.commit().await?;
    info!(%agent_id, run = %o.run_id, status, op, "software run finished");
    crate::auth::audit(
        &st.db,
        None,
        "agent.software_result",
        Some(("agent", agent_id)),
        serde_json::json!({ "run_id": o.run_id, "op": op, "status": status, "package_id": package_id, "provider": o.provider, "version": o.installed_version, "error": error }),
    )
    .await;
    publish(st, agent_id, client_id);
    // Chain the next requirement.
    evaluate(st, Some(&[agent_id])).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Enforcement
// ---------------------------------------------------------------------------

#[derive(sqlx::FromRow)]
struct Candidate {
    agent_id: Uuid,
    item_id: Uuid,
    config: serde_json::Value,
    installed: Option<String>,
    available: Option<String>,
    ignored: Option<String>,
    in_window: bool,
    #[sqlx(flatten)]
    pkg: PackageRow,
}

/// What a `software` item's config says, as far as enforcement cares.
fn read_config(c: &serde_json::Value) -> Option<(Want, bool)> {
    let want = serde_json::from_value(c.get("state")?.clone()).ok()?;
    Some((want, c.get("bootstrap_choco").and_then(|v| v.as_bool()).unwrap_or(false)))
}

/// Starts the runs the policies of these agents ask for (None: every online agent). One run per
/// agent at a time; the result of each starts the next.
pub async fn evaluate(st: &AppState, agent_ids: Option<&[Uuid]>) -> anyhow::Result<usize> {
    let rows: Vec<Candidate> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT a.id AS agent_id, ap.item_id, ap.config, ss.installed_version AS installed, ss.available_version AS available,
                ss.ignored_version AS ignored,
                in_maintenance_window(
                    CASE WHEN jsonb_typeof(ap.config -> 'window') = 'object'
                         THEN ARRAY(SELECT d::smallint FROM jsonb_array_elements_text(ap.config -> 'window' -> 'days') d) ELSE s.maint_days END,
                    CASE WHEN jsonb_typeof(ap.config -> 'window') = 'object' THEN (ap.config -> 'window' ->> 'start')::time ELSE s.maint_start END,
                    CASE WHEN jsonb_typeof(ap.config -> 'window') = 'object' THEN (ap.config -> 'window' ->> 'minutes')::int ELSE s.maint_minutes END,
                    CASE WHEN jsonb_typeof(ap.config -> 'window') = 'object' AND ap.config -> 'window' ->> 'tz' <> 'site'
                         THEN ap.config -> 'window' ->> 'tz' ELSE s.maint_tz END,
                    now()) AS in_window,
                {PACKAGE_COLS}
           FROM agents a
           JOIN sites s ON s.id = a.site_id
           JOIN agent_policy ap ON ap.agent_id = a.id AND ap.module = 'software' AND ap.enabled
           JOIN software_packages p ON p.id = (ap.config ->> 'package_id')::uuid AND (p.client_id IS NULL OR p.client_id = s.client_id)
           JOIN software_state ss ON ss.agent_id = a.id AND ss.package_id = p.id AND ss.provider IS NOT NULL
          WHERE a.online AND $1 = ANY(a.capabilities) AND ($2::uuid[] IS NULL OR a.id = ANY($2))
            AND NOT EXISTS (SELECT 1 FROM software_runs r WHERE r.agent_id = a.id AND r.status IN ('queued', 'sent'))
            AND (ss.fail_count = 0 OR ss.last_attempt_at IS NULL
                 OR ss.last_attempt_at < now() - make_interval(mins => least(24 * 60, 15 * (1 << least(ss.fail_count - 1, 7)))::int))
          ORDER BY a.id, p.name
          LIMIT 5000"
    )))
    .bind(rmm_proto::software::CAPABILITY)
    .bind(agent_ids)
    .fetch_all(&st.db)
    .await?;

    // Per agent and package: the strictest want. Then the first package with something to do.
    let mut by: HashMap<(Uuid, Uuid), Vec<&Candidate>> = HashMap::new();
    let mut order: Vec<(Uuid, Uuid)> = Vec::new();
    for c in &rows {
        let k = (c.agent_id, c.pkg.id);
        if !by.contains_key(&k) {
            order.push(k);
        }
        by.entry(k).or_default().push(c);
    }
    let mut started = 0;
    let mut busy = std::collections::HashSet::new();
    for k in order {
        if busy.contains(&k.0) {
            continue;
        }
        let cands = &by[&k];
        let wants: Vec<(Want, bool, Uuid)> = cands.iter().filter_map(|c| read_config(&c.config).map(|(w, b)| (w, b, c.item_id))).collect();
        let Some(want) = strictest(wants.iter().map(|w| w.0)) else { continue };
        let first = cands[0];
        let facts = Facts {
            installed: first.installed.as_deref(),
            available: first.available.as_deref(),
            ignored: first.ignored.as_deref(),
            pin: first.pkg.version.as_deref(),
            // Any item of the strongest kind may open the window.
            in_window: cands.iter().any(|c| c.in_window && read_config(&c.config).is_some_and(|(w, _)| w == want)),
        };
        let Some(op) = decide(want, facts) else { continue };
        if op != Op::Uninstall && !has_source(&first.pkg) {
            continue;
        }
        let (_, bootstrap, item) = wants.iter().find(|w| w.0 == want).copied().unwrap_or((want, false, first.item_id));
        let (run_id, sent) = start_run(st, k.0, &first.pkg, op, Trigger::Policy(item), bootstrap).await?;
        info!(agent_id = %k.0, %run_id, package = %first.pkg.name, op = op.as_str(), sent, "software policy run");
        busy.insert(k.0);
        started += 1;
    }
    Ok(started)
}

fn has_source(p: &PackageRow) -> bool {
    p.winget_id.is_some() || p.choco_id.is_some() || p.apt_name.is_some() || p.dnf_name.is_some() || p.installer_key.is_some()
}

/// After a policy change: agents that now have software requirements without scan data for
/// them get a scan; everything else is evaluated against what is known.
pub async fn policy_changed(st: &AppState, agents: Option<&[Uuid]>) {
    let res = async {
        let missing: Vec<Uuid> = sqlx::query_scalar(
            "SELECT DISTINCT a.id FROM agents a
               JOIN agent_policy ap ON ap.agent_id = a.id AND ap.module = 'software' AND ap.enabled
              WHERE a.online AND $1 = ANY(a.capabilities) AND ($2::uuid[] IS NULL OR a.id = ANY($2))
                AND NOT EXISTS (SELECT 1 FROM software_state ss WHERE ss.agent_id = a.id AND ss.package_id = (ap.config ->> 'package_id')::uuid)
              LIMIT 500",
        )
        .bind(rmm_proto::software::CAPABILITY)
        .bind(agents)
        .fetch_all(&st.db)
        .await?;
        for id in missing {
            request_scan(st, id).await?;
        }
        evaluate(st, agents).await
    }
    .await;
    if let Err(e) = res {
        warn!("software policy changed: {e:#}");
    }
}

/// Every minute: give up on silent runs, expire old queued ones, request stale scans, enforce.
pub async fn scheduler(st: Arc<AppState>) {
    let mut tick = tokio::time::interval(Duration::from_secs(60));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        if let Err(e) = scheduler_tick(&st).await {
            warn!("software scheduler: {e:#}");
        }
    }
}

pub async fn scheduler_tick(st: &AppState) -> anyhow::Result<()> {
    let silent: Vec<Uuid> = sqlx::query_scalar("SELECT DISTINCT agent_id FROM software_runs WHERE status = 'sent' AND sent_at < now() - make_interval(hours => $1)")
        .bind(RUN_TIMEOUT_HOURS)
        .fetch_all(&st.db)
        .await?;
    for agent_id in silent {
        mark_lost(st, agent_id, None).await?;
    }
    sqlx::query("UPDATE software_runs SET status = 'expired', finished_at = now() WHERE status = 'queued' AND created_at < now() - make_interval(days => $1)")
        .bind(st.cfg.job_queue_days as i32)
        .execute(&st.db)
        .await?;

    // Stale scans, oldest first, a batch at a time. Agents with no catalog to scan have nothing
    // to learn.
    let any: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM software_packages)").fetch_one(&st.db).await?;
    if !any {
        return Ok(());
    }
    let due: Vec<Uuid> = sqlx::query_scalar(
        "SELECT a.id FROM agents a LEFT JOIN software_agent_status ss ON ss.agent_id = a.id
          WHERE a.online AND $1 = ANY(a.capabilities)
            AND (ss.scanned_at IS NULL OR ss.scanned_at < now() - make_interval(hours => $2))
            AND (ss.requested_at IS NULL OR ss.requested_at < now() - make_interval(mins => $3))
          ORDER BY ss.scanned_at NULLS FIRST LIMIT $4",
    )
    .bind(rmm_proto::software::CAPABILITY)
    .bind(st.cfg.patch_scan_hours as i32)
    .bind(SCAN_RETRY_MINUTES)
    .bind(SCANS_PER_TICK)
    .fetch_all(&st.db)
    .await?;
    for id in due {
        request_scan(st, id).await?;
    }
    // Retries after a back-off, windows opening, devices that joined a set.
    let has_items: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM policy_items WHERE module = 'software' AND enabled)").fetch_one(&st.db).await?;
    if has_items {
        evaluate(st, None).await?;
    }
    Ok(())
}

/// Housekeeping: forget old runs.
pub async fn prune(db: &sqlx::PgPool) -> sqlx::Result<u64> {
    Ok(sqlx::query("DELETE FROM software_runs WHERE finished_at < now() - interval '180 days'").execute(db).await?.rows_affected())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f<'a>(installed: Option<&'a str>, available: Option<&'a str>, pin: Option<&'a str>) -> Facts<'a> {
        Facts { installed, available, ignored: None, pin, in_window: true }
    }

    #[test]
    fn present_installs_what_is_missing_and_leaves_the_rest() {
        assert_eq!(decide(Want::Present, f(None, None, None)), Some(Op::Install));
        assert_eq!(decide(Want::Present, f(Some("1.0"), Some("2.0"), None)), None, "present doesn't chase upgrades");
        assert_eq!(decide(Want::Present, f(Some("unknown"), None, None)), None);
    }

    #[test]
    fn pins_are_a_floor() {
        assert_eq!(decide(Want::Present, f(Some("1.0"), None, Some("1.5"))), Some(Op::Upgrade));
        assert_eq!(decide(Want::Present, f(Some("1.5"), None, Some("1.5"))), None);
        assert_eq!(decide(Want::Latest, f(Some("2.0"), Some("3.0"), Some("1.5"))), None, "a pinned package isn't kept current");
        assert_eq!(decide(Want::Present, f(Some("unknown"), None, Some("1.5"))), None);
        assert_eq!(decide(Want::Present, f(None, None, Some("1.5"))), Some(Op::Install));
    }

    #[test]
    fn latest_upgrades_in_the_window_unless_ignored() {
        assert_eq!(decide(Want::Latest, f(Some("1.0"), Some("2.0"), None)), Some(Op::Upgrade));
        let mut x = f(Some("1.0"), Some("2.0"), None);
        x.in_window = false;
        assert_eq!(decide(Want::Latest, x), None);
        assert_eq!(decide(Want::Latest, Facts { ignored: Some("2.0"), ..f(Some("1.0"), Some("2.0"), None) }), None);
        assert_eq!(decide(Want::Latest, Facts { ignored: Some("2.0"), ..f(Some("1.0"), Some("2.1"), None) }), Some(Op::Upgrade));
        assert_eq!(decide(Want::Latest, f(Some("1.0"), None, None)), None);
    }

    #[test]
    fn absent_removes() {
        assert_eq!(decide(Want::Absent, f(Some("1.0"), None, None)), Some(Op::Uninstall));
        assert_eq!(decide(Want::Absent, f(Some("unknown"), None, None)), Some(Op::Uninstall));
        assert_eq!(decide(Want::Absent, f(None, None, None)), None);
    }

    #[test]
    fn compliance_follows_the_want() {
        assert!(compliant(Want::Present, f(Some("1.0"), Some("2.0"), None)));
        assert!(!compliant(Want::Latest, f(Some("1.0"), Some("2.0"), None)));
        assert!(compliant(Want::Latest, Facts { ignored: Some("2.0"), ..f(Some("1.0"), Some("2.0"), None) }));
        assert!(!compliant(Want::Absent, f(Some("1.0"), None, None)));
        assert!(compliant(Want::Absent, f(None, None, None)));
        assert!(!compliant(Want::Present, f(None, None, None)));
    }

    #[test]
    fn strictest_want_wins() {
        assert_eq!(strictest([Want::Present, Want::Absent, Want::Latest]), Some(Want::Absent));
        assert_eq!(strictest([Want::Present, Want::Latest]), Some(Want::Latest));
        assert_eq!(strictest([]), None);
    }
}
