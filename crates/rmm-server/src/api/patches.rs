//! Patch management API: updates across the fleet and per agent, approvals, installs,
//! compliance, policies and maintenance windows. Everything is limited to the clients the
//! user can see.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, Query, State};
use chrono::{DateTime, NaiveTime, Utc};
use rmm_proto::patch::{Category, RebootPolicy, Severity};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::AssertSqlSafe;
use uuid::Uuid;

use crate::auth::{self, Role, User};
use crate::error::{ApiError, ApiResult};
use crate::patches::{self as core, Trigger};
use crate::state::AppState;

/// Most severe first; unrated last.
const SEVERITY_RANK: &str = "coalesce(array_position(ARRAY['critical','important','moderate','low'], p.severity), 5)";
/// The MSP-wide policy, created by the migration. It can be edited but not deleted.
const GLOBAL_POLICY: Uuid = Uuid::from_u128(0x00000000_0000_4000_8000_000000000001);

fn csv(s: &Option<String>) -> Option<Vec<String>> {
    s.as_deref().filter(|s| !s.is_empty()).map(|s| s.split(',').map(str::trim).map(str::to_string).collect())
}

// ---------------------------------------------------------------------------
// Fleet view: one row per update
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct ListQuery {
    client_id: Option<Uuid>,
    site_id: Option<Uuid>,
    agent_id: Option<Uuid>,
    /// Title, KB/advisory or id.
    q: Option<String>,
    /// Comma-separated; `unspecified` matches unrated updates.
    severity: Option<String>,
    category: Option<String>,
    /// Only updates with at least one agent in this approval state (still missing).
    approval: Option<String>,
    /// `missing` (default): still needed somewhere. `all`: include fully installed ones.
    state: Option<String>,
    os: Option<String>,
}

#[derive(Serialize, sqlx::FromRow)]
pub struct UpdateGroup {
    update_id: String,
    title: String,
    kb: Option<String>,
    severity: Option<String>,
    category: String,
    size: Option<i64>,
    requires_reboot: bool,
    /// Agents that still need it (including failed and installing).
    missing: i64,
    installed: i64,
    failed: i64,
    installing: i64,
    /// Of the agents that still need it:
    approved: i64,
    pending: i64,
    declined: i64,
    first_seen_at: DateTime<Utc>,
    #[serde(skip)]
    total: i64,
}

pub async fn list(State(st): State<Arc<AppState>>, u: User, Query(q): Query<ListQuery>) -> ApiResult<Json<serde_json::Value>> {
    let severity = csv(&q.severity);
    let category = csv(&q.category);
    let search = q.q.as_deref().map(str::trim).filter(|s| !s.is_empty());
    let approval = q.approval.as_deref().filter(|s| !s.is_empty());
    let all = q.state.as_deref() == Some("all");
    let os = q.os.as_deref().filter(|s| !s.is_empty());
    let sql = format!(
        "SELECT p.update_id,
                (array_agg(p.title ORDER BY p.last_seen_at DESC))[1] AS title,
                max(p.kb) AS kb,
                (array_agg(p.severity ORDER BY {SEVERITY_RANK}))[1] AS severity,
                (array_agg(p.category ORDER BY p.last_seen_at DESC))[1] AS category,
                max(p.size) AS size,
                bool_or(p.requires_reboot) AS requires_reboot,
                count(*) FILTER (WHERE p.state <> 'installed') AS missing,
                count(*) FILTER (WHERE p.state = 'installed') AS installed,
                count(*) FILTER (WHERE p.state = 'failed') AS failed,
                count(*) FILTER (WHERE p.state = 'installing') AS installing,
                count(*) FILTER (WHERE p.state <> 'installed' AND p.approval = 'approved') AS approved,
                count(*) FILTER (WHERE p.state <> 'installed' AND p.approval = 'pending') AS pending,
                count(*) FILTER (WHERE p.state <> 'installed' AND p.approval = 'declined') AS declined,
                min(p.first_seen_at) AS first_seen_at,
                count(*) OVER () AS total
           FROM patches p JOIN agents a ON a.id = p.agent_id JOIN sites s ON s.id = a.site_id
          WHERE ($1::uuid[] IS NULL OR s.client_id = ANY($1))
            AND ($2::uuid IS NULL OR s.client_id = $2)
            AND ($3::uuid IS NULL OR s.id = $3)
            AND ($4::uuid IS NULL OR a.id = $4)
            AND ($5::text IS NULL OR p.title ILIKE '%' || $5 || '%' OR p.kb ILIKE '%' || $5 || '%' OR p.update_id ILIKE $5 || '%')
            AND ($6::text[] IS NULL OR coalesce(p.severity, 'unspecified') = ANY($6))
            AND ($7::text[] IS NULL OR p.category = ANY($7))
            AND ($10::text IS NULL OR a.os_family = $10)
          GROUP BY p.update_id
         HAVING ($9 OR count(*) FILTER (WHERE p.state <> 'installed') > 0)
            AND ($8::text IS NULL OR count(*) FILTER (WHERE p.state <> 'installed' AND p.approval = $8) > 0)
          ORDER BY min({SEVERITY_RANK}), bool_or(p.category = 'security') DESC, count(*) FILTER (WHERE p.state <> 'installed') DESC,
                   (array_agg(p.title ORDER BY p.last_seen_at DESC))[1]
          LIMIT 500"
    );
    let rows: Vec<UpdateGroup> = sqlx::query_as(AssertSqlSafe(sql))
        .bind(u.scope())
        .bind(q.client_id)
        .bind(q.site_id)
        .bind(q.agent_id)
        .bind(search)
        .bind(&severity)
        .bind(&category)
        .bind(approval)
        .bind(all)
        .bind(os)
        .fetch_all(&st.db)
        .await?;
    let total = rows.first().map_or(0, |r| r.total);
    Ok(Json(json!({ "items": rows, "total": total, "truncated": total > 500 })))
}

#[derive(Deserialize)]
pub struct AgentsQuery {
    update_id: String,
    client_id: Option<Uuid>,
    site_id: Option<Uuid>,
}

#[derive(Serialize, sqlx::FromRow)]
pub struct UpdateAgent {
    agent_id: Uuid,
    hostname: String,
    online: bool,
    os_family: String,
    client_id: Uuid,
    client_name: String,
    site_name: String,
    state: String,
    approval: String,
    approval_manual: bool,
    approved_by_name: Option<String>,
    approved_at: Option<DateTime<Utc>>,
    version: Option<String>,
    current_version: Option<String>,
    first_seen_at: DateTime<Utc>,
    installed_at: Option<DateTime<Utc>>,
    last_error: Option<String>,
    fail_count: i32,
}

/// The agents one update applies to.
pub async fn agents_for_update(
    State(st): State<Arc<AppState>>,
    u: User,
    Query(q): Query<AgentsQuery>,
) -> ApiResult<Json<Vec<UpdateAgent>>> {
    Ok(Json(
        sqlx::query_as(
            "SELECT p.agent_id, a.hostname, a.online, a.os_family, c.id AS client_id, c.name AS client_name, s.name AS site_name,
                    p.state, p.approval, p.approval_manual, us.name AS approved_by_name, p.approved_at, p.version, p.current_version,
                    p.first_seen_at, p.installed_at, p.last_error, p.fail_count
               FROM patches p JOIN agents a ON a.id = p.agent_id JOIN sites s ON s.id = a.site_id JOIN clients c ON c.id = s.client_id
               LEFT JOIN users us ON us.id = p.approved_by
              WHERE p.update_id = $1 AND ($2::uuid[] IS NULL OR c.id = ANY($2))
                AND ($3::uuid IS NULL OR c.id = $3) AND ($4::uuid IS NULL OR s.id = $4)
              ORDER BY p.state = 'installed', lower(a.hostname)
              LIMIT 5000",
        )
        .bind(&q.update_id)
        .bind(u.scope())
        .bind(q.client_id)
        .bind(q.site_id)
        .fetch_all(&st.db)
        .await?,
    ))
}

// ---------------------------------------------------------------------------
// One agent
// ---------------------------------------------------------------------------

#[derive(Serialize, sqlx::FromRow)]
pub struct AgentPatch {
    update_id: String,
    title: String,
    kb: Option<String>,
    severity: Option<String>,
    category: String,
    size: Option<i64>,
    requires_reboot: bool,
    version: Option<String>,
    current_version: Option<String>,
    state: String,
    approval: String,
    approval_manual: bool,
    approved_by_name: Option<String>,
    approved_at: Option<DateTime<Utc>>,
    first_seen_at: DateTime<Utc>,
    installed_at: Option<DateTime<Utc>>,
    last_error: Option<String>,
    fail_count: i32,
    /// When an automatically approved update becomes eligible (deferral), if it isn't yet.
    deferred_until: Option<DateTime<Utc>>,
}

#[derive(Serialize, sqlx::FromRow)]
pub struct PatchStatus {
    supported: bool,
    online: bool,
    os_family: String,
    provider: Option<String>,
    all_or_nothing: bool,
    scanned_at: Option<DateTime<Utc>>,
    scan_requested_at: Option<DateTime<Utc>>,
    scan_error: Option<String>,
    reboot_pending: bool,
}

#[derive(Serialize, sqlx::FromRow)]
pub struct Policy {
    id: Uuid,
    client_id: Option<Uuid>,
    site_id: Option<Uuid>,
    client_name: Option<String>,
    site_name: Option<String>,
    auto_approve_severities: Vec<String>,
    auto_approve_categories: Vec<String>,
    deferral_days: i32,
    auto_install: bool,
    reboot_policy: String,
    updated_by_name: Option<String>,
    updated_at: DateTime<Utc>,
    /// Agents it applies to (within the user's clients).
    #[sqlx(default)]
    agents: i64,
    /// For an agent's effective policy: `site`, `client` or `global`.
    #[sqlx(default)]
    source: Option<String>,
}

const POLICY_COLS: &str = "p.id, p.client_id, p.site_id, c.name AS client_name, s.name AS site_name, p.auto_approve_severities,
       p.auto_approve_categories, p.deferral_days, p.auto_install, p.reboot_policy, us.name AS updated_by_name, p.updated_at";
const POLICY_JOINS: &str =
    "LEFT JOIN clients c ON c.id = p.client_id LEFT JOIN sites s ON s.id = p.site_id LEFT JOIN users us ON us.id = p.updated_by";

#[derive(Serialize, sqlx::FromRow)]
pub struct Window {
    site_id: Uuid,
    site_name: String,
    client_id: Uuid,
    client_name: String,
    days: Option<Vec<i16>>,
    /// `HH:MM`, local to `tz`.
    start: Option<String>,
    minutes: Option<i32>,
    tz: String,
    /// Inside the window now (always true without one).
    open_now: bool,
    next_start: Option<DateTime<Utc>>,
    #[sqlx(default)]
    agents: i64,
}

const WINDOW_COLS: &str = "s.id AS site_id, s.name AS site_name, c.id AS client_id, c.name AS client_name, s.maint_days AS days,
       to_char(s.maint_start, 'HH24:MI') AS start, s.maint_minutes AS minutes, s.maint_tz AS tz,
       in_maintenance_window(s.maint_days, s.maint_start, s.maint_minutes, s.maint_tz, now()) AS open_now,
       next_maintenance_window(s.maint_days, s.maint_start, s.maint_tz, now()) AS next_start";

pub async fn for_agent(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<serde_json::Value>> {
    super::access::agent(&st, &u, id).await?;
    let status: PatchStatus = sqlx::query_as(
        "SELECT $2 = ANY(capabilities) AS supported, online, os_family, patch_provider AS provider, patch_all_or_nothing AS all_or_nothing,
                patch_scanned_at AS scanned_at, patch_scan_requested_at AS scan_requested_at, patch_scan_error AS scan_error, reboot_pending
           FROM agents WHERE id = $1",
    )
    .bind(id)
    .bind(rmm_proto::patch::CAPABILITY)
    .fetch_one(&st.db)
    .await?;
    let sql = format!(
        "SELECT p.update_id, p.title, p.kb, p.severity, p.category, p.size, p.requires_reboot, p.version, p.current_version, p.state,
                p.approval, p.approval_manual, us.name AS approved_by_name, p.approved_at, p.first_seen_at, p.installed_at,
                p.last_error, p.fail_count,
                CASE WHEN p.approval = 'approved' AND NOT p.approval_manual AND p.state <> 'installed'
                          AND p.first_seen_at + make_interval(days => pol.deferral_days) > now()
                     THEN p.first_seen_at + make_interval(days => pol.deferral_days) END AS deferred_until
           FROM patches p LEFT JOIN agent_patch_policy pol ON pol.agent_id = p.agent_id LEFT JOIN users us ON us.id = p.approved_by
          WHERE p.agent_id = $1 AND (p.state <> 'installed' OR p.installed_at > now() - interval '30 days')
          ORDER BY p.state = 'installed', {SEVERITY_RANK}, p.category <> 'security', lower(p.title)"
    );
    let patches: Vec<AgentPatch> = sqlx::query_as(AssertSqlSafe(sql)).bind(id).fetch_all(&st.db).await?;
    let policy: Option<Policy> = sqlx::query_as(AssertSqlSafe(format!(
        "SELECT {POLICY_COLS}, ap.source FROM agent_patch_policy ap JOIN patch_policies p ON p.id = ap.id {POLICY_JOINS} WHERE ap.agent_id = $1"
    )))
    .bind(id)
    .fetch_optional(&st.db)
    .await?;
    let window: Window = sqlx::query_as(AssertSqlSafe(format!(
        "SELECT {WINDOW_COLS} FROM agents a JOIN sites s ON s.id = a.site_id JOIN clients c ON c.id = s.client_id WHERE a.id = $1"
    )))
    .bind(id)
    .fetch_one(&st.db)
    .await?;
    let runs = runs_query(&st, &u, &RunsQuery { agent_id: Some(id), client_id: None, status: None, limit: Some(20) }).await?;
    Ok(Json(json!({ "status": status, "policy": policy, "window": window, "patches": patches, "runs": runs })))
}

// ---------------------------------------------------------------------------
// Actions
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct ScanBody {
    agent_ids: Vec<Uuid>,
}

pub async fn scan(State(st): State<Arc<AppState>>, u: User, Json(b): Json<ScanBody>) -> ApiResult<Json<serde_json::Value>> {
    u.require(Role::Technician)?;
    let ids = visible_agents(&st, &u, &b.agent_ids).await?;
    let asked = core::scan_now(&st, &ids).await?;
    if asked == 0 {
        return Err(ApiError::Conflict(if ids.len() == 1 {
            "the agent is offline, or its version doesn't support patching".into()
        } else {
            "none of the selected agents are online with a version that supports patching".into()
        }));
    }
    Ok(Json(json!({ "requested": asked, "skipped": b.agent_ids.len() - asked })))
}

/// The subset of `ids` the user can see.
async fn visible_agents(st: &AppState, u: &User, ids: &[Uuid]) -> ApiResult<Vec<Uuid>> {
    if ids.is_empty() || ids.len() > 5000 {
        return Err(ApiError::BadRequest("agent_ids must contain 1-5000 agents".into()));
    }
    Ok(sqlx::query_scalar(
        "SELECT a.id FROM agents a JOIN sites s ON s.id = a.site_id WHERE a.id = ANY($1) AND ($2::uuid[] IS NULL OR s.client_id = ANY($2))",
    )
    .bind(ids)
    .bind(u.scope())
    .fetch_all(&st.db)
    .await?)
}

#[derive(Deserialize)]
pub struct ApprovalBody {
    /// approved, declined, or pending (back to what the policy says).
    decision: String,
    update_ids: Vec<String>,
    /// Limit to these agents...
    agent_ids: Option<Vec<Uuid>>,
    /// ...or to one client or site. Neither: every agent the user can see.
    client_id: Option<Uuid>,
    site_id: Option<Uuid>,
}

pub async fn approval(State(st): State<Arc<AppState>>, u: User, Json(b): Json<ApprovalBody>) -> ApiResult<Json<serde_json::Value>> {
    u.require(Role::Technician)?;
    if !matches!(b.decision.as_str(), "approved" | "declined" | "pending") {
        return Err(ApiError::BadRequest("decision must be approved, declined or pending".into()));
    }
    if b.update_ids.is_empty() || b.update_ids.len() > 5000 {
        return Err(ApiError::BadRequest("update_ids must contain 1-5000 updates".into()));
    }
    if let Some(c) = b.client_id {
        super::access::client(&u, c)?;
    }
    if let Some(s) = b.site_id {
        super::access::site(&st, &u, s).await?;
    }
    let manual = b.decision != "pending";
    let agents: Vec<Uuid> = sqlx::query_scalar(
        "UPDATE patches p
            SET approval = $1, approval_manual = $2, approved_by = CASE WHEN $2 THEN $3::uuid END,
                approved_at = CASE WHEN $1 = 'approved' THEN now() END
           FROM agents a JOIN sites s ON s.id = a.site_id
          WHERE p.agent_id = a.id AND p.update_id = ANY($4)
            AND ($5::uuid[] IS NULL OR a.id = ANY($5)) AND ($6::uuid IS NULL OR s.client_id = $6) AND ($7::uuid IS NULL OR s.id = $7)
            AND ($8::uuid[] IS NULL OR s.client_id = ANY($8))
          RETURNING p.agent_id",
    )
    .bind(&b.decision)
    .bind(manual)
    .bind(u.id)
    .bind(&b.update_ids)
    .bind(b.agent_ids.as_deref())
    .bind(b.client_id)
    .bind(b.site_id)
    .bind(u.scope())
    .fetch_all(&st.db)
    .await?;
    let changed = agents.len();
    let mut agents = agents;
    agents.sort();
    agents.dedup();
    if !manual {
        core::apply_policies(&st.db, Some(&agents)).await?;
    }
    publish_agents(&st, &agents).await?;
    auth::audit(
        &st.db,
        Some(u.id),
        "patch.approval",
        None,
        json!({ "decision": b.decision, "updates": b.update_ids.len(), "rows": changed, "agents": agents.len(),
                "update_ids": b.update_ids.iter().take(20).collect::<Vec<_>>() }),
    )
    .await;
    Ok(Json(json!({ "changed": changed, "agents": agents.len() })))
}

async fn publish_agents(st: &AppState, agents: &[Uuid]) -> sqlx::Result<()> {
    let rows: Vec<(Uuid, Uuid)> =
        sqlx::query_as("SELECT a.id, s.client_id FROM agents a JOIN sites s ON s.id = a.site_id WHERE a.id = ANY($1)")
            .bind(agents)
            .fetch_all(&st.db)
            .await?;
    for (agent_id, client_id) in rows {
        st.hub.publish(crate::hub::Event::Patches { agent_id, client_id });
    }
    Ok(())
}

#[derive(Deserialize)]
pub struct InstallBody {
    agent_ids: Vec<Uuid>,
    /// These updates (approving any that weren't)... Omitted: every approved update the
    /// agent still needs, ignoring deferrals and the maintenance window.
    update_ids: Option<Vec<String>>,
    /// Omitted: the agent's policy.
    reboot_policy: Option<String>,
}

pub async fn install(State(st): State<Arc<AppState>>, u: User, Json(b): Json<InstallBody>) -> ApiResult<Json<serde_json::Value>> {
    u.require(Role::Technician)?;
    let reboot = match b.reboot_policy.as_deref() {
        None => None,
        Some(r) => Some(RebootPolicy::parse(r).ok_or_else(|| ApiError::BadRequest("reboot_policy must be never, if_required or always".into()))?),
    };
    if b.update_ids.as_ref().is_some_and(|i| i.is_empty() || i.len() > 5000) {
        return Err(ApiError::BadRequest("update_ids must contain 1-5000 updates".into()));
    }
    let agents: Vec<(Uuid, String, bool, bool, bool, String)> = sqlx::query_as(
        "SELECT a.id, a.hostname, $3 = ANY(a.capabilities), a.patch_all_or_nothing,
                EXISTS (SELECT 1 FROM patch_runs r WHERE r.agent_id = a.id AND r.status IN ('queued', 'sent')),
                coalesce(pol.reboot_policy, 'never')
           FROM agents a JOIN sites s ON s.id = a.site_id LEFT JOIN agent_patch_policy pol ON pol.agent_id = a.id
          WHERE a.id = ANY($1) AND ($2::uuid[] IS NULL OR s.client_id = ANY($2))",
    )
    .bind(&b.agent_ids)
    .bind(u.scope())
    .bind(rmm_proto::patch::CAPABILITY)
    .fetch_all(&st.db)
    .await?;
    if agents.is_empty() || b.agent_ids.len() > 5000 {
        return Err(ApiError::NotFound("agent"));
    }
    let mut runs = Vec::new();
    let mut skipped = Vec::new();
    for (agent_id, hostname, capable, all_or_nothing, busy, policy_reboot) in agents {
        let skip = |reason: &str| json!({ "agent_id": agent_id, "hostname": hostname, "reason": reason });
        if !capable {
            skipped.push(skip("its agent version doesn't support patching; update the agent"));
            continue;
        }
        if busy {
            skipped.push(skip("an install is already queued or running"));
            continue;
        }
        let ids: Vec<String> = match &b.update_ids {
            Some(wanted) => {
                // Installing an update on purpose approves it.
                sqlx::query_scalar(
                    "UPDATE patches SET approval = 'approved', approval_manual = true, approved_by = $3,
                            approved_at = CASE WHEN approval = 'approved' THEN approved_at ELSE now() END
                      WHERE agent_id = $1 AND update_id = ANY($2) AND state IN ('missing', 'failed')
                      RETURNING update_id",
                )
                .bind(agent_id)
                .bind(wanted)
                .bind(u.id)
                .fetch_all(&st.db)
                .await?
            }
            None => {
                sqlx::query_scalar("SELECT update_id FROM patches WHERE agent_id = $1 AND approval = 'approved' AND state IN ('missing', 'failed')")
                    .bind(agent_id)
                    .fetch_all(&st.db)
                    .await?
            }
        };
        if ids.is_empty() {
            skipped.push(skip(if b.update_ids.is_some() { "it doesn't need any of these updates" } else { "it has no approved updates to install" }));
            continue;
        }
        let ids = if all_or_nothing {
            // pacman upgrades everything; record what that covers.
            sqlx::query_scalar("SELECT update_id FROM patches WHERE agent_id = $1 AND state IN ('missing', 'failed') ORDER BY update_id")
                .bind(agent_id)
                .fetch_all(&st.db)
                .await?
        } else {
            ids
        };
        let reboot = reboot.unwrap_or_else(|| RebootPolicy::parse(&policy_reboot).unwrap_or_default());
        let (run_id, sent) = core::start_run(&st, agent_id, &ids, reboot, Trigger::Manual(u.id)).await?;
        auth::audit(
            &st.db,
            Some(u.id),
            "agent.patch_install",
            Some(("agent", agent_id)),
            json!({ "run_id": run_id, "updates": ids.len(), "reboot_policy": reboot.as_str() }),
        )
        .await;
        runs.push(json!({ "agent_id": agent_id, "run_id": run_id, "sent": sent, "updates": ids.len() }));
    }
    if runs.is_empty() {
        let reason = skipped.first().and_then(|s| s["reason"].as_str()).unwrap_or("nothing to install").to_string();
        return Err(ApiError::Conflict(if skipped.len() == 1 { reason } else { format!("no installs started; for example, {reason}") }));
    }
    Ok(Json(json!({ "runs": runs, "skipped": skipped })))
}

// ---------------------------------------------------------------------------
// Installs (runs)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct RunsQuery {
    agent_id: Option<Uuid>,
    client_id: Option<Uuid>,
    /// Comma-separated; `active` = queued and sent.
    status: Option<String>,
    limit: Option<i64>,
}

#[derive(Serialize, sqlx::FromRow)]
pub struct RunRow {
    id: Uuid,
    agent_id: Uuid,
    hostname: String,
    client_id: Uuid,
    client_name: String,
    trigger: String,
    created_by_name: Option<String>,
    status: String,
    stage: Option<String>,
    progress: Option<String>,
    percent: Option<i16>,
    error: Option<String>,
    updates: i32,
    succeeded: i32,
    reboot_policy: String,
    reboot_required: bool,
    rebooting: bool,
    created_at: DateTime<Utc>,
    sent_at: Option<DateTime<Utc>>,
    finished_at: Option<DateTime<Utc>>,
    duration_ms: Option<i64>,
}

const RUN_COLS: &str = "r.id, r.agent_id, a.hostname, c.id AS client_id, c.name AS client_name, r.trigger, us.name AS created_by_name, r.status,
       r.stage, r.progress, r.percent, r.error, cardinality(r.update_ids) AS updates,
       (SELECT count(*)::int FROM jsonb_array_elements(r.results) x WHERE (x->>'ok')::boolean) AS succeeded,
       r.reboot_policy, r.reboot_required, r.rebooting, r.created_at, r.sent_at, r.finished_at, r.duration_ms";
const RUN_FROM: &str = "FROM patch_runs r JOIN agents a ON a.id = r.agent_id JOIN sites s ON s.id = a.site_id
       JOIN clients c ON c.id = s.client_id LEFT JOIN users us ON us.id = r.created_by";

async fn runs_query(st: &AppState, u: &User, q: &RunsQuery) -> ApiResult<Vec<RunRow>> {
    let status: Option<Vec<String>> = csv(&q.status).map(|v| {
        v.into_iter().flat_map(|s| if s == "active" { vec!["queued".to_string(), "sent".to_string()] } else { vec![s] }).collect()
    });
    let sql = format!(
        "SELECT {RUN_COLS} {RUN_FROM}
          WHERE ($1::uuid[] IS NULL OR c.id = ANY($1)) AND ($2::uuid IS NULL OR r.agent_id = $2)
            AND ($3::uuid IS NULL OR c.id = $3) AND ($4::text[] IS NULL OR r.status = ANY($4))
          ORDER BY r.created_at DESC, r.id DESC LIMIT $5"
    );
    Ok(sqlx::query_as(AssertSqlSafe(sql))
        .bind(u.scope())
        .bind(q.agent_id)
        .bind(q.client_id)
        .bind(&status)
        .bind(q.limit.unwrap_or(100).clamp(1, 500))
        .fetch_all(&st.db)
        .await?)
}

pub async fn runs(State(st): State<Arc<AppState>>, u: User, Query(q): Query<RunsQuery>) -> ApiResult<Json<Vec<RunRow>>> {
    Ok(Json(runs_query(&st, &u, &q).await?))
}

#[derive(Serialize, sqlx::FromRow)]
pub struct RunItem {
    update_id: String,
    title: Option<String>,
    kb: Option<String>,
    severity: Option<String>,
    ok: Option<bool>,
    message: Option<String>,
}

pub async fn run(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<serde_json::Value>> {
    let sql = format!("SELECT {RUN_COLS} {RUN_FROM} WHERE r.id = $1 AND ($2::uuid[] IS NULL OR c.id = ANY($2))");
    let row: RunRow = sqlx::query_as(AssertSqlSafe(sql))
        .bind(id)
        .bind(u.scope())
        .fetch_optional(&st.db)
        .await?
        .ok_or(ApiError::NotFound("install"))?;
    let output: String = sqlx::query_scalar("SELECT output FROM patch_runs WHERE id = $1").bind(id).fetch_one(&st.db).await?;
    let items: Vec<RunItem> = sqlx::query_as(
        "SELECT u.update_id, p.title, p.kb, p.severity, (x->>'ok')::boolean AS ok, x->>'message' AS message
           FROM patch_runs r CROSS JOIN LATERAL unnest(r.update_ids) WITH ORDINALITY AS u(update_id, n)
           LEFT JOIN patches p ON p.agent_id = r.agent_id AND p.update_id = u.update_id
           LEFT JOIN LATERAL (SELECT x FROM jsonb_array_elements(r.results) x WHERE x->>'id' = u.update_id LIMIT 1) res ON true
          WHERE r.id = $1 ORDER BY u.n",
    )
    .bind(id)
    .fetch_all(&st.db)
    .await?;
    let mut v = serde_json::to_value(&row).map_err(anyhow::Error::from)?;
    v["output"] = json!(output);
    v["items"] = serde_json::to_value(&items).map_err(anyhow::Error::from)?;
    Ok(Json(v))
}

/// Cancels an install that hasn't been sent yet.
pub async fn cancel_run(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<serde_json::Value>> {
    u.require(Role::Technician)?;
    let agent: Option<Uuid> = sqlx::query_scalar(
        "UPDATE patch_runs r SET status = 'cancelled', finished_at = now()
           FROM agents a JOIN sites s ON s.id = a.site_id
          WHERE r.id = $1 AND r.agent_id = a.id AND r.status = 'queued' AND ($2::uuid[] IS NULL OR s.client_id = ANY($2))
          RETURNING r.agent_id",
    )
    .bind(id)
    .bind(u.scope())
    .fetch_optional(&st.db)
    .await?;
    let agent = agent.ok_or_else(|| ApiError::Conflict("only installs that are still queued can be cancelled".into()))?;
    publish_agents(&st, &[agent]).await?;
    auth::audit(&st.db, Some(u.id), "agent.patch_cancel", Some(("agent", agent)), json!({ "run_id": id })).await;
    Ok(Json(json!({ "ok": true })))
}

// ---------------------------------------------------------------------------
// Compliance
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct ComplianceQuery {
    /// Narrow to one client, broken down by site.
    client_id: Option<Uuid>,
}

#[derive(Serialize, sqlx::FromRow)]
pub struct ComplianceRow {
    id: Uuid,
    name: String,
    /// For site rows.
    client_id: Option<Uuid>,
    agents: i64,
    /// Agents whose version can patch.
    supported: i64,
    /// Agents with a successful scan.
    scanned: i64,
    /// Scanned agents with nothing outstanding (declined updates don't count).
    compliant: i64,
    /// Outstanding updates, and agents missing a security or critical/important one.
    missing: i64,
    agents_missing_security: i64,
    failed: i64,
    reboot_pending: i64,
    scan_errors: i64,
    installed_30d: i64,
    oldest_scan: Option<DateTime<Utc>>,
}

pub async fn compliance(State(st): State<Arc<AppState>>, u: User, Query(q): Query<ComplianceQuery>) -> ApiResult<Json<serde_json::Value>> {
    let scope = super::agents::narrow(&u, q.client_id)?;
    let (group, name, client) =
        if q.client_id.is_some() { ("s.id", "s.name", "s.client_id") } else { ("c.id", "c.name", "NULL::uuid") };
    let sql = format!(
        "WITH ag AS (
            SELECT a.id, a.site_id, $2 = ANY(a.capabilities) AS supported, a.patch_scanned_at, a.patch_scan_error, a.reboot_pending,
                   o.missing, o.security, o.failed, o.installed_30d
              FROM agents a JOIN sites s ON s.id = a.site_id
              CROSS JOIN LATERAL (
                SELECT count(*) FILTER (WHERE p.state <> 'installed' AND p.approval <> 'declined') AS missing,
                       count(*) FILTER (WHERE p.state <> 'installed' AND p.approval <> 'declined'
                                          AND (p.category IN ('security', 'critical') OR p.severity IN ('critical', 'important'))) AS security,
                       count(*) FILTER (WHERE p.state = 'failed') AS failed,
                       count(*) FILTER (WHERE p.state = 'installed' AND p.installed_at > now() - interval '30 days') AS installed_30d
                  FROM patches p WHERE p.agent_id = a.id) o
             WHERE ($1::uuid[] IS NULL OR s.client_id = ANY($1)))
         SELECT {group} AS id, {name} AS name, {client} AS client_id,
                count(ag.id) AS agents,
                count(ag.id) FILTER (WHERE ag.supported) AS supported,
                count(ag.id) FILTER (WHERE ag.patch_scanned_at IS NOT NULL) AS scanned,
                count(ag.id) FILTER (WHERE ag.patch_scanned_at IS NOT NULL AND ag.missing = 0) AS compliant,
                coalesce(sum(ag.missing), 0)::bigint AS missing,
                count(ag.id) FILTER (WHERE ag.security > 0) AS agents_missing_security,
                coalesce(sum(ag.failed), 0)::bigint AS failed,
                count(ag.id) FILTER (WHERE ag.reboot_pending) AS reboot_pending,
                count(ag.id) FILTER (WHERE ag.patch_scan_error IS NOT NULL) AS scan_errors,
                coalesce(sum(ag.installed_30d), 0)::bigint AS installed_30d,
                min(ag.patch_scanned_at) AS oldest_scan
           FROM clients c JOIN sites s ON s.client_id = c.id LEFT JOIN ag ON ag.site_id = s.id
          WHERE ($1::uuid[] IS NULL OR c.id = ANY($1))
          GROUP BY {group}, {name}, {client}
          ORDER BY count(ag.id) FILTER (WHERE ag.patch_scanned_at IS NOT NULL AND ag.missing = 0)::float8
                   / nullif(count(ag.id) FILTER (WHERE ag.patch_scanned_at IS NOT NULL), 0) NULLS LAST,
                   count(ag.id) FILTER (WHERE ag.security > 0) DESC, lower({name})"
    );
    let rows: Vec<ComplianceRow> =
        sqlx::query_as(AssertSqlSafe(sql)).bind(scope.as_deref()).bind(rmm_proto::patch::CAPABILITY).fetch_all(&st.db).await?;
    let sum = |f: fn(&ComplianceRow) -> i64| rows.iter().map(f).sum::<i64>();
    let totals = json!({
        "agents": sum(|r| r.agents), "supported": sum(|r| r.supported), "scanned": sum(|r| r.scanned),
        "compliant": sum(|r| r.compliant), "missing": sum(|r| r.missing),
        "agents_missing_security": sum(|r| r.agents_missing_security), "failed": sum(|r| r.failed),
        "reboot_pending": sum(|r| r.reboot_pending), "scan_errors": sum(|r| r.scan_errors), "installed_30d": sum(|r| r.installed_30d),
    });
    Ok(Json(json!({ "totals": totals, "rows": rows, "by": if q.client_id.is_some() { "site" } else { "client" } })))
}

// ---------------------------------------------------------------------------
// Policies
// ---------------------------------------------------------------------------

pub async fn policies(State(st): State<Arc<AppState>>, u: User) -> ApiResult<Json<Vec<Policy>>> {
    let sql = format!(
        "SELECT {POLICY_COLS},
                (SELECT count(*) FROM agent_patch_policy ap JOIN agents a ON a.id = ap.agent_id JOIN sites s2 ON s2.id = a.site_id
                  WHERE ap.id = p.id AND ($1::uuid[] IS NULL OR s2.client_id = ANY($1))) AS agents
           FROM patch_policies p {POLICY_JOINS}
          WHERE p.client_id IS NULL OR $1::uuid[] IS NULL OR p.client_id = ANY($1)
          ORDER BY p.client_id IS NOT NULL, lower(c.name), p.site_id IS NOT NULL, lower(s.name)"
    );
    Ok(Json(sqlx::query_as(AssertSqlSafe(sql)).bind(u.scope()).fetch_all(&st.db).await?))
}

#[derive(Deserialize)]
pub struct PolicyBody {
    /// Creating only: the scope. Neither = not allowed (there is one MSP-wide policy).
    client_id: Option<Uuid>,
    site_id: Option<Uuid>,
    #[serde(default)]
    auto_approve_severities: Vec<String>,
    #[serde(default)]
    auto_approve_categories: Vec<String>,
    #[serde(default)]
    deferral_days: i32,
    #[serde(default)]
    auto_install: bool,
    reboot_policy: String,
}

impl PolicyBody {
    fn validate(&self) -> ApiResult<()> {
        if let Some(bad) = self.auto_approve_severities.iter().find(|s| Severity::parse(s).is_none()) {
            return Err(ApiError::BadRequest(format!("unknown severity {bad}")));
        }
        if let Some(bad) = self.auto_approve_categories.iter().find(|s| Category::parse(s).is_none()) {
            return Err(ApiError::BadRequest(format!("unknown category {bad}")));
        }
        if !(0..=365).contains(&self.deferral_days) {
            return Err(ApiError::BadRequest("deferral_days must be 0-365".into()));
        }
        if RebootPolicy::parse(&self.reboot_policy).is_none() {
            return Err(ApiError::BadRequest("reboot_policy must be never, if_required or always".into()));
        }
        Ok(())
    }
}

/// Who may change a policy: admins for the MSP-wide one, technicians with access otherwise.
fn may_edit(u: &User, client_id: Option<Uuid>) -> ApiResult<()> {
    match client_id {
        None => u.require(Role::Admin),
        Some(c) => {
            u.require(Role::Technician)?;
            super::access::client(u, c)
        }
    }
}

/// Agents a policy at this scope can affect (None = all).
async fn scope_agents(st: &AppState, client_id: Option<Uuid>, site_id: Option<Uuid>) -> sqlx::Result<Option<Vec<Uuid>>> {
    if client_id.is_none() {
        return Ok(None);
    }
    Ok(Some(
        sqlx::query_scalar(
            "SELECT a.id FROM agents a JOIN sites s ON s.id = a.site_id WHERE s.client_id = $1 AND ($2::uuid IS NULL OR s.id = $2)",
        )
        .bind(client_id)
        .bind(site_id)
        .fetch_all(&st.db)
        .await?,
    ))
}

async fn after_policy_change(st: &AppState, client_id: Option<Uuid>, site_id: Option<Uuid>) -> ApiResult<()> {
    let agents = scope_agents(st, client_id, site_id).await?;
    core::apply_policies(&st.db, agents.as_deref()).await?;
    // The MSP-wide policy can touch every agent; pages showing them refetch on their own.
    if let Some(a) = &agents {
        publish_agents(st, a).await?;
    }
    Ok(())
}

pub async fn create_policy(State(st): State<Arc<AppState>>, u: User, Json(b): Json<PolicyBody>) -> ApiResult<Json<serde_json::Value>> {
    b.validate()?;
    let client_id = match (b.client_id, b.site_id) {
        (_, Some(site)) => {
            let c = super::access::site(&st, &u, site).await?;
            if b.client_id.is_some_and(|x| x != c) {
                return Err(ApiError::BadRequest("the site belongs to a different client".into()));
            }
            c
        }
        (Some(c), None) => c,
        (None, None) => return Err(ApiError::BadRequest("a new policy needs a client or a site; edit the MSP-wide policy instead".into())),
    };
    may_edit(&u, Some(client_id))?;
    let id = Uuid::new_v4();
    let res = sqlx::query(
        "INSERT INTO patch_policies (id, client_id, site_id, auto_approve_severities, auto_approve_categories, deferral_days,
                                     auto_install, reboot_policy, updated_by)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
    )
    .bind(id)
    .bind(client_id)
    .bind(b.site_id)
    .bind(&b.auto_approve_severities)
    .bind(&b.auto_approve_categories)
    .bind(b.deferral_days)
    .bind(b.auto_install)
    .bind(&b.reboot_policy)
    .bind(u.id)
    .execute(&st.db)
    .await;
    if let Err(sqlx::Error::Database(e)) = &res
        && e.is_unique_violation()
    {
        return Err(ApiError::Conflict("there is already a policy for this client or site".into()));
    }
    res?;
    after_policy_change(&st, Some(client_id), b.site_id).await?;
    auth::audit(&st.db, Some(u.id), "patch.policy_create", None, json!({ "id": id, "client_id": client_id, "site_id": b.site_id })).await;
    Ok(Json(json!({ "id": id })))
}

pub async fn update_policy(
    State(st): State<Arc<AppState>>,
    u: User,
    Path(id): Path<Uuid>,
    Json(b): Json<PolicyBody>,
) -> ApiResult<Json<serde_json::Value>> {
    b.validate()?;
    let (client_id, site_id) = policy_scope(&st, &u, id).await?;
    may_edit(&u, client_id)?;
    sqlx::query(
        "UPDATE patch_policies SET auto_approve_severities = $2, auto_approve_categories = $3, deferral_days = $4, auto_install = $5,
                reboot_policy = $6, updated_by = $7, updated_at = now()
          WHERE id = $1",
    )
    .bind(id)
    .bind(&b.auto_approve_severities)
    .bind(&b.auto_approve_categories)
    .bind(b.deferral_days)
    .bind(b.auto_install)
    .bind(&b.reboot_policy)
    .bind(u.id)
    .execute(&st.db)
    .await?;
    after_policy_change(&st, client_id, site_id).await?;
    auth::audit(
        &st.db,
        Some(u.id),
        "patch.policy_update",
        None,
        json!({ "id": id, "client_id": client_id, "site_id": site_id, "auto_install": b.auto_install, "reboot_policy": b.reboot_policy,
                "categories": b.auto_approve_categories, "severities": b.auto_approve_severities, "deferral_days": b.deferral_days }),
    )
    .await;
    Ok(Json(json!({ "ok": true })))
}

pub async fn delete_policy(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<serde_json::Value>> {
    if id == GLOBAL_POLICY {
        return Err(ApiError::BadRequest("the MSP-wide policy can't be deleted".into()));
    }
    let (client_id, site_id) = policy_scope(&st, &u, id).await?;
    may_edit(&u, client_id)?;
    sqlx::query("DELETE FROM patch_policies WHERE id = $1 AND client_id IS NOT NULL").bind(id).execute(&st.db).await?;
    after_policy_change(&st, client_id, site_id).await?;
    auth::audit(&st.db, Some(u.id), "patch.policy_delete", None, json!({ "id": id, "client_id": client_id, "site_id": site_id })).await;
    Ok(Json(json!({ "ok": true })))
}

/// A visible policy's client and site.
async fn policy_scope(st: &AppState, u: &User, id: Uuid) -> ApiResult<(Option<Uuid>, Option<Uuid>)> {
    let row: Option<(Option<Uuid>, Option<Uuid>)> =
        sqlx::query_as("SELECT client_id, site_id FROM patch_policies WHERE id = $1").bind(id).fetch_optional(&st.db).await?;
    row.filter(|(c, _)| c.is_none_or(|c| u.can_see_client(c))).ok_or(ApiError::NotFound("policy"))
}

// ---------------------------------------------------------------------------
// Maintenance windows
// ---------------------------------------------------------------------------

pub async fn windows(State(st): State<Arc<AppState>>, u: User) -> ApiResult<Json<Vec<Window>>> {
    let sql = format!(
        "SELECT {WINDOW_COLS}, (SELECT count(*) FROM agents a WHERE a.site_id = s.id) AS agents
           FROM sites s JOIN clients c ON c.id = s.client_id
          WHERE $1::uuid[] IS NULL OR c.id = ANY($1)
          ORDER BY lower(c.name), lower(s.name)"
    );
    Ok(Json(sqlx::query_as(AssertSqlSafe(sql)).bind(u.scope()).fetch_all(&st.db).await?))
}

#[derive(Deserialize)]
pub struct WindowBody {
    /// 0 = Sunday ... 6 = Saturday. Empty or omitted: no window.
    #[serde(default)]
    days: Vec<i16>,
    /// `HH:MM`
    start: Option<String>,
    minutes: Option<i32>,
    tz: Option<String>,
}

pub async fn set_window(
    State(st): State<Arc<AppState>>,
    u: User,
    Path(site_id): Path<Uuid>,
    Json(b): Json<WindowBody>,
) -> ApiResult<Json<serde_json::Value>> {
    u.require(Role::Technician)?;
    super::access::site(&st, &u, site_id).await?;
    let tz = b.tz.as_deref().map(str::trim).filter(|t| !t.is_empty()).unwrap_or("UTC").to_string();
    let valid_tz: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM pg_timezone_names WHERE name = $1)").bind(&tz).fetch_one(&st.db).await?;
    if !valid_tz {
        return Err(ApiError::BadRequest(format!("unknown time zone {tz}")));
    }
    let mut days = b.days.clone();
    days.sort();
    days.dedup();
    if days.iter().any(|d| !(0..=6).contains(d)) {
        return Err(ApiError::BadRequest("days are 0 (Sunday) to 6 (Saturday)".into()));
    }
    let (start, minutes) = if days.is_empty() {
        (None, None)
    } else {
        let start = b
            .start
            .as_deref()
            .and_then(|s| NaiveTime::parse_from_str(s.trim(), "%H:%M").ok())
            .ok_or_else(|| ApiError::BadRequest("start must be a time like 02:00".into()))?;
        let minutes = b.minutes.filter(|m| (15..=1440).contains(m)).ok_or_else(|| ApiError::BadRequest("the window must last 15 minutes to 24 hours".into()))?;
        (Some(start), Some(minutes))
    };
    let days = (!days.is_empty()).then_some(days);
    sqlx::query("UPDATE sites SET maint_days = $2, maint_start = $3, maint_minutes = $4, maint_tz = $5 WHERE id = $1")
        .bind(site_id)
        .bind(&days)
        .bind(start)
        .bind(minutes)
        .bind(&tz)
        .execute(&st.db)
        .await?;
    auth::audit(
        &st.db,
        Some(u.id),
        "site.maintenance_window",
        Some(("site", site_id)),
        json!({ "days": days, "start": b.start, "minutes": minutes, "tz": tz }),
    )
    .await;
    Ok(Json(json!({ "ok": true })))
}

#[cfg(test)]
mod tests {
    #[test]
    fn csv_splits() {
        assert_eq!(super::csv(&Some("a, b".into())), Some(vec!["a".to_string(), "b".to_string()]));
        assert_eq!(super::csv(&Some(String::new())), None);
    }
}
