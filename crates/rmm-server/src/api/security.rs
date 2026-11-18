//! Endpoint protection API: the fleet view (agents by protection state, detections), one
//! agent's products, detections and actions, and starting scans and signature updates.
//! Everything is limited to the clients the user can see.
//!
//! Permissions: `security.read` to see anything here, `security.respond` for scans and
//! response actions and verdicts, `security.manage` for exclusions, rule modes and content
//! (and for the `security` module of the policy sets, `api::policies`). Roles grant defaults (read-only: read; technician: + respond; admin: all).

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, Query, State};
use chrono::{DateTime, Utc};
use rmm_proto::security::{Action, ProductKind};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::AssertSqlSafe;
use uuid::Uuid;

use crate::auth::{self, Perm, User};
use crate::error::{ApiError, ApiResult};
use crate::paging::{self, Page, PageQuery, Plan, SortKey};
use crate::security::{self as core, StartError};
use crate::state::AppState;

/// A column of the security policy that applies to agent `a` (its policy set's), as
/// `core::sensor_policy` reads it.
macro_rules! policy_col {
    ($col:literal) => {
        concat!("(SELECT p.", $col, " FROM agent_security_policy p WHERE p.agent_id = a.id)")
    };
}
/// How old our signature database may be on agent `a`, hours (0 = no limit).
macro_rules! db_max_age {
    () => {
        concat!("coalesce(", policy_col!("database_max_age_hours"), ", 72)")
    };
}
/// Product `sp` of agent `a` has current signatures: our sensor (its database, or its content
/// before it has one) within the policy's limit, other products within 72 hours or by Security
/// Center's verdict. Without a date it counts as current.
macro_rules! sp_fresh {
    () => {
        concat!(
            "(CASE WHEN sp.kind = 'rmm' THEN (sp.signatures_updated_at IS NULL OR ",
            db_max_age!(),
            " = 0 OR sp.signatures_updated_at > now() - make_interval(hours => ",
            db_max_age!(),
            "))
               ELSE coalesce(sp.signatures_updated_at > now() - interval '72 hours', sp.signatures_current, true) END)"
        )
    };
}
/// Each reason agent `a` is at risk (with something enabled), as one condition.
macro_rules! risk_realtime_off {
    () => {
        "NOT EXISTS (SELECT 1 FROM security_products sp WHERE sp.agent_id = a.id AND sp.enabled AND sp.realtime IS NOT FALSE)"
    };
}
macro_rules! risk_signatures {
    () => {
        concat!("NOT EXISTS (SELECT 1 FROM security_products sp WHERE sp.agent_id = a.id AND sp.enabled AND ", sp_fresh!(), ")")
    };
}
macro_rules! risk_database {
    () => {
        concat!("EXISTS (SELECT 1 FROM security_products sp WHERE sp.agent_id = a.id AND sp.enabled AND sp.kind = 'rmm' AND NOT ", sp_fresh!(), ")")
    };
}
/// Our real-time protection is wanted (the sensor on, the policy at audit or block) on Linux, the
/// one platform where it runs, and isn't on. Elsewhere `unavailable` is the platform, not a fault.
macro_rules! risk_sensor_realtime {
    () => {
        "(a.os_family = 'linux' AND coalesce((a.sensor->>'enabled')::boolean, false)
          AND a.sensor->'health'->'realtime'->>'mode' IN ('audit', 'block')
          AND NOT (coalesce((a.sensor->>'running')::boolean, false) AND a.sensor->'health'->'realtime'->>'state' = 'on'))"
    };
}
/// Why agent `a` is at risk: `realtime_off`, `signatures`, `database`, `sensor_realtime`.
macro_rules! risks {
    () => {
        concat!(
            "(CASE WHEN EXISTS (SELECT 1 FROM security_products sp WHERE sp.agent_id = a.id AND sp.enabled) THEN array_remove(ARRAY[
                CASE WHEN ", risk_realtime_off!(), " THEN 'realtime_off' END,
                CASE WHEN ", risk_signatures!(), " THEN 'signatures' END,
                CASE WHEN ", risk_database!(), " THEN 'database' END,
                CASE WHEN ", risk_sensor_realtime!(), " THEN 'sensor_realtime' END], NULL) ELSE '{}'::text[] END)"
        )
    };
}

/// Protection state of agent `a`, worst first: threats (an active detection), unprotected
/// (no product enabled), at_risk (real-time protection off everywhere, no product with current
/// signatures, our database older than the policy allows, or our real-time protection not on
/// where the policy wants it and the platform has it), unknown (never reported), protected.
macro_rules! state_rank {
    () => {
        concat!(
            "(CASE
            WHEN a.security_at IS NULL THEN 3
            WHEN EXISTS (SELECT 1 FROM security_detections sd WHERE sd.agent_id = a.id AND sd.resolved_at IS NULL AND sd.status = 'active') THEN 0
            WHEN NOT EXISTS (SELECT 1 FROM security_products sp WHERE sp.agent_id = a.id AND sp.enabled) THEN 1
            WHEN ",
            risk_realtime_off!(),
            " OR ",
            risk_signatures!(),
            " OR ",
            risk_database!(),
            " OR ",
            risk_sensor_realtime!(),
            " THEN 2
            ELSE 4 END)"
        )
    };
}
macro_rules! state_name {
    () => {
        concat!("(ARRAY['threats', 'unprotected', 'at_risk', 'unknown', 'protected'])[", state_rank!(), " + 1]")
    };
}
/// Newest signatures among the agent's enabled products.
macro_rules! signatures_at {
    () => {
        "(SELECT max(sp.signatures_updated_at) FROM security_products sp WHERE sp.agent_id = a.id AND sp.enabled)"
    };
}
macro_rules! last_scan_at {
    () => {
        "(SELECT max(greatest(sp.last_quick_scan_at, sp.last_full_scan_at)) FROM security_products sp WHERE sp.agent_id = a.id)"
    };
}
macro_rules! active_threats {
    () => {
        "(SELECT count(*) FROM security_detections sd WHERE sd.agent_id = a.id AND sd.resolved_at IS NULL AND sd.status = 'active')"
    };
}

const STATES: [&str; 5] = ["threats", "unprotected", "at_risk", "unknown", "protected"];
const AGENT_FROM: &str = "FROM agents a JOIN sites s ON s.id = a.site_id JOIN clients c ON c.id = s.client_id";

fn csv(s: &Option<String>) -> Option<Vec<String>> {
    s.as_deref().filter(|s| !s.is_empty()).map(|s| s.split(',').map(str::trim).map(str::to_string).collect())
}

fn start_error(e: StartError) -> ApiError {
    match e {
        StartError::Offline => ApiError::Conflict("agent is offline".into()),
        StartError::Unsupported(m) => ApiError::BadRequest(m),
        StartError::Busy => ApiError::Conflict("a scan or signature update is already running on this agent".into()),
        StartError::Db(e) => e.into(),
    }
}

fn parse_action(s: &str) -> ApiResult<Action> {
    Action::parse(s).ok_or_else(|| ApiError::BadRequest("action must be quick_scan, full_scan or update_signatures".into()))
}

// ---------------------------------------------------------------------------
// Fleet
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct ScopeQuery {
    client_id: Option<Uuid>,
}

/// Agents per protection state, active threats and recent detections.
pub async fn summary(State(st): State<Arc<AppState>>, u: User, Query(q): Query<ScopeQuery>) -> ApiResult<Json<Value>> {
    u.need(Perm::SecurityRead)?;
    let scope = super::agents::narrow(&u, q.client_id)?;
    let states: Value = sqlx::query_scalar(AssertSqlSafe(format!(
        "SELECT coalesce(jsonb_object_agg(state, n), '{{}}') FROM (
            SELECT {} AS state, count(*) n {AGENT_FROM} WHERE ($1::uuid[] IS NULL OR c.id = ANY($1)) GROUP BY 1) t",
        state_name!()
    )))
    .bind(&scope)
    .fetch_one(&st.db)
    .await?;
    let (active, week, running): (i64, i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM security_detections sd JOIN agents a ON a.id = sd.agent_id JOIN sites s ON s.id = a.site_id
                  WHERE sd.resolved_at IS NULL AND sd.status = 'active' AND ($1::uuid[] IS NULL OR s.client_id = ANY($1))),
                (SELECT count(*) FROM security_detections sd JOIN agents a ON a.id = sd.agent_id JOIN sites s ON s.id = a.site_id
                  WHERE sd.first_seen_at > now() - interval '7 days' AND ($1::uuid[] IS NULL OR s.client_id = ANY($1))),
                (SELECT count(*) FROM security_actions sa JOIN agents a ON a.id = sa.agent_id JOIN sites s ON s.id = a.site_id
                  WHERE sa.status IN ('sent', 'running') AND ($1::uuid[] IS NULL OR s.client_id = ANY($1)))",
    )
    .bind(&scope)
    .fetch_one(&st.db)
    .await?;
    let mut by_state = serde_json::Map::new();
    for s in STATES {
        by_state.insert(s.into(), states.get(s).cloned().unwrap_or(json!(0)));
    }
    Ok(Json(json!({ "agents": by_state, "active_threats": active, "detections_7d": week, "actions_running": running })))
}

#[derive(Serialize, sqlx::FromRow)]
pub struct AgentRow {
    id: Uuid,
    hostname: String,
    online: bool,
    os_family: String,
    client_id: Uuid,
    client_name: String,
    site_id: Uuid,
    site_name: String,
    /// See `state_rank!`.
    state: String,
    security_at: Option<DateTime<Utc>>,
    security_error: Option<String>,
    /// `[{kind, name, enabled, realtime}]`
    products: Value,
    signatures_updated_at: Option<DateTime<Utc>>,
    last_scan_at: Option<DateTime<Utc>>,
    active_threats: i64,
    /// The scan or update in progress, if any.
    running_action: Option<String>,
    isolated: bool,
    /// The sensor's last status (null: not enabled or never reported).
    sensor: Option<Value>,
    content_version: Option<String>,
    /// Why it's at risk (see `risks!`); empty otherwise.
    risks: Vec<String>,
    /// Our signature database there, when it was built, and the policy's age limit (hours, 0 =
    /// none).
    database_version: Option<String>,
    database_built_at: Option<DateTime<Utc>>,
    database_max_age_hours: i32,
    /// The policy's prevention: without it real-time `block` denies nothing.
    prevention: bool,
    #[sqlx(default)]
    #[serde(skip)]
    sort_key: String,
}

const AGENT_SORT: &[SortKey] = &[
    SortKey { name: "state", expr: state_rank!(), ty: "int" },
    SortKey { name: "hostname", expr: "lower(a.hostname)", ty: "text" },
    SortKey { name: "client", expr: "lower(c.name || ' / ' || s.name || ' / ' || a.hostname)", ty: "text" },
    SortKey { name: "signatures", expr: concat!("coalesce(", signatures_at!(), ", 'epoch'::timestamptz)"), ty: "timestamptz" },
    SortKey { name: "last_scan", expr: concat!("coalesce(", last_scan_at!(), ", 'epoch'::timestamptz)"), ty: "timestamptz" },
    SortKey { name: "threats", expr: active_threats!(), ty: "bigint" },
];

#[derive(Deserialize)]
pub struct AgentsQuery {
    client_id: Option<Uuid>,
    site_id: Option<Uuid>,
    /// Comma-separated states.
    state: Option<String>,
    os: Option<String>,
    q: Option<String>,
}

pub async fn agents(
    State(st): State<Arc<AppState>>,
    u: User,
    Query(q): Query<AgentsQuery>,
    Query(page): Query<PageQuery>,
) -> ApiResult<Json<Page<AgentRow>>> {
    u.need(Perm::SecurityRead)?;
    let plan = Plan::new(AGENT_SORT, ("state", false), &page, "a.id", "uuid", 7)?;
    let states = csv(&q.state);
    if states.iter().flatten().any(|s| !STATES.contains(&s.as_str())) {
        return Err(ApiError::BadRequest(format!("state must be one of {}", STATES.join(", "))));
    }
    let filters = format!(
        "{AGENT_FROM}
          WHERE ($1::uuid[] IS NULL OR c.id = ANY($1))
            AND ($2::uuid IS NULL OR c.id = $2)
            AND ($3::uuid IS NULL OR s.id = $3)
            AND ($4::text[] IS NULL OR {state} = ANY($4))
            AND ($5::text IS NULL OR a.os_family = $5)
            AND ($6::text IS NULL OR a.hostname ILIKE '%' || $6 || '%')",
        state = state_name!()
    );
    let cols = concat!(
        "a.id, a.hostname, a.online, a.os_family, c.id AS client_id, c.name AS client_name, s.id AS site_id, s.name AS site_name, ",
        state_name!(),
        " AS state, a.security_at, a.security_error,
         coalesce((SELECT jsonb_agg(jsonb_build_object('kind', sp.kind, 'name', sp.name, 'enabled', sp.enabled, 'realtime', sp.realtime)
                                    ORDER BY sp.kind, sp.name)
                     FROM security_products sp WHERE sp.agent_id = a.id), '[]') AS products, ",
        signatures_at!(),
        " AS signatures_updated_at, ",
        last_scan_at!(),
        " AS last_scan_at, ",
        active_threats!(),
        " AS active_threats,
         (SELECT sa.action FROM security_actions sa WHERE sa.agent_id = a.id AND sa.status IN ('sent', 'running')
           ORDER BY sa.created_at DESC LIMIT 1) AS running_action, a.isolated, a.sensor, a.content_version, ",
        risks!(),
        " AS risks, a.database_version,
         (SELECT sd.built_at FROM signature_databases sd WHERE sd.version = a.database_version) AS database_built_at, ",
        db_max_age!(),
        " AS database_max_age_hours, coalesce(",
        policy_col!("prevention"),
        ", false) AS prevention"
    );
    let os = q.os.as_deref().filter(|s| !s.is_empty());
    let search = q.q.as_deref().map(str::trim).filter(|s| !s.is_empty());
    macro_rules! bind_filters {
        ($query:expr) => {
            $query.bind(u.scope()).bind(q.client_id).bind(q.site_id).bind(&states).bind(os).bind(search)
        };
    }
    let sql = format!("SELECT {cols}, {} {filters} {} {} {}", plan.key_select, plan.keyset, plan.order, plan.limit_sql());
    let mut rows = bind_filters!(sqlx::query_as::<_, AgentRow>(AssertSqlSafe(sql)));
    if let Some((k, id)) = &plan.cursor {
        rows = rows.bind(k).bind(id);
    }
    let rows = rows.fetch_all(&st.db).await?;
    let total: i64 = bind_filters!(sqlx::query_scalar(AssertSqlSafe(paging::count_sql(&filters)))).fetch_one(&st.db).await?;
    Ok(Json(plan.finish(rows, |r| (r.sort_key.clone(), r.id.to_string()), total)))
}

#[derive(Serialize, sqlx::FromRow)]
pub struct DetectionRow {
    id: Uuid,
    agent_id: Uuid,
    hostname: String,
    client_id: Uuid,
    client_name: String,
    site_name: String,
    product: String,
    name: String,
    severity: String,
    status: String,
    resources: Vec<String>,
    process: Option<String>,
    username: Option<String>,
    detected_at: Option<DateTime<Utc>>,
    first_seen_at: DateTime<Utc>,
    last_seen_at: DateTime<Utc>,
    resolved_at: Option<DateTime<Utc>>,
    /// product (an antivirus's own), file or behaviour (our sensor).
    source: String,
    rule_id: Option<String>,
    mitre: Vec<String>,
    /// Recorded by a rule in audit mode: not acted on, not alerted.
    audit: bool,
    action_taken: Option<String>,
    sha256: Option<String>,
    verdict: Option<String>,
    /// `on_exec`, `on_write`, `scan`, `reputation` (file detections from our sensor).
    found_by: Option<String>,
    /// Refused before it ran.
    denied: bool,
    #[sqlx(default)]
    #[serde(skip)]
    sort_key: String,
}

const DETECTION_COLS: &str = "d.id, d.agent_id, a.hostname, c.id AS client_id, c.name AS client_name, s.name AS site_name, d.product,
       d.name, d.severity, d.status, d.resources, d.process, d.username, d.detected_at, d.first_seen_at, d.last_seen_at, d.resolved_at,
       d.source, d.rule_id, d.mitre, d.audit, d.action_taken, d.sha256, d.verdict, d.found_by, d.denied";
const DETECTION_FROM: &str =
    "FROM security_detections d JOIN agents a ON a.id = d.agent_id JOIN sites s ON s.id = a.site_id JOIN clients c ON c.id = s.client_id";
const SEVERITY_RANK: &str = "coalesce(array_position(ARRAY['severe', 'high', 'moderate', 'low'], d.severity), 5)";

const DETECTION_SORT: &[SortKey] = &[
    SortKey { name: "first_seen", expr: "d.first_seen_at", ty: "timestamptz" },
    SortKey { name: "severity", expr: SEVERITY_RANK, ty: "int" },
    SortKey { name: "name", expr: "lower(d.name)", ty: "text" },
    SortKey { name: "hostname", expr: "lower(a.hostname)", ty: "text" },
];

#[derive(Deserialize)]
pub struct DetectionsQuery {
    /// `active` (still on the machine, the default) or `all`.
    view: Option<String>,
    client_id: Option<Uuid>,
    agent_id: Option<Uuid>,
    severity: Option<String>,
    /// Threat name, file, or hostname.
    q: Option<String>,
    /// product / file / behaviour
    source: Option<String>,
    rule_id: Option<String>,
    sha256: Option<String>,
    /// Include audit-mode hits (left out unless asked for).
    audit: Option<bool>,
}

pub async fn detections(
    State(st): State<Arc<AppState>>,
    u: User,
    Query(q): Query<DetectionsQuery>,
    Query(page): Query<PageQuery>,
) -> ApiResult<Json<Page<DetectionRow>>> {
    u.need(Perm::SecurityRead)?;
    let plan = Plan::new(DETECTION_SORT, ("first_seen", true), &page, "d.id", "uuid", 11)?;
    let active = match q.view.as_deref().unwrap_or("active") {
        "active" => true,
        "all" => false,
        other => return Err(ApiError::BadRequest(format!("unknown view {other}"))),
    };
    let severity = csv(&q.severity);
    let search = q.q.as_deref().map(str::trim).filter(|s| !s.is_empty());
    let filters = format!(
        "{DETECTION_FROM}
          WHERE ($1::uuid[] IS NULL OR c.id = ANY($1))
            AND (NOT $2 OR (d.resolved_at IS NULL AND d.status = 'active'))
            AND ($3::uuid IS NULL OR c.id = $3)
            AND ($4::uuid IS NULL OR d.agent_id = $4)
            AND ($5::text[] IS NULL OR d.severity = ANY($5))
            AND ($6::text IS NULL OR d.name ILIKE '%' || $6 || '%' OR a.hostname ILIKE '%' || $6 || '%'
                 OR EXISTS (SELECT 1 FROM unnest(d.resources) r WHERE r ILIKE '%' || $6 || '%'))
            AND ($7::text IS NULL OR d.source = $7)
            AND ($8::text IS NULL OR d.rule_id = $8)
            AND ($9::text IS NULL OR d.sha256 = lower($9))
            AND ($10 OR NOT d.audit)"
    );
    let source = q.source.as_deref().filter(|s| !s.is_empty());
    let rule_id = q.rule_id.as_deref().filter(|s| !s.is_empty());
    let sha = q.sha256.as_deref().filter(|s| !s.is_empty());
    let audit = q.audit.unwrap_or(false);
    macro_rules! bind_filters {
        ($query:expr) => {
            $query.bind(u.scope()).bind(active).bind(q.client_id).bind(q.agent_id).bind(&severity).bind(search).bind(source).bind(rule_id).bind(sha).bind(audit)
        };
    }
    let sql = format!("SELECT {DETECTION_COLS}, {} {filters} {} {} {}", plan.key_select, plan.keyset, plan.order, plan.limit_sql());
    let mut rows = bind_filters!(sqlx::query_as::<_, DetectionRow>(AssertSqlSafe(sql)));
    if let Some((k, id)) = &plan.cursor {
        rows = rows.bind(k).bind(id);
    }
    let rows = rows.fetch_all(&st.db).await?;
    let total: i64 = bind_filters!(sqlx::query_scalar(AssertSqlSafe(paging::count_sql(&filters)))).fetch_one(&st.db).await?;
    Ok(Json(plan.finish(rows, |r| (r.sort_key.clone(), r.id.to_string()), total)))
}

#[derive(Deserialize)]
pub struct BulkAction {
    agent_ids: Vec<Uuid>,
    action: String,
}

/// Starts the same action on many agents, each with the first product that can run it.
pub async fn bulk_action(State(st): State<Arc<AppState>>, u: User, Json(b): Json<BulkAction>) -> ApiResult<Json<Value>> {
    u.need(Perm::SecurityRespond)?;
    let action = parse_action(&b.action)?;
    if b.agent_ids.is_empty() || b.agent_ids.len() > 500 {
        return Err(ApiError::BadRequest("pick 1-500 agents".into()));
    }
    let visible: Vec<(Uuid, String)> = sqlx::query_as(
        "SELECT a.id, a.hostname FROM agents a JOIN sites s ON s.id = a.site_id
          WHERE a.id = ANY($1) AND ($2::uuid[] IS NULL OR s.client_id = ANY($2)) ORDER BY lower(a.hostname)",
    )
    .bind(&b.agent_ids)
    .bind(u.scope())
    .fetch_all(&st.db)
    .await?;
    let mut started = 0;
    let mut skipped = Vec::new();
    for (agent_id, hostname) in visible {
        match core::start(&st, agent_id, None, action, u.id).await {
            Ok((id, product)) => {
                started += 1;
                auth::audit(
                    &st.db,
                    Some(u.id),
                    &format!("security.{}", action.as_str()),
                    Some(("agent", agent_id)),
                    json!({ "product": product.as_str(), "action_id": id }),
                )
                .await;
            }
            Err(StartError::Db(e)) => return Err(e.into()),
            Err(e) => {
                let reason = match start_error(e) {
                    ApiError::Conflict(m) | ApiError::BadRequest(m) => m,
                    other => other.to_string(),
                };
                skipped.push(json!({ "agent_id": agent_id, "hostname": hostname, "reason": reason }));
            }
        }
    }
    Ok(Json(json!({ "started": started, "skipped": skipped })))
}

// ---------------------------------------------------------------------------
// One agent
// ---------------------------------------------------------------------------

#[derive(Serialize, sqlx::FromRow)]
pub struct ProductRow {
    kind: String,
    name: String,
    version: Option<String>,
    enabled: Option<bool>,
    realtime: Option<bool>,
    signature_version: Option<String>,
    signatures_updated_at: Option<DateTime<Utc>>,
    signatures_current: Option<bool>,
    last_quick_scan_at: Option<DateTime<Utc>>,
    last_full_scan_at: Option<DateTime<Utc>>,
    tamper_protection: Option<bool>,
    actions: Vec<String>,
    detail: Option<String>,
}

#[derive(Serialize, sqlx::FromRow)]
pub struct ActionRow {
    id: Uuid,
    product: String,
    action: String,
    status: String,
    message: Option<String>,
    created_by_name: Option<String>,
    created_at: DateTime<Utc>,
    started_at: Option<DateTime<Utc>>,
    finished_at: Option<DateTime<Utc>>,
    params: Value,
    result: Option<Value>,
    /// A triage package is ready to download.
    has_download: bool,
}

#[derive(Serialize)]
pub struct AgentSecurity {
    /// The agent's build reports protection status.
    supported: bool,
    online: bool,
    state: String,
    reported_at: Option<DateTime<Utc>>,
    error: Option<String>,
    products: Vec<ProductRow>,
    /// Active first, then the most recent; up to 100.
    detections: Vec<DetectionRow>,
    /// The latest 20 scans, updates and response actions.
    actions: Vec<ActionRow>,
    /// The build runs our sensor and response actions.
    sensor_supported: bool,
    /// The sensor's last status (SensorStatus).
    sensor: Option<Value>,
    sensor_at: Option<DateTime<Utc>>,
    content_version: Option<String>,
    isolated: bool,
    /// What the sensor runs with here.
    policy: rmm_proto::security::SensorPolicy,
    quarantine: Vec<QuarantineRow>,
    /// Why it's at risk (`realtime_off`, `signatures`, `database`, `sensor_realtime`).
    risks: Vec<String>,
    /// The signature database the sensor runs: the uploaded version's details, when the server
    /// still has its row.
    database: Option<Value>,
    /// The policy's limit on the database's age, hours (0: none).
    database_max_age_hours: i32,
}

pub async fn for_agent(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<AgentSecurity>> {
    u.need(Perm::SecurityRead)?;
    super::access::agent(&st, &u, id).await?;
    let (supported, online, state, reported_at, error): (bool, bool, String, Option<DateTime<Utc>>, Option<String>) =
        sqlx::query_as(AssertSqlSafe(format!(
            "SELECT $2 = ANY(a.capabilities), a.online, {} AS state, a.security_at, a.security_error FROM agents a WHERE a.id = $1",
            state_name!()
        )))
        .bind(id)
        .bind(rmm_proto::security::CAPABILITY)
        .fetch_one(&st.db)
        .await?;
    let products = sqlx::query_as(
        "SELECT kind, name, version, enabled, realtime, signature_version, signatures_updated_at, signatures_current,
                last_quick_scan_at, last_full_scan_at, tamper_protection, actions, detail
           FROM security_products WHERE agent_id = $1
          ORDER BY enabled IS NOT TRUE, array_position(ARRAY['defender', 'clamav', 'xprotect', 'other'], kind), name",
    )
    .bind(id)
    .fetch_all(&st.db)
    .await?;
    let detections = sqlx::query_as(AssertSqlSafe(format!(
        "SELECT {DETECTION_COLS} {DETECTION_FROM} WHERE d.agent_id = $1
          ORDER BY (d.resolved_at IS NULL AND d.status = 'active') DESC, d.first_seen_at DESC LIMIT 100"
    )))
    .bind(id)
    .fetch_all(&st.db)
    .await?;
    let actions = sqlx::query_as(
        "SELECT sa.id, sa.product, sa.action, sa.status, sa.message, us.name AS created_by_name, sa.created_at, sa.started_at, sa.finished_at,
                sa.params, sa.result, sa.storage_key IS NOT NULL AS has_download
           FROM security_actions sa LEFT JOIN users us ON us.id = sa.created_by
          WHERE sa.agent_id = $1 ORDER BY sa.created_at DESC LIMIT 20",
    )
    .bind(id)
    .fetch_all(&st.db)
    .await?;
    #[allow(clippy::type_complexity)]
    let (sensor_supported, sensor, sensor_at, content_version, isolated): (bool, Option<Value>, Option<DateTime<Utc>>, Option<String>, bool) =
        sqlx::query_as("SELECT 'sensor' = ANY(capabilities), sensor, sensor_at, content_version, isolated FROM agents WHERE id = $1")
            .bind(id)
            .fetch_one(&st.db)
            .await?;
    let policy = core::sensor_policy(&st, id).await?;
    let quarantine = sqlx::query_as(AssertSqlSafe(format!("{QUARANTINE_SELECT} WHERE q.agent_id = $1 AND q.state = 'quarantined' ORDER BY q.quarantined_at DESC LIMIT 200")))
        .bind(id)
        .fetch_all(&st.db)
        .await?;
    let (risks, database, database_max_age_hours): (Vec<String>, Option<Value>, i32) = sqlx::query_as(AssertSqlSafe(format!(
        "SELECT {}, (SELECT jsonb_build_object('version', sd.version, 'built_at', sd.built_at, 'stage', sd.stage, 'hashes', sd.hashes,
                                                'yara_rules', sd.yara_rules, 'size', sd.size)
                       FROM signature_databases sd WHERE sd.version = a.database_version), {}
           FROM agents a WHERE a.id = $1",
        risks!(),
        db_max_age!()
    )))
    .bind(id)
    .fetch_one(&st.db)
    .await?;
    Ok(Json(AgentSecurity {
        supported,
        online,
        state,
        reported_at,
        error,
        products,
        detections,
        actions,
        sensor_supported,
        sensor,
        sensor_at,
        content_version,
        isolated,
        policy,
        quarantine,
        risks,
        database,
        database_max_age_hours,
    }))
}

#[derive(Deserialize)]
pub struct StartAction {
    action: String,
    /// Which product; the first one that can run the action if omitted.
    product: Option<String>,
}

pub async fn start(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>, Json(b): Json<StartAction>) -> ApiResult<Json<Value>> {
    u.need(Perm::SecurityRespond)?;
    super::access::agent(&st, &u, id).await?;
    let action = parse_action(&b.action)?;
    let product = match b.product.as_deref().filter(|p| !p.is_empty()) {
        Some(p) => Some(ProductKind::parse(p).ok_or_else(|| ApiError::BadRequest(format!("unknown product {p}")))?),
        None => None,
    };
    let (action_id, product) = core::start(&st, id, product, action, u.id).await.map_err(start_error)?;
    auth::audit(
        &st.db,
        Some(u.id),
        &format!("security.{}", action.as_str()),
        Some(("agent", id)),
        json!({ "product": product.as_str(), "action_id": action_id }),
    )
    .await;
    Ok(Json(json!({ "id": action_id, "product": product.as_str(), "action": action.as_str() })))
}

/// Ask the agent for its state now.
pub async fn refresh(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    u.need(Perm::SecurityRead)?;
    super::access::agent(&st, &u, id).await?;
    core::refresh(&st, id).await.map_err(start_error)?;
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
pub struct CanaryIn {
    canary: bool,
}

/// Canary clients get new detection content first.
pub async fn set_canary(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>, Json(b): Json<CanaryIn>) -> ApiResult<Json<Value>> {
    u.need(Perm::SecurityManage)?;
    super::access::client(&u, id)?;
    let n = sqlx::query("UPDATE clients SET security_canary = $2 WHERE id = $1").bind(id).bind(b.canary).execute(&st.db).await?.rows_affected();
    if n == 0 {
        return Err(ApiError::NotFound("client"));
    }
    auth::audit(&st.db, Some(u.id), "security.canary", None, json!({ "client_id": id, "canary": b.canary })).await;
    core::push_content(&st).await;
    Ok(Json(json!({ "ok": true })))
}

// ---------------------------------------------------------------------------
// Exclusions (milestone 2)
// ---------------------------------------------------------------------------

#[derive(Serialize, sqlx::FromRow)]
pub struct ExclusionRow {
    id: Uuid,
    client_id: Option<Uuid>,
    client_name: Option<String>,
    kind: String,
    value: String,
    comment: String,
    created_by_name: Option<String>,
    created_at: DateTime<Utc>,
}

pub async fn exclusions(State(st): State<Arc<AppState>>, u: User) -> ApiResult<Json<Vec<ExclusionRow>>> {
    u.need(Perm::SecurityRead)?;
    Ok(Json(
        sqlx::query_as(
            "SELECT e.id, e.client_id, c.name AS client_name, e.kind, e.value, e.comment, us.name AS created_by_name, e.created_at
               FROM security_exclusions e LEFT JOIN clients c ON c.id = e.client_id LEFT JOIN users us ON us.id = e.created_by
              WHERE e.client_id IS NULL OR $1::uuid[] IS NULL OR e.client_id = ANY($1)
              ORDER BY e.created_at DESC",
        )
        .bind(u.scope())
        .fetch_all(&st.db)
        .await?,
    ))
}

#[derive(Deserialize)]
pub struct ExclusionIn {
    client_id: Option<Uuid>,
    kind: String,
    value: String,
    #[serde(default)]
    comment: String,
}

async fn add_exclusion(st: &AppState, u: &User, b: &ExclusionIn) -> ApiResult<Uuid> {
    let kind = rmm_proto::security::ExclusionKind::parse(&b.kind).ok_or_else(|| ApiError::BadRequest("kind must be path, sha256, rule or process".into()))?;
    let value = b.value.trim();
    if value.is_empty() || value.len() > 1000 {
        return Err(ApiError::BadRequest("value must be 1-1000 characters".into()));
    }
    if kind == rmm_proto::security::ExclusionKind::Sha256 && (value.len() != 64 || !value.bytes().all(|c| c.is_ascii_hexdigit())) {
        return Err(ApiError::BadRequest("a sha256 is 64 hex characters".into()));
    }
    if kind == rmm_proto::security::ExclusionKind::Path && (value == "/" || value == "*" || value.eq_ignore_ascii_case("c:\\")) {
        return Err(ApiError::BadRequest("excluding a whole drive switches scanning off; exclude something narrower".into()));
    }
    match b.client_id {
        Some(c) => super::access::client(u, c)?,
        None if u.scope().is_some() => return Err(ApiError::BadRequest("pick a client: you can't add MSP-wide exclusions".into())),
        None => {}
    }
    let id = Uuid::new_v4();
    let value = if kind == rmm_proto::security::ExclusionKind::Sha256 { value.to_ascii_lowercase() } else { value.to_string() };
    sqlx::query("INSERT INTO security_exclusions (id, client_id, kind, value, comment, created_by) VALUES ($1, $2, $3, $4, $5, $6)")
        .bind(id)
        .bind(b.client_id)
        .bind(kind.as_str())
        .bind(&value)
        .bind(b.comment.trim().chars().take(500).collect::<String>())
        .bind(u.id)
        .execute(&st.db)
        .await?;
    auth::audit(&st.db, Some(u.id), "security.exclusion_add", None, json!({ "id": id, "client_id": b.client_id, "kind": kind.as_str(), "value": value, "comment": b.comment })).await;
    Ok(id)
}

pub async fn create_exclusion(State(st): State<Arc<AppState>>, u: User, Json(b): Json<ExclusionIn>) -> ApiResult<Json<Value>> {
    u.need(Perm::SecurityManage)?;
    let id = add_exclusion(&st, &u, &b).await?;
    core::push_policies(&st).await;
    Ok(Json(json!({ "id": id })))
}

pub async fn delete_exclusion(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    u.need(Perm::SecurityManage)?;
    let row: Option<(Option<Uuid>, String, String)> =
        sqlx::query_as("SELECT client_id, kind, value FROM security_exclusions WHERE id = $1").bind(id).fetch_optional(&st.db).await?;
    let Some((client, kind, value)) = row else { return Err(ApiError::NotFound("exclusion")) };
    match client {
        Some(c) => super::access::client(&u, c)?,
        None if u.scope().is_some() => return Err(ApiError::Forbidden),
        None => {}
    }
    sqlx::query("DELETE FROM security_exclusions WHERE id = $1").bind(id).execute(&st.db).await?;
    auth::audit(&st.db, Some(u.id), "security.exclusion_remove", None, json!({ "id": id, "client_id": client, "kind": kind, "value": value })).await;
    core::push_policies(&st).await;
    Ok(Json(json!({ "ok": true })))
}

// ---------------------------------------------------------------------------
// Rules (milestones 4 and 7)
// ---------------------------------------------------------------------------

/// Days a rule must have been in content before it may block.
const BLOCK_AFTER_DAYS: i64 = 7;

#[derive(Serialize)]
pub struct RuleRow {
    #[serde(flatten)]
    rule: Value,
    /// Server override, if any.
    override_mode: Option<String>,
    override_reason: Option<String>,
    /// What agents run (override, else the bundle's).
    effective_mode: String,
    /// In general (or canary) content since.
    first_seen: Option<DateTime<Utc>>,
    /// Stage of the newest version carrying it.
    stage: String,
    hits_7d: i64,
    audit_hits_7d: i64,
    agents_30d: i64,
    true_positives: i64,
    false_positives: i64,
    /// Share of its 30-day verdicts that were false positives (null without verdicts).
    fp_rate: Option<f64>,
    can_block: bool,
    block_blocker: Option<String>,
}

pub async fn rules(State(st): State<Arc<AppState>>, u: User) -> ApiResult<Json<Vec<RuleRow>>> {
    u.need(Perm::SecurityRead)?;
    // The newest version per stage that agents run (general, plus canary), of the content
    // bundles and of the signature databases.
    let versions: Vec<(String, Value, DateTime<Utc>)> = sqlx::query_as(
        "SELECT stage, rules, uploaded_at FROM (
             SELECT stage, rules, uploaded_at FROM content_versions WHERE stage IN ('general', 'canary')
             UNION ALL SELECT stage, rules, uploaded_at FROM signature_databases WHERE stage IN ('general', 'canary')) v
          ORDER BY stage = 'general' DESC, uploaded_at DESC",
    )
    .fetch_all(&st.db)
    .await?;
    let firsts: Vec<(String, DateTime<Utc>)> = sqlx::query_as(
        "SELECT r->>'id', min(cv.uploaded_at) FROM (
             SELECT rules, uploaded_at, stage FROM content_versions UNION ALL SELECT rules, uploaded_at, stage FROM signature_databases) cv,
             jsonb_array_elements(cv.rules) r
          WHERE cv.stage IN ('general', 'retired') GROUP BY 1",
    )
    .fetch_all(&st.db)
    .await?;
    let first: std::collections::HashMap<String, DateTime<Utc>> = firsts.into_iter().collect();
    let overrides: Vec<(String, String, String)> = sqlx::query_as("SELECT rule_id, mode, reason FROM security_rule_overrides").fetch_all(&st.db).await?;
    let ov: std::collections::HashMap<String, (String, String)> = overrides.into_iter().map(|(a, b, c)| (a, (b, c))).collect();
    let stats: Vec<(String, i64, i64, i64, i64, i64)> = sqlx::query_as(
        "SELECT d.rule_id,
                count(*) FILTER (WHERE NOT d.audit AND d.first_seen_at > now() - interval '7 days'),
                count(*) FILTER (WHERE d.audit AND d.first_seen_at > now() - interval '7 days'),
                count(DISTINCT d.agent_id),
                count(*) FILTER (WHERE d.verdict = 'true_positive'),
                count(*) FILTER (WHERE d.verdict IN ('false_positive', 'benign'))
           FROM security_detections d JOIN agents a ON a.id = d.agent_id JOIN sites s ON s.id = a.site_id
          WHERE d.rule_id IS NOT NULL AND d.first_seen_at > now() - interval '30 days' AND ($1::uuid[] IS NULL OR s.client_id = ANY($1))
          GROUP BY 1",
    )
    .bind(u.scope())
    .fetch_all(&st.db)
    .await?;
    let stats: std::collections::HashMap<String, (i64, i64, i64, i64, i64)> = stats.into_iter().map(|(id, a, b, c, d, e)| (id, (a, b, c, d, e))).collect();
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for (stage, rules, uploaded) in versions {
        for r in rules.as_array().cloned().unwrap_or_default() {
            let id = r.get("id").and_then(|v| v.as_str()).unwrap_or_default().to_string();
            if !seen.insert(id.clone()) {
                continue;
            }
            let (hits, audit_hits, agents, tp, fp) = stats.get(&id).copied().unwrap_or_default();
            let bundle_mode = r.get("mode").and_then(|v| v.as_str()).unwrap_or("audit").to_string();
            let (override_mode, override_reason) = ov.get(&id).cloned().map(|(m, r)| (Some(m), Some(r))).unwrap_or((None, None));
            let first_seen = first.get(&id).copied().or((stage == "general").then_some(uploaded));
            let blocker = block_blocker(&r, first_seen, fp);
            out.push(RuleRow {
                effective_mode: override_mode.clone().unwrap_or(bundle_mode),
                override_mode,
                override_reason,
                first_seen,
                stage: stage.clone(),
                hits_7d: hits,
                audit_hits_7d: audit_hits,
                agents_30d: agents,
                true_positives: tp,
                false_positives: fp,
                fp_rate: (tp + fp > 0).then(|| fp as f64 / (tp + fp) as f64),
                can_block: blocker.is_none(),
                block_blocker: blocker,
                rule: r,
            });
        }
    }
    Ok(Json(out))
}

/// Why a rule may not block yet, if it may not.
fn block_blocker(rule: &Value, first_seen: Option<DateTime<Utc>>, false_positives: i64) -> Option<String> {
    if rule.get("confidence").and_then(|v| v.as_str()) != Some("high") {
        return Some("only high-confidence rules can block".into());
    }
    match first_seen {
        None => return Some("it isn't in general content yet".into()),
        Some(t) if Utc::now() - t < chrono::Duration::days(BLOCK_AFTER_DAYS) => {
            return Some(format!("it needs {BLOCK_AFTER_DAYS} days in general content first (audit history)"));
        }
        _ => {}
    }
    if false_positives > 0 {
        return Some(format!("it had {false_positives} false positives in the last 30 days"));
    }
    None
}

#[derive(Deserialize)]
pub struct RuleModeIn {
    /// null removes the override.
    mode: Option<String>,
    #[serde(default)]
    reason: String,
}

/// Sets the mode a rule runs in fleet-wide. `disabled` is the kill switch.
pub async fn set_rule_mode(State(st): State<Arc<AppState>>, u: User, Path(id): Path<String>, Json(b): Json<RuleModeIn>) -> ApiResult<Json<Value>> {
    u.need(Perm::SecurityManage)?;
    if u.scope().is_some() {
        return Err(ApiError::BadRequest("rule modes apply to every client; ask someone who sees all of them".into()));
    }
    match b.mode.as_deref() {
        None => {
            sqlx::query("DELETE FROM security_rule_overrides WHERE rule_id = $1").bind(&id).execute(&st.db).await?;
        }
        Some(m) => {
            let mode = rmm_proto::security::RuleMode::parse(m).ok_or_else(|| ApiError::BadRequest("mode must be disabled, audit, alert or block".into()))?;
            if mode == rmm_proto::security::RuleMode::Block {
                let rule: Option<Value> = sqlx::query_scalar(
                    "SELECT r FROM (SELECT rules, uploaded_at, stage FROM content_versions UNION ALL SELECT rules, uploaded_at, stage FROM signature_databases) cv,
                            jsonb_array_elements(cv.rules) r WHERE cv.stage = 'general' AND r->>'id' = $1
                      ORDER BY cv.uploaded_at DESC LIMIT 1",
                )
                .bind(&id)
                .fetch_optional(&st.db)
                .await?;
                let Some(rule) = rule else { return Err(ApiError::BadRequest("that rule isn't in general content".into())) };
                let first: Option<DateTime<Utc>> = sqlx::query_scalar(
                    "SELECT min(cv.uploaded_at) FROM (SELECT rules, uploaded_at, stage FROM content_versions UNION ALL SELECT rules, uploaded_at, stage FROM signature_databases) cv,
                            jsonb_array_elements(cv.rules) r WHERE cv.stage IN ('general', 'retired') AND r->>'id' = $1",
                )
                .bind(&id)
                .fetch_one(&st.db)
                .await?;
                let fp: i64 = sqlx::query_scalar(
                    "SELECT count(*) FROM security_detections WHERE rule_id = $1 AND verdict IN ('false_positive', 'benign') AND first_seen_at > now() - interval '30 days'",
                )
                .bind(&id)
                .fetch_one(&st.db)
                .await?;
                if let Some(why) = block_blocker(&rule, first, fp) {
                    return Err(ApiError::BadRequest(format!("{id} can't block yet: {why}")));
                }
            }
            sqlx::query(
                "INSERT INTO security_rule_overrides (rule_id, mode, reason, updated_by) VALUES ($1, $2, $3, $4)
                 ON CONFLICT (rule_id) DO UPDATE SET mode = EXCLUDED.mode, reason = EXCLUDED.reason, updated_by = EXCLUDED.updated_by, updated_at = now()",
            )
            .bind(&id)
            .bind(mode.as_str())
            .bind(b.reason.trim().chars().take(500).collect::<String>())
            .bind(u.id)
            .execute(&st.db)
            .await?;
        }
    }
    auth::audit(&st.db, Some(u.id), "security.rule_mode", None, json!({ "rule": id, "mode": b.mode, "reason": b.reason })).await;
    core::push_policies(&st).await;
    Ok(Json(json!({ "ok": true })))
}

// ---------------------------------------------------------------------------
// Content (signed bundles, staged rollout)
// ---------------------------------------------------------------------------

#[derive(Serialize, sqlx::FromRow)]
pub struct ContentRow {
    id: Uuid,
    version: String,
    sha256: String,
    description: String,
    rule_count: i64,
    hashes: i32,
    stage: String,
    stage_reason: Option<String>,
    uploaded_by_name: Option<String>,
    uploaded_at: DateTime<Utc>,
    stage_changed_at: DateTime<Utc>,
    /// Agents reporting this version.
    agents: i64,
}

pub async fn content(State(st): State<Arc<AppState>>, u: User) -> ApiResult<Json<Value>> {
    u.need(Perm::SecurityRead)?;
    let rows: Vec<ContentRow> = sqlx::query_as(
        "SELECT cv.id, cv.version, cv.sha256, cv.description, jsonb_array_length(cv.rules)::bigint AS rule_count, cv.hashes, cv.stage, cv.stage_reason,
                us.name AS uploaded_by_name, cv.uploaded_at, cv.stage_changed_at,
                (SELECT count(*) FROM agents a WHERE a.content_version = cv.version) AS agents
           FROM content_versions cv LEFT JOIN users us ON us.id = cv.uploaded_by
          ORDER BY cv.uploaded_at DESC LIMIT 100",
    )
    .fetch_all(&st.db)
    .await?;
    let canary_clients: i64 = sqlx::query_scalar("SELECT count(*) FROM clients WHERE security_canary").fetch_one(&st.db).await?;
    Ok(Json(json!({
        "versions": rows,
        "canary_clients": canary_clients,
        "soak_minutes": st.cfg.content_soak_minutes,
        "verifies_signatures": st.cfg.content_pubkey.is_some(),
    })))
}

#[derive(Deserialize)]
pub struct ContentIn {
    /// The bundle's JSON text, exactly as signed.
    bundle: String,
    /// The `.sig` file `rmm-sign sign-content` wrote.
    signature: core::SignatureFile,
}

pub async fn upload_content(State(st): State<Arc<AppState>>, u: User, Json(b): Json<ContentIn>) -> ApiResult<Json<Value>> {
    u.need(Perm::SecurityManage)?;
    if u.scope().is_some() {
        return Err(ApiError::Forbidden);
    }
    let (id, version) = core::upload_content(&st, b.bundle.into_bytes(), b.signature, u.id).await.map_err(ApiError::BadRequest)?;
    auth::audit(&st.db, Some(u.id), "security.content_upload", None, json!({ "version": version })).await;
    Ok(Json(json!({ "id": id, "version": version, "stage": "canary" })))
}

#[derive(Deserialize, Default)]
pub struct StageIn {
    #[serde(default)]
    reason: String,
}

pub async fn promote_content(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>, body: Option<Json<StageIn>>) -> ApiResult<Json<Value>> {
    u.need(Perm::SecurityManage)?;
    if u.scope().is_some() {
        return Err(ApiError::Forbidden);
    }
    let reason = body.map(|b| b.0.reason).filter(|r| !r.trim().is_empty()).unwrap_or_else(|| "promoted by hand".into());
    if !core::set_stage(&st, core::Track::Content, id, "general", &reason, Some(u.id)).await? {
        return Err(ApiError::Conflict("already general (or no such version)".into()));
    }
    Ok(Json(json!({ "ok": true })))
}

pub async fn rollback_content(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>, body: Option<Json<StageIn>>) -> ApiResult<Json<Value>> {
    u.need(Perm::SecurityManage)?;
    if u.scope().is_some() {
        return Err(ApiError::Forbidden);
    }
    let reason = body.map(|b| b.0.reason).filter(|r| !r.trim().is_empty()).unwrap_or_else(|| "rolled back by hand".into());
    if !core::set_stage(&st, core::Track::Content, id, "rolled_back", &reason, Some(u.id)).await? {
        return Err(ApiError::Conflict("already rolled back (or no such version)".into()));
    }
    Ok(Json(json!({ "ok": true })))
}

// ---------------------------------------------------------------------------
// Signature databases (antivirus milestone 2): upload, stages, the agents' download
// ---------------------------------------------------------------------------

/// Largest database upload.
pub const DATABASE_MAX: u64 = 2 << 30;

#[derive(Serialize, sqlx::FromRow)]
pub struct DatabaseRow {
    id: Uuid,
    version: String,
    sha256: String,
    size: i64,
    description: String,
    hashes: i64,
    yara_rules: i32,
    rule_count: i64,
    sources: Value,
    built_at: DateTime<Utc>,
    stage: String,
    stage_reason: Option<String>,
    /// False once pruned from storage (it can't be rolled out again).
    stored: bool,
    uploaded_by_name: Option<String>,
    uploaded_at: DateTime<Utc>,
    stage_changed_at: DateTime<Utc>,
    /// Agents reporting this version.
    agents: i64,
}

pub async fn databases(State(st): State<Arc<AppState>>, u: User) -> ApiResult<Json<Value>> {
    u.need(Perm::SecurityRead)?;
    let rows: Vec<DatabaseRow> = sqlx::query_as(
        "SELECT sd.id, sd.version, sd.sha256, sd.size, sd.description, sd.hashes, sd.yara_rules, jsonb_array_length(sd.rules)::bigint AS rule_count,
                sd.sources, sd.built_at, sd.stage, sd.stage_reason, sd.storage_key IS NOT NULL AS stored, us.name AS uploaded_by_name,
                sd.uploaded_at, sd.stage_changed_at, (SELECT count(*) FROM agents a WHERE a.database_version = sd.version) AS agents
           FROM signature_databases sd LEFT JOIN users us ON us.id = sd.uploaded_by
          ORDER BY sd.uploaded_at DESC LIMIT 100",
    )
    .fetch_all(&st.db)
    .await?;
    Ok(Json(json!({ "versions": rows, "soak_minutes": st.cfg.content_soak_minutes, "verifies_signatures": st.cfg.content_pubkey.is_some() })))
}

/// `POST /security/databases`: the `.rmmdb` file `rmm-sign build-db` wrote, as the body.
pub async fn upload_database(State(st): State<Arc<AppState>>, u: User, body: axum::body::Body) -> ApiResult<Json<Value>> {
    u.need(Perm::SecurityManage)?;
    if u.scope().is_some() {
        return Err(ApiError::Forbidden);
    }
    let up = core::upload_database(&st, body.into_data_stream(), DATABASE_MAX, u.id).await.map_err(ApiError::BadRequest)?;
    auth::audit(&st.db, Some(u.id), "security.database_upload", None, json!({ "version": up.version, "size": up.size })).await;
    Ok(Json(json!({ "id": up.id, "version": up.version, "size": up.size, "stage": "canary" })))
}

pub async fn promote_database(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>, body: Option<Json<StageIn>>) -> ApiResult<Json<Value>> {
    u.need(Perm::SecurityManage)?;
    if u.scope().is_some() {
        return Err(ApiError::Forbidden);
    }
    let stored: Option<bool> = sqlx::query_scalar("SELECT storage_key IS NOT NULL FROM signature_databases WHERE id = $1").bind(id).fetch_optional(&st.db).await?;
    if stored == Some(false) {
        return Err(ApiError::Conflict("that version was pruned from storage; upload it again".into()));
    }
    let reason = body.map(|b| b.0.reason).filter(|r| !r.trim().is_empty()).unwrap_or_else(|| "promoted by hand".into());
    if !core::set_stage(&st, core::Track::Database, id, "general", &reason, Some(u.id)).await? {
        return Err(ApiError::Conflict("already general (or no such version)".into()));
    }
    Ok(Json(json!({ "ok": true })))
}

pub async fn rollback_database(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>, body: Option<Json<StageIn>>) -> ApiResult<Json<Value>> {
    u.need(Perm::SecurityManage)?;
    if u.scope().is_some() {
        return Err(ApiError::Forbidden);
    }
    let reason = body.map(|b| b.0.reason).filter(|r| !r.trim().is_empty()).unwrap_or_else(|| "rolled back by hand".into());
    if !core::set_stage(&st, core::Track::Database, id, "rolled_back", &reason, Some(u.id)).await? {
        return Err(ApiError::Conflict("already rolled back (or no such version)".into()));
    }
    Ok(Json(json!({ "ok": true })))
}

/// `GET /agent/databases/{version}`: the file, for an agent (its id in `X-Rmm-Agent`, its
/// secret as the bearer token), with `Range` so an interrupted download resumes.
pub async fn agent_database(State(st): State<Arc<AppState>>, Path(version): Path<String>, headers: axum::http::HeaderMap) -> ApiResult<axum::response::Response> {
    let agent_id = headers.get("x-rmm-agent").and_then(|v| v.to_str().ok()).and_then(|v| v.parse::<Uuid>().ok());
    let secret = headers.get(axum::http::header::AUTHORIZATION).and_then(|v| v.to_str().ok()).and_then(|v| v.strip_prefix("Bearer "));
    let (Some(agent_id), Some(secret)) = (agent_id, secret) else { return Err(ApiError::Unauthorized) };
    if !crate::agent_ws::authenticate(&st, agent_id, secret).await? {
        return Err(ApiError::Unauthorized);
    }
    let row: Option<(String, i64)> = sqlx::query_as("SELECT storage_key, size FROM signature_databases WHERE version = $1 AND storage_key IS NOT NULL AND stage <> 'rolled_back'")
        .bind(&version)
        .fetch_optional(&st.db)
        .await?;
    let (key, size) = row.ok_or(ApiError::NotFound("signature database"))?;
    super::attachments::serve(&st, &headers, &key, size, &format!("{version}.rmmdb"), "application/octet-stream", false).await
}

// ---------------------------------------------------------------------------
// Detection detail and verdicts (milestone 6)
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct DetectionDetail {
    #[serde(flatten)]
    detection: DetectionRow,
    os_family: String,
    online: bool,
    isolated: bool,
    /// The triggering event, its process's ancestors, then related events.
    context: Vec<rmm_proto::telemetry::Event>,
    /// The context is encrypted and this server has no (or another) key.
    context_unavailable: bool,
    content_version: Option<String>,
    /// The signature database it came from, and where in the file it matched.
    database_version: Option<String>,
    part: Option<String>,
    notes: Option<String>,
    verdict_by_name: Option<String>,
    verdict_at: Option<DateTime<Utc>>,
    quarantine_id: Option<Uuid>,
    /// Machines with the same file hash (it ran there, was detected or quarantined), within the
    /// user's clients, first seen first; how many, and when the first saw it.
    prevalence: Vec<Value>,
    seen_on: i64,
    first_seen: Option<DateTime<Utc>>,
    /// What the server's reputation set says about the hash (`[{name, severity, source}]`).
    reputation: Vec<Value>,
    /// Response actions started from this detection.
    actions: Vec<ActionRow>,
    alert: Option<Value>,
    rule: Option<Value>,
}

pub async fn detection(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<DetectionDetail>> {
    u.need(Perm::SecurityRead)?;
    let detection: DetectionRow = sqlx::query_as(AssertSqlSafe(format!(
        "SELECT {DETECTION_COLS} {DETECTION_FROM} WHERE d.id = $1 AND ($2::uuid[] IS NULL OR c.id = ANY($2))"
    )))
    .bind(id)
    .bind(u.scope())
    .fetch_optional(&st.db)
    .await?
    .ok_or(ApiError::NotFound("detection"))?;
    #[allow(clippy::type_complexity)]
    let (os_family, online, isolated, ctx, enc, content_version, notes, verdict_by_name, verdict_at, quarantine_id): (
        String,
        bool,
        bool,
        Option<Vec<u8>>,
        bool,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<DateTime<Utc>>,
        Option<Uuid>,
    ) = sqlx::query_as(
        "SELECT a.os_family, a.online, a.isolated, d.context, d.context_encrypted, d.content_version, d.notes, us.name, d.verdict_at, d.quarantine_id
           FROM security_detections d JOIN agents a ON a.id = d.agent_id LEFT JOIN users us ON us.id = d.verdict_by WHERE d.id = $1",
    )
    .bind(id)
    .fetch_one(&st.db)
    .await?;
    let (context, context_unavailable) = match ctx {
        None => (vec![], false),
        Some(b) => match crate::crypto::load(st.cfg.data_key.as_ref(), &b, enc).and_then(|p| serde_json::from_slice(&p).ok()) {
            Some(c) => (c, false),
            None => (vec![], true),
        },
    };
    let (prevalence, seen_on, first_seen, reputation) = match &detection.sha256 {
        Some(h) => {
            let p = hash_prevalence(&st, &u, h, 100).await?;
            (p.agents, p.seen_on, p.first_seen, p.known)
        }
        None => (vec![], 0, None, vec![]),
    };
    let actions = sqlx::query_as(
        "SELECT sa.id, sa.product, sa.action, sa.status, sa.message, us.name AS created_by_name, sa.created_at, sa.started_at, sa.finished_at,
                sa.params, sa.result, sa.storage_key IS NOT NULL AS has_download
           FROM security_actions sa LEFT JOIN users us ON us.id = sa.created_by WHERE sa.detection_id = $1 ORDER BY sa.created_at DESC",
    )
    .bind(id)
    .fetch_all(&st.db)
    .await?;
    let alert: Option<Value> = sqlx::query_scalar(
        "SELECT jsonb_build_object('id', al.id, 'title', al.title, 'state', CASE WHEN al.resolved_at IS NOT NULL THEN 'resolved' ELSE 'open' END)
           FROM alerts al WHERE al.key = 'threat:' || $1::text ORDER BY al.opened_at DESC LIMIT 1",
    )
    .bind(id)
    .fetch_optional(&st.db)
    .await?;
    let (database_version, part): (Option<String>, Option<String>) =
        sqlx::query_as("SELECT database_version, part FROM security_detections WHERE id = $1").bind(id).fetch_one(&st.db).await?;
    let rule: Option<Value> = match &detection.rule_id {
        Some(r) => sqlx::query_scalar(
            "SELECT r FROM (SELECT rules, uploaded_at FROM content_versions UNION ALL SELECT rules, uploaded_at FROM signature_databases) cv,
                    jsonb_array_elements(cv.rules) r WHERE r->>'id' = $1 ORDER BY cv.uploaded_at DESC LIMIT 1",
        )
        .bind(r)
        .fetch_optional(&st.db)
        .await?,
        None => None,
    };
    Ok(Json(DetectionDetail {
        detection,
        os_family,
        online,
        isolated,
        context,
        context_unavailable,
        content_version,
        database_version,
        part,
        notes,
        verdict_by_name,
        verdict_at,
        quarantine_id,
        prevalence,
        seen_on,
        first_seen,
        reputation,
        actions,
        alert,
        rule,
    }))
}

#[derive(Deserialize)]
pub struct VerdictIn {
    /// true_positive / false_positive / benign, or null to reopen.
    verdict: Option<String>,
    #[serde(default)]
    notes: String,
    /// With false_positive: also exclude this file's hash (or the rule) for the detection's client.
    #[serde(default)]
    exclude: Option<String>,
}

/// Records what a person decided. Verdicts resolve the detection and feed each rule's
/// false-positive rate (and the rollout's rollback check).
pub async fn verdict(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>, Json(b): Json<VerdictIn>) -> ApiResult<Json<Value>> {
    u.need(Perm::SecurityRespond)?;
    let row: Option<(Uuid, Uuid, Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT d.agent_id, s.client_id, d.sha256, d.rule_id FROM security_detections d JOIN agents a ON a.id = d.agent_id JOIN sites s ON s.id = a.site_id
          WHERE d.id = $1 AND ($2::uuid[] IS NULL OR s.client_id = ANY($2))",
    )
    .bind(id)
    .bind(u.scope())
    .fetch_optional(&st.db)
    .await?;
    let Some((agent_id, client_id, sha, rule)) = row else { return Err(ApiError::NotFound("detection")) };
    if b.verdict.as_deref().is_some_and(|v| !matches!(v, "true_positive" | "false_positive" | "benign")) {
        return Err(ApiError::BadRequest("verdict must be true_positive, false_positive or benign".into()));
    }
    sqlx::query(
        "UPDATE security_detections SET verdict = $2, notes = nullif($3, ''), verdict_by = $4, verdict_at = CASE WHEN $2::text IS NULL THEN NULL ELSE now() END,
                resolved_at = CASE WHEN $2::text IS NULL THEN (CASE WHEN status = 'active' AND NOT audit THEN NULL ELSE resolved_at END) ELSE coalesce(resolved_at, now()) END
          WHERE id = $1",
    )
    .bind(id)
    .bind(&b.verdict)
    .bind(b.notes.trim())
    .bind(u.id)
    .execute(&st.db)
    .await?;
    if let Some(kind) = b.exclude.as_deref().filter(|_| b.verdict.as_deref() == Some("false_positive")) {
        u.need(Perm::SecurityManage)?;
        let value = match kind {
            "sha256" => sha.clone().ok_or_else(|| ApiError::BadRequest("this detection has no file hash".into()))?,
            "rule" => rule.clone().ok_or_else(|| ApiError::BadRequest("this detection has no rule".into()))?,
            _ => return Err(ApiError::BadRequest("exclude must be sha256 or rule".into())),
        };
        add_exclusion(&st, &u, &ExclusionIn { client_id: Some(client_id), kind: kind.into(), value, comment: format!("false positive (detection {id})") }).await?;
        core::push_policies(&st).await;
    }
    auth::audit(&st.db, Some(u.id), "security.verdict", Some(("agent", agent_id)), json!({ "detection": id, "verdict": b.verdict, "rule": rule })).await;
    st.hub.publish(crate::hub::Event::Security { agent_id, client_id });
    // Resolving a threat alert follows the detection.
    crate::alerts::security_reported(&st, agent_id, &[]).await;
    Ok(Json(json!({ "ok": true })))
}

// ---------------------------------------------------------------------------
// Quarantine
// ---------------------------------------------------------------------------

#[derive(Serialize, sqlx::FromRow)]
pub struct QuarantineRow {
    id: Uuid,
    agent_id: Uuid,
    hostname: String,
    client_id: Uuid,
    client_name: String,
    path: String,
    sha256: String,
    size: i64,
    reason: Option<String>,
    quarantined_at: DateTime<Utc>,
    state: String,
    updated_at: DateTime<Utc>,
}

const QUARANTINE_SELECT: &str = "SELECT q.id, q.agent_id, a.hostname, c.id AS client_id, c.name AS client_name, q.path, q.sha256, q.size, q.reason,
       q.quarantined_at, q.state, q.updated_at
  FROM quarantine_items q JOIN agents a ON a.id = q.agent_id JOIN sites s ON s.id = a.site_id JOIN clients c ON c.id = s.client_id";

#[derive(Deserialize)]
pub struct QuarantineQuery {
    client_id: Option<Uuid>,
    agent_id: Option<Uuid>,
    /// quarantined (default) or all
    state: Option<String>,
    q: Option<String>,
}

pub async fn quarantine(State(st): State<Arc<AppState>>, u: User, Query(q): Query<QuarantineQuery>) -> ApiResult<Json<Vec<QuarantineRow>>> {
    u.need(Perm::SecurityRead)?;
    let all = q.state.as_deref() == Some("all");
    let search = q.q.as_deref().map(str::trim).filter(|s| !s.is_empty());
    Ok(Json(
        sqlx::query_as(AssertSqlSafe(format!(
            "{QUARANTINE_SELECT}
              WHERE ($1::uuid[] IS NULL OR c.id = ANY($1)) AND ($2::uuid IS NULL OR c.id = $2) AND ($3::uuid IS NULL OR q.agent_id = $3)
                AND ($4 OR q.state = 'quarantined')
                AND ($5::text IS NULL OR q.path ILIKE '%' || $5 || '%' OR a.hostname ILIKE '%' || $5 || '%' OR q.sha256 = lower($5))
              ORDER BY q.quarantined_at DESC LIMIT 500"
        )))
        .bind(u.scope())
        .bind(q.client_id)
        .bind(q.agent_id)
        .bind(all)
        .bind(search)
        .fetch_all(&st.db)
        .await?,
    ))
}

// ---------------------------------------------------------------------------
// Response actions (milestone 5)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct RespondIn {
    action: rmm_proto::security::ResponseAction,
    /// The detection this answers, so it shows on the investigation page.
    detection_id: Option<Uuid>,
    /// Restoring a file: also exclude its hash for this client, so the next scan doesn't
    /// quarantine it again.
    #[serde(default)]
    exclude_hash: bool,
}

pub async fn respond(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>, Json(b): Json<RespondIn>) -> ApiResult<Json<Value>> {
    use rmm_proto::security::ResponseAction as R;
    u.need(Perm::SecurityRespond)?;
    let client_id = super::access::agent(&st, &u, id).await?;
    match &b.action {
        R::KillProcess { pid, .. } if *pid <= 4 => return Err(ApiError::BadRequest("that's a system process".into())),
        R::QuarantineFile { path } | R::ScanPath { path } if path.trim().is_empty() || path.len() > 4096 => {
            return Err(ApiError::BadRequest("a path is required".into()));
        }
        R::Isolate { allow } if allow.len() > 20 || allow.iter().any(|h| h.trim().is_empty() || h.len() > 255) => {
            return Err(ApiError::BadRequest("up to 20 extra hosts".into()));
        }
        R::RestoreFile { id: qid } | R::DeleteQuarantined { id: qid } => {
            let sha: Option<String> = sqlx::query_scalar("SELECT sha256 FROM quarantine_items WHERE id = $1 AND agent_id = $2").bind(qid).bind(id).fetch_optional(&st.db).await?;
            let Some(sha) = sha else { return Err(ApiError::NotFound("quarantined file")) };
            if b.exclude_hash && matches!(b.action, R::RestoreFile { .. }) {
                u.need(Perm::SecurityManage)?;
                add_exclusion(&st, &u, &ExclusionIn { client_id: Some(client_id), kind: "sha256".into(), value: sha, comment: "restored from quarantine".into() }).await?;
                core::push_policies(&st).await;
            }
        }
        _ => {}
    }
    if let Some(d) = b.detection_id {
        let ok: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM security_detections WHERE id = $1 AND agent_id = $2)").bind(d).bind(id).fetch_one(&st.db).await?;
        if !ok {
            return Err(ApiError::NotFound("detection"));
        }
    }
    let name = b.action.name();
    let params = serde_json::to_value(&b.action).unwrap_or_default();
    let action_id = core::respond(&st, id, b.action, u.id, b.detection_id).await.map_err(start_error)?;
    auth::audit(&st.db, Some(u.id), &format!("security.{name}"), Some(("agent", id)), json!({ "action_id": action_id, "params": params, "detection": b.detection_id })).await;
    Ok(Json(json!({ "id": action_id, "action": name })))
}

/// A triage package.
pub async fn download(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<axum::response::Response> {
    use axum::http::header;
    use axum::response::IntoResponse;
    u.need(Perm::SecurityRespond)?;
    let row: Option<(Uuid, Option<String>, String, DateTime<Utc>)> = sqlx::query_as(
        "SELECT sa.agent_id, sa.storage_key, a.hostname, sa.created_at FROM security_actions sa JOIN agents a ON a.id = sa.agent_id WHERE sa.id = $1",
    )
    .bind(id)
    .fetch_optional(&st.db)
    .await?;
    let Some((agent_id, Some(key), hostname, at)) = row else { return Err(ApiError::NotFound("package")) };
    super::access::agent(&st, &u, agent_id).await?;
    let bytes = st.storage.get(&key).await?;
    auth::audit(&st.db, Some(u.id), "security.triage_download", Some(("agent", agent_id)), json!({ "action_id": id })).await;
    let name: String = hostname.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '.').collect();
    let file = format!("triage-{name}-{}.tar.gz", at.format("%Y%m%d-%H%M%S"));
    Ok((
        [
            (header::CONTENT_TYPE, "application/gzip".to_string()),
            (header::CONTENT_DISPOSITION, format!("attachment; filename=\"{file}\"")),
        ],
        bytes,
    )
        .into_response())
}

// ---------------------------------------------------------------------------
// Telemetry and hunting (milestones 3 and 6)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct TelemetryQueryIn {
    text: Option<String>,
    /// Comma-separated: process, network, file, registry, module.
    kinds: Option<String>,
    pid: Option<u32>,
    sha256: Option<String>,
    /// Only the last N minutes.
    minutes: Option<i64>,
    /// Around this time (± `window` minutes), for a detection's timeline.
    around: Option<DateTime<Utc>>,
    window: Option<i64>,
    limit: Option<u32>,
}

impl TelemetryQueryIn {
    fn query(&self) -> ApiResult<rmm_proto::telemetry::Query> {
        let kinds = match self.kinds.as_deref().filter(|k| !k.is_empty()) {
            Some(k) => k
                .split(',')
                .map(|x| rmm_proto::telemetry::EventKind::parse(x.trim()).ok_or_else(|| ApiError::BadRequest(format!("unknown event kind {x}"))))
                .collect::<ApiResult<Vec<_>>>()?,
            None => vec![],
        };
        let (since, until) = match (self.around, self.minutes) {
            (Some(t), _) => {
                let w = chrono::Duration::minutes(self.window.unwrap_or(10).clamp(1, 1440));
                (Some(t - w), Some(t + w))
            }
            (None, Some(m)) => (Some(Utc::now() - chrono::Duration::minutes(m.clamp(1, 60 * 24 * 90))), None),
            _ => (None, None),
        };
        Ok(rmm_proto::telemetry::Query {
            since,
            until,
            kinds,
            text: self.text.clone().filter(|t| !t.trim().is_empty()),
            pid: self.pid,
            sha256: self.sha256.clone().filter(|h| !h.is_empty()),
            limit: Some(self.limit.unwrap_or(200).clamp(1, rmm_proto::telemetry::QUERY_MAX)),
        })
    }
}

pub async fn telemetry(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>, Query(q): Query<TelemetryQueryIn>) -> ApiResult<Json<Value>> {
    u.need(Perm::SecurityRead)?;
    super::access::agent(&st, &u, id).await?;
    let query = q.query()?;
    let (events, truncated, error) = core::telemetry_query(&st, id, query).await.map_err(ApiError::Conflict)?;
    Ok(Json(json!({ "events": events, "truncated": truncated, "error": error })))
}

#[derive(Deserialize)]
pub struct HuntIn {
    #[serde(flatten)]
    query: TelemetryQueryIn,
    client_id: Option<Uuid>,
}

/// Runs a telemetry query on every online agent with a sensor (in the user's clients) at once.
pub async fn hunt(State(st): State<Arc<AppState>>, u: User, Json(b): Json<HuntIn>) -> ApiResult<Json<Value>> {
    u.need(Perm::SecurityRead)?;
    let mut query = b.query.query()?;
    if query.text.is_none() && query.sha256.is_none() && query.pid.is_none() {
        return Err(ApiError::BadRequest("search for something: text or a hash".into()));
    }
    query.limit = Some(query.limit.unwrap_or(50).min(100));
    let scope = super::agents::narrow(&u, b.client_id)?;
    let agents: Vec<(Uuid, String, String)> = sqlx::query_as(
        "SELECT a.id, a.hostname, c.name FROM agents a JOIN sites s ON s.id = a.site_id JOIN clients c ON c.id = s.client_id
          WHERE 'sensor' = ANY(a.capabilities) AND ($1::uuid[] IS NULL OR c.id = ANY($1)) ORDER BY lower(a.hostname) LIMIT 1000",
    )
    .bind(&scope)
    .fetch_all(&st.db)
    .await?;
    let (online, offline): (Vec<_>, Vec<_>) = agents.into_iter().partition(|a| st.hub.is_online(a.0));
    let st2 = st.clone();
    let futures = online.into_iter().map(|(id, hostname, client)| {
        let st = st2.clone();
        let query = query.clone();
        async move {
            let r = core::telemetry_query(&st, id, query).await;
            (id, hostname, client, r)
        }
    });
    let results = futures_util::future::join_all(futures).await;
    let mut hits = Vec::new();
    let mut errors = Vec::new();
    let mut searched = 0;
    for (id, hostname, client, r) in results {
        match r {
            Ok((events, truncated, None)) => {
                searched += 1;
                if !events.is_empty() {
                    hits.push(json!({ "agent_id": id, "hostname": hostname, "client_name": client, "events": events, "truncated": truncated }));
                }
            }
            Ok((_, _, Some(e))) | Err(e) => errors.push(json!({ "agent_id": id, "hostname": hostname, "error": e })),
        }
    }
    auth::audit(&st.db, Some(u.id), "security.hunt", None, json!({ "text": query.text, "sha256": query.sha256, "agents": searched, "hits": hits.len() })).await;
    Ok(Json(json!({ "hits": hits, "searched": searched, "offline": offline.len(), "errors": errors })))
}

#[derive(Deserialize)]
pub struct PrevalenceQuery {
    sha256: String,
}

struct Prevalence {
    agents: Vec<Value>,
    seen_on: i64,
    first_seen: Option<DateTime<Utc>>,
    known: Vec<Value>,
}

/// Which machines have this hash and since when: from the sensors' reputation lookups (it ran
/// there), detections and quarantine. Only the user's clients count, totals included, so a
/// technician limited to some clients learns nothing of the others.
async fn hash_prevalence(st: &AppState, u: &User, sha256: &str, limit: i64) -> ApiResult<Prevalence> {
    let h = sha256.trim().to_ascii_lowercase();
    if h.len() != 64 || !h.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err(ApiError::BadRequest("a sha256 is 64 hex characters".into()));
    }
    let rows: Vec<(Value, i64, Option<DateTime<Utc>>)> = sqlx::query_as(
        "WITH t AS (SELECT agent_id, first_seen_at AS at, 'detected' AS how, NULL::text AS path FROM security_detections WHERE sha256 = $1
                    UNION ALL SELECT agent_id, quarantined_at, 'quarantined', path FROM quarantine_items WHERE sha256 = $1
                    UNION ALL SELECT agent_id, first_seen, 'ran', path FROM hash_sightings WHERE sha256 = decode($1, 'hex')),
              v AS (SELECT a.id, a.hostname, c.name AS client_name, min(t.at) AS first_seen, string_agg(DISTINCT t.how, ', ') AS how, max(t.path) AS path
                      FROM t JOIN agents a ON a.id = t.agent_id JOIN sites s ON s.id = a.site_id JOIN clients c ON c.id = s.client_id
                     WHERE ($2::uuid[] IS NULL OR c.id = ANY($2)) GROUP BY a.id, a.hostname, c.name)
         SELECT jsonb_build_object('agent_id', id, 'hostname', hostname, 'client_name', client_name, 'first_seen', first_seen, 'how', how, 'path', path),
                count(*) OVER (), min(first_seen) OVER ()
           FROM v ORDER BY first_seen LIMIT $3",
    )
    .bind(&h)
    .bind(u.scope())
    .bind(limit)
    .fetch_all(&st.db)
    .await?;
    let known: Vec<Value> = sqlx::query_scalar(
        "SELECT jsonb_build_object('name', name, 'severity', severity, 'source', source, 'added_at', added_at)
           FROM reputation_hashes WHERE sha256 = decode($1, 'hex') ORDER BY source LIKE 'db:%' DESC, added_at DESC",
    )
    .bind(&h)
    .fetch_all(&st.db)
    .await?;
    let (seen_on, first_seen) = rows.first().map_or((0, None), |r| (r.1, r.2));
    Ok(Prevalence { agents: rows.into_iter().map(|r| r.0).collect(), seen_on, first_seen, known })
}

/// `GET /security/prevalence?sha256=`: which machines have seen this hash, first when, and
/// whether the server's reputation set knows it.
pub async fn prevalence(State(st): State<Arc<AppState>>, u: User, Query(q): Query<PrevalenceQuery>) -> ApiResult<Json<Value>> {
    u.need(Perm::SecurityRead)?;
    let p = hash_prevalence(&st, &u, &q.sha256, 500).await?;
    Ok(Json(json!({ "sha256": q.sha256.trim().to_ascii_lowercase(), "agents": p.agents, "seen_on": p.seen_on, "first_seen": p.first_seen, "known": p.known })))
}

#[derive(Deserialize)]
pub struct RareQuery {
    /// Seen on at most this many machines (default 1).
    max_agents: Option<i64>,
    /// First seen within this many days (default 7).
    days: Option<i32>,
    client_id: Option<Uuid>,
}

/// `GET /security/reputation/rare`: programs that ran on few machines, recently, and that the
/// server doesn't know: hunting leads, not detections. Counted within the user's clients.
pub async fn rare(State(st): State<Arc<AppState>>, u: User, Query(q): Query<RareQuery>) -> ApiResult<Json<Value>> {
    u.need(Perm::SecurityRead)?;
    if let Some(c) = q.client_id {
        super::access::client(&u, c)?;
    }
    let rows: Vec<Value> = sqlx::query_scalar(
        "SELECT jsonb_build_object('sha256', encode(h.sha256, 'hex'), 'seen_on', count(*), 'first_seen', min(h.first_seen),
                                   'agents', jsonb_agg(jsonb_build_object('agent_id', a.id, 'hostname', a.hostname, 'client_name', c.name, 'path', h.path)
                                                       ORDER BY h.first_seen))
           FROM hash_sightings h JOIN agents a ON a.id = h.agent_id JOIN sites s ON s.id = a.site_id JOIN clients c ON c.id = s.client_id
          WHERE ($1::uuid[] IS NULL OR c.id = ANY($1)) AND ($4::uuid IS NULL OR c.id = $4)
            AND NOT EXISTS (SELECT 1 FROM reputation_hashes r WHERE r.sha256 = h.sha256)
          GROUP BY h.sha256
         HAVING count(*) <= $2 AND min(h.first_seen) > now() - make_interval(days => $3)
          ORDER BY min(h.first_seen) DESC LIMIT 500",
    )
    .bind(u.scope())
    .bind(q.max_agents.unwrap_or(1).max(1))
    .bind(q.days.unwrap_or(7).clamp(1, 365))
    .bind(q.client_id)
    .fetch_all(&st.db)
    .await?;
    Ok(Json(json!({ "items": rows })))
}

/// `GET /security/reputation`: what the server's set holds, by source.
pub async fn reputation_sources(State(st): State<Arc<AppState>>, u: User) -> ApiResult<Json<Value>> {
    u.need(Perm::SecurityRead)?;
    let rows: Vec<Value> = sqlx::query_scalar(
        "SELECT jsonb_build_object('source', source, 'hashes', count(*), 'added_at', max(added_at)) FROM reputation_hashes GROUP BY source ORDER BY source",
    )
    .fetch_all(&st.db)
    .await?;
    Ok(Json(json!({ "sources": rows })))
}

/// Largest server-only hash list, as text.
pub const REPUTATION_LIST_MAX: usize = 256 << 20;

#[derive(Deserialize)]
pub struct ListQuery {
    severity: Option<String>,
}

fn valid_list_name(n: &str) -> bool {
    !n.is_empty() && n.len() <= 64 && n.bytes().all(|b| b.is_ascii_alphanumeric() || b".-_".contains(&b))
}

/// `PUT /security/reputation/lists/{name}`: a hash list for the server's reputation set only,
/// as text (one SHA-256 per line, optionally a name after it). Agents don't download it: this
/// is how the server's set is bigger than the database agents carry. Replaces the list.
pub async fn put_reputation_list(State(st): State<Arc<AppState>>, u: User, Path(name): Path<String>, Query(q): Query<ListQuery>, body: String) -> ApiResult<Json<Value>> {
    u.need(Perm::SecurityManage)?;
    if u.scope().is_some() {
        return Err(ApiError::Forbidden);
    }
    if !valid_list_name(&name) {
        return Err(ApiError::BadRequest("list names are letters, digits, dots, dashes and underscores".into()));
    }
    let severity = match q.severity.as_deref().unwrap_or("high") {
        "severe" => rmm_proto::security::ThreatSeverity::Severe,
        "high" => rmm_proto::security::ThreatSeverity::High,
        "moderate" => rmm_proto::security::ThreatSeverity::Moderate,
        "low" => rmm_proto::security::ThreatSeverity::Low,
        _ => return Err(ApiError::BadRequest("severity is severe, high, moderate or low".into())),
    };
    let n = core::reputation_list(&st, &name, severity, &body).await.map_err(ApiError::BadRequest)?;
    auth::audit(&st.db, Some(u.id), "security.reputation_list", None, json!({ "name": name, "hashes": n })).await;
    Ok(Json(json!({ "name": name, "hashes": n })))
}

pub async fn delete_reputation_list(State(st): State<Arc<AppState>>, u: User, Path(name): Path<String>) -> ApiResult<Json<Value>> {
    u.need(Perm::SecurityManage)?;
    if u.scope().is_some() {
        return Err(ApiError::Forbidden);
    }
    let n = sqlx::query("DELETE FROM reputation_hashes WHERE source = $1").bind(format!("list:{name}")).execute(&st.db).await?.rows_affected();
    auth::audit(&st.db, Some(u.id), "security.reputation_list_delete", None, json!({ "name": name, "hashes": n })).await;
    Ok(Json(json!({ "ok": true, "hashes": n })))
}
