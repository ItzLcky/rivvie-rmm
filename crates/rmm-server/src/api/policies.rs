//! Policy sets, their items and overrides, device categories, assignments and pins
//! (docs/design/policies.md, docs/design/policies-api.md).
//!
//! Permissions: MSP-wide sets, items in them without a client limit, their overrides and the
//! categories are for admins; a client's sets, items limited to a client, overrides in a
//! client's set, a client's assignments, pins and category moves are for technicians with
//! access to that client. The `security` module also needs `security.manage`. Anyone may read,
//! limited to the clients they can see (MSP-wide sets are visible to all).

use std::collections::HashMap;
use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, Query, State};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::AssertSqlSafe;
use uuid::Uuid;

use crate::auth::{self, Perm, Role, User};
use crate::error::{ApiError, ApiResult};
use crate::paging::{self, Page, PageQuery, Plan, SortKey};
use crate::policy::{self, Change, Module};
use crate::state::AppState;

/// Who may change something owned by this client (None: MSP-wide, admins).
fn may_edit(u: &User, owner: Option<Uuid>) -> ApiResult<()> {
    super::scripts::may_edit(u, owner)
}

fn may_edit_module(u: &User, owner: Option<Uuid>, module: Module) -> ApiResult<()> {
    may_edit(u, owner)?;
    if module == Module::Security {
        u.need(Perm::SecurityManage)?;
    }
    Ok(())
}

fn clean_name(name: &str) -> ApiResult<String> {
    let n = name.trim();
    if n.is_empty() || n.chars().count() > 200 {
        return Err(ApiError::BadRequest("name must be 1-200 characters".into()));
    }
    Ok(n.to_string())
}

fn bad(e: String) -> ApiError {
    ApiError::BadRequest(e)
}

// ---------------------------------------------------------------------------
// Sets
// ---------------------------------------------------------------------------

#[derive(Serialize, sqlx::FromRow, Clone)]
pub struct SetRow {
    id: Uuid,
    parent_id: Option<Uuid>,
    /// None: MSP-wide.
    client_id: Option<Uuid>,
    client_name: Option<String>,
    name: String,
    description: String,
    builtin: bool,
    /// All devices is 0.
    #[sqlx(default)]
    depth: i32,
    /// Devices using it (of the clients the user can see).
    devices: i64,
    /// Items defined here, and overrides held here.
    items: i64,
    overrides: i64,
    /// Modules it defines items of, and modules it overrides.
    defines: Vec<String>,
    overrides_modules: Vec<String>,
    /// The device categories it's the default set of.
    default_for: Vec<Uuid>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

/// `$1` the user's scope.
const SET_SELECT: &str = "SELECT ps.id, ps.parent_id, ps.client_id, c.name AS client_name, ps.name, ps.description, ps.builtin,
       (SELECT count(*) FROM agents a JOIN sites s ON s.id = a.site_id
         WHERE a.policy_set_id = ps.id AND ($1::uuid[] IS NULL OR s.client_id = ANY($1))) AS devices,
       (SELECT count(*) FROM policy_items i WHERE i.set_id = ps.id AND ($1::uuid[] IS NULL OR i.client_id IS NULL OR i.client_id = ANY($1))) AS items,
       (SELECT count(*) FROM policy_overrides o JOIN policy_items i ON i.id = o.item_id
         WHERE o.set_id = ps.id AND ($1::uuid[] IS NULL OR i.client_id IS NULL OR i.client_id = ANY($1))) AS overrides,
       coalesce((SELECT array_agg(DISTINCT i.module) FROM policy_items i
                  WHERE i.set_id = ps.id AND ($1::uuid[] IS NULL OR i.client_id IS NULL OR i.client_id = ANY($1))), '{}') AS defines,
       coalesce((SELECT array_agg(DISTINCT i.module) FROM policy_overrides o JOIN policy_items i ON i.id = o.item_id
                  WHERE o.set_id = ps.id AND ($1::uuid[] IS NULL OR i.client_id IS NULL OR i.client_id = ANY($1))), '{}') AS overrides_modules,
       ARRAY(SELECT dc.id FROM device_categories dc WHERE dc.default_set_id = ps.id ORDER BY dc.name) AS default_for,
       ps.created_at, ps.updated_at
  FROM policy_sets ps LEFT JOIN clients c ON c.id = ps.client_id";
const SET_VISIBLE: &str = "($1::uuid[] IS NULL OR ps.client_id IS NULL OR ps.client_id = ANY($1))";

/// A set's place in the tree.
#[derive(Serialize, sqlx::FromRow, Clone)]
pub struct ChainEntry {
    id: Uuid,
    name: String,
    client_id: Option<Uuid>,
    builtin: bool,
}

/// From All devices down to this set.
async fn chain(db: &mut sqlx::PgConnection, set_id: Uuid) -> sqlx::Result<Vec<ChainEntry>> {
    sqlx::query_as(
        "WITH RECURSIVE up AS (
            SELECT id, parent_id, name, client_id, builtin, 0 AS lvl FROM policy_sets WHERE id = $1
            UNION ALL
            SELECT p.id, p.parent_id, p.name, p.client_id, p.builtin, up.lvl + 1 FROM policy_sets p JOIN up ON p.id = up.parent_id)
         SELECT id, name, client_id, builtin FROM up ORDER BY lvl DESC",
    )
    .bind(set_id)
    .fetch_all(db)
    .await
}

/// Levels below this set (0 for a leaf).
async fn height(db: &mut sqlx::PgConnection, set_id: Uuid) -> sqlx::Result<i32> {
    sqlx::query_scalar(
        "WITH RECURSIVE down AS (SELECT id, 0 AS lvl FROM policy_sets WHERE id = $1
                                 UNION ALL SELECT c.id, down.lvl + 1 FROM policy_sets c JOIN down ON c.parent_id = down.id)
         SELECT max(lvl)::int FROM down",
    )
    .bind(set_id)
    .fetch_one(db)
    .await
}

/// The set, if the user may see it.
async fn fetch_set(st: &AppState, u: &User, id: Uuid) -> ApiResult<SetRow> {
    let mut row: SetRow = sqlx::query_as(AssertSqlSafe(format!("{SET_SELECT} WHERE {SET_VISIBLE} AND ps.id = $2")))
        .bind(u.scope())
        .bind(id)
        .fetch_optional(&st.db)
        .await?
        .ok_or(ApiError::NotFound("policy set"))?;
    row.depth = chain(&mut *st.db.acquire().await?, id).await?.len() as i32 - 1;
    Ok(row)
}

#[derive(Deserialize)]
pub struct SetsQuery {
    /// Only sets this client's devices can use: MSP-wide ones and the client's own.
    client_id: Option<Uuid>,
}

pub async fn list_sets(State(st): State<Arc<AppState>>, u: User, Query(q): Query<SetsQuery>) -> ApiResult<Json<Vec<SetRow>>> {
    if let Some(c) = q.client_id {
        super::access::client(&u, c)?;
    }
    let mut rows: Vec<SetRow> = sqlx::query_as(AssertSqlSafe(format!(
        "{SET_SELECT} WHERE {SET_VISIBLE} AND ($2::uuid IS NULL OR ps.client_id IS NULL OR ps.client_id = $2)
          ORDER BY ps.builtin DESC, ps.client_id IS NOT NULL, lower(ps.name)"
    )))
    .bind(u.scope())
    .bind(q.client_id)
    .fetch_all(&st.db)
    .await?;
    let parents: HashMap<Uuid, Option<Uuid>> = rows.iter().map(|r| (r.id, r.parent_id)).collect();
    for r in &mut rows {
        let (mut d, mut at) = (0, r.parent_id);
        while let Some(p) = at {
            d += 1;
            at = parents.get(&p).copied().flatten();
        }
        r.depth = d;
    }
    Ok(Json(rows))
}

#[derive(Serialize)]
pub struct SetDetail {
    #[serde(flatten)]
    set: SetRow,
    /// All devices down to this set.
    chain: Vec<ChainEntry>,
    children: Vec<SetRow>,
    /// Every item reaching this set, as it applies here.
    policies: Vec<ItemView>,
    /// The user may edit the set itself (rename, describe, move, delete, add items).
    editable: bool,
}

pub async fn get_set(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<SetDetail>> {
    let set = fetch_set(&st, &u, id).await?;
    let mut db = st.db.acquire().await?;
    let chain = chain(&mut db, id).await?;
    let mut children: Vec<SetRow> = sqlx::query_as(AssertSqlSafe(format!(
        "{SET_SELECT} WHERE {SET_VISIBLE} AND ps.parent_id = $2 ORDER BY ps.builtin DESC, lower(ps.name)"
    )))
    .bind(u.scope())
    .bind(id)
    .fetch_all(&mut *db)
    .await?;
    for c in &mut children {
        c.depth = set.depth + 1;
    }
    let policies = item_views(&st, &u, &chain, None).await?;
    let editable = may_edit(&u, set.client_id).is_ok();
    Ok(Json(SetDetail { set, chain, children, policies, editable }))
}

#[derive(Deserialize)]
pub struct NewSet {
    name: String,
    #[serde(default)]
    description: String,
    parent_id: Uuid,
    /// A client's own set. Children of a client's set always belong to that client.
    client_id: Option<Uuid>,
}

fn clean_description(d: &str) -> ApiResult<String> {
    let d = d.trim();
    if d.chars().count() > 2000 {
        return Err(ApiError::BadRequest("description must be at most 2000 characters".into()));
    }
    Ok(d.to_string())
}

/// The owner a child of `parent` gets when `asked` is what the request said.
fn child_owner(parent: &SetRow, asked: Option<Uuid>) -> ApiResult<Option<Uuid>> {
    match (parent.client_id, asked) {
        (Some(p), Some(a)) if p != a => Err(bad("a client's set can only have that client's sets below it".into())),
        (Some(p), _) => Ok(Some(p)),
        (None, a) => Ok(a),
    }
}

pub async fn create_set(State(st): State<Arc<AppState>>, u: User, Json(b): Json<NewSet>) -> ApiResult<Json<SetRow>> {
    let name = clean_name(&b.name)?;
    let description = clean_description(&b.description)?;
    let parent = fetch_set(&st, &u, b.parent_id).await?;
    let owner = child_owner(&parent, b.client_id)?;
    if let Some(c) = owner {
        super::access::client(&u, c)?;
        let exists: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM clients WHERE id = $1)").bind(c).fetch_one(&st.db).await?;
        if !exists {
            return Err(ApiError::NotFound("client"));
        }
    }
    may_edit(&u, owner)?;
    if parent.depth + 1 > policy::MAX_DEPTH {
        return Err(bad(format!("policy sets go at most {} levels deep", policy::MAX_DEPTH)));
    }
    let id = Uuid::new_v4();
    let mut tx = st.db.begin().await?;
    policy::lock(&mut tx).await?;
    sqlx::query("INSERT INTO policy_sets (id, parent_id, client_id, name, description, created_by) VALUES ($1, $2, $3, $4, $5, $6)")
        .bind(id)
        .bind(parent.id)
        .bind(owner)
        .bind(&name)
        .bind(&description)
        .bind(u.id)
        .execute(&mut *tx)
        .await?;
    let reaching: Vec<Uuid> = sqlx::query_scalar("SELECT item_id FROM policy_effective WHERE set_id = $1").bind(parent.id).fetch_all(&mut *tx).await?;
    policy::rebuild(&mut tx, Some(&reaching)).await?;
    tx.commit().await?;
    auth::audit(&st.db, Some(u.id), "policy_set.create", Some(("policy_set", id)), json!({ "name": name, "parent_id": parent.id, "client_id": owner }))
        .await;
    Ok(Json(fetch_set(&st, &u, id).await?))
}

#[derive(Deserialize)]
pub struct SetUpdate {
    name: Option<String>,
    description: Option<String>,
    /// Moves it (and everything below it). Built-in sets can't move.
    parent_id: Option<Uuid>,
}

pub async fn update_set(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>, Json(b): Json<SetUpdate>) -> ApiResult<Json<SetRow>> {
    let set = fetch_set(&st, &u, id).await?;
    may_edit(&u, set.client_id)?;
    let name = b.name.as_deref().map(clean_name).transpose()?;
    let description = b.description.as_deref().map(clean_description).transpose()?;
    let new_parent = b.parent_id.filter(|p| Some(*p) != set.parent_id);
    let mut tx = st.db.begin().await?;
    policy::lock(&mut tx).await?;
    let mut change = None;
    if let Some(p) = new_parent {
        if set.builtin {
            return Err(bad("built-in sets can't be moved".into()));
        }
        let parent = fetch_set(&st, &u, p).await?;
        if child_owner(&parent, set.client_id)? != set.client_id {
            return Err(bad("an MSP-wide set can only sit below MSP-wide sets".into()));
        }
        if chain(&mut tx, p).await?.iter().any(|c| c.id == id) {
            return Err(bad("a set can't move below itself".into()));
        }
        if parent.depth + 1 + height(&mut tx, id).await? > policy::MAX_DEPTH {
            return Err(bad(format!("policy sets go at most {} levels deep", policy::MAX_DEPTH)));
        }
        let before = policy::agents_under(&mut tx, id).await?;
        sqlx::query("UPDATE policy_sets SET parent_id = $2, updated_at = now() WHERE id = $1").bind(id).bind(p).execute(&mut *tx).await?;
        policy::rebuild(&mut tx, None).await?;
        // Overrides of items that no longer reach their set mean nothing now.
        sqlx::query(
            "DELETE FROM policy_overrides o WHERE NOT EXISTS (SELECT 1 FROM policy_effective e WHERE e.item_id = o.item_id AND e.set_id = o.set_id)",
        )
        .execute(&mut *tx)
        .await?;
        let items: Vec<Uuid> = sqlx::query_scalar("SELECT item_id FROM policy_effective WHERE set_id = $1").bind(id).fetch_all(&mut *tx).await?;
        policy::validate_effective(&mut tx, &items).await?.map_err(bad)?;
        let alert_items: Vec<Uuid> =
            sqlx::query_scalar("SELECT id FROM policy_items WHERE id = ANY($1) AND module = 'alert'").bind(&items).fetch_all(&mut *tx).await?;
        change = Some(Change { items: alert_items, agents: Some(before) });
    }
    sqlx::query("UPDATE policy_sets SET name = coalesce($2, name), description = coalesce($3, description), updated_at = now() WHERE id = $1")
        .bind(id)
        .bind(&name)
        .bind(&description)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    auth::audit(
        &st.db,
        Some(u.id),
        "policy_set.update",
        Some(("policy_set", id)),
        json!({ "name": name, "description": description.is_some(), "parent_id": new_parent }),
    )
    .await;
    if let Some(ch) = change {
        policy::changed(&st, ch).await;
    }
    Ok(Json(fetch_set(&st, &u, id).await?))
}

pub async fn delete_set(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    let set = fetch_set(&st, &u, id).await?;
    if set.builtin {
        return Err(bad("built-in sets can't be deleted".into()));
    }
    may_edit(&u, set.client_id)?;
    let mut tx = st.db.begin().await?;
    policy::lock(&mut tx).await?;
    let (children, assignments, pins, defaults): (i64, i64, i64, Vec<String>) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM policy_sets WHERE parent_id = $1),
                (SELECT count(*) FROM policy_assignments WHERE policy_set_id = $1),
                (SELECT count(*) FROM agents WHERE policy_pin_id = $1),
                ARRAY(SELECT name FROM device_categories WHERE default_set_id = $1 ORDER BY name)",
    )
    .bind(id)
    .fetch_one(&mut *tx)
    .await?;
    let mut uses = Vec::new();
    let n = |k: i64, one: &str, many: &str| format!("{k} {}", if k == 1 { one } else { many });
    if children > 0 {
        uses.push(n(children, "child set", "child sets"));
    }
    if assignments > 0 {
        uses.push(n(assignments, "assignment", "assignments"));
    }
    if pins > 0 {
        uses.push(n(pins, "pinned device", "pinned devices"));
    }
    if !defaults.is_empty() {
        uses.push(format!("the default of {}", defaults.join(", ")));
    }
    if !uses.is_empty() {
        return Err(ApiError::Conflict(format!("{} is still used by {}", set.name, uses.join(", "))));
    }
    sqlx::query("DELETE FROM policy_sets WHERE id = $1").bind(id).execute(&mut *tx).await?;
    tx.commit().await?;
    // Its items went with it; their open alerts (now without a policy) close quietly.
    crate::alerts::close_inapplicable(&st).await;
    auth::audit(&st.db, Some(u.id), "policy_set.delete", Some(("policy_set", id)), json!({ "name": set.name })).await;
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize, Default)]
pub struct Duplicate {
    name: Option<String>,
    /// Copy an MSP-wide set as this client's own.
    client_id: Option<Uuid>,
}

/// Copies a set beside itself (same parent): its own items (new ids) and its overrides, not
/// the sets below it.
pub async fn duplicate_set(
    State(st): State<Arc<AppState>>,
    u: User,
    Path(id): Path<Uuid>,
    body: Option<Json<Duplicate>>,
) -> ApiResult<Json<SetRow>> {
    let b = body.map(|Json(b)| b).unwrap_or_default();
    let set = fetch_set(&st, &u, id).await?;
    let Some(parent_id) = set.parent_id.filter(|_| id != policy::ROOT) else { return Err(bad("All devices can't be duplicated".into())) };
    let owner = match (set.client_id, b.client_id) {
        (Some(c), Some(a)) if c != a => return Err(bad("a client's set can only be copied for the same client".into())),
        (Some(c), _) => Some(c),
        (None, a) => a,
    };
    if let Some(c) = owner {
        super::access::client(&u, c)?;
    }
    may_edit(&u, owner)?;
    let name = clean_name(b.name.as_deref().unwrap_or(&format!("Copy of {}", set.name)))?;
    let id2 = Uuid::new_v4();
    let mut tx = st.db.begin().await?;
    policy::lock(&mut tx).await?;
    sqlx::query(
        "INSERT INTO policy_sets (id, parent_id, client_id, name, description, created_by)
         SELECT $2, parent_id, $3, $4, description, $5 FROM policy_sets WHERE id = $1",
    )
    .bind(id)
    .bind(id2)
    .bind(owner)
    .bind(&name)
    .bind(u.id)
    .execute(&mut *tx)
    .await?;
    // Its own items; a client's copy limits them to the client.
    let foreign: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM policy_items WHERE set_id = $1 AND client_id IS NOT NULL AND client_id IS DISTINCT FROM $2)")
        .bind(id)
        .bind(owner)
        .fetch_one(&mut *tx)
        .await?;
    if owner.is_some() && foreign {
        return Err(bad("the set has policies limited to another client".into()));
    }
    let copied: Vec<(Uuid, String, Value)> = sqlx::query_as(
        "INSERT INTO policy_items (id, set_id, module, name, enabled, config, client_id, site_id, excluded_agents, created_by)
         SELECT gen_random_uuid(), $2, module, name, enabled, config, coalesce($3, client_id), site_id, excluded_agents, $4
           FROM policy_items WHERE set_id = $1
         RETURNING id, module, config",
    )
    .bind(id)
    .bind(id2)
    .bind(owner)
    .bind(u.id)
    .fetch_all(&mut *tx)
    .await?;
    for (item, module, config) in &copied {
        if module == "schedule" {
            schedule_state(&mut tx, *item, config).await?;
        }
    }
    sqlx::query(
        "INSERT INTO policy_overrides (item_id, set_id, enabled, config, updated_by)
         SELECT item_id, $2, enabled, config, $3 FROM policy_overrides WHERE set_id = $1",
    )
    .bind(id)
    .bind(id2)
    .bind(u.id)
    .execute(&mut *tx)
    .await?;
    let reaching: Vec<Uuid> = sqlx::query_scalar("SELECT item_id FROM policy_effective WHERE set_id = $1").bind(parent_id).fetch_all(&mut *tx).await?;
    let all: Vec<Uuid> = reaching.into_iter().chain(copied.iter().map(|c| c.0)).collect();
    policy::rebuild(&mut tx, Some(&all)).await?;
    tx.commit().await?;
    auth::audit(&st.db, Some(u.id), "policy_set.duplicate", Some(("policy_set", id2)), json!({ "from": id, "name": name, "client_id": owner })).await;
    Ok(Json(fetch_set(&st, &u, id2).await?))
}

#[derive(Serialize, sqlx::FromRow)]
pub struct SetAgent {
    id: Uuid,
    hostname: String,
    online: bool,
    os_family: String,
    platform: String,
    client_id: Uuid,
    client_name: String,
    site_id: Uuid,
    site_name: String,
    category_id: Uuid,
    category_name: String,
    /// Why it uses this set: pin, site, client or default.
    reason: String,
    #[sqlx(default)]
    #[serde(skip)]
    sort_key: String,
}

const SET_AGENT_SORT: &[SortKey] = &[
    SortKey { name: "hostname", expr: "lower(a.hostname)", ty: "text" },
    SortKey { name: "client", expr: "lower(c.name || ' / ' || s.name || ' / ' || a.hostname)", ty: "text" },
];

/// The devices using the set.
pub async fn set_agents(
    State(st): State<Arc<AppState>>,
    u: User,
    Path(id): Path<Uuid>,
    Query(page): Query<PageQuery>,
) -> ApiResult<Json<Page<SetAgent>>> {
    fetch_set(&st, &u, id).await?;
    let plan = Plan::new(SET_AGENT_SORT, ("hostname", false), &page, "a.id", "uuid", 3)?;
    let filters = "FROM agents a JOIN sites s ON s.id = a.site_id JOIN clients c ON c.id = s.client_id
                   JOIN device_categories dc ON dc.id = a.category_id
                  WHERE a.policy_set_id = $1 AND ($2::uuid[] IS NULL OR c.id = ANY($2))";
    let cols = format!("a.id, a.hostname, a.online, a.os_family, a.platform, c.id AS client_id, c.name AS client_name, s.id AS site_id,
                        s.name AS site_name, a.category_id, dc.name AS category_name, {REASON} AS reason");
    let sql = format!("SELECT {cols}, {} {filters} {} {} {}", plan.key_select, plan.keyset, plan.order, plan.limit_sql());
    let mut q = sqlx::query_as::<_, SetAgent>(AssertSqlSafe(sql)).bind(id).bind(u.scope());
    if let Some((k, cur)) = &plan.cursor {
        q = q.bind(k).bind(cur);
    }
    let rows = q.fetch_all(&st.db).await?;
    let total: i64 = sqlx::query_scalar(AssertSqlSafe(paging::count_sql(filters))).bind(id).bind(u.scope()).fetch_one(&st.db).await?;
    Ok(Json(plan.finish(rows, |r| (r.sort_key.clone(), r.id.to_string()), total)))
}

/// Why agent `a` (site `s`) uses the set it uses.
const REASON: &str = "(CASE WHEN a.policy_pin_id IS NOT NULL THEN 'pin'
       WHEN EXISTS (SELECT 1 FROM policy_assignments pa WHERE pa.site_id = a.site_id AND pa.category_id = a.category_id) THEN 'site'
       WHEN EXISTS (SELECT 1 FROM policy_assignments pa WHERE pa.client_id = s.client_id AND pa.site_id IS NULL AND pa.category_id = a.category_id) THEN 'client'
       ELSE 'default' END)";

// ---------------------------------------------------------------------------
// Items as they apply to a set
// ---------------------------------------------------------------------------

#[derive(Serialize, Clone)]
pub struct Limit {
    client_id: Option<Uuid>,
    client_name: Option<String>,
    site_id: Option<Uuid>,
    site_name: Option<String>,
    /// `[{id, hostname}]`, of the agents the user can see.
    excluded: Value,
}

#[derive(Serialize, Clone)]
pub struct OverrideView {
    /// None: as inherited.
    enabled: Option<bool>,
    /// Only the fields that differ.
    config: Value,
    updated_at: DateTime<Utc>,
}

#[derive(Serialize, Clone)]
pub struct ScheduleState {
    next_run_at: Option<DateTime<Utc>>,
    last_run_at: Option<DateTime<Utc>>,
}

/// One item as it applies in one set.
#[derive(Serialize, Clone)]
pub struct ItemView {
    id: Uuid,
    module: Module,
    name: String,
    /// Where it's defined.
    origin_set_id: Uuid,
    origin_set_name: String,
    /// `defined` (here), `inherited` or `overridden` (here).
    status: &'static str,
    /// Merged, as it applies in this set.
    enabled: bool,
    config: Value,
    /// As defined at its origin.
    item_enabled: bool,
    item_config: Value,
    /// The set each field's value comes from, by dotted path (`params.threshold`), plus `enabled`.
    sources: std::collections::BTreeMap<String, Uuid>,
    /// This set's override, if any.
    #[serde(rename = "override")]
    override_: Option<OverrideView>,
    limit: Limit,
    /// The user may edit the item at its origin, and may override it here.
    editable: bool,
    overridable: bool,
    /// Unresolved alerts it raised (alerts; in the agent view, on that agent).
    open_alerts: i64,
    schedule: Option<ScheduleState>,
    /// Automations: how many runs are in each state (`waiting`, `pending`, `succeeded`, `failed`,
    /// `skipped`), on the agents the user can see (in the agent view, on that agent).
    runs: Option<Value>,
    /// Agent view only: the limit includes the agent.
    #[serde(skip_serializing_if = "Option::is_none")]
    applies: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    excluded: Option<bool>,
}

#[derive(sqlx::FromRow)]
struct ItemRow {
    id: Uuid,
    set_id: Uuid,
    module: String,
    name: String,
    enabled: bool,
    config: Value,
    client_id: Option<Uuid>,
    client_name: Option<String>,
    site_id: Option<Uuid>,
    site_name: Option<String>,
    excluded: Value,
    excluded_agents: Vec<Uuid>,
    eff_enabled: bool,
    eff_config: Value,
    open_alerts: i64,
    next_run_at: Option<DateTime<Utc>>,
    last_run_at: Option<DateTime<Utc>>,
    runs: Option<Value>,
}

/// (item, set, enabled, config, updated_at)
type OverrideRow = (Uuid, Uuid, Option<bool>, Value, DateTime<Utc>);

/// Every item reaching the last set of `chain`, as it applies there. `agent`: count alerts on
/// that agent only, and say whether its limit includes the agent.
async fn item_views(st: &AppState, u: &User, chain: &[ChainEntry], agent: Option<(Uuid, Uuid, Uuid)>) -> ApiResult<Vec<ItemView>> {
    let Some(here) = chain.last() else { return Ok(vec![]) };
    let rows: Vec<ItemRow> = sqlx::query_as(
        "SELECT i.id, i.set_id, i.module, i.name, i.enabled, i.config, i.client_id, c.name AS client_name, i.site_id, si.name AS site_name,
                (SELECT coalesce(jsonb_agg(jsonb_build_object('id', xa.id, 'hostname', xa.hostname) ORDER BY lower(xa.hostname)), '[]')
                   FROM agents xa JOIN sites xs ON xs.id = xa.site_id
                  WHERE xa.id = ANY(i.excluded_agents) AND ($2::uuid[] IS NULL OR xs.client_id = ANY($2))) AS excluded,
                i.excluded_agents, e.enabled AS eff_enabled, e.config AS eff_config,
                (SELECT count(*) FROM alerts al JOIN agents aa ON aa.id = al.agent_id JOIN sites sa ON sa.id = aa.site_id
                  WHERE al.policy_id = i.id AND al.resolved_at IS NULL AND ($2::uuid[] IS NULL OR sa.client_id = ANY($2))
                    AND ($3::uuid IS NULL OR al.agent_id = $3)) AS open_alerts,
                ss.next_run_at, ss.last_run_at,
                CASE WHEN i.module = 'automation' THEN (
                    SELECT jsonb_build_object('waiting', count(*) FILTER (WHERE r.status = 'waiting'), 'pending', count(*) FILTER (WHERE r.status = 'pending'),
                                              'succeeded', count(*) FILTER (WHERE r.status = 'succeeded'), 'failed', count(*) FILTER (WHERE r.status = 'failed'),
                                              'skipped', count(*) FILTER (WHERE r.status = 'skipped'))
                      FROM automation_runs r JOIN agents ra ON ra.id = r.agent_id JOIN sites rs ON rs.id = ra.site_id
                     WHERE r.item_id = i.id AND ($2::uuid[] IS NULL OR rs.client_id = ANY($2)) AND ($3::uuid IS NULL OR r.agent_id = $3)) END AS runs
           FROM policy_effective e JOIN policy_items i ON i.id = e.item_id
           LEFT JOIN clients c ON c.id = i.client_id LEFT JOIN sites si ON si.id = i.site_id
           LEFT JOIN policy_schedule_state ss ON ss.item_id = i.id
          WHERE e.set_id = $1 AND ($2::uuid[] IS NULL OR i.client_id IS NULL OR i.client_id = ANY($2))
          ORDER BY array_position(ARRAY['alert', 'schedule', 'patch', 'security', 'remote_access', 'agent', 'automation'], i.module), lower(i.name)",
    )
    .bind(here.id)
    .bind(u.scope())
    .bind(agent.map(|a| a.0))
    .fetch_all(&st.db)
    .await?;
    let ids: Vec<Uuid> = rows.iter().map(|r| r.id).collect();
    let chain_ids: Vec<Uuid> = chain.iter().map(|c| c.id).collect();
    let overrides: Vec<OverrideRow> = sqlx::query_as(
        "SELECT item_id, set_id, enabled, config, updated_at FROM policy_overrides WHERE item_id = ANY($1) AND set_id = ANY($2)",
    )
    .bind(&ids)
    .bind(&chain_ids)
    .fetch_all(&st.db)
    .await?;
    let pos = |set: Uuid| chain_ids.iter().position(|c| *c == set).unwrap_or(0);
    let names: HashMap<Uuid, &str> = chain.iter().map(|c| (c.id, c.name.as_str())).collect();
    let mut out = Vec::with_capacity(rows.len());
    for r in rows {
        let Some(module) = Module::parse(&r.module) else { continue };
        let mut mine: Vec<&OverrideRow> = overrides.iter().filter(|o| o.0 == r.id).collect();
        mine.sort_by_key(|o| pos(o.1));
        let chain_overrides: Vec<(Uuid, &Value)> = mine.iter().map(|o| (o.1, &o.3)).collect();
        let mut sources = policy::field_sources(r.set_id, &r.config, &chain_overrides);
        let enabled_from = mine.iter().rev().find(|o| o.2.is_some()).map(|o| o.1).unwrap_or(r.set_id);
        sources.insert("enabled".into(), enabled_from);
        let here_override = mine.iter().find(|o| o.1 == here.id).map(|o| OverrideView { enabled: o.2, config: o.3.clone(), updated_at: o.4 });
        let status = if r.set_id == here.id {
            "defined"
        } else if here_override.is_some() {
            "overridden"
        } else {
            "inherited"
        };
        let applies = agent.map(|(a, client, site)| {
            r.client_id.is_none_or(|c| c == client) && r.site_id.is_none_or(|s| s == site) && !r.excluded_agents.contains(&a)
        });
        let excluded = agent.map(|(a, _, _)| r.excluded_agents.contains(&a));
        out.push(ItemView {
            id: r.id,
            module,
            origin_set_name: names.get(&r.set_id).map(|n| n.to_string()).unwrap_or_default(),
            origin_set_id: r.set_id,
            name: r.name,
            status,
            enabled: r.eff_enabled,
            config: r.eff_config,
            item_enabled: r.enabled,
            item_config: r.config,
            sources,
            override_: here_override,
            limit: Limit { client_id: r.client_id, client_name: r.client_name, site_id: r.site_id, site_name: r.site_name, excluded: r.excluded },
            editable: may_edit_module(u, r.client_id, module).is_ok(),
            overridable: r.set_id != here.id && may_edit_module(u, here.client_id, module).is_ok(),
            open_alerts: r.open_alerts,
            schedule: (module == Module::Schedule).then_some(ScheduleState { next_run_at: r.next_run_at, last_run_at: r.last_run_at }),
            runs: r.runs,
            applies,
            excluded,
        });
    }
    Ok(out)
}

/// One item as it applies in one set (which it must reach).
async fn item_view(st: &AppState, u: &User, item: Uuid, set: Uuid) -> ApiResult<ItemView> {
    let chain = chain(&mut *st.db.acquire().await?, set).await?;
    item_views(st, u, &chain, None).await?.into_iter().find(|v| v.id == item).ok_or(ApiError::NotFound("policy"))
}

// ---------------------------------------------------------------------------
// Items
// ---------------------------------------------------------------------------

/// An item's identity, if the user may see it.
#[derive(sqlx::FromRow)]
pub(crate) struct ItemMeta {
    pub(crate) id: Uuid,
    set_id: Uuid,
    set_client_id: Option<Uuid>,
    pub(crate) module: String,
    pub(crate) name: String,
    enabled: bool,
    pub(crate) config: Value,
    client_id: Option<Uuid>,
    site_id: Option<Uuid>,
}

impl ItemMeta {
    fn module(&self) -> Module {
        Module::parse(&self.module).unwrap_or(Module::Alert)
    }
}

/// The item, if the user may see it.
pub(crate) async fn fetch_item(st: &AppState, u: &User, id: Uuid) -> ApiResult<ItemMeta> {
    let m: ItemMeta = sqlx::query_as(
        "SELECT i.id, i.set_id, ps.client_id AS set_client_id, i.module, i.name, i.enabled, i.config, i.client_id, i.site_id
           FROM policy_items i JOIN policy_sets ps ON ps.id = i.set_id WHERE i.id = $1",
    )
    .bind(id)
    .fetch_optional(&st.db)
    .await?
    .ok_or(ApiError::NotFound("policy"))?;
    let visible = |c: Option<Uuid>| c.is_none_or(|c| u.can_see_client(c));
    if !visible(m.client_id) || !visible(m.set_client_id) {
        return Err(ApiError::NotFound("policy"));
    }
    Ok(m)
}

/// The user may edit this item at its origin (and run it, for schedules).
pub(crate) async fn may_edit_item(st: &AppState, u: &User, id: Uuid) -> ApiResult<()> {
    let m = fetch_item(st, u, id).await?;
    may_edit_module(u, m.client_id, m.module())
}

/// What a config refers to exists, and the user may use it: channels, boards, scripts. A
/// client's own script can only be used by something owned by (limited to) that client.
async fn check_refs(st: &AppState, u: &User, module: Module, config: &Value, owner: Option<Uuid>) -> ApiResult<()> {
    let script_ok = |sid: Uuid| async move {
        let script_client: Option<Option<Uuid>> =
            sqlx::query_scalar("SELECT client_id FROM scripts WHERE id = $1").bind(sid).fetch_optional(&st.db).await?;
        match script_client {
            None => Err(ApiError::NotFound("script")),
            Some(Some(c)) if !u.can_see_client(c) => Err(ApiError::NotFound("script")),
            Some(Some(c)) if owner != Some(c) => Err(bad("that script belongs to another client".into())),
            _ => Ok(()),
        }
    };
    let uuid = |v: Option<&Value>| v.and_then(Value::as_str).and_then(|s| Uuid::parse_str(s).ok());
    match module {
        Module::Alert => {
            if let Some(ids) = config.get("channel_ids").and_then(Value::as_array) {
                let ids: Vec<Uuid> = ids.iter().filter_map(|v| v.as_str().and_then(|s| Uuid::parse_str(s).ok())).collect();
                let known: i64 = sqlx::query_scalar("SELECT count(*) FROM notification_channels WHERE id = ANY($1)").bind(&ids).fetch_one(&st.db).await?;
                if known as usize != ids.iter().collect::<std::collections::HashSet<_>>().len() {
                    return Err(bad("unknown notification channel".into()));
                }
            }
            if let Some(b) = uuid(config.get("ticket_board_id")) {
                let exists: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM boards WHERE id = $1)").bind(b).fetch_one(&st.db).await?;
                if !exists {
                    return Err(ApiError::NotFound("board"));
                }
            }
            if let Some(s) = uuid(config.get("run_script_id")) {
                script_ok(s).await?;
            }
            if let Some(s) = uuid(config.get("params").and_then(|p| p.get("script_id"))) {
                script_ok(s).await?;
            }
        }
        Module::Schedule => {
            if let Some(s) = uuid(config.get("script_id")) {
                script_ok(s).await?;
            }
        }
        Module::Automation => {
            if let Some(s) = uuid(config.get("script_id")) {
                script_ok(s).await?;
            }
            if let Some(t) = uuid(config.get("tag_id")) {
                let exists: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM tags WHERE id = $1)").bind(t).fetch_one(&st.db).await?;
                if !exists {
                    return Err(ApiError::NotFound("tag"));
                }
            }
            if let Some(f) = uuid(config.get("field_id")) {
                let def: Option<(String, Option<Uuid>, String, Vec<String>)> =
                    sqlx::query_as("SELECT entity, client_id, kind, options FROM custom_fields WHERE id = $1").bind(f).fetch_optional(&st.db).await?;
                let Some((entity, field_client, kind, options)) = def else { return Err(ApiError::NotFound("custom field")) };
                if entity != "agent" {
                    return Err(bad("an automation can only watch a custom field of devices".into()));
                }
                // A client's own field only exists for that client's devices.
                match field_client {
                    Some(c) if !u.can_see_client(c) => return Err(ApiError::NotFound("custom field")),
                    Some(c) if owner != Some(c) => return Err(bad("that field belongs to another client".into())),
                    _ => {}
                }
                if let Some(v) = config.get("field_value").and_then(Value::as_str)
                    && !matches!(crate::fields::coerce(&kind, &options, &Value::String(v.to_string())), Ok(Some(_)))
                {
                    return Err(bad("field_value isn't a value that field can hold".into()));
                }
            }
        }
        Module::Software => {
            // A client's own package can only be required of that client's devices.
            if let Some(p) = uuid(config.get("package_id")) {
                let pkg_client: Option<Option<Uuid>> =
                    sqlx::query_scalar("SELECT client_id FROM software_packages WHERE id = $1").bind(p).fetch_optional(&st.db).await?;
                match pkg_client {
                    None => return Err(ApiError::NotFound("software package")),
                    Some(Some(c)) if !u.can_see_client(c) => return Err(ApiError::NotFound("software package")),
                    Some(Some(c)) if owner != Some(c) => return Err(bad("that package belongs to another client".into())),
                    _ => {}
                }
            }
        }
        _ => {}
    }
    Ok(())
}

/// The limit of an item in `set` (owner `set_client`): a client's set limits to its client.
async fn check_limit(st: &AppState, u: &User, set_client: Option<Uuid>, client_id: Option<Uuid>, site_id: Option<Uuid>) -> ApiResult<Option<Uuid>> {
    let client = match (set_client, client_id) {
        (Some(s), Some(c)) if s != c => return Err(bad("a client's set can only hold policies for that client".into())),
        (Some(s), _) => Some(s),
        (None, c) => c,
    };
    if let Some(site) = site_id {
        let site_client = super::access::site(st, u, site).await?;
        if Some(site_client) != client {
            return Err(bad("the site must belong to the chosen client".into()));
        }
    }
    if let Some(c) = client {
        super::access::client(u, c)?;
        let exists: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM clients WHERE id = $1)").bind(c).fetch_one(&st.db).await?;
        if !exists {
            return Err(ApiError::NotFound("client"));
        }
    }
    Ok(client)
}

/// A schedule's next run, from its config (none if the cron no longer parses).
async fn schedule_state(db: &mut sqlx::PgConnection, item: Uuid, config: &Value) -> sqlx::Result<()> {
    let next = serde_json::from_value::<policy::ScheduleConfig>(config.clone())
        .ok()
        .and_then(|c| crate::scheduler::next_run(&c.cron, &c.timezone, Utc::now()).ok());
    sqlx::query(
        "INSERT INTO policy_schedule_state (item_id, next_run_at) VALUES ($1, $2)
         ON CONFLICT (item_id) DO UPDATE SET next_run_at = EXCLUDED.next_run_at",
    )
    .bind(item)
    .bind(next)
    .execute(db)
    .await?;
    Ok(())
}

#[derive(Deserialize)]
pub struct NewItem {
    /// `alert`, `schedule`, `software` or `automation` (the others live once, in All devices).
    module: String,
    name: String,
    #[serde(default = "yes")]
    enabled: bool,
    config: Value,
    client_id: Option<Uuid>,
    site_id: Option<Uuid>,
}

fn yes() -> bool {
    true
}

fn change_for(module: Module, item: Uuid, agents: Vec<Uuid>) -> Change {
    Change { items: if module == Module::Alert { vec![item] } else { vec![] }, agents: Some(agents) }
}

pub async fn create_item(State(st): State<Arc<AppState>>, u: User, Path(set_id): Path<Uuid>, Json(b): Json<NewItem>) -> ApiResult<Json<ItemView>> {
    let set = fetch_set(&st, &u, set_id).await?;
    let module = Module::parse(&b.module).ok_or_else(|| bad(format!("unknown module {}", b.module)))?;
    if module.single() {
        return Err(bad(format!("the {} policy exists once, in All devices; override it here instead", module.as_str())));
    }
    let name = clean_name(&b.name)?;
    let client = check_limit(&st, &u, set.client_id, b.client_id, b.site_id).await?;
    may_edit_module(&u, client, module)?;
    let config = policy::validate(module, &b.config).map_err(bad)?;
    check_refs(&st, &u, module, &config, client).await?;
    let id = Uuid::new_v4();
    let mut tx = st.db.begin().await?;
    policy::lock(&mut tx).await?;
    sqlx::query(
        "INSERT INTO policy_items (id, set_id, module, name, enabled, config, client_id, site_id, created_by)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
    )
    .bind(id)
    .bind(set_id)
    .bind(module.as_str())
    .bind(&name)
    .bind(b.enabled)
    .bind(&config)
    .bind(client)
    .bind(b.site_id)
    .bind(u.id)
    .execute(&mut *tx)
    .await?;
    if module == Module::Schedule {
        schedule_state(&mut tx, id, &config).await?;
    }
    policy::rebuild(&mut tx, Some(&[id])).await?;
    let agents = policy::agents_reached(&mut tx, &[id]).await?;
    tx.commit().await?;
    auth::audit(
        &st.db,
        Some(u.id),
        "policy.create",
        Some(("policy", id)),
        json!({ "name": name, "module": module.as_str(), "set_id": set_id, "kind": config.get("kind") }),
    )
    .await;
    policy::changed(&st, change_for(module, id, agents)).await;
    Ok(Json(item_view(&st, &u, id, set_id).await?))
}

/// One item as defined at its origin set (links from alerts, which know only the item).
pub async fn get_item(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<ItemView>> {
    let m = fetch_item(&st, &u, id).await?;
    Ok(Json(item_view(&st, &u, id, m.set_id).await?))
}

#[derive(Deserialize)]
pub struct ItemUpdate {
    name: Option<String>,
    enabled: Option<bool>,
    /// The whole config at the origin (omitted: unchanged).
    config: Option<Value>,
    /// The limit (alerts and schedules). Omitted: unchanged; null: none.
    #[serde(default, with = "double_option")]
    client_id: Option<Option<Uuid>>,
    #[serde(default, with = "double_option")]
    site_id: Option<Option<Uuid>>,
}

/// Tells an omitted field (outer None) from an explicit null (Some(None)).
mod double_option {
    use serde::{Deserialize, Deserializer};

    pub fn deserialize<'de, D: Deserializer<'de>, T: Deserialize<'de>>(d: D) -> Result<Option<Option<T>>, D::Error> {
        Option::<T>::deserialize(d).map(Some)
    }
}

pub async fn update_item(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>, Json(b): Json<ItemUpdate>) -> ApiResult<Json<ItemView>> {
    let cur = fetch_item(&st, &u, id).await?;
    let module = cur.module();
    may_edit_module(&u, cur.client_id, module)?;
    let name = b.name.as_deref().map(clean_name).transpose()?.unwrap_or(cur.name.clone());
    if module.single() && (b.enabled == Some(false) || b.client_id.flatten().is_some() || b.site_id.flatten().is_some()) {
        return Err(bad(format!("the {} policy is always on and applies to every device; override it in a set instead", module.as_str())));
    }
    let (client_id, site_id) = if module.single() {
        (None, None)
    } else {
        let client = b.client_id.unwrap_or(cur.client_id);
        let site = match b.site_id {
            Some(s) => s,
            None if b.client_id.is_some() && client != cur.client_id => None,
            None => cur.site_id,
        };
        (check_limit(&st, &u, cur.set_client_id, client, site).await?, site)
    };
    may_edit_module(&u, client_id, module)?;
    let config = match &b.config {
        Some(c) => policy::validate(module, c).map_err(bad)?,
        None => cur.config.clone(),
    };
    if module == Module::Alert && config.get("kind") != cur.config.get("kind") {
        // Open alerts were raised by the old rule and mean something else.
        return Err(bad("a policy's type can't change; create a new policy instead".into()));
    }
    check_refs(&st, &u, module, &config, client_id).await?;
    let mut tx = st.db.begin().await?;
    policy::lock(&mut tx).await?;
    let before = policy::agents_reached(&mut tx, &[id]).await?;
    sqlx::query(
        "UPDATE policy_items SET name = $2, enabled = $3, config = $4, client_id = $5, site_id = $6, updated_at = now() WHERE id = $1",
    )
    .bind(id)
    .bind(&name)
    .bind(b.enabled.unwrap_or(cur.enabled))
    .bind(&config)
    .bind(client_id)
    .bind(site_id)
    .execute(&mut *tx)
    .await?;
    if module == Module::Schedule && config != cur.config {
        schedule_state(&mut tx, id, &config).await?;
    }
    policy::rebuild(&mut tx, Some(&[id])).await?;
    policy::validate_effective(&mut tx, &[id]).await?.map_err(bad)?;
    tx.commit().await?;
    auth::audit(
        &st.db,
        Some(u.id),
        "policy.update",
        Some(("policy", id)),
        json!({ "name": name, "module": module.as_str(), "enabled": b.enabled, "config": b.config.is_some(), "client_id": client_id, "site_id": site_id }),
    )
    .await;
    policy::changed(&st, change_for(module, id, before)).await;
    Ok(Json(item_view(&st, &u, id, cur.set_id).await?))
}

pub async fn delete_item(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    let cur = fetch_item(&st, &u, id).await?;
    let module = cur.module();
    if module.single() {
        return Err(bad(format!("the {} policy can't be deleted; change it instead", module.as_str())));
    }
    may_edit_module(&u, cur.client_id, module)?;
    // Close its alerts first (quietly): once the item is gone they'd have no owner.
    crate::alerts::close_for_item(&st, id).await;
    let mut tx = st.db.begin().await?;
    policy::lock(&mut tx).await?;
    let before = policy::agents_reached(&mut tx, &[id]).await?;
    sqlx::query("DELETE FROM policy_items WHERE id = $1").bind(id).execute(&mut *tx).await?;
    tx.commit().await?;
    auth::audit(&st.db, Some(u.id), "policy.delete", Some(("policy", id)), json!({ "name": cur.name, "module": module.as_str() })).await;
    policy::changed(&st, Change::agents(before)).await;
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
pub struct OverrideIn {
    /// null or omitted: as inherited.
    enabled: Option<bool>,
    /// Only the fields that differ; `{}` with `enabled` null removes the override.
    #[serde(default)]
    config: Value,
}

/// The set `set_id` lies strictly below the item's set; returns the set.
async fn override_target(st: &AppState, u: &User, item: &ItemMeta, set_id: Uuid) -> ApiResult<SetRow> {
    let set = fetch_set(st, u, set_id).await?;
    let reaches: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM policy_effective WHERE item_id = $1 AND set_id = $2)")
        .bind(item.id)
        .bind(set_id)
        .fetch_one(&st.db)
        .await?;
    if !reaches || set_id == item.set_id {
        return Err(bad("an override belongs in a set below the one the policy is defined in".into()));
    }
    if let (Some(c), Some(d)) = (item.client_id, set.client_id)
        && c != d
    {
        return Err(bad("this policy is limited to another client".into()));
    }
    may_edit_module(u, set.client_id, item.module())?;
    Ok(set)
}

pub async fn put_override(
    State(st): State<Arc<AppState>>,
    u: User,
    Path((id, set_id)): Path<(Uuid, Uuid)>,
    Json(b): Json<OverrideIn>,
) -> ApiResult<Json<ItemView>> {
    let item = fetch_item(&st, &u, id).await?;
    let module = item.module();
    let set = override_target(&st, &u, &item, set_id).await?;
    if module.single() && b.enabled.is_some() {
        return Err(bad(format!("the {} policy is always on; override its settings instead", module.as_str())));
    }
    let raw = if b.config.is_null() { json!({}) } else { b.config.clone() };
    let config = policy::clean_override(module, &raw).map_err(bad)?;
    check_refs(&st, &u, module, &config, set.client_id.or(item.client_id)).await?;
    let mut tx = st.db.begin().await?;
    policy::lock(&mut tx).await?;
    if b.enabled.is_none() && config.as_object().is_some_and(|m| m.is_empty()) {
        sqlx::query("DELETE FROM policy_overrides WHERE item_id = $1 AND set_id = $2").bind(id).bind(set_id).execute(&mut *tx).await?;
    } else {
        sqlx::query(
            "INSERT INTO policy_overrides (item_id, set_id, enabled, config, updated_by) VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (item_id, set_id) DO UPDATE SET enabled = EXCLUDED.enabled, config = EXCLUDED.config,
                                                         updated_by = EXCLUDED.updated_by, updated_at = now()",
        )
        .bind(id)
        .bind(set_id)
        .bind(b.enabled)
        .bind(&config)
        .bind(u.id)
        .execute(&mut *tx)
        .await?;
    }
    policy::rebuild(&mut tx, Some(&[id])).await?;
    policy::validate_effective(&mut tx, &[id]).await?.map_err(bad)?;
    let agents = policy::agents_under(&mut tx, set_id).await?;
    tx.commit().await?;
    let fields: Vec<&String> = config.as_object().map(|m| m.keys().collect()).unwrap_or_default();
    auth::audit(
        &st.db,
        Some(u.id),
        "policy.override",
        Some(("policy", id)),
        json!({ "name": item.name, "set_id": set_id, "set": set.name, "enabled": b.enabled, "fields": fields }),
    )
    .await;
    policy::changed(&st, change_for(module, id, agents)).await;
    Ok(Json(item_view(&st, &u, id, set_id).await?))
}

pub async fn delete_override(State(st): State<Arc<AppState>>, u: User, Path((id, set_id)): Path<(Uuid, Uuid)>) -> ApiResult<Json<ItemView>> {
    let item = fetch_item(&st, &u, id).await?;
    let set = override_target(&st, &u, &item, set_id).await?;
    let mut tx = st.db.begin().await?;
    policy::lock(&mut tx).await?;
    sqlx::query("DELETE FROM policy_overrides WHERE item_id = $1 AND set_id = $2").bind(id).bind(set_id).execute(&mut *tx).await?;
    policy::rebuild(&mut tx, Some(&[id])).await?;
    policy::validate_effective(&mut tx, &[id]).await?.map_err(bad)?;
    let agents = policy::agents_under(&mut tx, set_id).await?;
    tx.commit().await?;
    auth::audit(&st.db, Some(u.id), "policy.override_reset", Some(("policy", id)), json!({ "name": item.name, "set_id": set_id, "set": set.name }))
        .await;
    policy::changed(&st, change_for(item.module(), id, agents)).await;
    Ok(Json(item_view(&st, &u, id, set_id).await?))
}

/// Leaves one agent out of an item (`excluded: true`) or puts it back. Its open alerts from
/// the item on that agent close quietly.
async fn set_excluded(st: &Arc<AppState>, u: &User, id: Uuid, agent_id: Uuid, excluded: bool) -> ApiResult<ItemView> {
    let item = fetch_item(st, u, id).await?;
    let module = item.module();
    if module.single() {
        return Err(bad(format!("the {} policy applies to every device; override it in a set instead", module.as_str())));
    }
    // Changing who an item covers is editing it; the agent must be one the user can manage.
    may_edit_module(u, item.client_id, module)?;
    super::access::agent(st, u, agent_id).await?;
    let sql = if excluded {
        "UPDATE policy_items SET excluded_agents = array_append(excluded_agents, $2), updated_at = now()
          WHERE id = $1 AND NOT ($2 = ANY(excluded_agents))"
    } else {
        "UPDATE policy_items SET excluded_agents = array_remove(excluded_agents, $2), updated_at = now() WHERE id = $1"
    };
    sqlx::query(sql).bind(id).bind(agent_id).execute(&st.db).await?;
    // Agents that were deleted don't need to stay listed.
    sqlx::query(
        "UPDATE policy_items SET excluded_agents = ARRAY(SELECT x FROM unnest(excluded_agents) x WHERE EXISTS (SELECT 1 FROM agents WHERE id = x))
          WHERE id = $1",
    )
    .bind(id)
    .execute(&st.db)
    .await?;
    auth::audit(
        &st.db,
        Some(u.id),
        if excluded { "policy.exclude_agent" } else { "policy.include_agent" },
        Some(("agent", agent_id)),
        json!({ "policy": id, "name": item.name }),
    )
    .await;
    policy::changed(st, change_for(module, id, vec![agent_id])).await;
    item_view(st, u, id, item.set_id).await
}

pub async fn exclude(State(st): State<Arc<AppState>>, u: User, Path((id, agent_id)): Path<(Uuid, Uuid)>) -> ApiResult<Json<ItemView>> {
    Ok(Json(set_excluded(&st, &u, id, agent_id, true).await?))
}

pub async fn include(State(st): State<Arc<AppState>>, u: User, Path((id, agent_id)): Path<(Uuid, Uuid)>) -> ApiResult<Json<ItemView>> {
    Ok(Json(set_excluded(&st, &u, id, agent_id, false).await?))
}

// ---------------------------------------------------------------------------
// Device categories
// ---------------------------------------------------------------------------

#[derive(Serialize, sqlx::FromRow)]
pub struct CategoryRow {
    id: Uuid,
    name: String,
    description: String,
    builtin: bool,
    os_family: Option<String>,
    platform: Option<String>,
    default_set_id: Uuid,
    default_set_name: String,
    /// Devices in it (of the clients the user can see).
    devices: i64,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

const CATEGORY_SELECT: &str = "SELECT dc.id, dc.name, dc.description, dc.builtin, dc.os_family, dc.platform, dc.default_set_id,
       ps.name AS default_set_name,
       (SELECT count(*) FROM agents a JOIN sites s ON s.id = a.site_id
         WHERE a.category_id = dc.id AND ($1::uuid[] IS NULL OR s.client_id = ANY($1))) AS devices,
       dc.created_at, dc.updated_at
  FROM device_categories dc JOIN policy_sets ps ON ps.id = dc.default_set_id";

async fn fetch_category(st: &AppState, u: &User, id: Uuid) -> ApiResult<CategoryRow> {
    sqlx::query_as(AssertSqlSafe(format!("{CATEGORY_SELECT} WHERE dc.id = $2")))
        .bind(u.scope())
        .bind(id)
        .fetch_optional(&st.db)
        .await?
        .ok_or(ApiError::NotFound("device category"))
}

pub async fn list_categories(State(st): State<Arc<AppState>>, u: User) -> ApiResult<Json<Vec<CategoryRow>>> {
    Ok(Json(
        sqlx::query_as(AssertSqlSafe(format!("{CATEGORY_SELECT} ORDER BY dc.builtin DESC, lower(dc.name)")))
            .bind(u.scope())
            .fetch_all(&st.db)
            .await?,
    ))
}

/// A category's default set: an MSP-wide one (categories serve every client).
async fn check_default_set(st: &AppState, u: &User, id: Uuid) -> ApiResult<()> {
    let set = fetch_set(st, u, id).await?;
    if set.client_id.is_some() {
        return Err(bad("a category's default set must be MSP-wide".into()));
    }
    Ok(())
}

fn name_taken(e: sqlx::Error) -> ApiError {
    match &e {
        sqlx::Error::Database(d) if d.is_unique_violation() => ApiError::Conflict("there is already a category with that name".into()),
        _ => e.into(),
    }
}

#[derive(Deserialize)]
pub struct NewCategory {
    name: String,
    #[serde(default)]
    description: String,
    default_set_id: Uuid,
}

pub async fn create_category(State(st): State<Arc<AppState>>, u: User, Json(b): Json<NewCategory>) -> ApiResult<Json<CategoryRow>> {
    u.require(Role::Admin)?;
    let name = clean_name(&b.name)?;
    let description = clean_description(&b.description)?;
    check_default_set(&st, &u, b.default_set_id).await?;
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO device_categories (id, name, description, default_set_id, created_by) VALUES ($1, $2, $3, $4, $5)")
        .bind(id)
        .bind(&name)
        .bind(&description)
        .bind(b.default_set_id)
        .bind(u.id)
        .execute(&st.db)
        .await
        .map_err(name_taken)?;
    auth::audit(&st.db, Some(u.id), "device_category.create", Some(("device_category", id)), json!({ "name": name, "default_set_id": b.default_set_id }))
        .await;
    Ok(Json(fetch_category(&st, &u, id).await?))
}

#[derive(Deserialize)]
pub struct CategoryUpdate {
    /// Built-in categories keep their names.
    name: Option<String>,
    description: Option<String>,
    default_set_id: Option<Uuid>,
}

pub async fn update_category(
    State(st): State<Arc<AppState>>,
    u: User,
    Path(id): Path<Uuid>,
    Json(b): Json<CategoryUpdate>,
) -> ApiResult<Json<CategoryRow>> {
    u.require(Role::Admin)?;
    let cur = fetch_category(&st, &u, id).await?;
    let name = b.name.as_deref().map(clean_name).transpose()?;
    if cur.builtin && name.as_ref().is_some_and(|n| *n != cur.name) {
        return Err(bad("built-in categories can't be renamed".into()));
    }
    let description = b.description.as_deref().map(clean_description).transpose()?;
    if let Some(s) = b.default_set_id {
        check_default_set(&st, &u, s).await?;
    }
    let mut tx = st.db.begin().await?;
    policy::lock(&mut tx).await?;
    sqlx::query(
        "UPDATE device_categories SET name = coalesce($2, name), description = coalesce($3, description),
                default_set_id = coalesce($4, default_set_id), updated_at = now() WHERE id = $1",
    )
    .bind(id)
    .bind(&name)
    .bind(&description)
    .bind(b.default_set_id)
    .execute(&mut *tx)
    .await
    .map_err(name_taken)?;
    let moved = policy::reresolve(&mut tx).await?;
    tx.commit().await?;
    auth::audit(
        &st.db,
        Some(u.id),
        "device_category.update",
        Some(("device_category", id)),
        json!({ "name": name, "default_set_id": b.default_set_id, "moved": moved.len() }),
    )
    .await;
    policy::changed(&st, Change::agents(moved)).await;
    Ok(Json(fetch_category(&st, &u, id).await?))
}

/// Deletes a custom category; its devices go back to their automatic (built-in) category.
pub async fn delete_category(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    u.require(Role::Admin)?;
    let cur = fetch_category(&st, &u, id).await?;
    if cur.builtin {
        return Err(bad("built-in categories can't be deleted".into()));
    }
    let mut tx = st.db.begin().await?;
    policy::lock(&mut tx).await?;
    let moved: Vec<Uuid> = sqlx::query_scalar("UPDATE agents SET category_manual = false WHERE category_id = $1 RETURNING id")
        .bind(id)
        .fetch_all(&mut *tx)
        .await?;
    sqlx::query("UPDATE enrollment_tokens SET category_id = NULL WHERE category_id = $1").bind(id).execute(&mut *tx).await?;
    sqlx::query("DELETE FROM device_categories WHERE id = $1").bind(id).execute(&mut *tx).await?;
    tx.commit().await?;
    auth::audit(&st.db, Some(u.id), "device_category.delete", Some(("device_category", id)), json!({ "name": cur.name, "devices": moved.len() })).await;
    policy::changed(&st, Change::agents(moved)).await;
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
pub struct MoveAgents {
    agent_ids: Vec<Uuid>,
    /// None: back to automatic (the built-in category for the OS and platform).
    category_id: Option<Uuid>,
}

pub async fn move_agents(State(st): State<Arc<AppState>>, u: User, Json(b): Json<MoveAgents>) -> ApiResult<Json<Value>> {
    u.require(Role::Technician)?;
    if b.agent_ids.is_empty() || b.agent_ids.len() > 5000 {
        return Err(bad("agent_ids must contain 1-5000 agents".into()));
    }
    let visible: i64 = sqlx::query_scalar(
        "SELECT count(DISTINCT a.id) FROM agents a JOIN sites s ON s.id = a.site_id WHERE a.id = ANY($1) AND ($2::uuid[] IS NULL OR s.client_id = ANY($2))",
    )
    .bind(&b.agent_ids)
    .bind(u.scope())
    .fetch_one(&st.db)
    .await?;
    if visible as usize != b.agent_ids.iter().collect::<std::collections::HashSet<_>>().len() {
        return Err(ApiError::NotFound("agent"));
    }
    if let Some(c) = b.category_id {
        fetch_category(&st, &u, c).await?;
    }
    let mut tx = st.db.begin().await?;
    policy::lock(&mut tx).await?;
    let rows: Vec<(Uuid, Uuid, Uuid)> = sqlx::query_as(
        "WITH old AS (SELECT id, policy_set_id FROM agents WHERE id = ANY($1) FOR UPDATE)
         UPDATE agents a SET category_id = coalesce($2, a.category_id), category_manual = $2 IS NOT NULL
           FROM old WHERE a.id = old.id
          RETURNING a.id, old.policy_set_id, a.policy_set_id",
    )
    .bind(&b.agent_ids)
    .bind(b.category_id)
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    let moved: Vec<Uuid> = rows.iter().filter(|r| r.1 != r.2).map(|r| r.0).collect();
    auth::audit(
        &st.db,
        Some(u.id),
        "agent.category",
        None,
        json!({ "agents": rows.len(), "category_id": b.category_id, "moved_set": moved.len() }),
    )
    .await;
    let n = moved.len();
    policy::changed(&st, Change::agents(moved)).await;
    Ok(Json(json!({ "changed": rows.len(), "moved": n })))
}

// ---------------------------------------------------------------------------
// Assignments
// ---------------------------------------------------------------------------

#[derive(Serialize, sqlx::FromRow)]
pub struct AssignmentRow {
    id: Uuid,
    client_id: Uuid,
    client_name: String,
    site_id: Option<Uuid>,
    site_name: Option<String>,
    category_id: Uuid,
    category_name: String,
    policy_set_id: Uuid,
    policy_set_name: String,
    updated_at: DateTime<Utc>,
}

const ASSIGNMENT_SELECT: &str = "SELECT pa.id, pa.client_id, c.name AS client_name, pa.site_id, si.name AS site_name, pa.category_id,
       dc.name AS category_name, pa.policy_set_id, ps.name AS policy_set_name, pa.updated_at
  FROM policy_assignments pa JOIN clients c ON c.id = pa.client_id LEFT JOIN sites si ON si.id = pa.site_id
  JOIN device_categories dc ON dc.id = pa.category_id JOIN policy_sets ps ON ps.id = pa.policy_set_id";

#[derive(Deserialize)]
pub struct AssignmentsQuery {
    client_id: Option<Uuid>,
}

pub async fn list_assignments(State(st): State<Arc<AppState>>, u: User, Query(q): Query<AssignmentsQuery>) -> ApiResult<Json<Vec<AssignmentRow>>> {
    if let Some(c) = q.client_id {
        super::access::client(&u, c)?;
    }
    Ok(Json(
        sqlx::query_as(AssertSqlSafe(format!(
            "{ASSIGNMENT_SELECT} WHERE ($1::uuid[] IS NULL OR pa.client_id = ANY($1)) AND ($2::uuid IS NULL OR pa.client_id = $2)
              ORDER BY lower(c.name), si.name NULLS FIRST, dc.builtin DESC, lower(dc.name)"
        )))
        .bind(u.scope())
        .bind(q.client_id)
        .fetch_all(&st.db)
        .await?,
    ))
}

#[derive(Deserialize)]
pub struct AssignmentIn {
    client_id: Uuid,
    site_id: Option<Uuid>,
    category_id: Uuid,
    policy_set_id: Uuid,
}

/// Sets which set a client's (or one site's) devices of a category use.
pub async fn put_assignment(State(st): State<Arc<AppState>>, u: User, Json(b): Json<AssignmentIn>) -> ApiResult<Json<AssignmentRow>> {
    super::access::client(&u, b.client_id)?;
    may_edit(&u, Some(b.client_id))?;
    if let Some(site) = b.site_id
        && super::access::site(&st, &u, site).await? != b.client_id
    {
        return Err(bad("the site must belong to the client".into()));
    }
    fetch_category(&st, &u, b.category_id).await?;
    let set = fetch_set(&st, &u, b.policy_set_id).await?;
    if set.client_id.is_some_and(|c| c != b.client_id) {
        return Err(bad("that set belongs to another client".into()));
    }
    let mut tx = st.db.begin().await?;
    policy::lock(&mut tx).await?;
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO policy_assignments (id, client_id, site_id, category_id, policy_set_id, updated_by) VALUES ($1, $2, $3, $4, $5, $6)
         ON CONFLICT (client_id, site_id, category_id) DO UPDATE SET policy_set_id = EXCLUDED.policy_set_id,
                                                                     updated_by = EXCLUDED.updated_by, updated_at = now()
         RETURNING id",
    )
    .bind(Uuid::new_v4())
    .bind(b.client_id)
    .bind(b.site_id)
    .bind(b.category_id)
    .bind(b.policy_set_id)
    .bind(u.id)
    .fetch_one(&mut *tx)
    .await?;
    let moved = policy::reresolve(&mut tx).await?;
    tx.commit().await?;
    auth::audit(
        &st.db,
        Some(u.id),
        "policy_assignment.set",
        Some(("client", b.client_id)),
        json!({ "site_id": b.site_id, "category_id": b.category_id, "policy_set_id": b.policy_set_id, "set": set.name, "moved": moved.len() }),
    )
    .await;
    policy::changed(&st, Change::agents(moved)).await;
    sqlx::query_as(AssertSqlSafe(format!("{ASSIGNMENT_SELECT} WHERE pa.id = $1"))).bind(id).fetch_one(&st.db).await.map(Json).map_err(Into::into)
}

pub async fn delete_assignment(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    let client: Option<Uuid> = sqlx::query_scalar("SELECT client_id FROM policy_assignments WHERE id = $1").bind(id).fetch_optional(&st.db).await?;
    let client = client.filter(|c| u.can_see_client(*c)).ok_or(ApiError::NotFound("assignment"))?;
    may_edit(&u, Some(client))?;
    let mut tx = st.db.begin().await?;
    policy::lock(&mut tx).await?;
    sqlx::query("DELETE FROM policy_assignments WHERE id = $1").bind(id).execute(&mut *tx).await?;
    let moved = policy::reresolve(&mut tx).await?;
    tx.commit().await?;
    auth::audit(&st.db, Some(u.id), "policy_assignment.delete", Some(("client", client)), json!({ "assignment": id, "moved": moved.len() })).await;
    policy::changed(&st, Change::agents(moved)).await;
    Ok(Json(json!({ "ok": true })))
}

// ---------------------------------------------------------------------------
// One agent
// ---------------------------------------------------------------------------

#[derive(Serialize, sqlx::FromRow)]
pub struct CategoryRef {
    id: Uuid,
    name: String,
    builtin: bool,
    /// Moved by hand (or enrolled with a category): reports don't move it back.
    manual: bool,
}

#[derive(Serialize)]
pub struct AgentPolicy {
    agent_id: Uuid,
    hostname: String,
    client_id: Uuid,
    site_id: Uuid,
    /// workstation / server.
    platform: String,
    category: CategoryRef,
    /// The set it uses and why: `pin`, `site`, `client` or `default`.
    set: ChainEntry,
    reason: policy::Reason,
    /// The assignment that picked the set (reason site or client).
    assignment_id: Option<Uuid>,
    pin: Option<ChainEntry>,
    chain: Vec<ChainEntry>,
    policies: Vec<ItemView>,
}

async fn agent_policy(st: &AppState, u: &User, id: Uuid) -> ApiResult<AgentPolicy> {
    let client_id = super::access::agent(st, u, id).await?;
    #[allow(clippy::type_complexity)]
    let (hostname, site_id, platform, set_id, pin, category_id): (String, Uuid, String, Uuid, Option<Uuid>, Uuid) =
        sqlx::query_as("SELECT hostname, site_id, platform, policy_set_id, policy_pin_id, category_id FROM agents WHERE id = $1")
            .bind(id)
            .fetch_one(&st.db)
            .await?;
    let category: CategoryRef = sqlx::query_as(
        "SELECT dc.id, dc.name, dc.builtin, a.category_manual AS manual FROM agents a JOIN device_categories dc ON dc.id = a.category_id WHERE a.id = $1",
    )
    .bind(id)
    .fetch_one(&st.db)
    .await?;
    let site_assignment: Option<(Uuid, Uuid)> =
        sqlx::query_as("SELECT id, policy_set_id FROM policy_assignments WHERE site_id = $1 AND category_id = $2")
            .bind(site_id)
            .bind(category_id)
            .fetch_optional(&st.db)
            .await?;
    let client_assignment: Option<(Uuid, Uuid)> =
        sqlx::query_as("SELECT id, policy_set_id FROM policy_assignments WHERE client_id = $1 AND site_id IS NULL AND category_id = $2")
            .bind(client_id)
            .bind(category_id)
            .fetch_optional(&st.db)
            .await?;
    let default: Uuid = sqlx::query_scalar("SELECT default_set_id FROM device_categories WHERE id = $1").bind(category_id).fetch_one(&st.db).await?;
    let (resolved, reason) = policy::resolve(pin, site_assignment.map(|a| a.1), client_assignment.map(|a| a.1), default);
    if resolved != set_id {
        tracing::warn!(agent = %id, stored = %set_id, %resolved, "an agent's stored policy set disagrees with its resolution");
    }
    let assignment_id = match reason {
        policy::Reason::Site => site_assignment.map(|a| a.0),
        policy::Reason::Client => client_assignment.map(|a| a.0),
        _ => None,
    };
    let chain = chain(&mut *st.db.acquire().await?, set_id).await?;
    let set = chain.last().cloned().ok_or(ApiError::NotFound("policy set"))?;
    let pin = match pin {
        Some(p) => chain.iter().find(|c| c.id == p).cloned(),
        None => None,
    };
    let policies = item_views(st, u, &chain, Some((id, client_id, site_id))).await?;
    Ok(AgentPolicy { agent_id: id, hostname, client_id, site_id, platform, category, set, reason, assignment_id, pin, chain, policies })
}

pub async fn get_agent_policy(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<AgentPolicy>> {
    Ok(Json(agent_policy(&st, &u, id).await?))
}

#[derive(Deserialize)]
pub struct PinIn {
    /// None: unpinned (the set stays; delete it separately).
    policy_set_id: Option<Uuid>,
}

async fn pin(st: &Arc<AppState>, u: &User, agent: Uuid, set: Option<Uuid>, action: &str) -> ApiResult<()> {
    let (before, after): (Uuid, Uuid) = sqlx::query_as(
        "WITH old AS (SELECT id, policy_set_id FROM agents WHERE id = $1 FOR UPDATE)
         UPDATE agents a SET policy_pin_id = $2 FROM old WHERE a.id = old.id RETURNING old.policy_set_id, a.policy_set_id",
    )
    .bind(agent)
    .bind(set)
    .fetch_one(&st.db)
    .await?;
    auth::audit(&st.db, Some(u.id), action, Some(("agent", agent)), json!({ "policy_set_id": set })).await;
    if before != after {
        policy::changed(st, Change::agents(vec![agent])).await;
    }
    Ok(())
}

pub async fn put_pin(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>, Json(b): Json<PinIn>) -> ApiResult<Json<AgentPolicy>> {
    u.require(Role::Technician)?;
    let client = super::access::agent(&st, &u, id).await?;
    if let Some(s) = b.policy_set_id {
        let set = fetch_set(&st, &u, s).await?;
        if set.client_id.is_some_and(|c| c != client) {
            return Err(bad("that set belongs to another client".into()));
        }
    }
    pin(&st, &u, id, b.policy_set_id, "agent.policy_pin").await?;
    Ok(Json(agent_policy(&st, &u, id).await?))
}

/// "Customize for this device": a client-owned child of the agent's current set, named after
/// the host, pinned to it.
pub async fn customize(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<AgentPolicy>> {
    u.require(Role::Technician)?;
    let client = super::access::agent(&st, &u, id).await?;
    let (hostname, current): (String, Uuid) =
        sqlx::query_as("SELECT hostname, policy_set_id FROM agents WHERE id = $1").bind(id).fetch_one(&st.db).await?;
    let parent = fetch_set(&st, &u, current).await?;
    if parent.depth + 1 > policy::MAX_DEPTH {
        return Err(bad(format!("policy sets go at most {} levels deep", policy::MAX_DEPTH)));
    }
    let set_id = Uuid::new_v4();
    let name: String = hostname.chars().take(200).collect();
    let mut tx = st.db.begin().await?;
    policy::lock(&mut tx).await?;
    sqlx::query("INSERT INTO policy_sets (id, parent_id, client_id, name, description, created_by) VALUES ($1, $2, $3, $4, $5, $6)")
        .bind(set_id)
        .bind(current)
        .bind(client)
        .bind(&name)
        .bind(format!("Customized for {hostname}"))
        .bind(u.id)
        .execute(&mut *tx)
        .await?;
    let reaching: Vec<Uuid> = sqlx::query_scalar("SELECT item_id FROM policy_effective WHERE set_id = $1").bind(current).fetch_all(&mut *tx).await?;
    policy::rebuild(&mut tx, Some(&reaching)).await?;
    tx.commit().await?;
    auth::audit(&st.db, Some(u.id), "policy_set.create", Some(("policy_set", set_id)), json!({ "name": name, "parent_id": current, "client_id": client }))
        .await;
    // Same policies as before: nothing to fan out beyond the pin itself.
    pin(&st, &u, id, Some(set_id), "agent.policy_customize").await?;
    Ok(Json(agent_policy(&st, &u, id).await?))
}
