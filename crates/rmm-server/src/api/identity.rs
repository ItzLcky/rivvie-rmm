//! A client's directories (Active Directory, Entra ID), their users and groups, the actions on
//! them, and the client's Intune devices. See [`crate::identity`], [`crate::mdm`] and
//! docs/design/identity.md, docs/design/mdm.md.
//!
//! Reading needs `identity.read`; actions need `identity.manage` and two-factor
//! authentication, privileged accounts an admin as well; adding and changing directories is for
//! admins. Not in the public API (except the Intune device list), like the vault.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::header;
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::AssertSqlSafe;
use uuid::Uuid;

use crate::auth::{self, Perm, Role, User};
use crate::error::{ApiError, ApiResult};
use crate::identity::{Action, Delivery};
use crate::paging::{self, Page, PageQuery, Plan, SortKey};
use crate::state::AppState;

fn read_gate(u: &User, client: Uuid) -> ApiResult<()> {
    super::access::client(u, client)?;
    u.need(Perm::IdentityRead)
}

/// The checks before any directory action: visible client (else 404), `identity.manage`,
/// a second factor, and the per-user rate limit.
pub fn manage_gate(st: &AppState, u: &User, client: Uuid) -> ApiResult<()> {
    super::access::client(u, client)?;
    u.need(Perm::IdentityManage)?;
    if !u.second_factor() {
        return Err(ApiError::Denied("turn on two-factor authentication to change directory accounts".into()));
    }
    st.limits.identity_action.take(&u.id.to_string()).map_err(ApiError::Throttled)
}

async fn source_client(st: &AppState, u: &User, id: Uuid) -> ApiResult<Uuid> {
    let c: Option<Uuid> = sqlx::query_scalar("SELECT client_id FROM identity_sources WHERE id = $1").bind(id).fetch_optional(&st.db).await?;
    c.filter(|c| u.can_see_client(*c)).ok_or(ApiError::NotFound("directory"))
}

// ---------------------------------------------------------------------------------------------
// Sources
// ---------------------------------------------------------------------------------------------

#[derive(Serialize, sqlx::FromRow)]
pub struct SourceRow {
    id: Uuid,
    client_id: Uuid,
    kind: String,
    name: String,
    agent_id: Option<Uuid>,
    agent_hostname: Option<String>,
    agent_online: Option<bool>,
    tenant_id: String,
    app_client_id: String,
    has_secret: bool,
    sync_devices: bool,
    sync_minutes: i32,
    enabled: bool,
    last_sync_at: Option<DateTime<Utc>>,
    last_error: Option<String>,
    users: i64,
    groups: i64,
    devices: i64,
}

/// Never a secret: `has_secret` only.
const SOURCE_COLS: &str = "s.id, s.client_id, s.kind, s.name, s.agent_id, a.hostname AS agent_hostname, a.online AS agent_online,
       s.tenant_id, s.app_client_id, s.secret IS NOT NULL AS has_secret, s.sync_devices, s.sync_minutes, s.enabled, s.last_sync_at, s.last_error,
       (SELECT count(*) FROM identity_users iu WHERE iu.source_id = s.id AND iu.deleted_at IS NULL) AS users,
       (SELECT count(*) FROM identity_groups ig WHERE ig.source_id = s.id AND ig.deleted_at IS NULL) AS groups,
       (SELECT count(*) FROM mdm_devices md WHERE md.source_id = s.id) AS devices
  FROM identity_sources s LEFT JOIN agents a ON a.id = s.agent_id";

async fn source_row(st: &AppState, id: Uuid) -> ApiResult<SourceRow> {
    sqlx::query_as(AssertSqlSafe(format!("SELECT {SOURCE_COLS} WHERE s.id = $1"))).bind(id).fetch_optional(&st.db).await?.ok_or(ApiError::NotFound("directory"))
}

pub async fn list_sources(State(st): State<Arc<AppState>>, u: User, Path(client): Path<Uuid>) -> ApiResult<Json<Vec<SourceRow>>> {
    read_gate(&u, client)?;
    Ok(Json(
        sqlx::query_as(AssertSqlSafe(format!("SELECT {SOURCE_COLS} WHERE s.client_id = $1 ORDER BY lower(s.name), s.id"))).bind(client).fetch_all(&st.db).await?,
    ))
}

#[derive(Deserialize)]
pub struct SourceIn {
    kind: Option<String>,
    name: String,
    agent_id: Option<Uuid>,
    #[serde(default)]
    tenant_id: String,
    #[serde(default)]
    app_client_id: String,
    /// Absent or empty on an update keeps the stored one.
    secret: Option<String>,
    #[serde(default)]
    sync_devices: bool,
    sync_minutes: Option<i32>,
    enabled: Option<bool>,
}

struct Clean {
    name: String,
    tenant: String,
    app: String,
    secret: Option<String>,
    minutes: i32,
}

async fn clean(st: &AppState, client: Uuid, kind: &str, b: &SourceIn) -> ApiResult<Clean> {
    let name = b.name.split_whitespace().collect::<Vec<_>>().join(" ");
    if name.is_empty() || name.chars().count() > 100 {
        return Err(ApiError::BadRequest("name must be 1-100 characters".into()));
    }
    let minutes = b.sync_minutes.unwrap_or(60);
    if !(5..=1440).contains(&minutes) {
        return Err(ApiError::BadRequest("sync every 5-1440 minutes".into()));
    }
    let secret = b.secret.as_deref().map(str::trim).filter(|s| !s.is_empty()).map(String::from);
    match kind {
        "ad" => {
            let agent = b.agent_id.ok_or_else(|| ApiError::BadRequest("choose the domain controller's agent".into()))?;
            let owner: Option<Uuid> = sqlx::query_scalar("SELECT s.client_id FROM agents a JOIN sites s ON s.id = a.site_id WHERE a.id = $1")
                .bind(agent)
                .fetch_optional(&st.db)
                .await?;
            if owner != Some(client) {
                return Err(ApiError::BadRequest("the agent must be one of this client's".into()));
            }
            Ok(Clean { name, tenant: String::new(), app: String::new(), secret: None, minutes })
        }
        "entra" => {
            let tenant = b.tenant_id.trim().to_string();
            if tenant.is_empty() || tenant.len() > 100 || !tenant.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'.') {
                return Err(ApiError::BadRequest("the tenant is its id or its .onmicrosoft.com domain".into()));
            }
            let app = b.app_client_id.trim().to_string();
            if Uuid::parse_str(&app).is_err() {
                return Err(ApiError::BadRequest("the application (client) id is a GUID".into()));
            }
            if secret.as_ref().is_some_and(|s| s.len() > 1000) {
                return Err(ApiError::BadRequest("the client secret is too long".into()));
            }
            Ok(Clean { name, tenant, app, secret, minutes })
        }
        _ => Err(ApiError::BadRequest("kind is ad or entra".into())),
    }
}

fn unique(e: sqlx::Error) -> ApiError {
    match e {
        sqlx::Error::Database(d) if d.is_unique_violation() => ApiError::Conflict("this client already has a directory with that name".into()),
        e => e.into(),
    }
}

pub async fn create_source(State(st): State<Arc<AppState>>, u: User, Path(client): Path<Uuid>, Json(b): Json<SourceIn>) -> ApiResult<Json<SourceRow>> {
    u.require(Role::Admin)?;
    super::access::client(&u, client)?;
    let kind = b.kind.clone().unwrap_or_default();
    let c = clean(&st, client, &kind, &b).await?;
    if kind == "entra" && c.secret.is_none() {
        return Err(ApiError::BadRequest("enter the app's client secret".into()));
    }
    let (sealed_secret, sealed) = match &c.secret {
        Some(s) => {
            let (v, f) = crate::crypto::store(st.cfg.data_key.as_ref(), s.as_bytes());
            (Some(v), f)
        }
        None => (None, false),
    };
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO identity_sources (id, client_id, kind, name, agent_id, tenant_id, app_client_id, secret, secret_sealed, sync_devices, sync_minutes, enabled)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
    )
    .bind(id)
    .bind(client)
    .bind(&kind)
    .bind(&c.name)
    .bind(if kind == "ad" { b.agent_id } else { None })
    .bind(&c.tenant)
    .bind(&c.app)
    .bind(sealed_secret)
    .bind(sealed)
    .bind(kind == "entra" && b.sync_devices)
    .bind(c.minutes)
    .bind(b.enabled.unwrap_or(true))
    .execute(&st.db)
    .await
    .map_err(|e| match e {
        sqlx::Error::Database(d) if d.is_foreign_key_violation() => ApiError::NotFound("client"),
        e => unique(e),
    })?;
    auth::audit(&st.db, Some(u.id), "identity.source.create", Some(("identity_source", id)), json!({ "client_id": client, "kind": kind, "name": c.name })).await;
    Ok(Json(source_row(&st, id).await?))
}

pub async fn update_source(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>, Json(b): Json<SourceIn>) -> ApiResult<Json<SourceRow>> {
    u.require(Role::Admin)?;
    let client = source_client(&st, &u, id).await?;
    let kind: String = sqlx::query_scalar("SELECT kind FROM identity_sources WHERE id = $1").bind(id).fetch_one(&st.db).await?;
    if b.kind.as_deref().is_some_and(|k| k != kind) {
        return Err(ApiError::BadRequest("a directory's kind can't change; add another".into()));
    }
    let c = clean(&st, client, &kind, &b).await?;
    let secret = c.secret.as_ref().map(|s| crate::crypto::store(st.cfg.data_key.as_ref(), s.as_bytes()));
    sqlx::query(
        "UPDATE identity_sources SET name = $2, agent_id = $3, tenant_id = $4, app_client_id = $5,
                secret = CASE WHEN $6 THEN $7 ELSE secret END, secret_sealed = CASE WHEN $6 THEN $8 ELSE secret_sealed END,
                sync_devices = $9, sync_minutes = $10, enabled = $11, updated_at = now(),
                -- Another domain controller (or tenant) is another USN space.
                high_usn = CASE WHEN agent_id IS DISTINCT FROM $3 OR tenant_id <> $4 THEN 0 ELSE high_usn END
          WHERE id = $1",
    )
    .bind(id)
    .bind(&c.name)
    .bind(if kind == "ad" { b.agent_id } else { None })
    .bind(&c.tenant)
    .bind(&c.app)
    .bind(secret.is_some())
    .bind(secret.as_ref().map(|s| s.0.clone()))
    .bind(secret.as_ref().is_some_and(|s| s.1))
    .bind(kind == "entra" && b.sync_devices)
    .bind(c.minutes)
    .bind(b.enabled.unwrap_or(true))
    .execute(&st.db)
    .await
    .map_err(unique)?;
    if kind == "entra" && !b.sync_devices {
        sqlx::query("DELETE FROM mdm_devices WHERE source_id = $1").bind(id).execute(&st.db).await?;
    }
    auth::audit(
        &st.db,
        Some(u.id),
        "identity.source.update",
        Some(("identity_source", id)),
        json!({ "client_id": client, "name": c.name, "secret_changed": secret.is_some() }),
    )
    .await;
    Ok(Json(source_row(&st, id).await?))
}

pub async fn delete_source(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    u.require(Role::Admin)?;
    let client = source_client(&st, &u, id).await?;
    let name: String = sqlx::query_scalar("DELETE FROM identity_sources WHERE id = $1 RETURNING name").bind(id).fetch_one(&st.db).await?;
    auth::audit(&st.db, Some(u.id), "identity.source.delete", Some(("identity_source", id)), json!({ "client_id": client, "name": name })).await;
    Ok(Json(json!({ "ok": true })))
}

/// Signs in (Entra) or asks the domain controller for its groups (AD), changing nothing.
pub async fn test_source(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    u.require(Role::Admin)?;
    source_client(&st, &u, id).await?;
    let res = crate::identity::test(&st, id).await;
    auth::audit(&st.db, Some(u.id), "identity.source.test", Some(("identity_source", id)), json!({ "ok": res.is_ok() })).await;
    Ok(Json(match res {
        Ok(detail) => json!({ "ok": true, "detail": detail }),
        Err(e) => json!({ "ok": false, "error": e }),
    }))
}

pub async fn sync_source(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    let client = source_client(&st, &u, id).await?;
    u.need(Perm::IdentityManage)?;
    u.require(Role::Technician)?;
    let res = crate::identity::sync(&st, id).await;
    auth::audit(&st.db, Some(u.id), "identity.source.sync", Some(("identity_source", id)), json!({ "client_id": client, "ok": res.is_ok() })).await;
    match res {
        Ok(stats) => Ok(Json(json!({ "ok": true, "stats": stats }))),
        Err(e) => Err(ApiError::Conflict(e)),
    }
}

// ---------------------------------------------------------------------------------------------
// Users and groups
// ---------------------------------------------------------------------------------------------

#[derive(Serialize, sqlx::FromRow)]
pub struct UserRow {
    id: Uuid,
    source_id: Uuid,
    source_name: String,
    kind: String,
    external_id: String,
    username: String,
    upn: String,
    display_name: String,
    email: String,
    enabled: bool,
    locked: bool,
    privileged: bool,
    synced_from_ad: bool,
    last_logon_at: Option<DateTime<Utc>>,
    password_last_set: Option<DateTime<Utc>>,
    password_expires_at: Option<DateTime<Utc>>,
    mfa_registered: Option<bool>,
    department: String,
    title: String,
    contact_id: Option<Uuid>,
    contact_name: Option<String>,
    deleted_at: Option<DateTime<Utc>>,
    synced_at: DateTime<Utc>,
    #[sqlx(default)]
    #[serde(skip)]
    sort_key: String,
}

const USER_COLS: &str = "u.id, u.source_id, s.name AS source_name, s.kind, u.external_id, u.username, u.upn, u.display_name, u.email, u.enabled,
       u.locked, u.privileged, u.synced_from_ad, u.last_logon_at, u.password_last_set, u.password_expires_at, u.mfa_registered, u.department,
       u.title, u.contact_id, c.name AS contact_name, u.deleted_at, u.synced_at";
const USER_FROM: &str = "FROM identity_users u JOIN identity_sources s ON s.id = u.source_id LEFT JOIN contacts c ON c.id = u.contact_id";

const USER_SORT: &[SortKey] = &[
    SortKey { name: "name", expr: "lower(coalesce(nullif(u.display_name, ''), u.username))", ty: "text" },
    SortKey { name: "username", expr: "lower(u.username)", ty: "text" },
    SortKey { name: "last_logon", expr: "coalesce(u.last_logon_at, 'epoch'::timestamptz)", ty: "timestamptz" },
    SortKey { name: "password_last_set", expr: "coalesce(u.password_last_set, 'epoch'::timestamptz)", ty: "timestamptz" },
];

/// Accounts not used for this long are "stale".
pub const STALE_DAYS: i32 = 90;

#[derive(Deserialize)]
pub struct UsersQuery {
    /// Comma-separated: locked, disabled, stale, no_mfa, privileged.
    filter: Option<String>,
    q: Option<String>,
    source_id: Option<Uuid>,
    contact_id: Option<Uuid>,
    /// Include accounts gone from the directory.
    #[serde(default)]
    deleted: bool,
}

pub async fn list_users(
    State(st): State<Arc<AppState>>,
    u: User,
    Path(client): Path<Uuid>,
    Query(q): Query<UsersQuery>,
    Query(page): Query<PageQuery>,
) -> ApiResult<Json<Page<UserRow>>> {
    read_gate(&u, client)?;
    let plan = Plan::new(USER_SORT, ("name", false), &page, "u.id", "uuid", 6)?;
    let mut conds = vec![];
    for f in q.filter.as_deref().unwrap_or_default().split(',').map(str::trim).filter(|f| !f.is_empty()) {
        conds.push(match f {
            "locked" => "u.locked".to_string(),
            "disabled" => "NOT u.enabled".to_string(),
            "stale" => format!("u.enabled AND coalesce(u.last_logon_at, 'epoch') < now() - interval '{STALE_DAYS} days'"),
            "no_mfa" => "u.mfa_registered = false".to_string(),
            "privileged" => "u.privileged".to_string(),
            other => return Err(ApiError::BadRequest(format!("unknown filter {other}: locked, disabled, stale, no_mfa or privileged"))),
        });
    }
    let extra = conds.iter().map(|c| format!(" AND {c}")).collect::<String>();
    let search = q.q.as_deref().map(str::trim).filter(|s| !s.is_empty()).map(String::from);
    let filters = format!(
        "{USER_FROM} WHERE s.client_id = $1 AND ($2::uuid IS NULL OR u.source_id = $2) AND ($3::uuid IS NULL OR u.contact_id = $3)
           AND ($4 OR u.deleted_at IS NULL)
           AND ($5::text IS NULL OR u.display_name ILIKE '%' || $5 || '%' OR u.username ILIKE '%' || $5 || '%'
                OR u.upn ILIKE '%' || $5 || '%' OR u.email ILIKE '%' || $5 || '%'){extra}"
    );
    macro_rules! bind_filters {
        ($query:expr) => {
            $query.bind(client).bind(q.source_id).bind(q.contact_id).bind(q.deleted).bind(&search)
        };
    }
    let sql = format!("SELECT {USER_COLS}, {} {filters} {} {} {}", plan.key_select, plan.keyset, plan.order, plan.limit_sql());
    let mut rows = bind_filters!(sqlx::query_as::<_, UserRow>(AssertSqlSafe(sql)));
    if let Some((k, id)) = &plan.cursor {
        rows = rows.bind(k).bind(id);
    }
    let rows = rows.fetch_all(&st.db).await?;
    let total: i64 = bind_filters!(sqlx::query_scalar(AssertSqlSafe(paging::count_sql(&filters)))).fetch_one(&st.db).await?;
    Ok(Json(plan.finish(rows, |r| (r.sort_key.clone(), r.id.to_string()), total)))
}

#[derive(Serialize, sqlx::FromRow)]
struct GroupRef {
    id: Uuid,
    name: String,
    privileged: bool,
}

pub async fn get_user(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    let row: UserRow = sqlx::query_as(AssertSqlSafe(format!("SELECT {USER_COLS} {USER_FROM} WHERE u.id = $1")))
        .bind(id)
        .fetch_optional(&st.db)
        .await?
        .ok_or(ApiError::NotFound("directory user"))?;
    let client: Uuid = sqlx::query_scalar("SELECT client_id FROM identity_sources WHERE id = $1").bind(row.source_id).fetch_one(&st.db).await?;
    if !u.can_see_client(client) {
        return Err(ApiError::NotFound("directory user"));
    }
    u.need(Perm::IdentityRead)?;
    let groups: Vec<GroupRef> = sqlx::query_as(
        "SELECT g.id, g.name, g.privileged FROM identity_group_members m JOIN identity_groups g ON g.id = m.group_id
          WHERE m.user_id = $1 AND g.deleted_at IS NULL ORDER BY lower(g.name)",
    )
    .bind(id)
    .fetch_all(&st.db)
    .await?;
    // The vault item a reset saved, if any (its id only: revealing it is the vault's business).
    let vault_item: Option<Uuid> = sqlx::query_scalar("SELECT id FROM vault_items WHERE client_id = $1 AND managed_kind = 'identity' AND managed_ref = $2")
        .bind(client)
        .bind(format!("{}:{}", row.source_id, row.external_id))
        .fetch_optional(&st.db)
        .await?;
    let mut v = serde_json::to_value(&row).map_err(anyhow::Error::from)?;
    v["client_id"] = json!(client);
    v["groups"] = serde_json::to_value(groups).map_err(anyhow::Error::from)?;
    v["vault_item_id"] = json!(vault_item);
    v["can_manage"] = json!(u.has(Perm::IdentityManage) && u.second_factor() && (!row.privileged || u.role() >= Role::Admin));
    Ok(Json(v))
}

#[derive(Deserialize, Default)]
pub struct ActionIn {
    /// reset-password: the technician's choice; generated when absent.
    password: Option<String>,
    /// reset-password: default true.
    must_change: Option<bool>,
    /// reset-password: `show` (once, in this response) or `vault`.
    delivery: Option<Delivery>,
    /// remove-groups: these groups; every group the user is in when absent.
    group_ids: Option<Vec<Uuid>>,
}

pub fn parse_action(name: &str, b: ActionIn) -> ApiResult<Action> {
    Ok(match name {
        "unlock" => Action::Unlock,
        "disable" => Action::SetEnabled(false),
        "enable" => Action::SetEnabled(true),
        "revoke-sessions" => Action::RevokeSessions,
        "remove-groups" => Action::RemoveGroups(b.group_ids),
        "reset-password" => Action::Reset {
            password: b.password.filter(|p| !p.is_empty()),
            must_change: b.must_change.unwrap_or(true),
            delivery: b.delivery.ok_or_else(|| ApiError::BadRequest("choose how to deliver the password: show or vault".into()))?,
        },
        _ => return Err(ApiError::NotFound("action")),
    })
}

/// `POST /identity/users/{id}/{unlock|reset-password|disable|enable|revoke-sessions|remove-groups}`.
pub async fn act(State(st): State<Arc<AppState>>, u: User, Path((id, name)): Path<(Uuid, String)>, body: Option<Json<ActionIn>>) -> ApiResult<Response> {
    let t = crate::identity::target(&st.db, id).await?.filter(|t| u.can_see_client(t.client_id)).ok_or(ApiError::NotFound("directory user"))?;
    let action = parse_action(&name, body.map(|b| b.0).unwrap_or_default())?;
    manage_gate(&st, &u, t.client_id)?;
    let out = crate::identity::act(&st, &u, &t, action, "users").await?;
    Ok(([(header::CACHE_CONTROL, "no-store")], Json(out)).into_response())
}

#[derive(Serialize, sqlx::FromRow)]
pub struct GroupRow {
    id: Uuid,
    source_id: Uuid,
    source_name: String,
    name: String,
    description: String,
    privileged: bool,
    members: i64,
}

pub async fn list_groups(State(st): State<Arc<AppState>>, u: User, Path(client): Path<Uuid>) -> ApiResult<Json<Vec<GroupRow>>> {
    read_gate(&u, client)?;
    Ok(Json(
        sqlx::query_as(
            "SELECT g.id, g.source_id, s.name AS source_name, g.name, g.description, g.privileged,
                    (SELECT count(*) FROM identity_group_members m WHERE m.group_id = g.id) AS members
               FROM identity_groups g JOIN identity_sources s ON s.id = g.source_id
              WHERE s.client_id = $1 AND g.deleted_at IS NULL ORDER BY lower(g.name), g.id",
        )
        .bind(client)
        .fetch_all(&st.db)
        .await?,
    ))
}

// ---------------------------------------------------------------------------------------------
// Intune devices
// ---------------------------------------------------------------------------------------------

#[derive(Serialize, sqlx::FromRow)]
pub struct DeviceRow {
    id: Uuid,
    source_id: Uuid,
    source_name: String,
    external_id: String,
    name: String,
    user_upn: String,
    os: String,
    os_version: String,
    compliance: String,
    encrypted: Option<bool>,
    ownership: String,
    serial: String,
    model: String,
    manufacturer: String,
    enrolled_at: Option<DateTime<Utc>>,
    last_sync_at: Option<DateTime<Utc>>,
    agent_id: Option<Uuid>,
    agent_hostname: Option<String>,
    agent_online: Option<bool>,
    synced_at: DateTime<Utc>,
    #[sqlx(default)]
    #[serde(skip)]
    sort_key: String,
}

const DEVICE_COLS: &str = "d.id, d.source_id, s.name AS source_name, d.external_id, d.name, d.user_upn, d.os, d.os_version, d.compliance, d.encrypted,
       d.ownership, d.serial, d.model, d.manufacturer, d.enrolled_at, d.last_sync_at, d.agent_id, a.hostname AS agent_hostname,
       a.online AS agent_online, d.synced_at";
const DEVICE_FROM: &str = "FROM mdm_devices d JOIN identity_sources s ON s.id = d.source_id LEFT JOIN agents a ON a.id = d.agent_id";

const DEVICE_SORT: &[SortKey] = &[
    SortKey { name: "name", expr: "lower(d.name)", ty: "text" },
    SortKey { name: "last_sync", expr: "coalesce(d.last_sync_at, 'epoch'::timestamptz)", ty: "timestamptz" },
    SortKey {
        name: "compliance",
        expr: "(CASE d.compliance WHEN 'noncompliant' THEN 0 WHEN 'error' THEN 1 WHEN 'conflict' THEN 2 WHEN 'inGracePeriod' THEN 3 WHEN 'unknown' THEN 4 ELSE 5 END)",
        ty: "int",
    },
    SortKey { name: "user", expr: "lower(d.user_upn)", ty: "text" },
];

#[derive(Deserialize)]
pub struct DevicesQuery {
    /// Comma-separated compliance states.
    compliance: Option<String>,
    os: Option<String>,
    /// Only devices with no matching agent.
    unmatched: Option<bool>,
    q: Option<String>,
}

pub async fn list_devices(
    State(st): State<Arc<AppState>>,
    u: User,
    Path(client): Path<Uuid>,
    Query(q): Query<DevicesQuery>,
    Query(page): Query<PageQuery>,
) -> ApiResult<Json<Page<DeviceRow>>> {
    read_gate(&u, client)?;
    let plan = Plan::new(DEVICE_SORT, ("name", false), &page, "d.id", "uuid", 6)?;
    let compliance: Option<Vec<String>> = q.compliance.as_deref().filter(|s| !s.is_empty()).map(|s| s.split(',').map(|c| c.trim().to_string()).collect());
    let os = q.os.as_deref().map(str::trim).filter(|s| !s.is_empty());
    let search = q.q.as_deref().map(str::trim).filter(|s| !s.is_empty()).map(String::from);
    let filters = format!(
        "{DEVICE_FROM} WHERE s.client_id = $1 AND ($2::text[] IS NULL OR d.compliance = ANY($2)) AND ($3::text IS NULL OR lower(d.os) = lower($3))
           AND ($4::bool IS NULL OR (d.agent_id IS NULL) = $4)
           AND ($5::text IS NULL OR d.name ILIKE '%' || $5 || '%' OR d.user_upn ILIKE '%' || $5 || '%' OR d.serial ILIKE '%' || $5 || '%')"
    );
    macro_rules! bind_filters {
        ($query:expr) => {
            $query.bind(client).bind(&compliance).bind(os).bind(q.unmatched).bind(&search)
        };
    }
    let sql = format!("SELECT {DEVICE_COLS}, {} {filters} {} {} {}", plan.key_select, plan.keyset, plan.order, plan.limit_sql());
    let mut rows = bind_filters!(sqlx::query_as::<_, DeviceRow>(AssertSqlSafe(sql)));
    if let Some((k, id)) = &plan.cursor {
        rows = rows.bind(k).bind(id);
    }
    let rows = rows.fetch_all(&st.db).await?;
    let total: i64 = bind_filters!(sqlx::query_scalar(AssertSqlSafe(paging::count_sql(&filters)))).fetch_one(&st.db).await?;
    Ok(Json(plan.finish(rows, |r| (r.sort_key.clone(), r.id.to_string()), total)))
}

pub async fn get_device(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<DeviceRow>> {
    let client: Option<Uuid> =
        sqlx::query_scalar("SELECT s.client_id FROM mdm_devices d JOIN identity_sources s ON s.id = d.source_id WHERE d.id = $1").bind(id).fetch_optional(&st.db).await?;
    let client = client.filter(|c| u.can_see_client(*c)).ok_or(ApiError::NotFound("device"))?;
    read_gate(&u, client)?;
    Ok(Json(sqlx::query_as(AssertSqlSafe(format!("SELECT {DEVICE_COLS} {DEVICE_FROM} WHERE d.id = $1"))).bind(id).fetch_one(&st.db).await?))
}

#[derive(Serialize, sqlx::FromRow)]
struct AgentGap {
    id: Uuid,
    hostname: String,
    os_family: String,
    online: bool,
    last_seen_at: Option<DateTime<Utc>>,
}

/// Counts by compliance, and the two gap lists' sizes and the agents not in Intune.
pub async fn devices_summary(State(st): State<Arc<AppState>>, u: User, Path(client): Path<Uuid>) -> ApiResult<Json<Value>> {
    read_gate(&u, client)?;
    let sources: i64 = sqlx::query_scalar("SELECT count(*) FROM identity_sources WHERE client_id = $1 AND kind = 'entra' AND sync_devices")
        .bind(client)
        .fetch_one(&st.db)
        .await?;
    let by: Vec<(String, i64)> = sqlx::query_as(
        "SELECT d.compliance, count(*) FROM mdm_devices d JOIN identity_sources s ON s.id = d.source_id WHERE s.client_id = $1 GROUP BY 1 ORDER BY 1",
    )
    .bind(client)
    .fetch_all(&st.db)
    .await?;
    let unmatched: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM mdm_devices d JOIN identity_sources s ON s.id = d.source_id WHERE s.client_id = $1 AND d.agent_id IS NULL",
    )
    .bind(client)
    .fetch_one(&st.db)
    .await?;
    // Windows and macOS workstations Intune would normally have; servers and Linux aren't expected.
    let gaps: Vec<AgentGap> = if sources == 0 {
        vec![]
    } else {
        sqlx::query_as(
            "SELECT a.id, a.hostname, a.os_family, a.online, a.last_seen_at FROM agents a JOIN sites si ON si.id = a.site_id
              WHERE si.client_id = $1 AND a.os_family IN ('windows', 'macos') AND coalesce(a.platform, 'workstation') = 'workstation'
                AND NOT EXISTS (SELECT 1 FROM mdm_devices d WHERE d.agent_id = a.id)
              ORDER BY lower(a.hostname) LIMIT 500",
        )
        .bind(client)
        .fetch_all(&st.db)
        .await?
    };
    let total: i64 = by.iter().map(|b| b.1).sum();
    Ok(Json(json!({
        "sources": sources,
        "total": total,
        "by_compliance": by.into_iter().collect::<std::collections::BTreeMap<_, _>>(),
        "unmatched": unmatched,
        "agents_not_in_intune": gaps,
    })))
}
