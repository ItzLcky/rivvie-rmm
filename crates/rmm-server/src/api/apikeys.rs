//! Managing API keys and service accounts. Dashboard sessions only: API keys can't reach
//! these routes (they aren't in the public registry) and can't mint other keys.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, Query, State};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::apikeys;
use crate::auth::{self, Perm, Role, User};
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

#[derive(Serialize, sqlx::FromRow)]
pub struct KeyView {
    id: Uuid,
    name: String,
    /// The start of the key, to tell keys apart.
    prefix: String,
    owner_id: Uuid,
    owner_name: String,
    service_account: bool,
    /// read or write.
    access: String,
    scopes: Vec<String>,
    permissions: Vec<String>,
    /// null: every client the owner can see.
    client_ids: Option<Vec<Uuid>>,
    rate_limit_per_min: i32,
    expires_at: Option<DateTime<Utc>>,
    last_used_at: Option<DateTime<Utc>>,
    last_used_ip: Option<String>,
    revoked_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
    created_by_name: Option<String>,
    /// active / expired / revoked
    status: String,
}

const SELECT: &str = "SELECT k.id, k.name, k.prefix, k.owner_id, o.name AS owner_name, o.service_account, k.access, k.scopes, k.permissions,
       k.client_ids, k.rate_limit_per_min, k.expires_at, k.last_used_at, k.last_used_ip, k.revoked_at, k.created_at,
       cb.name AS created_by_name,
       (CASE WHEN k.revoked_at IS NOT NULL THEN 'revoked' WHEN k.expires_at <= now() THEN 'expired' ELSE 'active' END) AS status
  FROM api_keys k JOIN users o ON o.id = k.owner_id LEFT JOIN users cb ON cb.id = k.created_by";

fn session_only(u: &User) -> ApiResult<()> {
    if u.api_key.is_some() { Err(ApiError::Forbidden) } else { Ok(()) }
}

#[derive(Deserialize)]
pub struct ListQuery {
    /// Admins: every key, including the service accounts'.
    #[serde(default)]
    all: bool,
}

pub async fn list(State(st): State<Arc<AppState>>, u: User, Query(q): Query<ListQuery>) -> ApiResult<Json<Vec<KeyView>>> {
    session_only(&u)?;
    if q.all {
        u.require(Role::Admin)?;
    }
    let rows = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "{SELECT} WHERE ($1 OR k.owner_id = $2) ORDER BY (k.revoked_at IS NOT NULL), k.created_at DESC LIMIT 500"
    )))
    .bind(q.all)
    .bind(u.id)
    .fetch_all(&st.db)
    .await?;
    Ok(Json(rows))
}

#[derive(Deserialize)]
pub struct OptionsQuery {
    owner_id: Option<Uuid>,
}

/// What a key can be limited to for an owner: the resource groups, and the named permissions
/// the owner holds (a key can only carry those).
pub async fn options(State(st): State<Arc<AppState>>, u: User, Query(q): Query<OptionsQuery>) -> ApiResult<Json<Value>> {
    session_only(&u)?;
    let owner = owner_of(&st, &u, q.owner_id).await?;
    Ok(Json(json!({
        "groups": apikeys::GROUPS.iter().map(|(id, label)| json!({ "id": id, "label": label })).collect::<Vec<_>>(),
        "permissions": owner.effective_permissions(),
        "can_write": owner.role() >= Role::Technician,
        "default_rate_limit": apikeys::DEFAULT_RATE,
    })))
}

/// Who a new key acts as: the signed-in user, or (admins) a service account.
async fn owner_of(st: &AppState, u: &User, owner_id: Option<Uuid>) -> ApiResult<User> {
    let Some(id) = owner_id.filter(|id| *id != u.id) else { return Ok(u.clone()) };
    u.require(Role::Admin)?;
    sqlx::query_as(concat!(
        "SELECT ",
        auth::user_columns!("$2", "$3::uuid"),
        " FROM users u WHERE u.id = $1 AND u.service_account AND NOT u.disabled"
    ))
    .bind(id)
    .bind(st.company().require_2fa_all)
    .bind(Uuid::nil())
    .fetch_optional(&st.db)
    .await?
    .ok_or_else(|| ApiError::BadRequest("keys for other people can't be created: pick a service account".into()))
}

#[derive(Deserialize)]
pub struct NewKey {
    name: String,
    /// `read` or `write`.
    access: String,
    scopes: Vec<String>,
    /// Named permissions (see Company settings → Users) the key carries; the owner must hold them.
    #[serde(default)]
    permissions: Vec<String>,
    /// Limit to these clients (the owner must see them); null for all the owner sees.
    client_ids: Option<Vec<Uuid>>,
    /// null: the key doesn't expire.
    expires_in_days: Option<i32>,
    rate_limit_per_min: Option<i32>,
    /// Admins: a service account to act as.
    owner_id: Option<Uuid>,
}

pub async fn create(State(st): State<Arc<AppState>>, u: User, Json(b): Json<NewKey>) -> ApiResult<Json<Value>> {
    session_only(&u)?;
    let owner = owner_of(&st, &u, b.owner_id).await?;
    let name = b.name.trim();
    if name.is_empty() || name.chars().count() > 100 {
        return Err(ApiError::BadRequest("name the key (1-100 characters)".into()));
    }
    if !matches!(b.access.as_str(), "read" | "write") {
        return Err(ApiError::BadRequest("access must be read or write".into()));
    }
    if b.access == "write" && owner.role() < Role::Technician {
        return Err(ApiError::BadRequest("a read-only account can't have a key with write access".into()));
    }
    let mut scopes: Vec<String> = Vec::new();
    for s in &b.scopes {
        if !apikeys::valid_group(s) {
            return Err(ApiError::BadRequest(format!("unknown scope {s}")));
        }
        if !scopes.contains(s) {
            scopes.push(s.clone());
        }
    }
    if scopes.is_empty() {
        return Err(ApiError::BadRequest("choose at least one scope".into()));
    }
    let mut permissions: Vec<String> = Vec::new();
    for p in &b.permissions {
        let perm = Perm::parse(p).ok_or_else(|| ApiError::BadRequest(format!("unknown permission {p}")))?;
        if !owner.has(perm) {
            return Err(ApiError::BadRequest(format!("{} doesn't hold {p}, so a key can't either", owner.name)));
        }
        if !permissions.contains(p) {
            permissions.push(p.clone());
        }
    }
    let client_ids = match &b.client_ids {
        None => None,
        Some(ids) => {
            let mut ids = ids.clone();
            ids.sort();
            ids.dedup();
            if ids.is_empty() {
                return Err(ApiError::BadRequest("choose at least one client, or leave it open to all of the owner's".into()));
            }
            if let Some(c) = ids.iter().find(|c| !owner.can_see_client(**c)) {
                return Err(ApiError::BadRequest(format!("{} can't see client {c}, so a key can't either", owner.name)));
            }
            let known: i64 = sqlx::query_scalar("SELECT count(*) FROM clients WHERE id = ANY($1)").bind(&ids).fetch_one(&st.db).await?;
            if known != ids.len() as i64 {
                return Err(ApiError::NotFound("client"));
            }
            Some(ids)
        }
    };
    if b.expires_in_days.is_some_and(|d| !(1..=3650).contains(&d)) {
        return Err(ApiError::BadRequest("expiry must be 1-3650 days".into()));
    }
    let rate = b.rate_limit_per_min.unwrap_or(apikeys::DEFAULT_RATE);
    if !(1..=100_000).contains(&rate) {
        return Err(ApiError::BadRequest("the rate limit must be 1-100000 requests per minute".into()));
    }
    let active: i64 = sqlx::query_scalar("SELECT count(*) FROM api_keys WHERE owner_id = $1 AND revoked_at IS NULL").bind(owner.id).fetch_one(&st.db).await?;
    if active >= 100 {
        return Err(ApiError::BadRequest("100 active keys is the limit: revoke some first".into()));
    }

    let (token, hash, prefix) = apikeys::generate();
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO api_keys (id, owner_id, name, prefix, token_hash, access, scopes, permissions, client_ids, rate_limit_per_min, expires_at, created_by)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
    )
    .bind(id)
    .bind(owner.id)
    .bind(name)
    .bind(&prefix)
    .bind(&hash)
    .bind(&b.access)
    .bind(&scopes)
    .bind(&permissions)
    .bind(&client_ids)
    .bind(rate)
    .bind(b.expires_in_days.map(|d| Utc::now() + Duration::days(i64::from(d))))
    .bind(u.id)
    .execute(&st.db)
    .await?;
    auth::audit(
        &st.db,
        Some(u.id),
        "api_key.create",
        Some(("api_key", id)),
        json!({ "name": name, "prefix": prefix, "owner": owner.id, "access": b.access, "scopes": scopes, "permissions": permissions,
                "clients": client_ids.as_ref().map(Vec::len), "expires_in_days": b.expires_in_days }),
    )
    .await;
    let key: KeyView = sqlx::query_as(sqlx::AssertSqlSafe(format!("{SELECT} WHERE k.id = $1"))).bind(id).fetch_one(&st.db).await?;
    // The only time the secret is shown: only its hash is kept.
    Ok(Json(json!({ "key": key, "token": token })))
}

pub async fn revoke(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    session_only(&u)?;
    let row: Option<(String, String)> = sqlx::query_as(
        "UPDATE api_keys SET revoked_at = now(), revoked_by = $2
          WHERE id = $1 AND revoked_at IS NULL AND (owner_id = $2 OR $3) RETURNING name, prefix",
    )
    .bind(id)
    .bind(u.id)
    .bind(u.role() == Role::Admin)
    .fetch_optional(&st.db)
    .await?;
    let (name, prefix) = row.ok_or(ApiError::NotFound("API key"))?;
    auth::audit(&st.db, Some(u.id), "api_key.revoke", Some(("api_key", id)), json!({ "name": name, "prefix": prefix })).await;
    Ok(Json(json!({ "ok": true })))
}

// ---------------------------------------------------------------------------
// Service accounts
// ---------------------------------------------------------------------------

#[derive(Serialize, sqlx::FromRow)]
pub struct ServiceAccount {
    id: Uuid,
    name: String,
    role: String,
    disabled: bool,
    all_clients: bool,
    client_ids: Vec<Uuid>,
    keys: i64,
    created_at: DateTime<Utc>,
}

pub async fn service_accounts(State(st): State<Arc<AppState>>, u: User) -> ApiResult<Json<Vec<ServiceAccount>>> {
    session_only(&u)?;
    u.require(Role::Admin)?;
    Ok(Json(
        sqlx::query_as(
            "SELECT u.id, u.name, u.role, u.disabled, u.all_clients, ARRAY(SELECT client_id FROM user_clients WHERE user_id = u.id) AS client_ids,
                    (SELECT count(*) FROM api_keys k WHERE k.owner_id = u.id AND k.revoked_at IS NULL) AS keys, u.created_at
               FROM users u WHERE u.service_account ORDER BY lower(u.name)",
        )
        .fetch_all(&st.db)
        .await?,
    ))
}

#[derive(Deserialize)]
pub struct NewServiceAccount {
    name: String,
    /// technician or readonly: service accounts are never admins.
    role: String,
    #[serde(default)]
    all_clients: bool,
    #[serde(default)]
    client_ids: Vec<Uuid>,
}

/// A user that can't sign in, to own keys. What it may see is its client access and, as for
/// anyone, its role and permission set (Company settings → Users).
pub async fn create_service_account(State(st): State<Arc<AppState>>, u: User, Json(b): Json<NewServiceAccount>) -> ApiResult<Json<Value>> {
    session_only(&u)?;
    u.require(Role::Admin)?;
    let name = b.name.trim();
    if name.is_empty() || name.chars().count() > 100 {
        return Err(ApiError::BadRequest("name the service account (1-100 characters)".into()));
    }
    if !matches!(b.role.as_str(), "technician" | "readonly") {
        return Err(ApiError::BadRequest("a service account is a technician or read-only".into()));
    }
    if !b.all_clients && b.client_ids.is_empty() {
        return Err(ApiError::BadRequest("choose its clients, or all of them".into()));
    }
    let id = Uuid::new_v4();
    let mut tx = st.db.begin().await?;
    // `!` is not a password hash: nothing verifies against it, so there is no sign-in.
    sqlx::query("INSERT INTO users (id, email, name, password_hash, role, all_clients, service_account) VALUES ($1, $2, $3, '!', $4, $5, true)")
        .bind(id)
        .bind(format!("svc-{}@service-account.invalid", &id.simple().to_string()[..8]))
        .bind(name)
        .bind(&b.role)
        .bind(b.all_clients)
        .execute(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO user_clients (user_id, client_id) SELECT $1, c FROM unnest($2::uuid[]) c ON CONFLICT DO NOTHING")
        .bind(id)
        .bind(&b.client_ids)
        .execute(&mut *tx)
        .await
        .map_err(|e| match e {
            sqlx::Error::Database(d) if d.is_foreign_key_violation() => ApiError::NotFound("client"),
            e => e.into(),
        })?;
    tx.commit().await?;
    auth::audit(
        &st.db,
        Some(u.id),
        "service_account.create",
        Some(("user", id)),
        json!({ "name": name, "role": b.role, "all_clients": b.all_clients, "clients": b.client_ids.len() }),
    )
    .await;
    Ok(Json(json!({ "id": id })))
}

/// Disables the account and revokes its keys.
pub async fn remove_service_account(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    session_only(&u)?;
    u.require(Role::Admin)?;
    let mut tx = st.db.begin().await?;
    let n = sqlx::query("UPDATE users SET disabled = true WHERE id = $1 AND service_account").bind(id).execute(&mut *tx).await?.rows_affected();
    if n == 0 {
        return Err(ApiError::NotFound("service account"));
    }
    let keys = sqlx::query("UPDATE api_keys SET revoked_at = now(), revoked_by = $2 WHERE owner_id = $1 AND revoked_at IS NULL")
        .bind(id)
        .bind(u.id)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    tx.commit().await?;
    auth::audit(&st.db, Some(u.id), "service_account.remove", Some(("user", id)), json!({ "keys_revoked": keys })).await;
    Ok(Json(json!({ "ok": true })))
}
