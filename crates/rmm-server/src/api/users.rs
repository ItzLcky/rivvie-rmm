use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use crate::auth::{self, Role, User};
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

#[derive(Serialize, sqlx::FromRow)]
pub struct UserRow {
    id: Uuid,
    email: String,
    name: String,
    role: String,
    disabled: bool,
    totp_enabled: bool,
    created_at: DateTime<Utc>,
    last_login_at: Option<DateTime<Utc>>,
    /// Ignored for admins, who always see every client.
    all_clients: bool,
    client_ids: Vec<Uuid>,
    /// Explicit permission set; null = the role's defaults.
    permissions: Option<Vec<String>>,
    /// May sign in with a password when SSO is required.
    sso_exempt: bool,
    /// Created by SSO, with no password.
    sso_only: bool,
    /// Passkeys registered.
    passkeys: i64,
    /// Identity providers the account is linked to.
    sso_providers: Vec<String>,
    /// Can't sign in; owns API keys (Company settings → API).
    service_account: bool,
}

pub async fn list(State(st): State<Arc<AppState>>, u: User) -> ApiResult<Json<Vec<UserRow>>> {
    u.require(Role::Admin)?;
    Ok(Json(
        sqlx::query_as(
            "SELECT id, email, name, role, disabled, totp_secret IS NOT NULL AS totp_enabled, created_at, last_login_at,
                    all_clients, ARRAY(SELECT client_id FROM user_clients WHERE user_id = users.id) AS client_ids, permissions,
                    sso_exempt, sso_only, (SELECT count(*) FROM user_passkeys k WHERE k.user_id = users.id) AS passkeys,
                    ARRAY(SELECT p.name FROM user_identities i JOIN sso_providers p ON p.id = i.provider_id WHERE i.user_id = users.id ORDER BY p.name) AS sso_providers,
                    service_account
               FROM users ORDER BY email",
        )
        .fetch_all(&st.db)
        .await?,
    ))
}

#[derive(Deserialize)]
pub struct NewUser {
    email: String,
    name: String,
    password: String,
    role: String,
    #[serde(flatten)]
    access: Option<Access>,
}

pub async fn create(State(st): State<Arc<AppState>>, u: User, Json(b): Json<NewUser>) -> ApiResult<Json<serde_json::Value>> {
    u.require(Role::Admin)?;
    let role = Role::parse(&b.role).ok_or_else(|| ApiError::BadRequest("role must be admin, technician or readonly".into()))?;
    let id = create_user(&st.db, &b.email, &b.name, &b.password, role).await?;
    if let Some(access) = &b.access {
        let mut tx = st.db.begin().await?;
        set_access(&mut tx, id, access).await?;
        tx.commit().await?;
    }
    auth::audit(
        &st.db,
        Some(u.id),
        "user.create",
        Some(("user", id)),
        json!({ "email": b.email, "role": b.role, "all_clients": b.access.as_ref().map(|a| a.all_clients), "clients": b.access.as_ref().map(|a| a.client_ids.len()) }),
    )
    .await;
    Ok(Json(json!({ "id": id })))
}

#[derive(Deserialize)]
pub struct Access {
    all_clients: bool,
    #[serde(default)]
    client_ids: Vec<Uuid>,
}

async fn set_access(tx: &mut sqlx::PgConnection, user_id: Uuid, a: &Access) -> ApiResult<()> {
    let n = sqlx::query("UPDATE users SET all_clients = $2 WHERE id = $1")
        .bind(user_id)
        .bind(a.all_clients)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    if n == 0 {
        return Err(ApiError::NotFound("user"));
    }
    sqlx::query("DELETE FROM user_clients WHERE user_id = $1").bind(user_id).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO user_clients (user_id, client_id) SELECT $1, c FROM unnest($2::uuid[]) c ON CONFLICT DO NOTHING")
        .bind(user_id)
        .bind(&a.client_ids)
        .execute(&mut *tx)
        .await
        .map_err(|e| match e {
            sqlx::Error::Database(d) if d.is_foreign_key_violation() => ApiError::NotFound("client"),
            e => e.into(),
        })?;
    Ok(())
}

/// Which clients a non-admin user can see. Takes effect on their next request.
pub async fn update_access(
    State(st): State<Arc<AppState>>,
    u: User,
    Path(id): Path<Uuid>,
    Json(b): Json<Access>,
) -> ApiResult<Json<serde_json::Value>> {
    u.require(Role::Admin)?;
    let mut tx = st.db.begin().await?;
    set_access(&mut tx, id, &b).await?;
    tx.commit().await?;
    auth::audit(
        &st.db,
        Some(u.id),
        "user.access_update",
        Some(("user", id)),
        json!({ "all_clients": b.all_clients, "client_ids": b.client_ids }),
    )
    .await;
    Ok(Json(json!({ "ok": true })))
}

pub async fn create_user(db: &sqlx::PgPool, email: &str, name: &str, password: &str, role: Role) -> ApiResult<Uuid> {
    let email = email.trim().to_lowercase();
    if !email.contains('@') {
        return Err(ApiError::BadRequest("invalid email".into()));
    }
    let hash = auth::hash_password_async(password).await?;
    let role = match role {
        Role::Admin => "admin",
        Role::Technician => "technician",
        Role::Readonly => "readonly",
    };
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO users (id, email, name, password_hash, role) VALUES ($1,$2,$3,$4,$5)")
        .bind(id)
        .bind(&email)
        .bind(name.trim())
        .bind(hash)
        .bind(role)
        .execute(db)
        .await?;
    Ok(id)
}

pub async fn disable(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<serde_json::Value>> {
    u.require(Role::Admin)?;
    if id == u.id {
        return Err(ApiError::BadRequest("you cannot disable yourself".into()));
    }
    let mut tx = st.db.begin().await?;
    sqlx::query("UPDATE users SET disabled = true WHERE id = $1").bind(id).execute(&mut *tx).await?;
    sqlx::query("DELETE FROM user_sessions WHERE user_id = $1").bind(id).execute(&mut *tx).await?;
    // With SSO required, the last break-glass admin has to stay able to sign in.
    super::sso::lockout_check(&mut tx).await?;
    tx.commit().await?;
    auth::audit(&st.db, Some(u.id), "user.disable", Some(("user", id)), json!({})).await;
    Ok(Json(json!({ "ok": true })))
}

pub async fn enable(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<serde_json::Value>> {
    u.require(Role::Admin)?;
    let n = sqlx::query("UPDATE users SET disabled = false WHERE id = $1").bind(id).execute(&st.db).await?.rows_affected();
    if n == 0 {
        return Err(ApiError::NotFound("user"));
    }
    auth::audit(&st.db, Some(u.id), "user.enable", Some(("user", id)), json!({})).await;
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
pub struct ResetPassword {
    password: String,
}

/// Admin sets a new password for someone else and signs them out everywhere.
/// Your own password goes through /auth/password, which asks for the current one.
pub async fn reset_password(
    State(st): State<Arc<AppState>>,
    u: User,
    Path(id): Path<Uuid>,
    Json(b): Json<ResetPassword>,
) -> ApiResult<Json<serde_json::Value>> {
    u.require(Role::Admin)?;
    if id == u.id {
        return Err(ApiError::BadRequest("use Account → Change password for your own account".into()));
    }
    let hash = auth::hash_password_async(&b.password).await?;
    let mut tx = st.db.begin().await?;
    let n = sqlx::query("UPDATE users SET password_hash = $2, sso_only = false WHERE id = $1 AND NOT service_account")
        .bind(id)
        .bind(hash)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    if n == 0 {
        return Err(ApiError::NotFound("user"));
    }
    sqlx::query("DELETE FROM user_sessions WHERE user_id = $1").bind(id).execute(&mut *tx).await?;
    tx.commit().await?;
    auth::audit(&st.db, Some(u.id), "user.password_reset", Some(("user", id)), json!({})).await;
    Ok(Json(json!({ "ok": true })))
}

/// Admin removes someone's 2FA (lost phone) and signs them out everywhere. If 2FA is
/// required for them, they set it up again on their next sign-in.
pub async fn reset_totp(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<serde_json::Value>> {
    u.require(Role::Admin)?;
    if id == u.id {
        return Err(ApiError::BadRequest("use Account → Two-factor authentication for your own account".into()));
    }
    let mut tx = st.db.begin().await?;
    if super::totp::clear(&mut tx, id).await? == 0 {
        return Err(ApiError::NotFound("user"));
    }
    sqlx::query("DELETE FROM user_sessions WHERE user_id = $1").bind(id).execute(&mut *tx).await?;
    tx.commit().await?;
    auth::audit(&st.db, Some(u.id), "user.mfa_reset", Some(("user", id)), json!({})).await;
    Ok(Json(json!({ "ok": true })))
}

pub async fn sessions(
    State(st): State<Arc<AppState>>,
    u: User,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Vec<super::auth::SessionRow>>> {
    u.require(Role::Admin)?;
    Ok(Json(super::auth::sessions_for(&st, id, u.session_id).await?))
}

pub async fn revoke_sessions(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<serde_json::Value>> {
    u.require(Role::Admin)?;
    // Your own current session is kept so this can't lock you out mid-click.
    let n = sqlx::query("DELETE FROM user_sessions WHERE user_id = $1 AND id <> $2")
        .bind(id)
        .bind(u.session_id)
        .execute(&st.db)
        .await?
        .rows_affected();
    auth::audit(&st.db, Some(u.id), "user.sessions_revoke", Some(("user", id)), json!({ "count": n })).await;
    Ok(Json(json!({ "ok": true, "revoked": n })))
}

pub async fn revoke_session(
    State(st): State<Arc<AppState>>,
    u: User,
    Path((id, sid)): Path<(Uuid, Uuid)>,
) -> ApiResult<Json<serde_json::Value>> {
    u.require(Role::Admin)?;
    let n = sqlx::query("DELETE FROM user_sessions WHERE id = $1 AND user_id = $2")
        .bind(sid)
        .bind(id)
        .execute(&st.db)
        .await?
        .rows_affected();
    if n == 0 {
        return Err(ApiError::NotFound("session"));
    }
    auth::audit(&st.db, Some(u.id), "user.session_revoke", Some(("user", id)), json!({ "session": sid })).await;
    Ok(Json(json!({ "ok": true })))
}

#[derive(Serialize, sqlx::FromRow)]
pub struct AuditRow {
    pub(super) id: i64,
    ts: DateTime<Utc>,
    user_name: Option<String>,
    action: String,
    target_type: Option<String>,
    target_id: Option<Uuid>,
    details: serde_json::Value,
    #[sqlx(default)]
    #[serde(skip)]
    pub(super) sort_key: String,
}

#[derive(Deserialize)]
pub struct Permissions {
    /// null = back to the role's defaults.
    permissions: Option<Vec<String>>,
}

/// Gives a user an explicit permission set (admins only; admins always hold everything).
pub async fn update_permissions(
    State(st): State<Arc<AppState>>,
    u: User,
    Path(id): Path<Uuid>,
    Json(b): Json<Permissions>,
) -> ApiResult<Json<serde_json::Value>> {
    u.require(Role::Admin)?;
    let perms: Option<Vec<String>> = match b.permissions {
        Some(list) => {
            let mut out = Vec::new();
            for p in list {
                let p = auth::Perm::parse(&p).ok_or_else(|| ApiError::BadRequest(format!("unknown permission {p}")))?;
                if !out.contains(&p.as_str().to_string()) {
                    out.push(p.as_str().to_string());
                }
            }
            Some(out)
        }
        None => None,
    };
    let n = sqlx::query("UPDATE users SET permissions = $2 WHERE id = $1").bind(id).bind(&perms).execute(&st.db).await?.rows_affected();
    if n == 0 {
        return Err(ApiError::NotFound("user"));
    }
    auth::audit(&st.db, Some(u.id), "user.permissions", Some(("user", id)), json!({ "permissions": perms })).await;
    Ok(Json(json!({ "ok": true, "permissions": perms })))
}
