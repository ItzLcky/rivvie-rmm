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
    created_at: DateTime<Utc>,
    last_login_at: Option<DateTime<Utc>>,
}

pub async fn list(State(st): State<Arc<AppState>>, u: User) -> ApiResult<Json<Vec<UserRow>>> {
    u.require(Role::Admin)?;
    Ok(Json(
        sqlx::query_as("SELECT id, email, name, role, disabled, created_at, last_login_at FROM users ORDER BY email")
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
}

pub async fn create(State(st): State<Arc<AppState>>, u: User, Json(b): Json<NewUser>) -> ApiResult<Json<serde_json::Value>> {
    u.require(Role::Admin)?;
    let role = Role::parse(&b.role).ok_or_else(|| ApiError::BadRequest("role must be admin, technician or readonly".into()))?;
    let id = create_user(&st.db, &b.email, &b.name, &b.password, role).await?;
    auth::audit(&st.db, Some(u.id), "user.create", Some(("user", id)), json!({ "email": b.email, "role": b.role })).await;
    Ok(Json(json!({ "id": id })))
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
    let n = sqlx::query("UPDATE users SET password_hash = $2 WHERE id = $1")
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
    id: i64,
    ts: DateTime<Utc>,
    user_name: Option<String>,
    action: String,
    target_type: Option<String>,
    target_id: Option<Uuid>,
    details: serde_json::Value,
}

pub async fn audit_log(State(st): State<Arc<AppState>>, u: User) -> ApiResult<Json<Vec<AuditRow>>> {
    u.require(Role::Admin)?;
    Ok(Json(
        sqlx::query_as(
            "SELECT l.id, l.ts, u.name AS user_name, l.action, l.target_type, l.target_id, l.details
               FROM audit_log l LEFT JOIN users u ON u.id = l.user_id
              ORDER BY l.ts DESC LIMIT 500",
        )
        .fetch_all(&st.db)
        .await?,
    ))
}
