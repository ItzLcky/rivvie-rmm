//! Passkeys (WebAuthn credentials) as a second factor beside TOTP: register, list, rename,
//! remove, and the sign-in step that asks for one. Recovery codes work for either factor.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;
use webauthn_rs::prelude::{Passkey, PublicKeyCredential, RegisterPublicKeyCredential};

use crate::auth::{self, User};
use crate::error::{ApiError, ApiResult};
use crate::ratelimit::ClientIp;
use crate::state::AppState;

const MAX_PER_USER: i64 = 10;

fn unavailable() -> ApiError {
    ApiError::BadRequest("passkeys need RMM_PUBLIC_URL to be a host name (not an IP address)".into())
}

/// Registering or removing a passkey asks for the password, like setting up TOTP does.
async fn confirm_password(st: &AppState, u: &User, password: &str) -> ApiResult<()> {
    if u.sso_only {
        return Err(ApiError::BadRequest("this account signs in with single sign-on and has no password, so it has no use for a second factor".into()));
    }
    super::totp::verify_password(st, u, password).await
}

#[derive(Serialize, sqlx::FromRow)]
pub struct Row {
    id: Uuid,
    name: String,
    created_at: DateTime<Utc>,
    last_used_at: Option<DateTime<Utc>>,
}

pub async fn list(State(st): State<Arc<AppState>>, u: User) -> ApiResult<Json<serde_json::Value>> {
    let rows: Vec<Row> = sqlx::query_as("SELECT id, name, created_at, last_used_at FROM user_passkeys WHERE user_id = $1 ORDER BY created_at")
        .bind(u.id)
        .fetch_all(&st.db)
        .await?;
    let (codes,): (i64,) = sqlx::query_as("SELECT count(*) FROM user_recovery_codes WHERE user_id = $1").bind(u.id).fetch_one(&st.db).await?;
    Ok(Json(json!({ "available": st.passkeys.webauthn.is_some(), "passkeys": rows, "recovery_codes_left": codes, "sso_only": u.sso_only })))
}

#[derive(Deserialize)]
pub struct Start {
    password: String,
}

pub async fn register_start(State(st): State<Arc<AppState>>, u: User, Json(b): Json<Start>) -> ApiResult<Json<serde_json::Value>> {
    let wa = st.passkeys.webauthn.as_ref().ok_or_else(unavailable)?;
    confirm_password(&st, &u, &b.password).await?;
    let stored: Vec<(Vec<u8>, serde_json::Value)> =
        sqlx::query_as("SELECT credential_id, passkey FROM user_passkeys WHERE user_id = $1").bind(u.id).fetch_all(&st.db).await?;
    if stored.len() as i64 >= MAX_PER_USER {
        return Err(ApiError::BadRequest(format!("at most {MAX_PER_USER} passkeys per account")));
    }
    // The browser refuses to register an authenticator that already holds one of these.
    let exclude = stored.iter().filter_map(|(_, p)| serde_json::from_value::<Passkey>(p.clone()).ok()).map(|p| p.cred_id().clone()).collect::<Vec<_>>();
    let (options, state) = wa
        .start_passkey_registration(u.id, &u.email, &u.name, Some(exclude).filter(|e| !e.is_empty()))
        .map_err(|e| ApiError::Internal(anyhow::anyhow!("starting passkey registration: {e}")))?;
    let id = st.passkeys.start_register(u.id, state).ok_or(ApiError::TooManyRequests(std::time::Duration::from_secs(60)))?;
    Ok(Json(json!({ "ceremony_id": id, "options": options })))
}

#[derive(Deserialize)]
pub struct Finish {
    ceremony_id: String,
    name: String,
    credential: RegisterPublicKeyCredential,
}

/// Completes registration. The first second factor of an account signs out its other
/// sessions (they were opened with a password alone) and, with no TOTP to have made some,
/// creates recovery codes, returned once.
pub async fn register_finish(State(st): State<Arc<AppState>>, u: User, Json(b): Json<Finish>) -> ApiResult<Json<serde_json::Value>> {
    let wa = st.passkeys.webauthn.as_ref().ok_or_else(unavailable)?;
    let name = b.name.trim();
    let name = if name.is_empty() { "Passkey" } else { name };
    if name.chars().count() > 60 {
        return Err(ApiError::BadRequest("a passkey's name must be at most 60 characters".into()));
    }
    let reg = st
        .passkeys
        .finish_register(&b.ceremony_id, u.id)
        .ok_or_else(|| ApiError::BadRequest("the registration expired; start again".into()))?;
    let passkey = wa.finish_passkey_registration(&b.credential, &reg).map_err(|e| {
        tracing::info!("passkey registration for {} rejected: {e}", u.email);
        ApiError::BadRequest("the browser's response wasn't accepted".into())
    })?;

    let mut tx = st.db.begin().await?;
    let (existing,): (i64,) = sqlx::query_as("SELECT count(*) FROM user_passkeys WHERE user_id = $1").bind(u.id).fetch_one(&mut *tx).await?;
    if existing >= MAX_PER_USER {
        return Err(ApiError::BadRequest(format!("at most {MAX_PER_USER} passkeys per account")));
    }
    let cred_id: &[u8] = passkey.cred_id().as_ref();
    let (id,): (Uuid,) =
        sqlx::query_as("INSERT INTO user_passkeys (user_id, name, credential_id, passkey) VALUES ($1,$2,$3,$4) RETURNING id")
            .bind(u.id)
            .bind(name)
            .bind(cred_id)
            .bind(serde_json::to_value(&passkey).map_err(anyhow::Error::from)?)
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| match e {
                sqlx::Error::Database(d) if d.is_unique_violation() => ApiError::Conflict("that passkey is already registered".into()),
                e => e.into(),
            })?;
    let (codes,): (i64,) = sqlx::query_as("SELECT count(*) FROM user_recovery_codes WHERE user_id = $1").bind(u.id).fetch_one(&mut *tx).await?;
    let recovery = if codes == 0 { Some(super::totp::replace_recovery_codes(&mut tx, u.id).await?) } else { None };
    let revoked = if !u.totp_enabled && existing == 0 {
        sqlx::query("DELETE FROM user_sessions WHERE user_id = $1 AND id <> $2").bind(u.id).bind(u.session_id).execute(&mut *tx).await?.rows_affected()
    } else {
        0
    };
    tx.commit().await?;
    auth::audit(&st.db, Some(u.id), "auth.passkey_add", Some(("user", u.id)), json!({ "name": name, "sessions_revoked": revoked })).await;
    Ok(Json(json!({ "id": id, "recovery_codes": recovery, "sessions_revoked": revoked })))
}

#[derive(Deserialize)]
pub struct Rename {
    name: String,
}

pub async fn rename(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>, Json(b): Json<Rename>) -> ApiResult<Json<serde_json::Value>> {
    let name = b.name.trim();
    if name.is_empty() || name.chars().count() > 60 {
        return Err(ApiError::BadRequest("a passkey's name must be 1 to 60 characters".into()));
    }
    let n = sqlx::query("UPDATE user_passkeys SET name = $3 WHERE id = $1 AND user_id = $2").bind(id).bind(u.id).bind(name).execute(&st.db).await?.rows_affected();
    if n == 0 {
        return Err(ApiError::NotFound("passkey"));
    }
    auth::audit(&st.db, Some(u.id), "auth.passkey_rename", Some(("user", u.id)), json!({ "name": name })).await;
    Ok(Json(json!({ "ok": true })))
}

/// Removes a passkey (password required). With no second factor left, the recovery codes go too.
pub async fn remove(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>, Json(b): Json<Start>) -> ApiResult<Json<serde_json::Value>> {
    confirm_password(&st, &u, &b.password).await?;
    let mut tx = st.db.begin().await?;
    let name: Option<String> =
        sqlx::query_scalar("DELETE FROM user_passkeys WHERE id = $1 AND user_id = $2 RETURNING name").bind(id).bind(u.id).fetch_optional(&mut *tx).await?;
    let Some(name) = name else { return Err(ApiError::NotFound("passkey")) };
    if !u.totp_enabled {
        let (left,): (i64,) = sqlx::query_as("SELECT count(*) FROM user_passkeys WHERE user_id = $1").bind(u.id).fetch_one(&mut *tx).await?;
        if left == 0 {
            sqlx::query("DELETE FROM user_recovery_codes WHERE user_id = $1").bind(u.id).execute(&mut *tx).await?;
        }
    }
    tx.commit().await?;
    auth::audit(&st.db, Some(u.id), "auth.passkey_remove", Some(("user", u.id)), json!({ "name": name })).await;
    Ok(Json(json!({ "ok": true })))
}

/// New recovery codes for an account whose second factor is passkeys only (with TOTP, the
/// code-confirmed endpoint of the TOTP settings does this).
pub async fn recovery_codes(State(st): State<Arc<AppState>>, u: User, Json(b): Json<Start>) -> ApiResult<Json<serde_json::Value>> {
    confirm_password(&st, &u, &b.password).await?;
    let (n,): (i64,) = sqlx::query_as("SELECT count(*) FROM user_passkeys WHERE user_id = $1").bind(u.id).fetch_one(&st.db).await?;
    if n == 0 {
        return Err(ApiError::BadRequest("register a passkey first".into()));
    }
    let mut tx = st.db.begin().await?;
    let codes = super::totp::replace_recovery_codes(&mut tx, u.id).await?;
    tx.commit().await?;
    auth::audit(&st.db, Some(u.id), "auth.mfa_recovery_regenerate", Some(("user", u.id)), json!({ "via": "passkey" })).await;
    Ok(Json(json!({ "recovery_codes": codes })))
}

#[derive(Deserialize)]
pub struct LoginStart {
    email: String,
    password: String,
}

/// Sign-in step two for an account with passkeys: after the password checks out, a challenge
/// for the browser to have one of the account's passkeys sign. The answer goes to `/auth/login`.
pub async fn login_challenge(
    State(st): State<Arc<AppState>>,
    ClientIp(ip): ClientIp,
    Json(b): Json<LoginStart>,
) -> ApiResult<Json<serde_json::Value>> {
    let wa = st.passkeys.webauthn.as_ref().ok_or_else(unavailable)?;
    let ip_key = ip.to_string();
    let row = super::auth::check_password(&st, &ip_key, &b.email, &b.password).await?;
    let stored: Vec<serde_json::Value> =
        sqlx::query_scalar("SELECT passkey FROM user_passkeys WHERE user_id = $1").bind(row.id).fetch_all(&st.db).await?;
    let keys: Vec<Passkey> = stored.into_iter().filter_map(|p| serde_json::from_value(p).ok()).collect();
    if keys.is_empty() {
        return Err(ApiError::BadRequest("this account has no passkeys".into()));
    }
    let (options, state) = wa
        .start_passkey_authentication(&keys)
        .map_err(|e| ApiError::Internal(anyhow::anyhow!("starting passkey authentication: {e}")))?;
    let id = st.passkeys.start_login(row.id, state).ok_or(ApiError::TooManyRequests(std::time::Duration::from_secs(60)))?;
    Ok(Json(json!({ "ceremony_id": id, "options": options })))
}

/// The browser's answer to a [`login_challenge`], checked against the account's passkeys; on
/// success the stored signature counter moves on. `false` for any failure.
pub async fn verify_login(st: &AppState, user_id: Uuid, ceremony_id: &str, credential: &PublicKeyCredential) -> ApiResult<bool> {
    let (Some(wa), Some(state)) = (st.passkeys.webauthn.as_ref(), st.passkeys.finish_login(ceremony_id, user_id)) else { return Ok(false) };
    let res = match wa.finish_passkey_authentication(credential, &state) {
        Ok(r) => r,
        Err(e) => {
            tracing::info!("passkey sign-in for {user_id} rejected: {e}");
            return Ok(false);
        }
    };
    let cred_id: &[u8] = res.cred_id().as_ref();
    let mut tx = st.db.begin().await?;
    // The credential must be one of this user's, whatever the challenge listed.
    let row: Option<(Uuid, serde_json::Value)> = sqlx::query_as("SELECT id, passkey FROM user_passkeys WHERE user_id = $1 AND credential_id = $2 FOR UPDATE")
        .bind(user_id)
        .bind(cred_id)
        .fetch_optional(&mut *tx)
        .await?;
    let Some((id, stored)) = row else { return Ok(false) };
    let mut passkey: Passkey = serde_json::from_value(stored).map_err(anyhow::Error::from)?;
    passkey.update_credential(&res);
    sqlx::query("UPDATE user_passkeys SET passkey = $2, last_used_at = now() WHERE id = $1")
        .bind(id)
        .bind(serde_json::to_value(&passkey).map_err(anyhow::Error::from)?)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(true)
}
