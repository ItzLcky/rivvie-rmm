use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, header};
use axum::response::{AppendHeaders, IntoResponse};
use axum::Json;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use crate::auth::{self, User};
use crate::error::{ApiError, ApiResult};
use crate::ratelimit::ClientIp;
use crate::state::AppState;

#[derive(Deserialize)]
pub struct Login {
    email: String,
    password: String,
    /// TOTP or recovery code; required once the password checks out for an account with 2FA
    /// (unless a passkey answers instead).
    #[serde(default)]
    code: Option<String>,
    /// The browser's answer to a challenge from `/auth/login/passkey`.
    #[serde(default)]
    passkey: Option<PasskeyAnswer>,
}

#[derive(Deserialize)]
pub struct PasskeyAnswer {
    ceremony_id: String,
    credential: webauthn_rs::prelude::PublicKeyCredential,
}

/// Verified against when the email is unknown so response timing doesn't reveal which accounts exist.
fn dummy_hash() -> String {
    static H: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    H.get_or_init(|| auth::hash_password("not-a-real-password").unwrap_or_default()).clone()
}

#[derive(sqlx::FromRow)]
pub struct PasswordRow {
    pub id: Uuid,
    password_hash: String,
    disabled: bool,
    totp_secret: Option<Vec<u8>>,
    totp_sealed: bool,
    sso_exempt: bool,
    passkeys: i64,
}

/// The first step of a password sign-in: rate limits, then the email and password. Failures
/// count against the limits and are audited; success leaves the second factor to the caller.
pub async fn check_password(st: &AppState, ip_key: &str, email: &str, password: &str) -> ApiResult<PasswordRow> {
    let account_key = email.trim().to_lowercase();
    st.limits.login_ip.check(ip_key).map_err(ApiError::TooManyRequests)?;
    st.limits.login_account.check(&account_key).map_err(ApiError::TooManyRequests)?;

    let row: Option<PasswordRow> = sqlx::query_as(
        "SELECT id, password_hash, disabled, totp_secret, totp_sealed, sso_exempt,
                (SELECT count(*) FROM user_passkeys k WHERE k.user_id = users.id) AS passkeys
           FROM users WHERE lower(email) = lower($1)",
    )
    .bind(email.trim())
    .fetch_optional(&st.db)
    .await?;

    let hash = row.as_ref().map(|r| r.password_hash.clone()).unwrap_or_else(dummy_hash);
    let ok = auth::verify_password_async(password, hash).await;
    let Some(row) = row.filter(|_| ok) else {
        st.limits.login_ip.fail(ip_key);
        st.limits.login_account.fail(&account_key);
        auth::audit(&st.db, None, "auth.login_failed", None, json!({ "email": email, "ip": ip_key })).await;
        return Err(ApiError::Unauthorized);
    };
    if row.disabled {
        return Err(ApiError::Unauthorized);
    }
    if st.company().sso_required && !row.sso_exempt {
        // The same answer as a wrong password, so this doesn't confirm that the password was right.
        auth::audit(&st.db, Some(row.id), "auth.login_denied_sso_required", Some(("user", row.id)), json!({ "ip": ip_key })).await;
        return Err(ApiError::Unauthorized);
    }
    Ok(row)
}

/// Opens a session exactly as a password sign-in does: a fresh token, its row (with the
/// browser, and the identity provider for SSO), and the user's last sign-in time.
pub async fn open_session(st: &AppState, headers: &HeaderMap, user_id: Uuid, sso_provider: Option<Uuid>) -> ApiResult<(String, Uuid)> {
    let token = auth::random_token();
    let ua = headers.get(header::USER_AGENT).and_then(|v| v.to_str().ok()).map(|s| s.chars().take(200).collect::<String>());
    let (session_id,): (Uuid,) = sqlx::query_as(
        "INSERT INTO user_sessions (token_hash, user_id, expires_at, user_agent, sso_provider_id) VALUES ($1,$2,$3,$4,$5) RETURNING id",
    )
    .bind(auth::token_hash(&token))
    .bind(user_id)
    .bind(Utc::now() + Duration::days(auth::SESSION_DAYS))
    .bind(ua)
    .bind(sso_provider)
    .fetch_one(&st.db)
    .await?;
    sqlx::query("UPDATE users SET last_login_at = now() WHERE id = $1").bind(user_id).execute(&st.db).await?;
    Ok((token, session_id))
}

pub async fn login(
    State(st): State<Arc<AppState>>,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    Json(body): Json<Login>,
) -> ApiResult<impl IntoResponse> {
    let ip_key = ip.to_string();
    let account_key = body.email.trim().to_lowercase();
    let row = check_password(&st, &ip_key, &body.email, &body.password).await?;
    let user_id = row.id;
    let failed = || {
        st.limits.login_ip.fail(&ip_key);
        st.limits.login_account.fail(&account_key);
    };
    let (has_totp, has_passkey) = (row.totp_secret.is_some(), row.passkeys > 0);
    let methods = |msg: &'static str| ApiError::MfaMethods { msg, totp: has_totp, passkey: has_passkey };
    if has_totp || has_passkey {
        if let Some(answer) = &body.passkey {
            if !super::passkeys::verify_login(&st, user_id, &answer.ceremony_id, &answer.credential).await? {
                failed();
                auth::audit(&st.db, Some(user_id), "auth.mfa_failed", Some(("user", user_id)), json!({ "ip": ip_key, "factor": "passkey" })).await;
                return Err(methods("passkey verification failed"));
            }
            auth::audit(&st.db, Some(user_id), "auth.passkey_used", Some(("user", user_id)), json!({})).await;
        } else {
            let Some(code) = body.code.as_deref().map(str::trim).filter(|c| !c.is_empty()) else {
                return Err(methods("two-factor code required"));
            };
            let secret = match &row.totp_secret {
                Some(stored) => Some(super::totp::open(&st, stored, row.totp_sealed)?),
                None => None,
            };
            match super::totp::check_code(&st.db, user_id, secret.as_deref(), code).await? {
                Some(super::totp::Factor::Totp) => {}
                Some(super::totp::Factor::Recovery { remaining }) => {
                    auth::audit(&st.db, Some(user_id), "auth.recovery_code_used", Some(("user", user_id)), json!({ "remaining": remaining }))
                        .await;
                }
                None => {
                    failed();
                    auth::audit(&st.db, Some(user_id), "auth.mfa_failed", Some(("user", user_id)), json!({ "ip": ip_key })).await;
                    return Err(methods("invalid two-factor code"));
                }
            }
        }
    }

    let (token, session_id) = open_session(&st, &headers, user_id, None).await?;
    auth::audit(&st.db, Some(user_id), "auth.login", None, json!({ "ip": ip_key })).await;

    let user: User = sqlx::query_as(concat!(
        "SELECT ",
        auth::user_columns!("$3", "$2::uuid", "false"),
        " FROM users u WHERE u.id = $1"
    ))
    .bind(user_id)
    .bind(session_id)
    .bind(st.company().require_2fa_all)
    .fetch_one(&st.db)
    .await?;
    Ok((
        AppendHeaders([(header::SET_COOKIE, auth::session_cookie(&token, st.cfg.secure_cookies()))]),
        // Token is also returned for non-browser API clients.
        Json(json!({ "user": user_json(&user), "token": token })),
    ))
}

pub async fn logout(State(st): State<Arc<AppState>>, headers: HeaderMap) -> ApiResult<impl IntoResponse> {
    if let Some(t) = auth::extract_token(&headers) {
        sqlx::query("DELETE FROM user_sessions WHERE token_hash = $1").bind(auth::token_hash(&t)).execute(&st.db).await?;
    }
    Ok((AppendHeaders([(header::SET_COOKIE, auth::clear_cookie())]), Json(json!({ "ok": true }))))
}

/// The signed-in user, plus their saved UI preferences.
/// The signed-in user for the dashboard, with the permissions they hold.
fn user_json(u: &User) -> serde_json::Value {
    let mut v = serde_json::to_value(u).unwrap_or_default();
    v["permissions"] = json!(u.effective_permissions());
    v
}

pub async fn me(State(st): State<Arc<AppState>>, user: User) -> ApiResult<Json<serde_json::Value>> {
    let prefs: serde_json::Value =
        sqlx::query_scalar("SELECT preferences FROM users WHERE id = $1").bind(user.id).fetch_one(&st.db).await?;
    let mut v = user_json(&user);
    v["preferences"] = prefs;
    Ok(Json(v))
}

/// Merges keys into the user's UI preferences (theme, table columns, density...). A key set to
/// null is removed. The dashboard owns the contents; the server only bounds the size.
pub async fn update_preferences(
    State(st): State<Arc<AppState>>,
    user: User,
    Json(patch): Json<serde_json::Map<String, serde_json::Value>>,
) -> ApiResult<Json<serde_json::Value>> {
    // The size check is in the UPDATE, so an oversized patch leaves the stored value alone.
    let prefs: Option<serde_json::Value> = sqlx::query_scalar(
        "UPDATE users SET preferences = jsonb_strip_nulls(preferences || $2)
          WHERE id = $1 AND octet_length(jsonb_strip_nulls(preferences || $2)::text) <= 32768
          RETURNING preferences",
    )
    .bind(user.id)
    .bind(serde_json::Value::Object(patch))
    .fetch_optional(&st.db)
    .await?;
    let prefs = prefs.ok_or_else(|| ApiError::BadRequest("preferences too large".into()))?;
    Ok(Json(prefs))
}

#[derive(Deserialize)]
pub struct ChangePassword {
    current_password: String,
    new_password: String,
}

/// Change your own password. Every other session of yours is revoked; this one stays.
pub async fn change_password(
    State(st): State<Arc<AppState>>,
    u: User,
    Json(b): Json<ChangePassword>,
) -> ApiResult<Json<serde_json::Value>> {
    let (hash,): (String,) =
        sqlx::query_as("SELECT password_hash FROM users WHERE id = $1").bind(u.id).fetch_one(&st.db).await?;
    if !auth::verify_password_async(&b.current_password, hash).await {
        auth::audit(&st.db, Some(u.id), "auth.password_change_failed", Some(("user", u.id)), json!({})).await;
        return Err(ApiError::BadRequest("current password is incorrect".into()));
    }
    if b.new_password == b.current_password {
        return Err(ApiError::BadRequest("new password must differ from the current one".into()));
    }
    let new_hash = auth::hash_password_async(&b.new_password).await?;
    let mut tx = st.db.begin().await?;
    sqlx::query("UPDATE users SET password_hash = $2 WHERE id = $1").bind(u.id).bind(new_hash).execute(&mut *tx).await?;
    let revoked = sqlx::query("DELETE FROM user_sessions WHERE user_id = $1 AND id <> $2")
        .bind(u.id)
        .bind(u.session_id)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    tx.commit().await?;
    auth::audit(&st.db, Some(u.id), "auth.password_change", Some(("user", u.id)), json!({ "sessions_revoked": revoked })).await;
    Ok(Json(json!({ "ok": true, "sessions_revoked": revoked })))
}

#[derive(Serialize, sqlx::FromRow)]
pub struct SessionRow {
    pub id: Uuid,
    pub created_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub user_agent: Option<String>,
    pub current: bool,
}

/// Live sessions of `user_id`; `current` marks the one making the request.
pub async fn sessions_for(st: &AppState, user_id: Uuid, current: Uuid) -> ApiResult<Vec<SessionRow>> {
    Ok(sqlx::query_as(
        "SELECT id, created_at, last_seen_at, expires_at, user_agent, id = $2 AS current
           FROM user_sessions
          WHERE user_id = $1 AND expires_at > now() AND last_seen_at > now() - make_interval(hours => $3)
          ORDER BY last_seen_at DESC",
    )
    .bind(user_id)
    .bind(current)
    .bind(st.session_idle_hours())
    .fetch_all(&st.db)
    .await?)
}

pub async fn my_sessions(State(st): State<Arc<AppState>>, u: User) -> ApiResult<Json<Vec<SessionRow>>> {
    Ok(Json(sessions_for(&st, u.id, u.session_id).await?))
}

pub async fn revoke_my_session(
    State(st): State<Arc<AppState>>,
    u: User,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<serde_json::Value>> {
    let n = sqlx::query("DELETE FROM user_sessions WHERE id = $1 AND user_id = $2")
        .bind(id)
        .bind(u.id)
        .execute(&st.db)
        .await?
        .rows_affected();
    if n == 0 {
        return Err(ApiError::NotFound("session"));
    }
    auth::audit(&st.db, Some(u.id), "auth.session_revoke", Some(("user", u.id)), json!({ "session": id })).await;
    Ok(Json(json!({ "ok": true, "current": id == u.session_id })))
}

/// Sign out everywhere except here.
pub async fn revoke_other_sessions(State(st): State<Arc<AppState>>, u: User) -> ApiResult<Json<serde_json::Value>> {
    let n = sqlx::query("DELETE FROM user_sessions WHERE user_id = $1 AND id <> $2")
        .bind(u.id)
        .bind(u.session_id)
        .execute(&st.db)
        .await?
        .rows_affected();
    auth::audit(&st.db, Some(u.id), "auth.session_revoke_others", Some(("user", u.id)), json!({ "count": n })).await;
    Ok(Json(json!({ "ok": true, "revoked": n })))
}
