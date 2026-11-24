//! Web Push subscriptions and notification preferences (docs/design/pwa.md). Session only:
//! none of this is in the public API.

use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use axum::http::HeaderMap;
use chrono::{DateTime, Utc};
use data_encoding::BASE64URL_NOPAD;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::auth::{self, User};
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

fn session_only(u: &User) -> ApiResult<()> {
    if u.api_key.is_some() { Err(ApiError::Forbidden) } else { Ok(()) }
}

/// The VAPID public key, for `pushManager.subscribe({ applicationServerKey })`.
pub async fn key(State(st): State<Arc<AppState>>, u: User) -> ApiResult<Json<Value>> {
    session_only(&u)?;
    let v = crate::push::keys(&st).await.map_err(|e| anyhow::anyhow!(e))?;
    Ok(Json(json!({ "public_key": BASE64URL_NOPAD.encode(&v.public) })))
}

#[derive(Serialize, sqlx::FromRow)]
pub struct Device {
    id: Uuid,
    user_agent: String,
    created_at: DateTime<Utc>,
    last_ok_at: Option<DateTime<Utc>>,
    /// The endpoint, so a browser can tell whether it is this one.
    endpoint: String,
}

pub async fn list(State(st): State<Arc<AppState>>, u: User) -> ApiResult<Json<Vec<Device>>> {
    session_only(&u)?;
    Ok(Json(
        sqlx::query_as("SELECT id, user_agent, created_at, last_ok_at, endpoint FROM push_subscriptions WHERE user_id = $1 ORDER BY created_at")
            .bind(u.id)
            .fetch_all(&st.db)
            .await?,
    ))
}

#[derive(Deserialize)]
pub struct Keys {
    p256dh: String,
    auth: String,
}

/// `PushSubscription.toJSON()`.
#[derive(Deserialize)]
pub struct SubscriptionIn {
    endpoint: String,
    keys: Keys,
}

fn b64(s: &str) -> Option<Vec<u8>> {
    let s = s.trim().trim_end_matches('=');
    BASE64URL_NOPAD.decode(s.as_bytes()).ok()
}

pub async fn subscribe(State(st): State<Arc<AppState>>, u: User, headers: HeaderMap, Json(b): Json<SubscriptionIn>) -> ApiResult<Json<Value>> {
    session_only(&u)?;
    if b.endpoint.len() > 2000 {
        return Err(ApiError::BadRequest("the endpoint is too long".into()));
    }
    let extra: Vec<String> = std::env::var("RMM_PUSH_ALLOW_HOSTS").unwrap_or_default().split(',').map(|h| h.trim().to_ascii_lowercase()).filter(|h| !h.is_empty()).collect();
    crate::push::endpoint_allowed(&b.endpoint, &extra).map_err(ApiError::BadRequest)?;
    let p256dh = b64(&b.keys.p256dh).filter(|k| k.len() == 65 && k[0] == 4).ok_or_else(|| ApiError::BadRequest("p256dh must be an uncompressed P-256 point".into()))?;
    let auth = b64(&b.keys.auth).filter(|k| k.len() == 16).ok_or_else(|| ApiError::BadRequest("auth must be 16 bytes".into()))?;
    let ua: String = headers.get(axum::http::header::USER_AGENT).and_then(|v| v.to_str().ok()).unwrap_or("").chars().take(300).collect();
    // A browser that signs in as someone else takes its subscription with it.
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO push_subscriptions (id, user_id, endpoint, p256dh, auth, user_agent) VALUES ($1, $2, $3, $4, $5, $6)
         ON CONFLICT (endpoint) DO UPDATE SET user_id = EXCLUDED.user_id, p256dh = EXCLUDED.p256dh, auth = EXCLUDED.auth,
                user_agent = EXCLUDED.user_agent, failures = 0
         RETURNING id",
    )
    .bind(Uuid::new_v4())
    .bind(u.id)
    .bind(&b.endpoint)
    .bind(p256dh)
    .bind(auth)
    .bind(&ua)
    .fetch_one(&st.db)
    .await?;
    auth::audit(&st.db, Some(u.id), "push.subscribe", Some(("push_subscription", id)), json!({ "user_agent": ua })).await;
    Ok(Json(json!({ "id": id })))
}

#[derive(Deserialize)]
pub struct Unsubscribe {
    endpoint: String,
}

pub async fn unsubscribe(State(st): State<Arc<AppState>>, u: User, Json(b): Json<Unsubscribe>) -> ApiResult<Json<Value>> {
    session_only(&u)?;
    let n = sqlx::query("DELETE FROM push_subscriptions WHERE user_id = $1 AND endpoint = $2").bind(u.id).bind(&b.endpoint).execute(&st.db).await?.rows_affected();
    if n > 0 {
        auth::audit(&st.db, Some(u.id), "push.unsubscribe", None, json!({})).await;
    }
    Ok(Json(json!({ "removed": n })))
}

/// Sends a test notification to all of the user's devices.
pub async fn test(State(st): State<Arc<AppState>>, u: User) -> ApiResult<Json<Value>> {
    session_only(&u)?;
    let payload = json!({ "title": "Test notification", "body": "Notifications work on this device.", "url": "/account", "tag": "test", "kind": "test" });
    let sent = crate::push::send_to_user(&st, u.id, &payload, false).await.map_err(|e| anyhow::anyhow!(e))?;
    Ok(Json(json!({ "sent": sent })))
}

#[derive(Serialize, Deserialize)]
pub struct Pref {
    event: String,
    push: bool,
    email: bool,
}

#[derive(Serialize)]
pub struct PrefsView {
    hide_details: bool,
    events: Vec<Value>,
}

async fn prefs_view(st: &AppState, user: Uuid) -> ApiResult<PrefsView> {
    let hide: bool = sqlx::query_scalar("SELECT push_hide_details FROM users WHERE id = $1").bind(user).fetch_one(&st.db).await?;
    let rows: Vec<(String, bool, bool)> = sqlx::query_as("SELECT event, push, email FROM user_notification_prefs WHERE user_id = $1").bind(user).fetch_all(&st.db).await?;
    let events = crate::push::EVENTS
        .iter()
        .map(|(event, label, push_default)| {
            let row = rows.iter().find(|r| r.0 == *event);
            json!({
                "event": event,
                "label": label,
                "push": row.map(|r| r.1).unwrap_or(*push_default),
                "email": row.map(|r| r.2).unwrap_or(true),
                // Alerts reach people by email through notification channels, pages through
                // contact methods: the email switch is for the ticket mails only.
                "email_applies": event.starts_with("ticket_") || *event == "sla_warning",
            })
        })
        .collect();
    Ok(PrefsView { hide_details: hide, events })
}

pub async fn get_prefs(State(st): State<Arc<AppState>>, u: User) -> ApiResult<Json<PrefsView>> {
    session_only(&u)?;
    Ok(Json(prefs_view(&st, u.id).await?))
}

#[derive(Deserialize)]
pub struct PrefsIn {
    hide_details: bool,
    events: Vec<Pref>,
}

pub async fn update_prefs(State(st): State<Arc<AppState>>, u: User, Json(b): Json<PrefsIn>) -> ApiResult<Json<PrefsView>> {
    session_only(&u)?;
    if let Some(bad) = b.events.iter().find(|p| !crate::push::EVENTS.iter().any(|e| e.0 == p.event)) {
        return Err(ApiError::BadRequest(format!("unknown event {}", bad.event)));
    }
    let mut tx = st.db.begin().await?;
    sqlx::query("UPDATE users SET push_hide_details = $2 WHERE id = $1").bind(u.id).bind(b.hide_details).execute(&mut *tx).await?;
    for p in &b.events {
        sqlx::query(
            "INSERT INTO user_notification_prefs (user_id, event, push, email) VALUES ($1, $2, $3, $4)
             ON CONFLICT (user_id, event) DO UPDATE SET push = EXCLUDED.push, email = EXCLUDED.email",
        )
        .bind(u.id)
        .bind(&p.event)
        .bind(p.push)
        .bind(p.email)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(Json(prefs_view(&st, u.id).await?))
}
