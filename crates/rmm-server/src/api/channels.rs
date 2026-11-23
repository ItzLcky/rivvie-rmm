//! Notification channels (admins), the mail server settings, and the delivery log.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::AssertSqlSafe;
use uuid::Uuid;

use crate::auth::{self, Role, User};
use crate::error::{ApiError, ApiResult};
use crate::notify;
use crate::state::{AppState, Company};

#[derive(Serialize)]
pub struct ChannelView {
    id: Uuid,
    name: String,
    kind: String,
    /// Admins only. A webhook secret is never in it (see `has_secret`).
    #[serde(skip_serializing_if = "Option::is_none")]
    config: Option<Value>,
    has_secret: bool,
    enabled: bool,
    /// Policies that send to this channel.
    policies: i64,
    created_at: DateTime<Utc>,
}

#[derive(sqlx::FromRow)]
struct ChannelRow {
    id: Uuid,
    name: String,
    kind: String,
    config: Value,
    enabled: bool,
    has_secret: bool,
    policies: i64,
    created_at: DateTime<Utc>,
}

const SELECT: &str = "SELECT ch.id, ch.name, ch.kind, ch.config, ch.enabled, ch.created_at, ch.secret IS NOT NULL AS has_secret,
       (SELECT count(*) FROM policy_items p WHERE p.module = 'alert' AND p.config -> 'channel_ids' ? ch.id::text) AS policies
  FROM notification_channels ch";

fn view(r: ChannelRow, admin: bool) -> ChannelView {
    let config = admin.then_some(r.config);
    ChannelView { id: r.id, name: r.name, kind: r.kind, config, has_secret: r.has_secret, enabled: r.enabled, policies: r.policies, created_at: r.created_at }
}

/// Everyone signed in can list channels (to pick them in a policy); only admins see where
/// they point.
pub async fn list(State(st): State<Arc<AppState>>, u: User) -> ApiResult<Json<Vec<ChannelView>>> {
    let admin = u.require(Role::Admin).is_ok();
    let rows: Vec<ChannelRow> =
        sqlx::query_as(sqlx::AssertSqlSafe(format!("{SELECT} ORDER BY lower(ch.name)"))).fetch_all(&st.db).await?;
    Ok(Json(rows.into_iter().map(|r| view(r, admin)).collect()))
}

async fn fetch(st: &AppState, id: Uuid) -> ApiResult<ChannelRow> {
    sqlx::query_as(sqlx::AssertSqlSafe(format!("{SELECT} WHERE ch.id = $1")))
        .bind(id)
        .fetch_optional(&st.db)
        .await?
        .ok_or(ApiError::NotFound("channel"))
}

#[derive(Deserialize)]
pub struct ChannelIn {
    name: String,
    kind: String,
    #[serde(default)]
    config: Value,
    #[serde(default = "yes")]
    enabled: bool,
}

fn yes() -> bool {
    true
}

fn conflict(e: sqlx::Error) -> ApiError {
    match e {
        sqlx::Error::Database(d) if d.is_unique_violation() => ApiError::Conflict("a channel with that name already exists".into()),
        e => e.into(),
    }
}

fn check_name(name: &str) -> ApiResult<&str> {
    let name = name.trim();
    if name.is_empty() || name.chars().count() > 100 {
        return Err(ApiError::BadRequest("name must be 1-100 characters".into()));
    }
    Ok(name)
}

pub async fn create(State(st): State<Arc<AppState>>, u: User, Json(b): Json<ChannelIn>) -> ApiResult<Json<ChannelView>> {
    u.require(Role::Admin)?;
    let name = check_name(&b.name)?;
    let mut config = notify::validate_config(&b.kind, &b.config).map_err(ApiError::BadRequest)?;
    let secret = take_secret(&mut config).map(|s| crate::crypto::store(st.cfg.data_key.as_ref(), s.as_bytes()));
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO notification_channels (id, name, kind, config, enabled, created_by, secret, secret_sealed) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)")
        .bind(id)
        .bind(name)
        .bind(&b.kind)
        .bind(&config)
        .bind(b.enabled)
        .bind(u.id)
        .bind(secret.as_ref().map(|s| s.0.clone()))
        .bind(secret.as_ref().is_some_and(|s| s.1))
        .execute(&st.db)
        .await
        .map_err(conflict)?;
    auth::audit(&st.db, Some(u.id), "channel.create", Some(("channel", id)), json!({ "name": name, "kind": b.kind })).await;
    Ok(Json(view(fetch(&st, id).await?, true)))
}

/// Moves the webhook secret out of a validated config (it lives sealed in its own column).
fn take_secret(config: &mut Value) -> Option<String> {
    config.as_object_mut()?.remove("secret")?.as_str().map(str::to_string).filter(|s| !s.is_empty())
}

/// A webhook secret left out of the config is kept; send `"secret": ""` to remove it.
pub async fn update(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>, Json(b): Json<ChannelIn>) -> ApiResult<Json<ChannelView>> {
    u.require(Role::Admin)?;
    let current = fetch(&st, id).await?;
    let name = check_name(&b.name)?;
    // The secret: left out = kept (when it stays a webhook channel), "" = removed, else replaced.
    let keep = b.kind == "webhook" && current.kind == "webhook" && b.config.get("secret").is_none();
    let mut config = notify::validate_config(&b.kind, &b.config).map_err(ApiError::BadRequest)?;
    let secret = take_secret(&mut config).map(|s| crate::crypto::store(st.cfg.data_key.as_ref(), s.as_bytes()));
    sqlx::query(
        "UPDATE notification_channels SET name = $2, kind = $3, config = $4, enabled = $5, updated_at = now(),
                secret = CASE WHEN $6 THEN secret ELSE $7 END, secret_sealed = CASE WHEN $6 THEN secret_sealed ELSE $8 END
          WHERE id = $1",
    )
        .bind(id)
        .bind(name)
        .bind(&b.kind)
        .bind(&config)
        .bind(b.enabled)
        .bind(keep)
        .bind(secret.as_ref().map(|s| s.0.clone()))
        .bind(secret.as_ref().is_some_and(|s| s.1))
        .execute(&st.db)
        .await
        .map_err(conflict)?;
    auth::audit(&st.db, Some(u.id), "channel.update", Some(("channel", id)), json!({ "name": name, "enabled": b.enabled })).await;
    Ok(Json(view(fetch(&st, id).await?, true)))
}

pub async fn remove(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    u.require(Role::Admin)?;
    let current = fetch(&st, id).await?;
    // Out of every alert item and override that names it.
    let mut tx = st.db.begin().await?;
    crate::policy::lock(&mut tx).await?;
    let drop = "jsonb_set(config, '{channel_ids}', coalesce((SELECT jsonb_agg(x) FROM jsonb_array_elements(config -> 'channel_ids') x
                                                              WHERE x <> to_jsonb($1::text)), '[]'))";
    let items: Vec<Uuid> = sqlx::query_scalar(AssertSqlSafe(format!(
        "UPDATE policy_items SET config = {drop} WHERE module = 'alert' AND config -> 'channel_ids' ? $1::text RETURNING id"
    )))
    .bind(id)
    .fetch_all(&mut *tx)
    .await?;
    let overridden: Vec<Uuid> = sqlx::query_scalar(AssertSqlSafe(format!(
        "UPDATE policy_overrides SET config = {drop} WHERE jsonb_typeof(config -> 'channel_ids') = 'array' AND config -> 'channel_ids' ? $1::text
         RETURNING item_id"
    )))
    .bind(id)
    .fetch_all(&mut *tx)
    .await?;
    let touched: Vec<Uuid> = items.into_iter().chain(overridden).collect();
    crate::policy::rebuild(&mut tx, Some(&touched)).await?;
    sqlx::query("DELETE FROM notification_channels WHERE id = $1").bind(id).execute(&mut *tx).await?;
    tx.commit().await?;
    auth::audit(&st.db, Some(u.id), "channel.delete", Some(("channel", id)), json!({ "name": current.name })).await;
    Ok(Json(json!({ "ok": true })))
}

/// Sends a test message right away and reports the outcome (nothing is queued).
pub async fn test(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    u.require(Role::Admin)?;
    let row: notify::ChannelRow =
        sqlx::query_as(sqlx::AssertSqlSafe(format!("SELECT {} FROM notification_channels WHERE id = $1", notify::ChannelRow::COLUMNS)))
            .bind(id)
            .fetch_optional(&st.db)
            .await?
            .ok_or(ApiError::NotFound("channel"))?;
    let channel = match row.open(st.cfg.data_key.as_ref()) {
        Ok(c) => c,
        Err(e) => return Ok(Json(json!({ "ok": false, "error": e }))),
    };
    let result = notify::send_test(&st, &channel).await;
    auth::audit(&st.db, Some(u.id), "channel.test", Some(("channel", id)), json!({ "ok": result.is_ok() })).await;
    Ok(Json(match result {
        Ok(()) => json!({ "ok": true }),
        Err(e) => json!({ "ok": false, "error": e }),
    }))
}

#[derive(Serialize, sqlx::FromRow)]
pub struct DeliveryRow {
    id: i64,
    channel_id: Uuid,
    channel_name: String,
    alert_id: Option<Uuid>,
    alert_title: Option<String>,
    hostname: Option<String>,
    event: String,
    status: String,
    attempts: i32,
    last_error: Option<String>,
    next_attempt_at: DateTime<Utc>,
    created_at: DateTime<Utc>,
    sent_at: Option<DateTime<Utc>>,
}

/// The latest 200 notifications, newest first (admins).
pub async fn deliveries(State(st): State<Arc<AppState>>, u: User) -> ApiResult<Json<Vec<DeliveryRow>>> {
    u.require(Role::Admin)?;
    Ok(Json(
        sqlx::query_as(
            "SELECT n.id, n.channel_id, ch.name AS channel_name, n.alert_id, al.title AS alert_title, a.hostname, n.event, n.status,
                    n.attempts, n.last_error, n.next_attempt_at, n.created_at, n.sent_at
               FROM notifications n JOIN notification_channels ch ON ch.id = n.channel_id
               LEFT JOIN alerts al ON al.id = n.alert_id LEFT JOIN agents a ON a.id = al.agent_id
              ORDER BY n.id DESC LIMIT 200",
        )
        .fetch_all(&st.db)
        .await?,
    ))
}

// ---------------------------------------------------------------------------
// Mail server
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct SmtpView {
    host: String,
    port: i32,
    security: String,
    username: String,
    password_set: bool,
    from: String,
}

fn smtp_view(c: &Company) -> SmtpView {
    SmtpView {
        host: c.smtp_host.clone(),
        port: c.smtp_port,
        security: c.smtp_security.clone(),
        username: c.smtp_username.clone(),
        password_set: c.smtp_password_enc.is_some(),
        from: c.smtp_from.clone(),
    }
}

pub async fn get_smtp(State(st): State<Arc<AppState>>, u: User) -> ApiResult<Json<SmtpView>> {
    u.require(Role::Admin)?;
    Ok(Json(smtp_view(&st.company())))
}

#[derive(Deserialize)]
pub struct SmtpIn {
    host: String,
    port: i32,
    security: String,
    #[serde(default)]
    username: String,
    /// Omitted = unchanged; "" clears it.
    password: Option<String>,
    from: String,
}

pub async fn update_smtp(State(st): State<Arc<AppState>>, u: User, Json(b): Json<SmtpIn>) -> ApiResult<Json<SmtpView>> {
    u.require(Role::Admin)?;
    if !(1..=65535).contains(&b.port) {
        return Err(ApiError::BadRequest("port must be 1-65535".into()));
    }
    if !matches!(b.security.as_str(), "starttls" | "tls" | "none") {
        return Err(ApiError::BadRequest("security must be starttls, tls or none".into()));
    }
    let host = b.host.trim();
    if host.len() > 255 || host.contains(char::is_whitespace) {
        return Err(ApiError::BadRequest("enter a host name or address".into()));
    }
    let from = b.from.trim();
    if !from.is_empty() && from.parse::<lettre::message::Mailbox>().is_err() {
        return Err(ApiError::BadRequest("the sender must be an address, like RMM <rmm@example.com>".into()));
    }
    // Omitted: unchanged. "": cleared. Otherwise sealed with RMM_DATA_KEY when the server has one.
    let password: Option<(Option<Vec<u8>>, bool)> = b.password.as_deref().map(|p| match p {
        "" => (None, false),
        p => {
            let (bytes, sealed) = crate::crypto::store(st.cfg.data_key.as_ref(), p.as_bytes());
            (Some(bytes), sealed)
        }
    });
    let new: Company = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "UPDATE company_settings SET smtp_host = $1, smtp_port = $2, smtp_security = $3, smtp_username = $4,
                smtp_password_enc = CASE WHEN $5 THEN $6 ELSE smtp_password_enc END,
                smtp_password_sealed = CASE WHEN $5 THEN $7 ELSE smtp_password_sealed END,
                smtp_from = $8, updated_at = now(), updated_by = $9
         RETURNING {}",
        Company::COLUMNS
    )))
    .bind(host)
    .bind(b.port)
    .bind(&b.security)
    .bind(b.username.trim())
    .bind(password.is_some())
    .bind(password.as_ref().and_then(|p| p.0.as_deref()))
    .bind(password.as_ref().is_some_and(|p| p.1))
    .bind(from)
    .bind(u.id)
    .fetch_one(&st.db)
    .await?;
    *st.company.write().unwrap_or_else(|e| e.into_inner()) = new.clone();
    auth::audit(&st.db, Some(u.id), "settings.smtp", None, json!({ "host": host, "port": b.port, "security": b.security })).await;
    Ok(Json(smtp_view(&new)))
}
