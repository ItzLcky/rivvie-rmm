//! Webhook subscriptions and their delivery log (admins). Delivery itself is `crate::webhooks`.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, Query, State};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::auth::{self, Role, User};
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;
use crate::webhooks;

#[derive(Serialize, sqlx::FromRow)]
pub struct Subscription {
    id: Uuid,
    name: String,
    url: String,
    /// null: every client.
    client_id: Option<Uuid>,
    client_name: Option<String>,
    events: Vec<String>,
    /// Internal notes are sent too.
    internal_notes: bool,
    enabled: bool,
    created_at: DateTime<Utc>,
    /// Deliveries waiting (including retries), and failures in the last 24 hours.
    pending: i64,
    failed_24h: i64,
    last_sent_at: Option<DateTime<Utc>>,
}

const SELECT: &str = "SELECT w.id, w.name, w.url, w.client_id, c.name AS client_name, w.events, w.internal_notes, w.enabled, w.created_at,
       (SELECT count(*) FROM webhook_deliveries d WHERE d.subscription_id = w.id AND d.status = 'pending') AS pending,
       (SELECT count(*) FROM webhook_deliveries d WHERE d.subscription_id = w.id AND d.status = 'failed' AND d.created_at > now() - interval '24 hours') AS failed_24h,
       (SELECT max(d.sent_at) FROM webhook_deliveries d WHERE d.subscription_id = w.id) AS last_sent_at
  FROM webhook_subscriptions w LEFT JOIN clients c ON c.id = w.client_id";

pub async fn list(State(st): State<Arc<AppState>>, u: User) -> ApiResult<Json<Value>> {
    u.require(Role::Admin)?;
    let rows: Vec<Subscription> =
        sqlx::query_as(sqlx::AssertSqlSafe(format!("{SELECT} ORDER BY lower(w.name)"))).fetch_all(&st.db).await?;
    Ok(Json(json!({ "webhooks": rows, "events": webhooks::EVENTS })))
}

#[derive(Deserialize)]
pub struct SubscriptionIn {
    name: String,
    url: String,
    events: Vec<String>,
    client_id: Option<Uuid>,
    #[serde(default)]
    internal_notes: bool,
    #[serde(default = "yes")]
    enabled: bool,
}

fn yes() -> bool {
    true
}

struct Checked {
    name: String,
    url: String,
    events: Vec<String>,
}

async fn check(st: &AppState, b: &SubscriptionIn) -> ApiResult<Checked> {
    let name = b.name.trim();
    if name.is_empty() || name.chars().count() > 100 {
        return Err(ApiError::BadRequest("name the webhook (1-100 characters)".into()));
    }
    let url = webhooks::validate_url(&b.url).map_err(ApiError::BadRequest)?;
    let mut events: Vec<String> = Vec::new();
    for e in &b.events {
        if !webhooks::valid_event(e) {
            return Err(ApiError::BadRequest(format!("unknown event {e}")));
        }
        if !events.contains(e) {
            events.push(e.clone());
        }
    }
    if events.is_empty() {
        return Err(ApiError::BadRequest("choose at least one event".into()));
    }
    if let Some(c) = b.client_id {
        let known: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM clients WHERE id = $1)").bind(c).fetch_one(&st.db).await?;
        if !known {
            return Err(ApiError::NotFound("client"));
        }
    }
    Ok(Checked { name: name.to_string(), url, events })
}

async fn fetch(st: &AppState, id: Uuid) -> ApiResult<Subscription> {
    sqlx::query_as(sqlx::AssertSqlSafe(format!("{SELECT} WHERE w.id = $1"))).bind(id).fetch_optional(&st.db).await?.ok_or(ApiError::NotFound("webhook"))
}

/// The signing secret is returned once, here and on rotation; it is stored sealed.
pub async fn create(State(st): State<Arc<AppState>>, u: User, Json(b): Json<SubscriptionIn>) -> ApiResult<Json<Value>> {
    u.require(Role::Admin)?;
    let c = check(&st, &b).await?;
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM webhook_subscriptions").fetch_one(&st.db).await?;
    if count >= 100 {
        return Err(ApiError::BadRequest("100 webhooks is the limit".into()));
    }
    let id = Uuid::new_v4();
    let secret = webhooks::new_secret();
    let (sealed, encrypted) = crate::crypto::store(st.cfg.data_key.as_ref(), secret.as_bytes());
    sqlx::query(
        "INSERT INTO webhook_subscriptions (id, name, url, secret, secret_sealed, client_id, events, internal_notes, enabled, created_by)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
    )
    .bind(id)
    .bind(&c.name)
    .bind(&c.url)
    .bind(sealed)
    .bind(encrypted)
    .bind(b.client_id)
    .bind(&c.events)
    .bind(b.internal_notes)
    .bind(b.enabled)
    .bind(u.id)
    .execute(&st.db)
    .await?;
    auth::audit(
        &st.db,
        Some(u.id),
        "webhook.create",
        Some(("webhook", id)),
        json!({ "name": c.name, "url": c.url, "events": c.events, "client_id": b.client_id }),
    )
    .await;
    Ok(Json(json!({ "webhook": fetch(&st, id).await?, "secret": secret })))
}

pub async fn update(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>, Json(b): Json<SubscriptionIn>) -> ApiResult<Json<Subscription>> {
    u.require(Role::Admin)?;
    let c = check(&st, &b).await?;
    let n = sqlx::query(
        "UPDATE webhook_subscriptions SET name = $2, url = $3, client_id = $4, events = $5, internal_notes = $6, enabled = $7, updated_at = now()
          WHERE id = $1",
    )
    .bind(id)
    .bind(&c.name)
    .bind(&c.url)
    .bind(b.client_id)
    .bind(&c.events)
    .bind(b.internal_notes)
    .bind(b.enabled)
    .execute(&st.db)
    .await?
    .rows_affected();
    if n == 0 {
        return Err(ApiError::NotFound("webhook"));
    }
    auth::audit(
        &st.db,
        Some(u.id),
        "webhook.update",
        Some(("webhook", id)),
        json!({ "name": c.name, "url": c.url, "events": c.events, "client_id": b.client_id, "enabled": b.enabled }),
    )
    .await;
    Ok(Json(fetch(&st, id).await?))
}

pub async fn remove(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    u.require(Role::Admin)?;
    let name: Option<String> = sqlx::query_scalar("DELETE FROM webhook_subscriptions WHERE id = $1 RETURNING name").bind(id).fetch_optional(&st.db).await?;
    let name = name.ok_or(ApiError::NotFound("webhook"))?;
    auth::audit(&st.db, Some(u.id), "webhook.delete", Some(("webhook", id)), json!({ "name": name })).await;
    Ok(Json(json!({ "ok": true })))
}

/// A new signing secret: deliveries queued from now on use it, so update the receiver first
/// or expect a few failed signature checks.
pub async fn rotate_secret(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    u.require(Role::Admin)?;
    let secret = webhooks::new_secret();
    let (sealed, encrypted) = crate::crypto::store(st.cfg.data_key.as_ref(), secret.as_bytes());
    let n = sqlx::query("UPDATE webhook_subscriptions SET secret = $2, secret_sealed = $3, updated_at = now() WHERE id = $1")
        .bind(id)
        .bind(sealed)
        .bind(encrypted)
        .execute(&st.db)
        .await?
        .rows_affected();
    if n == 0 {
        return Err(ApiError::NotFound("webhook"));
    }
    auth::audit(&st.db, Some(u.id), "webhook.rotate_secret", Some(("webhook", id)), json!({})).await;
    Ok(Json(json!({ "secret": secret })))
}

/// Queues a `ping` delivery (even for a disabled subscription): the result shows in its log.
pub async fn test(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    u.require(Role::Admin)?;
    fetch(&st, id).await?;
    sqlx::query("INSERT INTO webhook_deliveries (subscription_id, event, payload) VALUES ($1, 'ping', $2)")
        .bind(id)
        .bind(json!({ "message": "Test delivery from RMM" }))
        .execute(&st.db)
        .await?;
    st.notify_wake.notify_one();
    auth::audit(&st.db, Some(u.id), "webhook.test", Some(("webhook", id)), json!({})).await;
    Ok(Json(json!({ "ok": true })))
}

#[derive(Serialize, sqlx::FromRow)]
pub struct Delivery {
    id: i64,
    /// The id receivers see in `X-RMM-Delivery`; the same for every retry.
    delivery_id: Uuid,
    event: String,
    /// pending / sent / failed
    status: String,
    attempts: i32,
    response_status: Option<i32>,
    duration_ms: Option<i32>,
    last_error: Option<String>,
    created_at: DateTime<Utc>,
    sent_at: Option<DateTime<Utc>>,
    next_attempt_at: DateTime<Utc>,
}

#[derive(Deserialize)]
pub struct DeliveriesQuery {
    /// pending / sent / failed
    status: Option<String>,
    limit: Option<i64>,
}

pub async fn deliveries(
    State(st): State<Arc<AppState>>,
    u: User,
    Path(id): Path<Uuid>,
    Query(q): Query<DeliveriesQuery>,
) -> ApiResult<Json<Vec<Delivery>>> {
    u.require(Role::Admin)?;
    fetch(&st, id).await?;
    Ok(Json(
        sqlx::query_as(
            "SELECT id, delivery_id, event, status, attempts, response_status, duration_ms, last_error, created_at, sent_at, next_attempt_at
               FROM webhook_deliveries WHERE subscription_id = $1 AND ($2::text IS NULL OR status = $2)
              ORDER BY id DESC LIMIT $3",
        )
        .bind(id)
        .bind(q.status.as_deref().filter(|s| !s.is_empty()))
        .bind(q.limit.unwrap_or(100).clamp(1, 500))
        .fetch_all(&st.db)
        .await?,
    ))
}

/// One delivery with the data it carries.
pub async fn delivery(State(st): State<Arc<AppState>>, u: User, Path(id): Path<i64>) -> ApiResult<Json<Value>> {
    u.require(Role::Admin)?;
    let row: Option<(Value, Value)> = sqlx::query_as(
        "SELECT to_jsonb(d) - 'payload', d.payload FROM (
            SELECT id, delivery_id, subscription_id, event, status, attempts, response_status, duration_ms, last_error, created_at, sent_at, next_attempt_at, payload
              FROM webhook_deliveries WHERE id = $1) d",
    )
    .bind(id)
    .fetch_optional(&st.db)
    .await?;
    let (mut head, payload) = row.ok_or(ApiError::NotFound("delivery"))?;
    head["payload"] = payload;
    Ok(Json(head))
}

/// Sends a delivery again (it keeps its id): for after the receiver was fixed.
pub async fn redeliver(State(st): State<Arc<AppState>>, u: User, Path(id): Path<i64>) -> ApiResult<Json<Value>> {
    u.require(Role::Admin)?;
    let sub: Option<Uuid> = sqlx::query_scalar(
        "UPDATE webhook_deliveries SET status = 'pending', attempts = 0, next_attempt_at = now(), last_error = NULL
          WHERE id = $1 RETURNING subscription_id",
    )
    .bind(id)
    .fetch_optional(&st.db)
    .await?;
    let sub = sub.ok_or(ApiError::NotFound("delivery"))?;
    st.notify_wake.notify_one();
    auth::audit(&st.db, Some(u.id), "webhook.redeliver", Some(("webhook", sub)), json!({ "delivery": id })).await;
    Ok(Json(json!({ "ok": true })))
}
