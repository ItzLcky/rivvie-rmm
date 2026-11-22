//! SIEM destinations (admins): where the audit log, detections and alerts are streamed, and the
//! delivery status of each. Delivery itself is `crate::siem`.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::auth::{self, Role, User};
use crate::error::{ApiError, ApiResult};
use crate::siem;
use crate::state::AppState;

#[derive(Serialize, sqlx::FromRow)]
pub struct DestinationView {
    id: Uuid,
    name: String,
    kind: String,
    address: String,
    framing: String,
    https_format: String,
    /// The token is never sent back.
    has_token: bool,
    ca_pem: Option<String>,
    facility: i16,
    send_audit: bool,
    send_detections: bool,
    send_alerts: bool,
    enabled: bool,
    consecutive_failures: i32,
    next_attempt_at: DateTime<Utc>,
    last_attempt_at: Option<DateTime<Utc>>,
    last_success_at: Option<DateTime<Utc>>,
    last_error: Option<String>,
    sent_total: i64,
    dropped_total: i64,
    /// Events waiting to be sent.
    pending: i64,
    created_at: DateTime<Utc>,
}

const SELECT: &str = "SELECT d.id, d.name, d.kind, d.address, d.framing, d.https_format, d.token IS NOT NULL AS has_token, d.ca_pem, d.facility,
       d.send_audit, d.send_detections, d.send_alerts, d.enabled, d.consecutive_failures, d.next_attempt_at, d.last_attempt_at,
       d.last_success_at, d.last_error, d.sent_total, d.dropped_total,
       (SELECT count(*) FROM siem_outbox o WHERE o.destination_id = d.id) AS pending, d.created_at
  FROM siem_destinations d";

async fn fetch(st: &AppState, id: Uuid) -> ApiResult<DestinationView> {
    sqlx::query_as(sqlx::AssertSqlSafe(format!("{SELECT} WHERE d.id = $1"))).bind(id).fetch_optional(&st.db).await?.ok_or(ApiError::NotFound("destination"))
}

pub async fn list(State(st): State<Arc<AppState>>, u: User) -> ApiResult<Json<Value>> {
    u.require(Role::Admin)?;
    let rows: Vec<DestinationView> = sqlx::query_as(sqlx::AssertSqlSafe(format!("{SELECT} ORDER BY lower(d.name)"))).fetch_all(&st.db).await?;
    Ok(Json(json!({ "destinations": rows, "retain_days": siem::RETAIN_DAYS })))
}

#[derive(Deserialize)]
pub struct DestinationIn {
    name: String,
    kind: String,
    address: String,
    #[serde(default = "octet")]
    framing: String,
    #[serde(default = "generic")]
    https_format: String,
    /// Omitted = unchanged; "" clears it.
    token: Option<String>,
    /// Omitted or empty = none.
    ca_pem: Option<String>,
    #[serde(default = "audit_facility")]
    facility: i16,
    #[serde(default = "yes")]
    send_audit: bool,
    #[serde(default)]
    send_detections: bool,
    #[serde(default)]
    send_alerts: bool,
    #[serde(default = "yes")]
    enabled: bool,
}

fn yes() -> bool {
    true
}
fn octet() -> String {
    "octet".into()
}
fn generic() -> String {
    "generic".into()
}
fn audit_facility() -> i16 {
    13
}

struct Checked {
    name: String,
    address: String,
    ca_pem: Option<String>,
    token: Option<Option<(Vec<u8>, bool)>>,
}

fn check(st: &AppState, b: &DestinationIn) -> ApiResult<Checked> {
    let bad = |m: &str| ApiError::BadRequest(m.into());
    let name = b.name.trim();
    if name.is_empty() || name.chars().count() > 100 {
        return Err(bad("name must be 1-100 characters"));
    }
    if !matches!(b.framing.as_str(), "octet" | "newline") {
        return Err(bad("framing must be octet or newline"));
    }
    if !matches!(b.https_format.as_str(), "generic" | "splunk_hec") {
        return Err(bad("format must be generic or splunk_hec"));
    }
    if !(0..=23).contains(&b.facility) {
        return Err(bad("facility must be 0-23"));
    }
    if !(b.send_audit || b.send_detections || b.send_alerts) {
        return Err(bad("choose at least one kind of event to send"));
    }
    let ca_pem = b.ca_pem.as_deref().map(str::trim).filter(|p| !p.is_empty());
    let address = siem::validate(&b.kind, &b.address, ca_pem).map_err(ApiError::BadRequest)?;
    let token = match b.token.as_deref() {
        None => None,
        Some(t) if t.trim().is_empty() => Some(None),
        // Only an https destination has anywhere to put it.
        Some(_) if b.kind != "https" => return Err(bad("only an HTTPS destination takes a token")),
        Some(t) => Some(Some(crate::crypto::store(st.cfg.data_key.as_ref(), t.trim().as_bytes()))),
    };
    Ok(Checked { name: name.to_string(), address, ca_pem: ca_pem.map(str::to_string), token })
}

fn conflict(e: sqlx::Error) -> ApiError {
    match e {
        sqlx::Error::Database(d) if d.is_unique_violation() => ApiError::Conflict("a destination with that name already exists".into()),
        e => e.into(),
    }
}

pub async fn create(State(st): State<Arc<AppState>>, u: User, Json(b): Json<DestinationIn>) -> ApiResult<Json<DestinationView>> {
    u.require(Role::Admin)?;
    let c = check(&st, &b)?;
    let id = Uuid::new_v4();
    let token = c.token.flatten();
    sqlx::query(
        "INSERT INTO siem_destinations (id, name, kind, address, framing, https_format, token, token_sealed, ca_pem, facility,
                                        send_audit, send_detections, send_alerts, enabled, created_by)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)",
    )
    .bind(id)
    .bind(&c.name)
    .bind(&b.kind)
    .bind(&c.address)
    .bind(&b.framing)
    .bind(&b.https_format)
    .bind(token.as_ref().map(|t| t.0.clone()))
    .bind(token.as_ref().is_some_and(|t| t.1))
    .bind(&c.ca_pem)
    .bind(b.facility)
    .bind(b.send_audit)
    .bind(b.send_detections)
    .bind(b.send_alerts)
    .bind(b.enabled)
    .bind(u.id)
    .execute(&st.db)
    .await
    .map_err(conflict)?;
    auth::audit(&st.db, Some(u.id), "siem.create", Some(("siem_destination", id)), json!({ "name": c.name, "kind": b.kind, "address": c.address })).await;
    Ok(Json(fetch(&st, id).await?))
}

pub async fn update(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>, Json(b): Json<DestinationIn>) -> ApiResult<Json<DestinationView>> {
    u.require(Role::Admin)?;
    let cur = fetch(&st, id).await?;
    let c = check(&st, &b)?;
    // Changing the kind away from https drops the token it can't use.
    let keep_token = c.token.is_none() && b.kind == "https";
    let token = c.token.clone().flatten();
    sqlx::query(
        "UPDATE siem_destinations SET name = $2, kind = $3, address = $4, framing = $5, https_format = $6,
                token = CASE WHEN $7 THEN token ELSE $8 END, token_sealed = CASE WHEN $7 THEN token_sealed ELSE $9 END,
                ca_pem = $10, facility = $11, send_audit = $12, send_detections = $13, send_alerts = $14, enabled = $15,
                -- An edit is a reason to try again now.
                consecutive_failures = 0, next_attempt_at = now(), updated_at = now()
          WHERE id = $1",
    )
    .bind(id)
    .bind(&c.name)
    .bind(&b.kind)
    .bind(&c.address)
    .bind(&b.framing)
    .bind(&b.https_format)
    .bind(keep_token)
    .bind(token.as_ref().map(|t| t.0.clone()))
    .bind(token.as_ref().is_some_and(|t| t.1))
    .bind(&c.ca_pem)
    .bind(b.facility)
    .bind(b.send_audit)
    .bind(b.send_detections)
    .bind(b.send_alerts)
    .bind(b.enabled)
    .execute(&st.db)
    .await
    .map_err(conflict)?;
    auth::audit(
        &st.db,
        Some(u.id),
        "siem.update",
        Some(("siem_destination", id)),
        json!({ "name": c.name, "kind": b.kind, "address": c.address, "enabled": b.enabled, "was": cur.name }),
    )
    .await;
    Ok(Json(fetch(&st, id).await?))
}

pub async fn remove(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    u.require(Role::Admin)?;
    let cur = fetch(&st, id).await?;
    sqlx::query("DELETE FROM siem_destinations WHERE id = $1").bind(id).execute(&st.db).await?;
    auth::audit(&st.db, Some(u.id), "siem.delete", Some(("siem_destination", id)), json!({ "name": cur.name, "pending_dropped": cur.pending })).await;
    Ok(Json(json!({ "ok": true })))
}

/// Sends one test event right away (it isn't queued) and reports the outcome.
pub async fn test(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    u.require(Role::Admin)?;
    let d: siem::Destination =
        sqlx::query_as(sqlx::AssertSqlSafe(format!("SELECT {} FROM siem_destinations WHERE id = $1", siem::DESTINATION_COLUMNS)))
            .bind(id)
            .fetch_optional(&st.db)
            .await?
            .ok_or(ApiError::NotFound("destination"))?;
    let result = siem::send(&st, &d, &[siem::test_event(&d)]).await;
    auth::audit(&st.db, Some(u.id), "siem.test", Some(("siem_destination", id)), json!({ "ok": result.is_ok() })).await;
    Ok(Json(match result {
        Ok(()) => json!({ "ok": true }),
        Err(e) => json!({ "ok": false, "error": format!("{e:#}") }),
    }))
}
