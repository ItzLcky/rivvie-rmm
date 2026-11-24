//! Scheduled reports ([`crate::reports`]): `/report-schedules`, their runs and the stored PDFs.
//!
//! Technicians manage their own schedules; admins manage everyone's. A schedule keeps the
//! user who made it as its owner, and runs with the owner's access.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use axum::response::Response;
use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::auth::{self, Role, User};
use crate::error::{ApiError, ApiResult};
use crate::reports::{self, Kind};
use crate::state::AppState;

const MAX_RECIPIENTS: usize = 50;

#[derive(Serialize, sqlx::FromRow)]
pub struct ScheduleRow {
    id: Uuid,
    name: String,
    report: String,
    client_id: Option<Uuid>,
    client_name: Option<String>,
    params: Value,
    cron: String,
    timezone: String,
    user_ids: Vec<Uuid>,
    contact_ids: Vec<Uuid>,
    extra_emails: Vec<String>,
    subject: String,
    message: String,
    enabled: bool,
    owner_id: Uuid,
    owner_name: String,
    next_run_at: Option<DateTime<Utc>>,
    last_run_at: Option<DateTime<Utc>>,
    last_status: Option<String>,
    last_error: Option<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

const SELECT: &str = "SELECT r.id, r.name, r.report, r.client_id, c.name AS client_name, r.params, r.cron, r.timezone, r.user_ids,
        r.contact_ids, r.extra_emails, r.subject, r.message, r.enabled, r.owner_id, o.name AS owner_name, r.next_run_at,
        r.last_run_at, r.last_status, r.last_error, r.created_at, r.updated_at
   FROM report_schedules r JOIN users o ON o.id = r.owner_id LEFT JOIN clients c ON c.id = r.client_id";

/// The schedule, if `u` may manage it (its owner, or an admin); not found otherwise.
async fn fetch(st: &AppState, u: &User, id: Uuid) -> ApiResult<ScheduleRow> {
    u.require(Role::Technician)?;
    let row: ScheduleRow = sqlx::query_as(sqlx::AssertSqlSafe(format!("{SELECT} WHERE r.id = $1")))
        .bind(id)
        .fetch_optional(&st.db)
        .await?
        .ok_or(ApiError::NotFound("report schedule"))?;
    if row.owner_id != u.id && u.role() != Role::Admin {
        return Err(ApiError::NotFound("report schedule"));
    }
    Ok(row)
}

pub async fn list(State(st): State<Arc<AppState>>, u: User) -> ApiResult<Json<Vec<ScheduleRow>>> {
    u.require(Role::Technician)?;
    let mine = (u.role() != Role::Admin).then_some(u.id);
    Ok(Json(
        sqlx::query_as(sqlx::AssertSqlSafe(format!("{SELECT} WHERE ($1::uuid IS NULL OR r.owner_id = $1) ORDER BY lower(r.name), r.id")))
            .bind(mine)
            .fetch_all(&st.db)
            .await?,
    ))
}

pub async fn get(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<ScheduleRow>> {
    Ok(Json(fetch(&st, &u, id).await?))
}

#[derive(Deserialize)]
pub struct Body {
    name: String,
    report: String,
    #[serde(default)]
    client_id: Option<Uuid>,
    #[serde(default)]
    params: Option<Value>,
    cron: String,
    #[serde(default)]
    timezone: Option<String>,
    #[serde(default)]
    user_ids: Vec<Uuid>,
    #[serde(default)]
    contact_ids: Vec<Uuid>,
    #[serde(default)]
    extra_emails: Vec<String>,
    #[serde(default)]
    subject: String,
    #[serde(default)]
    message: String,
    #[serde(default = "yes")]
    enabled: bool,
}

fn yes() -> bool {
    true
}

fn bad(m: impl Into<String>) -> ApiError {
    ApiError::BadRequest(m.into())
}

/// A checked body, ready to store.
struct Clean {
    name: String,
    kind: Kind,
    client_id: Option<Uuid>,
    params: Value,
    cron: String,
    timezone: String,
    user_ids: Vec<Uuid>,
    contact_ids: Vec<Uuid>,
    extra_emails: Vec<String>,
    subject: String,
    message: String,
    enabled: bool,
    next_run_at: Option<DateTime<Utc>>,
}

fn dedup<T: PartialEq + Clone>(v: &[T]) -> Vec<T> {
    let mut out: Vec<T> = Vec::new();
    for x in v {
        if !out.contains(x) {
            out.push(x.clone());
        }
    }
    out
}

/// Checks a schedule for `owner`, saved by `u` (the owner, or an admin editing it).
async fn clean(st: &AppState, u: &User, owner: &User, b: Body) -> ApiResult<Clean> {
    let name = b.name.trim().to_string();
    if name.is_empty() || name.chars().count() > 200 {
        return Err(bad("give the schedule a name (up to 200 characters)"));
    }
    let kind = Kind::parse(&b.report).ok_or_else(|| bad("report must be service_desk, utilisation, profitability or qbr"))?;
    match kind {
        Kind::Qbr if b.client_id.is_none() => return Err(bad("a QBR is for one client: pick it")),
        Kind::Utilisation | Kind::Profitability if b.client_id.is_some() => {
            return Err(bad(format!("a {} report covers every client; it takes no client", kind.as_str())));
        }
        _ => {}
    }
    if let Some(c) = b.client_id {
        let exists: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM clients WHERE id = $1)").bind(c).fetch_one(&st.db).await?;
        if !exists || !u.can_see_client(c) {
            return Err(ApiError::NotFound("client"));
        }
    }
    if let Some(why) = reports::cannot_view(owner, kind, b.client_id) {
        return Err(if owner.id == u.id { ApiError::Forbidden } else { bad(format!("the schedule's owner {why}")) });
    }
    let params = b.params.unwrap_or_else(|| json!({}));
    let preset = reports::preset_of(kind, &params).map_err(bad)?;
    let range = match preset {
        reports::Preset::LastWeek => "last_week",
        reports::Preset::LastMonth => "last_month",
        reports::Preset::LastQuarter => "last_quarter",
        reports::Preset::Last30Days => "last_30_days",
    };
    let timezone = b.timezone.map(|t| t.trim().to_string()).filter(|t| !t.is_empty()).unwrap_or_else(|| "UTC".into());
    let cron = b.cron.trim().to_string();
    let next_run_at = reports::next_run_at(b.enabled, &cron, &timezone).map_err(bad)?;

    let user_ids = dedup(&b.user_ids);
    let contact_ids = dedup(&b.contact_ids);
    let extra_emails: Vec<String> = dedup(&b.extra_emails.iter().map(|e| e.trim().to_lowercase()).filter(|e| !e.is_empty()).collect::<Vec<_>>());
    if user_ids.len() + contact_ids.len() + extra_emails.len() == 0 {
        return Err(bad("choose at least one recipient"));
    }
    if user_ids.len() + contact_ids.len() + extra_emails.len() > MAX_RECIPIENTS {
        return Err(bad(format!("at most {MAX_RECIPIENTS} recipients")));
    }
    for id in &user_ids {
        let r = reports::load_user(st, *id).await?.ok_or_else(|| bad("a recipient isn't an active user"))?;
        if let Some(why) = reports::cannot_receive(&r, owner, kind, b.client_id) {
            return Err(bad(format!("{} {why}, so can't receive this report", r.name)));
        }
    }
    if !contact_ids.is_empty() {
        let contacts: Vec<(Uuid, Uuid, String, String)> =
            sqlx::query_as("SELECT id, client_id, name, email FROM contacts WHERE id = ANY($1)").bind(&contact_ids).fetch_all(&st.db).await?;
        if contacts.len() != contact_ids.len() || contacts.iter().any(|c| !u.can_see_client(c.1)) {
            return Err(ApiError::NotFound("contact"));
        }
        for (_, client, name, email) in &contacts {
            reports::recipient_rule(kind, b.client_id, *client).map_err(bad)?;
            if !reports::valid_email(email) {
                return Err(bad(format!("{name} has no email address")));
            }
        }
    }
    if !extra_emails.is_empty() {
        // Anything outside the MSP and its clients' contacts is an admin's call.
        if u.role() != Role::Admin || owner.role() != Role::Admin {
            return Err(ApiError::Denied("only admins can send reports to other email addresses".into()));
        }
        if let Some(e) = extra_emails.iter().find(|e| !reports::valid_email(e)) {
            return Err(bad(format!("{e} isn't an email address")));
        }
    }
    let subject = b.subject.trim().to_string();
    if subject.chars().count() > 200 || b.message.chars().count() > 4000 {
        return Err(bad("the subject is up to 200 characters and the message up to 4000"));
    }
    Ok(Clean {
        name,
        kind,
        client_id: b.client_id,
        params: json!({ "range": range }),
        cron,
        timezone,
        user_ids,
        contact_ids,
        extra_emails,
        subject,
        message: b.message.trim().to_string(),
        enabled: b.enabled,
        next_run_at,
    })
}

pub async fn create(State(st): State<Arc<AppState>>, u: User, Json(b): Json<Body>) -> ApiResult<Json<ScheduleRow>> {
    u.require(Role::Technician)?;
    let c = clean(&st, &u, &u, b).await?;
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO report_schedules (id, name, report, client_id, params, cron, timezone, user_ids, contact_ids, extra_emails, subject,
                                       message, enabled, owner_id, next_run_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)",
    )
    .bind(id)
    .bind(&c.name)
    .bind(c.kind.as_str())
    .bind(c.client_id)
    .bind(&c.params)
    .bind(&c.cron)
    .bind(&c.timezone)
    .bind(&c.user_ids)
    .bind(&c.contact_ids)
    .bind(&c.extra_emails)
    .bind(&c.subject)
    .bind(&c.message)
    .bind(c.enabled)
    .bind(u.id)
    .bind(c.next_run_at)
    .execute(&st.db)
    .await?;
    auth::audit(&st.db, Some(u.id), "report_schedule.create", Some(("report_schedule", id)), json!({ "name": c.name, "report": c.kind.as_str() })).await;
    Ok(Json(fetch(&st, &u, id).await?))
}

pub async fn update(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>, Json(b): Json<Body>) -> ApiResult<Json<ScheduleRow>> {
    let current = fetch(&st, &u, id).await?;
    let owner = if current.owner_id == u.id {
        u.clone()
    } else {
        reports::load_user(&st, current.owner_id).await?.ok_or_else(|| bad("the schedule's owner is disabled: delete it and make a new one"))?
    };
    let c = clean(&st, &u, &owner, b).await?;
    // The body replaces everything: other addresses (`extra_emails`) only stay when an admin saves.
    sqlx::query(
        "UPDATE report_schedules SET name = $2, report = $3, client_id = $4, params = $5, cron = $6, timezone = $7, user_ids = $8,
                contact_ids = $9, extra_emails = $10, subject = $11, message = $12, enabled = $13, next_run_at = $14, updated_at = now()
          WHERE id = $1",
    )
    .bind(id)
    .bind(&c.name)
    .bind(c.kind.as_str())
    .bind(c.client_id)
    .bind(&c.params)
    .bind(&c.cron)
    .bind(&c.timezone)
    .bind(&c.user_ids)
    .bind(&c.contact_ids)
    .bind(&c.extra_emails)
    .bind(&c.subject)
    .bind(&c.message)
    .bind(c.enabled)
    .bind(c.next_run_at)
    .execute(&st.db)
    .await?;
    auth::audit(&st.db, Some(u.id), "report_schedule.update", Some(("report_schedule", id)), json!({ "name": c.name, "report": c.kind.as_str() })).await;
    Ok(Json(fetch(&st, &u, id).await?))
}

pub async fn remove(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    let current = fetch(&st, &u, id).await?;
    let keys: Vec<String> =
        sqlx::query_scalar("SELECT storage_key FROM report_runs WHERE schedule_id = $1 AND storage_key IS NOT NULL").bind(id).fetch_all(&st.db).await?;
    sqlx::query("DELETE FROM report_schedules WHERE id = $1").bind(id).execute(&st.db).await?;
    for k in keys {
        if let Err(e) = st.storage.delete(&k).await {
            tracing::warn!(schedule = %id, "deleting a report PDF: {e:#}");
        }
    }
    auth::audit(&st.db, Some(u.id), "report_schedule.delete", Some(("report_schedule", id)), json!({ "name": current.name })).await;
    Ok(Json(json!({ "ok": true })))
}

#[derive(Serialize, sqlx::FromRow)]
pub struct RunRow {
    id: Uuid,
    schedule_id: Uuid,
    trigger: String,
    started_at: DateTime<Utc>,
    finished_at: Option<DateTime<Utc>>,
    status: String,
    from_date: Option<NaiveDate>,
    to_date: Option<NaiveDate>,
    bytes: Option<i64>,
    recipients: Value,
    error: Option<String>,
    started_by_name: Option<String>,
    /// A PDF is there to download.
    stored: bool,
}

const RUN_SELECT: &str = "SELECT r.id, r.schedule_id, r.trigger, r.started_at, r.finished_at, r.status, r.from_date, r.to_date, r.bytes,
        r.recipients, r.error, u.name AS started_by_name, r.storage_key IS NOT NULL AS stored
   FROM report_runs r LEFT JOIN users u ON u.id = r.started_by";

/// "Send now": runs the schedule at once (its timetable is unchanged) and returns the run.
pub async fn run_now(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<RunRow>> {
    let current = fetch(&st, &u, id).await?;
    let run_id = reports::run_schedule(&st, id, Some(u.id)).await?;
    let run: RunRow = sqlx::query_as(sqlx::AssertSqlSafe(format!("{RUN_SELECT} WHERE r.id = $1"))).bind(run_id).fetch_one(&st.db).await?;
    auth::audit(&st.db, Some(u.id), "report_schedule.run", Some(("report_schedule", id)), json!({ "name": current.name, "status": run.status })).await;
    Ok(Json(run))
}

/// The latest 100 runs, newest first.
pub async fn runs(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<Vec<RunRow>>> {
    fetch(&st, &u, id).await?;
    Ok(Json(
        sqlx::query_as(sqlx::AssertSqlSafe(format!("{RUN_SELECT} WHERE r.schedule_id = $1 ORDER BY r.started_at DESC LIMIT 100")))
            .bind(id)
            .fetch_all(&st.db)
            .await?,
    ))
}

/// A run's PDF, for whoever may manage its schedule.
pub async fn download(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Response> {
    let row: Option<(Uuid, Option<String>, Option<String>)> =
        sqlx::query_as("SELECT schedule_id, storage_key, file_name FROM report_runs WHERE id = $1").bind(id).fetch_optional(&st.db).await?;
    let (schedule_id, key, name) = row.ok_or(ApiError::NotFound("report run"))?;
    fetch(&st, &u, schedule_id).await.map_err(|_| ApiError::NotFound("report run"))?;
    let key = key.ok_or(ApiError::NotFound("report PDF"))?;
    let bytes = st.storage.get(&key).await?;
    super::billing::pdf_bytes_response(bytes, name.as_deref().unwrap_or("report"))
}
