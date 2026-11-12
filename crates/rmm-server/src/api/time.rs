//! Time: entries (by hand or from the timer), weekly timesheets, submission and approval.
//!
//! Technicians log their own time; people with `time.approve` see and decide everyone's. An
//! entry is editable until its week is submitted, and locked for good once it's invoiced.
//! Approval works out each entry's contract coverage, rate and amount
//! ([`crate::billing::resolve_entry`]). Rates and amounts are only shown with `billing.read`.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, Query, State};
use chrono::{DateTime, Datelike, Duration, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::PgConnection;
use uuid::Uuid;

use crate::auth::{self, Perm, Role, User};
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;
use crate::tickets::{self, Author};

#[derive(Serialize, sqlx::FromRow)]
pub struct EntryRow {
    id: Uuid,
    user_id: Uuid,
    user_name: String,
    client_id: Option<Uuid>,
    client_name: Option<String>,
    ticket_id: Option<Uuid>,
    ticket_number: Option<i64>,
    ticket_subject: Option<String>,
    project_id: Option<Uuid>,
    project_name: Option<String>,
    work_type_id: Uuid,
    work_type_name: String,
    started_at: DateTime<Utc>,
    ended_at: Option<DateTime<Utc>>,
    minutes: Option<i32>,
    billable: bool,
    note: String,
    coverage: Option<String>,
    contract_name: Option<String>,
    rate: Option<i64>,
    amount: Option<i64>,
    invoiced: bool,
    week_start: NaiveDate,
    /// open / submitted / approved / rejected (open when there's no timesheet yet).
    week_status: String,
}

const COLS: &str = "e.id, e.user_id, u.name AS user_name, e.client_id, c.name AS client_name, e.ticket_id, t.number AS ticket_number,
     t.subject AS ticket_subject, e.project_id, p.name AS project_name, e.work_type_id, w.name AS work_type_name, e.started_at, e.ended_at,
     e.minutes, e.billable, e.note, e.coverage, ct.name AS contract_name, e.rate, e.amount, e.invoice_line_id IS NOT NULL AS invoiced,
     (date_trunc('week', e.started_at AT TIME ZONE 'UTC'))::date AS week_start, coalesce(ts.status, 'open') AS week_status
  FROM time_entries e JOIN users u ON u.id = e.user_id JOIN work_types w ON w.id = e.work_type_id
  LEFT JOIN clients c ON c.id = e.client_id LEFT JOIN tickets t ON t.id = e.ticket_id LEFT JOIN projects p ON p.id = e.project_id
  LEFT JOIN contracts ct ON ct.id = e.contract_id
  LEFT JOIN timesheets ts ON ts.user_id = e.user_id AND ts.week_start = (date_trunc('week', e.started_at AT TIME ZONE 'UTC'))::date";

/// Rates and money are for billing people only.
fn redact(u: &User, mut rows: Vec<EntryRow>) -> Vec<EntryRow> {
    if !u.has(Perm::BillingRead) {
        for r in &mut rows {
            r.rate = None;
            r.amount = None;
        }
    }
    rows
}

pub fn week_of(day: NaiveDate) -> NaiveDate {
    day - Duration::days(day.weekday().num_days_from_monday() as i64)
}

async fn fetch(st: &AppState, id: Uuid) -> ApiResult<EntryRow> {
    sqlx::query_as(sqlx::AssertSqlSafe(format!("SELECT {COLS} WHERE e.id = $1")))
        .bind(id)
        .fetch_optional(&st.db)
        .await?
        .ok_or(ApiError::NotFound("time entry"))
}

/// The entry, if `u` may change it: their own (or an approver's), in an open week, not billed.
async fn editable(st: &AppState, u: &User, id: Uuid) -> ApiResult<EntryRow> {
    let e = fetch(st, id).await?;
    if e.user_id != u.id && !u.has(Perm::TimeApprove) {
        return Err(ApiError::NotFound("time entry"));
    }
    if e.invoiced {
        return Err(ApiError::Conflict("this time has been invoiced and can't change".into()));
    }
    if matches!(e.week_status.as_str(), "submitted" | "approved") {
        return Err(ApiError::Conflict(format!("that week's timesheet is {}; reopen it first", e.week_status)));
    }
    Ok(e)
}

async fn week_locked(db: &mut PgConnection, user: Uuid, day: NaiveDate) -> sqlx::Result<bool> {
    sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM timesheets WHERE user_id = $1 AND week_start = $2 AND status IN ('submitted', 'approved'))")
        .bind(user)
        .bind(week_of(day))
        .fetch_one(&mut *db)
        .await
}

#[derive(Deserialize)]
pub struct ListQuery {
    user_id: Option<Uuid>,
    from: Option<NaiveDate>,
    to: Option<NaiveDate>,
    ticket_id: Option<Uuid>,
    project_id: Option<Uuid>,
    client_id: Option<Uuid>,
}

/// Time entries: the user's own by default; everyone's (or a person's) for approvers; a
/// ticket's or project's for anyone who sees it.
pub async fn list(State(st): State<Arc<AppState>>, u: User, Query(q): Query<ListQuery>) -> ApiResult<Json<Vec<EntryRow>>> {
    let by_work = q.ticket_id.is_some() || q.project_id.is_some();
    let user = match q.user_id {
        Some(x) if x != u.id => {
            u.need(Perm::TimeApprove)?;
            Some(x)
        }
        Some(x) => Some(x),
        None if by_work || q.client_id.is_some() => None,
        None => Some(u.id),
    };
    if user.is_none() && !by_work && !u.has(Perm::TimeApprove) && !u.has(Perm::BillingRead) {
        return Err(ApiError::Forbidden);
    }
    if let Some(t) = q.ticket_id {
        super::tickets::visible(&st, &u, t).await?;
    }
    let rows: Vec<EntryRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT {COLS}
          WHERE ($1::uuid IS NULL OR e.user_id = $1) AND ($2::date IS NULL OR e.started_at >= $2) AND ($3::date IS NULL OR e.started_at < $3::date + 1)
            AND ($4::uuid IS NULL OR e.ticket_id = $4) AND ($5::uuid IS NULL OR e.project_id = $5) AND ($6::uuid IS NULL OR e.client_id = $6)
            AND ($7::uuid[] IS NULL OR e.client_id IS NULL OR e.client_id = ANY($7))
          ORDER BY e.started_at DESC LIMIT 2000"
    )))
    .bind(user)
    .bind(q.from)
    .bind(q.to)
    .bind(q.ticket_id)
    .bind(q.project_id)
    .bind(q.client_id)
    .bind(u.scope())
    .fetch_all(&st.db)
    .await?;
    Ok(Json(redact(&u, rows)))
}

/// What an entry is for: a ticket, a project, or a client directly (or nothing: internal).
struct Target {
    client_id: Option<Uuid>,
    ticket_id: Option<Uuid>,
    project_id: Option<Uuid>,
}

async fn target(st: &AppState, u: &User, ticket: Option<Uuid>, project: Option<Uuid>, client: Option<Uuid>) -> ApiResult<Target> {
    if let Some(t) = ticket {
        let c = super::tickets::visible(st, u, t).await?;
        let p: Option<Uuid> = sqlx::query_scalar("SELECT project_id FROM tickets WHERE id = $1").bind(t).fetch_one(&st.db).await?;
        return Ok(Target { client_id: c, ticket_id: Some(t), project_id: project.or(p) });
    }
    if let Some(p) = project {
        let c: Uuid = sqlx::query_scalar("SELECT client_id FROM projects WHERE id = $1")
            .bind(p)
            .fetch_optional(&st.db)
            .await?
            .ok_or(ApiError::NotFound("project"))?;
        super::access::client(u, c).map_err(|_| ApiError::NotFound("project"))?;
        return Ok(Target { client_id: Some(c), ticket_id: None, project_id: Some(p) });
    }
    if let Some(c) = client {
        super::access::client(u, c)?;
    }
    Ok(Target { client_id: client, ticket_id: None, project_id: None })
}

async fn default_work_type(db: &sqlx::PgPool) -> ApiResult<Uuid> {
    sqlx::query_scalar("SELECT id FROM work_types WHERE active ORDER BY NOT billable, position, name LIMIT 1")
        .fetch_optional(db)
        .await?
        .ok_or_else(|| ApiError::BadRequest("add a work type first (Billing settings)".into()))
}

async fn check_work_type(db: &sqlx::PgPool, id: Uuid) -> ApiResult<bool> {
    let billable: Option<bool> =
        sqlx::query_scalar("SELECT billable FROM work_types WHERE id = $1 AND active").bind(id).fetch_optional(db).await?;
    billable.ok_or(ApiError::NotFound("work type"))
}

/// Notes the time on the ticket's timeline (internal), and optionally posts the note as a reply.
async fn on_ticket(st: &AppState, u: &User, entry: Uuid, public: bool) -> ApiResult<()> {
    let e = fetch(st, entry).await?;
    let Some(ticket) = e.ticket_id else { return Ok(()) };
    let mins = e.minutes.unwrap_or(0) as u64;
    let mut tx = st.db.begin().await?;
    tickets::add_event(
        &mut tx,
        ticket,
        "time",
        false,
        &Author::user(u.id),
        &e.note,
        json!({ "entry_id": entry, "minutes": mins, "work_type": e.work_type_name, "billable": e.billable, "user": e.user_name }),
    )
    .await?;
    let reply = if public && !e.note.trim().is_empty() {
        let id = tickets::add_event(&mut tx, ticket, "reply", true, &Author::user(u.id), e.note.trim(), json!({})).await?;
        crate::sla::replied(&mut tx, ticket).await?;
        Some(id)
    } else {
        None
    };
    tx.commit().await?;
    if let Some(ev) = reply
        && let Err(err) = crate::email::queue_reply(st, ticket, ev, e.note.trim(), &u.name).await
    {
        tracing::warn!(%ticket, "queueing reply email: {err:#}");
    }
    tickets::announce(st, ticket).await;
    Ok(())
}

#[derive(Deserialize)]
pub struct EntryIn {
    ticket_id: Option<Uuid>,
    project_id: Option<Uuid>,
    client_id: Option<Uuid>,
    work_type_id: Option<Uuid>,
    /// Defaults to `minutes` ago.
    started_at: Option<DateTime<Utc>>,
    minutes: i32,
    billable: Option<bool>,
    #[serde(default)]
    note: String,
    /// Also post the note to the ticket as a public reply.
    #[serde(default)]
    public: bool,
    /// Approvers can log time for someone else.
    user_id: Option<Uuid>,
}

fn check_minutes(m: i32) -> ApiResult<()> {
    if !(1..=1440).contains(&m) {
        return Err(ApiError::BadRequest("time must be between 1 minute and 24 hours".into()));
    }
    Ok(())
}

fn clean_note(s: &str) -> ApiResult<String> {
    if s.chars().count() > 10_000 {
        return Err(ApiError::BadRequest("notes are limited to 10,000 characters".into()));
    }
    Ok(s.trim().to_string())
}

pub async fn create(State(st): State<Arc<AppState>>, u: User, Json(b): Json<EntryIn>) -> ApiResult<Json<EntryRow>> {
    u.require(Role::Technician)?;
    check_minutes(b.minutes)?;
    let note = clean_note(&b.note)?;
    let who = match b.user_id {
        Some(x) if x != u.id => {
            u.need(Perm::TimeApprove)?;
            x
        }
        _ => u.id,
    };
    let t = target(&st, &u, b.ticket_id, b.project_id, b.client_id).await?;
    let wt = match b.work_type_id {
        Some(w) => w,
        None => default_work_type(&st.db).await?,
    };
    let type_billable = check_work_type(&st.db, wt).await?;
    let started = b.started_at.unwrap_or_else(|| Utc::now() - Duration::minutes(b.minutes as i64));
    let mut tx = st.db.begin().await?;
    if week_locked(&mut tx, who, started.date_naive()).await? {
        return Err(ApiError::Conflict("that week's timesheet is already submitted".into()));
    }
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO time_entries (id, user_id, client_id, ticket_id, project_id, work_type_id, started_at, ended_at, minutes, billable, note)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $7 + make_interval(mins => $8), $8, $9, $10)",
    )
    .bind(id)
    .bind(who)
    .bind(t.client_id)
    .bind(t.ticket_id)
    .bind(t.project_id)
    .bind(wt)
    .bind(started)
    .bind(b.minutes)
    .bind(b.billable.unwrap_or(type_billable) && t.client_id.is_some())
    .bind(&note)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    on_ticket(&st, &u, id, b.public).await?;
    Ok(Json(redact(&u, vec![fetch(&st, id).await?]).remove(0)))
}

#[derive(Deserialize)]
pub struct EntryPatch {
    work_type_id: Option<Uuid>,
    started_at: Option<DateTime<Utc>>,
    minutes: Option<i32>,
    billable: Option<bool>,
    note: Option<String>,
}

pub async fn update(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>, Json(b): Json<EntryPatch>) -> ApiResult<Json<EntryRow>> {
    let cur = editable(&st, &u, id).await?;
    if let Some(m) = b.minutes {
        check_minutes(m)?;
    }
    if let Some(w) = b.work_type_id {
        check_work_type(&st.db, w).await?;
    }
    let note = b.note.as_deref().map(clean_note).transpose()?;
    let started = b.started_at.unwrap_or(cur.started_at);
    let mut tx = st.db.begin().await?;
    if b.started_at.is_some() && week_locked(&mut tx, cur.user_id, started.date_naive()).await? {
        return Err(ApiError::Conflict("that week's timesheet is already submitted".into()));
    }
    sqlx::query(
        "UPDATE time_entries SET work_type_id = coalesce($2, work_type_id), started_at = $3,
                minutes = CASE WHEN ended_at IS NULL THEN minutes ELSE coalesce($4, minutes) END,
                ended_at = CASE WHEN ended_at IS NULL THEN NULL ELSE $3 + make_interval(mins => coalesce($4, minutes)) END,
                billable = coalesce($5, billable) AND client_id IS NOT NULL, note = coalesce($6, note),
                coverage = NULL, contract_id = NULL, rate = NULL, amount = NULL, updated_at = now()
          WHERE id = $1",
    )
    .bind(id)
    .bind(b.work_type_id)
    .bind(started)
    .bind(b.minutes)
    .bind(b.billable)
    .bind(note)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Json(redact(&u, vec![fetch(&st, id).await?]).remove(0)))
}

pub async fn remove(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    editable(&st, &u, id).await?;
    sqlx::query("DELETE FROM time_entries WHERE id = $1").bind(id).execute(&st.db).await?;
    Ok(Json(json!({ "ok": true })))
}

// ---------------------------------------------------------------------------
// Timer
// ---------------------------------------------------------------------------

pub async fn timer(State(st): State<Arc<AppState>>, u: User) -> ApiResult<Json<Option<EntryRow>>> {
    let row: Option<EntryRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!("SELECT {COLS} WHERE e.user_id = $1 AND e.ended_at IS NULL")))
        .bind(u.id)
        .fetch_optional(&st.db)
        .await?;
    Ok(Json(row.map(|r| redact(&u, vec![r]).remove(0))))
}

/// Ends a running timer: at least a minute, rounded up.
async fn stop_running(db: &mut PgConnection, user: Uuid) -> sqlx::Result<Option<Uuid>> {
    sqlx::query_scalar(
        "UPDATE time_entries SET ended_at = now(),
                minutes = least(1440, greatest(1, ceil(extract(epoch FROM now() - started_at) / 60)::int)), updated_at = now()
          WHERE user_id = $1 AND ended_at IS NULL RETURNING id",
    )
    .bind(user)
    .fetch_optional(&mut *db)
    .await
}

#[derive(Deserialize)]
pub struct StartIn {
    ticket_id: Option<Uuid>,
    project_id: Option<Uuid>,
    client_id: Option<Uuid>,
    work_type_id: Option<Uuid>,
    #[serde(default)]
    note: String,
}

/// Starts the timer (stopping one that's running).
pub async fn start(State(st): State<Arc<AppState>>, u: User, Json(b): Json<StartIn>) -> ApiResult<Json<EntryRow>> {
    u.require(Role::Technician)?;
    let t = target(&st, &u, b.ticket_id, b.project_id, b.client_id).await?;
    let wt = match b.work_type_id {
        Some(w) => w,
        None => default_work_type(&st.db).await?,
    };
    let billable = check_work_type(&st.db, wt).await?;
    let note = clean_note(&b.note)?;
    let mut tx = st.db.begin().await?;
    if week_locked(&mut tx, u.id, Utc::now().date_naive()).await? {
        return Err(ApiError::Conflict("this week's timesheet is already submitted".into()));
    }
    let stopped = stop_running(&mut tx, u.id).await?;
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO time_entries (id, user_id, client_id, ticket_id, project_id, work_type_id, started_at, billable, note)
         VALUES ($1, $2, $3, $4, $5, $6, now(), $7, $8)",
    )
    .bind(id)
    .bind(u.id)
    .bind(t.client_id)
    .bind(t.ticket_id)
    .bind(t.project_id)
    .bind(wt)
    .bind(billable && t.client_id.is_some())
    .bind(&note)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    if let Some(s) = stopped {
        on_ticket(&st, &u, s, false).await?;
    }
    Ok(Json(redact(&u, vec![fetch(&st, id).await?]).remove(0)))
}

#[derive(Deserialize, Default)]
pub struct StopIn {
    note: Option<String>,
    work_type_id: Option<Uuid>,
    billable: Option<bool>,
    #[serde(default)]
    public: bool,
}

pub async fn stop(State(st): State<Arc<AppState>>, u: User, Json(b): Json<StopIn>) -> ApiResult<Json<Option<EntryRow>>> {
    if let Some(w) = b.work_type_id {
        check_work_type(&st.db, w).await?;
    }
    let note = b.note.as_deref().map(clean_note).transpose()?;
    let mut tx = st.db.begin().await?;
    let Some(id) = stop_running(&mut tx, u.id).await? else { return Ok(Json(None)) };
    sqlx::query(
        "UPDATE time_entries SET note = coalesce($2, note), work_type_id = coalesce($3, work_type_id),
                billable = coalesce($4, billable) AND client_id IS NOT NULL WHERE id = $1",
    )
    .bind(id)
    .bind(note)
    .bind(b.work_type_id)
    .bind(b.billable)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    on_ticket(&st, &u, id, b.public).await?;
    Ok(Json(Some(redact(&u, vec![fetch(&st, id).await?]).remove(0))))
}

// ---------------------------------------------------------------------------
// Timesheets
// ---------------------------------------------------------------------------

#[derive(Serialize, sqlx::FromRow)]
pub struct SheetRow {
    id: Option<Uuid>,
    user_id: Uuid,
    user_name: String,
    week_start: NaiveDate,
    status: String,
    submitted_at: Option<DateTime<Utc>>,
    decided_by_name: Option<String>,
    decided_at: Option<DateTime<Utc>>,
    note: String,
    minutes: i64,
    billable_minutes: i64,
}

#[derive(Deserialize)]
pub struct WeekQuery {
    /// Any day of the week; defaults to this week.
    week: Option<NaiveDate>,
    user_id: Option<Uuid>,
}

async fn sheet(st: &AppState, user: Uuid, week: NaiveDate) -> ApiResult<SheetRow> {
    sqlx::query_as(
        "SELECT ts.id, u.id AS user_id, u.name AS user_name, $2::date AS week_start, coalesce(ts.status, 'open') AS status, ts.submitted_at,
                d.name AS decided_by_name, ts.decided_at, coalesce(ts.note, '') AS note,
                coalesce((SELECT sum(minutes) FROM time_entries e WHERE e.user_id = u.id AND e.started_at >= $2 AND e.started_at < $2::date + 7), 0)::bigint AS minutes,
                coalesce((SELECT sum(minutes) FROM time_entries e WHERE e.user_id = u.id AND e.billable AND e.started_at >= $2 AND e.started_at < $2::date + 7), 0)::bigint AS billable_minutes
           FROM users u LEFT JOIN timesheets ts ON ts.user_id = u.id AND ts.week_start = $2 LEFT JOIN users d ON d.id = ts.decided_by
          WHERE u.id = $1",
    )
    .bind(user)
    .bind(week)
    .fetch_optional(&st.db)
    .await?
    .ok_or(ApiError::NotFound("user"))
}

/// A week's timesheet with its entries.
pub async fn week(State(st): State<Arc<AppState>>, u: User, Query(q): Query<WeekQuery>) -> ApiResult<Json<Value>> {
    let user = match q.user_id {
        Some(x) if x != u.id => {
            u.need(Perm::TimeApprove)?;
            x
        }
        _ => u.id,
    };
    let week = week_of(q.week.unwrap_or_else(|| Utc::now().date_naive()));
    let s = sheet(&st, user, week).await?;
    let entries: Vec<EntryRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT {COLS} WHERE e.user_id = $1 AND e.started_at >= $2 AND e.started_at < $2::date + 7 ORDER BY e.started_at"
    )))
    .bind(user)
    .bind(week)
    .fetch_all(&st.db)
    .await?;
    Ok(Json(json!({ "timesheet": s, "entries": redact(&u, entries) })))
}

#[derive(Deserialize)]
pub struct SubmitIn {
    week: NaiveDate,
}

pub async fn submit(State(st): State<Arc<AppState>>, u: User, Json(b): Json<SubmitIn>) -> ApiResult<Json<SheetRow>> {
    let week = week_of(b.week);
    let running: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM time_entries WHERE user_id = $1 AND ended_at IS NULL AND started_at >= $2 AND started_at < $2::date + 7)",
    )
    .bind(u.id)
    .bind(week)
    .fetch_one(&st.db)
    .await?;
    if running {
        return Err(ApiError::Conflict("stop the timer first".into()));
    }
    let n = sqlx::query(
        "INSERT INTO timesheets (id, user_id, week_start, status, submitted_at) VALUES ($1, $2, $3, 'submitted', now())
         ON CONFLICT (user_id, week_start) DO UPDATE SET status = 'submitted', submitted_at = now(), decided_by = NULL, decided_at = NULL
          WHERE timesheets.status IN ('open', 'rejected')",
    )
    .bind(Uuid::new_v4())
    .bind(u.id)
    .bind(week)
    .execute(&st.db)
    .await?
    .rows_affected();
    if n == 0 {
        return Err(ApiError::Conflict("that week is already submitted".into()));
    }
    auth::audit(&st.db, Some(u.id), "timesheet.submit", None, json!({ "week": week })).await;
    Ok(Json(sheet(&st, u.id, week).await?))
}

/// Submitted timesheets waiting for a decision.
pub async fn pending(State(st): State<Arc<AppState>>, u: User) -> ApiResult<Json<Vec<SheetRow>>> {
    u.need(Perm::TimeApprove)?;
    let ids: Vec<(Uuid, NaiveDate)> =
        sqlx::query_as("SELECT user_id, week_start FROM timesheets WHERE status = 'submitted' ORDER BY week_start, submitted_at LIMIT 200")
            .fetch_all(&st.db)
            .await?;
    let mut out = vec![];
    for (user, week) in ids {
        out.push(sheet(&st, user, week).await?);
    }
    Ok(Json(out))
}

#[derive(Deserialize, Default)]
pub struct DecideIn {
    #[serde(default)]
    note: String,
}

async fn load_sheet(st: &AppState, id: Uuid) -> ApiResult<(Uuid, NaiveDate, String)> {
    sqlx::query_as("SELECT user_id, week_start, status FROM timesheets WHERE id = $1")
        .bind(id)
        .fetch_optional(&st.db)
        .await?
        .ok_or(ApiError::NotFound("timesheet"))
}

/// Approves a week: each entry's coverage and amount are worked out, block hours drawn down.
pub async fn approve(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>, Json(b): Json<DecideIn>) -> ApiResult<Json<SheetRow>> {
    u.need(Perm::TimeApprove)?;
    let (user, week, status) = load_sheet(&st, id).await?;
    if status != "submitted" {
        return Err(ApiError::Conflict(format!("the timesheet is {status}, not submitted")));
    }
    let mut tx = st.db.begin().await?;
    sqlx::query("SELECT 1 FROM timesheets WHERE id = $1 FOR UPDATE").bind(id).execute(&mut *tx).await?;
    let entries: Vec<Uuid> = sqlx::query_scalar(
        "SELECT id FROM time_entries WHERE user_id = $1 AND started_at >= $2 AND started_at < $2::date + 7 AND invoice_line_id IS NULL ORDER BY started_at",
    )
    .bind(user)
    .bind(week)
    .fetch_all(&mut *tx)
    .await?;
    for e in &entries {
        crate::billing::resolve_entry(&mut tx, *e).await?;
    }
    sqlx::query("UPDATE timesheets SET status = 'approved', decided_by = $2, decided_at = now(), note = $3 WHERE id = $1")
        .bind(id)
        .bind(u.id)
        .bind(b.note.trim())
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    auth::audit(&st.db, Some(u.id), "timesheet.approve", Some(("user", user)), json!({ "week": week, "entries": entries.len() })).await;
    low_balance_check(&st).await;
    Ok(Json(sheet(&st, user, week).await?))
}

/// Rejects (or reopens) a week so it can be corrected: its unbilled entries lose their
/// coverage and give their block hours back.
pub async fn reject(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>, Json(b): Json<DecideIn>) -> ApiResult<Json<SheetRow>> {
    u.need(Perm::TimeApprove)?;
    let (user, week, status) = load_sheet(&st, id).await?;
    if !matches!(status.as_str(), "submitted" | "approved") {
        return Err(ApiError::Conflict(format!("the timesheet is {status}")));
    }
    let mut tx = st.db.begin().await?;
    let billed: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM time_entries WHERE user_id = $1 AND started_at >= $2 AND started_at < $2::date + 7 AND invoice_line_id IS NOT NULL)",
    )
    .bind(user)
    .bind(week)
    .fetch_one(&mut *tx)
    .await?;
    if billed {
        return Err(ApiError::Conflict("some of this week's time is on an invoice; remove it from the draft (or credit it) first".into()));
    }
    sqlx::query(
        "DELETE FROM contract_bank WHERE time_entry_id IN (SELECT id FROM time_entries WHERE user_id = $1 AND started_at >= $2 AND started_at < $2::date + 7)",
    )
    .bind(user)
    .bind(week)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "UPDATE time_entries SET coverage = NULL, contract_id = NULL, rate = NULL, amount = NULL
          WHERE user_id = $1 AND started_at >= $2 AND started_at < $2::date + 7",
    )
    .bind(user)
    .bind(week)
    .execute(&mut *tx)
    .await?;
    sqlx::query("UPDATE timesheets SET status = 'rejected', decided_by = $2, decided_at = now(), note = $3 WHERE id = $1")
        .bind(id)
        .bind(u.id)
        .bind(b.note.trim())
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    auth::audit(&st.db, Some(u.id), "timesheet.reject", Some(("user", user)), json!({ "week": week, "note": b.note })).await;
    Ok(Json(sheet(&st, user, week).await?))
}

/// Warns account managers (once per purchase) when a block-hours bank runs low.
pub async fn low_balance_check(st: &AppState) {
    let res: anyhow::Result<()> = async {
        let low: Vec<(Uuid, String, String, Option<Uuid>, i64, i32)> = sqlx::query_as(
            "SELECT ct.id, ct.name, cl.name, ct.manager_id, coalesce((SELECT sum(minutes) FROM contract_bank b WHERE b.contract_id = ct.id), 0)::bigint,
                    ct.low_balance_minutes
               FROM contracts ct JOIN clients cl ON cl.id = ct.client_id
              WHERE ct.kind = 'block_hours' AND ct.low_balance_minutes > 0 AND ct.low_balance_warned_at IS NULL
                AND coalesce((SELECT sum(minutes) FROM contract_bank b WHERE b.contract_id = ct.id), 0) < ct.low_balance_minutes",
        )
        .fetch_all(&st.db)
        .await?;
        for (id, name, client, manager, balance, _) in low {
            sqlx::query("UPDATE contracts SET low_balance_warned_at = now() WHERE id = $1").bind(id).execute(&st.db).await?;
            let body = format!(
                "{client}'s block of hours ({name}) is running low: {} hours left.\n\n{}/clients/{}\n",
                crate::billing::qty(crate::billing::minutes_milli(balance)),
                st.cfg.public_url,
                sqlx::query_scalar::<_, Uuid>("SELECT client_id FROM contracts WHERE id = $1").bind(id).fetch_one(&st.db).await?
            );
            if let Some(m) = manager {
                crate::email::queue_staff_note(st, m, &format!("{client}: block hours running low"), &body).await?;
            }
            auth::audit(&st.db, None, "contract.low_balance", Some(("contract", id)), json!({ "minutes": balance })).await;
        }
        Ok(())
    }
    .await;
    if let Err(e) = res {
        tracing::warn!("block-hours check: {e:#}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn weeks_start_on_monday() {
        let d = |s: &str| NaiveDate::parse_from_str(s, "%Y-%m-%d").unwrap();
        assert_eq!(week_of(d("2026-11-12")), d("2026-11-09"));
        assert_eq!(week_of(d("2026-11-09")), d("2026-11-09"));
        assert_eq!(week_of(d("2026-11-15")), d("2026-11-09"));
    }
}
