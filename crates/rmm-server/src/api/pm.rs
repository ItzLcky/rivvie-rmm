//! Scheduling (who works on what, when) and projects with tasks and budget burn-down.
//! Client documentation is in [`super::docs`].

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, Query, State};
use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::auth::{self, Role, User};
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;
use crate::tickets::{self, Author, NewTicket};

fn clean(s: &str, what: &str, max: usize) -> ApiResult<String> {
    let s = s.split_whitespace().collect::<Vec<_>>().join(" ");
    if s.is_empty() || s.chars().count() > max {
        return Err(ApiError::BadRequest(format!("{what} must be 1-{max} characters")));
    }
    Ok(s)
}

// ---------------------------------------------------------------------------
// Schedule
// ---------------------------------------------------------------------------

#[derive(Serialize, sqlx::FromRow)]
pub struct ScheduleRow {
    id: Uuid,
    user_id: Uuid,
    user_name: String,
    starts_at: DateTime<Utc>,
    ends_at: DateTime<Utc>,
    title: String,
    ticket_id: Option<Uuid>,
    ticket_number: Option<i64>,
    ticket_subject: Option<String>,
    project_id: Option<Uuid>,
    project_name: Option<String>,
    client_name: Option<String>,
    notes: String,
}

const SCHEDULE_COLS: &str = "s.id, s.user_id, u.name AS user_name, s.starts_at, s.ends_at, s.title, s.ticket_id, t.number AS ticket_number,
     t.subject AS ticket_subject, s.project_id, p.name AS project_name, coalesce(tc.name, pc.name) AS client_name, s.notes
  FROM schedule_entries s JOIN users u ON u.id = s.user_id LEFT JOIN tickets t ON t.id = s.ticket_id LEFT JOIN clients tc ON tc.id = t.client_id
  LEFT JOIN projects p ON p.id = s.project_id LEFT JOIN clients pc ON pc.id = p.client_id";

#[derive(Deserialize)]
pub struct ScheduleQuery {
    from: DateTime<Utc>,
    to: DateTime<Utc>,
    user_id: Option<Uuid>,
    ticket_id: Option<Uuid>,
}

pub async fn schedule(State(st): State<Arc<AppState>>, u: User, Query(q): Query<ScheduleQuery>) -> ApiResult<Json<Vec<ScheduleRow>>> {
    if q.to <= q.from || (q.to - q.from).num_days() > 62 {
        return Err(ApiError::BadRequest("choose a range of up to two months".into()));
    }
    Ok(Json(
        sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "SELECT {SCHEDULE_COLS}
              WHERE s.starts_at < $2 AND s.ends_at > $1 AND ($3::uuid IS NULL OR s.user_id = $3) AND ($4::uuid IS NULL OR s.ticket_id = $4)
                AND ($5::uuid[] IS NULL OR coalesce(t.client_id, p.client_id) IS NULL OR coalesce(t.client_id, p.client_id) = ANY($5))
              ORDER BY s.starts_at LIMIT 2000"
        )))
        .bind(q.from)
        .bind(q.to)
        .bind(q.user_id)
        .bind(q.ticket_id)
        .bind(u.scope())
        .fetch_all(&st.db)
        .await?,
    ))
}

#[derive(Deserialize)]
pub struct ScheduleIn {
    user_id: Uuid,
    starts_at: DateTime<Utc>,
    ends_at: DateTime<Utc>,
    #[serde(default)]
    title: String,
    ticket_id: Option<Uuid>,
    project_id: Option<Uuid>,
    #[serde(default)]
    notes: String,
}

impl ScheduleIn {
    async fn validate(&mut self, st: &AppState, u: &User) -> ApiResult<()> {
        if self.ends_at <= self.starts_at || (self.ends_at - self.starts_at).num_hours() > 24 * 14 {
            return Err(ApiError::BadRequest("the end must be after the start (and within two weeks)".into()));
        }
        let tech: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM users WHERE id = $1 AND NOT disabled AND role IN ('technician', 'admin'))")
            .bind(self.user_id)
            .fetch_one(&st.db)
            .await?;
        if !tech {
            return Err(ApiError::BadRequest("schedule an active technician".into()));
        }
        if let Some(t) = self.ticket_id {
            super::tickets::visible(st, u, t).await?;
        }
        if let Some(p) = self.project_id {
            let c: Uuid = sqlx::query_scalar("SELECT client_id FROM projects WHERE id = $1").bind(p).fetch_optional(&st.db).await?.ok_or(ApiError::NotFound("project"))?;
            super::access::client(u, c).map_err(|_| ApiError::NotFound("project"))?;
        }
        self.title = self.title.split_whitespace().collect::<Vec<_>>().join(" ").chars().take(200).collect();
        if self.title.is_empty() && self.ticket_id.is_none() && self.project_id.is_none() {
            return Err(ApiError::BadRequest("give the entry a title, or link a ticket or project".into()));
        }
        self.notes = self.notes.trim().chars().take(5000).collect();
        Ok(())
    }
}

async fn fetch_schedule(st: &AppState, id: Uuid) -> ApiResult<ScheduleRow> {
    sqlx::query_as(sqlx::AssertSqlSafe(format!("SELECT {SCHEDULE_COLS} WHERE s.id = $1")))
        .bind(id)
        .fetch_optional(&st.db)
        .await?
        .ok_or(ApiError::NotFound("schedule entry"))
}

pub async fn create_schedule(State(st): State<Arc<AppState>>, u: User, Json(mut b): Json<ScheduleIn>) -> ApiResult<Json<Value>> {
    u.require(Role::Technician)?;
    b.validate(&st, &u).await?;
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO schedule_entries (id, user_id, starts_at, ends_at, title, ticket_id, project_id, notes, created_by)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
    )
    .bind(id)
    .bind(b.user_id)
    .bind(b.starts_at)
    .bind(b.ends_at)
    .bind(&b.title)
    .bind(b.ticket_id)
    .bind(b.project_id)
    .bind(&b.notes)
    .bind(u.id)
    .execute(&st.db)
    .await?;
    if let Some(t) = b.ticket_id {
        let who: String = sqlx::query_scalar("SELECT name FROM users WHERE id = $1").bind(b.user_id).fetch_one(&st.db).await?;
        let mut conn = st.db.acquire().await?;
        tickets::add_event(
            &mut conn,
            t,
            "note",
            false,
            &Author::user(u.id),
            &format!("Scheduled {who} for {} – {} UTC.", b.starts_at.format("%a %-d %b %H:%M"), b.ends_at.format("%H:%M")),
            json!({ "schedule_id": id }),
        )
        .await?;
        tickets::announce(&st, t).await;
    }
    let overlaps: i64 = sqlx::query_scalar("SELECT count(*) FROM schedule_entries WHERE user_id = $1 AND id <> $2 AND starts_at < $4 AND ends_at > $3")
        .bind(b.user_id)
        .bind(id)
        .bind(b.starts_at)
        .bind(b.ends_at)
        .fetch_one(&st.db)
        .await?;
    Ok(Json(json!({ "id": id, "overlaps": overlaps })))
}

pub async fn update_schedule(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>, Json(mut b): Json<ScheduleIn>) -> ApiResult<Json<Value>> {
    u.require(Role::Technician)?;
    fetch_schedule(&st, id).await?;
    b.validate(&st, &u).await?;
    sqlx::query("UPDATE schedule_entries SET user_id = $2, starts_at = $3, ends_at = $4, title = $5, ticket_id = $6, project_id = $7, notes = $8 WHERE id = $1")
        .bind(id)
        .bind(b.user_id)
        .bind(b.starts_at)
        .bind(b.ends_at)
        .bind(&b.title)
        .bind(b.ticket_id)
        .bind(b.project_id)
        .bind(&b.notes)
        .execute(&st.db)
        .await?;
    Ok(Json(json!({ "ok": true })))
}

pub async fn remove_schedule(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    u.require(Role::Technician)?;
    sqlx::query("DELETE FROM schedule_entries WHERE id = $1").bind(id).execute(&st.db).await?;
    Ok(Json(json!({ "ok": true })))
}

// ---------------------------------------------------------------------------
// Projects
// ---------------------------------------------------------------------------

#[derive(Serialize, sqlx::FromRow)]
pub struct ProjectRow {
    id: Uuid,
    client_id: Uuid,
    client_name: String,
    name: String,
    description: String,
    status: String,
    budget_minutes: i32,
    start_date: Option<NaiveDate>,
    due_date: Option<NaiveDate>,
    owner_id: Option<Uuid>,
    owner_name: Option<String>,
    contract_id: Option<Uuid>,
    /// Time logged on the project and on its tickets.
    logged_minutes: i64,
    estimate_minutes: i64,
    tasks: i64,
    tasks_done: i64,
    created_at: DateTime<Utc>,
}

const PROJECT_COLS: &str = "p.id, p.client_id, c.name AS client_name, p.name, p.description, p.status, p.budget_minutes, p.start_date, p.due_date,
     p.owner_id, u.name AS owner_name, p.contract_id,
     coalesce((SELECT sum(e.minutes) FROM time_entries e WHERE e.project_id = p.id
                OR e.ticket_id IN (SELECT t.id FROM tickets t WHERE t.project_id = p.id)), 0)::bigint AS logged_minutes,
     coalesce((SELECT sum(estimate_minutes) FROM project_tasks WHERE project_id = p.id), 0)::bigint AS estimate_minutes,
     (SELECT count(*) FROM project_tasks WHERE project_id = p.id) AS tasks,
     (SELECT count(*) FROM project_tasks WHERE project_id = p.id AND status = 'done') AS tasks_done, p.created_at
  FROM projects p JOIN clients c ON c.id = p.client_id LEFT JOIN users u ON u.id = p.owner_id";

#[derive(Deserialize)]
pub struct ProjectQuery {
    client_id: Option<Uuid>,
    /// open (planned, active, on hold; default) or all
    state: Option<String>,
}

pub async fn projects(State(st): State<Arc<AppState>>, u: User, Query(q): Query<ProjectQuery>) -> ApiResult<Json<Vec<ProjectRow>>> {
    let all = q.state.as_deref() == Some("all");
    Ok(Json(
        sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "SELECT {PROJECT_COLS}
              WHERE ($1::uuid[] IS NULL OR p.client_id = ANY($1)) AND ($2::uuid IS NULL OR p.client_id = $2)
                AND ($3 OR p.status IN ('planned', 'active', 'on_hold'))
              ORDER BY p.status = 'active' DESC, p.due_date NULLS LAST, lower(p.name) LIMIT 500"
        )))
        .bind(u.scope())
        .bind(q.client_id)
        .bind(all)
        .fetch_all(&st.db)
        .await?,
    ))
}

async fn fetch_project(st: &AppState, u: &User, id: Uuid) -> ApiResult<ProjectRow> {
    let p: ProjectRow = sqlx::query_as(sqlx::AssertSqlSafe(format!("SELECT {PROJECT_COLS} WHERE p.id = $1")))
        .bind(id)
        .fetch_optional(&st.db)
        .await?
        .ok_or(ApiError::NotFound("project"))?;
    super::access::client(u, p.client_id).map_err(|_| ApiError::NotFound("project"))?;
    Ok(p)
}

#[derive(Serialize, sqlx::FromRow)]
pub struct TaskRow {
    id: Uuid,
    phase: String,
    title: String,
    status: String,
    estimate_minutes: i32,
    assignee_id: Option<Uuid>,
    assignee_name: Option<String>,
    ticket_id: Option<Uuid>,
    ticket_number: Option<i64>,
    ticket_status: Option<String>,
    due_date: Option<NaiveDate>,
    position: i32,
    logged_minutes: i64,
}

pub async fn project(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    let p = fetch_project(&st, &u, id).await?;
    let tasks: Vec<TaskRow> = sqlx::query_as(
        "SELECT k.id, k.phase, k.title, k.status, k.estimate_minutes, k.assignee_id, u.name AS assignee_name, k.ticket_id, t.number AS ticket_number,
                bs.category AS ticket_status, k.due_date, k.position,
                coalesce((SELECT sum(e.minutes) FROM time_entries e WHERE e.ticket_id = k.ticket_id), 0)::bigint AS logged_minutes
           FROM project_tasks k LEFT JOIN users u ON u.id = k.assignee_id LEFT JOIN tickets t ON t.id = k.ticket_id
           LEFT JOIN board_statuses bs ON bs.id = t.status_id
          WHERE k.project_id = $1 ORDER BY k.position, k.created_at",
    )
    .bind(id)
    .fetch_all(&st.db)
    .await?;
    // Burn-down: minutes logged per week since the project started.
    let burn: Vec<(NaiveDate, i64)> = sqlx::query_as(
        "SELECT (date_trunc('week', e.started_at AT TIME ZONE 'UTC'))::date AS week, sum(e.minutes)::bigint
           FROM time_entries e WHERE e.project_id = $1 OR e.ticket_id IN (SELECT t.id FROM tickets t WHERE t.project_id = $1)
          GROUP BY 1 ORDER BY 1",
    )
    .bind(id)
    .fetch_all(&st.db)
    .await?;
    let mut v = serde_json::to_value(&p).map_err(anyhow::Error::from)?;
    v["task_list"] = json!(tasks);
    v["burn"] = json!(burn.iter().map(|(w, m)| json!({ "week": w, "minutes": m })).collect::<Vec<_>>());
    Ok(Json(v))
}

#[derive(Deserialize)]
pub struct ProjectIn {
    client_id: Uuid,
    name: String,
    #[serde(default)]
    description: String,
    #[serde(default = "planned")]
    status: String,
    #[serde(default)]
    budget_minutes: i32,
    start_date: Option<NaiveDate>,
    due_date: Option<NaiveDate>,
    owner_id: Option<Uuid>,
    contract_id: Option<Uuid>,
}

fn planned() -> String {
    "planned".into()
}

impl ProjectIn {
    fn validate(&mut self, u: &User) -> ApiResult<()> {
        super::access::client(u, self.client_id)?;
        self.name = clean(&self.name, "name", 200)?;
        if !["planned", "active", "on_hold", "done", "cancelled"].contains(&self.status.as_str()) {
            return Err(ApiError::BadRequest(format!("unknown status {}", self.status)));
        }
        if self.budget_minutes < 0 {
            return Err(ApiError::BadRequest("the budget can't be negative".into()));
        }
        if let (Some(s), Some(d)) = (self.start_date, self.due_date)
            && d < s
        {
            return Err(ApiError::BadRequest("the due date can't be before the start".into()));
        }
        self.description = self.description.trim().chars().take(20_000).collect();
        Ok(())
    }
}

fn fk(e: sqlx::Error) -> ApiError {
    match e {
        sqlx::Error::Database(d) if d.is_foreign_key_violation() => ApiError::BadRequest("unknown client, owner or contract".into()),
        e => e.into(),
    }
}

pub async fn create_project(State(st): State<Arc<AppState>>, u: User, Json(mut b): Json<ProjectIn>) -> ApiResult<Json<Value>> {
    u.require(Role::Technician)?;
    b.validate(&u)?;
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO projects (id, client_id, name, description, status, budget_minutes, start_date, due_date, owner_id, contract_id)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
    )
    .bind(id)
    .bind(b.client_id)
    .bind(&b.name)
    .bind(&b.description)
    .bind(&b.status)
    .bind(b.budget_minutes)
    .bind(b.start_date)
    .bind(b.due_date)
    .bind(b.owner_id)
    .bind(b.contract_id)
    .execute(&st.db)
    .await
    .map_err(fk)?;
    auth::audit(&st.db, Some(u.id), "project.create", Some(("project", id)), json!({ "name": b.name })).await;
    Ok(Json(json!({ "id": id })))
}

pub async fn update_project(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>, Json(mut b): Json<ProjectIn>) -> ApiResult<Json<Value>> {
    u.require(Role::Technician)?;
    let cur = fetch_project(&st, &u, id).await?;
    if cur.client_id != b.client_id {
        return Err(ApiError::BadRequest("a project can't move to another client".into()));
    }
    b.validate(&u)?;
    sqlx::query(
        "UPDATE projects SET name = $2, description = $3, status = $4, budget_minutes = $5, start_date = $6, due_date = $7, owner_id = $8, contract_id = $9
          WHERE id = $1",
    )
    .bind(id)
    .bind(&b.name)
    .bind(&b.description)
    .bind(&b.status)
    .bind(b.budget_minutes)
    .bind(b.start_date)
    .bind(b.due_date)
    .bind(b.owner_id)
    .bind(b.contract_id)
    .execute(&st.db)
    .await
    .map_err(fk)?;
    Ok(Json(json!({ "ok": true })))
}

pub async fn remove_project(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    u.require(Role::Technician)?;
    fetch_project(&st, &u, id).await?;
    sqlx::query("DELETE FROM projects WHERE id = $1").bind(id).execute(&st.db).await?;
    auth::audit(&st.db, Some(u.id), "project.delete", Some(("project", id)), json!({})).await;
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
pub struct TaskIn {
    #[serde(default)]
    phase: String,
    title: String,
    #[serde(default = "todo")]
    status: String,
    #[serde(default)]
    estimate_minutes: i32,
    assignee_id: Option<Uuid>,
    due_date: Option<NaiveDate>,
    position: Option<i32>,
}

fn todo() -> String {
    "todo".into()
}

impl TaskIn {
    fn validate(&mut self) -> ApiResult<()> {
        self.title = clean(&self.title, "title", 300)?;
        self.phase = self.phase.split_whitespace().collect::<Vec<_>>().join(" ").chars().take(100).collect();
        if !["todo", "doing", "done"].contains(&self.status.as_str()) {
            return Err(ApiError::BadRequest("status must be todo, doing or done".into()));
        }
        if self.estimate_minutes < 0 {
            return Err(ApiError::BadRequest("the estimate can't be negative".into()));
        }
        Ok(())
    }
}

pub async fn create_task(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>, Json(mut b): Json<TaskIn>) -> ApiResult<Json<Value>> {
    u.require(Role::Technician)?;
    fetch_project(&st, &u, id).await?;
    b.validate()?;
    let tid = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO project_tasks (id, project_id, phase, title, status, estimate_minutes, assignee_id, due_date, position)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, coalesce($9, (SELECT coalesce(max(position), -1) + 1 FROM project_tasks WHERE project_id = $2)))",
    )
    .bind(tid)
    .bind(id)
    .bind(&b.phase)
    .bind(&b.title)
    .bind(&b.status)
    .bind(b.estimate_minutes)
    .bind(b.assignee_id)
    .bind(b.due_date)
    .bind(b.position)
    .execute(&st.db)
    .await
    .map_err(fk)?;
    Ok(Json(json!({ "id": tid })))
}

pub async fn update_task(State(st): State<Arc<AppState>>, u: User, Path((id, task)): Path<(Uuid, Uuid)>, Json(mut b): Json<TaskIn>) -> ApiResult<Json<Value>> {
    u.require(Role::Technician)?;
    fetch_project(&st, &u, id).await?;
    b.validate()?;
    let n = sqlx::query(
        "UPDATE project_tasks SET phase = $3, title = $4, status = $5, estimate_minutes = $6, assignee_id = $7, due_date = $8,
                position = coalesce($9, position) WHERE id = $2 AND project_id = $1",
    )
    .bind(id)
    .bind(task)
    .bind(&b.phase)
    .bind(&b.title)
    .bind(&b.status)
    .bind(b.estimate_minutes)
    .bind(b.assignee_id)
    .bind(b.due_date)
    .bind(b.position)
    .execute(&st.db)
    .await
    .map_err(fk)?
    .rows_affected();
    if n == 0 {
        return Err(ApiError::NotFound("task"));
    }
    Ok(Json(json!({ "ok": true })))
}

pub async fn remove_task(State(st): State<Arc<AppState>>, u: User, Path((id, task)): Path<(Uuid, Uuid)>) -> ApiResult<Json<Value>> {
    u.require(Role::Technician)?;
    fetch_project(&st, &u, id).await?;
    sqlx::query("DELETE FROM project_tasks WHERE id = $2 AND project_id = $1").bind(id).bind(task).execute(&st.db).await?;
    Ok(Json(json!({ "ok": true })))
}

/// Turns a task into a ticket on the project's client (linked both ways), for the service desk
/// to schedule and work.
pub async fn task_ticket(State(st): State<Arc<AppState>>, u: User, Path((id, task)): Path<(Uuid, Uuid)>) -> ApiResult<Json<Value>> {
    u.require(Role::Technician)?;
    let p = fetch_project(&st, &u, id).await?;
    let (title, assignee, existing): (String, Option<Uuid>, Option<Uuid>) =
        sqlx::query_as("SELECT title, assignee_id, ticket_id FROM project_tasks WHERE id = $2 AND project_id = $1")
            .bind(id)
            .bind(task)
            .fetch_optional(&st.db)
            .await?
            .ok_or(ApiError::NotFound("task"))?;
    if let Some(t) = existing {
        return Ok(Json(json!({ "ticket_id": t })));
    }
    let mut tx = st.db.begin().await?;
    let board: Uuid = sqlx::query_scalar("SELECT id FROM boards ORDER BY (name = 'Projects') DESC, position, name LIMIT 1")
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| ApiError::BadRequest("create a board first".into()))?;
    let created = tickets::create(
        &mut tx,
        NewTicket {
            client_id: Some(p.client_id),
            board_id: board,
            priority: 3,
            subject: format!("{}: {title}", p.name).chars().take(300).collect(),
            body: format!("Task from project {}.", p.name),
            body_public: false,
            source: "dashboard",
            assignee_id: assignee,
            created_by: Some(u.id),
            author: Author::user(u.id),
            ..Default::default()
        },
    )
    .await?;
    sqlx::query("UPDATE tickets SET project_id = $2 WHERE id = $1").bind(created.id).bind(id).execute(&mut *tx).await?;
    sqlx::query("UPDATE project_tasks SET ticket_id = $2, status = CASE WHEN status = 'todo' THEN 'doing' ELSE status END WHERE id = $1")
        .bind(task)
        .bind(created.id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    tickets::notify_created(&st, created.id).await;
    tickets::announce(&st, created.id).await;
    Ok(Json(json!({ "ticket_id": created.id, "number": created.number })))
}
