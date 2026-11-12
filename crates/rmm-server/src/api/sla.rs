//! SLA configuration: business calendars with holidays, policies with per-priority targets,
//! and which policy a client uses. Changes recompute the deadlines of open tickets.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use chrono::NaiveDate;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::auth::{self, Role, User};
use crate::error::{ApiError, ApiResult};
use crate::sla::Calendar;
use crate::state::AppState;

fn clean_name(s: &str) -> ApiResult<String> {
    let s = s.split_whitespace().collect::<Vec<_>>().join(" ");
    if s.is_empty() || s.chars().count() > 100 {
        return Err(ApiError::BadRequest("name must be 1-100 characters".into()));
    }
    Ok(s)
}

fn conflict(e: sqlx::Error) -> ApiError {
    match e {
        sqlx::Error::Database(d) if d.is_unique_violation() => ApiError::Conflict("that name is taken".into()),
        e => e.into(),
    }
}

/// Recomputes every open ticket's deadlines in the background (after a configuration change).
pub fn refresh_open(st: &Arc<AppState>) {
    let st = st.clone();
    tokio::spawn(async move {
        let ids: Vec<Uuid> = match sqlx::query_scalar(
            "SELECT t.id FROM tickets t JOIN board_statuses s ON s.id = t.status_id
              WHERE s.category NOT IN ('resolved', 'closed') AND t.merged_into IS NULL",
        )
        .fetch_all(&st.db)
        .await
        {
            Ok(ids) => ids,
            Err(e) => return tracing::warn!("listing tickets to recompute SLAs: {e}"),
        };
        for id in ids {
            let res = async {
                let mut tx = st.db.begin().await?;
                crate::sla::refresh(&mut tx, id).await?;
                tx.commit().await
            }
            .await;
            if let Err(e) = res {
                tracing::warn!(ticket = %id, "recomputing SLA: {e}");
            }
        }
        st.hub.publish(crate::hub::Event::Ticket { id: Uuid::nil(), client_id: None });
    });
}

// ---------------------------------------------------------------------------
// Calendars
// ---------------------------------------------------------------------------

#[derive(Serialize, sqlx::FromRow)]
pub struct CalendarRow {
    id: Uuid,
    name: String,
    timezone: String,
    hours: Value,
    holidays: Value,
    policies: i64,
}

pub async fn calendars(State(st): State<Arc<AppState>>, _u: User) -> ApiResult<Json<Vec<CalendarRow>>> {
    Ok(Json(
        sqlx::query_as(
            "SELECT c.id, c.name, c.timezone, c.hours,
                    coalesce((SELECT jsonb_agg(jsonb_build_object('day', h.day, 'name', h.name) ORDER BY h.day) FROM holidays h WHERE h.calendar_id = c.id), '[]') AS holidays,
                    (SELECT count(*) FROM sla_policies p WHERE p.calendar_id = c.id) AS policies
               FROM business_calendars c ORDER BY lower(c.name)",
        )
        .fetch_all(&st.db)
        .await?,
    ))
}

#[derive(Deserialize)]
pub struct HolidayIn {
    day: NaiveDate,
    #[serde(default)]
    name: String,
}

#[derive(Deserialize)]
pub struct CalendarIn {
    name: String,
    timezone: String,
    hours: Value,
    #[serde(default)]
    holidays: Vec<HolidayIn>,
}

impl CalendarIn {
    fn validate(&mut self) -> ApiResult<Value> {
        self.name = clean_name(&self.name)?;
        self.timezone = self.timezone.trim().to_string();
        self.timezone.parse::<chrono_tz::Tz>().map_err(|_| ApiError::BadRequest(format!("unknown time zone {}", self.timezone)))?;
        let hours = Calendar::parse_hours(&self.hours).map_err(ApiError::BadRequest)?;
        if self.holidays.len() > 1000 {
            return Err(ApiError::BadRequest("at most 1,000 holidays".into()));
        }
        Ok(Calendar::hours_json(&hours))
    }
}

async fn save_holidays(tx: &mut sqlx::PgConnection, id: Uuid, list: &[HolidayIn]) -> sqlx::Result<()> {
    sqlx::query("DELETE FROM holidays WHERE calendar_id = $1").bind(id).execute(&mut *tx).await?;
    for h in list {
        sqlx::query("INSERT INTO holidays (calendar_id, day, name) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING")
            .bind(id)
            .bind(h.day)
            .bind(h.name.trim().chars().take(100).collect::<String>())
            .execute(&mut *tx)
            .await?;
    }
    Ok(())
}

pub async fn create_calendar(State(st): State<Arc<AppState>>, u: User, Json(mut b): Json<CalendarIn>) -> ApiResult<Json<Value>> {
    u.require(Role::Admin)?;
    let hours = b.validate()?;
    let id = Uuid::new_v4();
    let mut tx = st.db.begin().await?;
    sqlx::query("INSERT INTO business_calendars (id, name, timezone, hours) VALUES ($1, $2, $3, $4)")
        .bind(id)
        .bind(&b.name)
        .bind(&b.timezone)
        .bind(hours)
        .execute(&mut *tx)
        .await
        .map_err(conflict)?;
    save_holidays(&mut tx, id, &b.holidays).await?;
    tx.commit().await?;
    auth::audit(&st.db, Some(u.id), "sla.calendar_create", Some(("calendar", id)), json!({ "name": b.name })).await;
    Ok(Json(json!({ "id": id })))
}

pub async fn update_calendar(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>, Json(mut b): Json<CalendarIn>) -> ApiResult<Json<Value>> {
    u.require(Role::Admin)?;
    let hours = b.validate()?;
    let mut tx = st.db.begin().await?;
    let n = sqlx::query("UPDATE business_calendars SET name = $2, timezone = $3, hours = $4 WHERE id = $1")
        .bind(id)
        .bind(&b.name)
        .bind(&b.timezone)
        .bind(hours)
        .execute(&mut *tx)
        .await
        .map_err(conflict)?
        .rows_affected();
    if n == 0 {
        return Err(ApiError::NotFound("calendar"));
    }
    save_holidays(&mut tx, id, &b.holidays).await?;
    tx.commit().await?;
    auth::audit(&st.db, Some(u.id), "sla.calendar_update", Some(("calendar", id)), json!({ "name": b.name })).await;
    refresh_open(&st);
    Ok(Json(json!({ "ok": true })))
}

pub async fn remove_calendar(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    u.require(Role::Admin)?;
    let n = sqlx::query("DELETE FROM business_calendars WHERE id = $1").bind(id).execute(&st.db).await?.rows_affected();
    if n == 0 {
        return Err(ApiError::NotFound("calendar"));
    }
    auth::audit(&st.db, Some(u.id), "sla.calendar_delete", Some(("calendar", id)), json!({})).await;
    refresh_open(&st);
    Ok(Json(json!({ "ok": true })))
}

// ---------------------------------------------------------------------------
// Policies
// ---------------------------------------------------------------------------

#[derive(Serialize, sqlx::FromRow)]
pub struct PolicyRow {
    id: Uuid,
    name: String,
    calendar_id: Option<Uuid>,
    calendar_name: Option<String>,
    is_default: bool,
    channel_ids: Vec<Uuid>,
    notify_assignee: bool,
    targets: Value,
    clients: i64,
    open_tickets: i64,
}

pub async fn policies(State(st): State<Arc<AppState>>, _u: User) -> ApiResult<Json<Vec<PolicyRow>>> {
    Ok(Json(
        sqlx::query_as(
            "SELECT p.id, p.name, p.calendar_id, c.name AS calendar_name, p.is_default, p.channel_ids, p.notify_assignee,
                    coalesce((SELECT jsonb_agg(jsonb_build_object('priority', t.priority, 'respond_mins', t.respond_mins,
                                                               'update_mins', t.update_mins, 'resolve_mins', t.resolve_mins) ORDER BY t.priority)
                                FROM sla_targets t WHERE t.policy_id = p.id), '[]') AS targets,
                    (SELECT count(*) FROM clients cl WHERE cl.sla_policy_id = p.id) AS clients,
                    (SELECT count(*) FROM tickets tk JOIN board_statuses s ON s.id = tk.status_id
                      WHERE tk.sla_policy_id = p.id AND s.category NOT IN ('resolved', 'closed') AND tk.merged_into IS NULL) AS open_tickets
               FROM sla_policies p LEFT JOIN business_calendars c ON c.id = p.calendar_id ORDER BY p.is_default DESC, lower(p.name)",
        )
        .fetch_all(&st.db)
        .await?,
    ))
}

#[derive(Deserialize)]
pub struct TargetIn {
    priority: i16,
    respond_mins: Option<i32>,
    update_mins: Option<i32>,
    resolve_mins: Option<i32>,
}

#[derive(Deserialize)]
pub struct PolicyIn {
    name: String,
    calendar_id: Option<Uuid>,
    #[serde(default)]
    is_default: bool,
    #[serde(default)]
    channel_ids: Vec<Uuid>,
    #[serde(default = "yes")]
    notify_assignee: bool,
    #[serde(default)]
    targets: Vec<TargetIn>,
}

fn yes() -> bool {
    true
}

/// A year of minutes is plenty for any target.
const MAX_TARGET: i32 = 525_600;

impl PolicyIn {
    async fn validate(&mut self, db: &sqlx::PgPool) -> ApiResult<()> {
        self.name = clean_name(&self.name)?;
        if let Some(c) = self.calendar_id {
            let ok: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM business_calendars WHERE id = $1)").bind(c).fetch_one(db).await?;
            if !ok {
                return Err(ApiError::NotFound("calendar"));
            }
        }
        let mut seen = [false; 5];
        for t in &self.targets {
            if !(1..=4).contains(&t.priority) {
                return Err(ApiError::BadRequest("priority must be 1-4".into()));
            }
            if std::mem::replace(&mut seen[t.priority as usize], true) {
                return Err(ApiError::BadRequest(format!("P{} is listed twice", t.priority)));
            }
            for m in [t.respond_mins, t.update_mins, t.resolve_mins].into_iter().flatten() {
                if !(1..=MAX_TARGET).contains(&m) {
                    return Err(ApiError::BadRequest("targets must be between 1 minute and a year".into()));
                }
            }
            if let (Some(r), Some(z)) = (t.respond_mins, t.resolve_mins)
                && r > z
            {
                return Err(ApiError::BadRequest(format!("P{}: the response target can't be longer than the resolution target", t.priority)));
            }
        }
        let known: i64 =
            sqlx::query_scalar("SELECT count(*) FROM notification_channels WHERE id = ANY($1)").bind(&self.channel_ids).fetch_one(db).await?;
        if known as usize != self.channel_ids.len() {
            return Err(ApiError::BadRequest("unknown notification channel".into()));
        }
        Ok(())
    }
}

async fn save_policy(tx: &mut sqlx::PgConnection, id: Uuid, b: &PolicyIn) -> sqlx::Result<()> {
    if b.is_default {
        sqlx::query("UPDATE sla_policies SET is_default = false WHERE is_default AND id <> $1").bind(id).execute(&mut *tx).await?;
    }
    sqlx::query(
        "INSERT INTO sla_policies (id, name, calendar_id, is_default, channel_ids, notify_assignee) VALUES ($1, $2, $3, $4, $5, $6)
         ON CONFLICT (id) DO UPDATE SET name = $2, calendar_id = $3, is_default = $4, channel_ids = $5, notify_assignee = $6",
    )
    .bind(id)
    .bind(&b.name)
    .bind(b.calendar_id)
    .bind(b.is_default)
    .bind(&b.channel_ids)
    .bind(b.notify_assignee)
    .execute(&mut *tx)
    .await?;
    sqlx::query("DELETE FROM sla_targets WHERE policy_id = $1").bind(id).execute(&mut *tx).await?;
    for t in &b.targets {
        if t.respond_mins.is_none() && t.update_mins.is_none() && t.resolve_mins.is_none() {
            continue;
        }
        sqlx::query("INSERT INTO sla_targets (policy_id, priority, respond_mins, update_mins, resolve_mins) VALUES ($1, $2, $3, $4, $5)")
            .bind(id)
            .bind(t.priority)
            .bind(t.respond_mins)
            .bind(t.update_mins)
            .bind(t.resolve_mins)
            .execute(&mut *tx)
            .await?;
    }
    Ok(())
}

pub async fn create_policy(State(st): State<Arc<AppState>>, u: User, Json(mut b): Json<PolicyIn>) -> ApiResult<Json<Value>> {
    u.require(Role::Admin)?;
    b.validate(&st.db).await?;
    let id = Uuid::new_v4();
    let mut tx = st.db.begin().await?;
    save_policy(&mut tx, id, &b).await.map_err(conflict)?;
    tx.commit().await?;
    auth::audit(&st.db, Some(u.id), "sla.policy_create", Some(("sla_policy", id)), json!({ "name": b.name })).await;
    refresh_open(&st);
    Ok(Json(json!({ "id": id })))
}

pub async fn update_policy(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>, Json(mut b): Json<PolicyIn>) -> ApiResult<Json<Value>> {
    u.require(Role::Admin)?;
    let exists: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM sla_policies WHERE id = $1)").bind(id).fetch_one(&st.db).await?;
    if !exists {
        return Err(ApiError::NotFound("SLA policy"));
    }
    b.validate(&st.db).await?;
    let mut tx = st.db.begin().await?;
    save_policy(&mut tx, id, &b).await.map_err(conflict)?;
    tx.commit().await?;
    auth::audit(&st.db, Some(u.id), "sla.policy_update", Some(("sla_policy", id)), json!({ "name": b.name })).await;
    refresh_open(&st);
    Ok(Json(json!({ "ok": true })))
}

pub async fn remove_policy(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    u.require(Role::Admin)?;
    let n = sqlx::query("DELETE FROM sla_policies WHERE id = $1").bind(id).execute(&st.db).await?.rows_affected();
    if n == 0 {
        return Err(ApiError::NotFound("SLA policy"));
    }
    auth::audit(&st.db, Some(u.id), "sla.policy_delete", Some(("sla_policy", id)), json!({})).await;
    refresh_open(&st);
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
pub struct ClientSla {
    sla_policy_id: Option<Uuid>,
    /// Omitted = unchanged.
    portal_devices: Option<bool>,
}

/// `PUT /clients/{id}/service`: the client's SLA policy (null = the default) and whether its
/// portal shows devices.
pub async fn set_client(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>, Json(b): Json<ClientSla>) -> ApiResult<Json<Value>> {
    u.require(Role::Admin)?;
    super::access::client(&u, id)?;
    let n = sqlx::query("UPDATE clients SET sla_policy_id = $2, portal_devices = coalesce($3, portal_devices) WHERE id = $1")
        .bind(id)
        .bind(b.sla_policy_id)
        .bind(b.portal_devices)
        .execute(&st.db)
        .await
        .map_err(|e| match e {
            sqlx::Error::Database(d) if d.is_foreign_key_violation() => ApiError::NotFound("SLA policy"),
            e => e.into(),
        })?
        .rows_affected();
    if n == 0 {
        return Err(ApiError::NotFound("client"));
    }
    auth::audit(&st.db, Some(u.id), "client.service_update", Some(("client", id)), json!({ "sla_policy_id": b.sla_policy_id, "portal_devices": b.portal_devices })).await;
    refresh_open(&st);
    Ok(Json(json!({ "ok": true })))
}
