//! Alert maintenance windows and snoozes (`alert_mutes`): times when alerts for a client, a
//! site or one agent are held back. See the migration for what "held back" means.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, Query, State};
use chrono::{DateTime, Duration, NaiveTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::AssertSqlSafe;
use uuid::Uuid;

use crate::auth::{self, Role, User};
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

#[derive(Serialize, sqlx::FromRow)]
pub struct MuteRow {
    id: Uuid,
    client_id: Option<Uuid>,
    site_id: Option<Uuid>,
    agent_id: Option<Uuid>,
    /// The client it belongs to, whatever its target.
    owner_client_id: Uuid,
    /// "Client", "Client › Site" or the agent's hostname.
    target_name: String,
    starts_at: Option<DateTime<Utc>>,
    ends_at: Option<DateTime<Utc>>,
    days: Option<Vec<i16>>,
    start_time: Option<NaiveTime>,
    minutes: Option<i32>,
    tz: String,
    reason: String,
    created_by_name: Option<String>,
    created_at: DateTime<Utc>,
    /// Holding alerts back right now.
    active: bool,
    /// A one-off period that's over.
    ended: bool,
}

const MUTE_SELECT: &str = "SELECT m.id, m.client_id, m.site_id, m.agent_id,
       coalesce(m.client_id, ms.client_id, mas.client_id) AS owner_client_id,
       coalesce(mc.name, msc.name || ' › ' || ms.name, ma.hostname) AS target_name,
       m.starts_at, m.ends_at, m.days, m.start_time, m.minutes, m.tz, m.reason, u.name AS created_by_name, m.created_at,
       CASE WHEN m.ends_at IS NOT NULL THEN now() >= coalesce(m.starts_at, '-infinity') AND now() < m.ends_at
            ELSE in_maintenance_window(m.days, m.start_time, m.minutes, m.tz, now()) END AS active,
       coalesce(m.ends_at <= now(), false) AS ended
  FROM alert_mutes m
  LEFT JOIN clients mc ON mc.id = m.client_id
  LEFT JOIN sites ms ON ms.id = m.site_id LEFT JOIN clients msc ON msc.id = ms.client_id
  LEFT JOIN agents ma ON ma.id = m.agent_id LEFT JOIN sites mas ON mas.id = ma.site_id
  LEFT JOIN users u ON u.id = m.created_by";

#[derive(Deserialize)]
pub struct ListQuery {
    /// Mutes that apply to this agent: its own, its site's and its client's.
    agent_id: Option<Uuid>,
    client_id: Option<Uuid>,
    /// Include one-off periods that are over.
    #[serde(default)]
    ended: bool,
}

pub async fn list(State(st): State<Arc<AppState>>, u: User, Query(q): Query<ListQuery>) -> ApiResult<Json<Vec<MuteRow>>> {
    if let Some(a) = q.agent_id {
        super::access::agent(&st, &u, a).await?;
    }
    if let Some(c) = q.client_id {
        super::access::client(&u, c)?;
    }
    let sql = format!(
        "SELECT * FROM ({MUTE_SELECT}) x
          WHERE ($1::uuid[] IS NULL OR x.owner_client_id = ANY($1))
            AND ($2::uuid IS NULL OR x.agent_id = $2
                 OR x.site_id = (SELECT site_id FROM agents WHERE id = $2)
                 OR x.client_id = (SELECT s.client_id FROM agents a JOIN sites s ON s.id = a.site_id WHERE a.id = $2))
            AND ($3::uuid IS NULL OR x.owner_client_id = $3)
            AND ($4 OR NOT x.ended)
          ORDER BY x.active DESC, x.ended, coalesce(x.starts_at, x.created_at) DESC"
    );
    Ok(Json(
        sqlx::query_as(AssertSqlSafe(sql)).bind(u.scope()).bind(q.agent_id).bind(q.client_id).bind(q.ended).fetch_all(&st.db).await?,
    ))
}

#[derive(Deserialize)]
pub struct MuteIn {
    /// Exactly one of these.
    client_id: Option<Uuid>,
    site_id: Option<Uuid>,
    agent_id: Option<Uuid>,
    /// One-off: from `starts_at` (default now) until `ends_at`, or for `for_minutes` from now.
    starts_at: Option<DateTime<Utc>>,
    ends_at: Option<DateTime<Utc>>,
    for_minutes: Option<i64>,
    /// Weekly: these days (0 = Sunday), from `start` (`HH:MM`) for `minutes`, in `tz`.
    #[serde(default)]
    days: Vec<i16>,
    start: Option<String>,
    minutes: Option<i32>,
    tz: Option<String>,
    #[serde(default)]
    reason: String,
}

pub async fn create(State(st): State<Arc<AppState>>, u: User, Json(b): Json<MuteIn>) -> ApiResult<Json<MuteRow>> {
    u.require(Role::Technician)?;
    match (b.client_id, b.site_id, b.agent_id) {
        (Some(c), None, None) => super::access::client(&u, c)?,
        (None, Some(s), None) => {
            super::access::site(&st, &u, s).await?;
        }
        (None, None, Some(a)) => {
            super::access::agent(&st, &u, a).await?;
        }
        _ => return Err(ApiError::BadRequest("pick one client, site or agent".into())),
    }
    let reason = b.reason.trim();
    if reason.chars().count() > 500 {
        return Err(ApiError::BadRequest("the reason must be at most 500 characters".into()));
    }
    let weekly = !b.days.is_empty();
    let (mut starts_at, mut ends_at, mut days, mut start, mut minutes) = (None, None, None, None, None);
    let tz = b.tz.as_deref().map(str::trim).filter(|t| !t.is_empty()).unwrap_or("UTC").to_string();
    if weekly {
        let valid_tz: bool =
            sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM pg_timezone_names WHERE name = $1)").bind(&tz).fetch_one(&st.db).await?;
        if !valid_tz {
            return Err(ApiError::BadRequest(format!("unknown time zone {tz}")));
        }
        let mut d = b.days.clone();
        d.sort();
        d.dedup();
        if d.iter().any(|d| !(0..=6).contains(d)) {
            return Err(ApiError::BadRequest("days are 0 (Sunday) to 6 (Saturday)".into()));
        }
        days = Some(d);
        start = Some(
            b.start
                .as_deref()
                .and_then(|s| NaiveTime::parse_from_str(s.trim(), "%H:%M").ok())
                .ok_or_else(|| ApiError::BadRequest("start must be a time like 22:00".into()))?,
        );
        minutes = Some(
            b.minutes
                .filter(|m| (15..=10080).contains(m))
                .ok_or_else(|| ApiError::BadRequest("the window must last 15 minutes to 7 days".into()))?,
        );
    } else {
        let now = Utc::now();
        let from = b.starts_at.unwrap_or(now);
        let until = match (b.ends_at, b.for_minutes) {
            (Some(e), None) => e,
            (None, Some(m)) if (1..=366 * 24 * 60).contains(&m) => now + Duration::minutes(m),
            (None, Some(_)) => return Err(ApiError::BadRequest("snooze for 1 minute to a year".into())),
            _ => return Err(ApiError::BadRequest("give an end time, a duration, or weekly days".into())),
        };
        if until <= from || until <= now {
            return Err(ApiError::BadRequest("the end must be after the start, and in the future".into()));
        }
        if until - from > Duration::days(366) {
            return Err(ApiError::BadRequest("a one-off period can last at most a year".into()));
        }
        starts_at = b.starts_at;
        ends_at = Some(until);
    }
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO alert_mutes (id, client_id, site_id, agent_id, starts_at, ends_at, days, start_time, minutes, tz, reason, created_by)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
    )
    .bind(id)
    .bind(b.client_id)
    .bind(b.site_id)
    .bind(b.agent_id)
    .bind(starts_at)
    .bind(ends_at)
    .bind(&days)
    .bind(start)
    .bind(minutes)
    .bind(&tz)
    .bind(reason)
    .bind(u.id)
    .execute(&st.db)
    .await?;
    // Alerts already open stay as they are; new ones are held back by the insert trigger.
    let target = b.agent_id.map(|a| ("agent", a)).or(b.site_id.map(|s| ("site", s))).or(b.client_id.map(|c| ("client", c)));
    auth::audit(
        &st.db,
        Some(u.id),
        "alert.mute",
        target,
        json!({ "mute": id, "ends_at": ends_at, "days": days, "start": b.start, "minutes": minutes, "tz": tz, "reason": reason }),
    )
    .await;
    publish(&st, target).await;
    fetch(&st, &u, id).await.map(Json)
}

async fn fetch(st: &AppState, u: &User, id: Uuid) -> ApiResult<MuteRow> {
    let row: MuteRow = sqlx::query_as(AssertSqlSafe(format!("SELECT * FROM ({MUTE_SELECT}) x WHERE x.id = $1")))
        .bind(id)
        .fetch_optional(&st.db)
        .await?
        .ok_or(ApiError::NotFound("maintenance window"))?;
    if !u.can_see_client(row.owner_client_id) {
        return Err(ApiError::NotFound("maintenance window"));
    }
    Ok(row)
}

/// Ends a mute (deletes it). Alerts it held back that are still open are announced at once.
pub async fn remove(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    u.require(Role::Technician)?;
    let row = fetch(&st, &u, id).await?;
    sqlx::query("DELETE FROM alert_mutes WHERE id = $1").bind(id).execute(&st.db).await?;
    let target = row.agent_id.map(|a| ("agent", a)).or(row.site_id.map(|s| ("site", s))).or(row.client_id.map(|c| ("client", c)));
    auth::audit(&st.db, Some(u.id), "alert.unmute", target, json!({ "mute": id, "reason": row.reason })).await;
    if let Err(e) = crate::alerts::unsuppress(&st).await {
        tracing::warn!("announcing alerts after a mute ended: {e}");
    }
    publish(&st, target).await;
    Ok(Json(json!({ "ok": true })))
}

/// Agent pages show whether alerts are muted: tell the affected agents' viewers.
async fn publish(st: &AppState, target: Option<(&str, Uuid)>) {
    let Some((kind, id)) = target else { return };
    let col = match kind {
        "agent" => "a.id",
        "site" => "a.site_id",
        _ => "s.client_id",
    };
    let rows: Vec<(Uuid, Uuid, bool)> = sqlx::query_as(AssertSqlSafe(format!(
        "SELECT a.id, s.client_id, a.online FROM agents a JOIN sites s ON s.id = a.site_id WHERE {col} = $1 LIMIT 5000"
    )))
    .bind(id)
    .fetch_all(&st.db)
    .await
    .unwrap_or_default();
    for (id, client_id, online) in rows {
        st.hub.publish(crate::hub::Event::Agent { id, client_id, online, last_metrics: None });
    }
}
