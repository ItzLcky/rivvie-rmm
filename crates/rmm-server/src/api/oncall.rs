//! On-call schedules, overrides, escalation policies, pages, contact methods and the SMS
//! provider (docs/design/oncall.md). The engine is `crate::oncall`.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, Query, State};
use chrono::{DateTime, Duration, Utc};
use chrono_tz::Tz;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::auth::{self, Perm, Role, User};
use crate::error::{ApiError, ApiResult};
use crate::oncall::{self, Target, Window};
use crate::state::{AppState, Company};

fn check_name(name: &str) -> ApiResult<&str> {
    let name = name.trim();
    if name.is_empty() || name.chars().count() > 100 {
        return Err(ApiError::BadRequest("name must be 1-100 characters".into()));
    }
    Ok(name)
}

fn conflict(e: sqlx::Error) -> ApiError {
    match e {
        sqlx::Error::Database(d) if d.is_unique_violation() => ApiError::Conflict("that name is taken".into()),
        e => e.into(),
    }
}

async fn names(st: &AppState, ids: &[Uuid]) -> ApiResult<std::collections::HashMap<Uuid, String>> {
    let rows: Vec<(Uuid, String)> = sqlx::query_as("SELECT id, name FROM users WHERE id = ANY($1)").bind(ids).fetch_all(&st.db).await?;
    Ok(rows.into_iter().collect())
}

/// People who can be put on call: technicians and admins who can sign in.
#[derive(Serialize, sqlx::FromRow)]
pub struct Person {
    id: Uuid,
    name: String,
    email: String,
    phone_verified: bool,
}

pub async fn people(State(st): State<Arc<AppState>>, u: User) -> ApiResult<Json<Vec<Person>>> {
    u.require(Role::Technician)?;
    Ok(Json(
        sqlx::query_as(
            "SELECT id, name, email, phone_verified_at IS NOT NULL AS phone_verified FROM users
              WHERE NOT disabled AND NOT service_account AND role IN ('technician', 'admin') ORDER BY lower(name)",
        )
        .fetch_all(&st.db)
        .await?,
    ))
}

// ---------------------------------------------------------------------------
// Schedules
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct LayerView {
    id: Uuid,
    position: i32,
    name: String,
    user_ids: Vec<Uuid>,
    start_at: DateTime<Utc>,
    shift_hours: i32,
    restrict: Vec<Window>,
}

#[derive(Serialize)]
pub struct OverrideView {
    id: Uuid,
    schedule_id: Uuid,
    user_id: Uuid,
    user_name: String,
    starts_at: DateTime<Utc>,
    ends_at: DateTime<Utc>,
}

#[derive(Serialize)]
pub struct OnCallNow {
    schedule_id: Uuid,
    schedule_name: String,
    user_id: Option<Uuid>,
    user_name: Option<String>,
    /// When their stretch ends (within the next two weeks).
    until: Option<DateTime<Utc>>,
    /// `override` or `layer`.
    source: Option<&'static str>,
}

#[derive(Serialize)]
pub struct ScheduleView {
    id: Uuid,
    name: String,
    timezone: String,
    layers: Vec<LayerView>,
    /// Current and future overrides.
    overrides: Vec<OverrideView>,
    now: OnCallNow,
}

fn now_of(s: &oncall::Schedule, names: &std::collections::HashMap<Uuid, String>) -> OnCallNow {
    let now = Utc::now();
    let who = s.on_call(now);
    let until = who.and_then(|(u, _)| {
        oncall::final_shifts(s.tz, &s.layers, &s.overrides, now, now + Duration::days(14)).into_iter().next().filter(|seg| seg.user_id == u).map(|seg| seg.end)
    });
    OnCallNow {
        schedule_id: s.id,
        schedule_name: s.name.clone(),
        user_id: who.map(|w| w.0),
        user_name: who.and_then(|w| names.get(&w.0).cloned()),
        until,
        source: who.map(|w| match w.1 {
            oncall::Source::Override(_) => "override",
            oncall::Source::Layer(_) => "layer",
        }),
    }
}

async fn view(st: &AppState, s: oncall::Schedule) -> ApiResult<ScheduleView> {
    let mut ids: Vec<Uuid> = s.layers.iter().flat_map(|l| l.user_ids.iter().copied()).chain(s.overrides.iter().map(|o| o.user_id)).collect();
    ids.dedup();
    let names = names(st, &ids).await?;
    let now = now_of(&s, &names);
    let tz = s.tz.name().to_string();
    Ok(ScheduleView {
        id: s.id,
        name: s.name.clone(),
        timezone: tz,
        layers: s
            .layers
            .iter()
            .map(|l| LayerView {
                id: l.id,
                position: l.position,
                name: l.name.clone(),
                user_ids: l.user_ids.clone(),
                start_at: l.start_at,
                shift_hours: l.shift_hours,
                restrict: l.restrict.clone(),
            })
            .collect(),
        overrides: s
            .overrides
            .iter()
            .map(|o| OverrideView {
                id: o.id,
                schedule_id: s.id,
                user_id: o.user_id,
                user_name: names.get(&o.user_id).cloned().unwrap_or_default(),
                starts_at: o.starts_at,
                ends_at: o.ends_at,
            })
            .collect(),
        now,
    })
}

async fn fetch(st: &AppState, id: Uuid) -> ApiResult<oncall::Schedule> {
    oncall::load_schedule(&st.db, id, Utc::now()).await?.ok_or(ApiError::NotFound("schedule"))
}

pub async fn list_schedules(State(st): State<Arc<AppState>>, u: User) -> ApiResult<Json<Vec<ScheduleView>>> {
    u.require(Role::Readonly)?;
    let ids: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM oncall_schedules ORDER BY lower(name)").fetch_all(&st.db).await?;
    let mut out = Vec::new();
    for id in ids {
        out.push(view(&st, fetch(&st, id).await?).await?);
    }
    Ok(Json(out))
}

pub async fn get_schedule(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<ScheduleView>> {
    u.require(Role::Readonly)?;
    Ok(Json(view(&st, fetch(&st, id).await?).await?))
}

#[derive(Deserialize)]
pub struct LayerIn {
    #[serde(default)]
    name: String,
    user_ids: Vec<Uuid>,
    start_at: DateTime<Utc>,
    shift_hours: i32,
    #[serde(default)]
    restrict: Vec<Window>,
}

#[derive(Deserialize)]
pub struct ScheduleIn {
    name: String,
    #[serde(default = "utc")]
    timezone: String,
    #[serde(default)]
    layers: Vec<LayerIn>,
}

fn utc() -> String {
    "UTC".into()
}

async fn check_schedule(st: &AppState, b: &ScheduleIn) -> ApiResult<()> {
    b.timezone.parse::<Tz>().map_err(|_| ApiError::BadRequest(format!("unknown time zone {}", b.timezone)))?;
    if b.layers.len() > 10 {
        return Err(ApiError::BadRequest("at most 10 layers".into()));
    }
    for (i, l) in b.layers.iter().enumerate() {
        let n = i + 1;
        if l.user_ids.is_empty() || l.user_ids.len() > 50 {
            return Err(ApiError::BadRequest(format!("layer {n}: add 1-50 people")));
        }
        if !(1..=672).contains(&l.shift_hours) {
            return Err(ApiError::BadRequest(format!("layer {n}: a shift is 1 hour to 4 weeks")));
        }
        if l.restrict.len() > 14 {
            return Err(ApiError::BadRequest(format!("layer {n}: at most 14 restrictions")));
        }
        for w in &l.restrict {
            w.validate().map_err(|e| ApiError::BadRequest(format!("layer {n}: {e}")))?;
        }
        if l.name.chars().count() > 100 {
            return Err(ApiError::BadRequest(format!("layer {n}: the name is at most 100 characters")));
        }
        let ok: i64 = sqlx::query_scalar("SELECT count(*) FROM users WHERE id = ANY($1) AND NOT disabled AND role IN ('technician', 'admin')")
            .bind(&l.user_ids)
            .fetch_one(&st.db)
            .await?;
        let mut distinct = l.user_ids.clone();
        distinct.sort_unstable();
        distinct.dedup();
        if ok as usize != distinct.len() {
            return Err(ApiError::BadRequest(format!("layer {n}: only technicians and admins can be on call")));
        }
    }
    Ok(())
}

async fn write_layers(tx: &mut sqlx::PgConnection, id: Uuid, layers: &[LayerIn]) -> sqlx::Result<()> {
    sqlx::query("DELETE FROM oncall_layers WHERE schedule_id = $1").bind(id).execute(&mut *tx).await?;
    for (i, l) in layers.iter().enumerate() {
        sqlx::query(
            "INSERT INTO oncall_layers (id, schedule_id, position, name, user_ids, start_at, shift_hours, restrict) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(Uuid::new_v4())
        .bind(id)
        .bind(i as i32)
        .bind(l.name.trim())
        .bind(&l.user_ids)
        .bind(l.start_at)
        .bind(l.shift_hours)
        .bind(serde_json::to_value(&l.restrict).unwrap_or_default())
        .execute(&mut *tx)
        .await?;
    }
    Ok(())
}

pub async fn create_schedule(State(st): State<Arc<AppState>>, u: User, Json(b): Json<ScheduleIn>) -> ApiResult<Json<ScheduleView>> {
    u.need(Perm::OncallManage)?;
    let name = check_name(&b.name)?.to_string();
    check_schedule(&st, &b).await?;
    let id = Uuid::new_v4();
    let mut tx = st.db.begin().await?;
    sqlx::query("INSERT INTO oncall_schedules (id, name, timezone) VALUES ($1, $2, $3)").bind(id).bind(&name).bind(&b.timezone).execute(&mut *tx).await.map_err(conflict)?;
    write_layers(&mut tx, id, &b.layers).await?;
    tx.commit().await?;
    auth::audit(&st.db, Some(u.id), "oncall.schedule_create", Some(("oncall_schedule", id)), json!({ "name": name })).await;
    Ok(Json(view(&st, fetch(&st, id).await?).await?))
}

pub async fn update_schedule(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>, Json(b): Json<ScheduleIn>) -> ApiResult<Json<ScheduleView>> {
    u.need(Perm::OncallManage)?;
    fetch(&st, id).await?;
    let name = check_name(&b.name)?.to_string();
    check_schedule(&st, &b).await?;
    let mut tx = st.db.begin().await?;
    sqlx::query("UPDATE oncall_schedules SET name = $2, timezone = $3, updated_at = now() WHERE id = $1")
        .bind(id)
        .bind(&name)
        .bind(&b.timezone)
        .execute(&mut *tx)
        .await
        .map_err(conflict)?;
    write_layers(&mut tx, id, &b.layers).await?;
    tx.commit().await?;
    auth::audit(&st.db, Some(u.id), "oncall.schedule_update", Some(("oncall_schedule", id)), json!({ "name": name, "layers": b.layers.len() })).await;
    Ok(Json(view(&st, fetch(&st, id).await?).await?))
}

pub async fn delete_schedule(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    u.need(Perm::OncallManage)?;
    let s = fetch(&st, id).await?;
    let used: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT p.name FROM escalation_steps x JOIN escalation_policies p ON p.id = x.policy_id
          WHERE EXISTS (SELECT 1 FROM jsonb_array_elements(x.targets) t WHERE t ->> 'schedule' = $1::text) ORDER BY 1",
    )
    .bind(id)
    .fetch_all(&st.db)
    .await?;
    if !used.is_empty() {
        return Err(ApiError::Conflict(format!("escalation policies page this schedule: {}", used.join(", "))));
    }
    sqlx::query("DELETE FROM oncall_schedules WHERE id = $1").bind(id).execute(&st.db).await?;
    auth::audit(&st.db, Some(u.id), "oncall.schedule_delete", Some(("oncall_schedule", id)), json!({ "name": s.name })).await;
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
pub struct Range {
    from: Option<DateTime<Utc>>,
    to: Option<DateTime<Utc>>,
}

#[derive(Serialize)]
struct SegmentView {
    user_id: Uuid,
    user_name: String,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
}

/// The timeline: each layer's own rotation, the overrides, and the result.
pub async fn shifts(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>, Query(q): Query<Range>) -> ApiResult<Json<Value>> {
    u.require(Role::Readonly)?;
    let from = q.from.unwrap_or_else(Utc::now);
    let to = q.to.unwrap_or(from + Duration::days(14));
    if to <= from || to - from > Duration::days(62) {
        return Err(ApiError::BadRequest("the range is up to 62 days".into()));
    }
    let s = oncall::load_schedule(&st.db, id, from).await?.ok_or(ApiError::NotFound("schedule"))?;
    let ids: Vec<Uuid> = s.layers.iter().flat_map(|l| l.user_ids.iter().copied()).chain(s.overrides.iter().map(|o| o.user_id)).collect();
    let names = names(&st, &ids).await?;
    let seg = |v: Vec<oncall::Segment>| -> Vec<SegmentView> {
        v.into_iter().map(|g| SegmentView { user_id: g.user_id, user_name: names.get(&g.user_id).cloned().unwrap_or_default(), start: g.start, end: g.end }).collect()
    };
    let layers: Vec<Value> = s
        .layers
        .iter()
        .map(|l| json!({ "id": l.id, "name": l.name, "position": l.position, "segments": seg(oncall::layer_shifts(s.tz, l, from, to)) }))
        .collect();
    let overrides: Vec<SegmentView> = s
        .overrides
        .iter()
        .filter(|o| o.starts_at < to && o.ends_at > from)
        .map(|o| SegmentView { user_id: o.user_id, user_name: names.get(&o.user_id).cloned().unwrap_or_default(), start: o.starts_at.max(from), end: o.ends_at.min(to) })
        .collect();
    let final_ = seg(oncall::final_shifts(s.tz, &s.layers, &s.overrides, from, to));
    Ok(Json(json!({ "from": from, "to": to, "timezone": s.tz.name(), "layers": layers, "overrides": overrides, "final": final_ })))
}

/// Who is on call on each schedule right now (the "On call now" chip).
pub async fn now(State(st): State<Arc<AppState>>, u: User) -> ApiResult<Json<Vec<OnCallNow>>> {
    u.require(Role::Readonly)?;
    let ids: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM oncall_schedules ORDER BY lower(name)").fetch_all(&st.db).await?;
    let mut out = Vec::new();
    for id in ids {
        let Some(s) = oncall::load_schedule(&st.db, id, Utc::now()).await? else { continue };
        let who: Vec<Uuid> = s.on_call(Utc::now()).map(|w| w.0).into_iter().collect();
        out.push(now_of(&s, &names(&st, &who).await?));
    }
    Ok(Json(out))
}

#[derive(Deserialize)]
pub struct OverrideIn {
    schedule_id: Uuid,
    user_id: Uuid,
    starts_at: DateTime<Utc>,
    ends_at: DateTime<Utc>,
}

/// Anyone technician and up may put themselves on call; `oncall.manage` may put anyone on.
pub async fn create_override(State(st): State<Arc<AppState>>, u: User, Json(b): Json<OverrideIn>) -> ApiResult<Json<OverrideView>> {
    u.require(Role::Technician)?;
    if b.user_id != u.id {
        u.need(Perm::OncallManage)?;
    }
    if b.ends_at <= b.starts_at || b.ends_at - b.starts_at > Duration::days(90) {
        return Err(ApiError::BadRequest("an override ends after it starts, within 90 days".into()));
    }
    if b.ends_at <= Utc::now() {
        return Err(ApiError::BadRequest("that override is already over".into()));
    }
    let s = fetch(&st, b.schedule_id).await?;
    let user: Option<String> = sqlx::query_scalar("SELECT name FROM users WHERE id = $1 AND NOT disabled AND role IN ('technician', 'admin')")
        .bind(b.user_id)
        .fetch_optional(&st.db)
        .await?;
    let user_name = user.ok_or_else(|| ApiError::BadRequest("only technicians and admins can be on call".into()))?;
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO oncall_overrides (id, schedule_id, user_id, starts_at, ends_at, created_by) VALUES ($1, $2, $3, $4, $5, $6)")
        .bind(id)
        .bind(b.schedule_id)
        .bind(b.user_id)
        .bind(b.starts_at)
        .bind(b.ends_at)
        .bind(u.id)
        .execute(&st.db)
        .await?;
    auth::audit(
        &st.db,
        Some(u.id),
        "oncall.override_create",
        Some(("oncall_schedule", b.schedule_id)),
        json!({ "schedule": s.name, "user": user_name, "starts_at": b.starts_at, "ends_at": b.ends_at }),
    )
    .await;
    Ok(Json(OverrideView { id, schedule_id: b.schedule_id, user_id: b.user_id, user_name, starts_at: b.starts_at, ends_at: b.ends_at }))
}

pub async fn delete_override(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    u.require(Role::Technician)?;
    let row: Option<(Uuid, Uuid, Option<Uuid>)> =
        sqlx::query_as("SELECT schedule_id, user_id, created_by FROM oncall_overrides WHERE id = $1").bind(id).fetch_optional(&st.db).await?;
    let (schedule, user, by) = row.ok_or(ApiError::NotFound("override"))?;
    if user != u.id && by != Some(u.id) {
        u.need(Perm::OncallManage)?;
    }
    sqlx::query("DELETE FROM oncall_overrides WHERE id = $1").bind(id).execute(&st.db).await?;
    auth::audit(&st.db, Some(u.id), "oncall.override_delete", Some(("oncall_schedule", schedule)), json!({ "override": id })).await;
    Ok(Json(json!({ "ok": true })))
}

// ---------------------------------------------------------------------------
// Escalation policies
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
pub struct StepIo {
    delay_minutes: i32,
    targets: Vec<Value>,
}

#[derive(Serialize)]
pub struct PolicyView {
    id: Uuid,
    name: String,
    repeat: i32,
    steps: Vec<StepIo>,
    /// On-call channels that page through it.
    channels: Vec<Value>,
}

async fn policy_view(st: &AppState, id: Uuid) -> ApiResult<PolicyView> {
    let (name, repeat): (String, i32) =
        sqlx::query_as("SELECT name, repeat FROM escalation_policies WHERE id = $1").bind(id).fetch_optional(&st.db).await?.ok_or(ApiError::NotFound("escalation policy"))?;
    let steps: Vec<(i32, Value)> =
        sqlx::query_as("SELECT delay_minutes, targets FROM escalation_steps WHERE policy_id = $1 ORDER BY position").bind(id).fetch_all(&st.db).await?;
    let channels: Vec<Value> = sqlx::query_scalar(
        "SELECT jsonb_build_object('id', id, 'name', name) FROM notification_channels WHERE kind = 'oncall' AND config ->> 'escalation_policy_id' = $1::text ORDER BY lower(name)",
    )
    .bind(id)
    .fetch_all(&st.db)
    .await?;
    Ok(PolicyView {
        id,
        name,
        repeat,
        steps: steps.into_iter().map(|(delay_minutes, t)| StepIo { delay_minutes, targets: t.as_array().cloned().unwrap_or_default() }).collect(),
        channels,
    })
}

pub async fn list_policies(State(st): State<Arc<AppState>>, u: User) -> ApiResult<Json<Vec<PolicyView>>> {
    u.require(Role::Readonly)?;
    let ids: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM escalation_policies ORDER BY lower(name)").fetch_all(&st.db).await?;
    let mut out = Vec::new();
    for id in ids {
        out.push(policy_view(&st, id).await?);
    }
    Ok(Json(out))
}

pub async fn get_policy(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<PolicyView>> {
    u.require(Role::Readonly)?;
    Ok(Json(policy_view(&st, id).await?))
}

#[derive(Deserialize)]
pub struct PolicyIn {
    name: String,
    #[serde(default)]
    repeat: i32,
    steps: Vec<StepIo>,
}

/// Normalised targets per step, each checked to exist.
async fn check_policy(st: &AppState, b: &PolicyIn) -> ApiResult<Vec<(i32, Value)>> {
    if !(0..=9).contains(&b.repeat) {
        return Err(ApiError::BadRequest("repeat 0-9 times".into()));
    }
    if b.steps.is_empty() || b.steps.len() > 10 {
        return Err(ApiError::BadRequest("add 1-10 steps".into()));
    }
    let mut out = Vec::new();
    for (i, s) in b.steps.iter().enumerate() {
        let n = i + 1;
        if !(1..=1440).contains(&s.delay_minutes) {
            return Err(ApiError::BadRequest(format!("step {n}: wait 1-1440 minutes before the next step")));
        }
        if s.targets.is_empty() || s.targets.len() > 10 {
            return Err(ApiError::BadRequest(format!("step {n}: add 1-10 targets")));
        }
        let mut targets = Vec::new();
        for t in &s.targets {
            let t = Target::parse(t).map_err(|e| ApiError::BadRequest(format!("step {n}: {e}")))?;
            let ok: bool = match &t {
                Target::Schedule(id) => sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM oncall_schedules WHERE id = $1)").bind(id).fetch_one(&st.db).await?,
                Target::User(id) => {
                    sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM users WHERE id = $1 AND NOT disabled AND role IN ('technician', 'admin'))").bind(id).fetch_one(&st.db).await?
                }
                // Not another on-call channel: pages would page in a loop.
                Target::Channel(id) => sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM notification_channels WHERE id = $1 AND kind <> 'oncall')").bind(id).fetch_one(&st.db).await?,
            };
            if !ok {
                return Err(ApiError::BadRequest(format!("step {n}: a target doesn't exist (or is an on-call channel)")));
            }
            targets.push(t.to_json());
        }
        out.push((s.delay_minutes, Value::Array(targets)));
    }
    Ok(out)
}

async fn write_steps(tx: &mut sqlx::PgConnection, id: Uuid, steps: &[(i32, Value)]) -> sqlx::Result<()> {
    sqlx::query("DELETE FROM escalation_steps WHERE policy_id = $1").bind(id).execute(&mut *tx).await?;
    for (i, (delay, targets)) in steps.iter().enumerate() {
        sqlx::query("INSERT INTO escalation_steps (policy_id, position, delay_minutes, targets) VALUES ($1, $2, $3, $4)")
            .bind(id)
            .bind(i as i32)
            .bind(delay)
            .bind(targets)
            .execute(&mut *tx)
            .await?;
    }
    Ok(())
}

pub async fn create_policy(State(st): State<Arc<AppState>>, u: User, Json(b): Json<PolicyIn>) -> ApiResult<Json<PolicyView>> {
    u.need(Perm::OncallManage)?;
    let name = check_name(&b.name)?.to_string();
    let steps = check_policy(&st, &b).await?;
    let id = Uuid::new_v4();
    let mut tx = st.db.begin().await?;
    sqlx::query("INSERT INTO escalation_policies (id, name, repeat) VALUES ($1, $2, $3)").bind(id).bind(&name).bind(b.repeat).execute(&mut *tx).await.map_err(conflict)?;
    write_steps(&mut tx, id, &steps).await?;
    tx.commit().await?;
    auth::audit(&st.db, Some(u.id), "oncall.policy_create", Some(("escalation_policy", id)), json!({ "name": name })).await;
    Ok(Json(policy_view(&st, id).await?))
}

pub async fn update_policy(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>, Json(b): Json<PolicyIn>) -> ApiResult<Json<PolicyView>> {
    u.need(Perm::OncallManage)?;
    policy_view(&st, id).await?;
    let name = check_name(&b.name)?.to_string();
    let steps = check_policy(&st, &b).await?;
    let mut tx = st.db.begin().await?;
    sqlx::query("UPDATE escalation_policies SET name = $2, repeat = $3, updated_at = now() WHERE id = $1")
        .bind(id)
        .bind(&name)
        .bind(b.repeat)
        .execute(&mut *tx)
        .await
        .map_err(conflict)?;
    write_steps(&mut tx, id, &steps).await?;
    tx.commit().await?;
    auth::audit(&st.db, Some(u.id), "oncall.policy_update", Some(("escalation_policy", id)), json!({ "name": name, "steps": steps.len() })).await;
    Ok(Json(policy_view(&st, id).await?))
}

pub async fn delete_policy(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    u.need(Perm::OncallManage)?;
    let p = policy_view(&st, id).await?;
    if !p.channels.is_empty() {
        let names: Vec<&str> = p.channels.iter().filter_map(|c| c["name"].as_str()).collect();
        return Err(ApiError::Conflict(format!("on-call channels page through it: {}", names.join(", "))));
    }
    sqlx::query("DELETE FROM escalation_policies WHERE id = $1").bind(id).execute(&st.db).await?;
    auth::audit(&st.db, Some(u.id), "oncall.policy_delete", Some(("escalation_policy", id)), json!({ "name": p.name })).await;
    Ok(Json(json!({ "ok": true })))
}

#[derive(Serialize, Deserialize)]
pub struct OncallSettings {
    /// New P1 tickets page through this policy.
    p1_escalation_policy_id: Option<Uuid>,
}

pub async fn get_settings(State(st): State<Arc<AppState>>, u: User) -> ApiResult<Json<OncallSettings>> {
    u.require(Role::Technician)?;
    Ok(Json(OncallSettings { p1_escalation_policy_id: st.company().p1_escalation_policy_id }))
}

pub async fn update_settings(State(st): State<Arc<AppState>>, u: User, Json(b): Json<OncallSettings>) -> ApiResult<Json<OncallSettings>> {
    u.need(Perm::OncallManage)?;
    if let Some(p) = b.p1_escalation_policy_id {
        policy_view(&st, p).await?;
    }
    let new: Company = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "UPDATE company_settings SET p1_escalation_policy_id = $1, updated_at = now(), updated_by = $2 RETURNING {}",
        Company::COLUMNS
    )))
    .bind(b.p1_escalation_policy_id)
    .bind(u.id)
    .fetch_one(&st.db)
    .await?;
    *st.company.write().unwrap_or_else(|e| e.into_inner()) = new;
    auth::audit(&st.db, Some(u.id), "oncall.settings", None, json!({ "p1_escalation_policy_id": b.p1_escalation_policy_id })).await;
    Ok(Json(b))
}

// ---------------------------------------------------------------------------
// Pages
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct PagesQuery {
    alert_id: Option<Uuid>,
    ticket_id: Option<Uuid>,
    /// `active` (held and triggered) or `all` (the default).
    #[serde(default)]
    status: String,
}

const PAGE_SELECT: &str = "SELECT p.id, p.alert_id, p.ticket_id, p.title, p.severity, p.status, p.step, p.round, ep.name AS policy_name,
        ua.name AS acked_by_name, p.acked_at, p.resolved_at, p.created_at, p.next_escalation_at,
        coalesce((SELECT jsonb_agg(jsonb_build_object('id', d.id, 'user_name', du.name, 'channel_name', ch.name, 'method', d.method,
                 'step', d.step, 'round', d.round, 'status', d.status, 'attempts', d.attempts, 'error', d.error,
                 'created_at', d.created_at, 'sent_at', d.sent_at, 'next_attempt_at', d.next_attempt_at) ORDER BY d.created_at, d.method)
            FROM page_deliveries d LEFT JOIN users du ON du.id = d.user_id LEFT JOIN notification_channels ch ON ch.id = d.channel_id
           WHERE d.page_id = p.id), '[]') AS deliveries
   FROM pages p LEFT JOIN escalation_policies ep ON ep.id = p.policy_id LEFT JOIN users ua ON ua.id = p.acked_by
   LEFT JOIN alerts al ON al.id = p.alert_id LEFT JOIN agents ag ON ag.id = al.agent_id LEFT JOIN sites s ON s.id = ag.site_id
   LEFT JOIN tickets t ON t.id = p.ticket_id";

#[derive(Serialize, sqlx::FromRow)]
pub struct PageRow {
    id: Uuid,
    alert_id: Option<Uuid>,
    ticket_id: Option<Uuid>,
    title: String,
    severity: String,
    status: String,
    step: i32,
    round: i32,
    policy_name: Option<String>,
    acked_by_name: Option<String>,
    acked_at: Option<DateTime<Utc>>,
    resolved_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
    next_escalation_at: Option<DateTime<Utc>>,
    deliveries: Value,
}

/// Pages the user can see (by the alert's or ticket's client), newest first.
pub async fn pages(State(st): State<Arc<AppState>>, u: User, Query(q): Query<PagesQuery>) -> ApiResult<Json<Vec<PageRow>>> {
    u.require(Role::Readonly)?;
    let active = q.status == "active";
    Ok(Json(
        sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "{PAGE_SELECT}
              WHERE ($1::uuid[] IS NULL OR coalesce(s.client_id, t.client_id) = ANY($1))
                AND ($2::uuid IS NULL OR p.alert_id = $2) AND ($3::uuid IS NULL OR p.ticket_id = $3)
                AND (NOT $4 OR p.status IN ('held', 'triggered'))
              ORDER BY p.created_at DESC LIMIT 100"
        )))
        .bind(u.scope())
        .bind(q.alert_id)
        .bind(q.ticket_id)
        .bind(active)
        .fetch_all(&st.db)
        .await?,
    ))
}

pub async fn ack_page(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<PageRow>> {
    u.require(Role::Technician)?;
    let fetch_one = || async {
        sqlx::query_as::<_, PageRow>(sqlx::AssertSqlSafe(format!("{PAGE_SELECT} WHERE p.id = $1 AND ($2::uuid[] IS NULL OR coalesce(s.client_id, t.client_id) = ANY($2))")))
            .bind(id)
            .bind(u.scope())
            .fetch_optional(&st.db)
            .await?
            .ok_or(ApiError::NotFound("page"))
    };
    fetch_one().await?;
    if oncall::ack(&st, id, u.id).await? {
        auth::audit(&st.db, Some(u.id), "page.ack", Some(("page", id)), json!({})).await;
        oncall::wake();
    }
    Ok(Json(fetch_one().await?))
}

// ---------------------------------------------------------------------------
// Account: how to reach me
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, sqlx::FromRow)]
pub struct Rule {
    method: String,
    delay_minutes: i32,
}

#[derive(Serialize)]
pub struct ContactMethods {
    phone: Option<String>,
    phone_verified: bool,
    /// The server can send text messages.
    sms_available: bool,
    /// Push subscriptions on this account.
    devices: i64,
    rules: Vec<Rule>,
}

async fn contact_view(st: &AppState, u: &User) -> ApiResult<ContactMethods> {
    let (phone, verified, devices): (Option<String>, bool, i64) = sqlx::query_as(
        "SELECT phone, phone_verified_at IS NOT NULL, (SELECT count(*) FROM push_subscriptions s WHERE s.user_id = u.id) FROM users u WHERE id = $1",
    )
    .bind(u.id)
    .fetch_one(&st.db)
    .await?;
    let rules: Vec<Rule> = sqlx::query_as("SELECT method, delay_minutes FROM user_contact_rules WHERE user_id = $1 ORDER BY delay_minutes, method")
        .bind(u.id)
        .fetch_all(&st.db)
        .await?;
    let c = st.company();
    Ok(ContactMethods { phone, phone_verified: verified, sms_available: !c.sms_account_sid.is_empty() && c.sms_token_enc.is_some(), devices, rules })
}

fn session_only(u: &User) -> ApiResult<()> {
    if u.api_key.is_some() { Err(ApiError::Forbidden) } else { Ok(()) }
}

pub async fn get_contact(State(st): State<Arc<AppState>>, u: User) -> ApiResult<Json<ContactMethods>> {
    session_only(&u)?;
    Ok(Json(contact_view(&st, &u).await?))
}

#[derive(Deserialize)]
pub struct ContactIn {
    /// Omitted: unchanged; null or "": removed. A new number has to be verified again.
    #[serde(default, deserialize_with = "some")]
    phone: Option<Option<String>>,
    rules: Vec<Rule>,
}

fn some<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<Option<String>>, D::Error> {
    Option::<String>::deserialize(d).map(Some)
}

pub async fn update_contact(State(st): State<Arc<AppState>>, u: User, Json(b): Json<ContactIn>) -> ApiResult<Json<ContactMethods>> {
    session_only(&u)?;
    if b.rules.len() > 10 {
        return Err(ApiError::BadRequest("at most 10 rules".into()));
    }
    for r in &b.rules {
        if !matches!(r.method.as_str(), "sms" | "email" | "push") || !(0..=120).contains(&r.delay_minutes) {
            return Err(ApiError::BadRequest("each rule is a text message, email or push, 0-120 minutes after a page".into()));
        }
    }
    let mut tx = st.db.begin().await?;
    if let Some(phone) = &b.phone {
        let phone = phone.as_deref().map(|p| p.chars().filter(|c| !c.is_whitespace() && *c != '-').collect::<String>()).filter(|p| !p.is_empty());
        if let Some(p) = &phone
            && !oncall::valid_e164(p)
        {
            return Err(ApiError::BadRequest("enter the number in international form, like +447700900123".into()));
        }
        sqlx::query(
            "UPDATE users SET phone = $2,
                    phone_verified_at = CASE WHEN phone IS NOT DISTINCT FROM $2 THEN phone_verified_at END,
                    phone_code_hash = CASE WHEN phone IS NOT DISTINCT FROM $2 THEN phone_code_hash END
              WHERE id = $1",
        )
        .bind(u.id)
        .bind(&phone)
        .execute(&mut *tx)
        .await?;
    }
    sqlx::query("DELETE FROM user_contact_rules WHERE user_id = $1").bind(u.id).execute(&mut *tx).await?;
    for r in &b.rules {
        sqlx::query("INSERT INTO user_contact_rules (user_id, method, delay_minutes) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING")
            .bind(u.id)
            .bind(&r.method)
            .bind(r.delay_minutes)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    auth::audit(&st.db, Some(u.id), "account.contact_methods", Some(("user", u.id)), json!({ "rules": b.rules.len(), "phone_changed": b.phone.is_some() })).await;
    Ok(Json(contact_view(&st, &u).await?))
}

#[derive(Deserialize)]
pub struct VerifyIn {
    /// Without a code: text one. With one: check it.
    code: Option<String>,
}

fn code_hash(user: Uuid, code: &str) -> Vec<u8> {
    auth::token_hash(&format!("{user}:{code}"))
}

pub async fn verify_phone(State(st): State<Arc<AppState>>, u: User, Json(b): Json<VerifyIn>) -> ApiResult<Json<Value>> {
    session_only(&u)?;
    let (phone, hash, expires): (Option<String>, Option<Vec<u8>>, Option<DateTime<Utc>>) =
        sqlx::query_as("SELECT phone, phone_code_hash, phone_code_expires_at FROM users WHERE id = $1").bind(u.id).fetch_one(&st.db).await?;
    let phone = phone.ok_or_else(|| ApiError::BadRequest("save a mobile number first".into()))?;
    match b.code.as_deref().map(str::trim) {
        None | Some("") => {
            if expires.is_some_and(|e| e > Utc::now() + Duration::minutes(9)) {
                return Err(ApiError::BadRequest("a code was just sent: wait a minute before asking for another".into()));
            }
            let mut n = [0u8; 4];
            getrandom::fill(&mut n).map_err(|e| anyhow::anyhow!("{e}"))?;
            let code = format!("{:06}", u32::from_le_bytes(n) % 1_000_000);
            let text = format!("{} verification code: {code}. It expires in 10 minutes.", crate::pwa::manifest_branding(&st).short_name);
            oncall::send_sms(&st, &phone, &text).await.map_err(ApiError::BadRequest)?;
            sqlx::query("UPDATE users SET phone_code_hash = $2, phone_code_expires_at = now() + interval '10 minutes' WHERE id = $1")
                .bind(u.id)
                .bind(code_hash(u.id, &code))
                .execute(&st.db)
                .await?;
            Ok(Json(json!({ "sent": true })))
        }
        Some(code) => {
            let good = hash.is_some_and(|h| subtle::ConstantTimeEq::ct_eq(h.as_slice(), code_hash(u.id, code).as_slice()).into()) && expires.is_some_and(|e| e > Utc::now());
            // One try per code.
            sqlx::query(
                "UPDATE users SET phone_code_hash = NULL, phone_code_expires_at = NULL,
                        phone_verified_at = CASE WHEN $2 THEN now() ELSE phone_verified_at END WHERE id = $1",
            )
            .bind(u.id)
            .bind(good)
            .execute(&st.db)
            .await?;
            if !good {
                return Err(ApiError::BadRequest("that code is wrong or has expired: ask for a new one".into()));
            }
            auth::audit(&st.db, Some(u.id), "account.phone_verified", Some(("user", u.id)), json!({})).await;
            Ok(Json(json!({ "verified": true })))
        }
    }
}

// ---------------------------------------------------------------------------
// The SMS provider
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct SmsView {
    account_sid: String,
    from: String,
    base_url: String,
    token_set: bool,
}

fn sms_view(c: &Company) -> SmsView {
    SmsView { account_sid: c.sms_account_sid.clone(), from: c.sms_from.clone(), base_url: c.sms_base_url.clone(), token_set: c.sms_token_enc.is_some() }
}

pub async fn get_sms(State(st): State<Arc<AppState>>, u: User) -> ApiResult<Json<SmsView>> {
    u.require(Role::Admin)?;
    Ok(Json(sms_view(&st.company())))
}

#[derive(Deserialize)]
pub struct SmsIn {
    account_sid: String,
    from: String,
    #[serde(default)]
    base_url: String,
    /// Omitted = unchanged; "" clears it.
    token: Option<String>,
}

pub async fn update_sms(State(st): State<Arc<AppState>>, u: User, Json(b): Json<SmsIn>) -> ApiResult<Json<SmsView>> {
    u.require(Role::Admin)?;
    let sid = b.account_sid.trim();
    if sid.len() > 64 || !sid.bytes().all(|c| c.is_ascii_alphanumeric()) {
        return Err(ApiError::BadRequest("the account SID is letters and digits".into()));
    }
    let from = b.from.trim();
    if !from.is_empty() && !oncall::valid_e164(from) && !(from.starts_with("MG") && from.len() == 34) {
        return Err(ApiError::BadRequest("the sender is a number in international form, like +15005550006".into()));
    }
    let base = if b.base_url.trim().is_empty() { "https://api.twilio.com" } else { b.base_url.trim().trim_end_matches('/') };
    let parsed = reqwest::Url::parse(base).map_err(|_| ApiError::BadRequest("the API URL must be a full URL".into()))?;
    if !matches!(parsed.scheme(), "https" | "http") || parsed.host_str().is_none() {
        return Err(ApiError::BadRequest("the API URL must start with https://".into()));
    }
    let token: Option<(Option<Vec<u8>>, bool)> = b.token.as_deref().map(|t| match t.trim() {
        "" => (None, false),
        t => {
            let (bytes, sealed) = crate::crypto::store(st.cfg.data_key.as_ref(), t.as_bytes());
            (Some(bytes), sealed)
        }
    });
    let new: Company = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "UPDATE company_settings SET sms_account_sid = $1, sms_from = $2, sms_base_url = $3,
                sms_token_enc = CASE WHEN $4 THEN $5 ELSE sms_token_enc END,
                sms_token_sealed = CASE WHEN $4 THEN $6 ELSE sms_token_sealed END,
                updated_at = now(), updated_by = $7
         RETURNING {}",
        Company::COLUMNS
    )))
    .bind(sid)
    .bind(from)
    .bind(base)
    .bind(token.is_some())
    .bind(token.as_ref().and_then(|t| t.0.as_deref()))
    .bind(token.as_ref().is_some_and(|t| t.1))
    .bind(u.id)
    .fetch_one(&st.db)
    .await?;
    *st.company.write().unwrap_or_else(|e| e.into_inner()) = new.clone();
    auth::audit(&st.db, Some(u.id), "settings.sms", None, json!({ "account_sid": sid, "base_url": base })).await;
    Ok(Json(sms_view(&new)))
}

#[derive(Deserialize)]
pub struct SmsTest {
    to: String,
}

pub async fn test_sms(State(st): State<Arc<AppState>>, u: User, Json(b): Json<SmsTest>) -> ApiResult<Json<Value>> {
    u.require(Role::Admin)?;
    let to = b.to.trim();
    if !oncall::valid_e164(to) {
        return Err(ApiError::BadRequest("enter the number in international form, like +447700900123".into()));
    }
    let text = format!("Test message from {}. If you can read it, text messages work.", crate::pwa::manifest_branding(&st).name);
    let res = oncall::send_sms(&st, to, &text).await;
    auth::audit(&st.db, Some(u.id), "settings.sms_test", None, json!({ "ok": res.is_ok() })).await;
    Ok(Json(match res {
        Ok(_) => json!({ "ok": true }),
        Err(e) => json!({ "ok": false, "error": e }),
    }))
}
