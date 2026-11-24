//! Billing: work types and roles, technician rates, the product catalog, contracts and their
//! block-hours bank, products sold (charges), invoices from draft to paid, billing settings, and
//! the accounting connection.
//!
//! Reading money needs `billing.read`; changing it `billing.manage`. Technicians can pick work
//! types and sell catalog products on tickets without seeing prices.

use std::sync::Arc;

use axum::Json;
use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderValue, header};
use axum::response::{IntoResponse, Redirect, Response};
use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::PgConnection;
use uuid::Uuid;

use crate::auth::{self, Perm, Role, User};
use crate::billing::{self, line_amount, money, qty};
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

fn clean(s: &str, what: &str, max: usize) -> ApiResult<String> {
    let s = s.split_whitespace().collect::<Vec<_>>().join(" ");
    if s.is_empty() || s.chars().count() > max {
        return Err(ApiError::BadRequest(format!("{what} must be 1-{max} characters")));
    }
    Ok(s)
}

fn money_in(v: i64, what: &str) -> ApiResult<i64> {
    if !(0..=100_000_000_000).contains(&v) {
        return Err(ApiError::BadRequest(format!("{what} must be zero or more")));
    }
    Ok(v)
}

fn conflict(e: sqlx::Error, msg: &str) -> ApiError {
    match e {
        sqlx::Error::Database(d) if d.is_unique_violation() => ApiError::Conflict(msg.into()),
        e => e.into(),
    }
}

// ---------------------------------------------------------------------------
// Work types and roles
// ---------------------------------------------------------------------------

#[derive(Serialize, sqlx::FromRow)]
pub struct WorkType {
    id: Uuid,
    name: String,
    rate: Option<i64>,
    billable: bool,
    active: bool,
    position: i32,
}

pub async fn work_types(State(st): State<Arc<AppState>>, u: User) -> ApiResult<Json<Vec<WorkType>>> {
    let mut rows: Vec<WorkType> =
        sqlx::query_as("SELECT id, name, rate, billable, active, position FROM work_types ORDER BY position, lower(name)").fetch_all(&st.db).await?;
    if !u.has(Perm::BillingRead) {
        rows.iter_mut().for_each(|r| r.rate = None);
    }
    Ok(Json(rows))
}

#[derive(Deserialize)]
pub struct WorkTypeIn {
    id: Option<Uuid>,
    name: String,
    rate: Option<i64>,
    #[serde(default = "yes")]
    billable: bool,
    #[serde(default = "yes")]
    active: bool,
}

fn yes() -> bool {
    true
}

#[derive(Deserialize)]
pub struct WorkTypesIn {
    types: Vec<WorkTypeIn>,
}

/// Saves the whole list in order. Types with time logged can't be removed: deactivate them.
pub async fn save_work_types(State(st): State<Arc<AppState>>, u: User, Json(b): Json<WorkTypesIn>) -> ApiResult<Json<Value>> {
    u.need(Perm::BillingManage)?;
    if b.types.is_empty() || b.types.len() > 100 {
        return Err(ApiError::BadRequest("keep 1-100 work types".into()));
    }
    let mut tx = st.db.begin().await?;
    let keep: Vec<Uuid> = b.types.iter().filter_map(|t| t.id).collect();
    let used: Option<String> = sqlx::query_scalar(
        "SELECT w.name FROM work_types w WHERE NOT (w.id = ANY($1)) AND EXISTS (SELECT 1 FROM time_entries e WHERE e.work_type_id = w.id) LIMIT 1",
    )
    .bind(&keep)
    .fetch_optional(&mut *tx)
    .await?;
    if let Some(n) = used {
        return Err(ApiError::Conflict(format!("time is logged as {n}; switch it off instead of removing it")));
    }
    sqlx::query("DELETE FROM work_types WHERE NOT (id = ANY($1))").bind(&keep).execute(&mut *tx).await?;
    sqlx::query("UPDATE work_types SET name = id::text").execute(&mut *tx).await?;
    for (pos, t) in b.types.iter().enumerate() {
        let name = clean(&t.name, "work type", 60)?;
        if let Some(r) = t.rate {
            money_in(r, "rate")?;
        }
        sqlx::query(
            "INSERT INTO work_types (id, name, rate, billable, active, position) VALUES ($1, $2, $3, $4, $5, $6)
             ON CONFLICT (id) DO UPDATE SET name = $2, rate = $3, billable = $4, active = $5, position = $6",
        )
        .bind(t.id.unwrap_or_else(Uuid::new_v4))
        .bind(&name)
        .bind(t.rate)
        .bind(t.billable)
        .bind(t.active)
        .bind(pos as i32)
        .execute(&mut *tx)
        .await
        .map_err(|e| conflict(e, "two work types have the same name"))?;
    }
    tx.commit().await?;
    auth::audit(&st.db, Some(u.id), "billing.work_types", None, json!({ "types": b.types.len() })).await;
    Ok(Json(json!({ "ok": true })))
}

#[derive(Serialize, sqlx::FromRow)]
pub struct WorkRole {
    id: Uuid,
    name: String,
    rate: i64,
    users: i64,
}

pub async fn work_roles(State(st): State<Arc<AppState>>, u: User) -> ApiResult<Json<Vec<WorkRole>>> {
    u.need(Perm::BillingRead)?;
    Ok(Json(
        sqlx::query_as("SELECT r.id, r.name, r.rate, (SELECT count(*) FROM users x WHERE x.work_role_id = r.id) AS users FROM work_roles r ORDER BY lower(r.name)")
            .fetch_all(&st.db)
            .await?,
    ))
}

#[derive(Deserialize)]
pub struct WorkRoleIn {
    name: String,
    rate: i64,
}

pub async fn create_work_role(State(st): State<Arc<AppState>>, u: User, Json(b): Json<WorkRoleIn>) -> ApiResult<Json<Value>> {
    u.need(Perm::BillingManage)?;
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO work_roles (id, name, rate) VALUES ($1, $2, $3)")
        .bind(id)
        .bind(clean(&b.name, "name", 100)?)
        .bind(money_in(b.rate, "rate")?)
        .execute(&st.db)
        .await
        .map_err(|e| conflict(e, "a role with that name exists"))?;
    Ok(Json(json!({ "id": id })))
}

pub async fn update_work_role(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>, Json(b): Json<WorkRoleIn>) -> ApiResult<Json<Value>> {
    u.need(Perm::BillingManage)?;
    let n = sqlx::query("UPDATE work_roles SET name = $2, rate = $3 WHERE id = $1")
        .bind(id)
        .bind(clean(&b.name, "name", 100)?)
        .bind(money_in(b.rate, "rate")?)
        .execute(&st.db)
        .await
        .map_err(|e| conflict(e, "a role with that name exists"))?
        .rows_affected();
    if n == 0 {
        return Err(ApiError::NotFound("work role"));
    }
    Ok(Json(json!({ "ok": true })))
}

pub async fn remove_work_role(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    u.need(Perm::BillingManage)?;
    sqlx::query("DELETE FROM work_roles WHERE id = $1").bind(id).execute(&st.db).await?;
    Ok(Json(json!({ "ok": true })))
}

#[derive(Serialize, sqlx::FromRow)]
pub struct UserRates {
    id: Uuid,
    name: String,
    email: String,
    role: String,
    work_role_id: Option<Uuid>,
    default_rate: Option<i64>,
    cost_rate: i64,
    capacity_hours: i32,
}

pub async fn user_rates(State(st): State<Arc<AppState>>, u: User) -> ApiResult<Json<Vec<UserRates>>> {
    u.need(Perm::BillingRead)?;
    Ok(Json(
        sqlx::query_as(
            "SELECT id, name, email, role, work_role_id, default_rate, cost_rate, capacity_hours FROM users
              WHERE NOT disabled AND role IN ('technician', 'admin') ORDER BY lower(name)",
        )
        .fetch_all(&st.db)
        .await?,
    ))
}

#[derive(Deserialize)]
pub struct UserRatesIn {
    work_role_id: Option<Uuid>,
    default_rate: Option<i64>,
    #[serde(default)]
    cost_rate: i64,
    #[serde(default = "forty")]
    capacity_hours: i32,
}

fn forty() -> i32 {
    40
}

pub async fn set_user_rates(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>, Json(b): Json<UserRatesIn>) -> ApiResult<Json<Value>> {
    u.need(Perm::BillingManage)?;
    if !(0..=168).contains(&b.capacity_hours) {
        return Err(ApiError::BadRequest("capacity must be 0-168 hours a week".into()));
    }
    let n = sqlx::query("UPDATE users SET work_role_id = $2, default_rate = $3, cost_rate = $4, capacity_hours = $5 WHERE id = $1")
        .bind(id)
        .bind(b.work_role_id)
        .bind(b.default_rate.map(|r| money_in(r, "rate")).transpose()?)
        .bind(money_in(b.cost_rate, "cost")?)
        .bind(b.capacity_hours)
        .execute(&st.db)
        .await
        .map_err(|e| match e {
            sqlx::Error::Database(d) if d.is_foreign_key_violation() => ApiError::NotFound("work role"),
            e => e.into(),
        })?
        .rows_affected();
    if n == 0 {
        return Err(ApiError::NotFound("user"));
    }
    auth::audit(&st.db, Some(u.id), "billing.user_rates", Some(("user", id)), json!({})).await;
    Ok(Json(json!({ "ok": true })))
}

// ---------------------------------------------------------------------------
// Products
// ---------------------------------------------------------------------------

#[derive(Serialize, sqlx::FromRow)]
pub struct Product {
    id: Uuid,
    sku: Option<String>,
    name: String,
    description: String,
    kind: String,
    cost: Option<i64>,
    price: Option<i64>,
    active: bool,
}

pub async fn products(State(st): State<Arc<AppState>>, u: User) -> ApiResult<Json<Vec<Product>>> {
    let mut rows: Vec<Product> = sqlx::query_as("SELECT id, sku, name, description, kind, cost, price, active FROM products ORDER BY lower(name)")
        .fetch_all(&st.db)
        .await?;
    if !u.has(Perm::BillingRead) {
        rows.iter_mut().for_each(|p| {
            p.cost = None;
            p.price = None;
        });
    }
    Ok(Json(rows))
}

#[derive(Deserialize)]
pub struct ProductIn {
    sku: Option<String>,
    name: String,
    #[serde(default)]
    description: String,
    #[serde(default = "one_off")]
    kind: String,
    #[serde(default)]
    cost: i64,
    #[serde(default)]
    price: i64,
    #[serde(default = "yes")]
    active: bool,
}

fn one_off() -> String {
    "one_off".into()
}

impl ProductIn {
    fn validate(&mut self) -> ApiResult<()> {
        self.name = clean(&self.name, "name", 200)?;
        self.sku = self.sku.as_deref().map(str::trim).filter(|s| !s.is_empty()).map(|s| s.chars().take(60).collect());
        if !matches!(self.kind.as_str(), "one_off" | "recurring") {
            return Err(ApiError::BadRequest("kind must be one_off or recurring".into()));
        }
        money_in(self.cost, "cost")?;
        money_in(self.price, "price")?;
        Ok(())
    }
}

pub async fn create_product(State(st): State<Arc<AppState>>, u: User, Json(mut b): Json<ProductIn>) -> ApiResult<Json<Value>> {
    u.need(Perm::BillingManage)?;
    b.validate()?;
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO products (id, sku, name, description, kind, cost, price, active) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)")
        .bind(id)
        .bind(&b.sku)
        .bind(&b.name)
        .bind(b.description.trim())
        .bind(&b.kind)
        .bind(b.cost)
        .bind(b.price)
        .bind(b.active)
        .execute(&st.db)
        .await
        .map_err(|e| conflict(e, "that SKU is taken"))?;
    Ok(Json(json!({ "id": id })))
}

pub async fn update_product(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>, Json(mut b): Json<ProductIn>) -> ApiResult<Json<Value>> {
    u.need(Perm::BillingManage)?;
    b.validate()?;
    let n = sqlx::query("UPDATE products SET sku = $2, name = $3, description = $4, kind = $5, cost = $6, price = $7, active = $8 WHERE id = $1")
        .bind(id)
        .bind(&b.sku)
        .bind(&b.name)
        .bind(b.description.trim())
        .bind(&b.kind)
        .bind(b.cost)
        .bind(b.price)
        .bind(b.active)
        .execute(&st.db)
        .await
        .map_err(|e| conflict(e, "that SKU is taken"))?
        .rows_affected();
    if n == 0 {
        return Err(ApiError::NotFound("product"));
    }
    Ok(Json(json!({ "ok": true })))
}

pub async fn remove_product(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    u.need(Perm::BillingManage)?;
    sqlx::query("DELETE FROM products WHERE id = $1").bind(id).execute(&st.db).await?;
    Ok(Json(json!({ "ok": true })))
}

// ---------------------------------------------------------------------------
// Contracts
// ---------------------------------------------------------------------------

#[derive(Serialize, sqlx::FromRow)]
pub struct ContractRow {
    id: Uuid,
    client_id: Uuid,
    client_name: String,
    name: String,
    kind: String,
    start_date: NaiveDate,
    end_date: Option<NaiveDate>,
    billing_cycle: String,
    unit_price: i64,
    device_filter: String,
    user_count: i32,
    block_minutes: i32,
    overage_rate: Option<i64>,
    low_balance_minutes: i32,
    covered_work_type_ids: Vec<Uuid>,
    sla_policy_id: Option<Uuid>,
    sla_policy_name: Option<String>,
    manager_id: Option<Uuid>,
    notes: String,
    active: bool,
    /// Block hours: minutes left in the bank.
    balance_minutes: Option<i64>,
    /// What the contract brings in per cycle at today's counts (for per-device, the agents now).
    devices: i64,
    created_at: DateTime<Utc>,
}

const CONTRACT_COLS: &str = "ct.id, ct.client_id, cl.name AS client_name, ct.name, ct.kind, ct.start_date, ct.end_date, ct.billing_cycle, ct.unit_price,
     ct.device_filter, ct.user_count, ct.block_minutes, ct.overage_rate, ct.low_balance_minutes, ct.covered_work_type_ids, ct.sla_policy_id,
     sp.name AS sla_policy_name, ct.manager_id, ct.notes,
     (ct.start_date <= current_date AND (ct.end_date IS NULL OR ct.end_date >= current_date)) AS active,
     CASE WHEN ct.kind = 'block_hours' THEN (SELECT coalesce(sum(minutes), 0) FROM contract_bank b WHERE b.contract_id = ct.id)::bigint END AS balance_minutes,
     (SELECT count(*) FROM agents a JOIN sites s ON s.id = a.site_id WHERE s.client_id = ct.client_id) AS devices, ct.created_at
  FROM contracts ct JOIN clients cl ON cl.id = ct.client_id LEFT JOIN sla_policies sp ON sp.id = ct.sla_policy_id";

#[derive(Deserialize)]
pub struct ContractQuery {
    client_id: Option<Uuid>,
}

pub async fn contracts(State(st): State<Arc<AppState>>, u: User, Query(q): Query<ContractQuery>) -> ApiResult<Json<Vec<ContractRow>>> {
    u.need(Perm::BillingRead)?;
    Ok(Json(
        sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "SELECT {CONTRACT_COLS} WHERE ($1::uuid[] IS NULL OR ct.client_id = ANY($1)) AND ($2::uuid IS NULL OR ct.client_id = $2)
              ORDER BY lower(cl.name), ct.start_date DESC"
        )))
        .bind(u.scope())
        .bind(q.client_id)
        .fetch_all(&st.db)
        .await?,
    ))
}

async fn fetch_contract(st: &AppState, u: &User, id: Uuid) -> ApiResult<ContractRow> {
    let c: ContractRow = sqlx::query_as(sqlx::AssertSqlSafe(format!("SELECT {CONTRACT_COLS} WHERE ct.id = $1")))
        .bind(id)
        .fetch_optional(&st.db)
        .await?
        .ok_or(ApiError::NotFound("contract"))?;
    super::access::client(u, c.client_id).map_err(|_| ApiError::NotFound("contract"))?;
    Ok(c)
}

pub async fn contract(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    u.need(Perm::BillingRead)?;
    let c = fetch_contract(&st, &u, id).await?;
    let items: Vec<(Uuid, Option<Uuid>, String, i64, i64)> = sqlx::query_as(
        "SELECT id, product_id, description, quantity_milli, unit_price FROM contract_items WHERE contract_id = $1 ORDER BY position",
    )
    .bind(id)
    .fetch_all(&st.db)
    .await?;
    let overrides: Vec<(Uuid, i64)> =
        sqlx::query_as("SELECT work_type_id, rate FROM contract_rate_overrides WHERE contract_id = $1").bind(id).fetch_all(&st.db).await?;
    #[allow(clippy::type_complexity)]
    let bank: Vec<(i64, i32, String, String, Option<i64>, Option<String>, DateTime<Utc>)> = sqlx::query_as(
        "SELECT b.id, b.minutes, b.reason, b.note, t.number, i.number, b.created_at FROM contract_bank b
           LEFT JOIN time_entries e ON e.id = b.time_entry_id LEFT JOIN tickets t ON t.id = e.ticket_id LEFT JOIN invoices i ON i.id = b.invoice_id
          WHERE b.contract_id = $1 ORDER BY b.created_at DESC LIMIT 200",
    )
    .bind(id)
    .fetch_all(&st.db)
    .await?;
    let mut v = serde_json::to_value(&c).map_err(anyhow::Error::from)?;
    v["items"] = json!(items
        .iter()
        .map(|(id, p, d, q, price)| json!({ "id": id, "product_id": p, "description": d, "quantity_milli": q, "unit_price": price }))
        .collect::<Vec<_>>());
    v["rate_overrides"] = json!(overrides.iter().map(|(w, r)| json!({ "work_type_id": w, "rate": r })).collect::<Vec<_>>());
    v["bank"] = json!(bank
        .iter()
        .map(|(id, m, r, n, t, i, at)| json!({ "id": id, "minutes": m, "reason": r, "note": n, "ticket_number": t, "invoice_number": i, "created_at": at }))
        .collect::<Vec<_>>());
    Ok(Json(v))
}

#[derive(Deserialize)]
pub struct ItemIn {
    product_id: Option<Uuid>,
    description: String,
    quantity_milli: i64,
    unit_price: i64,
}

#[derive(Deserialize)]
pub struct OverrideIn {
    work_type_id: Uuid,
    rate: i64,
}

#[derive(Deserialize)]
pub struct ContractIn {
    client_id: Uuid,
    name: String,
    kind: String,
    start_date: NaiveDate,
    end_date: Option<NaiveDate>,
    #[serde(default = "monthly")]
    billing_cycle: String,
    #[serde(default)]
    unit_price: i64,
    #[serde(default = "all")]
    device_filter: String,
    #[serde(default)]
    user_count: i32,
    #[serde(default)]
    block_minutes: i32,
    overage_rate: Option<i64>,
    #[serde(default)]
    low_balance_minutes: i32,
    #[serde(default)]
    covered_work_type_ids: Vec<Uuid>,
    sla_policy_id: Option<Uuid>,
    manager_id: Option<Uuid>,
    #[serde(default)]
    notes: String,
    #[serde(default)]
    items: Vec<ItemIn>,
    #[serde(default)]
    rate_overrides: Vec<OverrideIn>,
}

fn monthly() -> String {
    "monthly".into()
}
fn all() -> String {
    "all".into()
}

impl ContractIn {
    async fn validate(&mut self, st: &AppState, u: &User) -> ApiResult<()> {
        super::access::client(u, self.client_id)?;
        self.name = clean(&self.name, "name", 200)?;
        if !["per_device", "per_user", "block_hours", "time_materials", "recurring"].contains(&self.kind.as_str()) {
            return Err(ApiError::BadRequest(format!("unknown contract type {}", self.kind)));
        }
        if !["monthly", "quarterly", "annual"].contains(&self.billing_cycle.as_str()) {
            return Err(ApiError::BadRequest("billing cycle must be monthly, quarterly or annual".into()));
        }
        if !["all", "workstations", "servers"].contains(&self.device_filter.as_str()) {
            return Err(ApiError::BadRequest("device filter must be all, workstations or servers".into()));
        }
        if self.end_date.is_some_and(|e| e < self.start_date) {
            return Err(ApiError::BadRequest("the contract can't end before it starts".into()));
        }
        money_in(self.unit_price, "price")?;
        if let Some(r) = self.overage_rate {
            money_in(r, "overage rate")?;
        }
        if self.user_count < 0 || self.block_minutes < 0 || self.low_balance_minutes < 0 {
            return Err(ApiError::BadRequest("counts can't be negative".into()));
        }
        if self.kind == "block_hours" && self.block_minutes == 0 {
            return Err(ApiError::BadRequest("a block-hours contract needs the hours it buys each cycle".into()));
        }
        if self.items.len() > 100 || self.rate_overrides.len() > 100 {
            return Err(ApiError::BadRequest("too many items".into()));
        }
        for i in &mut self.items {
            i.description = clean(&i.description, "item description", 300)?;
            if i.quantity_milli <= 0 {
                return Err(ApiError::BadRequest("item quantities must be more than zero".into()));
            }
            money_in(i.unit_price, "item price")?;
        }
        for o in &self.rate_overrides {
            money_in(o.rate, "rate")?;
        }
        let n: i64 = sqlx::query_scalar("SELECT count(*) FROM work_types WHERE id = ANY($1)").bind(&self.covered_work_type_ids).fetch_one(&st.db).await?;
        if n as usize != self.covered_work_type_ids.len() {
            return Err(ApiError::BadRequest("unknown work type".into()));
        }
        self.notes = self.notes.trim().chars().take(10_000).collect();
        Ok(())
    }
}

async fn save_contract(db: &mut PgConnection, id: Uuid, b: &ContractIn) -> sqlx::Result<()> {
    sqlx::query(
        "INSERT INTO contracts (id, client_id, name, kind, start_date, end_date, billing_cycle, unit_price, device_filter, user_count, block_minutes,
                                overage_rate, low_balance_minutes, covered_work_type_ids, sla_policy_id, manager_id, notes)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
         ON CONFLICT (id) DO UPDATE SET name = $3, kind = $4, start_date = $5, end_date = $6, billing_cycle = $7, unit_price = $8,
                device_filter = $9, user_count = $10, block_minutes = $11, overage_rate = $12, low_balance_minutes = $13,
                covered_work_type_ids = $14, sla_policy_id = $15, manager_id = $16, notes = $17",
    )
    .bind(id)
    .bind(b.client_id)
    .bind(&b.name)
    .bind(&b.kind)
    .bind(b.start_date)
    .bind(b.end_date)
    .bind(&b.billing_cycle)
    .bind(b.unit_price)
    .bind(&b.device_filter)
    .bind(b.user_count)
    .bind(b.block_minutes)
    .bind(b.overage_rate)
    .bind(b.low_balance_minutes)
    .bind(&b.covered_work_type_ids)
    .bind(b.sla_policy_id)
    .bind(b.manager_id)
    .bind(&b.notes)
    .execute(&mut *db)
    .await?;
    sqlx::query("DELETE FROM contract_items WHERE contract_id = $1").bind(id).execute(&mut *db).await?;
    for (pos, i) in b.items.iter().enumerate() {
        sqlx::query(
            "INSERT INTO contract_items (id, contract_id, product_id, description, quantity_milli, unit_price, position) VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(Uuid::new_v4())
        .bind(id)
        .bind(i.product_id)
        .bind(&i.description)
        .bind(i.quantity_milli)
        .bind(i.unit_price)
        .bind(pos as i32)
        .execute(&mut *db)
        .await?;
    }
    sqlx::query("DELETE FROM contract_rate_overrides WHERE contract_id = $1").bind(id).execute(&mut *db).await?;
    for o in &b.rate_overrides {
        sqlx::query("INSERT INTO contract_rate_overrides (contract_id, work_type_id, rate) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING")
            .bind(id)
            .bind(o.work_type_id)
            .bind(o.rate)
            .execute(&mut *db)
            .await?;
    }
    Ok(())
}

fn fk(e: sqlx::Error) -> ApiError {
    match e {
        sqlx::Error::Database(d) if d.is_foreign_key_violation() => ApiError::BadRequest("unknown SLA policy, manager, product or work type".into()),
        e => e.into(),
    }
}

pub async fn create_contract(State(st): State<Arc<AppState>>, u: User, Json(mut b): Json<ContractIn>) -> ApiResult<Json<ContractRow>> {
    u.need(Perm::BillingManage)?;
    b.validate(&st, &u).await?;
    let id = Uuid::new_v4();
    let mut tx = st.db.begin().await?;
    save_contract(&mut tx, id, &b).await.map_err(fk)?;
    tx.commit().await?;
    auth::audit(&st.db, Some(u.id), "contract.create", Some(("contract", id)), json!({ "client_id": b.client_id, "kind": b.kind })).await;
    super::sla::refresh_open(&st);
    Ok(Json(fetch_contract(&st, &u, id).await?))
}

pub async fn update_contract(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>, Json(mut b): Json<ContractIn>) -> ApiResult<Json<ContractRow>> {
    u.need(Perm::BillingManage)?;
    let cur = fetch_contract(&st, &u, id).await?;
    if cur.client_id != b.client_id {
        return Err(ApiError::BadRequest("a contract can't move to another client".into()));
    }
    b.validate(&st, &u).await?;
    let mut tx = st.db.begin().await?;
    save_contract(&mut tx, id, &b).await.map_err(fk)?;
    tx.commit().await?;
    auth::audit(&st.db, Some(u.id), "contract.update", Some(("contract", id)), json!({})).await;
    super::sla::refresh_open(&st);
    Ok(Json(fetch_contract(&st, &u, id).await?))
}

pub async fn remove_contract(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    u.need(Perm::BillingManage)?;
    fetch_contract(&st, &u, id).await?;
    let billed: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM contract_cycles cc JOIN invoices i ON i.id = cc.invoice_id WHERE cc.contract_id = $1 AND i.status <> 'draft')",
    )
    .bind(id)
    .fetch_one(&st.db)
    .await?;
    if billed {
        return Err(ApiError::Conflict("this contract has been invoiced; give it an end date instead".into()));
    }
    sqlx::query("DELETE FROM contracts WHERE id = $1").bind(id).execute(&st.db).await?;
    auth::audit(&st.db, Some(u.id), "contract.delete", Some(("contract", id)), json!({})).await;
    super::sla::refresh_open(&st);
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
pub struct BankIn {
    minutes: i32,
    #[serde(default)]
    note: String,
}

/// A manual adjustment to a block-hours bank (hours given back, a top-up sold elsewhere).
pub async fn adjust_bank(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>, Json(b): Json<BankIn>) -> ApiResult<Json<Value>> {
    u.need(Perm::BillingManage)?;
    let c = fetch_contract(&st, &u, id).await?;
    if c.kind != "block_hours" {
        return Err(ApiError::BadRequest("only block-hours contracts have a bank".into()));
    }
    if b.minutes == 0 || b.minutes.abs() > 1_000_000 {
        return Err(ApiError::BadRequest("adjust by a non-zero number of minutes".into()));
    }
    sqlx::query("INSERT INTO contract_bank (contract_id, minutes, reason, note, created_by) VALUES ($1, $2, 'adjustment', $3, $4)")
        .bind(id)
        .bind(b.minutes)
        .bind(b.note.trim().chars().take(300).collect::<String>())
        .bind(u.id)
        .execute(&st.db)
        .await?;
    auth::audit(&st.db, Some(u.id), "contract.bank_adjust", Some(("contract", id)), json!({ "minutes": b.minutes })).await;
    if b.minutes > 0 {
        sqlx::query("UPDATE contracts SET low_balance_warned_at = NULL WHERE id = $1").bind(id).execute(&st.db).await?;
    }
    Ok(Json(json!({ "ok": true })))
}

// ---------------------------------------------------------------------------
// Charges (products sold)
// ---------------------------------------------------------------------------

#[derive(Serialize, sqlx::FromRow)]
pub struct ChargeRow {
    id: Uuid,
    client_id: Uuid,
    client_name: String,
    ticket_id: Option<Uuid>,
    ticket_number: Option<i64>,
    product_id: Option<Uuid>,
    description: String,
    quantity_milli: i64,
    unit_price: Option<i64>,
    unit_cost: Option<i64>,
    day: NaiveDate,
    invoiced: bool,
    created_by_name: Option<String>,
}

#[derive(Deserialize)]
pub struct ChargeQuery {
    client_id: Option<Uuid>,
    ticket_id: Option<Uuid>,
    #[serde(default)]
    unbilled: bool,
}

pub async fn charges(State(st): State<Arc<AppState>>, u: User, Query(q): Query<ChargeQuery>) -> ApiResult<Json<Vec<ChargeRow>>> {
    if let Some(t) = q.ticket_id {
        super::tickets::visible(&st, &u, t).await?;
    } else {
        u.need(Perm::BillingRead)?;
    }
    let mut rows: Vec<ChargeRow> = sqlx::query_as(
        "SELECT ch.id, ch.client_id, cl.name AS client_name, ch.ticket_id, t.number AS ticket_number, ch.product_id, ch.description, ch.quantity_milli,
                ch.unit_price, ch.unit_cost, ch.day, ch.invoice_line_id IS NOT NULL AS invoiced, u.name AS created_by_name
           FROM charges ch JOIN clients cl ON cl.id = ch.client_id LEFT JOIN tickets t ON t.id = ch.ticket_id LEFT JOIN users u ON u.id = ch.created_by
          WHERE ($1::uuid[] IS NULL OR ch.client_id = ANY($1)) AND ($2::uuid IS NULL OR ch.client_id = $2) AND ($3::uuid IS NULL OR ch.ticket_id = $3)
            AND (NOT $4 OR ch.invoice_line_id IS NULL)
          ORDER BY ch.day DESC, ch.created_at DESC LIMIT 1000",
    )
    .bind(u.scope())
    .bind(q.client_id)
    .bind(q.ticket_id)
    .bind(q.unbilled)
    .fetch_all(&st.db)
    .await?;
    if !u.has(Perm::BillingRead) {
        rows.iter_mut().for_each(|r| {
            r.unit_price = None;
            r.unit_cost = None;
        });
    }
    Ok(Json(rows))
}

#[derive(Deserialize)]
pub struct ChargeIn {
    client_id: Option<Uuid>,
    ticket_id: Option<Uuid>,
    product_id: Option<Uuid>,
    description: Option<String>,
    #[serde(default = "thousand")]
    quantity_milli: i64,
    /// Billing managers can set the price; otherwise it's the product's.
    unit_price: Option<i64>,
    day: Option<NaiveDate>,
}

fn thousand() -> i64 {
    1000
}

/// Sells something: a catalog product (technicians), or anything at any price (billing managers).
pub async fn create_charge(State(st): State<Arc<AppState>>, u: User, Json(b): Json<ChargeIn>) -> ApiResult<Json<Value>> {
    u.require(Role::Technician)?;
    let client = match (b.ticket_id, b.client_id) {
        (Some(t), _) => super::tickets::visible(&st, &u, t).await?.ok_or_else(|| ApiError::BadRequest("choose the ticket's client first".into()))?,
        (None, Some(c)) => {
            super::access::client(&u, c)?;
            c
        }
        (None, None) => return Err(ApiError::BadRequest("sell to a client or on a ticket".into())),
    };
    if !(1..=1_000_000_000).contains(&b.quantity_milli) {
        return Err(ApiError::BadRequest("quantity must be more than zero".into()));
    }
    let product: Option<(String, i64, i64)> = match b.product_id {
        Some(p) => Some(
            sqlx::query_as("SELECT name, price, cost FROM products WHERE id = $1 AND active")
                .bind(p)
                .fetch_optional(&st.db)
                .await?
                .ok_or(ApiError::NotFound("product"))?,
        ),
        None => None,
    };
    let manage = u.has(Perm::BillingManage);
    if product.is_none() && !manage {
        return Err(ApiError::BadRequest("pick a product from the catalog".into()));
    }
    let price = match (b.unit_price, &product) {
        (Some(p), _) if manage => money_in(p, "price")?,
        (Some(_), _) => return Err(ApiError::Forbidden),
        (None, Some((_, p, _))) => *p,
        (None, None) => return Err(ApiError::BadRequest("give the price".into())),
    };
    let description = match (&b.description, &product) {
        (Some(d), _) if !d.trim().is_empty() => clean(d, "description", 300)?,
        (_, Some((n, _, _))) => n.clone(),
        _ => return Err(ApiError::BadRequest("describe what was sold".into())),
    };
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO charges (id, client_id, ticket_id, product_id, description, quantity_milli, unit_price, unit_cost, day, created_by)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, coalesce($9, current_date), $10)",
    )
    .bind(id)
    .bind(client)
    .bind(b.ticket_id)
    .bind(b.product_id)
    .bind(&description)
    .bind(b.quantity_milli)
    .bind(price)
    .bind(product.as_ref().map_or(0, |p| p.2))
    .bind(b.day)
    .bind(u.id)
    .execute(&st.db)
    .await?;
    Ok(Json(json!({ "id": id })))
}

pub async fn remove_charge(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    u.require(Role::Technician)?;
    let row: Option<(Uuid, Option<Uuid>, Option<Uuid>)> =
        sqlx::query_as("SELECT client_id, invoice_line_id, created_by FROM charges WHERE id = $1").bind(id).fetch_optional(&st.db).await?;
    let (client, invoiced, by) = row.ok_or(ApiError::NotFound("charge"))?;
    super::access::client(&u, client).map_err(|_| ApiError::NotFound("charge"))?;
    if invoiced.is_some() {
        return Err(ApiError::Conflict("it's on an invoice already".into()));
    }
    if by != Some(u.id) && !u.has(Perm::BillingManage) {
        return Err(ApiError::Forbidden);
    }
    sqlx::query("DELETE FROM charges WHERE id = $1").bind(id).execute(&st.db).await?;
    Ok(Json(json!({ "ok": true })))
}

// ---------------------------------------------------------------------------
// Invoices
// ---------------------------------------------------------------------------

#[derive(Serialize, sqlx::FromRow)]
pub struct InvoiceRow {
    id: Uuid,
    number: Option<String>,
    client_id: Uuid,
    client_name: String,
    kind: String,
    credit_of: Option<Uuid>,
    credit_of_number: Option<String>,
    currency: String,
    status: String,
    issue_date: NaiveDate,
    due_date: NaiveDate,
    period_start: Option<NaiveDate>,
    period_end: Option<NaiveDate>,
    total: i64,
    notes: String,
    bill_to: String,
    finalised_at: Option<DateTime<Utc>>,
    sent_at: Option<DateTime<Utc>>,
    paid_at: Option<DateTime<Utc>>,
    voided_at: Option<DateTime<Utc>>,
    external: Value,
    overdue: bool,
    created_at: DateTime<Utc>,
}

const INVOICE_COLS: &str = "i.id, i.number, i.client_id, cl.name AS client_name, i.kind, i.credit_of, ci.number AS credit_of_number, i.currency,
     i.status, i.issue_date, i.due_date, i.period_start, i.period_end, i.total, i.notes, i.bill_to, i.finalised_at, i.sent_at, i.paid_at,
     i.voided_at, i.external, (i.status IN ('finalised', 'sent') AND i.kind = 'invoice' AND i.due_date < current_date) AS overdue, i.created_at
  FROM invoices i JOIN clients cl ON cl.id = i.client_id LEFT JOIN invoices ci ON ci.id = i.credit_of";

#[derive(Deserialize)]
pub struct InvoiceQuery {
    client_id: Option<Uuid>,
    /// draft, finalised, sent, paid, void, unpaid (finalised or sent), overdue
    status: Option<String>,
}

pub async fn invoices(State(st): State<Arc<AppState>>, u: User, Query(q): Query<InvoiceQuery>) -> ApiResult<Json<Vec<InvoiceRow>>> {
    u.need(Perm::BillingRead)?;
    let status = q.status.as_deref().filter(|s| !s.is_empty());
    if let Some(s) = status
        && !["draft", "finalised", "sent", "paid", "void", "unpaid", "overdue"].contains(&s)
    {
        return Err(ApiError::BadRequest(format!("unknown status {s}")));
    }
    Ok(Json(
        sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "SELECT {INVOICE_COLS}
              WHERE ($1::uuid[] IS NULL OR i.client_id = ANY($1)) AND ($2::uuid IS NULL OR i.client_id = $2)
                AND ($3::text IS NULL OR i.status = $3 OR ($3 = 'unpaid' AND i.status IN ('finalised', 'sent'))
                     OR ($3 = 'overdue' AND i.status IN ('finalised', 'sent') AND i.kind = 'invoice' AND i.due_date < current_date))
              ORDER BY i.status = 'draft' DESC, i.issue_date DESC, i.number DESC NULLS FIRST LIMIT 1000"
        )))
        .bind(u.scope())
        .bind(q.client_id)
        .bind(status)
        .fetch_all(&st.db)
        .await?,
    ))
}

async fn fetch_invoice(st: &AppState, u: &User, id: Uuid) -> ApiResult<InvoiceRow> {
    let i: InvoiceRow = sqlx::query_as(sqlx::AssertSqlSafe(format!("SELECT {INVOICE_COLS} WHERE i.id = $1")))
        .bind(id)
        .fetch_optional(&st.db)
        .await?
        .ok_or(ApiError::NotFound("invoice"))?;
    super::access::client(u, i.client_id).map_err(|_| ApiError::NotFound("invoice"))?;
    Ok(i)
}

#[derive(Serialize, sqlx::FromRow)]
pub struct LineRow {
    id: Uuid,
    position: i32,
    kind: String,
    description: String,
    quantity_milli: i64,
    unit_price: i64,
    amount: i64,
    contract_id: Option<Uuid>,
    product_id: Option<Uuid>,
    details: Value,
}

async fn lines_of(db: &sqlx::PgPool, id: Uuid) -> sqlx::Result<Vec<LineRow>> {
    sqlx::query_as(
        "SELECT id, position, kind, description, quantity_milli, unit_price, amount, contract_id, product_id, details
           FROM invoice_lines WHERE invoice_id = $1 ORDER BY position, description",
    )
    .bind(id)
    .fetch_all(db)
    .await
}

pub async fn invoice(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    u.need(Perm::BillingRead)?;
    let i = fetch_invoice(&st, &u, id).await?;
    let lines = lines_of(&st.db, id).await?;
    let recipients: Vec<String> = billing_contacts(&st.db, i.client_id).await?;
    let mut v = serde_json::to_value(&i).map_err(anyhow::Error::from)?;
    v["lines"] = json!(lines);
    v["recipients"] = json!(recipients);
    Ok(Json(v))
}

async fn billing_contacts(db: &sqlx::PgPool, client: Uuid) -> sqlx::Result<Vec<String>> {
    let mut list: Vec<String> =
        sqlx::query_scalar("SELECT email FROM contacts WHERE client_id = $1 AND is_billing AND email <> '' ORDER BY lower(name)")
            .bind(client)
            .fetch_all(db)
            .await?;
    if list.is_empty() {
        list = sqlx::query_scalar("SELECT email FROM contacts WHERE client_id = $1 AND is_primary AND email <> '' LIMIT 1")
            .bind(client)
            .fetch_all(db)
            .await?;
    }
    Ok(list)
}

#[derive(Deserialize)]
pub struct RunIn {
    from: NaiveDate,
    to: NaiveDate,
    /// Only these clients (default: every visible client with something to bill).
    client_ids: Option<Vec<Uuid>>,
}

/// The invoice run: a draft per client with anything to bill in the period.
pub async fn run(State(st): State<Arc<AppState>>, u: User, Json(b): Json<RunIn>) -> ApiResult<Json<Value>> {
    u.need(Perm::BillingManage)?;
    if b.to < b.from || (b.to - b.from).num_days() > 366 {
        return Err(ApiError::BadRequest("choose a period of at most a year".into()));
    }
    let clients: Vec<Uuid> = sqlx::query_scalar(
        "SELECT id FROM clients WHERE ($1::uuid[] IS NULL OR id = ANY($1)) AND ($2::uuid[] IS NULL OR id = ANY($2)) ORDER BY lower(name)",
    )
    .bind(u.scope())
    .bind(&b.client_ids)
    .fetch_all(&st.db)
    .await?;
    let mut created = vec![];
    for c in clients {
        let mut tx = st.db.begin().await?;
        // One run at a time per client: the lock keeps two runs from billing the same time twice.
        sqlx::query("SELECT 1 FROM clients WHERE id = $1 FOR UPDATE").bind(c).execute(&mut *tx).await?;
        if let Some(id) = billing::draft_for_client(&mut tx, c, b.from, b.to, u.id).await? {
            created.push(id);
        }
        tx.commit().await?;
    }
    auth::audit(&st.db, Some(u.id), "invoice.run", None, json!({ "from": b.from, "to": b.to, "drafts": created.len() })).await;
    Ok(Json(json!({ "created": created })))
}

#[derive(Deserialize)]
pub struct BlankIn {
    client_id: Uuid,
}

/// An empty draft for one client, to fill by hand.
pub async fn create_invoice(State(st): State<Arc<AppState>>, u: User, Json(b): Json<BlankIn>) -> ApiResult<Json<Value>> {
    u.need(Perm::BillingManage)?;
    super::access::client(&u, b.client_id)?;
    let mut tx = st.db.begin().await?;
    let currency = billing::currency_of(&mut tx, b.client_id).await?;
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO invoices (id, client_id, currency, due_date, created_by)
         VALUES ($1, $2, $3, current_date + (SELECT invoice_terms_days FROM company_settings), $4)",
    )
    .bind(id)
    .bind(b.client_id)
    .bind(currency)
    .bind(u.id)
    .execute(&mut *tx)
    .await
    .map_err(|e| match e {
        sqlx::Error::Database(d) if d.is_foreign_key_violation() => ApiError::NotFound("client"),
        e => e.into(),
    })?;
    tx.commit().await?;
    Ok(Json(json!({ "id": id })))
}

async fn draft(st: &AppState, u: &User, id: Uuid) -> ApiResult<InvoiceRow> {
    u.need(Perm::BillingManage)?;
    let i = fetch_invoice(st, u, id).await?;
    if i.status != "draft" {
        return Err(ApiError::Conflict("finalised invoices can't change: issue a credit note".into()));
    }
    Ok(i)
}

#[derive(Deserialize)]
pub struct InvoicePatch {
    notes: Option<String>,
    issue_date: Option<NaiveDate>,
    due_date: Option<NaiveDate>,
}

pub async fn update_invoice(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>, Json(b): Json<InvoicePatch>) -> ApiResult<Json<Value>> {
    draft(&st, &u, id).await?;
    if let (Some(i), Some(d)) = (b.issue_date, b.due_date)
        && d < i
    {
        return Err(ApiError::BadRequest("the due date can't be before the issue date".into()));
    }
    sqlx::query(
        "UPDATE invoices SET notes = coalesce($2, notes), issue_date = coalesce($3, issue_date), due_date = coalesce($4, due_date), updated_at = now()
          WHERE id = $1",
    )
    .bind(id)
    .bind(b.notes.map(|n| n.trim().chars().take(5000).collect::<String>()))
    .bind(b.issue_date)
    .bind(b.due_date)
    .execute(&st.db)
    .await?;
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
pub struct LineIn {
    description: String,
    quantity_milli: i64,
    unit_price: i64,
    product_id: Option<Uuid>,
}

impl LineIn {
    fn check(&mut self, credit: bool) -> ApiResult<()> {
        self.description = clean(&self.description, "description", 500)?;
        if self.quantity_milli == 0 || self.quantity_milli.abs() > 1_000_000_000 {
            return Err(ApiError::BadRequest("quantity must not be zero".into()));
        }
        if self.unit_price.abs() > 100_000_000_000 {
            return Err(ApiError::BadRequest("price is out of range".into()));
        }
        // Credit notes hold negative amounts, invoices positive ones (a discount is a negative quantity).
        let _ = credit;
        Ok(())
    }
}

pub async fn add_line(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>, Json(mut b): Json<LineIn>) -> ApiResult<Json<Value>> {
    let inv = draft(&st, &u, id).await?;
    b.check(inv.kind == "credit_note")?;
    let mut tx = st.db.begin().await?;
    let line = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO invoice_lines (id, invoice_id, position, kind, description, quantity_milli, unit_price, amount, product_id)
         VALUES ($1, $2, (SELECT coalesce(max(position), -1) + 1 FROM invoice_lines WHERE invoice_id = $2), 'manual', $3, $4, $5, $6, $7)",
    )
    .bind(line)
    .bind(id)
    .bind(&b.description)
    .bind(b.quantity_milli)
    .bind(b.unit_price)
    .bind(line_amount(b.quantity_milli, b.unit_price))
    .bind(b.product_id)
    .execute(&mut *tx)
    .await?;
    let total = billing::retotal(&mut tx, id).await?;
    tx.commit().await?;
    Ok(Json(json!({ "id": line, "total": total })))
}

pub async fn update_line(State(st): State<Arc<AppState>>, u: User, Path((id, line)): Path<(Uuid, Uuid)>, Json(mut b): Json<LineIn>) -> ApiResult<Json<Value>> {
    let inv = draft(&st, &u, id).await?;
    b.check(inv.kind == "credit_note")?;
    let mut tx = st.db.begin().await?;
    let n = sqlx::query("UPDATE invoice_lines SET description = $3, quantity_milli = $4, unit_price = $5, amount = $6 WHERE id = $2 AND invoice_id = $1")
        .bind(id)
        .bind(line)
        .bind(&b.description)
        .bind(b.quantity_milli)
        .bind(b.unit_price)
        .bind(line_amount(b.quantity_milli, b.unit_price))
        .execute(&mut *tx)
        .await?
        .rows_affected();
    if n == 0 {
        return Err(ApiError::NotFound("line"));
    }
    let total = billing::retotal(&mut tx, id).await?;
    tx.commit().await?;
    Ok(Json(json!({ "total": total })))
}

/// Removing a line gives its time and products back to the next run (and a recurring line's
/// cycle and block-hours purchase).
pub async fn remove_line(State(st): State<Arc<AppState>>, u: User, Path((id, line)): Path<(Uuid, Uuid)>) -> ApiResult<Json<Value>> {
    draft(&st, &u, id).await?;
    let mut tx = st.db.begin().await?;
    let row: Option<(Option<Uuid>, String, Value)> =
        sqlx::query_as("DELETE FROM invoice_lines WHERE id = $2 AND invoice_id = $1 RETURNING contract_id, kind, details")
            .bind(id)
            .bind(line)
            .fetch_optional(&mut *tx)
            .await?;
    let (contract, kind, details) = row.ok_or(ApiError::NotFound("line"))?;
    if let (Some(c), Some(start)) = (contract, details["period"][0].as_str().and_then(|s| s.parse::<NaiveDate>().ok())) {
        let others: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM invoice_lines WHERE invoice_id = $1 AND contract_id = $2 AND details->'period'->>0 = $3)",
        )
        .bind(id)
        .bind(c)
        .bind(start.to_string())
        .fetch_one(&mut *tx)
        .await?;
        if !others {
            sqlx::query("DELETE FROM contract_cycles WHERE contract_id = $1 AND period_start = $2 AND invoice_id = $3").bind(c).bind(start).bind(id).execute(&mut *tx).await?;
        }
        if kind == "block" {
            sqlx::query("DELETE FROM contract_bank WHERE contract_id = $1 AND invoice_id = $2 AND reason = 'purchase'").bind(c).bind(id).execute(&mut *tx).await?;
        }
    }
    let total = billing::retotal(&mut tx, id).await?;
    tx.commit().await?;
    Ok(Json(json!({ "total": total })))
}

/// Deletes a draft; what it billed goes back to the next run.
pub async fn remove_invoice(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    draft(&st, &u, id).await?;
    sqlx::query("DELETE FROM invoices WHERE id = $1 AND status = 'draft'").bind(id).execute(&st.db).await?;
    auth::audit(&st.db, Some(u.id), "invoice.delete_draft", Some(("invoice", id)), json!({})).await;
    Ok(Json(json!({ "ok": true })))
}

/// The bill-to block: the client's name and billing address.
async fn bill_to(db: &mut PgConnection, client: Uuid) -> sqlx::Result<String> {
    let (name, address): (String, String) =
        sqlx::query_as("SELECT name, billing_address FROM clients WHERE id = $1").bind(client).fetch_one(&mut *db).await?;
    Ok(if address.trim().is_empty() { name } else { format!("{name}\n{}", address.trim()) })
}

async fn render_pdf(st: &AppState, id: Uuid) -> ApiResult<Vec<u8>> {
    #[derive(sqlx::FromRow)]
    struct Head {
        number: Option<String>,
        kind: String,
        status: String,
        currency: String,
        issue_date: NaiveDate,
        due_date: NaiveDate,
        period_start: Option<NaiveDate>,
        period_end: Option<NaiveDate>,
        total: i64,
        notes: String,
        bill_to: String,
        client_id: Uuid,
        credit_of_number: Option<String>,
    }
    let h: Head = sqlx::query_as(
        "SELECT i.number, i.kind, i.status, i.currency, i.issue_date, i.due_date, i.period_start, i.period_end, i.total, i.notes, i.bill_to,
                i.client_id, ci.number AS credit_of_number
           FROM invoices i LEFT JOIN invoices ci ON ci.id = i.credit_of WHERE i.id = $1",
    )
    .bind(id)
    .fetch_one(&st.db)
    .await?;
    let lines = lines_of(&st.db, id).await?;
    let (address, footer): (String, String) =
        sqlx::query_as("SELECT company_address, invoice_footer FROM company_settings").fetch_one(&st.db).await?;
    let bill = if h.bill_to.is_empty() { bill_to(&mut *st.db.acquire().await?, h.client_id).await? } else { h.bill_to };
    let credit = h.kind == "credit_note";
    let banner = match (h.status.as_str(), &h.credit_of_number) {
        ("void", _) => Some("VOID".to_string()),
        ("draft", _) => Some("DRAFT".to_string()),
        (_, Some(n)) => Some(format!("Credit for {n}")),
        _ => None,
    };
    let logo = crate::branding::pdf_logo(st, Some(h.client_id)).await;
    let pdf = crate::pdf::invoice(&crate::pdf::Invoice {
        title: if credit { "Credit note".into() } else { "Invoice".into() },
        number: h.number.unwrap_or_else(|| "Draft".into()),
        company: crate::email::brand(st),
        company_address: address,
        bill_to: bill,
        issue_date: h.issue_date.format("%-d %B %Y").to_string(),
        due_date: if credit { "–".into() } else { h.due_date.format("%-d %B %Y").to_string() },
        period: match (h.period_start, h.period_end) {
            (Some(a), Some(b)) => Some(format!("{} – {}", a.format("%-d %b %Y"), b.format("%-d %b %Y"))),
            _ => None,
        },
        lines: lines
            .iter()
            .map(|l| crate::pdf::InvoiceLine {
                description: l.description.clone(),
                quantity: qty(l.quantity_milli),
                unit_price: money(l.unit_price, &h.currency),
                amount: money(l.amount, &h.currency),
            })
            .collect(),
        total: money(h.total, &h.currency),
        notes: h.notes,
        footer,
        banner,
        logo,
    });
    Ok(pdf)
}

pub(crate) fn pdf_bytes_response(bytes: Vec<u8>, name: &str) -> ApiResult<Response> {
    let mut res = Response::new(Body::from(bytes));
    let h = res.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/pdf"));
    let safe: String = name.chars().map(|c| if c.is_ascii_alphanumeric() || "-_.".contains(c) { c } else { '_' }).collect();
    h.insert(header::CONTENT_DISPOSITION, HeaderValue::from_str(&format!("inline; filename=\"{safe}.pdf\"")).map_err(anyhow::Error::from)?);
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("private, no-store"));
    // Our own generated PDFs (no script). Browsers' PDF viewers refuse `sandbox` and
    // `object-src 'none'`, so these get a policy of their own instead of the site default.
    h.insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static("default-src 'none'; frame-ancestors 'self'"));
    Ok(res)
}

/// The invoice as a PDF: the stored file once finalised, a preview while it's a draft.
pub async fn pdf(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Response> {
    u.need(Perm::BillingRead)?;
    let i = fetch_invoice(&st, &u, id).await?;
    let key: Option<String> = sqlx::query_scalar("SELECT pdf_key FROM invoices WHERE id = $1").bind(id).fetch_one(&st.db).await?;
    let bytes = match (key, i.status.as_str()) {
        (Some(k), s) if s != "void" => st.storage.get(&k).await?,
        _ => render_pdf(&st, id).await?,
    };
    pdf_bytes_response(bytes, i.number.as_deref().unwrap_or("draft"))
}

/// Stored PDF for the portal (finalised invoices only).
pub async fn stored_pdf(st: &AppState, id: Uuid) -> ApiResult<Response> {
    let (key, number, status): (Option<String>, Option<String>, String) =
        sqlx::query_as("SELECT pdf_key, number, status FROM invoices WHERE id = $1").bind(id).fetch_one(&st.db).await?;
    let bytes = match key {
        Some(k) if status != "void" => st.storage.get(&k).await?,
        _ => render_pdf(st, id).await?,
    };
    pdf_bytes_response(bytes, number.as_deref().unwrap_or("invoice"))
}

/// Numbers the invoice (without gaps), freezes it and stores its PDF.
pub async fn finalise(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    let inv = draft(&st, &u, id).await?;
    let mut tx = st.db.begin().await?;
    sqlx::query("SELECT 1 FROM invoices WHERE id = $1 FOR UPDATE").bind(id).execute(&mut *tx).await?;
    let lines: i64 = sqlx::query_scalar("SELECT count(*) FROM invoice_lines WHERE invoice_id = $1").bind(id).fetch_one(&mut *tx).await?;
    if lines == 0 {
        return Err(ApiError::BadRequest("add a line first".into()));
    }
    let total = billing::retotal(&mut tx, id).await?;
    if inv.kind == "invoice" && total < 0 {
        return Err(ApiError::BadRequest("an invoice can't total less than zero: issue a credit note instead".into()));
    }
    let number = billing::next_number(&mut tx).await?;
    let bill = bill_to(&mut tx, inv.client_id).await?;
    sqlx::query("UPDATE invoices SET number = $2, status = 'finalised', finalised_at = now(), bill_to = $3, updated_at = now() WHERE id = $1")
        .bind(id)
        .bind(&number)
        .bind(&bill)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    let pdf = render_pdf(&st, id).await?;
    let key = format!("invoices/{id}.pdf");
    st.storage.put(&key, pdf, "application/pdf").await?;
    sqlx::query("UPDATE invoices SET pdf_key = $2 WHERE id = $1").bind(id).bind(&key).execute(&st.db).await?;
    auth::audit(&st.db, Some(u.id), "invoice.finalise", Some(("invoice", id)), json!({ "number": number, "total": total, "currency": inv.currency })).await;
    // Off to the accounting system, if one is connected (errors are kept on the invoice).
    let st2 = st.clone();
    tokio::spawn(async move {
        if let Err(e) = crate::accounting::push(&st2, id).await
            && !e.to_string().contains("no accounting system")
        {
            let _ = sqlx::query("UPDATE invoices SET external = external || jsonb_build_object('error', $2::text) WHERE id = $1")
                .bind(id)
                .bind(format!("{e:#}"))
                .execute(&st2.db)
                .await;
        }
    });
    Ok(Json(json!({ "number": number })))
}

#[derive(Deserialize, Default)]
pub struct SendIn {
    /// Defaults to the client's billing contacts.
    to: Option<Vec<String>>,
    message: Option<String>,
}

pub async fn send(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>, Json(b): Json<SendIn>) -> ApiResult<Json<Value>> {
    u.need(Perm::BillingManage)?;
    let i = fetch_invoice(&st, &u, id).await?;
    if !matches!(i.status.as_str(), "finalised" | "sent" | "paid") {
        return Err(ApiError::Conflict("finalise the invoice first".into()));
    }
    let to = match b.to {
        Some(list) => list.into_iter().map(|t| t.trim().to_ascii_lowercase()).filter(|t| !t.is_empty()).collect::<Vec<_>>(),
        None => billing_contacts(&st.db, i.client_id).await?,
    };
    if to.is_empty() || to.len() > 20 {
        return Err(ApiError::BadRequest("mark a contact as a billing contact, or give 1-20 addresses".into()));
    }
    for t in &to {
        t.parse::<lettre::Address>().map_err(|_| ApiError::BadRequest(format!("{t} is not an email address")))?;
    }
    let key: Option<String> = sqlx::query_scalar("SELECT pdf_key FROM invoices WHERE id = $1").bind(id).fetch_one(&st.db).await?;
    let key = key.ok_or_else(|| ApiError::Conflict("the PDF isn't ready yet".into()))?;
    let number = i.number.clone().unwrap_or_default();
    let what = if i.kind == "credit_note" { "Credit note" } else { "Invoice" };
    let brand = crate::email::brand(&st);
    let body = format!(
        "{}\n\n{what} {number} for {}: {}{}\n\nThe PDF is attached.\n\n{brand}\n",
        b.message.as_deref().map(str::trim).filter(|m| !m.is_empty()).unwrap_or("Hello,"),
        i.client_name,
        money(i.total, &i.currency),
        if i.kind == "invoice" { format!(", due {}", i.due_date.format("%-d %B %Y")) } else { String::new() },
    );
    crate::email::queue_invoice(&st, i.client_id, to.clone(), format!("{what} {number} from {brand}"), body, (format!("{number}.pdf"), key)).await?;
    sqlx::query("UPDATE invoices SET status = CASE WHEN status = 'finalised' THEN 'sent' ELSE status END, sent_at = now(), updated_at = now() WHERE id = $1")
        .bind(id)
        .execute(&st.db)
        .await?;
    auth::audit(&st.db, Some(u.id), "invoice.send", Some(("invoice", id)), json!({ "to": to })).await;
    Ok(Json(json!({ "ok": true, "to": to })))
}

pub async fn mark_paid(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    u.need(Perm::BillingManage)?;
    fetch_invoice(&st, &u, id).await?;
    let n = sqlx::query("UPDATE invoices SET status = 'paid', paid_at = now(), updated_at = now() WHERE id = $1 AND status IN ('finalised', 'sent')")
        .bind(id)
        .execute(&st.db)
        .await?
        .rows_affected();
    if n == 0 {
        return Err(ApiError::Conflict("only finalised or sent invoices can be marked paid".into()));
    }
    auth::audit(&st.db, Some(u.id), "invoice.paid", Some(("invoice", id)), json!({})).await;
    Ok(Json(json!({ "ok": true })))
}

/// Voids a finalised invoice (its number stays used). What it billed is not released: credit it
/// and re-bill if needed.
pub async fn void(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    u.need(Perm::BillingManage)?;
    fetch_invoice(&st, &u, id).await?;
    let n = sqlx::query("UPDATE invoices SET status = 'void', voided_at = now(), updated_at = now() WHERE id = $1 AND status IN ('finalised', 'sent')")
        .bind(id)
        .execute(&st.db)
        .await?
        .rows_affected();
    if n == 0 {
        return Err(ApiError::Conflict("only finalised or sent invoices can be voided (delete a draft instead)".into()));
    }
    auth::audit(&st.db, Some(u.id), "invoice.void", Some(("invoice", id)), json!({})).await;
    Ok(Json(json!({ "ok": true })))
}

/// A draft credit note reversing the invoice's lines; edit it down for a partial credit.
pub async fn credit(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    u.need(Perm::BillingManage)?;
    let i = fetch_invoice(&st, &u, id).await?;
    if i.kind != "invoice" || !matches!(i.status.as_str(), "finalised" | "sent" | "paid") {
        return Err(ApiError::Conflict("credit a finalised invoice".into()));
    }
    let mut tx = st.db.begin().await?;
    let cn = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO invoices (id, client_id, kind, credit_of, currency, period_start, period_end, notes, created_by)
         VALUES ($1, $2, 'credit_note', $3, $4, $5, $6, $7, $8)",
    )
    .bind(cn)
    .bind(i.client_id)
    .bind(id)
    .bind(&i.currency)
    .bind(i.period_start)
    .bind(i.period_end)
    .bind(format!("Credit for {}", i.number.as_deref().unwrap_or_default()))
    .bind(u.id)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO invoice_lines (id, invoice_id, position, kind, description, quantity_milli, unit_price, amount, contract_id, product_id, details)
         SELECT gen_random_uuid(), $2, position, kind, description, -quantity_milli, unit_price, -amount, contract_id, product_id, details
           FROM invoice_lines WHERE invoice_id = $1",
    )
    .bind(id)
    .bind(cn)
    .execute(&mut *tx)
    .await?;
    billing::retotal(&mut tx, cn).await?;
    tx.commit().await?;
    auth::audit(&st.db, Some(u.id), "invoice.credit", Some(("invoice", id)), json!({ "credit_note": cn })).await;
    Ok(Json(json!({ "id": cn })))
}

// ---------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, sqlx::FromRow)]
pub struct BillingSettings {
    currency: String,
    company_address: String,
    invoice_prefix: String,
    invoice_terms_days: i32,
    invoice_footer: String,
    default_rate: i64,
}

pub async fn get_settings(State(st): State<Arc<AppState>>, u: User) -> ApiResult<Json<Value>> {
    u.need(Perm::BillingRead)?;
    let s: BillingSettings = sqlx::query_as(
        "SELECT currency, company_address, invoice_prefix, invoice_terms_days, invoice_footer, default_rate FROM company_settings",
    )
    .fetch_one(&st.db)
    .await?;
    let next: i64 = sqlx::query_scalar("SELECT next FROM invoice_counter WHERE id = 1").fetch_one(&st.db).await?;
    let mut v = serde_json::to_value(&s).map_err(anyhow::Error::from)?;
    v["next_number"] = json!(format!("{}{next}", s.invoice_prefix));
    Ok(Json(v))
}

pub async fn update_settings(State(st): State<Arc<AppState>>, u: User, Json(b): Json<BillingSettings>) -> ApiResult<Json<Value>> {
    u.need(Perm::BillingManage)?;
    let currency = b.currency.trim().to_ascii_uppercase();
    if currency.len() != 3 || !currency.bytes().all(|c| c.is_ascii_uppercase()) {
        return Err(ApiError::BadRequest("currency is a three-letter ISO code, like USD or EUR".into()));
    }
    let prefix: String = b.invoice_prefix.trim().chars().filter(|c| c.is_ascii_alphanumeric() || "-_/".contains(*c)).take(10).collect();
    if !(0..=365).contains(&b.invoice_terms_days) {
        return Err(ApiError::BadRequest("payment terms must be 0-365 days".into()));
    }
    sqlx::query(
        "UPDATE company_settings SET currency = $1, company_address = $2, invoice_prefix = $3, invoice_terms_days = $4, invoice_footer = $5,
                default_rate = $6, updated_at = now(), updated_by = $7",
    )
    .bind(&currency)
    .bind(b.company_address.trim().chars().take(1000).collect::<String>())
    .bind(prefix)
    .bind(b.invoice_terms_days)
    .bind(b.invoice_footer.trim().chars().take(2000).collect::<String>())
    .bind(money_in(b.default_rate, "rate")?)
    .bind(u.id)
    .execute(&st.db)
    .await?;
    auth::audit(&st.db, Some(u.id), "settings.billing", None, json!({ "currency": currency })).await;
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
pub struct ClientBillingIn {
    /// null: the company currency.
    currency: Option<String>,
    #[serde(default)]
    billing_address: String,
}

pub async fn set_client_billing(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>, Json(b): Json<ClientBillingIn>) -> ApiResult<Json<Value>> {
    u.need(Perm::BillingManage)?;
    super::access::client(&u, id)?;
    let currency = b.currency.map(|c| c.trim().to_ascii_uppercase()).filter(|c| !c.is_empty());
    if let Some(c) = &currency
        && (c.len() != 3 || !c.bytes().all(|x| x.is_ascii_uppercase()))
    {
        return Err(ApiError::BadRequest("currency is a three-letter ISO code".into()));
    }
    // Drafts follow the new currency; finalised invoices keep theirs.
    let n = sqlx::query("UPDATE clients SET currency = $2, billing_address = $3 WHERE id = $1")
        .bind(id)
        .bind(&currency)
        .bind(b.billing_address.trim().chars().take(1000).collect::<String>())
        .execute(&st.db)
        .await?
        .rows_affected();
    if n == 0 {
        return Err(ApiError::NotFound("client"));
    }
    Ok(Json(json!({ "ok": true })))
}

pub async fn get_client_billing(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    u.need(Perm::BillingRead)?;
    super::access::client(&u, id)?;
    let (currency, address, ids): (Option<String>, String, Value) =
        sqlx::query_as("SELECT currency, billing_address, accounting_ids FROM clients WHERE id = $1")
            .bind(id)
            .fetch_optional(&st.db)
            .await?
            .ok_or(ApiError::NotFound("client"))?;
    Ok(Json(json!({ "currency": currency, "billing_address": address, "accounting_ids": ids })))
}

// ---------------------------------------------------------------------------
// Accounting
// ---------------------------------------------------------------------------

pub async fn accounting(State(st): State<Arc<AppState>>, u: User) -> ApiResult<Json<Value>> {
    u.need(Perm::BillingRead)?;
    #[allow(clippy::type_complexity)]
    let rows: Vec<(String, String, bool, bool, Option<String>, Value, Option<DateTime<Utc>>, Option<DateTime<Utc>>, Option<String>)> =
        sqlx::query_as(
            "SELECT provider, client_id, client_secret IS NOT NULL, tenant_id IS NOT NULL AND refresh_token IS NOT NULL, tenant_name, settings,
                    connected_at, last_sync_at, last_error FROM accounting_connections",
        )
        .fetch_all(&st.db)
        .await?;
    let out: Vec<Value> = crate::accounting::PROVIDERS
        .iter()
        .map(|p| {
            let r = rows.iter().find(|r| r.0 == *p);
            json!({
                "provider": p,
                "label": crate::accounting::label(p),
                "redirect_uri": crate::accounting::redirect_uri(&st, p),
                "client_id": r.map(|r| r.1.clone()).unwrap_or_default(),
                "has_secret": r.is_some_and(|r| r.2),
                "connected": r.is_some_and(|r| r.3),
                "tenant_name": r.and_then(|r| r.4.clone()),
                "settings": r.map(|r| r.5.clone()).unwrap_or(json!({})),
                "connected_at": r.and_then(|r| r.6),
                "last_sync_at": r.and_then(|r| r.7),
                "last_error": r.and_then(|r| r.8.clone()),
            })
        })
        .collect();
    Ok(Json(json!(out)))
}

fn provider(p: &str) -> ApiResult<&str> {
    crate::accounting::PROVIDERS.iter().copied().find(|x| *x == p).ok_or(ApiError::NotFound("provider"))
}

#[derive(Deserialize)]
pub struct AppIn {
    client_id: String,
    client_secret: Option<String>,
    #[serde(default)]
    settings: Value,
}

pub async fn save_accounting(State(st): State<Arc<AppState>>, u: User, Path(p): Path<String>, Json(b): Json<AppIn>) -> ApiResult<Json<Value>> {
    u.need(Perm::BillingManage)?;
    let p = provider(&p)?;
    let id = b.client_id.trim();
    if id.is_empty() || id.len() > 200 {
        return Err(ApiError::BadRequest("enter the app's client id".into()));
    }
    let settings = if b.settings.is_object() { b.settings } else { json!({}) };
    crate::accounting::save_app(&st, p, id, b.client_secret.as_deref().map(str::trim).filter(|s| !s.is_empty()), &settings).await?;
    auth::audit(&st.db, Some(u.id), "accounting.app", None, json!({ "provider": p })).await;
    Ok(Json(json!({ "ok": true })))
}

pub async fn connect_accounting(State(st): State<Arc<AppState>>, u: User, Path(p): Path<String>) -> ApiResult<Json<Value>> {
    u.need(Perm::BillingManage)?;
    let p = provider(&p)?;
    let url = crate::accounting::authorize_url(&st, p, u.id).await.map_err(|e| ApiError::BadRequest(format!("{e:#}")))?;
    Ok(Json(json!({ "url": url })))
}

#[derive(Deserialize)]
pub struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    #[serde(rename = "realmId")]
    realm_id: Option<String>,
    error: Option<String>,
}

/// The provider sends the browser back here. The session cookie doesn't come along (it's
/// SameSite=Strict and this is a cross-site redirect), so the one-time state authenticates it.
pub async fn accounting_callback(State(st): State<Arc<AppState>>, Path(p): Path<String>, Query(q): Query<CallbackQuery>) -> Response {
    let Ok(p) = provider(&p) else { return Redirect::to("/settings/billing?accounting_error=unknown%20provider").into_response() };
    let res = match (&q.code, &q.state, &q.error) {
        (_, _, Some(e)) => Err(anyhow::anyhow!("{e}")),
        (Some(code), Some(state), None) => crate::accounting::callback(&st, p, code, state, q.realm_id.as_deref()).await,
        _ => Err(anyhow::anyhow!("missing code")),
    };
    match res {
        Ok(()) => {
            auth::audit(&st.db, None, "accounting.connected", None, json!({ "provider": p })).await;
            Redirect::to(&format!("/settings/billing?connected={p}")).into_response()
        }
        Err(e) => {
            let msg: String = format!("{e:#}").chars().take(200).collect();
            let enc: String = msg.bytes().map(|b| if b.is_ascii_alphanumeric() { (b as char).to_string() } else { format!("%{b:02X}") }).collect();
            Redirect::to(&format!("/settings/billing?accounting_error={enc}")).into_response()
        }
    }
}

pub async fn disconnect_accounting(State(st): State<Arc<AppState>>, u: User) -> ApiResult<Json<Value>> {
    u.need(Perm::BillingManage)?;
    crate::accounting::disconnect(&st).await?;
    auth::audit(&st.db, Some(u.id), "accounting.disconnected", None, json!({})).await;
    Ok(Json(json!({ "ok": true })))
}

pub async fn sync_accounting(State(st): State<Arc<AppState>>, u: User) -> ApiResult<Json<crate::accounting::SyncResult>> {
    u.need(Perm::BillingManage)?;
    Ok(Json(crate::accounting::sync(&st).await?))
}
