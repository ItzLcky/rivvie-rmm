//! Custom fields: admin-defined fields on agents, clients and sites, and their values
//! (migration 0029, docs/design/fields.md; script output → field is in `crate::fields`).
//!
//! Definitions are admin-only. A definition limited to one client is invisible to people who
//! can't see that client, and applies only to that client's agents and sites. Values follow the
//! entity's own scoping: whoever can see the agent, client or site sees its values, and a
//! technician edits them.

use std::collections::HashMap;
use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, Query, State};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sqlx::AssertSqlSafe;
use uuid::Uuid;

use crate::auth::{self, Role, User};
use crate::error::{ApiError, ApiResult};
use crate::fields::{KINDS, coerce, valid_name};
use crate::state::AppState;

/// Definitions per entity kind: a sanity limit, not a design one.
const MAX_FIELDS: i64 = 100;
const MAX_OPTIONS: usize = 50;

fn bad(msg: impl Into<String>) -> ApiError {
    ApiError::BadRequest(msg.into())
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Entity {
    Agent,
    Client,
    Site,
}

impl Entity {
    fn parse(s: &str) -> ApiResult<Entity> {
        match s {
            "agent" => Ok(Entity::Agent),
            "client" => Ok(Entity::Client),
            "site" => Ok(Entity::Site),
            _ => Err(bad("entity must be agent, client or site")),
        }
    }
    fn as_str(self) -> &'static str {
        match self {
            Entity::Agent => "agent",
            Entity::Client => "client",
            Entity::Site => "site",
        }
    }
    /// The `custom_field_values` column holding this entity's id.
    fn column(self) -> &'static str {
        match self {
            Entity::Agent => "agent_id",
            Entity::Client => "client_id",
            Entity::Site => "site_id",
        }
    }
    /// The entity's client, if it exists and `u` may see it.
    async fn client_of(self, st: &AppState, u: &User, id: Uuid) -> ApiResult<Uuid> {
        match self {
            Entity::Agent => super::access::agent(st, u, id).await,
            Entity::Site => super::access::site(st, u, id).await,
            Entity::Client => super::access::client(u, id).map(|()| id),
        }
    }
}

// ---------------------------------------------------------------------------
// Definitions
// ---------------------------------------------------------------------------

#[derive(Serialize, sqlx::FromRow)]
pub struct FieldDef {
    id: Uuid,
    entity: String,
    name: String,
    label: String,
    description: String,
    kind: String,
    options: Vec<String>,
    client_id: Option<Uuid>,
    client_name: Option<String>,
    script_writable: bool,
    position: i32,
    /// Entities with a value for it.
    in_use: i64,
}

const DEF_SELECT: &str = "SELECT f.id, f.entity, f.name, f.label, f.description, f.kind, f.options, f.client_id, c.name AS client_name,
       f.script_writable, f.position,
       (SELECT count(*) FROM custom_field_values v WHERE v.field_id = f.id) AS in_use
  FROM custom_fields f LEFT JOIN clients c ON c.id = f.client_id";

#[derive(Deserialize)]
pub struct DefQuery {
    entity: Option<String>,
}

pub async fn list_defs(State(st): State<Arc<AppState>>, u: User, Query(q): Query<DefQuery>) -> ApiResult<Json<Vec<FieldDef>>> {
    let entity = q.entity.as_deref().filter(|e| !e.is_empty()).map(Entity::parse).transpose()?.map(Entity::as_str);
    Ok(Json(
        sqlx::query_as(AssertSqlSafe(format!(
            "{DEF_SELECT} WHERE ($1::text IS NULL OR f.entity = $1) AND ($2::uuid[] IS NULL OR f.client_id IS NULL OR f.client_id = ANY($2))
              ORDER BY f.entity, f.position, lower(f.label)"
        )))
        .bind(entity)
        .bind(u.scope())
        .fetch_all(&st.db)
        .await?,
    ))
}

async fn get_def(st: &AppState, u: &User, id: Uuid) -> ApiResult<FieldDef> {
    sqlx::query_as(AssertSqlSafe(format!("{DEF_SELECT} WHERE f.id = $1 AND ($2::uuid[] IS NULL OR f.client_id IS NULL OR f.client_id = ANY($2))")))
        .bind(id)
        .bind(u.scope())
        .fetch_optional(&st.db)
        .await?
        .ok_or(ApiError::NotFound("custom field"))
}

fn clean_label(label: &str) -> ApiResult<String> {
    let label = label.trim();
    if label.is_empty() || label.chars().count() > 80 || label.chars().any(char::is_control) {
        return Err(bad("a label is 1-80 characters"));
    }
    Ok(label.to_string())
}

fn clean_description(d: &str) -> ApiResult<String> {
    let d = d.trim();
    if d.chars().count() > 500 {
        return Err(bad("a description is at most 500 characters"));
    }
    Ok(d.to_string())
}

fn clean_options(kind: &str, options: &[String]) -> ApiResult<Vec<String>> {
    if kind != "select" {
        if !options.is_empty() {
            return Err(bad("only select fields have options"));
        }
        return Ok(vec![]);
    }
    let mut out: Vec<String> = Vec::new();
    for o in options {
        let o = o.trim();
        if o.is_empty() || o.chars().count() > 80 || o.chars().any(char::is_control) {
            return Err(bad("each option is 1-80 characters"));
        }
        if out.iter().any(|x| x.eq_ignore_ascii_case(o)) {
            return Err(bad(format!("the option {o} is listed twice")));
        }
        out.push(o.to_string());
    }
    if out.is_empty() || out.len() > MAX_OPTIONS {
        return Err(bad(format!("a select field has 1-{MAX_OPTIONS} options")));
    }
    Ok(out)
}

#[derive(Deserialize)]
pub struct NewDef {
    entity: String,
    name: String,
    label: String,
    #[serde(default)]
    description: String,
    kind: String,
    #[serde(default)]
    options: Vec<String>,
    client_id: Option<Uuid>,
    #[serde(default)]
    script_writable: bool,
    #[serde(default)]
    position: i32,
}

pub async fn create_def(State(st): State<Arc<AppState>>, u: User, Json(b): Json<NewDef>) -> ApiResult<Json<FieldDef>> {
    u.require(Role::Admin)?;
    let entity = Entity::parse(&b.entity)?;
    let name = b.name.trim().to_string();
    if !valid_name(&name) {
        return Err(bad("a name is lowercase letters, digits and underscores, starting with a letter (at most 40)"));
    }
    if !KINDS.contains(&b.kind.as_str()) {
        return Err(bad(format!("type must be one of {}", KINDS.join(", "))));
    }
    let options = clean_options(&b.kind, &b.options)?;
    if b.client_id.is_some() && entity == Entity::Client {
        return Err(bad("a client field can't be limited to a client"));
    }
    if b.script_writable && entity != Entity::Agent {
        return Err(bad("only agent fields can be set by scripts"));
    }
    if let Some(c) = b.client_id {
        super::access::client(&u, c)?;
        let exists: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM clients WHERE id = $1)").bind(c).fetch_one(&st.db).await?;
        if !exists {
            return Err(ApiError::NotFound("client"));
        }
    }
    let have: i64 = sqlx::query_scalar("SELECT count(*) FROM custom_fields WHERE entity = $1").bind(entity.as_str()).fetch_one(&st.db).await?;
    if have >= MAX_FIELDS {
        return Err(bad(format!("at most {MAX_FIELDS} fields per kind of entity")));
    }
    let label = clean_label(&b.label)?;
    let description = clean_description(&b.description)?;
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO custom_fields (id, entity, name, label, description, kind, options, client_id, script_writable, position, created_by)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
    )
    .bind(id)
    .bind(entity.as_str())
    .bind(&name)
    .bind(&label)
    .bind(&description)
    .bind(&b.kind)
    .bind(&options)
    .bind(b.client_id)
    .bind(b.script_writable)
    .bind(b.position.clamp(-1000, 1000))
    .bind(u.id)
    .execute(&st.db)
    .await
    .map_err(|e| match e {
        sqlx::Error::Database(d) if d.is_unique_violation() => ApiError::Conflict(format!("a {} field named {name} already exists", entity.as_str())),
        e => e.into(),
    })?;
    auth::audit(
        &st.db,
        Some(u.id),
        "custom_field.create",
        Some(("custom_field", id)),
        json!({ "entity": entity.as_str(), "name": name, "kind": b.kind, "client_id": b.client_id, "script_writable": b.script_writable }),
    )
    .await;
    Ok(Json(get_def(&st, &u, id).await?))
}

#[derive(Deserialize)]
pub struct EditDef {
    label: Option<String>,
    description: Option<String>,
    options: Option<Vec<String>>,
    script_writable: Option<bool>,
    position: Option<i32>,
}

/// What can change after creation. The name, type, entity and client are fixed: values are
/// stored by type, and scripts and integrations address the field by name.
pub async fn update_def(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>, Json(b): Json<EditDef>) -> ApiResult<Json<FieldDef>> {
    u.require(Role::Admin)?;
    let cur = get_def(&st, &u, id).await?;
    let label = b.label.as_deref().map(clean_label).transpose()?;
    let description = b.description.as_deref().map(clean_description).transpose()?;
    let options = b.options.as_deref().map(|o| clean_options(&cur.kind, o)).transpose()?;
    if b.script_writable == Some(true) && cur.entity != "agent" {
        return Err(bad("only agent fields can be set by scripts"));
    }
    sqlx::query(
        "UPDATE custom_fields SET label = coalesce($2, label), description = coalesce($3, description), options = coalesce($4, options),
                script_writable = coalesce($5, script_writable), position = coalesce($6, position) WHERE id = $1",
    )
    .bind(id)
    .bind(&label)
    .bind(&description)
    .bind(&options)
    .bind(b.script_writable)
    .bind(b.position.map(|p| p.clamp(-1000, 1000)))
    .execute(&st.db)
    .await?;
    auth::audit(
        &st.db,
        Some(u.id),
        "custom_field.update",
        Some(("custom_field", id)),
        json!({ "name": cur.name, "label": label, "options": options, "script_writable": b.script_writable }),
    )
    .await;
    Ok(Json(get_def(&st, &u, id).await?))
}

/// Deleting a field deletes its values too.
pub async fn delete_def(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    u.require(Role::Admin)?;
    let cur = get_def(&st, &u, id).await?;
    sqlx::query("DELETE FROM custom_fields WHERE id = $1").bind(id).execute(&st.db).await?;
    auth::audit(&st.db, Some(u.id), "custom_field.delete", Some(("custom_field", id)), json!({ "name": cur.name, "entity": cur.entity, "values": cur.in_use })).await;
    Ok(Json(json!({ "ok": true })))
}

// ---------------------------------------------------------------------------
// Values
// ---------------------------------------------------------------------------

#[derive(Serialize, sqlx::FromRow)]
pub struct FieldValue {
    field_id: Uuid,
    name: String,
    label: String,
    description: String,
    kind: String,
    options: Vec<String>,
    script_writable: bool,
    client_id: Option<Uuid>,
    value: Option<Value>,
    /// user, api or script.
    source: Option<String>,
    updated_at: Option<DateTime<Utc>>,
    updated_by_name: Option<String>,
}

/// The fields that apply to the entity (global ones and those limited to its client), with its
/// value of each.
async fn load_values(st: &AppState, entity: Entity, id: Uuid, client: Uuid) -> ApiResult<Vec<FieldValue>> {
    Ok(sqlx::query_as(AssertSqlSafe(format!(
        "SELECT f.id AS field_id, f.name, f.label, f.description, f.kind, f.options, f.script_writable, f.client_id,
                v.value, v.source, v.updated_at, u.name AS updated_by_name
           FROM custom_fields f
           LEFT JOIN custom_field_values v ON v.field_id = f.id AND v.{col} = $1
           LEFT JOIN users u ON u.id = v.updated_by
          WHERE f.entity = $2 AND (f.client_id IS NULL OR f.client_id = $3)
          ORDER BY f.position, lower(f.label)",
        col = entity.column()
    )))
    .bind(id)
    .bind(entity.as_str())
    .bind(client)
    .fetch_all(&st.db)
    .await?)
}

async fn values_of(st: &AppState, u: &User, entity: Entity, id: Uuid) -> ApiResult<Json<Vec<FieldValue>>> {
    let client = entity.client_of(st, u, id).await?;
    Ok(Json(load_values(st, entity, id, client).await?))
}

pub async fn agent_values(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<Vec<FieldValue>>> {
    values_of(&st, &u, Entity::Agent, id).await
}
pub async fn client_values(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<Vec<FieldValue>>> {
    values_of(&st, &u, Entity::Client, id).await
}
pub async fn site_values(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<Vec<FieldValue>>> {
    values_of(&st, &u, Entity::Site, id).await
}

#[derive(Deserialize)]
pub struct SetValues {
    /// Field name → value; `null` (or an empty string) clears. Fields not named are left alone.
    values: Map<String, Value>,
}

async fn set_values(st: &AppState, u: &User, entity: Entity, id: Uuid, b: SetValues) -> ApiResult<Json<Vec<FieldValue>>> {
    u.require(Role::Technician)?;
    let client = entity.client_of(st, u, id).await?;
    if b.values.is_empty() || b.values.len() > MAX_FIELDS as usize {
        return Err(bad("values must name 1-100 fields"));
    }
    let current = load_values(st, entity, id, client).await?;
    let by_name: HashMap<&str, &FieldValue> = current.iter().map(|f| (f.name.as_str(), f)).collect();
    // Check every value before storing any.
    let mut changes: Vec<(&FieldValue, Option<Value>)> = Vec::new();
    for (name, input) in &b.values {
        let f = by_name.get(name.as_str()).ok_or_else(|| bad(format!("this {} has no field named {name}", entity.as_str())))?;
        let new = coerce(&f.kind, &f.options, input).map_err(|e| bad(format!("{name}: {e}")))?;
        if new != f.value {
            changes.push((f, new));
        }
    }
    if changes.is_empty() {
        return Ok(Json(current));
    }
    let source = if u.api_key.is_some() { "api" } else { "user" };
    let col = entity.column();
    let upsert = format!(
        "INSERT INTO custom_field_values (field_id, {col}, value, source, updated_by, job_id, updated_at) VALUES ($1, $2, $3, $4, $5, NULL, now())
         ON CONFLICT ({col}, field_id) WHERE {col} IS NOT NULL
         DO UPDATE SET value = $3, source = $4, updated_by = $5, job_id = NULL, updated_at = now()"
    );
    let delete = format!("DELETE FROM custom_field_values WHERE field_id = $1 AND {col} = $2");
    let mut tx = st.db.begin().await?;
    let mut audit = Map::new();
    for (f, new) in &changes {
        match new {
            Some(v) => {
                sqlx::query(AssertSqlSafe(upsert.clone())).bind(f.field_id).bind(id).bind(v).bind(source).bind(u.id).execute(&mut *tx).await?;
            }
            None => {
                sqlx::query(AssertSqlSafe(delete.clone())).bind(f.field_id).bind(id).execute(&mut *tx).await?;
            }
        }
        audit.insert(f.name.clone(), json!({ "from": f.value, "to": new }));
    }
    tx.commit().await?;
    auth::audit(&st.db, Some(u.id), &format!("{}.fields", entity.as_str()), Some((entity.as_str(), id)), Value::Object(audit)).await;
    Ok(Json(load_values(st, entity, id, client).await?))
}

pub async fn set_agent_values(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>, Json(b): Json<SetValues>) -> ApiResult<Json<Vec<FieldValue>>> {
    set_values(&st, &u, Entity::Agent, id, b).await
}
pub async fn set_client_values(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>, Json(b): Json<SetValues>) -> ApiResult<Json<Vec<FieldValue>>> {
    set_values(&st, &u, Entity::Client, id, b).await
}
pub async fn set_site_values(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>, Json(b): Json<SetValues>) -> ApiResult<Json<Vec<FieldValue>>> {
    set_values(&st, &u, Entity::Site, id, b).await
}

// ---------------------------------------------------------------------------
// The agents list filter
// ---------------------------------------------------------------------------

/// A filter on one agent field, ready to bind: `field` is the field's id, and the value is
/// matched exactly (`exact`, JSON) or, for text fields, as a case-insensitive substring
/// (`contains`). Neither: any agent that has a value for it.
pub struct Filter {
    pub field: Option<Uuid>,
    pub exact: Option<Value>,
    pub contains: Option<String>,
}

pub async fn filter(st: &AppState, u: &User, field: Option<Uuid>, value: Option<&str>) -> ApiResult<Filter> {
    let Some(field) = field else { return Ok(Filter { field: None, exact: None, contains: None }) };
    let def = get_def(st, u, field).await?;
    if def.entity != "agent" {
        return Err(bad("agents can only be filtered on agent fields"));
    }
    let Some(value) = value.map(str::trim).filter(|v| !v.is_empty()) else {
        return Ok(Filter { field: Some(field), exact: None, contains: None });
    };
    if def.kind == "text" {
        return Ok(Filter { field: Some(field), exact: None, contains: Some(value.to_string()) });
    }
    let exact = coerce(&def.kind, &def.options, &Value::String(value.to_string())).map_err(|e| bad(format!("{}: {e}", def.name)))?;
    Ok(Filter { field: Some(field), exact, contains: None })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn options_belong_to_selects() {
        assert!(clean_options("text", &["a".into()]).is_err());
        assert_eq!(clean_options("text", &[]).unwrap(), Vec::<String>::new());
        assert!(clean_options("select", &[]).is_err());
        assert_eq!(clean_options("select", &[" Gold ".into(), "Silver".into()]).unwrap(), vec!["Gold", "Silver"]);
        assert!(clean_options("select", &["Gold".into(), "gold".into()]).is_err());
        assert!(clean_options("select", &["".into()]).is_err());
        assert!(clean_options("select", &(0..51).map(|i| format!("o{i}")).collect::<Vec<_>>()).is_err());
    }

    #[test]
    fn labels() {
        assert_eq!(clean_label(" Warranty end ").unwrap(), "Warranty end");
        assert!(clean_label("").is_err());
        assert!(clean_label(&"x".repeat(81)).is_err());
        assert!(clean_description(&"x".repeat(501)).is_err());
    }

    #[test]
    fn entities() {
        assert!(Entity::parse("agent").is_ok() && Entity::parse("site").is_ok() && Entity::parse("client").is_ok());
        assert!(Entity::parse("ticket").is_err());
    }
}
