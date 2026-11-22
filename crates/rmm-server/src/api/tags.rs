//! Tags: MSP-wide labels on agents (migration 0029, docs/design/fields.md).
//!
//! Anyone who can work on agents (technician) creates tags and puts them on agents they can
//! see; renaming, recolouring and deleting a tag is for admins, because the tag is shared by
//! everyone. Tag names are visible to every signed-in user, whatever clients they can see (a
//! tag is not the place for something confidential); what is scoped is which agents carry it.

use std::collections::HashSet;
use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::auth::{self, Role, User};
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

/// The palette the dashboard draws tags in.
pub const COLORS: &[&str] = &["slate", "red", "orange", "amber", "green", "teal", "blue", "violet", "pink"];
/// Agents in one bulk tagging request.
const BULK_MAX: usize = 5000;

fn bad(msg: impl Into<String>) -> ApiError {
    ApiError::BadRequest(msg.into())
}

#[derive(Serialize, sqlx::FromRow)]
pub struct TagRow {
    id: Uuid,
    name: String,
    color: String,
    /// Agents carrying it that the user can see.
    agents: i64,
    created_at: DateTime<Utc>,
}

pub async fn list(State(st): State<Arc<AppState>>, u: User) -> ApiResult<Json<Vec<TagRow>>> {
    Ok(Json(
        sqlx::query_as(
            "SELECT t.id, t.name, t.color, t.created_at,
                    count(a.id) AS agents
               FROM tags t
               LEFT JOIN agent_tags atg ON atg.tag_id = t.id
               LEFT JOIN agents a ON a.id = atg.agent_id AND ($1::uuid[] IS NULL OR EXISTS
                    (SELECT 1 FROM sites s WHERE s.id = a.site_id AND s.client_id = ANY($1)))
              GROUP BY t.id ORDER BY lower(t.name)",
        )
        .bind(u.scope())
        .fetch_all(&st.db)
        .await?,
    ))
}

#[derive(Deserialize)]
pub struct NewTag {
    name: String,
    color: Option<String>,
}

fn clean_name(name: &str) -> ApiResult<String> {
    let name = name.trim();
    if name.is_empty() || name.chars().count() > 40 || name.chars().any(char::is_control) {
        return Err(bad("a tag name is 1-40 characters"));
    }
    Ok(name.to_string())
}

fn clean_color(color: Option<&str>) -> ApiResult<String> {
    let color = color.unwrap_or("slate");
    if !COLORS.contains(&color) {
        return Err(bad(format!("color must be one of {}", COLORS.join(", "))));
    }
    Ok(color.to_string())
}

fn taken(e: sqlx::Error) -> ApiError {
    match e {
        sqlx::Error::Database(d) if d.is_unique_violation() => ApiError::Conflict("a tag with that name already exists".into()),
        e => e.into(),
    }
}

pub async fn create(State(st): State<Arc<AppState>>, u: User, Json(b): Json<NewTag>) -> ApiResult<Json<TagRow>> {
    u.require(Role::Technician)?;
    let name = clean_name(&b.name)?;
    let color = clean_color(b.color.as_deref())?;
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO tags (id, name, color, created_by) VALUES ($1, $2, $3, $4)")
        .bind(id)
        .bind(&name)
        .bind(&color)
        .bind(u.id)
        .execute(&st.db)
        .await
        .map_err(taken)?;
    auth::audit(&st.db, Some(u.id), "tag.create", Some(("tag", id)), json!({ "name": name, "color": color })).await;
    Ok(Json(TagRow { id, name, color, agents: 0, created_at: Utc::now() }))
}

#[derive(Deserialize)]
pub struct EditTag {
    name: Option<String>,
    color: Option<String>,
}

pub async fn update(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>, Json(b): Json<EditTag>) -> ApiResult<Json<Value>> {
    u.require(Role::Admin)?;
    let name = b.name.as_deref().map(clean_name).transpose()?;
    let color = b.color.as_deref().map(|c| clean_color(Some(c))).transpose()?;
    let n = sqlx::query("UPDATE tags SET name = coalesce($2, name), color = coalesce($3, color) WHERE id = $1")
        .bind(id)
        .bind(&name)
        .bind(&color)
        .execute(&st.db)
        .await
        .map_err(taken)?
        .rows_affected();
    if n == 0 {
        return Err(ApiError::NotFound("tag"));
    }
    auth::audit(&st.db, Some(u.id), "tag.update", Some(("tag", id)), json!({ "name": name, "color": color })).await;
    Ok(Json(json!({ "ok": true })))
}

pub async fn remove(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    u.require(Role::Admin)?;
    let name: Option<String> = sqlx::query_scalar("DELETE FROM tags WHERE id = $1 RETURNING name").bind(id).fetch_optional(&st.db).await?;
    let name = name.ok_or(ApiError::NotFound("tag"))?;
    auth::audit(&st.db, Some(u.id), "tag.delete", Some(("tag", id)), json!({ "name": name })).await;
    Ok(Json(json!({ "ok": true })))
}

/// The tags among `ids` that exist; 404 if one doesn't.
async fn known(st: &AppState, ids: &[Uuid]) -> ApiResult<Vec<(Uuid, String)>> {
    let rows: Vec<(Uuid, String)> = sqlx::query_as("SELECT id, name FROM tags WHERE id = ANY($1)").bind(ids).fetch_all(&st.db).await?;
    if rows.len() != ids.len() {
        return Err(ApiError::NotFound("tag"));
    }
    Ok(rows)
}

fn unique(ids: &[Uuid]) -> Vec<Uuid> {
    let mut seen = HashSet::new();
    ids.iter().copied().filter(|i| seen.insert(*i)).collect()
}

#[derive(Deserialize)]
pub struct SetTags {
    tag_ids: Vec<Uuid>,
}

/// Replaces the agent's tags with exactly these.
pub async fn set_for_agent(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>, Json(b): Json<SetTags>) -> ApiResult<Json<Value>> {
    u.require(Role::Technician)?;
    super::access::agent(&st, &u, id).await?;
    let want = unique(&b.tag_ids);
    if want.len() > 50 {
        return Err(bad("at most 50 tags on an agent"));
    }
    let names = known(&st, &want).await?;
    let mut tx = st.db.begin().await?;
    let removed: Vec<String> = sqlx::query_scalar(
        "DELETE FROM agent_tags atg USING tags t WHERE atg.agent_id = $1 AND t.id = atg.tag_id AND NOT (atg.tag_id = ANY($2)) RETURNING t.name",
    )
    .bind(id)
    .bind(&want)
    .fetch_all(&mut *tx)
    .await?;
    let added: Vec<Uuid> = sqlx::query_scalar(
        "INSERT INTO agent_tags (agent_id, tag_id) SELECT $1, t FROM unnest($2::uuid[]) t ON CONFLICT DO NOTHING RETURNING tag_id",
    )
    .bind(id)
    .bind(&want)
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    if !removed.is_empty() || !added.is_empty() {
        let added: Vec<&str> = names.iter().filter(|(i, _)| added.contains(i)).map(|(_, n)| n.as_str()).collect();
        auth::audit(&st.db, Some(u.id), "agent.tags", Some(("agent", id)), json!({ "added": added, "removed": removed })).await;
    }
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
pub struct BulkTags {
    agent_ids: Vec<Uuid>,
    #[serde(default)]
    add: Vec<Uuid>,
    #[serde(default)]
    remove: Vec<Uuid>,
}

/// Adds and removes tags on many agents at once (the agents list's bulk action).
pub async fn bulk(State(st): State<Arc<AppState>>, u: User, Json(b): Json<BulkTags>) -> ApiResult<Json<Value>> {
    u.require(Role::Technician)?;
    let agents = unique(&b.agent_ids);
    if agents.is_empty() || agents.len() > BULK_MAX {
        return Err(bad(format!("agent_ids must contain 1-{BULK_MAX} agents")));
    }
    let add = unique(&b.add);
    let remove = unique(&b.remove);
    if add.is_empty() && remove.is_empty() {
        return Err(bad("nothing to add or remove"));
    }
    if add.iter().any(|t| remove.contains(t)) {
        return Err(bad("a tag can't be both added and removed"));
    }
    let visible: i64 = sqlx::query_scalar(
        "SELECT count(DISTINCT a.id) FROM agents a JOIN sites s ON s.id = a.site_id WHERE a.id = ANY($1) AND ($2::uuid[] IS NULL OR s.client_id = ANY($2))",
    )
    .bind(&agents)
    .bind(u.scope())
    .fetch_one(&st.db)
    .await?;
    if visible as usize != agents.len() {
        return Err(ApiError::NotFound("agent"));
    }
    let all: Vec<Uuid> = add.iter().chain(&remove).copied().collect();
    known(&st, &all).await?;
    let mut tx = st.db.begin().await?;
    let added = sqlx::query(
        "INSERT INTO agent_tags (agent_id, tag_id) SELECT a, t FROM unnest($1::uuid[]) a, unnest($2::uuid[]) t ON CONFLICT DO NOTHING",
    )
    .bind(&agents)
    .bind(&add)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    let removed = sqlx::query("DELETE FROM agent_tags WHERE agent_id = ANY($1) AND tag_id = ANY($2)")
        .bind(&agents)
        .bind(&remove)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    tx.commit().await?;
    auth::audit(
        &st.db,
        Some(u.id),
        "agent.tags_bulk",
        None,
        json!({ "agents": agents.len(), "add": add, "remove": remove, "added": added, "removed": removed }),
    )
    .await;
    Ok(Json(json!({ "agents": agents.len(), "added": added, "removed": removed })))
}

/// The tags of the agents filtered on, as `(tag ids)`; `Err` for an id that isn't one.
pub fn parse_filter(list: Option<&str>) -> ApiResult<Option<Vec<Uuid>>> {
    let Some(list) = list.filter(|l| !l.is_empty()) else { return Ok(None) };
    let ids = list.split(',').map(|s| s.trim().parse::<Uuid>().map_err(|_| bad("tag must be comma-separated tag ids"))).collect::<ApiResult<Vec<_>>>()?;
    Ok(Some(unique(&ids)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_and_colors() {
        assert_eq!(clean_name("  VIP ").unwrap(), "VIP");
        assert!(clean_name("").is_err());
        assert!(clean_name("   ").is_err());
        assert!(clean_name(&"x".repeat(41)).is_err());
        assert!(clean_name("a\nb").is_err());
        assert_eq!(clean_color(None).unwrap(), "slate");
        assert_eq!(clean_color(Some("teal")).unwrap(), "teal");
        assert!(clean_color(Some("#ff0000")).is_err());
    }

    #[test]
    fn filter_lists() {
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        assert_eq!(parse_filter(None).unwrap(), None);
        assert_eq!(parse_filter(Some("")).unwrap(), None);
        assert_eq!(parse_filter(Some(&format!("{a},{b},{a}"))).unwrap(), Some(vec![a, b]));
        assert!(parse_filter(Some("nope")).is_err());
    }
}
