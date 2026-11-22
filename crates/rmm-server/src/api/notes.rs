//! Agent notes (migration 0029, docs/design/fields.md): timestamped and authored, editable by
//! their author (and admins), with at most one pinned note per agent that the agent's header shows.
//!
//! Anyone who can work on agents (technician) writes notes, and anyone who can see the agent
//! reads them. The text is plain: the dashboard shows it as text, never as markup.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::AssertSqlSafe;
use uuid::Uuid;

use crate::auth::{self, Role, User};
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

pub const BODY_MAX: usize = 10_000;
/// Notes per agent, so a runaway script can't fill the table.
const PER_AGENT_MAX: i64 = 500;

fn bad(msg: impl Into<String>) -> ApiError {
    ApiError::BadRequest(msg.into())
}

#[derive(Serialize, sqlx::FromRow, Clone)]
pub struct Note {
    id: Uuid,
    agent_id: Uuid,
    body: String,
    author_id: Option<Uuid>,
    author_name: String,
    pinned: bool,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    /// The signed-in user may change the text or delete it (its author, or an admin).
    #[sqlx(default)]
    can_edit: bool,
}

const COLS: &str = "n.id, n.agent_id, n.body, n.author_id, n.author_name, n.pinned, n.created_at, n.updated_at,
       (coalesce(n.author_id = $2, false) OR $3) AS can_edit";

/// The agent's pinned note, for its header.
pub async fn pinned(st: &AppState, u: &User, agent_id: Uuid) -> ApiResult<Option<Note>> {
    Ok(sqlx::query_as(AssertSqlSafe(format!("SELECT {COLS} FROM agent_notes n WHERE n.agent_id = $1 AND n.pinned")))
        .bind(agent_id)
        .bind(u.id)
        .bind(u.role() == Role::Admin)
        .fetch_optional(&st.db)
        .await?)
}

pub async fn list(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<Vec<Note>>> {
    super::access::agent(&st, &u, id).await?;
    Ok(Json(
        sqlx::query_as(AssertSqlSafe(format!("SELECT {COLS} FROM agent_notes n WHERE n.agent_id = $1 ORDER BY n.pinned DESC, n.created_at DESC")))
            .bind(id)
            .bind(u.id)
            .bind(u.role() == Role::Admin)
            .fetch_all(&st.db)
            .await?,
    ))
}

fn clean_body(body: &str) -> ApiResult<String> {
    let body = body.trim();
    if body.is_empty() {
        return Err(bad("a note can't be empty"));
    }
    if body.chars().count() > BODY_MAX {
        return Err(bad(format!("a note is at most {BODY_MAX} characters")));
    }
    if body.chars().any(|c| c.is_control() && c != '\n' && c != '\t' && c != '\r') {
        return Err(bad("a note can't contain control characters"));
    }
    Ok(body.to_string())
}

#[derive(Deserialize)]
pub struct NewNote {
    body: String,
    #[serde(default)]
    pinned: bool,
}

pub async fn create(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>, Json(b): Json<NewNote>) -> ApiResult<Json<Note>> {
    u.require(Role::Technician)?;
    super::access::agent(&st, &u, id).await?;
    let body = clean_body(&b.body)?;
    let have: i64 = sqlx::query_scalar("SELECT count(*) FROM agent_notes WHERE agent_id = $1").bind(id).fetch_one(&st.db).await?;
    if have >= PER_AGENT_MAX {
        return Err(bad(format!("an agent has at most {PER_AGENT_MAX} notes; delete some first")));
    }
    let note_id = Uuid::new_v4();
    let mut tx = st.db.begin().await?;
    if b.pinned {
        sqlx::query("UPDATE agent_notes SET pinned = false WHERE agent_id = $1 AND pinned").bind(id).execute(&mut *tx).await?;
    }
    sqlx::query("INSERT INTO agent_notes (id, agent_id, body, author_id, author_name, pinned) VALUES ($1, $2, $3, $4, $5, $6)")
        .bind(note_id)
        .bind(id)
        .bind(&body)
        .bind(u.id)
        .bind(&u.name)
        .bind(b.pinned)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    auth::audit(&st.db, Some(u.id), "agent.note_create", Some(("agent", id)), json!({ "note_id": note_id, "pinned": b.pinned })).await;
    one(&st, &u, id, note_id).await.map(Json)
}

async fn one(st: &AppState, u: &User, agent_id: Uuid, note_id: Uuid) -> ApiResult<Note> {
    sqlx::query_as(AssertSqlSafe(format!("SELECT {COLS} FROM agent_notes n WHERE n.id = $1 AND n.agent_id = $4")))
        .bind(note_id)
        .bind(u.id)
        .bind(u.role() == Role::Admin)
        .bind(agent_id)
        .fetch_optional(&st.db)
        .await?
        .ok_or(ApiError::NotFound("note"))
}

#[derive(Deserialize)]
pub struct EditNote {
    body: Option<String>,
    pinned: Option<bool>,
}

/// Changing the text is for the author and admins; pinning and unpinning is for any technician
/// (the pinned note is the agent's header, not the author's).
pub async fn update(State(st): State<Arc<AppState>>, u: User, Path((id, note_id)): Path<(Uuid, Uuid)>, Json(b): Json<EditNote>) -> ApiResult<Json<Note>> {
    u.require(Role::Technician)?;
    super::access::agent(&st, &u, id).await?;
    let cur = one(&st, &u, id, note_id).await?;
    let body = match b.body.as_deref() {
        Some(t) => {
            if !cur.can_edit {
                return Err(ApiError::Denied("only the author or an admin can edit a note".into()));
            }
            Some(clean_body(t)?)
        }
        None => None,
    };
    let mut tx = st.db.begin().await?;
    if b.pinned == Some(true) {
        sqlx::query("UPDATE agent_notes SET pinned = false WHERE agent_id = $1 AND pinned AND id <> $2").bind(id).bind(note_id).execute(&mut *tx).await?;
    }
    sqlx::query(
        "UPDATE agent_notes SET body = coalesce($2, body), pinned = coalesce($3, pinned),
                updated_at = CASE WHEN $2::text IS NULL THEN updated_at ELSE now() END
          WHERE id = $1",
    )
    .bind(note_id)
    .bind(&body)
    .bind(b.pinned)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    auth::audit(
        &st.db,
        Some(u.id),
        "agent.note_update",
        Some(("agent", id)),
        json!({ "note_id": note_id, "edited": body.is_some(), "pinned": b.pinned }),
    )
    .await;
    one(&st, &u, id, note_id).await.map(Json)
}

pub async fn remove(State(st): State<Arc<AppState>>, u: User, Path((id, note_id)): Path<(Uuid, Uuid)>) -> ApiResult<Json<Value>> {
    u.require(Role::Technician)?;
    super::access::agent(&st, &u, id).await?;
    let cur = one(&st, &u, id, note_id).await?;
    if !cur.can_edit {
        return Err(ApiError::Denied("only the author or an admin can delete a note".into()));
    }
    sqlx::query("DELETE FROM agent_notes WHERE id = $1").bind(note_id).execute(&st.db).await?;
    auth::audit(&st.db, Some(u.id), "agent.note_delete", Some(("agent", id)), json!({ "note_id": note_id })).await;
    Ok(Json(json!({ "ok": true })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bodies() {
        assert_eq!(clean_body("  hello\nworld \n").unwrap(), "hello\nworld");
        assert!(clean_body("   ").is_err());
        assert!(clean_body(&"x".repeat(BODY_MAX + 1)).is_err());
        assert!(clean_body(&"x".repeat(BODY_MAX)).is_ok());
        assert!(clean_body("a\u{0}b").is_err());
        assert!(clean_body("tab\tand\r\nlines").is_ok());
    }
}
