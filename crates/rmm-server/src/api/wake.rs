//! `POST /agents/{id}/wake` and `POST /agents/wake`: Wake-on-LAN through another agent of
//! the site ([`crate::wol`]).

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::auth::{self, Role, User};
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;
use crate::wol::{Outcome, Woken};

/// The most devices one bulk call wakes.
const BULK_MAX: usize = 5000;

fn summary(results: &[Woken]) -> Value {
    let count = |o: Outcome| results.iter().filter(|r| r.outcome == o).count();
    json!({
        "results": results,
        "sent": count(Outcome::Sent),
        "no_mac": count(Outcome::NoMac),
        "no_sender": count(Outcome::NoSender),
        "online": count(Outcome::Online),
    })
}

/// Wake one device. 200 with its outcome, whatever it is (`sent`, `no_mac`, `no_sender`, `online`).
pub async fn wake_one(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    u.require(Role::Technician)?;
    super::access::agent(&st, &u, id).await?;
    let results = crate::wol::wake(&st, &[id], Some(u.id)).await?;
    let outcome = results.first().map(|r| r.outcome);
    auth::audit(&st.db, Some(u.id), "agent.wake", Some(("agent", id)), json!({ "outcome": outcome })).await;
    let mut out = summary(&results);
    out["outcome"] = json!(outcome);
    Ok(Json(out))
}

#[derive(Deserialize)]
pub struct WakeMany {
    agent_ids: Vec<Uuid>,
}

/// Wake many devices: every one must be visible to the user, or nothing happens (404).
pub async fn wake_many(State(st): State<Arc<AppState>>, u: User, Json(b): Json<WakeMany>) -> ApiResult<Json<Value>> {
    u.require(Role::Technician)?;
    let mut ids = b.agent_ids;
    ids.sort();
    ids.dedup();
    if ids.is_empty() || ids.len() > BULK_MAX {
        return Err(ApiError::BadRequest(format!("agent_ids must contain 1-{BULK_MAX} agents")));
    }
    let visible: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM agents a JOIN sites s ON s.id = a.site_id WHERE a.id = ANY($1) AND ($2::uuid[] IS NULL OR s.client_id = ANY($2))",
    )
    .bind(&ids)
    .bind(u.scope())
    .fetch_one(&st.db)
    .await?;
    if visible as usize != ids.len() {
        return Err(ApiError::NotFound("agent"));
    }
    let results = crate::wol::wake(&st, &ids, Some(u.id)).await?;
    let out = summary(&results);
    auth::audit(
        &st.db,
        Some(u.id),
        "agent.wake",
        None,
        json!({ "agents": ids.len(), "sent": out["sent"], "no_mac": out["no_mac"], "no_sender": out["no_sender"], "online": out["online"] }),
    )
    .await;
    Ok(Json(out))
}
