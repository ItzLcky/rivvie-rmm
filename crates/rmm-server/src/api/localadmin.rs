//! The managed local admin account of a device: its state and a manual rotation. Not in the
//! public API. See [`crate::localadmin`] and docs/design/local-admin.md.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::auth::{Perm, Role, User};
use crate::error::ApiResult;
use crate::state::AppState;

pub async fn for_agent(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    super::access::agent(&st, &u, id).await?;
    let mut v = crate::localadmin::view(&st, id).await?;
    // The vault item only for people who may open the vault.
    if !super::vault::can_read(&u)
        && let Some(s) = v.get_mut("state").and_then(Value::as_object_mut)
    {
        s.insert("vault_item_id".into(), Value::Null);
    }
    Ok(Json(v))
}

/// Rotates now (technician with `vault.manage`).
pub async fn rotate(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    u.require(Role::Technician)?;
    u.need(Perm::VaultManage)?;
    super::access::agent(&st, &u, id).await?;
    crate::localadmin::rotate_now(&st, id, u.id).await?;
    Ok(Json(json!({ "ok": true })))
}
