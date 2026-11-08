use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::auth::{self, Role, User};
use crate::error::{ApiError, ApiResult};
use crate::state::{AppState, Company};

/// What the login page and sidebar need; served without a session.
pub async fn public(State(st): State<Arc<AppState>>) -> Json<serde_json::Value> {
    Json(json!({ "company_name": st.company().company_name }))
}

#[derive(Serialize)]
pub struct SettingsView {
    company_name: String,
    session_idle_hours: Option<i32>,
    /// RMM_SESSION_IDLE_HOURS, used when `session_idle_hours` is null.
    session_idle_hours_default: u32,
    require_2fa_all: bool,
    auto_update_agents: bool,
}

fn view(st: &AppState) -> SettingsView {
    let c = st.company();
    SettingsView {
        company_name: c.company_name,
        session_idle_hours: c.session_idle_hours,
        session_idle_hours_default: st.cfg.session_idle_hours,
        require_2fa_all: c.require_2fa_all,
        auto_update_agents: c.auto_update_agents,
    }
}

pub async fn get(State(st): State<Arc<AppState>>, u: User) -> ApiResult<Json<SettingsView>> {
    u.require(Role::Admin)?;
    Ok(Json(view(&st)))
}

#[derive(Deserialize)]
pub struct Update {
    company_name: String,
    session_idle_hours: Option<i32>,
    /// Omitted = unchanged.
    require_2fa_all: Option<bool>,
    /// Omitted = unchanged.
    auto_update_agents: Option<bool>,
}

pub async fn update(State(st): State<Arc<AppState>>, u: User, Json(b): Json<Update>) -> ApiResult<Json<SettingsView>> {
    u.require(Role::Admin)?;
    let name = b.company_name.trim();
    if name.chars().count() > 100 {
        return Err(ApiError::BadRequest("company name must be at most 100 characters".into()));
    }
    if let Some(h) = b.session_idle_hours
        && !(1..=168).contains(&h)
    {
        return Err(ApiError::BadRequest("idle timeout must be between 1 and 168 hours".into()));
    }
    let new: Company = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "UPDATE company_settings
            SET company_name = $1, session_idle_hours = $2, require_2fa_all = COALESCE($4, require_2fa_all),
                auto_update_agents = COALESCE($5, auto_update_agents), updated_at = now(), updated_by = $3
         RETURNING {}",
        Company::COLUMNS
    )))
    .bind(name)
    .bind(b.session_idle_hours)
    .bind(u.id)
    .bind(b.require_2fa_all)
    .bind(b.auto_update_agents)
    .fetch_one(&st.db)
    .await?;
    *st.company.write().unwrap_or_else(|e| e.into_inner()) = new.clone();
    auth::audit(
        &st.db,
        Some(u.id),
        "settings.update",
        None,
        json!({
            "company_name": new.company_name,
            "session_idle_hours": new.session_idle_hours,
            "require_2fa_all": new.require_2fa_all,
            "auto_update_agents": new.auto_update_agents,
        }),
    )
    .await;
    Ok(Json(view(&st)))
}
