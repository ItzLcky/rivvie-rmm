use std::sync::Arc;

use axum::Router;
use axum::routing::{delete, get, post};

use crate::state::AppState;

pub mod access;
mod agents;
mod alerts;
mod channels;
mod auth;
mod clients;
mod downloads;
mod jobs;
mod packages;
mod schedules;
mod search;
mod scripts;
mod services;
mod settings;
mod totp;
pub(crate) mod users;

pub use jobs::{FAILED as JOB_FAILED, deliver as deliver_job};
pub use totp::clear as clear_totp;
pub use users::create_user as create_user_cli;

pub fn agent_platforms() -> impl Iterator<Item = &'static str> {
    downloads::PLATFORMS.iter().map(|p| p.id)
}

pub fn agent_binary_exists(st: &AppState, id: &str) -> bool {
    downloads::platform_path(st, id).is_some()
}

pub fn agent_binary_path(st: &AppState, id: &str) -> Option<std::path::PathBuf> {
    downloads::platform_path(st, id)
}

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/auth/login", post(auth::login))
        .route("/auth/logout", post(auth::logout))
        .route("/auth/me", get(auth::me))
        .route("/auth/preferences", axum::routing::put(auth::update_preferences))
        .route("/events", get(crate::events::handler))
        .route("/search", get(search::search))
        .route("/auth/password", post(auth::change_password))
        .route("/auth/sessions", get(auth::my_sessions).delete(auth::revoke_other_sessions))
        .route("/auth/sessions/{id}", delete(auth::revoke_my_session))
        .route("/auth/totp", get(totp::status))
        .route("/auth/totp/setup", post(totp::setup))
        .route("/auth/totp/enable", post(totp::enable))
        .route("/auth/totp/disable", post(totp::disable))
        .route("/auth/totp/recovery-codes", post(totp::regenerate_recovery))
        .route("/dashboard", get(agents::dashboard))
        .route("/clients", get(clients::list).post(clients::create))
        .route("/clients/{id}", get(clients::get).put(clients::rename).delete(clients::remove))
        .route("/clients/{id}/sites", post(clients::create_site))
        .route("/sites/{id}", axum::routing::put(clients::rename_site).delete(clients::remove_site))
        .route("/sites/{id}/enrollment-tokens", get(clients::list_tokens).post(clients::create_token))
        .route("/enrollment-tokens/{id}", delete(clients::revoke_token))
        .route("/agent-downloads", get(downloads::list))
        .route("/agent-downloads/{id}", get(downloads::download))
        .route("/agent-packages/{platform}/{file}", get(packages::download))
        .route("/agents", get(agents::list))
        .route("/agents/{id}", get(agents::get).delete(agents::remove))
        .route("/agents/{id}/metrics", get(agents::metrics))
        .route("/agents/{id}/activity", get(agents::activity))
        .route("/agents/{id}/inventory/refresh", post(agents::refresh_inventory))
        .route("/agents/{id}/update", post(agents::update))
        .route("/agent-updates", get(agents::releases))
        .route("/agent-updates/rollout", post(agents::rollout))
        .route("/agents/{id}/jobs", get(jobs::list_for_agent))
        .route("/agents/{id}/shell", get(crate::shell_ws::handler))
        .route("/jobs", get(jobs::list_recent).post(jobs::create))
        .route("/jobs/{id}", get(jobs::get))
        .route("/scripts", get(scripts::list).post(scripts::create))
        .route("/scripts/{id}", get(scripts::get).put(scripts::update).delete(scripts::remove))
        .route("/users", get(users::list).post(users::create))
        .route("/users/{id}", delete(users::disable))
        .route("/users/{id}/enable", post(users::enable))
        .route("/users/{id}/access", axum::routing::put(users::update_access))
        .route("/users/{id}/password", post(users::reset_password))
        .route("/users/{id}/totp", delete(users::reset_totp))
        .route("/users/{id}/sessions", get(users::sessions).delete(users::revoke_sessions))
        .route("/users/{id}/sessions/{sid}", delete(users::revoke_session))
        .route("/audit", get(users::audit_log))
        .route("/settings", get(settings::get).put(settings::update))
        .route("/settings/public", get(settings::public))
        .route("/settings/smtp", get(channels::get_smtp).put(channels::update_smtp))
        .route("/notification-channels", get(channels::list).post(channels::create))
        .route("/notification-channels/{id}", axum::routing::put(channels::update).delete(channels::remove))
        .route("/notification-channels/{id}/test", post(channels::test))
        .route("/notifications", get(channels::deliveries))
        .route("/alerts", get(alerts::list))
        .route("/alerts/summary", get(alerts::summary_handler))
        .route("/alerts/bulk", post(alerts::bulk))
        .route("/alerts/{id}", get(alerts::get))
        .route("/alerts/{id}/acknowledge", post(alerts::acknowledge))
        .route("/alerts/{id}/resolve", post(alerts::resolve))
        .route("/alert-policies", get(alerts::list_policies).post(alerts::create_policy))
        .route("/alert-policies/{id}", get(alerts::get_policy).put(alerts::update_policy).delete(alerts::remove_policy))
        .route("/schedules", get(schedules::list).post(schedules::create))
        .route("/schedules/preview", get(schedules::preview))
        .route("/schedules/{id}", get(schedules::get).put(schedules::update).delete(schedules::remove))
        .route("/schedules/{id}/run", post(schedules::run_now))
        .route("/agents/{id}/services", get(services::list))
        .route("/agents/{id}/services/refresh", post(services::refresh))
        .route("/agents/{id}/services/control", post(services::control))
        .route("/agents/{id}/log-events", get(services::log_events))
}
