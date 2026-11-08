use std::sync::Arc;

use axum::Router;
use axum::routing::{delete, get, post};

use crate::state::AppState;

mod agents;
mod auth;
mod clients;
mod downloads;
mod jobs;
mod scripts;
mod settings;
mod totp;
mod users;

pub use totp::clear as clear_totp;
pub use users::create_user as create_user_cli;

pub fn agent_platforms() -> impl Iterator<Item = &'static str> {
    downloads::PLATFORMS.iter().map(|p| p.id)
}

pub fn agent_binary_exists(st: &AppState, id: &str) -> bool {
    downloads::platform_path(st, id).is_some()
}

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/auth/login", post(auth::login))
        .route("/auth/logout", post(auth::logout))
        .route("/auth/me", get(auth::me))
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
        .route("/clients/{id}", delete(clients::remove))
        .route("/clients/{id}/sites", post(clients::create_site))
        .route("/sites/{id}", delete(clients::remove_site))
        .route("/sites/{id}/enrollment-tokens", get(clients::list_tokens).post(clients::create_token))
        .route("/enrollment-tokens/{id}", delete(clients::revoke_token))
        .route("/agent-downloads", get(downloads::list))
        .route("/agent-downloads/{id}", get(downloads::download))
        .route("/agents", get(agents::list))
        .route("/agents/{id}", get(agents::get).delete(agents::remove))
        .route("/agents/{id}/metrics", get(agents::metrics))
        .route("/agents/{id}/inventory/refresh", post(agents::refresh_inventory))
        .route("/agents/{id}/jobs", get(jobs::list_for_agent))
        .route("/agents/{id}/shell", get(crate::shell_ws::handler))
        .route("/jobs", get(jobs::list_recent).post(jobs::create))
        .route("/jobs/{id}", get(jobs::get))
        .route("/scripts", get(scripts::list).post(scripts::create))
        .route("/scripts/{id}", get(scripts::get).put(scripts::update).delete(scripts::remove))
        .route("/users", get(users::list).post(users::create))
        .route("/users/{id}", delete(users::disable))
        .route("/users/{id}/enable", post(users::enable))
        .route("/users/{id}/password", post(users::reset_password))
        .route("/users/{id}/totp", delete(users::reset_totp))
        .route("/users/{id}/sessions", get(users::sessions).delete(users::revoke_sessions))
        .route("/users/{id}/sessions/{sid}", delete(users::revoke_session))
        .route("/audit", get(users::audit_log))
        .route("/settings", get(settings::get).put(settings::update))
        .route("/settings/public", get(settings::public))
}
