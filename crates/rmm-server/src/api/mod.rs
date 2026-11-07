use std::sync::Arc;

use axum::Router;
use axum::routing::{delete, get, post};

use crate::state::AppState;

mod agents;
mod auth;
mod clients;
mod jobs;
mod scripts;
mod users;

pub use users::create_user as create_user_cli;

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/auth/login", post(auth::login))
        .route("/auth/logout", post(auth::logout))
        .route("/auth/me", get(auth::me))
        .route("/dashboard", get(agents::dashboard))
        .route("/clients", get(clients::list).post(clients::create))
        .route("/clients/{id}", delete(clients::remove))
        .route("/clients/{id}/sites", post(clients::create_site))
        .route("/sites/{id}", delete(clients::remove_site))
        .route("/sites/{id}/enrollment-tokens", get(clients::list_tokens).post(clients::create_token))
        .route("/enrollment-tokens/{id}", delete(clients::revoke_token))
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
        .route("/audit", get(users::audit_log))
}
