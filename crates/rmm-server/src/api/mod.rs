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
mod msi;
mod mutes;
mod packages;
mod schedules;
mod patches;
mod search;
mod scripts;
mod security;
mod servicedesk;
mod services;
mod settings;
pub(crate) mod tickets;
mod tools;
mod totp;
pub(crate) mod users;

pub use jobs::{FAILED as JOB_FAILED, deliver as deliver_job};
pub use totp::{clear as clear_totp, seal_existing as seal_totp_secrets};
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
        .route("/clients/{id}/desktop", axum::routing::put(clients::update_desktop))
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
        .route("/agents/{id}/patches", get(patches::for_agent))
        .route("/patches", get(patches::list))
        .route("/patches/agents", get(patches::agents_for_update))
        .route("/patches/approval", post(patches::approval))
        .route("/patches/install", post(patches::install))
        .route("/patches/scan", post(patches::scan))
        .route("/patches/compliance", get(patches::compliance))
        .route("/patch-runs", get(patches::runs))
        .route("/patch-runs/{id}", get(patches::run))
        .route("/patch-runs/{id}/cancel", post(patches::cancel_run))
        .route("/patch-policies", get(patches::policies).post(patches::create_policy))
        .route("/patch-policies/{id}", axum::routing::put(patches::update_policy).delete(patches::delete_policy))
        .route("/patch-windows", get(patches::windows))
        .route("/sites/{id}/maintenance-window", axum::routing::put(patches::set_window))
        .route("/agents/{id}/security", get(security::for_agent))
        .route("/agents/{id}/security/actions", post(security::start))
        .route("/agents/{id}/security/refresh", post(security::refresh))
        .route("/security/summary", get(security::summary))
        .route("/security/agents", get(security::agents))
        .route("/security/detections", get(security::detections))
        .route("/security/actions", post(security::bulk_action))
        .route("/security/actions/{id}/download", get(security::download))
        .route("/agents/{id}/security/respond", post(security::respond))
        .route("/agents/{id}/telemetry", get(security::telemetry))
        .route("/security/detections/{id}", get(security::detection))
        .route("/security/detections/{id}/verdict", post(security::verdict))
        .route("/security/quarantine", get(security::quarantine))
        .route("/security/policies", get(security::policies).post(security::create_policy))
        .route("/security/policies/{id}", axum::routing::put(security::update_policy).delete(security::delete_policy))
        .route("/security/exclusions", get(security::exclusions).post(security::create_exclusion))
        .route("/security/exclusions/{id}", delete(security::delete_exclusion))
        .route("/security/rules", get(security::rules))
        .route("/security/rules/{id}", axum::routing::put(security::set_rule_mode))
        .route("/security/content", get(security::content).post(security::upload_content))
        .route("/security/content/{id}/promote", post(security::promote_content))
        .route("/security/content/{id}/rollback", post(security::rollback_content))
        .route("/security/hunt", post(security::hunt))
        .route("/security/prevalence", get(security::prevalence))
        .route("/clients/{id}/security", axum::routing::put(security::set_canary))
        .route("/users/{id}/permissions", axum::routing::put(users::update_permissions))
        .route("/agents/{id}/shell", get(crate::shell_ws::handler))
        .route("/agents/{id}/desktop", get(crate::desktop_ws::handler))
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
        .route("/alert-policies/{id}/exclusions/{agent_id}", axum::routing::put(alerts::exclude).delete(alerts::include))
        .route("/agents/{id}/alert-policies", get(alerts::for_agent))
        .route("/alert-mutes", get(mutes::list).post(mutes::create))
        .route("/alert-mutes/{id}", delete(mutes::remove))
        .route("/schedules", get(schedules::list).post(schedules::create))
        .route("/schedules/preview", get(schedules::preview))
        .route("/schedules/{id}", get(schedules::get).put(schedules::update).delete(schedules::remove))
        .route("/schedules/{id}/run", post(schedules::run_now))
        .route("/agents/{id}/services", get(services::list))
        .route("/agents/{id}/services/refresh", post(services::refresh))
        .route("/agents/{id}/services/control", post(services::control))
        .route("/agents/{id}/log-events", get(services::log_events))
        .route("/tickets", get(tickets::list).post(tickets::create))
        .route("/tickets/summary", get(tickets::summary))
        .route("/tickets/meta", get(tickets::meta))
        .route("/tickets/bulk", post(tickets::bulk))
        .route("/tickets/{id}", get(tickets::get).patch(tickets::update))
        .route("/tickets/{id}/events", post(tickets::add_event))
        .route("/tickets/{id}/attachments", post(tickets::upload))
        .route("/tickets/{id}/attachments/{aid}", get(tickets::download))
        .route("/tickets/{id}/agents", post(tickets::link_agent))
        .route("/tickets/{id}/agents/{agent_id}", delete(tickets::unlink_agent))
        .route("/tickets/{id}/merge", post(tickets::merge))
        .route("/contacts", get(servicedesk::list_contacts).post(servicedesk::create_contact))
        .route("/contacts/{id}", get(servicedesk::get_contact).put(servicedesk::update_contact).delete(servicedesk::remove_contact))
        .route("/clients/{id}/email-domains", axum::routing::put(servicedesk::update_email_domains))
        .route("/boards", get(servicedesk::list_boards).post(servicedesk::create_board))
        .route("/boards/{id}", axum::routing::put(servicedesk::update_board).delete(servicedesk::remove_board))
        .route("/ticket-types", axum::routing::put(servicedesk::save_types))
        .route("/mailboxes", get(servicedesk::list_mailboxes).post(servicedesk::create_mailbox))
        .route("/mailboxes/inbound", get(servicedesk::inbound_log))
        .route("/mailboxes/{id}", axum::routing::put(servicedesk::update_mailbox).delete(servicedesk::remove_mailbox))
        .route("/mailboxes/{id}/poll", post(servicedesk::poll_mailbox))
        .route("/mailboxes/{id}/rotate-token", post(servicedesk::rotate_mailbox_token))
        .route("/inbound/email/{token}", post(servicedesk::inbound))
        .route("/agents/{id}/processes", get(tools::processes))
        .route("/agents/{id}/processes/{pid}/kill", post(tools::kill))
        .route("/agents/{id}/files", get(tools::list))
        .route("/agents/{id}/files/download", get(tools::download))
        // Everything above takes bodies of at most 8 MB; uploads stream to the agent instead.
        .layer(tower_http::limit::RequestBodyLimitLayer::new(8 * 1024 * 1024))
        .route("/agents/{id}/files/upload", axum::routing::put(tools::upload))
}
