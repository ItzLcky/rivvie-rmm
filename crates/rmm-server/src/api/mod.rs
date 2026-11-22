use std::sync::Arc;

use axum::Router;
use axum::routing::{delete, get, post};

use crate::state::AppState;

pub mod access;
mod agents;
mod attachments;
mod alerts;
mod apikeys;
mod billing;
mod channels;
mod auth;
mod clients;
mod desk;
mod docs;
mod downloads;
mod kb;
mod jobs;
mod msi;
mod mutes;
mod packages;
mod passkeys;
mod schedules;
mod patches;
mod pm;
pub(crate) mod policies;
pub(crate) mod portal;
pub(crate) mod public;
mod reports;
mod search;
mod scripts;
mod security;
mod servicedesk;
mod services;
mod settings;
mod sso;
pub(crate) mod sla;
pub(crate) mod tickets;
mod time;
mod tools;
mod totp;
pub(crate) mod users;
mod audit;
mod siem;
mod vault;
mod webhooks;

pub use agents::refresh_health as refresh_agent_health;
pub use jobs::{FAILED as JOB_FAILED, deliver as deliver_job};
pub use portal::PORTAL_LINK_MINUTES;
pub use sso::seal_existing as seal_sso_secrets;
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

/// `attachment_max` is RMM_ATTACHMENT_MAX_MB in bytes: the three attachment upload routes take
/// that much per file (streamed to storage), everything else at most 8 MB.
pub fn router(attachment_max: u64) -> Router<Arc<AppState>> {
    // A whole upload: every file it may carry at the per-file limit, plus the form fields.
    let upload_limit = |files: usize| axum::extract::DefaultBodyLimit::max((attachment_max as usize).saturating_mul(files).saturating_add(1 << 20));
    Router::new()
        .route("/auth/login", post(auth::login))
        .route("/auth/login/passkey", post(passkeys::login_challenge))
        .route("/auth/sso/providers", get(sso::public_providers))
        .route("/auth/sso/callback", get(sso::callback))
        .route("/auth/sso/{id}/start", get(sso::start))
        .route("/auth/logout", post(auth::logout))
        .route("/auth/me", get(auth::me))
        .route("/auth/preferences", axum::routing::put(auth::update_preferences))
        .route("/events", get(crate::events::handler))
        .route("/openapi.json", get(public::openapi))
        .route("/api-keys", get(apikeys::list).post(apikeys::create))
        .route("/api-keys/options", get(apikeys::options))
        .route("/api-keys/{id}", delete(apikeys::revoke))
        .route("/service-accounts", get(apikeys::service_accounts).post(apikeys::create_service_account))
        .route("/service-accounts/{id}", delete(apikeys::remove_service_account))
        .route("/siem/destinations", get(siem::list).post(siem::create))
        .route("/siem/destinations/{id}", axum::routing::put(siem::update).delete(siem::remove))
        .route("/siem/destinations/{id}/test", post(siem::test))
        .route("/webhooks", get(webhooks::list).post(webhooks::create))
        .route("/webhooks/{id}", axum::routing::put(webhooks::update).delete(webhooks::remove))
        .route("/webhooks/{id}/rotate-secret", post(webhooks::rotate_secret))
        .route("/webhooks/{id}/test", post(webhooks::test))
        .route("/webhooks/{id}/deliveries", get(webhooks::deliveries))
        .route("/webhook-deliveries/{id}", get(webhooks::delivery))
        .route("/webhook-deliveries/{id}/redeliver", post(webhooks::redeliver))
        .route("/search", get(search::search))
        .route("/auth/password", post(auth::change_password))
        .route("/auth/sessions", get(auth::my_sessions).delete(auth::revoke_other_sessions))
        .route("/auth/sessions/{id}", delete(auth::revoke_my_session))
        .route("/auth/totp", get(totp::status))
        .route("/auth/totp/setup", post(totp::setup))
        .route("/auth/totp/enable", post(totp::enable))
        .route("/auth/totp/disable", post(totp::disable))
        .route("/auth/totp/recovery-codes", post(totp::regenerate_recovery))
        .route("/auth/passkeys", get(passkeys::list))
        .route("/auth/passkeys/register/start", post(passkeys::register_start))
        .route("/auth/passkeys/register/finish", post(passkeys::register_finish))
        .route("/auth/passkeys/recovery-codes", post(passkeys::recovery_codes))
        .route("/auth/passkeys/{id}", axum::routing::patch(passkeys::rename))
        .route("/auth/passkeys/{id}/remove", post(passkeys::remove))
        .route("/dashboard", get(agents::dashboard))
        .route("/clients", get(clients::list).post(clients::create))
        .route("/clients/{id}", get(clients::get).put(clients::rename).delete(clients::remove))
        .route("/clients/{id}/sites", post(clients::create_site))
        .route("/sites", get(clients::list_sites))
        .route("/sites/{id}", get(clients::get_site).put(clients::rename_site).delete(clients::remove_site))
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
        .route("/security/exclusions", get(security::exclusions).post(security::create_exclusion))
        .route("/security/exclusions/{id}", delete(security::delete_exclusion))
        .route("/security/rules", get(security::rules))
        .route("/security/rules/{id}", axum::routing::put(security::set_rule_mode))
        .route("/security/content", get(security::content).post(security::upload_content))
        .route("/security/content/{id}/promote", post(security::promote_content))
        .route("/security/content/{id}/rollback", post(security::rollback_content))
        .route("/security/databases", get(security::databases))
        .route("/security/databases/{id}/promote", post(security::promote_database))
        .route("/security/databases/{id}/rollback", post(security::rollback_database))
        .route("/agent/databases/{version}", get(security::agent_database))
        .route("/security/hunt", post(security::hunt))
        .route("/security/prevalence", get(security::prevalence))
        .route("/security/reputation", get(security::reputation_sources))
        .route("/security/reputation/rare", get(security::rare))
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
        .route("/users/{id}/sso-exempt", axum::routing::put(sso::set_exempt))
        .route("/users/{id}/sessions", get(users::sessions).delete(users::revoke_sessions))
        .route("/users/{id}/sessions/{sid}", delete(users::revoke_session))
        .route("/audit", get(audit::list))
        .route("/audit/export", get(audit::export))
        .route("/settings", get(settings::get).put(settings::update))
        .route("/settings/public", get(settings::public))
        .route("/settings/sso", get(sso::settings).put(sso::set_required))
        .route("/settings/sso/providers", post(sso::create_provider))
        .route("/settings/sso/providers/{id}", axum::routing::put(sso::update_provider).delete(sso::delete_provider))
        .route("/settings/sso/providers/{id}/maps", axum::routing::put(sso::update_maps))
        .route("/settings/sso/providers/{id}/test", post(sso::test_provider))
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
        .route("/alert-mutes", get(mutes::list).post(mutes::create))
        .route("/alert-mutes/{id}", delete(mutes::remove))
        .route("/schedules", get(schedules::list))
        .route("/schedules/preview", get(schedules::preview))
        .route("/schedules/{id}", get(schedules::get))
        .route("/schedules/{id}/run", post(schedules::run_now))
        .route("/policy-sets", get(policies::list_sets).post(policies::create_set))
        .route("/policy-sets/{id}", get(policies::get_set).put(policies::update_set).delete(policies::delete_set))
        .route("/policy-sets/{id}/duplicate", post(policies::duplicate_set))
        .route("/policy-sets/{id}/agents", get(policies::set_agents))
        .route("/policy-sets/{id}/items", post(policies::create_item))
        .route("/policy-items/{id}", get(policies::get_item).put(policies::update_item).delete(policies::delete_item))
        .route("/policy-items/{id}/overrides/{set_id}", axum::routing::put(policies::put_override).delete(policies::delete_override))
        .route("/policy-items/{id}/exclusions/{agent_id}", axum::routing::put(policies::exclude).delete(policies::include))
        .route("/device-categories", get(policies::list_categories).post(policies::create_category))
        .route("/device-categories/{id}", axum::routing::put(policies::update_category).delete(policies::delete_category))
        .route("/agents/category", post(policies::move_agents))
        .route("/policy-assignments", get(policies::list_assignments).put(policies::put_assignment))
        .route("/policy-assignments/{id}", delete(policies::delete_assignment))
        .route("/agents/{id}/policy", get(policies::get_agent_policy))
        .route("/agents/{id}/policy-pin", axum::routing::put(policies::put_pin))
        .route("/agents/{id}/policy-pin/customize", post(policies::customize))
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
        .route("/tickets/{id}/attachments/{aid}", get(tickets::download))
        .route("/tickets/{id}/agents", post(tickets::link_agent))
        .route("/tickets/{id}/agents/{agent_id}", delete(tickets::unlink_agent))
        .route("/tickets/{id}/docs", post(tickets::link_doc))
        .route("/tickets/{id}/docs/{doc_id}", delete(tickets::unlink_doc))
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
        .route("/tickets/{id}/split", post(tickets::split))
        .route("/tickets/{id}/canned/{cid}", get(desk::render_canned))
        .route("/teams", get(desk::list_teams).post(desk::create_team))
        .route("/teams/{id}", axum::routing::put(desk::update_team).delete(desk::remove_team))
        .route("/canned-responses", get(desk::list_canned).post(desk::create_canned))
        .route("/canned-responses/{id}", axum::routing::put(desk::update_canned).delete(desk::remove_canned))
        .route("/settings/service-desk", get(desk::get_settings).put(desk::update_settings))
        .route("/sla/calendars", get(sla::calendars).post(sla::create_calendar))
        .route("/sla/calendars/{id}", axum::routing::put(sla::update_calendar).delete(sla::remove_calendar))
        .route("/sla/policies", get(sla::policies).post(sla::create_policy))
        .route("/sla/policies/{id}", axum::routing::put(sla::update_policy).delete(sla::remove_policy))
        .route("/clients/{id}/service", axum::routing::put(sla::set_client))
        .route("/kb", get(kb::list).post(kb::create))
        .route("/kb/{id}", get(kb::get).put(kb::update).delete(kb::remove))
        .route("/contacts/{id}/portal-invite", post(portal::invite))
        .route("/contacts/{id}/portal-credentials", delete(portal::reset_credentials))
        .route("/feedback/{token}", get(portal::feedback).post(portal::answer_feedback))
        .route("/files/{token}", get(attachments::shared))
        .route("/portal/info", get(portal::public_info))
        .route("/portal/auth/link", post(portal::request_link))
        .route("/portal/auth/verify", post(portal::verify))
        .route("/portal/auth/login", post(portal::login))
        .route("/portal/auth/logout", post(portal::logout))
        .route("/portal/me", get(portal::me))
        .route("/portal/account/password", post(portal::set_password))
        .route("/portal/account/totp/setup", post(portal::totp_setup))
        .route("/portal/account/totp/enable", post(portal::totp_enable))
        .route("/portal/account/totp/disable", post(portal::totp_disable))
        .route("/portal/tickets", get(portal::tickets))
        .route("/portal/tickets/{id}", get(portal::ticket))
        .route("/portal/tickets/{id}/resolve", post(portal::resolve))
        .route("/portal/tickets/{id}/attachments/{aid}", get(portal::download))
        .route("/portal/kb", get(portal::kb))
        .route("/portal/kb/{id}", get(portal::kb_article))
        .route("/portal/devices", get(portal::devices))
        .route("/portal/invoices", get(portal::invoices))
        .route("/portal/invoices/{id}/pdf", get(portal::invoice_pdf))
        .route("/time", get(time::list).post(time::create))
        .route("/time/{id}", axum::routing::put(time::update).delete(time::remove))
        .route("/time/timer", get(time::timer))
        .route("/time/timer/start", post(time::start))
        .route("/time/timer/stop", post(time::stop))
        .route("/timesheets", get(time::week))
        .route("/timesheets/submit", post(time::submit))
        .route("/timesheets/pending", get(time::pending))
        .route("/timesheets/{id}/approve", post(time::approve))
        .route("/timesheets/{id}/reject", post(time::reject))
        .route("/work-types", get(billing::work_types).put(billing::save_work_types))
        .route("/work-roles", get(billing::work_roles).post(billing::create_work_role))
        .route("/work-roles/{id}", axum::routing::put(billing::update_work_role).delete(billing::remove_work_role))
        .route("/billing/rates", get(billing::user_rates))
        .route("/users/{id}/rates", axum::routing::put(billing::set_user_rates))
        .route("/products", get(billing::products).post(billing::create_product))
        .route("/products/{id}", axum::routing::put(billing::update_product).delete(billing::remove_product))
        .route("/contracts", get(billing::contracts).post(billing::create_contract))
        .route("/contracts/{id}", get(billing::contract).put(billing::update_contract).delete(billing::remove_contract))
        .route("/contracts/{id}/bank", post(billing::adjust_bank))
        .route("/charges", get(billing::charges).post(billing::create_charge))
        .route("/charges/{id}", delete(billing::remove_charge))
        .route("/invoices", get(billing::invoices).post(billing::create_invoice))
        .route("/invoices/run", post(billing::run))
        .route("/invoices/{id}", get(billing::invoice).patch(billing::update_invoice).delete(billing::remove_invoice))
        .route("/invoices/{id}/lines", post(billing::add_line))
        .route("/invoices/{id}/lines/{lid}", axum::routing::put(billing::update_line).delete(billing::remove_line))
        .route("/invoices/{id}/pdf", get(billing::pdf))
        .route("/invoices/{id}/finalise", post(billing::finalise))
        .route("/invoices/{id}/send", post(billing::send))
        .route("/invoices/{id}/paid", post(billing::mark_paid))
        .route("/invoices/{id}/void", post(billing::void))
        .route("/invoices/{id}/credit", post(billing::credit))
        .route("/settings/billing", get(billing::get_settings).put(billing::update_settings))
        .route("/clients/{id}/billing", get(billing::get_client_billing).put(billing::set_client_billing))
        .route("/billing/accounting", get(billing::accounting).delete(billing::disconnect_accounting))
        .route("/billing/accounting/sync", post(billing::sync_accounting))
        .route("/billing/accounting/{provider}", axum::routing::put(billing::save_accounting))
        .route("/billing/accounting/{provider}/connect", post(billing::connect_accounting))
        .route("/billing/accounting/{provider}/callback", get(billing::accounting_callback))
        .route("/billing/overview", get(reports::billing_overview))
        .route("/schedule", get(pm::schedule).post(pm::create_schedule))
        .route("/schedule/{id}", axum::routing::put(pm::update_schedule).delete(pm::remove_schedule))
        .route("/projects", get(pm::projects).post(pm::create_project))
        .route("/projects/{id}", get(pm::project).put(pm::update_project).delete(pm::remove_project))
        .route("/projects/{id}/tasks", post(pm::create_task))
        .route("/projects/{id}/tasks/{tid}", axum::routing::put(pm::update_task).delete(pm::remove_task))
        .route("/projects/{id}/tasks/{tid}/ticket", post(pm::task_ticket))
        .route("/clients/{id}/docs", get(docs::list).post(docs::create))
        .route("/docs/{id}", get(docs::get).put(docs::update).delete(docs::remove))
        .route("/docs/{id}/revisions/{rev}", get(docs::revision))
        .route("/docs/{id}/export", get(docs::export))
        .route("/doc-categories", get(docs::categories).post(docs::create_category))
        .route("/doc-categories/order", axum::routing::put(docs::reorder_categories))
        .route("/doc-categories/{id}", axum::routing::put(docs::update_category).delete(docs::delete_category))
        .route("/doc-templates", get(docs::templates).post(docs::create_template))
        .route("/doc-templates/{id}", get(docs::template).put(docs::update_template).delete(docs::delete_template))
        .route("/clients/{id}/vault", get(vault::list).post(vault::create))
        .route("/vault/{id}", get(vault::get).put(vault::update).delete(vault::remove))
        .route("/vault/{id}/reveal", post(vault::reveal))
        .route("/vault/{id}/totp", post(vault::totp))
        .route("/reports/service-desk", get(reports::service_desk))
        .route("/reports/utilisation", get(reports::utilisation))
        .route("/reports/profitability", get(reports::profitability))
        .route("/reports/qbr/{id}", get(reports::qbr))
        .route("/agents/{id}/processes", get(tools::processes))
        .route("/agents/{id}/processes/{pid}/kill", post(tools::kill))
        .route("/agents/{id}/files", get(tools::list))
        .route("/agents/{id}/files/download", get(tools::download))
        // Everything above takes bodies of at most 8 MB; uploads stream to the agent or to storage instead.
        .layer(tower_http::limit::RequestBodyLimitLayer::new(8 * 1024 * 1024))
        .route("/agents/{id}/files/upload", axum::routing::put(tools::upload))
        // Streamed into storage and checked on the way (security::DATABASE_MAX).
        .route("/security/databases", post(security::upload_database))
        // A server-only hash list can be a whole feed (a million hashes is about 65 MB of text).
        .route(
            "/security/reputation/lists/{name}",
            axum::routing::put(security::put_reputation_list)
                .delete(security::delete_reputation_list)
                .layer(axum::extract::DefaultBodyLimit::max(security::REPUTATION_LIST_MAX)),
        )
        .route("/tickets/{id}/attachments", post(tickets::upload).layer(upload_limit(tickets::MAX_UPLOAD_FILES)))
        .route("/portal/tickets", post(portal::create_ticket).layer(upload_limit(portal::MAX_FILES)))
        .route("/portal/tickets/{id}/messages", post(portal::add_message).layer(upload_limit(portal::MAX_FILES)))
}
