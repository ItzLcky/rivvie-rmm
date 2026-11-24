use std::sync::RwLock;

use sqlx::PgPool;

use crate::hub::Hub;

pub struct AppState {
    pub db: PgPool,
    pub hub: Hub,
    pub cfg: Settings,
    /// Cached `company_settings` row; written through by the settings API.
    pub company: RwLock<Company>,
    /// Every `branding` row; read through [`crate::branding::resolve`].
    pub branding: crate::branding::Cache,
    pub limits: crate::ratelimit::Limits,
    pub releases: crate::updates::Releases,
    /// When this process started (offline alerts allow agents time to reconnect).
    pub started_at: chrono::DateTime<chrono::Utc>,
    /// Outbound HTTP for webhook, Slack and Teams notifications.
    pub http: reqwest::Client,
    /// Wakes the notification worker when something is queued.
    pub notify_wake: tokio::sync::Notify,
    /// Ticket attachments and raw email.
    pub storage: crate::storage::Storage,
    /// Triage packages being received, by action id.
    pub triage: std::sync::Mutex<std::collections::HashMap<uuid::Uuid, Vec<u8>>>,
    /// OIDC discovery documents and signing keys of the single sign-on providers.
    pub oidc: crate::oidc::Cache,
    /// WebAuthn relying party and pending passkey ceremonies.
    pub passkeys: crate::webauthn::Passkeys,
}

#[derive(Debug, Clone, Default, sqlx::FromRow)]
pub struct Company {
    pub company_name: String,
    pub session_idle_hours: Option<i32>,
    /// Require 2FA for every user, not just admins.
    pub require_2fa_all: bool,
    /// Outgoing mail for email notification channels.
    pub smtp_host: String,
    pub smtp_port: i32,
    /// starttls / tls / none
    pub smtp_security: String,
    pub smtp_username: String,
    /// The password, sealed with RMM_DATA_KEY when the server has one (`smtp_password_sealed`);
    /// read it with [`Company::smtp_password`].
    pub smtp_password_enc: Option<Vec<u8>>,
    pub smtp_password_sealed: bool,
    pub smtp_from: String,
    /// Satisfaction surveys on resolve.
    pub csat_enabled: bool,
    /// Password sign-in is refused for everyone but break-glass accounts.
    pub sso_required: bool,
}

impl Company {
    /// The mail server password, opened. `None` when none is set, or when it can't be opened.
    pub fn smtp_password(&self, key: Option<&crate::crypto::DataKey>) -> Option<String> {
        let stored = self.smtp_password_enc.as_deref()?;
        crate::crypto::load(key, stored, self.smtp_password_sealed).map(|p| String::from_utf8_lossy(&p).into_owned())
    }

    pub const COLUMNS: &str = "company_name, session_idle_hours, require_2fa_all,
        smtp_host, smtp_port, smtp_security, smtp_username, smtp_password_enc, smtp_password_sealed, smtp_from, csat_enabled, sso_required";

    pub async fn load(db: &PgPool) -> sqlx::Result<Self> {
        sqlx::query_as(sqlx::AssertSqlSafe(format!("SELECT {} FROM company_settings", Self::COLUMNS))).fetch_one(db).await
    }
}

impl AppState {
    pub fn company(&self) -> Company {
        self.company.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Company override, else RMM_SESSION_IDLE_HOURS.
    pub fn session_idle_hours(&self) -> i32 {
        self.company().session_idle_hours.unwrap_or(self.cfg.session_idle_hours as i32)
    }
}

#[derive(Debug, Clone)]
pub struct Settings {
    /// Prebuilt agent binaries offered for download.
    pub agent_dir: std::path::PathBuf,
    /// Public base URL agents and browsers use, e.g. https://rmm.example.com
    pub public_url: String,
    pub heartbeat_secs: u32,
    pub inventory_secs: u32,
    pub metrics_retention_days: u32,
    pub job_queue_days: u32,
    /// Online agents are asked for a patch scan when their last one is older than this.
    pub patch_scan_hours: u32,
    /// Sessions unused for this long are rejected (the 7-day absolute lifetime still applies).
    /// Default only: Company settings can override it.
    pub session_idle_hours: u32,
    /// Peers whose `X-Forwarded-For` is believed (RMM_TRUSTED_PROXIES).
    pub trusted_proxies: Vec<crate::ratelimit::Cidr>,
    /// Raw heartbeat samples are kept this long; hourly rollups for `metrics_retention_days`.
    pub metrics_raw_days: u32,
    /// Resolved alerts are deleted after this many days.
    pub alert_retention_days: u32,
    /// How often polled alert policies (offline, CPU, memory, disk) are checked.
    pub alert_eval_secs: u32,
    /// Resolved tickets move to Closed after this many days.
    pub ticket_close_days: u32,
    /// Raw inbound email (MIME) is deleted from storage after this many days.
    pub email_raw_days: u32,
    /// Canary content is promoted to everyone after this long without problems.
    pub content_soak_minutes: u32,
    /// When set, uploaded content must be signed by this key (the agents' release key).
    pub content_pubkey: Option<String>,
    /// Encrypts sensitive columns at rest (RMM_DATA_KEY).
    pub data_key: Option<crate::crypto::DataKey>,
    /// Largest ticket or portal attachment, per file (RMM_ATTACHMENT_MAX_MB).
    pub attachment_max_mb: u32,
    /// Bearer token for `GET /metrics` (RMM_METRICS_TOKEN); the route is off without it.
    pub metrics_token: Option<String>,
    /// The AGPL source offer shown in the console and portal (RMM_SOURCE_URL).
    pub source_url: String,
}

impl Settings {
    pub fn secure_cookies(&self) -> bool {
        self.public_url.starts_with("https://")
    }

    pub fn attachment_max_bytes(&self) -> u64 {
        u64::from(self.attachment_max_mb) * 1024 * 1024
    }
}
