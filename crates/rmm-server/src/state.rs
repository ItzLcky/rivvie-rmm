use std::sync::RwLock;

use sqlx::PgPool;

use crate::hub::Hub;

pub struct AppState {
    pub db: PgPool,
    pub hub: Hub,
    pub cfg: Settings,
    /// Cached `company_settings` row; written through by the settings API.
    pub company: RwLock<Company>,
}

#[derive(Debug, Clone, Default, sqlx::FromRow)]
pub struct Company {
    pub company_name: String,
    pub session_idle_hours: Option<i32>,
}

impl Company {
    pub async fn load(db: &PgPool) -> sqlx::Result<Self> {
        sqlx::query_as("SELECT company_name, session_idle_hours FROM company_settings").fetch_one(db).await
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
    /// Sessions unused for this long are rejected (the 7-day absolute lifetime still applies).
    /// Default only: Company settings can override it.
    pub session_idle_hours: u32,
}

impl Settings {
    pub fn secure_cookies(&self) -> bool {
        self.public_url.starts_with("https://")
    }
}
