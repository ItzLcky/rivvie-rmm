use sqlx::PgPool;

use crate::hub::Hub;

pub struct AppState {
    pub db: PgPool,
    pub hub: Hub,
    pub cfg: Settings,
}

#[derive(Debug, Clone)]
pub struct Settings {
    /// Public base URL agents and browsers use, e.g. https://rmm.example.com
    pub public_url: String,
    pub heartbeat_secs: u32,
    pub inventory_secs: u32,
    pub metrics_retention_days: u32,
    pub job_queue_days: u32,
}

impl Settings {
    pub fn secure_cookies(&self) -> bool {
        self.public_url.starts_with("https://")
    }
}
