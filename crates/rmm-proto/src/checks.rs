//! Checks the agent runs on a schedule for the server: uptime monitors (ping, TCP, HTTP, TLS
//! certificates, DNS) and backup jobs.
//!
//! The server sends the complete set ([`crate::ServerMsg::Checks`]) after connecting and
//! whenever it changes, like log watchers; the agent runs each at its interval and reports
//! [`CheckResult`]s in batches ([`crate::AgentMsg::CheckResults`]), every [`FLUSH_SECS`] and at
//! once when a check's outcome flips. The agent keeps nothing across restarts. Only agents that
//! list [`CAPABILITY`] get these messages.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const CAPABILITY: &str = "checks";

/// The most checks one agent runs.
pub const MAX_CHECKS: usize = 200;
/// The most checks running at the same time.
pub const MAX_IN_FLIGHT: usize = 16;
/// Results are batched this long.
pub const FLUSH_SECS: u64 = 30;
pub const MIN_INTERVAL_SECS: u32 = 30;
pub const MAX_INTERVAL_SECS: u32 = 86_400;
/// How often backup jobs are read unless the server says otherwise.
pub const BACKUP_INTERVAL_SECS: u32 = 3600;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckSpec {
    pub id: Uuid,
    /// 30-86400.
    pub interval_secs: u32,
    pub timeout_secs: u32,
    pub kind: CheckKind,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HttpMethod {
    #[default]
    Get,
    Head,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CheckKind {
    /// ICMP echo.
    Ping { host: String },
    /// A TCP handshake completes.
    Tcp { host: String, port: u16 },
    /// An HTTP(S) request; the status must be one of `statuses` (empty: 200-399), and the body
    /// must contain `keyword` (or not, with `keyword_absent`). Redirects are followed.
    Http {
        url: String,
        #[serde(default)]
        method: HttpMethod,
        #[serde(default)]
        statuses: Vec<u16>,
        #[serde(default)]
        keyword: Option<String>,
        #[serde(default)]
        keyword_absent: bool,
        /// An `https://` URL whose certificate the machine doesn't trust fails the check.
        #[serde(default = "yes")]
        verify_tls: bool,
    },
    /// A TLS handshake that reports the certificate (it never fails for the certificate itself).
    Tls {
        host: String,
        port: u16,
        /// The name to present (SNI), if not `host`.
        #[serde(default)]
        server_name: Option<String>,
    },
    /// A lookup: `record` is `A`, `AAAA`, `CNAME`, `MX` or `TXT`. With `expect`, at least one
    /// answer must equal one of them (case-insensitively).
    Dns {
        name: String,
        record: String,
        /// `ip` or `ip:port`; empty: the machine's resolvers.
        #[serde(default)]
        server: Option<String>,
        #[serde(default)]
        expect: Vec<String>,
    },
    /// Read the last result of backup jobs.
    Backup {
        /// `auto`, `wsb`, `veeam`, `restic`, `borg`, `timemachine`, `file_age`.
        #[serde(default)]
        providers: Vec<String>,
        /// Where to look, for providers that need to be told.
        #[serde(default)]
        sources: Vec<BackupSource>,
    },
}

fn yes() -> bool {
    true
}

/// A repository or directory to read. Secrets never come from the server: restic and borg read
/// an env file that is already on the machine.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupSource {
    pub provider: String,
    /// restic, borg: `KEY=value` lines (`RESTIC_REPOSITORY`, `RESTIC_PASSWORD_FILE`...), an absolute path.
    #[serde(default)]
    pub env_file: Option<String>,
    /// restic, borg: the repository, if the env file doesn't name it.
    #[serde(default)]
    pub repo: Option<String>,
    /// file_age: the directory to look in, absolute.
    #[serde(default)]
    pub path: Option<String>,
    /// file_age: file names to consider (`*.bak`); empty: all.
    #[serde(default)]
    pub glob: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackupResult {
    Success,
    Warning,
    Failed,
    Running,
    #[serde(other)]
    Unknown,
}

impl BackupResult {
    pub fn as_str(self) -> &'static str {
        match self {
            BackupResult::Success => "success",
            BackupResult::Warning => "warning",
            BackupResult::Failed => "failed",
            BackupResult::Running => "running",
            BackupResult::Unknown => "unknown",
        }
    }
}

/// One backup job as the machine reports it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupJob {
    pub provider: String,
    /// The job's name in the product, or the repository or path for restic, borg and file_age.
    pub job: String,
    #[serde(default)]
    pub last_run_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub last_success_at: Option<DateTime<Utc>>,
    pub last_result: BackupResult,
    #[serde(default)]
    pub message: String,
    #[serde(default)]
    pub size_bytes: Option<u64>,
}

/// A server's certificate, from a TLS check or an `https://` HTTP check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertInfo {
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    pub subject: String,
    pub issuer: String,
    #[serde(default)]
    pub sans: Vec<String>,
    /// Why the machine's roots don't trust it; None when they do.
    #[serde(default)]
    pub untrusted: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CheckData {
    Cert(CertInfo),
    /// The jobs found, and per provider that couldn't be read, why.
    Backups {
        jobs: Vec<BackupJob>,
        #[serde(default)]
        errors: Vec<(String, String)>,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CheckResult {
    pub check_id: Uuid,
    pub at: DateTime<Utc>,
    pub ok: bool,
    #[serde(default)]
    pub latency_ms: Option<u32>,
    /// A number the check measures: the HTTP status, a certificate's days left.
    #[serde(default)]
    pub value: Option<f64>,
    /// What happened, in a few words (`HTTP 200`, `connection refused`, `keyword not found`).
    #[serde(default)]
    pub message: String,
    #[serde(default)]
    pub data: Option<CheckData>,
}
