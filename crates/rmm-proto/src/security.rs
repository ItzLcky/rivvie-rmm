//! Endpoint protection payloads (Phase 8, milestone 1: the platform's built-in antivirus).
//!
//! The agent reads the state of the protection the OS already has (Microsoft Defender and
//! other products registered with Windows Security Center, ClamAV, XProtect) and sends a
//! [`Report`] after connecting, whenever it changes, and when asked
//! ([`crate::ServerMsg::SecurityRefresh`]). The server can start a scan or a signature update
//! ([`crate::ServerMsg::SecurityAction`]); the agent answers with
//! [`crate::AgentMsg::SecurityActionResult`] when it starts and again when it ends, then sends
//! a fresh report.
//!
//! Milestones 2-7 add our own sensor ([`SENSOR_CAPABILITY`]): a separate process the agent
//! supervises, which scans files against a signed content bundle ([`crate::ServerMsg::Content`]),
//! records telemetry, runs behaviour rules and reports [`SensorDetection`]s. Response actions
//! ([`ResponseAction`]) run in the agent, so they work even with the sensor switched off.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Capability an agent lists in `Auth` when it reports protection status.
pub const CAPABILITY: &str = "security";

/// Capability for the sensor, content bundles, response actions and telemetry queries.
pub const SENSOR_CAPABILITY: &str = "sensor";

/// Most detections the agent sends per report (newest first).
pub const MAX_DETECTIONS: usize = 200;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ProductKind {
    /// Microsoft Defender Antivirus.
    Defender,
    Clamav,
    Xprotect,
    /// Our own sensor.
    Rmm,
    /// A third-party product registered with Windows Security Center (state only).
    #[serde(other)]
    Other,
}

impl ProductKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ProductKind::Defender => "defender",
            ProductKind::Clamav => "clamav",
            ProductKind::Xprotect => "xprotect",
            ProductKind::Rmm => "rmm",
            ProductKind::Other => "other",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "defender" => ProductKind::Defender,
            "clamav" => ProductKind::Clamav,
            "xprotect" => ProductKind::Xprotect,
            "rmm" => ProductKind::Rmm,
            "other" => ProductKind::Other,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    QuickScan,
    FullScan,
    UpdateSignatures,
}

impl Action {
    pub const ALL: [Action; 3] = [Action::QuickScan, Action::FullScan, Action::UpdateSignatures];

    pub fn as_str(self) -> &'static str {
        match self {
            Action::QuickScan => "quick_scan",
            Action::FullScan => "full_scan",
            Action::UpdateSignatures => "update_signatures",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|a| a.as_str() == s)
    }

    pub fn label(self) -> &'static str {
        match self {
            Action::QuickScan => "quick scan",
            Action::FullScan => "full scan",
            Action::UpdateSignatures => "signature update",
        }
    }
}

/// One protection product and its state. `None` means the product doesn't say.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Product {
    pub kind: ProductKind,
    /// "Microsoft Defender Antivirus", "ClamAV", "XProtect", or a Security Center name.
    pub name: String,
    #[serde(default)]
    pub version: Option<String>,
    /// The scanning engine is on and protecting (for ClamAV: installed with signatures).
    #[serde(default)]
    pub enabled: Option<bool>,
    /// Files are scanned as they're opened (Defender real-time protection, clamonacc).
    #[serde(default)]
    pub realtime: Option<bool>,
    #[serde(default)]
    pub signature_version: Option<String>,
    #[serde(default)]
    pub signatures_updated_at: Option<DateTime<Utc>>,
    /// Security Center's own verdict for third-party products, which don't give a date.
    #[serde(default)]
    pub signatures_current: Option<bool>,
    #[serde(default)]
    pub last_quick_scan: Option<DateTime<Utc>>,
    #[serde(default)]
    pub last_full_scan: Option<DateTime<Utc>>,
    #[serde(default)]
    pub tamper_protection: Option<bool>,
    /// What the agent can start for this product.
    #[serde(default)]
    pub actions: Vec<Action>,
    /// Anything worth showing: passive mode, why a value is missing...
    #[serde(default)]
    pub detail: Option<String>,
}

impl Product {
    pub fn new(kind: ProductKind, name: impl Into<String>) -> Self {
        Product {
            kind,
            name: name.into(),
            version: None,
            enabled: None,
            realtime: None,
            signature_version: None,
            signatures_updated_at: None,
            signatures_current: None,
            last_quick_scan: None,
            last_full_scan: None,
            tamper_protection: None,
            actions: vec![],
            detail: None,
        }
    }
}

/// The vendor's rating, Defender's words.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ThreatSeverity {
    Severe,
    High,
    Moderate,
    Low,
    #[serde(other)]
    Unknown,
}

impl ThreatSeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            ThreatSeverity::Severe => "severe",
            ThreatSeverity::High => "high",
            ThreatSeverity::Moderate => "moderate",
            ThreatSeverity::Low => "low",
            ThreatSeverity::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ThreatStatus {
    /// Still on the machine: detected but not dealt with, or the remediation failed.
    Active,
    Quarantined,
    /// Cleaned or deleted.
    Removed,
    /// Blocked before it ran.
    Blocked,
    /// Someone allowed it.
    Allowed,
    #[serde(other)]
    Unknown,
}

impl ThreatStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            ThreatStatus::Active => "active",
            ThreatStatus::Quarantined => "quarantined",
            ThreatStatus::Removed => "removed",
            ThreatStatus::Blocked => "blocked",
            ThreatStatus::Allowed => "allowed",
            ThreatStatus::Unknown => "unknown",
        }
    }
}

/// Something a product found.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Detection {
    /// Stable per product and machine: Defender's DetectionID, or a hash for ClamAV.
    pub id: String,
    pub product: ProductKind,
    /// "Trojan:Win32/Wacatac.B!ml", "Eicar-Signature"...
    pub name: String,
    pub severity: ThreatSeverity,
    pub status: ThreatStatus,
    /// Files (or other resources) it was found in.
    #[serde(default)]
    pub resources: Vec<String>,
    #[serde(default)]
    pub detected_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub process: Option<String>,
    #[serde(default)]
    pub user: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Report {
    pub products: Vec<Product>,
    /// Every detection the products still remember (up to [`MAX_DETECTIONS`]). Ones that
    /// drop out of this list are no longer on the machine.
    #[serde(default)]
    pub detections: Vec<Detection>,
    /// Reading the state failed in a way worth showing (products may still be listed).
    #[serde(default)]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ActionState {
    Running,
    Succeeded,
    Failed,
}

impl ActionState {
    pub fn as_str(self) -> &'static str {
        match self {
            ActionState::Running => "running",
            ActionState::Succeeded => "succeeded",
            ActionState::Failed => "failed",
        }
    }
}

/// Longest action message the agent sends, in bytes.
pub const MESSAGE_MAX: usize = 4096;

// ---------------------------------------------------------------------------
// Sensor (milestones 2-7)
// ---------------------------------------------------------------------------

/// How a rule acts. New rules ship in `Audit`: they record what they would have caught
/// without alerting, until their false-positive rate is known.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum RuleMode {
    Disabled,
    Audit,
    Alert,
    /// Stop it: kill the process or quarantine the file. Only honoured for high-confidence
    /// rules, and only where the policy turns prevention on.
    Block,
}

impl RuleMode {
    pub fn as_str(self) -> &'static str {
        match self {
            RuleMode::Disabled => "disabled",
            RuleMode::Audit => "audit",
            RuleMode::Alert => "alert",
            RuleMode::Block => "block",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "disabled" => RuleMode::Disabled,
            "audit" => RuleMode::Audit,
            "alert" => RuleMode::Alert,
            "block" => RuleMode::Block,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ExclusionKind {
    /// A path prefix, or a glob with `*`.
    Path,
    Sha256,
    /// A rule id: never fires on this client.
    Rule,
    /// A process image path or name: its activity isn't matched against behaviour rules.
    Process,
}

impl ExclusionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ExclusionKind::Path => "path",
            ExclusionKind::Sha256 => "sha256",
            ExclusionKind::Rule => "rule",
            ExclusionKind::Process => "process",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "path" => ExclusionKind::Path,
            "sha256" => ExclusionKind::Sha256,
            "rule" => ExclusionKind::Rule,
            "process" => ExclusionKind::Process,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Exclusion {
    pub kind: ExclusionKind,
    pub value: String,
}

/// What the sensor should do on this machine (the effective security policy). Sent after
/// connecting and whenever a policy, exclusion or rule override changes.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SensorPolicy {
    /// Run the sensor at all.
    pub enabled: bool,
    /// Quick scan every N hours (0 = never).
    #[serde(default)]
    pub quick_scan_hours: u32,
    /// Full scan every N days (0 = never).
    #[serde(default)]
    pub full_scan_days: u32,
    /// Quarantine files that scans find (high and severe findings).
    #[serde(default)]
    pub auto_quarantine: bool,
    /// Honour `Block` on high-confidence rules.
    #[serde(default)]
    pub prevention: bool,
    /// Size of the local telemetry store.
    #[serde(default)]
    pub telemetry_mb: u32,
    /// Plant ransomware decoy files in user folders and alert when they change.
    #[serde(default)]
    pub canaries: bool,
    #[serde(default)]
    pub exclusions: Vec<Exclusion>,
    /// Server overrides of the bundle's rule modes (the kill switch is `Disabled`).
    #[serde(default)]
    pub rule_modes: Vec<(String, RuleMode)>,
}

/// Something the sensor found: a file a scan matched, or behaviour a rule matched.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SensorDetection {
    /// Stable: the same file at the same path, or the same rule on the same process, keeps it.
    pub id: String,
    /// `file` or `behaviour`.
    pub source: String,
    #[serde(default)]
    pub rule_id: Option<String>,
    pub name: String,
    pub severity: ThreatSeverity,
    #[serde(default)]
    pub mitre: Vec<String>,
    pub status: ThreatStatus,
    /// The rule was in audit mode: recorded, not acted on or alerted.
    #[serde(default)]
    pub audit: bool,
    /// `killed`, `quarantined`, or why it couldn't be.
    #[serde(default)]
    pub action_taken: Option<String>,
    #[serde(default)]
    pub resources: Vec<String>,
    #[serde(default)]
    pub sha256: Option<String>,
    #[serde(default)]
    pub process: Option<String>,
    #[serde(default)]
    pub user: Option<String>,
    pub detected_at: DateTime<Utc>,
    #[serde(default)]
    pub content_version: Option<String>,
    /// The process and its ancestors, then related events, for the investigation view.
    #[serde(default)]
    pub context: Vec<crate::telemetry::Event>,
    #[serde(default)]
    pub quarantine_id: Option<uuid::Uuid>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct SensorHealth {
    pub events_total: u64,
    pub events_per_min: f64,
    pub store_bytes: u64,
    /// Of the sensor process, averaged over the last minute.
    pub cpu_percent: f32,
    pub rss_bytes: u64,
    pub rules: u32,
    /// Which mechanism each collector uses (`proc-connector`, `poll`...).
    #[serde(default)]
    pub collectors: Vec<(String, String)>,
    /// Ransomware decoy files in place.
    #[serde(default)]
    pub canaries: u32,
    #[serde(default)]
    pub last_scan: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct SensorStatus {
    /// The policy wants it running.
    pub enabled: bool,
    pub running: bool,
    /// Crashes or unexpected exits since the agent started.
    pub restarts: u32,
    #[serde(default)]
    pub content_version: Option<String>,
    /// Why content or the sensor isn't working.
    #[serde(default)]
    pub error: Option<String>,
    /// The network is isolated (only the management channel open).
    #[serde(default)]
    pub isolated: bool,
    #[serde(default)]
    pub health: Option<SensorHealth>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct QuarantineItem {
    pub id: uuid::Uuid,
    pub path: String,
    pub sha256: String,
    pub size: u64,
    pub quarantined_at: DateTime<Utc>,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub detection_id: Option<String>,
}

/// Something a technician can do to an endpoint. Answered with
/// [`crate::AgentMsg::SecurityActionResult`] like scans.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ResponseAction {
    KillProcess { pid: u32, #[serde(default)] tree: bool },
    QuarantineFile { path: String },
    RestoreFile { id: uuid::Uuid },
    DeleteQuarantined { id: uuid::Uuid },
    /// Block all traffic except to these hosts (the server), DNS and DHCP.
    Isolate { allow: Vec<String> },
    Release,
    /// Gather processes, connections, autoruns, recent telemetry and logs into a zip that
    /// is sent as [`crate::AgentMsg::TriageChunk`]s.
    CollectTriage,
    /// Scan one file or directory with the sensor's content.
    ScanPath { path: String },
}

impl ResponseAction {
    pub fn name(&self) -> &'static str {
        match self {
            ResponseAction::KillProcess { .. } => "kill_process",
            ResponseAction::QuarantineFile { .. } => "quarantine_file",
            ResponseAction::RestoreFile { .. } => "restore_file",
            ResponseAction::DeleteQuarantined { .. } => "delete_quarantined",
            ResponseAction::Isolate { .. } => "isolate",
            ResponseAction::Release => "release",
            ResponseAction::CollectTriage => "collect_triage",
            ResponseAction::ScanPath { .. } => "scan_path",
        }
    }
}

/// Triage packages are sent in pieces this big.
pub const TRIAGE_CHUNK: usize = 512 * 1024;
/// Largest triage package the agent builds.
pub const TRIAGE_MAX: u64 = 64 * 1024 * 1024;

/// Signed bytes of a content bundle: the agent verifies the signature over this with the
/// release key it was built with, so a compromised server can't push its own rules.
pub fn content_signed_message(version: &str, sha256_hex: &str) -> Vec<u8> {
    format!("rmm-content-v1\n{version}\n{}\n", sha256_hex.to_ascii_lowercase()).into_bytes()
}
