//! Wire protocol between agent and server.
//!
//! Transport: a single WebSocket per agent (`/api/agent/ws`), carrying
//! MessagePack-encoded binary frames. The first frame from the agent must be
//! [`AgentMsg::Enroll`] or [`AgentMsg::Auth`]; the server answers with
//! [`ServerMsg::Enrolled`], [`ServerMsg::AuthOk`] or [`ServerMsg::AuthFailed`].
//!
//! Everything is multiplexed over that one connection: metrics, jobs,
//! interactive shells, patching, remote desktop streams and endpoint protection.

pub mod desktop;
pub mod patch;
pub mod security;
pub mod telemetry;
pub mod tools;
pub mod update;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Bumped on breaking wire changes; the server rejects agents it can't speak to.
pub const PROTOCOL_VERSION: u32 = 1;

/// Output the agent keeps per job stream so it can resend it after a reconnect. Matches the
/// server's storage cap, so nothing the server would keep is lost.
pub const JOB_OUTPUT_BUFFER: usize = 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum CodecError {
    #[error("encode: {0}")]
    Encode(#[from] rmp_serde::encode::Error),
    #[error("decode: {0}")]
    Decode(#[from] rmp_serde::decode::Error),
}

pub fn encode<T: Serialize>(msg: &T) -> Result<Vec<u8>, CodecError> {
    // Named (map) encoding so fields can be added without breaking old peers.
    Ok(rmp_serde::to_vec_named(msg)?)
}

pub fn decode<'a, T: Deserialize<'a>>(buf: &'a [u8]) -> Result<T, CodecError> {
    Ok(rmp_serde::from_slice(buf)?)
}

// ---------------------------------------------------------------------------
// Agent -> Server
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum AgentMsg {
    /// First-time registration with a one-time/limited enrollment token.
    Enroll {
        protocol: u32,
        token: String,
        system: SystemInfo,
        /// The credential from a previous enrollment of this machine, if it still has one.
        /// Only a valid one lets the server reuse the existing agent record; a bare token
        /// always creates a new record, so a leaked token can't take over existing agents.
        #[serde(default)]
        previous: Option<PreviousCredential>,
    },
    /// Reconnect of an already enrolled agent.
    Auth {
        protocol: u32,
        agent_id: Uuid,
        secret: String,
        agent_version: String,
        /// Jobs this agent still holds (running, or finished but not acknowledged). Any job
        /// the server thinks was dispatched to it and isn't listed can never report: the
        /// agent restarted, or the job never arrived. Agents that predate this send nothing.
        #[serde(default)]
        jobs: Vec<Uuid>,
        /// Optional features this build supports ([`patch::CAPABILITY`]...). The server
        /// doesn't send messages for a feature the agent didn't list.
        #[serde(default)]
        capabilities: Vec<String>,
        /// Patch installs still running or awaiting [`ServerMsg::PatchAck`], like `jobs`.
        #[serde(default)]
        patch_runs: Vec<Uuid>,
        /// Security actions still running, or finished and not yet reported to this server.
        #[serde(default)]
        security_actions: Vec<Uuid>,
    },
    Heartbeat(Metrics),
    Inventory(Inventory),
    JobOutput {
        job_id: Uuid,
        stream: OutputStream,
        #[serde(with = "serde_bytes")]
        data: Vec<u8>,
    },
    JobFinished {
        job_id: Uuid,
        status: JobStatus,
        exit_code: Option<i32>,
        duration_ms: u64,
    },
    /// After a reconnect: the job's output so far, replacing whatever the server stored.
    /// Chunks sent on the old connection may have been lost; live `JobOutput` continues
    /// after this. Capped by the agent at [`JOB_OUTPUT_BUFFER`] per stream.
    JobSync {
        job_id: Uuid,
        #[serde(with = "serde_bytes")]
        stdout: Vec<u8>,
        #[serde(with = "serde_bytes")]
        stderr: Vec<u8>,
    },
    /// Next piece of an offered update: the server answers with [`ServerMsg::UpdateChunk`].
    UpdateFetch {
        version: String,
        offset: u64,
    },
    /// Progress of a self-update, for the dashboard.
    UpdateStatus {
        version: String,
        state: UpdateState,
        #[serde(default)]
        detail: Option<String>,
    },
    ShellOpened {
        session_id: Uuid,
    },
    ShellOutput {
        session_id: Uuid,
        #[serde(with = "serde_bytes")]
        data: Vec<u8>,
    },
    ShellClosed {
        session_id: Uuid,
        reason: Option<String>,
    },
    Pong {
        nonce: u64,
    },
    /// Every service on the machine (systemd units / Windows services). Sent after connecting,
    /// when anything changes, and after a [`ServerMsg::ServiceControl`].
    Services {
        services: Vec<ServiceInfo>,
    },
    /// Answer to [`ServerMsg::ServiceControl`].
    ServiceControlResult {
        request_id: Uuid,
        ok: bool,
        message: String,
    },
    /// Log entries that matched a [`LogWatcher`]. `suppressed` counts further matches dropped
    /// by the agent's rate limit since the previous batch.
    LogMatches {
        watcher_id: Uuid,
        entries: Vec<LogEntry>,
        #[serde(default)]
        suppressed: u32,
    },
    /// Answer to [`ServerMsg::PatchScan`], and sent unasked after every install.
    PatchScanResult {
        /// The scan request this answers; `None` for the rescan after an install.
        #[serde(default)]
        request_id: Option<Uuid>,
        /// Which provider scanned: `wua`, `pswindowsupdate`, `apt`, `dnf`, `pacman`, `softwareupdate`.
        provider: String,
        /// The provider can only install everything at once (pacman).
        #[serde(default)]
        all_or_nothing: bool,
        /// The scan failed; `updates` is then empty and means nothing.
        #[serde(default)]
        error: Option<String>,
        updates: Vec<patch::PatchUpdate>,
        /// A reboot is pending from an earlier install.
        #[serde(default)]
        reboot_pending: bool,
    },
    PatchProgress {
        run_id: Uuid,
        stage: patch::PatchStage,
        #[serde(default)]
        message: Option<String>,
        /// Overall percentage, when the provider knows it.
        #[serde(default)]
        percent: Option<u8>,
    },
    PatchResult(patch::PatchOutcome),
    /// The session's monitors and which one is shown. Sent first, and again when either changes.
    DesktopInfo {
        session_id: Uuid,
        monitors: Vec<desktop::Monitor>,
        monitor: u32,
    },
    DesktopFrame {
        session_id: Uuid,
        frame: desktop::Frame,
    },
    /// The session ended (or never started): declined by the user, no desktop to show, the
    /// capture failed...
    DesktopClosed {
        session_id: Uuid,
        reason: Option<String>,
    },
    /// Protection status. Sent after connecting, when it changes, and when asked.
    SecurityStatus(security::Report),
    /// A [`ServerMsg::SecurityAction`] or [`ServerMsg::Response`] started (`Running`) or ended.
    SecurityActionResult {
        request_id: Uuid,
        state: security::ActionState,
        #[serde(default)]
        message: Option<String>,
        /// Structured result, as JSON (a response action's details).
        #[serde(default)]
        data: Option<String>,
    },
    /// The sensor's state. Sent after connecting, when it changes, and every few minutes.
    SensorStatus(security::SensorStatus),
    /// A sensor finding. Kept by the agent and resent until [`ServerMsg::SensorDetectionAck`].
    SensorDetection(security::SensorDetection),
    /// Every file in quarantine on this machine. Sent after connecting and on every change.
    QuarantineList {
        items: Vec<security::QuarantineItem>,
    },
    /// Answer to [`ServerMsg::TelemetryQuery`].
    TelemetryResult {
        request_id: Uuid,
        events: Vec<telemetry::Event>,
        #[serde(default)]
        truncated: bool,
        #[serde(default)]
        error: Option<String>,
    },
    /// A piece of a triage package ([`security::ResponseAction::CollectTriage`]).
    TriageChunk {
        request_id: Uuid,
        offset: u64,
        #[serde(with = "serde_bytes")]
        data: Vec<u8>,
        done: bool,
    },
    /// Answer to [`ServerMsg::Tool`].
    ToolReply {
        request_id: Uuid,
        reply: tools::Reply,
    },
    /// Hashes of programs this machine ran that its own database doesn't know, each asked once
    /// (at most [`security::REPUTATION_BATCH`]); only sent when the policy says the server
    /// answers ([`security::SensorPolicy::reputation`]). Answered with
    /// [`ServerMsg::ReputationResult`].
    ReputationQuery {
        hashes: Vec<security::HashSeen>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreviousCredential {
    pub agent_id: Uuid,
    pub secret: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OutputStream {
    Stdout,
    Stderr,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum JobStatus {
    Succeeded,
    Failed,
    TimedOut,
    Error,
}

impl JobStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            JobStatus::Succeeded => "succeeded",
            JobStatus::Failed => "failed",
            JobStatus::TimedOut => "timed_out",
            JobStatus::Error => "error",
        }
    }
}

// ---------------------------------------------------------------------------
// Server -> Agent
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum ServerMsg {
    Enrolled {
        agent_id: Uuid,
        /// Long-lived agent credential. Only ever sent once; server stores a hash.
        secret: String,
    },
    AuthOk {
        heartbeat_secs: u32,
        inventory_secs: u32,
    },
    AuthFailed {
        reason: String,
    },
    RequestInventory,
    RunScript(ScriptJob),
    /// The server has stored this job's `JobFinished`; the agent can forget the job.
    JobAck {
        job_id: Uuid,
    },
    /// Install this version. The agent checks the signature against its built-in key and
    /// refuses anything that isn't newer than itself.
    UpdateOffer {
        version: String,
        size: u64,
        sha256: String,
        signature: String,
    },
    UpdateChunk {
        version: String,
        offset: u64,
        #[serde(with = "serde_bytes")]
        data: Vec<u8>,
    },
    ShellOpen {
        session_id: Uuid,
        cols: u16,
        rows: u16,
    },
    ShellInput {
        session_id: Uuid,
        #[serde(with = "serde_bytes")]
        data: Vec<u8>,
    },
    ShellResize {
        session_id: Uuid,
        cols: u16,
        rows: u16,
    },
    ShellClose {
        session_id: Uuid,
    },
    Ping {
        nonce: u64,
    },
    /// Send a fresh [`AgentMsg::Services`].
    RequestServices,
    /// Start, stop or restart a service; the agent answers with [`AgentMsg::ServiceControlResult`].
    ServiceControl {
        request_id: Uuid,
        name: String,
        action: ServiceAction,
    },
    /// The complete set of log watchers for this agent, replacing any earlier set. Sent after
    /// connecting and whenever an alert policy changes.
    Watchers {
        watchers: Vec<LogWatcher>,
    },
    /// Look for available updates; answered with [`AgentMsg::PatchScanResult`].
    PatchScan {
        request_id: Uuid,
    },
    /// Install these updates (ids from a scan). Answered with progress, then
    /// [`AgentMsg::PatchResult`].
    PatchInstall {
        run_id: Uuid,
        ids: Vec<String>,
        reboot_policy: patch::RebootPolicy,
    },
    /// The server has stored this install's result; the agent can forget it.
    PatchAck {
        run_id: Uuid,
    },
    /// Start a remote desktop session (only sent to agents listing [`desktop::CAPABILITY`]).
    DesktopOpen {
        session_id: Uuid,
        settings: desktop::Settings,
        /// Ask the person at the machine first.
        #[serde(default)]
        consent: Option<desktop::Consent>,
    },
    DesktopSettings {
        session_id: Uuid,
        settings: desktop::Settings,
    },
    DesktopInput {
        session_id: Uuid,
        events: Vec<desktop::InputEvent>,
    },
    /// The browser has drawn frame `seq` (and everything before it).
    DesktopAck {
        session_id: Uuid,
        seq: u32,
    },
    DesktopClose {
        session_id: Uuid,
    },
    /// Send a fresh [`AgentMsg::SecurityStatus`] (only to agents listing [`security::CAPABILITY`]).
    SecurityRefresh,
    /// Start a scan or signature update with one product; answered with
    /// [`AgentMsg::SecurityActionResult`].
    SecurityAction {
        request_id: Uuid,
        product: security::ProductKind,
        action: security::Action,
    },
    /// The content bundle (rules and hashes) to run: JSON, with an ed25519 signature over
    /// [`security::content_signed_message`].
    Content {
        version: String,
        #[serde(with = "serde_bytes")]
        bundle: Vec<u8>,
        signature: String,
    },
    SensorPolicy(security::SensorPolicy),
    /// The signature database to run (only to agents listing [`security::SIGDB_CAPABILITY`]);
    /// `None` means none (every version was rolled back). The file comes over HTTPS, not this
    /// socket.
    Database {
        offer: Option<security::DatabaseOffer>,
    },
    /// The server stored this detection.
    SensorDetectionAck {
        id: String,
    },
    /// A response action; answered with [`AgentMsg::SecurityActionResult`].
    Response {
        request_id: Uuid,
        action: security::ResponseAction,
    },
    TelemetryQuery {
        request_id: Uuid,
        query: telemetry::Query,
    },
    /// A process list, kill or file operation (only to agents listing [`tools::CAPABILITY`]);
    /// answered with [`AgentMsg::ToolReply`].
    Tool {
        request_id: Uuid,
        request: tools::Request,
    },
    /// The hashes of a [`AgentMsg::ReputationQuery`] the server knows as malicious.
    ReputationResult {
        known: Vec<security::HashKnown>,
    },
}

// ---------------------------------------------------------------------------
// Services and logs
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ServiceState {
    Running,
    Stopped,
    /// systemd `failed`.
    Failed,
    Starting,
    Stopping,
    Paused,
    #[serde(other)]
    Unknown,
}

impl ServiceState {
    pub fn as_str(self) -> &'static str {
        match self {
            ServiceState::Running => "running",
            ServiceState::Stopped => "stopped",
            ServiceState::Failed => "failed",
            ServiceState::Starting => "starting",
            ServiceState::Stopping => "stopping",
            ServiceState::Paused => "paused",
            ServiceState::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum StartMode {
    /// systemd `enabled`, Windows Automatic (including delayed and boot/system drivers).
    Auto,
    /// Started on demand or by another unit (systemd `static`, `indirect`...).
    Manual,
    Disabled,
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct ServiceInfo {
    /// Unit name (`nginx.service`) or Windows service name (`Spooler`).
    pub name: String,
    pub display_name: String,
    pub state: ServiceState,
    pub start_mode: StartMode,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ServiceAction {
    Start,
    Stop,
    Restart,
}

impl ServiceAction {
    pub fn as_str(self) -> &'static str {
        match self {
            ServiceAction::Start => "start",
            ServiceAction::Stop => "stop",
            ServiceAction::Restart => "restart",
        }
    }
}

/// Severity, most severe first, so `level <= min_level` means "at least this severe".
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "snake_case")]
pub enum LogLevel {
    Critical,
    Error,
    Warning,
    Info,
}

impl LogLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            LogLevel::Critical => "critical",
            LogLevel::Error => "error",
            LogLevel::Warning => "warning",
            LogLevel::Info => "info",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "critical" => LogLevel::Critical,
            "error" => LogLevel::Error,
            "warning" => LogLevel::Warning,
            "info" => LogLevel::Info,
            _ => return None,
        })
    }

    /// syslog/journald priority (0 emerg ... 7 debug).
    pub fn from_syslog(p: u8) -> Self {
        match p {
            0..=2 => LogLevel::Critical,
            3 => LogLevel::Error,
            4 => LogLevel::Warning,
            _ => LogLevel::Info,
        }
    }

    /// Windows event `Level` (1 critical, 2 error, 3 warning, 4/0 information, 5 verbose).
    pub fn from_windows(l: u8) -> Self {
        match l {
            1 => LogLevel::Critical,
            2 => LogLevel::Error,
            3 => LogLevel::Warning,
            _ => LogLevel::Info,
        }
    }
}

/// What to watch for in the system log (journald on Linux, the Event Log on Windows).
/// Every set condition must hold for an entry to match.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LogWatcher {
    pub id: Uuid,
    /// Windows event log channels (`System`, `Application`, ...). Ignored on Linux, where
    /// the whole journal is read.
    #[serde(default)]
    pub channels: Vec<String>,
    /// systemd units or syslog identifiers on Linux, event providers on Windows. Empty = any.
    #[serde(default)]
    pub sources: Vec<String>,
    /// Windows event ids. Empty = any (and always on Linux).
    #[serde(default)]
    pub event_ids: Vec<u32>,
    /// Least severe level that matches.
    pub min_level: LogLevel,
    /// Regular expression (`regex-lite` syntax) the message must match. Case-insensitive.
    #[serde(default)]
    pub pattern: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LogEntry {
    pub ts: DateTime<Utc>,
    pub level: LogLevel,
    /// Unit, syslog identifier or event provider.
    pub source: String,
    /// Windows event id.
    #[serde(default)]
    pub event_id: Option<u32>,
    pub message: String,
}

/// Longest log message the agent sends, in bytes.
pub const LOG_MESSAGE_MAX: usize = 4096;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UpdateState {
    Downloading,
    /// Downloaded and verified; waiting for running jobs to finish before restarting.
    Waiting,
    /// Restarting into the new version.
    Applying,
    /// The new version is running and connected.
    Completed,
    /// The new version didn't connect in time; the previous one was restored.
    RolledBack,
    Failed,
}

impl UpdateState {
    pub fn as_str(self) -> &'static str {
        match self {
            UpdateState::Downloading => "downloading",
            UpdateState::Waiting => "waiting",
            UpdateState::Applying => "applying",
            UpdateState::Completed => "completed",
            UpdateState::RolledBack => "rolled_back",
            UpdateState::Failed => "failed",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScriptJob {
    pub job_id: Uuid,
    pub interpreter: Interpreter,
    pub script: String,
    #[serde(default)]
    pub args: Vec<String>,
    pub timeout_secs: u32,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Interpreter {
    /// `/bin/sh` on unix. Not available on Windows.
    Sh,
    Bash,
    /// `powershell.exe` on Windows, `pwsh` elsewhere.
    PowerShell,
    /// `cmd.exe`, Windows only.
    Cmd,
    Python,
}

// ---------------------------------------------------------------------------
// Data payloads
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OsFamily {
    Linux,
    Windows,
    Macos,
    Other,
}

impl OsFamily {
    pub fn current() -> Self {
        if cfg!(target_os = "linux") {
            OsFamily::Linux
        } else if cfg!(target_os = "windows") {
            OsFamily::Windows
        } else if cfg!(target_os = "macos") {
            OsFamily::Macos
        } else {
            OsFamily::Other
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            OsFamily::Linux => "linux",
            OsFamily::Windows => "windows",
            OsFamily::Macos => "macos",
            OsFamily::Other => "other",
        }
    }
}

/// Workstation or server, as the agent sees its machine (it picks the device category).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Platform {
    Workstation,
    Server,
}

impl Platform {
    pub fn as_str(self) -> &'static str {
        match self {
            Platform::Workstation => "workstation",
            Platform::Server => "server",
        }
    }
}

/// Small identity block sent at enrollment (and inside every inventory).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemInfo {
    pub hostname: String,
    pub os_family: OsFamily,
    pub os_name: String,
    pub os_version: String,
    pub kernel_version: String,
    pub arch: String,
    pub agent_version: String,
    /// Stable machine id (/etc/machine-id, MachineGuid, IOPlatformUUID).
    pub machine_id: Option<String>,
    /// None from builds that predate it (the server then guesses from the OS name).
    #[serde(default)]
    pub platform: Option<Platform>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Metrics {
    pub ts: DateTime<Utc>,
    pub uptime_secs: u64,
    pub cpu_percent: f32,
    pub load_avg: Option<[f64; 3]>,
    pub mem_total: u64,
    pub mem_used: u64,
    pub swap_total: u64,
    pub swap_used: u64,
    pub disks: Vec<DiskUsage>,
    pub net_rx_bytes: u64,
    pub net_tx_bytes: u64,
    pub process_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskUsage {
    pub mount: String,
    pub total: u64,
    pub available: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Inventory {
    pub collected_at: DateTime<Utc>,
    pub system: SystemInfo,
    pub cpu_brand: String,
    pub cpu_cores_physical: Option<u32>,
    pub cpu_cores_logical: u32,
    pub mem_total: u64,
    pub disks: Vec<DiskInfo>,
    pub network: Vec<NetInterface>,
    pub software: Vec<Software>,
    pub logged_in_users: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskInfo {
    pub name: String,
    pub mount: String,
    pub fs: String,
    pub kind: String,
    pub removable: bool,
    pub total: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetInterface {
    pub name: String,
    pub mac: String,
    pub addrs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Software {
    pub name: String,
    pub version: String,
    pub publisher: Option<String>,
    /// e.g. "dpkg", "rpm", "pacman", "registry", "msi".
    pub source: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_shell_output() {
        let id = Uuid::new_v4();
        let msg = AgentMsg::ShellOutput { session_id: id, data: b"hello\x1b[0m".to_vec() };
        let buf = encode(&msg).unwrap();
        match decode::<AgentMsg>(&buf).unwrap() {
            AgentMsg::ShellOutput { session_id, data } => {
                assert_eq!(session_id, id);
                assert_eq!(data, b"hello\x1b[0m");
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn roundtrip_run_script() {
        let msg = ServerMsg::RunScript(ScriptJob {
            job_id: Uuid::new_v4(),
            interpreter: Interpreter::PowerShell,
            script: "Get-Date".into(),
            args: vec![],
            timeout_secs: 30,
        });
        let buf = encode(&msg).unwrap();
        assert!(matches!(decode::<ServerMsg>(&buf).unwrap(), ServerMsg::RunScript(_)));
    }

    #[test]
    fn system_info_without_platform_decodes() {
        // What builds before platform reporting send.
        #[derive(Serialize)]
        struct Old {
            hostname: &'static str,
            os_family: OsFamily,
            os_name: &'static str,
            os_version: &'static str,
            kernel_version: &'static str,
            arch: &'static str,
            agent_version: &'static str,
            machine_id: Option<String>,
        }
        let old = Old { hostname: "h", os_family: OsFamily::Windows, os_name: "Windows", os_version: "", kernel_version: "", arch: "x86_64", agent_version: "0.1.0", machine_id: None };
        let s: SystemInfo = decode(&encode(&old).unwrap()).unwrap();
        assert_eq!((s.hostname.as_str(), s.platform), ("h", None));
        let new = SystemInfo { platform: Some(Platform::Server), ..s };
        assert_eq!(decode::<SystemInfo>(&encode(&new).unwrap()).unwrap().platform, Some(Platform::Server));
    }

    #[test]
    fn unknown_service_state_decodes() {
        #[derive(Serialize)]
        struct Raw {
            name: &'static str,
            display_name: &'static str,
            state: &'static str,
            start_mode: &'static str,
        }
        let buf = encode(&Raw { name: "x", display_name: "", state: "reloading-ish", start_mode: "weird" }).unwrap();
        let s: ServiceInfo = decode(&buf).unwrap();
        assert_eq!((s.state, s.start_mode), (ServiceState::Unknown, StartMode::Unknown));
    }

    #[test]
    fn old_sensor_policies_mean_no_realtime_and_reputation_roundtrips() {
        // A server that predates real-time protection and reputation sends neither field.
        #[derive(Serialize)]
        struct Old {
            enabled: bool,
        }
        let p: security::SensorPolicy = decode(&encode(&Old { enabled: true }).unwrap()).unwrap();
        assert_eq!((p.realtime, p.scan_on_write, p.archive_depth, p.reputation), (security::RealtimeMode::Off, false, 0, false));
        let q = AgentMsg::ReputationQuery { hashes: vec![security::HashSeen { sha256: "ab".repeat(32), path: Some("/usr/bin/x".into()) }] };
        match decode::<AgentMsg>(&encode(&q).unwrap()).unwrap() {
            AgentMsg::ReputationQuery { hashes } => assert_eq!(hashes[0].path.as_deref(), Some("/usr/bin/x")),
            other => panic!("{other:?}"),
        }
        let r = ServerMsg::ReputationResult {
            known: vec![security::HashKnown { sha256: "ab".repeat(32), name: "X".into(), severity: security::ThreatSeverity::High, source: "list:x".into() }],
        };
        assert!(matches!(decode::<ServerMsg>(&encode(&r).unwrap()).unwrap(), ServerMsg::ReputationResult { known } if known[0].source == "list:x"));
        assert_eq!(security::RealtimeMode::parse("block").map(security::RealtimeMode::as_str), Some("block"));
    }

    #[test]
    fn log_levels_order_by_severity() {
        assert!(LogLevel::Critical < LogLevel::Error && LogLevel::Warning < LogLevel::Info);
        assert_eq!(LogLevel::from_syslog(3), LogLevel::Error);
        assert_eq!(LogLevel::from_windows(3), LogLevel::Warning);
    }

    #[test]
    fn old_auth_has_no_capabilities_and_patch_messages_roundtrip() {
        #[derive(Serialize)]
        #[serde(tag = "t", rename_all = "snake_case")]
        enum Old {
            Auth { protocol: u32, agent_id: Uuid, secret: String, agent_version: String },
        }
        let buf = encode(&Old::Auth { protocol: 1, agent_id: Uuid::nil(), secret: "s".into(), agent_version: "0.1.0".into() }).unwrap();
        match decode::<AgentMsg>(&buf).unwrap() {
            AgentMsg::Auth { capabilities, patch_runs, jobs, security_actions, .. } => {
                assert!(capabilities.is_empty() && patch_runs.is_empty() && jobs.is_empty() && security_actions.is_empty())
            }
            other => panic!("unexpected {other:?}"),
        }
        let run_id = Uuid::new_v4();
        let msg = ServerMsg::PatchInstall { run_id, ids: vec!["openssl".into()], reboot_policy: patch::RebootPolicy::IfRequired };
        match decode::<ServerMsg>(&encode(&msg).unwrap()).unwrap() {
            ServerMsg::PatchInstall { run_id: r, ids, reboot_policy } => {
                assert_eq!((r, ids.as_slice(), reboot_policy), (run_id, &["openssl".to_string()][..], patch::RebootPolicy::IfRequired))
            }
            other => panic!("unexpected {other:?}"),
        }
        let out = patch::PatchOutcome {
            run_id,
            results: vec![patch::PatchItemResult { id: "openssl".into(), ok: true, message: None }],
            error: None,
            reboot_required: true,
            rebooting: false,
            output: "done".into(),
            duration_ms: 5,
        };
        match decode::<AgentMsg>(&encode(&AgentMsg::PatchResult(out.clone())).unwrap()).unwrap() {
            AgentMsg::PatchResult(o) => assert_eq!(o, out),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn security_messages_roundtrip() {
        use security::*;
        let mut p = Product::new(ProductKind::Defender, "Microsoft Defender Antivirus");
        p.enabled = Some(true);
        p.actions = vec![Action::QuickScan, Action::UpdateSignatures];
        let report = Report {
            products: vec![p],
            detections: vec![Detection {
                id: "{1}".into(),
                product: ProductKind::Defender,
                name: "Virus:DOS/EICAR_Test_File".into(),
                severity: ThreatSeverity::Severe,
                status: ThreatStatus::Quarantined,
                resources: vec!["file:_C:\\eicar.com".into()],
                detected_at: None,
                process: None,
                user: None,
            }],
            error: None,
        };
        match decode::<AgentMsg>(&encode(&AgentMsg::SecurityStatus(report.clone())).unwrap()).unwrap() {
            AgentMsg::SecurityStatus(r) => assert_eq!(r, report),
            other => panic!("unexpected {other:?}"),
        }
        let msg = ServerMsg::SecurityAction { request_id: Uuid::nil(), product: ProductKind::Clamav, action: Action::FullScan };
        assert!(matches!(
            decode::<ServerMsg>(&encode(&msg).unwrap()).unwrap(),
            ServerMsg::SecurityAction { product: ProductKind::Clamav, action: Action::FullScan, .. }
        ));
        // A product kind from a newer agent decodes as Other rather than failing the report.
        #[derive(Serialize)]
        struct Raw {
            kind: &'static str,
            name: &'static str,
        }
        let p: Product = decode(&encode(&Raw { kind: "sentinelone", name: "x" }).unwrap()).unwrap();
        assert_eq!(p.kind, ProductKind::Other);
    }

    /// Agents built before `previous` existed must still be able to enroll.
    #[test]
    fn enroll_without_previous_decodes() {
        #[derive(Serialize)]
        #[serde(tag = "t", rename_all = "snake_case")]
        enum Old {
            Enroll { protocol: u32, token: String, system: SystemInfo },
        }
        let system = SystemInfo {
            hostname: "h".into(),
            os_family: OsFamily::Linux,
            os_name: String::new(),
            os_version: String::new(),
            kernel_version: String::new(),
            arch: String::new(),
            machine_id: None,
            agent_version: String::new(),
            platform: None,
        };
        let buf = encode(&Old::Enroll { protocol: 1, token: "t".into(), system }).unwrap();
        assert!(matches!(decode::<AgentMsg>(&buf).unwrap(), AgentMsg::Enroll { previous: None, .. }));
    }
}
