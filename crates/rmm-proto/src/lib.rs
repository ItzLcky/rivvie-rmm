//! Wire protocol between agent and server.
//!
//! Transport: a single WebSocket per agent (`/api/agent/ws`), carrying
//! MessagePack-encoded binary frames. The first frame from the agent must be
//! [`AgentMsg::Enroll`] or [`AgentMsg::Auth`]; the server answers with
//! [`ServerMsg::Enrolled`], [`ServerMsg::AuthOk`] or [`ServerMsg::AuthFailed`].
//!
//! Everything is multiplexed over that one connection: metrics, jobs,
//! interactive shells and (later) patching and remote desktop streams.

pub mod patch;
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
}

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

/// Small identity block sent at enrollment.
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
    fn old_auth_has_no_capabilities_and_patch_messages_roundtrip() {
        #[derive(Serialize)]
        #[serde(tag = "t", rename_all = "snake_case")]
        enum Old {
            Auth { protocol: u32, agent_id: Uuid, secret: String, agent_version: String },
        }
        let buf = encode(&Old::Auth { protocol: 1, agent_id: Uuid::nil(), secret: "s".into(), agent_version: "0.1.0".into() }).unwrap();
        match decode::<AgentMsg>(&buf).unwrap() {
            AgentMsg::Auth { capabilities, patch_runs, jobs, .. } => assert!(capabilities.is_empty() && patch_runs.is_empty() && jobs.is_empty()),
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
        };
        let buf = encode(&Old::Enroll { protocol: 1, token: "t".into(), system }).unwrap();
        assert!(matches!(decode::<AgentMsg>(&buf).unwrap(), AgentMsg::Enroll { previous: None, .. }));
    }
}
