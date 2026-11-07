//! Wire protocol between agent and server.
//!
//! Transport: a single WebSocket per agent (`/api/agent/ws`), carrying
//! MessagePack-encoded binary frames. The first frame from the agent must be
//! [`AgentMsg::Enroll`] or [`AgentMsg::Auth`]; the server answers with
//! [`ServerMsg::Enrolled`], [`ServerMsg::AuthOk`] or [`ServerMsg::AuthFailed`].
//!
//! Everything is multiplexed over that one connection: metrics, jobs,
//! interactive shells and (later) patching and remote desktop streams.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Bumped on breaking wire changes; the server rejects agents it can't speak to.
pub const PROTOCOL_VERSION: u32 = 1;

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
    },
    /// Reconnect of an already enrolled agent.
    Auth {
        protocol: u32,
        agent_id: Uuid,
        secret: String,
        agent_version: String,
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
}
