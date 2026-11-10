//! Endpoint telemetry (Phase 8, milestone 3): what the sensor records about processes,
//! network connections, files, registry keys and modules.
//!
//! Events stay on the machine, in the sensor's size-capped local store. The server sees them
//! only as context attached to a detection, or when someone queries an agent (or the fleet)
//! during an investigation ([`crate::ServerMsg::TelemetryQuery`]).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    Process,
    Network,
    File,
    Registry,
    Module,
}

impl EventKind {
    pub const ALL: [EventKind; 5] = [EventKind::Process, EventKind::Network, EventKind::File, EventKind::Registry, EventKind::Module];

    pub fn as_str(self) -> &'static str {
        match self {
            EventKind::Process => "process",
            EventKind::Network => "network",
            EventKind::File => "file",
            EventKind::Registry => "registry",
            EventKind::Module => "module",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.as_str() == s)
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Proc {
    pub pid: u32,
    #[serde(default)]
    pub ppid: u32,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exe: Option<String>,
    #[serde(default)]
    pub command_line: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    /// Of the executable image.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileEvent {
    pub path: String,
    /// The previous path of a rename.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub old_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetEvent {
    /// tcp / udp
    pub protocol: String,
    #[serde(default)]
    pub local_addr: String,
    #[serde(default)]
    pub local_port: u16,
    #[serde(default)]
    pub remote_addr: String,
    #[serde(default)]
    pub remote_port: u16,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegEvent {
    pub key: String,
    #[serde(default)]
    pub value: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ModuleEvent {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

/// One thing that happened. `action` says what: `start`/`exit` (process), `connect`/`listen`
/// (network), `create`/`modify`/`delete`/`rename` (file), `set`/`delete` (registry), `load`
/// (module).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Event {
    /// Increasing per sensor run; with `ts` it orders events on one machine.
    #[serde(default)]
    pub seq: u64,
    pub ts: DateTime<Utc>,
    pub kind: EventKind,
    pub action: String,
    /// The process that did it, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process: Option<Proc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<Proc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<FileEvent>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<NetEvent>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registry: Option<RegEvent>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub module: Option<ModuleEvent>,
}

impl Event {
    pub fn new(kind: EventKind, action: &str) -> Self {
        Event {
            seq: 0,
            ts: Utc::now(),
            kind,
            action: action.to_string(),
            process: None,
            parent: None,
            file: None,
            network: None,
            registry: None,
            module: None,
        }
    }
}

/// What to look for in an agent's local store. Every set field must match.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Query {
    #[serde(default)]
    pub since: Option<DateTime<Utc>>,
    #[serde(default)]
    pub until: Option<DateTime<Utc>>,
    /// Empty = every kind.
    #[serde(default)]
    pub kinds: Vec<EventKind>,
    /// Case-insensitive substring of any field (command line, path, address...).
    #[serde(default)]
    pub text: Option<String>,
    #[serde(default)]
    pub pid: Option<u32>,
    /// A file or process image hash.
    #[serde(default)]
    pub sha256: Option<String>,
    /// At most this many, newest first (capped at [`QUERY_MAX`]).
    #[serde(default)]
    pub limit: Option<u32>,
}

pub const QUERY_MAX: u32 = 1000;
