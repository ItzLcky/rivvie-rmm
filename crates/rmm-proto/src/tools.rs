//! Technician tools that answer one request at a time: the process list and the file
//! browser. The server sends [`crate::ServerMsg::Tool`] and the agent answers with one
//! [`crate::AgentMsg::ToolReply`] per request.
//!
//! Files move in chunks the server asks for (downloads) or sends one at a time, waiting for
//! each to be written (uploads), so neither side buffers a whole file and a slow link only
//! slows the transfer down.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Agents listing this in `Auth.capabilities` understand [`Request`].
pub const CAPABILITY: &str = "tools";

/// The most a [`Request::ReadFile`] returns, and the most a [`Request::WriteFile`] carries.
pub const CHUNK: usize = 512 * 1024;

/// At most this many entries in one directory listing.
pub const LIST_MAX: usize = 10_000;

/// Uploads are written here next to the target, then renamed over it when complete.
pub const UPLOAD_SUFFIX: &str = ".rmm-upload";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    /// Every process: answered with [`Reply::Processes`].
    Processes,
    /// Kill `pid` (and with `tree`, everything started under it, children first).
    Kill { pid: u32, tree: bool },
    /// A directory's entries. An empty path lists the roots: drives on Windows, `/` elsewhere.
    ListDir { path: String },
    /// Up to `len` bytes (at most [`CHUNK`]) from `offset`.
    ReadFile { path: String, offset: u64, len: u32 },
    /// A piece of an upload. The first (`offset` 0) creates the partial file next to `path`,
    /// refusing to replace an existing file unless `overwrite`; `last` moves it into place.
    WriteFile {
        path: String,
        offset: u64,
        #[serde(with = "serde_bytes")]
        data: Vec<u8>,
        last: bool,
        overwrite: bool,
    },
    /// Abandon an upload: remove its partial file.
    AbortWrite { path: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", content = "data", rename_all = "snake_case")]
pub enum Reply {
    Processes(Vec<Process>),
    Killed { message: String },
    Dir(DirListing),
    Chunk {
        #[serde(with = "serde_bytes")]
        data: Vec<u8>,
        /// The file's size when read.
        size: u64,
        eof: bool,
    },
    /// Bytes written so far (the whole file after the `last` piece).
    Written { size: u64 },
    Error(String),
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Process {
    pub pid: u32,
    #[serde(default)]
    pub ppid: Option<u32>,
    pub name: String,
    #[serde(default)]
    pub exe: Option<String>,
    #[serde(default)]
    pub cmd: Option<String>,
    #[serde(default)]
    pub user: Option<String>,
    /// Percent of one core, since the previous sample.
    pub cpu: f32,
    /// Resident memory, bytes.
    pub mem: u64,
    #[serde(default)]
    pub started_at: Option<DateTime<Utc>>,
    /// Never killed by the agent (system and agent processes).
    #[serde(default)]
    pub protected: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct DirListing {
    /// The directory, as the agent resolved it ("" for the roots).
    pub path: String,
    /// Its parent, if it has one.
    #[serde(default)]
    pub parent: Option<String>,
    pub entries: Vec<DirEntry>,
    /// There were more than [`LIST_MAX`] entries.
    #[serde(default)]
    pub truncated: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct DirEntry {
    pub name: String,
    /// The full path to open or download it.
    pub path: String,
    pub dir: bool,
    #[serde(default)]
    pub symlink: bool,
    pub size: u64,
    #[serde(default)]
    pub modified: Option<DateTime<Utc>>,
    /// Couldn't be read (permissions, a broken link).
    #[serde(default)]
    pub error: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        let req = Request::WriteFile { path: "/tmp/x".into(), offset: 0, data: vec![1, 2, 3], last: true, overwrite: false };
        let back: Request = rmp_serde::from_slice(&rmp_serde::to_vec_named(&req).unwrap()).unwrap();
        assert!(matches!(back, Request::WriteFile { data, last: true, .. } if data == [1, 2, 3]));
        let rep = Reply::Chunk { data: vec![9; 10], size: 10, eof: true };
        let back: Reply = rmp_serde::from_slice(&rmp_serde::to_vec_named(&rep).unwrap()).unwrap();
        assert!(matches!(back, Reply::Chunk { eof: true, size: 10, .. }));
        let rep = Reply::Error("nope".into());
        let back: Reply = rmp_serde::from_slice(&rmp_serde::to_vec_named(&rep).unwrap()).unwrap();
        assert!(matches!(back, Reply::Error(e) if e == "nope"));
    }
}
