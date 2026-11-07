use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Persisted agent state. Written once at enrollment, read on every start.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Base server URL, e.g. `https://rmm.example.com`.
    pub server_url: String,
    pub agent_id: Uuid,
    pub secret: String,
}

pub fn default_path() -> PathBuf {
    if cfg!(windows) {
        let base = std::env::var_os("ProgramData").unwrap_or_else(|| "C:\\ProgramData".into());
        PathBuf::from(base).join("RMM").join("agent.toml")
    } else if cfg!(target_os = "macos") {
        PathBuf::from("/Library/Application Support/RMM/agent.toml")
    } else {
        PathBuf::from("/etc/rmm-agent/agent.toml")
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("reading {} (has this agent been enrolled?)", path.display()))?;
        toml::from_str(&raw).with_context(|| format!("parsing {}", path.display()))
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        }
        let raw = toml::to_string_pretty(self)?;
        write_private(path, raw.as_bytes()).with_context(|| format!("writing {}", path.display()))
    }

    /// `https://host` -> `wss://host/api/agent/ws`
    pub fn ws_url(&self) -> String {
        ws_url(&self.server_url)
    }
}

pub fn ws_url(server_url: &str) -> String {
    let base = server_url.trim_end_matches('/');
    let base = if let Some(rest) = base.strip_prefix("https://") {
        format!("wss://{rest}")
    } else if let Some(rest) = base.strip_prefix("http://") {
        format!("ws://{rest}")
    } else {
        base.to_string()
    };
    format!("{base}/api/agent/ws")
}

/// The config contains the agent secret, so keep it readable by root/SYSTEM only.
#[cfg(unix)]
fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(data)
}

#[cfg(not(unix))]
fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    // ProgramData\RMM inherits an ACL that the installer locks down to SYSTEM/Administrators.
    std::fs::write(path, data)
}

#[cfg(test)]
mod tests {
    #[test]
    fn ws_url_mapping() {
        assert_eq!(super::ws_url("https://a.b/"), "wss://a.b/api/agent/ws");
        assert_eq!(super::ws_url("http://localhost:8080"), "ws://localhost:8080/api/agent/ws");
    }
}
