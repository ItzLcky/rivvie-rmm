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
    /// The MSP's branded product name, from the package or the MSI (`enroll --product-name`):
    /// the service is shown as "<product> Agent". `None` keeps "RMM Agent".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub product_name: Option<String>,
}

/// The service's display name: "<product> Agent", or "RMM Agent". One line, at most 80 characters.
pub fn service_display_name(product: Option<&str>) -> String {
    let p: String = product.unwrap_or_default().chars().filter(|c| !c.is_control()).take(60).collect();
    match p.trim() {
        "" => "RMM Agent".into(),
        p => format!("{p} Agent"),
    }
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

/// `enroll --from-file`: what the server bakes into .deb/.rpm packages.
#[derive(Debug, Deserialize)]
pub struct EnrollFile {
    pub server: String,
    pub token: String,
    #[serde(default)]
    pub product_name: Option<String>,
}

impl EnrollFile {
    pub fn load(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        toml::from_str(&raw).with_context(|| format!("parsing {}", path.display()))
    }
}

/// Validates the server URL given at enrollment and strips any trailing slash.
pub fn normalize_server_url(raw: &str, allow_insecure: bool) -> Result<String> {
    let url = raw.trim().trim_end_matches('/');
    if url.starts_with("https://") {
        return Ok(url.to_string());
    }
    let Some(rest) = url.strip_prefix("http://") else {
        anyhow::bail!("server URL must start with https:// (got {url})");
    };
    let authority = rest.split('/').next().unwrap_or_default();
    let host = match authority.strip_prefix('[') {
        Some(v6) => v6.split(']').next().unwrap_or_default(),
        None => authority.split(':').next().unwrap_or_default(),
    };
    let local = host == "localhost" || host == "::1" || host.starts_with("127.");
    if !local && !allow_insecure {
        anyhow::bail!(
            "refusing plain http:// to {host}: the agent secret and scripts would be sent unencrypted. \
             Use https://, or pass --insecure on a trusted lab network"
        );
    }
    Ok(url.to_string())
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

#[cfg(windows)]
fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    if path.parent() == data_dir().as_deref() {
        prepare_data_dir().map_err(std::io::Error::other)?;
    } else {
        tracing::warn!("{} is outside the agent data directory; make sure only SYSTEM can read it", path.display());
    }
    std::fs::write(path, data)
}

/// Where the agent keeps state that must survive restarts and stay away from users: the
/// endpoint protection content, quarantine, telemetry and unsent results. `RMM_STATE_DIR`
/// overrides it (tests run the agent unprivileged).
pub fn state_dir() -> PathBuf {
    if let Some(d) = std::env::var_os("RMM_STATE_DIR") {
        return PathBuf::from(d);
    }
    if cfg!(windows) {
        default_path().parent().map(|p| p.join("state")).unwrap_or_else(|| PathBuf::from("C:\\ProgramData\\RMM\\state"))
    } else if cfg!(target_os = "macos") {
        PathBuf::from("/Library/Application Support/RMM/state")
    } else {
        PathBuf::from("/var/lib/rmm-agent")
    }
}

/// Creates `state_dir()/sub`, readable by the agent's account only (on Windows the data
/// directory's ACL already allows only SYSTEM and Administrators).
pub fn state_subdir(sub: &str) -> Result<PathBuf> {
    let dir = state_dir().join(sub);
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
        let _ = std::fs::set_permissions(state_dir(), std::fs::Permissions::from_mode(0o700));
    }
    Ok(dir)
}

/// Where the agent keeps its config, logs and job scratch files.
#[cfg(windows)]
pub fn data_dir() -> Option<PathBuf> {
    default_path().parent().map(Path::to_path_buf)
}

/// Creates the data directory and restricts it to SYSTEM and Administrators. ProgramData's
/// default ACL lets every local user read subfolders, which would expose the agent secret.
#[cfg(windows)]
pub fn prepare_data_dir() -> Result<PathBuf> {
    let dir = data_dir().context("no data directory")?;
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    let root = std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into());
    let icacls = PathBuf::from(root).join("System32").join("icacls.exe");
    // S-1-5-18 = SYSTEM, S-1-5-32-544 = Administrators. /inheritance:r drops the inherited
    // ACEs (including Users); (OI)(CI) makes the grants apply to everything inside.
    let out = std::process::Command::new(&icacls)
        .arg(&dir)
        .args(["/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F", "/grant:r", "*S-1-5-32-544:(OI)(CI)F", "/q"])
        .output()
        .with_context(|| format!("running {}", icacls.display()))?;
    if !out.status.success() {
        anyhow::bail!(
            "locking down {}: icacls failed: {}",
            dir.display(),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(dir)
}

#[cfg(test)]
mod tests {
    #[test]
    fn server_url_validation() {
        use super::normalize_server_url as n;
        assert_eq!(n("https://rmm.example.com/", false).unwrap(), "https://rmm.example.com");
        assert!(n("http://localhost:8080", false).is_ok());
        assert!(n("http://127.0.0.1:8080/", false).is_ok());
        assert!(n("http://[::1]:8080", false).is_ok());
        assert!(n("http://rmm.example.com", false).is_err());
        assert!(n("http://localhost.evil.com", false).is_err());
        assert!(n("http://rmm.example.com", true).is_ok());
        assert!(n("rmm.example.com", true).is_err());
    }

    #[test]
    fn ws_url_mapping() {
        assert_eq!(super::ws_url("https://a.b/"), "wss://a.b/api/agent/ws");
        assert_eq!(super::ws_url("http://localhost:8080"), "ws://localhost:8080/api/agent/ws");
    }

    #[test]
    fn branded_names() {
        use super::service_display_name as n;
        assert_eq!(n(None), "RMM Agent");
        assert_eq!(n(Some("  ")), "RMM Agent");
        assert_eq!(n(Some("Acme Remote")), "Acme Remote Agent");
        assert_eq!(n(Some("Evil\nName")), "EvilName Agent");
        // Older packages have no product name; older agents ignore the key.
        let f: super::EnrollFile = toml::from_str("server = \"https://x\"\ntoken = \"t\"\n").unwrap();
        assert_eq!(f.product_name, None);
        let f: super::EnrollFile = toml::from_str("server = \"https://x\"\ntoken = \"t\"\nproduct_name = \"Acme\"\n").unwrap();
        assert_eq!(f.product_name.as_deref(), Some("Acme"));
        let c: super::Config = toml::from_str("server_url = \"https://x\"\nagent_id = \"00000000-0000-0000-0000-000000000000\"\nsecret = \"s\"\n").unwrap();
        assert!(c.product_name.is_none() && !toml::to_string(&c).unwrap().contains("product_name"));
    }
}
