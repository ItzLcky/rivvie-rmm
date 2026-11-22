//! Software deployment payloads.
//!
//! The server asks for a scan ([`crate::ServerMsg::SoftwareScan`]) naming the catalog packages
//! it cares about, and the agent answers with [`crate::AgentMsg::SoftwareScanResult`]: what is
//! installed and what newer version is on offer. A run ([`crate::ServerMsg::SoftwareRun`])
//! installs, upgrades or removes one package; it streams [`crate::AgentMsg::SoftwareProgress`]
//! and ends with [`crate::AgentMsg::SoftwareResult`], which the agent keeps and resends after
//! reconnects until the server's [`crate::ServerMsg::SoftwareAck`] (like patch installs).

use std::cmp::Ordering;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Capability an agent lists in `Auth` when it understands the software messages.
pub const CAPABILITY: &str = "software";

/// Longest run log the agent sends, in bytes.
pub const OUTPUT_MAX: usize = 128 * 1024;

/// What a run does to the package.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Op {
    /// Install it (at the package's pinned version, else the latest).
    Install,
    /// Bring an installed package to the pinned version, else the latest.
    Upgrade,
    Uninstall,
}

impl Op {
    pub fn as_str(self) -> &'static str {
        match self {
            Op::Install => "install",
            Op::Upgrade => "upgrade",
            Op::Uninstall => "uninstall",
        }
    }

    pub fn parse(s: &str) -> Option<Op> {
        Some(match s {
            "install" => Op::Install,
            "upgrade" => Op::Upgrade,
            "uninstall" => Op::Uninstall,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum InstallerKind {
    Msi,
    Exe,
}

impl InstallerKind {
    pub fn as_str(self) -> &'static str {
        match self {
            InstallerKind::Msi => "msi",
            InstallerKind::Exe => "exe",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "msi" => Some(InstallerKind::Msi),
            "exe" => Some(InstallerKind::Exe),
            _ => None,
        }
    }
}

/// An uploaded MSI or EXE the agent downloads from the server and checks against `sha256`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Installer {
    pub kind: InstallerKind,
    pub size: u64,
    /// Lowercase hex.
    pub sha256: String,
    /// Arguments for a silent install, split on whitespace (double quotes group).
    pub silent_args: String,
    /// How to remove it: for an MSI the product code (`{GUID}`) is enough; for an EXE a full
    /// command line.
    #[serde(default)]
    pub uninstall_cmd: Option<String>,
    #[serde(default)]
    pub product_code: Option<String>,
    /// Matches the DisplayName of its entry under Uninstall, to tell whether it's installed
    /// (when there's no product code).
    #[serde(default)]
    pub detect_name: Option<String>,
}

/// A catalog package as the agent sees it: the ways to handle it on each platform. The agent
/// uses the first it can: winget, Chocolatey, then the uploaded installer on Windows; apt, then
/// dnf/yum on Linux.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Package {
    pub id: Uuid,
    pub name: String,
    /// Pinned version; `None` means the latest.
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub winget: Option<String>,
    #[serde(default)]
    pub choco: Option<String>,
    #[serde(default)]
    pub apt: Option<String>,
    #[serde(default)]
    pub dnf: Option<String>,
    #[serde(default)]
    pub installer: Option<Installer>,
}

/// What a scan found for one package.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Status {
    pub package_id: Uuid,
    /// Installed version; `None` when it isn't installed.
    #[serde(default)]
    pub installed: Option<String>,
    /// A newer version on offer from the package manager.
    #[serde(default)]
    pub available: Option<String>,
    /// Which provider answered (`winget`, `choco`, `apt`, `dnf`, `installer`), if any could.
    #[serde(default)]
    pub provider: Option<String>,
}

/// The end of a run.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Outcome {
    pub run_id: Uuid,
    pub ok: bool,
    #[serde(default)]
    pub message: Option<String>,
    /// Provider that did the work.
    #[serde(default)]
    pub provider: Option<String>,
    /// What is installed afterwards (`None`: not installed, or unknown).
    #[serde(default)]
    pub installed_version: Option<String>,
    #[serde(default)]
    pub reboot_required: bool,
    /// Package manager output, capped at [`OUTPUT_MAX`].
    #[serde(default)]
    pub output: String,
    pub duration_ms: u64,
}

/// Package ids and versions end up on command lines, so only the characters real ones use are
/// allowed, and never a leading `-` (an option). Both ends check this.
pub fn valid_token(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 200
        && !s.starts_with('-')
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'+' | b'-' | b':' | b'~'))
}

/// Orders two version strings the way package versions usually behave: numeric runs compare as
/// numbers, other runs as text, case-insensitively; a version that is a prefix of another
/// (`1.2` vs `1.2.1`) is older. Epochs (`1:`) and Debian revisions are treated as more segments.
pub fn compare_versions(a: &str, b: &str) -> Ordering {
    fn parts(s: &str) -> Vec<Part> {
        let mut out = Vec::new();
        let mut chars = s.trim().trim_start_matches(['v', 'V']).chars().peekable();
        while let Some(&c) = chars.peek() {
            if c.is_ascii_digit() {
                let mut n = String::new();
                while let Some(&d) = chars.peek().filter(|d| d.is_ascii_digit()) {
                    n.push(d);
                    chars.next();
                }
                out.push(Part::Num(n.trim_start_matches('0').to_string()));
            } else if c.is_alphabetic() {
                let mut t = String::new();
                while let Some(&d) = chars.peek().filter(|d| d.is_alphabetic()) {
                    t.push(d.to_ascii_lowercase());
                    chars.next();
                }
                out.push(Part::Text(t));
            } else {
                chars.next();
            }
        }
        out
    }
    #[derive(PartialEq, Eq)]
    enum Part {
        Num(String),
        Text(String),
    }
    let (pa, pb) = (parts(a), parts(b));
    for (x, y) in pa.iter().zip(&pb) {
        let ord = match (x, y) {
            // Numbers have no leading zeros here, so a longer one is bigger.
            (Part::Num(x), Part::Num(y)) => x.len().cmp(&y.len()).then_with(|| x.cmp(y)),
            // A pre-release word (`beta`) sorts before a number, as in 1.0beta < 1.0.
            (Part::Text(_), Part::Num(_)) => Ordering::Less,
            (Part::Num(_), Part::Text(_)) => Ordering::Greater,
            (Part::Text(x), Part::Text(y)) => x.cmp(y),
        };
        if ord != Ordering::Equal {
            return ord;
        }
    }
    match pa.len().cmp(&pb.len()) {
        Ordering::Equal => Ordering::Equal,
        // `1.0` vs `1.0.0`: trailing zeros don't make a version newer; trailing text (a
        // pre-release tag) makes it older.
        Ordering::Less => match &pb[pa.len()] {
            Part::Num(n) if n.is_empty() => Ordering::Equal,
            Part::Text(_) => Ordering::Greater,
            _ => Ordering::Less,
        },
        Ordering::Greater => match &pa[pb.len()] {
            Part::Num(n) if n.is_empty() => Ordering::Equal,
            Part::Text(_) => Ordering::Less,
            _ => Ordering::Greater,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_compare() {
        use Ordering::*;
        for (a, b, want) in [
            ("1.2.3", "1.2.3", Equal),
            ("1.10", "1.9", Greater),
            ("2.0", "10.0", Less),
            ("1.2", "1.2.1", Less),
            ("1.0", "1.0.0", Equal),
            ("v1.0", "1.0", Equal),
            ("1.0beta", "1.0", Less),
            ("1.0-rc1", "1.0", Less),
            ("124.0.6367.60", "124.0.6367.118", Less),
            ("3.0.13-0ubuntu3.1", "3.0.13-0ubuntu3.4", Less),
            ("007", "7", Equal),
        ] {
            assert_eq!(compare_versions(a, b), want, "{a} vs {b}");
            assert_eq!(compare_versions(b, a), want.reverse(), "{b} vs {a}");
        }
    }

    #[test]
    fn tokens_are_safe_for_command_lines() {
        for ok in ["Mozilla.Firefox", "firefox", "libssl3:amd64", "7zip.install", "g++", "Microsoft.VisualStudioCode", "124.0.6367.60", "1:2.4-1~bpo12"] {
            assert!(valid_token(ok), "{ok}");
        }
        for bad in ["", "-y", "--force", "a b", "a;b", "a$(b)", "a=b", "a\"b", "a|b", "../x", "a\nb", &"x".repeat(201)] {
            assert!(!valid_token(bad), "{bad:?}");
        }
    }

    #[test]
    fn unknown_fields_decode() {
        #[derive(Serialize)]
        struct Raw {
            id: Uuid,
            name: &'static str,
            future: u8,
        }
        let buf = crate::encode(&Raw { id: Uuid::nil(), name: "x", future: 1 }).unwrap();
        let p: Package = crate::decode(&buf).unwrap();
        assert!(p.winget.is_none() && p.installer.is_none() && p.version.is_none());
    }
}
