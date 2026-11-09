//! Patch management payloads.
//!
//! The server asks for a scan ([`crate::ServerMsg::PatchScan`]) and the agent answers with
//! [`crate::AgentMsg::PatchScanResult`]. An install ([`crate::ServerMsg::PatchInstall`])
//! streams [`crate::AgentMsg::PatchProgress`] and ends with [`crate::AgentMsg::PatchResult`],
//! which the agent keeps and resends after reconnects until the server's
//! [`crate::ServerMsg::PatchAck`]. After every install the agent rescans by itself.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Capability an agent lists in `Auth` when it understands the patch messages.
pub const CAPABILITY: &str = "patch";

/// Longest install log the agent sends, in bytes.
pub const OUTPUT_MAX: usize = 256 * 1024;

/// Vendor severity. Windows uses MSRC ratings; RHEL advisories use the same words. Debian,
/// Ubuntu, Arch and macOS don't rate updates, so theirs are `None`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Critical,
    Important,
    Moderate,
    Low,
    #[serde(other)]
    Unspecified,
}

impl Severity {
    pub const ALL: [Severity; 5] = [Severity::Critical, Severity::Important, Severity::Moderate, Severity::Low, Severity::Unspecified];

    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Critical => "critical",
            Severity::Important => "important",
            Severity::Moderate => "moderate",
            Severity::Low => "low",
            Severity::Unspecified => "unspecified",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|v| v.as_str() == s)
    }

    /// MSRC and Red Hat wording ("Critical", "Important", "Moderate", "Low").
    pub fn from_vendor(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "critical" => Some(Severity::Critical),
            "important" | "high" => Some(Severity::Important),
            "moderate" | "medium" => Some(Severity::Moderate),
            "low" => Some(Severity::Low),
            _ => None,
        }
    }
}

/// What kind of update this is. Windows categories map one to one; package managers report
/// `security` (from the security pocket or a security advisory) or `update`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    Security,
    /// Windows "Critical Updates": non-security fixes for critical bugs.
    Critical,
    /// Defender and other definition updates.
    Definition,
    Driver,
    /// Windows feature updates and service packs, macOS major upgrades.
    Feature,
    /// Cumulative updates and update rollups.
    Rollup,
    /// Ordinary updates and bug fixes.
    Update,
    #[serde(other)]
    Other,
}

impl Category {
    pub const ALL: [Category; 8] = [
        Category::Security,
        Category::Critical,
        Category::Definition,
        Category::Driver,
        Category::Feature,
        Category::Rollup,
        Category::Update,
        Category::Other,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Category::Security => "security",
            Category::Critical => "critical",
            Category::Definition => "definition",
            Category::Driver => "driver",
            Category::Feature => "feature",
            Category::Rollup => "rollup",
            Category::Update => "update",
            Category::Other => "other",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|v| v.as_str() == s)
    }
}

/// One available update.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PatchUpdate {
    /// Stable id to install it by: the Windows Update id, the package name on Linux (one row
    /// per package, whatever the version), the softwareupdate label on macOS.
    pub id: String,
    pub title: String,
    /// `KB5034441` on Windows; the advisory (`RHSA-2024:1234`) on RHEL/Fedora.
    #[serde(default)]
    pub kb: Option<String>,
    #[serde(default)]
    pub severity: Option<Severity>,
    pub category: Category,
    /// Download size in bytes, when known.
    #[serde(default)]
    pub size: Option<u64>,
    #[serde(default)]
    pub requires_reboot: bool,
    /// Version it updates to, and from (package managers).
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub current_version: Option<String>,
}

/// What to do about rebooting once an install finishes.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum RebootPolicy {
    /// Never reboot; the agent reports that a reboot is pending.
    #[default]
    Never,
    /// Reboot when an installed update needs it.
    IfRequired,
    /// Reboot after every install that changed something.
    Always,
}

impl RebootPolicy {
    pub fn as_str(self) -> &'static str {
        match self {
            RebootPolicy::Never => "never",
            RebootPolicy::IfRequired => "if_required",
            RebootPolicy::Always => "always",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "never" => RebootPolicy::Never,
            "if_required" => RebootPolicy::IfRequired,
            "always" => RebootPolicy::Always,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PatchStage {
    /// Waiting for another scan or install on this machine to finish.
    Queued,
    /// Refreshing package lists.
    Refreshing,
    Downloading,
    Installing,
    /// The install finished and the machine restarts shortly.
    Rebooting,
    #[serde(other)]
    Other,
}

impl PatchStage {
    pub fn as_str(self) -> &'static str {
        match self {
            PatchStage::Queued => "queued",
            PatchStage::Refreshing => "refreshing",
            PatchStage::Downloading => "downloading",
            PatchStage::Installing => "installing",
            PatchStage::Rebooting => "rebooting",
            PatchStage::Other => "other",
        }
    }
}

/// How one requested update fared.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PatchItemResult {
    pub id: String,
    pub ok: bool,
    #[serde(default)]
    pub message: Option<String>,
}

/// The end of an install.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PatchOutcome {
    pub run_id: Uuid,
    /// One entry per requested update. Package managers that install everything at once
    /// report the same result for each.
    pub results: Vec<PatchItemResult>,
    /// Set when the install couldn't run at all (no provider, package manager locked...).
    #[serde(default)]
    pub error: Option<String>,
    /// The machine needs a reboot to finish (whether or not one was started).
    #[serde(default)]
    pub reboot_required: bool,
    /// The agent scheduled a reboot because of the run's reboot policy.
    #[serde(default)]
    pub rebooting: bool,
    /// Combined package manager output, capped at [`OUTPUT_MAX`].
    #[serde(default)]
    pub output: String,
    pub duration_ms: u64,
}

impl PatchOutcome {
    pub fn succeeded(&self) -> usize {
        self.results.iter().filter(|r| r.ok).count()
    }
}

/// Truncates `s` to at most `max` bytes on a char boundary, keeping the end (where errors are).
pub fn tail(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut start = s.len() - max;
    while !s.is_char_boundary(start) {
        start += 1;
    }
    &s[start..]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_enums_decode() {
        #[derive(Serialize)]
        struct Raw {
            id: &'static str,
            title: &'static str,
            severity: &'static str,
            category: &'static str,
        }
        let buf = crate::encode(&Raw { id: "x", title: "t", severity: "apocalyptic", category: "weird" }).unwrap();
        let u: PatchUpdate = crate::decode(&buf).unwrap();
        assert_eq!((u.severity, u.category), (Some(Severity::Unspecified), Category::Other));
        assert!(!u.requires_reboot && u.kb.is_none());
    }

    #[test]
    fn severity_orders_most_severe_first() {
        assert!(Severity::Critical < Severity::Important && Severity::Low < Severity::Unspecified);
        assert_eq!(Severity::from_vendor(" Important "), Some(Severity::Important));
        assert_eq!(Severity::from_vendor("None"), None);
        for s in Severity::ALL {
            assert_eq!(Severity::parse(s.as_str()), Some(s));
        }
        for c in Category::ALL {
            assert_eq!(Category::parse(c.as_str()), Some(c));
        }
    }

    #[test]
    fn tail_keeps_char_boundaries() {
        assert_eq!(tail("abc", 10), "abc");
        assert_eq!(tail("abcdef", 3), "def");
        assert_eq!(tail("aé", 1), "");
        assert_eq!(tail("aéb", 2), "b");
    }
}
