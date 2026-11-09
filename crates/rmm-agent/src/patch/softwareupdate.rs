//! macOS: `softwareupdate`.
//!
//! Scan: `softwareupdate -l`. Install: `softwareupdate -i <label>...`. Updates that need a
//! restart are installed but not restarted by `softwareupdate` itself; the run's reboot
//! policy decides. On Apple silicon, macOS updates that need a restart may also need a
//! signed-in user's approval, which an agent running as root can't give.
//!
//! Only the parser is exercised off macOS.

#![cfg_attr(not(target_os = "macos"), allow(dead_code))]

use std::time::Duration;

use anyhow::{Result, bail};
use rmm_proto::patch::{Category, PatchItemResult, PatchStage, PatchUpdate};

use super::cmd::{self, Log, Opts};
use super::{Installed, PatchProvider, Progress};

pub struct SoftwareUpdate;

impl PatchProvider for SoftwareUpdate {
    fn name(&self) -> &'static str {
        "softwareupdate"
    }

    fn scan(&self, log: &Log, progress: Progress, refresh: bool) -> Result<Vec<PatchUpdate>> {
        if refresh {
            progress(PatchStage::Refreshing, Some("softwareupdate -l".into()), None);
        }
        let out = cmd::output(log, "softwareupdate", &["-l"], Opts { timeout: Duration::from_secs(1200), log: refresh, ..Default::default() })?;
        if !out.success() {
            bail!("softwareupdate -l failed: {}", out.reason());
        }
        // It prints the list on stdout and "No new software available." on stderr.
        Ok(parse(&out.stdout))
    }

    fn install(&self, ids: &[String], log: &Log, progress: Progress) -> Result<Installed> {
        progress(PatchStage::Installing, Some(format!("softwareupdate -i ({} updates)", ids.len())), None);
        let mut results = Vec::new();
        let mut reboot = false;
        // One at a time, so a failure only fails that update.
        for (i, id) in ids.iter().enumerate() {
            progress(PatchStage::Installing, Some(id.clone()), Some((i * 100 / ids.len().max(1)) as u8));
            let out = cmd::output(log, "softwareupdate", &["-i", id], Opts { timeout: Duration::from_secs(3 * 3600), ..Default::default() })?;
            let text = format!("{}{}", out.stdout, out.stderr);
            reboot |= text.contains("restart") || text.contains("Restart");
            results.push(PatchItemResult { id: id.clone(), ok: out.success(), message: (!out.success()).then(|| out.reason()) });
        }
        Ok(Installed { results, reboot_required: reboot })
    }

    fn reboot_pending(&self) -> bool {
        false
    }
}

/// ```text
/// * Label: macOS Sonoma 14.4.1-23E224
///     Title: macOS Sonoma 14.4.1, Version: 14.4.1, Size: 3327206KiB, Recommended: YES, Action: restart,
/// ```
fn parse(out: &str) -> Vec<PatchUpdate> {
    let mut updates: Vec<PatchUpdate> = Vec::new();
    for line in out.lines() {
        let t = line.trim();
        if let Some(label) = t.strip_prefix("* Label: ") {
            updates.push(PatchUpdate {
                id: label.trim().to_string(),
                title: label.trim().to_string(),
                kb: None,
                severity: None,
                category: Category::Update,
                size: None,
                requires_reboot: false,
                version: None,
                current_version: None,
            });
        } else if t.starts_with("Title: ")
            && let Some(u) = updates.last_mut()
        {
            for field in t.split(", ") {
                let Some((k, v)) = field.split_once(": ") else { continue };
                let v = v.trim().trim_end_matches(',');
                match k.trim() {
                    "Title" => u.title = v.to_string(),
                    "Version" => u.version = Some(v.to_string()),
                    "Size" => u.size = v.strip_suffix("KiB").or_else(|| v.strip_suffix('K')).and_then(|n| n.parse::<u64>().ok()).map(|k| k * 1024),
                    "Action" => u.requires_reboot = v.eq_ignore_ascii_case("restart"),
                    _ => {}
                }
            }
            let title = u.title.to_ascii_lowercase();
            u.category = if title.contains("security") {
                Category::Security
            } else if title.starts_with("macos") {
                Category::Rollup
            } else {
                Category::Update
            };
        }
    }
    updates
}

#[cfg(test)]
mod tests {
    #[test]
    fn parses_list() {
        let out = "Software Update Tool\n\nFinding available software\nSoftware Update found the following new or updated software:\n\
* Label: Command Line Tools for Xcode-15.3\n\tTitle: Command Line Tools for Xcode, Version: 15.3, Size: 751051KiB, Recommended: YES, \n\
* Label: macOS Sonoma 14.4.1-23E224\n\tTitle: macOS Sonoma 14.4.1, Version: 14.4.1, Size: 3327206KiB, Recommended: YES, Action: restart, \n";
        let u = super::parse(out);
        assert_eq!(u.len(), 2);
        assert_eq!(u[0].id, "Command Line Tools for Xcode-15.3");
        assert_eq!(u[0].size, Some(751051 * 1024));
        assert!(!u[0].requires_reboot);
        assert_eq!((u[1].title.as_str(), u[1].requires_reboot), ("macOS Sonoma 14.4.1", true));
        assert_eq!(u[1].category, rmm_proto::patch::Category::Rollup);
    }
}
