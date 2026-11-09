//! Arch Linux: pacman.
//!
//! Scan: `checkupdates` (pacman-contrib), which syncs a private copy of the databases so the
//! scan never leaves the system half-synced. Install: `pacman -Syu --noconfirm`. Arch
//! doesn't support partial upgrades, so this is all or nothing: the requested ids are
//! ignored and everything is upgraded.

#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::time::Duration;

use anyhow::{Result, bail};
use rmm_proto::patch::{Category, PatchStage, PatchUpdate};

use super::cmd::{self, Log, Opts};
use super::{Installed, PatchProvider, Progress, likely_needs_reboot};

pub struct Pacman;

impl PatchProvider for Pacman {
    fn name(&self) -> &'static str {
        "pacman"
    }

    fn all_or_nothing(&self) -> bool {
        true
    }

    fn scan(&self, log: &Log, progress: Progress, refresh: bool) -> Result<Vec<PatchUpdate>> {
        if !cmd::which("checkupdates") {
            bail!("checkupdates not found: install pacman-contrib to scan for updates");
        }
        if refresh {
            progress(PatchStage::Refreshing, Some("checkupdates".into()), None);
        }
        // --nosync reuses the databases from the last sync (the rescan after an install).
        let args: &[&str] = if refresh { &[] } else { &["--nosync"] };
        let out = cmd::output(log, "checkupdates", args, Opts { timeout: Duration::from_secs(900), log: refresh, ..Default::default() })?;
        // 0: updates, 2: none, 1: error.
        match out.code {
            Some(0) => Ok(parse(&out.stdout)),
            Some(2) => Ok(vec![]),
            _ => bail!("checkupdates failed: {}", out.reason()),
        }
    }

    fn install(&self, _ids: &[String], log: &Log, progress: Progress) -> Result<Installed> {
        progress(PatchStage::Installing, Some("pacman -Syu".into()), None);
        let out = cmd::run(log, "pacman", &["-Syu", "--noconfirm", "--noprogressbar"], Opts { timeout: Duration::from_secs(3 * 3600), ..Default::default() }, &mut |line| {
            // "(12/40) upgrading openssl"
            if let Some((counter, rest)) = line.trim_start().strip_prefix('(').and_then(|l| l.split_once(") "))
                && let Some((n, total)) = counter.split_once('/')
                && let (Ok(n), Ok(total)) = (n.trim().parse::<usize>(), total.trim().parse::<usize>())
                && total > 0
                && (rest.starts_with("upgrading") || rest.starts_with("installing"))
            {
                progress(PatchStage::Installing, Some(rest.to_string()), Some((n * 100 / total).min(99) as u8));
            }
        })?;
        if !out.success() {
            bail!("pacman -Syu failed: {}", out.reason());
        }
        Ok(Installed { results: vec![], reboot_required: self.reboot_pending() })
    }

    fn reboot_pending(&self) -> bool {
        super::running_kernel_removed()
    }
}

/// `openssl 3.3.1-1 -> 3.3.2-1`
fn parse(out: &str) -> Vec<PatchUpdate> {
    out.lines()
        .filter_map(|l| {
            let t: Vec<&str> = l.split_whitespace().collect();
            match t.as_slice() {
                [name, from, "->", to, ..] => Some(PatchUpdate {
                    id: name.to_string(),
                    title: format!("{name} {to}"),
                    kb: None,
                    severity: None,
                    category: Category::Update,
                    size: None,
                    requires_reboot: likely_needs_reboot(name),
                    version: Some(to.to_string()),
                    current_version: Some(from.to_string()),
                }),
                _ => None,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    #[test]
    fn parses_checkupdates() {
        let u = super::parse("linux 6.11.5.arch1-1 -> 6.11.6.arch1-1\nopenssl 3.3.1-1 -> 3.3.2-1\n\ngarbage\n");
        assert_eq!(u.len(), 2);
        assert!(u[0].requires_reboot);
        assert_eq!((u[1].id.as_str(), u[1].version.as_deref(), u[1].current_version.as_deref()), ("openssl", Some("3.3.2-1"), Some("3.3.1-1")));
    }
}
