//! Debian and Ubuntu: apt.
//!
//! Scan: `apt-get update`, then `apt-get -s dist-upgrade` (apt-get's output is a stable
//! interface, unlike `apt list`). Updates from a `*-security` suite are security updates.
//! Install: `apt-get install --only-upgrade <pkgs>`, non-interactive, keeping existing
//! config files.

#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::collections::HashMap;
use std::time::Duration;

use anyhow::{Result, bail};
use rmm_proto::patch::{Category, PatchStage, PatchUpdate};

use super::cmd::{self, Log, Opts};
use super::{Installed, PatchProvider, Progress, likely_needs_reboot};

pub struct Apt;

const ENV: &[(&str, &str)] = &[("DEBIAN_FRONTEND", "noninteractive"), ("NEEDRESTART_MODE", "a"), ("APT_LISTCHANGES_FRONTEND", "none")];

impl PatchProvider for Apt {
    fn name(&self) -> &'static str {
        "apt"
    }

    fn scan(&self, log: &Log, progress: Progress, refresh: bool) -> Result<Vec<PatchUpdate>> {
        if refresh {
            progress(PatchStage::Refreshing, Some("apt-get update".into()), None);
            let out = cmd::output(log, "apt-get", &["update", "-q"], Opts { env: ENV, timeout: Duration::from_secs(900), ..Default::default() })?;
            if !out.success() {
                bail!("apt-get update failed: {}", out.reason());
            }
        }
        // The simulation is long and uninteresting; keep it out of the log.
        let out = cmd::output(log, "apt-get", &["-s", "-q", "dist-upgrade"], Opts { env: ENV, log: false, ..Default::default() })?;
        if !out.success() {
            bail!("apt-get -s dist-upgrade failed: {}", out.reason());
        }
        let mut updates = parse_simulation(&out.stdout);
        add_sizes(log, &mut updates);
        Ok(updates)
    }

    fn install(&self, ids: &[String], log: &Log, progress: Progress) -> Result<Installed> {
        progress(PatchStage::Installing, Some(format!("apt-get install --only-upgrade ({} packages)", ids.len())), None);
        let mut args = vec![
            "-y",
            "-q",
            "-o",
            "Dpkg::Options::=--force-confdef",
            "-o",
            "Dpkg::Options::=--force-confold",
            "install",
            "--only-upgrade",
        ];
        args.extend(ids.iter().map(String::as_str));
        let total = ids.len().max(1);
        let mut done = 0usize;
        let out = cmd::run(log, "apt-get", &args, Opts { env: ENV, timeout: Duration::from_secs(3 * 3600), detach: true, ..Default::default() }, &mut |line| {
            if let Some(rest) = line.strip_prefix("Setting up ") {
                done += 1;
                let pkg = rest.split_whitespace().next().unwrap_or(rest);
                let pct = (done * 100 / total).min(99) as u8;
                progress(PatchStage::Installing, Some(format!("setting up {pkg}")), Some(pct));
            } else if line.starts_with("Get:") && done == 0 {
                progress(PatchStage::Downloading, Some(line.to_string()), None);
            }
        })?;
        if !out.success() {
            bail!("apt-get failed: {}", out.reason());
        }
        // Per-package results come from the rescan.
        Ok(Installed { results: vec![], reboot_required: self.reboot_pending() })
    }

    fn reboot_pending(&self) -> bool {
        std::path::Path::new("/var/run/reboot-required").exists() || super::running_kernel_removed()
    }
}

/// `Inst libssl3 [3.0.2-0ubuntu1.10] (3.0.2-0ubuntu1.12 Ubuntu:22.04/jammy-updates, Ubuntu:22.04/jammy-security [amd64])`
/// Only upgrades count: `Inst` lines without a `[current version]` are new dependencies.
pub(crate) fn parse_simulation(out: &str) -> Vec<PatchUpdate> {
    let mut updates = Vec::new();
    for line in out.lines() {
        let Some(rest) = line.strip_prefix("Inst ") else { continue };
        let Some((name, rest)) = rest.split_once(' ') else { continue };
        let Some(rest) = rest.strip_prefix('[') else { continue };
        let Some((current, rest)) = rest.split_once(']') else { continue };
        let Some(rest) = rest.trim_start().strip_prefix('(') else { continue };
        let inner = rest.split_once(')').map_or(rest, |(i, _)| i);
        let (version, origins) = inner.split_once(' ').unwrap_or((inner, ""));
        let security = origins.split(", ").any(|o| o.to_ascii_lowercase().contains("security"));
        updates.push(PatchUpdate {
            id: name.to_string(),
            title: format!("{name} {version}"),
            kb: None,
            severity: None,
            category: if security { Category::Security } else { Category::Update },
            size: None,
            requires_reboot: likely_needs_reboot(name),
            version: Some(version.to_string()),
            current_version: Some(current.to_string()),
        });
    }
    updates
}

/// Download sizes from `apt-cache show`, one call for all packages. Best effort.
fn add_sizes(log: &Log, updates: &mut [PatchUpdate]) {
    if updates.is_empty() {
        return;
    }
    let specs: Vec<String> =
        updates.iter().map(|u| format!("{}={}", u.id, u.version.as_deref().unwrap_or_default())).collect();
    let mut args = vec!["show", "--no-all-versions"];
    args.extend(specs.iter().map(String::as_str));
    let Ok(out) = cmd::output(log, "apt-cache", &args, Opts { log: false, ..Default::default() }) else { return };
    let sizes = parse_sizes(&out.stdout);
    for u in updates {
        let base = u.id.split(':').next().unwrap_or(&u.id);
        u.size = sizes.get(base).copied();
    }
}

fn parse_sizes(out: &str) -> HashMap<String, u64> {
    let mut sizes = HashMap::new();
    let mut pkg: Option<String> = None;
    for line in out.lines() {
        if let Some(p) = line.strip_prefix("Package: ") {
            pkg = Some(p.trim().to_string());
        } else if let Some(s) = line.strip_prefix("Size: ")
            && let (Some(p), Ok(n)) = (pkg.take(), s.trim().parse())
        {
            sizes.insert(p, n);
        }
    }
    sizes
}

#[cfg(test)]
mod tests {
    use super::*;

    const SIM: &str = "\
NOTE: This is only a simulation!
Reading package lists...
The following NEW packages will be installed:
  linux-image-6.8.0-49-generic
Inst linux-image-6.8.0-49-generic (6.8.0-49.49 Ubuntu:24.04/noble-updates, Ubuntu:24.04/noble-security [amd64])
Inst libssl3t64 [3.0.13-0ubuntu3.1] (3.0.13-0ubuntu3.4 Ubuntu:24.04/noble-updates, Ubuntu:24.04/noble-security [amd64])
Inst curl [8.5.0-2ubuntu10.4] (8.5.0-2ubuntu10.5 Ubuntu:24.04/noble-updates [amd64]) []
Inst tzdata [2024a-3ubuntu1.1] (2024b-0ubuntu0.24.04 Debian:12.7/stable-updates [all])
Inst libc6:i386 [2.36-9+deb12u7] (2.36-9+deb12u8 Debian-Security:12/stable-security [i386])
Conf libssl3t64 (3.0.13-0ubuntu3.4 Ubuntu:24.04/noble-updates, Ubuntu:24.04/noble-security [amd64])
";

    #[test]
    fn parses_upgrades_only() {
        let u = parse_simulation(SIM);
        let ids: Vec<&str> = u.iter().map(|u| u.id.as_str()).collect();
        assert_eq!(ids, ["libssl3t64", "curl", "tzdata", "libc6:i386"]);
        assert_eq!(u[0].category, Category::Security);
        assert_eq!(u[0].version.as_deref(), Some("3.0.13-0ubuntu3.4"));
        assert_eq!(u[0].current_version.as_deref(), Some("3.0.13-0ubuntu3.1"));
        assert_eq!(u[1].category, Category::Update);
        assert_eq!(u[3].category, Category::Security);
        assert!(u[3].requires_reboot && !u[1].requires_reboot);
    }

    #[test]
    fn parses_sizes() {
        let s = parse_sizes("Package: curl\nVersion: 8.5\nSize: 226334\n\nPackage: libc6\nSize: 2754688\n");
        assert_eq!(s["curl"], 226334);
        assert_eq!(s["libc6"], 2754688);
    }
}
