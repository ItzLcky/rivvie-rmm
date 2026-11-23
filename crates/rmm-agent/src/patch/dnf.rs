//! RHEL, Fedora and friends: dnf (dnf4 and dnf5), or yum on older systems.
//!
//! Scan: `dnf check-update --refresh` for the packages, then `dnf updateinfo list` for the
//! advisories that cover them, which give the severity (RHSA "Important", Fedora
//! "Moderate"...) and whether it's a security fix. Ids are `name.arch`, so multilib
//! packages are separate. Install: `dnf -y upgrade <name.arch...>`.

#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::collections::HashMap;
use std::time::Duration;

use anyhow::{Result, bail};
use rmm_proto::patch::{Category, PatchStage, PatchUpdate, Severity};

use super::cmd::{self, Log, Opts};
use super::{Installed, PatchProvider, Progress, likely_needs_reboot};

pub struct Dnf {
    bin: &'static str,
}

impl Dnf {
    pub fn new() -> Self {
        Dnf { bin: if cmd::which("dnf") { "dnf" } else { "dnf5" } }
    }

    pub fn yum() -> Self {
        Dnf { bin: "yum" }
    }
}

impl PatchProvider for Dnf {
    fn name(&self) -> &'static str {
        if self.bin == "yum" { "yum" } else { "dnf" }
    }

    fn scan(&self, log: &Log, progress: Progress, refresh: bool) -> Result<Vec<PatchUpdate>> {
        if refresh {
            progress(PatchStage::Refreshing, Some(format!("{} check-update --refresh", self.bin)), None);
        }
        let mut args = vec!["-q", "check-update"];
        if refresh {
            args.push("--refresh");
        } else {
            args.push("--cacheonly");
        }
        let out = cmd::output(log, self.bin, &args, Opts { timeout: Duration::from_secs(900), log: refresh, ..Default::default() })?;
        // 100: updates available, 0: none, anything else: error.
        match out.code {
            Some(0) => return Ok(vec![]),
            Some(100) => {}
            _ => bail!("{} check-update failed: {}", self.bin, out.reason()),
        }
        let mut updates = parse_check_update(&out.stdout);
        // Advisories are optional: repos without updateinfo just give nothing.
        if let Ok(info) = cmd::output(log, self.bin, &["-q", "--cacheonly", "updateinfo", "list", "--updates"], Opts { log: false, ..Default::default() })
            && info.success()
        {
            apply_advisories(&mut updates, &parse_updateinfo(&info.stdout));
        }
        Ok(updates)
    }

    fn install(&self, ids: &[String], log: &Log, progress: Progress) -> Result<Installed> {
        progress(PatchStage::Installing, Some(format!("{} upgrade ({} packages)", self.bin, ids.len())), None);
        let mut args = vec!["-y", "upgrade"];
        args.extend(ids.iter().map(String::as_str));
        let total = ids.len().max(1);
        let mut done = 0usize;
        let out = cmd::run(log, self.bin, &args, Opts { timeout: Duration::from_secs(3 * 3600), detach: true, ..Default::default() }, &mut |line| {
            if let Some((stage, msg, pct)) = progress_line(line, total, &mut done) {
                progress(stage, msg, pct);
            }
        })?;
        if !out.success() {
            bail!("{} upgrade failed: {}", self.bin, out.reason());
        }
        Ok(Installed { results: vec![], reboot_required: self.reboot_pending() })
    }

    fn reboot_pending(&self) -> bool {
        // dnf-utils' needs-restarting: exit 1 means a reboot is needed.
        if cmd::which("needs-restarting") {
            let log = Log::default();
            if let Ok(o) = cmd::output(&log, "needs-restarting", &["-r"], Opts { log: false, ..Default::default() }) {
                return o.code == Some(1);
            }
        }
        if self.bin != "yum" {
            let log = Log::default();
            if let Ok(o) = cmd::output(&log, self.bin, &["-q", "needs-restarting", "-r"], Opts { log: false, ..Default::default() })
                && matches!(o.code, Some(0 | 1))
            {
                return o.code == Some(1);
            }
        }
        super::running_kernel_removed()
    }
}

/// Progress from an upgrade's output. dnf5: `[3/6] Upgrading xz-libs-1:5.8.1-4.fc41.x86_64 100% | ...`;
/// dnf4: `  Upgrading        : openssl-libs-1:3.0.7-27.el9.x86_64     3/12`.
fn progress_line(line: &str, total: usize, done: &mut usize) -> Option<(PatchStage, Option<String>, Option<u8>)> {
    let l = line.trim_start();
    if l.starts_with("Downloading Packages") {
        return Some((PatchStage::Downloading, None, None));
    }
    // dnf5's step counter covers the whole transaction.
    if let Some((counter, rest)) = l.strip_prefix('[').and_then(|r| r.split_once("] "))
        && let Some((n, of)) = counter.split_once('/')
        && let (Ok(n), Ok(of)) = (n.parse::<usize>(), of.parse::<usize>())
        && of > 0
        && (rest.starts_with("Upgrading") || rest.starts_with("Installing"))
    {
        let what = rest.split_whitespace().take(2).collect::<Vec<_>>().join(" ");
        return Some((PatchStage::Installing, Some(what), Some((n * 100 / of).min(99) as u8)));
    }
    if l.starts_with("Upgrading ") || l.starts_with("Upgrading:") || l.starts_with("Installing ") {
        *done += 1;
        let what = l.split_whitespace().filter(|t| *t != ":").take(2).collect::<Vec<_>>().join(" ");
        return Some((PatchStage::Installing, Some(what), Some((*done * 100 / (2 * total)).min(99) as u8)));
    }
    None
}

/// `name.arch  version  repo`, one per line. Long names wrap the rest onto the next line.
/// Stops at the "Obsoleting Packages" section.
pub(crate) fn parse_check_update(out: &str) -> Vec<PatchUpdate> {
    let mut updates = Vec::new();
    let mut pending: Vec<&str> = Vec::new();
    for line in out.lines() {
        let t = line.trim();
        if t.starts_with("Obsoleting") || t.starts_with("Security:") {
            break;
        }
        if t.is_empty() || t.starts_with("Last metadata") || t.ends_with(':') {
            pending.clear();
            continue;
        }
        pending.extend(t.split_whitespace());
        if pending.len() < 3 {
            continue;
        }
        let (name_arch, version) = (pending[0], pending[1]);
        pending.clear();
        let Some((name, _arch)) = name_arch.rsplit_once('.') else { continue };
        updates.push(PatchUpdate {
            id: name_arch.to_string(),
            title: format!("{name} {version}"),
            kb: None,
            severity: None,
            category: Category::Update,
            size: None,
            requires_reboot: likely_needs_reboot(name),
            version: Some(version.to_string()),
            current_version: None,
        });
    }
    updates
}

struct Advisory {
    id: String,
    security: bool,
    severity: Option<Severity>,
}

/// dnf4: `RHSA-2024:1234 Important/Sec. openssl-libs-1:3.0.7-25.el9_3.x86_64`
/// dnf5: `FEDORA-2024-1a2b  security  Moderate  curl-8.6.0-7.fc40.x86_64  2024-04-01 00:00:00`
/// Keyed by `name.arch`.
fn parse_updateinfo(out: &str) -> HashMap<String, Vec<Advisory>> {
    let mut map: HashMap<String, Vec<Advisory>> = HashMap::new();
    for line in out.lines() {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        if tokens.len() < 3 || tokens[0] == "Name" || !tokens[0].contains('-') {
            continue;
        }
        let Some(nevra) = tokens[1..].iter().find(|t| t.contains('.') && t.matches('-').count() >= 2) else { continue };
        let Some(key) = name_arch(nevra) else { continue };
        let mut security = false;
        let mut severity = None;
        for t in &tokens[1..] {
            for part in t.split('/') {
                let p = part.trim_end_matches('.').to_ascii_lowercase();
                if p == "sec" || p == "security" {
                    security = true;
                }
                if severity.is_none() {
                    severity = Severity::from_vendor(&p);
                }
            }
        }
        map.entry(key).or_default().push(Advisory { id: tokens[0].to_string(), security, severity });
    }
    map
}

/// `openssl-libs-1:3.0.7-25.el9_3.x86_64` -> `openssl-libs.x86_64`
fn name_arch(nevra: &str) -> Option<String> {
    let (rest, arch) = nevra.rsplit_once('.')?;
    let (rest, _release) = rest.rsplit_once('-')?;
    let (name, _version) = rest.rsplit_once('-')?;
    Some(format!("{name}.{arch}"))
}

/// The most severe advisory names the update: security beats non-security, then severity.
fn apply_advisories(updates: &mut [PatchUpdate], advisories: &HashMap<String, Vec<Advisory>>) {
    for u in updates {
        let Some(list) = advisories.get(&u.id) else { continue };
        let best = list.iter().min_by_key(|a| (!a.security, a.severity.unwrap_or(Severity::Unspecified)));
        if let Some(a) = best {
            u.kb = Some(a.id.clone());
            u.severity = a.severity;
            if a.security {
                u.category = Category::Security;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHECK: &str = "\
Last metadata expiration check: 0:01:02 ago on Mon 04 Nov 2024.

openssl-libs.x86_64                  1:3.0.7-25.el9_3          baseos
kernel-core.x86_64                   5.14.0-427.13.1.el9_4     baseos
a-really-long-package-name-that-wraps.noarch
                                     2.0-1.el9                 appstream
curl.x86_64                          7.76.1-29.el9_4           baseos
Obsoleting Packages
grub2-tools.x86_64                   1:2.06-80.el9             baseos
";

    #[test]
    fn parses_check_update() {
        let u = parse_check_update(CHECK);
        let ids: Vec<&str> = u.iter().map(|u| u.id.as_str()).collect();
        assert_eq!(ids, ["openssl-libs.x86_64", "kernel-core.x86_64", "a-really-long-package-name-that-wraps.noarch", "curl.x86_64"]);
        assert_eq!(u[0].version.as_deref(), Some("1:3.0.7-25.el9_3"));
        assert!(u[1].requires_reboot && !u[3].requires_reboot);
    }

    #[test]
    fn applies_dnf4_and_dnf5_advisories() {
        let dnf4 = "\
RHSA-2024:1234 Important/Sec. openssl-libs-1:3.0.7-25.el9_3.x86_64
RHBA-2024:0001 bugfix         openssl-libs-1:3.0.7-25.el9_3.x86_64
RHBA-2024:0002 bugfix         kernel-core-5.14.0-427.13.1.el9_4.x86_64
";
        let dnf5 = "\
Name             Type      Severity  Package                    Issued
FEDORA-2024-1a2b security  Moderate  curl-7.76.1-29.el9_4.x86_64 2024-04-01 00:00:00
";
        let mut u = parse_check_update(CHECK);
        apply_advisories(&mut u, &parse_updateinfo(dnf4));
        apply_advisories(&mut u, &parse_updateinfo(dnf5));
        assert_eq!((u[0].category, u[0].severity, u[0].kb.as_deref()), (Category::Security, Some(Severity::Important), Some("RHSA-2024:1234")));
        assert_eq!((u[1].category, u[1].kb.as_deref()), (Category::Update, Some("RHBA-2024:0002")));
        assert_eq!((u[3].category, u[3].severity), (Category::Security, Some(Severity::Moderate)));
        assert_eq!(u[2].kb, None);
    }

    #[test]
    fn progress_lines() {
        let mut done = 0;
        let p = progress_line("[3/6] Upgrading xz-libs-1:5.8.1-4.fc41.x86_64 100% | 26.7 MiB/s", 2, &mut done).unwrap();
        assert_eq!((p.0, p.2), (PatchStage::Installing, Some(50)));
        assert_eq!(p.1.as_deref(), Some("Upgrading xz-libs-1:5.8.1-4.fc41.x86_64"));
        let p = progress_line("  Upgrading        : openssl-libs-1:3.0.7-27.el9.x86_64     3/12", 2, &mut done).unwrap();
        assert_eq!(p.1.as_deref(), Some("Upgrading openssl-libs-1:3.0.7-27.el9.x86_64"));
        assert!(progress_line("Complete!", 2, &mut done).is_none());
    }

    #[test]
    fn nevra_to_name_arch() {
        assert_eq!(name_arch("openssl-libs-1:3.0.7-25.el9_3.x86_64").as_deref(), Some("openssl-libs.x86_64"));
        assert_eq!(name_arch("curl-8.6.0-7.fc40.x86_64").as_deref(), Some("curl.x86_64"));
        assert_eq!(name_arch("bogus"), None);
    }
}
