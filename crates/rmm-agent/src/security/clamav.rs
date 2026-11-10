//! Linux: ClamAV. The signature version and date come from `clamscan --version`; on-access
//! scanning is `clamonacc`. ClamAV keeps no record of scans, so the agent remembers its own
//! (when they ran and what they found) in `/var/lib/rmm-agent/security/clamav.json`.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Local, NaiveDateTime, TimeZone, Utc};
use rmm_proto::security::{Action, Detection, MAX_DETECTIONS, ProductKind, ThreatSeverity, ThreatStatus};
use serde::{Deserialize, Serialize};

/// `ClamAV 1.0.7/27455/Wed Nov  6 09:35:43 2024` → (engine, signature version, date). Without
/// a signature database the output is just `ClamAV 1.0.7`.
pub fn parse_version(out: &str) -> Option<(String, Option<String>, Option<DateTime<Utc>>)> {
    let line = out.lines().map(str::trim).find(|l| l.starts_with("ClamAV "))?;
    let mut parts = line.trim_start_matches("ClamAV ").splitn(3, '/');
    let engine = parts.next()?.trim().to_string();
    let sigs = parts.next().map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
    let date = parts.next().and_then(|d| {
        let d = d.split_whitespace().collect::<Vec<_>>().join(" ");
        NaiveDateTime::parse_from_str(&d, "%a %b %d %H:%M:%S %Y").ok()
    });
    // The date is the database's build time in the machine's local zone.
    let date = date.and_then(|n| Local.from_local_datetime(&n).earliest()).map(|d| d.with_timezone(&Utc));
    Some((engine, sigs, date))
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct ScanOutput {
    /// (path, signature name)
    pub found: Vec<(String, String)>,
    pub scanned: Option<u64>,
    pub errors: usize,
}

/// `clamscan`/`clamdscan` output: `/path: Name FOUND` lines and the summary.
pub fn parse_scan(out: &str) -> ScanOutput {
    let mut s = ScanOutput::default();
    for line in out.lines() {
        let line = line.trim_end();
        if let Some(rest) = line.strip_suffix(" FOUND")
            && let Some((path, name)) = rest.rsplit_once(": ")
        {
            s.found.push((path.to_string(), name.trim().to_string()));
        } else if line.ends_with(" ERROR") {
            s.errors += 1;
        } else if let Some(n) = line.strip_prefix("Scanned files:") {
            s.scanned = n.trim().parse().ok();
        }
    }
    s
}

/// A stable id for one finding: the same file and signature on a later scan is the same
/// detection.
pub fn detection_id(path: &str, name: &str) -> String {
    use sha2::{Digest, Sha256};
    let h = Sha256::digest(format!("{path}\0{name}").as_bytes());
    format!("clamav-{}", hex::encode(&h[..12]))
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct State {
    #[serde(default)]
    pub last_quick_scan: Option<DateTime<Utc>>,
    #[serde(default)]
    pub last_full_scan: Option<DateTime<Utc>>,
    #[serde(default)]
    pub found: Vec<Found>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Found {
    pub id: String,
    pub name: String,
    pub path: String,
    pub detected_at: DateTime<Utc>,
    /// Set once the file is gone.
    #[serde(default)]
    pub removed_at: Option<DateTime<Utc>>,
}

impl State {
    /// Records a finished scan's findings.
    pub fn record(&mut self, action: Action, found: &[(String, String)], now: DateTime<Utc>) {
        match action {
            Action::FullScan => self.last_full_scan = Some(now),
            _ => self.last_quick_scan = Some(now),
        }
        for (path, name) in found {
            let id = detection_id(path, name);
            match self.found.iter_mut().find(|f| f.id == id) {
                Some(f) => f.removed_at = None,
                None => self.found.push(Found { id, name: name.clone(), path: path.clone(), detected_at: now, removed_at: None }),
            }
        }
        self.found.sort_by_key(|f| std::cmp::Reverse(f.detected_at));
        self.found.truncate(MAX_DETECTIONS);
    }

    /// Marks findings whose file is gone, and forgets removed ones after 30 days.
    pub fn settle(&mut self, exists: impl Fn(&str) -> bool, now: DateTime<Utc>) -> bool {
        let before = self.clone();
        for f in &mut self.found {
            if f.removed_at.is_none() && !exists(&f.path) {
                f.removed_at = Some(now);
            }
        }
        self.found.retain(|f| f.removed_at.is_none_or(|r| now - r < chrono::Duration::days(30)));
        *self != before
    }

    pub fn detections(&self) -> Vec<Detection> {
        self.found
            .iter()
            .map(|f| Detection {
                id: f.id.clone(),
                product: ProductKind::Clamav,
                name: f.name.clone(),
                severity: ThreatSeverity::Unknown,
                status: if f.removed_at.is_some() { ThreatStatus::Removed } else { ThreatStatus::Active },
                resources: vec![f.path.clone()],
                detected_at: Some(f.detected_at),
                process: None,
                user: None,
            })
            .collect()
    }
}

/// What to scan: a quick scan covers home and temporary directories, a full scan every
/// top-level directory except the kernel's pseudo-filesystems.
pub fn scan_paths(action: Action, root: &Path) -> Vec<PathBuf> {
    let quick = ["home", "root", "tmp", "var/tmp", "dev/shm", "opt", "srv"];
    let skip: HashSet<&str> = ["proc", "sys", "dev", "run", "lost+found", "snap"].into();
    let mut paths: Vec<PathBuf> = match action {
        Action::FullScan => std::fs::read_dir(root)
            .map(|rd| {
                rd.flatten()
                    .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
                    .filter(|e| !skip.contains(e.file_name().to_string_lossy().as_ref()))
                    .map(|e| e.path())
                    .collect()
            })
            .unwrap_or_default(),
        _ => quick.iter().map(|p| root.join(p)).filter(|p| p.is_dir()).collect(),
    };
    paths.sort();
    paths
}

#[cfg(target_os = "linux")]
pub use imp::Clamav;

#[cfg(target_os = "linux")]
mod imp {
    use super::*;
    use crate::patch::cmd::{self, Log, Opts};
    use anyhow::{Result, bail};
    use rmm_proto::security::Product;
    use std::sync::Mutex;

    pub struct Clamav {
        state: Mutex<State>,
        path: Option<PathBuf>,
    }

    impl Clamav {
        pub fn detect() -> Option<Self> {
            if !cmd::which("clamscan") && !cmd::which("clamdscan") {
                return None;
            }
            let path = Some(PathBuf::from("/var/lib/rmm-agent/security/clamav.json"));
            let state = path.as_deref().and_then(|p| std::fs::read(p).ok()).and_then(|b| serde_json::from_slice::<State>(&b).ok()).unwrap_or_default();
            Some(Clamav { state: Mutex::new(state), path })
        }

        fn save(&self, s: &State) {
            let Some(p) = &self.path else { return };
            if let Some(dir) = p.parent() {
                let _ = std::fs::create_dir_all(dir);
            }
            if let Ok(b) = serde_json::to_vec_pretty(s) {
                let _ = std::fs::write(p, b);
            }
        }

        pub fn product(&self) -> (Product, Vec<Detection>) {
            let log = Log::default();
            let opts = Opts { timeout: std::time::Duration::from_secs(60), log: false, ..Default::default() };
            let program = if cmd::which("clamscan") { "clamscan" } else { "clamdscan" };
            let version = cmd::output(&log, program, &["--version"], opts).ok().and_then(|o| parse_version(&o.stdout));
            let procs = running(&["clamd", "clamonacc", "freshclam"]);
            let mut p = Product::new(ProductKind::Clamav, "ClamAV");
            let mut notes = Vec::new();
            match version {
                Some((engine, sigs, date)) => {
                    p.version = Some(engine);
                    p.enabled = Some(sigs.is_some());
                    if sigs.is_none() {
                        notes.push("no signature database; run freshclam".to_string());
                    }
                    p.signature_version = sigs;
                    p.signatures_updated_at = date;
                }
                None => {
                    p.enabled = Some(false);
                    notes.push(format!("{program} --version failed"));
                }
            }
            p.realtime = Some(procs.contains("clamonacc"));
            if !procs.contains("clamd") {
                notes.push("scans load the signatures themselves (clamd isn't running)".into());
            }
            if !procs.contains("freshclam") {
                notes.push("signatures only update when asked (the freshclam daemon isn't running)".into());
            }
            p.detail = (!notes.is_empty()).then(|| capitalize(&notes.join("; ")));
            p.actions = vec![Action::QuickScan, Action::FullScan, Action::UpdateSignatures];

            let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
            if s.settle(|path| Path::new(path).exists(), Utc::now()) {
                self.save(&s);
            }
            p.last_quick_scan = s.last_quick_scan;
            p.last_full_scan = s.last_full_scan;
            (p, s.detections())
        }

        pub fn run(&self, action: Action) -> Result<String> {
            match action {
                Action::UpdateSignatures => update(),
                Action::QuickScan | Action::FullScan => self.scan(action),
            }
        }

        fn scan(&self, action: Action) -> Result<String> {
            let paths = scan_paths(action, Path::new("/"));
            if paths.is_empty() {
                bail!("nothing to scan");
            }
            let paths: Vec<String> = paths.iter().map(|p| p.to_string_lossy().into_owned()).collect();
            let log = Log::default();
            let opts = Opts { timeout: super::super::timeout(action), log: false, ..Default::default() };
            // clamd has the signatures loaded already; clamscan needs ~1 GB to load them.
            // Full scans use clamscan anyway: it can stay on one filesystem (no network mounts).
            let daemon = action == Action::QuickScan && cmd::which("clamdscan") && running(&["clamd"]).contains("clamd");
            let mut args: Vec<&str> = if daemon {
                vec!["clamdscan", "--fdpass", "--multiscan", "--infected"]
            } else {
                vec!["-n", "19", "clamscan", "--recursive", "--infected", "--cross-fs=no"]
            };
            args.extend(paths.iter().map(String::as_str));
            let out = if daemon { cmd::output(&log, args[0], &args[1..], opts)? } else { cmd::output(&log, "nice", &args, opts)? };
            let parsed = parse_scan(&out.stdout);
            // Exit 0: clean, 1: found something, 2: errors (some files unreadable, or failure).
            if out.code == Some(2) && parsed.found.is_empty() && parsed.scanned.is_none() {
                bail!("scan failed: {}", out.reason());
            }
            let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
            s.record(action, &parsed.found, Utc::now());
            self.save(&s);
            let scanned = parsed.scanned.map(|n| format!("{n} files scanned")).unwrap_or_else(|| format!("scanned {}", paths.join(" ")));
            let mut msg = match parsed.found.len() {
                0 => format!("No threats found ({scanned})"),
                n => format!("Found {n} infected file{} ({scanned})", if n == 1 { "" } else { "s" }),
            };
            if parsed.errors > 0 || out.code == Some(2) {
                msg.push_str("; some files couldn't be read");
            }
            Ok(msg)
        }
    }

    fn update() -> Result<String> {
        let log = Log::default();
        let opts = Opts { timeout: super::super::timeout(Action::UpdateSignatures), log: false, ..Default::default() };
        // A running freshclam daemon holds the lock; it checks for updates when it starts.
        if running(&["freshclam"]).contains("freshclam") {
            for unit in ["clamav-freshclam.service", "freshclam.service"] {
                let active = cmd::output(&log, "systemctl", &["is-active", "--quiet", unit], opts).is_ok_and(|o| o.success());
                if active {
                    let out = cmd::output(&log, "systemctl", &["restart", "--no-ask-password", unit], opts)?;
                    if !out.success() {
                        bail!("restarting {unit}: {}", out.reason());
                    }
                    return Ok(format!("Restarted {unit}, which checks for new signatures as it starts"));
                }
            }
            bail!("the freshclam daemon is running outside systemd and holds the update lock");
        }
        let out = cmd::output(&log, "freshclam", &["--stdout"], opts)?;
        if !out.success() {
            bail!("freshclam failed: {}", out.reason());
        }
        let lines: Vec<&str> =
            out.stdout.lines().map(str::trim).filter(|l| l.contains("updated") || l.contains("up-to-date") || l.contains("up to date")).collect();
        Ok(if lines.is_empty() { "Signatures checked".into() } else { lines.join("; ") })
    }

    /// Which of these process names are running (from `/proc/*/comm`).
    fn running(names: &[&str]) -> HashSet<String> {
        let mut found = HashSet::new();
        let Ok(rd) = std::fs::read_dir("/proc") else { return found };
        for e in rd.flatten() {
            if !e.file_name().to_string_lossy().bytes().all(|b| b.is_ascii_digit()) {
                continue;
            }
            if let Ok(comm) = std::fs::read_to_string(e.path().join("comm")) {
                let comm = comm.trim();
                if names.contains(&comm) {
                    found.insert(comm.to_string());
                }
            }
        }
        found
    }

    fn capitalize(s: &str) -> String {
        let mut c = s.chars();
        c.next().map(|f| f.to_uppercase().chain(c).collect()).unwrap_or_default()
    }

    impl super::super::Provider for Clamav {
        fn status(&self) -> rmm_proto::security::Report {
            let (p, detections) = self.product();
            rmm_proto::security::Report { products: vec![p], detections, error: None }
        }

        fn run(&self, product: ProductKind, action: Action) -> Result<String> {
            if product != ProductKind::Clamav {
                bail!("only ClamAV can be controlled on this machine");
            }
            Clamav::run(self, action)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_parses() {
        let (engine, sigs, date) = parse_version("ClamAV 1.0.7/27455/Wed Nov  6 09:35:43 2024\n").unwrap();
        assert_eq!((engine.as_str(), sigs.as_deref()), ("1.0.7", Some("27455")));
        let local = date.unwrap().with_timezone(&Local);
        assert_eq!(local.format("%Y-%m-%d %H:%M").to_string(), "2024-11-06 09:35");
        let (engine, sigs, date) = parse_version("ClamAV 1.4.1").unwrap();
        assert_eq!((engine.as_str(), sigs, date), ("1.4.1", None, None));
        assert!(parse_version("clamscan: command not found").is_none());
    }

    #[test]
    fn scan_output_parses() {
        let out = "/home/bob/eicar.com: Win.Test.EICAR_HDB-1 FOUND\n/home/bob/odd: name.txt: Eicar-Signature FOUND\n\
                   /root/secret: Access denied. ERROR\n\n----------- SCAN SUMMARY -----------\nKnown viruses: 8700000\n\
                   Scanned directories: 12\nScanned files: 340\nInfected files: 2\n";
        let s = parse_scan(out);
        assert_eq!(s.found, [
            ("/home/bob/eicar.com".to_string(), "Win.Test.EICAR_HDB-1".to_string()),
            ("/home/bob/odd: name.txt".to_string(), "Eicar-Signature".to_string()),
        ]);
        assert_eq!((s.scanned, s.errors), (Some(340), 1));
    }

    #[test]
    fn findings_are_remembered_and_settle() {
        let t0 = Utc::now() - chrono::Duration::days(40);
        let mut s = State::default();
        s.record(Action::QuickScan, &[("/tmp/a".into(), "Eicar".into()), ("/tmp/b".into(), "Eicar".into())], t0);
        assert_eq!(s.last_quick_scan, Some(t0));
        assert!(s.last_full_scan.is_none());
        let id_a = detection_id("/tmp/a", "Eicar");
        assert!(id_a.starts_with("clamav-") && id_a != detection_id("/tmp/b", "Eicar"));
        // /tmp/a was deleted.
        assert!(s.settle(|p| p != "/tmp/a", t0));
        let d = s.detections();
        let a = d.iter().find(|d| d.id == id_a).unwrap();
        assert_eq!(a.status, ThreatStatus::Removed);
        assert_eq!(d.iter().filter(|d| d.status == ThreatStatus::Active).count(), 1);
        assert!(!s.settle(|p| p != "/tmp/a", t0), "nothing changed");
        // Found again: active again, same id.
        s.record(Action::FullScan, &[("/tmp/a".into(), "Eicar".into())], t0);
        assert_eq!(s.detections().iter().find(|d| d.id == id_a).unwrap().status, ThreatStatus::Active);
        // Removed 30+ days ago: forgotten.
        s.settle(|p| p != "/tmp/a", t0);
        assert!(s.settle(|p| p != "/tmp/a", Utc::now()));
        assert!(s.detections().iter().all(|d| d.id != id_a));
    }

    #[test]
    fn quick_and_full_paths() {
        let root = std::env::temp_dir().join(format!("rmm-clam-{}", uuid::Uuid::new_v4()));
        for d in ["home", "tmp", "proc", "etc", "usr"] {
            std::fs::create_dir_all(root.join(d)).unwrap();
        }
        std::fs::write(root.join("vmlinuz"), b"").unwrap();
        let names = |v: Vec<PathBuf>| v.iter().map(|p| p.file_name().unwrap().to_string_lossy().into_owned()).collect::<Vec<_>>();
        assert_eq!(names(scan_paths(Action::QuickScan, &root)), ["home", "tmp"]);
        assert_eq!(names(scan_paths(Action::FullScan, &root)), ["etc", "home", "tmp", "usr"]);
        std::fs::remove_dir_all(&root).unwrap();
    }
}
