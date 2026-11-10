//! Polled watchers for the changes that matter for persistence and tampering:
//!
//! - **Files of interest:** autostart locations (cron, systemd units, startup folders,
//!   scheduled tasks, launch agents), SSH keys, shell profiles, hosts and sudoers. Snapshots of
//!   size and modification time, diffed into create/modify/delete events.
//! - **Canaries:** decoy documents in each user's folder. Ransomware encrypts or renames
//!   them along with everything else; nothing legitimate touches them.
//! - **Registry (Windows):** Run/RunOnce keys of the machine and every loaded user hive,
//!   Winlogon, Image File Execution Options debuggers and services.
//! - **Modules:** Linux kernel modules, Windows drivers.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use rmm_proto::telemetry::{Event, EventKind, FileEvent, ModuleEvent};

/// Expands one `*` path component (`/home/*/.ssh`).
pub fn expand(pattern: &str) -> Vec<PathBuf> {
    let p = Path::new(pattern);
    let mut out = vec![PathBuf::new()];
    for comp in p.components() {
        let c = comp.as_os_str().to_string_lossy();
        if c == "*" {
            out = out
                .into_iter()
                .flat_map(|base| std::fs::read_dir(&base).into_iter().flatten().flatten().filter(|e| e.path().is_dir()).map(|e| e.path()).collect::<Vec<_>>())
                .collect();
        } else {
            for b in &mut out {
                b.push(comp.as_os_str());
            }
        }
    }
    out
}

/// (path pattern, depth): depth 0 watches the path itself, 1 a directory's entries...
fn watch_patterns() -> Vec<(String, usize)> {
    let mut v: Vec<(&str, usize)> = if cfg!(windows) {
        vec![
            ("C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup", 1),
            ("C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup", 1),
            ("C:\\Windows\\System32\\Tasks", 3),
            ("C:\\Windows\\System32\\drivers\\etc\\hosts", 0),
            ("C:\\Windows\\System32\\GroupPolicy\\Machine\\Scripts", 3),
        ]
    } else if cfg!(target_os = "macos") {
        vec![
            ("/Library/LaunchAgents", 1),
            ("/Library/LaunchDaemons", 1),
            ("/Users/*/Library/LaunchAgents", 1),
            ("/etc/hosts", 0),
            ("/etc/sudoers", 0),
            ("/private/etc/sudoers.d", 1),
            ("/private/var/at/tabs", 1),
            ("/Users/*/.ssh/authorized_keys", 0),
            ("/Users/*/.zshrc", 0),
        ]
    } else {
        vec![
            ("/etc/crontab", 0),
            ("/etc/cron.d", 1),
            ("/etc/cron.hourly", 1),
            ("/etc/cron.daily", 1),
            ("/etc/cron.weekly", 1),
            ("/var/spool/cron", 2),
            ("/etc/systemd/system", 2),
            ("/etc/ld.so.preload", 0),
            ("/etc/rc.local", 0),
            ("/etc/profile.d", 1),
            ("/etc/sudoers", 0),
            ("/etc/sudoers.d", 1),
            ("/etc/passwd", 0),
            ("/etc/shadow", 0),
            ("/etc/hosts", 0),
            ("/etc/xdg/autostart", 1),
            ("/root/.ssh", 1),
            ("/root/.bashrc", 0),
            ("/home/*/.ssh", 1),
            ("/home/*/.bashrc", 0),
            ("/home/*/.profile", 0),
            ("/home/*/.config/autostart", 1),
            ("/home/*/.config/systemd/user", 2),
        ]
    };
    let mut out: Vec<(String, usize)> = v.drain(..).map(|(p, d)| (p.to_string(), d)).collect();
    // Tests point the sensor at a scratch directory.
    #[cfg(debug_assertions)]
    if let Ok(extra) = std::env::var("RMM_SENSOR_WATCH") {
        out.extend(std::env::split_paths(&extra).map(|p| (p.to_string_lossy().into_owned(), 3)));
    }
    out
}

fn walk(path: &Path, depth: usize, out: &mut HashMap<PathBuf, (u64, Option<SystemTime>)>) {
    if out.len() > 20_000 {
        return;
    }
    let Ok(md) = std::fs::symlink_metadata(path) else { return };
    if md.is_file() || md.file_type().is_symlink() {
        out.insert(path.to_path_buf(), (md.len(), md.modified().ok()));
    } else if md.is_dir() && depth > 0 {
        for e in std::fs::read_dir(path).into_iter().flatten().flatten() {
            walk(&e.path(), depth - 1, out);
        }
    }
}

#[derive(Default)]
pub struct FileWatch {
    snap: HashMap<PathBuf, (u64, Option<SystemTime>)>,
    primed: bool,
}

impl FileWatch {
    pub fn poll(&mut self) -> Vec<Event> {
        let mut now = HashMap::new();
        for (pattern, depth) in watch_patterns() {
            for p in expand(&pattern) {
                walk(&p, depth, &mut now);
            }
        }
        let mut events = Vec::new();
        if self.primed {
            for (p, v) in &now {
                match self.snap.get(p) {
                    None => events.push(file_event("create", p)),
                    Some(old) if old != v => events.push(file_event("modify", p)),
                    _ => {}
                }
            }
            for p in self.snap.keys().filter(|p| !now.contains_key(*p)) {
                events.push(file_event("delete", p));
            }
        }
        self.snap = now;
        self.primed = true;
        events
    }
}

pub fn file_event(action: &str, p: &Path) -> Event {
    let mut e = Event::new(EventKind::File, action);
    e.file = Some(FileEvent { path: p.to_string_lossy().into_owned(), old_path: None, sha256: None });
    e
}

// ---------------------------------------------------------------------------
// Canaries
// ---------------------------------------------------------------------------

const CANARY_NAME: &str = if cfg!(windows) { "~rmm-canary-do-not-touch.docx" } else { ".rmm-canary-do-not-touch.docx" };
/// Fixed, recognisable content: a zip header and a note.
const CANARY_BODY: &[u8] = b"PK\x03\x04 This file is a decoy placed by the RMM agent's ransomware protection. If it changes, \
the agent raises an alert. Please leave it alone; deleting it also raises an alert.\n";

fn canary_dirs() -> Vec<PathBuf> {
    #[cfg(debug_assertions)]
    if let Ok(dirs) = std::env::var("RMM_SENSOR_CANARY_DIRS") {
        return std::env::split_paths(&dirs).collect();
    }
    let patterns: &[&str] = if cfg!(windows) {
        &["C:\\Users\\*\\Documents"]
    } else if cfg!(target_os = "macos") {
        &["/Users/*/Documents"]
    } else {
        &["/home/*", "/root"]
    };
    patterns
        .iter()
        .flat_map(|p| expand(p))
        .filter(|d| d.is_dir())
        .filter(|d| {
            let s = d.to_string_lossy().to_ascii_lowercase();
            !s.contains("\\public\\") && !s.contains("\\default") && !s.contains("/shared")
        })
        .collect()
}

/// What happened to a decoy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tripped {
    pub path: PathBuf,
    pub what: &'static str,
}

#[derive(Default)]
pub struct Canaries {
    files: Vec<PathBuf>,
    /// Re-planting waits a little after a trip, so one attack isn't reported over and over.
    tripped_at: HashMap<PathBuf, std::time::Instant>,
}

fn manifest() -> Option<PathBuf> {
    crate::config::state_subdir("sensor").ok().map(|d| d.join("canaries.json"))
}

impl Canaries {
    pub fn count(&self) -> usize {
        self.files.len()
    }

    /// Places (or replaces) decoys in every user folder.
    pub fn plant(&mut self) {
        self.plant_in(&canary_dirs());
    }

    pub fn plant_in(&mut self, dirs: &[PathBuf]) {
        for d in dirs {
            let p = d.join(CANARY_NAME);
            if self.tripped_at.get(&p).is_some_and(|t| t.elapsed().as_secs() < 600) {
                continue;
            }
            if std::fs::read(&p).ok().as_deref() != Some(CANARY_BODY) && std::fs::write(&p, CANARY_BODY).is_err() {
                continue;
            }
            if !self.files.contains(&p) {
                self.files.push(p);
            }
        }
        if let Some(m) = manifest() {
            let _ = std::fs::write(m, serde_json::to_vec(&self.files).unwrap_or_default());
        }
    }

    /// Decoys that were changed, renamed or deleted since the last check.
    pub fn check(&mut self) -> Vec<Tripped> {
        let mut out = Vec::new();
        self.files.retain(|p| {
            let what = match std::fs::read(p) {
                Ok(b) if b == CANARY_BODY => return true,
                Ok(_) => "modified",
                Err(_) => {
                    // Renamed (an extension appended) or deleted.
                    let renamed = p.parent().and_then(|d| std::fs::read_dir(d).ok()).is_some_and(|rd| {
                        rd.flatten().any(|e| e.file_name().to_string_lossy().starts_with(CANARY_NAME) && e.path() != *p)
                    });
                    if renamed { "renamed" } else { "deleted" }
                }
            };
            out.push(Tripped { path: p.clone(), what });
            false
        });
        for t in &out {
            self.tripped_at.insert(t.path.clone(), std::time::Instant::now());
        }
        out
    }

    /// Takes every decoy away (the policy turned them off, or the sensor is being disabled).
    pub fn remove_all(&mut self) {
        let mut files = std::mem::take(&mut self.files);
        if let Some(m) = manifest()
            && let Ok(b) = std::fs::read(&m)
        {
            files.extend(serde_json::from_slice::<Vec<PathBuf>>(&b).unwrap_or_default());
            let _ = std::fs::remove_file(m);
        }
        for p in files {
            if std::fs::read(&p).ok().as_deref() == Some(CANARY_BODY) {
                let _ = std::fs::remove_file(&p);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Modules
// ---------------------------------------------------------------------------

/// `/proc/modules` -> module names.
pub fn parse_proc_modules(s: &str) -> Vec<String> {
    s.lines().filter_map(|l| l.split_whitespace().next()).map(str::to_string).collect()
}

/// `driverquery /fo csv /nh` -> driver names.
pub fn parse_driverquery(s: &str) -> Vec<String> {
    s.lines().filter_map(|l| l.split("\",\"").next()).map(|n| n.trim_matches(['"', '\r', ' ']).to_string()).filter(|n| !n.is_empty()).collect()
}

fn modules() -> Vec<String> {
    if cfg!(target_os = "linux") {
        std::fs::read_to_string("/proc/modules").map(|s| parse_proc_modules(&s)).unwrap_or_default()
    } else if cfg!(windows) {
        let log = crate::patch::cmd::Log::default();
        let opts = crate::patch::cmd::Opts { timeout: std::time::Duration::from_secs(60), log: false, ..Default::default() };
        crate::patch::cmd::output(&log, "driverquery.exe", &["/fo", "csv", "/nh"], opts).map(|o| parse_driverquery(&o.stdout)).unwrap_or_default()
    } else {
        vec![]
    }
}

#[derive(Default)]
pub struct ModuleWatch {
    known: std::collections::HashSet<String>,
    primed: bool,
}

impl ModuleWatch {
    pub fn poll(&mut self) -> Vec<Event> {
        let now: std::collections::HashSet<String> = modules().into_iter().collect();
        let events = if self.primed {
            now.difference(&self.known)
                .map(|n| {
                    let mut e = Event::new(EventKind::Module, "load");
                    e.module = Some(ModuleEvent { name: n.clone(), path: None });
                    e
                })
                .collect()
        } else {
            vec![]
        };
        self.known = now;
        self.primed = true;
        events
    }
}

// ---------------------------------------------------------------------------
// Registry (Windows)
// ---------------------------------------------------------------------------

#[derive(Default)]
pub struct RegistryWatch {
    #[allow(dead_code)]
    snap: HashMap<(String, String), String>,
    #[allow(dead_code)]
    primed: bool,
}

#[cfg(windows)]
impl RegistryWatch {
    fn read() -> HashMap<(String, String), String> {
        use winreg::RegKey;
        use winreg::enums::{HKEY_LOCAL_MACHINE, HKEY_USERS, KEY_READ};
        let mut out = HashMap::new();
        let mut values = |root: &RegKey, root_name: &str, path: &str, only: Option<&[&str]>| {
            if let Ok(k) = root.open_subkey_with_flags(path, KEY_READ) {
                for (name, v) in k.enum_values().flatten() {
                    if only.is_some_and(|o| !o.iter().any(|x| x.eq_ignore_ascii_case(&name))) {
                        continue;
                    }
                    out.insert((format!("{root_name}\\{path}"), name), v.to_string());
                }
            }
        };
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        for p in [
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
            "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
            "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        ] {
            values(&hklm, "HKLM", p, None);
        }
        values(&hklm, "HKLM", "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", Some(&["Shell", "Userinit"]));
        if let Ok(ifeo) = hklm.open_subkey_with_flags("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options", KEY_READ) {
            for sub in ifeo.enum_keys().flatten() {
                values(&hklm, "HKLM", &format!("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\{sub}"), Some(&["Debugger"]));
            }
        }
        if let Ok(svcs) = hklm.open_subkey_with_flags("SYSTEM\\CurrentControlSet\\Services", KEY_READ) {
            for sub in svcs.enum_keys().flatten() {
                values(&hklm, "HKLM", &format!("SYSTEM\\CurrentControlSet\\Services\\{sub}"), Some(&["ImagePath"]));
            }
        }
        let hku = RegKey::predef(HKEY_USERS);
        for sid in hku.enum_keys().flatten().filter(|s| s.starts_with("S-1-5-21-") && !s.ends_with("_Classes")) {
            for p in ["Software\\Microsoft\\Windows\\CurrentVersion\\Run", "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"] {
                values(&hku, "HKU", &format!("{sid}\\{p}"), None);
            }
        }
        out
    }

    pub fn poll(&mut self) -> Vec<Event> {
        use rmm_proto::telemetry::RegEvent;
        let now = Self::read();
        let mut events = Vec::new();
        if self.primed {
            let ev = |action: &str, k: &(String, String), data: Option<String>| {
                let mut e = Event::new(EventKind::Registry, action);
                e.registry = Some(RegEvent { key: k.0.clone(), value: k.1.clone(), data });
                e
            };
            for (k, v) in &now {
                if self.snap.get(k) != Some(v) {
                    events.push(ev("set", k, Some(v.clone())));
                }
            }
            for k in self.snap.keys().filter(|k| !now.contains_key(*k)) {
                events.push(ev("delete", k, None));
            }
        }
        self.snap = now;
        self.primed = true;
        events
    }
}

#[cfg(not(windows))]
impl RegistryWatch {
    pub fn poll(&mut self) -> Vec<Event> {
        vec![]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canaries_trip_on_change_rename_and_delete() {
        let root = std::env::temp_dir().join(format!("rmm-canary-{}", uuid::Uuid::new_v4()));
        let dirs: Vec<PathBuf> = (0..3).map(|i| root.join(format!("u{i}"))).collect();
        for d in &dirs {
            std::fs::create_dir_all(d).unwrap();
        }
        let mut c = Canaries::default();
        c.plant_in(&dirs);
        assert_eq!(c.count(), 3);
        assert!(c.check().is_empty());
        std::fs::write(dirs[0].join(CANARY_NAME), b"encrypted garbage").unwrap();
        std::fs::rename(dirs[1].join(CANARY_NAME), dirs[1].join(format!("{CANARY_NAME}.locked"))).unwrap();
        std::fs::remove_file(dirs[2].join(CANARY_NAME)).unwrap();
        let mut t: Vec<(String, &str)> = c.check().into_iter().map(|t| (t.path.parent().unwrap().file_name().unwrap().to_string_lossy().into_owned(), t.what)).collect();
        t.sort();
        assert_eq!(t, [("u0".to_string(), "modified"), ("u1".into(), "renamed"), ("u2".into(), "deleted")]);
        assert!(c.check().is_empty(), "reported once");
        c.plant_in(&dirs);
        assert_eq!(c.count(), 0, "not re-planted right after an attack");
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn module_lists_parse() {
        assert_eq!(parse_proc_modules("nf_conntrack 172032 2 nft_ct, Live 0x0\nwireguard 98304 0 - Live 0x0\n"), ["nf_conntrack", "wireguard"]);
        assert_eq!(parse_driverquery("\"1394ohci\",\"1394 OHCI Compliant Host Controller\",\"Kernel \",\"10/12/2023\"\r\n\"ACPI\",\"Microsoft ACPI Driver\",\"Kernel \",\"\"\r\n"), ["1394ohci", "ACPI"]);
    }

    #[test]
    fn file_watch_diffs() {
        let mut w = FileWatch::default();
        let mut snap = HashMap::new();
        let root = std::env::temp_dir().join(format!("rmm-watch-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(root.join("a")).unwrap();
        std::fs::write(root.join("a/x"), b"1").unwrap();
        walk(&root, 2, &mut snap);
        assert_eq!(snap.len(), 1);
        walk(&root, 0, &mut HashMap::new());
        assert!(expand(&format!("{}/*/x", root.display())).iter().any(|p| p.ends_with("a/x")));
        let _ = w.poll();
        std::fs::remove_dir_all(&root).unwrap();
    }
}
