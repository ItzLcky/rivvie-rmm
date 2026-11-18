//! File scanning: walks directories at low priority and checks each file with the scan engine
//! (`rmm-scan`: the signature database, the bundle's legacy hashes and file rules, YARA,
//! heuristics, archives and macros). What to do about a match is the sensor's call
//! ([`super::best`]); this module only finds.
//!
//! Files that scanned clean go into the verdict cache, so an unchanged file isn't read again
//! until the engine, database or bundle changes.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use rmm_scan::cache::Cache;
use rmm_scan::{Engine, Match};

use super::policy::Exclusions;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Quick,
    Full,
    Path,
}

pub struct Finding {
    pub path: PathBuf,
    pub sha256: String,
    /// Every match, rule exclusions already applied.
    pub matches: Vec<Match>,
}

/// Where a quick or full scan looks.
pub fn roots(kind: Kind) -> Vec<PathBuf> {
    let quick: Vec<&str> = if cfg!(windows) {
        vec![
            "C:\\Users\\*\\Downloads",
            "C:\\Users\\*\\Desktop",
            "C:\\Users\\*\\AppData\\Local\\Temp",
            "C:\\Users\\*\\AppData\\Roaming",
            "C:\\Users\\Public",
            "C:\\Windows\\Temp",
            "C:\\ProgramData",
        ]
    } else if cfg!(target_os = "macos") {
        vec!["/Users/*/Downloads", "/Users/*/Desktop", "/Users/*/Library/LaunchAgents", "/Library/LaunchAgents", "/Library/LaunchDaemons", "/tmp", "/private/var/tmp"]
    } else {
        vec!["/home", "/root", "/tmp", "/var/tmp", "/dev/shm", "/opt", "/srv", "/etc/cron.d", "/etc/systemd/system", "/var/www"]
    };
    #[cfg(debug_assertions)]
    if let Ok(extra) = std::env::var("RMM_SENSOR_SCAN_ROOTS") {
        return std::env::split_paths(&extra).collect();
    }
    match kind {
        Kind::Full => {
            if cfg!(windows) {
                ('C'..='Z').map(|d| PathBuf::from(format!("{d}:\\"))).filter(|p| p.is_dir()).collect()
            } else {
                vec![PathBuf::from("/")]
            }
        }
        _ => quick.iter().flat_map(|p| super::watch_expand(p)).filter(|p| p.exists()).collect(),
    }
}

/// Pseudo-filesystems and our own state (quarantine!) are never scanned.
fn skip_dir(p: &Path) -> bool {
    let s = p.to_string_lossy();
    if p.starts_with(crate::config::state_dir()) {
        return true;
    }
    if cfg!(windows) {
        let l = s.to_ascii_lowercase();
        l.ends_with("\\system volume information") || l.ends_with("\\$recycle.bin") || l.contains("\\windows\\winsxs")
    } else {
        matches!(s.as_ref(), "/proc" | "/sys" | "/dev" | "/run" | "/snap" | "/var/lib/docker" | "/var/lib/containers")
    }
}

pub struct Scanner<'a> {
    pub engine: &'a Engine,
    pub excl: &'a Exclusions,
    pub cache: Option<&'a Mutex<Cache>>,
    /// Files read and checked.
    pub scanned: u64,
    /// Files skipped because the cache knew them clean.
    pub cached: u64,
}

impl<'a> Scanner<'a> {
    pub fn new(engine: &'a Engine, excl: &'a Exclusions, cache: Option<&'a Mutex<Cache>>) -> Self {
        Scanner { engine, excl, cache, scanned: 0, cached: 0 }
    }

    fn cache(&self) -> Option<std::sync::MutexGuard<'a, Cache>> {
        self.cache.map(|c| c.lock().unwrap_or_else(|e| e.into_inner()))
    }

    /// Checks one file. `None` when it's clean, excluded, unchanged since a clean scan, or
    /// unreadable.
    pub fn file(&mut self, path: &Path) -> Option<Finding> {
        let ps = path.to_string_lossy();
        if self.excl.path(&ps) {
            return None;
        }
        let md = std::fs::symlink_metadata(path).ok()?;
        if !md.is_file() || md.len() == 0 {
            return None;
        }
        let key = rmm_scan::cache::key(path, &md);
        if let Some(k) = &key
            && self.cache().is_some_and(|mut c| c.clean(k))
        {
            self.cached += 1;
            return None;
        }
        let v = self.engine.scan_path(path).ok()?;
        self.scanned += 1;
        if v.clean() {
            if let (Some(k), Some(mut c)) = (key, self.cache()) {
                c.insert(k);
            }
            return None;
        }
        if self.excl.hash(&v.sha256) {
            return None;
        }
        let matches: Vec<Match> = v.matches.into_iter().filter(|m| !self.excl.rule(&m.id)).collect();
        if matches.is_empty() {
            return None;
        }
        Some(Finding { path: path.to_path_buf(), sha256: v.sha256, matches })
    }

    /// Walks `root` (same filesystem only), calling `found` for each finding and `pace` after
    /// every file so the caller can throttle or stop (return false).
    pub fn walk(&mut self, root: &Path, found: &mut dyn FnMut(Finding), pace: &mut dyn FnMut() -> bool) {
        #[cfg(unix)]
        let dev = {
            use std::os::unix::fs::MetadataExt;
            std::fs::metadata(root).map(|m| m.dev()).ok()
        };
        let mut stack = vec![root.to_path_buf()];
        while let Some(p) = stack.pop() {
            let Ok(md) = std::fs::symlink_metadata(&p) else { continue };
            if md.is_dir() {
                if skip_dir(&p) || self.excl.path(&p.to_string_lossy()) {
                    continue;
                }
                #[cfg(unix)]
                {
                    use std::os::unix::fs::MetadataExt;
                    if dev.is_some_and(|d| d != md.dev()) {
                        continue;
                    }
                }
                for e in std::fs::read_dir(&p).into_iter().flatten().flatten() {
                    stack.push(e.path());
                }
            } else if md.is_file() {
                let before = self.cached;
                if let Some(f) = self.file(&p) {
                    found(f);
                }
                // Cache hits cost a stat: only files actually read count against the pace.
                if self.cached == before && !pace() {
                    return;
                }
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use rmm_content::Bundle;
    use rmm_content::files::FileMatcher;

    /// The EICAR string, assembled at runtime so this source file doesn't contain it.
    pub fn eicar() -> String {
        format!("X5O!P%@AP[4\\PZX54(P^)7CC)7{}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*", "}")
    }

    pub fn starter_engine() -> Engine {
        let b = Bundle::parse(rmm_content::STARTER.as_bytes()).unwrap();
        Engine::new(None, Some((b.version.clone(), FileMatcher::new(&b).unwrap())), rmm_scan::Limits::default()).unwrap()
    }

    #[test]
    fn finds_by_rule_and_hash_and_honours_exclusions_and_the_cache() {
        let e = starter_engine();
        let root = std::env::temp_dir().join(format!("rmm-scan-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(root.join("sub/deeper")).unwrap();
        std::fs::write(root.join("sub/deeper/e.com"), eicar()).unwrap();
        std::fs::write(root.join("sub/shell.php"), "<?php system($_GET['c']); ?>").unwrap();
        std::fs::write(root.join("clean.txt"), "nothing here").unwrap();
        let excl = Exclusions::default();
        let cache = Mutex::new(Cache::new(rmm_scan::cache::generation(&[&e.generation()]), 1000));
        let mut s = Scanner::new(&e, &excl, Some(&cache));
        let mut found = vec![];
        s.walk(&root, &mut |f| found.push((f.path.file_name().unwrap().to_string_lossy().into_owned(), f.matches[0].id.clone(), f.matches[0].name.clone())), &mut || true);
        found.sort();
        assert_eq!(
            found,
            [("e.com".to_string(), "RMM-HASH".to_string(), "EICAR test file".to_string()), ("shell.php".into(), "RMM-F-0003".into(), "PHP web shell".into())],
            "the hash matches before the rule"
        );
        assert_eq!((s.scanned, s.cached), (3, 0));
        let mut s = Scanner::new(&e, &excl, Some(&cache));
        let mut n = 0;
        s.walk(&root, &mut |_| n += 1, &mut || true);
        assert_eq!((n, s.scanned, s.cached), (2, 2, 1), "the clean file isn't read again; findings always are");
        let p = rmm_proto::security::SensorPolicy {
            exclusions: vec![rmm_proto::security::Exclusion { kind: rmm_proto::security::ExclusionKind::Path, value: root.join("sub/deeper").to_string_lossy().into_owned() }],
            ..Default::default()
        };
        let excl = Exclusions::from_policy(&p);
        let mut s = Scanner::new(&e, &excl, None);
        let mut n = 0;
        s.walk(&root, &mut |_| n += 1, &mut || true);
        assert_eq!(n, 1, "the excluded folder is skipped");
        std::fs::remove_dir_all(&root).unwrap();
    }
}
