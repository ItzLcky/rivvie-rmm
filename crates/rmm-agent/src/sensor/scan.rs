//! File scanning: walks directories at low priority, hashes each file and checks it against
//! the bundle's hashes and file rules.

use std::path::{Path, PathBuf};

use rmm_content::files::FileMatcher;
use rmm_content::{FileRule, HashIoc};

use super::policy::Exclusions;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Quick,
    Full,
    Path,
}

pub enum Hit<'a> {
    Hash(&'a HashIoc),
    Rule(&'a FileRule),
}

pub struct Finding<'a> {
    pub path: PathBuf,
    pub sha256: String,
    pub hit: Hit<'a>,
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
    pub matcher: &'a FileMatcher,
    pub excl: &'a Exclusions,
    pub scanned: u64,
}

impl<'a> Scanner<'a> {
    /// Checks one file. `None` when it's clean, excluded or unreadable.
    pub fn file(&mut self, path: &Path) -> Option<Finding<'a>> {
        let ps = path.to_string_lossy();
        if self.excl.path(&ps) {
            return None;
        }
        let md = std::fs::symlink_metadata(path).ok()?;
        if !md.is_file() || md.len() == 0 || md.len() > self.matcher.max_size() {
            return None;
        }
        let data = std::fs::read(path).ok()?;
        self.scanned += 1;
        use sha2::{Digest, Sha256};
        let sha256 = hex::encode(Sha256::digest(&data));
        if self.excl.hash(&sha256) {
            return None;
        }
        if let Some(h) = self.matcher.hash(&sha256) {
            return Some(Finding { path: path.to_path_buf(), sha256, hit: Hit::Hash(h) });
        }
        let rule = self.matcher.scan(&data).into_iter().find(|r| !self.excl.rule(&r.id))?;
        Some(Finding { path: path.to_path_buf(), sha256, hit: Hit::Rule(rule) })
    }

    /// Walks `root` (same filesystem only), calling `found` for each finding and `pace` after
    /// every file so the caller can throttle or stop (return false).
    pub fn walk(&mut self, root: &Path, found: &mut dyn FnMut(Finding<'a>), pace: &mut dyn FnMut() -> bool) {
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
                if let Some(f) = self.file(&p) {
                    found(f);
                }
                if !pace() {
                    return;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmm_content::Bundle;

    #[test]
    fn finds_by_rule_and_hash_and_honours_exclusions() {
        let b = Bundle::parse(rmm_content::STARTER.as_bytes()).unwrap();
        let m = FileMatcher::new(&b).unwrap();
        let root = std::env::temp_dir().join(format!("rmm-scan-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(root.join("sub/deeper")).unwrap();
        // The EICAR string, assembled at runtime so this source file doesn't contain it.
        let eicar = format!("X5O!P%@AP[4\\PZX54(P^)7CC)7{}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*", "}");
        std::fs::write(root.join("sub/deeper/e.com"), &eicar).unwrap();
        std::fs::write(root.join("sub/shell.php"), "<?php system($_GET['c']); ?>").unwrap();
        std::fs::write(root.join("clean.txt"), "nothing here").unwrap();
        let excl = Exclusions::default();
        let mut s = Scanner { matcher: &m, excl: &excl, scanned: 0 };
        let mut found = vec![];
        s.walk(&root, &mut |f| found.push((f.path.file_name().unwrap().to_string_lossy().into_owned(), match f.hit { Hit::Hash(h) => h.name.clone(), Hit::Rule(r) => r.id.clone() })), &mut || true);
        found.sort();
        assert_eq!(found, [("e.com".to_string(), "EICAR test file".to_string()), ("shell.php".into(), "RMM-F-0003".into())], "the hash matches before the rule");
        assert_eq!(s.scanned, 3);
        let p = rmm_proto::security::SensorPolicy {
            exclusions: vec![rmm_proto::security::Exclusion { kind: rmm_proto::security::ExclusionKind::Path, value: root.join("sub/deeper").to_string_lossy().into_owned() }],
            ..Default::default()
        };
        let excl = Exclusions::from_policy(&p);
        let mut s = Scanner { matcher: &m, excl: &excl, scanned: 0 };
        let mut n = 0;
        s.walk(&root, &mut |_| n += 1, &mut || true);
        assert_eq!(n, 1, "the excluded folder is skipped");
        std::fs::remove_dir_all(&root).unwrap();
    }
}
