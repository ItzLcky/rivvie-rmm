//! The newest file under a directory, for products that leave files behind (SQL dumps, NAS
//! targets, anything with an export folder): its modification time is the last success. Looks
//! three levels deep and at most 20,000 entries.

use std::path::Path;
use std::time::SystemTime;

use chrono::{DateTime, Utc};
use rmm_proto::checks::{BackupJob, BackupResult, BackupSource};

const MAX_DEPTH: usize = 3;
const MAX_ENTRIES: usize = 20_000;

pub fn read(s: &BackupSource) -> Result<Vec<BackupJob>, String> {
    let dir = s.path.as_deref().map(str::trim).filter(|p| !p.is_empty()).ok_or("file_age needs a path")?;
    let root = super::plain_path(dir)?;
    let glob = s.glob.as_deref().map(str::trim).filter(|g| !g.is_empty()).unwrap_or("*");
    let job = if glob == "*" { dir.to_string() } else { format!("{}/{glob}", dir.trim_end_matches(['/', '\\'])) };
    if !root.is_dir() {
        return Ok(vec![super::failed("file_age", job, format!("{dir} isn't a directory this agent can read"))]);
    }
    let mut seen = 0usize;
    let newest = walk(root, glob, 0, &mut seen);
    Ok(vec![match newest {
        Some((t, size, name)) => {
            let t: DateTime<Utc> = t.into();
            BackupJob {
                provider: "file_age".into(),
                job,
                last_run_at: Some(t),
                last_success_at: Some(t),
                last_result: BackupResult::Success,
                message: format!("newest file {name}"),
                size_bytes: Some(size),
            }
        }
        None => BackupJob { provider: "file_age".into(), job, last_run_at: None, last_success_at: None, last_result: BackupResult::Unknown, message: "no matching files".into(), size_bytes: None },
    }])
}

fn walk(dir: &Path, glob: &str, depth: usize, seen: &mut usize) -> Option<(SystemTime, u64, String)> {
    let mut best: Option<(SystemTime, u64, String)> = None;
    let Ok(entries) = std::fs::read_dir(dir) else { return None };
    for e in entries.flatten() {
        *seen += 1;
        if *seen > MAX_ENTRIES {
            break;
        }
        // Symlinks aren't followed.
        let Ok(ft) = e.file_type() else { continue };
        let found = if ft.is_dir() {
            if depth + 1 < MAX_DEPTH { walk(&e.path(), glob, depth + 1, seen) } else { None }
        } else if ft.is_file() && matches(glob, &e.file_name().to_string_lossy()) {
            e.metadata().ok().and_then(|m| Some((m.modified().ok()?, m.len(), e.file_name().to_string_lossy().into_owned())))
        } else {
            None
        };
        if let Some(f) = found
            && best.as_ref().is_none_or(|b| f.0 > b.0)
        {
            best = Some(f);
        }
    }
    best
}

/// `*` and `?` globs, case-insensitive.
pub(super) fn matches(glob: &str, name: &str) -> bool {
    fn m(p: &[u8], s: &[u8]) -> bool {
        match (p.first(), s.first()) {
            (None, None) => true,
            (Some(b'*'), _) => m(&p[1..], s) || (!s.is_empty() && m(p, &s[1..])),
            (Some(b'?'), Some(_)) => m(&p[1..], &s[1..]),
            (Some(a), Some(b)) if a.eq_ignore_ascii_case(b) => m(&p[1..], &s[1..]),
            _ => false,
        }
    }
    m(glob.as_bytes(), name.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn globs() {
        assert!(matches("*.bak", "db-2026-11-23.BAK"));
        assert!(matches("dump-????.sql", "dump-0001.sql"));
        assert!(!matches("*.bak", "db.bak.tmp"));
        assert!(matches("*", "anything"));
    }

    #[test]
    fn newest_matching_file() {
        let dir = std::env::temp_dir().join(format!("rmm-file-age-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("2026/11")).unwrap();
        std::fs::write(dir.join("old.bak"), b"x").unwrap();
        std::thread::sleep(std::time::Duration::from_millis(20));
        std::fs::write(dir.join("2026/11/new.bak"), b"xyz").unwrap();
        std::thread::sleep(std::time::Duration::from_millis(20));
        std::fs::write(dir.join("notes.txt"), b"not a backup").unwrap();
        let s = BackupSource { provider: "file_age".into(), path: Some(dir.to_string_lossy().into()), glob: Some("*.bak".into()), ..Default::default() };
        let j = read(&s).unwrap().remove(0);
        assert_eq!((j.last_result, j.message.as_str(), j.size_bytes), (BackupResult::Success, "newest file new.bak", Some(3)));
        assert!(j.job.ends_with("/*.bak"));
        let none = read(&BackupSource { glob: Some("*.zip".into()), ..s.clone() }).unwrap().remove(0);
        assert_eq!(none.last_result, BackupResult::Unknown);
        let missing = read(&BackupSource { path: Some(dir.join("missing").to_string_lossy().into()), ..s.clone() }).unwrap().remove(0);
        assert_eq!(missing.last_result, BackupResult::Failed);
        assert!(read(&BackupSource { path: Some("../x".into()), ..s }).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
