//! Time Machine: `tmutil latestbackup` names the newest backup, whose folder is its local
//! time (`2026-11-23-101503`, `...backup` on APFS destinations); `tmutil status` says whether
//! one is running; `AutoBackup` in `com.apple.TimeMachine`'s preferences whether backups
//! happen on their own.

#![cfg_attr(not(target_os = "macos"), allow(dead_code))]

use chrono::{DateTime, Local, NaiveDateTime, TimeZone, Utc};
use rmm_proto::checks::{BackupJob, BackupResult};

pub async fn read() -> Result<Vec<BackupJob>, String> {
    #[cfg(target_os = "macos")]
    {
        let latest = super::run("tmutil", &["latestbackup"], &[]).await;
        let status = super::run("tmutil", &["status"], &[]).await.unwrap_or_default();
        let auto = super::run("defaults", &["read", "/Library/Preferences/com.apple.TimeMachine", "AutoBackup"], &[]).await.ok();
        match latest {
            Ok(path) => Ok(vec![job(&path, &status, auto.as_deref())]),
            // No destination, or no backup yet: tmutil says so on stderr and exits non-zero.
            Err(e) if e.contains("No machine directory") || e.contains("No backups") || e.contains("Unable to locate") => {
                Ok(vec![BackupJob { provider: "timemachine".into(), job: "Time Machine".into(), last_run_at: None, last_success_at: None, last_result: BackupResult::Unknown, message: e, size_bytes: None }])
            }
            Err(e) => Err(e),
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        Err("Time Machine is only on macOS".into())
    }
}

/// The time of a backup from its path.
pub(super) fn backup_time(path: &str) -> Option<DateTime<Utc>> {
    let last = path.trim().trim_end_matches('/').rsplit('/').next()?;
    let stamp = last.strip_suffix(".backup").unwrap_or(last);
    let n = NaiveDateTime::parse_from_str(stamp, "%Y-%m-%d-%H%M%S").ok()?;
    Local.from_local_datetime(&n).earliest().map(|t| t.with_timezone(&Utc))
}

pub(super) fn job(latest: &str, status: &str, auto_backup: Option<&str>) -> BackupJob {
    let t = backup_time(latest);
    let running = status.lines().any(|l| l.trim().trim_end_matches(';').replace(' ', "") == "Running=1");
    let mut message = match t {
        Some(_) => format!("latest backup {}", latest.trim().rsplit('/').next().unwrap_or("")),
        None => "no backup found".into(),
    };
    if auto_backup.is_some_and(|a| a.trim() == "0") {
        message.push_str("; automatic backups are off");
    }
    BackupJob {
        provider: "timemachine".into(),
        job: "Time Machine".into(),
        last_run_at: t,
        last_success_at: t,
        last_result: if running {
            BackupResult::Running
        } else if t.is_some() {
            BackupResult::Success
        } else {
            BackupResult::Unknown
        },
        message,
        size_bytes: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn local(s: &str) -> DateTime<Utc> {
        Local.from_local_datetime(&NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S").unwrap()).earliest().unwrap().with_timezone(&Utc)
    }

    #[test]
    fn latest_backups() {
        assert_eq!(backup_time(include_str!("fixtures/tmutil-latest-hfs.txt")), Some(local("2026-11-23 10:15:03")));
        assert_eq!(backup_time(include_str!("fixtures/tmutil-latest-apfs.txt")), Some(local("2026-11-22 21:30:45")));
        assert_eq!(backup_time("/Volumes/x/not-a-date"), None);
        let j = job(include_str!("fixtures/tmutil-latest-apfs.txt"), include_str!("fixtures/tmutil-status.txt"), Some("0\n"));
        assert_eq!(j.last_result, BackupResult::Running);
        assert!(j.message.ends_with("automatic backups are off"), "{}", j.message);
        let j = job(include_str!("fixtures/tmutil-latest-hfs.txt"), "Backup session status:\n{\n    ClientID = \"com.apple.backupd\";\n    Running = 0;\n}\n", Some("1"));
        assert_eq!((j.last_result, j.message.as_str()), (BackupResult::Success, "latest backup 2026-11-23-101503"));
    }
}
