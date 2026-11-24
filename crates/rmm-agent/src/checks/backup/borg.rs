//! Borg: `borg list --last 1 --json`, with the repository and passphrase from an env file
//! already on the machine (`BORG_REPO`, `BORG_PASSCOMMAND`...). As with restic, an archive is a
//! finished backup and "failed" means the repository can't be read.

use chrono::{DateTime, Local, NaiveDateTime, TimeZone, Utc};
use rmm_proto::checks::{BackupJob, BackupResult, BackupSource};

pub async fn read(s: &BackupSource) -> Result<Vec<BackupJob>, String> {
    let mut env = super::source_env(s)?;
    if let Some(repo) = s.repo.as_deref().filter(|r| !r.trim().is_empty()) {
        env.retain(|(k, _)| k != "BORG_REPO");
        env.push(("BORG_REPO".into(), repo.trim().to_string()));
    }
    let job = match env.iter().find(|(k, _)| k == "BORG_REPO") {
        Some((_, r)) => super::redact(r),
        None => return Err("no repository: set BORG_REPO in the env file, or the source's repository".into()),
    };
    // Never wait for a passphrase or a host-key prompt.
    env.push(("BORG_RELOCATED_REPO_ACCESS_IS_OK".into(), "no".into()));
    env.push(("BORG_UNKNOWN_UNENCRYPTED_REPO_ACCESS_IS_OK".into(), "no".into()));
    match super::run("borg", &["list", "--last", "1", "--json", "--bypass-lock"], &env).await {
        Ok(out) => Ok(vec![parse(&out, &job)?]),
        Err(e) => Ok(vec![super::failed("borg", job, e)]),
    }
}

/// Borg prints local times without an offset (`2026-11-23T02:00:01.000000`).
fn local_time(s: &str) -> Option<DateTime<Utc>> {
    if let Ok(t) = DateTime::parse_from_rfc3339(s) {
        return Some(t.with_timezone(&Utc));
    }
    let n = NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S%.f").ok()?;
    Local.from_local_datetime(&n).earliest().map(|t| t.with_timezone(&Utc))
}

pub(super) fn parse(json: &str, job: &str) -> Result<BackupJob, String> {
    let v: serde_json::Value = serde_json::from_str(json.trim()).map_err(|e| format!("unreadable borg output: {e}"))?;
    let archives = v["archives"].as_array().ok_or("unexpected borg output")?;
    let latest = archives.iter().filter_map(|a| Some((local_time(a["time"].as_str().or(a["start"].as_str())?)?, a))).max_by_key(|(t, _)| *t);
    Ok(match latest {
        Some((t, a)) => BackupJob {
            provider: "borg".into(),
            job: job.to_string(),
            last_run_at: Some(t),
            last_success_at: Some(t),
            last_result: BackupResult::Success,
            message: format!("archive {}", a["name"].as_str().unwrap_or("?")),
            size_bytes: None,
        },
        None => BackupJob { provider: "borg".into(), job: job.to_string(), last_run_at: None, last_success_at: None, last_result: BackupResult::Unknown, message: "the repository has no archives".into(), size_bytes: None },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn archives() {
        let j = parse(include_str!("fixtures/borg-list.json"), "ssh://nas.corp.example/./fs01").unwrap();
        assert_eq!((j.last_result, j.message.as_str()), (BackupResult::Success, "archive fs01-2026-11-23T02:00:01"));
        let want = Local.from_local_datetime(&NaiveDateTime::parse_from_str("2026-11-23T02:00:01", "%Y-%m-%dT%H:%M:%S").unwrap()).earliest().unwrap();
        assert_eq!(j.last_success_at.unwrap(), want.with_timezone(&Utc), "a local time");
        let none = parse(r#"{"archives": []}"#, "r").unwrap();
        assert_eq!(none.last_result, BackupResult::Unknown);
        assert!(parse("[]", "r").is_err());
    }
}
