//! restic: `restic snapshots --latest 1 --json`, with the repository and its password from an
//! env file already on the machine (`RESTIC_REPOSITORY`, `RESTIC_PASSWORD_FILE`...). A snapshot
//! is a finished backup; restic keeps no record of failed runs, so "failed" here means the
//! repository can't be read, and a backup that stopped running shows as stale.

use chrono::{DateTime, Utc};
use rmm_proto::checks::{BackupJob, BackupResult, BackupSource};

pub async fn read(s: &BackupSource) -> Result<Vec<BackupJob>, String> {
    let mut env = super::source_env(s)?;
    if let Some(repo) = s.repo.as_deref().filter(|r| !r.trim().is_empty()) {
        env.retain(|(k, _)| k != "RESTIC_REPOSITORY");
        env.push(("RESTIC_REPOSITORY".into(), repo.trim().to_string()));
    }
    let job = match env.iter().find(|(k, _)| k == "RESTIC_REPOSITORY") {
        Some((_, r)) => super::redact(r),
        None => return Err("no repository: set RESTIC_REPOSITORY in the env file, or the source's repository".into()),
    };
    if !env.iter().any(|(k, _)| k.starts_with("RESTIC_PASSWORD")) {
        return Err("no password: set RESTIC_PASSWORD_FILE (or RESTIC_PASSWORD_COMMAND) in the env file".into());
    }
    match super::run("restic", &["snapshots", "--latest", "1", "--json", "--no-lock"], &env).await {
        Ok(out) => Ok(vec![parse(&out, &job)?]),
        Err(e) => Ok(vec![super::failed("restic", job, e)]),
    }
}

pub(super) fn parse(json: &str, job: &str) -> Result<BackupJob, String> {
    let v: serde_json::Value = serde_json::from_str(json.trim()).map_err(|e| format!("unreadable restic output: {e}"))?;
    let snaps = v.as_array().ok_or("unexpected restic output")?;
    let latest = snaps
        .iter()
        .filter_map(|s| Some((DateTime::parse_from_rfc3339(s["time"].as_str()?).ok()?.with_timezone(&Utc), s)))
        .max_by_key(|(t, _)| *t);
    Ok(match latest {
        Some((t, s)) => BackupJob {
            provider: "restic".into(),
            job: job.to_string(),
            last_run_at: Some(t),
            last_success_at: Some(t),
            last_result: BackupResult::Success,
            message: format!("snapshot {} of {}", s["short_id"].as_str().unwrap_or("?"), s["paths"].as_array().map(|p| p.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>().join(", ")).unwrap_or_default()),
            size_bytes: s["summary"]["total_bytes_processed"].as_u64(),
        },
        None => BackupJob {
            provider: "restic".into(),
            job: job.to_string(),
            last_run_at: None,
            last_success_at: None,
            last_result: BackupResult::Unknown,
            message: "the repository has no snapshots".into(),
            size_bytes: None,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshots() {
        let j = parse(include_str!("fixtures/restic-snapshots.json"), "/srv/restic").unwrap();
        // The /etc snapshot at 03:30Z is newer than /srv/data's at 00:00:04Z.
        assert_eq!(j.last_success_at.unwrap().to_rfc3339(), "2026-11-23T03:30:00+00:00");
        assert_eq!((j.last_result, j.message.as_str(), j.size_bytes), (BackupResult::Success, "snapshot 77 of /etc", None));
        let empty = parse("[]", "/srv/restic").unwrap();
        assert_eq!((empty.last_result, empty.last_success_at), (BackupResult::Unknown, None));
        assert!(parse("{}", "x").is_err());
    }

    #[tokio::test]
    async fn needs_a_repository_and_a_password() {
        let s = BackupSource { provider: "restic".into(), ..Default::default() };
        assert!(read(&s).await.unwrap_err().contains("repository"));
        let s = BackupSource { provider: "restic".into(), repo: Some("/srv/restic".into()), ..Default::default() };
        assert!(read(&s).await.unwrap_err().contains("password"));
        let s = BackupSource { provider: "restic".into(), env_file: Some("relative".into()), ..Default::default() };
        assert!(read(&s).await.unwrap_err().contains("absolute"));
    }
}
