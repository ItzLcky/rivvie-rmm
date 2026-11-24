//! Windows Server Backup: `Get-WBSummary` as JSON, or the `Microsoft-Windows-Backup` event log
//! when the cmdlets aren't there (event 4 is a finished backup; an error-level event is a
//! failure; event 1, started, is a backup running).

use chrono::{DateTime, Utc};
use rmm_proto::checks::{BackupJob, BackupResult};

#[cfg(windows)]
const SUMMARY: &str = "Get-WBSummary | Select-Object LastSuccessfulBackupTime,LastBackupTime,LastBackupResultHR,DetailedMessage,NumberOfVersions,CurrentOperationStatus,LastBackupTarget | ConvertTo-Json -Compress";

pub async fn read() -> Result<Vec<BackupJob>, String> {
    #[cfg(windows)]
    {
        let ps = super::run("powershell.exe", &["-NoProfile", "-NonInteractive", "-Command", &format!("Import-Module WindowsServerBackup -ErrorAction Stop; {SUMMARY}")], &[]).await;
        match ps {
            Ok(json) => parse_summary(&json).map(|j| j.into_iter().collect()),
            Err(summary_err) => match super::wevtutil("Microsoft-Windows-Backup", 50).await {
                Ok(xml) => Ok(from_events(&super::parse_events(&xml)).into_iter().collect()),
                Err(_) => Err(format!("Windows Server Backup can't be read: {summary_err}")),
            },
        }
    }
    #[cfg(not(windows))]
    {
        Err("Windows Server Backup is only on Windows".into())
    }
}

/// `"\/Date(1700000000000)\/"` (Windows PowerShell 5.1) or an ISO date (PowerShell 7). The
/// year-1 date WSB uses for "never" is None.
fn ps_date(v: &serde_json::Value) -> Option<DateTime<Utc>> {
    let s = v.as_str()?;
    let t = if let Some(inner) = s.trim_start_matches('\\').strip_prefix("/Date(") {
        // Milliseconds, maybe negative, maybe followed by an offset (`+0100`).
        let (neg, rest) = inner.strip_prefix('-').map_or((false, inner), |r| (true, r));
        let ms: i64 = rest.chars().take_while(char::is_ascii_digit).collect::<String>().parse().ok()?;
        DateTime::from_timestamp_millis(if neg { -ms } else { ms })?
    } else {
        DateTime::parse_from_rfc3339(s).ok()?.with_timezone(&Utc)
    };
    (t.timestamp() > 0).then_some(t)
}

pub(super) fn parse_summary(json: &str) -> Result<Option<BackupJob>, String> {
    let v: serde_json::Value = serde_json::from_str(json.trim()).map_err(|e| format!("unreadable Get-WBSummary output: {e}"))?;
    let last_run = ps_date(&v["LastBackupTime"]);
    let last_success = ps_date(&v["LastSuccessfulBackupTime"]);
    if last_run.is_none() && last_success.is_none() && v["NumberOfVersions"].as_i64().unwrap_or(0) == 0 {
        // Installed, never run (or no schedule): no job to report.
        return Ok(None);
    }
    let hr = v["LastBackupResultHR"].as_i64().unwrap_or(0);
    let running = v["CurrentOperationStatus"].as_i64().unwrap_or(0) != 0;
    let result = if running {
        BackupResult::Running
    } else if hr == 0 {
        BackupResult::Success
    } else {
        BackupResult::Failed
    };
    let message = match (hr, v["DetailedMessage"].as_str()) {
        (0, _) if !running => format!("{} versions", v["NumberOfVersions"].as_i64().unwrap_or(0)),
        (_, Some(m)) if !m.is_empty() => m.to_string(),
        (hr, _) => format!("error 0x{:08X}", hr as u32),
    };
    Ok(Some(BackupJob { provider: "wsb".into(), job: "Windows Server Backup".into(), last_run_at: last_run, last_success_at: last_success, last_result: result, message, size_bytes: None }))
}

/// The newest events first, as `wevtutil /rd:true` gives them.
pub(super) fn from_events(events: &[super::Event]) -> Option<BackupJob> {
    let mut job = BackupJob { provider: "wsb".into(), job: "Windows Server Backup".into(), last_run_at: None, last_success_at: None, last_result: BackupResult::Unknown, message: String::new(), size_bytes: None };
    let mut decided = false;
    for e in events {
        let outcome = match (e.id, e.level) {
            (4, _) => Some(BackupResult::Success),
            (_, 1 | 2) => Some(BackupResult::Failed),
            (1, _) => Some(BackupResult::Running),
            _ => None,
        };
        let Some(outcome) = outcome else { continue };
        if !decided {
            decided = true;
            job.last_result = outcome;
            job.last_run_at = e.time;
            job.message = e.message.chars().take(300).collect();
        }
        if outcome == BackupResult::Success {
            job.last_success_at = e.time;
            break;
        }
    }
    decided.then_some(job)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summary() {
        let j = parse_summary(include_str!("fixtures/wsb-summary.json")).unwrap().unwrap();
        assert_eq!(j.last_result, BackupResult::Failed);
        assert_eq!(j.last_success_at.unwrap().to_rfc3339(), "2026-11-26T01:54:09+00:00");
        assert_eq!(j.last_run_at.unwrap().to_rfc3339(), "2026-11-27T01:50:01+00:00");
        assert_eq!(j.message, "The shadow copy provider had an error.");
        // Installed and never run (the Windows CI runner after Install-WindowsFeature).
        assert_eq!(parse_summary(include_str!("fixtures/wsb-empty.json")).unwrap(), None);
        assert!(parse_summary("not json").is_err());
        let ok = parse_summary(r#"{"LastBackupTime":"2026-11-20T02:00:00Z","LastSuccessfulBackupTime":"2026-11-20T02:00:00Z","LastBackupResultHR":0,"NumberOfVersions":3}"#).unwrap().unwrap();
        assert_eq!((ok.last_result, ok.message.as_str()), (BackupResult::Success, "3 versions"));
    }

    #[test]
    fn events() {
        let ev = super::super::parse_events(include_str!("fixtures/wsb-events.xml"));
        let j = from_events(&ev).unwrap();
        assert_eq!(j.last_result, BackupResult::Success);
        assert_eq!(j.last_success_at, j.last_run_at);
        // Without the success: the failure is the latest, and there's no success to go by.
        let j = from_events(&ev[1..]).unwrap();
        assert_eq!((j.last_result, j.last_success_at), (BackupResult::Failed, None));
        assert!(j.message.contains("0x80042306"));
        assert!(from_events(&[]).is_none());
    }
}
