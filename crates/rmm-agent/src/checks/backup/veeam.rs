//! Veeam Backup & Replication and Veeam Agent for Windows, from their event logs (`Veeam
//! Backup`, `Veeam Agent`): event 190 is "job finished", with the job's name and its result.
//! Veeam's PowerShell module isn't used: it is slow to load and tied to the product version.
//!
//! The data of event 190 differs between products and versions, so the job and result are
//! taken from named data (`JobName`, `Result`) when there is any, else from the unnamed values
//! (the first that isn't an id or a number is the name; `Success`/`Warning`/`Failed` or 0/1/2 is
//! the result), else from the message (`Backup job 'X' finished with Y`).

use std::collections::BTreeMap;

use rmm_proto::checks::{BackupJob, BackupResult};

use super::Event;

pub async fn read() -> Result<Vec<BackupJob>, String> {
    #[cfg(windows)]
    {
        let mut events = Vec::new();
        let mut errors = Vec::new();
        for channel in ["Veeam Backup", "Veeam Agent"] {
            match super::wevtutil(channel, 500).await {
                Ok(xml) => events.extend(super::parse_events(&xml)),
                Err(e) => errors.push(e),
            }
        }
        if events.is_empty() && errors.len() == 2 {
            return Err(format!("Veeam's event logs can't be read: {}", errors[0]));
        }
        Ok(jobs(&events))
    }
    #[cfg(not(windows))]
    {
        Err("Veeam is only read on Windows".into())
    }
}

fn result_word(s: &str) -> Option<BackupResult> {
    match s.trim().to_ascii_lowercase().as_str() {
        "success" | "succeeded" | "0" => Some(BackupResult::Success),
        "warning" | "1" => Some(BackupResult::Warning),
        "failed" | "failure" | "error" | "2" => Some(BackupResult::Failed),
        "running" | "inprogress" | "working" | "5" => Some(BackupResult::Running),
        _ => None,
    }
}

fn looks_like_id(s: &str) -> bool {
    s.len() == 36 && s.chars().filter(|c| *c == '-').count() == 4 && s.chars().all(|c| c.is_ascii_hexdigit() || c == '-')
}

/// `Backup job 'Nightly VMs' finished with Success.` → (name, result).
fn from_message(m: &str) -> (Option<String>, Option<BackupResult>) {
    let name = m.split_once('\'').and_then(|(_, rest)| rest.split_once('\'')).map(|(n, _)| n.to_string());
    let result = m.to_ascii_lowercase().split("finished with").nth(1).and_then(|r| {
        let w: String = r.trim().chars().take_while(|c| c.is_ascii_alphabetic()).collect();
        result_word(&w)
    });
    (name, result)
}

fn job_of(e: &Event) -> Option<(String, BackupResult)> {
    let (msg_name, msg_result) = from_message(&e.message);
    let named_name = e.get("JobName").map(str::to_string);
    let named_result = e.get("Result").and_then(result_word);
    let unnamed: Vec<&str> = e.data.iter().filter(|(k, _)| k.is_empty()).map(|(_, v)| v.as_str()).collect();
    let pos_name = unnamed.iter().find(|v| !v.is_empty() && !looks_like_id(v) && v.parse::<f64>().is_err() && result_word(v).is_none()).map(|v| v.to_string());
    let pos_result = unnamed.iter().filter_map(|v| v.parse::<f64>().is_err().then(|| result_word(v)).flatten()).next();
    let name = named_name.or(pos_name).or(msg_name)?;
    let result = named_result.or(pos_result).or(msg_result).unwrap_or(match e.level {
        1 | 2 => BackupResult::Failed,
        3 => BackupResult::Warning,
        _ => BackupResult::Unknown,
    });
    Some((name, result))
}

/// Per job, its latest result and its latest success (events in any order).
pub(super) fn jobs(events: &[Event]) -> Vec<BackupJob> {
    let mut by_job: BTreeMap<String, BackupJob> = BTreeMap::new();
    for e in events.iter().filter(|e| e.id == 190) {
        let Some((name, result)) = job_of(e) else { continue };
        let j = by_job.entry(name.clone()).or_insert_with(|| BackupJob {
            provider: "veeam".into(),
            job: name,
            last_run_at: None,
            last_success_at: None,
            last_result: BackupResult::Unknown,
            message: String::new(),
            size_bytes: None,
        });
        if e.time > j.last_run_at || j.last_run_at.is_none() {
            j.last_run_at = e.time;
            j.last_result = result;
            j.message = e.message.chars().take(300).collect();
        }
        if result == BackupResult::Success && e.time > j.last_success_at {
            j.last_success_at = e.time;
        }
    }
    by_job.into_values().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn job_finished_events() {
        let ev = super::super::parse_events(include_str!("fixtures/veeam-events.xml"));
        let j = jobs(&ev);
        let names: Vec<&str> = j.iter().map(|j| j.job.as_str()).collect();
        assert_eq!(names, ["Backup Job LAPTOP7", "Nightly VMs", "SQL & Files"], "event 110 (started) isn't a result");
        let nightly = &j[1];
        assert_eq!(nightly.last_result, BackupResult::Success, "the newer of two runs wins");
        assert_eq!(nightly.last_success_at, nightly.last_run_at);
        assert!(nightly.message.contains("finished with Success"));
        assert_eq!(j[2].last_result, BackupResult::Warning);
        assert_eq!(j[2].last_success_at, None);
        assert_eq!(j[0].last_result, BackupResult::Failed, "named data (Veeam Agent)");
    }

    #[test]
    fn messages_alone() {
        assert_eq!(from_message("Backup job 'Daily' finished with Failed. Error: x"), (Some("Daily".into()), Some(BackupResult::Failed)));
        assert_eq!(from_message("nothing to see"), (None, None));
    }
}
