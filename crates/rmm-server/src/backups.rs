//! Backup monitoring (docs/design/backups.md). A `backup` alert item, in a device's own policy
//! set, becomes a check the device runs ([`specs_for`]): read the last result of its backup
//! jobs. The jobs are stored in `backup_jobs` (the fleet view and the device's card) and the item
//! opens an alert per job that failed or hasn't succeeded for `max_age_hours`, and one when no
//! job is found and the item requires one. Key: `backup:<provider>:<job>` (`backup:none`).

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use rmm_proto::checks::{BACKUP_INTERVAL_SECS, BackupJob, BackupSource, CheckData, CheckKind, CheckResult, CheckSpec};
use serde_json::{Value, json};
use tracing::warn;
use uuid::Uuid;

use crate::alerts::{BackupRule, Policy, Rule, clear, fire, policies_for, service_matches};
use crate::state::AppState;

pub const PROVIDERS: &[&str] = &["auto", "wsb", "veeam", "restic", "borg", "timemachine", "file_age"];
/// Providers that read a source the item names.
const WITH_SOURCES: &[&str] = &["restic", "borg", "file_age"];
/// The longest a backup check may run (restic or borg over a slow link).
const TIMEOUT_SECS: u32 = 300;

pub fn label(provider: &str) -> &str {
    match provider {
        "wsb" => "Windows Server Backup",
        "veeam" => "Veeam",
        "restic" => "restic",
        "borg" => "Borg",
        "timemachine" => "Time Machine",
        "file_age" => "Backup files",
        other => other,
    }
}

/// An absolute path (Unix, `C:\`, or `\\server\share`) without `..`.
fn absolute(p: &str) -> bool {
    let b = p.as_bytes();
    let abs = p.starts_with('/') || p.starts_with("\\\\") || (b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && (b[2] == b'\\' || b[2] == b'/'));
    abs && !p.split(['/', '\\']).any(|c| c == "..") && !p.contains('\0') && p.len() <= 1024
}

pub fn validate(r: &BackupRule) -> Result<(), String> {
    if let Some(p) = r.providers.iter().find(|p| !PROVIDERS.contains(&p.as_str())) {
        return Err(format!("unknown backup provider {p:?}: {}", PROVIDERS.join(", ")));
    }
    if r.providers.is_empty() && r.sources.is_empty() {
        return Err("pick a provider, or add a source".into());
    }
    if !(1..=8760).contains(&r.max_age_hours) {
        return Err("the age limit must be 1-8760 hours".into());
    }
    if r.jobs.len() > 100 || r.jobs.iter().any(|j| j.trim().is_empty() || j.len() > 256) {
        return Err("jobs: up to 100 non-empty names of at most 256 characters".into());
    }
    if r.sources.len() > 20 {
        return Err("at most 20 sources".into());
    }
    for s in &r.sources {
        let p = s.provider.as_str();
        if !WITH_SOURCES.contains(&p) {
            return Err(format!("sources are for {}; {p:?} finds its jobs by itself", WITH_SOURCES.join(", ")));
        }
        let set = |v: &Option<String>| v.as_deref().map(str::trim).filter(|x| !x.is_empty()).map(String::from);
        for path in [set(&s.env_file), set(&s.path)].into_iter().flatten() {
            if !absolute(&path) {
                return Err(format!("{path:?} must be an absolute path without '..'"));
            }
        }
        if let Some(repo) = set(&s.repo)
            && (repo.len() > 1024 || repo.chars().any(char::is_control))
        {
            return Err("the repository is too long or has control characters".into());
        }
        match p {
            "restic" | "borg" if set(&s.env_file).is_none() && set(&s.repo).is_none() => {
                return Err(format!("a {p} source needs an env file (or at least the repository)"));
            }
            "file_age" if set(&s.path).is_none() => return Err("a file_age source needs a path".into()),
            "file_age" if set(&s.glob).is_some_and(|g| g.len() > 100 || g.contains(['/', '\\'])) => {
                return Err("the file pattern is a name pattern like *.bak, at most 100 characters".into());
            }
            _ => {}
        }
    }
    Ok(())
}

fn source(s: &crate::alerts::BackupSourceRule) -> BackupSource {
    let set = |v: &Option<String>| v.as_deref().map(str::trim).filter(|x| !x.is_empty()).map(String::from);
    BackupSource { provider: s.provider.clone(), env_file: set(&s.env_file), repo: set(&s.repo), path: set(&s.path), glob: set(&s.glob) }
}

/// The check an item asks of each device it reaches.
pub fn spec(item_id: Uuid, r: &BackupRule) -> CheckSpec {
    CheckSpec {
        id: item_id,
        interval_secs: BACKUP_INTERVAL_SECS,
        timeout_secs: TIMEOUT_SECS,
        kind: CheckKind::Backup { providers: r.providers.clone(), sources: r.sources.iter().map(source).collect() },
    }
}

/// The backup checks of each of these agents.
pub async fn specs_for(st: &AppState, agents: &[Uuid]) -> sqlx::Result<HashMap<Uuid, Vec<CheckSpec>>> {
    let rows: Vec<(Uuid, Uuid, Value)> = sqlx::query_as(
        "SELECT ap.agent_id, ap.item_id, ap.config FROM agent_policy ap
          WHERE ap.agent_id = ANY($1) AND ap.module = 'alert' AND ap.enabled AND ap.config ->> 'kind' = 'backup' ORDER BY ap.item_id",
    )
    .bind(agents)
    .fetch_all(&st.db)
    .await?;
    let mut out: HashMap<Uuid, Vec<CheckSpec>> = HashMap::new();
    for (agent, item, config) in rows {
        let rule = serde_json::from_value::<crate::policy::AlertConfig>(config).ok().and_then(|c| c.rule().ok());
        if let Some(Rule::Backup(r)) = rule {
            out.entry(agent).or_default().push(spec(item, &r));
        }
    }
    Ok(out)
}

/// A job as the alert logic sees it, from a report or the table.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Job {
    pub provider: String,
    pub job: String,
    pub last_run_at: Option<DateTime<Utc>>,
    pub last_success_at: Option<DateTime<Utc>>,
    pub last_result: String,
    pub message: String,
}

impl From<&BackupJob> for Job {
    fn from(j: &BackupJob) -> Job {
        Job {
            provider: j.provider.clone(),
            job: j.job.clone(),
            last_run_at: j.last_run_at,
            last_success_at: j.last_success_at,
            last_result: j.last_result.as_str().into(),
            message: j.message.clone(),
        }
    }
}

/// The jobs an item is about: its providers (`auto`: any) and its job patterns.
fn covers(r: &BackupRule, j: &Job) -> bool {
    let provider = r.providers.iter().any(|p| p == "auto" || p == &j.provider) || r.sources.iter().any(|s| s.provider == j.provider);
    provider && (r.jobs.is_empty() || r.jobs.iter().any(|p| service_matches(p, &j.job)))
}

/// What an item finds: `(key, title, details)`. `errors` are providers that couldn't be read.
pub fn findings(r: &BackupRule, jobs: &[Job], errors: &[(String, String)], now: DateTime<Utc>) -> Vec<(String, String, Value)> {
    let mine: Vec<&Job> = jobs.iter().filter(|j| covers(r, j)).collect();
    let mut out = Vec::new();
    if mine.is_empty() {
        if r.require {
            let why: Vec<String> = errors.iter().map(|(p, e)| format!("{}: {e}", label(p))).collect();
            out.push(("backup:none".into(), "No backup jobs found".into(), json!({ "providers": r.providers, "errors": why })));
        }
        return out;
    }
    let cutoff = now - chrono::Duration::hours(i64::from(r.max_age_hours));
    for j in mine {
        let key = format!("backup:{}:{}", j.provider, j.job);
        let details = json!({
            "provider": j.provider, "job": j.job, "result": j.last_result, "message": j.message,
            "last_run_at": j.last_run_at, "last_success_at": j.last_success_at, "max_age_hours": r.max_age_hours,
        });
        let failed = j.last_result == "failed" || (r.warning_is_failure && j.last_result == "warning");
        if failed {
            let what = if j.last_result == "warning" { "Backup finished with warnings" } else { "Backup failed" };
            out.push((key, format!("{what}: {} ({})", j.job, label(&j.provider)), details));
        } else if j.last_success_at.is_none_or(|t| t < cutoff) {
            let title = match j.last_success_at {
                Some(_) => format!("No successful backup for {} hours: {} ({})", r.max_age_hours, j.job, label(&j.provider)),
                None => format!("No successful backup yet: {} ({})", j.job, label(&j.provider)),
            };
            out.push((key, title, details));
        }
    }
    out
}

async fn check(st: &AppState, p: &Policy, agent_id: Uuid, jobs: &[Job], errors: &[(String, String)]) -> sqlx::Result<()> {
    let Some(Rule::Backup(r)) = p.rule() else { return Ok(()) };
    let found = findings(&r, jobs, errors, Utc::now());
    let keep: Vec<String> = found.iter().map(|f| f.0.clone()).collect();
    for (key, title, details) in found {
        fire(st, p, agent_id, &key, &title, details, 0).await?;
    }
    clear(st, p, agent_id, None, &keep).await
}

/// Results of backup checks (`check_id` is the item).
pub async fn ingest(st: &AppState, agent_id: Uuid, results: Vec<CheckResult>) -> sqlx::Result<()> {
    if results.is_empty() {
        return Ok(());
    }
    let policies = policies_for(st, agent_id, "backup").await?;
    let mut changed = false;
    for r in results {
        // A result for an item that no longer reaches this agent: the agent hasn't got the new set yet.
        let Some(p) = policies.iter().find(|p| p.id == r.check_id) else { continue };
        let Some(CheckData::Backups { jobs, errors }) = r.data else { continue };
        for j in &jobs {
            let provider = if PROVIDERS.contains(&j.provider.as_str()) && j.provider != "auto" { j.provider.as_str() } else { continue };
            sqlx::query(
                "INSERT INTO backup_jobs (agent_id, provider, job, last_run_at, last_success_at, last_result, message, size_bytes, updated_at)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, now())
                 ON CONFLICT (agent_id, provider, job) DO UPDATE SET last_run_at = EXCLUDED.last_run_at,
                        last_success_at = greatest(backup_jobs.last_success_at, EXCLUDED.last_success_at), last_result = EXCLUDED.last_result,
                        message = EXCLUDED.message, size_bytes = EXCLUDED.size_bytes, updated_at = now()",
            )
            .bind(agent_id)
            .bind(provider)
            .bind(j.job.chars().take(500).collect::<String>())
            .bind(j.last_run_at)
            .bind(j.last_success_at)
            .bind(j.last_result.as_str())
            .bind(j.message.chars().take(500).collect::<String>())
            .bind(j.size_bytes.map(|s| s.min(i64::MAX as u64) as i64))
            .execute(&st.db)
            .await?;
            changed = true;
        }
        let rows: Vec<Job> = jobs.iter().map(Job::from).collect();
        check(st, p, agent_id, &rows, &errors).await?;
    }
    if changed && let Ok(client_id) = sqlx::query_scalar::<_, Uuid>("SELECT s.client_id FROM agents a JOIN sites s ON s.id = a.site_id WHERE a.id = $1").bind(agent_id).fetch_one(&st.db).await {
        st.hub.publish(crate::hub::Event::Backups { agent_id, client_id });
    }
    Ok(())
}

/// An agent may run under other items now: check them against its stored jobs (the next report
/// corrects anything a provider no longer sees).
pub async fn recheck_agent(st: &AppState, agent_id: Uuid) {
    let res: sqlx::Result<()> = async {
        let policies = policies_for(st, agent_id, "backup").await?;
        if policies.is_empty() {
            return Ok(());
        }
        let jobs: Vec<Job> = sqlx::query_as("SELECT provider, job, last_run_at, last_success_at, last_result, message FROM backup_jobs WHERE agent_id = $1")
            .bind(agent_id)
            .fetch_all(&st.db)
            .await?;
        for p in &policies {
            check(st, p, agent_id, &jobs, &[]).await?;
        }
        Ok(())
    }
    .await;
    if let Err(e) = res {
        warn!(%agent_id, "re-checking backup alerts: {e}");
    }
}

pub async fn recheck_item(st: &AppState, item_id: Uuid) {
    let rows: sqlx::Result<Vec<Uuid>> =
        sqlx::query_scalar("SELECT ap.agent_id FROM agent_policy ap WHERE ap.item_id = $1 AND ap.module = 'alert' AND ap.enabled AND ap.config ->> 'kind' = 'backup'")
            .bind(item_id)
            .fetch_all(&st.db)
            .await;
    for agent_id in rows.unwrap_or_default() {
        recheck_agent(st, agent_id).await;
    }
}

/// Jobs nobody has reported for 30 days (the product was removed, the item too).
pub async fn prune(db: &sqlx::PgPool) -> sqlx::Result<()> {
    sqlx::query("DELETE FROM backup_jobs WHERE updated_at < now() - interval '30 days'").execute(db).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alerts::BackupSourceRule;

    fn job(provider: &str, name: &str, result: &str, success_hours_ago: Option<i64>) -> Job {
        let now = Utc::now();
        Job {
            provider: provider.into(),
            job: name.into(),
            last_run_at: Some(now),
            last_success_at: success_hours_ago.map(|h| now - chrono::Duration::hours(h)),
            last_result: result.into(),
            message: String::new(),
        }
    }

    fn keys(f: Vec<(String, String, Value)>) -> Vec<String> {
        f.into_iter().map(|f| f.0).collect()
    }

    #[test]
    fn failed_stale_and_missing() {
        let r = BackupRule::default();
        let now = Utc::now();
        let jobs = [
            job("veeam", "Nightly", "success", Some(2)),
            job("veeam", "Weekly", "failed", Some(100)),
            job("restic", "/srv/repo", "success", Some(30)),
            job("wsb", "Windows Server Backup", "warning", Some(1)),
            job("file_age", "/backups/*.bak", "unknown", None),
        ];
        let f = findings(&r, &jobs, &[], now);
        assert_eq!(f[0].1, "Backup failed: Weekly (Veeam)");
        assert_eq!(f[1].1, "No successful backup for 26 hours: /srv/repo (restic)");
        assert_eq!(f[2].1, "No successful backup yet: /backups/*.bak (Backup files)");
        assert_eq!(keys(f), ["backup:veeam:Weekly", "backup:restic:/srv/repo", "backup:file_age:/backups/*.bak"], "a warning is fine by default");
        let strict = BackupRule { warning_is_failure: true, ..r.clone() };
        assert!(keys(findings(&strict, &jobs, &[], now)).contains(&"backup:wsb:Windows Server Backup".to_string()));
        let only = BackupRule { providers: vec!["veeam".into()], jobs: vec!["night*".into()], ..r.clone() };
        assert!(findings(&only, &jobs, &[], now).is_empty(), "only Nightly, which is fine");
        let sourced = BackupRule { providers: vec![], sources: vec![BackupSourceRule { provider: "restic".into(), env_file: Some("/etc/restic/env".into()), ..Default::default() }], ..r.clone() };
        assert_eq!(keys(findings(&sourced, &jobs, &[], now)), ["backup:restic:/srv/repo"]);
        // None found: only an alert when the item requires a backup.
        assert!(findings(&r, &[], &[], now).is_empty());
        let req = BackupRule { require: true, ..r };
        let f = findings(&req, &[], &[("wsb".into(), "not installed".into())], now);
        assert_eq!(keys(f.clone()), ["backup:none"]);
        assert_eq!(f[0].2["errors"][0], "Windows Server Backup: not installed");
    }

    #[test]
    fn paths() {
        for ok in ["/etc/restic/env", "C:\\ProgramData\\restic\\env", "D:/dumps", "\\\\nas\\backups"] {
            assert!(absolute(ok), "{ok}");
        }
        for bad in ["etc/env", "C:relative", "/etc/../shadow", "..\\x", ""] {
            assert!(!absolute(bad), "{bad}");
        }
        let s = spec(Uuid::nil(), &BackupRule::default());
        assert_eq!((s.interval_secs, s.timeout_secs), (3600, 300));
    }
}
