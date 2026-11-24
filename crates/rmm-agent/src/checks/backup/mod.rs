//! Reads the last result of the backup jobs on this machine, for `CheckKind::Backup`.
//!
//! Each provider reads what the product already records: Windows Server Backup's summary,
//! Veeam's event logs, the newest restic or borg snapshot, Time Machine's latest backup, or the
//! newest file in a directory. Nothing is started or changed. Tools run without a shell, with a
//! timeout. Paths and env files the server names must be absolute, without `..`, and (on Unix)
//! owned by root or the agent's own user and not writable by anyone else: the server can point
//! the agent at a file, but can't make it read one a local user could have planted.
//!
//! Debug builds: `RMM_BACKUP_FAKE=<file>` reports the jobs in that JSON file instead
//! (`{"jobs": [BackupJob...], "errors": [["provider", "why"]...]}`), read on every check, while
//! the file exists (without it the real providers are read).

#![cfg_attr(not(windows), allow(dead_code))]

mod borg;
mod file_age;
mod restic;
mod timemachine;
mod veeam;
mod wsb;

use std::path::{Component, Path};
use std::time::Duration;

use chrono::{DateTime, Utc};
use rmm_proto::checks::{BackupJob, BackupResult, BackupSource};

/// One tool run.
const TOOL_TIMEOUT: Duration = Duration::from_secs(120);

/// What a check found: the jobs, and per provider that couldn't be read, why.
#[derive(Debug, Default)]
pub struct Found {
    pub jobs: Vec<BackupJob>,
    pub errors: Vec<(String, String)>,
}

impl Found {
    fn add(&mut self, provider: &str, r: Result<Vec<BackupJob>, String>) {
        match r {
            Ok(j) => self.jobs.extend(j),
            Err(e) => self.errors.push((provider.to_string(), e)),
        }
    }
}

pub async fn collect(providers: &[String], sources: &[BackupSource]) -> Found {
    #[cfg(debug_assertions)]
    if let Some(path) = std::env::var_os("RMM_BACKUP_FAKE")
        && Path::new(&path).exists()
    {
        return fake(Path::new(&path));
    }
    let mut want: Vec<String> = if providers.is_empty() { vec!["auto".into()] } else { providers.iter().map(|p| p.to_ascii_lowercase()).collect() };
    // Sources name their own provider.
    for s in sources {
        let p = s.provider.to_ascii_lowercase();
        if !want.contains(&p) {
            want.push(p);
        }
    }
    if want.iter().any(|p| p == "auto") {
        want.retain(|p| p != "auto");
        for p in detect().await {
            if !want.iter().any(|w| w == p) {
                want.push(p.to_string());
            }
        }
    }
    let mut found = Found::default();
    for p in &want {
        let mine: Vec<&BackupSource> = sources.iter().filter(|s| s.provider.eq_ignore_ascii_case(p)).collect();
        match p.as_str() {
            "wsb" => found.add(p, wsb::read().await),
            "veeam" => found.add(p, veeam::read().await),
            "timemachine" => found.add(p, timemachine::read().await),
            "restic" | "borg" | "file_age" if mine.is_empty() => found.errors.push((p.clone(), "needs a source (an env file or a path) to read".into())),
            "restic" => {
                for s in mine {
                    found.add(p, restic::read(s).await);
                }
            }
            "borg" => {
                for s in mine {
                    found.add(p, borg::read(s).await);
                }
            }
            "file_age" => {
                for s in mine {
                    found.add(p, file_age::read(s));
                }
            }
            other => found.errors.push((other.to_string(), "unknown backup provider".into())),
        }
    }
    found
}

/// The providers `auto` stands for on this machine: Windows Server Backup and Veeam when their
/// services exist, Time Machine on a Mac.
async fn detect() -> Vec<&'static str> {
    #[cfg(windows)]
    {
        let mut out = Vec::new();
        if service_exists("wbengine").await {
            out.push("wsb");
        }
        for s in ["VeeamBackupSvc", "VeeamEndpointBackupSvc"] {
            if service_exists(s).await {
                out.push("veeam");
                break;
            }
        }
        out
    }
    #[cfg(target_os = "macos")]
    {
        vec!["timemachine"]
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        Vec::new()
    }
}

#[cfg(windows)]
async fn service_exists(name: &str) -> bool {
    // `sc.exe query` exits 1060 for a service that doesn't exist.
    run("sc.exe", &["query", name], &[]).await.is_ok()
}

#[cfg(debug_assertions)]
fn fake(path: &Path) -> Found {
    #[derive(serde::Deserialize, Default)]
    struct File {
        #[serde(default)]
        jobs: Vec<BackupJob>,
        #[serde(default)]
        errors: Vec<(String, String)>,
    }
    match std::fs::read(path) {
        Ok(b) => match serde_json::from_slice::<File>(&b) {
            Ok(f) => Found { jobs: f.jobs, errors: f.errors },
            Err(e) => Found { jobs: vec![], errors: vec![("fake".into(), e.to_string())] },
        },
        Err(_) => Found::default(),
    }
}

/// Runs a tool without a shell. `Ok(stdout)` when it exits 0, else the first line of stderr.
pub(crate) async fn run(program: &str, args: &[&str], env: &[(String, String)]) -> Result<String, String> {
    use std::process::Stdio;
    let mut c = tokio::process::Command::new(program);
    c.args(args).envs(env.iter().map(|(k, v)| (k.as_str(), v.as_str()))).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).kill_on_drop(true);
    let out = match tokio::time::timeout(TOOL_TIMEOUT, c.output()).await {
        Err(_) => return Err(format!("{program} took longer than {}s", TOOL_TIMEOUT.as_secs())),
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::NotFound => return Err(format!("{program} isn't installed")),
        Ok(Err(e)) => return Err(format!("{program}: {e}")),
        Ok(Ok(o)) => o,
    };
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        let err = String::from_utf8_lossy(&out.stderr);
        let line = err.lines().map(str::trim).find(|l| !l.is_empty()).unwrap_or("").chars().take(300).collect::<String>();
        Err(format!("{program} exited with {}{}", out.status.code().map_or("a signal".into(), |c| c.to_string()), if line.is_empty() { String::new() } else { format!(": {line}") }))
    }
}

/// An absolute path without `..`.
pub(crate) fn plain_path(p: &str) -> Result<&Path, String> {
    let path = Path::new(p);
    if !path.is_absolute() || p.contains('\0') {
        return Err(format!("{p:?} isn't an absolute path"));
    }
    if path.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err(format!("{p:?} has '..' in it"));
    }
    Ok(path)
}

/// A file or directory the agent may trust: a plain path, and on Unix owned by root or by the
/// agent's own user, and writable by nobody else.
pub(crate) fn trusted(p: &str) -> Result<&Path, String> {
    let path = plain_path(p)?;
    let meta = std::fs::metadata(path).map_err(|e| format!("{p}: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        // SAFETY: geteuid has no preconditions.
        let me = unsafe { libc::geteuid() };
        if meta.uid() != 0 && meta.uid() != me {
            return Err(format!("{p} must be owned by root or by the agent's user"));
        }
        if meta.mode() & 0o022 != 0 {
            return Err(format!("{p} is writable by other users"));
        }
    }
    let _ = meta;
    Ok(path)
}

/// `KEY=value` lines (an optional `export `, `#` comments, single or double quotes).
pub(crate) fn parse_env(text: &str) -> Vec<(String, String)> {
    text.lines()
        .filter_map(|l| {
            let l = l.trim();
            if l.is_empty() || l.starts_with('#') {
                return None;
            }
            let l = l.strip_prefix("export ").unwrap_or(l);
            let (k, v) = l.split_once('=')?;
            let k = k.trim();
            if k.is_empty() || !k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                return None;
            }
            let v = v.trim();
            let v = v.strip_prefix('"').and_then(|x| x.strip_suffix('"')).or_else(|| v.strip_prefix('\'').and_then(|x| x.strip_suffix('\''))).unwrap_or(v);
            Some((k.to_string(), v.to_string()))
        })
        .collect()
}

/// The env file of a source, read after the [`trusted`] checks.
pub(crate) fn source_env(s: &BackupSource) -> Result<Vec<(String, String)>, String> {
    match s.env_file.as_deref().filter(|f| !f.trim().is_empty()) {
        Some(f) => {
            let path = trusted(f.trim())?;
            let text = std::fs::read_to_string(path).map_err(|e| format!("{f}: {e}"))?;
            Ok(parse_env(&text))
        }
        None => Ok(Vec::new()),
    }
}

/// A repository location as shown: without a user name or password in it.
pub(crate) fn redact(location: &str) -> String {
    match location.find("://") {
        Some(i) => {
            let rest = &location[i + 3..];
            let end = rest.find('/').unwrap_or(rest.len());
            match rest[..end].rfind('@') {
                Some(at) => format!("{}{}", &location[..i + 3], &rest[at + 1..]),
                None => location.to_string(),
            }
        }
        None => location.to_string(),
    }
}

/// A job with only a failure to report.
pub(crate) fn failed(provider: &str, job: String, message: String) -> BackupJob {
    BackupJob { provider: provider.into(), job, last_run_at: Some(Utc::now()), last_success_at: None, last_result: BackupResult::Failed, message, size_bytes: None }
}

/// Event Log records as `wevtutil qe ... /f:xml` prints them; only the fields the backup
/// providers use.
#[derive(Debug, Default, PartialEq)]
pub(crate) struct Event {
    pub id: u32,
    pub level: u8,
    pub time: Option<DateTime<Utc>>,
    pub provider: String,
    /// `<Data Name='x'>v</Data>`; unnamed data has an empty name.
    pub data: Vec<(String, String)>,
    /// From `/f:RenderedXml`.
    pub message: String,
}

impl Event {
    pub fn get(&self, name: &str) -> Option<&str> {
        self.data.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }
}

fn unescape(s: &str) -> String {
    s.replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", "\"").replace("&apos;", "'").replace("&amp;", "&")
}

fn attr<'a>(tag: &'a str, name: &str) -> Option<&'a str> {
    let i = tag.find(&format!("{name}="))? + name.len() + 1;
    let q = tag[i..].chars().next()?;
    let rest = &tag[i + 1..];
    Some(&rest[..rest.find(q)?])
}

fn between<'a>(s: &'a str, open: &str, close: &str) -> Option<&'a str> {
    let start = s.find(open)? + open.len();
    let rest = &s[start..];
    Some(&rest[..rest.find(close)?])
}

pub(crate) fn parse_events(xml: &str) -> Vec<Event> {
    let mut out = Vec::new();
    for chunk in xml.split("<Event ").skip(1) {
        let chunk = chunk.split("</Event>").next().unwrap_or(chunk);
        let mut data = Vec::new();
        if let Some(d) = between(chunk, "<EventData>", "</EventData>").or_else(|| between(chunk, "<UserData>", "</UserData>")) {
            for d in d.split("<Data").skip(1) {
                let (open, rest) = d.split_once('>').unwrap_or((d, ""));
                let name = attr(open, "Name").unwrap_or("").to_string();
                let value = if open.ends_with('/') { String::new() } else { unescape(rest.split("</Data>").next().unwrap_or("").trim()) };
                data.push((name, value));
            }
        }
        let e = Event {
            id: between(chunk, "<EventID", "</EventID>").and_then(|s| s.rsplit('>').next()).and_then(|s| s.trim().parse().ok()).unwrap_or(0),
            level: between(chunk, "<Level>", "</Level>").and_then(|s| s.trim().parse().ok()).unwrap_or(0),
            provider: chunk.find("<Provider ").and_then(|i| attr(&chunk[i..], "Name")).unwrap_or("").to_string(),
            time: chunk
                .find("<TimeCreated ")
                .and_then(|i| attr(&chunk[i..], "SystemTime"))
                .and_then(|t| DateTime::parse_from_rfc3339(t).ok())
                .map(|t| t.with_timezone(&Utc)),
            data,
            message: between(chunk, "<Message>", "</Message>").map(|m| unescape(m.trim())).unwrap_or_default(),
        };
        out.push(e);
    }
    out
}

#[cfg(windows)]
pub(crate) async fn wevtutil(channel: &str, count: u32) -> Result<String, String> {
    run("wevtutil.exe", &["qe", channel, &format!("/c:{count}"), "/rd:true", "/f:RenderedXml"], &[]).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_files() {
        let t = "# repo\nexport RESTIC_REPOSITORY=\"sftp:backup@nas:/srv/restic\"\nRESTIC_PASSWORD_FILE='/etc/restic/pw'\nbad line\n1=2\n  B2_ACCOUNT_ID = abc \n";
        assert_eq!(
            parse_env(t),
            [
                ("RESTIC_REPOSITORY".to_string(), "sftp:backup@nas:/srv/restic".to_string()),
                ("RESTIC_PASSWORD_FILE".into(), "/etc/restic/pw".into()),
                ("1".into(), "2".into()),
                ("B2_ACCOUNT_ID".into(), "abc".into()),
            ]
        );
    }

    #[cfg(unix)]
    #[test]
    fn paths_are_checked() {
        assert!(plain_path("relative/env").is_err());
        assert!(plain_path("/etc/../root/.ssh/id").unwrap_err().contains(".."));
        assert!(plain_path("/etc/restic/env").is_ok());
        let dir = std::env::temp_dir().join(format!("rmm-backup-trust-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("env");
        std::fs::write(&f, "RESTIC_REPOSITORY=/tmp/x\n").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(trusted(f.to_str().unwrap()).is_ok());
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(trusted(f.to_str().unwrap()).unwrap_err().contains("writable"));
        assert!(trusted("/nonexistent/env").is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn locations_lose_their_credentials() {
        assert_eq!(redact("rest:https://user:secret@backup.example:8000/repo"), "rest:https://backup.example:8000/repo");
        assert_eq!(redact("s3:https://s3.amazonaws.com/bucket"), "s3:https://s3.amazonaws.com/bucket");
        assert_eq!(redact("/srv/restic"), "/srv/restic");
        assert_eq!(redact("ssh://borg@nas/./repo"), "ssh://nas/./repo");
    }

    #[test]
    fn event_xml() {
        let xml = include_str!("fixtures/wsb-events.xml");
        let ev = parse_events(xml);
        assert_eq!(ev.len(), 3);
        assert_eq!((ev[0].id, ev[0].level, ev[0].provider.as_str()), (4, 4, "Microsoft-Windows-Backup"));
        assert_eq!(ev[0].time.unwrap().to_rfc3339(), "2026-11-20T02:14:09.123456+00:00");
        assert_eq!(ev[1].get("HRESULT"), Some("0x80042306"));
        assert!(ev[1].message.contains("failed"), "{:?}", ev[1].message);
    }

    #[cfg(debug_assertions)]
    #[tokio::test]
    async fn the_fake_reports_its_file() {
        let f = std::env::temp_dir().join(format!("rmm-backup-fake-{}.json", std::process::id()));
        std::fs::write(&f, r#"{"jobs":[{"provider":"veeam","job":"Nightly","last_result":"failed","message":"disk full"}],"errors":[["wsb","not installed"]]}"#).unwrap();
        let got = fake(&f);
        assert_eq!((got.jobs.len(), got.jobs[0].last_result, got.errors.len()), (1, BackupResult::Failed, 1));
        std::fs::remove_file(&f).unwrap();
        let got = collect(&["restic".into()], &[]).await;
        assert!(got.errors.iter().any(|(p, e)| p == "restic" && e.contains("source")), "{got:?}");
    }
}
