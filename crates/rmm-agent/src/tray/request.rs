//! Help requests on the service side: the checks a request must pass, the per-user limit, and
//! the few kept on disk while the server can't be reached.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use rmm_proto::tray::{MAX_BODY, MAX_SCREENSHOT, MAX_SUBJECT};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Requests per user per hour.
pub const PER_HOUR: usize = 5;
/// Unsent requests kept on the machine.
pub const MAX_UNSENT: usize = 3;

/// Trims and checks what a tray sent. The subject comes back on one line.
pub fn validate(subject: &str, body: &str, screenshot: &[u8]) -> Result<(String, String), String> {
    let subject = subject.split_whitespace().collect::<Vec<_>>().join(" ");
    if subject.is_empty() {
        return Err("give the request a subject".into());
    }
    if subject.chars().count() > MAX_SUBJECT {
        return Err(format!("the subject is limited to {MAX_SUBJECT} characters"));
    }
    let body = body.trim().to_string();
    if body.chars().count() > MAX_BODY {
        return Err(format!("the description is limited to {MAX_BODY} characters"));
    }
    if screenshot.len() > MAX_SCREENSHOT {
        return Err(format!("the screenshot is limited to {} MiB", MAX_SCREENSHOT / (1024 * 1024)));
    }
    if !screenshot.is_empty() && image_type(screenshot).is_none() {
        return Err("the screenshot must be a JPEG or PNG image".into());
    }
    Ok((subject, body))
}

/// `jpg` or `png` from the file's first bytes.
pub fn image_type(data: &[u8]) -> Option<&'static str> {
    if data.starts_with(&[0xff, 0xd8, 0xff]) {
        Some("jpg")
    } else if data.starts_with(b"\x89PNG\r\n\x1a\n") {
        Some("png")
    } else {
        None
    }
}

/// At most [`PER_HOUR`] requests per user in any hour.
#[derive(Default)]
pub struct Limiter {
    seen: HashMap<String, Vec<Instant>>,
}

impl Limiter {
    /// Counts the request if it's allowed; otherwise how long until the next one is.
    pub fn check(&mut self, user: &str, now: Instant) -> Result<(), Duration> {
        let hour = Duration::from_secs(3600);
        let times = self.seen.entry(user.to_string()).or_default();
        times.retain(|t| now.duration_since(*t) < hour);
        if times.len() >= PER_HOUR {
            return Err(hour - now.duration_since(times[0]));
        }
        times.push(now);
        // Don't grow without bound with many users.
        if self.seen.len() > 1000 {
            self.seen.retain(|_, v| v.iter().any(|t| now.duration_since(*t) < hour));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pending {
    pub request_id: Uuid,
    pub user: String,
    pub session: u32,
    pub subject: String,
    pub body: String,
    pub created_at: DateTime<Utc>,
    /// The screenshot's file name next to the request's, if it has one.
    #[serde(default)]
    pub screenshot: Option<String>,
}

/// Unsent requests: `<id>.json`, and `<id>.jpg` / `<id>.png` for the screenshot.
pub struct Store {
    dir: PathBuf,
}

impl Store {
    pub fn open(dir: PathBuf) -> Store {
        Store { dir }
    }

    /// Writes the request (and its screenshot) unless [`MAX_UNSENT`] are already waiting.
    pub fn add(&self, mut p: Pending, screenshot: &[u8]) -> Result<Pending, String> {
        if self.list().len() >= MAX_UNSENT {
            return Err(format!("{MAX_UNSENT} help requests are already waiting to be sent from this computer; try again once it is back online"));
        }
        let res = (|| -> Result<()> {
            std::fs::create_dir_all(&self.dir)?;
            if let Some(ext) = image_type(screenshot) {
                let name = format!("{}.{ext}", p.request_id);
                std::fs::write(self.dir.join(&name), screenshot)?;
                p.screenshot = Some(name);
            }
            // The metadata last: a request is only listed once it is whole.
            let tmp = self.dir.join(format!("{}.json.tmp", p.request_id));
            std::fs::write(&tmp, serde_json::to_vec(&p)?)?;
            std::fs::rename(&tmp, self.dir.join(format!("{}.json", p.request_id)))?;
            Ok(())
        })();
        match res {
            Ok(()) => Ok(p),
            Err(e) => {
                self.remove(p.request_id);
                Err(format!("couldn't keep the request on this computer: {e:#}"))
            }
        }
    }

    /// Oldest first.
    pub fn list(&self) -> Vec<Pending> {
        let mut out: Vec<Pending> = std::fs::read_dir(&self.dir)
            .into_iter()
            .flatten()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().ends_with(".json"))
            .filter_map(|e| serde_json::from_slice(&std::fs::read(e.path()).ok()?).ok())
            .collect();
        out.sort_by_key(|p: &Pending| p.created_at);
        out
    }

    pub fn screenshot(&self, p: &Pending) -> Vec<u8> {
        p.screenshot.as_deref().filter(|n| safe_name(n)).and_then(|n| std::fs::read(self.dir.join(n)).ok()).unwrap_or_default()
    }

    pub fn remove(&self, id: Uuid) {
        for ext in ["json", "jpg", "png", "json.tmp"] {
            let _ = std::fs::remove_file(self.dir.join(format!("{id}.{ext}")));
        }
    }
}

fn safe_name(n: &str) -> bool {
    !n.is_empty() && n.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.') && !n.starts_with('.')
}

/// Reads a cached value, if there is one.
pub fn load_cached<T: for<'a> Deserialize<'a>>(path: &Path) -> Option<T> {
    rmm_proto::decode(&std::fs::read(path).ok()?).ok()
}

pub fn save_cached<T: Serialize>(path: &Path, v: &T) -> Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, rmm_proto::encode(v)?).with_context(|| format!("writing {}", tmp.display()))?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const JPEG: &[u8] = &[0xff, 0xd8, 0xff, 0xe0, 1, 2, 3];

    #[test]
    fn size_caps_and_types() {
        assert_eq!(validate("  Printer\n  jammed ", " body \n", &[]).unwrap(), ("Printer jammed".into(), "body".into()));
        assert!(validate("   ", "", &[]).is_err());
        assert!(validate(&"x".repeat(MAX_SUBJECT), "", &[]).is_ok());
        assert!(validate(&"x".repeat(MAX_SUBJECT + 1), "", &[]).is_err());
        assert!(validate("s", &"é".repeat(MAX_BODY), &[]).is_ok(), "characters, not bytes");
        assert!(validate("s", &"x".repeat(MAX_BODY + 1), &[]).is_err());
        assert!(validate("s", "", JPEG).is_ok());
        assert!(validate("s", "", b"\x89PNG\r\n\x1a\nrest").is_ok());
        assert!(validate("s", "", b"<svg/>").is_err());
        let mut big = JPEG.to_vec();
        big.resize(MAX_SCREENSHOT + 1, 0);
        assert!(validate("s", "", &big).is_err());
        big.truncate(MAX_SCREENSHOT);
        assert!(validate("s", "", &big).is_ok());
    }

    #[test]
    fn five_an_hour_per_user() {
        let mut l = Limiter::default();
        let t0 = Instant::now();
        for i in 0..PER_HOUR {
            assert!(l.check("alice", t0 + Duration::from_secs(i as u64)).is_ok());
        }
        let wait = l.check("alice", t0 + Duration::from_secs(60)).unwrap_err();
        assert_eq!(wait, Duration::from_secs(3540));
        assert!(l.check("bob", t0 + Duration::from_secs(60)).is_ok(), "per user");
        assert!(l.check("alice", t0 + Duration::from_secs(3600)).is_ok(), "the first one has aged out");
        assert!(l.check("alice", t0 + Duration::from_secs(3600)).is_err(), "and only that one");
    }

    #[test]
    fn persistence() {
        let dir = std::env::temp_dir().join(format!("rmm-tray-test-{}", Uuid::new_v4()));
        let store = Store::open(dir.clone());
        let mk = |n: i64| Pending {
            request_id: Uuid::new_v4(),
            user: "alice".into(),
            session: 1,
            subject: format!("s{n}"),
            body: String::new(),
            created_at: DateTime::from_timestamp(1_700_000_000 + n, 0).unwrap(),
            screenshot: None,
        };
        let a = store.add(mk(2), JPEG).unwrap();
        assert_eq!(a.screenshot.as_deref(), Some(format!("{}.jpg", a.request_id).as_str()));
        let b = store.add(mk(1), &[]).unwrap();
        store.add(mk(3), &[]).unwrap();
        assert!(store.add(mk(4), &[]).is_err(), "three at most");
        // Reopened (a restart): oldest first, with the screenshot.
        let store = Store::open(dir.clone());
        let list = store.list();
        assert_eq!(list.iter().map(|p| p.subject.as_str()).collect::<Vec<_>>(), ["s1", "s2", "s3"]);
        assert_eq!(store.screenshot(&list[1]), JPEG);
        assert!(store.screenshot(&list[0]).is_empty());
        store.remove(a.request_id);
        store.remove(b.request_id);
        assert_eq!(store.list().len(), 1);
        assert!(!dir.join(format!("{}.jpg", a.request_id)).exists());
        // A tampered file name never leaves the directory.
        let mut evil = list[2].clone();
        evil.screenshot = Some("../../etc/passwd".into());
        assert!(store.screenshot(&evil).is_empty());
        let _ = std::fs::remove_dir_all(dir);
    }
}
