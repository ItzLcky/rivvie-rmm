//! System log watchers: the journal on Linux, the Event Log on Windows.
//!
//! The server sends the complete watcher set ([`ServerMsg::Watchers`]) after every connect and
//! whenever an alert policy changes. Reading continues across reconnects. Matches are batched
//! every few seconds and rate-limited per watcher; while disconnected a small backlog is kept.
//!
//! [`ServerMsg::Watchers`]: rmm_proto::ServerMsg::Watchers

#![cfg_attr(not(any(target_os = "linux", windows)), allow(dead_code, unused_imports))]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rmm_proto::{AgentMsg, LOG_MESSAGE_MAX, LogEntry, LogLevel, LogWatcher};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};
use uuid::Uuid;

const FLUSH_EVERY: Duration = Duration::from_secs(5);
/// Per watcher: at most this many entries a minute reach the server; the rest are counted.
const RATE_PER_MINUTE: usize = 20;
/// Entries kept per watcher while disconnected.
const BACKLOG: usize = 50;

struct Compiled {
    w: LogWatcher,
    pattern: Option<regex_lite::Regex>,
}

impl Compiled {
    fn new(w: LogWatcher) -> Self {
        let pattern = w.pattern.as_deref().filter(|p| !p.is_empty()).and_then(|p| {
            regex_lite::RegexBuilder::new(p)
                .case_insensitive(true)
                .build()
                .inspect_err(|e| warn!(watcher = %w.id, "ignoring invalid pattern: {e}"))
                .ok()
        });
        Compiled { w, pattern }
    }

    /// `channel` is the Windows log the entry came from (None on Linux). `sources` are the
    /// names the entry can be matched by (unit, syslog identifier, provider).
    fn matches(&self, channel: Option<&str>, sources: &[&str], e: &LogEntry) -> bool {
        let w = &self.w;
        e.level <= w.min_level
            && channel.is_none_or(|c| w.channels.is_empty() || w.channels.iter().any(|x| x.eq_ignore_ascii_case(c)))
            && (w.sources.is_empty()
                || w.sources.iter().any(|want| {
                    sources.iter().any(|s| {
                        s.eq_ignore_ascii_case(want) || s.strip_suffix(".service").is_some_and(|b| b.eq_ignore_ascii_case(want))
                    })
                }))
            && (w.event_ids.is_empty() || e.event_id.is_some_and(|id| w.event_ids.contains(&id)))
            && self.pattern.as_ref().is_none_or(|re| re.is_match(&e.message))
    }
}

#[derive(Default)]
struct Pending {
    entries: Vec<LogEntry>,
    suppressed: u32,
    window: Option<Instant>,
    in_window: usize,
}

#[derive(Default)]
struct Shared {
    pending: Mutex<HashMap<Uuid, Pending>>,
    link: Mutex<Option<mpsc::Sender<AgentMsg>>>,
}

impl Shared {
    fn record(&self, id: Uuid, e: LogEntry) {
        let mut all = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        let p = all.entry(id).or_default();
        let now = Instant::now();
        if p.window.is_none_or(|w| now.duration_since(w) >= Duration::from_secs(60)) {
            p.window = Some(now);
            p.in_window = 0;
        }
        if p.in_window >= RATE_PER_MINUTE || p.entries.len() >= BACKLOG {
            p.suppressed = p.suppressed.saturating_add(1);
            return;
        }
        p.in_window += 1;
        p.entries.push(e);
    }

    async fn flush(&self) {
        let Some(tx) = self.link.lock().unwrap_or_else(|e| e.into_inner()).clone() else { return };
        let batches: Vec<(Uuid, Vec<LogEntry>, u32)> = {
            let mut all = self.pending.lock().unwrap_or_else(|e| e.into_inner());
            all.iter_mut()
                .filter(|(_, p)| !p.entries.is_empty() || p.suppressed > 0)
                .map(|(id, p)| (*id, std::mem::take(&mut p.entries), std::mem::take(&mut p.suppressed)))
                .collect()
        };
        for (watcher_id, entries, suppressed) in batches {
            let _ = tx.send(AgentMsg::LogMatches { watcher_id, entries, suppressed }).await;
        }
    }
}

/// Owns the reader task. Lives for the agent's lifetime; connections attach and detach.
#[derive(Default)]
pub struct LogWatchers {
    current: tokio::sync::Mutex<(Vec<LogWatcher>, Option<JoinHandle<()>>)>,
    shared: Arc<Shared>,
    flusher: Mutex<Option<JoinHandle<()>>>,
}

impl LogWatchers {
    pub fn attach(&self, tx: mpsc::Sender<AgentMsg>) {
        *self.shared.link.lock().unwrap_or_else(|e| e.into_inner()) = Some(tx);
        let mut f = self.flusher.lock().unwrap_or_else(|e| e.into_inner());
        if f.is_none() {
            let shared = self.shared.clone();
            *f = Some(tokio::spawn(async move {
                let mut tick = tokio::time::interval(FLUSH_EVERY);
                loop {
                    tick.tick().await;
                    shared.flush().await;
                }
            }));
        }
    }

    pub fn detach(&self) {
        *self.shared.link.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }

    /// Replaces the watcher set. The reader restarts only if the set changed.
    pub async fn set(&self, watchers: Vec<LogWatcher>) {
        let mut cur = self.current.lock().await;
        if cur.0 == watchers && (watchers.is_empty() || cur.1.as_ref().is_some_and(|h| !h.is_finished())) {
            return;
        }
        if let Some(h) = cur.1.take() {
            h.abort();
        }
        {
            let keep: Vec<Uuid> = watchers.iter().map(|w| w.id).collect();
            self.shared.pending.lock().unwrap_or_else(|e| e.into_inner()).retain(|id, _| keep.contains(id));
        }
        cur.0 = watchers.clone();
        if watchers.is_empty() {
            return;
        }
        info!(watchers = watchers.len(), "log watchers updated");
        let compiled: Vec<Compiled> = watchers.into_iter().map(Compiled::new).collect();
        cur.1 = Some(tokio::spawn(read(compiled, self.shared.clone())));
    }
}

fn truncate(mut s: String) -> String {
    let s2 = s.trim_end();
    if s2.len() != s.len() {
        s.truncate(s2.len());
    }
    if s.len() > LOG_MESSAGE_MAX {
        let mut cut = LOG_MESSAGE_MAX;
        while !s.is_char_boundary(cut) {
            cut -= 1;
        }
        s.truncate(cut);
        s.push('…');
    }
    s
}

// ---------------------------------------------------------------------------
// Linux: journalctl -f -o json
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
async fn read(watchers: Vec<Compiled>, shared: Arc<Shared>) {
    use std::process::Stdio;
    use tokio::io::{AsyncBufReadExt, BufReader};
    use tokio::process::Command;

    let least = watchers.iter().map(|w| w.w.min_level).max().unwrap_or(LogLevel::Info);
    let priority = match least {
        LogLevel::Critical => "2",
        LogLevel::Error => "3",
        LogLevel::Warning => "4",
        LogLevel::Info => "6",
    };
    loop {
        let child = Command::new("journalctl")
            .args(["--follow", "--lines=0", "--output=json", "--no-pager", "--priority", priority])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn();
        let mut child = match child {
            Ok(c) => c,
            Err(e) => {
                warn!("cannot start journalctl: {e}");
                tokio::time::sleep(Duration::from_secs(300)).await;
                continue;
            }
        };
        let mut lines = BufReader::new(child.stdout.take().expect("piped")).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            if let Some((sources, e)) = parse_journal(&line) {
                let sources: Vec<&str> = sources.iter().map(String::as_str).collect();
                for w in &watchers {
                    if w.matches(None, &sources, &e) {
                        shared.record(w.w.id, e.clone());
                    }
                }
            }
        }
        let _ = child.kill().await;
        debug!("journalctl exited; restarting in 30s");
        tokio::time::sleep(Duration::from_secs(30)).await;
    }
}

/// One `journalctl -o json` line: the names it can be matched by, and the entry.
#[cfg(any(target_os = "linux", test))]
fn parse_journal(line: &str) -> Option<(Vec<String>, LogEntry)> {
    use chrono::{TimeZone, Utc};
    let v: serde_json::Value = serde_json::from_str(line).ok()?;
    let field = |k: &str| v.get(k).and_then(|x| x.as_str()).map(str::to_string);
    let message = match v.get("MESSAGE")? {
        serde_json::Value::String(s) => s.clone(),
        // Non-UTF-8 messages come as byte arrays.
        serde_json::Value::Array(a) => {
            String::from_utf8_lossy(&a.iter().filter_map(|b| b.as_u64().map(|b| b as u8)).collect::<Vec<_>>()).into_owned()
        }
        _ => return None,
    };
    let level = LogLevel::from_syslog(field("PRIORITY").and_then(|p| p.parse().ok()).unwrap_or(6));
    let ts = field("__REALTIME_TIMESTAMP")
        .and_then(|t| t.parse::<i64>().ok())
        .and_then(|us| Utc.timestamp_micros(us).single())
        .unwrap_or_else(Utc::now);
    let sources: Vec<String> = ["_SYSTEMD_UNIT", "SYSLOG_IDENTIFIER", "_COMM"].iter().filter_map(|k| field(k)).collect();
    let source = sources.first().cloned().unwrap_or_default();
    Some((sources, LogEntry { ts, level, source, event_id: None, message: truncate(message) }))
}

// ---------------------------------------------------------------------------
// Windows: poll each channel with wevtutil
// ---------------------------------------------------------------------------

#[cfg(windows)]
async fn read(watchers: Vec<Compiled>, shared: Arc<Shared>) {
    use std::collections::BTreeSet;
    const POLL: Duration = Duration::from_secs(30);

    // Watchers without channels read System and Application.
    let channels: BTreeSet<String> = watchers
        .iter()
        .flat_map(|w| if w.w.channels.is_empty() { vec!["System".into(), "Application".into()] } else { w.w.channels.clone() })
        .collect();
    let least = watchers.iter().map(|w| w.w.min_level).max().unwrap_or(LogLevel::Info);
    let level_filter = match least {
        LogLevel::Critical => " and (Level=1)",
        LogLevel::Error => " and (Level=1 or Level=2)",
        LogLevel::Warning => " and (Level=1 or Level=2 or Level=3)",
        LogLevel::Info => "",
    };
    // Start at the newest record: only new events count.
    let mut last: HashMap<String, u64> = HashMap::new();
    for c in &channels {
        let newest = wevtutil(&[c, "/c:1", "/rd:true", "/f:xml"]).await.ok().and_then(|x| parse_events(&x).first().map(|e| e.record));
        last.insert(c.clone(), newest.unwrap_or(0));
    }
    let mut tick = tokio::time::interval(POLL);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        for c in &channels {
            let from = last.get(c).copied().unwrap_or(0);
            let query = format!("/q:*[System[(EventRecordID>{from}){level_filter}]]");
            let xml = match wevtutil(&[c, &query, "/f:RenderedXml", "/e:Events", "/c:500"]).await {
                Ok(x) => x,
                Err(e) => {
                    debug!(channel = %c, "wevtutil: {e:#}");
                    continue;
                }
            };
            for ev in parse_events(&xml) {
                last.insert(c.clone(), ev.record.max(last.get(c).copied().unwrap_or(0)));
                let sources = [ev.entry.source.as_str()];
                for w in &watchers {
                    if w.matches(Some(c), &sources, &ev.entry) {
                        shared.record(w.w.id, ev.entry.clone());
                    }
                }
            }
        }
    }
}

#[cfg(windows)]
async fn wevtutil(args: &[&str]) -> anyhow::Result<String> {
    use std::process::Stdio;
    let mut c = tokio::process::Command::new("wevtutil.exe");
    c.arg("qe").args(args).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).kill_on_drop(true);
    let out = tokio::time::timeout(Duration::from_secs(60), c.output()).await??;
    anyhow::ensure!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr).trim());
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

#[cfg(any(windows, test))]
struct WinEvent {
    record: u64,
    entry: LogEntry,
}

/// Picks the fields we need out of wevtutil's XML. It's machine-generated and regular, so
/// plain string scanning is enough (and avoids an XML parser in the agent).
#[cfg(any(windows, test))]
fn parse_events(xml: &str) -> Vec<WinEvent> {
    fn between<'a>(s: &'a str, open: &str, close: &str) -> Option<&'a str> {
        let start = s.find(open)? + open.len();
        let rest = &s[start..];
        Some(&rest[..rest.find(close)?])
    }
    /// Text of `<tag ...>text</tag>`.
    fn text<'a>(s: &'a str, tag: &str) -> Option<&'a str> {
        let start = s.find(&format!("<{tag}"))?;
        let rest = &s[start..];
        let gt = rest.find('>')?;
        if rest[..gt].ends_with('/') {
            return Some("");
        }
        let body = &rest[gt + 1..];
        Some(&body[..body.find(&format!("</{tag}>"))?])
    }
    fn attr<'a>(s: &'a str, tag: &str, name: &str) -> Option<&'a str> {
        let start = s.find(&format!("<{tag} "))?;
        let el = &s[start..start + s[start..].find('>')?];
        between(el, &format!("{name}='"), "'").or_else(|| between(el, &format!("{name}=\""), "\""))
    }
    fn unescape(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        let mut rest = s;
        while let Some(i) = rest.find('&') {
            out.push_str(&rest[..i]);
            rest = &rest[i..];
            let Some(end) = rest.find(';').filter(|e| *e <= 10) else {
                out.push('&');
                rest = &rest[1..];
                continue;
            };
            let ent = &rest[1..end];
            let ch = match ent {
                "lt" => Some('<'),
                "gt" => Some('>'),
                "amp" => Some('&'),
                "quot" => Some('"'),
                "apos" => Some('\''),
                _ => ent
                    .strip_prefix("#x")
                    .and_then(|h| u32::from_str_radix(h, 16).ok())
                    .or_else(|| ent.strip_prefix('#').and_then(|d| d.parse().ok()))
                    .and_then(char::from_u32),
            };
            match ch {
                Some(c) => out.push(c),
                None => out.push_str(&rest[..=end]),
            }
            rest = &rest[end + 1..];
        }
        out.push_str(rest);
        out
    }

    let mut out = Vec::new();
    for chunk in xml.split("<Event ").skip(1) {
        let Some(record) = text(chunk, "EventRecordID").and_then(|r| r.trim().parse().ok()) else { continue };
        let level = LogLevel::from_windows(text(chunk, "Level").and_then(|l| l.trim().parse().ok()).unwrap_or(4));
        let ts = attr(chunk, "TimeCreated", "SystemTime")
            .and_then(|t| chrono::DateTime::parse_from_rfc3339(t).ok())
            .map(|t| t.with_timezone(&chrono::Utc))
            .unwrap_or_else(chrono::Utc::now);
        let source = attr(chunk, "Provider", "Name").map(unescape).unwrap_or_default();
        let event_id = text(chunk, "EventID").and_then(|e| e.trim().parse().ok());
        let message = text(chunk, "Message").map(unescape).unwrap_or_default();
        out.push(WinEvent { record, entry: LogEntry { ts, level, source, event_id, message: truncate(message) } });
    }
    out
}

#[cfg(not(any(target_os = "linux", windows)))]
async fn read(_watchers: Vec<Compiled>, _shared: Arc<Shared>) {
    debug!("log watching isn't supported on this OS yet");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn watcher(min_level: LogLevel) -> LogWatcher {
        LogWatcher { id: Uuid::new_v4(), channels: vec![], sources: vec![], event_ids: vec![], min_level, pattern: None }
    }

    fn entry(level: LogLevel, msg: &str) -> LogEntry {
        LogEntry { ts: chrono::Utc::now(), level, source: "sshd".into(), event_id: Some(7036), message: msg.into() }
    }

    #[test]
    fn matching_rules() {
        let w = Compiled::new(LogWatcher {
            sources: vec!["nginx".into()],
            pattern: Some("upstream timed out".into()),
            ..watcher(LogLevel::Error)
        });
        let e = entry(LogLevel::Error, "x UPSTREAM timed out y");
        assert!(w.matches(None, &["nginx.service"], &e), "unit suffix and case are ignored");
        assert!(!w.matches(None, &["sshd"], &e));
        assert!(!w.matches(None, &["nginx"], &entry(LogLevel::Warning, "upstream timed out")), "too mild");
        assert!(w.matches(None, &["nginx"], &entry(LogLevel::Critical, "upstream timed out")));

        let ids = Compiled::new(LogWatcher { channels: vec!["System".into()], event_ids: vec![41], ..watcher(LogLevel::Info) });
        let mut e = entry(LogLevel::Critical, "rebooted");
        e.event_id = Some(41);
        assert!(ids.matches(Some("system"), &["Kernel-Power"], &e));
        assert!(!ids.matches(Some("Application"), &["Kernel-Power"], &e));
        e.event_id = Some(42);
        assert!(!ids.matches(Some("System"), &["Kernel-Power"], &e));
    }

    #[test]
    fn rate_limit_counts_the_rest() {
        let s = Shared::default();
        let id = Uuid::new_v4();
        for _ in 0..RATE_PER_MINUTE + 7 {
            s.record(id, entry(LogLevel::Error, "x"));
        }
        let p = &s.pending.lock().unwrap()[&id];
        assert_eq!((p.entries.len(), p.suppressed), (RATE_PER_MINUTE, 7));
    }

    #[test]
    fn journal_json_parses() {
        let line = r#"{"__REALTIME_TIMESTAMP":"1700000000000000","PRIORITY":"3","_SYSTEMD_UNIT":"nginx.service","SYSLOG_IDENTIFIER":"nginx","MESSAGE":"boom  "}"#;
        let (sources, e) = parse_journal(line).unwrap();
        assert_eq!(sources, ["nginx.service", "nginx"]);
        assert_eq!((e.level, e.message.as_str(), e.ts.timestamp()), (LogLevel::Error, "boom", 1_700_000_000));
        let bytes = r#"{"MESSAGE":[104,105],"PRIORITY":"6"}"#;
        assert_eq!(parse_journal(bytes).unwrap().1.message, "hi");
        assert!(parse_journal(r#"{"PRIORITY":"6"}"#).is_none());
    }

    #[test]
    fn windows_events_parse() {
        let xml = r#"<Events><Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Service Control Manager' Guid='{555908d1}' EventSourceName='Service Control Manager'/><EventID Qualifiers='16384'>7036</EventID><Level>2</Level><TimeCreated SystemTime='2026-01-02T03:04:05.1234567Z'/><EventRecordID>9912</EventRecordID><Channel>System</Channel></System><RenderingInfo Culture='en-US'><Message>The Print Spooler service entered the &lt;stopped&gt; state.&#xD;&#xA;</Message></RenderingInfo></Event><Event xmlns='x'><System><Provider Name='A'/><EventID>1</EventID><Level>4</Level><EventRecordID>9913</EventRecordID></System></Event></Events>"#;
        let evs = parse_events(xml);
        assert_eq!(evs.len(), 2);
        let e = &evs[0];
        assert_eq!((e.record, e.entry.event_id, e.entry.level), (9912, Some(7036), LogLevel::Error));
        assert_eq!(e.entry.source, "Service Control Manager");
        assert_eq!(e.entry.message, "The Print Spooler service entered the <stopped> state.");
        assert_eq!(e.entry.ts.timestamp(), 1_767_323_045);
        assert_eq!((evs[1].record, evs[1].entry.message.as_str()), (9913, ""));
    }

    #[test]
    fn long_messages_are_cut_on_a_char_boundary() {
        let s = truncate("é".repeat(LOG_MESSAGE_MAX));
        assert!(s.len() <= LOG_MESSAGE_MAX + '…'.len_utf8() && s.ends_with('…'));
    }
}
