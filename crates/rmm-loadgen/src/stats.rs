//! What the run measured: counters, and latency samples for percentiles.

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use serde_json::{Value, json};

#[derive(Default)]
pub struct Stats {
    pub enrolled: AtomicU64,
    pub enroll_failed: AtomicU64,
    /// Sessions that authenticated, and attempts that didn't get that far.
    pub connected: AtomicU64,
    pub connect_failed: AtomicU64,
    /// Agents with a session open right now.
    pub online: AtomicU64,
    /// Sessions the server (or the network) ended while the run wanted them open.
    pub dropped: AtomicU64,
    pub sent_msgs: AtomicU64,
    pub sent_bytes: AtomicU64,
    pub recv_msgs: AtomicU64,
    pub recv_bytes: AtomicU64,
    pub jobs_received: AtomicU64,
    pub jobs_acked: AtomicU64,
    pub scans_requested: AtomicU64,
    pub sse_events: AtomicU64,
    pub sse_resyncs: AtomicU64,
    pub sse_dropped: AtomicU64,
    pub api_errors: AtomicU64,
    pub bulk_runs: AtomicU64,
    pub bulk_jobs: AtomicU64,
    /// Latency samples by name (connect, job round trip, each API endpoint...).
    samples: Mutex<HashMap<&'static str, Vec<u32>>>,
    /// First few error messages, for the report.
    errors: Mutex<Vec<String>>,
}

/// Most samples kept per series; later ones replace earlier ones at random positions, so a
/// long run stays a fair sample without growing.
const MAX_SAMPLES: usize = 200_000;

impl Stats {
    pub fn inc(c: &AtomicU64) {
        c.fetch_add(1, Ordering::Relaxed);
    }

    pub fn add(c: &AtomicU64, n: u64) {
        c.fetch_add(n, Ordering::Relaxed);
    }

    pub fn get(c: &AtomicU64) -> u64 {
        c.load(Ordering::Relaxed)
    }

    pub fn sample(&self, name: &'static str, d: Duration) {
        let us = d.as_micros().min(u32::MAX as u128) as u32;
        let mut s = self.samples.lock().unwrap();
        let v = s.entry(name).or_default();
        if v.len() < MAX_SAMPLES {
            v.push(us);
        } else {
            let i = (uuid::Uuid::new_v4().as_u128() % MAX_SAMPLES as u128) as usize;
            v[i] = us;
        }
    }

    pub fn error(&self, e: String) {
        let mut errs = self.errors.lock().unwrap();
        if errs.len() < 20 && !errs.contains(&e) {
            errs.push(e);
        }
    }

    pub fn errors(&self) -> Vec<String> {
        self.errors.lock().unwrap().clone()
    }

    /// Percentiles in milliseconds for every series.
    pub fn latencies(&self) -> Value {
        let s = self.samples.lock().unwrap();
        let mut out = serde_json::Map::new();
        let mut names: Vec<_> = s.keys().copied().collect();
        names.sort();
        for n in names {
            let mut v = s[n].clone();
            v.sort_unstable();
            out.insert(n.to_string(), percentiles(&v));
        }
        Value::Object(out)
    }

    pub fn counters(&self) -> Value {
        let g = Self::get;
        json!({
            "enrolled": g(&self.enrolled), "enroll_failed": g(&self.enroll_failed),
            "sessions_connected": g(&self.connected), "connect_failed": g(&self.connect_failed),
            "online_now": g(&self.online), "sessions_dropped": g(&self.dropped),
            "messages_sent": g(&self.sent_msgs), "bytes_sent": g(&self.sent_bytes),
            "messages_received": g(&self.recv_msgs), "bytes_received": g(&self.recv_bytes),
            "jobs_received": g(&self.jobs_received), "jobs_acked": g(&self.jobs_acked),
            "patch_scans_requested": g(&self.scans_requested),
            "sse_events": g(&self.sse_events), "sse_resyncs": g(&self.sse_resyncs), "sse_dropped": g(&self.sse_dropped),
            "api_errors": g(&self.api_errors), "bulk_runs": g(&self.bulk_runs), "bulk_jobs": g(&self.bulk_jobs),
        })
    }
}

/// Sorted microsecond samples to {n, p50, p95, p99, max} in milliseconds.
pub fn percentiles(v: &[u32]) -> Value {
    if v.is_empty() {
        return json!({ "n": 0 });
    }
    let at = |p: f64| v[((v.len() as f64 - 1.0) * p).round() as usize] as f64 / 1000.0;
    json!({ "n": v.len(), "p50": at(0.50), "p95": at(0.95), "p99": at(0.99), "max": at(1.0) })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percentile_positions() {
        let v: Vec<u32> = (1..=100).map(|i| i * 1000).collect();
        let p = percentiles(&v);
        assert_eq!((p["p50"].as_f64(), p["p99"].as_f64(), p["max"].as_f64()), (Some(51.0), Some(99.0), Some(100.0)));
        assert_eq!(percentiles(&[])["n"], 0);
    }
}
