//! `GET /metrics`: what the server is doing, in the Prometheus text format.
//!
//! A small registry of atomics and fixed-bucket histograms rather than a metrics crate: the
//! set of series is known up front, and every label has a bounded set of values (message
//! types, route templates, status classes). Nothing here is labelled with an agent, client,
//! user or ticket id.
//!
//! The route is off unless `RMM_METRICS_TOKEN` is set (it answers 404), and then wants
//! `Authorization: Bearer <token>`.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, RwLock};
use std::time::{Duration, Instant};

use axum::extract::{MatchedPath, Request, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use subtle::ConstantTimeEq;

use crate::state::AppState;

/// Upper bounds (seconds) of the duration histograms.
const BUCKETS: [f64; 14] = [0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0];

pub struct Histogram {
    buckets: [AtomicU64; BUCKETS.len()],
    count: AtomicU64,
    /// Sum in microseconds (an integer, so it can be an atomic).
    sum_us: AtomicU64,
}

impl Histogram {
    pub const fn new() -> Self {
        Histogram { buckets: [const { AtomicU64::new(0) }; BUCKETS.len()], count: AtomicU64::new(0), sum_us: AtomicU64::new(0) }
    }

    pub fn observe(&self, d: Duration) {
        let secs = d.as_secs_f64();
        if let Some(i) = BUCKETS.iter().position(|b| secs <= *b) {
            self.buckets[i].fetch_add(1, Ordering::Relaxed);
        }
        self.count.fetch_add(1, Ordering::Relaxed);
        self.sum_us.fetch_add(d.as_micros() as u64, Ordering::Relaxed);
    }

    /// Times `f` into this histogram.
    pub async fn time<T>(&self, f: impl Future<Output = T>) -> T {
        let t = Instant::now();
        let out = f.await;
        self.observe(t.elapsed());
        out
    }

    fn write(&self, out: &mut String, name: &str, labels: &str) {
        let sep = if labels.is_empty() { "" } else { "," };
        let mut cum = 0;
        for (i, b) in BUCKETS.iter().enumerate() {
            cum += self.buckets[i].load(Ordering::Relaxed);
            let _ = writeln!(out, "{name}_bucket{{{labels}{sep}le=\"{b}\"}} {cum}");
        }
        let count = self.count.load(Ordering::Relaxed);
        let _ = writeln!(out, "{name}_bucket{{{labels}{sep}le=\"+Inf\"}} {count}");
        let braces = if labels.is_empty() { String::new() } else { format!("{{{labels}}}") };
        let _ = writeln!(out, "{name}_sum{braces} {}", self.sum_us.load(Ordering::Relaxed) as f64 / 1e6);
        let _ = writeln!(out, "{name}_count{braces} {count}");
    }
}

/// Agent message types, in the order of [`Metrics::agent_messages`]. Must match
/// `agent_ws::message_type`.
pub const AGENT_MESSAGE_TYPES: [&str; 33] = [
    "enroll",
    "auth",
    "heartbeat",
    "inventory",
    "job_output",
    "job_finished",
    "job_sync",
    "update_fetch",
    "update_status",
    "shell_opened",
    "shell_output",
    "shell_closed",
    "pong",
    "services",
    "service_control_result",
    "log_matches",
    "patch_scan_result",
    "patch_progress",
    "patch_result",
    "desktop_info",
    "desktop_frame",
    "desktop_closed",
    "security_status",
    "security_action_result",
    "sensor_status",
    "sensor_detection",
    "quarantine_list",
    "telemetry_result",
    "triage_chunk",
    "tool_reply",
    "reputation_query",
    "net_scan_result",
    "snmp_poll_result",
];

/// Why a message for an agent or a browser session was thrown away.
pub const DROP_REASONS: [&str; 3] = ["agent_offline", "agent_queue_closed", "desktop_queue_full"];

pub struct Metrics {
    pub agent_messages: [AtomicU64; AGENT_MESSAGE_TYPES.len()],
    pub agent_message_bytes: AtomicU64,
    pub agent_connects: AtomicU64,
    pub agent_auth_failures: AtomicU64,
    pub hub_dropped: [AtomicU64; DROP_REASONS.len()],
    pub sse_lagged_events: AtomicU64,
    pub sse_resyncs: AtomicU64,
    pub alert_eval: Histogram,
    pub scheduler_tick: Histogram,
    pub db_acquire: Histogram,
    pub db_acquire_timeouts: AtomicU64,
}

pub static M: Metrics = Metrics {
    agent_messages: [const { AtomicU64::new(0) }; AGENT_MESSAGE_TYPES.len()],
    agent_message_bytes: AtomicU64::new(0),
    agent_connects: AtomicU64::new(0),
    agent_auth_failures: AtomicU64::new(0),
    hub_dropped: [const { AtomicU64::new(0) }; DROP_REASONS.len()],
    sse_lagged_events: AtomicU64::new(0),
    sse_resyncs: AtomicU64::new(0),
    alert_eval: Histogram::new(),
    scheduler_tick: Histogram::new(),
    db_acquire: Histogram::new(),
    db_acquire_timeouts: AtomicU64::new(0),
};

pub fn inc(c: &AtomicU64) {
    c.fetch_add(1, Ordering::Relaxed);
}

pub fn dropped(reason: &str) {
    if let Some(i) = DROP_REASONS.iter().position(|r| *r == reason) {
        inc(&M.hub_dropped[i]);
    }
}

/// HTTP requests by (method, route template, status class).
#[derive(Default)]
struct HttpSeries {
    count: AtomicU64,
    duration: Histogram,
}

type HttpKey = (&'static str, String, &'static str);
static HTTP: LazyLock<RwLock<HashMap<HttpKey, Arc<HttpSeries>>>> = LazyLock::new(Default::default);

impl Default for Histogram {
    fn default() -> Self {
        Self::new()
    }
}

fn method_label(m: &axum::http::Method) -> &'static str {
    match *m {
        axum::http::Method::GET => "GET",
        axum::http::Method::POST => "POST",
        axum::http::Method::PUT => "PUT",
        axum::http::Method::PATCH => "PATCH",
        axum::http::Method::DELETE => "DELETE",
        axum::http::Method::HEAD => "HEAD",
        axum::http::Method::OPTIONS => "OPTIONS",
        _ => "other",
    }
}

fn status_class(s: StatusCode) -> &'static str {
    match s.as_u16() {
        100..=199 => "1xx",
        200..=299 => "2xx",
        300..=399 => "3xx",
        400..=499 => "4xx",
        _ => "5xx",
    }
}

/// The matched route template (`/api/tickets/{id}`), never the path itself. Requests no
/// route matched are the dashboard's static files (or a 404) and share one label.
pub fn route_of(req: &Request) -> String {
    req.extensions().get::<MatchedPath>().map(|p| p.as_str().to_string()).unwrap_or_else(|| "static".into())
}

/// Every request: metrics by route template, and one log line with method, route, status,
/// duration and a request id (also sent back as `x-request-id`). Never the query string
/// (portal sign-in links and survey tokens travel there), headers or bodies.
pub async fn http_layer(req: Request, next: Next) -> Response {
    use tracing::Instrument;
    let method = method_label(req.method());
    let route = route_of(&req);
    let id = request_id();
    let span = tracing::info_span!("request", id = %id, method, route = %route);
    let start = Instant::now();
    let mut res = next.run(req).instrument(span.clone()).await;
    let elapsed = start.elapsed();
    let status = res.status();
    let key = (method, route, status_class(status));
    let series = HTTP.read().unwrap_or_else(|e| e.into_inner()).get(&key).cloned();
    let series = match series {
        Some(s) => s,
        None => HTTP.write().unwrap_or_else(|e| e.into_inner()).entry(key).or_default().clone(),
    };
    series.count.fetch_add(1, Ordering::Relaxed);
    series.duration.observe(elapsed);
    let ms = elapsed.as_secs_f64() * 1000.0;
    span.in_scope(|| {
        if status.is_server_error() {
            tracing::warn!(target: "rmm_server::http", status = status.as_u16(), duration_ms = ms, "request failed");
        } else {
            tracing::info!(target: "rmm_server::http", status = status.as_u16(), duration_ms = ms, "request");
        }
    });
    if let Ok(v) = header::HeaderValue::from_str(&id) {
        res.headers_mut().insert("x-request-id", v);
    }
    res
}

fn request_id() -> String {
    let mut b = [0u8; 8];
    getrandom::fill(&mut b).expect("OS RNG unavailable");
    hex::encode(b)
}

/// Samples how long getting a database connection takes, every few seconds: sqlx doesn't
/// report it, and a probe is what a new request would see.
pub async fn probe_pool(st: Arc<AppState>) {
    let mut tick = tokio::time::interval(Duration::from_secs(5));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        let t = Instant::now();
        match st.db.acquire().await {
            Ok(c) => {
                M.db_acquire.observe(t.elapsed());
                drop(c);
            }
            Err(sqlx::Error::PoolTimedOut) => {
                M.db_acquire.observe(t.elapsed());
                inc(&M.db_acquire_timeouts);
            }
            Err(e) => tracing::debug!("pool probe: {e}"),
        }
    }
}

/// `GET /metrics`.
pub async fn handler(State(st): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let Some(want) = st.cfg.metrics_token.as_deref() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let given = headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()).and_then(|v| v.strip_prefix("Bearer ")).unwrap_or("");
    if !bool::from(given.as_bytes().ct_eq(want.as_bytes())) {
        return (StatusCode::UNAUTHORIZED, [(header::WWW_AUTHENTICATE, "Bearer")]).into_response();
    }
    let body = render(&st).await;
    ([(header::CONTENT_TYPE, "text/plain; version=0.0.4; charset=utf-8"), (header::CACHE_CONTROL, "no-store")], body).into_response()
}

fn family(out: &mut String, name: &str, kind: &str, help: &str) {
    let _ = writeln!(out, "# HELP {name} {help}");
    let _ = writeln!(out, "# TYPE {name} {kind}");
}

fn gauge(out: &mut String, name: &str, help: &str, v: f64) {
    family(out, name, "gauge", help);
    let _ = writeln!(out, "{name} {v}");
}

fn counter(out: &mut String, name: &str, help: &str, v: u64) {
    family(out, name, "counter", help);
    let _ = writeln!(out, "{name} {v}");
}

/// Label values here come from fixed lists or route templates, but escape anyway.
fn esc(v: &str) -> String {
    v.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n")
}

pub async fn render(st: &AppState) -> String {
    let mut out = String::with_capacity(16 * 1024);
    family(&mut out, "rmm_build_info", "gauge", "The running server's version (always 1).");
    let _ = writeln!(out, "rmm_build_info{{version=\"{}\"}} 1", env!("CARGO_PKG_VERSION"));
    gauge(&mut out, "rmm_uptime_seconds", "Seconds since this server process started.", (chrono::Utc::now() - st.started_at).num_milliseconds() as f64 / 1000.0);

    // --- agents and the hub --------------------------------------------------------------------
    let hub = st.hub.stats();
    gauge(&mut out, "rmm_agents_connected", "Agents with an open WebSocket to this server.", hub.agents as f64);
    counter(&mut out, "rmm_agent_connects_total", "Agent sessions authenticated.", M.agent_connects.load(Ordering::Relaxed));
    counter(&mut out, "rmm_agent_auth_failures_total", "Agent connections refused for bad credentials.", M.agent_auth_failures.load(Ordering::Relaxed));
    family(&mut out, "rmm_agent_messages_total", "counter", "Messages received from agents, by type.");
    for (i, t) in AGENT_MESSAGE_TYPES.iter().enumerate() {
        let _ = writeln!(out, "rmm_agent_messages_total{{type=\"{t}\"}} {}", M.agent_messages[i].load(Ordering::Relaxed));
    }
    counter(&mut out, "rmm_agent_message_bytes_total", "Bytes of agent messages received.", M.agent_message_bytes.load(Ordering::Relaxed));
    gauge(&mut out, "rmm_hub_send_queue_depth", "Messages waiting in the per-agent send queues, all agents together.", hub.queued as f64);
    gauge(&mut out, "rmm_hub_send_queue_max", "Messages waiting in the fullest single agent send queue.", hub.queued_max as f64);
    gauge(&mut out, "rmm_hub_send_queue_capacity", "Capacity of one agent's send queue.", hub.capacity as f64);
    family(&mut out, "rmm_hub_dropped_total", "counter", "Messages for an agent or a session that were thrown away, by reason.");
    for (i, r) in DROP_REASONS.iter().enumerate() {
        let _ = writeln!(out, "rmm_hub_dropped_total{{reason=\"{r}\"}} {}", M.hub_dropped[i].load(Ordering::Relaxed));
    }
    gauge(&mut out, "rmm_shell_sessions", "Open terminal sessions.", hub.shells as f64);
    gauge(&mut out, "rmm_desktop_sessions", "Open remote desktop sessions.", hub.desktops as f64);
    gauge(&mut out, "rmm_sse_subscribers", "Open dashboard event streams (/api/events).", hub.subscribers as f64);
    counter(&mut out, "rmm_sse_lagged_events_total", "Events skipped because a dashboard stream fell behind.", M.sse_lagged_events.load(Ordering::Relaxed));
    counter(&mut out, "rmm_sse_resyncs_total", "Times a dashboard stream fell behind and was told to refetch.", M.sse_resyncs.load(Ordering::Relaxed));

    // --- background work -------------------------------------------------------------------------
    gauge(&mut out, "rmm_alert_eval_interval_seconds", "How often polled alert policies are evaluated (RMM_ALERT_EVAL_SECS).", st.cfg.alert_eval_secs.max(5) as f64);
    family(&mut out, "rmm_alert_eval_duration_seconds", "histogram", "Time to evaluate every polled alert policy once.");
    M.alert_eval.write(&mut out, "rmm_alert_eval_duration_seconds", "");
    family(&mut out, "rmm_scheduler_tick_duration_seconds", "histogram", "Time for one scheduler tick (claiming and starting due scheduled scripts).");
    M.scheduler_tick.write(&mut out, "rmm_scheduler_tick_duration_seconds", "");
    // Outboxes: one cheap query each (both have partial indexes on pending rows).
    let outbox: Vec<(String, i64, Option<f64>)> = sqlx::query_as(
        "SELECT 'notifications', count(*), extract(epoch FROM now() - min(created_at))::float8 FROM notifications WHERE status = 'pending'
         UNION ALL
         SELECT 'email', count(*), extract(epoch FROM now() - min(created_at))::float8 FROM email_messages WHERE direction = 'out' AND status = 'pending'",
    )
    .fetch_all(&st.db)
    .await
    .unwrap_or_default();
    family(&mut out, "rmm_outbox_pending", "gauge", "Notifications and emails waiting to be sent (including retries), by outbox.");
    for (o, n, _) in &outbox {
        let _ = writeln!(out, "rmm_outbox_pending{{outbox=\"{o}\"}} {n}");
    }
    family(&mut out, "rmm_outbox_oldest_seconds", "gauge", "Age of the oldest pending item, by outbox (0 when empty).");
    for (o, _, age) in &outbox {
        let _ = writeln!(out, "rmm_outbox_oldest_seconds{{outbox=\"{o}\"}} {}", age.unwrap_or(0.0).max(0.0));
    }

    // --- HTTP ------------------------------------------------------------------------------------
    let http: Vec<(HttpKey, Arc<HttpSeries>)> = {
        let map = HTTP.read().unwrap_or_else(|e| e.into_inner());
        let mut v: Vec<_> = map.iter().map(|(k, s)| (k.clone(), s.clone())).collect();
        v.sort_by(|a, b| a.0.cmp(&b.0));
        v
    };
    family(&mut out, "rmm_http_requests_total", "counter", "HTTP requests by method, route template and status class.");
    for ((m, r, c), s) in &http {
        let _ = writeln!(out, "rmm_http_requests_total{{method=\"{m}\",route=\"{}\",status=\"{c}\"}} {}", esc(r), s.count.load(Ordering::Relaxed));
    }
    family(&mut out, "rmm_http_request_duration_seconds", "histogram", "Time to the response headers, by method, route template and status class.");
    for ((m, r, c), s) in &http {
        s.duration.write(&mut out, "rmm_http_request_duration_seconds", &format!("method=\"{m}\",route=\"{}\",status=\"{c}\"", esc(r)));
    }

    // --- database --------------------------------------------------------------------------------
    gauge(&mut out, "rmm_db_pool_connections", "Open database connections.", st.db.size() as f64);
    gauge(&mut out, "rmm_db_pool_idle", "Idle database connections.", st.db.num_idle() as f64);
    gauge(&mut out, "rmm_db_pool_max", "The pool's connection limit.", st.db.options().get_max_connections() as f64);
    family(&mut out, "rmm_db_pool_acquire_seconds", "histogram", "Time to get a connection, sampled every 5 seconds.");
    M.db_acquire.write(&mut out, "rmm_db_pool_acquire_seconds", "");
    counter(&mut out, "rmm_db_pool_acquire_timeouts_total", "Times getting a connection timed out (pool exhausted).", M.db_acquire_timeouts.load(Ordering::Relaxed));

    // --- process ---------------------------------------------------------------------------------
    if let Some(p) = process() {
        gauge(&mut out, "process_resident_memory_bytes", "Resident memory size in bytes.", p.rss as f64);
        counter_f(&mut out, "process_cpu_seconds_total", "User and system CPU time in seconds.", p.cpu_secs);
        gauge(&mut out, "process_open_fds", "Open file descriptors.", p.fds as f64);
        gauge(&mut out, "process_threads", "Threads.", p.threads as f64);
    }
    out
}

fn counter_f(out: &mut String, name: &str, help: &str, v: f64) {
    family(out, name, "counter", help);
    let _ = writeln!(out, "{name} {v}");
}

struct Process {
    rss: u64,
    cpu_secs: f64,
    fds: usize,
    threads: u64,
}

/// From /proc on Linux (where the server runs in production); nothing elsewhere.
#[cfg(target_os = "linux")]
fn process() -> Option<Process> {
    let stat = std::fs::read_to_string("/proc/self/stat").ok()?;
    // Fields after the command name, which is in parentheses and may contain spaces.
    let rest = &stat[stat.rfind(')')? + 2..];
    let f: Vec<&str> = rest.split_whitespace().collect();
    // utime and stime are fields 14 and 15, rss 24, num_threads 20 (1-based, counting pid and comm).
    let tick = 100.0; // USER_HZ: 100 on every Linux architecture we ship.
    let cpu_secs = (f.get(11)?.parse::<f64>().ok()? + f.get(12)?.parse::<f64>().ok()?) / tick;
    let threads = f.get(17)?.parse().ok()?;
    let page = 4096u64;
    let rss = f.get(21)?.parse::<u64>().ok()? * page;
    let fds = std::fs::read_dir("/proc/self/fd").map(|d| d.count()).unwrap_or(0);
    Some(Process { rss, cpu_secs, fds, threads })
}

#[cfg(not(target_os = "linux"))]
fn process() -> Option<Process> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn histogram_is_cumulative() {
        let h = Histogram::new();
        h.observe(Duration::from_millis(3));
        h.observe(Duration::from_millis(30));
        h.observe(Duration::from_secs(60));
        let mut out = String::new();
        h.write(&mut out, "x", "a=\"b\"");
        assert!(out.contains("x_bucket{a=\"b\",le=\"0.005\"} 1\n"), "{out}");
        assert!(out.contains("x_bucket{a=\"b\",le=\"0.05\"} 2\n"), "{out}");
        assert!(out.contains("x_bucket{a=\"b\",le=\"30\"} 2\n"), "{out}");
        assert!(out.contains("x_bucket{a=\"b\",le=\"+Inf\"} 3\n"), "{out}");
        assert!(out.contains("x_count{a=\"b\"} 3\n"), "{out}");
        assert!(out.contains("x_sum{a=\"b\"} 60.033\n"), "{out}");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn reads_own_process() {
        let p = process().unwrap();
        assert!(p.rss > 1024 * 1024 && p.threads >= 1 && p.fds > 0);
    }
}
