//! Sampling during the run: the server's `/metrics`, Postgres (size, largest tables, row
//! counts), the Postgres container's CPU and memory, and the generator's own CPU (so a
//! generator that runs out of CPU first is visible as such).

use std::collections::HashMap;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use serde_json::{Value, json};

/// `/metrics` as series (name with labels) to value.
pub type Scrape = HashMap<String, f64>;

pub fn parse(text: &str) -> Scrape {
    text.lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        .filter_map(|l| {
            let (k, v) = l.rsplit_once(' ')?;
            Some((k.to_string(), v.parse().ok()?))
        })
        .collect()
}

pub async fn scrape(http: &reqwest::Client, server: &str, token: &str) -> Result<Scrape> {
    let res = http.get(format!("{}/metrics", server.trim_end_matches('/'))).bearer_auth(token).send().await?;
    anyhow::ensure!(res.status().is_success(), "/metrics: HTTP {}", res.status());
    Ok(parse(&res.text().await?))
}

/// Histogram mean between two scrapes (seconds), and the bucket bound that 99% fall under.
fn hist_delta(a: &Scrape, b: &Scrape, name: &str) -> Value {
    let get = |s: &Scrape, k: &str| s.get(k).copied().unwrap_or(0.0);
    let count = get(b, &format!("{name}_count")) - get(a, &format!("{name}_count"));
    let sum = get(b, &format!("{name}_sum")) - get(a, &format!("{name}_sum"));
    if count <= 0.0 {
        return json!({ "count": 0 });
    }
    let mut bounds: Vec<(f64, f64)> = b
        .iter()
        .filter_map(|(k, v)| {
            let le = k.strip_prefix(&format!("{name}_bucket{{le=\""))?.strip_suffix("\"}")?;
            let le: f64 = if le == "+Inf" { f64::INFINITY } else { le.parse().ok()? };
            Some((le, v - a.get(k).copied().unwrap_or(0.0)))
        })
        .collect();
    bounds.sort_by(|x, y| x.0.total_cmp(&y.0));
    let p = |q: f64| bounds.iter().find(|(_, c)| *c >= q * count).map(|(le, _)| *le).unwrap_or(f64::INFINITY);
    json!({ "count": count, "mean_ms": sum / count * 1000.0, "p50_le_ms": p(0.5) * 1000.0, "p99_le_ms": p(0.99) * 1000.0 })
}

/// What changed on the server between two scrapes `secs` apart.
pub fn window(a: &Scrape, b: &Scrape, secs: f64) -> Value {
    let get = |s: &Scrape, k: &str| s.get(k).copied().unwrap_or(0.0);
    let dropped: f64 = ["agent_offline", "agent_queue_closed", "desktop_queue_full"]
        .iter()
        .map(|r| {
            let k = format!("rmm_hub_dropped_total{{reason=\"{r}\"}}");
            get(b, &k) - get(a, &k)
        })
        .sum();
    let msgs: f64 = b.iter().filter(|(k, _)| k.starts_with("rmm_agent_messages_total{")).map(|(k, v)| v - get(a, k)).sum();
    json!({
        "agents_connected": get(b, "rmm_agents_connected"),
        "server_cpu_cores": (get(b, "process_cpu_seconds_total") - get(a, "process_cpu_seconds_total")) / secs,
        "server_rss_mb": get(b, "process_resident_memory_bytes") / 1048576.0,
        "server_threads": get(b, "process_threads"),
        "server_fds": get(b, "process_open_fds"),
        "agent_messages_per_sec": msgs / secs,
        "agent_bytes_per_sec": (get(b, "rmm_agent_message_bytes_total") - get(a, "rmm_agent_message_bytes_total")) / secs,
        "hub_queue_depth": get(b, "rmm_hub_send_queue_depth"),
        "hub_queue_max": get(b, "rmm_hub_send_queue_max"),
        "hub_dropped": dropped,
        "sse_subscribers": get(b, "rmm_sse_subscribers"),
        "sse_lagged_events": get(b, "rmm_sse_lagged_events_total") - get(a, "rmm_sse_lagged_events_total"),
        "db_pool_connections": get(b, "rmm_db_pool_connections"),
        "db_pool_idle": get(b, "rmm_db_pool_idle"),
        "db_acquire_timeouts": get(b, "rmm_db_pool_acquire_timeouts_total") - get(a, "rmm_db_pool_acquire_timeouts_total"),
        "db_acquire": hist_delta(a, b, "rmm_db_pool_acquire_seconds"),
        "alert_eval": hist_delta(a, b, "rmm_alert_eval_duration_seconds"),
        "alert_eval_interval_s": get(b, "rmm_alert_eval_interval_seconds"),
        "outbox_notifications": get(b, "rmm_outbox_pending{outbox=\"notifications\"}"),
        "http_5xx": b.iter().filter(|(k, _)| k.starts_with("rmm_http_requests_total{") && k.contains("status=\"5xx\"")).map(|(k, v)| v - get(a, k)).sum::<f64>(),
    })
}

pub async fn postgres(db: &sqlx::PgPool) -> Result<Value> {
    let size: i64 = sqlx::query_scalar("SELECT pg_database_size(current_database())").fetch_one(db).await?;
    let tables: Vec<(String, i64, i64)> = sqlx::query_as(
        "SELECT c.relname::text, pg_total_relation_size(c.oid), coalesce(s.n_live_tup, 0)
           FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace LEFT JOIN pg_stat_user_tables s ON s.relid = c.oid
          WHERE c.relkind = 'r' AND n.nspname = 'public' ORDER BY 2 DESC LIMIT 10",
    )
    .fetch_all(db)
    .await?;
    let metric_rows: i64 = sqlx::query_scalar("SELECT count(*) FROM agent_metrics").fetch_one(db).await?;
    let stats: (i64, i64, i64) = sqlx::query_as(
        "SELECT xact_commit + xact_rollback, tup_inserted + tup_updated + tup_deleted, blks_read FROM pg_stat_database WHERE datname = current_database()",
    )
    .fetch_one(db)
    .await?;
    Ok(json!({
        "database_bytes": size,
        "agent_metrics_rows": metric_rows,
        "transactions": stats.0, "rows_written": stats.1, "blocks_read": stats.2,
        "largest_tables": tables.iter().map(|(n, b, r)| json!({ "table": n, "bytes": b, "live_rows": r })).collect::<Vec<_>>(),
    }))
}

/// CPU (cores) and memory of a container, from `docker stats`.
pub async fn container(name: &str) -> Option<Value> {
    let out = tokio::process::Command::new("docker")
        .args(["stats", "--no-stream", "--format", "{{.CPUPerc}}|{{.MemUsage}}", name])
        .output()
        .await
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let (cpu, mem) = text.trim().split_once('|')?;
    let cpu: f64 = cpu.trim_end_matches('%').parse().ok()?;
    Some(json!({ "cpu_cores": cpu / 100.0, "memory": mem.split('/').next()?.trim() }))
}

/// This process's CPU seconds so far (Linux).
pub fn own_cpu_secs() -> Option<f64> {
    let stat = std::fs::read_to_string("/proc/self/stat").ok()?;
    let f: Vec<&str> = stat[stat.rfind(')')? + 2..].split_whitespace().collect();
    Some((f.get(11)?.parse::<f64>().ok()? + f.get(12)?.parse::<f64>().ok()?) / 100.0)
}

pub struct Sampler {
    pub http: reqwest::Client,
    pub server: String,
    pub token: Option<String>,
    pub db: Option<sqlx::PgPool>,
    pub pg_container: Option<String>,
    last: Option<(Instant, Scrape, f64)>,
    pub windows: Vec<Value>,
}

impl Sampler {
    pub fn new(server: &str, token: Option<String>, db: Option<sqlx::PgPool>, pg_container: Option<String>) -> Self {
        Sampler { http: reqwest::Client::new(), server: server.into(), token, db, pg_container, last: None, windows: vec![] }
    }

    /// Takes a sample; returns the window since the previous one.
    pub async fn sample(&mut self, elapsed: Duration, stats: &crate::stats::Stats) -> Result<Option<Value>> {
        let Some(token) = &self.token else { return Ok(None) };
        let now = Instant::now();
        let s = scrape(&self.http, &self.server, token).await.context("scraping /metrics")?;
        let cpu = own_cpu_secs().unwrap_or(0.0);
        let mut out = None;
        if let Some((t, prev, prev_cpu)) = &self.last {
            let secs = now.duration_since(*t).as_secs_f64();
            let mut w = window(prev, &s, secs);
            w["t_s"] = json!(elapsed.as_secs());
            w["generator_cpu_cores"] = json!((cpu - prev_cpu) / secs);
            w["generator_online"] = json!(crate::stats::Stats::get(&stats.online));
            if let Some(c) = &self.pg_container {
                w["postgres"] = container(c).await.unwrap_or(Value::Null);
            }
            if let Some(db) = &self.db {
                let size: Option<i64> = sqlx::query_scalar("SELECT pg_database_size(current_database())").fetch_one(db).await.ok();
                w["database_bytes"] = json!(size);
            }
            self.windows.push(w.clone());
            out = Some(w);
        }
        self.last = Some((now, s, cpu));
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_from_scrapes() {
        let a = parse("process_cpu_seconds_total 10\nrmm_alert_eval_duration_seconds_bucket{le=\"0.01\"} 1\nrmm_alert_eval_duration_seconds_bucket{le=\"0.1\"} 2\nrmm_alert_eval_duration_seconds_bucket{le=\"+Inf\"} 2\nrmm_alert_eval_duration_seconds_sum 0.05\nrmm_alert_eval_duration_seconds_count 2\n");
        let b = parse("process_cpu_seconds_total 30\nrmm_alert_eval_duration_seconds_bucket{le=\"0.01\"} 1\nrmm_alert_eval_duration_seconds_bucket{le=\"0.1\"} 4\nrmm_alert_eval_duration_seconds_bucket{le=\"+Inf\"} 4\nrmm_alert_eval_duration_seconds_sum 0.15\nrmm_alert_eval_duration_seconds_count 4\n");
        let w = window(&a, &b, 10.0);
        assert_eq!(w["server_cpu_cores"], 2.0);
        assert_eq!(w["alert_eval"]["count"], 2.0);
        assert!((w["alert_eval"]["mean_ms"].as_f64().unwrap() - 50.0).abs() < 1e-6);
        assert_eq!(w["alert_eval"]["p99_le_ms"], 100.0);
    }
}
