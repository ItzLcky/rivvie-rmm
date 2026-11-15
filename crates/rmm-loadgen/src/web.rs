//! The dashboard side: signing in, creating clients, sites and enrollment tokens, and during
//! the run the open dashboards (SSE), technicians reading pages, and bulk script runs.

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use futures_util::StreamExt;
use hmac::{Hmac, KeyInit, Mac};
use serde_json::{Value, json};
use sha1::Sha1;
use tokio::sync::watch;
use uuid::Uuid;

use crate::sim::Dispatched;
use crate::stats::Stats;

pub struct Api {
    pub http: reqwest::Client,
    pub base: String,
}

fn totp(secret_b32: &str) -> Result<String> {
    let secret = data_encoding::BASE32_NOPAD.decode(secret_b32.as_bytes()).context("TOTP secret")?;
    let step = (std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs() / 30).to_be_bytes();
    let mut mac = Hmac::<Sha1>::new_from_slice(&secret).expect("any key length");
    mac.update(&step);
    let h = mac.finalize().into_bytes();
    let off = (h[h.len() - 1] & 0x0f) as usize;
    let bin = u32::from_be_bytes([h[off] & 0x7f, h[off + 1], h[off + 2], h[off + 3]]);
    Ok(format!("{:06}", bin % 1_000_000))
}

impl Api {
    pub fn new(server: &str) -> Result<Self> {
        let http = reqwest::Client::builder().cookie_store(true).pool_max_idle_per_host(64).timeout(Duration::from_secs(120)).build()?;
        Ok(Api { http, base: format!("{}/api", server.trim_end_matches('/')) })
    }

    pub async fn call(&self, method: reqwest::Method, path: &str, body: Option<Value>) -> Result<(u16, Value)> {
        let mut req = self.http.request(method, format!("{}{path}", self.base));
        if let Some(b) = body {
            req = req.json(&b);
        }
        let res = req.send().await?;
        let s = res.status().as_u16();
        Ok((s, res.json().await.unwrap_or(Value::Null)))
    }

    pub async fn post(&self, path: &str, body: Value) -> Result<Value> {
        let (s, v) = self.call(reqwest::Method::POST, path, Some(body)).await?;
        if !(200..300).contains(&s) {
            bail!("POST {path}: {s} {v}");
        }
        Ok(v)
    }

    /// Signs in as the admin. Admins must use two-factor auth: the first run turns it on and
    /// returns the new secret, which later runs pass back in.
    pub async fn login(&self, email: &str, password: &str, totp_secret: Option<&str>) -> Result<Option<String>> {
        let code = totp_secret.map(totp).transpose()?;
        let (s, v) = self.call(reqwest::Method::POST, "/auth/login", Some(json!({ "email": email, "password": password, "code": code }))).await?;
        if !(200..300).contains(&s) {
            bail!("signing in: {s} {v}");
        }
        if totp_secret.is_some() {
            return Ok(None);
        }
        let setup = self.post("/auth/totp/setup", json!({ "password": password })).await?;
        let secret = setup["secret"].as_str().context("TOTP setup without a secret")?.to_string();
        self.post("/auth/totp/enable", json!({ "code": totp(&secret)? })).await?;
        Ok(Some(secret))
    }

    /// MSP-wide offline, CPU, memory and disk policies (once), so every alert evaluation has
    /// the whole fleet to check.
    pub async fn ensure_policies(&self) -> Result<()> {
        let (_, have) = self.call(reqwest::Method::GET, "/alert-policies", None).await?;
        if have.as_array().into_iter().flatten().any(|p| p["name"].as_str().is_some_and(|n| n.starts_with("Loadgen"))) {
            return Ok(());
        }
        for (name, kind, params) in [
            ("Loadgen offline", "offline", json!({ "minutes": 10 })),
            ("Loadgen CPU", "cpu", json!({ "threshold": 90, "minutes": 5 })),
            ("Loadgen memory", "memory", json!({ "threshold": 95, "minutes": 10 })),
            ("Loadgen disk", "disk", json!({ "threshold": 90, "minutes": 5 })),
        ] {
            self.post("/alert-policies", json!({ "name": name, "kind": kind, "params": params, "severity": "warning" })).await?;
        }
        Ok(())
    }

    /// `clients` clients with `sites` sites each; returns an unlimited enrollment token per site.
    /// `batch` keeps the names of a later enrollment's clients apart from earlier ones.
    pub async fn make_sites(&self, clients: usize, sites: usize, batch: &str) -> Result<Vec<String>> {
        let mut tokens = vec![];
        for c in 0..clients {
            let client = self.post("/clients", json!({ "name": format!("Loadgen {batch} client {c:03}") })).await?;
            let id = client["id"].as_str().context("client id")?.to_string();
            let mut site_ids = vec![client["default_site_id"].as_str().context("default site")?.to_string()];
            for s in 1..sites {
                let site = self.post(&format!("/clients/{id}/sites"), json!({ "name": format!("Site {s}") })).await?;
                site_ids.push(site["id"].as_str().context("site id")?.to_string());
            }
            for s in site_ids {
                let t = self.post(&format!("/sites/{s}/enrollment-tokens"), json!({ "label": "loadgen", "expires_in_hours": 0 })).await?;
                tokens.push(t["token"].as_str().context("token")?.to_string());
            }
        }
        Ok(tokens)
    }
}

/// One open dashboard: holds `/api/events` open and counts what arrives; reopens it if the
/// server ends it.
pub async fn sse(api: Arc<Api>, stats: Arc<Stats>, mut stop: watch::Receiver<bool>) {
    loop {
        let res = tokio::select! {
            r = api.http.get(format!("{}/events", api.base)).timeout(Duration::from_secs(86_400 * 7)).send() => r,
            _ = stop.changed() => return,
        };
        let mut body = match res {
            Ok(r) if r.status().is_success() => r.bytes_stream(),
            Ok(r) => {
                stats.error(format!("SSE: HTTP {}", r.status()));
                Stats::inc(&stats.sse_dropped);
                tokio::time::sleep(Duration::from_secs(5)).await;
                continue;
            }
            Err(e) => {
                stats.error(format!("SSE: {e}"));
                Stats::inc(&stats.sse_dropped);
                tokio::time::sleep(Duration::from_secs(5)).await;
                continue;
            }
        };
        loop {
            let chunk = tokio::select! {
                c = body.next() => c,
                _ = stop.changed() => return,
            };
            match chunk {
                Some(Ok(b)) => {
                    let text = String::from_utf8_lossy(&b);
                    Stats::add(&stats.sse_events, text.matches("data:").count() as u64);
                    Stats::add(&stats.sse_resyncs, text.matches("\"resync\"").count() as u64);
                }
                _ => {
                    Stats::inc(&stats.sse_dropped);
                    break;
                }
            }
        }
    }
}

/// Technicians browsing: `rps` requests a second spread over the pages a technician opens
/// most (agents list, one agent, its metrics, alerts, search, the dashboard).
pub async fn browse(api: Arc<Api>, stats: Arc<Stats>, agents: Arc<Vec<(Uuid, String)>>, rps: f64, mut stop: watch::Receiver<bool>) {
    if rps <= 0.0 || agents.is_empty() {
        return;
    }
    let mut tick = tokio::time::interval(Duration::from_secs_f64(1.0 / rps));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut n = 0usize;
    loop {
        tokio::select! {
            _ = tick.tick() => {}
            _ = stop.changed() => return,
        }
        n += 1;
        let (id, host) = &agents[(Uuid::new_v4().as_u128() % agents.len() as u128) as usize];
        let (name, path): (&'static str, String) = match n % 6 {
            0 => ("api_agents_list", "/agents?limit=50".into()),
            1 => ("api_agent", format!("/agents/{id}")),
            2 => ("api_agent_metrics", format!("/agents/{id}/metrics?hours=24")),
            3 => ("api_alerts", "/alerts?limit=50".into()),
            4 => ("api_search", format!("/search?q={}", &host[..host.len().min(9)])),
            _ => ("api_dashboard", "/dashboard".into()),
        };
        let (api, stats) = (api.clone(), stats.clone());
        tokio::spawn(async move {
            let t = Instant::now();
            match api.call(reqwest::Method::GET, &path, None).await {
                Ok((s, _)) if (200..300).contains(&s) => stats.sample(name, t.elapsed()),
                Ok((s, v)) => {
                    Stats::inc(&stats.api_errors);
                    stats.error(format!("GET {path}: {s} {v}"));
                }
                Err(e) => {
                    Stats::inc(&stats.api_errors);
                    stats.error(format!("GET {path}: {e}"));
                }
            }
        });
    }
}

/// A bulk script run every `every`, on `size` agents picked at random.
pub async fn bulk(api: Arc<Api>, stats: Arc<Stats>, agents: Arc<Vec<(Uuid, String)>>, dispatched: Dispatched, every: Duration, size: usize, mut stop: watch::Receiver<bool>) {
    if every.is_zero() || size == 0 || agents.is_empty() {
        return;
    }
    let mut tick = tokio::time::interval_at(tokio::time::Instant::now() + every, every);
    loop {
        tokio::select! {
            _ = tick.tick() => {}
            _ = stop.changed() => return,
        }
        let start = (Uuid::new_v4().as_u128() % agents.len() as u128) as usize;
        let ids: Vec<Uuid> = (0..size.min(agents.len())).map(|i| agents[(start + i) % agents.len()].0).collect();
        let t = Instant::now();
        match api.call(reqwest::Method::POST, "/jobs", Some(json!({ "agent_ids": ids, "interpreter": "bash", "body": "echo loadgen", "timeout_secs": 60 }))).await {
            Ok((s, v)) if (200..300).contains(&s) => {
                stats.sample("api_bulk_jobs_create", t.elapsed());
                Stats::inc(&stats.bulk_runs);
                // The jobs went to connected agents before the response; time from the request.
                let mut d = dispatched.lock().unwrap();
                for j in v["jobs"].as_array().into_iter().flatten() {
                    if let Some(id) = j["job_id"].as_str().and_then(|s| s.parse().ok()) {
                        if let Some(took) = d.asked(id, t) {
                            stats.sample("job_dispatch", took);
                        }
                        Stats::inc(&stats.bulk_jobs);
                    }
                }
            }
            Ok((s, v)) => {
                Stats::inc(&stats.api_errors);
                stats.error(format!("POST /jobs: {s} {v}"));
            }
            Err(e) => {
                Stats::inc(&stats.api_errors);
                stats.error(format!("POST /jobs: {e}"));
            }
        }
    }
}
