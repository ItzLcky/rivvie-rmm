//! `rmm-loadgen`: simulated agents, dashboards and technicians against a real server.
//!
//! It enrolls `--agents` agents across `--clients` × `--sites` (credentials are saved to
//! `--state`, so later runs skip enrollment), connects them at `--ramp` per second, holds them
//! for `--duration`, and meanwhile keeps `--sse` dashboards open, makes `--api-rps` page
//! requests a second and starts a bulk script run on `--bulk-size` agents every
//! `--bulk-every` seconds. With `--metrics-token` it samples the server's `/metrics` every
//! `--sample-secs`, and with `--database-url` Postgres too. The summary (JSON) goes to
//! `--out` and stdout. See docs/research/load-test-2026-11.md for how it was used.
//!
//! ```sh
//! cargo run --release -p rmm-loadgen -- --server http://127.0.0.1:8080 \
//!     --admin-email admin@example.com --admin-password ... --agents 1000 --duration 600 \
//!     --metrics-token ... --database-url postgres://... --out run.json
//! ```

mod sample;
mod sim;
mod stats;
mod web;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use clap::Parser;
use serde_json::json;
use tokio::sync::watch;

use crate::sim::{Cred, Shape};
use crate::stats::Stats;

#[derive(Parser)]
#[command(name = "rmm-loadgen", about = "Load generator for the RMM server")]
struct Args {
    #[arg(long, default_value = "http://127.0.0.1:8080")]
    server: String,
    #[arg(long, env = "RMM_LOADGEN_ADMIN_EMAIL")]
    admin_email: String,
    #[arg(long, env = "RMM_LOADGEN_ADMIN_PASSWORD", hide_env_values = true)]
    admin_password: String,
    /// Simulated agents.
    #[arg(long, default_value_t = 100)]
    agents: usize,
    /// Agent connections started per second.
    #[arg(long, default_value_t = 200.0)]
    ramp: f64,
    /// Seconds to hold every agent connected after the ramp.
    #[arg(long, default_value_t = 60)]
    duration: u64,
    #[arg(long, default_value_t = 20)]
    clients: usize,
    #[arg(long, default_value_t = 2)]
    sites: usize,
    /// Divides every agent-side interval (heartbeats, inventory...): 60 writes an hour of
    /// agent data a minute. The server's own timers are not compressed.
    #[arg(long, default_value_t = 1.0)]
    time_compression: f64,
    /// Share of agents reporting as Windows (the rest Linux).
    #[arg(long, default_value_t = 0.7)]
    windows_share: f64,
    /// Installed software entries per inventory.
    #[arg(long, default_value_t = 300)]
    software: usize,
    /// Services per service list.
    #[arg(long, default_value_t = 250)]
    services: usize,
    /// How often an agent's service list changes (the real agent sends it only on change).
    #[arg(long, default_value_t = 3600)]
    services_change_secs: u64,
    /// Available updates per patch scan result.
    #[arg(long, default_value_t = 12)]
    patch_updates: usize,
    /// Open dashboards (SSE streams).
    #[arg(long, default_value_t = 10)]
    sse: usize,
    /// Page requests per second (agents list, one agent, metrics, alerts, search, dashboard).
    #[arg(long, default_value_t = 5.0)]
    api_rps: f64,
    /// Seconds between bulk script runs (0: none).
    #[arg(long, default_value_t = 120)]
    bulk_every: u64,
    #[arg(long, default_value_t = 500)]
    bulk_size: usize,
    /// RMM_METRICS_TOKEN of the server, to sample `/metrics`.
    #[arg(long, env = "RMM_METRICS_TOKEN", hide_env_values = true)]
    metrics_token: Option<String>,
    /// The server's database, to sample its size and largest tables.
    #[arg(long)]
    database_url: Option<String>,
    /// Docker container running Postgres, for its CPU and memory.
    #[arg(long)]
    pg_container: Option<String>,
    #[arg(long, default_value_t = 15)]
    sample_secs: u64,
    /// Saved agent credentials and the admin's TOTP secret (created on the first run).
    #[arg(long, default_value = "loadgen-state.json")]
    state: PathBuf,
    /// Summary JSON.
    #[arg(long)]
    out: Option<PathBuf>,
    /// Exit non-zero unless every agent connected, none dropped, and no API call failed (CI).
    #[arg(long)]
    check: bool,
}

#[derive(serde::Serialize, serde::Deserialize, Default)]
struct State {
    totp_secret: Option<String>,
    agents: Vec<Cred>,
}

fn ws_url(server: &str) -> String {
    let base = server.trim_end_matches('/');
    let base = base.replacen("https://", "wss://", 1).replacen("http://", "ws://", 1);
    format!("{base}/api/agent/ws")
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let stats = Arc::new(Stats::default());
    let mut state: State = match std::fs::read(&args.state) {
        Ok(b) => serde_json::from_slice(&b).context("reading --state")?,
        Err(_) => State::default(),
    };
    let save = |s: &State| std::fs::write(&args.state, serde_json::to_vec(s).expect("serialisable")).context("writing --state");

    let api = Arc::new(web::Api::new(&args.server)?);
    if let Some(secret) = api.login(&args.admin_email, &args.admin_password, state.totp_secret.as_deref()).await? {
        state.totp_secret = Some(secret);
        save(&state)?;
    }
    let url = ws_url(&args.server);
    api.ensure_policies().await?;

    // --- enrollment (only what --state doesn't already have) ----------------------------------
    if state.agents.len() < args.agents {
        let t = Instant::now();
        let batch = chrono::Utc::now().format("%Y%m%d-%H%M%S").to_string();
        let tokens = api.make_sites(args.clients.max(1), args.sites.max(1), &batch).await?;
        let missing = args.agents - state.agents.len();
        println!("enrolling {missing} agents across {} sites", tokens.len());
        let sem = Arc::new(tokio::sync::Semaphore::new(64));
        let mut tasks = vec![];
        for i in state.agents.len()..args.agents {
            let (sem, url, token, stats) = (sem.clone(), url.clone(), tokens[i % tokens.len()].clone(), stats.clone());
            let windows = (i as f64 / args.agents.max(1) as f64) < args.windows_share;
            let host = format!("lg-{:03}-{i:05}", i % tokens.len());
            tasks.push(tokio::spawn(async move {
                let _p = sem.acquire().await;
                let t = Instant::now();
                let r = sim::enroll(&url, &token, &host, windows).await;
                stats.sample("enroll", t.elapsed());
                r
            }));
        }
        for t in tasks {
            match t.await? {
                Ok(c) => {
                    Stats::inc(&stats.enrolled);
                    state.agents.push(c);
                }
                Err(e) => {
                    Stats::inc(&stats.enroll_failed);
                    stats.error(format!("enroll: {e:#}"));
                }
            }
        }
        save(&state)?;
        println!("enrolled {} in {:.1}s", Stats::get(&stats.enrolled), t.elapsed().as_secs_f64());
    }
    let creds: Vec<Cred> = state.agents.iter().take(args.agents).cloned().collect();
    if creds.len() < args.agents {
        bail!("only {} of {} agents could be enrolled: {:?}", creds.len(), args.agents, stats.errors());
    }

    let shape = Arc::new(Shape {
        ws_url: url,
        compression: args.time_compression.max(0.01),
        software: args.software,
        services: args.services,
        services_change_secs: args.services_change_secs,
        patch_updates: args.patch_updates,
    });
    let db = match &args.database_url {
        Some(u) => Some(sqlx::postgres::PgPoolOptions::new().max_connections(2).connect(u).await.context("--database-url")?),
        None => None,
    };
    let mut sampler = sample::Sampler::new(&args.server, args.metrics_token.clone(), db.clone(), args.pg_container.clone());
    let pg_before = match &db {
        Some(db) => Some(sample::postgres(db).await?),
        None => None,
    };
    let (stop_tx, stop) = watch::channel(false);
    let dispatched: sim::Dispatched = Default::default();
    let started = Instant::now();
    let _ = sampler.sample(Duration::ZERO, &stats).await;

    // --- dashboards and technicians -------------------------------------------------------
    let mut bg = vec![];
    for _ in 0..args.sse {
        bg.push(tokio::spawn(web::sse(api.clone(), stats.clone(), stop.clone())));
    }

    // --- ramp -------------------------------------------------------------------------------
    let ramp_gap = Duration::from_secs_f64(1.0 / args.ramp.max(0.1));
    let mut agents = vec![];
    let ramp_start = Instant::now();
    let mut next_sample = Instant::now() + Duration::from_secs(args.sample_secs);
    for (i, c) in creds.iter().enumerate() {
        agents.push(tokio::spawn(sim::run(c.clone(), shape.clone(), stats.clone(), dispatched.clone(), stop.clone())));
        let due = ramp_start + ramp_gap * (i as u32 + 1);
        if let Some(wait) = due.checked_duration_since(Instant::now()) {
            tokio::time::sleep(wait).await;
        }
        if Instant::now() >= next_sample {
            next_sample += Duration::from_secs(args.sample_secs);
            progress(&mut sampler, started, &stats).await;
        }
    }
    // Every agent has had its first try; wait (up to a minute) for them to be online.
    let deadline = Instant::now() + Duration::from_secs(60);
    while (Stats::get(&stats.online) as usize) < creds.len() && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    let ramp_secs = ramp_start.elapsed().as_secs_f64();
    let online_after_ramp = Stats::get(&stats.online);
    println!("ramp done in {ramp_secs:.1}s: {online_after_ramp}/{} online", creds.len());

    let ids: Arc<Vec<(uuid::Uuid, String)>> = Arc::new(creds.iter().map(|c| (c.agent_id, c.hostname.clone())).collect());
    bg.push(tokio::spawn(web::browse(api.clone(), stats.clone(), ids.clone(), args.api_rps, stop.clone())));
    bg.push(tokio::spawn(web::bulk(api.clone(), stats.clone(), ids, dispatched, Duration::from_secs(args.bulk_every), args.bulk_size, stop.clone())));

    // --- hold -------------------------------------------------------------------------------
    let hold_start = Instant::now();
    let dropped_at_hold = Stats::get(&stats.dropped);
    let mut min_online = Stats::get(&stats.online);
    while hold_start.elapsed() < Duration::from_secs(args.duration) {
        tokio::time::sleep(Duration::from_secs(1)).await;
        min_online = min_online.min(Stats::get(&stats.online));
        if Instant::now() >= next_sample {
            next_sample += Duration::from_secs(args.sample_secs);
            progress(&mut sampler, started, &stats).await;
        }
    }
    let _ = sampler.sample(started.elapsed(), &stats).await;
    let dropped_in_hold = Stats::get(&stats.dropped) - dropped_at_hold;
    let _ = stop_tx.send(true);
    for t in agents.into_iter().chain(bg) {
        let _ = tokio::time::timeout(Duration::from_secs(10), t).await;
    }
    let pg_after = match &db {
        Some(db) => Some(sample::postgres(db).await?),
        None => None,
    };

    let summary = json!({
        "args": {
            "agents": args.agents, "ramp_per_sec": args.ramp, "duration_s": args.duration, "clients": args.clients, "sites_per_client": args.sites,
            "time_compression": args.time_compression, "windows_share": args.windows_share, "sse": args.sse, "api_rps": args.api_rps,
            "bulk_every_s": args.bulk_every, "bulk_size": args.bulk_size, "software": args.software, "services": args.services,
            "services_change_s": args.services_change_secs, "patch_updates": args.patch_updates,
        },
        "message_bytes": sim::message_sizes(&shape),
        "ramp_s": ramp_secs,
        "online_after_ramp": online_after_ramp,
        "min_online_during_hold": min_online,
        "dropped_during_hold": dropped_in_hold,
        "hold_s": hold_start.elapsed().as_secs_f64(),
        "counters": stats.counters(),
        "latency_ms": stats.latencies(),
        "server": sampler.windows,
        "postgres_before": pg_before,
        "postgres_after": pg_after,
        "errors": stats.errors(),
    });
    let text = serde_json::to_string_pretty(&summary)?;
    if let Some(p) = &args.out {
        std::fs::write(p, &text)?;
    }
    println!("{text}");

    if args.check {
        let c = &summary["counters"];
        let problems: Vec<String> = [
            (online_after_ramp < creds.len() as u64).then(|| format!("{online_after_ramp}/{} agents online after the ramp", creds.len())),
            (dropped_in_hold > 0).then(|| format!("{dropped_in_hold} sessions dropped")),
            (c["api_errors"].as_u64() != Some(0)).then(|| format!("{} API errors", c["api_errors"])),
            (c["sse_dropped"].as_u64() != Some(0)).then(|| format!("{} SSE streams dropped", c["sse_dropped"])),
            (args.bulk_every > 0 && args.bulk_every < args.duration && c["jobs_acked"].as_u64().unwrap_or(0) == 0).then(|| "no bulk job finished".to_string()),
        ]
        .into_iter()
        .flatten()
        .collect();
        if !problems.is_empty() {
            bail!("check failed: {}", problems.join("; "));
        }
        println!("check: ok");
    }
    Ok(())
}

async fn progress(sampler: &mut sample::Sampler, started: Instant, stats: &Stats) {
    match sampler.sample(started.elapsed(), stats).await {
        Ok(Some(w)) => println!(
            "t={:>5}s online={:>6} server: cpu={:.2} cores rss={:.0} MB msgs/s={:.0} pool={}/{} idle alert_eval={}",
            started.elapsed().as_secs(),
            Stats::get(&stats.online),
            w["server_cpu_cores"].as_f64().unwrap_or(0.0),
            w["server_rss_mb"].as_f64().unwrap_or(0.0),
            w["agent_messages_per_sec"].as_f64().unwrap_or(0.0),
            w["db_pool_connections"],
            w["db_pool_idle"],
            w["alert_eval"],
        ),
        Ok(None) => println!("t={:>5}s online={:>6}", started.elapsed().as_secs(), Stats::get(&stats.online)),
        Err(e) => println!("t={:>5}s sampling failed: {e:#}", started.elapsed().as_secs()),
    }
}
