mod agent_ws;
mod api;
mod auth;
mod error;
mod hub;
mod shell_ws;
mod state;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use axum::Router;
use axum::routing::get;
use clap::{Parser, Subcommand};
use sqlx::postgres::PgPoolOptions;
use tower_http::services::{ServeDir, ServeFile};
use tower_http::trace::TraceLayer;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

use crate::state::{AppState, Settings};

#[derive(Parser)]
#[command(name = "rmm-server", version, about = "RMM control server")]
struct Cli {
    #[arg(long, env = "DATABASE_URL")]
    database_url: String,
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the server (default).
    Serve(ServeArgs),
    /// Apply database migrations and exit.
    Migrate,
    /// Create a dashboard user (use this to bootstrap the first admin).
    CreateUser {
        #[arg(long)]
        email: String,
        #[arg(long)]
        name: String,
        /// Read from RMM_PASSWORD if omitted, so it stays out of shell history.
        #[arg(long, env = "RMM_PASSWORD", hide_env_values = true)]
        password: String,
        #[arg(long, default_value = "admin")]
        role: String,
    },
}

#[derive(clap::Args)]
struct ServeArgs {
    #[arg(long, env = "RMM_BIND", default_value = "0.0.0.0:8080")]
    bind: SocketAddr,
    /// External URL (behind your TLS reverse proxy), used for enrollment commands and cookie flags.
    #[arg(long, env = "RMM_PUBLIC_URL", default_value = "http://localhost:8080")]
    public_url: String,
    /// Built dashboard (web/build). Served at / with SPA fallback.
    #[arg(long, env = "RMM_WEB_DIR", default_value = "web/build")]
    web_dir: PathBuf,
    #[arg(long, env = "RMM_HEARTBEAT_SECS", default_value_t = 30)]
    heartbeat_secs: u32,
    #[arg(long, env = "RMM_INVENTORY_SECS", default_value_t = 6 * 3600)]
    inventory_secs: u32,
    #[arg(long, env = "RMM_METRICS_RETENTION_DAYS", default_value_t = 30)]
    metrics_retention_days: u32,
}

impl Default for ServeArgs {
    fn default() -> Self {
        // Mirrors clap defaults/env so `rmm-server` with no subcommand behaves like `serve`.
        let env = |k: &str, d: &str| std::env::var(k).unwrap_or_else(|_| d.to_string());
        Self {
            bind: env("RMM_BIND", "0.0.0.0:8080").parse().expect("RMM_BIND"),
            public_url: env("RMM_PUBLIC_URL", "http://localhost:8080"),
            web_dir: env("RMM_WEB_DIR", "web/build").into(),
            heartbeat_secs: env("RMM_HEARTBEAT_SECS", "30").parse().unwrap_or(30),
            inventory_secs: env("RMM_INVENTORY_SECS", "21600").parse().unwrap_or(21600),
            metrics_retention_days: env("RMM_METRICS_RETENTION_DAYS", "30").parse().unwrap_or(30),
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info,tower_http=warn,sqlx=warn".into()))
        .init();
    let cli = Cli::parse();

    let db = PgPoolOptions::new()
        .max_connections(32)
        .acquire_timeout(Duration::from_secs(10))
        .connect(&cli.database_url)
        .await
        .context("connecting to Postgres")?;
    sqlx::migrate!("./migrations").run(&db).await.context("running migrations")?;

    match cli.cmd.unwrap_or(Cmd::Serve(ServeArgs::default())) {
        Cmd::Migrate => {
            info!("migrations applied");
            Ok(())
        }
        Cmd::CreateUser { email, name, password, role } => {
            let role = auth::Role::parse(&role).context("role must be admin, technician or readonly")?;
            let id = api::create_user_cli(&db, &email, &name, &password, role).await?;
            println!("created user {email} ({id})");
            Ok(())
        }
        Cmd::Serve(args) => serve(db, args).await,
    }
}

async fn serve(db: sqlx::PgPool, args: ServeArgs) -> Result<()> {
    // Nothing is connected yet, whatever the DB says from the last run.
    sqlx::query("UPDATE agents SET online = false WHERE online").execute(&db).await?;
    bootstrap_admin(&db).await?;

    let state = Arc::new(AppState {
        db,
        hub: Default::default(),
        cfg: Settings {
            public_url: args.public_url.trim_end_matches('/').to_string(),
            heartbeat_secs: args.heartbeat_secs,
            inventory_secs: args.inventory_secs,
            metrics_retention_days: args.metrics_retention_days,
        },
    });
    tokio::spawn(housekeeping(state.clone()));

    // adapter-static writes the SPA shell as 200.html; every non-file route falls back to it.
    let index = args.web_dir.join("200.html");
    if !index.exists() {
        warn!("dashboard not found at {} (build it with `npm --prefix web run build`)", args.web_dir.display());
    }
    let app = Router::new()
        .route("/api/agent/ws", get(agent_ws::handler))
        .route("/healthz", get(|| async { "ok" }))
        .nest("/api", api::router())
        .fallback_service(ServeDir::new(&args.web_dir).fallback(ServeFile::new(index)))
        .layer(tower_http::limit::RequestBodyLimitLayer::new(8 * 1024 * 1024))
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(args.bind).await.with_context(|| format!("binding {}", args.bind))?;
    info!("listening on {} (public url {})", args.bind, args.public_url);
    axum::serve(listener, app).with_graceful_shutdown(shutdown_signal()).await?;
    Ok(())
}

/// Container-friendly first run: if RMM_ADMIN_EMAIL and RMM_ADMIN_PASSWORD are set and
/// no users exist yet, create that admin. Ignored once any user exists, so the
/// variables can be left in place (but should be removed after first login).
async fn bootstrap_admin(db: &sqlx::PgPool) -> Result<()> {
    let (Ok(email), Ok(password)) = (std::env::var("RMM_ADMIN_EMAIL"), std::env::var("RMM_ADMIN_PASSWORD")) else {
        return Ok(());
    };
    let users: i64 = sqlx::query_scalar("SELECT count(*) FROM users").fetch_one(db).await?;
    if users > 0 {
        warn!("RMM_ADMIN_EMAIL/RMM_ADMIN_PASSWORD are set but users already exist; ignoring (you can remove them)");
        return Ok(());
    }
    api::create_user_cli(db, &email, "Administrator", &password, auth::Role::Admin)
        .await
        .map_err(|e| anyhow::anyhow!("creating bootstrap admin {email}: {e}"))?;
    info!("created initial admin user {email}");
    Ok(())
}

/// Periodic cleanup: expired sessions, old metrics.
async fn housekeeping(state: Arc<AppState>) {
    let mut tick = tokio::time::interval(Duration::from_secs(3600));
    loop {
        tick.tick().await;
        let r1 = sqlx::query("DELETE FROM user_sessions WHERE expires_at < now()").execute(&state.db).await;
        let r2 = sqlx::query("DELETE FROM agent_metrics WHERE ts < now() - make_interval(days => $1)")
            .bind(state.cfg.metrics_retention_days as i32)
            .execute(&state.db)
            .await;
        if let (Err(e), _) | (_, Err(e)) = (&r1, &r2) {
            warn!("housekeeping: {e}");
        }
        info!(online = state.hub.online_count(), "housekeeping done");
    }
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let term = async {
        if let Ok(mut s) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            s.recv().await;
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! { _ = ctrl_c => {}, _ = term => {} }
    info!("shutting down");
}
