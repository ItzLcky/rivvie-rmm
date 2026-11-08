mod agent_ws;
mod api;
mod auth;
mod error;
mod hub;
mod shell_ws;
mod state;
mod totp;

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
use tracing::{error, info, warn};
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
    /// Remove a user's two-factor auth and sign them out (e.g. the only admin lost their phone).
    Reset2fa {
        #[arg(long)]
        email: String,
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
    /// Prebuilt agent binaries (rmm-agent-linux-x86_64, rmm-agent-windows-x86_64.exe)
    /// offered by the "Enroll agents" dialog.
    #[arg(long, env = "RMM_AGENT_DIR", default_value = "agents")]
    agent_dir: PathBuf,
    #[arg(long, env = "RMM_HEARTBEAT_SECS", default_value_t = 30)]
    heartbeat_secs: u32,
    #[arg(long, env = "RMM_INVENTORY_SECS", default_value_t = 6 * 3600)]
    inventory_secs: u32,
    #[arg(long, env = "RMM_METRICS_RETENTION_DAYS", default_value_t = 30)]
    metrics_retention_days: u32,
    /// Jobs queued for an offline agent expire after this many days instead of running late.
    #[arg(long, env = "RMM_JOB_QUEUE_DAYS", default_value_t = 7)]
    job_queue_days: u32,
    /// Dashboard sessions unused for this many hours are signed out (absolute limit: 7 days).
    /// Admins can override it under Company settings.
    #[arg(long, env = "RMM_SESSION_IDLE_HOURS", default_value_t = 12)]
    session_idle_hours: u32,
}

impl Default for ServeArgs {
    fn default() -> Self {
        // Mirrors clap defaults/env so `rmm-server` with no subcommand behaves like `serve`.
        let env = |k: &str, d: &str| std::env::var(k).unwrap_or_else(|_| d.to_string());
        Self {
            bind: env("RMM_BIND", "0.0.0.0:8080").parse().expect("RMM_BIND"),
            public_url: env("RMM_PUBLIC_URL", "http://localhost:8080"),
            web_dir: env("RMM_WEB_DIR", "web/build").into(),
            agent_dir: env("RMM_AGENT_DIR", "agents").into(),
            heartbeat_secs: env("RMM_HEARTBEAT_SECS", "30").parse().unwrap_or(30),
            inventory_secs: env("RMM_INVENTORY_SECS", "21600").parse().unwrap_or(21600),
            metrics_retention_days: env("RMM_METRICS_RETENTION_DAYS", "30").parse().unwrap_or(30),
            job_queue_days: env("RMM_JOB_QUEUE_DAYS", "7").parse().unwrap_or(7),
            session_idle_hours: env("RMM_SESSION_IDLE_HOURS", "12").parse().unwrap_or(12),
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
        Cmd::Reset2fa { email } => {
            let id: uuid::Uuid = sqlx::query_scalar("SELECT id FROM users WHERE lower(email) = lower($1)")
                .bind(email.trim())
                .fetch_optional(&db)
                .await?
                .with_context(|| format!("no user with email {email}"))?;
            let mut tx = db.begin().await?;
            api::clear_totp(&mut tx, id).await.map_err(|e| anyhow::anyhow!("{e}"))?;
            sqlx::query("DELETE FROM user_sessions WHERE user_id = $1").bind(id).execute(&mut *tx).await?;
            tx.commit().await?;
            auth::audit(&db, None, "user.mfa_reset", Some(("user", id)), serde_json::json!({ "via": "cli" })).await;
            println!("two-factor auth removed for {email}; they will be asked to set it up again if required");
            Ok(())
        }
        Cmd::Serve(args) => serve(db, args).await,
    }
}

async fn serve(db: sqlx::PgPool, args: ServeArgs) -> Result<()> {
    // Nothing is connected yet, whatever the DB says from the last run.
    sqlx::query("UPDATE agents SET online = false WHERE online").execute(&db).await?;
    // Their connections died with the previous process, so they can never report.
    sqlx::query(
        "UPDATE jobs SET status = 'lost', finished_at = now(),
                stderr = stderr || E'\\n[rmm] the server restarted before the agent reported a result\\n'
          WHERE status = 'sent'",
    )
    .execute(&db)
    .await?;
    bootstrap_admin(&db).await?;
    let company = state::Company::load(&db).await.context("loading company settings")?;

    let state = Arc::new(AppState {
        company: company.into(),
        db,
        hub: Default::default(),
        cfg: Settings {
            agent_dir: args.agent_dir.clone(),
            public_url: args.public_url.trim_end_matches('/').to_string(),
            heartbeat_secs: args.heartbeat_secs,
            inventory_secs: args.inventory_secs,
            metrics_retention_days: args.metrics_retention_days,
            job_queue_days: args.job_queue_days,
            session_idle_hours: args.session_idle_hours.max(1),
        },
    });
    tokio::spawn(housekeeping(state.clone()));

    // adapter-static writes the SPA shell as 200.html; every non-file route falls back to it.
    let found: Vec<_> = api::agent_platforms().filter(|id| api::agent_binary_exists(&state, id)).collect();
    if found.is_empty() {
        warn!("no agent binaries in {}; the dashboard won't offer downloads", args.agent_dir.display());
    } else {
        info!("agent downloads: {}", found.join(", "));
    }
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
        .layer(TraceLayer::new_for_http());
    let https = state.cfg.secure_cookies();
    let app = security_headers(app.with_state(state), https);

    let listener = tokio::net::TcpListener::bind(args.bind).await.with_context(|| format!("binding {}", args.bind))?;
    info!("listening on {} (public url {})", args.bind, args.public_url);
    axum::serve(listener, app).with_graceful_shutdown(shutdown_signal()).await?;
    Ok(())
}

/// Baseline browser hardening for the dashboard. The CSP only restricts framing, plugins and
/// `<base>`; a script-src policy needs SvelteKit's hash-based CSP, which is a separate change.
fn security_headers(router: Router, https: bool) -> Router {
    use axum::http::{HeaderName, HeaderValue, header};
    use tower_http::set_header::SetResponseHeaderLayer;
    let set = |name: HeaderName, value: &'static str| SetResponseHeaderLayer::if_not_present(name, HeaderValue::from_static(value));
    let router = router
        .layer(set(header::CONTENT_SECURITY_POLICY, "frame-ancestors 'none'; object-src 'none'; base-uri 'self'"))
        .layer(set(header::X_FRAME_OPTIONS, "DENY"))
        .layer(set(header::X_CONTENT_TYPE_OPTIONS, "nosniff"))
        .layer(set(header::REFERRER_POLICY, "same-origin"));
    if https { router.layer(set(header::STRICT_TRANSPORT_SECURITY, "max-age=31536000")) } else { router }
}

/// Container-friendly first run: if RMM_ADMIN_EMAIL and RMM_ADMIN_PASSWORD are set and
/// no users exist yet, create that admin. Ignored once any user exists, so the
/// variables can be left in place (but should be removed after first login).
async fn bootstrap_admin(db: &sqlx::PgPool) -> Result<()> {
    // Compose passes `${VAR:-}` through as an empty string, so empty means "not set".
    let var = |k: &str| std::env::var(k).ok().map(|v| v.trim().to_string()).filter(|v| !v.is_empty());
    let (email, password) = match (var("RMM_ADMIN_EMAIL"), var("RMM_ADMIN_PASSWORD")) {
        (None, None) => return Ok(()),
        (Some(e), Some(p)) => (e, p),
        (e, p) => {
            warn!(
                email_set = e.is_some(),
                password_set = p.is_some(),
                "set both RMM_ADMIN_EMAIL and RMM_ADMIN_PASSWORD to create the first admin; skipping"
            );
            return Ok(());
        }
    };
    let users: i64 = sqlx::query_scalar("SELECT count(*) FROM users").fetch_one(db).await?;
    if users > 0 {
        info!("users already exist; ignoring RMM_ADMIN_EMAIL/RMM_ADMIN_PASSWORD (you can remove them)");
        return Ok(());
    }
    // Don't crash-loop the container over bad bootstrap input; log it and keep serving.
    match api::create_user_cli(db, &email, "Administrator", &password, auth::Role::Admin).await {
        Ok(_) => info!("created initial admin user {email}"),
        Err(e) => error!("could not create initial admin '{email}': {e}"),
    }
    Ok(())
}

/// Periodic cleanup: expired sessions, old metrics, jobs that will never finish.
async fn housekeeping(state: Arc<AppState>) {
    let mut tick = tokio::time::interval(Duration::from_secs(300));
    let mut runs: u64 = 0;
    loop {
        tick.tick().await;
        let db = &state.db;
        let mut results = vec![
            // The agent enforces the timeout itself; well past it, the result isn't coming
            // (agent hung, or the message was lost while the socket was dying).
            sqlx::query(
                "UPDATE jobs SET status = 'lost', finished_at = now(),
                        stderr = stderr || E'\\n[rmm] no result from the agent long after the job timeout\\n'
                  WHERE status = 'sent' AND sent_at + make_interval(secs => timeout_secs + 600) < now()",
            )
            .execute(db)
            .await,
            sqlx::query(
                "UPDATE jobs SET status = 'expired', finished_at = now()
                  WHERE status = 'queued' AND created_at < now() - make_interval(days => $1)",
            )
            .bind(state.cfg.job_queue_days as i32)
            .execute(db)
            .await,
        ];
        // The rest is bulk deletion; hourly is plenty.
        if runs.is_multiple_of(12) {
            results.push(
                sqlx::query(
                    "DELETE FROM user_sessions
                      WHERE expires_at < now() OR last_seen_at < now() - make_interval(hours => $1)",
                )
                .bind(state.session_idle_hours())
                .execute(db)
                .await,
            );
            results.push(
                sqlx::query("DELETE FROM agent_metrics WHERE ts < now() - make_interval(days => $1)")
                    .bind(state.cfg.metrics_retention_days as i32)
                    .execute(db)
                    .await,
            );
        }
        runs += 1;
        for e in results.iter().filter_map(|r| r.as_ref().err()) {
            warn!("housekeeping: {e}");
        }
        tracing::debug!(online = state.hub.online_count(), "housekeeping done");
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
