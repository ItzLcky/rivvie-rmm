mod accounting;
mod agent_ws;
mod backups;
mod billing;
mod branding;
mod checks;
mod pdf;
mod policy;
mod alerts;
mod automation;
mod apikeys;
mod webhooks;
mod desktop_ws;
mod diskenc;
mod api;
mod auth;
mod email;
mod error;
mod events;
mod fields;
mod hub;
mod localadmin;
mod metrics;
mod netalerts;
mod netmon;
mod notify;
mod oncall;
mod push;
mod pwa;
mod oui;
mod oidc;
mod paging;
mod patches;
mod software;
mod ratelimit;
mod reports;
mod rotate;
mod siem;
mod scheduler;
mod crypto;
mod csat;
mod graph;
mod entra;
mod identity;
mod mdm;
mod helpdesk_agent;
mod security;
mod sla;
mod shell_ws;
mod state;
mod storage;
mod tickets;
mod vault;
mod params;
mod totp;
mod updates;
mod uptime;
mod vuln;
mod webauthn;
mod wol;

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
    /// Replace RMM_DATA_KEY: re-encrypt everything sealed with it under a new key, in one
    /// transaction. Stop the server first. The keys come from the environment (never the
    /// command line): RMM_DATA_KEY_NEW, and RMM_DATA_KEY_OLD (default: RMM_DATA_KEY).
    RotateDataKey {
        /// Count what would change and check that the old key opens everything; write nothing.
        #[arg(long)]
        dry_run: bool,
    },
    /// Load vulnerability feed files saved from the internet, for servers that can't reach the
    /// feeds: OSV `all.zip` dumps (named after their ecosystem: `Debian/all.zip` or
    /// `Debian.zip`), the Arch tracker's `all.json`, saved NVD API pages, CISA's KEV catalogue
    /// and the EPSS CSV. A running server re-evaluates its devices within seconds.
    VulnImport {
        dir: PathBuf,
    },
    /// Store a managed vault item through the system write path (vault::put_managed), as disk
    /// encryption escrow and LAPS do. For tests and break-glass imports; needs RMM_DATA_KEY. The
    /// password comes from RMM_VAULT_PASSWORD (never the command line).
    #[command(hide = true)]
    VaultPutManaged {
        #[arg(long)]
        client: uuid::Uuid,
        /// disk_recovery, local_admin or identity.
        #[arg(long)]
        kind: String,
        #[arg(long)]
        reference: String,
        #[arg(long)]
        name: String,
        #[arg(long, default_value = "")]
        username: String,
        #[arg(long)]
        agent: Option<uuid::Uuid>,
        #[arg(long)]
        state: Option<String>,
        #[arg(long, env = "RMM_VAULT_PASSWORD", hide_env_values = true)]
        password: String,
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
    /// Hourly metric rollups (charts beyond 48 hours) are kept this long.
    #[arg(long, env = "RMM_METRICS_RETENTION_DAYS", default_value_t = 90)]
    metrics_retention_days: u32,
    /// Raw heartbeat samples (charts up to 48 hours, threshold alerts) are kept this long.
    #[arg(long, env = "RMM_METRICS_RAW_DAYS", default_value_t = 7)]
    metrics_raw_days: u32,
    /// Resolved alerts are deleted after this many days.
    #[arg(long, env = "RMM_ALERT_RETENTION_DAYS", default_value_t = 180)]
    alert_retention_days: u32,
    /// How often offline, CPU, memory and disk policies are checked.
    #[arg(long, env = "RMM_ALERT_EVAL_SECS", default_value_t = 60, hide = true)]
    alert_eval_secs: u32,
    /// Jobs queued for an offline agent expire after this many days instead of running late.
    #[arg(long, env = "RMM_JOB_QUEUE_DAYS", default_value_t = 7)]
    job_queue_days: u32,
    /// Online agents scan for OS updates when their last scan is older than this.
    #[arg(long, env = "RMM_PATCH_SCAN_HOURS", default_value_t = 12)]
    patch_scan_hours: u32,
    /// Dashboard sessions unused for this many hours are signed out (absolute limit: 7 days).
    /// Admins can override it under Company settings.
    #[arg(long, env = "RMM_SESSION_IDLE_HOURS", default_value_t = 12)]
    session_idle_hours: u32,
    /// Reverse proxies whose X-Forwarded-For header is trusted for the client IP (rate
    /// limiting, audit). Comma-separated CIDRs; `private` = loopback + RFC 1918 + ULA.
    #[arg(long, env = "RMM_TRUSTED_PROXIES", default_value = "")]
    trusted_proxies: String,
    /// Ticket attachments and raw email, unless RMM_S3_BUCKET is set.
    #[arg(long, env = "RMM_STORAGE_DIR", default_value = "data/storage")]
    storage_dir: PathBuf,
    #[arg(long, env = "RMM_MAIL_POLL_SECS", default_value_t = 60)]
    mail_poll_secs: u32,
    #[arg(long, env = "RMM_TICKET_CLOSE_DAYS", default_value_t = 7)]
    ticket_close_days: u32,
    #[arg(long, env = "RMM_EMAIL_RAW_DAYS", default_value_t = 90)]
    email_raw_days: u32,
    /// Minutes new detection content stays on canary clients before everyone gets it.
    #[arg(long, env = "RMM_CONTENT_SOAK_MINUTES", default_value_t = 1440)]
    content_soak_minutes: u32,
    /// The agents' release public key (hex). When set, content uploads are verified here too.
    #[arg(long, env = "RMM_UPDATE_PUBKEY")]
    content_pubkey: Option<String>,
    /// 32-byte key (hex or base64) for encrypting detection context at rest.
    #[arg(long, env = "RMM_DATA_KEY", hide_env_values = true)]
    data_key: Option<String>,
    /// Largest ticket or portal attachment, in MB per file. Uploads stream to storage, so
    /// this bounds disk use, not memory.
    #[arg(long, env = "RMM_ATTACHMENT_MAX_MB", default_value_t = 100)]
    attachment_max_mb: u32,
    /// Turns on `GET /metrics` (Prometheus), for scrapers sending `Authorization: Bearer <token>`.
    #[arg(long, env = "RMM_METRICS_TOKEN", hide_env_values = true)]
    metrics_token: Option<String>,
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
            metrics_retention_days: env("RMM_METRICS_RETENTION_DAYS", "90").parse().unwrap_or(90),
            metrics_raw_days: env("RMM_METRICS_RAW_DAYS", "7").parse().unwrap_or(7),
            alert_retention_days: env("RMM_ALERT_RETENTION_DAYS", "180").parse().unwrap_or(180),
            alert_eval_secs: env("RMM_ALERT_EVAL_SECS", "60").parse().unwrap_or(60),
            job_queue_days: env("RMM_JOB_QUEUE_DAYS", "7").parse().unwrap_or(7),
            patch_scan_hours: env("RMM_PATCH_SCAN_HOURS", "12").parse().unwrap_or(12),
            session_idle_hours: env("RMM_SESSION_IDLE_HOURS", "12").parse().unwrap_or(12),
            trusted_proxies: env("RMM_TRUSTED_PROXIES", ""),
            storage_dir: env("RMM_STORAGE_DIR", "data/storage").into(),
            mail_poll_secs: env("RMM_MAIL_POLL_SECS", "60").parse().unwrap_or(60),
            ticket_close_days: env("RMM_TICKET_CLOSE_DAYS", "7").parse().unwrap_or(7),
            email_raw_days: env("RMM_EMAIL_RAW_DAYS", "90").parse().unwrap_or(90),
            content_soak_minutes: env("RMM_CONTENT_SOAK_MINUTES", "1440").parse().unwrap_or(1440),
            content_pubkey: std::env::var("RMM_UPDATE_PUBKEY").ok().filter(|s| !s.trim().is_empty()),
            data_key: std::env::var("RMM_DATA_KEY").ok().filter(|s| !s.trim().is_empty()),
            attachment_max_mb: env("RMM_ATTACHMENT_MAX_MB", "100").parse().unwrap_or(100),
            metrics_token: std::env::var("RMM_METRICS_TOKEN").ok().filter(|s| !s.trim().is_empty()),
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| "info,tower_http=warn,sqlx=warn".into());
    // RMM_LOG_FORMAT=json: one JSON object per line (with the request span's id, method and
    // route on request logs), for log shippers. Text otherwise.
    match std::env::var("RMM_LOG_FORMAT").unwrap_or_default().trim() {
        "json" => tracing_subscriber::fmt().json().with_current_span(true).with_span_list(false).with_env_filter(filter).init(),
        "" | "text" => tracing_subscriber::fmt().with_env_filter(filter).init(),
        other => {
            tracing_subscriber::fmt().with_env_filter(filter).init();
            warn!("RMM_LOG_FORMAT must be text or json, not {other:?}; using text");
        }
    }
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
            println!("two-factor auth (authenticator app, passkeys and recovery codes) removed for {email}; they will be asked to set it up again if required");
            Ok(())
        }
        Cmd::RotateDataKey { dry_run } => {
            let (old, new) = rotate::keys_from_env()?;
            let report = rotate::rotate(&db, old.as_ref(), &new, dry_run).await?;
            if dry_run {
                println!("dry run, nothing written:\n{report}");
            } else {
                auth::audit(&db, None, "system.data_key_rotated", None, rotate::audit_details(&report)).await;
                println!("RMM_DATA_KEY rotated:\n{report}\nSet RMM_DATA_KEY to the new key and start the server.");
            }
            Ok(())
        }
        Cmd::VaultPutManaged { client, kind, reference, name, username, agent, state, password } => {
            let key = std::env::var("RMM_DATA_KEY").ok().filter(|k| !k.trim().is_empty()).context(vault::NEEDS_KEY)?;
            let key = crypto::DataKey::parse(key.trim()).context("RMM_DATA_KEY")?;
            let kind = vault::ManagedKind::parse(&kind).context("kind must be disk_recovery, local_admin or identity")?;
            let m = vault::Managed { kind, agent_id: agent, reference, name, username, state, ..Default::default() };
            let id = vault::put_managed_with(&db, &key, client, m, &password, vault::Source::system("cli")).await.map_err(|e| anyhow::anyhow!("{e}"))?;
            println!("{id}");
            Ok(())
        }
        Cmd::VulnImport { dir } => {
            let added = vuln::seed_products(&db).await?;
            if added > 0 {
                println!("{added} built-in Windows product mappings added");
            }
            println!("{}", vuln::feeds::import_dir(&db, &dir).await?);
            auth::audit(&db, None, "vuln.sync", None, serde_json::json!({ "via": "cli", "dir": dir.display().to_string() })).await;
            Ok(())
        }
        Cmd::Serve(args) => serve(db, args).await,
    }
}

async fn serve(db: sqlx::PgPool, args: ServeArgs) -> Result<()> {
    // Nothing is connected yet, whatever the DB says from the last run.
    sqlx::query("UPDATE agents SET online = false WHERE online").execute(&db).await?;
    // Jobs left `sent` by the previous process aren't lost: agents keep running them and
    // report when they reconnect (and anything they don't hold is marked `lost` then).
    bootstrap_admin(&db).await?;
    let trusted_proxies = ratelimit::parse_trusted(&args.trusted_proxies).map_err(anyhow::Error::msg)?;

    let http = reqwest::Client::builder()
        .user_agent(concat!("rmm-server/", env!("CARGO_PKG_VERSION")))
        .timeout(Duration::from_secs(20))
        .redirect(reqwest::redirect::Policy::limited(3))
        .build()
        .context("building HTTP client")?;
    let storage = storage::Storage::from_env(args.storage_dir.clone(), http.clone())?;
    info!("file storage: {}", storage.describe());

    let data_key = match args.data_key.as_deref() {
        Some(k) => Some(crypto::DataKey::parse(k)?),
        None => {
            warn!("RMM_DATA_KEY isn't set: two-factor secrets and detection context (command lines) are stored unencrypted");
            None
        }
    };
    api::seal_totp_secrets(&db, data_key.as_ref()).await.context("encrypting two-factor secrets")?;
    api::seal_sso_secrets(&db, data_key.as_ref()).await.context("encrypting single sign-on secrets")?;
    rotate::seal_plaintext_credentials(&db, data_key.as_ref()).await.context("encrypting mail and notification credentials")?;
    // After sealing: the company settings in memory hold the mail server password as stored.
    let company = state::Company::load(&db).await.context("loading company settings")?;
    if data_key.is_none() {
        let (n,): (i64,) = sqlx::query_as("SELECT count(*) FROM vault_keys").fetch_one(&db).await.context("checking vault keys")?;
        if n > 0 {
            warn!("{n} client vault(s) are encrypted with RMM_DATA_KEY, which isn't set: the vault is unavailable until it is");
        }
    }
    let branding = branding::Cache::load(&db).await.context("loading branding")?;
    let state = Arc::new(AppState {
        storage,
        branding,
        company: company.into(),
        db,
        hub: Default::default(),
        limits: Default::default(),
        releases: Default::default(),
        started_at: chrono::Utc::now(),
        http,
        notify_wake: Default::default(),
        cfg: Settings {
            agent_dir: args.agent_dir.clone(),
            public_url: args.public_url.trim_end_matches('/').to_string(),
            heartbeat_secs: args.heartbeat_secs,
            inventory_secs: args.inventory_secs,
            metrics_retention_days: args.metrics_retention_days,
            job_queue_days: args.job_queue_days,
            patch_scan_hours: args.patch_scan_hours.max(1),
            session_idle_hours: args.session_idle_hours.max(1),
            trusted_proxies,
            metrics_raw_days: args.metrics_raw_days.max(1),
            alert_retention_days: args.alert_retention_days.max(1),
            alert_eval_secs: args.alert_eval_secs,
            // Read here rather than as a flag, like RMM_SOURCE_URL: a server on the public internet
            // must not let monitors probe its own network, so it's off unless asked for.
            uptime_allow_private: std::env::var("RMM_UPTIME_ALLOW_PRIVATE").is_ok_and(|v| matches!(v.trim(), "1" | "true" | "yes")),
            ticket_close_days: args.ticket_close_days.max(1),
            email_raw_days: args.email_raw_days.max(1),
            content_soak_minutes: args.content_soak_minutes,
            content_pubkey: args.content_pubkey.clone(),
            data_key,
            attachment_max_mb: args.attachment_max_mb.max(1),
            metrics_token: args.metrics_token.clone().map(|t| t.trim().to_string()).filter(|t| !t.is_empty()),
            // Where the console and portal offer this server's source code (AGPL-3.0 §13). Read
            // here rather than as a flag: it only matters to operators running modified code.
            source_url: std::env::var("RMM_SOURCE_URL")
                .ok()
                .map(|u| u.trim().to_string())
                .filter(|u| !u.is_empty())
                .unwrap_or_else(|| branding::DEFAULT_SOURCE_URL.to_string()),
        },
        triage: Default::default(),
        oidc: oidc::Cache::new(),
        passkeys: webauthn::Passkeys::new(args.public_url.trim_end_matches('/')),
    });
    tokio::spawn(housekeeping(state.clone()));
    tokio::spawn(alerts::run(state.clone()));
    tokio::spawn(notify::worker(state.clone()));
    tokio::spawn(scheduler::run(state.clone()));
    tokio::spawn(automation::run(state.clone()));
    tokio::spawn(patches::scheduler(state.clone()));
    tokio::spawn(software::scheduler(state.clone()));
    tokio::spawn(security::rollout_loop(state.clone()));
    tokio::spawn(email::poll_loop(state.clone(), args.mail_poll_secs));
    tokio::spawn(sla::run(state.clone()));
    tokio::spawn(accounting::run(state.clone()));
    tokio::spawn(metrics::probe_pool(state.clone()));
    tokio::spawn(updates::run(state.clone()));
    tokio::spawn(siem::run(state.clone()));
    tokio::spawn(netmon::run(state.clone()));
    tokio::spawn(reports::run(state.clone()));
    tokio::spawn(oncall::run(state.clone()));
    tokio::spawn(push::run(state.clone()));
    tokio::spawn(uptime::run(state.clone()));
    tokio::spawn(identity::run(state.clone()));
    tokio::spawn(diskenc::run(state.clone()));
    tokio::spawn(localadmin::run(state.clone()));
    tokio::spawn(vuln::run(state.clone()));
    if state.cfg.metrics_token.is_some() {
        info!("metrics: GET /metrics (bearer token required)");
    }

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
        .route("/metrics", get(metrics::handler))
        // The installable app's manifest, and the short link in on-call text messages.
        .route("/manifest.webmanifest", get(pwa::handler))
        .route("/a/{token}", get(oncall::short_link))
        .nest("/api", api::router(state.cfg.attachment_max_bytes()))
        // The same routes under a version: what API keys and integrations should use.
        .nest("/api/v1", api::router(state.cfg.attachment_max_bytes()))
        .fallback_service(ServeDir::new(&args.web_dir).fallback(ServeFile::new(index)))
        // (The API sets its own body limit, see `api::router`.)
        .layer(axum::middleware::from_fn(metrics::http_layer));
    let https = state.cfg.secure_cookies();
    let app = security_headers(app.with_state(state), https);

    let listener = tokio::net::TcpListener::bind(args.bind).await.with_context(|| format!("binding {}", args.bind))?;
    info!("listening on {} (public url {})", args.bind, args.public_url);
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

/// Baseline browser hardening for the dashboard. This header CSP covers what a `<meta>` tag
/// can't (frame-ancestors); script-src and the rest come from the `<meta>` policy SvelteKit
/// writes into the built pages with hashes of its inline scripts (see web/vite.config.ts).
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

/// Periodic cleanup: expired sessions, old metrics, jobs that will never finish; metric rollups.
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
        if results.iter().any(|r| r.as_ref().is_ok_and(|r| r.rows_affected() > 0)) {
            state.hub.publish(hub::Event::Jobs);
        }
        if let Err(e) = security::sweep(&state).await {
            warn!("housekeeping: security actions: {e}");
        }
        // Stored agent health follows alerts, jobs and patches through triggers; this catches
        // what only the clock changes (a job failed 24 hours ago, an update missing for a week)
        // and anything the triggers missed.
        if let Err(e) = api::refresh_agent_health(db).await {
            warn!("housekeeping: refreshing agent health: {e}");
        }
        // Roll the last few complete hours of samples up (idempotent; late samples are folded in).
        results.push(
            sqlx::query(
                "INSERT INTO agent_metrics_hourly
                 SELECT agent_id, date_trunc('hour', ts), count(*), avg(cpu_percent), max(cpu_percent), avg(mem_used)::bigint,
                        max(mem_used), max(mem_total), max(disk_max_pct), max(net_rx_bytes), max(net_tx_bytes)
                   FROM agent_metrics
                  WHERE ts >= date_trunc('hour', now()) - interval '3 hours' AND ts < date_trunc('hour', now())
                  GROUP BY 1, 2
                 ON CONFLICT (agent_id, hour) DO UPDATE SET
                   samples = EXCLUDED.samples, cpu_avg = EXCLUDED.cpu_avg, cpu_max = EXCLUDED.cpu_max,
                   mem_used_avg = EXCLUDED.mem_used_avg, mem_used_max = EXCLUDED.mem_used_max, mem_total = EXCLUDED.mem_total,
                   disk_max_pct = EXCLUDED.disk_max_pct, net_rx_bytes = EXCLUDED.net_rx_bytes, net_tx_bytes = EXCLUDED.net_tx_bytes",
            )
            .execute(db)
            .await,
        );
        if let Err(e) = netmon::rollup(db).await {
            warn!("housekeeping: rolling up network samples: {e}");
        }
        if let Err(e) = uptime::rollup(db).await {
            warn!("housekeeping: rolling up uptime results: {e}");
        }
        // The rest is bulk deletion; hourly is plenty.
        if runs.is_multiple_of(12) {
            state.limits.prune();
            state.passkeys.prune();
            // Sign-ins started but never finished at the identity provider.
            results.push(sqlx::query("DELETE FROM sso_login_states WHERE expires_at < now()").execute(db).await);
            results.push(
                sqlx::query(
                    "DELETE FROM user_sessions
                      WHERE expires_at < now() OR last_seen_at < now() - make_interval(hours => $1)",
                )
                .bind(state.session_idle_hours())
                .execute(db)
                .await,
            );
            if let Err(e) = netmon::prune(db, state.cfg.metrics_raw_days as i32, state.cfg.metrics_retention_days as i32).await {
                warn!("housekeeping: pruning network samples: {e}");
            }
            if let Err(e) = uptime::prune(db, state.cfg.metrics_raw_days as i32, state.cfg.metrics_retention_days as i32).await {
                warn!("housekeeping: pruning uptime results: {e}");
            }
            if let Err(e) = backups::prune(db).await {
                warn!("housekeeping: pruning backup jobs: {e}");
            }
            if let Err(e) = patches::prune(db).await {
                warn!("housekeeping: pruning patches: {e}");
            }
            if let Err(e) = software::prune(db).await {
                warn!("housekeeping: pruning software runs: {e}");
            }
            results.push(
                sqlx::query("DELETE FROM agent_metrics WHERE ts < now() - make_interval(days => $1)")
                    .bind(state.cfg.metrics_raw_days as i32)
                    .execute(db)
                    .await,
            );
            results.push(
                sqlx::query("DELETE FROM agent_metrics_hourly WHERE hour < now() - make_interval(days => $1)")
                    .bind(state.cfg.metrics_retention_days as i32)
                    .execute(db)
                    .await,
            );
            // Output retention for scheduled runs, per schedule.
            results.push(
                sqlx::query(
                    "DELETE FROM jobs j USING policy_items s
                      WHERE j.schedule_id = s.id AND j.finished_at < now() - make_interval(days => coalesce((s.config ->> 'retain_days')::int, 30))",
                )
                .execute(db)
                .await,
            );
            if let Err(e) = automation::prune(db).await {
                warn!("housekeeping: pruning automation runs: {e}");
            }
            results.push(
                sqlx::query("DELETE FROM alerts WHERE resolved_at < now() - make_interval(days => $1)")
                    .bind(state.cfg.alert_retention_days as i32)
                    .execute(db)
                    .await,
            );
            results.push(
                sqlx::query("DELETE FROM log_events WHERE received_at < now() - interval '30 days'").execute(db).await,
            );
            results.push(sqlx::query("DELETE FROM alert_mutes WHERE ends_at < now() - interval '30 days'").execute(db).await);
            results.push(sqlx::query("DELETE FROM attachment_links WHERE expires_at < now()").execute(db).await);
            results.push(
                sqlx::query("DELETE FROM notifications WHERE status <> 'pending' AND created_at < now() - interval '30 days'")
                    .execute(db)
                    .await,
            );
            results.push(
                sqlx::query("DELETE FROM webhook_deliveries WHERE status <> 'pending' AND created_at < now() - interval '30 days'")
                    .execute(db)
                    .await,
            );
            match tickets::auto_close(&state, state.cfg.ticket_close_days).await {
                Ok(n) if n > 0 => info!(tickets = n, "closed resolved tickets"),
                Ok(_) => {}
                Err(e) => warn!("housekeeping: closing resolved tickets: {e}"),
            }
            if let Err(e) = prune_raw_email(&state).await {
                warn!("housekeeping: pruning raw email: {e:#}");
            }
        }
        runs += 1;
        for e in results.iter().filter_map(|r| r.as_ref().err()) {
            warn!("housekeeping: {e}");
        }
        tracing::debug!(online = state.hub.online_count(), "housekeeping done");
    }
}

/// Raw MIME is kept for RMM_EMAIL_RAW_DAYS; the parsed text stays on the ticket. The row
/// stays too (threading looks up its Message-ID).
async fn prune_raw_email(state: &AppState) -> Result<()> {
    let old: Vec<(uuid::Uuid, String)> = sqlx::query_as(
        "SELECT id, raw_key FROM email_messages
          WHERE raw_key IS NOT NULL AND created_at < now() - make_interval(days => $1) LIMIT 1000",
    )
    .bind(state.cfg.email_raw_days as i32)
    .fetch_all(&state.db)
    .await?;
    for (id, key) in old {
        state.storage.delete(&key).await?;
        sqlx::query("UPDATE email_messages SET raw_key = NULL WHERE id = $1").bind(id).execute(&state.db).await?;
    }
    Ok(())
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
