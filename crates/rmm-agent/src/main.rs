mod checks;
mod collect;
mod config;
mod conn;
mod deploy;
mod desktop;
mod fetch;
mod fsutil;
mod jobs;
mod logwatch;
mod net;
mod patch;
mod security;
mod sensor;
mod service;
mod services;
mod shell;
mod software;
mod tools;
mod update;
#[cfg(windows)]
mod winjob;

use std::io::Write as _;
use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "rmm-agent", version = collect::AGENT_VERSION, about = "RMM endpoint agent")]
struct Cli {
    /// Path to agent.toml (defaults to the platform system location).
    #[arg(long, global = true, env = "RMM_AGENT_CONFIG")]
    config: Option<PathBuf>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Register this machine with a server using an enrollment token.
    Enroll {
        /// Server base URL, e.g. https://rmm.example.com
        #[arg(long, required_unless_present = "from_file")]
        server: Option<String>,
        #[arg(long, env = "RMM_ENROLL_TOKEN", required_unless_present = "from_file")]
        token: Option<String>,
        /// Read `server` and `token` from a TOML file instead (what the .deb/.rpm ships).
        #[arg(long, conflicts_with_all = ["server", "token"])]
        from_file: Option<PathBuf>,
        /// Also install and start the system service.
        #[arg(long)]
        install: bool,
        /// Allow a plain http:// server that isn't localhost. The agent secret and every
        /// script would cross the network unencrypted; only use this on a trusted lab network.
        #[arg(long)]
        insecure: bool,
        /// If this machine is already enrolled with this server (or no server is given), keep
        /// that enrollment and only do `--install`. What the MSI runs, so upgrades and
        /// repairs keep the agent's identity without spending a token use.
        #[arg(long)]
        keep_existing: bool,
        /// Also append the outcome to this file (the MSI has no console to show it on).
        #[arg(long)]
        log_file: Option<PathBuf>,
        /// The MSP's product name: the service is shown as "<name> Agent". Kept in agent.toml.
        #[arg(long)]
        product_name: Option<String>,
    },
    /// Run in the foreground (what the service runs).
    Run,
    /// Install and start the system service (systemd / Windows service).
    Install,
    /// Stop and remove the system service.
    Uninstall,
    /// Print collected metrics and inventory as JSON, then exit. Useful for debugging.
    Inspect,
    /// Scan for OS updates the way the server would, and print them as JSON. With
    /// `--install`, install those updates (ids from a scan) and print the result.
    Patches {
        /// Update ids to install.
        #[arg(long, num_args = 1..)]
        install: Vec<String>,
        /// Skip refreshing package lists.
        #[arg(long)]
        no_refresh: bool,
    },
    /// Print the antivirus state the server would see, as JSON. With `--run`, start a
    /// `quick_scan`, `full_scan` or `update_signatures` and wait for it.
    Security {
        #[arg(long)]
        run: Option<String>,
    },
    /// Remote desktop capture and input, started by the agent inside the user's session.
    #[command(hide = true)]
    DesktopHelper,
    /// The endpoint protection sensor, started and supervised by the agent.
    #[command(hide = true)]
    Sensor,
    /// The sensor supervisor alone, on the stored policy, without a server (for tests).
    #[command(hide = true)]
    SuperviseSensor,
    /// Entry point used by the Windows Service Control Manager.
    #[command(hide = true)]
    Service,
    /// Swaps in a downloaded update and rolls back if it doesn't check in (started by the agent).
    #[command(hide = true)]
    UpdateWatchdog,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let config_path = cli.config.unwrap_or_else(config::default_path);

    // Windows SCM entry must happen before we build a runtime; it builds its own.
    if let Cmd::Service = cli.cmd {
        return service::run_as_service(config_path);
    }

    if let Cmd::DesktopHelper = cli.cmd {
        // stdout carries frames to the agent, so logs must go to stderr.
        tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
            .with_writer(std::io::stderr)
            .with_ansi(false)
            .without_time()
            .init();
        return desktop::helper_main();
    }

    if let Cmd::Sensor = cli.cmd {
        // stdout carries messages to the agent; logs go to stderr (the agent's log).
        tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
            .with_writer(std::io::stderr)
            .with_ansi(false)
            .init();
        return sensor::main();
    }

    if let Cmd::SuperviseSensor = cli.cmd {
        // stdout carries the status lines.
        tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
            .with_writer(std::io::stderr)
            .with_ansi(false)
            .init();
        return security::supervisor::standalone();
    }

    if let Cmd::UpdateWatchdog = cli.cmd {
        // No console under systemd-run or a detached Windows process: log to a file too.
        service::init_watchdog_logging(&config_path);
        return update::watchdog(&config_path).inspect_err(|e| tracing::error!("update watchdog: {e:#}"));
    }

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();
    install_crypto();

    match cli.cmd {
        Cmd::Enroll { server, token, from_file, install, insecure, keep_existing, log_file, product_name } => {
            let res = (|| {
                let (server, token, product_name) = match from_file {
                    Some(path) => {
                        let f = config::EnrollFile::load(&path)?;
                        (f.server, f.token, f.product_name.or(product_name))
                    }
                    None => (server.unwrap_or_default(), token.unwrap_or_default(), product_name),
                };
                let product_name = product_name.map(|p| p.trim().to_string()).filter(|p| !p.is_empty());
                if keep_existing && let Some(mut existing) = enrolled_with(&config_path, &server, insecure) {
                    // An upgrade with a newly branded package renames the service.
                    if product_name.is_some() && product_name != existing.product_name {
                        existing.product_name = product_name.clone();
                        existing.save(&config_path)?;
                    }
                    let msg = format!("already enrolled as {} with {}; keeping it", existing.agent_id, existing.server_url);
                    println!("{msg}");
                    if install {
                        service::install(&config_path)?;
                    }
                    return Ok(msg);
                }
                let server = config::normalize_server_url(&server, insecure)?;
                anyhow::ensure!(!token.trim().is_empty(), "no enrollment token given");
                // Re-enrolling: prove ownership of the existing record so the server keeps it.
                // Never hand the old secret to a different server.
                let previous = config::Config::load(&config_path).ok().filter(|c| c.server_url == server);
                let mut cfg = runtime()?.block_on(conn::enroll(&server, &token, previous.as_ref()))?;
                cfg.product_name = product_name.or_else(|| previous.and_then(|p| p.product_name));
                cfg.save(&config_path)?;
                let msg = format!("enrolled as {} (config: {})", cfg.agent_id, config_path.display());
                println!("{msg}");
                if install {
                    service::install(&config_path)?;
                }
                Ok(msg)
            })();
            if let Some(path) = log_file {
                append_log(&path, &match &res {
                    Ok(msg) => format!("ok: {msg}"),
                    Err(e) => format!("failed: {e:#}"),
                });
            }
            res.map(|_| ())
        }
        Cmd::Run => {
            let cfg = config::Config::load(&config_path)?;
            runtime()?.block_on(async {
                let (tx, rx) = tokio::sync::watch::channel(false);
                tokio::spawn(async move {
                    let _ = tokio::signal::ctrl_c().await;
                    let _ = tx.send(true);
                });
                conn::run_forever(cfg, config_path, rx).await;
            });
            Ok(())
        }
        Cmd::Install => service::install(&config_path),
        Cmd::Uninstall => service::uninstall(),
        Cmd::Inspect => {
            let mut c = collect::Collector::new()?;
            std::thread::sleep(std::time::Duration::from_millis(300)); // CPU usage needs two samples
            let out = serde_json_like(&c.metrics(), &c.inventory());
            println!("{out}");
            Ok(())
        }
        Cmd::Patches { install, no_refresh } => patch::cli(&install, !no_refresh),
        Cmd::Security { run } => security::cli(run.as_deref()),
        Cmd::Service | Cmd::UpdateWatchdog | Cmd::DesktopHelper | Cmd::Sensor | Cmd::SuperviseSensor => unreachable!(),
    }
}

/// The existing enrollment, if it's with `server` (or `server` is empty).
fn enrolled_with(config_path: &std::path::Path, server: &str, insecure: bool) -> Option<config::Config> {
    let existing = config::Config::load(config_path).ok()?;
    if server.trim().is_empty() {
        return Some(existing);
    }
    let server = config::normalize_server_url(server, insecure).ok()?;
    (existing.server_url == server).then_some(existing)
}

fn append_log(path: &std::path::Path, line: &str) {
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
        let _ = writeln!(f, "{} rmm-agent {}: {line}", chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true), collect::AGENT_VERSION);
    }
}

pub(crate) fn install_crypto() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

pub(crate) fn runtime() -> Result<tokio::runtime::Runtime> {
    // Small fixed pool: an agent should never compete with the workloads it monitors.
    Ok(tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build()?)
}

fn serde_json_like(m: &rmm_proto::Metrics, i: &rmm_proto::Inventory) -> String {
    format!("metrics:\n{m:#?}\n\ninventory ({} packages):\n{:#?}", i.software.len(), InvSummary(i))
}

struct InvSummary<'a>(&'a rmm_proto::Inventory);
impl std::fmt::Debug for InvSummary<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let i = self.0;
        f.debug_struct("Inventory")
            .field("system", &i.system)
            .field("cpu", &i.cpu_brand)
            .field("cores", &(i.cpu_cores_physical, i.cpu_cores_logical))
            .field("mem_total", &i.mem_total)
            .field("disks", &i.disks)
            .field("network", &i.network)
            .field("users", &i.logged_in_users)
            .field("software_sample", &i.software.iter().take(5).collect::<Vec<_>>())
            .finish()
    }
}
