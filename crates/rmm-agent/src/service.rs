//! System service integration: systemd on Linux, SCM on Windows.

use std::path::Path;

use anyhow::Result;

#[cfg(target_os = "linux")]
mod imp {
    use super::*;
    use anyhow::{Context, bail};
    use std::process::Command;

    const UNIT_PATH: &str = "/etc/systemd/system/rmm-agent.service";
    const BIN_PATH: &str = "/usr/local/bin/rmm-agent";
    /// Where the .deb/.rpm puts it; the package manager owns that copy, so run it in place.
    const PACKAGED_PATH: &str = "/usr/bin/rmm-agent";

    pub fn install(config: &Path) -> Result<()> {
        let exe = std::env::current_exe()?;
        let bin = if exe == Path::new(PACKAGED_PATH) {
            PACKAGED_PATH
        } else {
            if exe != Path::new(BIN_PATH) {
                // Copy beside it, then rename over: writing into the binary of a running agent
                // fails with ETXTBSY, but replacing the directory entry is fine (the old
                // process keeps its inode until the restart below).
                let tmp = format!("{BIN_PATH}.install");
                let _ = std::fs::remove_file(&tmp);
                std::fs::copy(&exe, &tmp).with_context(|| format!("copying agent to {tmp} (run as root)"))?;
                {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755))?;
                }
                std::fs::rename(&tmp, BIN_PATH).with_context(|| format!("installing agent to {BIN_PATH} (run as root)"))?;
            }
            BIN_PATH
        };
        // No Nice=/MemoryMax= here: everything the agent spawns (scripts, shells, later
        // patch installs) inherits the unit's cgroup and priority, and a 128M cap OOM-killed
        // ordinary scripts. The agent's own footprint is small without it.
        let name = crate::config::service_display_name(crate::config::Config::load(config).ok().and_then(|c| c.product_name).as_deref());
        let unit = format!(
            "[Unit]\n\
             Description={name}\n\
             After=network-online.target\n\
             Wants=network-online.target\n\n\
             [Service]\n\
             ExecStart={bin} --config {cfg} run\n\
             Restart=always\n\
             RestartSec=5\n\n\
             [Install]\n\
             WantedBy=multi-user.target\n",
            cfg = config.display()
        );
        if let Some(dir) = Path::new(UNIT_PATH).parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        std::fs::write(UNIT_PATH, unit).with_context(|| format!("writing {UNIT_PATH} (run as root)"))?;
        systemctl(&["daemon-reload"])?;
        systemctl(&["enable", "rmm-agent.service"])?;
        // restart, not start: on a reinstall the old binary (and old config) is still running.
        systemctl(&["restart", "rmm-agent.service"])?;
        println!("rmm-agent service installed and started");
        Ok(())
    }

    pub fn uninstall() -> Result<()> {
        let _ = systemctl(&["disable", "--now", "rmm-agent.service"]);
        let _ = std::fs::remove_file(UNIT_PATH);
        systemctl(&["daemon-reload"])?;
        println!("rmm-agent service removed (config and binary left in place)");
        Ok(())
    }

    fn systemctl(args: &[&str]) -> Result<()> {
        let st = Command::new("systemctl").args(args).status().context("running systemctl")?;
        if !st.success() {
            bail!("systemctl {} failed: {st}", args.join(" "));
        }
        Ok(())
    }

    pub fn run_as_service(_config: std::path::PathBuf) -> Result<()> {
        bail!("`service` is only used on Windows; systemd runs `rmm-agent run`")
    }
}

#[cfg(windows)]
mod imp {
    use super::*;
    use std::ffi::OsString;
    use std::sync::OnceLock;
    use std::time::Duration;

    use anyhow::Context;
    use windows_service::service::{
        ServiceAccess, ServiceAction, ServiceActionType, ServiceControl, ServiceControlAccept, ServiceErrorControl,
        ServiceExitCode, ServiceFailureActions, ServiceFailureResetPeriod, ServiceInfo, ServiceStartType, ServiceState,
        ServiceStatus, ServiceType,
    };
    use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
    use windows_service::{define_windows_service, service_dispatcher};

    const NAME: &str = "RmmAgent";
    static CONFIG: OnceLock<std::path::PathBuf> = OnceLock::new();
    static AS_SERVICE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

    pub fn running_as_service() -> bool {
        AS_SERVICE.load(std::sync::atomic::Ordering::SeqCst)
    }

    fn wait_for(svc: &windows_service::service::Service, want: ServiceState) -> Result<()> {
        for _ in 0..60 {
            if svc.query_status()?.current_state == want {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        anyhow::bail!("{NAME} didn't reach {want:?} within 30 s")
    }

    /// Used by the update watchdog, which runs outside the service.
    pub fn stop_service() -> Result<()> {
        let mgr = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
        let svc = mgr.open_service(NAME, ServiceAccess::STOP | ServiceAccess::QUERY_STATUS)?;
        if svc.query_status()?.current_state != ServiceState::Stopped {
            let _ = svc.stop();
            wait_for(&svc, ServiceState::Stopped)?;
        }
        Ok(())
    }

    pub fn start_service() -> Result<()> {
        let mgr = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
        let svc = mgr.open_service(NAME, ServiceAccess::START | ServiceAccess::QUERY_STATUS)?;
        // The SCM's recovery action (or someone at the console) may have started it already
        // since it stopped: that is what the watchdog wants, not an error that would roll a
        // good update back.
        match svc.start::<&str>(&[]) {
            Ok(()) => {}
            Err(e) if already_running(&e) => {}
            Err(e) => return Err(e.into()),
        }
        wait_for(&svc, ServiceState::Running)
    }

    /// ERROR_SERVICE_ALREADY_RUNNING (1056).
    fn already_running(e: &windows_service::Error) -> bool {
        matches!(e, windows_service::Error::Winapi(io) if io.raw_os_error() == Some(1056))
    }

    pub fn install(config: &Path) -> Result<()> {
        crate::config::prepare_data_dir()?;
        let mgr = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE)
            .context("opening service manager (run as Administrator)")?;
        // Reinstall: the running service holds its .exe open, so stop it before copying.
        let existing = mgr.open_service(NAME, ServiceAccess::QUERY_STATUS | ServiceAccess::CHANGE_CONFIG | ServiceAccess::START).ok();
        if existing.is_some() {
            stop_service()?;
        }
        let exe = install_binary()?;
        let display_name =
            crate::config::service_display_name(crate::config::Config::load(config).ok().and_then(|c| c.product_name).as_deref());
        let info = ServiceInfo {
            name: NAME.into(),
            display_name: display_name.into(),
            service_type: ServiceType::OWN_PROCESS,
            start_type: ServiceStartType::AutoStart,
            error_control: ServiceErrorControl::Normal,
            executable_path: exe,
            launch_arguments: vec!["--config".into(), config.as_os_str().to_owned(), "service".into()],
            dependencies: vec![],
            account_name: None, // LocalSystem
            account_password: None,
        };
        let svc = match existing {
            Some(svc) => {
                svc.change_config(&info)?;
                svc
            }
            None => mgr.create_service(&info, ServiceAccess::CHANGE_CONFIG | ServiceAccess::START)?,
        };
        svc.set_description("Remote monitoring and management agent")?;
        // Equivalent of systemd's Restart=always: restart on crashes and on error exits.
        svc.update_failure_actions(ServiceFailureActions {
            reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(24 * 3600)),
            reboot_msg: None,
            command: None,
            actions: Some(vec![
                ServiceAction { action_type: ServiceActionType::Restart, delay: Duration::from_secs(5) },
                ServiceAction { action_type: ServiceActionType::Restart, delay: Duration::from_secs(30) },
                ServiceAction { action_type: ServiceActionType::Restart, delay: Duration::from_secs(60) },
            ]),
        })?;
        svc.set_failure_actions_on_non_crash_failures(true)?;
        svc.start::<&str>(&[])?;
        println!("RmmAgent service installed and started");
        Ok(())
    }

    /// The service runs as SYSTEM, so its binary must not live anywhere a normal user can
    /// write (Downloads, Desktop). Copy it under Program Files, which only admins can modify.
    fn install_binary() -> Result<std::path::PathBuf> {
        let base = std::env::var_os("ProgramFiles").unwrap_or_else(|| "C:\\Program Files".into());
        let dir = std::path::PathBuf::from(base).join("RMM");
        let target = dir.join("rmm-agent.exe");
        let exe = std::env::current_exe()?;
        if exe != target {
            std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
            // A remote desktop helper can hold the old .exe for a moment after the service stops.
            let mut copied = std::fs::copy(&exe, &target).map(|_| ());
            for _ in 0..20 {
                if copied.is_ok() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(250));
                copied = std::fs::copy(&exe, &target).map(|_| ());
            }
            copied.with_context(|| format!("copying agent to {}", target.display()))?;
        }
        Ok(target)
    }

    pub fn uninstall() -> Result<()> {
        let mgr = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
        let svc = mgr.open_service(NAME, ServiceAccess::STOP | ServiceAccess::DELETE | ServiceAccess::QUERY_STATUS)?;
        let _ = svc.stop();
        svc.delete()?;
        println!("RmmAgent service removed");
        Ok(())
    }

    define_windows_service!(ffi_service_main, service_main);

    pub fn run_as_service(config: std::path::PathBuf) -> Result<()> {
        let _ = CONFIG.set(config);
        service_dispatcher::start(NAME, ffi_service_main)?;
        Ok(())
    }

    fn service_main(_args: Vec<OsString>) {
        AS_SERVICE.store(true, std::sync::atomic::Ordering::SeqCst);
        let logging = init_file_logging("agent.log");
        if let Err(e) = service_body() {
            tracing::error!("service failed: {e:#}");
            if logging.is_err() {
                let _ = std::fs::write(std::env::temp_dir().join("rmm-agent-error.txt"), format!("{e:#}"));
            }
            // Non-zero exit so the SCM's failure actions restart us.
            std::process::exit(1);
        }
    }

    const LOG_MAX_BYTES: u64 = 10 * 1024 * 1024;

    /// There's no console under the SCM, so log to `logs/<name>` in the data dir, keeping
    /// one previous file (`<name>.1`) once it passes 10 MB at startup.
    pub fn init_file_logging(name: &str) -> Result<()> {
        use tracing_subscriber::EnvFilter;
        let dir = crate::config::prepare_data_dir()?.join("logs");
        std::fs::create_dir_all(&dir)?;
        let path = dir.join(name);
        if std::fs::metadata(&path).is_ok_and(|m| m.len() > LOG_MAX_BYTES) {
            let _ = std::fs::rename(&path, dir.join(format!("{name}.1")));
        }
        let file = std::fs::OpenOptions::new().create(true).append(true).open(&path)?;
        tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
            .with_ansi(false)
            .with_writer(std::sync::Mutex::new(file))
            .try_init()
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        Ok(())
    }

    fn service_body() -> Result<()> {
        crate::install_crypto();
        fn set(
            status: service_control_handler::ServiceStatusHandle,
            state: ServiceState,
            accept: ServiceControlAccept,
        ) -> windows_service::Result<()> {
            status.set_service_status(ServiceStatus {
                service_type: ServiceType::OWN_PROCESS,
                current_state: state,
                controls_accepted: accept,
                exit_code: ServiceExitCode::Win32(0),
                checkpoint: 0,
                wait_hint: Duration::from_secs(10),
                process_id: None,
            })
        }
        let (tx, rx) = tokio::sync::watch::channel(false);
        let handle = std::sync::Arc::new(std::sync::OnceLock::new());
        let in_handler = handle.clone();
        let status = service_control_handler::register(NAME, move |ctrl| match ctrl {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                // StopPending before anything else (and so before Stopped): left at Running
                // while shutting down, Stop-Service/Restart-Service give up with "stop failed".
                if let Some(&status) = in_handler.get() {
                    let _ = set(status, ServiceState::StopPending, ServiceControlAccept::empty());
                }
                let _ = tx.send(true);
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        })?;
        let _ = handle.set(status);
        set(status, ServiceState::Running, ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN)?;

        let config_path = CONFIG.get().expect("config path set").clone();
        let cfg = crate::config::Config::load(&config_path)?;
        let rt = crate::runtime()?;
        rt.block_on(crate::conn::run_forever(cfg, config_path, rx));
        // Dropping the runtime would wait for blocking tasks, and on Windows a child's output
        // pipe is read on one: a running job would hold the stop until it ended. Dropping the
        // job tasks kills their process trees (kill-on-close Job Objects), which ends those
        // reads anyway; the timeout is for anything else.
        rt.shutdown_timeout(Duration::from_secs(5));

        set(status, ServiceState::Stopped, ServiceControlAccept::empty())?;
        Ok(())
    }
}

#[cfg(not(any(target_os = "linux", windows)))]
mod imp {
    use super::*;
    pub fn install(_: &Path) -> Result<()> {
        anyhow::bail!("service install not implemented on this OS yet (launchd planned for macOS)")
    }
    pub fn uninstall() -> Result<()> {
        anyhow::bail!("service uninstall not implemented on this OS yet")
    }
    pub fn run_as_service(_: std::path::PathBuf) -> Result<()> {
        anyhow::bail!("not supported")
    }
}

pub use imp::{install, run_as_service, uninstall};
#[cfg(windows)]
pub use imp::{running_as_service, start_service, stop_service};

/// Logging for `update-watchdog`. Under systemd-run stdout goes to the journal
/// (`journalctl -u 'rmm-agent-update-*'`); on Windows there's no console, so it goes to
/// `logs\update.log` in the data dir.
pub fn init_watchdog_logging(_config: &Path) {
    #[cfg(windows)]
    if imp::init_file_logging("update.log").is_ok() {
        return;
    }
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .try_init();
}
