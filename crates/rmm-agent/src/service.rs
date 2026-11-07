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

    pub fn install(config: &Path) -> Result<()> {
        let exe = std::env::current_exe()?;
        if exe != Path::new(BIN_PATH) {
            std::fs::copy(&exe, BIN_PATH).with_context(|| format!("copying agent to {BIN_PATH} (run as root)"))?;
        }
        let unit = format!(
            "[Unit]\n\
             Description=RMM Agent\n\
             After=network-online.target\n\
             Wants=network-online.target\n\n\
             [Service]\n\
             ExecStart={BIN_PATH} --config {cfg} run\n\
             Restart=always\n\
             RestartSec=5\n\
             Nice=10\n\
             MemoryMax=128M\n\n\
             [Install]\n\
             WantedBy=multi-user.target\n",
            cfg = config.display()
        );
        std::fs::write(UNIT_PATH, unit).with_context(|| format!("writing {UNIT_PATH} (run as root)"))?;
        systemctl(&["daemon-reload"])?;
        systemctl(&["enable", "--now", "rmm-agent.service"])?;
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
        ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode, ServiceInfo,
        ServiceStartType, ServiceState, ServiceStatus, ServiceType,
    };
    use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
    use windows_service::{define_windows_service, service_dispatcher};

    const NAME: &str = "RmmAgent";
    static CONFIG: OnceLock<std::path::PathBuf> = OnceLock::new();

    pub fn install(config: &Path) -> Result<()> {
        let mgr = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE)
            .context("opening service manager (run as Administrator)")?;
        let info = ServiceInfo {
            name: NAME.into(),
            display_name: "RMM Agent".into(),
            service_type: ServiceType::OWN_PROCESS,
            start_type: ServiceStartType::AutoStart,
            error_control: ServiceErrorControl::Normal,
            executable_path: std::env::current_exe()?,
            launch_arguments: vec!["--config".into(), config.as_os_str().to_owned(), "service".into()],
            dependencies: vec![],
            account_name: None, // LocalSystem
            account_password: None,
        };
        let svc = mgr.create_service(&info, ServiceAccess::CHANGE_CONFIG | ServiceAccess::START)?;
        svc.set_description("Remote monitoring and management agent")?;
        svc.start::<&str>(&[])?;
        println!("RmmAgent service installed and started");
        Ok(())
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
        if let Err(e) = service_body() {
            // No console under SCM; the event log integration can come later.
            let _ = std::fs::write(std::env::temp_dir().join("rmm-agent-error.txt"), format!("{e:#}"));
        }
    }

    fn service_body() -> Result<()> {
        crate::install_crypto();
        let (tx, rx) = tokio::sync::watch::channel(false);
        let status = service_control_handler::register(NAME, move |ctrl| match ctrl {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                let _ = tx.send(true);
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        })?;
        let set = |state, accept| {
            status.set_service_status(ServiceStatus {
                service_type: ServiceType::OWN_PROCESS,
                current_state: state,
                controls_accepted: accept,
                exit_code: ServiceExitCode::Win32(0),
                checkpoint: 0,
                wait_hint: Duration::from_secs(10),
                process_id: None,
            })
        };
        set(ServiceState::Running, ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN)?;

        let cfg = crate::config::Config::load(CONFIG.get().expect("config path set"))?;
        crate::runtime()?.block_on(crate::conn::run_forever(cfg, rx));

        set(ServiceState::Stopped, ServiceControlAccept::empty())?;
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
