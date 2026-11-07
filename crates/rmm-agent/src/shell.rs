//! Interactive PTY shells (bash/zsh on unix, PowerShell via ConPTY on Windows).

use std::io::{Read, Write};

use anyhow::{Context, Result};
use portable_pty::{Child, CommandBuilder, MasterPty, PtySize, native_pty_system};
use rmm_proto::AgentMsg;
use tokio::sync::mpsc;
use uuid::Uuid;

pub struct ShellSession {
    writer: Box<dyn Write + Send>,
    master: Box<dyn MasterPty + Send>,
    child: Box<dyn Child + Send + Sync>,
}

impl ShellSession {
    pub fn open(session_id: Uuid, cols: u16, rows: u16, out: mpsc::Sender<AgentMsg>) -> Result<Self> {
        let pty = native_pty_system();
        let pair = pty.openpty(size(cols, rows)).context("openpty")?;

        let mut cmd = CommandBuilder::new(default_shell());
        if cfg!(windows) {
            cmd.arg("-NoLogo");
        } else {
            cmd.arg("-l");
        }
        cmd.env("TERM", "xterm-256color");
        if let Some(home) = home_dir() {
            cmd.cwd(home);
        }

        let child = pair.slave.spawn_command(cmd).context("spawning shell")?;
        drop(pair.slave);

        let mut reader = pair.master.try_clone_reader().context("pty reader")?;
        let writer = pair.master.take_writer().context("pty writer")?;

        // PTY reads are blocking, so each session gets a small OS thread.
        std::thread::Builder::new().name(format!("pty-{session_id}")).spawn(move || {
            let mut buf = [0u8; 8192];
            loop {
                match reader.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if out.blocking_send(AgentMsg::ShellOutput { session_id, data: buf[..n].to_vec() }).is_err() {
                            return;
                        }
                    }
                }
            }
            let _ = out.blocking_send(AgentMsg::ShellClosed { session_id, reason: Some("shell exited".into()) });
        })?;

        Ok(Self { writer, master: pair.master, child })
    }

    pub fn write(&mut self, data: &[u8]) -> Result<()> {
        self.writer.write_all(data)?;
        self.writer.flush()?;
        Ok(())
    }

    pub fn resize(&self, cols: u16, rows: u16) -> Result<()> {
        self.master.resize(size(cols, rows))
    }
}

impl Drop for ShellSession {
    fn drop(&mut self) {
        let _ = self.child.kill();
    }
}

fn size(cols: u16, rows: u16) -> PtySize {
    PtySize { cols: cols.max(10), rows: rows.max(2), pixel_width: 0, pixel_height: 0 }
}

fn default_shell() -> String {
    if cfg!(windows) {
        return "powershell.exe".into();
    }
    if let Ok(sh) = std::env::var("SHELL")
        && !sh.is_empty() {
            return sh;
        }
    // systemd services usually have no $SHELL.
    if std::path::Path::new("/bin/bash").exists() { "/bin/bash".into() } else { "/bin/sh".into() }
}

fn home_dir() -> Option<std::path::PathBuf> {
    let var = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
    std::env::var_os(var).map(Into::into).or_else(|| (!cfg!(windows)).then(|| "/root".into()))
}
