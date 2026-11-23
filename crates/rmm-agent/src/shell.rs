//! Interactive PTY shells (bash/zsh on unix, PowerShell via ConPTY on Windows).

use std::io::{Read, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{Context, Result};
use portable_pty::{Child, CommandBuilder, MasterPty, PtySize, native_pty_system};
use rmm_proto::AgentMsg;
use tokio::sync::mpsc;
use uuid::Uuid;

pub struct ShellSession {
    writer: Box<dyn Write + Send>,
    master: Box<dyn MasterPty + Send>,
    child: Box<dyn Child + Send + Sync>,
    /// Everything started from the terminal, killed when the session closes.
    #[cfg(windows)]
    tree: Option<crate::winjob::ProcessTree>,
    /// Ends the Windows exit watcher (see [`watch_exit`]).
    #[cfg(windows)]
    stop: Arc<AtomicBool>,
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
        // Assigned before the session is returned, so before anything is typed into it.
        #[cfg(windows)]
        let tree = child.as_raw_handle().and_then(|h| match crate::winjob::ProcessTree::new(h, true) {
            Ok(t) => Some(t),
            Err(e) => {
                tracing::warn!(%session_id, "closing this shell will only kill PowerShell itself: {e:#}");
                None
            }
        });

        let mut reader = pair.master.try_clone_reader().context("pty reader")?;
        let writer = pair.master.take_writer().context("pty writer")?;
        // Whichever of the reader thread and the exit watcher notices the end reports it.
        let closed = Arc::new(AtomicBool::new(false));
        #[cfg(windows)]
        let stop = Arc::new(AtomicBool::new(false));
        #[cfg(windows)]
        if let Some(pid) = child.process_id() {
            watch_exit(session_id, pid, out.clone(), closed.clone(), stop.clone());
        }
        let reader_closed = closed.clone();

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
            if !reader_closed.swap(true, Ordering::SeqCst) {
                let _ = out.blocking_send(AgentMsg::ShellClosed { session_id, reason: Some("shell exited".into()) });
            }
        })?;

        Ok(Self {
            writer,
            master: pair.master,
            child,
            #[cfg(windows)]
            tree,
            #[cfg(windows)]
            stop,
        })
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
        #[cfg(unix)]
        if let Some(pid) = self.child.process_id() {
            kill_session(pid);
        }
        // Kill-on-close would do this when the handle drops; terminate first so the shell
        // goes with its children rather than after them.
        #[cfg(windows)]
        {
            self.stop.store(true, Ordering::SeqCst);
            if let Some(t) = self.tree.take() {
                t.kill();
            }
        }
        let _ = self.child.kill();
    }
}

/// Windows: a ConPTY's output pipe stays open after the shell exits, until the pseudo console
/// is closed, so the reader thread never sees the end when someone types `exit` and the
/// console would sit on a dead terminal. This waits on the shell process itself (a handle of
/// its own, so it can't outlive or race the session's) and reports the exit. It gives up once
/// the session is dropped (`stop`).
#[cfg(windows)]
fn watch_exit(session_id: Uuid, pid: u32, out: mpsc::Sender<AgentMsg>, closed: Arc<AtomicBool>, stop: Arc<AtomicBool>) {
    use windows::Win32::Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0};
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_SYNCHRONIZE, WaitForSingleObject};
    // SAFETY: plain Win32 calls; the handle is closed exactly once, on every path below.
    let Ok(handle) = (unsafe { OpenProcess(PROCESS_SYNCHRONIZE, false, pid) }) else { return };
    // A HANDLE isn't Send; the thread gets its address and owns the handle from here.
    let raw = handle.0 as usize;
    let spawned = std::thread::Builder::new().name(format!("pty-exit-{session_id}")).spawn(move || {
        let handle = HANDLE(raw as *mut std::ffi::c_void);
        while !stop.load(Ordering::SeqCst) {
            if unsafe { WaitForSingleObject(handle, 500) } == WAIT_OBJECT_0 {
                if !closed.swap(true, Ordering::SeqCst) {
                    let _ = out.blocking_send(AgentMsg::ShellClosed { session_id, reason: Some("shell exited".into()) });
                }
                break;
            }
        }
        unsafe {
            let _ = CloseHandle(handle);
        }
    });
    if spawned.is_err() {
        unsafe {
            let _ = CloseHandle(handle);
        }
    }
}

/// The shell leads its own session (portable-pty calls `setsid`), so everything started
/// from the terminal, background jobs in other process groups included, shares its
/// session id. Send SIGHUP, as a closed terminal would, then SIGKILL whatever is left.
/// Only processes that started a new session themselves (`setsid`, `systemd-run`) escape.
#[cfg(unix)]
fn kill_session(leader: u32) {
    let Ok(leader) = i32::try_from(leader) else { return };
    // SAFETY: plain syscalls; a negative pid targets the shell's process group.
    unsafe {
        libc::kill(-leader, libc::SIGHUP);
    }
    let _ = std::thread::Builder::new().name("pty-reaper".into()).spawn(move || {
        std::thread::sleep(std::time::Duration::from_secs(2));
        for pid in session_members(leader) {
            unsafe {
                libc::kill(pid, libc::SIGKILL);
            }
        }
        unsafe {
            libc::kill(-leader, libc::SIGKILL);
        }
    });
}

#[cfg(target_os = "linux")]
fn session_members(sid: i32) -> Vec<i32> {
    let Ok(dir) = std::fs::read_dir("/proc") else { return vec![] };
    dir.filter_map(|e| e.ok()?.file_name().to_str()?.parse::<i32>().ok())
        .filter(|&pid| pid != sid && unsafe { libc::getsid(pid) } == sid)
        .collect()
}

/// No /proc: the process-group kill above is all we can do.
#[cfg(all(unix, not(target_os = "linux")))]
fn session_members(_sid: i32) -> Vec<i32> {
    vec![]
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
