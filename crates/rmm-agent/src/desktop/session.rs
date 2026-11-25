//! Agent side of a desktop session: find the user's session, ask for consent, start the
//! helper there, and relay between it and the server.

use std::io::{BufRead, Read, Write};

use anyhow::{Context, Result};
use rmm_proto::AgentMsg;
use rmm_proto::desktop::{Consent, InputEvent, Settings};
use tokio::sync::{mpsc, oneshot};
use tracing::{info, warn};
use uuid::Uuid;

use super::{FromHelper, ToHelper, read_msg, write_msg};

/// A running helper process.
pub(crate) struct Helper {
    pub stdin: Box<dyn Write + Send>,
    pub stdout: Box<dyn Read + Send>,
    pub stderr: Box<dyn Read + Send>,
    pub process: Box<dyn Process>,
}

pub(crate) trait Process: Send {
    /// Stops the helper (if still running) and reaps it.
    fn kill(&mut self);
}

impl Process for std::process::Child {
    fn kill(&mut self) {
        let _ = std::process::Child::kill(self);
        let _ = self.wait();
    }
}

/// Starts `cmd` (an `rmm-agent desktop-helper` command line) with piped stdio.
pub(crate) fn spawn_command(mut cmd: std::process::Command) -> Result<Helper> {
    use std::process::Stdio;
    let mut child = cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().context("starting the desktop helper")?;
    Ok(Helper {
        stdin: Box::new(child.stdin.take().expect("piped")),
        stdout: Box::new(child.stdout.take().expect("piped")),
        stderr: Box::new(child.stderr.take().expect("piped")),
        process: Box::new(child),
    })
}

pub(crate) fn helper_command(exe: &std::path::Path) -> std::process::Command {
    let mut cmd = std::process::Command::new(exe);
    cmd.arg("desktop-helper");
    cmd
}

/// Where a session runs.
enum Target {
    /// `RMM_DESKTOP_FAKE`: the helper runs as the agent's user with a synthetic screen.
    /// Debug aid and e2e tests; see `fake.rs`.
    Fake,
    #[cfg(target_os = "linux")]
    Linux(super::linux::Display),
    #[cfg(windows)]
    Windows(super::win::ConsoleSession),
}

impl Target {
    fn find() -> Result<Target> {
        if std::env::var_os("RMM_DESKTOP_FAKE").is_some() {
            return Ok(Target::Fake);
        }
        #[cfg(target_os = "linux")]
        return Ok(Target::Linux(super::linux::Display::find()?));
        #[cfg(windows)]
        return Ok(Target::Windows(super::win::ConsoleSession::active()?));
        #[allow(unreachable_code)]
        {
            anyhow::bail!("remote desktop isn't supported on this platform yet")
        }
    }

    /// `Some(answer)`, or `None` when there is nobody to ask (no one signed in).
    fn ask(&self, c: &Consent) -> Result<Option<bool>> {
        match self {
            // The answer is in `<RMM_DESKTOP_FAKE>.consent` (`deny`; anything else allows).
            Target::Fake => {
                let _ = c;
                let mut path = std::env::var_os("RMM_DESKTOP_FAKE").unwrap_or_default();
                path.push(".consent");
                Ok(Some(std::fs::read_to_string(path).map(|a| a.trim() != "deny").unwrap_or(true)))
            }
            #[cfg(target_os = "linux")]
            Target::Linux(d) => d.ask(c),
            #[cfg(windows)]
            Target::Windows(s) => s.ask(c),
        }
    }

    /// The session a tray connection for this target reports (`tray::Peer::session`).
    fn tray_session(&self) -> Option<u32> {
        match self {
            Target::Fake => None,
            #[cfg(target_os = "linux")]
            Target::Linux(d) => (d.uid >= 1000).then_some(d.uid),
            #[cfg(windows)]
            Target::Windows(s) => Some(s.id()),
        }
    }

    fn spawn(&self) -> Result<Helper> {
        let exe = std::env::current_exe().context("locating the agent binary")?;
        match self {
            Target::Fake => spawn_command(helper_command(&exe)),
            #[cfg(target_os = "linux")]
            Target::Linux(d) => d.spawn(&exe),
            #[cfg(windows)]
            Target::Windows(s) => s.spawn(&exe),
        }
    }
}

#[cfg_attr(not(any(target_os = "linux", windows)), allow(dead_code))]
pub(crate) fn consent_text(c: &Consent, host: &str) -> (String, String) {
    let who = if c.company.trim().is_empty() { c.requester.clone() } else { format!("{} ({})", c.requester, c.company) };
    let product = c.product.trim();
    (
        if product.is_empty() { "Remote support request".into() } else { format!("{product}: remote support request") },
        format!(
            "{who} wants to view and control this computer ({host}).\n\nAllow the remote session? It is refused if nobody answers within {} seconds.",
            c.timeout_secs
        ),
    )
}

/// Handle kept by the connection loop. Dropping it ends the session.
pub struct DesktopSession {
    tx: mpsc::UnboundedSender<ToHelper>,
    sas: bool,
}

impl DesktopSession {
    pub fn open(session_id: Uuid, settings: Settings, consent: Option<Consent>, out: mpsc::Sender<AgentMsg>) -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        // Decided before the task starts so input arriving early is routed the same way.
        let sas = cfg!(windows) && std::env::var_os("RMM_DESKTOP_FAKE").is_none();
        tokio::spawn(async move {
            let reason = match serve(session_id, settings, consent, out.clone(), rx).await {
                Ok(r) => r,
                Err(e) => Some(format!("{e:#}")),
            };
            info!(%session_id, reason = reason.as_deref().unwrap_or(""), "desktop session ended");
            let _ = out.send(AgentMsg::DesktopClosed { session_id, reason }).await;
        }.instrument_session(session_id));
        DesktopSession { tx, sas }
    }

    pub fn settings(&self, settings: Settings) {
        let _ = self.tx.send(ToHelper::Settings { settings });
    }

    pub fn ack(&self, seq: u32) {
        let _ = self.tx.send(ToHelper::Ack { seq });
    }

    pub fn input(&self, mut events: Vec<InputEvent>) {
        if self.sas && events.iter().any(|e| matches!(e, InputEvent::CtrlAltDel)) {
            events.retain(|e| !matches!(e, InputEvent::CtrlAltDel));
            #[cfg(windows)]
            tokio::task::spawn_blocking(|| {
                if let Err(e) = super::win::send_sas() {
                    warn!("Ctrl+Alt+Del: {e:#}");
                }
            });
        }
        if !events.is_empty() {
            let _ = self.tx.send(ToHelper::Input { events });
        }
    }
}

/// Attaches the session id to the task's log lines.
trait InstrumentSession: Sized {
    fn instrument_session(self, id: Uuid) -> tracing::instrument::Instrumented<Self>;
}

impl<F: std::future::Future> InstrumentSession for F {
    fn instrument_session(self, id: Uuid) -> tracing::instrument::Instrumented<Self> {
        use tracing::Instrument;
        self.instrument(tracing::info_span!("desktop", session = %id))
    }
}

/// Runs a session until the server closes it or the helper ends. `Ok(reason)` for the
/// expected endings: `None` when the server closed it.
async fn serve(
    session_id: Uuid,
    settings: Settings,
    consent: Option<Consent>,
    out: mpsc::Sender<AgentMsg>,
    mut rx: mpsc::UnboundedReceiver<ToHelper>,
) -> Result<Option<String>> {
    let target = tokio::task::spawn_blocking(Target::find).await??;
    let target = std::sync::Arc::new(target);

    if let Some(c) = consent {
        let t = target.clone();
        // The tray connected for that session asks first, in the user's own session; without
        // one, the platform's prompt.
        let mut ask = std::pin::pin!(async move {
            if let (Some(tray), Some(session)) = (crate::tray::global(), t.tray_session()) {
                let host = crate::collect::system_info().hostname;
                let (title, text) = consent_text(&c, &host);
                if let Some(a) = tray.ask_consent(session, &title, &text, c.timeout_secs).await {
                    info!("asked through the tray");
                    return Ok(Some(a));
                }
            }
            tokio::task::spawn_blocking(move || t.ask(&c)).await?
        });
        let answer: Option<bool> = loop {
            tokio::select! {
                a = &mut ask => break a?,
                // Input and acks can't arrive before the first frame; only a close matters.
                m = rx.recv() => if m.is_none() { return Ok(None) },
            }
        };
        match answer {
            Some(false) => return Ok(Some("the user declined the session".into())),
            Some(true) => info!("the user allowed the session"),
            None => info!("nobody is signed in to ask; starting without consent"),
        }
    }

    let t = target.clone();
    let helper = tokio::task::spawn_blocking(move || t.spawn()).await??;
    info!("desktop helper started");
    if let Some(tray) = crate::tray::global() {
        tray.notice(true);
    }
    struct NoticeOff;
    impl Drop for NoticeOff {
        fn drop(&mut self) {
            if let Some(tray) = crate::tray::global() {
                tray.notice(false);
            }
        }
    }
    let _notice = NoticeOff;

    // Writer: messages for the helper's stdin.
    let (wtx, wrx) = std::sync::mpsc::channel::<ToHelper>();
    let mut stdin = helper.stdin;
    std::thread::Builder::new().name("desktop-to-helper".into()).spawn(move || {
        while let Ok(msg) = wrx.recv() {
            if write_msg(&mut stdin, &msg).is_err() {
                break;
            }
        }
        // Dropping stdin tells the helper to exit.
    })?;
    // Reader: frames to the server. Ends when the helper exits or the connection is gone.
    let (done_tx, mut done) = oneshot::channel::<Option<String>>();
    let mut stdout = helper.stdout;
    let session_out = out.clone();
    std::thread::Builder::new().name("desktop-from-helper".into()).spawn(move || {
        let mut error = None;
        loop {
            let msg = match read_msg::<FromHelper>(&mut stdout) {
                Ok(Some(m)) => m,
                Ok(None) => break,
                Err(e) => {
                    error = Some(format!("desktop helper: {e:#}"));
                    break;
                }
            };
            let msg = match msg {
                FromHelper::Info { monitors, monitor } => AgentMsg::DesktopInfo { session_id, monitors, monitor },
                FromHelper::Frame { frame } => AgentMsg::DesktopFrame { session_id, frame },
                FromHelper::Error { message } => {
                    error = Some(message);
                    break;
                }
            };
            if session_out.blocking_send(msg).is_err() {
                break;
            }
        }
        let _ = done_tx.send(error);
    })?;
    let stderr = helper.stderr;
    std::thread::Builder::new().name("desktop-helper-log".into()).spawn(move || {
        for line in std::io::BufReader::new(stderr).lines().map_while(Result::ok) {
            info!(target: "desktop_helper", "{line}");
        }
    })?;

    let _ = wtx.send(ToHelper::Settings { settings });
    let result = loop {
        tokio::select! {
            m = rx.recv() => match m {
                Some(m) => { let _ = wtx.send(m); }
                None => break None,
            },
            r = &mut done => break Some(r.ok().flatten().unwrap_or_else(|| "the desktop helper exited".into())),
        }
    };
    drop(wtx);
    let mut process = helper.process;
    tokio::task::spawn_blocking(move || process.kill()).await?;
    if let Some(r) = &result {
        warn!("desktop session failed: {r}");
    }
    Ok(result)
}
