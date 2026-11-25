//! The end-user tray app (docs/design/tray.md): `rmm-agent tray`, run as the signed-in user,
//! talking to the agent service over a local socket.
//!
//! - Windows: a notification-area icon with a menu (raw Win32, [`win`]), started at sign-in by
//!   the `HKLM\…\Run` value the MSI and `rmm-agent install` write. It stays connected so the
//!   service can route consent prompts and "technician connected" notices to it.
//! - Linux: no icon (that needs a D-Bus stack). The launcher in the applications menu opens the
//!   request form with zenity or kdialog; `--background`, started by the XDG autostart entry,
//!   stays connected for prompts and notices ([`linux`]).
//! - Everywhere: `--request` sends a request without any window (scripts and tests), and
//!   `--show-config` prints what the tray would show.
//!
//! The service end is [`server`]; the wire format [`ipc`].

pub mod ipc;
pub mod request;
pub mod server;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(windows)]
pub mod win;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use rmm_proto::tray::Config;
use tokio::io::{AsyncRead, AsyncWrite, ReadHalf, WriteHalf};
use tracing::{info, warn};

use ipc::{AgentToTray, Decoder, TrayToAgent};
pub use server::{Peer, Tray, global};

#[derive(clap::Args, Debug, Default)]
pub struct Args {
    /// Send a help request and exit, without any window.
    #[arg(long)]
    pub request: bool,
    #[arg(long, requires = "request")]
    pub subject: Option<String>,
    #[arg(long, requires = "request", default_value = "")]
    pub body: String,
    /// A JPEG or PNG to attach.
    #[arg(long, requires = "request")]
    pub screenshot: Option<PathBuf>,
    /// Print the contact card and settings the agent has, as JSON, and exit.
    #[arg(long, conflicts_with = "request")]
    pub show_config: bool,
    /// Stay connected without a window, showing consent prompts and notices (Linux autostart).
    #[arg(long, conflicts_with_all = ["request", "show_config"])]
    pub background: bool,
}

/// `rmm-agent tray`.
pub fn main(args: Args) -> Result<()> {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    if args.request {
        let subject = args.subject.clone().context("--request needs --subject")?;
        let shot = match &args.screenshot {
            Some(p) => std::fs::read(p).with_context(|| format!("reading {}", p.display()))?,
            None => vec![],
        };
        let reply = rt.block_on(async {
            let mut c = Client::connect(false).await?;
            c.request(&subject, &args.body, shot).await
        })?;
        return match reply {
            AgentToTray::HelpResult { error: Some(e), .. } => bail!("{e}"),
            AgentToTray::HelpResult { ticket_number: Some(n), .. } => {
                println!("ticket #{n} created");
                Ok(())
            }
            AgentToTray::HelpResult { request_id, .. } => {
                println!("queued: request {} will be sent when the agent reaches the server", request_id.map(|i| i.to_string()).unwrap_or_default());
                Ok(())
            }
            other => bail!("unexpected answer from the agent: {other:?}"),
        };
    }
    if args.show_config {
        let config = rt.block_on(async { Client::connect(false).await?.config().await })?;
        println!("{}", config_json(config.as_ref()));
        return Ok(());
    }
    drop(rt);
    #[cfg(windows)]
    return win::gui();
    #[cfg(target_os = "linux")]
    return if args.background { linux::background() } else { linux::gui() };
    #[allow(unreachable_code)]
    {
        let _ = args.background;
        bail!("the tray app isn't available on this platform yet; use --request")
    }
}

/// What `--show-config` prints: the config without the icon's bytes.
pub fn config_json(c: Option<&Config>) -> serde_json::Value {
    match c {
        None => serde_json::Value::Null,
        Some(c) => serde_json::json!({
            "enabled": c.enabled,
            "product_name": c.product_name,
            "contact": { "name": c.contact.name, "phone": c.contact.phone, "email": c.contact.email, "url": c.contact.url, "hours": c.contact.hours },
            "links": c.links.iter().map(|l| serde_json::json!({ "label": l.label, "url": l.url })).collect::<Vec<_>>(),
            "request_help": c.request_help,
            "screenshot_default": c.screenshot_default,
            "icon_png_bytes": c.icon_png.len(),
        }),
    }
}

/// The contact card as plain lines, for dialogs.
pub fn contact_text(c: &Config) -> String {
    let k = &c.contact;
    let mut lines = vec![];
    if !k.name.is_empty() {
        lines.push(k.name.clone());
    }
    for (label, v) in [("Phone", &k.phone), ("Email", &k.email), ("Web", &k.url), ("Hours", &k.hours)] {
        if !v.is_empty() {
            lines.push(format!("{label}: {v}"));
        }
    }
    lines.join("\n")
}

/// Only http(s) links are opened.
pub fn safe_url(u: &str) -> bool {
    (u.starts_with("https://") || u.starts_with("http://")) && u.len() < 2048 && !u.chars().any(|c| c.is_control() || c == '"' || c.is_whitespace())
}

/// The service's socket.
#[cfg(unix)]
pub fn socket_path() -> PathBuf {
    if let Some(p) = std::env::var_os("RMM_TRAY_SOCKET") {
        return PathBuf::from(p);
    }
    // Tests run the agent unprivileged with its own state directory.
    if std::env::var_os("RMM_STATE_DIR").is_some() {
        return crate::config::state_dir().join("tray.sock");
    }
    PathBuf::from("/run/rmm-agent/tray.sock")
}

/// Listens on the Unix socket, identifying each peer by `SO_PEERCRED`.
#[cfg(unix)]
pub(crate) async fn listen(tray: Arc<Tray>) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let path = socket_path();
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        if dir == std::path::Path::new("/run/rmm-agent") {
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755))?;
        }
    }
    let _ = std::fs::remove_file(&path);
    let listener = tokio::net::UnixListener::bind(&path).with_context(|| format!("binding {}", path.display()))?;
    // Any local user may connect; what they may do is decided per message.
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666))?;
    info!("tray socket at {}", path.display());
    loop {
        let (stream, _) = match listener.accept().await {
            Ok(s) => s,
            Err(e) => {
                warn!("tray socket accept: {e}");
                tokio::time::sleep(Duration::from_secs(1)).await;
                continue;
            }
        };
        let Ok(cred) = stream.peer_cred() else { continue };
        let peer = Peer { user: unix_user(cred.uid()), session: cred.uid() };
        tokio::spawn(tray.clone().serve(stream, peer));
    }
}

#[cfg(windows)]
pub(crate) async fn listen(tray: Arc<Tray>) -> Result<()> {
    win::listen(tray).await
}

#[cfg(not(any(unix, windows)))]
pub(crate) async fn listen(_tray: Arc<Tray>) -> Result<()> {
    bail!("no tray socket on this platform")
}

/// The login name for a uid, or `uid N` when it has none.
#[cfg(unix)]
pub fn unix_user(uid: u32) -> String {
    let mut buf = vec![0u8; 4096];
    // SAFETY: getpwuid_r writes into `pw` and `buf`, both owned here and large enough; `found`
    // is either null or points at `pw`.
    unsafe {
        let mut pw: libc::passwd = std::mem::zeroed();
        let mut found: *mut libc::passwd = std::ptr::null_mut();
        if libc::getpwuid_r(uid, &mut pw, buf.as_mut_ptr().cast(), buf.len(), &mut found) == 0 && !found.is_null() && !pw.pw_name.is_null() {
            let name = std::ffi::CStr::from_ptr(pw.pw_name).to_string_lossy().into_owned();
            if !name.is_empty() {
                return name;
            }
        }
    }
    format!("uid {uid}")
}

trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

/// The tray's end of a connection.
pub struct Client {
    r: ReadHalf<Box<dyn Io>>,
    w: WriteHalf<Box<dyn Io>>,
    dec: Decoder,
}

impl Client {
    pub async fn connect(link: bool) -> Result<Client> {
        #[cfg(unix)]
        let stream: Box<dyn Io> = Box::new(
            tokio::net::UnixStream::connect(socket_path())
                .await
                .with_context(|| format!("connecting to the agent at {} (is the agent running?)", socket_path().display()))?,
        );
        #[cfg(windows)]
        let stream: Box<dyn Io> = Box::new(win::connect().await?);
        #[cfg(not(any(unix, windows)))]
        let stream: Box<dyn Io> = bail!("no tray socket on this platform");
        let (r, w) = tokio::io::split(stream);
        let mut c = Client { r, w, dec: Decoder::default() };
        c.send(&TrayToAgent::Hello { version: crate::collect::AGENT_VERSION.into(), link }).await?;
        Ok(c)
    }

    pub async fn send(&mut self, m: &TrayToAgent) -> Result<()> {
        ipc::write(&mut self.w, m).await
    }

    pub async fn recv(&mut self) -> Result<Option<AgentToTray>> {
        ipc::read(&mut self.r, &mut self.dec).await
    }

    pub async fn config(&mut self) -> Result<Option<Config>> {
        self.send(&TrayToAgent::GetConfig).await?;
        loop {
            match self.recv().await? {
                Some(AgentToTray::Config { config }) => return Ok(config),
                Some(_) => continue,
                None => bail!("the agent closed the connection"),
            }
        }
    }

    /// Sends a request and waits for its [`AgentToTray::HelpResult`].
    pub async fn request(&mut self, subject: &str, body: &str, screenshot: Vec<u8>) -> Result<AgentToTray> {
        self.send(&TrayToAgent::HelpRequest { subject: subject.into(), body: body.into(), screenshot }).await?;
        loop {
            match self.recv().await? {
                Some(r @ AgentToTray::HelpResult { .. }) => return Ok(r),
                Some(_) => continue,
                None => bail!("the agent closed the connection before answering"),
            }
        }
    }
}

/// What a long-lived tray shows.
pub trait Ui: Send + Sync + 'static {
    fn config(&self, c: Option<Config>);
    /// Blocks until answered; `false` on a timeout.
    fn consent(&self, title: &str, text: &str, timeout_secs: u32) -> bool;
    fn notice(&self, text: &str, active: bool);
}

/// Keeps a link to the service, reconnecting, until the process ends.
pub async fn run_link(ui: Arc<dyn Ui>) {
    let mut backoff = Duration::from_secs(2);
    loop {
        match link_once(ui.clone()).await {
            Ok(()) => backoff = Duration::from_secs(2),
            Err(e) => info!("tray link: {e:#}"),
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(Duration::from_secs(30));
    }
}

async fn link_once(ui: Arc<dyn Ui>) -> Result<()> {
    let mut c = Client::connect(true).await?;
    c.send(&TrayToAgent::GetConfig).await?;
    let (answers_tx, mut answers) = tokio::sync::mpsc::unbounded_channel::<TrayToAgent>();
    let Client { mut r, mut w, mut dec } = c;
    loop {
        tokio::select! {
            m = ipc::read::<AgentToTray>(&mut r, &mut dec) => match m? {
                None => return Ok(()),
                Some(AgentToTray::Config { config }) => ui.config(config),
                Some(AgentToTray::Notice { text, active }) => ui.notice(&text, active),
                Some(AgentToTray::Consent { id, title, text, timeout_secs }) => {
                    let (ui, tx) = (ui.clone(), answers_tx.clone());
                    tokio::task::spawn_blocking(move || {
                        let allow = ui.consent(&title, &text, timeout_secs);
                        let _ = tx.send(TrayToAgent::ConsentAnswer { id, allow });
                    });
                }
                Some(AgentToTray::Restart) => restart(),
                Some(AgentToTray::Error { message }) => warn!("agent: {message}"),
                Some(AgentToTray::HelpResult { .. }) => {}
            },
            Some(a) = answers.recv() => ipc::write(&mut w, &a).await?,
        }
    }
}

/// Starts this tray again from the binary on disk (replaced by a self-update) and exits.
fn restart() -> ! {
    info!("the agent was updated; restarting the tray");
    if let Ok(exe) = std::env::current_exe() {
        // Linux names a replaced binary "/usr/bin/rmm-agent (deleted)".
        let exe = PathBuf::from(exe.to_string_lossy().trim_end_matches(" (deleted)").to_string());
        let _ = std::process::Command::new(exe).args(std::env::args_os().skip(1)).spawn();
    }
    std::process::exit(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cards_and_links() {
        let mut c = Config { product_name: "Acme".into(), ..Default::default() };
        assert_eq!(contact_text(&c), "");
        c.contact.name = "Acme IT".into();
        c.contact.phone = "+1 555".into();
        c.contact.hours = "9-5".into();
        assert_eq!(contact_text(&c), "Acme IT\nPhone: +1 555\nHours: 9-5");
        assert!(safe_url("https://status.example.com/x?y=1"));
        assert!(!safe_url("file:///etc/passwd"));
        assert!(!safe_url("javascript:alert(1)"));
        assert!(!safe_url("https://a b"));
        assert!(!safe_url("https://a\"&calc"));
        assert_eq!(config_json(None), serde_json::Value::Null);
        assert_eq!(config_json(Some(&c))["contact"]["phone"], "+1 555");
    }

    #[cfg(unix)]
    #[test]
    fn peer_identity() {
        // SAFETY: no preconditions.
        let me = unsafe { libc::getuid() };
        let name = unix_user(me);
        assert!(!name.is_empty() && !name.starts_with("uid "), "{name}");
        assert_eq!(unix_user(0), "root");
        assert_eq!(unix_user(4_000_000_000), "uid 4000000000");
    }

    /// The service and a client over a real socket.
    #[cfg(unix)]
    #[tokio::test]
    async fn over_a_unix_socket() {
        let dir = std::env::temp_dir().join(format!("rmm-tray-sock-{}", uuid::Uuid::new_v4().simple()));
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("t.sock");
        let tray = server::Tray::start_at(dir.clone());
        let listener = tokio::net::UnixListener::bind(&sock).unwrap();
        let t = tray.clone();
        tokio::spawn(async move {
            let (s, _) = listener.accept().await.unwrap();
            let cred = s.peer_cred().unwrap();
            t.serve(s, Peer { user: unix_user(cred.uid()), session: cred.uid() }).await;
        });
        let s: Box<dyn Io> = Box::new(tokio::net::UnixStream::connect(&sock).await.unwrap());
        let (r, w) = tokio::io::split(s);
        let mut c = Client { r, w, dec: Decoder::default() };
        c.send(&TrayToAgent::Hello { version: "x".into(), link: false }).await.unwrap();
        assert_eq!(c.config().await.unwrap(), None);
        let r = c.request("From a test", "", vec![]).await.unwrap();
        assert!(matches!(r, AgentToTray::HelpResult { queued: true, .. }), "{r:?}");
        let pending = tray.pending();
        assert_eq!(pending.len(), 1);
        // SAFETY: no preconditions.
        assert_eq!(pending[0].session, unsafe { libc::getuid() }, "the peer's uid, not anything the client said");
        let _ = std::fs::remove_dir_all(dir);
    }
}
