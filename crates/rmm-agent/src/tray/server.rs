//! The service's end of the tray socket.
//!
//! Every local user can connect, so a tray is untrusted. It may read the contact card, submit a
//! help request (checked, limited to [`request::PER_HOUR`] per user, kept on disk until the
//! server answers), and answer a consent prompt that was sent to *its* connection. Nothing
//! else: no paths, no commands.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use anyhow::Result;
use chrono::Utc;
use rmm_proto::AgentMsg;
use rmm_proto::tray::{CHUNK, Config, Context};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{mpsc, oneshot};
use tracing::{info, warn};
use uuid::Uuid;

use super::ipc::{self, AgentToTray, Decoder, TrayToAgent};
use super::request::{self, Limiter, Pending, Store};

/// Connections at once, all users together.
const MAX_CONNECTIONS: usize = 64;
/// Long-lived trays per session (a user may have the icon and a script running).
const MAX_LINKS_PER_SESSION: usize = 4;
/// How long a one-off connection may sit idle, and how long a new one has to say hello.
const IDLE: Duration = Duration::from_secs(120);
const HELLO: Duration = Duration::from_secs(10);
/// How long a tray waits for the ticket number before being told the request is queued.
const RESULT_WAIT: Duration = Duration::from_secs(30);

/// Who is on the other end, as the operating system says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Peer {
    /// `DOMAIN\user` on Windows, the login name on Unix.
    pub user: String,
    /// The Windows session id; the uid on Unix.
    pub session: u32,
}

struct LinkConn {
    session: u32,
    tx: mpsc::UnboundedSender<AgentToTray>,
}

/// The server's answer: a ticket number or why not.
type Answer = (Option<i64>, Option<String>);

#[derive(Default)]
struct Inner {
    server: Option<mpsc::Sender<AgentMsg>>,
    config: Option<Config>,
    limiter: Limiter,
    waiters: HashMap<Uuid, oneshot::Sender<Answer>>,
    links: HashMap<u64, LinkConn>,
    /// Consent prompts out: which connection may answer, and who is waiting.
    consents: HashMap<Uuid, (u64, oneshot::Sender<bool>)>,
    connections: usize,
    next_conn: u64,
    /// The technician notice currently showing, for trays that connect during a session.
    notice: Option<String>,
}

pub struct Tray {
    inner: Mutex<Inner>,
    store: Store,
    config_path: PathBuf,
}

static GLOBAL: OnceLock<Arc<Tray>> = OnceLock::new();

/// The running service's tray end, once [`Tray::start`] ran.
pub fn global() -> Option<Arc<Tray>> {
    GLOBAL.get().cloned()
}

fn lock(m: &Mutex<Inner>) -> std::sync::MutexGuard<'_, Inner> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl Tray {
    /// Opens the state directory and starts listening. Failing to listen only disables the tray.
    pub fn start() -> Arc<Tray> {
        let dir = crate::config::state_subdir("tray").unwrap_or_else(|e| {
            warn!("tray state directory: {e:#}");
            crate::config::state_dir().join("tray")
        });
        let config_path = dir.join("config.bin");
        let tray = Arc::new(Tray {
            inner: Mutex::new(Inner { config: request::load_cached(&config_path), ..Default::default() }),
            store: Store::open(dir.join("requests")),
            config_path,
        });
        let _ = GLOBAL.set(tray.clone());
        let t = tray.clone();
        tokio::spawn(async move {
            if let Err(e) = super::listen(t).await {
                warn!("the tray socket isn't available: {e:#}");
            }
        });
        tray
    }

    /// Without a listener (tests).
    #[cfg(test)]
    pub(crate) fn start_at(dir: PathBuf) -> Arc<Tray> {
        Arc::new(Tray { inner: Mutex::new(Inner::default()), store: Store::open(dir.join("requests")), config_path: dir.join("config.bin") })
    }

    #[cfg(all(test, unix))]
    pub(crate) fn pending(&self) -> Vec<Pending> {
        self.store.list()
    }

    /// Connected: send what is waiting.
    pub fn attach(self: &Arc<Self>, tx: mpsc::Sender<AgentMsg>) {
        lock(&self.inner).server = Some(tx.clone());
        let pending = self.store.list();
        if pending.is_empty() {
            return;
        }
        info!(requests = pending.len(), "sending help requests kept while offline");
        let me = self.clone();
        tokio::spawn(async move {
            for p in pending {
                if me.send(&tx, &p).await.is_err() {
                    break;
                }
            }
        });
    }

    pub fn detach(&self) {
        lock(&self.inner).server = None;
    }

    pub fn set_config(&self, config: Config) {
        if let Err(e) = request::save_cached(&self.config_path, &config) {
            warn!("caching the tray configuration: {e:#}");
        }
        let mut inner = lock(&self.inner);
        if inner.config.as_ref() == Some(&config) {
            return;
        }
        for l in inner.links.values() {
            let _ = l.tx.send(AgentToTray::Config { config: Some(config.clone()) });
        }
        inner.config = Some(config);
    }

    /// The server's answer to a help request; final either way.
    pub fn result(&self, request_id: Uuid, ticket_number: Option<i64>, error: Option<String>) {
        self.store.remove(request_id);
        match (&ticket_number, &error) {
            (_, Some(e)) => warn!(%request_id, "help request refused: {e}"),
            (Some(n), None) => info!(%request_id, ticket = n, "help request became a ticket"),
            (None, None) => {}
        }
        if let Some(w) = lock(&self.inner).waiters.remove(&request_id) {
            let _ = w.send((ticket_number, error));
        }
    }

    /// Asks through the tray connected for `session`. `None` when there's no tray to ask (or it
    /// went away): the caller falls back to its own prompt. No answer in time denies.
    pub async fn ask_consent(&self, session: u32, title: &str, text: &str, timeout_secs: u32) -> Option<bool> {
        let id = Uuid::new_v4();
        let (tx, rx) = oneshot::channel();
        {
            let mut inner = lock(&self.inner);
            let (conn, link) = inner.links.iter().filter(|(_, l)| l.session == session).max_by_key(|(id, _)| **id)?;
            let conn = *conn;
            link.tx.send(AgentToTray::Consent { id, title: title.into(), text: text.into(), timeout_secs }).ok()?;
            inner.consents.insert(id, (conn, tx));
        }
        let answer = tokio::time::timeout(Duration::from_secs(u64::from(timeout_secs.max(5)) + 5), rx).await;
        lock(&self.inner).consents.remove(&id);
        match answer {
            Ok(Ok(a)) => Some(a),
            Ok(Err(_)) => None,
            Err(_) => Some(false),
        }
    }

    /// Tells every tray that a technician connected (or left).
    pub fn notice(&self, active: bool) {
        let mut inner = lock(&self.inner);
        let product = inner.config.as_ref().map(|c| c.product_name.clone()).filter(|p| !p.is_empty()).unwrap_or_else(|| "Support".into());
        let text = if active {
            format!("{product}: a technician is connected to this computer.")
        } else {
            format!("{product}: the technician has disconnected.")
        };
        inner.notice = active.then(|| text.clone());
        for l in inner.links.values() {
            let _ = l.tx.send(AgentToTray::Notice { text: text.clone(), active });
        }
    }

    /// One request up to the server: the request, then its screenshot in pieces.
    async fn send(&self, tx: &mpsc::Sender<AgentMsg>, p: &Pending) -> Result<(), ()> {
        let shot = self.store.screenshot(p);
        let msg = AgentMsg::HelpRequest {
            request_id: p.request_id,
            user: p.user.clone(),
            session: p.session,
            subject: p.subject.clone(),
            body: p.body.clone(),
            context: context(p),
            screenshot_len: shot.len() as u32,
        };
        tx.send(msg).await.map_err(|_| ())?;
        if shot.is_empty() {
            return Ok(());
        }
        let n = shot.len().div_ceil(CHUNK);
        for (i, piece) in shot.chunks(CHUNK).enumerate() {
            let msg = AgentMsg::HelpAttachment { request_id: p.request_id, offset: (i * CHUNK) as u32, data: piece.to_vec(), done: i + 1 == n };
            tx.send(msg).await.map_err(|_| ())?;
        }
        Ok(())
    }

    async fn help(self: &Arc<Self>, peer: &Peer, subject: String, body: String, screenshot: Vec<u8>) -> AgentToTray {
        let refuse = |message: String| AgentToTray::HelpResult { request_id: None, ticket_number: None, queued: false, error: Some(message) };
        let (subject, body) = match request::validate(&subject, &body, &screenshot) {
            Ok(v) => v,
            Err(e) => return refuse(e),
        };
        {
            let mut inner = lock(&self.inner);
            if let Some(c) = &inner.config
                && (!c.enabled || !c.request_help)
            {
                return refuse("help requests are turned off for this computer".into());
            }
            if let Err(wait) = inner.limiter.check(&peer.user, Instant::now()) {
                return refuse(format!(
                    "you have sent {} help requests in the last hour; try again in {} minutes, or call the help desk",
                    request::PER_HOUR,
                    wait.as_secs().div_ceil(60)
                ));
            }
        }
        let p = Pending {
            request_id: Uuid::new_v4(),
            user: peer.user.clone(),
            session: peer.session,
            subject,
            body,
            created_at: Utc::now(),
            screenshot: None,
        };
        let p = match self.store.add(p, &screenshot) {
            Ok(p) => p,
            Err(e) => return refuse(e),
        };
        info!(request_id = %p.request_id, user = %p.user, screenshot = screenshot.len(), "help request from the tray");
        let (wtx, wrx) = oneshot::channel();
        let server = {
            let mut inner = lock(&self.inner);
            inner.waiters.insert(p.request_id, wtx);
            inner.server.clone()
        };
        let queued = AgentToTray::HelpResult { request_id: Some(p.request_id), ticket_number: None, queued: true, error: None };
        let sent = match server {
            Some(tx) => self.send(&tx, &p).await.is_ok(),
            None => false,
        };
        let reply = if sent {
            match tokio::time::timeout(RESULT_WAIT, wrx).await {
                Ok(Ok((ticket_number, error))) => {
                    AgentToTray::HelpResult { request_id: Some(p.request_id), ticket_number, queued: false, error }
                }
                _ => queued,
            }
        } else {
            queued
        };
        lock(&self.inner).waiters.remove(&p.request_id);
        reply
    }

    /// Serves one connection until it closes.
    pub async fn serve<S: AsyncRead + AsyncWrite + Send + 'static>(self: Arc<Self>, stream: S, peer: Peer) {
        let conn = {
            let mut inner = lock(&self.inner);
            if inner.connections >= MAX_CONNECTIONS {
                warn!(user = %peer.user, "too many tray connections; refusing one");
                return;
            }
            inner.connections += 1;
            inner.next_conn += 1;
            inner.next_conn
        };
        if let Err(e) = self.clone().serve_inner(stream, &peer, conn).await {
            info!(user = %peer.user, "tray connection ended: {e:#}");
        }
        let mut inner = lock(&self.inner);
        inner.connections -= 1;
        inner.links.remove(&conn);
        inner.consents.retain(|_, (c, _)| *c != conn);
    }

    async fn serve_inner<S: AsyncRead + AsyncWrite + Send + 'static>(self: Arc<Self>, stream: S, peer: &Peer, conn: u64) -> Result<()> {
        let (mut r, mut w) = tokio::io::split(stream);
        let (tx, mut rx) = mpsc::unbounded_channel::<AgentToTray>();
        let writer = tokio::spawn(async move {
            while let Some(m) = rx.recv().await {
                if ipc::write(&mut w, &m).await.is_err() {
                    break;
                }
            }
        });
        let mut dec = Decoder::default();
        let link = match tokio::time::timeout(HELLO, ipc::read::<TrayToAgent>(&mut r, &mut dec)).await {
            Ok(Ok(Some(TrayToAgent::Hello { version, link }))) => {
                if link {
                    let mut inner = lock(&self.inner);
                    if inner.links.values().filter(|l| l.session == peer.session).count() >= MAX_LINKS_PER_SESSION {
                        anyhow::bail!("too many trays in session {}", peer.session);
                    }
                    inner.links.insert(conn, LinkConn { session: peer.session, tx: tx.clone() });
                    if let Some(text) = &inner.notice {
                        let _ = tx.send(AgentToTray::Notice { text: text.clone(), active: true });
                    }
                }
                // An older tray binary still running after a self-update: start the new one.
                if link && version != crate::collect::AGENT_VERSION {
                    let _ = tx.send(AgentToTray::Restart);
                }
                link
            }
            Ok(Ok(None)) => return Ok(()),
            Ok(Ok(Some(_))) => anyhow::bail!("expected hello"),
            Ok(Err(e)) => return Err(e),
            Err(_) => anyhow::bail!("no hello"),
        };
        let mut asked: HashSet<Uuid> = HashSet::new();
        loop {
            let msg = if link {
                ipc::read::<TrayToAgent>(&mut r, &mut dec).await?
            } else {
                match tokio::time::timeout(IDLE, ipc::read::<TrayToAgent>(&mut r, &mut dec)).await {
                    Ok(m) => m?,
                    Err(_) => break,
                }
            };
            let Some(msg) = msg else { break };
            match msg {
                TrayToAgent::Hello { .. } => anyhow::bail!("hello twice"),
                TrayToAgent::GetConfig => {
                    let config = lock(&self.inner).config.clone();
                    let _ = tx.send(AgentToTray::Config { config });
                }
                TrayToAgent::HelpRequest { subject, body, screenshot } => {
                    // Not in the read loop: a link must stay able to answer prompts meanwhile.
                    let (me, tx, peer) = (self.clone(), tx.clone(), peer.clone());
                    tokio::spawn(async move {
                        let reply = me.help(&peer, subject, body, screenshot).await;
                        let _ = tx.send(reply);
                    });
                }
                TrayToAgent::ConsentAnswer { id, allow } => {
                    // Only the connection the prompt went to may answer it, once.
                    if !asked.insert(id) {
                        continue;
                    }
                    let mut inner = lock(&self.inner);
                    if inner.consents.get(&id).is_some_and(|(c, _)| *c == conn)
                        && let Some((_, waiter)) = inner.consents.remove(&id)
                    {
                        let _ = waiter.send(allow);
                    }
                }
            }
        }
        drop(tx);
        lock(&self.inner).links.remove(&conn);
        let _ = tokio::time::timeout(Duration::from_secs(5), writer).await;
        Ok(())
    }
}

/// What the request goes up with.
fn context(p: &Pending) -> Context {
    let networks = sysinfo::Networks::new_with_refreshed_list().ok();
    let mut ips: Vec<String> = networks
        .iter()
        .flat_map(|n| n.into_iter().map(|(_, d)| d))
        .flat_map(|n| n.ip_networks().iter().map(|ip| ip.addr))
        .filter(|a| !a.is_loopback() && !matches!(a, std::net::IpAddr::V6(v6) if (v6.segments()[0] & 0xffc0) == 0xfe80))
        .map(|a| a.to_string())
        .collect();
    ips.sort();
    ips.dedup();
    ips.truncate(16);
    Context {
        uptime_secs: sysinfo::System::uptime().unwrap_or(0),
        ips,
        queued_secs: (Utc::now() - p.created_at).num_seconds().max(0) as u64,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir() -> PathBuf {
        std::env::temp_dir().join(format!("rmm-tray-srv-{}", Uuid::new_v4()))
    }

    async fn connect(t: &Arc<Tray>, peer: Peer, link: bool) -> (tokio::io::DuplexStream, Decoder) {
        let (a, mut b) = tokio::io::duplex(1 << 20);
        tokio::spawn(t.clone().serve(a, peer));
        ipc::write(&mut b, &TrayToAgent::Hello { version: crate::collect::AGENT_VERSION.into(), link }).await.unwrap();
        (b, Decoder::default())
    }

    fn alice() -> Peer {
        Peer { user: "alice".into(), session: 7 }
    }

    #[tokio::test]
    async fn offline_requests_queue_and_go_up_on_attach() {
        let d = dir();
        let t = Tray::start_at(d.clone());
        let (mut s, mut dec) = connect(&t, alice(), false).await;
        let shot = [0xff, 0xd8, 0xff, 0xe0].iter().copied().chain(std::iter::repeat_n(7u8, CHUNK + 10)).collect::<Vec<u8>>();
        ipc::write(&mut s, &TrayToAgent::HelpRequest { subject: "Help".into(), body: "b".into(), screenshot: shot.clone() }).await.unwrap();
        let AgentToTray::HelpResult { request_id: Some(id), queued: true, .. } = ipc::read(&mut s, &mut dec).await.unwrap().unwrap() else { panic!() };
        // The server comes back: request, then two pieces.
        let (tx, mut rx) = mpsc::channel(16);
        t.attach(tx);
        let Some(AgentMsg::HelpRequest { request_id, user, session, screenshot_len, .. }) = rx.recv().await else { panic!() };
        assert_eq!((request_id, user.as_str(), session, screenshot_len as usize), (id, "alice", 7, shot.len()));
        let Some(AgentMsg::HelpAttachment { offset: 0, done: false, data, .. }) = rx.recv().await else { panic!() };
        assert_eq!(data.len(), CHUNK);
        let Some(AgentMsg::HelpAttachment { offset, done: true, .. }) = rx.recv().await else { panic!() };
        assert_eq!(offset as usize, CHUNK);
        t.result(id, Some(12), None);
        assert!(t.store.list().is_empty(), "answered: forgotten");
        let _ = std::fs::remove_dir_all(d);
    }

    #[tokio::test]
    async fn online_request_gets_its_ticket_number_and_limits_apply() {
        let d = dir();
        let t = Tray::start_at(d.clone());
        let (tx, mut rx) = mpsc::channel(16);
        t.attach(tx);
        let t2 = t.clone();
        tokio::spawn(async move {
            let mut n = 100;
            while let Some(m) = rx.recv().await {
                if let AgentMsg::HelpRequest { request_id, .. } = m {
                    n += 1;
                    t2.result(request_id, Some(n), None);
                }
            }
        });
        let (mut s, mut dec) = connect(&t, alice(), false).await;
        for i in 0..request::PER_HOUR {
            ipc::write(&mut s, &TrayToAgent::HelpRequest { subject: format!("r{i}"), body: String::new(), screenshot: vec![] }).await.unwrap();
            let r = ipc::read::<AgentToTray>(&mut s, &mut dec).await.unwrap().unwrap();
            let AgentToTray::HelpResult { ticket_number: Some(n), queued: false, error: None, .. } = r else { panic!("{r:?}") };
            assert_eq!(n, 101 + i as i64);
        }
        ipc::write(&mut s, &TrayToAgent::HelpRequest { subject: "sixth".into(), body: String::new(), screenshot: vec![] }).await.unwrap();
        let r = ipc::read::<AgentToTray>(&mut s, &mut dec).await.unwrap().unwrap();
        assert!(matches!(&r, AgentToTray::HelpResult { error: Some(e), .. } if e.contains("last hour")), "{r:?}");
        // Bad input never reaches the server.
        ipc::write(&mut s, &TrayToAgent::HelpRequest { subject: " ".into(), body: String::new(), screenshot: vec![] }).await.unwrap();
        assert!(matches!(ipc::read::<AgentToTray>(&mut s, &mut dec).await.unwrap().unwrap(), AgentToTray::HelpResult { error: Some(_), .. }));
        // Turned off by policy.
        t.set_config(Config { enabled: true, request_help: false, ..Default::default() });
        let (mut s, mut dec) = connect(&t, Peer { user: "bob".into(), session: 8 }, false).await;
        ipc::write(&mut s, &TrayToAgent::HelpRequest { subject: "x".into(), body: String::new(), screenshot: vec![] }).await.unwrap();
        let r = ipc::read::<AgentToTray>(&mut s, &mut dec).await.unwrap().unwrap();
        assert!(matches!(&r, AgentToTray::HelpResult { error: Some(e), .. } if e.contains("turned off")), "{r:?}");
        let _ = std::fs::remove_dir_all(d);
    }

    #[tokio::test]
    async fn consent_goes_to_the_sessions_link_only() {
        let d = dir();
        let t = Tray::start_at(d.clone());
        assert_eq!(t.ask_consent(7, "t", "x", 5).await, None, "no tray: fall back");
        let (mut other, mut odec) = connect(&t, Peer { user: "bob".into(), session: 8 }, true).await;
        let (mut s, mut dec) = connect(&t, alice(), true).await;
        // Let both register.
        ipc::write(&mut s, &TrayToAgent::GetConfig).await.unwrap();
        assert_eq!(ipc::read::<AgentToTray>(&mut s, &mut dec).await.unwrap(), Some(AgentToTray::Config { config: None }));
        ipc::write(&mut other, &TrayToAgent::GetConfig).await.unwrap();
        ipc::read::<AgentToTray>(&mut other, &mut odec).await.unwrap();
        let t2 = t.clone();
        let ask = tokio::spawn(async move { t2.ask_consent(7, "title", "text", 5).await });
        let Some(AgentToTray::Consent { id, .. }) = ipc::read(&mut s, &mut dec).await.unwrap() else { panic!() };
        // Another session can't answer it.
        ipc::write(&mut other, &TrayToAgent::ConsentAnswer { id, allow: true }).await.unwrap();
        ipc::write(&mut s, &TrayToAgent::ConsentAnswer { id, allow: false }).await.unwrap();
        assert_eq!(ask.await.unwrap(), Some(false));
        t.notice(true);
        assert!(matches!(ipc::read(&mut s, &mut dec).await.unwrap(), Some(AgentToTray::Notice { active: true, .. })));
        let _ = std::fs::remove_dir_all(d);
    }

    #[tokio::test]
    async fn junk_and_silence_end_the_connection() {
        let t = Tray::start_at(dir());
        let (a, mut b) = tokio::io::duplex(1024);
        let h = tokio::spawn(t.clone().serve(a, alice()));
        use tokio::io::AsyncWriteExt;
        b.write_all(&[3, 0, 0, 0, 0xc1, 0xc1, 0xc1]).await.unwrap();
        tokio::time::timeout(Duration::from_secs(5), h).await.unwrap().unwrap();
        assert_eq!(lock(&t.inner).connections, 0);
        let (a, mut b) = tokio::io::duplex(1024);
        let h = tokio::spawn(t.clone().serve(a, alice()));
        b.write_all(&(u32::MAX).to_le_bytes()).await.unwrap();
        tokio::time::timeout(Duration::from_secs(5), h).await.unwrap().unwrap();
    }
}
