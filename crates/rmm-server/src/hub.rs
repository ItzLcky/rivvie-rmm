//! In-memory registry of connected agents and live shell sessions.
//!
//! Single-node for now. To scale horizontally, swap this for a pub/sub
//! (Postgres LISTEN/NOTIFY or NATS) keyed by agent id.

use std::collections::HashMap;
use std::sync::RwLock;

use rmm_proto::ServerMsg;
use serde::Serialize;
use tokio::sync::{broadcast, mpsc};
use uuid::Uuid;

/// Something the dashboard should redraw: pushed to browsers over `/api/events`.
///
/// `client_id` scopes delivery: users only get events for clients they can see. `None`
/// carries no data about any one client and goes to everyone.
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Event {
    /// Came online, went offline, or sent fresh metrics.
    Agent {
        id: Uuid,
        #[serde(skip)]
        client_id: Uuid,
        online: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        last_metrics: Option<serde_json::Value>,
    },
    /// A job was created, changed status, or produced output (`output: true`).
    Job {
        id: Uuid,
        agent_id: Uuid,
        #[serde(skip)]
        client_id: Uuid,
        status: String,
        output: bool,
    },
    /// Many jobs changed at once (the housekeeping sweep): refetch job lists.
    Jobs,
}

impl Event {
    pub fn client_id(&self) -> Option<Uuid> {
        match self {
            Event::Agent { client_id, .. } | Event::Job { client_id, .. } => Some(*client_id),
            Event::Jobs => None,
        }
    }
}

#[derive(Clone)]
pub struct AgentHandle {
    pub conn_id: Uuid,
    pub tx: mpsc::Sender<ServerMsg>,
}

pub enum ShellEvent {
    Opened,
    Output(Vec<u8>),
    Closed(Option<String>),
}

struct ShellRoute {
    agent_id: Uuid,
    tx: mpsc::Sender<ShellEvent>,
}

pub struct Hub {
    agents: RwLock<HashMap<Uuid, AgentHandle>>,
    shells: RwLock<HashMap<Uuid, ShellRoute>>,
    events: broadcast::Sender<Event>,
}

impl Default for Hub {
    fn default() -> Self {
        // A browser that falls this far behind gets a `resync` and refetches instead.
        let (events, _) = broadcast::channel(4096);
        Hub { agents: Default::default(), shells: Default::default(), events }
    }
}

impl Hub {
    /// Publishes to every open dashboard. Never blocks; a no-op when nobody is listening.
    pub fn publish(&self, ev: Event) {
        let _ = self.events.send(ev);
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.events.subscribe()
    }

    /// Registers a connection, returning the one it replaced (if the agent reconnected).
    pub fn register(&self, agent_id: Uuid, handle: AgentHandle) -> Option<AgentHandle> {
        self.agents.write().unwrap().insert(agent_id, handle)
    }

    /// Removes the agent only if `conn_id` is still the current connection. Returns true if
    /// the agent is now offline (false if a newer connection has replaced this one).
    pub fn unregister(&self, agent_id: Uuid, conn_id: Uuid) -> bool {
        let mut agents = self.agents.write().unwrap();
        match agents.get(&agent_id) {
            Some(h) if h.conn_id == conn_id => {
                agents.remove(&agent_id);
                true
            }
            Some(_) => false,
            // Kicked (agent deleted or re-enrolled) while this connection was open.
            None => true,
        }
    }

    /// Force-disconnect (e.g. agent deleted). Dropping the sender ends its writer task.
    pub fn kick(&self, agent_id: Uuid) {
        self.agents.write().unwrap().remove(&agent_id);
        self.drop_agent_shells(agent_id);
    }

    pub fn is_online(&self, agent_id: Uuid) -> bool {
        self.agents.read().unwrap().contains_key(&agent_id)
    }

    pub fn online_count(&self) -> usize {
        self.agents.read().unwrap().len()
    }

    /// Sends to a connected agent; returns false if it is offline or its queue is gone.
    pub async fn send(&self, agent_id: Uuid, msg: ServerMsg) -> bool {
        let tx = self.agents.read().unwrap().get(&agent_id).map(|h| h.tx.clone());
        match tx {
            Some(tx) => tx.send(msg).await.is_ok(),
            None => false,
        }
    }

    pub fn open_shell(&self, session_id: Uuid, agent_id: Uuid) -> mpsc::Receiver<ShellEvent> {
        let (tx, rx) = mpsc::channel(256);
        self.shells.write().unwrap().insert(session_id, ShellRoute { agent_id, tx });
        rx
    }

    pub fn close_shell(&self, session_id: Uuid) {
        self.shells.write().unwrap().remove(&session_id);
    }

    /// Delivers agent output to the dashboard socket that owns the session.
    /// Only accepted from the agent the session was opened on.
    pub async fn route_shell(&self, from_agent: Uuid, session_id: Uuid, ev: ShellEvent) {
        let tx = {
            let shells = self.shells.read().unwrap();
            shells.get(&session_id).filter(|r| r.agent_id == from_agent).map(|r| r.tx.clone())
        };
        if let Some(tx) = tx {
            let _ = tx.send(ev).await;
        }
    }

    /// Agent went away: tell every open terminal for it.
    pub fn drop_agent_shells(&self, agent_id: Uuid) {
        let mut shells = self.shells.write().unwrap();
        shells.retain(|_, r| {
            if r.agent_id == agent_id {
                let _ = r.tx.try_send(ShellEvent::Closed(Some("agent disconnected".into())));
                false
            } else {
                true
            }
        });
    }
}
