//! `/api/events`: one Server-Sent Events stream per open dashboard, replacing per-page polling.
//!
//! Each message is a JSON [`Event`] (`{"type":"agent",...}`, `{"type":"job",...}`), plus
//! `{"type":"hello"}` on connect and `{"type":"resync"}` when this stream fell behind and
//! the page should refetch everything it shows. Events for clients the user can't see are
//! never sent.
//!
//! Updates are coalesced per agent and job and flushed every [`FLUSH_EVERY`], so a fleet of
//! heartbeating agents costs each browser at most one message per agent per flush.
//!
//! The session is re-checked every [`RECHECK_EVERY`]: the stream ends when it is revoked or
//! expires, and access changes apply without a reconnect.

use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue};
use axum::response::sse::{Event as SseEvent, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use futures_util::Stream;
use tokio::sync::{broadcast, mpsc};
use uuid::Uuid;

use crate::auth::{self, User};
use crate::error::{ApiError, ApiResult};
use crate::hub::Event;
use crate::state::AppState;

const FLUSH_EVERY: Duration = Duration::from_secs(1);
const RECHECK_EVERY: Duration = Duration::from_secs(60);

pub async fn handler(State(st): State<Arc<AppState>>, user: User, headers: HeaderMap) -> ApiResult<Response> {
    let token = auth::extract_token(&headers).ok_or(ApiError::Unauthorized)?;
    let (tx, rx) = mpsc::channel::<String>(64);
    let events = st.hub.subscribe();
    tokio::spawn(pump(st, user, token, events, tx));
    let mut res = Sse::new(stream(rx)).keep_alive(KeepAlive::new().interval(Duration::from_secs(20))).into_response();
    // nginx and friends buffer responses by default, which would hold events back.
    res.headers_mut().insert("x-accel-buffering", HeaderValue::from_static("no"));
    res.headers_mut().insert(axum::http::header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(res)
}

fn stream(rx: mpsc::Receiver<String>) -> impl Stream<Item = Result<SseEvent, Infallible>> {
    futures_util::stream::unfold(rx, |mut rx| async move { rx.recv().await.map(|data| (Ok(SseEvent::default().data(data)), rx)) })
}

/// Coalescing key: the latest event per agent or job wins.
#[derive(Hash, PartialEq, Eq)]
enum Key {
    Agent(Uuid),
    Job(Uuid),
    Jobs,
    Alert(Uuid),
    Services(Uuid),
    Patches(Uuid),
    Security(Uuid),
    Network(Uuid),
    Ticket(Uuid),
}

fn key(ev: &Event) -> Key {
    match ev {
        Event::Agent { id, .. } => Key::Agent(*id),
        Event::Job { id, .. } => Key::Job(*id),
        Event::Jobs => Key::Jobs,
        Event::Alert { id, .. } => Key::Alert(*id),
        Event::Services { agent_id, .. } => Key::Services(*agent_id),
        Event::Patches { agent_id, .. } => Key::Patches(*agent_id),
        Event::Security { agent_id, .. } => Key::Security(*agent_id),
        Event::Network { site_id, .. } => Key::Network(*site_id),
        Event::Ticket { id, .. } => Key::Ticket(*id),
    }
}

/// Merges `new` over `old`. A job keeps `output: true` if any coalesced event had it, and an
/// agent keeps the last metrics it was sent.
fn merge(old: Event, new: Event) -> Event {
    match (old, new) {
        (Event::Job { output: o1, .. }, Event::Job { id, agent_id, client_id, status, output: o2 }) => {
            Event::Job { id, agent_id, client_id, status, output: o1 || o2 }
        }
        (Event::Agent { last_metrics: m1, .. }, Event::Agent { id, client_id, online, last_metrics: m2 }) => {
            Event::Agent { id, client_id, online, last_metrics: m2.or(m1) }
        }
        (_, new) => new,
    }
}

async fn pump(st: Arc<AppState>, mut user: User, token: String, mut events: broadcast::Receiver<Event>, tx: mpsc::Sender<String>) {
    if tx.send(r#"{"type":"hello"}"#.into()).await.is_err() {
        return;
    }
    let mut pending: HashMap<Key, Event> = HashMap::new();
    let mut flush = tokio::time::interval(FLUSH_EVERY);
    let mut recheck = tokio::time::interval(RECHECK_EVERY);
    recheck.tick().await;
    loop {
        tokio::select! {
            ev = events.recv() => match ev {
                Ok(ev) => {
                    if !ev.visible_to(&user) {
                        continue;
                    }
                    let k = key(&ev);
                    let ev = match pending.remove(&k) {
                        Some(old) => merge(old, ev),
                        None => ev,
                    };
                    pending.insert(k, ev);
                }
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    crate::metrics::M.sse_lagged_events.fetch_add(n, std::sync::atomic::Ordering::Relaxed);
                    crate::metrics::inc(&crate::metrics::M.sse_resyncs);
                    pending.clear();
                    if tx.send(r#"{"type":"resync"}"#.into()).await.is_err() {
                        return;
                    }
                }
                Err(broadcast::error::RecvError::Closed) => return,
            },
            _ = flush.tick() => {
                for (_, ev) in pending.drain() {
                    let Ok(json) = serde_json::to_string(&ev) else { continue };
                    if tx.send(json).await.is_err() {
                        return; // browser went away
                    }
                }
            }
            _ = recheck.tick() => match auth::session_user(&st, &token).await {
                Ok(Some(u)) if !u.mfa_setup_required => user = u,
                Ok(_) => return, // revoked, expired or disabled: the stream ends, the page's next fetch gets 401
                Err(e) => tracing::warn!("events: rechecking session: {e}"),
            },
            _ = tx.closed() => return,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merge_keeps_output_flag_and_metrics() {
        let (id, a, c) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        let j = |status: &str, output| Event::Job { id, agent_id: a, client_id: c, status: status.into(), output };
        match merge(j("sent", true), j("succeeded", false)) {
            Event::Job { status, output, .. } => assert!(status == "succeeded" && output),
            _ => unreachable!(),
        }
        let ag = |online, m: Option<serde_json::Value>| Event::Agent { id: a, client_id: c, online, last_metrics: m };
        match merge(ag(true, Some(serde_json::json!({"cpu_percent": 5}))), ag(false, None)) {
            Event::Agent { online, last_metrics, .. } => assert!(!online && last_metrics.is_some()),
            _ => unreachable!(),
        }
    }

    #[test]
    fn serialized_events_hide_client() {
        let ev = Event::Job { id: Uuid::nil(), agent_id: Uuid::nil(), client_id: Uuid::nil(), status: "sent".into(), output: false };
        let v = serde_json::to_value(&ev).unwrap();
        assert_eq!(v["type"], "job");
        assert!(v.get("client_id").is_none());
    }
}
