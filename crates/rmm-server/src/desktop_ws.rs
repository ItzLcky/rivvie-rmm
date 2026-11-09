//! Browser remote desktop: `/api/agents/{id}/desktop?quality=..&monitor=..`
//!
//! Server -> browser:
//! - text `{"type":"waiting"}`: the person at the machine is being asked to allow the session.
//! - text `{"type":"info","monitors":[...],"monitor":N}`: sent first and on every change.
//! - binary frame, big-endian:
//!   `u8 kind (1) | u32 seq | u16 screen_w | u16 screen_h | u16 width | u16 height |
//!    i32 cursor_x | i32 cursor_y (i32::MIN = unknown) | u16 rect count`, then per rect
//!   `u16 x | u16 y | u16 w | u16 h | u8 codec (1 = JPEG) | u32 length | bytes`.
//! - text `{"type":"closed","reason":...}`, then the socket closes.
//!
//! Browser -> server (text):
//! - `{"type":"ack","seq":N}` once frame N is drawn. Without acks the agent stops sending.
//! - `{"type":"input","events":[...]}` with [`rmm_proto::desktop::InputEvent`]s.
//! - `{"type":"settings","monitor":N,"quality":"low|balanced|high"}`.

use std::sync::Arc;
use std::time::Instant;

use axum::extract::ws::{Message, WebSocket};
use axum::extract::{Path, Query, State, WebSocketUpgrade};
use axum::http::HeaderMap;
use axum::response::Response;
use futures_util::{SinkExt, StreamExt};
use rmm_proto::ServerMsg;
use rmm_proto::desktop::{self, Consent, Frame, InputEvent, Quality, Settings};
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use crate::auth::{self, Role, User};
use crate::error::{ApiError, ApiResult};
use crate::hub::DesktopEvent;
use crate::state::AppState;

/// How long the person at the machine has to answer the consent prompt.
const CONSENT_TIMEOUT_SECS: u32 = 30;
/// Most input events accepted in one message.
const MAX_EVENTS: usize = 256;

#[derive(Deserialize)]
pub struct Params {
    #[serde(default)]
    monitor: u32,
    #[serde(default)]
    quality: Quality,
    /// Opened from this ticket: start and end are recorded on its timeline.
    ticket_id: Option<Uuid>,
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum Control {
    Ack { seq: u32 },
    Input { events: Vec<InputEvent> },
    Settings { monitor: u32, quality: Quality },
}

pub async fn handler(
    ws: WebSocketUpgrade,
    State(st): State<Arc<AppState>>,
    user: User,
    headers: HeaderMap,
    Path(agent_id): Path<Uuid>,
    Query(p): Query<Params>,
) -> ApiResult<Response> {
    user.require(Role::Technician)?;
    crate::shell_ws::check_origin(&headers, &st.cfg.public_url)?;
    crate::api::access::agent(&st, &user, agent_id).await?;
    if !st.hub.is_online(agent_id) {
        return Err(ApiError::Conflict("agent is offline".into()));
    }
    let (capable, ask): (bool, bool) = sqlx::query_as(
        "SELECT $2 = ANY(a.capabilities), c.desktop_consent FROM agents a JOIN sites s ON s.id = a.site_id JOIN clients c ON c.id = s.client_id
          WHERE a.id = $1",
    )
    .bind(agent_id)
    .bind(desktop::CAPABILITY)
    .fetch_one(&st.db)
    .await?;
    if !capable {
        return Err(ApiError::Conflict("this agent version doesn't support remote desktop; update the agent".into()));
    }
    let consent = ask.then(|| Consent {
        requester: if user.name.trim().is_empty() { user.email.clone() } else { user.name.clone() },
        company: st.company().company_name,
        timeout_secs: CONSENT_TIMEOUT_SECS,
    });
    let settings = Settings { monitor: p.monitor, quality: p.quality };
    let ticket = crate::api::tickets::session_ticket(&st, &user, p.ticket_id, agent_id).await?;
    Ok(ws.on_upgrade(move |socket| run(socket, st, user, agent_id, settings, consent, ticket)))
}

/// The browser's binary frame layout (see the module docs).
pub(crate) fn encode_frame(f: &Frame) -> Vec<u8> {
    let len: usize = f.rects.iter().map(|r| 13 + r.data.len()).sum();
    let mut out = Vec::with_capacity(23 + len);
    out.push(1u8);
    out.extend_from_slice(&f.seq.to_be_bytes());
    for v in [f.screen_width, f.screen_height, f.width, f.height] {
        out.extend_from_slice(&(v.min(u16::MAX.into()) as u16).to_be_bytes());
    }
    let (cx, cy) = f.cursor.unwrap_or((i32::MIN, i32::MIN));
    out.extend_from_slice(&cx.to_be_bytes());
    out.extend_from_slice(&cy.to_be_bytes());
    out.extend_from_slice(&(f.rects.len().min(u16::MAX.into()) as u16).to_be_bytes());
    for r in f.rects.iter().take(u16::MAX.into()) {
        for v in [r.x, r.y, r.width, r.height] {
            out.extend_from_slice(&v.to_be_bytes());
        }
        out.push(r.codec.id());
        out.extend_from_slice(&(r.data.len() as u32).to_be_bytes());
        out.extend_from_slice(&r.data);
    }
    out
}

async fn run(
    socket: WebSocket,
    st: Arc<AppState>,
    user: User,
    agent_id: Uuid,
    settings: Settings,
    consent: Option<Consent>,
    ticket: Option<Uuid>,
) {
    let session_id = Uuid::new_v4();
    if let Some(t) = ticket {
        crate::tickets::session_event(&st, t, user.id, agent_id, "desktop", None).await;
    }
    let started = Instant::now();
    let mut events = st.hub.open_desktop(session_id, agent_id);
    let asked = consent.is_some();
    auth::audit(
        &st.db,
        Some(user.id),
        "desktop.open",
        Some(("agent", agent_id)),
        json!({ "session_id": session_id, "consent_requested": asked }),
    )
    .await;

    let (mut sink, mut stream) = socket.split();
    if !st.hub.send(agent_id, ServerMsg::DesktopOpen { session_id, settings, consent }).await {
        st.hub.close_desktop(session_id);
        let _ = sink.send(Message::Text(json!({ "type": "closed", "reason": "agent disconnected" }).to_string().into())).await;
        return;
    }
    if asked {
        let _ = sink.send(Message::Text(json!({ "type": "waiting" }).to_string().into())).await;
    }

    let mut reason: Option<String> = None;
    let to_browser = async {
        while let Some(ev) = events.recv().await {
            let frame = match ev {
                DesktopEvent::Info { monitors, monitor } => {
                    Message::Text(json!({ "type": "info", "monitors": monitors, "monitor": monitor }).to_string().into())
                }
                DesktopEvent::Frame(f) => Message::Binary(encode_frame(&f).into()),
                DesktopEvent::Closed(r) => {
                    reason.clone_from(&r);
                    let _ = sink.send(Message::Text(json!({ "type": "closed", "reason": r }).to_string().into())).await;
                    break;
                }
            };
            if sink.send(frame).await.is_err() {
                break;
            }
        }
        let _ = sink.close().await;
    };
    let from_browser = async {
        while let Some(Ok(frame)) = stream.next().await {
            let control = match frame {
                Message::Text(t) => match serde_json::from_str::<Control>(&t) {
                    Ok(c) => c,
                    Err(_) => continue,
                },
                Message::Close(_) => break,
                _ => continue,
            };
            let msg = match control {
                Control::Ack { seq } => ServerMsg::DesktopAck { session_id, seq },
                Control::Input { mut events } => {
                    events.retain(InputEvent::valid);
                    events.truncate(MAX_EVENTS);
                    if events.is_empty() {
                        continue;
                    }
                    ServerMsg::DesktopInput { session_id, events }
                }
                Control::Settings { monitor, quality } => ServerMsg::DesktopSettings { session_id, settings: Settings { monitor, quality } },
            };
            if !st.hub.send(agent_id, msg).await {
                break;
            }
        }
    };
    tokio::select! {
        _ = to_browser => {}
        _ = from_browser => {}
    }

    st.hub.close_desktop(session_id);
    let _ = st.hub.send(agent_id, ServerMsg::DesktopClose { session_id }).await;
    auth::audit(
        &st.db,
        Some(user.id),
        "desktop.close",
        Some(("agent", agent_id)),
        json!({ "session_id": session_id, "duration_secs": started.elapsed().as_secs(), "reason": reason }),
    )
    .await;
    if let Some(t) = ticket {
        crate::tickets::session_event(&st, t, user.id, agent_id, "desktop", Some(started.elapsed().as_secs())).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmm_proto::desktop::{Codec, Rect};

    #[test]
    fn frame_layout() {
        let f = Frame {
            seq: 3,
            screen_width: 1920,
            screen_height: 1080,
            width: 960,
            height: 540,
            rects: vec![Rect { x: 1, y: 2, width: 3, height: 4, codec: Codec::Jpeg, data: vec![9, 8] }],
            cursor: None,
        };
        let b = encode_frame(&f);
        assert_eq!(b.len(), 23 + 13 + 2);
        assert_eq!(&b[..5], &[1, 0, 0, 0, 3]);
        assert_eq!(&b[5..13], &[0x07, 0x80, 0x04, 0x38, 0x03, 0xc0, 0x02, 0x1c]);
        assert_eq!(&b[13..17], &i32::MIN.to_be_bytes());
        assert_eq!(&b[21..23], &[0, 1]);
        assert_eq!(&b[23..], &[0, 1, 0, 2, 0, 3, 0, 4, 1, 0, 0, 0, 2, 9, 8]);
    }
}
