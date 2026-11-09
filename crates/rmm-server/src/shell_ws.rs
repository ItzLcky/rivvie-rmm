//! Browser terminal: `/api/agents/{id}/shell?cols=..&rows=..`
//!
//! Binary frames carry raw terminal bytes in both directions. Text frames carry
//! JSON control messages: browser -> `{"type":"resize","cols":N,"rows":N}`,
//! server -> `{"type":"opened"}` / `{"type":"closed","reason":...}`.

use std::sync::Arc;

use axum::extract::ws::{Message, WebSocket};
use axum::extract::{Path, Query, State, WebSocketUpgrade};
use axum::http::{HeaderMap, header};
use axum::response::Response;
use futures_util::{SinkExt, StreamExt};
use rmm_proto::ServerMsg;
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use crate::auth::{self, Role, User};
use crate::error::{ApiError, ApiResult};
use crate::hub::ShellEvent;
use crate::state::AppState;

#[derive(Deserialize)]
pub struct Size {
    cols: Option<u16>,
    rows: Option<u16>,
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum Control {
    Resize { cols: u16, rows: u16 },
}

pub async fn handler(
    ws: WebSocketUpgrade,
    State(st): State<Arc<AppState>>,
    user: User,
    headers: HeaderMap,
    Path(agent_id): Path<Uuid>,
    Query(size): Query<Size>,
) -> ApiResult<Response> {
    user.require(Role::Technician)?;
    check_origin(&headers, &st.cfg.public_url)?;
    crate::api::access::agent(&st, &user, agent_id).await?;
    if !st.hub.is_online(agent_id) {
        return Err(ApiError::Conflict("agent is offline".into()));
    }
    let (cols, rows) = (size.cols.unwrap_or(120), size.rows.unwrap_or(32));
    Ok(ws.on_upgrade(move |socket| run(socket, st, user, agent_id, cols, rows)))
}

/// Cross-site WebSocket hijacking guard (defence in depth on top of SameSite cookies).
pub(crate) fn check_origin(headers: &HeaderMap, public_url: &str) -> ApiResult<()> {
    let Some(origin) = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) else {
        return Ok(()); // non-browser client
    };
    let host = headers.get(header::HOST).and_then(|v| v.to_str().ok()).unwrap_or_default();
    let origin_host = origin.split("://").nth(1).unwrap_or(origin);
    if origin_host == host || origin.trim_end_matches('/') == public_url.trim_end_matches('/') {
        Ok(())
    } else {
        Err(ApiError::Forbidden)
    }
}

async fn run(socket: WebSocket, st: Arc<AppState>, user: User, agent_id: Uuid, cols: u16, rows: u16) {
    let session_id = Uuid::new_v4();
    let mut events = st.hub.open_shell(session_id, agent_id);
    auth::audit(&st.db, Some(user.id), "shell.open", Some(("agent", agent_id)), json!({ "session_id": session_id })).await;

    if !st.hub.send(agent_id, ServerMsg::ShellOpen { session_id, cols, rows }).await {
        st.hub.close_shell(session_id);
        return;
    }

    let (mut sink, mut stream) = socket.split();
    let to_browser = async {
        while let Some(ev) = events.recv().await {
            let frame = match ev {
                ShellEvent::Opened => Message::Text(json!({ "type": "opened" }).to_string().into()),
                ShellEvent::Output(data) => Message::Binary(data.into()),
                ShellEvent::Closed(reason) => {
                    let _ = sink.send(Message::Text(json!({ "type": "closed", "reason": reason }).to_string().into())).await;
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
            let msg = match frame {
                Message::Binary(data) => ServerMsg::ShellInput { session_id, data: data.to_vec() },
                Message::Text(t) => match serde_json::from_str::<Control>(&t) {
                    Ok(Control::Resize { cols, rows }) => ServerMsg::ShellResize { session_id, cols, rows },
                    Err(_) => continue,
                },
                Message::Close(_) => break,
                _ => continue,
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

    st.hub.close_shell(session_id);
    let _ = st.hub.send(agent_id, ServerMsg::ShellClose { session_id }).await;
    auth::audit(&st.db, Some(user.id), "shell.close", Some(("agent", agent_id)), json!({ "session_id": session_id })).await;
}
