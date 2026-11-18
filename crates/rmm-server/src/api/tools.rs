//! Process list with kill, and the file browser with downloads and uploads, relayed to the
//! agent over its socket ([`rmm_proto::tools`]). Technicians only, like the terminal: both
//! act with the agent's privileges. Kills, downloads and uploads are audited.

use std::sync::Arc;
use std::time::Duration;

use axum::Json;
use axum::body::{Body, Bytes};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderValue, header};
use axum::response::Response;
use futures_util::StreamExt;
use rmm_proto::tools::{CHUNK, Reply, Request};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::auth::{self, Role, User};
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

/// One request's wait for the agent. Listing a huge directory or killing a stubborn process
/// can take a while; a file chunk shouldn't.
const SLOW: Duration = Duration::from_secs(30);
const CHUNK_WAIT: Duration = Duration::from_secs(60);
/// Largest upload accepted.
const UPLOAD_MAX: u64 = 4 * 1024 * 1024 * 1024;

/// Checks access, the role and that the agent can do this; returns its hostname. `files`: the
/// file tools, which the agent's remote access policy can turn off.
async fn ready(st: &AppState, u: &User, agent_id: Uuid, files: bool) -> ApiResult<String> {
    u.require(Role::Technician)?;
    super::access::agent(st, u, agent_id).await?;
    if files {
        let (policy, set) = crate::policy::remote_access(st, agent_id).await?;
        if !policy.files_enabled {
            return Err(ApiError::Denied(format!("file access is turned off for this device by policy set {set}")));
        }
    }
    let (hostname, capable): (String, bool) =
        sqlx::query_as("SELECT hostname, $2 = ANY(capabilities) FROM agents WHERE id = $1")
            .bind(agent_id)
            .bind(rmm_proto::tools::CAPABILITY)
            .fetch_one(&st.db)
            .await?;
    if !st.hub.is_online(agent_id) {
        return Err(ApiError::Conflict("the agent is offline".into()));
    }
    if !capable {
        return Err(ApiError::Conflict("this agent version can't do this; update the agent".into()));
    }
    Ok(hostname)
}

async fn ask(st: &AppState, agent_id: Uuid, req: Request, wait: Duration) -> ApiResult<Reply> {
    match st.hub.tool(agent_id, req, wait).await.map_err(ApiError::Conflict)? {
        Reply::Error(e) => Err(ApiError::BadRequest(e)),
        r => Ok(r),
    }
}

fn unexpected() -> ApiError {
    ApiError::Internal(anyhow::anyhow!("unexpected answer from the agent"))
}

// ---------------------------------------------------------------------------
// Processes
// ---------------------------------------------------------------------------

pub async fn processes(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    ready(&st, &u, id, false).await?;
    match ask(&st, id, Request::Processes, SLOW).await? {
        Reply::Processes(list) => Ok(Json(json!({ "processes": list }))),
        _ => Err(unexpected()),
    }
}

#[derive(Deserialize)]
pub struct KillBody {
    #[serde(default)]
    tree: bool,
    /// For the audit log: what the technician saw.
    #[serde(default)]
    name: Option<String>,
}

pub async fn kill(State(st): State<Arc<AppState>>, u: User, Path((id, pid)): Path<(Uuid, u32)>, Json(b): Json<KillBody>) -> ApiResult<Json<Value>> {
    ready(&st, &u, id, false).await?;
    let res = ask(&st, id, Request::Kill { pid, tree: b.tree }, SLOW).await;
    let name: Option<String> = b.name.map(|n| n.chars().take(200).collect());
    let (ok, message) = match &res {
        Ok(Reply::Killed { message }) => (true, message.clone()),
        Ok(_) => (false, "unexpected answer".into()),
        Err(e) => (false, e.to_string()),
    };
    auth::audit(&st.db, Some(u.id), "agent.process_kill", Some(("agent", id)), json!({ "pid": pid, "tree": b.tree, "name": name, "ok": ok, "message": message }))
        .await;
    match res? {
        Reply::Killed { message } => Ok(Json(json!({ "message": message }))),
        _ => Err(unexpected()),
    }
}

// ---------------------------------------------------------------------------
// Files
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct PathQuery {
    #[serde(default)]
    path: String,
    #[serde(default)]
    overwrite: bool,
}

fn check_path(path: &str) -> ApiResult<()> {
    if path.len() > 4096 || path.contains('\0') {
        return Err(ApiError::BadRequest("that isn't a valid path".into()));
    }
    Ok(())
}

pub async fn list(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>, Query(q): Query<PathQuery>) -> ApiResult<Json<Value>> {
    ready(&st, &u, id, true).await?;
    check_path(&q.path)?;
    match ask(&st, id, Request::ListDir { path: q.path }, SLOW).await? {
        Reply::Dir(d) => Ok(Json(serde_json::to_value(d).map_err(anyhow::Error::from)?)),
        _ => Err(unexpected()),
    }
}

fn file_name(path: &str) -> String {
    path.rsplit(['/', '\\']).find(|s| !s.is_empty()).unwrap_or("download").to_string()
}

fn disposition(name: &str) -> String {
    let ascii: String = name.chars().map(|c| if c.is_ascii_alphanumeric() || " ._-()".contains(c) { c } else { '_' }).collect();
    let encoded: String = name
        .bytes()
        .map(|b| if b.is_ascii_alphanumeric() || b"._-".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") })
        .collect();
    format!("attachment; filename=\"{ascii}\"; filename*=UTF-8''{encoded}")
}

/// Streams a file from the agent, a chunk at a time, as the browser reads it.
pub async fn download(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>, Query(q): Query<PathQuery>) -> ApiResult<Response> {
    ready(&st, &u, id, true).await?;
    check_path(&q.path)?;
    // The first chunk before any headers: a missing file is an error, not a broken download.
    let first = ask(&st, id, Request::ReadFile { path: q.path.clone(), offset: 0, len: CHUNK as u32 }, CHUNK_WAIT).await?;
    let Reply::Chunk { data, size, eof } = first else { return Err(unexpected()) };
    auth::audit(&st.db, Some(u.id), "agent.file_download", Some(("agent", id)), json!({ "path": q.path, "size": size })).await;
    let path = q.path.clone();
    let start = data.len() as u64;
    let rest = futures_util::stream::unfold((st.clone(), path, start, eof), move |(st, path, offset, done)| async move {
        if done || offset >= size {
            return None;
        }
        let req = Request::ReadFile { path: path.clone(), offset, len: CHUNK as u32 };
        match st.hub.tool(id, req, CHUNK_WAIT).await {
            Ok(Reply::Chunk { data, eof, .. }) if !data.is_empty() => {
                let next = offset + data.len() as u64;
                Some((Ok::<Bytes, std::io::Error>(Bytes::from(data)), (st, path, next, eof)))
            }
            // The file shrank: stop where it ends now.
            Ok(Reply::Chunk { .. }) => None,
            Ok(Reply::Error(e)) => Some((Err(std::io::Error::other(e)), (st, path, offset, true))),
            Ok(_) => Some((Err(std::io::Error::other("unexpected answer from the agent")), (st, path, offset, true))),
            Err(e) => Some((Err(std::io::Error::other(e)), (st, path, offset, true))),
        }
    });
    let body = futures_util::stream::once(async move { Ok::<Bytes, std::io::Error>(Bytes::from(data)) }).chain(rest);
    let mut res = Response::new(Body::from_stream(body));
    let h = res.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/octet-stream"));
    h.insert(header::CONTENT_DISPOSITION, HeaderValue::from_str(&disposition(&file_name(&q.path))).map_err(anyhow::Error::from)?);
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("private, no-store"));
    // No Content-Length: a file that changes size while it's read would break it. The
    // size is in this header for progress.
    h.insert("x-file-size", HeaderValue::from(size));
    Ok(res)
}

/// Writes the request body to `path` on the agent, piece by piece. Nothing appears at
/// `path` until the whole file has arrived. Not subject to the server's request size limit.
pub async fn upload(
    State(st): State<Arc<AppState>>,
    u: User,
    Path(id): Path<Uuid>,
    Query(q): Query<PathQuery>,
    body: Body,
) -> ApiResult<Json<Value>> {
    ready(&st, &u, id, true).await?;
    check_path(&q.path)?;
    if q.path.trim().is_empty() || q.path.ends_with(['/', '\\']) {
        return Err(ApiError::BadRequest("give the full path of the file to write".into()));
    }
    let mut stream = body.into_data_stream();
    let mut buf: Vec<u8> = Vec::with_capacity(CHUNK);
    let mut offset: u64 = 0;
    let result: ApiResult<u64> = async {
        loop {
            let next = stream.next().await;
            let end = next.is_none();
            if let Some(piece) = next {
                let piece = piece.map_err(|e| ApiError::BadRequest(format!("reading the upload: {e}")))?;
                buf.extend_from_slice(&piece);
            }
            // Send full chunks as they fill; the rest with the end of the body.
            while buf.len() >= CHUNK || (end && (!buf.is_empty() || offset == 0)) {
                let take = buf.len().min(CHUNK);
                let data: Vec<u8> = buf.drain(..take).collect();
                let last = end && buf.is_empty();
                if offset + data.len() as u64 > UPLOAD_MAX {
                    return Err(ApiError::BadRequest("uploads are limited to 4 GB".into()));
                }
                let n = data.len() as u64;
                let req = Request::WriteFile { path: q.path.clone(), offset, data, last, overwrite: q.overwrite };
                match ask(&st, id, req, CHUNK_WAIT).await? {
                    Reply::Written { .. } => offset += n,
                    _ => return Err(unexpected()),
                }
                if last {
                    return Ok(offset);
                }
            }
        }
    }
    .await;
    if result.is_err() && offset > 0 {
        let _ = st.hub.tool(id, Request::AbortWrite { path: q.path.clone() }, SLOW).await;
    }
    let ok = result.is_ok();
    auth::audit(
        &st.db,
        Some(u.id),
        "agent.file_upload",
        Some(("agent", id)),
        json!({ "path": q.path, "size": result.as_ref().ok(), "overwrite": q.overwrite, "ok": ok,
                "error": result.as_ref().err().map(|e| e.to_string()) }),
    )
    .await;
    Ok(Json(json!({ "size": result? })))
}

#[cfg(test)]
mod tests {
    #[test]
    fn names() {
        assert_eq!(super::file_name("/var/log/syslog"), "syslog");
        assert_eq!(super::file_name("C:\\Users\\a\\report.pdf"), "report.pdf");
        assert_eq!(super::file_name("/"), "download");
        assert_eq!(super::disposition("a b.txt"), "attachment; filename=\"a b.txt\"; filename*=UTF-8''a%20b.txt");
    }
}
