//! Ticket attachments in and out, shared by the technician and portal routes: uploads stream
//! from the multipart body into storage (size and SHA-256 worked out on the way, the per-file
//! limit enforced as the bytes arrive), downloads stream back out with `Range` support.

use axum::body::Body;
use axum::extract::multipart::{Field, MultipartError};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::Response;
use uuid::Uuid;

use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

/// One file stored by [`save`], not yet recorded in `ticket_attachments`.
pub(crate) struct Saved {
    pub id: Uuid,
    pub key: String,
    pub name: String,
    pub content_type: String,
    pub size: i64,
    pub sha256: Vec<u8>,
}

/// The 413 for a file over RMM_ATTACHMENT_MAX_MB. The web UI shows the same words.
pub(crate) fn too_large(st: &AppState, name: &str) -> ApiError {
    ApiError::TooLarge(format!("{name} is larger than the {} MB limit for attachments", st.cfg.attachment_max_mb))
}

/// A multipart read error. Hitting the route's body limit (all files together) is a 413 too.
pub(crate) fn multipart_error(st: &AppState, e: MultipartError) -> ApiError {
    if e.status() == StatusCode::PAYLOAD_TOO_LARGE {
        ApiError::TooLarge(format!("the upload is too large: attachments are limited to {} MB each", st.cfg.attachment_max_mb))
    } else {
        ApiError::BadRequest(format!("upload: {e}"))
    }
}

pub(crate) fn content_type(field: &Field<'_>) -> String {
    field
        .content_type()
        .filter(|c| c.len() < 100 && c.contains('/') && c.bytes().all(|b| b.is_ascii_graphic()))
        .unwrap_or("application/octet-stream")
        .to_ascii_lowercase()
}

/// Streams one `file` field into storage under a new key. `None` for an empty file. On any
/// error nothing is left in storage.
pub(crate) async fn save(st: &AppState, mut field: Field<'_>) -> ApiResult<Option<Saved>> {
    let name = super::tickets::clean_filename(field.file_name().unwrap_or("attachment"));
    let ct = content_type(&field);
    let id = Uuid::new_v4();
    let key = format!("attachments/{id}");
    let limit = st.cfg.attachment_max_bytes();
    let mut w = st.storage.writer(&key, &ct).await?;
    loop {
        let chunk = match field.chunk().await {
            Ok(Some(c)) => c,
            Ok(None) => break,
            Err(e) => {
                w.abort().await;
                return Err(multipart_error(st, e));
            }
        };
        if w.size() + chunk.len() as u64 > limit {
            w.abort().await;
            return Err(too_large(st, &name));
        }
        if let Err(e) = w.write(&chunk).await {
            w.abort().await;
            return Err(e.into());
        }
    }
    if w.size() == 0 {
        w.abort().await;
        return Ok(None);
    }
    let stored = w.finish().await?;
    Ok(Some(Saved { id, key, name, content_type: ct, size: stored.size as i64, sha256: stored.sha256 }))
}

/// Removes files stored for a request that then failed.
pub(crate) async fn discard(st: &AppState, saved: &[Saved]) {
    for s in saved {
        if let Err(e) = st.storage.delete(&s.key).await {
            tracing::warn!(key = %s.key, "removing an unused upload: {e:#}");
        }
    }
}

/// Images that are safe to show inline. Everything else downloads (an HTML or SVG file opened
/// from our origin could run script).
const INLINE_TYPES: &[&str] = &["image/png", "image/jpeg", "image/gif", "image/webp"];

/// `Range: bytes=a-b` against an object of `size` bytes: `Ok(None)` for no (or a multi-part,
/// which we answer in full) range, `Err(())` when it can't be satisfied.
fn parse_range(h: Option<&HeaderValue>, size: u64) -> Result<Option<(u64, u64)>, ()> {
    let Some(spec) = h.and_then(|v| v.to_str().ok()).and_then(|v| v.trim().strip_prefix("bytes=")) else { return Ok(None) };
    if spec.contains(',') {
        return Ok(None);
    }
    let (a, b) = spec.split_once('-').ok_or(())?;
    let (a, b) = (a.trim(), b.trim());
    let (start, end) = if a.is_empty() {
        // The last `b` bytes.
        let n: u64 = b.parse().map_err(|_| ())?;
        if n == 0 {
            return Err(());
        }
        (size.saturating_sub(n), size.saturating_sub(1))
    } else {
        let start: u64 = a.parse().map_err(|_| ())?;
        let end = if b.is_empty() { size.saturating_sub(1) } else { b.parse::<u64>().map_err(|_| ())?.min(size.saturating_sub(1)) };
        (start, end)
    };
    if size == 0 || start >= size || end < start {
        return Err(());
    }
    Ok(Some((start, end)))
}

/// A stored attachment as a download, streamed from storage. Only safe image types may show
/// inline; everything else is `application/octet-stream` with a sandboxing CSP.
pub(crate) async fn serve(st: &AppState, req: &HeaderMap, key: &str, size: i64, name: &str, ct: &str, inline: bool) -> ApiResult<Response> {
    let size = size.max(0) as u64;
    let (status, start, len) = match parse_range(req.get(header::RANGE), size) {
        Ok(None) => (StatusCode::OK, 0, size),
        Ok(Some((a, b))) => (StatusCode::PARTIAL_CONTENT, a, b - a + 1),
        Err(()) => {
            let mut res = Response::new(Body::empty());
            *res.status_mut() = StatusCode::RANGE_NOT_SATISFIABLE;
            res.headers_mut().insert(header::CONTENT_RANGE, HeaderValue::from_str(&format!("bytes */{size}")).map_err(anyhow::Error::from)?);
            return Ok(res);
        }
    };
    let stream = st.storage.read(key, start, len).await?;
    let inline = inline && INLINE_TYPES.contains(&ct);
    let ascii: String = name.chars().map(|c| if c.is_ascii_alphanumeric() || " ._-()".contains(c) { c } else { '_' }).collect();
    let encoded: String = name
        .bytes()
        .map(|b| if b.is_ascii_alphanumeric() || b"._-".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") })
        .collect();
    let disposition = format!("{}; filename=\"{ascii}\"; filename*=UTF-8''{encoded}", if inline { "inline" } else { "attachment" });
    let content_type = if inline { ct.to_string() } else { "application/octet-stream".to_string() };
    let mut res = Response::new(Body::from_stream(stream));
    *res.status_mut() = status;
    let h = res.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_str(&content_type).unwrap_or(HeaderValue::from_static("application/octet-stream")));
    h.insert(header::CONTENT_DISPOSITION, HeaderValue::from_str(&disposition).map_err(anyhow::Error::from)?);
    h.insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static("sandbox; default-src 'none'; img-src 'self'"));
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("private, no-store"));
    h.insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    h.insert(header::CONTENT_LENGTH, HeaderValue::from(len));
    if status == StatusCode::PARTIAL_CONTENT {
        h.insert(header::CONTENT_RANGE, HeaderValue::from_str(&format!("bytes {start}-{}/{size}", start + len - 1)).map_err(anyhow::Error::from)?);
    }
    Ok(res)
}

/// `GET /api/files/{token}`: an attachment linked from an email because it was too large to
/// attach (see `email::too_large_section`). The token is the only key, so it expires.
pub async fn shared(
    axum::extract::State(st): axum::extract::State<std::sync::Arc<AppState>>,
    axum::extract::Path(token): axum::extract::Path<String>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    let row: Option<(String, String, String, i64)> = sqlx::query_as(
        "SELECT a.name, a.content_type, a.storage_key, a.size FROM attachment_links l JOIN ticket_attachments a ON a.id = l.attachment_id
          WHERE l.token_hash = $1 AND l.expires_at > now()",
    )
    .bind(crate::auth::token_hash(&token))
    .fetch_optional(&st.db)
    .await?;
    let (name, ct, key, size) = row.ok_or(ApiError::NotFound("link (it may have expired)"))?;
    serve(&st, &headers, &key, size, &name, &ct, false).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranges() {
        let r = |s: &str, size| parse_range(Some(&HeaderValue::from_str(s).unwrap()), size);
        assert_eq!(parse_range(None, 10), Ok(None));
        assert_eq!(r("bytes=0-3", 10), Ok(Some((0, 3))));
        assert_eq!(r("bytes=4-", 10), Ok(Some((4, 9))));
        assert_eq!(r("bytes=-3", 10), Ok(Some((7, 9))));
        assert_eq!(r("bytes=5-100", 10), Ok(Some((5, 9))));
        assert_eq!(r("bytes=0-1,4-5", 10), Ok(None));
        assert_eq!(r("items=0-1", 10), Ok(None));
        assert_eq!(r("bytes=10-", 10), Err(()));
        assert_eq!(r("bytes=5-2", 10), Err(()));
        assert_eq!(r("bytes=-0", 10), Err(()));
        assert_eq!(r("bytes=x-", 10), Err(()));
    }
}
