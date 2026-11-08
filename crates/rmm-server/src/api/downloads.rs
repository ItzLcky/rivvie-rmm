//! Agent binaries for the "Enroll agents" dialog and the generated install commands.
//!
//! Files live in `RMM_AGENT_DIR` under fixed names (the server image builds them in). A
//! download is allowed for a signed-in user, or with `?token=` carrying a valid enrollment
//! token, so a headless machine can fetch the agent in the same command that enrolls it.

use std::path::PathBuf;
use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::header;
use axum::response::IntoResponse;
use axum::Json;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::auth::{self, User};
use crate::error::{ApiError, ApiResult};
use crate::ratelimit::ClientIp;
use crate::state::AppState;

pub struct Platform {
    pub id: &'static str,
    pub label: &'static str,
    /// Name in RMM_AGENT_DIR.
    file: &'static str,
    /// Name the browser saves it as; the install commands assume this.
    pub save_as: &'static str,
}

pub const PLATFORMS: &[Platform] = &[
    Platform { id: "windows-x86_64", label: "Windows (x64)", file: "rmm-agent-windows-x86_64.exe", save_as: "rmm-agent.exe" },
    Platform { id: "linux-x86_64", label: "Linux (x86_64)", file: "rmm-agent-linux-x86_64", save_as: "rmm-agent" },
];

pub fn platform_path(st: &AppState, id: &str) -> Option<PathBuf> {
    let p = PLATFORMS.iter().find(|p| p.id == id)?;
    Some(st.cfg.agent_dir.join(p.file)).filter(|path| path.is_file())
}

#[derive(Serialize)]
pub struct Available {
    id: &'static str,
    label: &'static str,
    file_name: &'static str,
    size: u64,
    sha256: String,
    url: String,
}

pub async fn list(State(st): State<Arc<AppState>>, _u: User) -> ApiResult<Json<Vec<Available>>> {
    let mut out = Vec::new();
    for p in PLATFORMS {
        let Some(path) = platform_path(&st, p.id) else { continue };
        let (size, sha256) = tokio::task::spawn_blocking(move || -> std::io::Result<(u64, String)> {
            let bytes = std::fs::read(path)?;
            Ok((bytes.len() as u64, hex::encode(Sha256::digest(&bytes))))
        })
        .await
        .map_err(anyhow::Error::from)?
        .map_err(anyhow::Error::from)?;
        out.push(Available {
            id: p.id,
            label: p.label,
            file_name: p.save_as,
            size,
            sha256,
            url: format!("/api/agent-downloads/{}", p.id),
        });
    }
    Ok(Json(out))
}

/// Site of a usable enrollment token, for downloads authorized by `?token=`. Checked, not
/// consumed: a use is only spent when the agent actually enrolls. Bad tokens count against
/// the same per-IP limit as bad enrollments.
pub async fn token_site(st: &AppState, ip: std::net::IpAddr, token: &str) -> ApiResult<uuid::Uuid> {
    let key = ip.to_string();
    st.limits.enroll_ip.check(&key).map_err(ApiError::TooManyRequests)?;
    let site: Option<uuid::Uuid> = sqlx::query_scalar(
        "SELECT site_id FROM enrollment_tokens
          WHERE token_hash = $1
            AND (expires_at IS NULL OR expires_at > now())
            AND (max_uses IS NULL OR uses < max_uses)",
    )
    .bind(auth::token_hash(token))
    .fetch_optional(&st.db)
    .await?;
    site.ok_or_else(|| {
        st.limits.enroll_ip.fail(&key);
        ApiError::Unauthorized
    })
}

#[derive(Deserialize)]
pub struct TokenQuery {
    token: Option<String>,
}

pub async fn download(
    State(st): State<Arc<AppState>>,
    ClientIp(ip): ClientIp,
    user: Option<User>,
    Path(id): Path<String>,
    Query(q): Query<TokenQuery>,
) -> ApiResult<impl IntoResponse> {
    if user.is_none() {
        let token = q.token.ok_or(ApiError::Unauthorized)?;
        token_site(&st, ip, &token).await?;
    }
    let platform = PLATFORMS.iter().find(|p| p.id == id).ok_or(ApiError::NotFound("platform"))?;
    let path = platform_path(&st, platform.id).ok_or(ApiError::NotFound("agent binary"))?;
    let bytes = tokio::fs::read(&path).await.map_err(anyhow::Error::from)?;
    Ok((
        [
            (header::CONTENT_TYPE, "application/octet-stream".to_string()),
            (header::CONTENT_DISPOSITION, format!("attachment; filename=\"{}\"", platform.save_as)),
            (header::CACHE_CONTROL, "no-store".to_string()),
        ],
        bytes,
    ))
}
