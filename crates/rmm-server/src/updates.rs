//! Agent self-update, server side: signed releases in RMM_AGENT_DIR, offers, chunked delivery.
//!
//! A release is an agent binary plus `<binary>.update.json` written by `rmm-sign`. The server
//! never holds the signing key and doesn't verify signatures itself (agents do, against
//! their built-in key); it only checks that the manifest matches the file next to it.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use rmm_proto::ServerMsg;
use rmm_proto::update::{Manifest, is_newer};
use sha2::{Digest, Sha256};
use tracing::warn;
use uuid::Uuid;

use crate::state::AppState;

pub const CHUNK: usize = 256 * 1024;

pub struct Release {
    pub manifest: Manifest,
    pub bytes: Vec<u8>,
}

/// Releases by platform, reloaded when the binary or manifest changes on disk.
#[derive(Default)]
pub struct Releases {
    cache: Mutex<HashMap<String, Cached>>,
}

/// Modification times of the binary and its manifest when last loaded.
type Stamp = (Option<SystemTime>, Option<SystemTime>);
type Cached = (Stamp, Option<Arc<Release>>);

fn manifest_path(binary: &std::path::Path) -> PathBuf {
    let mut name = binary.file_name().unwrap_or_default().to_os_string();
    name.push(".update.json");
    binary.with_file_name(name)
}

fn mtime(p: &std::path::Path) -> Option<SystemTime> {
    std::fs::metadata(p).and_then(|m| m.modified()).ok()
}

impl Releases {
    /// The signed release for `platform`, if there is a valid one.
    pub fn get(&self, st: &AppState, platform: &str) -> Option<Arc<Release>> {
        let binary = crate::api::agent_binary_path(st, platform)?;
        let manifest = manifest_path(&binary);
        let stamp = (mtime(&binary), mtime(&manifest));
        if let Some((s, r)) = self.cache.lock().unwrap_or_else(|e| e.into_inner()).get(platform)
            && *s == stamp
        {
            return r.clone();
        }
        let release = load(platform, &binary, &manifest).map(Arc::new);
        self.cache.lock().unwrap_or_else(|e| e.into_inner()).insert(platform.to_string(), (stamp, release.clone()));
        release
    }
}

fn load(platform: &str, binary: &std::path::Path, manifest: &std::path::Path) -> Option<Release> {
    let raw = std::fs::read_to_string(manifest).ok()?;
    let m: Manifest = match serde_json::from_str(&raw) {
        Ok(m) => m,
        Err(e) => {
            warn!("{}: {e}", manifest.display());
            return None;
        }
    };
    let bytes = std::fs::read(binary).ok()?;
    let sha = hex::encode(Sha256::digest(&bytes));
    if m.platform != platform || sha != m.sha256.to_ascii_lowercase() {
        warn!("{} doesn't match {} (platform or checksum); not offering it as an update", manifest.display(), binary.display());
        return None;
    }
    Some(Release { manifest: m, bytes })
}

/// Download id for an agent's OS and architecture.
pub fn platform_of(os_family: &str, arch: &str) -> String {
    format!("{os_family}-{arch}")
}

/// Offers the newest release to one agent. `Err` explains why not.
pub async fn offer(st: &AppState, agent_id: Uuid) -> Result<String, String> {
    let row: Option<(String, String, String)> =
        sqlx::query_as("SELECT os_family, arch, agent_version FROM agents WHERE id = $1")
            .bind(agent_id)
            .fetch_optional(&st.db)
            .await
            .map_err(|e| e.to_string())?;
    let (os, arch, current) = row.ok_or("agent not found")?;
    let platform = platform_of(&os, &arch);
    let release = st.releases.get(st, &platform).ok_or_else(|| format!("no signed {platform} release on this server"))?;
    let version = release.manifest.version.clone();
    if !is_newer(&version, &current) {
        return Err(format!("already up to date ({current})"));
    }
    let msg = ServerMsg::UpdateOffer {
        version: version.clone(),
        size: release.bytes.len() as u64,
        sha256: release.manifest.sha256.clone(),
        signature: release.manifest.signature.clone(),
    };
    if !st.hub.send(agent_id, msg).await {
        return Err("agent is offline".into());
    }
    let _ = sqlx::query(
        "UPDATE agents SET update_version = $2, update_state = 'offered', update_detail = NULL, update_at = now() WHERE id = $1",
    )
    .bind(agent_id)
    .bind(&version)
    .execute(&st.db)
    .await;
    Ok(version)
}

/// What [`due`] needs to know about an agent.
#[derive(sqlx::FromRow)]
struct UpdateRow {
    id: Uuid,
    os_family: String,
    arch: String,
    agent_version: String,
    update_version: Option<String>,
    update_state: Option<String>,
}

/// Whether the release for this agent's platform is newer than what it runs and hasn't
/// already failed on it.
fn due(st: &AppState, r: &UpdateRow) -> bool {
    let Some(release) = st.releases.get(st, &platform_of(&r.os_family, &r.arch)) else { return false };
    let failed_before = r.update_version.as_deref() == Some(release.manifest.version.as_str())
        && matches!(r.update_state.as_deref(), Some("failed" | "rolled_back"));
    is_newer(&release.manifest.version, &r.agent_version) && !failed_before
}

/// On connect, when the agent's policy (`agent.auto_update`) has automatic updates on: offer
/// unless this exact version already failed here.
pub async fn auto_offer(st: &AppState, agent_id: Uuid) {
    match crate::policy::auto_update(st, agent_id).await {
        Ok(true) => {}
        Ok(false) => return,
        Err(e) => return tracing::warn!(%agent_id, "reading the agent policy: {e}"),
    }
    let row: Option<UpdateRow> = sqlx::query_as(
        "SELECT id, os_family, arch, agent_version, update_version, update_state FROM agents WHERE id = $1",
    )
    .bind(agent_id)
    .fetch_optional(&st.db)
    .await
    .ok()
    .flatten();
    if let Some(r) = row
        && due(st, &r)
    {
        let _ = offer(st, agent_id).await;
    }
}

/// How often connected agents are checked for a newer release.
const SWEEP_EVERY: std::time::Duration = std::time::Duration::from_secs(120);

/// An update in progress that hasn't reported for this long is presumed dead and offered
/// again. Longer than the agent's 30 minute wait for running jobs.
const STALE_MINUTES: i32 = 45;

/// Offers new releases to agents that stay connected: a release uploaded (or a policy turned
/// on) after an agent connected would otherwise wait for its next reconnect.
pub async fn run(st: Arc<AppState>) {
    let mut tick = tokio::time::interval(SWEEP_EVERY);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        if let Err(e) = sweep(&st).await {
            warn!("agent update sweep: {e}");
        }
    }
}

async fn sweep(st: &AppState) -> sqlx::Result<()> {
    let rows: Vec<UpdateRow> = sqlx::query_as(
        "SELECT a.id, a.os_family, a.arch, a.agent_version, a.update_version, a.update_state FROM agents a
           JOIN policy_effective e ON e.set_id = a.policy_set_id AND e.item_id = $1
          WHERE a.online AND coalesce((e.config ->> 'auto_update')::boolean, false)
            AND NOT (coalesce(a.update_state, '') IN ('offered', 'downloading', 'waiting', 'applying')
                     AND a.update_at > now() - make_interval(mins => $2))",
    )
    .bind(crate::policy::AGENT_ITEM)
    .bind(STALE_MINUTES)
    .fetch_all(&st.db)
    .await?;
    for r in rows.iter().filter(|r| due(st, r)) {
        match offer(st, r.id).await {
            Ok(v) => tracing::info!(agent_id = %r.id, version = %v, "offered agent update"),
            Err(e) => tracing::debug!(agent_id = %r.id, "not offering an update: {e}"),
        }
    }
    Ok(())
}

/// The piece of the release an agent asked for. Empty if the version moved on meanwhile,
/// which the agent treats as a failed download.
pub async fn chunk(st: &AppState, agent_id: Uuid, version: &str, offset: u64) -> ServerMsg {
    let row: Option<(String, String)> = sqlx::query_as("SELECT os_family, arch FROM agents WHERE id = $1")
        .bind(agent_id)
        .fetch_optional(&st.db)
        .await
        .ok()
        .flatten();
    let data = row
        .and_then(|(os, arch)| st.releases.get(st, &platform_of(&os, &arch)))
        .filter(|r| r.manifest.version == version)
        .and_then(|r| {
            let start = usize::try_from(offset).ok().filter(|&o| o < r.bytes.len())?;
            Some(r.bytes[start..(start + CHUNK).min(r.bytes.len())].to_vec())
        })
        .unwrap_or_default();
    ServerMsg::UpdateChunk { version: version.to_string(), offset, data }
}
