//! The checks each agent runs for the server ([`rmm_proto::checks`]): its uptime monitors
//! ([`crate::uptime`]) and the backup checks of its `backup` alert items ([`crate::backups`]).
//! The whole set is pushed after the agent connects and whenever it may have changed (a monitor
//! edited, a policy changed, a site's designated agent moved), like log watchers. Only agents that
//! list the `checks` capability get it.

use std::collections::HashMap;

use rmm_proto::ServerMsg;
use rmm_proto::checks::{CAPABILITY, CheckResult, CheckSpec, MAX_CHECKS};
use tokio::sync::mpsc;
use tracing::warn;
use uuid::Uuid;

use crate::state::AppState;

async fn specs(st: &AppState, agents: &[Uuid]) -> sqlx::Result<HashMap<Uuid, Vec<CheckSpec>>> {
    let mut out = crate::uptime::specs_for(st, agents).await?;
    for (agent, list) in crate::backups::specs_for(st, agents).await? {
        out.entry(agent).or_default().extend(list);
    }
    for list in out.values_mut() {
        if list.len() > MAX_CHECKS {
            warn!(checks = list.len(), "an agent has more checks than it runs; the rest are left out");
            list.truncate(MAX_CHECKS);
        }
    }
    Ok(out)
}

/// After the agent authenticated: its set (only to agents that can run checks).
pub async fn on_connect(st: &AppState, agent_id: Uuid, capabilities: &[String], tx: &mpsc::Sender<ServerMsg>) {
    if !capabilities.iter().any(|c| c == CAPABILITY) {
        return;
    }
    match specs(st, &[agent_id]).await {
        Ok(mut s) => {
            let checks = s.remove(&agent_id).unwrap_or_default();
            let _ = tx.send(ServerMsg::Checks { checks, run_now: vec![] }).await;
        }
        Err(e) => warn!(%agent_id, "loading checks: {e}"),
    }
}

/// Re-sends online agents (these, or all of them) their sets; `run_now` checks run at once.
pub async fn push(st: &AppState, agents: Option<&[Uuid]>, run_now: &[Uuid]) {
    let res: sqlx::Result<()> = async {
        let online: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM agents WHERE online AND $2 = ANY(capabilities) AND ($1::uuid[] IS NULL OR id = ANY($1))")
            .bind(agents)
            .bind(CAPABILITY)
            .fetch_all(&st.db)
            .await?;
        if online.is_empty() {
            return Ok(());
        }
        let mut all = specs(st, &online).await?;
        for agent_id in online {
            let checks = all.remove(&agent_id).unwrap_or_default();
            let now: Vec<Uuid> = run_now.iter().copied().filter(|id| checks.iter().any(|c| c.id == *id)).collect();
            st.hub.send(agent_id, ServerMsg::Checks { checks, run_now: now }).await;
        }
        Ok(())
    }
    .await;
    if let Err(e) = res {
        warn!("pushing checks: {e}");
    }
}

/// [`push`] in the background, for request handlers.
pub fn push_soon(st: &std::sync::Arc<AppState>, agents: Option<Vec<Uuid>>) {
    let st = st.clone();
    tokio::spawn(async move { push(&st, agents.as_deref(), &[]).await });
}

/// Results from an agent: monitors' go to uptime, the rest are backup items'.
pub async fn ingest(st: &AppState, agent_id: Uuid, results: Vec<CheckResult>) -> anyhow::Result<()> {
    let results: Vec<CheckResult> = results.into_iter().take(MAX_CHECKS * 4).collect();
    let ids: Vec<Uuid> = results.iter().map(|r| r.check_id).collect();
    let monitors: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM uptime_monitors WHERE id = ANY($1)").bind(&ids).fetch_all(&st.db).await?;
    let (uptime, rest): (Vec<CheckResult>, Vec<CheckResult>) = results.into_iter().partition(|r| monitors.contains(&r.check_id));
    crate::uptime::ingest(st, agent_id, uptime).await?;
    crate::backups::ingest(st, agent_id, rest).await?;
    Ok(())
}
