//! Alerts about network devices. The items are ordinary alert items (`net_down`,
//! `net_interface`, `net_threshold`, see [`crate::alerts::Rule`]) in the policy set of the
//! designated agent that reads the device; the alerts they open carry the device
//! (`alerts.device_id`) and keep the agent, so notifications, tickets, muting and webhooks
//! work as for any alert.
//!
//! Checked whenever the agent reports a device ([`evaluate`]) and again for the devices an
//! item reaches when it changes ([`recheck_item`], [`recheck_agent`]). An alert's key says
//! what it is about: `dev:<device>`, `dev:<device>:if:<index>`, `dev:<device>:<metric>`.

use serde_json::{Value, json};
use sqlx::Row;
use tracing::warn;
use uuid::Uuid;

use crate::alerts::{NetDownRule, NetInterfaceRule, NetThresholdRule, Policy, Rule, announce, fire_for, policies_for, service_matches};
use crate::state::AppState;

const KINDS: [&str; 3] = ["net_down", "net_interface", "net_threshold"];

#[derive(sqlx::FromRow)]
struct Device {
    id: Uuid,
    name: String,
    host: String,
    kind: String,
    enabled: bool,
    state: String,
    state_since: chrono::DateTime<chrono::Utc>,
    last_error: Option<String>,
    supplies: Value,
    poll_secs: i32,
}

#[derive(sqlx::FromRow)]
struct Iface {
    if_index: i32,
    name: String,
    descr: String,
    alias: String,
    admin_status: i16,
    oper_status: i16,
    monitored: bool,
    status_since: chrono::DateTime<chrono::Utc>,
}

fn kind_matches(kinds: &[String], kind: &str) -> bool {
    kinds.is_empty() || kinds.iter().any(|k| k.eq_ignore_ascii_case(kind))
}

fn iface_matches(names: &[String], i: &Iface) -> bool {
    names.is_empty() || names.iter().any(|p| service_matches(p, &i.name) || service_matches(p, &i.descr) || (!i.alias.is_empty() && service_matches(p, &i.alias)))
}

/// Resolves the policy's open alerts about this device whose key isn't in `keep`.
async fn clear(st: &AppState, p: &Policy, agent_id: Uuid, device_id: Uuid, keep: &[String]) -> sqlx::Result<()> {
    let ids: Vec<Uuid> = sqlx::query_scalar(
        "UPDATE alerts SET resolved_at = now(), resolution = 'cleared'
          WHERE policy_id = $1 AND agent_id = $2 AND device_id = $3 AND resolved_at IS NULL AND NOT (key = ANY($4))
          RETURNING id",
    )
    .bind(p.id)
    .bind(agent_id)
    .bind(device_id)
    .bind(keep)
    .fetch_all(&st.db)
    .await?;
    announce(st, &ids, "resolved", &p.channel_ids, p.notify_resolved).await;
    Ok(())
}

/// Closes every open alert about a device, quietly: it was switched off or removed from monitoring.
pub async fn close_device(st: &AppState, device_id: Uuid) {
    let res: sqlx::Result<Vec<Uuid>> =
        sqlx::query_scalar("UPDATE alerts SET resolved_at = now(), resolution = 'policy' WHERE device_id = $1 AND resolved_at IS NULL RETURNING id")
            .bind(device_id)
            .fetch_all(&st.db)
            .await;
    match res {
        Ok(ids) => announce(st, &ids, "resolved", &[], false).await,
        Err(e) => warn!(%device_id, "closing a device's alerts: {e}"),
    }
}

/// Checks one device against every network alert item that reaches its designated agent.
pub async fn evaluate(st: &AppState, agent_id: Uuid, device_id: Uuid) {
    if let Err(e) = eval(st, agent_id, device_id).await {
        warn!(%device_id, "network alerts: {e}");
    }
}

async fn eval(st: &AppState, agent_id: Uuid, device_id: Uuid) -> sqlx::Result<()> {
    let Some(d): Option<Device> = sqlx::query_as(
        "SELECT d.id, d.name, d.host, d.kind, d.enabled, d.state, d.state_since, d.last_error, d.supplies,
                coalesce(d.poll_secs, sn.poll_secs, 300) AS poll_secs
           FROM net_devices d LEFT JOIN site_network sn ON sn.site_id = d.site_id WHERE d.id = $1",
    )
    .bind(device_id)
    .fetch_optional(&st.db)
    .await?
    else {
        return Ok(());
    };
    if !d.enabled {
        return Ok(());
    }
    let ifaces: Vec<Iface> = sqlx::query_as(
        "SELECT if_index, name, descr, alias, admin_status, oper_status, monitored, status_since FROM net_interfaces WHERE device_id = $1 ORDER BY if_index",
    )
    .bind(device_id)
    .fetch_all(&st.db)
    .await?;
    for kind in KINDS {
        for p in policies_for(st, agent_id, kind).await? {
            let res = match p.rule() {
                Some(Rule::NetDown(r)) => down(st, &p, agent_id, &d, &r).await,
                Some(Rule::NetInterface(r)) => interface_down(st, &p, agent_id, &d, &ifaces, &r).await,
                Some(Rule::NetThreshold(r)) => threshold(st, &p, agent_id, &d, &ifaces, &r).await,
                _ => Ok(()),
            };
            if let Err(e) = res {
                warn!(device = %device_id, policy = %p.id, "checking {}: {e}", p.name);
            }
        }
    }
    Ok(())
}

async fn down(st: &AppState, p: &Policy, agent_id: Uuid, d: &Device, r: &NetDownRule) -> sqlx::Result<()> {
    if !kind_matches(&r.kinds, &d.kind) {
        return clear(st, p, agent_id, d.id, &[]).await;
    }
    let key = format!("dev:{}", d.id);
    let overdue = d.state == "down" && d.state_since <= chrono::Utc::now() - chrono::Duration::minutes(i64::from(r.minutes));
    if overdue {
        let title = format!("Device down: {}", d.name);
        let details = json!({ "device_id": d.id, "device": d.name, "host": d.host, "since": d.state_since, "minutes": r.minutes, "error": d.last_error });
        fire_for(st, p, agent_id, Some(d.id), &key, &title, details, 0).await?;
        Ok(())
    } else if d.state == "up" {
        clear(st, p, agent_id, d.id, &[]).await
    } else {
        // Down for less than the item's time, or not known: nothing to open, and an open alert stays until the device answers.
        Ok(())
    }
}

async fn interface_down(st: &AppState, p: &Policy, agent_id: Uuid, d: &Device, ifaces: &[Iface], r: &NetInterfaceRule) -> sqlx::Result<()> {
    if !kind_matches(&r.kinds, &d.kind) || d.state != "up" {
        // A device that doesn't answer says nothing about its ports (the device alert covers it).
        return if d.state == "up" { clear(st, p, agent_id, d.id, &[]).await } else { Ok(()) };
    }
    let cutoff = chrono::Utc::now() - chrono::Duration::minutes(i64::from(r.minutes));
    let mut keep = Vec::new();
    for i in ifaces {
        // Switched off on purpose (admin down) isn't a fault.
        if !i.monitored || i.admin_status != 1 || !iface_matches(&r.names, i) {
            continue;
        }
        if i.oper_status != 1 && i.status_since <= cutoff {
            let key = format!("dev:{}:if:{}", d.id, i.if_index);
            let label = if i.alias.is_empty() { i.name.clone() } else { format!("{} ({})", i.name, i.alias) };
            let title = format!("Interface down: {} on {}", label, d.name);
            let details = json!({ "device_id": d.id, "device": d.name, "interface": i.name, "alias": i.alias, "if_index": i.if_index, "oper_status": i.oper_status, "since": i.status_since });
            fire_for(st, p, agent_id, Some(d.id), &key, &title, details, 0).await?;
            keep.push(key);
        }
    }
    clear(st, p, agent_id, d.id, &keep).await
}

async fn threshold(st: &AppState, p: &Policy, agent_id: Uuid, d: &Device, ifaces: &[Iface], r: &NetThresholdRule) -> sqlx::Result<()> {
    if !kind_matches(&r.kinds, &d.kind) || d.state != "up" {
        return Ok(());
    }
    let slack = f64::from(d.poll_secs) + 30.0;
    match r.metric.as_str() {
        "supply" => {
            let mut keep = Vec::new();
            for s in d.supplies.as_array().into_iter().flatten() {
                let (Some(pct), Some(idx)) = (s["percent"].as_f64(), s["index"].as_i64()) else { continue };
                // Class 3 is consumed (toner, ink): low is bad. A waste container (class 4) filling up is the opposite, and isn't this item's.
                if s["class"].as_i64() != Some(3) || pct > r.threshold {
                    continue;
                }
                let key = format!("dev:{}:supply:{idx}", d.id);
                let what = s["description"].as_str().unwrap_or("supply");
                let title = format!("{what} low on {}: {pct:.0}%", d.name);
                let details = json!({ "device_id": d.id, "device": d.name, "supply": what, "percent": pct, "threshold": r.threshold });
                fire_for(st, p, agent_id, Some(d.id), &key, &title, details, 0).await?;
                keep.push(key);
            }
            clear(st, p, agent_id, d.id, &keep).await
        }
        "cpu" | "memory" => {
            let (expr, label) = if r.metric == "cpu" { ("cpu_percent::float8", "CPU") } else { ("100.0 * mem_used / nullif(mem_total, 0)", "Memory") };
            let row = sqlx::query(sqlx::AssertSqlSafe(format!(
                "SELECT count(*) AS n, min({expr}) AS lo, avg({expr}) AS av, min(ts) AS first,
                        (SELECT {expr} FROM net_device_metrics WHERE device_id = $1 AND reachable ORDER BY ts DESC LIMIT 1) AS latest
                   FROM net_device_metrics
                  WHERE device_id = $1 AND reachable AND {expr} IS NOT NULL AND ts > now() - make_interval(mins => $2)"
            )))
            .bind(d.id)
            .bind(r.minutes)
            .fetch_one(&st.db)
            .await?;
            let n: i64 = row.get("n");
            let (lo, av, latest): (Option<f64>, Option<f64>, Option<f64>) = (row.get("lo"), row.get("av"), row.get("latest"));
            let first: Option<chrono::DateTime<chrono::Utc>> = row.get("first");
            let covered = first.is_some_and(|f| (chrono::Utc::now() - f).num_milliseconds() as f64 / 1000.0 + slack >= f64::from(r.minutes) * 60.0);
            let key = format!("dev:{}:{}", d.id, r.metric);
            if n > 0 && covered && lo.is_some_and(|l| l >= r.threshold) {
                let title = format!("{label} on {} at or above {}% for {} minutes", d.name, r.threshold, r.minutes);
                let details = json!({ "device_id": d.id, "device": d.name, "metric": r.metric, "value": av.map(|v| (v * 10.0).round() / 10.0), "threshold": r.threshold, "minutes": r.minutes });
                fire_for(st, p, agent_id, Some(d.id), &key, &title, details, 0).await?;
            } else if latest.is_some_and(|l| l < r.threshold) {
                clear(st, p, agent_id, d.id, &[]).await?;
            }
            Ok(())
        }
        "interface_util" => {
            let mut keep = Vec::new();
            let mut any_over = false;
            for i in ifaces.iter().filter(|i| i.monitored && iface_matches(&r.names, i)) {
                let row = sqlx::query(
                    "SELECT count(*) AS n, min(util_pct) AS lo, avg(util_pct) AS av, min(ts) AS first FROM net_interface_metrics
                      WHERE device_id = $1 AND if_index = $2 AND util_pct IS NOT NULL AND ts > now() - make_interval(mins => $3)",
                )
                .bind(d.id)
                .bind(i.if_index)
                .bind(r.minutes)
                .fetch_one(&st.db)
                .await?;
                let n: i64 = row.get("n");
                let (lo, av): (Option<f32>, Option<f64>) = (row.get("lo"), row.get("av"));
                let first: Option<chrono::DateTime<chrono::Utc>> = row.get("first");
                let covered = first.is_some_and(|f| (chrono::Utc::now() - f).num_milliseconds() as f64 / 1000.0 + slack >= f64::from(r.minutes) * 60.0);
                if n > 0 && covered && lo.is_some_and(|l| f64::from(l) >= r.threshold) {
                    any_over = true;
                    let key = format!("dev:{}:util:{}", d.id, i.if_index);
                    let title = format!("{} on {} at or above {}% for {} minutes", i.name, d.name, r.threshold, r.minutes);
                    let details = json!({ "device_id": d.id, "device": d.name, "interface": i.name, "if_index": i.if_index, "value": av.map(|v| (v * 10.0).round() / 10.0), "threshold": r.threshold, "minutes": r.minutes });
                    fire_for(st, p, agent_id, Some(d.id), &key, &title, details, 0).await?;
                    keep.push(key);
                } else if lo.is_some_and(|l| f64::from(l) >= r.threshold) {
                    // Over, but not for long enough yet: whatever is open stays.
                    keep.push(format!("dev:{}:util:{}", d.id, i.if_index));
                }
            }
            let _ = any_over;
            clear(st, p, agent_id, d.id, &keep).await
        }
        _ => Ok(()),
    }
}

/// An alert item changed: check the devices read by the agents it reaches.
pub async fn recheck_item(st: &AppState, item_id: Uuid) {
    let rows: sqlx::Result<Vec<Uuid>> = sqlx::query_scalar(
        "SELECT ap.agent_id FROM agent_policy ap WHERE ap.item_id = $1 AND ap.module = 'alert' AND ap.enabled AND ap.config ->> 'kind' = ANY($2)",
    )
    .bind(item_id)
    .bind(KINDS.map(String::from).to_vec())
    .fetch_all(&st.db)
    .await;
    for agent_id in rows.unwrap_or_default() {
        recheck_agent(st, agent_id).await;
    }
}

/// An agent may run under other items now: check the devices it reads.
pub async fn recheck_agent(st: &AppState, agent_id: Uuid) {
    let devices: sqlx::Result<Vec<Uuid>> = sqlx::query_scalar(
        "SELECT d.id FROM net_devices d JOIN site_network sn ON sn.site_id = d.site_id WHERE sn.agent_id = $1 AND d.enabled",
    )
    .bind(agent_id)
    .fetch_all(&st.db)
    .await;
    for id in devices.unwrap_or_default() {
        evaluate(st, agent_id, id).await;
    }
}
