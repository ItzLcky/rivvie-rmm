//! Uptime monitors (docs/design/uptime.md): ping, TCP, HTTP(S), TLS certificate and DNS checks
//! run by an agent, the one a monitor names or its site's designated agent.
//!
//! The runner gets its monitors as [`rmm_proto::checks::CheckSpec`]s ([`crate::checks`]) and
//! reports results; [`ingest`] stores them and moves the monitor's state, and [`evaluate`] opens
//! and clears alerts from the `uptime` alert items of the runner's policy set. Keys:
//! `mon:<id>` (down), `mon:<id>:cert` (certificate), `mon:<id>:latency` (slow). A monitor whose
//! runner is offline, or has gone quiet, is `unknown`, not down ([`run`]).
//!
//! Step C1b of the parity plan adds monitors run by the server (`runner = 'server'`); they are
//! refused for now.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use rmm_proto::checks::{CheckData, CheckKind, CheckResult, CheckSpec, HttpMethod};
use serde_json::{Value, json};
use sqlx::Row;
use tracing::warn;
use uuid::Uuid;

use crate::alerts::{Policy, Rule, UptimeRule, announce, fire_on, policies_for};
use crate::state::AppState;

pub const KINDS: &[&str] = &["ping", "tcp", "http", "tls", "dns"];
pub const DNS_RECORDS: &[&str] = &["A", "AAAA", "CNAME", "MX", "TXT"];

fn host(v: &Value, what: &str) -> Result<String, String> {
    let h = v.as_str().unwrap_or("").trim();
    if h.is_empty() || h.len() > 253 || h.chars().any(|c| c.is_whitespace() || c.is_control() || "/@?#".contains(c)) {
        return Err(format!("{what} must be a host name or address"));
    }
    Ok(h.trim_matches(['[', ']']).to_string())
}

fn port(v: &Value, default: Option<u16>) -> Result<u16, String> {
    match (v.as_u64(), default) {
        (Some(p), _) if (1..=65535).contains(&p) => Ok(p as u16),
        (None, Some(d)) if v.is_null() => Ok(d),
        _ => Err("port must be 1-65535".into()),
    }
}

/// A monitor's `config` as the check the agent runs, validated. The stored config is
/// [`clean_config`] of the same.
pub fn check_kind(kind: &str, c: &Value) -> Result<CheckKind, String> {
    Ok(match kind {
        "ping" => CheckKind::Ping { host: host(&c["host"], "host")? },
        "tcp" => CheckKind::Tcp { host: host(&c["host"], "host")?, port: port(&c["port"], None)? },
        "http" => {
            let url = c["url"].as_str().unwrap_or("").trim().to_string();
            if url.len() > 2000 {
                return Err("the URL is too long".into());
            }
            rmm_checks::http::Url::parse(&url)?;
            let method = match c["method"].as_str().unwrap_or("get").to_ascii_lowercase().as_str() {
                "get" => HttpMethod::Get,
                "head" => HttpMethod::Head,
                _ => return Err("method must be GET or HEAD".into()),
            };
            let statuses: Vec<u16> = match &c["statuses"] {
                Value::Null => vec![],
                Value::Array(a) => a.iter().map(|s| s.as_u64().filter(|s| (100..=599).contains(s)).map(|s| s as u16).ok_or("statuses are HTTP status codes (100-599)")).collect::<Result<_, _>>()?,
                _ => return Err("statuses must be a list of status codes".into()),
            };
            if statuses.len() > 20 {
                return Err("at most 20 statuses".into());
            }
            let keyword = c["keyword"].as_str().map(str::trim).filter(|k| !k.is_empty()).map(String::from);
            if keyword.as_ref().is_some_and(|k| k.chars().count() > 200) {
                return Err("the keyword must be at most 200 characters".into());
            }
            if method == HttpMethod::Head && keyword.is_some() {
                return Err("a HEAD request has no body to look for a keyword in".into());
            }
            CheckKind::Http { url, method, statuses, keyword, keyword_absent: c["keyword_absent"].as_bool().unwrap_or(false), verify_tls: c["verify_tls"].as_bool().unwrap_or(true) }
        }
        "tls" => CheckKind::Tls {
            host: host(&c["host"], "host")?,
            port: port(&c["port"], Some(443))?,
            server_name: match c["server_name"].as_str().map(str::trim).filter(|s| !s.is_empty()) {
                Some(s) => Some(host(&json!(s), "server name")?),
                None => None,
            },
        },
        "dns" => {
            let name = c["name"].as_str().unwrap_or("").trim().trim_end_matches('.').to_string();
            if name.is_empty() || name.len() > 253 || name.split('.').any(|l| l.is_empty() || l.len() > 63) || name.chars().any(|ch| ch.is_whitespace()) {
                return Err("name must be a DNS name".into());
            }
            let record = c["record"].as_str().unwrap_or("A").trim().to_ascii_uppercase();
            if !DNS_RECORDS.contains(&record.as_str()) {
                return Err(format!("record must be one of {}", DNS_RECORDS.join(", ")));
            }
            let server = c["server"].as_str().map(str::trim).filter(|s| !s.is_empty()).map(String::from);
            if let Some(s) = &server
                && s.parse::<std::net::SocketAddr>().is_err()
                && s.trim_matches(['[', ']']).parse::<std::net::IpAddr>().is_err()
            {
                return Err("the DNS server must be an address (ip or ip:port)".into());
            }
            let expect: Vec<String> = c["expect"].as_array().map(|a| a.iter().filter_map(|e| e.as_str()).map(str::trim).filter(|e| !e.is_empty()).map(String::from).collect()).unwrap_or_default();
            if expect.len() > 20 || expect.iter().any(|e| e.len() > 255) {
                return Err("at most 20 expected answers".into());
            }
            CheckKind::Dns { name, record, server, expect }
        }
        _ => return Err(format!("kind must be one of {}", KINDS.join(", "))),
    })
}

/// The config as stored: only the fields of the kind, normalised.
pub fn clean_config(kind: &CheckKind) -> Value {
    match kind {
        CheckKind::Ping { host } => json!({ "host": host }),
        CheckKind::Tcp { host, port } => json!({ "host": host, "port": port }),
        CheckKind::Http { url, method, statuses, keyword, keyword_absent, verify_tls } => json!({
            "url": url, "method": if *method == HttpMethod::Head { "head" } else { "get" }, "statuses": statuses,
            "keyword": keyword, "keyword_absent": keyword_absent, "verify_tls": verify_tls,
        }),
        CheckKind::Tls { host, port, server_name } => json!({ "host": host, "port": port, "server_name": server_name }),
        CheckKind::Dns { name, record, server, expect } => json!({ "name": name, "record": record, "server": server, "expect": expect }),
        CheckKind::Backup { .. } => json!({}),
    }
}

/// What a monitor looks at, for lists: the host, `host:port` or URL.
pub fn target(kind: &str, c: &Value) -> String {
    let s = |k: &str| c[k].as_str().unwrap_or("").to_string();
    match kind {
        "tcp" | "tls" => format!("{}:{}", s("host"), c["port"].as_u64().unwrap_or(443)),
        "http" => s("url"),
        "dns" => format!("{} {}", s("name"), s("record")),
        _ => s("host"),
    }
}

// ---------------------------------------------------------------------------
// What the runner runs
// ---------------------------------------------------------------------------

/// The monitors each of these agents runs, as checks.
pub async fn specs_for(st: &AppState, agents: &[Uuid]) -> sqlx::Result<HashMap<Uuid, Vec<CheckSpec>>> {
    let rows: Vec<(Uuid, Uuid, String, Value, i32, i32)> = sqlx::query_as(
        "SELECT coalesce(m.agent_id, sn.agent_id), m.id, m.kind, m.config, m.interval_secs, m.timeout_secs
           FROM uptime_monitors m LEFT JOIN site_network sn ON sn.site_id = m.site_id
          WHERE m.enabled AND m.runner = 'agent' AND coalesce(m.agent_id, sn.agent_id) = ANY($1)
          ORDER BY m.created_at",
    )
    .bind(agents)
    .fetch_all(&st.db)
    .await?;
    let mut out: HashMap<Uuid, Vec<CheckSpec>> = HashMap::new();
    for (agent, id, kind, config, interval, timeout) in rows {
        match check_kind(&kind, &config) {
            Ok(k) => out.entry(agent).or_default().push(CheckSpec { id, interval_secs: interval as u32, timeout_secs: timeout as u32, kind: k }),
            Err(e) => warn!(monitor = %id, "monitor config no longer valid: {e}"),
        }
    }
    Ok(out)
}

/// The agent that runs a monitor now: the one it names, else the site's designated agent.
pub async fn runner_of(st: &AppState, monitor_id: Uuid) -> sqlx::Result<Option<Uuid>> {
    Ok(sqlx::query_scalar(
        "SELECT coalesce(m.agent_id, sn.agent_id) FROM uptime_monitors m LEFT JOIN site_network sn ON sn.site_id = m.site_id WHERE m.id = $1 AND m.runner = 'agent'",
    )
    .bind(monitor_id)
    .fetch_optional(&st.db)
    .await?
    .flatten())
}

// ---------------------------------------------------------------------------
// Results
// ---------------------------------------------------------------------------

/// Results the agent reported for monitors it runs (others are ignored: it was moved off them).
pub async fn ingest(st: &AppState, agent_id: Uuid, mut results: Vec<CheckResult>) -> sqlx::Result<()> {
    if results.is_empty() {
        return Ok(());
    }
    let ids: Vec<Uuid> = results.iter().map(|r| r.check_id).collect();
    let mine: Vec<(Uuid, Uuid)> = sqlx::query_as(
        "SELECT m.id, m.client_id FROM uptime_monitors m LEFT JOIN site_network sn ON sn.site_id = m.site_id
          WHERE m.id = ANY($1) AND m.enabled AND m.runner = 'agent' AND coalesce(m.agent_id, sn.agent_id) = $2",
    )
    .bind(&ids)
    .bind(agent_id)
    .fetch_all(&st.db)
    .await?;
    let client: HashMap<Uuid, Uuid> = mine.into_iter().collect();
    results.retain(|r| client.contains_key(&r.check_id));
    results.sort_by_key(|r| r.at);
    let now = Utc::now();
    let mut touched = Vec::new();
    for r in results {
        // Agent clocks drift: keep its time only when it's plausible.
        let at = if r.at > now || r.at < now - chrono::Duration::hours(24) { now } else { r.at };
        let message: String = r.message.chars().take(500).collect();
        let cert = match &r.data {
            Some(CheckData::Cert(c)) => Some(c.clone()),
            _ => None,
        };
        let mut tx = st.db.begin().await?;
        sqlx::query("INSERT INTO uptime_results (monitor_id, ts, ok, ms, message) VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING")
            .bind(r.check_id)
            .bind(at)
            .bind(r.ok)
            .bind(r.latency_ms.map(|m| m.min(i32::MAX as u32) as i32))
            .bind(&message)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "UPDATE uptime_monitors SET
                    fail_count = CASE WHEN $2 THEN 0 ELSE fail_count + 1 END,
                    state_since = CASE WHEN state = (CASE WHEN $2 THEN 'up' ELSE 'down' END) THEN state_since ELSE $3 END,
                    state = CASE WHEN $2 THEN 'up' ELSE 'down' END,
                    last_at = $3, last_ms = $4, last_message = $5, last_value = $6,
                    cert_not_after = coalesce($7, cert_not_after), cert = coalesce($8, cert)
              WHERE id = $1 AND (last_at IS NULL OR last_at <= $3)",
        )
        .bind(r.check_id)
        .bind(r.ok)
        .bind(at)
        .bind(r.latency_ms.map(|m| m.min(i32::MAX as u32) as i32))
        .bind(&message)
        .bind(r.value)
        .bind(cert.as_ref().map(|c| c.not_after))
        .bind(cert.as_ref().map(|c| json!({ "subject": c.subject, "issuer": c.issuer, "sans": c.sans, "not_before": c.not_before, "not_after": c.not_after, "untrusted": c.untrusted })))
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        if !touched.contains(&r.check_id) {
            touched.push(r.check_id);
        }
    }
    for id in touched {
        st.hub.publish(crate::hub::Event::Monitor { id, client_id: client[&id] });
        evaluate(st, id).await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Alerts
// ---------------------------------------------------------------------------

#[derive(sqlx::FromRow, Debug, Clone)]
pub struct Monitor {
    pub id: Uuid,
    pub name: String,
    pub kind: String,
    pub config: Value,
    pub enabled: bool,
    pub state: String,
    pub state_since: DateTime<Utc>,
    pub fail_count: i32,
    pub last_message: Option<String>,
    pub last_ms: Option<i32>,
    pub cert_not_after: Option<DateTime<Utc>>,
    pub runner: Option<Uuid>,
}

/// What one item finds about one monitor: `(key, title, details)` to open, and whether the
/// down key is to be kept open even though it isn't firing (the monitor isn't known to be up).
pub fn findings(m: &Monitor, r: &UptimeRule, recent_ms: &[Option<i32>], now: DateTime<Utc>) -> (Vec<(String, String, Value)>, Vec<String>) {
    let mut fire = Vec::new();
    let mut hold = Vec::new();
    if !r.kinds.is_empty() && !r.kinds.iter().any(|k| k.eq_ignore_ascii_case(&m.kind)) {
        return (fire, hold);
    }
    let what = target(&m.kind, &m.config);
    let down_key = format!("mon:{}", m.id);
    match m.state.as_str() {
        "down" if m.fail_count >= r.failures => fire.push((
            down_key,
            format!("Monitor down: {}", m.name),
            json!({ "monitor_id": m.id, "monitor": m.name, "kind": m.kind, "target": what, "since": m.state_since, "failures": m.fail_count, "message": m.last_message }),
        )),
        // Failing, but not for long enough yet; or not known: whatever is open stays.
        "down" | "unknown" => hold.push(down_key),
        _ => {}
    }
    let cert_key = format!("mon:{}:cert", m.id);
    if r.cert_days > 0
        && let Some(after) = m.cert_not_after
    {
        let days = (after - now).num_seconds().div_euclid(86_400);
        if days <= i64::from(r.cert_days) {
            let title = if after <= now { format!("Certificate expired: {}", m.name) } else { format!("Certificate expires in {days} days: {}", m.name) };
            fire.push((cert_key, title, json!({ "monitor_id": m.id, "monitor": m.name, "target": what, "not_after": after, "days_left": days, "cert_days": r.cert_days })));
        }
    }
    if let Some(limit) = r.latency_ms {
        let key = format!("mon:{}:latency", m.id);
        let n = r.failures.max(1) as usize;
        let slow = recent_ms.len() >= n && recent_ms[..n].iter().all(|ms| ms.is_some_and(|ms| ms > limit));
        if m.state == "up" && slow {
            fire.push((key, format!("Monitor slow: {}", m.name), json!({ "monitor_id": m.id, "monitor": m.name, "target": what, "ms": m.last_ms, "latency_ms": limit })));
        } else if m.state != "up" || recent_ms.first().is_some_and(|ms| ms.is_some_and(|ms| ms > limit)) {
            // Down, unknown, or still slow but not for long enough: an open alert stays.
            hold.push(key);
        }
    }
    (fire, hold)
}

async fn clear_monitor(st: &AppState, p: &Policy, agent_id: Uuid, monitor_id: Uuid, keep: &[String]) -> sqlx::Result<()> {
    let ids: Vec<Uuid> = sqlx::query_scalar(
        "UPDATE alerts SET resolved_at = now(), resolution = 'cleared'
          WHERE policy_id = $1 AND agent_id = $2 AND monitor_id = $3 AND resolved_at IS NULL AND NOT (key = ANY($4))
          RETURNING id",
    )
    .bind(p.id)
    .bind(agent_id)
    .bind(monitor_id)
    .bind(keep)
    .fetch_all(&st.db)
    .await?;
    announce(st, &ids, "resolved", &p.channel_ids, p.notify_resolved).await;
    Ok(())
}

/// Closes every open alert about a monitor, quietly (it was switched off, moved or deleted).
pub async fn close_monitor(st: &AppState, monitor_id: Uuid) {
    let res: sqlx::Result<Vec<Uuid>> =
        sqlx::query_scalar("UPDATE alerts SET resolved_at = now(), resolution = 'policy' WHERE monitor_id = $1 AND resolved_at IS NULL RETURNING id")
            .bind(monitor_id)
            .fetch_all(&st.db)
            .await;
    match res {
        Ok(ids) => announce(st, &ids, "resolved", &[], false).await,
        Err(e) => warn!(%monitor_id, "closing a monitor's alerts: {e}"),
    }
}

const MONITOR_SELECT: &str = "SELECT m.id, m.name, m.kind, m.config, m.enabled, m.state, m.state_since, m.fail_count, m.last_message, m.last_ms,
        m.cert_not_after, coalesce(m.agent_id, sn.agent_id) AS runner
   FROM uptime_monitors m LEFT JOIN site_network sn ON sn.site_id = m.site_id";

/// Checks one monitor against every `uptime` item that reaches its runner.
pub async fn evaluate(st: &AppState, monitor_id: Uuid) {
    if let Err(e) = eval(st, monitor_id).await {
        warn!(%monitor_id, "uptime alerts: {e}");
    }
}

async fn eval(st: &AppState, monitor_id: Uuid) -> sqlx::Result<()> {
    let Some(m): Option<Monitor> = sqlx::query_as(sqlx::AssertSqlSafe(format!("{MONITOR_SELECT} WHERE m.id = $1"))).bind(monitor_id).fetch_optional(&st.db).await? else {
        return Ok(());
    };
    let Some(runner) = m.runner.filter(|_| m.enabled) else { return Ok(()) };
    // Alerts opened under an earlier runner close: that agent's items don't own them any more.
    let moved: Vec<Uuid> = sqlx::query_scalar(
        "UPDATE alerts SET resolved_at = now(), resolution = 'policy' WHERE monitor_id = $1 AND agent_id <> $2 AND resolved_at IS NULL RETURNING id",
    )
    .bind(m.id)
    .bind(runner)
    .fetch_all(&st.db)
    .await?;
    announce(st, &moved, "resolved", &[], false).await;
    let policies = policies_for(st, runner, "uptime").await?;
    if policies.is_empty() {
        return Ok(());
    }
    let recent: Vec<Option<i32>> =
        sqlx::query_scalar("SELECT ms FROM uptime_results WHERE monitor_id = $1 AND ok ORDER BY ts DESC LIMIT 20").bind(m.id).fetch_all(&st.db).await?;
    for p in policies {
        let Some(Rule::Uptime(r)) = p.rule() else { continue };
        let (fire, mut keep) = findings(&m, &r, &recent, Utc::now());
        for (key, title, details) in fire {
            fire_on(st, &p, runner, None, Some(m.id), &key, &title, details, 0).await?;
            keep.push(key);
        }
        clear_monitor(st, &p, runner, m.id, &keep).await?;
    }
    Ok(())
}

/// An alert item changed: check the monitors run by the agents it reaches.
pub async fn recheck_item(st: &AppState, item_id: Uuid) {
    let rows: sqlx::Result<Vec<Uuid>> =
        sqlx::query_scalar("SELECT ap.agent_id FROM agent_policy ap WHERE ap.item_id = $1 AND ap.module = 'alert' AND ap.enabled AND ap.config ->> 'kind' = 'uptime'")
            .bind(item_id)
            .fetch_all(&st.db)
            .await;
    for agent_id in rows.unwrap_or_default() {
        recheck_agent(st, agent_id).await;
    }
}

/// An agent may run under other items now: check the monitors it runs.
pub async fn recheck_agent(st: &AppState, agent_id: Uuid) {
    let ids: sqlx::Result<Vec<Uuid>> = sqlx::query_scalar(
        "SELECT m.id FROM uptime_monitors m LEFT JOIN site_network sn ON sn.site_id = m.site_id WHERE m.enabled AND m.runner = 'agent' AND coalesce(m.agent_id, sn.agent_id) = $1",
    )
    .bind(agent_id)
    .fetch_all(&st.db)
    .await;
    for id in ids.unwrap_or_default() {
        evaluate(st, id).await;
    }
}

// ---------------------------------------------------------------------------
// Background: staleness, rollups, retention
// ---------------------------------------------------------------------------

/// Monitors nobody is checking become `unknown`: the runner is offline, can't run checks, there
/// is no runner, or it hasn't reported for three intervals.
pub async fn mark_unknown(st: &AppState) -> sqlx::Result<()> {
    let ids: Vec<(Uuid, Uuid)> = sqlx::query_as(
        "UPDATE uptime_monitors m SET state = 'unknown', state_since = now(), fail_count = 0
           FROM uptime_monitors x LEFT JOIN site_network sn ON sn.site_id = x.site_id
                LEFT JOIN agents a ON a.id = coalesce(x.agent_id, sn.agent_id)
          WHERE m.id = x.id AND m.state <> 'unknown' AND m.runner = 'agent'
            AND (NOT m.enabled OR a.id IS NULL OR NOT a.online OR NOT ($1 = ANY(a.capabilities))
                 OR m.last_at IS NULL OR m.last_at < now() - make_interval(secs => m.interval_secs * 3 + 90))
          RETURNING m.id, m.client_id",
    )
    .bind(rmm_proto::checks::CAPABILITY)
    .fetch_all(&st.db)
    .await?;
    for (id, client_id) in ids {
        st.hub.publish(crate::hub::Event::Monitor { id, client_id });
        evaluate(st, id).await;
    }
    Ok(())
}

pub async fn run(st: Arc<AppState>) {
    let every = Duration::from_secs(st.cfg.alert_eval_secs.clamp(2, 60).into());
    let mut tick = tokio::time::interval(every);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        if let Err(e) = mark_unknown(&st).await {
            warn!("uptime: marking unchecked monitors unknown: {e}");
        }
    }
}

pub async fn rollup(db: &sqlx::PgPool) -> sqlx::Result<()> {
    sqlx::query(
        "INSERT INTO uptime_hourly (monitor_id, hour, checks, failures, avg_ms, max_ms)
         SELECT monitor_id, date_trunc('hour', ts), count(*), count(*) FILTER (WHERE NOT ok), avg(ms) FILTER (WHERE ok), max(ms) FILTER (WHERE ok)
           FROM uptime_results
          WHERE ts >= date_trunc('hour', now()) - interval '3 hours' AND ts < date_trunc('hour', now())
          GROUP BY 1, 2
         ON CONFLICT (monitor_id, hour) DO UPDATE SET checks = EXCLUDED.checks, failures = EXCLUDED.failures, avg_ms = EXCLUDED.avg_ms, max_ms = EXCLUDED.max_ms",
    )
    .execute(db)
    .await?;
    Ok(())
}

pub async fn prune(db: &sqlx::PgPool, raw_days: i32, retention_days: i32) -> sqlx::Result<()> {
    sqlx::query("DELETE FROM uptime_results WHERE ts < now() - make_interval(days => $1)").bind(raw_days).execute(db).await?;
    sqlx::query("DELETE FROM uptime_hourly WHERE hour < now() - make_interval(days => $1)").bind(retention_days).execute(db).await?;
    Ok(())
}

/// Checks and failures per monitor since `since`: hourly rollups where there are any, raw
/// results after them.
pub async fn availability(db: &sqlx::PgPool, ids: &[Uuid], since: DateTime<Utc>) -> sqlx::Result<HashMap<Uuid, (i64, i64)>> {
    let rows = sqlx::query(
        "WITH h AS (SELECT monitor_id, hour, checks, failures FROM uptime_hourly WHERE monitor_id = ANY($1) AND hour >= date_trunc('hour', $2::timestamptz)),
              edge AS (SELECT monitor_id, max(hour) + interval '1 hour' AS after FROM h GROUP BY 1),
              r AS (SELECT u.monitor_id, count(*) AS checks, count(*) FILTER (WHERE NOT u.ok) AS failures
                      FROM uptime_results u LEFT JOIN edge e ON e.monitor_id = u.monitor_id
                     WHERE u.monitor_id = ANY($1) AND u.ts >= greatest($2, coalesce(e.after, $2)) GROUP BY 1)
         SELECT monitor_id, sum(checks)::bigint AS checks, sum(failures)::bigint AS failures
           FROM (SELECT monitor_id, checks::bigint, failures::bigint FROM h UNION ALL SELECT monitor_id, checks, failures FROM r) x
          GROUP BY 1",
    )
    .bind(ids)
    .bind(since)
    .fetch_all(db)
    .await?;
    Ok(rows.into_iter().map(|r| (r.get::<Uuid, _>("monitor_id"), (r.get::<i64, _>("checks"), r.get::<i64, _>("failures")))).collect())
}

/// Percent of checks that passed, to two decimals; None without checks.
pub fn percent(checks: i64, failures: i64) -> Option<f64> {
    (checks > 0).then(|| ((checks - failures) as f64 * 10_000.0 / checks as f64).round() / 100.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn monitor(state: &str, fails: i32) -> Monitor {
        Monitor {
            id: Uuid::from_u128(7),
            name: "Web".into(),
            kind: "http".into(),
            config: json!({ "url": "https://example.com" }),
            enabled: true,
            state: state.into(),
            state_since: Utc::now(),
            fail_count: fails,
            last_message: None,
            last_ms: Some(900),
            cert_not_after: None,
            runner: None,
        }
    }

    fn keys(f: &[(String, String, Value)]) -> Vec<&str> {
        f.iter().map(|f| f.0.as_str()).collect()
    }

    #[test]
    fn consecutive_failures() {
        let r = UptimeRule::default();
        let now = Utc::now();
        let id = "mon:00000000-0000-0000-0000-000000000007";
        let (f, hold) = findings(&monitor("down", 1), &r, &[], now);
        assert!(f.is_empty() && hold == [id], "one failure isn't down yet, but doesn't clear an open alert");
        let (f, _) = findings(&monitor("down", 2), &r, &[], now);
        assert_eq!(keys(&f), [id]);
        assert_eq!(f[0].1, "Monitor down: Web");
        let (f, hold) = findings(&monitor("up", 0), &r, &[], now);
        assert!(f.is_empty() && hold.is_empty(), "up clears");
        let (f, hold) = findings(&monitor("unknown", 0), &r, &[], now);
        assert!(f.is_empty() && hold == [id], "unknown neither opens nor clears");
        let only_tls = UptimeRule { kinds: vec!["tls".into()], ..r.clone() };
        assert!(findings(&monitor("down", 5), &only_tls, &[], now).0.is_empty(), "another kind of monitor");
    }

    #[test]
    fn certificates_and_latency() {
        let now = Utc::now();
        let mut m = monitor("up", 0);
        m.cert_not_after = Some(now + chrono::Duration::days(5) + chrono::Duration::hours(1));
        let r = UptimeRule::default();
        let (f, _) = findings(&m, &r, &[], now);
        assert_eq!(f[0].1, "Certificate expires in 5 days: Web");
        m.cert_not_after = Some(now - chrono::Duration::hours(1));
        assert_eq!(findings(&m, &r, &[], now).0[0].1, "Certificate expired: Web");
        m.cert_not_after = Some(now + chrono::Duration::days(60));
        assert!(findings(&m, &r, &[], now).0.is_empty());
        m.cert_not_after = Some(now + chrono::Duration::days(1));
        assert!(findings(&m, &UptimeRule { cert_days: 0, ..r.clone() }, &[], now).0.is_empty(), "0: off");

        let m = monitor("up", 0);
        let slow = UptimeRule { latency_ms: Some(500), cert_days: 0, ..r };
        let (f, _) = findings(&m, &slow, &[Some(900), Some(800)], now);
        assert_eq!(keys(&f), ["mon:00000000-0000-0000-0000-000000000007:latency"]);
        let (f, hold) = findings(&m, &slow, &[Some(900), Some(100)], now);
        assert!(f.is_empty() && hold.len() == 1, "slow once: not yet, but an open alert stays");
        let (f, hold) = findings(&m, &slow, &[Some(100), Some(900)], now);
        assert!(f.is_empty() && hold.is_empty(), "fast again clears");
    }

    #[test]
    fn configs() {
        let ok = |kind: &str, c: Value| check_kind(kind, &c).map(|k| clean_config(&k));
        assert_eq!(ok("ping", json!({ "host": " 10.0.0.1 " })).unwrap(), json!({ "host": "10.0.0.1" }));
        assert!(ok("ping", json!({ "host": "a b" })).is_err());
        assert!(ok("tcp", json!({ "host": "db", "port": 0 })).is_err());
        assert_eq!(ok("tls", json!({ "host": "example.com" })).unwrap()["port"], 443);
        let http = ok("http", json!({ "url": "https://example.com/health", "statuses": [200, 204], "keyword": "ok" })).unwrap();
        assert_eq!((http["method"].as_str(), http["verify_tls"].as_bool()), (Some("get"), Some(true)));
        assert!(ok("http", json!({ "url": "https://user:pw@example.com/" })).unwrap_err().contains("password"));
        assert!(ok("http", json!({ "url": "ftp://example.com/" })).is_err());
        assert!(ok("http", json!({ "url": "http://x/", "statuses": [99] })).is_err());
        assert!(ok("http", json!({ "url": "http://x/", "method": "head", "keyword": "ok" })).is_err());
        let dns = ok("dns", json!({ "name": "example.com.", "record": "mx", "server": "10.0.0.53", "expect": ["10 mail.example.com", ""] })).unwrap();
        assert_eq!(dns, json!({ "name": "example.com", "record": "MX", "server": "10.0.0.53", "expect": ["10 mail.example.com"] }));
        assert!(ok("dns", json!({ "name": "example.com", "record": "SOA" })).is_err());
        assert!(ok("dns", json!({ "name": "example.com", "server": "resolver.example" })).is_err());
        assert!(ok("smtp", json!({})).is_err());
        assert_eq!(target("tcp", &json!({ "host": "db", "port": 5432 })), "db:5432");
        assert_eq!(percent(1000, 1), Some(99.9));
        assert_eq!(percent(3, 1), Some(66.67));
        assert_eq!(percent(0, 0), None);
    }
}
