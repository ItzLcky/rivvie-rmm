//! Reports: service desk (volume, backlog, response and resolution times, SLA attainment,
//! satisfaction), technician utilisation, client profitability, and the quarterly business
//! review PDF that combines service desk and RMM figures for one client.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::response::Response;
use chrono::{Datelike, Duration, NaiveDate, Utc};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::auth::{Perm, User};
use crate::billing::{money, qty};
use crate::error::{ApiError, ApiResult};
use crate::pdf::Block;
use crate::state::AppState;

#[derive(Deserialize)]
pub struct Range {
    from: Option<NaiveDate>,
    to: Option<NaiveDate>,
    client_id: Option<Uuid>,
}

/// Defaults to the last 30 days; `to` is inclusive.
fn range(r: &Range) -> ApiResult<(NaiveDate, NaiveDate)> {
    let to = r.to.unwrap_or_else(|| Utc::now().date_naive());
    let from = r.from.unwrap_or(to - Duration::days(29));
    if to < from || (to - from).num_days() > 731 {
        return Err(ApiError::BadRequest("choose a range of up to two years".into()));
    }
    Ok((from, to))
}

fn pct(n: i64, d: i64) -> Option<f64> {
    (d > 0).then(|| (n as f64 * 1000.0 / d as f64).round() / 10.0)
}

#[derive(sqlx::FromRow)]
struct DeskTotals {
    opened: i64,
    closed: i64,
    backlog: i64,
    age_1d: i64,
    age_3d: i64,
    age_7d: i64,
    age_30d: i64,
    age_older: i64,
    first_response_mins: Option<f64>,
    resolution_mins: Option<f64>,
    respond_met: i64,
    respond_total: i64,
    resolve_met: i64,
    resolve_total: i64,
    csat_good: i64,
    csat_bad: i64,
}

async fn desk_totals(st: &AppState, scope: Option<&[Uuid]>, client: Option<Uuid>, from: NaiveDate, to: NaiveDate) -> sqlx::Result<DeskTotals> {
    sqlx::query_as(
        "WITH t AS (
            SELECT t.*, bs.category FROM tickets t JOIN board_statuses bs ON bs.id = t.status_id
             WHERE t.merged_into IS NULL AND ($1::uuid[] IS NULL OR t.client_id = ANY($1)) AND ($2::uuid IS NULL OR t.client_id = $2)
         )
         SELECT
            (SELECT count(*) FROM t WHERE created_at >= $3 AND created_at < $4::date + 1) AS opened,
            (SELECT count(*) FROM t WHERE resolved_at >= $3 AND resolved_at < $4::date + 1) AS closed,
            (SELECT count(*) FROM t WHERE category NOT IN ('resolved', 'closed')) AS backlog,
            (SELECT count(*) FROM t WHERE category NOT IN ('resolved', 'closed') AND created_at > now() - interval '1 day') AS age_1d,
            (SELECT count(*) FROM t WHERE category NOT IN ('resolved', 'closed') AND created_at <= now() - interval '1 day' AND created_at > now() - interval '3 days') AS age_3d,
            (SELECT count(*) FROM t WHERE category NOT IN ('resolved', 'closed') AND created_at <= now() - interval '3 days' AND created_at > now() - interval '7 days') AS age_7d,
            (SELECT count(*) FROM t WHERE category NOT IN ('resolved', 'closed') AND created_at <= now() - interval '7 days' AND created_at > now() - interval '30 days') AS age_30d,
            (SELECT count(*) FROM t WHERE category NOT IN ('resolved', 'closed') AND created_at <= now() - interval '30 days') AS age_older,
            (SELECT percentile_cont(0.5) WITHIN GROUP (ORDER BY extract(epoch FROM first_response_at - created_at) / 60)
               FROM t WHERE first_response_at IS NOT NULL AND created_at >= $3 AND created_at < $4::date + 1) AS first_response_mins,
            (SELECT percentile_cont(0.5) WITHIN GROUP (ORDER BY extract(epoch FROM resolved_at - created_at) / 60)
               FROM t WHERE resolved_at >= $3 AND resolved_at < $4::date + 1) AS resolution_mins,
            (SELECT count(*) FROM t WHERE respond_by IS NOT NULL AND first_response_at IS NOT NULL AND first_response_at <= respond_by
                AND created_at >= $3 AND created_at < $4::date + 1) AS respond_met,
            (SELECT count(*) FROM t WHERE respond_by IS NOT NULL AND (first_response_at IS NOT NULL OR respond_by < now())
                AND created_at >= $3 AND created_at < $4::date + 1) AS respond_total,
            (SELECT count(*) FROM t WHERE resolve_by IS NOT NULL AND resolved_at <= resolve_by AND resolved_at >= $3 AND resolved_at < $4::date + 1) AS resolve_met,
            (SELECT count(*) FROM t WHERE resolve_by IS NOT NULL AND resolved_at >= $3 AND resolved_at < $4::date + 1) AS resolve_total,
            (SELECT count(*) FROM csat_surveys c JOIN t ON t.id = c.ticket_id WHERE c.rating = 'good' AND c.answered_at >= $3 AND c.answered_at < $4::date + 1) AS csat_good,
            (SELECT count(*) FROM csat_surveys c JOIN t ON t.id = c.ticket_id WHERE c.rating = 'bad' AND c.answered_at >= $3 AND c.answered_at < $4::date + 1) AS csat_bad",
    )
    .bind(scope)
    .bind(client)
    .bind(from)
    .bind(to)
    .fetch_one(&st.db)
    .await
}

async fn breakdown(st: &AppState, scope: Option<&[Uuid]>, client: Option<Uuid>, from: NaiveDate, to: NaiveDate, by: &str) -> sqlx::Result<Vec<Value>> {
    let (label, join) = match by {
        "client" => ("coalesce(c.name, 'Triage')", "LEFT JOIN clients c ON c.id = t.client_id"),
        "board" => ("b.name", "JOIN boards b ON b.id = t.board_id"),
        "type" => ("coalesce(ty.name, 'No type')", "LEFT JOIN ticket_types ty ON ty.id = t.type_id"),
        _ => ("coalesce(u.name, 'Unassigned')", "LEFT JOIN users u ON u.id = t.assignee_id"),
    };
    let rows: Vec<(String, i64, i64)> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT {label} AS name,
                count(*) FILTER (WHERE t.created_at >= $3 AND t.created_at < $4::date + 1),
                count(*) FILTER (WHERE t.resolved_at >= $3 AND t.resolved_at < $4::date + 1)
           FROM tickets t {join}
          WHERE t.merged_into IS NULL AND ($1::uuid[] IS NULL OR t.client_id = ANY($1)) AND ($2::uuid IS NULL OR t.client_id = $2)
            AND ((t.created_at >= $3 AND t.created_at < $4::date + 1) OR (t.resolved_at >= $3 AND t.resolved_at < $4::date + 1))
          GROUP BY 1 ORDER BY 2 DESC, 1 LIMIT 50"
    )))
    .bind(scope)
    .bind(client)
    .bind(from)
    .bind(to)
    .fetch_all(&st.db)
    .await?;
    Ok(rows.into_iter().map(|(n, o, c)| json!({ "name": n, "opened": o, "closed": c })).collect())
}

pub async fn service_desk(State(st): State<Arc<AppState>>, u: User, Query(q): Query<Range>) -> ApiResult<Json<Value>> {
    let (from, to) = range(&q)?;
    if let Some(c) = q.client_id {
        super::access::client(&u, c)?;
    }
    let t = desk_totals(&st, u.scope(), q.client_id, from, to).await?;
    Ok(Json(json!({
        "from": from, "to": to,
        "opened": t.opened, "closed": t.closed, "backlog": t.backlog,
        "backlog_age": { "under_1d": t.age_1d, "1_3d": t.age_3d, "3_7d": t.age_7d, "7_30d": t.age_30d, "over_30d": t.age_older },
        "first_response_median_mins": t.first_response_mins.map(|m| m.round()),
        "resolution_median_mins": t.resolution_mins.map(|m| m.round()),
        "sla": {
            "respond": { "met": t.respond_met, "total": t.respond_total, "pct": pct(t.respond_met, t.respond_total) },
            "resolve": { "met": t.resolve_met, "total": t.resolve_total, "pct": pct(t.resolve_met, t.resolve_total) },
        },
        "csat": { "good": t.csat_good, "bad": t.csat_bad, "pct": pct(t.csat_good, t.csat_good + t.csat_bad) },
        "by_client": breakdown(&st, u.scope(), q.client_id, from, to, "client").await?,
        "by_board": breakdown(&st, u.scope(), q.client_id, from, to, "board").await?,
        "by_technician": breakdown(&st, u.scope(), q.client_id, from, to, "technician").await?,
        "by_type": breakdown(&st, u.scope(), q.client_id, from, to, "type").await?,
    })))
}

/// Logged, billable and available hours per technician.
pub async fn utilisation(State(st): State<Arc<AppState>>, u: User, Query(q): Query<Range>) -> ApiResult<Json<Value>> {
    if !u.has(Perm::TimeApprove) && !u.has(Perm::BillingRead) {
        return Err(ApiError::Forbidden);
    }
    let (from, to) = range(&q)?;
    let days = (to - from).num_days() + 1;
    let rows: Vec<(Uuid, String, i32, i64, i64, i64)> = sqlx::query_as(
        "SELECT u.id, u.name, u.capacity_hours,
                coalesce(sum(e.minutes), 0)::bigint,
                coalesce(sum(e.minutes) FILTER (WHERE e.billable), 0)::bigint,
                coalesce(sum(e.minutes) FILTER (WHERE e.coverage IN ('billable', 'block') AND e.amount > 0), 0)::bigint
           FROM users u LEFT JOIN time_entries e ON e.user_id = u.id AND e.started_at >= $1 AND e.started_at < $2::date + 1
          WHERE NOT u.disabled AND u.role IN ('technician', 'admin')
          GROUP BY u.id ORDER BY lower(u.name)",
    )
    .bind(from)
    .bind(to)
    .fetch_all(&st.db)
    .await?;
    let out: Vec<Value> = rows
        .into_iter()
        .map(|(id, name, cap, logged, billable, charged)| {
            // Capacity counts weekdays only.
            let weekdays = (0..days).filter(|i| (from + Duration::days(*i)).weekday().num_days_from_monday() < 5).count() as i64;
            let available = cap as i64 * 60 * weekdays / 5;
            json!({
                "user_id": id, "name": name, "logged_minutes": logged, "billable_minutes": billable, "charged_minutes": charged,
                "available_minutes": available, "utilisation_pct": pct(logged, available), "billable_pct": pct(billable, available),
            })
        })
        .collect();
    Ok(Json(json!({ "from": from, "to": to, "technicians": out })))
}

/// Invoiced revenue against the cost of the time and products that went into it, per client.
pub async fn profitability(State(st): State<Arc<AppState>>, u: User, Query(q): Query<Range>) -> ApiResult<Json<Value>> {
    u.need(Perm::BillingRead)?;
    let (from, to) = range(&q)?;
    #[allow(clippy::type_complexity)]
    let rows: Vec<(Uuid, String, String, i64, i64, i64, i64)> = sqlx::query_as(
        "SELECT c.id, c.name, coalesce(c.currency, (SELECT currency FROM company_settings)),
                coalesce((SELECT sum(i.total) FROM invoices i WHERE i.client_id = c.id AND i.status IN ('finalised', 'sent', 'paid')
                           AND i.issue_date BETWEEN $2 AND $3), 0)::bigint,
                coalesce((SELECT sum(e.minutes) FROM time_entries e WHERE e.client_id = c.id AND e.started_at >= $2 AND e.started_at < $3::date + 1), 0)::bigint,
                coalesce((SELECT sum(e.minutes::bigint * u.cost_rate / 60) FROM time_entries e JOIN users u ON u.id = e.user_id
                           WHERE e.client_id = c.id AND e.started_at >= $2 AND e.started_at < $3::date + 1), 0)::bigint,
                coalesce((SELECT sum(ch.quantity_milli * ch.unit_cost / 1000) FROM charges ch WHERE ch.client_id = c.id AND ch.day BETWEEN $2 AND $3), 0)::bigint
           FROM clients c WHERE ($1::uuid[] IS NULL OR c.id = ANY($1)) ORDER BY lower(c.name)",
    )
    .bind(u.scope())
    .bind(from)
    .bind(to)
    .fetch_all(&st.db)
    .await?;
    let out: Vec<Value> = rows
        .into_iter()
        .filter(|r| r.3 != 0 || r.4 != 0 || r.6 != 0)
        .map(|(id, name, cur, revenue, minutes, time_cost, product_cost)| {
            let margin = revenue - time_cost - product_cost;
            json!({
                "client_id": id, "name": name, "currency": cur, "revenue": revenue, "minutes": minutes, "time_cost": time_cost,
                "product_cost": product_cost, "margin": margin, "margin_pct": pct(margin, revenue),
            })
        })
        .collect();
    Ok(Json(json!({ "from": from, "to": to, "clients": out })))
}

fn last_quarter(today: NaiveDate) -> (NaiveDate, NaiveDate) {
    let q = today.month0() / 3;
    let (y, q) = if q == 0 { (today.year() - 1, 3) } else { (today.year(), q - 1) };
    let start = NaiveDate::from_ymd_opt(y, q * 3 + 1, 1).expect("valid");
    let next = if q == 3 { NaiveDate::from_ymd_opt(y + 1, 1, 1) } else { NaiveDate::from_ymd_opt(y, q * 3 + 4, 1) }.expect("valid");
    (start, next - Duration::days(1))
}

fn mins(m: Option<f64>) -> String {
    match m {
        None => "–".into(),
        Some(m) if m < 90.0 => format!("{} min", m.round()),
        Some(m) if m < 48.0 * 60.0 => format!("{:.1} h", m / 60.0),
        Some(m) => format!("{:.1} days", m / 1440.0),
    }
}

/// The quarterly business review for one client, as a PDF (default: last quarter).
pub async fn qbr(State(st): State<Arc<AppState>>, u: User, Path(client): Path<Uuid>, Query(q): Query<Range>) -> ApiResult<Response> {
    super::access::client(&u, client)?;
    let (from, to) = match (q.from, q.to) {
        (Some(_), Some(_)) => range(&q)?,
        _ => last_quarter(Utc::now().date_naive()),
    };
    let name: String =
        sqlx::query_scalar("SELECT name FROM clients WHERE id = $1").bind(client).fetch_optional(&st.db).await?.ok_or(ApiError::NotFound("client"))?;
    let t = desk_totals(&st, None, Some(client), from, to).await?;
    let months: Vec<(NaiveDate, i64, i64)> = sqlx::query_as(
        "SELECT m::date, (SELECT count(*) FROM tickets t WHERE t.client_id = $1 AND t.merged_into IS NULL AND t.created_at >= m AND t.created_at < m + interval '1 month'),
                (SELECT count(*) FROM tickets t WHERE t.client_id = $1 AND t.merged_into IS NULL AND t.resolved_at >= m AND t.resolved_at < m + interval '1 month')
           FROM generate_series(date_trunc('month', $2::date), $3::date, interval '1 month') m",
    )
    .bind(client)
    .bind(from)
    .bind(to)
    .fetch_all(&st.db)
    .await?;
    let types = breakdown(&st, None, Some(client), from, to, "type").await?;
    let (devices, servers, online, compliant, reboot): (i64, i64, i64, i64, i64) = sqlx::query_as(
        "SELECT count(*), count(*) FILTER (WHERE a.os_family = 'linux' OR a.os_name ILIKE '%server%'), count(*) FILTER (WHERE a.online),
                count(*) FILTER (WHERE NOT EXISTS (SELECT 1 FROM patches p WHERE p.agent_id = a.id AND p.state IN ('missing', 'failed') AND p.approval <> 'declined')),
                count(*) FILTER (WHERE a.reboot_pending)
           FROM agents a JOIN sites s ON s.id = a.site_id WHERE s.client_id = $1",
    )
    .bind(client)
    .fetch_one(&st.db)
    .await?;
    let os: Vec<(String, i64)> = sqlx::query_as(
        "SELECT coalesce(nullif(a.os_name, ''), a.os_family), count(*) FROM agents a JOIN sites s ON s.id = a.site_id WHERE s.client_id = $1
          GROUP BY 1 ORDER BY 2 DESC LIMIT 8",
    )
    .bind(client)
    .fetch_all(&st.db)
    .await?;
    let alerts: Vec<(String, i64)> = sqlx::query_as(
        "SELECT al.severity, count(*) FROM alerts al JOIN agents a ON a.id = al.agent_id JOIN sites s ON s.id = a.site_id
          WHERE s.client_id = $1 AND al.opened_at >= $2 AND al.opened_at < $3::date + 1 GROUP BY 1 ORDER BY 2 DESC",
    )
    .bind(client)
    .bind(from)
    .bind(to)
    .fetch_all(&st.db)
    .await?;
    // `extract` returns numeric (Postgres 14+); sqlx only checks the type of a non-NULL value,
    // so without the cast this failed only for clients with an offline alert in the period.
    let offline: (i64, Option<f64>) = sqlx::query_as(
        "SELECT count(*), (sum(extract(epoch FROM coalesce(al.resolved_at, now()) - al.opened_at)) / 3600)::float8
           FROM alerts al JOIN agents a ON a.id = al.agent_id JOIN sites s ON s.id = a.site_id
          WHERE s.client_id = $1 AND al.kind = 'offline' AND al.opened_at >= $2 AND al.opened_at < $3::date + 1",
    )
    .bind(client)
    .bind(from)
    .bind(to)
    .fetch_one(&st.db)
    .await?;
    let (time_minutes,): (i64,) = sqlx::query_as(
        "SELECT coalesce(sum(minutes), 0)::bigint FROM time_entries WHERE client_id = $1 AND started_at >= $2 AND started_at < $3::date + 1",
    )
    .bind(client)
    .bind(from)
    .bind(to)
    .fetch_one(&st.db)
    .await?;

    let mut blocks = vec![
        Block::Heading("Service desk".into()),
        Block::Figures(vec![
            ("Tickets opened".into(), t.opened.to_string()),
            ("Tickets resolved".into(), t.closed.to_string()),
            ("Open now".into(), t.backlog.to_string()),
            ("Median first response".into(), mins(t.first_response_mins)),
            ("Median resolution".into(), mins(t.resolution_mins)),
            ("Hours of work".into(), qty(crate::billing::minutes_milli(time_minutes))),
            ("First response within SLA".into(), pct(t.respond_met, t.respond_total).map_or("–".into(), |p| format!("{p}%"))),
            ("Resolved within SLA".into(), pct(t.resolve_met, t.resolve_total).map_or("–".into(), |p| format!("{p}%"))),
            ("Satisfaction".into(), pct(t.csat_good, t.csat_good + t.csat_bad).map_or("–".into(), |p| format!("{p}% good"))),
        ]),
        Block::Heading("Tickets by month".into()),
        Block::Table(
            vec!["Month".into(), "Opened".into(), "Resolved".into()],
            months.iter().map(|(m, o, c)| vec![m.format("%B %Y").to_string(), o.to_string(), c.to_string()]).collect(),
        ),
        Block::Bars(months.iter().map(|(m, o, _)| (m.format("%b %Y").to_string(), *o as f64, format!("{o} opened"))).collect()),
    ];
    if !types.is_empty() {
        blocks.push(Block::Heading("What the tickets were about".into()));
        blocks.push(Block::Table(
            vec!["Type".into(), "Opened".into(), "Resolved".into()],
            types.iter().map(|r| vec![r["name"].as_str().unwrap_or_default().to_string(), r["opened"].to_string(), r["closed"].to_string()]).collect(),
        ));
    }
    blocks.push(Block::Heading("Devices".into()));
    blocks.push(Block::Figures(vec![
        ("Managed devices".into(), devices.to_string()),
        ("Servers".into(), servers.to_string()),
        ("Workstations".into(), (devices - servers).to_string()),
        ("Fully patched".into(), pct(compliant, devices).map_or("–".into(), |p| format!("{p}%"))),
        ("Restart pending".into(), reboot.to_string()),
        ("Online at report time".into(), format!("{online} of {devices}")),
    ]));
    if !os.is_empty() {
        blocks.push(Block::Bars(os.iter().map(|(n, c)| (n.clone(), *c as f64, c.to_string())).collect()));
    }
    blocks.push(Block::Heading("Monitoring".into()));
    let total_alerts: i64 = alerts.iter().map(|a| a.1).sum();
    blocks.push(Block::Paragraph(format!(
        "{total_alerts} alerts in the period ({}). Devices were reported offline {} times, for {:.1} hours in total.",
        if alerts.is_empty() { "none".into() } else { alerts.iter().map(|(s, n)| format!("{n} {s}")).collect::<Vec<_>>().join(", ") },
        offline.0,
        offline.1.unwrap_or(0.0)
    )));
    let subtitle = format!("{name} · {} – {}", from.format("%-d %B %Y"), to.format("%-d %B %Y"));
    let pdf = crate::pdf::report("Quarterly business review", &subtitle, &crate::email::brand(&st), &blocks);
    let file = format!("QBR-{}-{}", name.chars().filter(|c| c.is_ascii_alphanumeric()).collect::<String>(), from.format("%Y-%m"));
    super::billing::pdf_bytes_response(pdf, &file)
}

/// Revenue figures need the billing permission; this is the overview the dashboard shows.
pub async fn billing_overview(State(st): State<Arc<AppState>>, u: User) -> ApiResult<Json<Value>> {
    u.need(Perm::BillingRead)?;
    let rows: Vec<(String, i64, i64, i64)> = sqlx::query_as(
        "SELECT currency,
                coalesce(sum(total) FILTER (WHERE status IN ('finalised', 'sent') AND kind = 'invoice'), 0)::bigint,
                coalesce(sum(total) FILTER (WHERE status IN ('finalised', 'sent') AND kind = 'invoice' AND due_date < current_date), 0)::bigint,
                count(*) FILTER (WHERE status = 'draft')
           FROM invoices WHERE ($1::uuid[] IS NULL OR client_id = ANY($1)) GROUP BY currency ORDER BY currency",
    )
    .bind(u.scope())
    .fetch_all(&st.db)
    .await?;
    let pending: i64 = sqlx::query_scalar("SELECT count(*) FROM timesheets WHERE status = 'submitted'").fetch_one(&st.db).await?;
    Ok(Json(json!({
        "currencies": rows.iter().map(|(c, o, d, n)| json!({ "currency": c, "outstanding": o, "overdue": d, "drafts": n,
                                                              "outstanding_text": money(*o, c), "overdue_text": money(*d, c) })).collect::<Vec<_>>(),
        "timesheets_pending": pending,
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quarters_and_durations() {
        let d = |s: &str| NaiveDate::parse_from_str(s, "%Y-%m-%d").unwrap();
        assert_eq!(last_quarter(d("2026-11-12")), (d("2026-07-01"), d("2026-09-30")));
        assert_eq!(last_quarter(d("2026-02-01")), (d("2025-10-01"), d("2025-12-31")));
        assert_eq!(mins(Some(42.4)), "42 min");
        assert_eq!(mins(Some(150.0)), "2.5 h");
        assert_eq!(mins(None), "–");
        assert_eq!(pct(1, 3), Some(33.3));
        assert_eq!(pct(1, 0), None);
    }
}
