//! The audit log: the filtered list the dashboard pages through, and a streamed export (CSV or
//! JSON Lines) of the same filters. Both need the `audit.read` permission (admins; a technician
//! or an API key only when given it), and an export is itself audited.

use std::sync::Arc;

use axum::Json;
use axum::body::{Body, Bytes};
use axum::extract::{Query, State};
use axum::http::{HeaderValue, header};
use axum::response::Response;
use chrono::{DateTime, Utc};
use futures_util::StreamExt;
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::AssertSqlSafe;
use uuid::Uuid;

use super::users::AuditRow;
use crate::auth::{self, Perm, User};
use crate::error::{ApiError, ApiResult};
use crate::paging::{self, Page, PageQuery, Plan, SortKey};
use crate::state::AppState;

const AUDIT_KEYS: &[SortKey] = &[SortKey { name: "ts", expr: "l.ts", ty: "timestamptz" }];

#[derive(Deserialize, Default)]
pub struct AuditQuery {
    /// Exact action, or a prefix ending in `.` (`agent.`).
    action: Option<String>,
    user_id: Option<Uuid>,
    target_type: Option<String>,
    target_id: Option<Uuid>,
    /// RFC 3339; events at or after it.
    from: Option<DateTime<Utc>>,
    /// RFC 3339; events at or before it.
    to: Option<DateTime<Utc>>,
}

/// `FROM … WHERE …` for the filters, binding `$1`-`$6` in the order of [`bind_filters`].
const FILTERS: &str = "FROM audit_log l LEFT JOIN users u ON u.id = l.user_id
          WHERE ($1::text IS NULL OR l.action = $1 OR (right($1, 1) = '.' AND starts_with(l.action, $1)))
            AND ($2::uuid IS NULL OR l.user_id = $2)
            AND ($3::text IS NULL OR l.target_type = $3)
            AND ($4::uuid IS NULL OR l.target_id = $4)
            AND ($5::timestamptz IS NULL OR l.ts >= $5)
            AND ($6::timestamptz IS NULL OR l.ts <= $6)";

fn text(v: &Option<String>) -> Option<&str> {
    v.as_deref().map(str::trim).filter(|s| !s.is_empty())
}

macro_rules! bind_filters {
    ($q:expr, $f:expr) => {
        $q.bind(text(&$f.action)).bind($f.user_id).bind(text(&$f.target_type)).bind($f.target_id).bind($f.from).bind($f.to)
    };
}

pub async fn list(
    State(st): State<Arc<AppState>>,
    u: User,
    Query(q): Query<AuditQuery>,
    Query(page): Query<PageQuery>,
) -> ApiResult<Json<Page<AuditRow>>> {
    u.need(Perm::AuditRead)?;
    let plan = Plan::new(AUDIT_KEYS, ("ts", true), &page, "l.id", "bigint", 7)?;
    let sql = format!(
        "SELECT l.id, l.ts, u.name AS user_name, l.action, l.target_type, l.target_id, l.details, {} {FILTERS} {} {} {}",
        plan.key_select,
        plan.keyset,
        plan.order,
        plan.limit_sql()
    );
    let mut rows = bind_filters!(sqlx::query_as::<_, AuditRow>(AssertSqlSafe(sql)), q);
    if let Some((k, id)) = &plan.cursor {
        rows = rows.bind(k).bind(id);
    }
    let rows = rows.fetch_all(&st.db).await?;
    let total: i64 = bind_filters!(sqlx::query_scalar(AssertSqlSafe(paging::count_sql(FILTERS))), q).fetch_one(&st.db).await?;
    Ok(Json(plan.finish(rows, |r| (r.sort_key.clone(), r.id.to_string()), total)))
}

#[derive(Deserialize)]
pub struct ExportQuery {
    #[serde(flatten)]
    filters: AuditQuery,
    /// `csv` (default) or `jsonl`.
    format: Option<String>,
}

#[derive(sqlx::FromRow)]
struct ExportRow {
    id: i64,
    ts: DateTime<Utc>,
    user_id: Option<Uuid>,
    user_email: Option<String>,
    user_name: Option<String>,
    action: String,
    target_type: Option<String>,
    target_id: Option<Uuid>,
    details: Value,
}

const CSV_HEADER: &str = "id,time,user_id,user_email,user_name,action,target_type,target_id,details\r\n";

/// A CSV field. One that starts with `= + - @` or a control character is prefixed with `'`, so a
/// spreadsheet doesn't run it as a formula (user names and audit details are attacker-influenced).
fn csv_field(out: &mut String, v: &str) {
    let risky = v.starts_with(['=', '+', '-', '@', '\t', '\r']);
    if risky || v.contains([',', '"', '\r', '\n']) {
        out.push('"');
        if risky {
            out.push('\'');
        }
        out.push_str(&v.replace('"', "\"\""));
        out.push('"');
    } else {
        out.push_str(v);
    }
}

fn csv_line(r: &ExportRow) -> String {
    let mut out = String::new();
    let opt = |v: &Option<String>| v.clone().unwrap_or_default();
    let fields = [
        r.id.to_string(),
        r.ts.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        r.user_id.map(|i| i.to_string()).unwrap_or_default(),
        opt(&r.user_email),
        opt(&r.user_name),
        r.action.clone(),
        opt(&r.target_type),
        r.target_id.map(|i| i.to_string()).unwrap_or_default(),
        serde_json::to_string(&r.details).unwrap_or_default(),
    ];
    for (i, f) in fields.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        csv_field(&mut out, f);
    }
    out.push_str("\r\n");
    out
}

fn json_line(r: &ExportRow) -> String {
    let mut s = serde_json::to_string(&json!({
        "id": r.id, "time": r.ts, "user_id": r.user_id, "user_email": r.user_email, "user_name": r.user_name,
        "action": r.action, "target_type": r.target_type, "target_id": r.target_id, "details": r.details,
    }))
    .unwrap_or_default();
    s.push('\n');
    s
}

/// `GET /audit/export`: every matching event, oldest first, streamed from the database in
/// bounded chunks (the table is never held in memory). If the query fails part way the
/// connection is aborted, so a truncated file never looks complete.
pub async fn export(State(st): State<Arc<AppState>>, u: User, Query(q): Query<ExportQuery>) -> ApiResult<Response> {
    u.need(Perm::AuditRead)?;
    let jsonl = match q.format.as_deref().unwrap_or("csv") {
        "csv" => false,
        "jsonl" | "ndjson" => true,
        _ => return Err(ApiError::BadRequest("format must be csv or jsonl".into())),
    };
    let f = q.filters;
    auth::audit(
        &st.db,
        Some(u.id),
        "audit.export",
        None,
        json!({
            "format": if jsonl { "jsonl" } else { "csv" },
            "via": if u.api_key.is_some() { "api_key" } else { "session" },
            "action": text(&f.action), "user_id": f.user_id, "target_type": text(&f.target_type), "target_id": f.target_id,
            "from": f.from, "to": f.to,
        }),
    )
    .await;

    let sql = format!(
        "SELECT l.id, l.ts, l.user_id, u.email AS user_email, u.name AS user_name, l.action, l.target_type, l.target_id, l.details {FILTERS} ORDER BY l.id"
    );
    let db = st.db.clone();
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(8);
    tokio::spawn(async move {
        let mut rows = bind_filters!(sqlx::query_as::<_, ExportRow>(AssertSqlSafe(sql)), f).fetch(&db);
        let mut buf = String::new();
        if !jsonl {
            buf.push_str(CSV_HEADER);
        }
        while let Some(row) = rows.next().await {
            match row {
                Ok(r) => buf.push_str(&if jsonl { json_line(&r) } else { csv_line(&r) }),
                Err(e) => {
                    tracing::warn!("audit export failed: {e}");
                    let _ = tx.send(Err(std::io::Error::other("the export failed; the file is incomplete"))).await;
                    return;
                }
            }
            if buf.len() >= 64 * 1024 && tx.send(Ok(Bytes::from(std::mem::take(&mut buf)))).await.is_err() {
                return; // the client went away
            }
        }
        if !buf.is_empty() {
            let _ = tx.send(Ok(Bytes::from(buf))).await;
        }
    });
    let stream = futures_util::stream::poll_fn(move |cx| rx.poll_recv(cx));

    let name = format!("audit-{}.{}", Utc::now().format("%Y%m%d-%H%M%S"), if jsonl { "jsonl" } else { "csv" });
    let mut res = Response::new(Body::from_stream(stream));
    let h = res.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static(if jsonl { "application/x-ndjson" } else { "text/csv; charset=utf-8" }));
    h.insert(header::CONTENT_DISPOSITION, HeaderValue::from_str(&format!("attachment; filename=\"{name}\"")).map_err(anyhow::Error::from)?);
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("private, no-store"));
    h.insert("x-content-type-options", HeaderValue::from_static("nosniff"));
    Ok(res)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(name: &str, details: Value) -> ExportRow {
        ExportRow {
            id: 7,
            ts: "2026-11-22T10:00:00Z".parse().unwrap(),
            user_id: None,
            user_email: Some("a@b.test".into()),
            user_name: Some(name.into()),
            action: "user.login".into(),
            target_type: None,
            target_id: None,
            details,
        }
    }

    #[test]
    fn csv_quotes_and_defuses_formulas() {
        let line = csv_line(&row("Smith, \"Bob\"", json!({ "a": 1 })));
        assert_eq!(line, "7,2026-11-22T10:00:00.000Z,,a@b.test,\"Smith, \"\"Bob\"\"\",user.login,,,\"{\"\"a\"\":1}\"\r\n");
        let line = csv_line(&row("=HYPERLINK(\"http://evil\")", json!({})));
        assert!(line.contains("\"'=HYPERLINK("), "{line}");
        let line = csv_line(&row("-2+3", json!({})));
        assert!(line.contains("\"'-2+3\""), "{line}");
        // A value with a line break stays one record.
        assert!(csv_line(&row("a\nb", json!({}))).contains("\"a\nb\""));
    }

    #[test]
    fn json_lines_are_one_object_per_line() {
        let l = json_line(&row("n", json!({ "x": "a\nb" })));
        assert!(l.ends_with('\n') && l.matches('\n').count() == 1);
        let v: Value = serde_json::from_str(&l).unwrap();
        assert_eq!((v["id"].as_i64(), v["action"].as_str(), v["details"]["x"].as_str()), (Some(7), Some("user.login"), Some("a\nb")));
    }
}
