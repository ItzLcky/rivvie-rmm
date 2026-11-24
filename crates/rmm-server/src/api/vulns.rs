//! Vulnerabilities: the fleet by CVE, by device and by software; one CVE; accepted risk; the
//! feeds and the Windows product map. See [`crate::vuln`] and docs/design/vulnerabilities.md.
//!
//! Reads need `security.read`, accepting risk `security.respond`, products, feeds and sync
//! `security.manage`.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::AssertSqlSafe;
use uuid::Uuid;

use crate::auth::{self, Perm, User};
use crate::error::{ApiError, ApiResult};
use crate::paging::{self, Page, PageQuery, Plan, SortKey};
use crate::state::AppState;
use crate::vuln::{self, matcher};

fn bad(s: &str) -> ApiError {
    ApiError::BadRequest(s.into())
}

const SEVERITIES: &[&str] = &["critical", "high", "medium", "low", "none", "unknown"];

fn severities(s: Option<&str>) -> ApiResult<Option<Vec<String>>> {
    let Some(list) = s.map(str::trim).filter(|s| !s.is_empty()) else { return Ok(None) };
    let list: Vec<String> = list.split(',').map(|x| x.trim().to_string()).collect();
    if let Some(b) = list.iter().find(|x| !SEVERITIES.contains(&x.as_str())) {
        return Err(ApiError::BadRequest(format!("unknown severity {b}")));
    }
    Ok(Some(list))
}

/// SQL: the severity name of a rank.
const SEV_NAME: &str = "(CASE g.sev_rank WHEN 4 THEN 'critical' WHEN 3 THEN 'high' WHEN 2 THEN 'medium' WHEN 1 THEN 'low' ELSE 'unknown' END)";

// ---------------------------------------------------------------------------
// By CVE
// ---------------------------------------------------------------------------

#[derive(Serialize, sqlx::FromRow)]
pub struct CveRow {
    /// The CVE, or the advisory id when there is no CVE: what `/vulnerabilities/{id}` takes.
    key: String,
    cve: Option<String>,
    advisories: Vec<String>,
    summary: String,
    severity: String,
    cvss: Option<f32>,
    epss: Option<f32>,
    kev: bool,
    published: Option<DateTime<Utc>>,
    /// Devices with it open and not accepted (in the caller's scope).
    devices: i64,
    accepted_devices: i64,
    fix_available: bool,
    packages: Vec<String>,
    first_seen: DateTime<Utc>,
    #[sqlx(default)]
    #[serde(skip)]
    sort_key: String,
}

const CVE_SORT: &[SortKey] = &[
    SortKey { name: "devices", expr: "g.devices", ty: "bigint" },
    SortKey { name: "severity", expr: "(g.sev_rank * 1000 + coalesce(g.cvss, 0) * 10)", ty: "double precision" },
    SortKey { name: "cvss", expr: "coalesce(g.cvss, -1)", ty: "real" },
    SortKey { name: "epss", expr: "coalesce(g.epss, -1)", ty: "real" },
    SortKey { name: "published", expr: "coalesce(g.published, 'epoch'::timestamptz)", ty: "timestamptz" },
    SortKey { name: "first_seen", expr: "g.first_seen", ty: "timestamptz" },
    SortKey { name: "cve", expr: "g.key", ty: "text" },
];

#[derive(Deserialize)]
pub struct ListQuery {
    client_id: Option<Uuid>,
    /// Comma-separated severities.
    severity: Option<String>,
    kev: Option<bool>,
    /// Only with (true) or without (false) a fixed version.
    fix: Option<bool>,
    /// Also CVEs every affected device has accepted.
    #[serde(default)]
    accepted: bool,
    /// CVE, advisory, summary or package.
    q: Option<String>,
}

/// One row per CVE (advisories without one stand alone), with the devices that have it open.
pub async fn list(State(st): State<Arc<AppState>>, u: User, Query(q): Query<ListQuery>, Query(page): Query<PageQuery>) -> ApiResult<Json<Page<CveRow>>> {
    u.need(Perm::SecurityRead)?;
    if let Some(c) = q.client_id {
        super::access::client(&u, c)?;
    }
    let sev = severities(q.severity.as_deref())?;
    let search = q.q.as_deref().map(str::trim).filter(|s| !s.is_empty()).map(String::from);
    let plan = Plan::new(CVE_SORT, ("severity", true), &page, "g.key", "text", 8)?;
    let filters = format!(
        "FROM (SELECT coalesce(v.cve, v.id) AS key, max(v.cve) AS cve, array_agg(DISTINCT v.id) AS advisories, max(v.summary) AS summary,
                      max({rank}) AS sev_rank, max(v.cvss) AS cvss, max(v.epss) AS epss, bool_or(v.kev) AS kev, min(v.published) AS published,
                      count(DISTINCT f.agent_id) FILTER (WHERE NOT vuln_accepted(f.agent_id, f.vuln_id, v.cve)) AS devices,
                      count(DISTINCT f.agent_id) FILTER (WHERE vuln_accepted(f.agent_id, f.vuln_id, v.cve)) AS accepted_devices,
                      bool_or(f.fix_available) AS fix_available, (array_agg(DISTINCT f.package))[1:5] AS packages, min(f.first_seen) AS first_seen,
                      string_agg(DISTINCT f.package, ' ') AS all_packages
                 FROM vuln_findings f JOIN vulns v ON v.id = f.vuln_id JOIN agents a ON a.id = f.agent_id JOIN sites s ON s.id = a.site_id
                WHERE f.resolved_at IS NULL AND ($1::uuid[] IS NULL OR s.client_id = ANY($1)) AND ($2::uuid IS NULL OR s.client_id = $2)
                GROUP BY 1) g
        WHERE ($3 OR g.devices > 0) AND ($4::text[] IS NULL OR {SEV_NAME} = ANY($4)) AND ($5::bool IS NULL OR g.kev = $5)
          AND ($6::bool IS NULL OR g.fix_available = $6)
          AND ($7::text IS NULL OR g.key ILIKE '%' || $7 || '%' OR g.summary ILIKE '%' || $7 || '%' OR g.all_packages ILIKE '%' || $7 || '%'
               OR array_to_string(g.advisories, ' ') ILIKE '%' || $7 || '%')",
        rank = matcher::rank_sql("v.severity"),
    );
    macro_rules! bind_filters {
        ($query:expr) => {
            $query.bind(u.scope()).bind(q.client_id).bind(q.accepted).bind(&sev).bind(q.kev).bind(q.fix).bind(&search)
        };
    }
    let sql = format!(
        "SELECT g.key, g.cve, g.advisories, g.summary, {SEV_NAME} AS severity, g.cvss, g.epss, g.kev, g.published, g.devices, g.accepted_devices,
                g.fix_available, g.packages, g.first_seen, {} {filters} {} {} {}",
        plan.key_select,
        plan.keyset,
        plan.order,
        plan.limit_sql()
    );
    let mut rows = bind_filters!(sqlx::query_as::<_, CveRow>(AssertSqlSafe(sql)));
    if let Some((k, id)) = &plan.cursor {
        rows = rows.bind(k).bind(id);
    }
    let rows = rows.fetch_all(&st.db).await?;
    let total: i64 = bind_filters!(sqlx::query_scalar(AssertSqlSafe(paging::count_sql(&filters)))).fetch_one(&st.db).await?;
    Ok(Json(plan.finish(rows, |r| (r.sort_key.clone(), r.key.clone()), total)))
}

/// Counts for the dashboard and a client's overview, from the stored per-device counts.
pub async fn summary(State(st): State<Arc<AppState>>, u: User, Query(q): Query<ListQuery>) -> ApiResult<Json<Value>> {
    u.need(Perm::SecurityRead)?;
    if let Some(c) = q.client_id {
        super::access::client(&u, c)?;
    }
    let (crit, high, devices, unassessed, assessed): (i64, i64, i64, i64, i64) = sqlx::query_as(
        "SELECT coalesce(sum(a.vuln_critical), 0)::bigint, coalesce(sum(a.vuln_high), 0)::bigint,
                count(*) FILTER (WHERE a.vuln_critical + a.vuln_high > 0),
                count(*) FILTER (WHERE a.vuln_unassessed IS NOT NULL), count(*) FILTER (WHERE a.vuln_ecosystem IS NOT NULL)
           FROM agents a JOIN sites s ON s.id = a.site_id
          WHERE ($1::uuid[] IS NULL OR s.client_id = ANY($1)) AND ($2::uuid IS NULL OR s.client_id = $2)",
    )
    .bind(u.scope())
    .bind(q.client_id)
    .fetch_one(&st.db)
    .await?;
    let kev: i64 = sqlx::query_scalar(
        "SELECT count(DISTINCT coalesce(v.cve, v.id)) FROM vuln_findings f JOIN vulns v ON v.id = f.vuln_id
           JOIN agents a ON a.id = f.agent_id JOIN sites s ON s.id = a.site_id
          WHERE f.resolved_at IS NULL AND v.kev AND NOT vuln_accepted(f.agent_id, f.vuln_id, v.cve)
            AND ($1::uuid[] IS NULL OR s.client_id = ANY($1)) AND ($2::uuid IS NULL OR s.client_id = $2)",
    )
    .bind(u.scope())
    .bind(q.client_id)
    .fetch_one(&st.db)
    .await?;
    let synced: Option<DateTime<Utc>> = sqlx::query_scalar("SELECT max(last_sync_at) FROM vuln_feeds WHERE enabled").fetch_one(&st.db).await?;
    Ok(Json(json!({
        "critical": crit, "high": high, "devices_affected": devices, "kev": kev, "unassessed": unassessed, "assessed": assessed,
        "last_sync_at": synced,
    })))
}

// ---------------------------------------------------------------------------
// One CVE
// ---------------------------------------------------------------------------

#[derive(Serialize, sqlx::FromRow)]
struct AdvisoryRow {
    id: String,
    source: String,
    aliases: Vec<String>,
    summary: String,
    details: String,
    severity: String,
    cvss: Option<f32>,
    cvss_vector: Option<String>,
    published: Option<DateTime<Utc>>,
    modified: Option<DateTime<Utc>>,
    url: Option<String>,
}

#[derive(Serialize, sqlx::FromRow)]
struct RangeRow {
    vuln_id: String,
    ecosystem: String,
    package: String,
    introduced: Option<String>,
    fixed: Option<String>,
    last_affected: Option<String>,
}

#[derive(Serialize, sqlx::FromRow)]
struct AcceptanceRow {
    id: Uuid,
    vuln_id: String,
    client_id: Uuid,
    client_name: String,
    agent_id: Option<Uuid>,
    hostname: Option<String>,
    note: String,
    expires_at: Option<DateTime<Utc>>,
    by_name: Option<String>,
    created_at: DateTime<Utc>,
    active: bool,
}

/// The advisories about a CVE (or one advisory), its ranges, KEV and EPSS, and who accepted it.
pub async fn get(State(st): State<Arc<AppState>>, u: User, Path(id): Path<String>) -> ApiResult<Json<Value>> {
    u.need(Perm::SecurityRead)?;
    let advisories: Vec<AdvisoryRow> = sqlx::query_as(
        "SELECT id, source, aliases, summary, details, severity, cvss, cvss_vector, published, modified, url
           FROM vulns WHERE cve = $1 OR (id = $1 AND cve IS NULL) ORDER BY (source = 'nvd') DESC, cvss DESC NULLS LAST, id",
    )
    .bind(&id)
    .fetch_all(&st.db)
    .await?;
    if advisories.is_empty() {
        return Err(ApiError::NotFound("vulnerability"));
    }
    let ids: Vec<&str> = advisories.iter().map(|a| a.id.as_str()).collect();
    let ranges: Vec<RangeRow> = sqlx::query_as(
        "SELECT vuln_id, ecosystem, package, introduced, fixed, last_affected FROM vuln_ranges WHERE vuln_id = ANY($1)
          ORDER BY ecosystem, package LIMIT 200",
    )
    .bind(&ids)
    .fetch_all(&st.db)
    .await?;
    let cve = advisories.iter().find_map(|_| if id.starts_with("CVE-") { Some(id.clone()) } else { None });
    type Scores = (Option<f32>, Option<f32>, bool, Option<NaiveDate>, Option<NaiveDate>);
    let scores: Option<Scores> =
        sqlx::query_as("SELECT epss, epss_percentile, kev, kev_added, kev_due FROM vuln_cve_scores WHERE cve = $1").bind(&cve).fetch_optional(&st.db).await?;
    let (epss, pct, kev, kev_added, kev_due) = scores.unwrap_or_default();
    let acceptances: Vec<AcceptanceRow> = sqlx::query_as(
        "SELECT va.id, va.vuln_id, va.client_id, c.name AS client_name, va.agent_id, a.hostname, va.note, va.expires_at,
                us.name AS by_name, va.created_at, (va.expires_at IS NULL OR va.expires_at > now()) AS active
           FROM vuln_acceptances va JOIN clients c ON c.id = va.client_id LEFT JOIN agents a ON a.id = va.agent_id
           LEFT JOIN users us ON us.id = va.by
          WHERE (va.vuln_id = $1 OR va.vuln_id = ANY($2)) AND ($3::uuid[] IS NULL OR va.client_id = ANY($3))
          ORDER BY va.created_at DESC",
    )
    .bind(&id)
    .bind(&ids)
    .bind(u.scope())
    .fetch_all(&st.db)
    .await?;
    let worst = advisories.iter().max_by_key(|a| (vuln::severity_rank(&a.severity), a.cvss.map(|c| (c * 10.0) as i32))).unwrap();
    let (devices, accepted): (i64, i64) = sqlx::query_as(
        "SELECT count(DISTINCT f.agent_id) FILTER (WHERE NOT vuln_accepted(f.agent_id, f.vuln_id, v.cve)),
                count(DISTINCT f.agent_id) FILTER (WHERE vuln_accepted(f.agent_id, f.vuln_id, v.cve))
           FROM vuln_findings f JOIN vulns v ON v.id = f.vuln_id JOIN agents a ON a.id = f.agent_id JOIN sites s ON s.id = a.site_id
          WHERE f.resolved_at IS NULL AND f.vuln_id = ANY($1) AND ($2::uuid[] IS NULL OR s.client_id = ANY($2))",
    )
    .bind(&ids)
    .bind(u.scope())
    .fetch_one(&st.db)
    .await?;
    Ok(Json(json!({
        "key": id, "cve": cve, "summary": worst.summary, "severity": worst.severity, "cvss": worst.cvss, "cvss_vector": worst.cvss_vector,
        "epss": epss, "epss_percentile": pct, "kev": kev, "kev_added": kev_added, "kev_due": kev_due,
        "devices": devices, "accepted_devices": accepted,
        "advisories": advisories, "ranges": ranges, "acceptances": acceptances,
    })))
}

#[derive(Serialize, sqlx::FromRow)]
pub struct DeviceRow {
    agent_id: Uuid,
    hostname: String,
    online: bool,
    os_family: String,
    os_name: String,
    client_id: Uuid,
    client_name: String,
    site_name: String,
    vuln_id: String,
    package: String,
    software_name: String,
    installed_version: String,
    fixed_version: Option<String>,
    fix_available: bool,
    first_seen: DateTime<Utc>,
    accepted: bool,
    product_id: Option<Uuid>,
    /// How to fix it from here: the device's pending update for the package (Linux), the
    /// catalog package to upgrade with, or a mapped product without one (Windows).
    #[sqlx(json)]
    remediation: Value,
}

/// The remediation for a finding row `f` on agent `a` (see [`DeviceRow::remediation`]).
const REMEDIATION: &str = "coalesce(
    (SELECT jsonb_build_object('kind', 'patch', 'update_id', p.update_id, 'title', p.title, 'version', p.version, 'approval', p.approval, 'state', p.state)
       FROM patches p WHERE p.agent_id = f.agent_id AND p.state <> 'installed' AND f.fix_available
        AND (p.update_id = f.software_name OR p.update_id LIKE f.software_name || '.%' OR p.title = f.software_name)
      ORDER BY p.update_id LIMIT 1),
    (SELECT CASE WHEN vp.package_id IS NOT NULL
                 THEN jsonb_build_object('kind', 'upgrade', 'package_id', vp.package_id, 'package_name', sp.name)
                 ELSE jsonb_build_object('kind', 'catalog', 'product_id', vp.id, 'product_name', vp.name) END
       FROM vuln_products vp LEFT JOIN software_packages sp ON sp.id = vp.package_id WHERE vp.id = f.product_id),
    'null'::jsonb)";

const DEVICE_COLS: &str = "a.id AS agent_id, a.hostname, a.online, a.os_family, a.os_name, s.client_id, c.name AS client_name, s.name AS site_name,
    f.vuln_id, f.package, f.software_name, f.installed_version, f.fixed_version, f.fix_available, f.first_seen,
    vuln_accepted(f.agent_id, f.vuln_id, v.cve) AS accepted, f.product_id";

/// The devices with a CVE open (at most 2000).
pub async fn devices(State(st): State<Arc<AppState>>, u: User, Path(id): Path<String>, Query(q): Query<ListQuery>) -> ApiResult<Json<Vec<DeviceRow>>> {
    u.need(Perm::SecurityRead)?;
    if let Some(c) = q.client_id {
        super::access::client(&u, c)?;
    }
    let rows: Vec<DeviceRow> = sqlx::query_as(AssertSqlSafe(format!(
        "SELECT {DEVICE_COLS}, {REMEDIATION} AS remediation
           FROM vuln_findings f JOIN vulns v ON v.id = f.vuln_id JOIN agents a ON a.id = f.agent_id
           JOIN sites s ON s.id = a.site_id JOIN clients c ON c.id = s.client_id
          WHERE f.resolved_at IS NULL AND (v.cve = $1 OR (v.id = $1 AND v.cve IS NULL))
            AND ($2::uuid[] IS NULL OR s.client_id = ANY($2)) AND ($3::uuid IS NULL OR s.client_id = $3)
          ORDER BY accepted, lower(c.name), lower(a.hostname), f.package LIMIT 2000"
    )))
    .bind(&id)
    .bind(u.scope())
    .bind(q.client_id)
    .fetch_all(&st.db)
    .await?;
    Ok(Json(rows))
}

// ---------------------------------------------------------------------------
// One device
// ---------------------------------------------------------------------------

#[derive(Serialize, sqlx::FromRow)]
pub struct AgentFinding {
    key: String,
    cve: Option<String>,
    vuln_id: String,
    summary: String,
    severity: String,
    cvss: Option<f32>,
    epss: Option<f32>,
    kev: bool,
    package: String,
    software_name: String,
    installed_version: String,
    fixed_version: Option<String>,
    fix_available: bool,
    first_seen: DateTime<Utc>,
    accepted: bool,
    #[sqlx(json)]
    remediation: Value,
}

/// A device's open findings and whether (and how) it is assessed.
pub async fn for_agent(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    u.need(Perm::SecurityRead)?;
    super::access::agent(&st, &u, id).await?;
    let (eco, why, at, crit, high): (Option<String>, Option<String>, Option<DateTime<Utc>>, i32, i32) =
        sqlx::query_as("SELECT vuln_ecosystem, vuln_unassessed, vuln_evaluated_at, vuln_critical, vuln_high FROM agents WHERE id = $1")
            .bind(id)
            .fetch_one(&st.db)
            .await?;
    let findings: Vec<AgentFinding> = sqlx::query_as(AssertSqlSafe(format!(
        "SELECT coalesce(v.cve, v.id) AS key, v.cve, v.id AS vuln_id, v.summary, v.severity, v.cvss, v.epss, v.kev, f.package, f.software_name,
                f.installed_version, f.fixed_version, f.fix_available, f.first_seen, vuln_accepted(f.agent_id, f.vuln_id, v.cve) AS accepted,
                {REMEDIATION} AS remediation
           FROM vuln_findings f JOIN vulns v ON v.id = f.vuln_id
          WHERE f.agent_id = $1 AND f.resolved_at IS NULL
          ORDER BY accepted, {rank} DESC, v.kev DESC, v.cvss DESC NULLS LAST, 1 LIMIT 2000",
        rank = matcher::rank_sql("v.severity")
    )))
    .bind(id)
    .fetch_all(&st.db)
    .await?;
    Ok(Json(json!({
        "ecosystem": eco, "unassessed": why, "evaluated_at": at, "critical": crit, "high": high, "findings": findings,
    })))
}

// ---------------------------------------------------------------------------
// By device
// ---------------------------------------------------------------------------

#[derive(Serialize, sqlx::FromRow)]
pub struct AgentRow {
    agent_id: Uuid,
    hostname: String,
    online: bool,
    os_family: String,
    os_name: String,
    client_name: String,
    site_name: String,
    ecosystem: Option<String>,
    critical: i32,
    high: i32,
    /// Open, not accepted, any severity (one per CVE).
    open: i64,
    kev: i64,
    fixable: i64,
    evaluated_at: Option<DateTime<Utc>>,
}

/// Assessed devices with open findings, worst first (at most 1000).
pub async fn agents(State(st): State<Arc<AppState>>, u: User, Query(q): Query<ListQuery>) -> ApiResult<Json<Vec<AgentRow>>> {
    u.need(Perm::SecurityRead)?;
    if let Some(c) = q.client_id {
        super::access::client(&u, c)?;
    }
    let search = q.q.as_deref().map(str::trim).filter(|s| !s.is_empty()).map(String::from);
    let rows: Vec<AgentRow> = sqlx::query_as(
        "SELECT a.id AS agent_id, a.hostname, a.online, a.os_family, a.os_name, c.name AS client_name, s.name AS site_name,
                a.vuln_ecosystem AS ecosystem, a.vuln_critical AS critical, a.vuln_high AS high, x.open, x.kev, x.fixable,
                a.vuln_evaluated_at AS evaluated_at
           FROM agents a JOIN sites s ON s.id = a.site_id JOIN clients c ON c.id = s.client_id
           JOIN LATERAL (SELECT count(DISTINCT coalesce(v.cve, v.id)) AS open,
                                count(DISTINCT coalesce(v.cve, v.id)) FILTER (WHERE v.kev) AS kev,
                                count(DISTINCT coalesce(v.cve, v.id)) FILTER (WHERE f.fix_available) AS fixable
                           FROM vuln_findings f JOIN vulns v ON v.id = f.vuln_id
                          WHERE f.agent_id = a.id AND f.resolved_at IS NULL AND NOT vuln_accepted(f.agent_id, f.vuln_id, v.cve)) x ON x.open > 0
          WHERE ($1::uuid[] IS NULL OR s.client_id = ANY($1)) AND ($2::uuid IS NULL OR s.client_id = $2)
            AND ($3::text IS NULL OR a.hostname ILIKE '%' || $3 || '%')
          ORDER BY a.vuln_critical DESC, x.kev DESC, a.vuln_high DESC, x.open DESC, lower(a.hostname) LIMIT 1000",
    )
    .bind(u.scope())
    .bind(q.client_id)
    .bind(&search)
    .fetch_all(&st.db)
    .await?;
    Ok(Json(rows))
}

// ---------------------------------------------------------------------------
// By software
// ---------------------------------------------------------------------------

#[derive(Serialize, sqlx::FromRow)]
pub struct SoftwareRow {
    package: String,
    ecosystems: Vec<String>,
    product_id: Option<Uuid>,
    product_name: Option<String>,
    package_id: Option<Uuid>,
    devices: i64,
    cves: i64,
    severity: String,
    kev: bool,
    fix_available: bool,
    /// The highest fixed version any finding names (what to upgrade to).
    fixed_versions: Vec<String>,
}

/// Vulnerable packages and products, worst first (at most 500).
pub async fn software(State(st): State<Arc<AppState>>, u: User, Query(q): Query<ListQuery>) -> ApiResult<Json<Vec<SoftwareRow>>> {
    u.need(Perm::SecurityRead)?;
    if let Some(c) = q.client_id {
        super::access::client(&u, c)?;
    }
    let search = q.q.as_deref().map(str::trim).filter(|s| !s.is_empty()).map(String::from);
    let rows: Vec<SoftwareRow> = sqlx::query_as(AssertSqlSafe(format!(
        "SELECT g.package, g.ecosystems, g.product_id, vp.name AS product_name, vp.package_id, g.devices, g.cves, {SEV_NAME} AS severity,
                g.kev, g.fix_available, g.fixed_versions
           FROM (SELECT f.package, array_agg(DISTINCT coalesce(a.vuln_ecosystem, '')) AS ecosystems, max(f.product_id::text)::uuid AS product_id,
                        count(DISTINCT f.agent_id) AS devices, count(DISTINCT coalesce(v.cve, v.id)) AS cves, max({rank}) AS sev_rank,
                        bool_or(v.kev) AS kev, bool_or(f.fix_available) AS fix_available,
                        (array_agg(DISTINCT f.fixed_version) FILTER (WHERE f.fixed_version IS NOT NULL))[1:5] AS fixed_versions
                   FROM vuln_findings f JOIN vulns v ON v.id = f.vuln_id JOIN agents a ON a.id = f.agent_id JOIN sites s ON s.id = a.site_id
                  WHERE f.resolved_at IS NULL AND NOT vuln_accepted(f.agent_id, f.vuln_id, v.cve)
                    AND ($1::uuid[] IS NULL OR s.client_id = ANY($1)) AND ($2::uuid IS NULL OR s.client_id = $2)
                    AND ($3::text IS NULL OR f.package ILIKE '%' || $3 || '%' OR f.software_name ILIKE '%' || $3 || '%')
                  GROUP BY f.package) g
           LEFT JOIN vuln_products vp ON vp.id = g.product_id
          ORDER BY g.sev_rank DESC, g.kev DESC, g.devices DESC, g.package LIMIT 500",
        rank = matcher::rank_sql("v.severity")
    )))
    .bind(u.scope())
    .bind(q.client_id)
    .bind(&search)
    .fetch_all(&st.db)
    .await?;
    Ok(Json(rows))
}

// ---------------------------------------------------------------------------
// Not assessed
// ---------------------------------------------------------------------------

#[derive(Serialize, sqlx::FromRow)]
struct UnassessedDevice {
    agent_id: Uuid,
    hostname: String,
    os_family: String,
    os_name: String,
    agent_version: String,
    client_name: String,
    reason: String,
}

#[derive(Serialize)]
struct Title {
    title: String,
    publisher: Option<String>,
    devices: usize,
    versions: Vec<String>,
}

/// Devices that aren't assessed (and why), and Windows titles the product map doesn't cover.
pub async fn unassessed(State(st): State<Arc<AppState>>, u: User, Query(q): Query<ListQuery>) -> ApiResult<Json<Value>> {
    u.need(Perm::SecurityRead)?;
    if let Some(c) = q.client_id {
        super::access::client(&u, c)?;
    }
    let devices: Vec<UnassessedDevice> = sqlx::query_as(
        "SELECT a.id AS agent_id, a.hostname, a.os_family, a.os_name, a.agent_version, c.name AS client_name, a.vuln_unassessed AS reason
           FROM agents a JOIN sites s ON s.id = a.site_id JOIN clients c ON c.id = s.client_id
          WHERE a.vuln_unassessed IS NOT NULL AND ($1::uuid[] IS NULL OR s.client_id = ANY($1)) AND ($2::uuid IS NULL OR s.client_id = $2)
          ORDER BY a.vuln_unassessed, lower(a.hostname) LIMIT 1000",
    )
    .bind(u.scope())
    .bind(q.client_id)
    .fetch_all(&st.db)
    .await?;
    let titles: Vec<(Uuid, String, Option<String>, String)> = sqlx::query_as(
        "SELECT a.id, sw ->> 'name', sw ->> 'publisher', coalesce(sw ->> 'version', '')
           FROM agents a JOIN sites s ON s.id = a.site_id, jsonb_array_elements(coalesce(a.inventory -> 'software', '[]')) sw
          WHERE a.os_family = 'windows' AND sw ->> 'source' IN ('registry', 'msi')
            AND ($1::uuid[] IS NULL OR s.client_id = ANY($1)) AND ($2::uuid IS NULL OR s.client_id = $2)
          LIMIT 200000",
    )
    .bind(u.scope())
    .bind(q.client_id)
    .fetch_all(&st.db)
    .await?;
    let products = matcher::products(&st.db).await?;
    type Seen = (std::collections::BTreeSet<Uuid>, std::collections::BTreeSet<String>);
    let mut by_title: BTreeMap<(String, Option<String>), Seen> = BTreeMap::new();
    for (agent, title, publisher, version) in titles {
        if matcher::best_product(&products, &title, publisher.as_deref()).is_some() {
            continue;
        }
        let e = by_title.entry((title, publisher)).or_default();
        e.0.insert(agent);
        if e.1.len() < 5 {
            e.1.insert(version);
        }
    }
    let mut titles: Vec<Title> = by_title
        .into_iter()
        .map(|((title, publisher), (agents, versions))| Title { title, publisher, devices: agents.len(), versions: versions.into_iter().collect() })
        .collect();
    titles.sort_by(|a, b| b.devices.cmp(&a.devices).then_with(|| a.title.to_lowercase().cmp(&b.title.to_lowercase())));
    titles.truncate(1000);
    Ok(Json(json!({ "devices": devices, "titles": titles, "products": products.len() })))
}

// ---------------------------------------------------------------------------
// Accepting risk
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct AcceptBody {
    /// A CVE or an advisory id.
    vuln_id: String,
    client_id: Uuid,
    /// One device; omitted: every device of the client.
    agent_id: Option<Uuid>,
    #[serde(default)]
    note: String,
    expires_at: Option<DateTime<Utc>>,
}

/// The agents an acceptance (or its removal) touches.
async fn touched(st: &AppState, client_id: Uuid, agent_id: Option<Uuid>, vuln_id: &str) -> sqlx::Result<Vec<Uuid>> {
    sqlx::query_scalar(
        "SELECT DISTINCT f.agent_id FROM vuln_findings f JOIN vulns v ON v.id = f.vuln_id JOIN agents a ON a.id = f.agent_id
           JOIN sites s ON s.id = a.site_id
          WHERE f.resolved_at IS NULL AND s.client_id = $1 AND ($2::uuid IS NULL OR f.agent_id = $2) AND (v.cve = $3 OR v.id = $3)",
    )
    .bind(client_id)
    .bind(agent_id)
    .bind(vuln_id)
    .fetch_all(&st.db)
    .await
}

async fn after_acceptance(st: &AppState, agents: &[Uuid]) {
    if let Err(e) = matcher::refresh_counts(&st.db, agents).await {
        tracing::warn!("vulnerabilities: recounting after an acceptance: {e}");
    }
    for a in agents {
        crate::alerts::vulns_changed(st, *a).await;
    }
}

pub async fn accept(State(st): State<Arc<AppState>>, u: User, Json(b): Json<AcceptBody>) -> ApiResult<(StatusCode, Json<Value>)> {
    u.need(Perm::SecurityRespond)?;
    super::access::client(&u, b.client_id)?;
    let vuln_id = b.vuln_id.trim().to_string();
    if vuln_id.is_empty() || vuln_id.len() > 200 {
        return Err(bad("vuln_id is a CVE or advisory id"));
    }
    let known: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM vulns WHERE id = $1 OR cve = $1)").bind(&vuln_id).fetch_one(&st.db).await?;
    if !known {
        return Err(ApiError::NotFound("vulnerability"));
    }
    if let Some(a) = b.agent_id
        && super::access::agent(&st, &u, a).await? != b.client_id
    {
        return Err(bad("the device belongs to another client"));
    }
    if b.note.chars().count() > 2000 {
        return Err(bad("the note is at most 2000 characters"));
    }
    if b.expires_at.is_some_and(|t| t <= Utc::now()) {
        return Err(bad("expires_at is in the past"));
    }
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO vuln_acceptances (id, vuln_id, client_id, agent_id, note, expires_at, by) VALUES ($1, $2, $3, $4, $5, $6, $7)")
        .bind(id)
        .bind(&vuln_id)
        .bind(b.client_id)
        .bind(b.agent_id)
        .bind(b.note.trim())
        .bind(b.expires_at)
        .bind(u.id)
        .execute(&st.db)
        .await?;
    auth::audit(
        &st.db,
        Some(u.id),
        "vuln.accept",
        Some(("client", b.client_id)),
        json!({ "id": id, "vuln_id": vuln_id, "agent_id": b.agent_id, "expires_at": b.expires_at, "note": b.note.trim() }),
    )
    .await;
    let agents = touched(&st, b.client_id, b.agent_id, &vuln_id).await?;
    after_acceptance(&st, &agents).await;
    Ok((StatusCode::CREATED, Json(json!({ "id": id, "devices": agents.len() }))))
}

pub async fn unaccept(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    u.need(Perm::SecurityRespond)?;
    let row: Option<(Uuid, Option<Uuid>, String)> =
        sqlx::query_as("SELECT client_id, agent_id, vuln_id FROM vuln_acceptances WHERE id = $1").bind(id).fetch_optional(&st.db).await?;
    let Some((client_id, agent_id, vuln_id)) = row.filter(|r| u.can_see_client(r.0)) else { return Err(ApiError::NotFound("acceptance")) };
    sqlx::query("DELETE FROM vuln_acceptances WHERE id = $1").bind(id).execute(&st.db).await?;
    auth::audit(&st.db, Some(u.id), "vuln.unaccept", Some(("client", client_id)), json!({ "id": id, "vuln_id": vuln_id, "agent_id": agent_id })).await;
    let agents = touched(&st, client_id, agent_id, &vuln_id).await?;
    after_acceptance(&st, &agents).await;
    Ok(Json(json!({ "ok": true })))
}

// ---------------------------------------------------------------------------
// Feeds
// ---------------------------------------------------------------------------

fn feed_label(name: &str) -> String {
    match name {
        "arch" => "Arch Linux security tracker".into(),
        "nvd" => "NVD (Windows applications in the product map)".into(),
        "kev" => "CISA Known Exploited Vulnerabilities".into(),
        "epss" => "EPSS (FIRST)".into(),
        n => format!("OSV: {}", n.trim_start_matches("osv:")),
    }
}

#[derive(sqlx::FromRow)]
struct FeedRow {
    name: String,
    enabled: bool,
    last_sync_at: Option<DateTime<Utc>>,
    last_attempt_at: Option<DateTime<Utc>>,
    progress: Option<String>,
    records: i32,
    error: Option<String>,
}

pub async fn feeds(State(st): State<Arc<AppState>>, u: User) -> ApiResult<Json<Value>> {
    u.need(Perm::SecurityManage)?;
    let rows: Vec<FeedRow> =
        sqlx::query_as("SELECT name, enabled, last_sync_at, last_attempt_at, progress, records, error FROM vuln_feeds ORDER BY name").fetch_all(&st.db).await?;
    let relevant = vuln::feeds::relevant(&st.db).await?;
    let order = |n: &str| match n {
        n if n.starts_with("osv:") => 0,
        "arch" => 1,
        "nvd" => 2,
        "kev" => 3,
        _ => 4,
    };
    let mut list: Vec<Value> = rows
        .into_iter()
        .map(|r| {
            json!({
                "name": r.name, "label": feed_label(&r.name), "enabled": r.enabled, "needed": relevant.contains(&r.name),
                "last_sync_at": r.last_sync_at, "last_attempt_at": r.last_attempt_at, "progress": r.progress, "records": r.records, "error": r.error,
            })
        })
        .collect();
    list.sort_by_key(|f| (order(f["name"].as_str().unwrap_or_default()), f["name"].as_str().unwrap_or_default().to_string()));
    let urls = vuln::feeds::Urls::from_env();
    Ok(Json(json!({
        "feeds": list,
        "running": vuln::feeds::running(),
        "nvd_api_key": urls.nvd_key.is_some(),
        "automatic": std::env::var("RMM_VULN_SYNC_HOURS").ok().and_then(|v| v.trim().parse::<i64>().ok()).unwrap_or(24) > 0,
        "attribution": [
            "This product uses the NVD API but is not endorsed or certified by the NVD.",
            "Advisory data from OSV.dev (CC-BY 4.0), collected from the Debian, Ubuntu, AlmaLinux, Rocky Linux, Red Hat, SUSE and Alpine security teams.",
            "Arch Linux security data from security.archlinux.org.",
            "Known exploited vulnerabilities from CISA's KEV catalog (CC0).",
            "EPSS scores from FIRST (first.org/epss).",
        ],
    })))
}

#[derive(Deserialize)]
pub struct FeedBody {
    enabled: bool,
}

pub async fn update_feed(State(st): State<Arc<AppState>>, u: User, Path(name): Path<String>, Json(b): Json<FeedBody>) -> ApiResult<Json<Value>> {
    u.need(Perm::SecurityManage)?;
    let n = sqlx::query("UPDATE vuln_feeds SET enabled = $2 WHERE name = $1").bind(&name).bind(b.enabled).execute(&st.db).await?.rows_affected();
    if n == 0 {
        return Err(ApiError::NotFound("feed"));
    }
    auth::audit(&st.db, Some(u.id), "vuln.feed.update", None, json!({ "feed": name, "enabled": b.enabled })).await;
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize, Default)]
pub struct SyncBody {
    /// Only these feeds (default: every feed the fleet needs).
    feeds: Option<Vec<String>>,
    /// Download even if the feed synced recently.
    #[serde(default)]
    force: bool,
}

/// Starts a sync in the background; `GET /vulnerabilities/feeds` shows its progress.
pub async fn sync(State(st): State<Arc<AppState>>, u: User, body: Option<Json<SyncBody>>) -> ApiResult<(StatusCode, Json<Value>)> {
    u.need(Perm::SecurityManage)?;
    let b = body.map(|b| b.0).unwrap_or_default();
    if vuln::feeds::running() {
        return Err(ApiError::Conflict("a sync is already running".into()));
    }
    if let Some(list) = &b.feeds {
        let known: Vec<String> = sqlx::query_scalar("SELECT name FROM vuln_feeds").fetch_all(&st.db).await?;
        if let Some(x) = list.iter().find(|f| !known.contains(f)) {
            return Err(ApiError::BadRequest(format!("unknown feed {x}")));
        }
    }
    auth::audit(&st.db, Some(u.id), "vuln.sync", None, json!({ "feeds": b.feeds, "force": b.force })).await;
    let db = st.db.clone();
    tokio::spawn(async move {
        match vuln::feeds::sync(&db, b.feeds, b.force, 24).await {
            Ok(r) => tracing::info!("vulnerabilities: sync: {}", vuln::feeds::summary(&r)),
            Err(e) => tracing::warn!("vulnerabilities: sync: {e:#}"),
        }
    });
    Ok((StatusCode::ACCEPTED, Json(json!({ "started": true }))))
}

// ---------------------------------------------------------------------------
// Product map
// ---------------------------------------------------------------------------

#[derive(Serialize, sqlx::FromRow)]
pub struct ProductRow {
    id: Uuid,
    vendor: String,
    product: String,
    name: String,
    name_patterns: Vec<String>,
    publisher_pattern: Option<String>,
    package_id: Option<Uuid>,
    package_name: Option<String>,
    builtin: bool,
    nvd_synced_at: Option<DateTime<Utc>>,
    /// Devices with an open finding through it.
    devices: i64,
}

const PRODUCT_COLS: &str = "p.id, p.vendor, p.product, p.name, p.name_patterns, p.publisher_pattern, p.package_id, sp.name AS package_name, p.builtin,
    p.nvd_synced_at, (SELECT count(DISTINCT f.agent_id) FROM vuln_findings f WHERE f.product_id = p.id AND f.resolved_at IS NULL) AS devices";

pub async fn products(State(st): State<Arc<AppState>>, u: User) -> ApiResult<Json<Vec<ProductRow>>> {
    u.need(Perm::SecurityManage)?;
    let rows: Vec<ProductRow> = sqlx::query_as(AssertSqlSafe(format!(
        "SELECT {PRODUCT_COLS} FROM vuln_products p LEFT JOIN software_packages sp ON sp.id = p.package_id WHERE NOT p.hidden ORDER BY lower(p.name)"
    )))
    .fetch_all(&st.db)
    .await?;
    Ok(Json(rows))
}

#[derive(Deserialize)]
pub struct ProductBody {
    vendor: String,
    product: String,
    name: String,
    name_patterns: Vec<String>,
    #[serde(default)]
    publisher_pattern: Option<String>,
    #[serde(default)]
    package_id: Option<Uuid>,
}

/// CPE vendor and product names: lowercase letters, digits and `_-.~!`, `\` escapes.
fn cpe_part(s: &str, what: &str) -> ApiResult<String> {
    let s = s.trim().to_string();
    if s.is_empty() || s.len() > 100 || s.chars().any(|c| c.is_whitespace() || c == ':' || c == '*' || c == '?' || c.is_ascii_uppercase()) {
        return Err(ApiError::BadRequest(format!("{what} is the NVD CPE {what} name: lowercase, no spaces or colons (e.g. google, chrome)")));
    }
    Ok(s)
}

async fn check_product(st: &AppState, b: &ProductBody) -> ApiResult<(String, String, String, Vec<String>, Option<String>)> {
    let vendor = cpe_part(&b.vendor, "vendor")?;
    let product = cpe_part(&b.product, "product")?;
    let name = b.name.trim().to_string();
    if name.is_empty() || name.chars().count() > 200 {
        return Err(bad("name: 1-200 characters"));
    }
    let patterns: Vec<String> = b.name_patterns.iter().map(|p| p.trim().to_string()).filter(|p| !p.is_empty()).collect();
    if patterns.is_empty() || patterns.len() > 20 || patterns.iter().any(|p| p.chars().count() > 200 || p.chars().all(|c| c == '*')) {
        return Err(bad("name_patterns: 1-20 patterns of the installed title (`*` matches anything), not just `*`"));
    }
    let publisher = b.publisher_pattern.as_deref().map(str::trim).filter(|p| !p.is_empty()).map(String::from);
    if publisher.as_ref().is_some_and(|p| p.chars().count() > 200) {
        return Err(bad("publisher_pattern: at most 200 characters"));
    }
    if let Some(pid) = b.package_id {
        // A global catalog package: per-client ones would offer the upgrade to the wrong clients.
        let ok: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM software_packages WHERE id = $1 AND client_id IS NULL)").bind(pid).fetch_one(&st.db).await?;
        if !ok {
            return Err(bad("package_id is a catalog package for every client"));
        }
    }
    Ok((vendor, product, name, patterns, publisher))
}

/// After the map changes: Windows devices again, and NVD for a product new to the fleet.
async fn products_changed(st: &AppState) {
    if let Err(e) = vuln::requeue(&st.db, Some(&["Windows".to_string()])).await {
        tracing::warn!("vulnerabilities: requeueing Windows devices: {e}");
    }
    let auto = std::env::var("RMM_VULN_SYNC_HOURS").ok().and_then(|v| v.trim().parse::<i64>().ok()).unwrap_or(24) > 0;
    if auto && !vuln::feeds::running() {
        let db = st.db.clone();
        tokio::spawn(async move {
            if let Err(e) = vuln::feeds::sync(&db, Some(vec!["nvd".into()]), true, 24).await {
                tracing::warn!("vulnerabilities: NVD after a product map change: {e:#}");
            }
        });
    }
}

async fn product_row(st: &AppState, id: Uuid) -> ApiResult<ProductRow> {
    sqlx::query_as(AssertSqlSafe(format!(
        "SELECT {PRODUCT_COLS} FROM vuln_products p LEFT JOIN software_packages sp ON sp.id = p.package_id WHERE p.id = $1 AND NOT p.hidden"
    )))
    .bind(id)
    .fetch_optional(&st.db)
    .await?
    .ok_or(ApiError::NotFound("product"))
}

pub async fn create_product(State(st): State<Arc<AppState>>, u: User, Json(b): Json<ProductBody>) -> ApiResult<(StatusCode, Json<ProductRow>)> {
    u.need(Perm::SecurityManage)?;
    let (vendor, product, name, patterns, publisher) = check_product(&st, &b).await?;
    // A hidden built-in of the same product comes back with the new settings.
    let id: Option<Uuid> = sqlx::query_scalar(
        "INSERT INTO vuln_products (vendor, product, name, name_patterns, publisher_pattern, package_id)
         VALUES ($1, $2, $3, $4, $5, $6)
         ON CONFLICT (vendor, product) DO UPDATE SET name = EXCLUDED.name, name_patterns = EXCLUDED.name_patterns,
                publisher_pattern = EXCLUDED.publisher_pattern, package_id = EXCLUDED.package_id, hidden = false, updated_at = now()
          WHERE vuln_products.hidden
         RETURNING id",
    )
    .bind(&vendor)
    .bind(&product)
    .bind(&name)
    .bind(&patterns)
    .bind(&publisher)
    .bind(b.package_id)
    .fetch_optional(&st.db)
    .await?;
    let Some(id) = id else { return Err(ApiError::Conflict(format!("{vendor}:{product} is already mapped; edit it instead"))) };
    auth::audit(&st.db, Some(u.id), "vuln.product.create", None, json!({ "id": id, "vendor": vendor, "product": product, "patterns": patterns })).await;
    products_changed(&st).await;
    Ok((StatusCode::CREATED, Json(product_row(&st, id).await?)))
}

pub async fn update_product(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>, Json(b): Json<ProductBody>) -> ApiResult<Json<ProductRow>> {
    u.need(Perm::SecurityManage)?;
    let (vendor, product, name, patterns, publisher) = check_product(&st, &b).await?;
    let res = sqlx::query(
        "UPDATE vuln_products SET vendor = $2, product = $3, name = $4, name_patterns = $5, publisher_pattern = $6, package_id = $7,
                nvd_synced_at = CASE WHEN vendor = $2 AND product = $3 THEN nvd_synced_at END, updated_at = now()
          WHERE id = $1 AND NOT hidden",
    )
    .bind(id)
    .bind(&vendor)
    .bind(&product)
    .bind(&name)
    .bind(&patterns)
    .bind(&publisher)
    .bind(b.package_id)
    .execute(&st.db)
    .await;
    match res {
        Ok(r) if r.rows_affected() == 0 => return Err(ApiError::NotFound("product")),
        Ok(_) => {}
        Err(sqlx::Error::Database(e)) if e.is_unique_violation() => return Err(ApiError::Conflict(format!("{vendor}:{product} is already mapped"))),
        Err(e) => return Err(e.into()),
    }
    auth::audit(&st.db, Some(u.id), "vuln.product.update", None, json!({ "id": id, "vendor": vendor, "product": product, "patterns": patterns })).await;
    products_changed(&st).await;
    Ok(Json(product_row(&st, id).await?))
}

/// Built-in mappings are hidden (so the seed doesn't bring them back); others deleted.
pub async fn delete_product(State(st): State<Arc<AppState>>, u: User, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    u.need(Perm::SecurityManage)?;
    let row: Option<(String, String, bool)> =
        sqlx::query_as("SELECT vendor, product, builtin FROM vuln_products WHERE id = $1 AND NOT hidden").bind(id).fetch_optional(&st.db).await?;
    let Some((vendor, product, builtin)) = row else { return Err(ApiError::NotFound("product")) };
    if builtin {
        sqlx::query("UPDATE vuln_products SET hidden = true, updated_at = now() WHERE id = $1").bind(id).execute(&st.db).await?;
    } else {
        sqlx::query("DELETE FROM vuln_products WHERE id = $1").bind(id).execute(&st.db).await?;
    }
    auth::audit(&st.db, Some(u.id), "vuln.product.delete", None, json!({ "id": id, "vendor": vendor, "product": product })).await;
    products_changed(&st).await;
    Ok(Json(json!({ "ok": true })))
}

// ---------------------------------------------------------------------------
// QBR
// ---------------------------------------------------------------------------

/// QBR "Vulnerabilities": what is open now (not accepted), what was found and fixed in the
/// period, and the worst CVEs.
pub(crate) async fn qbr_blocks(st: &AppState, client: Uuid, from: NaiveDate, to: NaiveDate, blocks: &mut Vec<crate::pdf::Block>) -> ApiResult<()> {
    use crate::pdf::Block;
    let (assessed, crit, high, affected): (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT count(*) FILTER (WHERE a.vuln_ecosystem IS NOT NULL), coalesce(sum(a.vuln_critical), 0)::bigint, coalesce(sum(a.vuln_high), 0)::bigint,
                count(*) FILTER (WHERE a.vuln_critical + a.vuln_high > 0)
           FROM agents a JOIN sites s ON s.id = a.site_id WHERE s.client_id = $1",
    )
    .bind(client)
    .fetch_one(&st.db)
    .await?;
    if assessed == 0 {
        return Ok(());
    }
    let (found, fixed): (i64, i64) = sqlx::query_as(
        "SELECT count(*) FILTER (WHERE f.first_seen >= $2 AND f.first_seen < $3::date + 1),
                count(*) FILTER (WHERE f.resolved_at >= $2 AND f.resolved_at < $3::date + 1)
           FROM vuln_findings f JOIN agents a ON a.id = f.agent_id JOIN sites s ON s.id = a.site_id WHERE s.client_id = $1",
    )
    .bind(client)
    .bind(from)
    .bind(to)
    .fetch_one(&st.db)
    .await?;
    blocks.push(Block::Heading("Vulnerabilities".into()));
    blocks.push(Block::Figures(vec![
        ("Devices assessed".into(), assessed.to_string()),
        ("Devices with critical or high".into(), affected.to_string()),
        ("Open critical".into(), crit.to_string()),
        ("Open high".into(), high.to_string()),
        ("Found in the period".into(), found.to_string()),
        ("Fixed in the period".into(), fixed.to_string()),
    ]));
    let top: Vec<(String, String, bool, i64)> = sqlx::query_as(AssertSqlSafe(format!(
        "SELECT coalesce(v.cve, v.id),
                (CASE max({rank}) WHEN 4 THEN 'critical' WHEN 3 THEN 'high' WHEN 2 THEN 'medium' WHEN 1 THEN 'low' ELSE 'unrated' END),
                bool_or(v.kev), count(DISTINCT f.agent_id)
           FROM vuln_findings f JOIN vulns v ON v.id = f.vuln_id JOIN agents a ON a.id = f.agent_id JOIN sites s ON s.id = a.site_id
          WHERE s.client_id = $1 AND f.resolved_at IS NULL AND NOT vuln_accepted(f.agent_id, f.vuln_id, v.cve)
          GROUP BY 1 ORDER BY max({rank}) DESC, bool_or(v.kev) DESC, 4 DESC, 1 LIMIT 10",
        rank = matcher::rank_sql("v.severity")
    )))
    .bind(client)
    .fetch_all(&st.db)
    .await?;
    if !top.is_empty() {
        blocks.push(Block::Table(
            vec!["Open vulnerability".into(), "Severity".into(), "Devices".into()],
            top.into_iter().map(|(k, sev, kev, n)| vec![k, if kev { format!("{sev}, exploited") } else { sev }, n.to_string()]).collect(),
        ));
    }
    Ok(())
}
