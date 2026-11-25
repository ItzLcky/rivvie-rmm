//! One device's inventory against the advisories' ranges, into `vuln_findings`, and its
//! `vulnerability` alert.
//!
//! The inventory is read from `agents.inventory` (no per-package table). Linux packages are
//! looked up by `(ecosystem, package)`: on Debian and Ubuntu by source package, elsewhere by
//! binary and source name. When a package is installed more than once (kernels), the newest
//! counts. Windows titles go through the curated product map to `NVD` + `vendor:product`, every
//! installed version counting.

use std::collections::{BTreeMap, HashMap};

use rmm_proto::Software;
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::AssertSqlSafe;
use tracing::{debug, warn};
use uuid::Uuid;

use super::version::{Range, Scheme};
use crate::alerts::{self, Rule};
use crate::state::AppState;

/// A Windows product mapping.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Product {
    pub id: Uuid,
    pub vendor: String,
    pub product: String,
    pub name_patterns: Vec<String>,
    pub publisher_pattern: Option<String>,
}

impl Product {
    pub fn matches(&self, title: &str, publisher: Option<&str>) -> bool {
        self.match_len(title, publisher).is_some()
    }

    /// The length of the longest pattern that matches: the most specific mapping wins
    /// (`Mozilla Firefox ESR*` over `Mozilla Firefox*`).
    pub fn match_len(&self, title: &str, publisher: Option<&str>) -> Option<usize> {
        if !self.publisher_pattern.as_deref().filter(|p| !p.is_empty()).is_none_or(|p| publisher.is_some_and(|x| super::glob(p, x))) {
            return None;
        }
        self.name_patterns.iter().filter(|p| super::glob(p, title)).map(|p| p.len()).max()
    }

    pub fn key(&self) -> String {
        format!("{}:{}", self.vendor, self.product)
    }
}

pub async fn products(db: &sqlx::PgPool) -> sqlx::Result<Vec<Product>> {
    sqlx::query_as("SELECT id, vendor, product, name_patterns, publisher_pattern FROM vuln_products WHERE NOT hidden ORDER BY lower(name)")
        .fetch_all(db)
        .await
}

/// A range of an advisory, with what the storage rule and the alert need.
#[derive(Debug, Clone)]
pub struct Candidate {
    pub vuln_id: String,
    pub package: String,
    pub severity: String,
    pub kev: bool,
    pub range: Range,
}

/// An installed package as the feeds name it.
#[derive(Debug, Clone)]
pub struct Installed {
    pub key: String,
    pub software_name: String,
    pub version: String,
    pub product_id: Option<Uuid>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Finding {
    pub vuln_id: String,
    pub package: String,
    pub software_name: String,
    pub installed: String,
    pub fixed: Option<String>,
    pub product_id: Option<Uuid>,
}

/// The storage rule: a fix exists, or it is high or critical, or it is known exploited.
pub fn keep(fix_available: bool, severity: &str, kev: bool) -> bool {
    fix_available || super::severity_rank(severity) >= 3 || kev
}

/// The packages of an inventory that an ecosystem's feed covers. Linux: one entry per feed
/// package name, at the newest installed version; Windows: every mapped title and version.
pub fn installed(ecosystem: &str, software: &[Software], products: &[Product]) -> Vec<Installed> {
    let scheme = super::scheme(ecosystem);
    if ecosystem == "Windows" {
        let mut out = Vec::new();
        for s in software.iter().filter(|s| matches!(s.source.as_str(), "registry" | "msi")) {
            if let Some(p) = best_product(products, &s.name, s.publisher.as_deref()) {
                out.push(Installed { key: p.key(), software_name: s.name.clone(), version: s.version.clone(), product_id: Some(p.id) });
            }
        }
        return out;
    }
    let source = super::inventory_source(ecosystem);
    let mut best: BTreeMap<String, Installed> = BTreeMap::new();
    for s in software.iter().filter(|s| s.source == source && !s.version.is_empty()) {
        let keys: Vec<&str> = match (scheme, s.source_name.as_deref()) {
            // Debian and Ubuntu publish by source package only.
            (Scheme::Dpkg, Some(src)) => vec![src],
            (_, Some(src)) => vec![s.name.as_str(), src],
            (_, None) => vec![s.name.as_str()],
        };
        for k in keys {
            let cand = Installed { key: k.to_string(), software_name: s.name.clone(), version: s.version.clone(), product_id: None };
            match best.get(k) {
                Some(cur) if scheme.cmp(&cur.version, &s.version) != std::cmp::Ordering::Less => {}
                _ => {
                    best.insert(k.to_string(), cand);
                }
            }
        }
    }
    best.into_values().collect()
}

/// The most specific mapping for an installed title.
pub fn best_product<'a>(products: &'a [Product], title: &str, publisher: Option<&str>) -> Option<&'a Product> {
    products.iter().filter_map(|p| p.match_len(title, publisher).map(|n| (n, p))).max_by_key(|(n, _)| *n).map(|(_, p)| p)
}

/// Which installed packages fall in which ranges, after the storage rule.
pub fn find(scheme: Scheme, installed: &[Installed], candidates: &[Candidate]) -> Vec<Finding> {
    let mut by_key: HashMap<&str, Vec<&Installed>> = HashMap::new();
    for i in installed {
        by_key.entry(i.key.as_str()).or_default().push(i);
    }
    let mut out: BTreeMap<(String, String), Finding> = BTreeMap::new();
    for c in candidates {
        let Some(list) = by_key.get(c.package.as_str()) else { continue };
        for i in list {
            if !c.range.contains(scheme, &i.version) {
                continue;
            }
            if !keep(c.range.fixed.is_some(), &c.severity, c.kev) {
                continue;
            }
            out.entry((c.vuln_id.clone(), c.package.clone())).or_insert_with(|| Finding {
                vuln_id: c.vuln_id.clone(),
                package: c.package.clone(),
                software_name: i.software_name.clone(),
                installed: i.version.clone(),
                fixed: c.range.fixed.clone(),
                product_id: i.product_id,
            });
        }
    }
    out.into_values().collect()
}

#[derive(Deserialize, Default)]
struct Inv {
    #[serde(default)]
    system: Option<Sys>,
    #[serde(default)]
    software: Vec<Software>,
}

#[derive(Deserialize, Default)]
struct Sys {
    #[serde(default)]
    os_id: Option<String>,
    #[serde(default)]
    os_version_id: Option<String>,
}

/// Evaluates up to `limit` queued devices. Returns how many.
pub async fn evaluate_queued(st: &AppState, limit: i64) -> anyhow::Result<usize> {
    let ids: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM agents WHERE vuln_evaluated_at IS NULL ORDER BY inventory_at NULLS LAST LIMIT $1")
        .bind(limit)
        .fetch_all(&st.db)
        .await?;
    for id in &ids {
        if let Err(e) = evaluate(st, *id).await {
            warn!(agent_id = %id, "vulnerabilities: evaluating: {e:#}");
            // Don't retry in a tight loop: the next inventory or sync queues it again.
            let _ = sqlx::query("UPDATE agents SET vuln_evaluated_at = now() WHERE id = $1").bind(id).execute(&st.db).await;
        }
    }
    Ok(ids.len())
}

/// Matches one device and stores the result: findings, the ecosystem (or why there is none),
/// the stored counts, and the alert.
pub async fn evaluate(st: &AppState, agent_id: Uuid) -> anyhow::Result<()> {
    let row: Option<(String, Option<Value>)> = sqlx::query_as("SELECT os_family, inventory FROM agents WHERE id = $1").bind(agent_id).fetch_optional(&st.db).await?;
    let Some((os_family, inventory)) = row else { return Ok(()) };
    let inv: Option<Inv> = inventory.map(serde_json::from_value).transpose().unwrap_or_else(|e| {
        warn!(%agent_id, "vulnerabilities: unreadable inventory: {e}");
        None
    });
    let eco = match &inv {
        None => Err(super::Unassessed::NoInventory),
        Some(inv) => {
            let sys = inv.system.as_ref();
            let pacman = inv.software.iter().any(|s| s.source == "pacman");
            super::ecosystem(&os_family, sys.and_then(|s| s.os_id.as_deref()), sys.and_then(|s| s.os_version_id.as_deref()), pacman)
        }
    };
    let findings = match (&eco, &inv) {
        (Ok(eco), Some(inv)) => {
            let products = if eco == "Windows" { products(&st.db).await? } else { vec![] };
            let installed = installed(eco, &inv.software, &products);
            let range_eco = if eco == "Windows" { "NVD" } else { eco.as_str() };
            let keys: Vec<&str> = installed.iter().map(|i| i.key.as_str()).collect();
            #[allow(clippy::type_complexity)]
            let rows: Vec<(String, String, String, bool, Option<String>, bool, Option<String>, Option<String>)> = sqlx::query_as(
                "SELECT r.vuln_id, r.package, v.severity, v.kev, r.introduced, r.introduced_exclusive, r.fixed, r.last_affected
                   FROM vuln_ranges r JOIN vulns v ON v.id = r.vuln_id
                  WHERE r.ecosystem = $1 AND r.package = ANY($2)",
            )
            .bind(range_eco)
            .bind(&keys)
            .fetch_all(&st.db)
            .await?;
            let candidates: Vec<Candidate> = rows
                .into_iter()
                .map(|(vuln_id, package, severity, kev, introduced, introduced_exclusive, fixed, last_affected)| Candidate {
                    vuln_id,
                    package,
                    severity,
                    kev,
                    range: Range { introduced, introduced_exclusive, fixed, last_affected },
                })
                .collect();
            find(super::scheme(range_eco), &installed, &candidates)
        }
        _ => vec![],
    };
    store(st, agent_id, &findings).await?;
    let (eco_s, why) = match &eco {
        Ok(e) => (Some(e.clone()), None),
        Err(u) => (None, Some(u.as_str())),
    };
    sqlx::query("UPDATE agents SET vuln_evaluated_at = now(), vuln_ecosystem = $2, vuln_unassessed = $3 WHERE id = $1")
        .bind(agent_id)
        .bind(eco_s)
        .bind(why)
        .execute(&st.db)
        .await?;
    refresh_counts(&st.db, &[agent_id]).await?;
    debug!(%agent_id, findings = findings.len(), "vulnerabilities: evaluated");
    crate::alerts::vulns_changed(st, agent_id).await;
    Ok(())
}

async fn store(st: &AppState, agent_id: Uuid, findings: &[Finding]) -> sqlx::Result<()> {
    let rows: Vec<Value> = findings
        .iter()
        .map(|f| {
            json!({ "vuln_id": f.vuln_id, "package": f.package, "software_name": f.software_name, "installed": f.installed,
                    "fixed": f.fixed, "product_id": f.product_id })
        })
        .collect();
    let mut tx = st.db.begin().await?;
    sqlx::query(
        "INSERT INTO vuln_findings (agent_id, vuln_id, package, software_name, installed_version, fixed_version, fix_available, product_id)
         SELECT $1, x.vuln_id, x.package, x.software_name, x.installed, x.fixed, x.fixed IS NOT NULL, x.product_id
           FROM jsonb_to_recordset($2) AS x(vuln_id text, package text, software_name text, installed text, fixed text, product_id uuid)
         ON CONFLICT (agent_id, vuln_id, package) DO UPDATE SET
                software_name = EXCLUDED.software_name, installed_version = EXCLUDED.installed_version,
                fixed_version = EXCLUDED.fixed_version, fix_available = EXCLUDED.fix_available, product_id = EXCLUDED.product_id,
                last_seen = now(), resolved_at = NULL,
                first_seen = CASE WHEN vuln_findings.resolved_at IS NULL THEN vuln_findings.first_seen ELSE now() END",
    )
    .bind(agent_id)
    .bind(Value::Array(rows))
    .execute(&mut *tx)
    .await?;
    let ids: Vec<&str> = findings.iter().map(|f| f.vuln_id.as_str()).collect();
    let pkgs: Vec<&str> = findings.iter().map(|f| f.package.as_str()).collect();
    sqlx::query(
        "UPDATE vuln_findings f SET resolved_at = now()
          WHERE f.agent_id = $1 AND f.resolved_at IS NULL
            AND NOT EXISTS (SELECT 1 FROM unnest($2::text[], $3::text[]) k(v, p) WHERE k.v = f.vuln_id AND k.p = f.package)",
    )
    .bind(agent_id)
    .bind(&ids)
    .bind(&pkgs)
    .execute(&mut *tx)
    .await?;
    tx.commit().await
}

/// Recounts open, unaccepted critical and high findings (one per CVE) on these agents.
pub async fn refresh_counts(db: &sqlx::PgPool, agents: &[Uuid]) -> sqlx::Result<()> {
    sqlx::query(
        "UPDATE agents a SET vuln_critical = c.crit, vuln_high = c.high
           FROM (SELECT x.id,
                        count(DISTINCT coalesce(v.cve, v.id)) FILTER (WHERE v.severity = 'critical') AS crit,
                        count(DISTINCT coalesce(v.cve, v.id)) FILTER (WHERE v.severity = 'high') AS high
                   FROM unnest($1::uuid[]) x(id)
                   LEFT JOIN vuln_findings f ON f.agent_id = x.id AND f.resolved_at IS NULL
                   LEFT JOIN vulns v ON v.id = f.vuln_id AND NOT vuln_accepted(f.agent_id, f.vuln_id, v.cve)
                  GROUP BY x.id) c
          WHERE a.id = c.id AND (a.vuln_critical, a.vuln_high) IS DISTINCT FROM (c.crit::int, c.high::int)",
    )
    .bind(agents)
    .execute(db)
    .await?;
    Ok(())
}

/// SQL rank of a severity column.
pub const RANK_SQL: &str = "(CASE {} WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END)";

pub fn rank_sql(col: &str) -> String {
    RANK_SQL.replace("{}", col)
}

/// The device's `vulnerability` alerts, from its stored findings (`alerts::vulns_changed`).
pub async fn check_alerts(st: &AppState, agent_id: Uuid) {
    let res: sqlx::Result<()> = async {
        for p in alerts::policies_for(st, agent_id, "vulnerability").await? {
            let Some(Rule::Vulnerability(r)) = p.rule() else { continue };
            #[allow(clippy::type_complexity)]
            let rows: Vec<(String, String, Option<f32>, Option<f32>, bool, String, String, Option<String>)> = sqlx::query_as(AssertSqlSafe(format!(
                "SELECT coalesce(v.cve, v.id), v.severity, v.cvss, v.epss, v.kev, f.package, f.installed_version, f.fixed_version
                   FROM vuln_findings f JOIN vulns v ON v.id = f.vuln_id
                  WHERE f.agent_id = $1 AND f.resolved_at IS NULL AND NOT vuln_accepted(f.agent_id, f.vuln_id, v.cve)
                    AND {rank} >= $2 AND (NOT $3 OR v.kev) AND (NOT $4 OR f.fix_available)
                    AND f.first_seen <= now() - make_interval(days => $5) AND ($6::real IS NULL OR coalesce(v.epss, 0) >= $6)
                  ORDER BY {rank} DESC, v.kev DESC, v.epss DESC NULLS LAST, v.cvss DESC NULLS LAST, 1",
                rank = rank_sql("v.severity")
            )))
            .bind(agent_id)
            .bind(super::severity_rank(&r.min_severity))
            .bind(r.kev_only)
            .bind(r.fix_available_only)
            .bind(r.older_than_days)
            .bind(r.min_epss.map(|e| e as f32))
            .fetch_all(&st.db)
            .await?;
            // One per CVE (an advisory can list several of the device's packages).
            let mut seen = std::collections::HashSet::new();
            let rows: Vec<_> = rows.into_iter().filter(|r| seen.insert(r.0.clone())).collect();
            if rows.is_empty() {
                alerts::clear(st, &p, agent_id, None, &[]).await?;
                continue;
            }
            let count = |s: &str| rows.iter().filter(|r| r.1 == s).count();
            let (crit, high) = (count("critical"), count("high"));
            let mut parts = vec![];
            if crit > 0 {
                parts.push(format!("{crit} critical"));
            }
            if high > 0 {
                parts.push(format!("{high} high"));
            }
            let n = rows.len();
            let title = format!(
                "{n} vulnerabilit{} to fix{}",
                if n == 1 { "y" } else { "ies" },
                if parts.is_empty() { String::new() } else { format!(" ({})", parts.join(", ")) }
            );
            let top: Vec<Value> = rows
                .iter()
                .take(5)
                .map(|(cve, sev, cvss, epss, kev, pkg, inst, fixed)| {
                    json!({ "cve": cve, "severity": sev, "cvss": cvss, "epss": epss, "kev": kev, "package": pkg, "installed": inst, "fixed": fixed })
                })
                .collect();
            let details = json!({
                "count": n, "critical": crit, "high": high, "kev": rows.iter().filter(|r| r.4).count(), "top": top,
            });
            alerts::fire(st, &p, agent_id, "", &title, details, 0).await?;
        }
        Ok(())
    }
    .await;
    if let Err(e) = res {
        warn!(%agent_id, "vulnerability alerts: {e}");
    }
}

/// An alert item changed: its devices' vulnerability alerts again.
pub async fn recheck_item(st: &AppState, item_id: Uuid) {
    let agents: Vec<Uuid> = sqlx::query_scalar(
        "SELECT DISTINCT agent_id FROM agent_policy WHERE item_id = $1 AND module = 'alert' AND enabled AND config ->> 'kind' = 'vulnerability'",
    )
    .bind(item_id)
    .fetch_all(&st.db)
    .await
    .unwrap_or_default();
    for a in agents {
        check_alerts(st, a).await;
    }
}

/// What only the clock changes: acceptances that expired, and findings that just became older
/// than an item's `older_than_days`.
pub async fn clock_tick(st: &AppState, last: chrono::DateTime<chrono::Utc>, now: chrono::DateTime<chrono::Utc>) -> sqlx::Result<()> {
    let mut agents: Vec<Uuid> = sqlx::query_scalar(
        "SELECT DISTINCT a.id FROM vuln_acceptances va JOIN sites s ON s.client_id = va.client_id JOIN agents a ON a.site_id = s.id
          WHERE va.expires_at > $1 AND va.expires_at <= $2 AND (va.agent_id IS NULL OR va.agent_id = a.id)",
    )
    .bind(last)
    .bind(now)
    .fetch_all(&st.db)
    .await?;
    if !agents.is_empty() {
        refresh_counts(&st.db, &agents).await?;
    }
    let days: Vec<i32> = sqlx::query_scalar(
        "SELECT DISTINCT coalesce((e.config -> 'params' ->> 'older_than_days')::int, 14)
           FROM policy_effective e JOIN policy_items i ON i.id = e.item_id
          WHERE i.module = 'alert' AND e.enabled AND e.config ->> 'kind' = 'vulnerability'",
    )
    .fetch_all(&st.db)
    .await?;
    for d in days.into_iter().filter(|d| *d > 0) {
        let more: Vec<Uuid> = sqlx::query_scalar(
            "SELECT DISTINCT agent_id FROM vuln_findings
              WHERE resolved_at IS NULL AND first_seen > $1 - make_interval(days => $3) AND first_seen <= $2 - make_interval(days => $3)",
        )
        .bind(last)
        .bind(now)
        .bind(d)
        .fetch_all(&st.db)
        .await?;
        agents.extend(more);
    }
    agents.sort();
    agents.dedup();
    for a in agents {
        check_alerts(st, a).await;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sw(name: &str, version: &str, source: &str, src: Option<&str>) -> Software {
        Software { name: name.into(), version: version.into(), publisher: None, source: source.into(), source_name: src.map(Into::into) }
    }

    fn cand(id: &str, pkg: &str, sev: &str, kev: bool, fixed: Option<&str>) -> Candidate {
        Candidate {
            vuln_id: id.into(),
            package: pkg.into(),
            severity: sev.into(),
            kev,
            range: Range { introduced: Some("0".into()), fixed: fixed.map(Into::into), ..Default::default() },
        }
    }

    #[test]
    fn debian_by_source_package() {
        let inv = [
            sw("libssl3", "3.0.11-1~deb12u2", "dpkg", Some("openssl")),
            sw("openssl", "3.0.11-1~deb12u2", "dpkg", None),
            sw("bash", "5.2.15-2+b2", "dpkg", None),
            sw("vim", "2:9.0.1378-2", "dpkg", None),
            sw("firefox", "120.0", "registry", None),
        ];
        let got = installed("Debian:12", &inv, &[]);
        let keys: Vec<&str> = got.iter().map(|i| i.key.as_str()).collect();
        assert_eq!(keys, ["bash", "openssl", "vim"], "by source package, dpkg only");
        let found = find(
            Scheme::Dpkg,
            &got,
            &[
                cand("DEBIAN-CVE-1", "openssl", "medium", false, Some("3.0.14-1~deb12u2")),
                cand("DEBIAN-CVE-2", "openssl", "medium", false, Some("3.0.11-1~deb12u2")),
                cand("DEBIAN-CVE-3", "bash", "low", false, None),
                cand("DEBIAN-CVE-4", "bash", "critical", false, None),
                cand("DEBIAN-CVE-5", "bash", "low", true, None),
                cand("DEBIAN-CVE-6", "vim", "high", false, Some("2:9.0.1378-2+deb12u1")),
                cand("DEBIAN-CVE-7", "curl", "critical", false, Some("9")),
            ],
        );
        let ids: Vec<&str> = found.iter().map(|f| f.vuln_id.as_str()).collect();
        // 2: fixed at the installed version. 3: low, unfixed, not exploited (the storage rule).
        assert_eq!(ids, ["DEBIAN-CVE-1", "DEBIAN-CVE-4", "DEBIAN-CVE-5", "DEBIAN-CVE-6"]);
        assert_eq!(found[0].software_name, "libssl3");
        assert_eq!(found[0].fixed.as_deref(), Some("3.0.14-1~deb12u2"));
        assert_eq!(found[1].fixed, None);
    }

    #[test]
    fn rpm_newest_install_counts_and_both_names() {
        let inv = [
            sw("kernel", "5.14.0-362.el9", "rpm", None),
            sw("kernel", "5.14.0-427.el9", "rpm", None),
            sw("openssl-libs", "1:3.0.7-27.el9", "rpm", Some("openssl")),
        ];
        let got = installed("Rocky Linux:9", &inv, &[]);
        let k = got.iter().find(|i| i.key == "kernel").unwrap();
        assert_eq!(k.version, "5.14.0-427.el9");
        assert!(got.iter().any(|i| i.key == "openssl") && got.iter().any(|i| i.key == "openssl-libs"));
        let found = find(
            Scheme::Rpm,
            &got,
            &[cand("RLSA-1", "kernel", "high", false, Some("5.14.0-400.el9")), cand("RLSA-2", "openssl-libs", "high", false, Some("1:3.0.7-28.el9"))],
        );
        assert_eq!(found.iter().map(|f| f.vuln_id.as_str()).collect::<Vec<_>>(), ["RLSA-2"], "the old kernel doesn't count");
    }

    #[test]
    fn windows_through_the_product_map() {
        let chrome = Product {
            id: Uuid::nil(),
            vendor: "google".into(),
            product: "chrome".into(),
            name_patterns: vec!["Google Chrome".into()],
            publisher_pattern: Some("Google*".into()),
        };
        let mut inv = vec![sw("Google Chrome", "127.0.6533.120", "registry", None), sw("Chrome Remote Desktop Host", "1.0", "registry", None)];
        inv[0].publisher = Some("Google LLC".into());
        let got = installed("Windows", &inv, std::slice::from_ref(&chrome));
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].key, "google:chrome");
        let found = find(Scheme::Dotted, &got, &[cand("CVE-2024-7971", "google:chrome", "high", false, Some("128.0.6613.84"))]);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].product_id, Some(Uuid::nil()));
        inv[0].publisher = Some("Someone Else".into());
        assert!(installed("Windows", &inv, &[chrome]).is_empty(), "the publisher pattern must match too");
    }

    #[test]
    fn most_specific_mapping_wins() {
        let p = |product: &str, pats: &[&str]| Product {
            id: Uuid::new_v4(),
            vendor: "mozilla".into(),
            product: product.into(),
            name_patterns: pats.iter().map(|s| s.to_string()).collect(),
            publisher_pattern: None,
        };
        let all = [p("firefox", &["Mozilla Firefox*"]), p("firefox_esr", &["Mozilla Firefox ESR*", "Mozilla Firefox * ESR*"])];
        assert_eq!(best_product(&all, "Mozilla Firefox (x64 en-US)", None).unwrap().product, "firefox");
        assert_eq!(best_product(&all, "Mozilla Firefox ESR (x64 en-US)", None).unwrap().product, "firefox_esr");
        assert_eq!(best_product(&all, "Mozilla Firefox 115.5.0 ESR (x64 en-US)", None).unwrap().product, "firefox_esr");
        assert!(best_product(&all, "Mozilla Maintenance Service", None).is_none());
    }

    #[test]
    fn storage_rule() {
        assert!(keep(true, "low", false));
        assert!(keep(false, "high", false));
        assert!(keep(false, "critical", false));
        assert!(keep(false, "low", true));
        assert!(!keep(false, "medium", false));
        assert!(!keep(false, "unknown", false));
    }
}
