//! Vulnerabilities: advisories mirrored from the distributions, Arch, NVD, CISA KEV and EPSS,
//! matched against each device's software inventory (docs/design/vulnerabilities.md).
//!
//! - [`version`]: the comparers (dpkg, rpm, pacman, apk, dotted).
//! - [`feeds`]: daily sync of the feeds into Postgres, and `rmm-server vuln-import <dir>`.
//! - [`osv`], [`arch`], [`nvd`]: record parsing.
//! - [`matcher`]: one device's inventory against the ranges, into `vuln_findings`; the alert.
//!
//! Nothing about the fleet is sent anywhere: feeds are downloaded whole (NVD by product).

pub mod arch;
pub mod feeds;
pub mod matcher;
pub mod nvd;
pub mod osv;
pub mod version;
mod zip;

use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::state::AppState;
use version::Scheme;

/// Wakes the evaluation queue (an inventory changed, a sync finished, someone accepted a risk).
pub static WAKE: tokio::sync::Notify = tokio::sync::Notify::const_new();

/// Why a device isn't assessed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Unassessed {
    /// No inventory yet.
    NoInventory,
    /// The agent predates os-release reporting: update the agent.
    OldAgent,
    /// macOS, or a distribution without a feed here.
    UnsupportedOs,
}

impl Unassessed {
    pub fn as_str(self) -> &'static str {
        match self {
            Unassessed::NoInventory => "no_inventory",
            Unassessed::OldAgent => "old_agent",
            Unassessed::UnsupportedOs => "unsupported_os",
        }
    }
}

/// The ecosystem a device's operating system packages are matched in, from `/etc/os-release`
/// (`ID`, `VERSION_ID`). Arch and its derivatives are found by their package manager instead
/// (`has_pacman`); Windows applications by the curated product map (`Windows`).
pub fn ecosystem(os_family: &str, os_id: Option<&str>, version_id: Option<&str>, has_pacman: bool) -> Result<String, Unassessed> {
    match os_family {
        "windows" => return Ok("Windows".into()),
        "linux" => {}
        _ => return Err(Unassessed::UnsupportedOs),
    }
    if has_pacman {
        return Ok("Arch".into());
    }
    let Some(id) = os_id else { return Err(Unassessed::OldAgent) };
    let v = version_id.unwrap_or_default().trim();
    let major = v.split('.').next().unwrap_or_default();
    let need = |s: &str| if s.is_empty() { Err(Unassessed::UnsupportedOs) } else { Ok(()) };
    Ok(match id {
        "debian" => {
            need(major)?;
            format!("Debian:{major}")
        }
        "ubuntu" => {
            need(v)?;
            format!("Ubuntu:{v}")
        }
        "almalinux" => {
            need(major)?;
            format!("AlmaLinux:{major}")
        }
        "rocky" => {
            need(major)?;
            format!("Rocky Linux:{major}")
        }
        "rhel" => {
            need(major)?;
            format!("Red Hat:{major}")
        }
        "sles" | "sled" => {
            need(major)?;
            match v.split_once('.') {
                Some((m, sp)) if sp != "0" => format!("SUSE:Linux Enterprise Server {m} SP{sp}"),
                _ => format!("SUSE:Linux Enterprise Server {major}"),
            }
        }
        "opensuse-leap" => {
            need(v)?;
            format!("openSUSE:Leap {v}")
        }
        "opensuse-tumbleweed" => "openSUSE:Tumbleweed".into(),
        "alpine" => {
            let mut it = v.split('.');
            match (it.next(), it.next()) {
                (Some(a), Some(b)) if !a.is_empty() => format!("Alpine:v{a}.{b}"),
                _ => return Err(Unassessed::UnsupportedOs),
            }
        }
        "arch" | "archarm" | "manjaro" | "endeavouros" | "cachyos" | "garuda" => "Arch".into(),
        _ => return Err(Unassessed::UnsupportedOs),
    })
}

/// How versions in an ecosystem compare.
pub fn scheme(ecosystem: &str) -> Scheme {
    match ecosystem.split(':').next().unwrap_or_default() {
        "Debian" | "Ubuntu" => Scheme::Dpkg,
        "AlmaLinux" | "Rocky Linux" | "Red Hat" | "SUSE" | "openSUSE" => Scheme::Rpm,
        "Alpine" => Scheme::Apk,
        "Arch" => Scheme::Pacman,
        _ => Scheme::Dotted,
    }
}

/// The feed that covers an ecosystem.
pub fn feed_for(ecosystem: &str) -> String {
    match ecosystem {
        "Arch" => "arch".into(),
        "Windows" | "NVD" => "nvd".into(),
        e => format!("osv:{}", e.split(':').next().unwrap_or(e)),
    }
}

/// The package source an ecosystem's packages are listed under in the inventory.
pub fn inventory_source(ecosystem: &str) -> &'static str {
    match scheme(ecosystem) {
        Scheme::Dpkg => "dpkg",
        Scheme::Rpm => "rpm",
        Scheme::Apk => "apk",
        Scheme::Pacman => "pacman",
        Scheme::Dotted => "registry",
    }
}

/// OSV's ecosystem names as stored here: Ubuntu without the `:LTS` tag, Red Hat by major
/// release; Ubuntu Pro (ESM) and Red Hat EUS streams are left out (no entitlement awareness).
pub fn canonical_osv(eco: &str) -> Option<String> {
    let parts: Vec<&str> = eco.split(':').collect();
    match parts.first().copied()? {
        "Ubuntu" => {
            if parts.get(1) == Some(&"Pro") || parts.len() < 2 {
                return None;
            }
            Some(format!("Ubuntu:{}", parts[1]))
        }
        "Red Hat" => {
            if parts.get(1) != Some(&"enterprise_linux") {
                return None;
            }
            let major = parts.get(2)?.split('.').next()?;
            (!major.is_empty()).then(|| format!("Red Hat:{major}"))
        }
        _ => Some(eco.to_string()),
    }
}

/// Severity rank: higher is worse.
pub fn severity_rank(s: &str) -> i32 {
    match s {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

/// From a CVSS base score.
pub fn severity_of_score(score: f32) -> &'static str {
    match score {
        s if s >= 9.0 => "critical",
        s if s >= 7.0 => "high",
        s if s >= 4.0 => "medium",
        s if s > 0.0 => "low",
        _ => "none",
    }
}

/// A vendor's word for severity, normalised (Ubuntu priorities, Debian urgencies, Red Hat and
/// SUSE ratings, Arch's).
pub fn severity_of_word(w: &str) -> Option<&'static str> {
    Some(match w.trim().to_ascii_lowercase().as_str() {
        "critical" => "critical",
        "important" | "high" => "high",
        "moderate" | "medium" => "medium",
        "low" | "negligible" | "unimportant" => "low",
        _ => return None,
    })
}

/// A built-in Windows product mapping (`content/vuln/products.json`).
#[derive(Debug, Clone, Deserialize)]
pub struct ProductSeed {
    pub vendor: String,
    pub product: String,
    pub name: String,
    pub patterns: Vec<String>,
    #[serde(default)]
    pub publisher: Option<String>,
}

pub fn builtin_products() -> Vec<ProductSeed> {
    serde_json::from_str(include_str!("../../../../content/vuln/products.json")).unwrap_or_else(|e| {
        warn!("content/vuln/products.json: {e}");
        vec![]
    })
}

/// Adds built-in products that aren't there yet (hidden ones stay hidden; edited ones keep the
/// edits).
pub async fn seed_products(db: &sqlx::PgPool) -> sqlx::Result<u64> {
    let seeds = builtin_products();
    let mut added = 0;
    for p in &seeds {
        added += sqlx::query(
            "INSERT INTO vuln_products (vendor, product, name, name_patterns, publisher_pattern, builtin)
             VALUES ($1, $2, $3, $4, $5, true) ON CONFLICT (vendor, product) DO NOTHING",
        )
        .bind(&p.vendor)
        .bind(&p.product)
        .bind(&p.name)
        .bind(&p.patterns)
        .bind(&p.publisher)
        .execute(db)
        .await?
        .rows_affected();
    }
    Ok(added)
}

/// Case-insensitive glob: `*` matches any run of characters, everything else itself.
pub fn glob(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.to_lowercase().chars().collect();
    let t: Vec<char> = text.to_lowercase().chars().collect();
    let (mut pi, mut ti) = (0, 0);
    let (mut star, mut mark) = (None, 0);
    while ti < t.len() {
        if pi < p.len() && p[pi] != '*' && p[pi] == t[ti] {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = ti;
            pi += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

/// The background worker: seeds the product map, evaluates devices whose inventory changed
/// (a bounded queue in the database: `vuln_evaluated_at IS NULL`), re-checks alerts that only
/// the clock changes, and syncs the feeds daily.
pub async fn run(st: Arc<AppState>) {
    match seed_products(&st.db).await {
        Ok(n) if n > 0 => info!(products = n, "vulnerabilities: built-in product map seeded"),
        Ok(_) => {}
        Err(e) => warn!("vulnerabilities: seeding the product map: {e}"),
    }
    let st2 = st.clone();
    tokio::spawn(async move { feeds::daily(st2).await });
    let every = Duration::from_secs(st.cfg.alert_eval_secs.clamp(2, 60).into());
    let mut last_tick = chrono::Utc::now();
    let mut next_tick = tokio::time::Instant::now() + every;
    loop {
        // Evaluate in batches until the queue is empty.
        loop {
            match matcher::evaluate_queued(&st, 50).await {
                Ok(0) => break,
                Ok(_) => continue,
                Err(e) => {
                    warn!("vulnerabilities: evaluating devices: {e:#}");
                    break;
                }
            }
        }
        if tokio::time::Instant::now() >= next_tick {
            let now = chrono::Utc::now();
            if let Err(e) = matcher::clock_tick(&st, last_tick, now).await {
                warn!("vulnerabilities: time-based alert checks: {e}");
            }
            last_tick = now;
            next_tick = tokio::time::Instant::now() + every;
        }
        // Another process (`vuln-import`) may have queued work: look at least every 10 seconds.
        let _ = tokio::time::timeout_at(next_tick.min(tokio::time::Instant::now() + Duration::from_secs(10)), WAKE.notified()).await;
    }
}

/// An agent's inventory was stored: queue a re-evaluation when what matters for matching
/// changed (the OS ids and the software list).
pub async fn inventory_stored(st: &AppState, agent_id: uuid::Uuid, inv: &rmm_proto::Inventory) {
    let hash = inventory_hash(inv);
    let res = sqlx::query(
        "UPDATE agents SET vuln_inventory_hash = $2, vuln_evaluated_at = NULL
          WHERE id = $1 AND vuln_inventory_hash IS DISTINCT FROM $2",
    )
    .bind(agent_id)
    .bind(&hash)
    .execute(&st.db)
    .await;
    match res {
        Ok(r) if r.rows_affected() > 0 => WAKE.notify_one(),
        Ok(_) => {}
        Err(e) => warn!(%agent_id, "vulnerabilities: queueing the device: {e}"),
    }
}

pub fn inventory_hash(inv: &rmm_proto::Inventory) -> String {
    use sha2::{Digest, Sha256};
    let mut items: Vec<String> = inv
        .software
        .iter()
        .map(|s| format!("{}\u{1f}{}\u{1f}{}\u{1f}{}\u{1f}{}", s.source, s.name, s.version, s.source_name.as_deref().unwrap_or(""), s.publisher.as_deref().unwrap_or("")))
        .collect();
    items.sort();
    let mut h = Sha256::new();
    h.update(format!("{}\u{1e}{}\u{1e}{}\u{1e}", inv.system.os_family.as_str(), inv.system.os_id.as_deref().unwrap_or(""), inv.system.os_version_id.as_deref().unwrap_or("")));
    for i in items {
        h.update(i.as_bytes());
        h.update(b"\x1e");
    }
    hex::encode(h.finalize())
}

/// Queues these agents (all when None) for re-evaluation.
pub async fn requeue(db: &sqlx::PgPool, ecosystems: Option<&[String]>) -> sqlx::Result<u64> {
    let n = sqlx::query("UPDATE agents SET vuln_evaluated_at = NULL WHERE inventory IS NOT NULL AND ($1::text[] IS NULL OR vuln_ecosystem = ANY($1))")
        .bind(ecosystems)
        .execute(db)
        .await?
        .rows_affected();
    WAKE.notify_one();
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ecosystems_from_os_release() {
        let e = |id: &str, v: &str| ecosystem("linux", Some(id), Some(v), false);
        assert_eq!(e("debian", "12").as_deref(), Ok("Debian:12"));
        assert_eq!(e("ubuntu", "24.04").as_deref(), Ok("Ubuntu:24.04"));
        assert_eq!(e("rocky", "9.3").as_deref(), Ok("Rocky Linux:9"));
        assert_eq!(e("almalinux", "8.10").as_deref(), Ok("AlmaLinux:8"));
        assert_eq!(e("rhel", "9.4").as_deref(), Ok("Red Hat:9"));
        assert_eq!(e("sles", "15.5").as_deref(), Ok("SUSE:Linux Enterprise Server 15 SP5"));
        assert_eq!(e("sles", "15").as_deref(), Ok("SUSE:Linux Enterprise Server 15"));
        assert_eq!(e("opensuse-leap", "15.5").as_deref(), Ok("openSUSE:Leap 15.5"));
        assert_eq!(e("opensuse-tumbleweed", "20241120").as_deref(), Ok("openSUSE:Tumbleweed"));
        assert_eq!(e("alpine", "3.19.1").as_deref(), Ok("Alpine:v3.19"));
        assert_eq!(e("debian", ""), Err(Unassessed::UnsupportedOs), "sid has no VERSION_ID");
        assert_eq!(e("gentoo", "2.15"), Err(Unassessed::UnsupportedOs));
        assert_eq!(ecosystem("linux", Some("cachyos"), None, true).as_deref(), Ok("Arch"), "pacman decides");
        assert_eq!(ecosystem("linux", None, None, false), Err(Unassessed::OldAgent));
        assert_eq!(ecosystem("windows", None, None, false).as_deref(), Ok("Windows"));
        assert_eq!(ecosystem("macos", None, None, false), Err(Unassessed::UnsupportedOs));
    }

    #[test]
    fn osv_ecosystem_names() {
        assert_eq!(canonical_osv("Ubuntu:22.04:LTS").as_deref(), Some("Ubuntu:22.04"));
        assert_eq!(canonical_osv("Ubuntu:24.10").as_deref(), Some("Ubuntu:24.10"));
        assert_eq!(canonical_osv("Ubuntu:Pro:18.04:LTS"), None);
        assert_eq!(canonical_osv("Red Hat:enterprise_linux:9::appstream").as_deref(), Some("Red Hat:9"));
        assert_eq!(canonical_osv("Red Hat:rhel_eus:9.2::baseos"), None);
        assert_eq!(canonical_osv("Debian:12").as_deref(), Some("Debian:12"));
        assert_eq!(feed_for("Rocky Linux:9"), "osv:Rocky Linux");
        assert_eq!(feed_for("Arch"), "arch");
        assert_eq!(scheme("openSUSE:Leap 15.5"), Scheme::Rpm);
        assert_eq!(inventory_source("Ubuntu:24.04"), "dpkg");
    }

    #[test]
    fn globs_and_seed() {
        assert!(glob("Google Chrome", "google chrome"));
        assert!(glob("Mozilla Firefox*", "Mozilla Firefox (x64 en-US)"));
        assert!(glob("*7-Zip*", "7-Zip 23.01 (x64)"));
        assert!(!glob("Mozilla Firefox*", "Mozilla Thunderbird"));
        assert!(glob("a*b*c", "aXXbYYc") && !glob("a*b*c", "aXXbYY"));
        let seeds = builtin_products();
        assert!(seeds.len() >= 100, "{} built-in products", seeds.len());
        let mut keys = std::collections::HashSet::new();
        for p in &seeds {
            assert!(keys.insert((p.vendor.clone(), p.product.clone())), "duplicate {}:{}", p.vendor, p.product);
            assert!(!p.patterns.is_empty() && !p.name.is_empty(), "{}:{}", p.vendor, p.product);
            assert!(!p.vendor.contains(':') && !p.product.contains(':'), "{}:{}", p.vendor, p.product);
        }
    }

    #[test]
    fn severities() {
        assert_eq!(severity_of_score(9.8), "critical");
        assert_eq!(severity_of_score(7.0), "high");
        assert_eq!(severity_of_score(0.0), "none");
        assert_eq!(severity_of_word("Important"), Some("high"));
        assert_eq!(severity_of_word("negligible"), Some("low"));
        assert_eq!(severity_of_word("not yet assigned"), None);
    }
}
