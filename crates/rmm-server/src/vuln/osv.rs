//! OSV records (<https://ossf.github.io/osv-schema/>), as the distributions publish them, and the
//! [`Advisory`] every feed is parsed into. Also CVSS v3 base scores from vectors (OSV gives
//! vectors, not scores).

use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::Value;

use super::version::Range;

/// One advisory, whatever the feed, ready to store.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Advisory {
    pub id: String,
    pub aliases: Vec<String>,
    pub cve: Option<String>,
    pub summary: String,
    pub details: String,
    /// critical, high, medium, low, none or unknown.
    pub severity: String,
    pub cvss: Option<f32>,
    pub cvss_vector: Option<String>,
    pub published: Option<DateTime<Utc>>,
    pub modified: Option<DateTime<Utc>>,
    pub url: Option<String>,
    pub ranges: Vec<AffectedRange>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AffectedRange {
    pub ecosystem: String,
    pub package: String,
    pub range: Range,
}

/// Summaries and details are shown, not searched in depth: keep them bounded.
pub fn clip(s: &str, max: usize) -> String {
    let s = s.trim();
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &s[..end])
}

#[derive(Deserialize)]
struct Record {
    id: String,
    #[serde(default)]
    aliases: Vec<String>,
    #[serde(default)]
    upstream: Vec<String>,
    #[serde(default)]
    related: Vec<String>,
    #[serde(default)]
    summary: String,
    #[serde(default)]
    details: String,
    #[serde(default)]
    severity: Vec<Severity>,
    #[serde(default)]
    published: Option<String>,
    #[serde(default)]
    modified: Option<String>,
    #[serde(default)]
    withdrawn: Option<String>,
    #[serde(default)]
    affected: Vec<Affected>,
    #[serde(default)]
    references: Vec<Reference>,
    #[serde(default)]
    database_specific: Option<Value>,
}

#[derive(Deserialize)]
struct Severity {
    #[serde(rename = "type")]
    kind: String,
    score: String,
}

#[derive(Deserialize)]
struct Reference {
    #[serde(rename = "type", default)]
    kind: String,
    url: String,
}

#[derive(Deserialize)]
struct Affected {
    #[serde(default)]
    package: Option<Package>,
    #[serde(default)]
    ranges: Vec<OsvRange>,
    #[serde(default)]
    severity: Vec<Severity>,
    #[serde(default)]
    ecosystem_specific: Option<Value>,
    #[serde(default)]
    database_specific: Option<Value>,
}

#[derive(Deserialize)]
struct Package {
    ecosystem: String,
    name: String,
}

#[derive(Deserialize)]
struct OsvRange {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    events: Vec<serde_json::Map<String, Value>>,
}

pub fn parse_time(s: Option<&str>) -> Option<DateTime<Utc>> {
    let s = s?.trim();
    DateTime::parse_from_rfc3339(s)
        .map(|t| t.with_timezone(&Utc))
        .or_else(|_| chrono::NaiveDateTime::parse_from_str(s.trim_end_matches('Z'), "%Y-%m-%dT%H:%M:%S%.f").map(|t| t.and_utc()))
        .ok()
}

/// A word from a vendor-specific field (`severity`, `urgency`, `priority`).
fn word_in(v: Option<&Value>) -> Option<&'static str> {
    let v = v?;
    ["severity", "urgency", "priority"].iter().find_map(|k| v.get(k).and_then(Value::as_str).and_then(super::severity_of_word))
}

/// Parses one OSV record. `None` for records to skip: withdrawn, or affecting none of the
/// ecosystems kept (Ubuntu Pro, Red Hat EUS). The id is namespaced when it is a bare CVE id
/// (Alpine's), so it can't collide with NVD's record of the same CVE.
pub fn parse(json: &[u8], feed: &str) -> anyhow::Result<Option<Advisory>> {
    let r: Record = serde_json::from_slice(json)?;
    if r.withdrawn.is_some() {
        return Ok(None);
    }
    let mut ranges = Vec::new();
    let mut words: Vec<&'static str> = Vec::new();
    let mut vectors: Vec<String> = r.severity.iter().filter(|s| s.kind.starts_with("CVSS_V3")).map(|s| s.score.clone()).collect();
    for s in &r.severity {
        if s.kind == "Ubuntu"
            && let Some(w) = super::severity_of_word(&s.score)
        {
            words.push(w);
        }
    }
    for a in &r.affected {
        let Some(p) = &a.package else { continue };
        let Some(eco) = super::canonical_osv(&p.ecosystem) else { continue };
        vectors.extend(a.severity.iter().filter(|s| s.kind.starts_with("CVSS_V3")).map(|s| s.score.clone()));
        words.extend(word_in(a.ecosystem_specific.as_ref()));
        words.extend(word_in(a.database_specific.as_ref()));
        for range in a.ranges.iter().filter(|r| r.kind == "ECOSYSTEM") {
            let mut cur: Option<Range> = None;
            for ev in &range.events {
                let get = |k: &str| ev.get(k).and_then(Value::as_str).map(str::to_string);
                if let Some(i) = get("introduced") {
                    if let Some(open) = cur.take() {
                        ranges.push(AffectedRange { ecosystem: eco.clone(), package: p.name.clone(), range: open });
                    }
                    cur = Some(Range { introduced: Some(i), ..Default::default() });
                } else if let Some(f) = get("fixed") {
                    let mut c = cur.take().unwrap_or_default();
                    c.fixed = Some(f);
                    ranges.push(AffectedRange { ecosystem: eco.clone(), package: p.name.clone(), range: c });
                } else if let Some(l) = get("last_affected") {
                    let mut c = cur.take().unwrap_or_default();
                    c.last_affected = Some(l);
                    ranges.push(AffectedRange { ecosystem: eco.clone(), package: p.name.clone(), range: c });
                }
            }
            if let Some(open) = cur {
                ranges.push(AffectedRange { ecosystem: eco.clone(), package: p.name.clone(), range: open });
            }
        }
    }
    if ranges.is_empty() {
        return Ok(None);
    }
    words.extend(word_in(r.database_specific.as_ref()));
    let best = vectors.iter().filter_map(|v| cvss3_score(v).map(|s| (s, v))).max_by(|a, b| a.0.total_cmp(&b.0));
    let severity = match (best, words.iter().max_by_key(|w| super::severity_rank(w))) {
        (Some((s, _)), _) => super::severity_of_score(s),
        (None, Some(w)) => w,
        (None, None) => "unknown",
    };
    let cve = std::iter::once(&r.id)
        .chain(&r.aliases)
        .chain(&r.upstream)
        .chain(&r.related)
        .map(|s| s.strip_prefix("DEBIAN-").or_else(|| s.strip_prefix("UBUNTU-")).or_else(|| s.strip_prefix("ALPINE-")).unwrap_or(s))
        .find(|s| s.starts_with("CVE-"))
        .map(str::to_string);
    let id = if r.id.starts_with("CVE-") || r.id.starts_with("GHSA-") {
        format!("{}-{}", feed.trim_start_matches("osv:").to_ascii_uppercase().replace(' ', "_"), r.id)
    } else {
        r.id.clone()
    };
    let mut aliases: Vec<String> = r.aliases.iter().chain(&r.upstream).cloned().collect();
    aliases.sort();
    aliases.dedup();
    aliases.truncate(50);
    let url = r.references.iter().find(|x| x.kind == "ADVISORY").or_else(|| r.references.first()).map(|x| x.url.clone());
    Ok(Some(Advisory {
        id,
        aliases,
        cve,
        summary: clip(if r.summary.is_empty() { r.details.lines().next().unwrap_or_default() } else { &r.summary }, 500),
        details: clip(&r.details, 8000),
        severity: severity.to_string(),
        cvss: best.map(|b| b.0),
        cvss_vector: best.map(|b| b.1.clone()),
        published: parse_time(r.published.as_deref()),
        modified: parse_time(r.modified.as_deref()),
        url,
        ranges,
    }))
}

/// CVSS v3.0/v3.1 base score from a vector (`CVSS:3.1/AV:N/AC:L/...`), per the specification's
/// formulas and its Roundup.
pub fn cvss3_score(vector: &str) -> Option<f32> {
    let mut m = std::collections::HashMap::new();
    let mut parts = vector.trim().split('/');
    if !parts.next()?.starts_with("CVSS:3") {
        return None;
    }
    for p in parts {
        let (k, v) = p.split_once(':')?;
        m.insert(k, v);
    }
    let scope_changed = match *m.get("S")? {
        "U" => false,
        "C" => true,
        _ => return None,
    };
    let av = match *m.get("AV")? {
        "N" => 0.85,
        "A" => 0.62,
        "L" => 0.55,
        "P" => 0.2,
        _ => return None,
    };
    let ac = match *m.get("AC")? {
        "L" => 0.77,
        "H" => 0.44,
        _ => return None,
    };
    let pr = match (*m.get("PR")?, scope_changed) {
        ("N", _) => 0.85,
        ("L", false) => 0.62,
        ("L", true) => 0.68,
        ("H", false) => 0.27,
        ("H", true) => 0.5,
        _ => return None,
    };
    let ui = match *m.get("UI")? {
        "N" => 0.85,
        "R" => 0.62,
        _ => return None,
    };
    let cia = |k: &str| -> Option<f64> {
        Some(match *m.get(k)? {
            "H" => 0.56,
            "L" => 0.22,
            "N" => 0.0,
            _ => return None,
        })
    };
    let (c, i, a) = (cia("C")?, cia("I")?, cia("A")?);
    let iss = 1.0 - (1.0 - c) * (1.0 - i) * (1.0 - a);
    let impact = if scope_changed { 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02f64).powi(15) } else { 6.42 * iss };
    let exploitability = 8.22 * av * ac * pr * ui;
    if impact <= 0.0 {
        return Some(0.0);
    }
    let raw = if scope_changed { (1.08 * (impact + exploitability)).min(10.0) } else { (impact + exploitability).min(10.0) };
    Some(roundup(raw) as f32)
}

fn roundup(x: f64) -> f64 {
    let int = (x * 100_000.0).round() as i64;
    if int % 10_000 == 0 { int as f64 / 100_000.0 } else { ((int / 10_000) + 1) as f64 / 10.0 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cvss_vectors() {
        let s = |v| cvss3_score(v).unwrap();
        assert_eq!(s("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), 9.8);
        assert_eq!(s("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"), 10.0);
        assert_eq!(s("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"), 7.8);
        assert_eq!(s("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"), 6.1);
        assert_eq!(s("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N"), 5.9);
        assert_eq!(s("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"), 0.0);
        assert_eq!(cvss3_score("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"), None);
        assert_eq!(cvss3_score("CVSS:3.1/AV:X"), None);
    }

    fn fixture(name: &str) -> Vec<u8> {
        std::fs::read(format!("{}/tests/fixtures/vuln/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap()
    }

    #[test]
    fn debian_record() {
        let a = parse(&fixture("osv-debian.json"), "osv:Debian").unwrap().unwrap();
        assert_eq!(a.id, "DEBIAN-CVE-2024-6119");
        assert_eq!(a.cve.as_deref(), Some("CVE-2024-6119"));
        assert_eq!(a.ranges.len(), 2, "{:?}", a.ranges);
        assert_eq!((a.ranges[0].ecosystem.as_str(), a.ranges[0].package.as_str()), ("Debian:12", "openssl"));
        assert_eq!(a.ranges[0].range.fixed.as_deref(), Some("3.0.14-1~deb12u2"));
        assert_eq!(a.ranges[1].ecosystem, "Debian:13");
        assert_eq!(a.severity, "medium", "Debian's urgency, there being no vector");
    }

    #[test]
    fn ubuntu_record() {
        let a = parse(&fixture("osv-ubuntu.json"), "osv:Ubuntu").unwrap().unwrap();
        assert_eq!(a.cve.as_deref(), Some("CVE-2024-3094"));
        let ecos: Vec<&str> = a.ranges.iter().map(|r| r.ecosystem.as_str()).collect();
        assert_eq!(ecos, ["Ubuntu:24.04"], "Pro streams are skipped, LTS tags dropped");
        assert_eq!(a.severity, "critical");
        assert_eq!(a.cvss, Some(10.0));
        assert!(a.ranges[0].range.fixed.is_none() && a.ranges[0].range.introduced.as_deref() == Some("0"));
    }

    #[test]
    fn rpm_record_with_two_ranges() {
        let a = parse(&fixture("osv-rocky.json"), "osv:Rocky Linux").unwrap().unwrap();
        assert_eq!(a.id, "RLSA-2024:1234");
        assert_eq!(a.severity, "high");
        assert_eq!(a.ranges.len(), 2);
        assert_eq!(a.ranges[1].range.introduced.as_deref(), Some("1:3.1.0-1.el9"));
        assert_eq!(a.ranges[1].range.last_affected.as_deref(), Some("1:3.1.1-2.el9"));
    }

    #[test]
    fn alpine_ids_are_namespaced_and_withdrawn_records_skipped() {
        let rec = br#"{"id":"CVE-2023-0001","affected":[{"package":{"ecosystem":"Alpine:v3.19","name":"musl"},
            "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1.2.4-r3"}]}]}]}"#;
        let a = parse(rec, "osv:Alpine").unwrap().unwrap();
        assert_eq!((a.id.as_str(), a.cve.as_deref()), ("ALPINE-CVE-2023-0001", Some("CVE-2023-0001")));
        let gone = br#"{"id":"X-1","withdrawn":"2024-01-01T00:00:00Z","affected":[]}"#;
        assert!(parse(gone, "osv:Debian").unwrap().is_none());
        assert!(parse(b"{nope", "osv:Debian").is_err());
    }
}
