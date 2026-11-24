//! NVD API 2.0 (`/rest/json/cves/2.0`), queried per mapped product with `virtualMatchString`.
//! Only the configuration nodes for that product count, and configurations that need another
//! platform than Windows (an `AND` with a non-Microsoft OS, a `target_sw` like `android`) are
//! left out.

use serde::Deserialize;
use serde_json::Value;

use super::osv::{Advisory, AffectedRange, clip, parse_time};
use super::version::Range;

#[derive(Deserialize)]
pub struct Page {
    #[serde(default, rename = "resultsPerPage")]
    pub results_per_page: i64,
    #[serde(default, rename = "startIndex")]
    pub start_index: i64,
    #[serde(default, rename = "totalResults")]
    pub total_results: i64,
    #[serde(default)]
    vulnerabilities: Vec<Item>,
}

#[derive(Deserialize)]
struct Item {
    cve: Cve,
}

#[derive(Deserialize)]
struct Cve {
    id: String,
    #[serde(default)]
    published: Option<String>,
    #[serde(default, rename = "lastModified")]
    last_modified: Option<String>,
    #[serde(default, rename = "vulnStatus")]
    status: Option<String>,
    #[serde(default)]
    descriptions: Vec<Description>,
    #[serde(default)]
    metrics: Value,
    #[serde(default)]
    configurations: Vec<Config>,
}

#[derive(Deserialize)]
struct Description {
    lang: String,
    value: String,
}

#[derive(Deserialize)]
struct Config {
    #[serde(default)]
    operator: Option<String>,
    #[serde(default)]
    nodes: Vec<Node>,
}

#[derive(Deserialize)]
struct Node {
    #[serde(default, rename = "cpeMatch")]
    cpe_match: Vec<CpeMatch>,
}

#[derive(Deserialize)]
struct CpeMatch {
    #[serde(default)]
    vulnerable: bool,
    criteria: String,
    #[serde(rename = "versionStartIncluding")]
    start_including: Option<String>,
    #[serde(rename = "versionStartExcluding")]
    start_excluding: Option<String>,
    #[serde(rename = "versionEndIncluding")]
    end_including: Option<String>,
    #[serde(rename = "versionEndExcluding")]
    end_excluding: Option<String>,
}

/// The fields of a CPE 2.3 formatted string (`\:` escapes are rare in vendor and product names
/// and are kept as written).
fn cpe_fields(c: &str) -> Vec<&str> {
    c.split(':').collect()
}

pub fn parse_page(json: &[u8]) -> anyhow::Result<Page> {
    Ok(serde_json::from_slice(json)?)
}

impl Page {
    /// The page's CVEs as advisories with ranges for `vendor:product` (ecosystem `NVD`).
    /// CVEs with no range for the product here (another platform, rejected) are dropped.
    pub fn advisories(&self, vendor: &str, product: &str) -> Vec<Advisory> {
        let key = format!("{vendor}:{product}");
        self.vulnerabilities
            .iter()
            .filter(|i| !i.cve.status.as_deref().is_some_and(|s| s.eq_ignore_ascii_case("rejected")))
            .filter_map(|i| {
                let c = &i.cve;
                let mut ranges = Vec::new();
                for cfg in &c.configurations {
                    let and = cfg.operator.as_deref().is_some_and(|o| o.eq_ignore_ascii_case("and"));
                    let other_platform = and
                        && cfg.nodes.iter().flat_map(|n| &n.cpe_match).any(|m| {
                            let f = cpe_fields(&m.criteria);
                            !m.vulnerable && f.get(2) == Some(&"o") && f.get(3).is_some_and(|v| !v.eq_ignore_ascii_case("microsoft"))
                        });
                    if other_platform {
                        continue;
                    }
                    for m in cfg.nodes.iter().flat_map(|n| &n.cpe_match).filter(|m| m.vulnerable) {
                        let f = cpe_fields(&m.criteria);
                        if f.len() < 6 || !f[3].eq_ignore_ascii_case(vendor) || !f[4].eq_ignore_ascii_case(product) {
                            continue;
                        }
                        if f.get(10).is_some_and(|t| !matches!(*t, "*" | "-" | "windows")) {
                            continue;
                        }
                        let exact = Some(f[5]).filter(|v| !matches!(*v, "*" | "-" | ""));
                        let range = match exact {
                            Some(v) if m.start_including.is_none() && m.start_excluding.is_none() && m.end_including.is_none() && m.end_excluding.is_none() => {
                                Range { introduced: Some(v.into()), last_affected: Some(v.into()), ..Default::default() }
                            }
                            _ => Range {
                                introduced: m.start_including.clone().or_else(|| m.start_excluding.clone()),
                                introduced_exclusive: m.start_including.is_none() && m.start_excluding.is_some(),
                                fixed: m.end_excluding.clone(),
                                last_affected: m.end_including.clone(),
                            },
                        };
                        ranges.push(AffectedRange { ecosystem: "NVD".into(), package: key.clone(), range });
                    }
                }
                if ranges.is_empty() {
                    return None;
                }
                let (cvss, vector, severity) = metrics(&c.metrics);
                let text = c.descriptions.iter().find(|d| d.lang == "en").map(|d| d.value.as_str()).unwrap_or_default();
                Some(Advisory {
                    id: c.id.clone(),
                    cve: Some(c.id.clone()),
                    summary: clip(text.split(". ").next().unwrap_or(text), 500),
                    details: clip(text, 8000),
                    severity,
                    cvss,
                    cvss_vector: vector,
                    published: parse_time(c.published.as_deref()),
                    modified: parse_time(c.last_modified.as_deref()),
                    url: Some(format!("https://nvd.nist.gov/vuln/detail/{}", c.id)),
                    ranges,
                    ..Default::default()
                })
            })
            .collect()
    }
}

/// The best CVSS base score: v3.1, v3.0, then v2 (primary source first).
fn metrics(m: &Value) -> (Option<f32>, Option<String>, String) {
    for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"] {
        let Some(list) = m.get(key).and_then(Value::as_array) else { continue };
        let pick = list.iter().find(|x| x.get("type").and_then(Value::as_str) == Some("Primary")).or_else(|| list.first());
        if let Some(x) = pick {
            let data = &x["cvssData"];
            let score = data.get("baseScore").and_then(Value::as_f64).map(|s| s as f32);
            let vector = data.get("vectorString").and_then(Value::as_str).map(str::to_string);
            if let Some(s) = score {
                return (Some(s), vector, super::severity_of_score(s).to_string());
            }
        }
    }
    (None, None, "unknown".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vuln::version::Scheme;

    #[test]
    fn chrome_page() {
        let json = std::fs::read(format!("{}/tests/fixtures/vuln/nvd-chrome.json", env!("CARGO_MANIFEST_DIR"))).unwrap();
        let page = parse_page(&json).unwrap();
        assert_eq!(page.total_results, 2);
        let all = page.advisories("google", "chrome");
        assert_eq!(all.len(), 2);
        let a = &all[0];
        assert_eq!((a.id.as_str(), a.severity.as_str(), a.cvss), ("CVE-2024-7971", "high", Some(8.8)));
        assert!(a.summary.starts_with("Type confusion in V8"));
        assert_eq!(a.ranges.len(), 1);
        assert!(a.ranges[0].range.contains(Scheme::Dotted, "127.0.6533.120"));
        assert!(!a.ranges[0].range.contains(Scheme::Dotted, "128.0.6613.84"));
        // The Android-only configuration and the iPhone target are dropped; the exact version stays.
        let b = &all[1];
        assert_eq!(b.ranges.len(), 1, "{:?}", b.ranges);
        assert_eq!(b.ranges[0].range.last_affected.as_deref(), Some("120.0.1"));
        assert_eq!(b.severity, "medium");
        assert!(page.advisories("mozilla", "firefox").len() == 1);
        assert!(page.advisories("videolan", "vlc_media_player").is_empty());
    }
}
