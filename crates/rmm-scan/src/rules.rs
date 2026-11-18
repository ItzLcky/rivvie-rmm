//! YARA rules (with the `yara` feature: boreal, a pure-Rust YARA engine without a JIT) and
//! how a rule's metadata becomes an id, severity, confidence and mode.
//!
//! First-party rules state those in `meta:` (`id`, `name`, `severity`, `confidence`, `mode`,
//! `mitre`). Imported rules usually don't: they get `YARA:<namespace>:<rule>` as id, severity
//! from `severity` or YARA Forge's `score`, and run in audit mode like every new rule.
//!
//! The database keeps the source as one text, split into namespaces by marker lines
//! (`// rmm-namespace: <name>`), so rules from different feeds can share a name.

use rmm_content::Confidence;
use rmm_proto::security::{RuleMode, ThreatSeverity};

pub const NAMESPACE_MARKER: &str = "// rmm-namespace: ";

#[derive(Debug, Clone, PartialEq)]
pub struct RuleMeta {
    pub id: String,
    pub name: String,
    pub severity: ThreatSeverity,
    pub confidence: Confidence,
    pub mode: RuleMode,
    pub mitre: Vec<String>,
    pub description: String,
    pub author: Option<String>,
    pub reference: Option<String>,
    pub licence: Option<String>,
}

pub fn severity(s: &str) -> Option<ThreatSeverity> {
    Some(match s.trim().to_ascii_lowercase().as_str() {
        "severe" | "critical" => ThreatSeverity::Severe,
        "high" => ThreatSeverity::High,
        "medium" | "moderate" => ThreatSeverity::Moderate,
        "low" | "info" | "informational" => ThreatSeverity::Low,
        _ => return None,
    })
}

/// Builds a rule's meta from its `meta:` values (name -> text or integer).
pub fn rule_meta(namespace: &str, rule: &str, get: impl Fn(&str) -> Option<String>) -> RuleMeta {
    let id = get("id").filter(|s| !s.trim().is_empty()).unwrap_or_else(|| {
        if namespace.is_empty() || namespace == "default" { format!("YARA:{rule}") } else { format!("YARA:{namespace}:{rule}") }
    });
    let sev = get("severity").and_then(|s| severity(&s)).or_else(|| {
        get("score").and_then(|s| s.trim().parse::<i64>().ok()).map(|n| match n {
            80.. => ThreatSeverity::High,
            60..=79 => ThreatSeverity::Moderate,
            _ => ThreatSeverity::Low,
        })
    });
    let confidence = match get("confidence").map(|c| c.to_ascii_lowercase()).as_deref() {
        Some("high") => Confidence::High,
        Some("low") => Confidence::Low,
        _ => Confidence::Medium,
    };
    let mode = get("mode").and_then(|m| RuleMode::parse(m.trim())).unwrap_or(RuleMode::Audit);
    let mitre = get("mitre")
        .or_else(|| get("mitre_attack"))
        .or_else(|| get("mitre_att"))
        .map(|m| m.split([',', ' ']).map(str::trim).filter(|s| !s.is_empty()).map(str::to_string).collect())
        .unwrap_or_default();
    RuleMeta {
        id,
        name: get("name").filter(|s| !s.trim().is_empty()).unwrap_or_else(|| rule.replace('_', " ")),
        severity: sev.unwrap_or(ThreatSeverity::Moderate),
        confidence,
        mode,
        mitre,
        description: get("description").unwrap_or_default(),
        author: get("author"),
        reference: get("reference"),
        licence: get("license").or_else(|| get("licence")),
    }
}

/// Splits the database's YARA text into (namespace, source) by the marker lines.
pub fn namespaces(source: &str) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    let mut ns = String::from("default");
    let mut cur = String::new();
    for line in source.split_inclusive('\n') {
        if let Some(n) = line.strip_prefix(NAMESPACE_MARKER) {
            if !cur.trim().is_empty() {
                out.push((ns.clone(), std::mem::take(&mut cur)));
            }
            cur.clear();
            ns = n.trim().to_string();
        } else {
            cur.push_str(line);
        }
    }
    if !cur.trim().is_empty() {
        out.push((ns, cur));
    }
    out
}

#[cfg(feature = "yara")]
pub use engine::Rules;

#[cfg(feature = "yara")]
mod engine {
    use std::collections::HashMap;
    use std::time::Duration;

    use boreal::MetadataValue;
    use boreal::scanner::ScanParams;

    use super::*;

    pub struct Rules {
        scanner: boreal::Scanner,
        meta: HashMap<(String, String), RuleMeta>,
        count: usize,
    }

    impl Rules {
        /// Compiles (namespace, source) pairs. Includes are refused: a database is one file.
        pub fn compile(sources: &[(String, String)], timeout: Duration) -> Result<Rules, String> {
            let mut c = boreal::Compiler::new();
            c.set_include_callback(|name, _, _| Err(std::io::Error::other(format!("include \"{name}\": includes aren't allowed in a signature database"))));
            for (ns, src) in sources {
                c.add_rules_str_in_namespace(src, ns).map_err(|e| {
                    let d = e.to_diagnostic();
                    boreal::compiler::generate_description(&d, ns, src).lines().take(6).collect::<Vec<_>>().join("\n")
                })?;
            }
            let mut scanner = c.finalize();
            scanner.set_scan_params(ScanParams::default().timeout_duration(Some(timeout)).string_max_nb_matches(1000).compute_full_matches(false));
            let mut meta = HashMap::new();
            let mut count = 0;
            for r in scanner.rules() {
                count += 1;
                if r.is_private {
                    continue;
                }
                let get = |name: &str| {
                    r.metadatas.iter().find(|m| scanner.get_string_symbol(m.name) == name).map(|m| match &m.value {
                        MetadataValue::Bytes(b) => String::from_utf8_lossy(scanner.get_bytes_symbol(*b)).into_owned(),
                        MetadataValue::Integer(i) => i.to_string(),
                        MetadataValue::Boolean(b) => b.to_string(),
                    })
                };
                meta.insert((r.namespace.to_string(), r.name.to_string()), rule_meta(r.namespace, r.name, get));
            }
            Ok(Rules { scanner, meta, count })
        }

        pub fn len(&self) -> usize {
            self.count
        }

        pub fn is_empty(&self) -> bool {
            self.count == 0
        }

        pub fn all(&self) -> impl Iterator<Item = &RuleMeta> {
            self.meta.values()
        }

        /// The rules that match. A timeout keeps what matched before it.
        pub fn scan(&self, data: &[u8]) -> Vec<&RuleMeta> {
            let r = match self.scanner.scan_mem(data) {
                Ok(r) => r,
                Err((_, r)) => r,
            };
            r.rules.iter().filter_map(|m| self.meta.get(&(m.namespace.to_string(), m.name.to_string()))).collect()
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn compile_scan_and_meta() {
            let src = format!(
                "{NAMESPACE_MARKER}rmm\nrule A {{ meta: id = \"RMM-Y-1\" severity = \"high\" confidence = \"high\" mode = \"alert\" mitre = \"T1059, T1027\"\n strings: $a = \"evil\" condition: $a }}\n\
                 {NAMESPACE_MARKER}forge\nrule A {{ meta: score = 75 author = \"x\" license = \"DRL 1.1\" strings: $a = {{ 4d 5a }} condition: $a at 0 }}\n\
                 rule P : private_tag {{ condition: uint16(0) == 0x5a4d and filesize < 10 }}\n"
            );
            let r = Rules::compile(&namespaces(&src), Duration::from_secs(5)).unwrap();
            assert_eq!(r.len(), 3);
            let hits: Vec<&str> = r.scan(b"so evil").iter().map(|m| m.id.as_str()).collect();
            assert_eq!(hits, ["RMM-Y-1"]);
            let a = r.scan(b"so evil")[0].clone();
            assert_eq!((a.severity, a.confidence, a.mode, a.mitre.clone()), (ThreatSeverity::High, Confidence::High, RuleMode::Alert, vec!["T1059".to_string(), "T1027".into()]));
            let mut ids: Vec<String> = r.scan(b"MZ evil").iter().map(|m| m.id.clone()).collect();
            ids.sort();
            assert_eq!(ids, ["RMM-Y-1", "YARA:forge:A", "YARA:forge:P"], "same rule name in two namespaces");
            let f = r.all().find(|m| m.id == "YARA:forge:A").unwrap();
            assert_eq!((f.severity, f.mode, f.licence.as_deref()), (ThreatSeverity::Moderate, RuleMode::Audit, Some("DRL 1.1")), "imported rules start in audit");
            assert!(Rules::compile(&[("x".into(), "include \"/etc/passwd\"".into())], Duration::from_secs(1)).is_err());
            assert!(Rules::compile(&[("x".into(), "rule { broken".into())], Duration::from_secs(1)).is_err());
        }
    }
}
