//! The effective policy inside the sensor: exclusions, and the mode each rule runs in.

use std::collections::{HashMap, HashSet};

use rmm_content::Confidence;
use rmm_proto::security::{ExclusionKind, RuleMode, SensorPolicy};
use rmm_proto::telemetry::Proc;

/// `*` matches any run of characters; case-insensitive (paths on Windows and macOS are).
pub fn glob(pattern: &str, s: &str) -> bool {
    fn m(p: &[u8], s: &[u8]) -> bool {
        match (p.first(), s.first()) {
            (None, None) => true,
            (Some(b'*'), _) => m(&p[1..], s) || (!s.is_empty() && m(p, &s[1..])),
            (Some(a), Some(b)) if a.eq_ignore_ascii_case(b) => m(&p[1..], &s[1..]),
            _ => false,
        }
    }
    m(pattern.as_bytes(), s.as_bytes())
}

#[derive(Debug, Clone, Default)]
pub struct Exclusions {
    paths: Vec<String>,
    hashes: HashSet<String>,
    rules: HashSet<String>,
    processes: Vec<String>,
}

fn path_match(pattern: &str, path: &str) -> bool {
    // Windows takes either separator; compare them as one.
    let norm = |s: &str| if cfg!(windows) { s.replace('/', "\\") } else { s.to_string() };
    let (pattern, path) = (norm(pattern), norm(path));
    let (pattern, path) = (pattern.as_str(), path.as_str());
    if pattern.contains('*') {
        glob(pattern, path)
    } else {
        let (p, s) = (pattern.to_ascii_lowercase(), path.to_ascii_lowercase());
        s == p || (s.starts_with(&p) && (p.ends_with(['/', '\\']) || s[p.len()..].starts_with(['/', '\\'])))
    }
}

impl Exclusions {
    pub fn from_policy(p: &SensorPolicy) -> Self {
        let mut e = Exclusions::default();
        for x in &p.exclusions {
            let v = x.value.trim().to_string();
            if v.is_empty() {
                continue;
            }
            match x.kind {
                ExclusionKind::Path => e.paths.push(v),
                ExclusionKind::Sha256 => {
                    e.hashes.insert(v.to_ascii_lowercase());
                }
                ExclusionKind::Rule => {
                    e.rules.insert(v);
                }
                ExclusionKind::Process => e.processes.push(v),
            }
        }
        e
    }

    pub fn path(&self, path: &str) -> bool {
        self.paths.iter().any(|p| path_match(p, path))
    }

    pub fn hash(&self, sha256: &str) -> bool {
        self.hashes.contains(&sha256.to_ascii_lowercase())
    }

    pub fn rule(&self, id: &str) -> bool {
        self.rules.contains(id)
    }

    /// By image path (prefix or glob) or bare name.
    pub fn process(&self, p: &Proc) -> bool {
        self.processes.iter().any(|x| {
            let name_only = !x.contains(['/', '\\']);
            if name_only {
                glob(x, &p.name) || x.eq_ignore_ascii_case(p.name.trim_end_matches(".exe"))
            } else {
                p.exe.as_deref().is_some_and(|e| path_match(x, e))
            }
        })
    }
}

/// The mode a rule actually runs in: the server's override, else the bundle's; never `Block`
/// unless prevention is on and the rule is high-confidence; `Disabled` if excluded.
pub fn effective_mode(policy: &SensorPolicy, overrides: &HashMap<String, RuleMode>, excl: &Exclusions, id: &str, bundle_mode: RuleMode, confidence: Confidence) -> RuleMode {
    if excl.rule(id) {
        return RuleMode::Disabled;
    }
    let m = overrides.get(id).copied().unwrap_or(bundle_mode);
    if m == RuleMode::Block && !(policy.prevention && confidence == Confidence::High) {
        return RuleMode::Alert;
    }
    m
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmm_proto::security::Exclusion;

    #[test]
    fn exclusions_match() {
        let p = SensorPolicy {
            exclusions: vec![
                Exclusion { kind: ExclusionKind::Path, value: "/srv/backups".into() },
                Exclusion { kind: ExclusionKind::Path, value: "C:\\Users\\*\\AppData\\Local\\Vendor\\*".into() },
                Exclusion { kind: ExclusionKind::Sha256, value: "AB".repeat(32) },
                Exclusion { kind: ExclusionKind::Rule, value: "RMM-B-0018".into() },
                Exclusion { kind: ExclusionKind::Process, value: "backup-agent".into() },
                Exclusion { kind: ExclusionKind::Process, value: "C:\\Program Files\\Vendor\\".into() },
            ],
            prevention: true,
            ..Default::default()
        };
        let e = Exclusions::from_policy(&p);
        assert!(e.path("/srv/backups/x.tar") && e.path("/srv/backups") && !e.path("/srv/backups2/x"));
        assert!(e.path("c:\\users\\bob\\appdata\\local\\vendor\\cache.bin"));
        assert!(e.hash(&"ab".repeat(32)) && e.rule("RMM-B-0018"));
        assert!(e.process(&Proc { name: "backup-agent".into(), ..Default::default() }));
        assert!(e.process(&Proc { name: "x.exe".into(), exe: Some("C:\\Program Files\\Vendor\\x.exe".into()), ..Default::default() }));
        assert!(!e.process(&Proc { name: "x.exe".into(), exe: Some("C:\\Temp\\x.exe".into()), ..Default::default() }));
        let none = HashMap::new();
        assert_eq!(effective_mode(&p, &none, &e, "RMM-B-0018", RuleMode::Alert, Confidence::High), RuleMode::Disabled);
        assert_eq!(effective_mode(&p, &none, &e, "X", RuleMode::Block, Confidence::Medium), RuleMode::Alert, "only high confidence blocks");
        assert_eq!(effective_mode(&p, &none, &e, "X", RuleMode::Block, Confidence::High), RuleMode::Block);
        let off = SensorPolicy { prevention: false, ..p.clone() };
        assert_eq!(effective_mode(&off, &none, &e, "X", RuleMode::Block, Confidence::High), RuleMode::Alert, "prevention off");
        let o: HashMap<String, RuleMode> = [("X".to_string(), RuleMode::Disabled)].into();
        assert_eq!(effective_mode(&p, &o, &e, "X", RuleMode::Alert, Confidence::High), RuleMode::Disabled, "kill switch");
    }
}
