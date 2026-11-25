//! The Arch Linux security tracker (`security.archlinux.org/issues/all.json`): one AVG per
//! group of packages and CVEs, with the fixed version once there is one.

use serde::Deserialize;

use super::osv::{Advisory, AffectedRange};
use super::version::Range;

#[derive(Deserialize)]
struct Group {
    name: String,
    #[serde(default)]
    packages: Vec<String>,
    #[serde(default)]
    status: String,
    #[serde(default)]
    severity: String,
    #[serde(default, rename = "type")]
    kind: String,
    #[serde(default)]
    fixed: Option<String>,
    #[serde(default)]
    issues: Vec<String>,
    #[serde(default)]
    advisories: Vec<String>,
}

/// Every AVG that affects something: `Not affected` groups are left out; `Vulnerable` ones
/// without a fix affect every version.
pub fn parse(json: &[u8]) -> anyhow::Result<Vec<Advisory>> {
    let groups: Vec<Group> = serde_json::from_slice(json)?;
    Ok(groups
        .into_iter()
        .filter(|g| !g.status.eq_ignore_ascii_case("not affected") && !g.packages.is_empty())
        .map(|g| {
            let range = Range { introduced: Some("0".into()), fixed: g.fixed.clone().filter(|f| !f.is_empty()), ..Default::default() };
            let what = if g.kind.is_empty() || g.kind == "unknown" { "security issue".to_string() } else { g.kind.clone() };
            let mut aliases = g.issues.clone();
            aliases.extend(g.advisories.iter().cloned());
            Advisory {
                summary: format!("{} in {}", capitalise(&what), g.packages.join(", ")),
                details: format!("Arch Linux {}: {} ({}).", g.name, what, if g.issues.is_empty() { "no CVE".into() } else { g.issues.join(", ") }),
                severity: super::severity_of_word(&g.severity).unwrap_or("unknown").to_string(),
                cve: g.issues.iter().find(|i| i.starts_with("CVE-")).cloned(),
                url: Some(format!("https://security.archlinux.org/{}", g.name)),
                ranges: g.packages.iter().map(|p| AffectedRange { ecosystem: "Arch".into(), package: p.clone(), range: range.clone() }).collect(),
                id: g.name,
                aliases,
                ..Default::default()
            }
        })
        .collect())
}

fn capitalise(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        Some(f) => f.to_uppercase().chain(c).collect(),
        None => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn groups() {
        let json = std::fs::read(format!("{}/tests/fixtures/vuln/arch-all.json", env!("CARGO_MANIFEST_DIR"))).unwrap();
        let all = parse(&json).unwrap();
        assert_eq!(all.len(), 2, "the not-affected group is skipped");
        let a = &all[0];
        assert_eq!((a.id.as_str(), a.cve.as_deref(), a.severity.as_str()), ("AVG-2843", Some("CVE-2023-0286"), "high"));
        assert_eq!(a.ranges.len(), 2);
        assert_eq!(a.ranges[1].package, "lib32-openssl");
        assert_eq!(a.ranges[0].range.fixed.as_deref(), Some("3.0.8-1"));
        assert!(a.ranges[0].range.contains(crate::vuln::version::Scheme::Pacman, "3.0.7-4"));
        assert!(!a.ranges[0].range.contains(crate::vuln::version::Scheme::Pacman, "3.0.8-1"));
        assert_eq!(all[1].ranges[0].range.fixed, None, "vulnerable, no fix yet");
        assert!(all[1].summary.starts_with("Arbitrary code execution in vim"));
    }
}
