//! Matching files against a bundle: known-bad hashes, and file rules (byte patterns found
//! with one Aho-Corasick pass over the file, for all rules at once).

use std::collections::HashMap;

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};

use crate::{Bundle, Condition, Error, FileRule, HashIoc, Pattern};

/// Files larger than this aren't read unless a rule asks for more.
pub const DEFAULT_MAX_SIZE: u64 = 32 * 1024 * 1024;

struct Automaton {
    ac: AhoCorasick,
    /// Pattern index -> (rule index, string index).
    owners: Vec<(usize, usize)>,
}

pub struct FileMatcher {
    hashes: HashMap<String, HashIoc>,
    rules: Vec<FileRule>,
    /// Each rule's required leading bytes (`FileRule::header`), by rule index.
    headers: Vec<Option<Vec<u8>>>,
    exact: Option<Automaton>,
    nocase: Option<Automaton>,
    max_size: u64,
}

fn build(patterns: Vec<(Vec<u8>, (usize, usize))>, nocase: bool) -> Result<Option<Automaton>, Error> {
    if patterns.is_empty() {
        return Ok(None);
    }
    let (bytes, owners): (Vec<Vec<u8>>, Vec<(usize, usize)>) = patterns.into_iter().unzip();
    let ac = AhoCorasickBuilder::new()
        .match_kind(MatchKind::Standard)
        .ascii_case_insensitive(nocase)
        .build(&bytes)
        .map_err(|e| Error::Invalid(format!("building file patterns: {e}")))?;
    Ok(Some(Automaton { ac, owners }))
}

impl FileMatcher {
    pub fn new(bundle: &Bundle) -> Result<Self, Error> {
        Self::with_rules(&bundle.hashes, &bundle.file_rules)
    }

    pub fn with_rules(hashes: &[HashIoc], rules: &[FileRule]) -> Result<Self, Error> {
        let (mut exact, mut nocase) = (Vec::new(), Vec::new());
        for (ri, r) in rules.iter().enumerate() {
            for (si, p) in r.strings.iter().enumerate() {
                let b = p.bytes()?;
                if p.nocase { nocase.push((b, (ri, si))) } else { exact.push((b, (ri, si))) }
            }
        }
        let headers = rules.iter().map(|r| r.header.as_ref().map(Pattern::bytes).transpose()).collect::<Result<Vec<_>, _>>()?;
        let max_size = rules.iter().filter_map(|r| r.max_size).max().unwrap_or(DEFAULT_MAX_SIZE).max(DEFAULT_MAX_SIZE);
        Ok(FileMatcher {
            hashes: hashes.iter().map(|h| (h.sha256.to_ascii_lowercase(), h.clone())).collect(),
            rules: rules.to_vec(),
            headers,
            exact: build(exact, false)?,
            nocase: build(nocase, true)?,
            max_size,
        })
    }

    pub fn max_size(&self) -> u64 {
        self.max_size
    }

    pub fn has_rules(&self) -> bool {
        !self.rules.is_empty() || !self.hashes.is_empty()
    }

    pub fn hash(&self, sha256: &str) -> Option<&HashIoc> {
        self.hashes.get(&sha256.to_ascii_lowercase())
    }

    /// File rules whose condition holds for this content.
    pub fn scan(&self, data: &[u8]) -> Vec<&FileRule> {
        let mut seen: HashMap<usize, Vec<bool>> = HashMap::new();
        for a in [&self.exact, &self.nocase].into_iter().flatten() {
            for m in a.ac.find_overlapping_iter(data) {
                let (ri, si) = a.owners[m.pattern().as_usize()];
                seen.entry(ri).or_insert_with(|| vec![false; self.rules[ri].strings.len()])[si] = true;
            }
        }
        let mut out: Vec<usize> = seen
            .into_iter()
            .filter(|(ri, hits)| {
                let r = &self.rules[*ri];
                if r.max_size.is_some_and(|m| data.len() as u64 > m) {
                    return false;
                }
                if let Some(h) = &self.headers[*ri]
                    && !data.starts_with(h)
                {
                    return false;
                }
                let n = hits.iter().filter(|h| **h).count();
                match r.condition {
                    Condition::Any => n >= 1,
                    Condition::All => n == hits.len(),
                    Condition::AtLeast(k) => n >= k as usize,
                }
            })
            .map(|(ri, _)| ri)
            .collect();
        out.sort_unstable();
        out.into_iter().map(|ri| &self.rules[ri]).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Confidence;
    use rmm_proto::security::{RuleMode, ThreatSeverity};

    fn rule(id: &str, strings: Vec<Pattern>, condition: Condition) -> FileRule {
        FileRule {
            id: id.into(),
            name: id.into(),
            severity: ThreatSeverity::High,
            confidence: Confidence::Medium,
            mode: RuleMode::Alert,
            mitre: vec![],
            strings,
            condition,
            max_size: None,
            header: None,
            tests: vec![],
        }
    }

    fn text(t: &str, nocase: bool) -> Pattern {
        Pattern { text: Some(t.into()), hex: None, nocase }
    }

    #[test]
    fn conditions_and_case() {
        let rules = vec![
            rule("any", vec![text("evil", false), text("bad", false)], Condition::Any),
            rule("all", vec![text("evil", false), Pattern { text: None, hex: Some("4d 5a".into()), nocase: false }], Condition::All),
            rule("nocase", vec![text("Invoke-Mimikatz", true)], Condition::Any),
            rule("two", vec![text("a1", false), text("b2", false), text("c3", false)], Condition::AtLeast(2)),
        ];
        let m = FileMatcher::with_rules(&[], &rules).unwrap();
        let ids = |d: &[u8]| m.scan(d).into_iter().map(|r| r.id.clone()).collect::<Vec<_>>();
        assert_eq!(ids(b"so evil"), ["any"]);
        assert_eq!(ids(b"MZ.. evil"), ["any", "all"]);
        assert_eq!(ids(b"invoke-MIMIKATZ"), ["nocase"]);
        assert_eq!(ids(b"a1 c3"), ["two"]);
        assert!(ids(b"a1 harmless").is_empty());
        // A header must lead the content, not merely appear in it.
        let mut pe = rule("pe", vec![text("evil", false)], Condition::Any);
        pe.header = Some(Pattern { text: None, hex: Some("4d 5a".into()), nocase: false });
        let m = FileMatcher::with_rules(&[], &[pe]).unwrap();
        assert_eq!(m.scan(b"MZ\x90\0 evil").len(), 1);
        assert!(m.scan(b"text quoting MZ and evil").is_empty());
        let h = HashIoc { sha256: "AB".repeat(32), name: "x".into(), severity: ThreatSeverity::Severe };
        let m = FileMatcher::with_rules(&[h], &[]).unwrap();
        assert!(m.hash(&"ab".repeat(32)).is_some() && m.hash(&"cd".repeat(32)).is_none());
    }
}
