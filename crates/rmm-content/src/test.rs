//! The replay harness: runs every rule's own test cases, then the whole bundle over a benign
//! corpus (recorded activity of ordinary admin work and software) where nothing may fire.
//! `rmm-sign sign-content` refuses to sign a bundle that fails, and CI runs it on the starter
//! content.

use rmm_proto::telemetry::Event;

use crate::engine::Engine;
use crate::files::FileMatcher;
use crate::{Bundle, Pattern};

#[derive(Debug, Default)]
pub struct Report {
    pub tests: usize,
    pub failures: Vec<String>,
    /// (rule id, how many benign events it fired on).
    pub benign_hits: Vec<(String, usize)>,
    pub benign_events: usize,
}

impl Report {
    pub fn ok(&self) -> bool {
        self.failures.is_empty() && self.benign_hits.is_empty()
    }

    pub fn summary(&self) -> String {
        let mut s = format!("{} rule tests, {} failed; {} benign events", self.tests, self.failures.len(), self.benign_events);
        for f in &self.failures {
            s.push_str(&format!("\n  FAIL {f}"));
        }
        for (id, n) in &self.benign_hits {
            s.push_str(&format!("\n  FALSE POSITIVE {id}: fired on {n} benign events"));
        }
        s
    }
}

/// The benign corpus shipped with the source (`content/benign.jsonl`, one event per line).
pub fn benign_corpus() -> Vec<Event> {
    parse_events(include_str!("../../../content/benign.jsonl"))
}

pub fn parse_events(jsonl: &str) -> Vec<Event> {
    jsonl
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.trim_start().starts_with("//"))
        .filter_map(|l| serde_json::from_str(l).map_err(|e| eprintln!("benign corpus: skipping a line: {e}")).ok())
        .collect()
}

pub fn run(bundle: &Bundle, benign: &[Event]) -> Report {
    let mut r = Report { benign_events: benign.len(), ..Default::default() };
    for rule in &bundle.behaviour_rules {
        for (i, t) in rule.tests.iter().enumerate() {
            r.tests += 1;
            // A fresh engine per test, so windows don't leak between cases.
            let mut e = Engine::new(std::slice::from_ref(rule));
            let fired = t.events().iter().any(|ev| !e.evaluate(ev, |_| false).is_empty());
            if fired != t.expect {
                r.failures.push(format!("{} test {}: expected {}", rule.id, i + 1, if t.expect { "a match" } else { "no match" }));
            }
        }
    }
    for rule in &bundle.file_rules {
        let m = match FileMatcher::with_rules(&[], std::slice::from_ref(rule)) {
            Ok(m) => m,
            Err(e) => {
                r.failures.push(format!("{}: {e}", rule.id));
                continue;
            }
        };
        for (i, t) in rule.tests.iter().enumerate() {
            r.tests += 1;
            let data = match (Pattern { text: t.text.clone(), hex: t.hex.clone(), nocase: false }).bytes() {
                Ok(d) => d,
                Err(e) => {
                    r.failures.push(format!("{} test {}: {e}", rule.id, i + 1));
                    continue;
                }
            };
            if m.scan(&data).is_empty() == t.expect {
                r.failures.push(format!("{} test {}: expected {}", rule.id, i + 1, if t.expect { "a match" } else { "no match" }));
            }
        }
    }
    let mut e = Engine::new(&bundle.behaviour_rules);
    let mut hits: std::collections::BTreeMap<String, usize> = Default::default();
    for ev in benign {
        for rule in e.evaluate(ev, |_| false) {
            *hits.entry(rule.id.clone()).or_default() += 1;
        }
    }
    r.benign_hits = hits.into_iter().collect();
    r
}
