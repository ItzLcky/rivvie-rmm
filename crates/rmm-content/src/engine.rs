//! Behaviour rules over telemetry events.
//!
//! [`Engine::evaluate`] takes one event at a time and returns the rules it fires. Comparisons
//! ignore case, and `process.name`/`parent.name` also ignore a trailing `.exe`, so one rule
//! covers `vssadmin` and `vssadmin.exe`.

use std::collections::{HashMap, VecDeque};

use chrono::{DateTime, Duration, Utc};
use rmm_proto::telemetry::Event;

use crate::{BehaviourRule, Expr, Op};

/// The value of a rule field on an event, if the event has it.
pub fn field(ev: &Event, name: &str) -> Option<String> {
    let p = ev.process.as_ref();
    let pa = ev.parent.as_ref();
    let f = ev.file.as_ref();
    let n = ev.network.as_ref();
    let r = ev.registry.as_ref();
    let m = ev.module.as_ref();
    Some(match name {
        "action" => ev.action.clone(),
        "process.name" => p?.name.clone(),
        "process.exe" => p?.exe.clone()?,
        "process.command_line" => p?.command_line.clone(),
        "process.user" => p?.user.clone()?,
        "process.sha256" => p?.sha256.clone()?,
        "process.pid" => p?.pid.to_string(),
        "parent.name" => pa?.name.clone(),
        "parent.exe" => pa?.exe.clone()?,
        "parent.command_line" => pa?.command_line.clone(),
        "file.path" => f?.path.clone(),
        "file.name" => basename(&f?.path).to_string(),
        "file.extension" => extension(&f?.path)?,
        "file.old_path" => f?.old_path.clone()?,
        "file.old_extension" => extension(f?.old_path.as_deref()?)?,
        "network.protocol" => n?.protocol.clone(),
        "network.remote_addr" => n?.remote_addr.clone(),
        "network.remote_port" => n?.remote_port.to_string(),
        "network.local_port" => n?.local_port.to_string(),
        "registry.key" => r?.key.clone(),
        "registry.value" => r?.value.clone(),
        "registry.data" => r?.data.clone()?,
        "module.name" => m?.name.clone(),
        "module.path" => m?.path.clone()?,
        _ => return None,
    })
}

pub fn basename(path: &str) -> &str {
    path.rsplit(['/', '\\']).next().unwrap_or(path)
}

fn extension(path: &str) -> Option<String> {
    let name = basename(path);
    let (stem, ext) = name.rsplit_once('.')?;
    (!stem.is_empty() && !ext.is_empty()).then(|| ext.to_ascii_lowercase())
}

fn strip_exe(s: &str) -> &str {
    s.strip_suffix(".exe").unwrap_or(s)
}

/// A rule expression with its regexes compiled and its values lowercased.
enum Compiled {
    All(Vec<Compiled>),
    Any(Vec<Compiled>),
    Not(Box<Compiled>),
    Field { field: String, op: Op, values: Vec<String>, regexes: Vec<regex_lite::Regex>, numbers: Vec<f64> },
}

fn compile(e: &Expr) -> Compiled {
    match e {
        Expr::All { all } => Compiled::All(all.iter().map(compile).collect()),
        Expr::Any { any } => Compiled::Any(any.iter().map(compile).collect()),
        Expr::Not { not } => Compiled::Not(Box::new(compile(not))),
        Expr::Field { field, op, value } => {
            let values: Vec<String> = value.list().iter().map(|v| v.to_lowercase()).collect();
            let regexes = if *op == Op::Regex {
                value.list().iter().filter_map(|v| regex_lite::Regex::new(&format!("(?i){v}")).ok()).collect()
            } else {
                vec![]
            };
            let numbers = values.iter().filter_map(|v| v.parse().ok()).collect();
            Compiled::Field { field: field.clone(), op: *op, values, regexes, numbers }
        }
    }
}

fn eval(c: &Compiled, ev: &Event) -> bool {
    match c {
        Compiled::All(v) => v.iter().all(|c| eval(c, ev)),
        Compiled::Any(v) => v.iter().any(|c| eval(c, ev)),
        Compiled::Not(c) => !eval(c, ev),
        Compiled::Field { field: name, op, values, regexes, numbers } => {
            let Some(raw) = field(ev, name) else { return false };
            let v = raw.to_lowercase();
            let names = name == "process.name" || name == "parent.name";
            match op {
                Op::Exists => true,
                Op::Equals => values.iter().any(|x| if names { strip_exe(&v) == strip_exe(x) } else { &v == x }),
                Op::Contains => values.iter().any(|x| v.contains(x.as_str())),
                Op::StartsWith => values.iter().any(|x| v.starts_with(x.as_str())),
                Op::EndsWith => values.iter().any(|x| v.ends_with(x.as_str())),
                Op::Regex => regexes.iter().any(|r| r.is_match(&raw)),
                Op::Gt => raw.parse::<f64>().is_ok_and(|n| numbers.iter().any(|x| n > *x)),
                Op::Lt => raw.parse::<f64>().is_ok_and(|n| numbers.iter().any(|x| n < *x)),
            }
        }
    }
}

struct Rule {
    rule: BehaviourRule,
    when: Compiled,
}

/// Evaluates behaviour rules, keeping the sliding windows of thresholded ones.
pub struct Engine {
    rules: Vec<Rule>,
    windows: HashMap<(usize, String), VecDeque<DateTime<Utc>>>,
}

impl Engine {
    pub fn new(rules: &[BehaviourRule]) -> Self {
        Engine { rules: rules.iter().map(|r| Rule { when: compile(&r.when), rule: r.clone() }).collect(), windows: HashMap::new() }
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// The rules this event fires. `skip` filters rules out first (disabled, excluded).
    pub fn evaluate(&mut self, ev: &Event, skip: impl Fn(&BehaviourRule) -> bool) -> Vec<&BehaviourRule> {
        let mut fired = Vec::new();
        for (i, r) in self.rules.iter().enumerate() {
            if r.rule.event != ev.kind || (!r.rule.actions.is_empty() && !r.rule.actions.iter().any(|a| a.eq_ignore_ascii_case(&ev.action))) {
                continue;
            }
            if skip(&r.rule) || !eval(&r.when, ev) {
                continue;
            }
            match &r.rule.threshold {
                None => fired.push(i),
                Some(t) => {
                    let group = t.group_by.as_deref().and_then(|g| field(ev, g)).unwrap_or_default();
                    let w = self.windows.entry((i, group)).or_default();
                    let cutoff = ev.ts - Duration::seconds(t.seconds.into());
                    while w.front().is_some_and(|ts| *ts < cutoff) {
                        w.pop_front();
                    }
                    w.push_back(ev.ts);
                    if w.len() >= t.count as usize {
                        w.clear();
                        fired.push(i);
                    }
                }
            }
        }
        // Old windows would otherwise pile up, one per group ever seen.
        if self.windows.len() > 10_000 {
            let now = ev.ts;
            self.windows.retain(|_, w| w.back().is_some_and(|t| now - *t < Duration::hours(1)));
        }
        fired.into_iter().map(|i| &self.rules[i].rule).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BehaviourRule, Confidence, Expr, Threshold, Values};
    use rmm_proto::security::{RuleMode, ThreatSeverity};
    use rmm_proto::telemetry::{EventKind, FileEvent, Proc};

    fn proc_event(name: &str, cmd: &str) -> Event {
        let mut e = Event::new(EventKind::Process, "start");
        e.process = Some(Proc { pid: 10, name: name.into(), command_line: cmd.into(), ..Default::default() });
        e.parent = Some(Proc { pid: 1, name: "explorer.exe".into(), ..Default::default() });
        e
    }

    fn rule(when: Expr) -> BehaviourRule {
        BehaviourRule {
            id: "T-1".into(),
            name: "t".into(),
            description: String::new(),
            severity: ThreatSeverity::High,
            confidence: Confidence::High,
            mode: RuleMode::Alert,
            mitre: vec![],
            event: EventKind::Process,
            actions: vec![],
            when,
            threshold: None,
            tests: vec![],
        }
    }

    fn f(field: &str, op: Op, v: &[&str]) -> Expr {
        Expr::Field { field: field.into(), op, value: Values::Many(v.iter().map(|s| s.to_string()).collect()) }
    }

    #[test]
    fn fields_and_ops() {
        let r = rule(Expr::All {
            all: vec![
                f("process.name", Op::Equals, &["vssadmin"]),
                f("process.command_line", Op::Contains, &["delete shadows"]),
                Expr::Not { not: Box::new(f("parent.name", Op::Equals, &["msiexec"])) },
            ],
        });
        let mut e = Engine::new(&[r]);
        assert_eq!(e.evaluate(&proc_event("VSSADMIN.EXE", "vssadmin Delete Shadows /all /quiet"), |_| false).len(), 1);
        assert!(e.evaluate(&proc_event("vssadmin.exe", "vssadmin list shadows"), |_| false).is_empty());
        assert!(e.evaluate(&proc_event("vssadmin.exe", "vssadmin delete shadows"), |_| true).is_empty(), "skipped");
        let mut fe = Event::new(EventKind::File, "rename");
        fe.file = Some(FileEvent { path: "C:\\Users\\a\\doc.DOCX.locked".into(), old_path: Some("C:\\Users\\a\\doc.docx".into()), sha256: None });
        assert_eq!(field(&fe, "file.extension").as_deref(), Some("locked"));
        assert_eq!(field(&fe, "file.old_extension").as_deref(), Some("docx"));
        assert_eq!(field(&fe, "file.name").as_deref(), Some("doc.DOCX.locked"));
        assert_eq!(field(&fe, "process.name"), None);
        let re = rule(f("process.command_line", Op::Regex, &[r"-e(nc|ncodedcommand)?\s+[a-z0-9+/=]{20,}"]));
        let mut e = Engine::new(&[re]);
        assert_eq!(e.evaluate(&proc_event("powershell.exe", "powershell -NoP -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBi"), |_| false).len(), 1);
    }

    #[test]
    fn thresholds_count_per_group_within_the_window() {
        let mut r = rule(f("action", Op::Equals, &["rename"]));
        r.event = EventKind::File;
        r.threshold = Some(Threshold { count: 3, seconds: 10, group_by: Some("process.pid".into()) });
        let mut e = Engine::new(&[r]);
        let t0 = Utc::now();
        let ev = |pid: u32, secs: i64| {
            let mut x = Event::new(EventKind::File, "rename");
            x.ts = t0 + Duration::seconds(secs);
            x.process = Some(Proc { pid, name: "x".into(), ..Default::default() });
            x.file = Some(FileEvent { path: "/a".into(), ..Default::default() });
            x
        };
        assert!(e.evaluate(&ev(1, 0), |_| false).is_empty());
        assert!(e.evaluate(&ev(2, 1), |_| false).is_empty(), "another process counts separately");
        assert!(e.evaluate(&ev(1, 2), |_| false).is_empty());
        assert!(e.evaluate(&ev(1, 30), |_| false).is_empty(), "the first two fell out of the window");
        assert!(e.evaluate(&ev(1, 31), |_| false).is_empty());
        assert_eq!(e.evaluate(&ev(1, 32), |_| false).len(), 1);
        assert!(e.evaluate(&ev(1, 33), |_| false).is_empty(), "the window restarts after firing");
    }
}
