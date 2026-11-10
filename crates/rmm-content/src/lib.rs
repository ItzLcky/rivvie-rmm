//! Detection content for the RMM sensor (Phase 8, milestones 2 and 4).
//!
//! A [`Bundle`] holds known-bad hashes, file rules (byte patterns, YARA-style) and behaviour
//! rules (conditions over telemetry events, with MITRE ATT&CK tags). Bundles are JSON, signed
//! offline with the release key (`rmm-sign sign-content`), uploaded to the server, rolled out
//! to canary clients first and verified by every agent before use.
//!
//! Every rule carries test cases; [`test::run`] replays them, plus a benign corpus, and
//! signing refuses a bundle that fails.

pub mod engine;
pub mod files;
pub mod test;

use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use rmm_proto::security::{RuleMode, ThreatSeverity, content_signed_message};
use rmm_proto::telemetry::{Event, EventKind};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid bundle: {0}")]
    Parse(#[from] serde_json::Error),
    #[error("{0}")]
    Invalid(String),
    #[error("signature: {0}")]
    Signature(String),
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Low,
    #[default]
    Medium,
    /// Few or no false positives across the benign corpus and fleet baselines: may block.
    High,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HashIoc {
    pub sha256: String,
    pub name: String,
    #[serde(default = "severe")]
    pub severity: ThreatSeverity,
}

fn severe() -> ThreatSeverity {
    ThreatSeverity::Severe
}

fn audit() -> RuleMode {
    RuleMode::Audit
}

/// A byte pattern: `text` (UTF-8) or `hex` (`4d 5a 90 00`), optionally case-insensitive.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Pattern {
    #[serde(default)]
    pub text: Option<String>,
    #[serde(default)]
    pub hex: Option<String>,
    #[serde(default)]
    pub nocase: bool,
}

impl Pattern {
    pub fn bytes(&self) -> Result<Vec<u8>, Error> {
        match (&self.text, &self.hex) {
            (Some(t), None) if !t.is_empty() => Ok(t.as_bytes().to_vec()),
            (None, Some(h)) => {
                let clean: String = h.chars().filter(|c| !c.is_whitespace()).collect();
                let b = hex::decode(&clean).map_err(|e| Error::Invalid(format!("hex pattern {h:?}: {e}")))?;
                if b.is_empty() {
                    return Err(Error::Invalid("empty hex pattern".into()));
                }
                Ok(b)
            }
            _ => Err(Error::Invalid("a pattern needs exactly one of text or hex".into())),
        }
    }
}

/// How many of a file rule's patterns must appear.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum Condition {
    #[default]
    Any,
    All,
    AtLeast(u32),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileTest {
    #[serde(default)]
    pub text: Option<String>,
    #[serde(default)]
    pub hex: Option<String>,
    pub expect: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileRule {
    pub id: String,
    pub name: String,
    pub severity: ThreatSeverity,
    #[serde(default)]
    pub confidence: Confidence,
    #[serde(default = "audit")]
    pub mode: RuleMode,
    #[serde(default)]
    pub mitre: Vec<String>,
    pub strings: Vec<Pattern>,
    #[serde(default)]
    pub condition: Condition,
    /// Skip larger files (bytes).
    #[serde(default)]
    pub max_size: Option<u64>,
    #[serde(default)]
    pub tests: Vec<FileTest>,
}

/// A condition on one event field. Comparisons ignore case.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum Expr {
    All { all: Vec<Expr> },
    Any { any: Vec<Expr> },
    Not { not: Box<Expr> },
    Field {
        field: String,
        op: Op,
        #[serde(default)]
        value: Values,
    },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Op {
    /// Equal to one of the values.
    Equals,
    Contains,
    StartsWith,
    EndsWith,
    /// Matches one of the regular expressions (`regex-lite`, case-insensitive).
    Regex,
    /// Numeric: greater / less than the (first) value.
    Gt,
    Lt,
    /// The field is present (value ignored).
    Exists,
}

/// One value or a list; a field matches if any value does.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(untagged)]
pub enum Values {
    #[default]
    None,
    One(String),
    Many(Vec<String>),
}

impl Values {
    pub fn list(&self) -> Vec<&str> {
        match self {
            Values::None => vec![],
            Values::One(s) => vec![s.as_str()],
            Values::Many(v) => v.iter().map(String::as_str).collect(),
        }
    }
}

/// Fire only once `count` matching events arrive within `seconds`, per value of `group_by`
/// (e.g. many files renamed by one process).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Threshold {
    pub count: u32,
    pub seconds: u32,
    #[serde(default)]
    pub group_by: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BehaviourTest {
    /// One event, or a sequence for thresholded rules.
    #[serde(default)]
    pub event: Option<Event>,
    #[serde(default)]
    pub events: Vec<Event>,
    pub expect: bool,
}

impl BehaviourTest {
    pub fn events(&self) -> Vec<Event> {
        self.event.iter().cloned().chain(self.events.iter().cloned()).collect()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BehaviourRule {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub severity: ThreatSeverity,
    #[serde(default)]
    pub confidence: Confidence,
    #[serde(default = "audit")]
    pub mode: RuleMode,
    #[serde(default)]
    pub mitre: Vec<String>,
    pub event: EventKind,
    /// Only these actions (`start`, `connect`, `modify`...). Empty = any.
    #[serde(default)]
    pub actions: Vec<String>,
    pub when: Expr,
    #[serde(default)]
    pub threshold: Option<Threshold>,
    #[serde(default)]
    pub tests: Vec<BehaviourTest>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Bundle {
    pub version: String,
    pub created_at: DateTime<Utc>,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub hashes: Vec<HashIoc>,
    #[serde(default)]
    pub file_rules: Vec<FileRule>,
    #[serde(default)]
    pub behaviour_rules: Vec<BehaviourRule>,
}

/// Fields behaviour rules can test. Anything else is a mistake in the rule.
pub const FIELDS: &[&str] = &[
    "action",
    "process.name",
    "process.exe",
    "process.command_line",
    "process.user",
    "process.sha256",
    "process.pid",
    "parent.name",
    "parent.exe",
    "parent.command_line",
    "file.path",
    "file.name",
    "file.extension",
    "file.old_path",
    "file.old_extension",
    "network.protocol",
    "network.remote_addr",
    "network.remote_port",
    "network.local_port",
    "registry.key",
    "registry.value",
    "registry.data",
    "module.name",
    "module.path",
];

impl Bundle {
    pub fn parse(json: &[u8]) -> Result<Bundle, Error> {
        let b: Bundle = serde_json::from_slice(json)?;
        b.validate()?;
        Ok(b)
    }

    pub fn rule_count(&self) -> usize {
        self.file_rules.len() + self.behaviour_rules.len()
    }

    /// Ids, fields, patterns and regexes are all usable, and every rule has tests.
    pub fn validate(&self) -> Result<(), Error> {
        let bad = |m: String| Err(Error::Invalid(m));
        if self.version.trim().is_empty() || self.version.len() > 64 {
            return bad("version must be 1-64 characters".into());
        }
        for h in &self.hashes {
            if h.sha256.len() != 64 || !h.sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
                return bad(format!("hash {:?} isn't a sha256", h.sha256));
            }
        }
        let mut ids = std::collections::HashSet::new();
        for r in &self.file_rules {
            if !ids.insert(r.id.as_str()) {
                return bad(format!("duplicate rule id {}", r.id));
            }
            if r.strings.is_empty() {
                return bad(format!("{}: no patterns", r.id));
            }
            for p in &r.strings {
                p.bytes().map_err(|e| Error::Invalid(format!("{}: {e}", r.id)))?;
            }
            if let Condition::AtLeast(n) = r.condition
                && (n == 0 || n as usize > r.strings.len())
            {
                return bad(format!("{}: at_least must be 1-{}", r.id, r.strings.len()));
            }
            if !r.tests.iter().any(|t| t.expect) || !r.tests.iter().any(|t| !t.expect) {
                return bad(format!("{}: needs a test that matches and one that doesn't", r.id));
            }
        }
        for r in &self.behaviour_rules {
            if !ids.insert(r.id.as_str()) {
                return bad(format!("duplicate rule id {}", r.id));
            }
            check_expr(&r.when).map_err(|e| Error::Invalid(format!("{}: {e}", r.id)))?;
            if let Some(t) = &r.threshold {
                if t.count < 2 || t.seconds == 0 {
                    return bad(format!("{}: a threshold needs count >= 2 and seconds > 0", r.id));
                }
                if let Some(g) = &t.group_by
                    && !FIELDS.contains(&g.as_str())
                {
                    return bad(format!("{}: unknown group_by field {g}", r.id));
                }
            }
            if !r.tests.iter().any(|t| t.expect) || !r.tests.iter().any(|t| !t.expect) {
                return bad(format!("{}: needs a test that fires and one that doesn't", r.id));
            }
            if r.mode == RuleMode::Block && r.confidence != Confidence::High {
                return bad(format!("{}: only high-confidence rules can block", r.id));
            }
        }
        Ok(())
    }

    pub fn sha256(json: &[u8]) -> String {
        hex::encode(Sha256::digest(json))
    }
}

fn check_expr(e: &Expr) -> Result<(), String> {
    match e {
        Expr::All { all: v } | Expr::Any { any: v } => {
            if v.is_empty() {
                return Err("empty all/any".into());
            }
            v.iter().try_for_each(check_expr)
        }
        Expr::Not { not } => check_expr(not),
        Expr::Field { field, op, value } => {
            if !FIELDS.contains(&field.as_str()) {
                return Err(format!("unknown field {field}"));
            }
            if *op != Op::Exists && value.list().is_empty() {
                return Err(format!("{field}: no value"));
            }
            match op {
                Op::Regex => {
                    for v in value.list() {
                        regex_lite::Regex::new(&format!("(?i){v}")).map_err(|e| format!("{field}: bad regex {v:?}: {e}"))?;
                    }
                }
                Op::Gt | Op::Lt => {
                    for v in value.list() {
                        v.parse::<f64>().map_err(|_| format!("{field}: {v:?} isn't a number"))?;
                    }
                }
                _ => {}
            }
            Ok(())
        }
    }
}

/// Checks a bundle's signature (hex ed25519 over [`content_signed_message`]) with a public
/// key (hex), and that it parses. Returns the bundle.
pub fn verify(json: &[u8], version: &str, signature_hex: &str, pubkey_hex: &str) -> Result<Bundle, Error> {
    let sig = |m: &str| Error::Signature(m.to_string());
    let pk: [u8; 32] = hex::decode(pubkey_hex.trim()).ok().and_then(|b| b.try_into().ok()).ok_or_else(|| sig("bad public key"))?;
    let pk = VerifyingKey::from_bytes(&pk).map_err(|_| sig("bad public key"))?;
    let s: [u8; 64] = hex::decode(signature_hex.trim()).ok().and_then(|b| b.try_into().ok()).ok_or_else(|| sig("malformed signature"))?;
    pk.verify(&content_signed_message(version, &Bundle::sha256(json)), &Signature::from_bytes(&s))
        .map_err(|_| sig("doesn't match the release key"))?;
    let b = Bundle::parse(json)?;
    if b.version != version {
        return Err(sig("the version inside doesn't match the signed one"));
    }
    Ok(b)
}

/// The starter content shipped with the source (`content/starter.json`).
pub const STARTER: &str = include_str!("../../../content/starter.json");

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    #[test]
    fn starter_bundle_is_valid_and_passes_its_tests() {
        let b = Bundle::parse(STARTER.as_bytes()).unwrap();
        assert!(b.behaviour_rules.len() >= 15, "starter set covers ransomware, credential theft, persistence");
        let r = test::run(&b, &test::benign_corpus());
        assert!(r.ok(), "{}", r.summary());
    }

    #[test]
    fn signatures() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let json = STARTER.as_bytes();
        let b = Bundle::parse(json).unwrap();
        let sig = key.sign(&content_signed_message(&b.version, &Bundle::sha256(json)));
        let pk = hex::encode(key.verifying_key().as_bytes());
        assert!(verify(json, &b.version, &hex::encode(sig.to_bytes()), &pk).is_ok());
        assert!(verify(json, "other", &hex::encode(sig.to_bytes()), &pk).is_err(), "version is signed");
        let mut tampered = json.to_vec();
        tampered.push(b' ');
        assert!(verify(&tampered, &b.version, &hex::encode(sig.to_bytes()), &pk).is_err());
        let other = hex::encode(SigningKey::from_bytes(&[8u8; 32]).verifying_key().as_bytes());
        assert!(verify(json, &b.version, &hex::encode(sig.to_bytes()), &other).is_err());
    }

    #[test]
    fn validation_catches_mistakes() {
        let mut b = Bundle::parse(STARTER.as_bytes()).unwrap();
        b.behaviour_rules[0].when = Expr::Field { field: "process.nmae".into(), op: Op::Equals, value: Values::One("x".into()) };
        assert!(b.validate().unwrap_err().to_string().contains("unknown field"));
        let mut b = Bundle::parse(STARTER.as_bytes()).unwrap();
        b.behaviour_rules[0].tests.retain(|t| t.expect);
        assert!(b.validate().is_err(), "a rule needs a negative test");
        let mut b = Bundle::parse(STARTER.as_bytes()).unwrap();
        b.behaviour_rules[0].mode = RuleMode::Block;
        b.behaviour_rules[0].confidence = Confidence::Low;
        assert!(b.validate().is_err());
    }
}
