//! The scan engine (antivirus milestone 1): takes a file or bytes and returns a verdict. No
//! I/O policy here (what to scan, exclusions, what to do about a match): that's the sensor's.
//!
//! A file is hashed as it streams (no size limit for hash signatures); files up to the
//! content cap are then identified by content, matched against YARA rules, the legacy JSON
//! bundle's file rules and the heuristics, and opened: archive members, macros, embedded
//! scripts and files come out as parts, which are hashed and matched like files, recursively,
//! within a [`Limits`] budget.
//!
//! Every parser here reads hostile input: no panics (the sensor is built with
//! `panic = "abort"`), no unbounded loops or allocations. Each has a mutation test.

#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod cache;
pub mod container;
pub mod db;
pub mod embedded;
pub mod exe;
pub mod filetype;
pub mod hash;
pub mod heuristics;
pub mod ole;
pub mod rules;

#[cfg(test)]
mod fuzz;

use std::io::Read;
use std::path::Path;
use std::sync::Arc;

use rmm_content::Confidence;
use rmm_content::files::FileMatcher;
use rmm_proto::security::{RuleMode, ThreatSeverity};
use serde::Serialize;

pub use container::Budget;
pub use filetype::FileType;
pub use hash::Digests;

/// Bumped when the engine would give a different verdict for the same file and content: the
/// verdict cache is tied to it.
pub const ENGINE_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Containers inside containers, at most.
    pub max_depth: u32,
    /// Members (and other parts) per scanned file.
    pub max_entries: u32,
    /// Bytes unpacked per scanned file.
    pub max_unpacked: u64,
    /// Content rules look at files and members up to this size; larger ones are only hashed.
    pub content_cap: u64,
    /// Unpacked / packed, for members over 1 MB.
    pub max_ratio: u32,
    /// Per YARA evaluation.
    pub yara_timeout_ms: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Limits { max_depth: 5, max_entries: 10_000, max_unpacked: 512 * 1024 * 1024, content_cap: 32 * 1024 * 1024, max_ratio: 250, yara_timeout_ms: 5000 }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    /// A hash signature from the database.
    Hash,
    /// A hash from the legacy JSON bundle.
    BundleHash,
    Yara,
    /// A legacy JSON bundle file rule.
    BundleRule,
    Heuristic,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Match {
    pub kind: Kind,
    /// Hash matches all share `RMM-HASH`, so one switch covers them.
    pub id: String,
    pub name: String,
    pub severity: ThreatSeverity,
    pub confidence: Confidence,
    /// The rule's own mode, before the policy and the server's overrides.
    pub mode: RuleMode,
    pub mitre: Vec<String>,
    /// Where inside the file (`a.zip>b.docm>word/vbaProject.bin>VBA/Module1`), `None` for the
    /// file itself.
    pub part: Option<String>,
}

pub const HASH_RULE: &str = "RMM-HASH";

#[derive(Debug, Clone, Default, Serialize)]
pub struct Verdict {
    #[serde(skip)]
    pub digests: Digests,
    pub sha256: String,
    pub size: u64,
    pub file_type: Option<FileType>,
    pub matches: Vec<Match>,
    /// Parts taken out and scanned (members, macros, scripts).
    pub parts: u32,
    /// Something was only hashed: over the content cap.
    pub truncated: bool,
}

impl Verdict {
    pub fn clean(&self) -> bool {
        self.matches.is_empty()
    }
}

/// What the engine knows about where the bytes came from.
#[derive(Debug, Clone, Copy, Default)]
pub struct Context<'a> {
    pub path: Option<&'a str>,
}

pub struct Engine {
    db: Option<Arc<db::Database>>,
    #[cfg(feature = "yara")]
    yara: Option<rules::Rules>,
    legacy: Option<(String, FileMatcher)>,
    limits: Limits,
}

/// Whether this build evaluates YARA rules.
pub const YARA: bool = cfg!(feature = "yara");

impl Engine {
    /// Compiles the database's YARA rules. `legacy` is the JSON bundle's version and matcher.
    pub fn new(db: Option<Arc<db::Database>>, legacy: Option<(String, FileMatcher)>, limits: Limits) -> Result<Engine, String> {
        #[cfg(feature = "yara")]
        let yara = match &db {
            Some(d) if !d.yara_source().trim().is_empty() => Some(rules::Rules::compile(
                &rules::namespaces(d.yara_source()),
                std::time::Duration::from_millis(limits.yara_timeout_ms.into()),
            )?),
            _ => None,
        };
        Ok(Engine {
            db,
            #[cfg(feature = "yara")]
            yara,
            legacy,
            limits,
        })
    }

    pub fn limits(&self) -> Limits {
        self.limits
    }

    pub fn database(&self) -> Option<&db::Database> {
        self.db.as_deref()
    }

    pub fn yara_rules(&self) -> usize {
        #[cfg(feature = "yara")]
        return self.yara.as_ref().map_or(0, rules::Rules::len);
        #[cfg(not(feature = "yara"))]
        0
    }

    /// The database has YARA rules this build can't evaluate.
    pub fn yara_unsupported(&self) -> bool {
        !YARA && self.db.as_ref().is_some_and(|d| !d.yara_source().trim().is_empty())
    }

    /// Anything to match against at all.
    pub fn has_signatures(&self) -> bool {
        self.db.is_some() || self.legacy.as_ref().is_some_and(|(_, m)| m.has_rules())
    }

    /// Identifies what verdicts depend on, for the verdict cache.
    pub fn generation(&self) -> String {
        format!(
            "engine {ENGINE_VERSION} yara {YARA}; db {}; bundle {}; {:?}",
            self.db.as_ref().map_or("-", |d| d.sha256()),
            self.legacy.as_ref().map_or("-", |(v, _)| v.as_str()),
            self.limits
        )
    }

    fn content_cap(&self) -> u64 {
        // The legacy bundle could ask for more per rule.
        self.limits.content_cap.max(self.legacy.as_ref().map_or(0, |(_, m)| m.max_size().min(256 * 1024 * 1024)))
    }

    fn wants(&self) -> (bool, bool) {
        self.db.as_ref().map_or((false, false), |d| (d.wants_md5(), d.wants_sha1()))
    }

    pub fn scan_path(&self, path: &Path) -> std::io::Result<Verdict> {
        let f = std::fs::File::open(path)?;
        let p = path.to_string_lossy();
        self.scan_reader(f, &Context { path: Some(&p) })
    }

    /// Streams `r` through the hashes, keeping the first `content_cap` bytes for content rules.
    pub fn scan_reader(&self, mut r: impl Read, ctx: &Context) -> std::io::Result<Verdict> {
        let (md5, sha1) = self.wants();
        let mut h = hash::Hasher::new(md5, sha1);
        let cap = usize::try_from(self.content_cap()).unwrap_or(usize::MAX);
        let mut head: Vec<u8> = Vec::new();
        let mut buf = vec![0u8; 256 * 1024];
        let mut over = false;
        loop {
            let n = match r.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            };
            let chunk = buf.get(..n).unwrap_or_default();
            h.update(chunk);
            if !over {
                if head.len() + n <= cap {
                    head.extend_from_slice(chunk);
                } else {
                    over = true;
                    head = Vec::new();
                }
            }
        }
        let d = h.finish();
        Ok(self.verdict(d, (!over).then_some(&head[..]), ctx))
    }

    /// Bytes already in memory (an AMSI buffer, a test).
    pub fn scan_bytes(&self, data: &[u8], ctx: &Context) -> Verdict {
        let (md5, sha1) = self.wants();
        let d = hash::digests(data, md5, sha1);
        let content = (data.len() as u64 <= self.content_cap()).then_some(data);
        self.verdict(d, content, ctx)
    }

    fn verdict(&self, d: Digests, content: Option<&[u8]>, ctx: &Context) -> Verdict {
        let mut v = Verdict { digests: d, sha256: d.sha256_hex(), size: d.size, truncated: content.is_none(), ..Default::default() };
        self.hashes(&d, None, &mut v.matches);
        // A hash signature is the strongest verdict there is; no need to open the file.
        if let Some(data) = content.filter(|_| v.matches.is_empty()) {
            let mut budget = Budget::new(Limits { content_cap: self.content_cap(), ..self.limits });
            let name = ctx.path.map(|p| p.rsplit(['/', '\\']).next().unwrap_or(p));
            v.file_type = Some(self.analyze(data, name, None, 0, ctx, &mut budget, &mut v));
            if let Some(why) = budget.exceeded {
                let mut m = heuristic(&heuristics::ARCHIVE_BOMB, None);
                m.name = format!("{}: {}", m.name, why.describe());
                v.matches.push(m);
            }
            v.truncated |= budget.truncated;
        }
        // One match per rule: where it matched both a container and a member (a string in a
        // stored member is in the container's bytes too), the member says more.
        let mut best: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
        for (i, m) in v.matches.iter().enumerate() {
            let e = best.entry(m.id.clone()).or_insert(i);
            if v.matches[*e].part.is_none() && m.part.is_some() {
                *e = i;
            }
        }
        let keep: std::collections::HashSet<usize> = best.into_values().collect();
        let mut i = 0;
        v.matches.retain(|_| {
            i += 1;
            keep.contains(&(i - 1))
        });
        v
    }

    fn hashes(&self, d: &Digests, part: Option<&str>, out: &mut Vec<Match>) {
        let mk = |kind, name: &str, severity| Match {
            kind,
            id: HASH_RULE.into(),
            name: name.to_string(),
            severity,
            confidence: Confidence::High,
            // Blocks where the policy turns prevention on (the spec's "hash matches and
            // high-confidence rules"); the server's `RMM-HASH` override can lower it.
            mode: RuleMode::Block,
            mitre: vec![],
            part: part.map(str::to_string),
        };
        if let Some(db) = &self.db {
            let hit = db.lookup_sha256(&d.sha256).or_else(|| d.md5.and_then(|m| db.lookup_md5(&m, Some(d.size)))).or_else(|| d.sha1.and_then(|s| db.lookup_sha1(&s, Some(d.size))));
            if let Some(h) = hit {
                out.push(mk(Kind::Hash, h.name, h.severity));
                return;
            }
        }
        if let Some((_, m)) = &self.legacy
            && let Some(h) = m.hash(&d.sha256_hex())
        {
            out.push(mk(Kind::BundleHash, &h.name, h.severity));
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn analyze(&self, data: &[u8], name: Option<&str>, part: Option<&str>, depth: u32, ctx: &Context, budget: &mut Budget, v: &mut Verdict) -> FileType {
        let ft = filetype::identify(data);
        let at = |m: Match| Match { part: part.map(str::to_string), ..m };
        #[cfg(feature = "yara")]
        if let Some(y) = &self.yara {
            for r in y.scan(data) {
                v.matches.push(at(Match {
                    kind: Kind::Yara,
                    id: r.id.clone(),
                    name: r.name.clone(),
                    severity: r.severity,
                    confidence: r.confidence,
                    mode: r.mode,
                    mitre: r.mitre.clone(),
                    part: None,
                }));
            }
        }
        if let Some((_, m)) = &self.legacy {
            for r in m.scan(data) {
                v.matches.push(at(Match {
                    kind: Kind::BundleRule,
                    id: r.id.clone(),
                    name: r.name.clone(),
                    severity: r.severity,
                    confidence: r.confidence,
                    mode: r.mode,
                    mitre: r.mitre.clone(),
                    part: None,
                }));
            }
        }
        let pe = if ft == FileType::Pe { exe::pe(data) } else { None };
        let elf = if ft == FileType::Elf { exe::elf(data) } else { None };
        for h in heuristics::check(ft, data, pe.as_ref(), elf.as_ref(), ctx.path, name) {
            v.matches.push(heuristic(h, part.map(str::to_string)));
        }
        let container = matches!(ft, FileType::Zip | FileType::Gzip | FileType::Bzip2 | FileType::Xz | FileType::Tar | FileType::Ole2 | FileType::Pdf);
        if container && depth >= self.limits.max_depth {
            budget.stop(container::Exceeded::Depth);
            return ft;
        }
        let cap = usize::try_from(budget.limits.content_cap).unwrap_or(usize::MAX);
        let mut children: Vec<container::Member> = Vec::new();
        match ft {
            FileType::Zip => container::zip(data, budget, |m, b| self.part(m, part, depth, ctx, b, v)),
            FileType::Tar => container::tar(data, budget, |m, b| self.part(m, part, depth, ctx, b, v)),
            FileType::Gzip => children.extend(container::gzip(data, budget)),
            FileType::Bzip2 => children.extend(container::bzip2(data, budget)),
            FileType::Xz => children.extend(container::xz(data, budget)),
            FileType::Ole2 => {
                if let Some(o) = ole::Ole::parse(data) {
                    for m in ole::vba_modules(&o, cap) {
                        children.push(container::Member { name: format!("VBA/{}", m.name), data: m.source });
                    }
                    for (path, i) in o.streams() {
                        if path.rsplit('/').next().is_some_and(|n| n.eq_ignore_ascii_case("\u{1}Ole10Native"))
                            && let Some((name, body)) = ole::ole10native(&o.read(i, cap.saturating_add(4096)), cap)
                        {
                            children.push(container::Member { name, data: body });
                        }
                    }
                }
            }
            FileType::Pdf => children.extend(embedded::pdf_parts(data, budget)),
            FileType::Lnk => children.extend(embedded::lnk(data).map(|t| container::Member { name: "lnk".into(), data: t.into_bytes() })),
            FileType::Html => {
                for (i, s) in embedded::html_scripts(data).into_iter().enumerate() {
                    children.push(container::Member { name: format!("script[{}]", i + 1), data: s });
                }
            }
            _ => {}
        }
        for m in children {
            if !budget.entry() {
                break;
            }
            self.part(m, part, depth, ctx, budget, v);
        }
        ft
    }

    fn part(&self, m: container::Member, parent: Option<&str>, depth: u32, ctx: &Context, budget: &mut Budget, v: &mut Verdict) {
        v.parts = v.parts.saturating_add(1);
        let path = match parent {
            Some(p) => format!("{p}>{}", m.name),
            None => m.name.clone(),
        };
        let (md5, sha1) = self.wants();
        let d = hash::digests(&m.data, md5, sha1);
        let before = v.matches.len();
        self.hashes(&d, Some(&path), &mut v.matches);
        if v.matches.len() > before {
            return;
        }
        let name = m.name.rsplit(['/', '\\']).next().unwrap_or(&m.name).to_string();
        self.analyze(&m.data, Some(&name), Some(&path), depth + 1, ctx, budget, v);
    }
}

fn heuristic(h: &heuristics::Heuristic, part: Option<String>) -> Match {
    Match {
        kind: Kind::Heuristic,
        id: h.id.into(),
        name: h.name.into(),
        severity: h.severity,
        confidence: heuristics::CONFIDENCE,
        mode: heuristics::MODE,
        mitre: h.mitre.iter().map(|m| m.to_string()).collect(),
        part,
    }
}

/// The heuristics as database rule summaries (the console lists them with the rules).
pub fn heuristic_rules() -> Vec<db::RuleInfo> {
    heuristics::ALL
        .iter()
        .map(|h| db::RuleInfo {
            id: h.id.into(),
            name: h.name.into(),
            kind: "heuristic".into(),
            severity: h.severity,
            confidence: heuristics::CONFIDENCE,
            mode: heuristics::MODE,
            mitre: h.mitre.iter().map(|m| m.to_string()).collect(),
            description: h.description.into(),
            digest: format!("engine-{ENGINE_VERSION}"),
            source: Some("engine".into()),
            licence: None,
            author: None,
            reference: None,
        })
        .collect()
}

#[cfg(test)]
mod tests;
