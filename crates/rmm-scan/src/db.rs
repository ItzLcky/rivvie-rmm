//! The signature database: one binary file of hash signatures and YARA rules, built and signed
//! offline (`rmm-sign build-db`), memory-mapped by the sensor.
//!
//! ```text
//! header   "RMMSIGDB" | format u32 | section count u32 | body length u64 | reserved u64
//! sections kind u32 | records u32 | offset u64 | length u64     (24 bytes each)
//! META     JSON: version, dates, counts, the rules summary (first, so the server can read it
//!          from the head of an upload)
//! NAMES    UTF-8 names, concatenated
//! ENTRIES  name offset u32 | name length u16 | severity u8 | reserved u8   (8 bytes)
//! SHA256   first 16 bytes of the hash | entry u32 (20 bytes), sorted: a binary search
//! SHA256_TAIL  the other 16 bytes, same order: a hit is confirmed on the full hash
//! MD5      hash 16 | entry u32 | file size u64 (0: any) (28 bytes), sorted
//! SHA1     hash 20 | entry u32 | file size u64 (32 bytes), sorted
//! YARA     rule source text (compiled when loaded: compiled forms aren't stable across
//!          engine versions)
//! trailer  "RMMSIG01" | ed25519 signature (64) over
//!          rmm_proto::security::database_signed_message(version, sha256(everything before))
//! ```
//!
//! Unknown section kinds are skipped, so later formats can add some; a breaking change bumps
//! the format number. Everything is little-endian and 8-byte aligned. A 1M-hash database is
//! about 36 MB, mapped read-only, so its pages are shared page cache, not sensor memory.

use std::io::Read;
use std::path::Path;

use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use rmm_content::Confidence;
use rmm_proto::security::{RuleMode, ThreatSeverity, database_signed_message};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const MAGIC: [u8; 8] = *b"RMMSIGDB";
pub const FORMAT: u32 = 1;
pub const TRAILER_MAGIC: [u8; 8] = *b"RMMSIG01";
pub const TRAILER: usize = 8 + 64;
const HEADER: usize = 32;
const SECTION: usize = 24;
/// The server reads META from the head of an upload: it must start and end within this.
pub const HEAD_MAX: usize = 16 * 1024 * 1024;

const META: u32 = 1;
const NAMES: u32 = 2;
const ENTRIES: u32 = 3;
const SHA256: u32 = 4;
const SHA256_TAIL: u32 = 5;
const MD5: u32 = 6;
const SHA1: u32 = 7;
const YARA: u32 = 8;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("not a signature database: {0}")]
    Format(String),
    #[error("signature: {0}")]
    Signature(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

fn bad<T>(m: impl Into<String>) -> Result<T, Error> {
    Err(Error::Format(m.into()))
}

/// A rule as the console and the canary rollout see it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RuleInfo {
    pub id: String,
    pub name: String,
    /// `yara` or `heuristic`.
    pub kind: String,
    pub severity: ThreatSeverity,
    pub confidence: Confidence,
    pub mode: RuleMode,
    #[serde(default)]
    pub mitre: Vec<String>,
    #[serde(default)]
    pub description: String,
    /// Changes when the rule does (the rollout tells new and changed rules by it).
    pub digest: String,
    /// The feed or file it came from, and its licence, author and reference as the rule states
    /// them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub licence: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SourceInfo {
    pub name: String,
    /// `sha256-list`, `yara`, `clamav-hdb`, `clamav-hsb`.
    pub kind: String,
    pub entries: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Meta {
    pub version: String,
    pub created_at: DateTime<Utc>,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub sha256: u64,
    #[serde(default)]
    pub md5: u64,
    #[serde(default)]
    pub sha1: u64,
    #[serde(default)]
    pub yara_rules: u64,
    #[serde(default)]
    pub rules: Vec<RuleInfo>,
    #[serde(default)]
    pub sources: Vec<SourceInfo>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Algo {
    Sha256,
    Md5,
    Sha1,
}

impl Algo {
    pub fn digest_len(self) -> usize {
        match self {
            Algo::Sha256 => 32,
            Algo::Md5 => 16,
            Algo::Sha1 => 20,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashSig {
    pub algo: Algo,
    pub digest: Vec<u8>,
    /// The file size the signature is for (ClamAV's), `None` for any.
    pub size: Option<u64>,
    pub name: String,
    pub severity: ThreatSeverity,
}

pub fn severity_byte(s: ThreatSeverity) -> u8 {
    match s {
        ThreatSeverity::Severe => 4,
        ThreatSeverity::High => 3,
        ThreatSeverity::Moderate => 2,
        ThreatSeverity::Low => 1,
        ThreatSeverity::Unknown => 0,
    }
}

fn severity_from(b: u8) -> ThreatSeverity {
    match b {
        4 => ThreatSeverity::Severe,
        3 => ThreatSeverity::High,
        2 => ThreatSeverity::Moderate,
        1 => ThreatSeverity::Low,
        _ => ThreatSeverity::Unknown,
    }
}

/// Collects signatures and rules, then writes the (unsigned) body.
pub struct Builder {
    pub meta: Meta,
    hashes: Vec<HashSig>,
    yara: String,
}

impl Builder {
    pub fn new(version: &str, description: &str) -> Self {
        Builder {
            meta: Meta {
                version: version.into(),
                created_at: Utc::now(),
                description: description.into(),
                sha256: 0,
                md5: 0,
                sha1: 0,
                yara_rules: 0,
                rules: Vec::new(),
                sources: Vec::new(),
            },
            hashes: Vec::new(),
            yara: String::new(),
        }
    }

    pub fn add_hash(&mut self, h: HashSig) {
        self.hashes.push(h);
    }

    pub fn hash_count(&self) -> usize {
        self.hashes.len()
    }

    /// YARA source, appended as given (namespaces are the caller's business).
    pub fn add_yara(&mut self, source: &str) {
        self.yara.push_str(source);
        if !source.ends_with('\n') {
            self.yara.push('\n');
        }
    }

    pub fn yara(&self) -> &str {
        &self.yara
    }

    /// Sorts and de-duplicates (the first of equal hashes wins), then lays the file out.
    pub fn build(mut self) -> Result<Vec<u8>, Error> {
        if self.meta.version.trim().is_empty() || self.meta.version.len() > 64 {
            return bad("version must be 1-64 characters");
        }
        self.hashes.retain(|h| h.digest.len() == h.algo.digest_len());
        // Stable sort, then dedup keeps the first occurrence.
        self.hashes.sort_by(|a, b| (a.algo, &a.digest).cmp(&(b.algo, &b.digest)));
        self.hashes.dedup_by(|b, a| a.algo == b.algo && a.digest == b.digest);
        let mut names = Vec::new();
        let mut entries = Vec::new();
        let mut index: std::collections::HashMap<(String, u8), u32> = std::collections::HashMap::new();
        let mut entry_of = |name: &str, sev: ThreatSeverity, names: &mut Vec<u8>, entries: &mut Vec<u8>| -> u32 {
            let name: String = name.chars().take(200).collect();
            let key = (name, severity_byte(sev));
            if let Some(i) = index.get(&key) {
                return *i;
            }
            let i = (entries.len() / 8) as u32;
            entries.extend_from_slice(&(names.len() as u32).to_le_bytes());
            entries.extend_from_slice(&(key.0.len() as u16).to_le_bytes());
            entries.push(key.1);
            entries.push(0);
            names.extend_from_slice(key.0.as_bytes());
            index.insert(key, i);
            i
        };
        let (mut sha, mut tail, mut md5, mut sha1) = (Vec::new(), Vec::new(), Vec::new(), Vec::new());
        for h in &self.hashes {
            let e = entry_of(&h.name, h.severity, &mut names, &mut entries);
            match h.algo {
                Algo::Sha256 => {
                    sha.extend_from_slice(&h.digest[..16]);
                    sha.extend_from_slice(&e.to_le_bytes());
                    tail.extend_from_slice(&h.digest[16..]);
                }
                Algo::Md5 | Algo::Sha1 => {
                    let t = if h.algo == Algo::Md5 { &mut md5 } else { &mut sha1 };
                    t.extend_from_slice(&h.digest);
                    t.extend_from_slice(&e.to_le_bytes());
                    t.extend_from_slice(&h.size.unwrap_or(0).to_le_bytes());
                }
            }
        }
        self.meta.sha256 = (sha.len() / 20) as u64;
        self.meta.md5 = (md5.len() / 28) as u64;
        self.meta.sha1 = (sha1.len() / 32) as u64;
        let meta = serde_json::to_vec(&self.meta).map_err(|e| Error::Format(e.to_string()))?;
        let sections: Vec<(u32, u32, Vec<u8>)> = vec![
            (META, 1, meta),
            (NAMES, 0, names),
            (ENTRIES, (entries.len() / 8) as u32, entries),
            (SHA256, self.meta.sha256 as u32, sha),
            (SHA256_TAIL, self.meta.sha256 as u32, tail),
            (MD5, self.meta.md5 as u32, md5),
            (SHA1, self.meta.sha1 as u32, sha1),
            (YARA, 0, self.yara.into_bytes()),
        ];
        let mut out = vec![0u8; HEADER + SECTION * sections.len()];
        let mut table = Vec::new();
        for (kind, count, data) in &sections {
            out.resize(out.len().div_ceil(8) * 8, 0);
            table.push((*kind, *count, out.len() as u64, data.len() as u64));
            out.extend_from_slice(data);
        }
        out.resize(out.len().div_ceil(8) * 8, 0);
        if table.first().is_some_and(|(_, _, off, len)| off + len > HEAD_MAX as u64) {
            return bad("the rules summary is too large");
        }
        out[..8].copy_from_slice(&MAGIC);
        out[8..12].copy_from_slice(&FORMAT.to_le_bytes());
        out[12..16].copy_from_slice(&(sections.len() as u32).to_le_bytes());
        let body_len = out.len() as u64;
        out[16..24].copy_from_slice(&body_len.to_le_bytes());
        for (i, (kind, count, off, len)) in table.into_iter().enumerate() {
            let at = HEADER + i * SECTION;
            out[at..at + 4].copy_from_slice(&kind.to_le_bytes());
            out[at + 4..at + 8].copy_from_slice(&count.to_le_bytes());
            out[at + 8..at + 16].copy_from_slice(&off.to_le_bytes());
            out[at + 16..at + 24].copy_from_slice(&len.to_le_bytes());
        }
        Ok(out)
    }
}

/// Appends the signature trailer: `sign` gets the message to sign.
pub fn seal(mut body: Vec<u8>, version: &str, sign: impl FnOnce(&[u8]) -> [u8; 64]) -> Vec<u8> {
    let sha = hex::encode(Sha256::digest(&body));
    let sig = sign(&database_signed_message(version, &sha));
    body.extend_from_slice(&TRAILER_MAGIC);
    body.extend_from_slice(&sig);
    body
}

fn u32le(d: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(d.get(at..at.checked_add(4)?)?.try_into().ok()?))
}

fn u64le(d: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(d.get(at..at.checked_add(8)?)?.try_into().ok()?))
}

#[derive(Debug, Clone, Copy, Default)]
struct Range {
    off: usize,
    len: usize,
    count: usize,
}

#[derive(Debug, Default)]
struct Layout {
    meta: Range,
    names: Range,
    entries: Range,
    sha256: Range,
    sha256_tail: Range,
    md5: Range,
    sha1: Range,
    yara: Range,
}

/// The header and section table, checked against `total` (the whole file's length, or what
/// is known of it): every section inside the body, every table its record size times its
/// count.
fn layout(d: &[u8], total: usize) -> Result<Layout, Error> {
    if d.get(..8) != Some(&MAGIC[..]) {
        return bad("wrong magic");
    }
    let format = u32le(d, 8).unwrap_or(0);
    if format != FORMAT {
        return bad(format!("format {format}; this agent reads format {FORMAT}"));
    }
    let n = u32le(d, 12).unwrap_or(0) as usize;
    let body_len = u64le(d, 16).and_then(|b| usize::try_from(b).ok()).unwrap_or(usize::MAX);
    if n > 1024 || body_len.checked_add(TRAILER) != Some(total) {
        return bad("the header doesn't match the file's size");
    }
    let mut l = Layout::default();
    for i in 0..n {
        let at = HEADER + i * SECTION;
        let (Some(kind), Some(count), Some(off), Some(len)) = (u32le(d, at), u32le(d, at + 4), u64le(d, at + 8), u64le(d, at + 16)) else {
            return bad("truncated section table");
        };
        let (Ok(off), Ok(len)) = (usize::try_from(off), usize::try_from(len)) else { return bad("section out of range") };
        if off.checked_add(len).is_none_or(|end| end > body_len) || off < HEADER + n * SECTION {
            return bad(format!("section {kind} out of range"));
        }
        let r = Range { off, len, count: count as usize };
        let stride = match kind {
            ENTRIES => 8,
            SHA256 => 20,
            SHA256_TAIL => 16,
            MD5 => 28,
            SHA1 => 32,
            _ => 0,
        };
        if stride > 0 && r.count.checked_mul(stride) != Some(len) {
            return bad(format!("section {kind}: {count} records don't fill {len} bytes"));
        }
        match kind {
            META => l.meta = r,
            NAMES => l.names = r,
            ENTRIES => l.entries = r,
            SHA256 => l.sha256 = r,
            SHA256_TAIL => l.sha256_tail = r,
            MD5 => l.md5 = r,
            SHA1 => l.sha1 = r,
            YARA => l.yara = r,
            _ => {}
        }
    }
    if l.sha256_tail.count != l.sha256.count {
        return bad("SHA-256 table and its tail differ in length");
    }
    if l.meta.len == 0 {
        return bad("no META section");
    }
    Ok(l)
}

/// What the server needs before it has the whole upload: the META section from the file's
/// head (`head` is at least the first [`HEAD_MAX`] bytes, or the whole file), given the
/// file's total size.
pub fn read_head(head: &[u8], total: u64) -> Result<Meta, Error> {
    let total = usize::try_from(total).map_err(|_| Error::Format("too large".into()))?;
    let l = layout(head, total)?;
    let meta = head.get(l.meta.off..l.meta.off + l.meta.len).ok_or_else(|| Error::Format("META isn't in the head of the file".into()))?;
    serde_json::from_slice(meta).map_err(|e| Error::Format(format!("META: {e}")))
}

/// Checks the signature as the file streams past (server upload, agent download): feed every
/// byte to [`Verifier::update`], then [`Verifier::finish`].
pub struct Verifier {
    body: Sha256,
    whole: Sha256,
    held: Vec<u8>,
    total: u64,
}

impl Default for Verifier {
    fn default() -> Self {
        Self::new()
    }
}

impl Verifier {
    pub fn new() -> Self {
        Verifier { body: Sha256::new(), whole: Sha256::new(), held: Vec::new(), total: 0 }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.whole.update(data);
        self.total += data.len() as u64;
        // The last TRAILER bytes might be the trailer: hold them back from the body hash.
        self.held.extend_from_slice(data);
        if self.held.len() > TRAILER {
            let n = self.held.len() - TRAILER;
            self.body.update(&self.held[..n]);
            self.held.drain(..n);
        }
    }

    /// Checks the trailer against `version` (from META) and the key. Returns the SHA-256 of
    /// the whole file.
    pub fn finish(self, version: &str, pubkey_hex: &str) -> Result<String, Error> {
        if self.held.len() != TRAILER || self.held[..8] != TRAILER_MAGIC {
            return Err(Error::Signature("no signature trailer".into()));
        }
        let sig: [u8; 64] = self.held[8..].try_into().map_err(|_| Error::Signature("malformed signature".into()))?;
        let pk: [u8; 32] = hex::decode(pubkey_hex.trim())
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| Error::Signature("bad public key".into()))?;
        let pk = VerifyingKey::from_bytes(&pk).map_err(|_| Error::Signature("bad public key".into()))?;
        let body = hex::encode(self.body.finalize());
        pk.verify(&database_signed_message(version, &body), &Signature::from_bytes(&sig))
            .map_err(|_| Error::Signature("doesn't match the release key".into()))?;
        Ok(hex::encode(self.whole.finalize()))
    }

    /// Only that a trailer is there (for a server that wasn't given the release key: the
    /// agents check the signature anyway). Returns the SHA-256 of the whole file.
    pub fn finish_unverified(self) -> Result<String, Error> {
        if self.held.len() != TRAILER || self.held[..8] != TRAILER_MAGIC {
            return Err(Error::Signature("no signature trailer".into()));
        }
        Ok(hex::encode(self.whole.finalize()))
    }

    pub fn total(&self) -> u64 {
        self.total
    }
}

enum Backing {
    Map(memmap2::Mmap),
    Owned(Vec<u8>),
}

impl Backing {
    fn bytes(&self) -> &[u8] {
        match self {
            Backing::Map(m) => m,
            Backing::Owned(v) => v,
        }
    }
}

/// A verified database, ready for lookups.
pub struct Database {
    data: Backing,
    layout: Layout,
    meta: Meta,
    sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HashHit<'a> {
    pub name: &'a str,
    pub severity: ThreatSeverity,
}

impl Database {
    /// Verifies the file (read once in full, not through the mapping, so its pages don't stay
    /// resident), then maps it.
    pub fn open(path: &Path, pubkey_hex: &str) -> Result<Database, Error> {
        let mut f = std::fs::File::open(path)?;
        let mut v = Verifier::new();
        let mut buf = vec![0u8; 1 << 20];
        let mut head = Vec::new();
        loop {
            let n = f.read(&mut buf)?;
            if n == 0 {
                break;
            }
            if head.len() < HEAD_MAX {
                head.extend_from_slice(&buf[..n.min(HEAD_MAX - head.len())]);
            }
            v.update(&buf[..n]);
        }
        let meta = read_head(&head, v.total())?;
        let sha256 = v.finish(&meta.version, pubkey_hex)?;
        // SAFETY: the file is ours (the agent's state directory, root-only) and is never
        // written in place: a new version is a new file renamed into place, so the mapping
        // can't change under us.
        let map = unsafe { memmap2::Mmap::map(&f)? };
        Self::with(Backing::Map(map), meta, sha256)
    }

    pub fn from_bytes(bytes: Vec<u8>, pubkey_hex: &str) -> Result<Database, Error> {
        let meta = read_head(&bytes, bytes.len() as u64)?;
        let mut v = Verifier::new();
        v.update(&bytes);
        let sha256 = v.finish(&meta.version, pubkey_hex)?;
        Self::with(Backing::Owned(bytes), meta, sha256)
    }

    fn with(data: Backing, meta: Meta, sha256: String) -> Result<Database, Error> {
        let d = data.bytes();
        let layout = layout(d, d.len())?;
        if std::str::from_utf8(d.get(layout.yara.off..layout.yara.off + layout.yara.len).unwrap_or_default()).is_err() {
            return bad("YARA section isn't UTF-8");
        }
        Ok(Database { data, layout, meta, sha256 })
    }

    /// A file whose signature was checked when it arrived (the server's own store, where an
    /// upload without a configured release key is only checked for its trailer).
    pub fn from_checked_bytes(bytes: Vec<u8>) -> Result<Database, Error> {
        let meta = read_head(&bytes, bytes.len() as u64)?;
        let mut v = Verifier::new();
        v.update(&bytes);
        let sha256 = v.finish_unverified()?;
        Self::with(Backing::Owned(bytes), meta, sha256)
    }

    /// Every SHA-256 signature, in table order, with its name and severity.
    pub fn sha256_entries(&self) -> impl Iterator<Item = ([u8; 32], HashHit<'_>)> + '_ {
        (0..self.layout.sha256.count).filter_map(move |i| {
            let rec = self.record(self.layout.sha256, 20, i);
            let mut d = [0u8; 32];
            d[..16].copy_from_slice(rec.get(..16)?);
            d[16..].copy_from_slice(self.record(self.layout.sha256_tail, 16, i).get(..16)?);
            Some((d, self.entry(u32le(rec, 16)?)?))
        })
    }

    pub fn version(&self) -> &str {
        &self.meta.version
    }

    pub fn meta(&self) -> &Meta {
        &self.meta
    }

    /// Of the whole file.
    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    pub fn wants_md5(&self) -> bool {
        self.layout.md5.count > 0
    }

    pub fn wants_sha1(&self) -> bool {
        self.layout.sha1.count > 0
    }

    pub fn yara_source(&self) -> &str {
        let r = self.layout.yara;
        self.data.bytes().get(r.off..r.off + r.len).and_then(|b| std::str::from_utf8(b).ok()).unwrap_or_default()
    }

    fn record(&self, r: Range, stride: usize, i: usize) -> &[u8] {
        let at = r.off + i * stride;
        self.data.bytes().get(at..at + stride).unwrap_or_default()
    }

    /// Binary search for `key` over the first `key.len()` bytes of each record.
    fn search(&self, r: Range, stride: usize, key: &[u8]) -> Option<usize> {
        let (mut lo, mut hi) = (0usize, r.count);
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            match self.record(r, stride, mid).get(..key.len())?.cmp(key) {
                std::cmp::Ordering::Less => lo = mid + 1,
                std::cmp::Ordering::Greater => hi = mid,
                std::cmp::Ordering::Equal => return Some(mid),
            }
        }
        None
    }

    fn entry(&self, i: u32) -> Option<HashHit<'_>> {
        let e = self.record(self.layout.entries, 8, i as usize);
        let off = u32le(e, 0)? as usize;
        let len = u16::from_le_bytes(e.get(4..6)?.try_into().ok()?) as usize;
        let names = self.layout.names;
        let name = self.data.bytes().get(names.off + off..(names.off + off + len).min(names.off + names.len))?;
        Some(HashHit { name: std::str::from_utf8(name).ok()?, severity: severity_from(*e.get(6)?) })
    }

    pub fn lookup_sha256(&self, d: &[u8; 32]) -> Option<HashHit<'_>> {
        let i = self.search(self.layout.sha256, 20, &d[..16])?;
        if self.record(self.layout.sha256_tail, 16, i) != &d[16..] {
            return None;
        }
        self.entry(u32le(self.record(self.layout.sha256, 20, i), 16)?)
    }

    /// `size` None: any (an operator's lookup by hash alone).
    fn sized(&self, r: Range, stride: usize, key: &[u8], size: Option<u64>) -> Option<HashHit<'_>> {
        let i = self.search(r, stride, key)?;
        // Equal hashes are adjacent; ClamAV has one size per hash in practice.
        let rec = self.record(r, stride, i);
        let want = u64le(rec, key.len() + 4)?;
        if want != 0 && size.is_some_and(|s| s != want) {
            return None;
        }
        self.entry(u32le(rec, key.len())?)
    }

    pub fn lookup_md5(&self, d: &[u8; 16], size: Option<u64>) -> Option<HashHit<'_>> {
        self.sized(self.layout.md5, 28, d, size)
    }

    pub fn lookup_sha1(&self, d: &[u8; 20], size: Option<u64>) -> Option<HashHit<'_>> {
        self.sized(self.layout.sha1, 32, d, size)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    pub const SEED: [u8; 32] = [5u8; 32];

    pub fn pubkey() -> String {
        hex::encode(SigningKey::from_bytes(&SEED).verifying_key().as_bytes())
    }

    pub fn sealed(b: Builder) -> Vec<u8> {
        let version = b.meta.version.clone();
        let key = SigningKey::from_bytes(&SEED);
        seal(b.build().unwrap(), &version, |m| key.sign(m).to_bytes())
    }

    fn sha(s: &[u8]) -> [u8; 32] {
        Sha256::digest(s).into()
    }

    #[test]
    fn build_sign_load_lookup() {
        let mut b = Builder::new("2026.11.15.1", "test");
        for i in 0..1000u32 {
            b.add_hash(HashSig { algo: Algo::Sha256, digest: sha(&i.to_le_bytes()).to_vec(), size: None, name: format!("Family.{}", i % 7), severity: ThreatSeverity::High });
        }
        b.add_hash(HashSig { algo: Algo::Sha256, digest: sha(b"dup").to_vec(), size: None, name: "First".into(), severity: ThreatSeverity::Low });
        b.add_hash(HashSig { algo: Algo::Sha256, digest: sha(b"dup").to_vec(), size: None, name: "Second".into(), severity: ThreatSeverity::Low });
        b.add_hash(HashSig { algo: Algo::Md5, digest: md5::Md5::digest(b"m").to_vec(), size: Some(1), name: "Clam.M".into(), severity: ThreatSeverity::Moderate });
        b.add_hash(HashSig { algo: Algo::Sha1, digest: sha1::Sha1::digest(b"s").to_vec(), size: None, name: "Clam.S".into(), severity: ThreatSeverity::Severe });
        b.add_yara("rule x { condition: true }");
        let file = sealed(b);
        let db = Database::from_bytes(file.clone(), &pubkey()).unwrap();
        assert_eq!((db.meta().sha256, db.meta().md5, db.meta().sha1), (1001, 1, 1));
        assert_eq!(db.lookup_sha256(&sha(&5u32.to_le_bytes())), Some(HashHit { name: "Family.5", severity: ThreatSeverity::High }));
        assert_eq!(db.lookup_sha256(&sha(b"dup")).unwrap().name, "First", "duplicates: the first wins");
        assert!(db.lookup_sha256(&sha(b"absent")).is_none());
        // Same first 16 bytes, different tail: not a hit.
        let mut near = sha(&5u32.to_le_bytes());
        near[31] ^= 1;
        assert!(db.lookup_sha256(&near).is_none());
        let m: [u8; 16] = md5::Md5::digest(b"m").into();
        assert!(db.lookup_md5(&m, Some(1)).is_some() && db.lookup_md5(&m, Some(2)).is_none() && db.lookup_md5(&m, None).is_some(), "size must match");
        let s: [u8; 20] = sha1::Sha1::digest(b"s").into();
        assert_eq!(db.lookup_sha1(&s, Some(99)).unwrap().severity, ThreatSeverity::Severe);
        assert_eq!(db.yara_source(), "rule x { condition: true }\n");
        let all: Vec<([u8; 32], HashHit)> = db.sha256_entries().collect();
        assert_eq!(all.len(), 1001);
        assert!(all.iter().all(|(d, h)| db.lookup_sha256(d) == Some(*h)), "every entry reads back with its full hash");
        assert_eq!(Database::from_checked_bytes(file.clone()).unwrap().sha256_entries().count(), 1001);
        assert!(db.wants_md5() && db.wants_sha1());
        // Through a file and the mapping.
        let p = std::env::temp_dir().join(format!("rmm-db-{}.rmmdb", std::process::id()));
        std::fs::write(&p, &file).unwrap();
        let mapped = Database::open(&p, &pubkey()).unwrap();
        assert_eq!(mapped.lookup_sha256(&sha(&999u32.to_le_bytes())).unwrap().name, "Family.5");
        assert_eq!(mapped.sha256(), hex::encode(Sha256::digest(&file)));
        std::fs::remove_file(&p).unwrap();
        // The head alone gives the server what it needs.
        assert_eq!(read_head(&file[..file.len().min(4096)], file.len() as u64).unwrap().version, "2026.11.15.1");
    }

    #[test]
    fn tampering_and_wrong_keys_are_refused() {
        let mut b = Builder::new("v1", "");
        b.add_hash(HashSig { algo: Algo::Sha256, digest: sha(b"x").to_vec(), size: None, name: "X".into(), severity: ThreatSeverity::High });
        let file = sealed(b);
        let mut t = file.clone();
        let n = t.len() - TRAILER - 1;
        t[n] ^= 1;
        assert!(matches!(Database::from_bytes(t, &pubkey()), Err(Error::Signature(_))));
        let other = hex::encode(SigningKey::from_bytes(&[6u8; 32]).verifying_key().as_bytes());
        assert!(Database::from_bytes(file.clone(), &other).is_err());
        assert!(Database::from_bytes(file[..file.len() - 1].to_vec(), &pubkey()).is_err(), "truncated");
        // Signed for another version than META says: refused.
        let body = Builder::new("v1", "").build().unwrap();
        let key = SigningKey::from_bytes(&SEED);
        let wrong = seal(body, "v2", |m| key.sign(m).to_bytes());
        assert!(Database::from_bytes(wrong, &pubkey()).is_err());
    }

    #[test]
    fn hostile_input_never_panics() {
        let mut b = Builder::new("v1", "");
        b.add_hash(HashSig { algo: Algo::Sha256, digest: sha(b"x").to_vec(), size: None, name: "X".into(), severity: ThreatSeverity::High });
        b.add_hash(HashSig { algo: Algo::Md5, digest: vec![1; 16], size: None, name: "M".into(), severity: ThreatSeverity::High });
        let body = b.build().unwrap();
        // The structure is checked before the signature matters: parse the unsigned layout
        // and look up through it as if it had been signed.
        crate::fuzz::mutate(&[&body], 5000, |d| {
            let total = d.len() + TRAILER;
            if let Ok(l) = layout(d, total) {
                let mut file = d.to_vec();
                file.extend_from_slice(&[0u8; TRAILER]);
                let db = Database { data: Backing::Owned(file), layout: l, meta: read_head(d, total as u64).unwrap_or_else(|_| Builder::new("x", "").meta), sha256: String::new() };
                let _ = db.lookup_sha256(&sha(b"x"));
                let _ = db.lookup_md5(&[1; 16], Some(0));
                let _ = db.lookup_sha1(&[1; 20], None);
                let _ = db.yara_source();
            }
        });
    }
}
