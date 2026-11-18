//! `build-db` and `inspect-db`: the signature database, built from local feed files.
//!
//! Feeds are read from files the operator downloaded; nothing is fetched here, and which
//! feeds an MSP may use commercially is theirs to check (each rule keeps its licence meta).
//!
//! - `--rules DIR`: the first-party set: `DIR/*.yar`, `DIR/*.sha256`, and the samples each
//!   rule must pass (`DIR/samples/<rule id>/match-*` and `clean-*`; a `.hex` name is
//!   hex-decoded first, for samples that would trip other scanners as files) plus benign
//!   files no rule may match (`DIR/benign/`).
//! - `--sha256 FILE`: one hash per line, optionally followed by a name; `#` comments, and a
//!   `# severity: low` line sets the severity of the lines after it. MalwareBazaar's CSV
//!   export is recognised by its header (the name is its `signature` column).
//! - `--yara FILE|DIR`: YARA rules (YARA Forge packages, say). Namespace: the file's name.
//! - `--clamav FILE`: ClamAV `.hdb` (`md5:size:name`) and `.hsb` (`sha1-or-sha256:size:name`,
//!   size `*` for any).
//! - `--benign DIR`: real software (`/usr/bin`, `C:\Windows\System32`): nothing but
//!   heuristics may match there.
//!
//! Every rule's samples and the benign files are scanned with the engine the sensor runs,
//! from a database signed with a throwaway key; any failure refuses the build.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use ed25519_dalek::{Signer, SigningKey};
use rmm_proto::security::{RuleMode, ThreatSeverity};
use rmm_scan::db::{Algo, Builder, Database, HashSig, RuleInfo, SourceInfo};
use rmm_scan::rules::NAMESPACE_MARKER;
use rmm_scan::{Engine, Limits};
use sha2::{Digest, Sha256};

pub struct BuildArgs {
    pub version: String,
    pub description: String,
    pub rules: Vec<PathBuf>,
    pub sha256: Vec<PathBuf>,
    pub yara: Vec<PathBuf>,
    pub clamav: Vec<PathBuf>,
    pub benign: Vec<PathBuf>,
    pub severity: ThreatSeverity,
}

fn parse_hex<const N: usize>(s: &str) -> Option<[u8; N]> {
    hex::decode(s.trim()).ok()?.try_into().ok()
}

/// A plain hash list, or MalwareBazaar's CSV export.
pub fn read_sha256_list(text: &str, default_name: &str, severity: ThreatSeverity) -> Result<Vec<HashSig>> {
    let mut out = Vec::new();
    let mut sev = severity;
    let mut csv_cols: Option<(usize, Option<usize>)> = None;
    for (n, line) in text.lines().enumerate() {
        let l = line.trim();
        if let Some(c) = l.strip_prefix('#') {
            let c = c.trim();
            if let Some(s) = c.strip_prefix("severity:") {
                sev = rmm_scan::rules::severity(s).with_context(|| format!("line {}: unknown severity {s:?}", n + 1))?;
            }
            // MalwareBazaar's CSV header is a comment line naming the columns.
            if c.contains("sha256_hash") {
                let cols: Vec<String> = c.split(',').map(|x| x.trim().trim_matches('"').to_string()).collect();
                csv_cols = cols.iter().position(|x| x == "sha256_hash").map(|h| (h, cols.iter().position(|x| x == "signature")));
            }
            continue;
        }
        if l.is_empty() {
            continue;
        }
        let (hash, name) = if let Some((h, s)) = csv_cols {
            let cols: Vec<&str> = l.split("\", \"").map(|x| x.trim().trim_matches('"')).collect();
            let sig = s.and_then(|i| cols.get(i)).filter(|x| !x.is_empty() && **x != "n/a").map(|x| format!("MalwareBazaar: {x}"));
            (cols.get(h).copied().unwrap_or_default().to_string(), sig.unwrap_or_else(|| default_name.to_string()))
        } else {
            let mut it = l.splitn(2, [' ', '\t', ',']);
            let h = it.next().unwrap_or_default().to_string();
            let name = it.next().map(str::trim).filter(|s| !s.is_empty()).unwrap_or(default_name).to_string();
            (h, name)
        };
        let d: [u8; 32] = parse_hex(&hash).with_context(|| format!("line {}: {hash:?} isn't a SHA-256", n + 1))?;
        out.push(HashSig { algo: Algo::Sha256, digest: d.to_vec(), size: None, name, severity: sev });
    }
    Ok(out)
}

/// ClamAV `.hdb` (MD5) or `.hsb` (SHA-1 or SHA-256).
pub fn read_clamav(text: &str, severity: ThreatSeverity) -> Result<Vec<HashSig>> {
    let mut out = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let l = line.trim();
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        let f: Vec<&str> = l.split(':').collect();
        let (Some(h), Some(size), Some(name)) = (f.first(), f.get(1), f.get(2)) else { bail!("line {}: expected hash:size:name", n + 1) };
        let size = if *size == "*" { None } else { Some(size.parse::<u64>().with_context(|| format!("line {}: bad size {size:?}", n + 1))?) };
        let algo = match h.len() {
            32 => Algo::Md5,
            40 => Algo::Sha1,
            64 => Algo::Sha256,
            _ => bail!("line {}: {h:?} isn't an MD5, SHA-1 or SHA-256", n + 1),
        };
        let digest = hex::decode(h).with_context(|| format!("line {}: bad hex", n + 1))?;
        out.push(HashSig { algo, digest, size, name: format!("ClamAV: {name}"), severity });
    }
    Ok(out)
}

fn yara_files(p: &Path) -> Result<Vec<PathBuf>> {
    if p.is_dir() {
        let mut v: Vec<PathBuf> = std::fs::read_dir(p)?
            .flatten()
            .map(|e| e.path())
            .filter(|f| f.extension().is_some_and(|x| x.eq_ignore_ascii_case("yar") || x.eq_ignore_ascii_case("yara")))
            .collect();
        v.sort();
        Ok(v)
    } else {
        Ok(vec![p.to_path_buf()])
    }
}

fn stem(p: &Path) -> String {
    p.file_stem().map(|s| s.to_string_lossy().chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' }).collect()).unwrap_or_else(|| "rules".into())
}

fn read_sample(p: &Path) -> Result<Vec<u8>> {
    let raw = std::fs::read(p).with_context(|| format!("reading {}", p.display()))?;
    if p.extension().is_some_and(|e| e == "hex") {
        let clean: String = String::from_utf8_lossy(&raw).chars().filter(|c| c.is_ascii_hexdigit()).collect();
        return hex::decode(clean).with_context(|| format!("{}: bad hex", p.display()));
    }
    Ok(raw)
}

fn walk(root: &Path, out: &mut Vec<PathBuf>, limit: usize) {
    let mut stack = vec![root.to_path_buf()];
    while let Some(p) = stack.pop() {
        if out.len() >= limit {
            return;
        }
        let Ok(md) = std::fs::symlink_metadata(&p) else { continue };
        if md.is_dir() {
            for e in std::fs::read_dir(&p).into_iter().flatten().flatten() {
                stack.push(e.path());
            }
        } else if md.is_file() && md.len() > 0 {
            out.push(p);
        }
    }
}

fn digest(v: &serde_json::Value) -> String {
    hex::encode(Sha256::digest(v.to_string().as_bytes()))[..16].to_string()
}

pub struct Built {
    pub file: Vec<u8>,
    pub meta: rmm_scan::db::Meta,
    pub tests: usize,
    pub benign_files: usize,
    pub heuristic_hits: Vec<String>,
}

pub fn build(a: &BuildArgs, key: Option<&SigningKey>) -> Result<Built> {
    let mut b = Builder::new(&a.version, &a.description);
    let mut sources = Vec::new();
    let mut first_party_sources = Vec::new();
    // (namespace, source, first party?)
    let mut yara: Vec<(String, String, bool)> = Vec::new();
    let add_hashes = |b: &mut Builder, sources: &mut Vec<SourceInfo>, name: String, kind: &str, h: Vec<HashSig>| {
        sources.push(SourceInfo { name, kind: kind.into(), entries: h.len() as u64 });
        for x in h {
            b.add_hash(x);
        }
    };
    for dir in &a.rules {
        for f in yara_files(dir)? {
            let src = std::fs::read_to_string(&f).with_context(|| format!("reading {}", f.display()))?;
            first_party_sources.push(f.clone());
            yara.push((format!("rmm-{}", stem(&f)), src, true));
            sources.push(SourceInfo { name: f.display().to_string(), kind: "yara".into(), entries: 0 });
        }
        let mut lists: Vec<PathBuf> = std::fs::read_dir(dir)?.flatten().map(|e| e.path()).filter(|p| p.extension().is_some_and(|x| x == "sha256")).collect();
        lists.sort();
        for l in lists {
            let h = read_sha256_list(&std::fs::read_to_string(&l)?, &stem(&l), a.severity).with_context(|| l.display().to_string())?;
            add_hashes(&mut b, &mut sources, l.display().to_string(), "sha256-list", h);
        }
    }
    for l in &a.sha256 {
        let h = read_sha256_list(&std::fs::read_to_string(l).with_context(|| format!("reading {}", l.display()))?, &stem(l), a.severity)
            .with_context(|| l.display().to_string())?;
        add_hashes(&mut b, &mut sources, l.display().to_string(), "sha256-list", h);
    }
    for c in &a.clamav {
        let h = read_clamav(&std::fs::read_to_string(c).with_context(|| format!("reading {}", c.display()))?, a.severity).with_context(|| c.display().to_string())?;
        let kind = if c.extension().is_some_and(|e| e == "hdb") { "clamav-hdb" } else { "clamav-hsb" };
        add_hashes(&mut b, &mut sources, c.display().to_string(), kind, h);
    }
    for y in &a.yara {
        for f in yara_files(y)? {
            let src = std::fs::read_to_string(&f).with_context(|| format!("reading {}", f.display()))?;
            yara.push((stem(&f), src, false));
            sources.push(SourceInfo { name: f.display().to_string(), kind: "yara".into(), entries: 0 });
        }
    }
    let mut seen_ns = HashSet::new();
    for (ns, _, _) in &yara {
        if !seen_ns.insert(ns.clone()) {
            bail!("two rule files would share the namespace {ns}; rename one");
        }
    }

    // Compile each file alone first, so an error names the file.
    let timeout = std::time::Duration::from_secs(10);
    let mut rules: Vec<RuleInfo> = Vec::new();
    let mut ids: HashSet<String> = rmm_scan::heuristic_rules().into_iter().map(|r| r.id).collect();
    let mut first_party_ids = Vec::new();
    for (i, (ns, src, first)) in yara.iter().enumerate() {
        if src.contains(NAMESPACE_MARKER) {
            bail!("namespace {ns}: the text {NAMESPACE_MARKER:?} is reserved");
        }
        let compiled = rmm_scan::rules::Rules::compile(&[(ns.clone(), src.clone())], timeout).map_err(|e| anyhow::anyhow!("{ns}: {e}"))?;
        let mut metas: Vec<_> = compiled.all().cloned().collect();
        metas.sort_by(|a, b| a.id.cmp(&b.id));
        if let Some(s) = sources.iter_mut().filter(|s| s.kind == "yara").nth(i) {
            s.entries = metas.len() as u64;
        }
        for m in metas {
            if !ids.insert(m.id.clone()) {
                bail!("rule id {} appears twice", m.id);
            }
            if m.mode == RuleMode::Block && m.confidence != rmm_content::Confidence::High {
                bail!("{}: only high-confidence rules can block", m.id);
            }
            if *first {
                first_party_ids.push(m.id.clone());
            }
            let v = serde_json::json!({ "src": src, "id": m.id, "sev": m.severity, "mode": m.mode, "conf": m.confidence });
            rules.push(RuleInfo {
                id: m.id.clone(),
                name: m.name.clone(),
                kind: "yara".into(),
                severity: m.severity,
                confidence: m.confidence,
                mode: m.mode,
                mitre: m.mitre.clone(),
                description: m.description.clone(),
                digest: digest(&v),
                source: Some(ns.clone()),
                licence: m.licence.clone(),
                author: m.author.clone(),
                reference: m.reference.clone(),
            });
        }
    }
    for (ns, src, _) in &yara {
        b.add_yara(&format!("{NAMESPACE_MARKER}{ns}\n{src}"));
    }
    b.meta.yara_rules = rules.len() as u64;
    rules.extend(rmm_scan::heuristic_rules());
    b.meta.rules = rules;
    b.meta.sources = sources;
    let meta = b.meta.clone();
    let yara_text = b.yara().to_string();
    let body = b.build()?;

    // Test with the engine the sensor runs, from a database sealed with a throwaway key: the
    // rules alone for the samples (a sample's hash being listed would hide the rule), the
    // whole database for the benign files.
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).map_err(|e| anyhow::anyhow!("OS RNG: {e}"))?;
    let temp = SigningKey::from_bytes(&seed);
    let temp_pk = hex::encode(temp.verifying_key().as_bytes());
    let seal = |body: Vec<u8>, k: &SigningKey| rmm_scan::db::seal(body, &a.version, |m| k.sign(m).to_bytes());
    let mut rules_only = Builder::new(&a.version, "");
    rules_only.add_yara(&yara_text);
    let rules_db = Database::from_bytes(seal(rules_only.build()?, &temp), &temp_pk)?;
    let rules_engine = Engine::new(Some(Arc::new(rules_db)), None, Limits::default()).map_err(anyhow::Error::msg)?;
    let mut failures = Vec::new();
    let mut tests = 0;
    for dir in &a.rules {
        let samples = dir.join("samples");
        for id in &first_party_ids {
            let d = samples.join(id);
            let mut files: Vec<PathBuf> = std::fs::read_dir(&d).into_iter().flatten().flatten().map(|e| e.path()).collect();
            files.sort();
            let name = |p: &Path| p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
            let (pos, neg): (Vec<&PathBuf>, Vec<&PathBuf>) = files.iter().filter(|p| name(p).starts_with("match-") || name(p).starts_with("clean-")).partition(|p| name(p).starts_with("match-"));
            if pos.is_empty() || neg.is_empty() {
                failures.push(format!("{id}: needs a match-* and a clean-* sample in {}", d.display()));
                continue;
            }
            for (p, expect) in pos.iter().map(|p| (p, true)).chain(neg.iter().map(|p| (p, false))) {
                tests += 1;
                let data = read_sample(p)?;
                let v = rules_engine.scan_bytes(&data, &rmm_scan::Context { path: Some(&p.to_string_lossy()) });
                let hit = v.matches.iter().any(|m| &m.id == id);
                if hit != expect {
                    failures.push(format!("{id}: {} should {}match", p.display(), if expect { "" } else { "not " }));
                }
            }
        }
    }
    let full_db = Database::from_bytes(seal(body.clone(), &temp), &temp_pk)?;
    let engine = Engine::new(Some(Arc::new(full_db)), None, Limits::default()).map_err(anyhow::Error::msg)?;
    let mut benign = Vec::new();
    for dir in &a.rules {
        walk(&dir.join("benign"), &mut benign, 1_000_000);
    }
    for dir in &a.benign {
        walk(dir, &mut benign, 1_000_000);
    }
    let mut heuristic_hits = Vec::new();
    for p in &benign {
        let Ok(v) = engine.scan_path(p) else { continue };
        for m in &v.matches {
            let what = format!("{} ({}) on {}{}", m.id, m.name, p.display(), m.part.as_ref().map(|x| format!(" in {x}")).unwrap_or_default());
            if m.kind == rmm_scan::Kind::Heuristic {
                heuristic_hits.push(what);
            } else {
                failures.push(format!("false positive: {what}"));
            }
        }
    }
    if !failures.is_empty() {
        let shown: Vec<&String> = failures.iter().take(50).collect();
        bail!("{} problem(s); not writing the database:\n  {}", failures.len(), shown.iter().map(|s| s.as_str()).collect::<Vec<_>>().join("\n  "));
    }
    // The counts are worked out while the body is written.
    let meta = rmm_scan::db::read_head(&body, (body.len() + rmm_scan::db::TRAILER) as u64).unwrap_or(meta);
    let file = match key {
        Some(k) => seal(body, k),
        None => body,
    };
    Ok(Built { file, meta, tests, benign_files: benign.len(), heuristic_hits })
}

pub fn inspect(path: &Path, pubkey: Option<&str>, lookup: &[String], rules: bool) -> Result<()> {
    let raw = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let meta = rmm_scan::db::read_head(&raw, raw.len() as u64)?;
    println!("{}: signature database {} ({} bytes, sha256 {})", path.display(), meta.version, raw.len(), hex::encode(Sha256::digest(&raw)));
    println!("  created {}{}", meta.created_at.to_rfc3339(), if meta.description.is_empty() { String::new() } else { format!(": {}", meta.description) });
    println!("  hashes: {} SHA-256, {} MD5, {} SHA-1; {} YARA rules", meta.sha256, meta.md5, meta.sha1, meta.yara_rules);
    for s in &meta.sources {
        println!("  source {} ({}): {} entries", s.name, s.kind, s.entries);
    }
    if rules {
        for r in &meta.rules {
            println!("  rule {:<24} {:<9} {:<8} {:<6} {}{}", r.id, r.kind, r.severity.as_str(), r.mode.as_str(), r.name, r.licence.as_ref().map(|l| format!(" [{l}]")).unwrap_or_default());
        }
    }
    match pubkey {
        Some(pk) => {
            let db = Database::from_bytes(raw, pk)?;
            println!("  signature: ok ({pk})");
            for h in lookup {
                let hit = match h.len() {
                    64 => parse_hex::<32>(h).and_then(|d| db.lookup_sha256(&d).map(|x| x.name.to_string())),
                    32 => parse_hex::<16>(h).and_then(|d| db.lookup_md5(&d, None).map(|x| x.name.to_string())),
                    40 => parse_hex::<20>(h).and_then(|d| db.lookup_sha1(&d, None).map(|x| x.name.to_string())),
                    _ => None,
                };
                println!("  {h}: {}", hit.as_deref().unwrap_or("not listed"));
            }
        }
        None => println!("  signature: not checked (pass --pubkey)"),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn feed_formats() {
        let list = "# from a test\n275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f EICAR test file\n# severity: low\n\
                    ab00000000000000000000000000000000000000000000000000000000000000\n";
        let h = read_sha256_list(list, "list", ThreatSeverity::High).unwrap();
        assert_eq!((h[0].name.as_str(), h[0].severity), ("EICAR test file", ThreatSeverity::High));
        assert_eq!((h[1].name.as_str(), h[1].severity), ("list", ThreatSeverity::Low));
        assert!(read_sha256_list("nothex\n", "x", ThreatSeverity::High).is_err());
        let csv = "################\n# \"first_seen_utc\",\"sha256_hash\",\"md5_hash\",\"signature\"\n\
                   \"2026-11-01 00:00:00\", \"cd00000000000000000000000000000000000000000000000000000000000000\", \"x\", \"AgentTesla\"\n\
                   \"2026-11-01 00:00:01\", \"ef00000000000000000000000000000000000000000000000000000000000000\", \"x\", \"n/a\"\n";
        let h = read_sha256_list(csv, "malwarebazaar", ThreatSeverity::High).unwrap();
        assert_eq!(h.iter().map(|x| x.name.as_str()).collect::<Vec<_>>(), ["MalwareBazaar: AgentTesla", "malwarebazaar"]);
        assert_eq!(h[0].digest[0], 0xcd);
        let clam = "44d88612fea8a8f36de82e1278abb02f:68:Eicar-Test-Signature\n\
                    3395856ce81f2b7382dee72602f798b642f14140:*:Win.Test.Sha1\n\
                    275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f:68:Win.Test.Sha256:73\n";
        let h = read_clamav(clam, ThreatSeverity::High).unwrap();
        assert_eq!(h.iter().map(|x| (x.algo, x.size)).collect::<Vec<_>>(), [(Algo::Md5, Some(68)), (Algo::Sha1, None), (Algo::Sha256, Some(68))]);
        assert_eq!(h[0].name, "ClamAV: Eicar-Test-Signature");
        assert!(read_clamav("zz:1:x\n", ThreatSeverity::High).is_err());
    }

    fn content_dir() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../content")
    }

    #[test]
    fn first_party_rules_pass_their_samples() {
        let dir = std::env::temp_dir().join(format!("rmm-sign-db-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let feeds = content_dir().join("feeds-example");
        let a = BuildArgs {
            version: "test.1".into(),
            description: "test".into(),
            rules: vec![content_dir().join("yara")],
            sha256: vec![feeds.join("malwarebazaar.csv"), feeds.join("plain.sha256")],
            yara: vec![feeds.join("forge-example.yar")],
            clamav: vec![feeds.join("example.hdb"), feeds.join("example.hsb")],
            benign: vec![],
            severity: ThreatSeverity::High,
        };
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let built = build(&a, Some(&key)).unwrap();
        assert!(built.tests >= 20, "{}", built.tests);
        let db = Database::from_bytes(built.file, &hex::encode(key.verifying_key().as_bytes())).unwrap();
        assert!(db.meta().yara_rules >= 12, "{}", db.meta().yara_rules);
        assert!(db.meta().rules.iter().any(|r| r.id == "RMM-H-0001" && r.kind == "heuristic"));
        assert!(db.meta().rules.iter().any(|r| r.id.starts_with("YARA:forge-example:") && r.mode == RuleMode::Audit));
        let eicar: [u8; 32] = parse_hex("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f").unwrap();
        assert_eq!(db.lookup_sha256(&eicar).unwrap().name, "EICAR test file");
        assert!(db.wants_md5() && db.wants_sha1());
        // A rule that matches a benign file refuses the build.
        std::fs::write(dir.join("fp.yar"), "rule FP { meta: id = \"FP-1\" strings: $a = \"<?php\" condition: $a }").unwrap();
        let bad = BuildArgs { yara: vec![dir.join("fp.yar")], sha256: vec![], clamav: vec![], ..a };
        let e = build(&bad, Some(&key)).err().unwrap().to_string();
        assert!(e.contains("false positive: FP-1"), "{e}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Regression: the content shipped in this repository quotes rule strings (the starter
    /// bundle's behaviour-rule tests, the YARA sources, the bundle generator). Written to a
    /// machine with auto-quarantine on, a match that acts (block, or alert at high or severe)
    /// would move the file away; RMM-F-0002 matched `starter.json` and `offensive-tools.yar`
    /// that way until it required a Windows program header. Audit matches only report.
    #[test]
    fn rule_sources_do_not_trip_acting_rules() {
        let a = BuildArgs {
            version: "test.1".into(),
            description: "test".into(),
            rules: vec![content_dir().join("yara")],
            sha256: vec![],
            yara: vec![],
            clamav: vec![],
            benign: vec![],
            severity: ThreatSeverity::High,
        };
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let db = Arc::new(Database::from_bytes(build(&a, Some(&key)).unwrap().file, &hex::encode(key.verifying_key().as_bytes())).unwrap());
        let starter = rmm_content::Bundle::parse(rmm_content::STARTER.as_bytes()).unwrap();
        let legacy = Some((starter.version.clone(), rmm_content::files::FileMatcher::new(&starter).unwrap()));
        let engine = Engine::new(Some(db), legacy, Limits::default()).unwrap();
        let mut files: Vec<PathBuf> = std::fs::read_dir(content_dir().join("yara")).unwrap().flatten().map(|e| e.path()).filter(|p| p.is_file()).collect();
        files.extend(["starter.json", "build_starter.py", "benign.jsonl"].map(|f| content_dir().join(f)));
        let mut acting = Vec::new();
        for f in &files {
            for m in engine.scan_path(f).unwrap().matches {
                let quarantines = m.mode == RuleMode::Block || (m.mode == RuleMode::Alert && m.severity <= ThreatSeverity::High);
                if quarantines {
                    acting.push(format!("{}: {} ({:?}, {:?})", f.display(), m.id, m.mode, m.severity));
                }
            }
        }
        assert!(acting.is_empty(), "rule sources would be quarantined:\n{}", acting.join("\n"));
        // Still a match on the program itself.
        let sample = std::fs::read(content_dir().join("yara/samples/RMM-F-0002/match-program.bin")).unwrap();
        let ids: Vec<String> = engine.scan_bytes(&sample, &rmm_scan::Context::default()).matches.into_iter().map(|m| m.id).collect();
        assert!(ids.iter().filter(|i| *i == "RMM-F-0002").count() >= 1, "{ids:?}");
    }
}
