//! `rmm-sign`: create the release key and sign agent binaries for self-update.
//!
//! Run this on a build machine or in CI, never on the RMM server: the server already
//! controls agents through scripts, and the signature is what stops someone who takes over
//! the server (or the download path) from pushing their own agent binary.
//!
//! ```sh
//! rmm-sign keygen --out release.key          # prints the public key for RMM_UPDATE_PUBKEY
//! rmm-sign sign --key release.key --platform linux-x86_64 --version 0.2.0 rmm-agent-linux-x86_64
//! rmm-sign verify --pubkey <hex> rmm-agent-linux-x86_64
//! rmm-sign test-content content/starter.json      # rule tests + benign corpus
//! rmm-sign sign-content --key release.key content/starter.json   # writes starter.json.sig
//! rmm-sign build-db --key release.key --version 2026.11.15.1 --rules content/yara \
//!     --sha256 full_sha256.txt --yara yara-forge-core.yar --clamav main.hdb --benign /usr/bin --out sigs.rmmdb
//! rmm-sign inspect-db --pubkey <hex> --rules sigs.rmmdb
//! rmm-sign scan --db sigs.rmmdb --pubkey <hex> /home              # the sensor's engine, from here
//! ```
//!
//! Detection content (Phase 8) is signed with the same release key: agents only run rules
//! signed by it. `sign-content` runs the replay harness first and refuses a bundle whose rule
//! tests fail or that fires on the benign corpus.
//!
//! Signature databases (`build-db`, see [`db`]) are signed with the same key, after every
//! first-party rule has passed its samples and nothing but heuristics matched the benign files.
//!
//! The key file holds the 32-byte ed25519 seed in hex. `--key` can be omitted when
//! `RMM_UPDATE_SIGNING_KEY` holds that hex (for CI secrets).

mod db;

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rmm_proto::update::{Manifest, signed_message};
use sha2::{Digest, Sha256};

#[derive(Parser)]
#[command(name = "rmm-sign", version, about = "Sign RMM agent binaries for self-update")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Generate a new release key. Prints the public key to build agents with.
    Keygen {
        #[arg(long)]
        out: PathBuf,
    },
    /// Print the public key for an existing release key.
    Pubkey {
        #[arg(long, env = "RMM_UPDATE_SIGNING_KEY_FILE")]
        key: Option<PathBuf>,
    },
    /// Write `<binary>.update.json` next to the binary.
    Sign {
        #[arg(long, env = "RMM_UPDATE_SIGNING_KEY_FILE")]
        key: Option<PathBuf>,
        /// e.g. linux-x86_64, windows-x86_64
        #[arg(long)]
        platform: String,
        /// The version the binary reports (`rmm-agent --version`).
        #[arg(long)]
        version: String,
        binary: PathBuf,
    },
    /// Run a content bundle's rule tests and the benign corpus.
    TestContent {
        bundle: PathBuf,
        /// Extra benign events (JSON lines) on top of the built-in corpus.
        #[arg(long)]
        benign: Option<PathBuf>,
    },
    /// Test, then sign a content bundle: writes `<bundle>.sig` ({version, sha256, signature}),
    /// which the server takes together with the bundle.
    SignContent {
        #[arg(long, env = "RMM_UPDATE_SIGNING_KEY_FILE")]
        key: Option<PathBuf>,
        bundle: PathBuf,
        #[arg(long)]
        benign: Option<PathBuf>,
    },
    /// Build a signature database from local feed files, test it, and sign it.
    BuildDb {
        #[arg(long, env = "RMM_UPDATE_SIGNING_KEY_FILE")]
        key: Option<PathBuf>,
        #[arg(long)]
        version: String,
        #[arg(long, default_value = "")]
        description: String,
        #[arg(long)]
        out: PathBuf,
        /// First-party rule directories (`content/yara`): rules, hash lists, samples, benign files.
        #[arg(long)]
        rules: Vec<PathBuf>,
        /// Plain SHA-256 lists or MalwareBazaar CSV exports.
        #[arg(long)]
        sha256: Vec<PathBuf>,
        /// YARA rule files, or directories of them.
        #[arg(long)]
        yara: Vec<PathBuf>,
        /// ClamAV `.hdb` / `.hsb` hash signatures.
        #[arg(long)]
        clamav: Vec<PathBuf>,
        /// Directories of real software nothing may match (heuristics only warn).
        #[arg(long)]
        benign: Vec<PathBuf>,
        /// Severity of imported hashes that don't say.
        #[arg(long, default_value = "high")]
        severity: String,
        /// Write it without the signature trailer (for inspection; agents refuse it).
        #[arg(long)]
        unsigned: bool,
    },
    /// Show what a signature database holds, and check its signature.
    InspectDb {
        db: PathBuf,
        #[arg(long, env = "RMM_UPDATE_PUBKEY")]
        pubkey: Option<String>,
        /// List every rule.
        #[arg(long)]
        rules: bool,
        /// Look up hashes (SHA-256, MD5 or SHA-1, hex).
        #[arg(long)]
        hash: Vec<String>,
    },
    /// Scan files with the sensor's engine and a database: matches, throughput, and with
    /// `--cache` the verdict cache across runs.
    Scan {
        #[arg(long)]
        db: Option<PathBuf>,
        #[arg(long, env = "RMM_UPDATE_PUBKEY")]
        pubkey: Option<String>,
        #[arg(long)]
        cache: Option<PathBuf>,
        paths: Vec<PathBuf>,
    },
    /// Check `<binary>.update.json` against the binary and a public key.
    Verify {
        #[arg(long)]
        pubkey: String,
        binary: PathBuf,
    },
}

fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Keygen { out } => {
            if out.exists() {
                bail!("{} already exists; refusing to overwrite a release key", out.display());
            }
            let mut seed = [0u8; 32];
            getrandom::fill(&mut seed).map_err(|e| anyhow::anyhow!("OS RNG: {e}"))?;
            write_private(&out, format!("{}\n", hex::encode(seed)).as_bytes())?;
            let key = SigningKey::from_bytes(&seed);
            println!("wrote {} (keep it secret, and back it up: agents only accept updates signed by it)", out.display());
            println!("RMM_UPDATE_PUBKEY={}", hex::encode(key.verifying_key().as_bytes()));
            Ok(())
        }
        Cmd::Pubkey { key } => {
            println!("{}", hex::encode(load_key(key.as_deref())?.verifying_key().as_bytes()));
            Ok(())
        }
        Cmd::Sign { key, platform, version, binary } => {
            let key = load_key(key.as_deref())?;
            let manifest = sign(&key, &platform, &version, &std::fs::read(&binary).with_context(|| format!("reading {}", binary.display()))?);
            let out = manifest_path(&binary);
            std::fs::write(&out, serde_json::to_string_pretty(&manifest)? + "\n")?;
            println!("wrote {} ({platform} {version}, sha256 {})", out.display(), manifest.sha256);
            Ok(())
        }
        Cmd::TestContent { bundle, benign } => {
            let (_, b) = test_content(&bundle, benign.as_deref())?;
            println!("ok: {} ({} rules, {} hashes)", b.version, b.rule_count(), b.hashes.len());
            Ok(())
        }
        Cmd::SignContent { key, bundle, benign } => {
            let key = load_key(key.as_deref())?;
            let (json, b) = test_content(&bundle, benign.as_deref())?;
            let sha256 = rmm_content::Bundle::sha256(&json);
            let signature = key.sign(&rmm_proto::security::content_signed_message(&b.version, &sha256));
            let mut out = bundle.clone().into_os_string();
            out.push(".sig");
            let sig = serde_json::json!({ "version": b.version, "sha256": sha256, "signature": hex::encode(signature.to_bytes()) });
            std::fs::write(&out, serde_json::to_string_pretty(&sig)? + "\n")?;
            println!("wrote {} ({} {} rules)", PathBuf::from(out).display(), b.version, b.rule_count());
            Ok(())
        }
        Cmd::BuildDb { key, version, description, out, rules, sha256, yara, clamav, benign, severity, unsigned } => {
            let key = if unsigned { None } else { Some(load_key(key.as_deref())?) };
            let severity = rmm_scan::rules::severity(&severity).ok_or_else(|| anyhow::anyhow!("unknown severity {severity:?}"))?;
            let a = db::BuildArgs { version, description, rules, sha256, yara, clamav, benign, severity };
            let b = db::build(&a, key.as_ref())?;
            for h in b.heuristic_hits.iter().take(20) {
                eprintln!("heuristic (audit) on benign software: {h}");
            }
            std::fs::write(&out, &b.file).with_context(|| format!("writing {}", out.display()))?;
            println!(
                "wrote {} ({} bytes): {} SHA-256, {} MD5, {} SHA-1 hashes, {} YARA rules; {} sample tests and {} benign files passed{}",
                out.display(),
                b.file.len(),
                b.meta.sha256,
                b.meta.md5,
                b.meta.sha1,
                b.meta.yara_rules,
                b.tests,
                b.benign_files,
                if key.is_some() { "" } else { " (UNSIGNED)" }
            );
            Ok(())
        }
        Cmd::InspectDb { db, pubkey, rules, hash } => db::inspect(&db, pubkey.as_deref(), &hash, rules),
        Cmd::Scan { db, pubkey, cache, paths } => scan(db.as_deref(), pubkey.as_deref(), cache.as_deref(), &paths),
        Cmd::Verify { pubkey, binary } => {
            let raw = std::fs::read_to_string(manifest_path(&binary)).context("reading manifest")?;
            let manifest: Manifest = serde_json::from_str(&raw)?;
            verify(&pubkey, &manifest, &std::fs::read(&binary)?)?;
            println!("ok: {} {} signed by {pubkey}", manifest.platform, manifest.version);
            Ok(())
        }
    }
}

fn scan(db: Option<&Path>, pubkey: Option<&str>, cache: Option<&Path>, paths: &[PathBuf]) -> Result<()> {
    let loaded = std::time::Instant::now();
    let db = match db {
        Some(p) => Some(std::sync::Arc::new(rmm_scan::db::Database::open(p, pubkey.context("--pubkey is needed with --db")?)?)),
        None => None,
    };
    let engine = rmm_scan::Engine::new(db, None, rmm_scan::Limits::default()).map_err(anyhow::Error::msg)?;
    eprintln!("engine ready in {:.2}s ({} YARA rules)", loaded.elapsed().as_secs_f64(), engine.yara_rules());
    let mut vc = cache.map(|p| rmm_scan::cache::Cache::load(p, rmm_scan::cache::generation(&[&engine.generation()]), 1_000_000));
    let started = std::time::Instant::now();
    let (mut files, mut bytes, mut skipped, mut found) = (0u64, 0u64, 0u64, 0u64);
    let mut stack: Vec<PathBuf> = paths.to_vec();
    while let Some(p) = stack.pop() {
        let Ok(md) = std::fs::symlink_metadata(&p) else { continue };
        if md.is_dir() {
            stack.extend(std::fs::read_dir(&p).into_iter().flatten().flatten().map(|e| e.path()));
            continue;
        }
        if !md.is_file() {
            continue;
        }
        let key = rmm_scan::cache::key(&p, &md);
        if let (Some(c), Some(k)) = (vc.as_mut(), key)
            && c.clean(&k)
        {
            skipped += 1;
            continue;
        }
        let Ok(v) = engine.scan_path(&p) else { continue };
        files += 1;
        bytes += v.size;
        if v.clean() {
            if let (Some(c), Some(k)) = (vc.as_mut(), key) {
                c.insert(k);
            }
        } else {
            found += 1;
            for m in &v.matches {
                println!("{}: {} {} ({}){}", p.display(), m.id, m.name, m.mode.as_str(), m.part.as_ref().map(|x| format!(" in {x}")).unwrap_or_default());
            }
        }
    }
    let secs = started.elapsed().as_secs_f64();
    if let Some(c) = vc.as_mut() {
        c.save()?;
    }
    eprintln!(
        "{files} files read ({:.1} MB), {skipped} unchanged (cache), {found} with matches, in {secs:.2}s: {:.1} MB/s, {:.0} files/s",
        bytes as f64 / 1e6,
        bytes as f64 / 1e6 / secs.max(1e-9),
        (files + skipped) as f64 / secs.max(1e-9)
    );
    Ok(())
}

fn test_content(path: &Path, extra: Option<&Path>) -> Result<(Vec<u8>, rmm_content::Bundle)> {
    let json = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let b = rmm_content::Bundle::parse(&json)?;
    let mut benign = rmm_content::test::benign_corpus();
    if let Some(p) = extra {
        benign.extend(rmm_content::test::parse_events(&std::fs::read_to_string(p).with_context(|| format!("reading {}", p.display()))?));
    }
    let report = rmm_content::test::run(&b, &benign);
    eprintln!("{}", report.summary());
    if !report.ok() {
        bail!("content tests failed; not signing");
    }
    Ok((json, b))
}

fn manifest_path(binary: &Path) -> PathBuf {
    let mut name = binary.file_name().unwrap_or_default().to_os_string();
    name.push(".update.json");
    binary.with_file_name(name)
}

fn sign(key: &SigningKey, platform: &str, version: &str, binary: &[u8]) -> Manifest {
    let sha256 = hex::encode(Sha256::digest(binary));
    let signature = key.sign(&signed_message(platform, version, &sha256));
    Manifest { platform: platform.into(), version: version.into(), sha256, signature: hex::encode(signature.to_bytes()) }
}

fn verify(pubkey_hex: &str, m: &Manifest, binary: &[u8]) -> Result<()> {
    let pk: [u8; 32] = hex::decode(pubkey_hex.trim())?.try_into().map_err(|_| anyhow::anyhow!("public key must be 32 bytes"))?;
    let pk = VerifyingKey::from_bytes(&pk)?;
    let actual = hex::encode(Sha256::digest(binary));
    if actual != m.sha256.to_ascii_lowercase() {
        bail!("binary sha256 {actual} doesn't match the manifest ({})", m.sha256);
    }
    let sig: [u8; 64] = hex::decode(&m.signature)?.try_into().map_err(|_| anyhow::anyhow!("signature must be 64 bytes"))?;
    pk.verify(&signed_message(&m.platform, &m.version, &m.sha256), &Signature::from_bytes(&sig))
        .context("bad signature")?;
    Ok(())
}

fn load_key(path: Option<&Path>) -> Result<SigningKey> {
    let raw = match path {
        Some(p) => std::fs::read_to_string(p).with_context(|| format!("reading {}", p.display()))?,
        None => std::env::var("RMM_UPDATE_SIGNING_KEY").context("pass --key or set RMM_UPDATE_SIGNING_KEY")?,
    };
    let seed: [u8; 32] =
        hex::decode(raw.trim()).context("key must be hex")?.try_into().map_err(|_| anyhow::anyhow!("key must be 32 bytes"))?;
    Ok(SigningKey::from_bytes(&seed))
}

#[cfg(unix)]
fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)?;
    f.write_all(data)?;
    Ok(())
}

#[cfg(not(unix))]
fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    Ok(std::fs::write(path, data)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_then_verify() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let pk = hex::encode(key.verifying_key().as_bytes());
        let m = sign(&key, "linux-x86_64", "0.2.0", b"binary");
        verify(&pk, &m, b"binary").unwrap();
        assert!(verify(&pk, &m, b"tampered").is_err());
        assert!(verify(&pk, &Manifest { version: "9.9.9".into(), ..m.clone() }, b"binary").is_err(), "version is signed");
        assert!(verify(&pk, &Manifest { platform: "windows-x86_64".into(), ..m.clone() }, b"binary").is_err());
        let other = hex::encode(SigningKey::from_bytes(&[8u8; 32]).verifying_key().as_bytes());
        assert!(verify(&other, &m, b"binary").is_err());
    }
}
