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
//! ```
//!
//! The key file holds the 32-byte ed25519 seed in hex. `--key` can be omitted when
//! `RMM_UPDATE_SIGNING_KEY` holds that hex (for CI secrets).

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
        Cmd::Verify { pubkey, binary } => {
            let raw = std::fs::read_to_string(manifest_path(&binary)).context("reading manifest")?;
            let manifest: Manifest = serde_json::from_str(&raw)?;
            verify(&pubkey, &manifest, &std::fs::read(&binary)?)?;
            println!("ok: {} {} signed by {pubkey}", manifest.platform, manifest.version);
            Ok(())
        }
    }
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
