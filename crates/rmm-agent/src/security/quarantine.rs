//! Quarantine: files moved into a protected store instead of being deleted, so a false
//! positive can be put back exactly as it was.
//!
//! Each item is `<id>.bin` (the content XORed with a keystream, so the file can't be run or
//! picked up by another scanner from the store) and `<id>.json` (where it came from, its
//! hash, permissions and times). The store lives under the agent's state directory, which only
//! root/SYSTEM can read. Both the agent and the sensor process use it.

use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use rmm_proto::security::QuarantineItem;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Meta {
    id: Uuid,
    path: String,
    sha256: String,
    size: u64,
    quarantined_at: DateTime<Utc>,
    #[serde(default)]
    reason: Option<String>,
    #[serde(default)]
    detection_id: Option<String>,
    /// Hex key for the keystream.
    key: String,
    #[serde(default)]
    mode: Option<u32>,
    #[serde(default)]
    uid: Option<u32>,
    #[serde(default)]
    gid: Option<u32>,
    #[serde(default)]
    modified: Option<DateTime<Utc>>,
}

impl Meta {
    fn item(&self) -> QuarantineItem {
        QuarantineItem {
            id: self.id,
            path: self.path.clone(),
            sha256: self.sha256.clone(),
            size: self.size,
            quarantined_at: self.quarantined_at,
            reason: self.reason.clone(),
            detection_id: self.detection_id.clone(),
        }
    }
}

/// XORs `data` in place with SHA-256(key || block counter), starting at byte `offset`.
fn xor(key: &[u8], offset: u64, data: &mut [u8]) {
    let mut pos = offset;
    let mut i = 0;
    while i < data.len() {
        let block = pos / 32;
        let mut h = Sha256::new();
        h.update(key);
        h.update(block.to_le_bytes());
        let ks = h.finalize();
        let start = (pos % 32) as usize;
        let n = (32 - start).min(data.len() - i);
        for j in 0..n {
            data[i + j] ^= ks[start + j];
        }
        i += n;
        pos += n as u64;
    }
}

pub struct Store {
    dir: PathBuf,
}

/// Largest file that can be quarantined.
pub const MAX_SIZE: u64 = 512 * 1024 * 1024;

impl Store {
    pub fn open() -> Result<Store> {
        Ok(Store { dir: crate::config::state_subdir("quarantine")? })
    }

    #[cfg(test)]
    pub fn at(dir: PathBuf) -> Store {
        fs::create_dir_all(&dir).unwrap();
        Store { dir }
    }

    fn meta_path(&self, id: Uuid) -> PathBuf {
        self.dir.join(format!("{id}.json"))
    }

    fn data_path(&self, id: Uuid) -> PathBuf {
        self.dir.join(format!("{id}.bin"))
    }

    fn load(&self, id: Uuid) -> Result<Meta> {
        let raw = fs::read(self.meta_path(id)).with_context(|| format!("no quarantined file {id}"))?;
        Ok(serde_json::from_slice(&raw)?)
    }

    pub fn list(&self) -> Vec<QuarantineItem> {
        let mut out: Vec<QuarantineItem> = fs::read_dir(&self.dir)
            .into_iter()
            .flatten()
            .flatten()
            .filter(|e| e.path().extension().is_some_and(|x| x == "json"))
            .filter_map(|e| fs::read(e.path()).ok())
            .filter_map(|b| serde_json::from_slice::<Meta>(&b).ok())
            .map(|m| m.item())
            .collect();
        out.sort_by_key(|i| std::cmp::Reverse(i.quarantined_at));
        out
    }

    /// Moves `path` into the store. The original is removed only once the copy is safely
    /// written.
    pub fn quarantine(&self, path: &Path, reason: Option<String>, detection_id: Option<String>) -> Result<QuarantineItem> {
        // A cheap first look, so a directory or device is never opened at all.
        if !fs::symlink_metadata(path).with_context(|| format!("{}", path.display()))?.is_file() {
            bail!("{} isn't a regular file", path.display());
        }
        // Then what counts: open without following a link, and judge (and record) what was
        // actually opened. The file may sit in a directory its user can write to, and could be
        // swapped for a link to something else between a check by path and the open.
        let mut src = crate::fsutil::open_no_follow(fs::OpenOptions::new().read(true), path).with_context(|| format!("opening {}", path.display()))?;
        let md = src.metadata().with_context(|| format!("{}", path.display()))?;
        if !md.is_file() {
            bail!("{} isn't a regular file", path.display());
        }
        if md.len() > MAX_SIZE {
            bail!("{} is larger than {} MB", path.display(), MAX_SIZE / 1024 / 1024);
        }
        let id = Uuid::new_v4();
        let mut key = [0u8; 32];
        key[..16].copy_from_slice(Uuid::new_v4().as_bytes());
        key[16..].copy_from_slice(Uuid::new_v4().as_bytes());
        let tmp = self.dir.join(format!("{id}.bin.tmp"));
        let mut dst = fs::File::create(&tmp)?;
        let mut hasher = Sha256::new();
        let mut buf = vec![0u8; 64 * 1024];
        let mut off = 0u64;
        loop {
            let n = src.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
            xor(&key, off, &mut buf[..n]);
            dst.write_all(&buf[..n])?;
            off += n as u64;
        }
        dst.sync_all()?;
        drop(src);
        #[cfg(unix)]
        let (mode, uid, gid) = {
            use std::os::unix::fs::MetadataExt;
            (Some(md.mode()), Some(md.uid()), Some(md.gid()))
        };
        #[cfg(not(unix))]
        let (mode, uid, gid) = (None, None, None);
        let meta = Meta {
            id,
            path: path.to_string_lossy().into_owned(),
            sha256: hex::encode(hasher.finalize()),
            size: off,
            quarantined_at: Utc::now(),
            reason,
            detection_id,
            key: hex::encode(key),
            mode,
            uid,
            gid,
            modified: md.modified().ok().map(DateTime::<Utc>::from),
        };
        fs::rename(&tmp, self.data_path(id))?;
        fs::write(self.meta_path(id), serde_json::to_vec_pretty(&meta)?)?;
        // Only take away the file that was copied: if the path (or a directory above it) was
        // swapped meanwhile, removing by path would delete something else.
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if !fs::symlink_metadata(path).is_ok_and(|now| now.dev() == md.dev() && now.ino() == md.ino()) {
                self.remove(id);
                bail!("{} changed while it was being quarantined", path.display());
            }
        }
        if let Err(e) = fs::remove_file(path) {
            // Couldn't take it away (in use, read-only medium): undo, so nothing is lost.
            let _ = fs::remove_file(self.data_path(id));
            let _ = fs::remove_file(self.meta_path(id));
            return Err(e).with_context(|| format!("removing {}", path.display()));
        }
        Ok(meta.item())
    }

    /// Puts a file back where it was (or at `to`). Refuses to overwrite an existing file.
    pub fn restore(&self, id: Uuid, to: Option<&Path>) -> Result<String> {
        let meta = self.load(id)?;
        let target = to.map(Path::to_path_buf).unwrap_or_else(|| PathBuf::from(&meta.path));
        let target = crate::fsutil::checked_absolute(&target).context("not restoring there")?;
        let exists = || anyhow::anyhow!("{} already exists; move it away first", target.display());
        // `symlink_metadata`, not `exists()`: a dangling link counts as something in the way.
        if fs::symlink_metadata(&target).is_ok() {
            return Err(exists());
        }
        let key = hex::decode(&meta.key)?;
        let mut data = fs::read(self.data_path(id)).context("reading the quarantined copy")?;
        xor(&key, 0, &mut data);
        if hex::encode(Sha256::digest(&data)) != meta.sha256 {
            bail!("the quarantined copy is damaged (hash mismatch)");
        }
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }
        // One exclusive create (which never follows a link at the name), and everything after
        // it through that handle: the directory may be writable by the file's user, who could
        // otherwise swap in a link between a check and a write by path.
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            // Not readable by anyone else until the real mode is applied.
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = match crate::fsutil::open_no_follow(&mut opts, &target) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => return Err(exists()),
            Err(e) => return Err(e).with_context(|| format!("writing {}", target.display())),
        };
        if let Err(e) = f.write_all(&data).and_then(|()| f.sync_all()) {
            drop(f);
            let _ = fs::remove_file(&target);
            return Err(e).with_context(|| format!("writing {}", target.display()));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            // Owner first: changing it clears set-user/group-ID bits the mode would restore.
            if let (Some(uid), Some(gid)) = (meta.uid, meta.gid) {
                let _ = std::os::unix::fs::fchown(&f, Some(uid), Some(gid));
            }
            if let Some(mode) = meta.mode {
                let _ = f.set_permissions(fs::Permissions::from_mode(mode & 0o7777));
            }
        }
        if let Some(m) = meta.modified {
            let _ = f.set_modified(m.into());
        }
        drop(f);
        self.remove(id);
        Ok(target.to_string_lossy().into_owned())
    }

    /// Deletes a quarantined file for good.
    pub fn delete(&self, id: Uuid) -> Result<String> {
        let meta = self.load(id)?;
        self.remove(id);
        Ok(meta.path)
    }

    fn remove(&self, id: Uuid) {
        let _ = fs::remove_file(self.data_path(id));
        let _ = fs::remove_file(self.meta_path(id));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quarantine_and_restore_round_trip() {
        let root = std::env::temp_dir().join(format!("rmm-q-{}", Uuid::new_v4()));
        let store = Store::at(root.join("store"));
        let file = root.join("victim/evil.bin");
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        let content: Vec<u8> = (0..100_000u32).map(|i| (i % 251) as u8).collect();
        fs::write(&file, &content).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&file, fs::Permissions::from_mode(0o751)).unwrap();
        }
        let item = store.quarantine(&file, Some("test".into()), Some("d-1".into())).unwrap();
        assert!(!file.exists(), "moved, not copied");
        assert_eq!(item.size, content.len() as u64);
        assert_eq!(item.sha256, hex::encode(Sha256::digest(&content)));
        let stored = fs::read(store.data_path(item.id)).unwrap();
        assert_ne!(&stored[..64], &content[..64], "the stored copy isn't the original bytes");
        assert_eq!(store.list().len(), 1);

        fs::write(&file, b"someone put a file back").unwrap();
        assert!(store.restore(item.id, None).unwrap_err().to_string().contains("already exists"));
        fs::remove_file(&file).unwrap();
        assert_eq!(store.restore(item.id, None).unwrap(), file.to_string_lossy());
        assert_eq!(fs::read(&file).unwrap(), content);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(fs::metadata(&file).unwrap().permissions().mode() & 0o777, 0o751);
        }
        assert!(store.list().is_empty());

        let item = store.quarantine(&file, None, None).unwrap();
        assert_eq!(store.delete(item.id).unwrap(), file.to_string_lossy());
        assert!(store.list().is_empty() && !file.exists());
        assert!(store.quarantine(&root, None, None).is_err(), "directories aren't quarantined");
        fs::remove_dir_all(&root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_are_neither_followed_in_nor_written_through_out() {
        let root = std::env::temp_dir().join(format!("rmm-q-{}", Uuid::new_v4()));
        let store = Store::at(root.join("store"));
        let dir = root.join("victim");
        fs::create_dir_all(&dir).unwrap();
        let precious = dir.join("precious");
        fs::write(&precious, b"not malware").unwrap();
        let link = dir.join("evil.bin");
        std::os::unix::fs::symlink(&precious, &link).unwrap();
        assert!(store.quarantine(&link, None, None).unwrap_err().to_string().contains("isn't a regular file"));
        assert_eq!(fs::read(&precious).unwrap(), b"not malware");
        assert!(fs::symlink_metadata(&link).unwrap().file_type().is_symlink() && store.list().is_empty());
        fs::remove_file(&link).unwrap();

        // Restoring onto a link (dangling or not) is refused rather than written through.
        fs::write(&link, b"payload").unwrap();
        let item = store.quarantine(&link, None, None).unwrap();
        std::os::unix::fs::symlink(&precious, &link).unwrap();
        assert!(store.restore(item.id, None).unwrap_err().to_string().contains("already exists"));
        assert_eq!(fs::read(&precious).unwrap(), b"not malware");
        fs::remove_file(&link).unwrap();
        let created = dir.join("created-by-root");
        std::os::unix::fs::symlink(&created, &link).unwrap();
        assert!(store.restore(item.id, None).unwrap_err().to_string().contains("already exists"));
        assert!(fs::symlink_metadata(&created).is_err(), "the dangling link's target wasn't created");
        fs::remove_file(&link).unwrap();
        // And an ordinary file in the way still is.
        fs::write(&link, b"someone else's").unwrap();
        assert!(store.restore(item.id, None).unwrap_err().to_string().contains("already exists"));
        assert_eq!(fs::read(&link).unwrap(), b"someone else's");
        fs::remove_file(&link).unwrap();

        // Targets must be absolute and free of `..`.
        assert!(store.restore(item.id, Some(Path::new("relative/evil.bin"))).is_err());
        let up = dir.join("sub").join("..").join("evil.bin");
        assert!(format!("{:#}", store.restore(item.id, Some(&up)).unwrap_err()).contains(".."));
        assert!(!link.exists());
        assert_eq!(store.restore(item.id, None).unwrap(), link.to_string_lossy());
        assert_eq!(fs::read(&link).unwrap(), b"payload");
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn keystream_is_position_independent() {
        let key = [3u8; 32];
        let mut a: Vec<u8> = (0..100).collect();
        let orig = a.clone();
        xor(&key, 0, &mut a[..45]);
        xor(&key, 45, &mut a[45..]);
        let mut b = orig.clone();
        xor(&key, 0, &mut b);
        assert_eq!(a, b);
        xor(&key, 0, &mut b);
        assert_eq!(b, orig);
    }
}
