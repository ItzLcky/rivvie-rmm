//! Technician tools ([`rmm_proto::tools`]): the process list with kill, and the file browser.
//! Everything here runs on a blocking thread and answers one request.

use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use chrono::{DateTime, TimeZone, Utc};
use rmm_proto::telemetry::Proc;
use rmm_proto::tools::{CHUNK, DirEntry, DirListing, LIST_MAX, Process, Reply, Request, UPLOAD_SUFFIX};
use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind, Users};

pub fn handle(req: Request) -> Reply {
    let res = match req {
        Request::Processes => processes().map(Reply::Processes),
        Request::Kill { pid, tree } => {
            crate::security::response::kill_process(pid, tree).map(|(message, _)| Reply::Killed { message })
        }
        Request::ListDir { path } => list_dir(&path).map(Reply::Dir),
        Request::ReadFile { path, offset, len } => read_file(Path::new(&path), offset, len),
        Request::WriteFile { path, offset, data, last, overwrite } => write_file(Path::new(&path), offset, &data, last, overwrite),
        Request::AbortWrite { path } => absolute(&path).map(|path| {
            let _ = std::fs::remove_file(partial(&path));
            Reply::Written { size: 0 }
        }),
    };
    res.unwrap_or_else(|e| Reply::Error(format!("{e:#}")))
}

// ---------------------------------------------------------------------------
// Processes
// ---------------------------------------------------------------------------

/// Kept between requests so CPU usage is measured since the previous list (a technician
/// refreshing the view), not over a fresh 200 ms sample every time.
struct Sampler {
    sys: System,
    users: Users,
    at: Instant,
}

static SAMPLER: Mutex<Option<Sampler>> = Mutex::new(None);

fn processes() -> Result<Vec<Process>> {
    let mut guard = SAMPLER.lock().unwrap_or_else(|e| e.into_inner());
    let kind = ProcessRefreshKind::nothing()
        .with_cpu()
        .with_memory()
        .with_cmd(UpdateKind::OnlyIfNotSet)
        .with_exe(UpdateKind::OnlyIfNotSet)
        .with_user(UpdateKind::OnlyIfNotSet);
    let fresh = guard.as_ref().is_none_or(|s| s.at.elapsed() > Duration::from_secs(600));
    if fresh {
        let mut sys = System::new()?;
        sys.refresh_processes_specifics(ProcessesToUpdate::All, true, kind);
        // CPU usage needs two samples.
        std::thread::sleep(sysinfo::MINIMUM_CPU_UPDATE_INTERVAL.max(Duration::from_millis(250)));
        *guard = Some(Sampler { sys, users: Users::new_with_refreshed_list()?, at: Instant::now() });
    }
    let s = guard.as_mut().expect("set above");
    s.sys.refresh_processes_specifics(ProcessesToUpdate::All, true, kind);
    s.at = Instant::now();
    let mut out: Vec<Process> = s
        .sys
        .processes()
        .iter()
        .filter(|(_, p)| p.thread_kind().is_none())
        .map(|(pid, p)| {
            let name = p.name().to_string_lossy().into_owned();
            let ppid = p.parent().map(|x| x.as_u32());
            let cmd: Vec<String> = p.cmd().iter().map(|c| c.to_string_lossy().into_owned()).collect();
            let protected = crate::sensor::procs::protected(&Proc { pid: pid.as_u32(), ppid: ppid.unwrap_or(0), name: name.clone(), ..Default::default() });
            Process {
                pid: pid.as_u32(),
                ppid,
                name,
                exe: p.exe().map(|e| e.to_string_lossy().into_owned()),
                cmd: (!cmd.is_empty()).then(|| cmd.join(" ").chars().take(2000).collect()),
                user: p.user_id().and_then(|u| s.users.get_user_by_id(u)).map(|u| u.name().to_string()),
                cpu: p.cpu_usage(),
                mem: p.memory(),
                started_at: Utc.timestamp_opt(p.start_time() as i64, 0).single().filter(|t| t.timestamp() > 0),
                protected,
            }
        })
        .collect();
    out.sort_by_key(|p| p.pid);
    Ok(out)
}

// ---------------------------------------------------------------------------
// Files
// ---------------------------------------------------------------------------

fn modified(m: &std::fs::Metadata) -> Option<DateTime<Utc>> {
    m.modified().ok().map(DateTime::<Utc>::from)
}

/// Where the roots are: drive letters on Windows, `/` elsewhere.
fn roots() -> DirListing {
    let mut entries = Vec::new();
    if cfg!(windows) {
        for d in b'A'..=b'Z' {
            let path = format!("{}:\\", d as char);
            if let Ok(m) = std::fs::metadata(&path) {
                entries.push(DirEntry { name: path.clone(), path, dir: true, size: 0, modified: modified(&m), ..Default::default() });
            }
        }
    } else {
        entries.push(DirEntry { name: "/".into(), path: "/".into(), dir: true, ..Default::default() });
    }
    DirListing { path: String::new(), parent: None, entries, truncated: false }
}

/// Any absolute path on the machine (that's the point of a file browser), but no `..`.
fn absolute(path: &str) -> Result<PathBuf> {
    crate::fsutil::checked_absolute(Path::new(path))
}

fn list_dir(path: &str) -> Result<DirListing> {
    if path.trim().is_empty() {
        return Ok(roots());
    }
    let dir = absolute(path)?;
    let read = std::fs::read_dir(&dir).with_context(|| format!("reading {}", dir.display()))?;
    let mut entries = Vec::new();
    let mut truncated = false;
    for e in read {
        if entries.len() >= LIST_MAX {
            truncated = true;
            break;
        }
        let Ok(e) = e else { continue };
        let path = e.path();
        let name = e.file_name().to_string_lossy().into_owned();
        let symlink = e.file_type().map(|t| t.is_symlink()).unwrap_or(false);
        // Follow links for what they point at; a broken link is listed with its error.
        let entry = match std::fs::metadata(&path) {
            Ok(m) => DirEntry {
                name,
                path: path.to_string_lossy().into_owned(),
                dir: m.is_dir(),
                symlink,
                size: if m.is_dir() { 0 } else { m.len() },
                modified: modified(&m),
                error: None,
            },
            Err(err) => DirEntry { name, path: path.to_string_lossy().into_owned(), symlink, error: Some(err.to_string()), ..Default::default() },
        };
        entries.push(entry);
    }
    entries.sort_by(|a, b| b.dir.cmp(&a.dir).then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase())));
    let parent = dir.parent().map(|p| p.to_string_lossy().into_owned()).or_else(|| Some(String::new()));
    Ok(DirListing { path: dir.to_string_lossy().into_owned(), parent, entries, truncated })
}

fn read_file(path: &Path, offset: u64, len: u32) -> Result<Reply> {
    let path = absolute(&path.to_string_lossy())?;
    let mut f = std::fs::File::open(&path).with_context(|| format!("opening {}", path.display()))?;
    let m = f.metadata()?;
    if m.is_dir() {
        bail!("{} is a directory", path.display());
    }
    let size = m.len();
    f.seek(SeekFrom::Start(offset))?;
    let want = (len as usize).min(CHUNK);
    let mut data = Vec::with_capacity(want);
    f.take(want as u64).read_to_end(&mut data)?;
    // A file that's still growing is read up to where it was when the transfer started;
    // the server stops at the first `eof`.
    let eof = data.len() < want || offset + data.len() as u64 >= size;
    Ok(Reply::Chunk { data, size, eof })
}

fn partial(path: &Path) -> PathBuf {
    let mut name = path.file_name().map(|n| n.to_os_string()).unwrap_or_default();
    name.push(UPLOAD_SUFFIX);
    path.with_file_name(name)
}

fn write_file(path: &Path, offset: u64, data: &[u8], last: bool, overwrite: bool) -> Result<Reply> {
    let path = absolute(&path.to_string_lossy())?;
    if path.file_name().is_none() {
        bail!("{} isn't a file name", path.display());
    }
    if data.len() > CHUNK {
        bail!("chunks are at most {CHUNK} bytes");
    }
    let tmp = partial(&path);
    let mut f = if offset == 0 {
        if let Ok(m) = std::fs::metadata(&path) {
            if m.is_dir() {
                bail!("{} is a directory", path.display());
            }
            if !overwrite {
                bail!("{} already exists", path.display());
            }
        }
        // The partial file sits at a predictable name, often in a directory its user can
        // write to: never write through whatever might already be there (a planted link
        // would have us write the upload wherever it points).
        let _ = std::fs::remove_file(&tmp);
        crate::fsutil::open_no_follow(std::fs::OpenOptions::new().write(true).create_new(true), &tmp)
            .with_context(|| format!("creating {}", tmp.display()))?
    } else {
        let f = crate::fsutil::open_no_follow(std::fs::OpenOptions::new().write(true), &tmp)
            .with_context(|| format!("the upload to {} was interrupted; start again", path.display()))?;
        let m = f.metadata()?;
        if !m.is_file() {
            bail!("{} isn't a regular file", tmp.display());
        }
        // A hard link swapped in for the partial file would point the rest of the upload at
        // another file.
        #[cfg(unix)]
        if std::os::unix::fs::MetadataExt::nlink(&m) != 1 {
            bail!("{} has other links; start again", tmp.display());
        }
        // Pieces arrive in order; anything else means a piece was lost.
        let have = m.len();
        if have != offset {
            bail!("expected the piece at byte {have}, got {offset}");
        }
        f
    };
    f.seek(SeekFrom::Start(offset))?;
    f.write_all(data)?;
    let size = offset + data.len() as u64;
    if last {
        f.sync_all()?;
        drop(f);
        if path.exists() && !overwrite {
            let _ = std::fs::remove_file(&tmp);
            bail!("{} appeared while uploading", path.display());
        }
        // Windows' rename doesn't replace an existing file.
        if cfg!(windows) && path.exists() {
            std::fs::remove_file(&path).with_context(|| format!("replacing {}", path.display()))?;
        }
        std::fs::rename(&tmp, &path).with_context(|| format!("moving the upload into place at {}", path.display()))?;
    }
    Ok(Reply::Written { size })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir() -> PathBuf {
        let d = std::env::temp_dir().join(format!("rmm-tools-{}", uuid::Uuid::new_v4().simple()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn lists_reads_and_writes() {
        let d = tmpdir();
        std::fs::create_dir(d.join("sub")).unwrap();
        std::fs::write(d.join("b.txt"), b"hello world").unwrap();
        let l = list_dir(&d.to_string_lossy()).unwrap();
        assert_eq!(l.entries.iter().map(|e| (e.name.as_str(), e.dir)).collect::<Vec<_>>(), [("sub", true), ("b.txt", false)], "dirs first");
        assert_eq!(l.entries[1].size, 11);
        assert_eq!(l.parent.as_deref(), d.parent().map(|p| p.to_string_lossy()).as_deref());

        let p = d.join("b.txt");
        let Reply::Chunk { data, size, eof } = read_file(&p, 6, 3).unwrap() else { panic!() };
        assert_eq!((data.as_slice(), size, eof), (&b"wor"[..], 11, false));
        let Reply::Chunk { data, eof, .. } = read_file(&p, 9, 100).unwrap() else { panic!() };
        assert_eq!((data.as_slice(), eof), (&b"ld"[..], true));

        // Upload in pieces; nothing appears until the last one.
        let up = d.join("up.bin");
        assert!(matches!(write_file(&up, 0, b"abc", false, false).unwrap(), Reply::Written { size: 3 }));
        assert!(!up.exists() && partial(&up).exists());
        assert!(write_file(&up, 10, b"x", false, false).is_err(), "a gap is refused");
        assert!(matches!(write_file(&up, 3, b"def", true, false).unwrap(), Reply::Written { size: 6 }));
        assert_eq!(std::fs::read(&up).unwrap(), b"abcdef");
        assert!(!partial(&up).exists());
        // Existing files need overwrite.
        assert!(write_file(&up, 0, b"z", true, false).is_err());
        write_file(&up, 0, b"z", true, true).unwrap();
        assert_eq!(std::fs::read(&up).unwrap(), b"z");
        assert!(matches!(handle(Request::ListDir { path: "relative".into() }), Reply::Error(_)));
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn relative_and_dotdot_paths_are_refused() {
        let d = tmpdir();
        std::fs::write(d.join("a.txt"), b"x").unwrap();
        let dotdot = d.join("sub").join("..").join("a.txt");
        assert!(read_file(Path::new("a.txt"), 0, 10).is_err());
        assert!(read_file(&dotdot, 0, 10).unwrap_err().to_string().contains(".."));
        assert!(write_file(Path::new("up.bin"), 0, b"x", true, false).is_err());
        assert!(write_file(&dotdot, 0, b"x", true, true).unwrap_err().to_string().contains(".."));
        assert_eq!(std::fs::read(d.join("a.txt")).unwrap(), b"x");
        assert!(matches!(handle(Request::ListDir { path: dotdot.parent().unwrap().to_string_lossy().into() }), Reply::Error(_)));
        assert!(matches!(handle(Request::AbortWrite { path: "up.bin".into() }), Reply::Error(_)));
        // An abort with a `..` path leaves the partial file it would have named alone.
        let up = d.join("up.bin");
        write_file(&up, 0, b"abc", false, false).unwrap();
        let sneaky = d.join("sub").join("..").join("up.bin").to_string_lossy().into_owned();
        assert!(matches!(handle(Request::AbortWrite { path: sneaky }), Reply::Error(_)));
        assert!(partial(&up).exists());
        assert!(matches!(handle(Request::AbortWrite { path: up.to_string_lossy().into() }), Reply::Written { size: 0 }));
        assert!(!partial(&up).exists());
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn uploads_dont_write_through_planted_links() {
        let d = tmpdir();
        let victim = d.join("victim");
        std::fs::write(&victim, b"precious").unwrap();
        let up = d.join("up.bin");
        // A link at the partial name before the upload starts: replaced, not followed.
        std::os::unix::fs::symlink(&victim, partial(&up)).unwrap();
        write_file(&up, 0, b"abc", false, false).unwrap();
        assert!(!std::fs::symlink_metadata(partial(&up)).unwrap().file_type().is_symlink());
        assert_eq!(std::fs::read(&victim).unwrap(), b"precious");
        // A link swapped in mid-upload: refused.
        std::fs::remove_file(partial(&up)).unwrap();
        std::os::unix::fs::symlink(&victim, partial(&up)).unwrap();
        assert!(write_file(&up, 3, b"def", true, false).is_err());
        assert_eq!(std::fs::read(&victim).unwrap(), b"precious");
        assert!(!up.exists());
        // Likewise a hard link.
        std::fs::remove_file(partial(&up)).unwrap();
        std::fs::write(&victim, b"pre").unwrap();
        std::fs::hard_link(&victim, partial(&up)).unwrap();
        assert!(write_file(&up, 3, b"def", true, false).unwrap_err().to_string().contains("links"));
        assert_eq!(std::fs::read(&victim).unwrap(), b"pre");
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn roots_and_processes() {
        assert!(!list_dir("").unwrap().entries.is_empty());
        let ps = processes().unwrap();
        let me = ps.iter().find(|p| p.pid == std::process::id()).expect("lists this process");
        assert!(me.mem > 0);
    }
}
