//! Path checks and file opens for code that runs as root/SYSTEM on paths the server sends,
//! often in directories ordinary users can write to (Downloads, /tmp).

use std::fs::{File, OpenOptions};
use std::io;
use std::path::{Component, Path, PathBuf};

use anyhow::{Result, bail};

/// `path` if it is absolute, has no `..` components and no NUL bytes. Nothing legitimate
/// sends `..` (the console navigates with the `parent` the agent returns), and refusing it
/// keeps what was asked for and what gets touched the same thing.
pub fn checked_absolute(path: &Path) -> Result<PathBuf> {
    if path.as_os_str().as_encoded_bytes().contains(&0) {
        bail!("{} contains a NUL byte", path.display());
    }
    if !path.is_absolute() {
        bail!("{} isn't an absolute path", path.display());
    }
    if path.components().any(|c| c == Component::ParentDir) {
        bail!("{} contains '..'", path.display());
    }
    Ok(path.to_path_buf())
}

/// Opens `path` with `opts` without following a symbolic link (or other reparse point) at
/// its final component. On unix a link there fails the open (`ELOOP`), and `O_NONBLOCK`
/// keeps a FIFO planted at the path from blocking it (it changes nothing for regular files).
/// On Windows the reparse point itself is opened, so its metadata is not a regular file.
/// Callers check the opened handle's metadata.
pub fn open_no_follow(opts: &mut OpenOptions, path: &Path) -> io::Result<File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        /// winbase.h; the `windows` crate only has it behind a feature this crate doesn't use.
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        opts.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    opts.open(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absolute_paths_only_without_dotdot() {
        let ok = if cfg!(windows) { "C:\\Users\\x\\a.txt" } else { "/home/x/a.txt" };
        assert_eq!(checked_absolute(Path::new(ok)).unwrap(), Path::new(ok));
        assert!(checked_absolute(Path::new("relative/a.txt")).unwrap_err().to_string().contains("absolute"));
        let up = if cfg!(windows) { "C:\\Users\\..\\Windows\\a" } else { "/tmp/../etc/passwd" };
        assert!(checked_absolute(Path::new(up)).unwrap_err().to_string().contains(".."));
        let nul = if cfg!(windows) { "C:\\a\0b" } else { "/tmp/a\0b" };
        assert!(checked_absolute(Path::new(nul)).unwrap_err().to_string().contains("NUL"));
        // `..` inside a name is just a name.
        let dots = if cfg!(windows) { "C:\\a..b" } else { "/tmp/a..b" };
        assert!(checked_absolute(Path::new(dots)).is_ok());
    }
}
