//! Windows Job Objects: a script's or shell's whole process tree, so it can be killed as one.
//!
//! Windows has no process groups. A child's own children aren't tied to it, so killing the
//! interpreter after a timeout left anything it started running (and holding the output
//! pipes). Every process created by a process in a job joins that job, so the tree is
//! assigned right after spawning, before the interpreter has started anything of its own.

use std::os::windows::io::RawHandle;

use anyhow::{Context, Result};
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JobObjectExtendedLimitInformation, SetInformationJobObject, TerminateJobObject,
};
use windows::core::PCWSTR;

pub struct ProcessTree {
    job: HANDLE,
}

// SAFETY: a job handle is a kernel object handle, usable from any thread.
unsafe impl Send for ProcessTree {}
unsafe impl Sync for ProcessTree {}

impl ProcessTree {
    /// A job holding `process` (a process handle the caller keeps open). With
    /// `kill_on_close`, everything still in the job dies when this is dropped; without it,
    /// processes outlive the handle (a script may start something meant to keep running)
    /// and only [`ProcessTree::kill`] stops them.
    pub fn new(process: RawHandle, kill_on_close: bool) -> Result<Self> {
        // SAFETY: plain Win32 calls on handles we own.
        unsafe {
            let job = CreateJobObjectW(None, PCWSTR::null()).context("CreateJobObjectW")?;
            let tree = Self { job };
            if kill_on_close {
                tree.set_kill_on_close(true)?;
            }
            AssignProcessToJobObject(job, HANDLE(process)).context("AssignProcessToJobObject")?;
            Ok(tree)
        }
    }

    /// Lets whatever is still in the tree outlive this handle (see [`ProcessTree::new`]).
    pub fn release(&self) -> Result<()> {
        self.set_kill_on_close(false)
    }

    fn set_kill_on_close(&self, on: bool) -> Result<()> {
        let mut info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        if on {
            info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        }
        // SAFETY: `info` outlives the call that reads it; the handle is valid until drop.
        unsafe {
            SetInformationJobObject(
                self.job,
                JobObjectExtendedLimitInformation,
                (&raw const info).cast(),
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
            .context("SetInformationJobObject")
        }
    }

    /// Kills every process in the tree.
    pub fn kill(&self) {
        // SAFETY: the handle is valid until drop.
        unsafe {
            let _ = TerminateJobObject(self.job, 1);
        }
    }
}

impl Drop for ProcessTree {
    fn drop(&mut self) {
        // SAFETY: closed exactly once.
        unsafe {
            let _ = CloseHandle(self.job);
        }
    }
}
