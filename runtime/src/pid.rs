use std::fmt;
use std::fs;
use std::io;
use std::path::PathBuf;

#[derive(Debug)]
pub enum PidError {
    AlreadyRunning(u32),
    Io(io::Error),
}

impl fmt::Display for PidError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyRunning(pid) => write!(f, "daemon already running (pid {pid})"),
            Self::Io(e) => write!(f, "pid file error: {e}"),
        }
    }
}

impl std::error::Error for PidError {}

impl From<io::Error> for PidError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

#[derive(Debug)]
pub struct PidGuard {
    path: PathBuf,
}

impl PidGuard {
    pub fn acquire(path: PathBuf) -> Result<Self, PidError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        if path.exists() {
            if let Ok(contents) = fs::read_to_string(&path) {
                match contents.trim().parse::<u32>() {
                    Ok(pid) if is_process_alive(pid) => {
                        return Err(PidError::AlreadyRunning(pid));
                    }
                    _ => {}
                }
            }
        }

        fs::write(&path, std::process::id().to_string())?;
        Ok(Self { path })
    }

    pub fn path(&self) -> &PathBuf {
        &self.path
    }

    /// Inspects a pid file without taking the lock. Returns the owning pid if
    /// the file exists and points at a live process. Use this from admin
    /// subcommands that should refuse to mutate state owned by a running
    /// daemon (e.g. an nft-cleanup tool).
    pub fn live_owner(path: &PathBuf) -> Option<u32> {
        let contents = fs::read_to_string(path).ok()?;
        let pid: u32 = contents.trim().parse().ok()?;
        if is_process_alive(pid) {
            Some(pid)
        } else {
            None
        }
    }
}

impl Drop for PidGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn is_process_alive(pid: u32) -> bool {
    #[cfg(unix)]
    {
        // PIDs on Linux are capped at /proc/sys/kernel/pid_max (default 4194304).
        // A value that overflows i32 or exceeds the plausible range cannot be alive.
        let signed = match i32::try_from(pid) {
            Ok(v) if v > 0 => v,
            _ => return false,
        };
        let ret = unsafe { libc::kill(signed, 0) };
        if ret == 0 {
            return true;
        }
        let errno = io::Error::last_os_error().raw_os_error().unwrap_or(0);
        // ESRCH  → no such process (dead / never existed)
        // EPERM  → process exists but we lack permission to signal it
        // anything else → treat conservatively as alive
        errno != libc::ESRCH
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        false
    }
}
