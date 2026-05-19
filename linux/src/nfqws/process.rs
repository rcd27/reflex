use std::path::PathBuf;
use std::process::ExitStatus;

use thiserror::Error;
use tokio::process::{Child, Command};
use tokio::sync::Mutex;

/// Owned handle to a running nfqws2 subprocess.
///
/// Drop semantics: child process is SIGKILLed on Drop (via tokio's
/// kill_on_drop). Use `kill` for explicit shutdown.
pub struct NfqwsProcess {
    child: Mutex<Option<Child>>,
}

#[derive(Debug, Error)]
pub enum NfqwsError {
    #[error("failed to spawn nfqws2 from {path}: {source}")]
    Spawn {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("nfqws2 already terminated")]
    AlreadyExited,
    #[error("kill failed: {0}")]
    Kill(#[source] std::io::Error),
    #[error("wait failed: {0}")]
    Wait(#[source] std::io::Error),
}

impl NfqwsProcess {
    /// Spawn nfqws2 with the given args.
    ///
    /// `path` points at the nfqws2 binary (the test fixture or a real
    /// `nfqws` binary from zapret2). `args` is passed verbatim — caller
    /// is responsible for `--qnum=N` and strategy args.
    pub async fn spawn(
        path: PathBuf,
        args: Vec<String>,
    ) -> Result<Self, NfqwsError> {
        let child = Command::new(&path)
            .args(&args)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .map_err(|source| NfqwsError::Spawn { path, source })?;
        Ok(Self {
            child: Mutex::new(Some(child)),
        })
    }

    /// Return true if the subprocess is still running (best-effort).
    pub fn is_alive(&self) -> bool {
        match self.child.try_lock() {
            Ok(guard) => guard.is_some(),
            Err(_) => true,
        }
    }

    /// Wait for the subprocess to exit naturally. Returns exit status.
    pub async fn wait_for_exit(&self) -> Result<ExitStatus, NfqwsError> {
        let mut guard = self.child.lock().await;
        if let Some(child) = guard.as_mut() {
            let status = child.wait().await.map_err(NfqwsError::Wait)?;
            *guard = None;
            Ok(status)
        } else {
            Err(NfqwsError::AlreadyExited)
        }
    }

    /// Kill the subprocess. Idempotent — calling on an exited process
    /// returns AlreadyExited.
    pub async fn kill(self) -> Result<(), NfqwsError> {
        let mut guard = self.child.lock().await;
        if let Some(child) = guard.as_mut() {
            child.kill().await.map_err(NfqwsError::Kill)?;
            let _ = child.wait().await; // reap zombie
            *guard = None;
            Ok(())
        } else {
            Err(NfqwsError::AlreadyExited)
        }
    }
}
