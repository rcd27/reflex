use std::path::PathBuf;

use thiserror::Error;

/// Owned handle to a running nfqws2 subprocess.
///
/// Drop semantics: child process is killed on Drop. Use `kill` for
/// explicit shutdown with exit-code reporting.
pub struct NfqwsProcess {
    // Fields filled in Task 2.
    _placeholder: (),
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
    /// Spawn nfqws2 with the given args. `path` points at the nfqws2 binary
    /// (usually `nfqws` on a zapret2-installed system, or a fixture script
    /// during tests).
    pub async fn spawn(
        _path: PathBuf,
        _args: Vec<String>,
    ) -> Result<Self, NfqwsError> {
        unimplemented!("Task 2 — TDD: test will fail first, implementation follows")
    }
}
