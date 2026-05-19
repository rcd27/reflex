//! Subprocess management for nfqws2 — the packet executor from zapret2.
//!
//! `NfqwsProcess` owns a spawned nfqws2 child process. Spawn with strategy
//! args (e.g. `["--qnum=200", "--lua-desync=fake"]`); kill explicitly or
//! drop to terminate. Process lifetime tied to NfqwsProcess; no dangling
//! subprocesses when handle is dropped (Rule 2: IO at edge).
//!
//! Provisioning of the nfqws2 binary itself is out of scope — caller
//! supplies the path. See spec section 10.2.

pub mod process;

pub use process::{NfqwsError, NfqwsProcess};
