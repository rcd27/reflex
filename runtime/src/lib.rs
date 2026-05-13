//! Runtime adapters for reflex-core.
//!
//! This crate holds everything that depends on a concrete async runtime (tokio),
//! OS facilities (libc, std::fs, signals, pid files), or other system primitives.
//! reflex-core itself stays pure: types, parsing, building, detectors, pure stream
//! operators. Anything that needs a clock, an OS signal, or a process-wide channel
//! lives here.

pub mod ext;
pub mod pid;
pub mod signal;
pub mod stream;
pub mod subject;

pub use ext::ReflexRuntimeExt;
pub use pid::{PidError, PidGuard};
pub use signal::shutdown_signal;
pub use stream::{
    DebounceStream, DetectStream, FlowConfig, GroupByConnectionStream, GroupByFlowStream,
};
pub use subject::Subject;
