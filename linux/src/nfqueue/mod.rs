mod backend;
mod combined;
mod guard;
mod pipeline;
mod preflight;

pub use backend::NfqueueBackend;
pub use combined::NfqAfPacketBackend;
pub use guard::{
    ConnmarkConfig, Direction, FirewallRule, MarkMatch, NfqGuard, NfqGuardError, PolicyRoute,
    RuleAction, RuleProtocol,
};

/// Backward compatibility alias — remove after all consumers migrate.
pub type FirewallGuard = NfqGuard;
pub use pipeline::{NfqHandler, NfqPacket, NfqPipeline, NfqVerdict};
