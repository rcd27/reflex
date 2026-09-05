mod backend;
mod combined;
mod guard;
mod nft_guard;
mod pipeline;
mod preflight;
mod terminal;
mod typed;
mod witness;

pub use backend::{NfqueueBackend, Waited};
pub use combined::NfqAfPacketBackend;
pub use guard::{
    ConnmarkConfig, Direction, FirewallRule, MarkMatch, NfqGuard, NfqGuardError, PolicyRoute,
    RuleAction, RuleProtocol,
};
pub use nft_guard::{NftConfig, NftGuard, NftGuardError, NftMarkGuard, SlotConfig};
pub use terminal::{Answer, NotTaken};

/// Backward compatibility alias — remove after all consumers migrate.
pub type FirewallGuard = NfqGuard;
pub use pipeline::{
    NfqCounts, NfqHandler, NfqPacket, NfqPipeline, NfqShared, NfqStep, NfqVerdict, NfqVerdictKind,
};
pub use typed::{classify_l7, TypedNfq, WireHandler, WirePacket, L7};
pub use witness::FlowWitness;
