mod backend;
mod combined;
mod guard;
mod nft_guard;
mod pipeline;
mod preflight;
mod typed;
mod witness;

pub use backend::NfqueueBackend;
pub use combined::NfqAfPacketBackend;
pub use guard::{
    ConnmarkConfig, Direction, FirewallRule, MarkMatch, NfqGuard, NfqGuardError, PolicyRoute,
    RuleAction, RuleProtocol,
};
pub use nft_guard::{NftConfig, NftGuard, NftGuardError, SlotConfig};

/// Backward compatibility alias — remove after all consumers migrate.
pub type FirewallGuard = NfqGuard;
pub use pipeline::{NfqHandler, NfqPacket, NfqPipeline, NfqStep, NfqVerdict, NfqVerdictKind};
pub use typed::{TypedNfq, WireHandler, WirePacket, L7};
pub use witness::FlowWitness;
