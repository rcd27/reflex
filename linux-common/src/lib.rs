#![no_std]

/// Action that XDP program should take for a given flow.
/// Stored in BPF hash map, written by userspace, read by XDP.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FlowAction {
    /// Pass packet through to bridge (default)
    Pass = 0,
    /// Drop packet silently
    Drop = 1,
    /// Copy packet to userspace via perf ring, then drop
    CopyAndDrop = 2,
}
