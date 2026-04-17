use std::time::Instant;

/// A stateful observer that processes packets and emits typed signals.
///
/// Detectors are the building blocks of Floor 1 (detection) in the reflex
/// pipeline. Each detector maintains its own internal state (flow tables,
/// counters, windows) and emits signals through the `emit` callback.
///
/// # Contract
///
/// - `on_packet` is called for every incoming packet. The detector updates
///   its internal state and calls `emit` zero or more times.
/// - `on_tick` is called periodically by the scheduler. Used by window-based
///   (throttle) and timeout-based (blackhole, silent drop) detectors.
/// - Cross-flow correlation is internal state — not a separate stream.
pub trait Detector {
    type Input;
    type Signal;

    fn on_packet(&mut self, input: Self::Input, emit: &mut dyn FnMut(Self::Signal));

    fn on_tick(&mut self, now: Instant, emit: &mut dyn FnMut(Self::Signal));
}
