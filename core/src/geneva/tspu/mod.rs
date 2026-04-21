pub mod drop;
pub mod flow_state;
pub mod injection;
mod signal;
pub mod throughput;

pub use signal::BlockageSignal;

use std::time::{Duration, Instant};

use smallvec::SmallVec;

use crate::detector::{Detector, DetectorEvent};
use crate::types::{Flow, TcpSegment};
use flow_state::FlowState;

#[derive(Debug, Clone)]
pub struct TspuConfig {
    pub syn_timeout: Duration,
    pub post_hello_timeout: Duration,
    pub ttl_tolerance: u8,
    pub cliff_timeout: Duration,
    pub cliff_min_bytes: u64,
    pub cliff_max_bytes: u64,
    pub throttle_window: Duration,
    pub retransmit_ratio: f32,
}

impl Default for TspuConfig {
    fn default() -> Self {
        Self {
            syn_timeout: Duration::from_secs(5),
            post_hello_timeout: Duration::from_secs(15),
            ttl_tolerance: 2,
            cliff_timeout: Duration::from_secs(3),
            cliff_min_bytes: 8192,
            cliff_max_bytes: 32768,
            throttle_window: Duration::from_secs(10),
            retransmit_ratio: 0.3,
        }
    }
}

/// Composite TSPU detector — all 8 detection types in one.
/// One instance per flow (used with group_by_flow).
pub struct TspuDetector {
    config: TspuConfig,
    client_flow: Flow,
    state: FlowState,
}

impl TspuDetector {
    pub fn new(config: TspuConfig, client_flow: Flow) -> Self {
        Self {
            config,
            client_flow,
            state: FlowState::new(Instant::now()),
        }
    }
}

impl Detector for TspuDetector {
    type Input = TcpSegment;
    type Signal = BlockageSignal;

    fn step(mut self, event: DetectorEvent<TcpSegment>) -> (Self, SmallVec<[BlockageSignal; 2]>) {
        let mut signals = SmallVec::new();

        match event {
            DetectorEvent::Packet(ref seg) => {
                let now = Instant::now();
                self.state.update(seg, &self.client_flow, now);

                if let Some(sig) =
                    injection::check_rst(seg, &self.state, &self.config, &self.client_flow, now)
                {
                    signals.push(sig);
                }
                if let Some(sig) =
                    injection::check_fin(seg, &self.state, &self.config, &self.client_flow)
                {
                    signals.push(sig);
                }
                if let Some(sig) =
                    injection::check_window(seg, &self.state, &self.config, &self.client_flow)
                {
                    signals.push(sig);
                }
            }
            DetectorEvent::Tick(now) => {
                if let Some(sig) = self::drop::check_ip_blackhole(
                    &self.state,
                    &self.config,
                    &self.client_flow,
                    now,
                ) {
                    signals.push(sig);
                    self.state.timeout_signal_fired = true;
                }
                if let Some(sig) =
                    self::drop::check_silent_drop(&self.state, &self.config, &self.client_flow, now)
                {
                    signals.push(sig);
                    self.state.timeout_signal_fired = true;
                }
                if let Some(sig) =
                    throughput::check_cliff(&self.state, &self.config, &self.client_flow, now)
                {
                    signals.push(sig);
                    self.state.timeout_signal_fired = true;
                }
                if let Some(sig) = throughput::check_probabilistic(
                    &self.state,
                    &self.config,
                    &self.client_flow,
                    now,
                ) {
                    signals.push(sig);
                }
                if let Some(sig) =
                    throughput::check_ack_drop(&self.state, &self.config, &self.client_flow, now)
                {
                    signals.push(sig);
                }
            }
        }

        (self, signals)
    }
}
