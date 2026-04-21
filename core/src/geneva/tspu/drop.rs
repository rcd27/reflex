use std::time::Instant;

use crate::geneva::tspu::flow_state::{FlowPhase, FlowState};
use crate::geneva::tspu::signal::BlockageSignal;
use crate::geneva::tspu::TspuConfig;
use crate::types::Flow;

pub fn check_ip_blackhole(
    state: &FlowState,
    cfg: &TspuConfig,
    client_flow: &Flow,
    now: Instant,
) -> Option<BlockageSignal> {
    if state.phase() != FlowPhase::SynSent {
        return None;
    }
    if state.timeout_signal_fired {
        return None;
    }
    if state.retransmit_count() < 1 {
        return None;
    }
    if now.duration_since(state.syn_at()) < cfg.syn_timeout {
        return None;
    }
    Some(BlockageSignal::IpBlackhole {
        flow: client_flow.clone(),
        sni: state.sni().map(String::from),
        syn_retransmits: state.retransmit_count(),
    })
}

pub fn check_silent_drop(
    state: &FlowState,
    cfg: &TspuConfig,
    client_flow: &Flow,
    now: Instant,
) -> Option<BlockageSignal> {
    if state.phase() != FlowPhase::Established {
        return None;
    }
    if state.timeout_signal_fired {
        return None;
    }
    if !state.has_client_hello() {
        return None;
    }
    if state.bytes_rx() > 0 {
        return None;
    }
    if state.rst_salvo_count() > 0 {
        return None;
    }
    let hello_at = state.client_hello_at()?;
    if now.duration_since(hello_at) < cfg.post_hello_timeout {
        return None;
    }
    Some(BlockageSignal::SilentDrop {
        flow: client_flow.clone(),
        sni: state.sni().map(String::from),
        retransmit_count: state.retransmit_count(),
    })
}
