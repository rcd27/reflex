use std::time::Instant;

use crate::geneva::tspu::flow_state::{FlowPhase, FlowState};
use crate::geneva::tspu::signal::BlockageSignal;
use crate::geneva::tspu::TspuConfig;
use crate::types::Flow;

pub fn check_cliff(
    state: &FlowState,
    cfg: &TspuConfig,
    client_flow: &Flow,
    now: Instant,
) -> Option<BlockageSignal> {
    if state.phase() != FlowPhase::Transferring {
        return None;
    }
    if state.timeout_signal_fired {
        return None;
    }
    let last_data = state.last_data_at()?;
    if now.duration_since(last_data) < cfg.cliff_timeout {
        return None;
    }
    let bytes = state.bytes_rx();
    if bytes < cfg.cliff_min_bytes || bytes > cfg.cliff_max_bytes {
        return None;
    }
    Some(BlockageSignal::ThrottleCliff {
        flow: client_flow.clone(),
        sni: state.sni().map(String::from),
        bytes_before: bytes,
    })
}

pub fn check_probabilistic(
    state: &FlowState,
    cfg: &TspuConfig,
    client_flow: &Flow,
    now: Instant,
) -> Option<BlockageSignal> {
    if state.phase() != FlowPhase::Transferring {
        return None;
    }
    let first_data = state.first_data_at()?;
    if now.duration_since(first_data) < cfg.throttle_window {
        return None;
    }
    let retx = state.server_retransmit_count();
    let total = retx + 1;
    if total < 5 {
        return None;
    }
    let ratio = retx as f32 / total as f32;
    if ratio < cfg.retransmit_ratio {
        return None;
    }
    Some(BlockageSignal::ThrottleProbabilistic {
        flow: client_flow.clone(),
        sni: state.sni().map(String::from),
        retransmit_ratio: ratio,
    })
}

pub fn check_ack_drop(
    state: &FlowState,
    cfg: &TspuConfig,
    client_flow: &Flow,
    _now: Instant,
) -> Option<BlockageSignal> {
    if state.phase() != FlowPhase::Transferring {
        return None;
    }
    if state.server_retransmit_count() <= 5 {
        return None;
    }
    if state.bytes_tx() == 0 {
        return None;
    }
    let total = state.server_retransmit_count() + 1;
    let ratio = state.server_retransmit_count() as f32 / total as f32;
    if ratio < cfg.retransmit_ratio {
        return None;
    }
    Some(BlockageSignal::AckDrop {
        flow: client_flow.clone(),
        sni: state.sni().map(String::from),
        server_retransmits: state.server_retransmit_count(),
    })
}
