use crate::geneva::tspu::flow_state::FlowState;
use crate::geneva::tspu::signal::BlockageSignal;
use crate::geneva::tspu::TspuConfig;
use crate::types::{Flow, TcpSegment};
use std::time::Instant;

fn is_from_server(seg: &TcpSegment, client_flow: &Flow) -> bool {
    seg.flow.src == client_flow.dst
}

fn has_ttl_anomaly(actual: u8, baseline: Option<u8>, tolerance: u8) -> bool {
    if let Some(expected) = baseline {
        (actual as i16 - expected as i16).abs() >= tolerance as i16
    } else {
        false
    }
}

pub fn check_rst(
    seg: &TcpSegment,
    state: &FlowState,
    cfg: &TspuConfig,
    client_flow: &Flow,
    now: Instant,
) -> Option<BlockageSignal> {
    if !seg.flags.is_rst() || !is_from_server(seg, client_flow) {
        return None;
    }
    if has_ttl_anomaly(seg.ttl, state.ttl_baseline(), cfg.ttl_tolerance) {
        return Some(BlockageSignal::RstInjection {
            flow: client_flow.clone(),
            sni: state.sni().map(String::from),
            ttl_expected: state.ttl_baseline().unwrap_or(0),
            ttl_actual: seg.ttl,
            salvo_count: state.rst_salvo_count() + 1,
        });
    }
    if state.ttl_baseline().is_none() {
        if let Some(hello_at) = state.client_hello_at() {
            if now.duration_since(hello_at).as_millis() <= 50 && state.bytes_rx() == 0 {
                return Some(BlockageSignal::RstInjection {
                    flow: client_flow.clone(),
                    sni: state.sni().map(String::from),
                    ttl_expected: 0,
                    ttl_actual: seg.ttl,
                    salvo_count: state.rst_salvo_count() + 1,
                });
            }
        }
    }
    None
}

pub fn check_fin(
    seg: &TcpSegment,
    state: &FlowState,
    cfg: &TspuConfig,
    client_flow: &Flow,
) -> Option<BlockageSignal> {
    if !seg.flags.is_fin() || !is_from_server(seg, client_flow) {
        return None;
    }
    if !has_ttl_anomaly(seg.ttl, state.ttl_baseline(), cfg.ttl_tolerance) {
        return None;
    }
    if !state.has_client_hello() || state.bytes_rx() > 0 {
        return None;
    }
    Some(BlockageSignal::FinInjection {
        flow: client_flow.clone(),
        sni: state.sni().map(String::from),
        ttl_expected: state.ttl_baseline().unwrap_or(0),
        ttl_actual: seg.ttl,
    })
}

pub fn check_window(
    seg: &TcpSegment,
    state: &FlowState,
    cfg: &TspuConfig,
    client_flow: &Flow,
) -> Option<BlockageSignal> {
    if seg.flags.is_syn() || !is_from_server(seg, client_flow) {
        return None;
    }
    if seg.window > 1 {
        return None;
    }
    if !has_ttl_anomaly(seg.ttl, state.ttl_baseline(), cfg.ttl_tolerance) {
        return None;
    }
    Some(BlockageSignal::WindowManipulation {
        flow: client_flow.clone(),
        sni: state.sni().map(String::from),
        window: seg.window,
    })
}
