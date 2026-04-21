use reflex_core::geneva::tspu::flow_state::FlowState;
use reflex_core::geneva::tspu::injection;
use reflex_core::geneva::tspu::{BlockageSignal, TspuConfig};
use reflex_core::types::{Flow, Protocol, TcpFlags, TcpOptions, TcpSegment};
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Instant;

fn client_flow() -> Flow {
    Flow {
        src: SocketAddr::new(Ipv4Addr::new(10, 0, 0, 1).into(), 12345),
        dst: SocketAddr::new(Ipv4Addr::new(93, 184, 216, 34).into(), 443),
        protocol: Protocol::Tcp,
    }
}
fn server_flow() -> Flow {
    client_flow().reversed()
}
fn seg(flow: &Flow, flags: TcpFlags, ttl: u8, payload: &[u8]) -> TcpSegment {
    TcpSegment {
        flow: flow.clone(),
        seq: 1000,
        ack: 0,
        flags,
        window: 65535,
        options: TcpOptions::default(),
        ttl,
        payload: payload.to_vec(),
    }
}
fn seg_window(flow: &Flow, flags: TcpFlags, ttl: u8, window: u16) -> TcpSegment {
    TcpSegment {
        flow: flow.clone(),
        seq: 1000,
        ack: 0,
        flags,
        window,
        options: TcpOptions::default(),
        ttl,
        payload: vec![],
    }
}
fn tls_hello() -> Vec<u8> {
    vec![0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00]
}
fn established_state(now: Instant) -> FlowState {
    let mut state = FlowState::new(now);
    let syn_ack = seg(&server_flow(), TcpFlags::SYN | TcpFlags::ACK, 52, &[]);
    state.update(&syn_ack, &client_flow(), now);
    let hello = seg(
        &client_flow(),
        TcpFlags::PSH | TcpFlags::ACK,
        64,
        &tls_hello(),
    );
    state.update(&hello, &client_flow(), now);
    state
}

#[test]
fn rst_with_ttl_anomaly_detected() {
    let now = Instant::now();
    let state = established_state(now);
    let cfg = TspuConfig::default();
    let rst = seg(&server_flow(), TcpFlags::RST, 128, &[]);
    let signal = injection::check_rst(&rst, &state, &cfg, &client_flow(), now);
    assert!(signal.is_some());
    match signal.unwrap() {
        BlockageSignal::RstInjection {
            ttl_expected: 52,
            ttl_actual: 128,
            ..
        } => {}
        other => panic!("unexpected: {:?}", other),
    }
}

#[test]
fn rst_with_normal_ttl_not_detected() {
    let now = Instant::now();
    let state = established_state(now);
    let cfg = TspuConfig::default();
    let rst = seg(&server_flow(), TcpFlags::RST, 52, &[]);
    assert!(injection::check_rst(&rst, &state, &cfg, &client_flow(), now).is_none());
}

#[test]
fn rst_from_client_not_detected() {
    let now = Instant::now();
    let state = established_state(now);
    let cfg = TspuConfig::default();
    let rst = seg(&client_flow(), TcpFlags::RST, 128, &[]);
    assert!(injection::check_rst(&rst, &state, &cfg, &client_flow(), now).is_none());
}

#[test]
fn fin_with_ttl_anomaly_post_hello_detected() {
    let now = Instant::now();
    let state = established_state(now);
    let cfg = TspuConfig::default();
    let fin = seg(&server_flow(), TcpFlags::FIN | TcpFlags::ACK, 128, &[]);
    assert!(injection::check_fin(&fin, &state, &cfg, &client_flow()).is_some());
}

#[test]
fn fin_without_ttl_anomaly_not_detected() {
    let now = Instant::now();
    let state = established_state(now);
    let cfg = TspuConfig::default();
    let fin = seg(&server_flow(), TcpFlags::FIN | TcpFlags::ACK, 52, &[]);
    assert!(injection::check_fin(&fin, &state, &cfg, &client_flow()).is_none());
}

#[test]
fn window_zero_with_ttl_anomaly_detected() {
    let now = Instant::now();
    let state = established_state(now);
    let cfg = TspuConfig::default();
    let pkt = seg_window(&server_flow(), TcpFlags::ACK, 128, 0);
    assert!(injection::check_window(&pkt, &state, &cfg, &client_flow()).is_some());
}

#[test]
fn window_normal_not_detected() {
    let now = Instant::now();
    let state = established_state(now);
    let cfg = TspuConfig::default();
    let pkt = seg_window(&server_flow(), TcpFlags::ACK, 128, 65535);
    assert!(injection::check_window(&pkt, &state, &cfg, &client_flow()).is_none());
}
