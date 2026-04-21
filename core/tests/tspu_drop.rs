use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use reflex_core::geneva::tspu::drop as tspu_drop;
use reflex_core::geneva::tspu::flow_state::FlowState;
use reflex_core::geneva::tspu::{BlockageSignal, TspuConfig};
use reflex_core::types::{Flow, Protocol, TcpFlags, TcpOptions, TcpSegment};

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

fn tls_hello() -> Vec<u8> {
    vec![0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00]
}

#[test]
fn ip_blackhole_after_syn_timeout() {
    let start = Instant::now();
    let later = start + Duration::from_secs(6);
    let mut state = FlowState::new(start);
    let syn = seg(&client_flow(), TcpFlags::SYN, 64, &[]);
    state.update(&syn, &client_flow(), start + Duration::from_secs(1));
    let cfg = TspuConfig::default();
    assert!(tspu_drop::check_ip_blackhole(&state, &cfg, &client_flow(), later).is_some());
}

#[test]
fn ip_blackhole_not_before_timeout() {
    let start = Instant::now();
    let later = start + Duration::from_secs(3);
    let mut state = FlowState::new(start);
    let syn = seg(&client_flow(), TcpFlags::SYN, 64, &[]);
    state.update(&syn, &client_flow(), start + Duration::from_secs(1));
    let cfg = TspuConfig::default();
    assert!(tspu_drop::check_ip_blackhole(&state, &cfg, &client_flow(), later).is_none());
}

#[test]
fn ip_blackhole_not_if_syn_ack_received() {
    let start = Instant::now();
    let later = start + Duration::from_secs(6);
    let mut state = FlowState::new(start);
    let syn_ack = seg(&server_flow(), TcpFlags::SYN | TcpFlags::ACK, 52, &[]);
    state.update(&syn_ack, &client_flow(), start);
    let cfg = TspuConfig::default();
    assert!(tspu_drop::check_ip_blackhole(&state, &cfg, &client_flow(), later).is_none());
}

#[test]
fn silent_drop_after_hello_timeout() {
    let start = Instant::now();
    let later = start + Duration::from_secs(16);
    let mut state = FlowState::new(start);
    let syn_ack = seg(&server_flow(), TcpFlags::SYN | TcpFlags::ACK, 52, &[]);
    state.update(&syn_ack, &client_flow(), start);
    let hello = seg(
        &client_flow(),
        TcpFlags::PSH | TcpFlags::ACK,
        64,
        &tls_hello(),
    );
    state.update(&hello, &client_flow(), start);
    let cfg = TspuConfig::default();
    let sig = tspu_drop::check_silent_drop(&state, &cfg, &client_flow(), later);
    assert!(sig.is_some());
    assert!(matches!(sig.unwrap(), BlockageSignal::SilentDrop { .. }));
}

#[test]
fn silent_drop_not_before_timeout() {
    let start = Instant::now();
    let later = start + Duration::from_secs(10);
    let mut state = FlowState::new(start);
    let syn_ack = seg(&server_flow(), TcpFlags::SYN | TcpFlags::ACK, 52, &[]);
    state.update(&syn_ack, &client_flow(), start);
    let hello = seg(
        &client_flow(),
        TcpFlags::PSH | TcpFlags::ACK,
        64,
        &tls_hello(),
    );
    state.update(&hello, &client_flow(), start);
    let cfg = TspuConfig::default();
    assert!(tspu_drop::check_silent_drop(&state, &cfg, &client_flow(), later).is_none());
}

#[test]
fn silent_drop_not_if_server_responded() {
    let start = Instant::now();
    let later = start + Duration::from_secs(16);
    let mut state = FlowState::new(start);
    let syn_ack = seg(&server_flow(), TcpFlags::SYN | TcpFlags::ACK, 52, &[]);
    state.update(&syn_ack, &client_flow(), start);
    let hello = seg(
        &client_flow(),
        TcpFlags::PSH | TcpFlags::ACK,
        64,
        &tls_hello(),
    );
    state.update(&hello, &client_flow(), start);
    let data = seg(
        &server_flow(),
        TcpFlags::PSH | TcpFlags::ACK,
        52,
        &[1, 2, 3],
    );
    state.update(&data, &client_flow(), start);
    let cfg = TspuConfig::default();
    assert!(tspu_drop::check_silent_drop(&state, &cfg, &client_flow(), later).is_none());
}

#[test]
fn silent_drop_not_if_rst_received() {
    let start = Instant::now();
    let later = start + Duration::from_secs(16);
    let mut state = FlowState::new(start);
    let syn_ack = seg(&server_flow(), TcpFlags::SYN | TcpFlags::ACK, 52, &[]);
    state.update(&syn_ack, &client_flow(), start);
    let hello = seg(
        &client_flow(),
        TcpFlags::PSH | TcpFlags::ACK,
        64,
        &tls_hello(),
    );
    state.update(&hello, &client_flow(), start);
    let rst = seg(&server_flow(), TcpFlags::RST, 128, &[]);
    state.update(&rst, &client_flow(), start);
    let cfg = TspuConfig::default();
    assert!(tspu_drop::check_silent_drop(&state, &cfg, &client_flow(), later).is_none());
}

#[test]
fn fire_once_prevents_duplicate() {
    let start = Instant::now();
    let later = start + Duration::from_secs(16);
    let mut state = FlowState::new(start);
    let syn_ack = seg(&server_flow(), TcpFlags::SYN | TcpFlags::ACK, 52, &[]);
    state.update(&syn_ack, &client_flow(), start);
    let hello = seg(
        &client_flow(),
        TcpFlags::PSH | TcpFlags::ACK,
        64,
        &tls_hello(),
    );
    state.update(&hello, &client_flow(), start);
    let cfg = TspuConfig::default();
    assert!(tspu_drop::check_silent_drop(&state, &cfg, &client_flow(), later).is_some());
    state.timeout_signal_fired = true;
    assert!(tspu_drop::check_silent_drop(&state, &cfg, &client_flow(), later).is_none());
}
