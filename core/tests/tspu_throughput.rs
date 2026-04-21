use reflex_core::geneva::tspu::flow_state::FlowState;
use reflex_core::geneva::tspu::throughput;
use reflex_core::geneva::tspu::{BlockageSignal, TspuConfig};
use reflex_core::types::{Flow, Protocol, TcpFlags, TcpOptions, TcpSegment};
use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

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
fn seg(flow: &Flow, flags: TcpFlags, seq: u32, ttl: u8, payload: &[u8]) -> TcpSegment {
    TcpSegment {
        flow: flow.clone(),
        seq,
        ack: 0,
        flags,
        window: 65535,
        options: TcpOptions::default(),
        ttl,
        payload: payload.to_vec(),
    }
}

fn transferring_state(start: Instant, bytes: usize) -> FlowState {
    let mut state = FlowState::new(start);
    let syn_ack = seg(&server_flow(), TcpFlags::SYN | TcpFlags::ACK, 1000, 52, &[]);
    state.update(&syn_ack, &client_flow(), start);
    let data = seg(
        &server_flow(),
        TcpFlags::PSH | TcpFlags::ACK,
        1000,
        52,
        &vec![0u8; bytes],
    );
    state.update(&data, &client_flow(), start);
    state
}

#[test]
fn throttle_cliff_detected() {
    let start = Instant::now();
    let stall = start + Duration::from_secs(4);
    let state = transferring_state(start, 16384);
    let cfg = TspuConfig::default();
    let sig = throughput::check_cliff(&state, &cfg, &client_flow(), stall);
    assert!(sig.is_some());
    assert!(matches!(
        sig.unwrap(),
        BlockageSignal::ThrottleCliff {
            bytes_before: 16384,
            ..
        }
    ));
}

#[test]
fn throttle_cliff_not_enough_bytes() {
    let start = Instant::now();
    let stall = start + Duration::from_secs(4);
    let state = transferring_state(start, 100);
    let cfg = TspuConfig::default();
    assert!(throughput::check_cliff(&state, &cfg, &client_flow(), stall).is_none());
}

#[test]
fn throttle_cliff_too_many_bytes() {
    let start = Instant::now();
    let stall = start + Duration::from_secs(4);
    let state = transferring_state(start, 70000);
    let cfg = TspuConfig::default();
    assert!(throughput::check_cliff(&state, &cfg, &client_flow(), stall).is_none());
}

#[test]
fn throttle_cliff_not_stalled_long_enough() {
    let start = Instant::now();
    let soon = start + Duration::from_secs(1);
    let state = transferring_state(start, 16384);
    let cfg = TspuConfig::default();
    assert!(throughput::check_cliff(&state, &cfg, &client_flow(), soon).is_none());
}

#[test]
fn throttle_probabilistic_detected() {
    let start = Instant::now();
    let later = start + Duration::from_secs(11);
    let mut state = transferring_state(start, 1000);
    for _ in 0..5 {
        let retx = seg(
            &server_flow(),
            TcpFlags::PSH | TcpFlags::ACK,
            1000,
            52,
            &[0u8; 100],
        );
        state.update(&retx, &client_flow(), start + Duration::from_secs(1));
    }
    let cfg = TspuConfig::default();
    assert!(throughput::check_probabilistic(&state, &cfg, &client_flow(), later).is_some());
}

#[test]
fn ack_drop_detected() {
    let start = Instant::now();
    let mut state = transferring_state(start, 1000);
    let client_data = seg(
        &client_flow(),
        TcpFlags::PSH | TcpFlags::ACK,
        100,
        64,
        &[1, 2, 3],
    );
    state.update(&client_data, &client_flow(), start);
    for _ in 0..6 {
        let retx = seg(
            &server_flow(),
            TcpFlags::PSH | TcpFlags::ACK,
            1000,
            52,
            &[0u8; 100],
        );
        state.update(&retx, &client_flow(), start);
    }
    let cfg = TspuConfig::default();
    assert!(throughput::check_ack_drop(
        &state,
        &cfg,
        &client_flow(),
        start + Duration::from_secs(1)
    )
    .is_some());
}
