use std::net::{Ipv4Addr, SocketAddr};
use std::time::Instant;

use reflex_core::geneva::tspu::flow_state::{FlowPhase, FlowState};
use reflex_core::types::{Flow, Protocol, TcpFlags, TcpOptions, TcpSegment};

fn client_flow() -> Flow {
    Flow {
        src: SocketAddr::new(Ipv4Addr::new(10, 0, 0, 1).into(), 12345),
        dst: SocketAddr::new(Ipv4Addr::new(93, 184, 216, 34).into(), 443),
        protocol: Protocol::Tcp,
    }
}

fn server_flow() -> Flow {
    Flow {
        src: SocketAddr::new(Ipv4Addr::new(93, 184, 216, 34).into(), 443),
        dst: SocketAddr::new(Ipv4Addr::new(10, 0, 0, 1).into(), 12345),
        protocol: Protocol::Tcp,
    }
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

fn tls_hello_payload() -> Vec<u8> {
    vec![0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00]
}

#[test]
fn new_flow_starts_syn_sent() {
    let state = FlowState::new(Instant::now());
    assert_eq!(state.phase(), FlowPhase::SynSent);
}

#[test]
fn syn_ack_transitions_to_established() {
    let now = Instant::now();
    let mut state = FlowState::new(now);
    let syn_ack = seg(&server_flow(), TcpFlags::SYN | TcpFlags::ACK, 1000, 52, &[]);
    state.update(&syn_ack, &client_flow(), now);
    assert_eq!(state.phase(), FlowPhase::Established);
    assert_eq!(state.ttl_baseline(), Some(52));
}

#[test]
fn client_hello_sets_flag_and_timestamp() {
    let now = Instant::now();
    let mut state = FlowState::new(now);
    let syn_ack = seg(&server_flow(), TcpFlags::SYN | TcpFlags::ACK, 1000, 52, &[]);
    state.update(&syn_ack, &client_flow(), now);
    let hello = seg(
        &client_flow(),
        TcpFlags::PSH | TcpFlags::ACK,
        1,
        64,
        &tls_hello_payload(),
    );
    state.update(&hello, &client_flow(), now);
    assert!(state.has_client_hello());
    assert!(state.client_hello_at().is_some());
}

#[test]
fn client_hello_retransmit_does_not_reset_timestamp() {
    let now = Instant::now();
    let later = now + std::time::Duration::from_millis(500);
    let mut state = FlowState::new(now);
    let syn_ack = seg(&server_flow(), TcpFlags::SYN | TcpFlags::ACK, 1000, 52, &[]);
    state.update(&syn_ack, &client_flow(), now);
    let hello = seg(
        &client_flow(),
        TcpFlags::PSH | TcpFlags::ACK,
        1,
        64,
        &tls_hello_payload(),
    );
    state.update(&hello, &client_flow(), now);
    let first_ts = state.client_hello_at().unwrap();
    state.update(&hello, &client_flow(), later);
    assert_eq!(state.client_hello_at().unwrap(), first_ts);
    assert_eq!(state.retransmit_count(), 1);
}

#[test]
fn server_data_transitions_to_transferring() {
    let now = Instant::now();
    let mut state = FlowState::new(now);
    let syn_ack = seg(&server_flow(), TcpFlags::SYN | TcpFlags::ACK, 1000, 52, &[]);
    state.update(&syn_ack, &client_flow(), now);
    let data = seg(
        &server_flow(),
        TcpFlags::PSH | TcpFlags::ACK,
        1000,
        52,
        &[1, 2, 3],
    );
    state.update(&data, &client_flow(), now);
    assert_eq!(state.phase(), FlowPhase::Transferring);
    assert_eq!(state.bytes_rx(), 3);
}

#[test]
fn fin_in_transferring_goes_to_finished() {
    let now = Instant::now();
    let mut state = FlowState::new(now);
    let syn_ack = seg(&server_flow(), TcpFlags::SYN | TcpFlags::ACK, 1000, 52, &[]);
    state.update(&syn_ack, &client_flow(), now);
    let data = seg(
        &server_flow(),
        TcpFlags::PSH | TcpFlags::ACK,
        1000,
        52,
        &[1, 2, 3],
    );
    state.update(&data, &client_flow(), now);
    let fin = seg(&server_flow(), TcpFlags::FIN | TcpFlags::ACK, 1003, 52, &[]);
    state.update(&fin, &client_flow(), now);
    assert_eq!(state.phase(), FlowPhase::Finished);
}

#[test]
fn direction_detection_by_flow() {
    let now = Instant::now();
    let mut state = FlowState::new(now);
    let pkt = seg(&server_flow(), TcpFlags::SYN | TcpFlags::ACK, 1000, 52, &[]);
    state.update(&pkt, &client_flow(), now);
    assert_eq!(state.ttl_baseline(), Some(52));
}

#[test]
fn server_retransmit_detection() {
    let now = Instant::now();
    let mut state = FlowState::new(now);
    let syn_ack = seg(&server_flow(), TcpFlags::SYN | TcpFlags::ACK, 1000, 52, &[]);
    state.update(&syn_ack, &client_flow(), now);
    let data1 = seg(
        &server_flow(),
        TcpFlags::PSH | TcpFlags::ACK,
        1000,
        52,
        &[1, 2, 3],
    );
    state.update(&data1, &client_flow(), now);
    let data2 = seg(
        &server_flow(),
        TcpFlags::PSH | TcpFlags::ACK,
        1000,
        52,
        &[1, 2, 3],
    );
    state.update(&data2, &client_flow(), now);
    assert_eq!(state.server_retransmit_count(), 1);
}
