use reflex_core::detector::DetectorEvent;
use reflex_core::geneva::tspu::{BlockageSignal, TspuConfig, TspuDetector};
use reflex_core::types::{Flow, Protocol, TcpFlags, TcpOptions, TcpSegment};
use reflex_core::Detector;
use std::net::{Ipv4Addr, SocketAddr};


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
fn tls_hello() -> Vec<u8> {
    vec![0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00]
}

#[test]
fn detects_rst_injection_step_by_step() {
    let cfg = TspuConfig::default();
    let detector = TspuDetector::new(cfg, client_flow());

    let (detector, sigs) = detector.step(DetectorEvent::Packet(seg(
        &client_flow(),
        TcpFlags::SYN,
        100,
        64,
        &[],
    )));
    assert!(sigs.is_empty());

    let (detector, sigs) = detector.step(DetectorEvent::Packet(seg(
        &server_flow(),
        TcpFlags::SYN | TcpFlags::ACK,
        1000,
        52,
        &[],
    )));
    assert!(sigs.is_empty());

    let (detector, sigs) = detector.step(DetectorEvent::Packet(seg(
        &client_flow(),
        TcpFlags::PSH | TcpFlags::ACK,
        101,
        64,
        &tls_hello(),
    )));
    assert!(sigs.is_empty());

    let (_detector, sigs) = detector.step(DetectorEvent::Packet(seg(
        &server_flow(),
        TcpFlags::RST,
        1001,
        128,
        &[],
    )));
    assert_eq!(sigs.len(), 1);
    assert!(matches!(
        sigs[0],
        BlockageSignal::RstInjection {
            ttl_actual: 128,
            ..
        }
    ));
}

#[tokio::test]
async fn detects_rst_injection_via_stream() {
    use futures::StreamExt;
    use reflex_core::ReflexExt;
    use tokio_stream::iter;

    let packets = vec![
        seg(&client_flow(), TcpFlags::SYN, 100, 64, &[]),
        seg(&server_flow(), TcpFlags::SYN | TcpFlags::ACK, 1000, 52, &[]),
        seg(
            &client_flow(),
            TcpFlags::PSH | TcpFlags::ACK,
            101,
            64,
            &tls_hello(),
        ),
        seg(&server_flow(), TcpFlags::RST, 1001, 128, &[]),
    ];

    let detector = TspuDetector::new(TspuConfig::default(), client_flow());

    let signals: Vec<BlockageSignal> = iter(packets).detect(detector).collect().await;

    assert!(!signals.is_empty());
    assert!(signals
        .iter()
        .any(|s| matches!(s, BlockageSignal::RstInjection { .. })));
}
