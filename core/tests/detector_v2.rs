use futures::StreamExt;
use reflex_core::types::{Flow, Protocol, TcpFlags, TcpOptions, TcpSegment};
use reflex_core::{Detector, DetectorEvent, ReflexExt};
use smallvec::SmallVec;
use std::net::{Ipv4Addr, SocketAddr};

#[derive(Debug)]
enum RstState {
    Idle,
    Established { server_ttl: u8 },
}

struct SimpleRstDetector {
    state: RstState,
}

#[derive(Debug, Clone, PartialEq)]
struct RstSignal {
    ttl_delta: i16,
}

impl Detector for SimpleRstDetector {
    type Input = TcpSegment;
    type Signal = RstSignal;

    fn step(mut self, event: DetectorEvent<TcpSegment>) -> (Self, SmallVec<[RstSignal; 2]>) {
        let mut signals = SmallVec::new();

        match event {
            DetectorEvent::Packet(seg) => {
                if seg.flags.is_syn_ack() {
                    self.state = RstState::Established {
                        server_ttl: seg.ttl,
                    };
                } else if seg.flags.is_rst() {
                    if let RstState::Established { server_ttl } = self.state {
                        let delta = seg.ttl as i16 - server_ttl as i16;
                        if delta.abs() > 5 {
                            signals.push(RstSignal { ttl_delta: delta });
                        }
                    }
                }
            }
            DetectorEvent::Tick(_) => {}
        }

        (self, signals)
    }
}

fn make_segment(flags: TcpFlags, ttl: u8) -> TcpSegment {
    TcpSegment {
        flow: Flow {
            src: SocketAddr::new(Ipv4Addr::new(10, 0, 0, 1).into(), 443),
            dst: SocketAddr::new(Ipv4Addr::new(10, 0, 0, 2).into(), 8080),
            protocol: Protocol::Tcp,
        },
        seq: 1,
        ack: 1,
        flags,
        window: 29200,
        options: TcpOptions::default(),
        ttl,
        payload: vec![],
    }
}

#[tokio::test]
async fn detector_v2_rst_injection_detected() {
    let packets = vec![
        make_segment(TcpFlags::SYN | TcpFlags::ACK, 52),
        make_segment(TcpFlags::RST, 63),
    ];

    let detector = SimpleRstDetector {
        state: RstState::Idle,
    };

    let signals: Vec<RstSignal> = futures::stream::iter(packets)
        .detect(detector)
        .collect()
        .await;

    assert_eq!(signals.len(), 1);
    assert_eq!(signals[0].ttl_delta, 11);
}

#[tokio::test]
async fn detector_v2_no_signal_for_normal_rst() {
    let packets = vec![
        make_segment(TcpFlags::SYN | TcpFlags::ACK, 64),
        make_segment(TcpFlags::RST, 64),
    ];

    let detector = SimpleRstDetector {
        state: RstState::Idle,
    };

    let signals: Vec<RstSignal> = futures::stream::iter(packets)
        .detect(detector)
        .collect()
        .await;

    assert!(signals.is_empty());
}

#[tokio::test]
async fn detector_v2_rst_without_syn_ack_ignored() {
    let packets = vec![make_segment(TcpFlags::RST, 128)];

    let detector = SimpleRstDetector {
        state: RstState::Idle,
    };

    let signals: Vec<RstSignal> = futures::stream::iter(packets)
        .detect(detector)
        .collect()
        .await;

    assert!(signals.is_empty());
}
