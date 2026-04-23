use reflex_core::detector::DetectorEvent;
use reflex_core::flow_table::FlowTable;
use reflex_core::types::{Flow, Protocol, TcpFlags, TcpOptions, TcpSegment};
use reflex_core::Detector;
use smallvec::SmallVec;
use std::net::{Ipv4Addr, SocketAddr};

#[derive(Clone)]
struct RstCounter {
    count: u32,
    flow: Flow,
}

impl Detector for RstCounter {
    type Input = TcpSegment;
    type Signal = u32;

    fn step(mut self, event: DetectorEvent<TcpSegment>) -> (Self, SmallVec<[u32; 2]>) {
        let mut signals = SmallVec::new();
        if let DetectorEvent::Packet(ref seg) = event {
            if seg.flags.is_rst() {
                self.count += 1;
                signals.push(self.count);
            }
        }
        (self, signals)
    }
}

fn make_segment(src_port: u16, dst_port: u16, flags: TcpFlags) -> TcpSegment {
    TcpSegment {
        flow: Flow {
            src: SocketAddr::new(Ipv4Addr::new(10, 0, 0, 1).into(), src_port),
            dst: SocketAddr::new(Ipv4Addr::new(93, 184, 216, 34).into(), dst_port),
            protocol: Protocol::Tcp,
        },
        seq: 1000,
        ack: 0,
        flags,
        window: 29200,
        options: TcpOptions::default(),
        ttl: 64,
        payload: vec![],
    }
}

#[test]
fn process_creates_detector_on_first_packet() {
    let mut table: FlowTable<RstCounter> = FlowTable::new(|flow| RstCounter { count: 0, flow });
    let seg = make_segment(12345, 443, TcpFlags::SYN);
    let signals = table.process(&seg);
    assert!(signals.is_empty());
    assert_eq!(table.flow_count(), 1);
}

#[test]
fn process_reuses_detector_for_same_flow() {
    let mut table: FlowTable<RstCounter> = FlowTable::new(|flow| RstCounter { count: 0, flow });
    let rst = make_segment(12345, 443, TcpFlags::RST);
    let signals1 = table.process(&rst);
    assert_eq!(signals1.as_slice(), &[1]);
    let signals2 = table.process(&rst);
    assert_eq!(signals2.as_slice(), &[2]);
    assert_eq!(table.flow_count(), 1);
}

#[test]
fn process_normalizes_server_response_to_same_flow() {
    let mut table: FlowTable<RstCounter> = FlowTable::new(|flow| RstCounter { count: 0, flow });
    let syn = make_segment(12345, 443, TcpFlags::SYN);
    table.process(&syn);

    let rst = TcpSegment {
        flow: Flow {
            src: SocketAddr::new(Ipv4Addr::new(93, 184, 216, 34).into(), 443),
            dst: SocketAddr::new(Ipv4Addr::new(10, 0, 0, 1).into(), 12345),
            protocol: Protocol::Tcp,
        },
        seq: 0,
        ack: 0,
        flags: TcpFlags::RST,
        window: 0,
        options: TcpOptions::default(),
        ttl: 53,
        payload: vec![],
    };
    let signals = table.process(&rst);
    assert_eq!(signals.as_slice(), &[1]);
    assert_eq!(table.flow_count(), 1);
}

#[test]
fn different_flows_get_different_detectors() {
    let mut table: FlowTable<RstCounter> = FlowTable::new(|flow| RstCounter { count: 0, flow });
    let rst1 = make_segment(11111, 443, TcpFlags::RST);
    let rst2 = make_segment(22222, 443, TcpFlags::RST);
    table.process(&rst1);
    table.process(&rst2);
    assert_eq!(table.flow_count(), 2);
}
