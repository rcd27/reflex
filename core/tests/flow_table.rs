use reflex_core::detector::DetectorEvent;
use reflex_core::flow_table::FlowTable;
use reflex_core::step::Step;
use reflex_core::types::{Flow, Protocol, TcpFlags, TcpOptions, TcpSegment};
use smallvec::SmallVec;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

#[derive(Clone)]
struct RstCounter {
    count: u32,
    flow: Flow,
}

impl Step for RstCounter {
    type From = DetectorEvent<TcpSegment>;
    type To = SmallVec<[u32; 2]>;

    fn step(mut self, event: Self::From) -> (Self, Self::To) {
        let mut signals = SmallVec::new();
        if let DetectorEvent::Packet { input: ref seg, .. } = event {
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

/// Простой заведомо длиннее прогона файла: тесты здесь — про АДРЕСАЦИЮ пакета в детектор
/// (нормализация флоу, переиспользование, счёт), а не про эвикт мёртвых потоков. Эвикт покрыт
/// юнит-тестами в `core/src/flow_table.rs` и вмешиваться сюда не должен.
const IDLE: Duration = Duration::from_secs(3600);

/// Единственная дверь к конструктору. Отдельная функция, потому что расширение
/// `FlowTable::new` (idle-таймаут, 8d27bd1) отстало ровно здесь — девять одинаковых вызовов
/// правились по одному, и файл остался несобираемым больше месяца.
fn new_table() -> FlowTable<RstCounter> {
    FlowTable::new(IDLE, |flow| RstCounter { count: 0, flow })
}

#[test]
fn process_creates_detector_on_first_packet() {
    let mut table = new_table();
    let seg = make_segment(12345, 443, TcpFlags::SYN);
    let signals = table.process(&seg, Instant::now());
    assert!(signals.is_empty());
    assert_eq!(table.flow_count(), 1);
}

#[test]
fn process_reuses_detector_for_same_flow() {
    let mut table = new_table();
    let rst = make_segment(12345, 443, TcpFlags::RST);
    let signals1 = table.process(&rst, Instant::now());
    assert_eq!(signals1.as_slice(), &[1]);
    let signals2 = table.process(&rst, Instant::now());
    assert_eq!(signals2.as_slice(), &[2]);
    assert_eq!(table.flow_count(), 1);
}

#[test]
fn process_normalizes_server_response_to_same_flow() {
    let mut table = new_table();
    let syn = make_segment(12345, 443, TcpFlags::SYN);
    table.process(&syn, Instant::now());

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
    let signals = table.process(&rst, Instant::now());
    assert_eq!(signals.as_slice(), &[1]);
    assert_eq!(table.flow_count(), 1);
}

#[test]
fn different_flows_get_different_detectors() {
    let mut table = new_table();
    let rst1 = make_segment(11111, 443, TcpFlags::RST);
    let rst2 = make_segment(22222, 443, TcpFlags::RST);
    table.process(&rst1, Instant::now());
    table.process(&rst2, Instant::now());
    assert_eq!(table.flow_count(), 2);
}

#[test]
fn tick_visits_all_flows() {
    let mut table = new_table();
    let syn1 = make_segment(11111, 443, TcpFlags::SYN);
    let syn2 = make_segment(22222, 443, TcpFlags::SYN);
    table.process(&syn1, Instant::now());
    table.process(&syn2, Instant::now());
    assert_eq!(table.flow_count(), 2);

    // tick() should visit all flows (no signals from RstCounter on Tick)
    let signals = table.tick(Instant::now());
    assert!(signals.is_empty());
    // Flows should still be present after tick
    assert_eq!(table.flow_count(), 2);
}

#[test]
fn get_returns_detector_for_existing_flow() {
    let mut table = new_table();
    let seg = make_segment(12345, 443, TcpFlags::RST);
    table.process(&seg, Instant::now());

    let detector = table.get(&seg.flow);
    assert!(detector.is_some());
    assert_eq!(detector.unwrap().count, 1);
}

#[test]
fn get_returns_none_for_missing_flow() {
    let table = new_table();
    let seg = make_segment(12345, 443, TcpFlags::SYN);
    assert!(table.get(&seg.flow).is_none());
}

#[test]
fn multiple_flows_with_different_states() {
    let mut table = new_table();

    let rst_a = make_segment(11111, 443, TcpFlags::RST);
    let rst_b = make_segment(22222, 443, TcpFlags::RST);

    // Flow A gets 3 RSTs
    table.process(&rst_a, Instant::now());
    table.process(&rst_a, Instant::now());
    table.process(&rst_a, Instant::now());

    // Flow B gets 1 RST
    table.process(&rst_b, Instant::now());

    assert_eq!(table.flow_count(), 2);
    assert_eq!(table.get(&rst_a.flow).unwrap().count, 3);
    assert_eq!(table.get(&rst_b.flow).unwrap().count, 1);
}

#[test]
fn normalize_reverses_high_port_source() {
    // When src has a high port and dst has a high port (not 443, not <1024),
    // flow gets reversed for normalization. Verify they map to the same detector.
    let mut table = new_table();

    let seg_forward = make_segment(12345, 443, TcpFlags::SYN);
    table.process(&seg_forward, Instant::now());

    // Reverse direction (server -> client)
    let seg_reverse = TcpSegment {
        flow: Flow {
            src: SocketAddr::new(Ipv4Addr::new(93, 184, 216, 34).into(), 443),
            dst: SocketAddr::new(Ipv4Addr::new(10, 0, 0, 1).into(), 12345),
            protocol: Protocol::Tcp,
        },
        seq: 0,
        ack: 1001,
        flags: TcpFlags::RST,
        window: 0,
        options: TcpOptions::default(),
        ttl: 53,
        payload: vec![],
    };

    let signals = table.process(&seg_reverse, Instant::now());
    assert_eq!(signals.as_slice(), &[1]);
    // Both directions should be in the same flow entry
    assert_eq!(table.flow_count(), 1);
}
