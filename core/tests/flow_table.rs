use reflex_core::detector::DetectorEvent;
use reflex_core::flow_table::{normalize_flow, FlowTable};
use reflex_core::mealy::Mealy;
use reflex_core::timeout::Departure;
use reflex_core::types::{Flow, HasFlow, Protocol, TcpFlags, TcpOptions, TcpSegment};
use reflex_core::word::{Base, Word};
use smallvec::SmallVec;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

/// ОБЛАСТЬ ЗАКОННОГО СТЕНДА.
///
/// Объявляется здесь, а не в фундаменте: закон обязан быть выразим для того, кто заводит свою
/// область снаружи, и стенд — законный заводящий.
struct Bench;
impl Base for Bench {
    type Fibre = ();
}

/// СЧЁТ СБРОСОВ — с именем, а не голым числом: адрес объявляет значение, а число молчит.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Count(u32);

impl Word for Count {
    type Of = Bench;
}

#[derive(Debug, Clone)]
struct RstCounter {
    count: u32,
}

/// Сброс концом НЕ объявляется: для этого дерева `RST` — беда (возможно, поддельная), а не
/// прощание. Машина живёт дальше и считает следующие.
impl reflex_core::detector::Ended for RstCounter {}

impl Mealy for RstCounter {
    type In = DetectorEvent<TcpSegment>;
    type Out = SmallVec<[Count; 2]>;
    type Log = ();

    fn step(mut self, event: Self::In) -> (Self, Self::Out, ()) {
        let mut signals = SmallVec::new();
        if let DetectorEvent::Packet { input: ref seg, .. } = event {
            if seg.flags.is_rst() {
                self.count += 1;
                signals.push(Count(self.count));
            }
        }
        (self, signals, ())
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
/// (нормализация флоу, переиспользование, счёт), а не про эвикт мёртвых потоков: тот проверяется
/// отдельно, юнит-тестами модуля, и вмешиваться сюда не должен.
const IDLE: Duration = Duration::from_secs(3600);

/// Единственная дверь к конструктору: правка сигнатуры трогает одно место, а не рассыпанные по
/// файлу вызовы.
fn new_table() -> FlowTable<RstCounter, Flow> {
    FlowTable::new(IDLE, 1024, |_key: &Flow| RstCounter { count: 0 })
}

#[test]
fn process_creates_detector_on_first_packet() {
    let mut table = new_table();
    let seg = make_segment(12345, 443, TcpFlags::SYN);
    let (said, _notes) = table.process(normalize_flow(seg.flow()), &seg, Instant::now());
    assert!(said.is_empty());
    assert_eq!(table.flow_count(), 1);
}

#[test]
fn process_reuses_detector_for_same_flow() {
    let mut table = new_table();
    let rst = make_segment(12345, 443, TcpFlags::RST);
    let (first, ()) = table.process(normalize_flow(rst.flow()), &rst, Instant::now());
    assert_eq!(first.as_slice(), &[Count(1)]);
    let (second, ()) = table.process(normalize_flow(rst.flow()), &rst, Instant::now());
    assert_eq!(second.as_slice(), &[Count(2)]);
    assert_eq!(table.flow_count(), 1);
}

#[test]
fn process_normalizes_server_response_to_same_flow() {
    let mut table = new_table();
    let syn = make_segment(12345, 443, TcpFlags::SYN);
    table.process(normalize_flow(syn.flow()), &syn, Instant::now());

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
    let (said, _notes) = table.process(normalize_flow(rst.flow()), &rst, Instant::now());
    assert_eq!(said.as_slice(), &[Count(1)]);
    assert_eq!(table.flow_count(), 1);
}

#[test]
fn different_flows_get_different_detectors() {
    let mut table = new_table();
    let rst1 = make_segment(11111, 443, TcpFlags::RST);
    let rst2 = make_segment(22222, 443, TcpFlags::RST);
    table.process(normalize_flow(rst1.flow()), &rst1, Instant::now());
    table.process(normalize_flow(rst2.flow()), &rst2, Instant::now());
    assert_eq!(table.flow_count(), 2);
}

#[test]
fn tick_visits_all_flows() {
    let mut table = new_table();
    let syn1 = make_segment(11111, 443, TcpFlags::SYN);
    let syn2 = make_segment(22222, 443, TcpFlags::SYN);
    table.process(normalize_flow(syn1.flow()), &syn1, Instant::now());
    table.process(normalize_flow(syn2.flow()), &syn2, Instant::now());
    assert_eq!(table.flow_count(), 2);

    // ТИК ОБХОДИТ ВСЕ ПОТОКИ, и с каждого выходит пара — даже когда сказать было нечего: `tick`
    // отдаёт то, что дал шаг, а не только непустое.
    let spoken = table.each(DetectorEvent::Tick {
        node: 1,
        at: Instant::now(),
    });
    assert_eq!(spoken.len(), 2, "тик обязан дойти до обоих потоков");
    assert!(
        spoken.iter().all(|(_, (said, _notes))| said.is_empty()),
        "счётчик сбросов на тике не говорит: {spoken:?}"
    );
    // Flows should still be present after tick
    assert_eq!(table.flow_count(), 2);
}

#[test]
fn get_returns_detector_for_existing_flow() {
    let mut table = new_table();
    let seg = make_segment(12345, 443, TcpFlags::RST);
    table.process(normalize_flow(seg.flow()), &seg, Instant::now());

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
    table.process(normalize_flow(rst_a.flow()), &rst_a, Instant::now());
    table.process(normalize_flow(rst_a.flow()), &rst_a, Instant::now());
    table.process(normalize_flow(rst_a.flow()), &rst_a, Instant::now());

    // Flow B gets 1 RST
    table.process(normalize_flow(rst_b.flow()), &rst_b, Instant::now());

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
    table.process(
        normalize_flow(seg_forward.flow()),
        &seg_forward,
        Instant::now(),
    );

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

    let (said, _notes) = table.process(
        normalize_flow(seg_reverse.flow()),
        &seg_reverse,
        Instant::now(),
    );
    assert_eq!(said.as_slice(), &[Count(1)]);
    // Both directions should be in the same flow entry
    assert_eq!(table.flow_count(), 1);
}

/// МАШИНА, ОБЪЯВИВШАЯ КОНЕЦ, УХОДИТ ИЗ ТАБЛИЦЫ СРАЗУ — не дожидаясь простоя (§12.6: уборка
/// выводится из алфавита; у разговора с прощанием она наступает раньше срока).
///
/// Держать исчерпанный разговор до истечения `idle_timeout` значит копить улику из чужих пауз и
/// занимать память тем, чего уже нет. Прежде так и было: приборы прощание слушали, память — нет.
#[test]
fn a_machine_that_declared_the_end_leaves_without_waiting_out_the_idle_timeout() {
    #[derive(Debug, Clone, Default)]
    struct Farewell {
        done: bool,
    }

    /// Предмет исчерпан, когда сторона ПОПРОЩАЛАСЬ (`FIN`). Сброс сюда не входит намеренно.
    impl reflex_core::detector::Ended for Farewell {
        fn ended(&self) -> bool {
            self.done
        }
    }

    impl Mealy for Farewell {
        type In = DetectorEvent<TcpSegment>;
        type Out = SmallVec<[Count; 2]>;
        type Log = ();

        fn step(mut self, event: Self::In) -> (Self, Self::Out, ()) {
            if let DetectorEvent::Packet { input: ref seg, .. } = event {
                if seg.flags.is_fin() {
                    self.done = true;
                    // ПОСЛЕДНЕЕ СЛОВО СКАЗАНО: машину снимают после шага, не вместо него.
                    return (self, smallvec::smallvec![Count(1)], ());
                }
            }
            (self, SmallVec::new(), ())
        }
    }

    let mut table: FlowTable<Farewell, Flow> =
        FlowTable::new(Duration::from_secs(3600), 1024, |_flow| Farewell::default());

    let alive = make_segment(40000, 443, TcpFlags::ACK);
    table.process(normalize_flow(alive.flow()), &alive, Instant::now());
    assert_eq!(table.flow_count(), 1, "разговор идёт — машина на месте");

    let reset = make_segment(40000, 443, TcpFlags::RST);
    table.process(normalize_flow(reset.flow()), &reset, Instant::now());
    assert_eq!(
        table.flow_count(),
        1,
        "сброс концом не объявлен: поддельный RST — предмет наблюдения, а не конец предмета"
    );

    let farewell = make_segment(40000, 443, TcpFlags::FIN);
    let (said, _) = table.process(normalize_flow(farewell.flow()), &farewell, Instant::now());
    assert_eq!(said.as_slice(), &[Count(1)], "последнее слово сказано");
    assert_eq!(
        table.flow_count(),
        0,
        "предмет исчерпан — память освобождена сразу, а не через час простоя"
    );
}

/// ПОТОЛОК ДЕРЖИТ ПАМЯТЬ КОНЕЧНОЙ ДАЖЕ ТОГДА, КОГДА НИКТО НЕ МОЛЧИТ.
///
/// Срок снимает ЗАМОЛЧАВШИХ, и против потока говорящих он бессилен: скан портов, раздача торрента,
/// ботнет за одним NAT. Замер на таблице без потолка: сто тысяч разговоров вошли, не встретив
/// возражения — то есть «память конечна» держалось лишь тем, что ключи вовремя затихают.
///
/// Свежий разговор входит ВСЕГДА, место освобождает самый давний по последнему наблюдению: отказ
/// принять новое сделал бы полную таблицу слепой к происходящему сейчас — и тем прочнее, чем
/// дольше она живёт.
#[test]
fn the_ceiling_keeps_memory_finite_even_when_nobody_falls_silent() {
    const CEILING: usize = 64;
    let t0 = Instant::now();
    let mut table: FlowTable<RstCounter, Flow> =
        FlowTable::new(Duration::from_secs(3600), CEILING, |_key: &Flow| {
            RstCounter { count: 0 }
        });

    // Тысяча разговоров, и ни один не молчит дольше часа: сроку снимать нечего.
    for n in 0..1000u16 {
        let seg = make_segment(10_000 + n, 443, TcpFlags::ACK);
        table.process(
            normalize_flow(seg.flow()),
            &seg,
            t0 + Duration::from_millis(n as u64),
        );
    }

    assert_eq!(
        table.flow_count(),
        CEILING,
        "потолок держит: без него вошли бы все тысяча"
    );

    let departed = table.departed();
    assert_eq!(
        departed.len(),
        1000 - CEILING,
        "каждая утрата названа: снимали ЖИВЫХ, и молчание о них неотличимо от «разговора не было»"
    );
    assert!(
        departed
            .iter()
            .all(|(_key, why)| matches!(why, Departure::Ceiling)),
        "и названа ПРИЧИНОЙ: по этому ключу помнит не только таблица, а убрать своё может лишь \
         тот, кто узнал об уходе — причина говорит ему, мёртвое сняли или живое"
    );

    assert!(
        table.departed().is_empty(),
        "объявления забирают один раз — второй раз говорить не о чем"
    );
}
