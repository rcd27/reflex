//! ТРАНСПОРТ QUIC НА НАСТОЯЩЕМ РУКОПОЖАТИИ.
//!
//! Фикстура снята не нами: `Initial` собрал **curl/ngtcp2**, кадры записал **tcpdump -i any**
//! (канальный слой Linux SLL2, не Ethernet), а имя `www.google.com` независимо подтвердил
//! **tshark -e tls.handshake.extensions_server_name`. Ни одного нашего байта в цепочке
//! производителей — синтетика проверяла бы нас же обоими концами.
//!
//! Предмет теста — ДОРОГА: расшифровка `Initial` лежала в фундаменте готовой, а имя цели до
//! цепочки не доходило, потому что транспорта не было. Здесь проверяется, что доходит.

#![cfg(feature = "quic")]

use reflex::*;

/// Прибор, говорящий на каждом пакете: предмет — доезд букв, а не пороги паркового прибора.
#[derive(Clone, Copy, Default)]
struct Always;

impl Mealy for Always {
    type In = DetectorEvent<Seen>;
    type Out = SmallVec<[Distress; 2]>;
    type Log = ();

    fn step(self, event: Self::In) -> (Self, Self::Out, ()) {
        match event {
            DetectorEvent::Packet { .. } => (self, smallvec![Distress::NoBytes], ()),
            DetectorEvent::Tick { .. } | DetectorEvent::Opaque { .. } | DetectorEvent::Torn { .. } => {
                (self, SmallVec::new(), ())
            }
        }
    }
}

/// ПРЕДМЕТ: имя цели из ЗАШИФРОВАННОГО `Initial` доезжает до реакции.
///
/// Это первый прогон разбора QUIC на настоящих байтах во всём дереве: в ядре он поверялся по частям
/// (варинты, заголовок, склейка кусков), а целиком — «байты с провода → имя» — ни разу. Механизм
/// стоял написанным и непредъявленным.
#[test]
fn имя_цели_достаётся_из_настоящего_quic_рукопожатия() {
    let heard = std::sync::Mutex::new(Vec::new());

    let report = pcap("tests/fixtures/quic-handshake.pcap")
        .from(Quic)
        .extract(Sni)
        .detect(own(Always))
        .on(|target: &str, _distress: Distress| {
            heard
                .lock()
                .expect("журнал не отравлен")
                .push(target.to_string())
        })
        .run();

    let heard = heard.into_inner().expect("журнал не отравлен");
    assert!(
        heard.iter().any(|name| name == "www.google.com"),
        "имя обязано прийти из расшифрованного `Initial`, как его читает и tshark; \
         услышано: {heard:?}, отчёт: {report:?}"
    );
}

/// Вторая половина: `.from(Tcp)` на той же записи НЕ ВИДИТ НИЧЕГО — и это не дефект, а причина,
/// по которой транспорт понадобился. Без этой половины первый тест зелен и на цепочке, которая
/// слышит всё подряд.
#[test]
fn тот_же_файл_на_транспорте_tcp_молчит() {
    let heard = std::sync::Mutex::new(Vec::new());

    pcap("tests/fixtures/quic-handshake.pcap")
        .from(Tcp)
        .extract(Sni)
        .detect(own(Always))
        .on(|target: &str, _distress: Distress| {
            heard
                .lock()
                .expect("журнал не отравлен")
                .push(target.to_string())
        })
        .run();

    assert!(
        heard.into_inner().expect("журнал не отравлен").is_empty(),
        "беда живёт на 443/UDP, а `.from(Tcp)` слушает TCP — молчание здесь ВЕРНО, и именно оно \
         неотличимо от «всё хорошо» для того, кто не знает про транспорт"
    );
}

// ─── ЗАКОН ПОВТОРА, поданный транспорту напрямую ───────────────────────────────────────────────
//
// Прямо `Transport::observe`, а не через цепочку: предмет — ОДНО правило разбора, и гонять ради
// него весь движок значило бы проверять заодно десять чужих законов. Возможно это потому, что
// `Read`/`Datagram` выведены наружу: без них свой транспорт снаружи не написать и не поверить.

use reflex_core::types::{Addr, Dir, Flow, Protocol};

fn talk() -> Flow {
    Flow {
        src: "10.0.0.5:40000".parse::<std::net::SocketAddr>().unwrap(),
        dst: "142.251.156.119:443".parse::<std::net::SocketAddr>().unwrap(),
        protocol: Protocol::Udp,
    }
}

/// Первый клиентский `Initial` из настоящей записи — берём его байты, а не сочиняем: заголовок
/// QUIC сочинить можно, но тогда поверялся бы наш сочинитель.
fn real_initial() -> Vec<u8> {
    let data = std::fs::read("tests/fixtures/quic-handshake.pcap").expect("фикстура на месте");
    let (frames, _broken) = reflex_core::pcap::read(&data, std::time::Instant::now());
    let net = frames.first().expect("кадр есть").network().to_vec();
    let ihl = ((net[0] & 0x0f) as usize) * 4;
    net[ihl + 8..].to_vec()
}

fn seen(state: &mut QuicState, payload: &[u8], dir: Dir) -> Seen {
    let datagram = Datagram {
        dst: Addr(0x8EFB_9C77),
        dir,
        flow: talk(),
        payload,
    };
    match Quic::observe(state, Read::Udp(datagram)) {
        Observation::Seen(observed) => observed.wire,
        other => panic!("наблюдение обязано состояться, а вышло другое: {:?}", other.кратко()),
    }
}

trait Кратко {
    fn кратко(&self) -> &'static str;
}

impl<W> Кратко for Observation<W> {
    fn кратко(&self) -> &'static str {
        match self {
            Observation::Seen(_) => "наблюдение",
            Observation::Unread(_) => "непрочитанное",
            Observation::Foreign => "чужое",
        }
    }
}

/// ПРЕДМЕТ: повтор `Initial` с тем же `DCID`, пока цель молчит, — это ПОВТОР, и он обязан
/// называться своим словом. Клиент, не получивший ответа, шлёт открытие заново; для приборов это
/// та же улика, что повтор `ClientHello` на TCP.
#[test]
fn повтор_открытия_при_молчащей_цели_называется_повтором() {
    let initial = real_initial();
    let mut state = QuicState::default();

    assert!(
        matches!(seen(&mut state, &initial, Dir::Up), Seen::Payload { from_client: true, .. }),
        "первое открытие — голова разговора: по ней узнаётся цель"
    );
    assert!(
        matches!(seen(&mut state, &initial, Dir::Up), Seen::Resent { .. }),
        "второе открытие с тем же DCID при молчащей цели — повтор"
    );
}

/// Вторая половина, и она не симметрия ради симметрии: ПОСЛЕ ОТВЕТА ЦЕЛИ тот же повтор уликой быть
/// перестаёт. Так выглядит миграция соединения — клиент шлёт `Initial` заново по другому пути, и
/// обвинять цель за это значило бы выдать штатное поведение за беду.
#[test]
fn после_ответа_цели_повтор_уликой_не_является() {
    let initial = real_initial();
    let mut state = QuicState::default();

    let _ = seen(&mut state, &initial, Dir::Up);
    assert!(
        matches!(seen(&mut state, b"\x40\x01\x02\x03", Dir::Down), Seen::Received { .. }),
        "датаграмма вниз — цель ответила"
    );

    assert!(
        !matches!(seen(&mut state, &initial, Dir::Up), Seen::Resent { .. }),
        "после ответа цели повтор открытия улики не несёт"
    );
}
