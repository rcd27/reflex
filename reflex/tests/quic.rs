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
            DetectorEvent::Tick { .. }
            | DetectorEvent::Opaque { .. }
            | DetectorEvent::Torn { .. } => (self, SmallVec::new(), ()),
        }
    }
}

/// ПРЕДМЕТ: имя цели из ЗАШИФРОВАННОГО `Initial` доезжает до реакции.
///
/// Это первый прогон разбора QUIC на настоящих байтах во всём дереве: в ядре он поверялся по частям
/// (варинты, заголовок, склейка кусков), а целиком — «байты с провода → имя» — ни разу. Механизм
/// стоял написанным и непредъявленным.
#[test]
fn the_target_name_is_lifted_from_a_real_quic_handshake() {
    let heard = std::sync::Mutex::new(Vec::new());

    let report = pcap("tests/fixtures/quic-handshake.pcap")
        .from(Quic)
        .extract(Sni)
        // ПРИБОРЫ ПАРКА СТОЯТ ЗДЕСЬ НАРОЧНО. Первая редакция обещала докблоком, что они встают на
        // QUIC «как есть», и обещание было неверным: компилятор потребителя его не подтвердил, а
        // мой собственный тест не мог — в нём стоял только `own(...)`. Теперь обещание держит
        // сборка ЭТОГО теста: разъедься словарь транспорта с парком, и он не соберётся.
        .detect(Retransmit::unanswered())
        .detect(Silence::after(secs(5)))
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
fn the_same_file_stays_silent_on_the_tcp_transport() {
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
        dst: "142.251.156.119:443"
            .parse::<std::net::SocketAddr>()
            .unwrap(),
        protocol: Protocol::Udp,
    }
}

/// Первый клиентский `Initial` из настоящей записи — берём его байты, а не сочиняем: заголовок
/// QUIC сочинить можно, но тогда поверялся бы наш сочинитель.
fn real_initial() -> Vec<u8> {
    datagram_of_record(0)
}

/// Датаграмма `n`-го кадра записи (с нуля). В записи кадры 0 и 1 — ОБА клиентские `Initial` с одним
/// `DCID`, через 8 мкс: `ClientHello` не влез в одну датаграмму, и имя лежит во второй (tshark).
fn datagram_of_record(n: usize) -> Vec<u8> {
    let data = std::fs::read("tests/fixtures/quic-handshake.pcap").expect("фикстура на месте");
    let (frames, _broken) = reflex_core::pcap::read(&data, std::time::Instant::now());
    let net = frames.get(n).expect("кадр есть").network().to_vec();
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
        // Сужаем до общего словаря тем же законом, что и цепочка (`Reading::anywhere`): второй
        // способ сужения в тесте разошёлся бы с тем, что делает цепочка, молча.
        Observation::Seen(observed) => observed
            .wire
            .anywhere()
            .expect("датаграмма даёт общее слово"),
        other => panic!(
            "наблюдение обязано состояться, а вышло другое: {:?}",
            other.briefly()
        ),
    }
}

trait Briefly {
    fn briefly(&self) -> &'static str;
}

impl<W> Briefly for Observation<W> {
    fn briefly(&self) -> &'static str {
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
fn a_repeated_opening_while_the_target_is_silent_is_named_a_repeat() {
    let initial = real_initial();
    let mut state = QuicState::default();

    assert!(
        matches!(
            seen(&mut state, &initial, Dir::Up),
            Seen::Payload {
                from_client: true,
                ..
            }
        ),
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
fn after_the_target_answered_a_repeat_is_no_longer_evidence() {
    let initial = real_initial();
    let mut state = QuicState::default();

    let _ = seen(&mut state, &initial, Dir::Up);
    assert!(
        matches!(
            seen(&mut state, b"\x40\x01\x02\x03", Dir::Down),
            Seen::Received { .. }
        ),
        "датаграмма вниз — цель ответила"
    );

    assert!(
        !matches!(seen(&mut state, &initial, Dir::Up), Seen::Resent { .. }),
        "после ответа цели повтор открытия улики не несёт"
    );
}

/// ПРЕДМЕТ: ВТОРАЯ ПОЛОВИНА `ClientHello` — не повтор, хотя `DCID` тот же и цель ещё молчит.
///
/// Замер 14.09.2026 на стенде и в парке: браузерное приветствие с постквантовым ключом не влезает в
/// одну датаграмму, и КАЖДЫЙ разговор QUIC давал `Retransmit { after_ms: 0 }` — «повтор» через 8
/// мкс. Продукт уводил в контур `googlevideo`, `youtube`, `quic.nginx.org`, и цель, не
/// заблокированная никем, лечилась. Повтор отличается от продолжения тем, что НЕ НЕСЁТ НОВЫХ
/// БАЙТОВ рукопожатия: смещения `CRYPTO` второй датаграммы (1077…1468) лежат дальше первой.
#[test]
fn hello_continued_in_next_datagram_is_not_a_repeat() {
    let mut state = QuicState::default();

    let _ = seen(&mut state, &datagram_of_record(0), Dir::Up);
    assert!(
        !matches!(
            seen(&mut state, &datagram_of_record(1), Dir::Up),
            Seen::Resent { .. }
        ),
        "вторая датаграмма несёт ДАЛЬНЕЙШИЕ байты приветствия — это продолжение, а не повтор"
    );
}

/// Терминальная половина того же: на настоящем рукопожатии, где цель ответила через 45 мс, прибор
/// повтора обязан молчать. Именно его слово уводило чистые цели в контур.
#[test]
fn retransmit_is_silent_on_a_real_split_handshake() {
    let heard = std::sync::Mutex::new(Vec::new());

    pcap("tests/fixtures/quic-handshake.pcap")
        .from(Quic)
        .extract(Sni)
        .detect(Retransmit::unanswered())
        .on(|_target: &str, distress: Distress| {
            heard.lock().expect("журнал не отравлен").push(distress)
        })
        .run();

    let heard = heard.into_inner().expect("журнал не отравлен");
    assert!(
        !heard
            .iter()
            .any(|distress| matches!(distress, Distress::Retransmit { .. })),
        "клиент разбил приветствие на две датаграммы, цель ответила — беды нет; услышано: {heard:?}"
    );
}

/// Обезоруживающая половина, и она не выдумана: под НАСТОЯЩИМ дропом клиент повторяет открытие
/// ПРОБОЙ — `Initial` из `PING` и `PADDING`, без единого байта `CRYPTO`. Запись стенда 14.09.2026
/// (curl/ngtcp2, дроп UDP/443 на `lab-dpi`, tcpdump у клиента): приветствие двумя датаграммами,
/// затем пробы через 1 и 3 с, и так на обоих адресах цели.
///
/// Проба новых байт не несёт — это повтор, и прибор обязан назвать беду. Первая редакция закона
/// «ни одного нового байта» считала пустую датаграмму «не повтором» и молчала на настоящей беде;
/// нашлось обезоруживанием на стенде, а не чтением. Порог в 500 мс отделяет честную пробу от ложного
/// «повтора» второй половины приветствия через 0 мс.
#[test]
fn a_probe_without_crypto_under_a_real_drop_is_a_repeat() {
    let heard = std::sync::Mutex::new(Vec::new());

    pcap("tests/fixtures/quic-drop.pcap")
        .from(Quic)
        .extract(Sni)
        .detect(Retransmit::unanswered())
        .on(|_target: &str, distress: Distress| {
            heard.lock().expect("журнал не отравлен").push(distress)
        })
        .run();

    let heard = heard.into_inner().expect("журнал не отравлен");
    assert!(
        heard
            .iter()
            .any(|distress| matches!(distress, Distress::Retransmit { after_ms } if *after_ms >= 500)),
        "цель молчит, клиент шлёт пробы через 1 и 3 с — беда обязана быть названа; услышано: {heard:?}"
    );
}

// ─── КРАЙ НА ДАТАГРАММАХ: возраст разговора ────────────────────────────────────────────────────

/// Собрать запись из `(мкс от начала, кадр)` — та же оснастка, что у `recording.rs`, с разведёнными
/// полями секунд и долей (доля клампится сотней тысяч).
fn recording(frames: &[(u32, Vec<u8>)]) -> Vec<u8> {
    let head: Vec<u8> = [0xd4u8, 0xc3, 0xb2, 0xa1]
        .into_iter()
        .chain([2, 0, 4, 0])
        .chain([0; 8])
        .chain(65535u32.to_le_bytes())
        .chain(1u32.to_le_bytes())
        .collect();

    frames.iter().fold(head, |acc, (micros, body)| {
        acc.into_iter()
            .chain((1_756_000_000 + micros / 1_000_000).to_le_bytes())
            .chain((micros % 1_000_000).to_le_bytes())
            .chain((body.len() as u32).to_le_bytes())
            .chain((body.len() as u32).to_le_bytes())
            .chain(body.iter().copied())
            .collect()
    })
}

/// ПРЕДМЕТ: краевой прибор высказывается на ДАТАГРАММАХ. Пока открытие разговора у UDP не
/// опознавалось, возраст не считался вовсе, и приборы, судящие ПО ВОЗРАСТУ, были на QUIC немы
/// НАВСЕГДА — замер потребителя: цель не ответила 6,999 секунды при пороге 1,5, прибор промолчал.
///
/// Признак открытия у QUIC — клиентский `Initial`, ровно как `SYN` у TCP. Здесь он настоящий:
/// байты взяты из снятого рукопожатия.
#[test]
fn the_edge_instrument_speaks_on_datagrams_too() {
    use reflex_core::builder::UdpBuilder;
    use reflex_core::types::Protocol;

    let flow = reflex_core::types::Flow {
        src: "10.0.0.5:40000".parse::<std::net::SocketAddr>().unwrap(),
        dst: "142.251.156.119:443"
            .parse::<std::net::SocketAddr>()
            .unwrap(),
        protocol: Protocol::Udp,
    };
    let initial = real_initial();
    let datagram = || {
        UdpBuilder::new()
            .flow(&flow)
            .ttl(64)
            .payload(&initial)
            .build()
            .serialize()
    };

    // Клиент открыл разговор и через семь секунд повторил открытие. Цель не ответила ни разу —
    // это блэкхол, и порог тут возрастной, а не счётный.
    let path = std::env::temp_dir().join(format!("reflex-quic-drop-{}.pcap", std::process::id()));
    std::fs::write(
        &path,
        recording(&[(0, datagram()), (7_000_000, datagram())]),
    )
    .expect("временный файл записан");

    let heard = std::sync::Mutex::new(Vec::new());
    pcap(&path)
        .from(Quic)
        .extract(Sni)
        .detect(Silence::after(secs(5)))
        .on(|_target: &str, distress| heard.lock().expect("журнал не отравлен").push(distress))
        .run();

    let heard = heard.into_inner().expect("журнал не отравлен");
    assert!(
        heard
            .iter()
            .any(|distress| matches!(distress, Distress::Blackhole { .. } | Distress::NoBytes)),
        "цель не ответила за семь секунд при пороге пять — прибор обязан высказаться; \
         услышано: {heard:?}"
    );
}

/// ПРЕДМЕТ: на датаграммах дверь тишины называет «цель не ответила вовсе» ПО СВОИМ ЧАСАМ — раньше,
/// чем клиент повторит открытие.
///
/// Канон, Утв. 7.5: тождественное молчание законно лишь при (а) слове о наблюдателе, (б) выводе без
/// отсутствия или (в) независимом свидетеле отсутствия. Слово `NoBytes` отнято у проводной половины
/// двери по доводу (в) — свидетель есть край. На датаграммах довод не держится: краевой прибор
/// выражает этот класс парой «рукопожатие состоялось, а байтов сверх заголовков нет», а у датаграмм
/// рукопожатия нет вовсе — молчащая цель даёт ноль пакетов, и край говорит об этом другим словом (`Blackhole`) и
/// только по приходу СЛЕДУЮЩЕГО пакета, ибо ct-вид едет с пакетом. Свидетеля нет — значит и
/// молчать нечем.
///
/// Цена, которой закон оплачен: первый заход человека по QUIC теряется целиком. Прибор повтора
/// заперт в чужом таймере (первый PTO клиента ≈ 999 мс, RFC 9002), краевой ждёт того же пакета, а
/// порог в 300 мс, выставленный потребителем, открывал ветку, ведущую в вырезанное слово, и эффекта
/// не имел — замер на стенде: 413 датаграмм, 11 бед, все `Retransmit` с `after_ms` 999–1000.
#[test]
fn on_datagrams_the_silence_door_names_a_target_that_never_answered() {
    use reflex_core::builder::UdpBuilder;
    use reflex_core::types::Protocol;

    let flow = reflex_core::types::Flow {
        src: "10.0.0.5:40000".parse::<std::net::SocketAddr>().unwrap(),
        dst: "142.251.156.119:443"
            .parse::<std::net::SocketAddr>()
            .unwrap(),
        protocol: Protocol::Udp,
    };
    // Чужой разговор той же машины: его кадры двигают узлы сетки, а нашему разговору не говорят
    // ничего. Без них лента кончилась бы на первом же пакете, и тишина проверялась бы концом
    // записи, а не порогом.
    let others = reflex_core::types::Flow {
        src: "10.0.0.5:40001".parse::<std::net::SocketAddr>().unwrap(),
        dst: "142.251.156.119:53"
            .parse::<std::net::SocketAddr>()
            .unwrap(),
        protocol: Protocol::Udp,
    };
    let initial = real_initial();
    let datagram = |flow: &reflex_core::types::Flow, payload: &[u8]| {
        UdpBuilder::new()
            .flow(flow)
            .ttl(64)
            .payload(payload)
            .build()
            .serialize()
    };

    // Клиент открыл разговор и умолк; запись длится полсекунды — короче любого PTO, дольше порога.
    let frames: Vec<(u32, Vec<u8>)> = [(0u32, datagram(&flow, &initial))]
        .into_iter()
        .chain((1..=5).map(|i| (i * 100_000, datagram(&others, b"x"))))
        .collect();
    let path = std::env::temp_dir().join(format!("reflex-quic-mute-{}.pcap", std::process::id()));
    std::fs::write(&path, recording(&frames)).expect("временный файл записан");

    let heard = std::sync::Mutex::new(Vec::new());
    pcap(&path)
        .from(Quic)
        .extract(Sni)
        .detect(Silence::after(std::time::Duration::from_millis(300)))
        .on(|_target: &str, distress| heard.lock().expect("журнал не отравлен").push(distress))
        .run();

    let heard = heard.into_inner().expect("журнал не отравлен");
    assert!(
        heard
            .iter()
            .any(|distress| matches!(distress, Distress::NoBytes)),
        "цель молчит полсекунды при пороге 300 мс, а повтора клиента ещё не было — \
         дверь обязана назвать беду сама; услышано: {heard:?}"
    );
}

/// ПАРА к закону выше: цель, ОТВЕТИВШАЯ в пределах порога, беды не вызывает.
///
/// Без этой половины первый закон зелен по ложной причине: дверь, кричащая на всяком разговоре,
/// прошла бы его так же. Правило 10.7 — зелёное не считается, пока не показана способность дать
/// красный; здесь показывается обратная способность, промолчать.
///
/// Цена порога названа замером, а не догадкой: при пороге 300 мс и шаге сетки 200 мс слово
/// рождается на узле 400 мс, и цель, чей первый ответ пришёл позже него, объявляется молчащей —
/// живая, с RTT 450 мс, получает `NoBytes`. Потому порог ставится шире p99 времени первого ответа
/// на своей земле, а этот закон держит только ближний край: ответ в пределах порога беды не даёт.
#[test]
fn a_datagram_target_that_answered_in_time_is_not_accused() {
    use reflex_core::builder::UdpBuilder;
    use reflex_core::types::{Flow, Protocol};

    let flow = Flow {
        src: "10.0.0.5:40000".parse::<std::net::SocketAddr>().unwrap(),
        dst: "142.251.156.119:443"
            .parse::<std::net::SocketAddr>()
            .unwrap(),
        protocol: Protocol::Udp,
    };
    let back = Flow {
        src: "142.251.156.119:443"
            .parse::<std::net::SocketAddr>()
            .unwrap(),
        dst: "10.0.0.5:40000".parse::<std::net::SocketAddr>().unwrap(),
        protocol: Protocol::Udp,
    };
    let others = Flow {
        src: "10.0.0.5:40001".parse::<std::net::SocketAddr>().unwrap(),
        dst: "142.251.156.119:53"
            .parse::<std::net::SocketAddr>()
            .unwrap(),
        protocol: Protocol::Udp,
    };
    let initial = real_initial();
    let datagram = |flow: &Flow, payload: &[u8]| {
        UdpBuilder::new()
            .flow(flow)
            .ttl(64)
            .payload(payload)
            .build()
            .serialize()
    };

    // Цель ответила через 150 мс — раньше первого узла, на котором порог перейдён. Дальше лента
    // живёт чужим трафиком ещё полсекунды: молчания после ответа тоже быть не должно.
    let mut frames: Vec<(u32, Vec<u8>)> = vec![
        (0, datagram(&flow, &initial)),
        (150_000, datagram(&back, &vec![7u8; 1200])),
    ];
    frames.extend((1..=12).map(|i| (i * 50_000, datagram(&others, b"x"))));
    frames.sort_by_key(|(at, _)| *at);
    let path = std::env::temp_dir().join(format!("reflex-quic-live-{}.pcap", std::process::id()));
    std::fs::write(&path, recording(&frames)).expect("временный файл записан");

    let heard = std::sync::Mutex::new(Vec::new());
    pcap(&path)
        .from(Quic)
        .extract(Sni)
        .detect(Silence::after(std::time::Duration::from_millis(300)))
        .on(|_target: &str, distress| heard.lock().expect("журнал не отравлен").push(distress))
        .run();

    let heard = heard.into_inner().expect("журнал не отравлен");
    assert!(
        heard.is_empty(),
        "цель ответила в пределах порога — обвинять её не в чем; услышано: {heard:?}"
    );
}
