//! ЗАПИСЬ ДОХОДИТ ДО ПРИБОРОВ. Проверяется не чтение файла (о нём есть свои тесты в ядре), а стык:
//! носитель → шов → транспорт → прибор → реакция, где время едет ИЗ ФАЙЛА.
//!
//! Почему прогоном, а не подстрочно: цепочка собирается типами, и «собралось» ещё не значит
//! «буквы дошли». Единственный способ отличить одно от другого — пустить настоящие байты и
//! спросить реакцию.

use std::net::SocketAddr;
use std::path::PathBuf;

use reflex::*;
use reflex_core::builder::TcpBuilder;
use reflex_core::types::{Flow, Protocol, TcpFlags};

/// Собрать файл из записей `(мкс от начала, кадр)`. Заголовок — классический `pcap` LE, Ethernet.
fn recording(frames: &[(u32, Vec<u8>)]) -> Vec<u8> {
    let head: Vec<u8> = [0xd4u8, 0xc3, 0xb2, 0xa1]
        .into_iter()
        .chain([2, 0, 4, 0])
        .chain([0; 8])
        .chain(65535u32.to_le_bytes())
        .chain(1u32.to_le_bytes())
        .collect();

    frames.iter().fold(head, |acc, (micros, body)| {
        // Секунды и доли — РАЗНЫЕ поля записи: доля клампится сотней тысяч, и всё, что дальше
        // секунды, положенное в неё, тихо превратилось бы в 999999 мкс. Наступлено при первом же
        // прогоне: разрыв в тридцать секунд стал одной, и прибор возраста промолчал законно.
        acc.into_iter()
            .chain((1_756_000_000 + micros / 1_000_000).to_le_bytes())
            .chain((micros % 1_000_000).to_le_bytes())
            .chain((body.len() as u32).to_le_bytes())
            .chain((body.len() as u32).to_le_bytes())
            .chain(body.iter().copied())
            .collect()
    })
}

/// Положить запись на диск: носитель открывает ПУТЬ, а не буфер, — проверяется та дверь, которой
/// пользуется человек.
fn saved(name: &str, bytes: &[u8]) -> PathBuf {
    let path = std::env::temp_dir().join(format!("reflex-{name}-{}.pcap", std::process::id()));
    std::fs::write(&path, bytes).expect("временный файл записан");
    path
}

fn talk() -> Flow {
    Flow {
        src: "10.0.0.5:40000".parse::<SocketAddr>().unwrap(),
        dst: "93.184.216.34:443".parse::<SocketAddr>().unwrap(),
        protocol: Protocol::Tcp,
    }
}

/// Кадр цели: та же пятёрка, стороны наоборот. Без него разговор выглядит неотвеченным вовсе
/// (`Blackhole`), а предмет здесь другой — цель подтвердила соединение и смолкла.
fn from_target(seq: u32, ack: u32, flags: TcpFlags) -> Vec<u8> {
    let back = Flow {
        src: talk().dst,
        dst: talk().src,
        protocol: Protocol::Tcp,
    };
    TcpBuilder::new()
        .flow(&back)
        .seq(seq)
        .ack(ack)
        .flags(flags)
        .ttl(64)
        .build()
        .serialize()
}

/// Кадр клиента с телом и заданным `seq`.
fn from_client(seq: u32, flags: TcpFlags, payload: &[u8]) -> Vec<u8> {
    TcpBuilder::new()
        .flow(&talk())
        .seq(seq)
        .ack(0)
        .flags(flags)
        .ttl(64)
        .payload(payload)
        .build()
        .serialize()
}

/// ПРЕДМЕТ: клиент попросил, цель не отдала байта, клиент повторил — и всё это лежит в файле.
/// Величина `after_ms` взята из ШТАМПОВ ЗАПИСИ (10мс → 310мс), а не из часов прогона: прогон
/// занимает микросекунды, и совпадение с тремястами доказывает, что время пришло из файла.
#[test]
fn повтор_из_записи_доходит_до_прибора_со_временем_файла() {
    let hello = reflex_core::tls::build_client_hello("example.com");
    let path = saved(
        "retransmit",
        &recording(&[
            (0, from_client(0, TcpFlags::SYN, &[])),
            (10_000, from_client(1, TcpFlags::PSH | TcpFlags::ACK, &hello)),
            (310_000, from_client(1, TcpFlags::PSH | TcpFlags::ACK, &hello)),
        ]),
    );

    let heard = std::sync::Mutex::new(Vec::new());
    let report = pcap(&path)
        .from(Tcp)
        .extract(Sni)
        .detect(Retransmit::unanswered())
        .on(|target: &str, distress| {
            heard
                .lock()
                .expect("журнал не отравлен")
                .push((target.to_string(), distress))
        })
        .run();

    let heard = heard.into_inner().expect("журнал не отравлен");
    assert_eq!(
        heard,
        vec![(
            "example.com".to_string(),
            Distress::Retransmit { after_ms: 300 }
        )],
        "запись обязана доносить букву до прибора, а время — из штампов файла; отчёт: {report:?}"
    );
}

/// ПРЕДМЕТ: тихий дроп, снятый в файл. Цель подтвердила соединение (`SYN+ACK`) и смолкла; клиент
/// отдал `ClientHello` и через тридцать секунд повторил. Прибор тишины судит по ВОЗРАСТУ разговора,
/// и возраст здесь — разность штампов ЗАПИСИ: пять секунд окна проходят за микросекунды прогона.
///
/// Тем и ценна запись: то же окно на живом проводе стоило бы тридцати секунд ожидания, а здесь
/// прогон детерминирован целиком — один файл даёт один ответ.
#[test]
fn тихий_дроп_из_записи_подтверждается_возрастом_из_файла() {
    let hello = reflex_core::tls::build_client_hello("example.com");
    let path = saved(
        "silence",
        &recording(&[
            (0, from_client(0, TcpFlags::SYN, &[])),
            (20_000, from_target(0, 1, TcpFlags::SYN | TcpFlags::ACK)),
            (25_000, from_client(1, TcpFlags::PSH | TcpFlags::ACK, &hello)),
            // Цель молчит, и ядро клиента повторяет просьбу с нарастающим RTO — ровно то, что
            // видно в записи настоящего тихого дропа. На третьем повторе возраст разговора
            // перешагивает окно.
            (
                1_025_000,
                from_client(1, TcpFlags::PSH | TcpFlags::ACK, &hello),
            ),
            (
                3_025_000,
                from_client(1, TcpFlags::PSH | TcpFlags::ACK, &hello),
            ),
            (
                7_025_000,
                from_client(1, TcpFlags::PSH | TcpFlags::ACK, &hello),
            ),
        ]),
    );

    let started = std::time::Instant::now();
    let heard = std::sync::Mutex::new(Vec::new());
    let report = pcap(&path)
        .from(Tcp)
        .extract(Sni)
        .detect(Silence::after(secs(5)))
        .on(|target: &str, distress| {
            heard
                .lock()
                .expect("журнал не отравлен")
                .push((target.to_string(), distress))
        })
        .run();
    let spent = started.elapsed();

    let heard = heard.into_inner().expect("журнал не отравлен");
    assert_eq!(
        heard,
        vec![("example.com".to_string(), Distress::NoBytes)],
        "тихий дроп записи обязан дойти до прибора тишины; отчёт: {report:?}"
    );
    assert!(
        spent < secs(1),
        "окно в пять секунд обязано идти по часам ФАЙЛА, а не по нашим: прогон занял {spent:?}"
    );
}

/// ПРЕДМЕТ: два прибора над одним проводом говорят КАЖДЫЙ СВОЁ. Быстрый (`Retransmit`) —
/// подозрение по повтору клиента, медленный (`Silence`) — подтверждение по возрасту разговора.
/// Склейку «подозрение → подтверждение» пишет потребитель, и для этого ему нужны ОБА слова.
///
/// Тест заведён находкой примера: на той же записи цепочка с двумя приборами сказала только
/// повтор, хотя прибор тишины на ней же в одиночку говорит `NoBytes`.
#[test]
fn два_прибора_над_одной_записью_говорят_каждый_своё() {
    let hello = reflex_core::tls::build_client_hello("example.com");
    let path = saved(
        "both",
        &recording(&[
            (0, from_client(0, TcpFlags::SYN, &[])),
            (20_000, from_target(0, 1, TcpFlags::SYN | TcpFlags::ACK)),
            (25_000, from_client(1, TcpFlags::PSH | TcpFlags::ACK, &hello)),
            (
                1_025_000,
                from_client(1, TcpFlags::PSH | TcpFlags::ACK, &hello),
            ),
            (
                3_025_000,
                from_client(1, TcpFlags::PSH | TcpFlags::ACK, &hello),
            ),
            (
                7_025_000,
                from_client(1, TcpFlags::PSH | TcpFlags::ACK, &hello),
            ),
        ]),
    );

    let heard = std::sync::Mutex::new(Vec::new());
    let report = pcap(&path)
        .from(Tcp)
        .extract(Sni)
        .detect(Retransmit::unanswered())
        .detect(Silence::after(secs(5)))
        .on(|_target: &str, distress| heard.lock().expect("журнал не отравлен").push(distress))
        .run();

    let heard = heard.into_inner().expect("журнал не отравлен");
    assert!(
        heard.iter().any(|d| matches!(d, Distress::Retransmit { .. })),
        "быстрый прибор обязан высказаться; услышано: {heard:?}, отчёт: {report:?}"
    );
    assert!(
        heard.contains(&Distress::NoBytes),
        "медленный прибор обязан подтвердить — в одиночку на этой же записи он это делает; \
         услышано: {heard:?}"
    );
}


/// Прибор, который говорит на КАЖДОМ пакете. Нужен затем, что здоровый разговор беды не рождает, а
/// предмет теста — «дошли ли буквы», а не «нашлась ли блокировка».
#[derive(Clone, Copy, Default)]
struct Counter;

impl Mealy for Counter {
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

/// ПРЕДМЕТ: запись, снятая НЕ НАМИ, доходит до цепочки и даёт НАСТОЯЩЕЕ имя цели.
///
/// Цепочка производителей здесь не содержит ни одного нашего байта, и в этом весь смысл теста:
/// `ClientHello` собрал OpenSSL, кадры записал `tcpdump -i lo`, а имя `proof.reflex.lab`
/// независимо подтвердил `tshark -T fields -e tls.handshake.extensions_server_name`. Синтетический
/// корпус (`recording(&[…])` выше) проверяет НАС ЖЕ обоими концами — он ловит логику, но не ловит
/// расхождения с форматом, который пишет мир. Этот ловит.
///
/// Фикстура — 15 кадров и 3.5КБ: рукопожатие к своему же серверу на петле, без чужих адресов и без
/// личных данных. Снята заново командой из докблока `examples/replay-recording`.
#[test]
fn запись_снятая_чужими_руками_даёт_настоящее_имя_цели() {
    let started = std::time::Instant::now();
    let heard = std::sync::Mutex::new(Vec::new());

    let report = pcap("tests/fixtures/handshake.pcap")
        .from(Tcp)
        .extract(Sni)
        .detect(own(Counter))
        .on(|target: &str, _distress: Distress| {
            heard
                .lock()
                .expect("журнал не отравлен")
                .push(target.to_string())
        })
        .run();

    let heard = heard.into_inner().expect("журнал не отравлен");
    assert!(
        heard.iter().any(|name| name == "proof.reflex.lab"),
        "имя цели обязано прийти из настоящего `ClientHello`, а не из нашего сборщика; \
         услышано: {heard:?}, отчёт: {report:?}"
    );
    assert!(
        started.elapsed() < secs(1),
        "разбор пятнадцати кадров не должен занимать секунду"
    );
}
