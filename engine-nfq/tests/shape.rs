use reflex_engine::{Programme, Tick};
use reflex_engine_nfq::parse::{read, Read, SERVER_PORT};
use reflex_engine_nfq::plane::Plane;

const CLIENT: u32 = 0xC0A8_0164;

/// СУЖЕНИЕ ДЛЯ ТЕСТА: имя берётся как есть. Ширина ключа здесь не предмет — предмет плоскость.
fn as_seen(host: &str) -> &str {
    host
}

fn frame(dst: u32, sport: u16, flags: u8, body: &[u8]) -> Vec<u8> {
    let total = (40 + body.len()) as u16;
    [
        &[0x45u8, 0x00][..],
        &total.to_be_bytes(),
        &[0x00, 0x01, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00],
        &CLIENT.to_be_bytes(),
        &dst.to_be_bytes(),
        &sport.to_be_bytes(),
        &SERVER_PORT.to_be_bytes(),
        &[0, 0, 0, 1, 0, 0, 0, 1],
        &[0x50, flags, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00],
        body,
    ]
    .concat()
}

fn feed(plane: &mut Plane, bytes: &[u8], at: u64) {
    match read(bytes, SERVER_PORT) {
        Read::Tcp(wire) => {
            plane.feed(wire, Tick(at));
        }
        other => panic!("кадр не разобран: {other:?}"),
    }
}

/// Завести `targets` разговоров, потом прогнать `packets` продолжений и вернуть, сколько записей
/// плоскость просмотрела при уборке. Это и есть предмет: работа НА ПАКЕТ, растущая с числом целей.
fn scanned(targets: u32, packets: u32) -> u64 {
    let mut plane = Plane::new(Programme::Pass, as_seen);
    (0..targets).for_each(|i| {
        feed(&mut plane, &frame(0x0A00_0000 + i, 40000, 0x02, b""), 1);
    });
    let before = plane.swept();
    (0..packets).for_each(|i| {
        feed(
            &mut plane,
            &frame(0x0A00_0000, 40000, 0x18, &[0u8; 100]),
            2 + i as u64,
        );
    });
    plane.swept() - before
}

#[test]
fn work_per_packet_does_not_grow_with_the_number_of_targets() {
    let few = scanned(100, 20_000);
    let many = scanned(10_000, 20_000);

    // ФОРМА, А НЕ ВЕЛИЧИНА. Сто целей против десяти тысяч — стократная разница. Если уборка
    // обходит карту целиком, просмотренное вырастет во столько же раз, и это работа НА ПАКЕТ,
    // пропорциональная N: именно ею невод 1 и сжигал ядро под нагрузкой.
    assert!(
        many <= few * 4 + 4096,
        "просмотрено при 100 целях {few}, при 10 000 — {many}: работа растёт с числом целей"
    );
}

#[test]
fn a_sweep_never_scans_more_than_its_budget_in_one_go() {
    let mut plane = Plane::new(Programme::Pass, as_seen);
    (0..50_000u32).for_each(|i| {
        feed(&mut plane, &frame(0x0A00_0000 + i, 40000, 0x02, b""), 1);
    });

    let before = plane.swept();
    let sweeps_before = plane.sweeps();
    (0..8_192u32).for_each(|i| {
        feed(
            &mut plane,
            &frame(0x0A00_0000, 40000, 0x18, &[0u8; 100]),
            2 + i as u64,
        );
    });
    let sweeps = plane.sweeps() - sweeps_before;
    let seen = plane.swept() - before;

    assert!(sweeps > 0, "уборка ни разу не запускалась — тест вакуумен");
    assert!(
        seen <= sweeps * reflex_engine_nfq::plane::SWEEP_BUDGET as u64 * 2,
        "за {sweeps} уборок просмотрено {seen} записей при бюджете {}",
        reflex_engine_nfq::plane::SWEEP_BUDGET
    );
}

/// ИМЯ НЕ ПЕРЕЖИВАЕТ СВОЮ ЦЕЛЬ (#302, срез 3).
///
/// Имя держится ради петли познания: беда наблюдается по адресу, а знание ключуется именем.
/// Живи имя дольше цели — карта имён росла бы отдельно от карты целей, и её никто бы не убирал:
/// утечка, которая выглядит как исправная работа, потому что ничего не падает.
///
/// ЗАКОН ИМЕННО ТАКОЙ, А НЕ «НЕ БОЛЬШЕ `TARGETS`». Первая редакция сравнивала с константой
/// `TARGETS` — и покраснела на 20 000 имён. Разбор показал, что виновата не карта имён: ЦЕЛЕЙ в
/// том же прогоне тоже 20 000, потому что `TARGETS` объявлена и НИГДЕ НЕ ПРИМЕНЯЕТСЯ (обе её
/// единственные ссылки — объявление и комментарий рядом). Карты плоскости ограничены не числом,
/// а вытеснением по времени. Требовать от имён того, чего не выполняют цели, значило бы
/// проверять несуществующий закон и чинить не то место.
///
/// ПРЕДПОСЫЛКА ДОКАЗЫВАЕТСЯ ЗДЕСЬ ЖЕ: первая редакция кормила голыми `SYN`, имён не появлялось
/// вовсе, и закон выполнялся на нуле — тест был зелёным, ничего не проверяя.
#[test]
fn a_name_never_outlives_the_target_it_belongs_to() {
    fn hello_with(name: &[u8]) -> Vec<u8> {
        let entry = [&[0x00u8][..], &(name.len() as u16).to_be_bytes(), name].concat();
        let list = (entry.len() as u16).to_be_bytes();
        let payload = [&list[..], &entry].concat();
        let ext = [
            &[0x00u8, 0x00][..],
            &(payload.len() as u16).to_be_bytes(),
            &payload,
        ]
        .concat();
        let body = [
            &[0x03u8, 0x03][..],
            &[0x11; 32],
            &[32],
            &[0x22; 32],
            &[0x00, 0x04],
            &[0x13, 0x01, 0x13, 0x02],
            &[0x01, 0x00],
            &(ext.len() as u16).to_be_bytes(),
            &ext,
        ]
        .concat();
        let handshake = [
            &[0x01u8][..],
            &(body.len() as u32).to_be_bytes()[1..4],
            &body,
        ]
        .concat();
        [
            &[0x16u8, 0x03, 0x01][..],
            &(handshake.len() as u16).to_be_bytes(),
            &handshake,
        ]
        .concat()
    }

    let mut plane = Plane::new(Programme::Pass, as_seen);

    // ПЕРВАЯ ВОЛНА: тысяча целей с именами, все в первую миллисекунду.
    (0..1_000u32).for_each(|i| {
        let hello = hello_with(format!("target-{i}.example.org").as_bytes());
        feed(
            &mut plane,
            &frame(0x0A00_0000 + i, 40000, 0x18, &hello),
            1 + i as u64,
        );
    });
    let named_at_first = plane.named_held();

    // ВТОРАЯ ВОЛНА, ЧЕРЕЗ МИНУТУ ПОСЛЕ ПЕРВОЙ. Горизонт памяти плоскости ≈ 8,6 с (64 ведра по
    // 2^27 нс), значит первая волна протухла целиком. Пакетов нужно много: подметание случается
    // раз в `SWEEP_EVERY` и смотрит не больше `SWEEP_BUDGET` записей за раз — иначе уборка была
    // бы работой, пропорциональной числу целей, то есть ровно тем, что этот файл и стережёт.
    let minute = 60_000_000_000u64;
    (0..20_000u32).for_each(|i| {
        feed(
            &mut plane,
            &frame(0x0B00_0000, 41000, 0x18, b"opaque"),
            minute + i as u64,
        );
    });

    // ПРЕДПОСЫЛКА ДОКАЗЫВАЕТСЯ, А НЕ ПРЕДПОЛАГАЕТСЯ. Первая редакция этого теста была ЗЕЛЁНОЙ и
    // при снятом удалении имени: цели в ней не протухали вовсе, `gone` был пуст, и закон
    // проверялся на прогоне, где нечего вытеснять. Обезоруживание это и вскрыло.
    assert!(
        named_at_first > 0,
        "имён не набралось вовсе — проверять было бы нечего"
    );
    assert!(
        plane.evicted_targets() > 0,
        "ни одна цель не вытеснена — тест не касается предмета"
    );
    assert!(
        plane.named_held() <= plane.targets_held(),
        "имён {}, целей {}: имя пережило свою цель, и карту имён больше никто не уберёт",
        plane.named_held(),
        plane.targets_held()
    );
}
