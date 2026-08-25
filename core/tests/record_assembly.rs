#![cfg(feature = "tls")]

//! Сборка первой TLS-записи через границу сегмента — проекция `model/desync/RecordAssembly.tla`
//! и `model/molecule/AssembledRecord.tla`.
//!
//! Тесты названы по инвариантам модели, а не по методам: краснеющий тест обязан сразу говорить,
//! КАКОЙ закон нарушен, иначе он сообщает о поломке, но не о предмете.

use std::time::{Duration, Instant};

use reflex_core::detector::{Detector, DetectorEvent};
use reflex_core::tls::{Assembly, RecordAssembler, RecordChunk};

const DEADLINE: Duration = Duration::from_millis(200);

/// TLS-запись рукопожатия объявленной длины `body_len`. Заголовок настоящий — `record_need`
/// судит именно по нему; тело набивается узнаваемым байтом, чтобы склейку было видно глазом.
fn record(body_len: usize, fill: u8) -> Vec<u8> {
    let len = body_len as u16;
    [0x16, 0x03, 0x01, (len >> 8) as u8, (len & 0xff) as u8]
        .into_iter()
        .chain(std::iter::repeat(fill).take(body_len))
        .collect()
}

fn chunk(seq: u32, payload: Vec<u8>) -> DetectorEvent<RecordChunk> {
    DetectorEvent::Packet {
        input: RecordChunk { seq, payload },
        at: Instant::now(),
    }
}

fn chunk_at(seq: u32, payload: Vec<u8>, at: Instant) -> DetectorEvent<RecordChunk> {
    DetectorEvent::Packet {
        input: RecordChunk { seq, payload },
        at,
    }
}

/// Запись уместилась в сегмент — держать нечего. Это полевой случай `hello=517`, на котором
/// техника работает и сегодня.
#[test]
fn запись_в_одном_сегменте_отдаётся_сразу() {
    let whole = record(512, 0xAA);
    let (_, signals) = RecordAssembler::new(DEADLINE).step(chunk(1000, whole.clone()));

    assert_eq!(
        signals.as_slice(),
        [Assembly::Assembled {
            seq: 1000,
            record: whole,
            held: 0
        }]
    );
}

/// ГЛАВНЫЙ ТЕСТ СРЕЗА. Запись разорвана границей сегмента (полевой замер: 1400 + 175).
/// Проверяются ОБЕ оси молекулы разом: seq собранной записи — от ГОЛОВЫ, а байты — склейка
/// обоих кусков без потерь и дублей.
#[test]
fn запись_через_границу_собирается_и_адресуется_от_головы() {
    let whole = record(1570, 0xBB);
    let (head, tail) = whole.split_at(1400);

    let (assembler, first) = RecordAssembler::new(DEADLINE).step(chunk(7000, head.to_vec()));
    assert_eq!(
        first.as_slice(),
        [Assembly::Held],
        "голова обязана быть удержана"
    );

    let (_, second) = assembler.step(chunk(7000 + 1400, tail.to_vec()));
    assert_eq!(
        second.as_slice(),
        [Assembly::Assembled {
            seq: 7000,
            record: whole,
            held: 1400
        }],
        "seq — от ГОЛОВЫ (иначе запись ляжет правее и сервер не увидит её начала), \
         байты — точная склейка (иначе дубль или пропажа внутри записи)"
    );
}

/// Не TLS — сборщику здесь делать нечего, и ждать продолжения нельзя: его не будет,
/// а ожидание стало бы задержкой на каждом не-TLS соединении.
#[test]
fn не_tls_проходит_нетронутым() {
    let (_, signals) =
        RecordAssembler::new(DEADLINE).step(chunk(1, b"GET / HTTP/1.1\r\n".to_vec()));

    assert_eq!(signals.as_slice(), [Assembly::PassThrough]);
}

/// `Delivered` — удержанное возвращается на провод, даже если остаток не придёт НИКОГДА.
/// Без этого перехода сборщик сам порождает вечную загрузку, которую призван лечить.
#[test]
fn удержанное_отдаётся_по_сроку_когда_хвоста_не_будет() {
    let whole = record(1570, 0xCC);
    let head = whole[..1400].to_vec();
    let started = Instant::now();

    let (assembler, _) = RecordAssembler::new(DEADLINE).step(chunk_at(4242, head.clone(), started));
    let (_, signals) = assembler.step(DetectorEvent::Tick {
        at: started + DEADLINE,
    });

    assert_eq!(
        signals.as_slice(),
        [Assembly::Abandoned {
            seq: 4242,
            record: head
        }],
        "по сроку удержанное обязано уйти на провод НЕТРОНУТЫМ"
    );
}

/// `BoundedHold` со второй стороны: до срока сборщик держит и молчит. Тик, отдающий байты
/// раньше времени, ломал бы лечение — техника не получала бы запись НИ РАЗУ.
#[test]
fn до_срока_удержание_не_размыкается() {
    let whole = record(1570, 0xDD);
    let started = Instant::now();

    let (assembler, _) =
        RecordAssembler::new(DEADLINE).step(chunk_at(1, whole[..1400].to_vec(), started));
    let (assembler, signals) = assembler.step(DetectorEvent::Tick {
        at: started + DEADLINE / 2,
    });

    assert!(signals.is_empty(), "до срока сборщику нечего сказать");
    assert!(assembler.is_holding(), "и он всё ещё держит байты");
}

/// Сняв пакет с провода, мы лишили сервер повода его подтвердить — клиент пришлёт его снова.
/// Повтор обязан быть проглочен: отдать его сейчас значит доставить те же байты дважды.
#[test]
fn повтор_головы_не_рождает_дубля() {
    let whole = record(1570, 0xEE);
    let head = whole[..1400].to_vec();

    let (assembler, _) = RecordAssembler::new(DEADLINE).step(chunk(900, head.clone()));
    let (assembler, signals) = assembler.step(chunk(900, head));

    assert_eq!(signals.as_slice(), [Assembly::Held], "дубль поглощён");
    assert!(assembler.is_holding());
}

/// Поток пошёл не туда: пришёл кусок не с той позиции. Склеивать вслепую нельзя — соберём не то.
/// Удержанное отдаётся нетронутым, текущий пакет идёт как шёл.
#[test]
fn дыра_в_потоке_размыкает_удержание_без_потери_байт() {
    let whole = record(1570, 0x11);
    let head = whole[..1400].to_vec();

    let (assembler, _) = RecordAssembler::new(DEADLINE).step(chunk(500, head.clone()));
    let (_, signals) = assembler.step(chunk(999_999, vec![0x42; 10]));

    assert_eq!(
        signals.as_slice(),
        [
            Assembly::Abandoned {
                seq: 500,
                record: head
            },
            Assembly::PassThrough
        ]
    );
}

/// `Conserved` в единице байт: собранная запись равна конкатенации кусков ровно, без единого
/// лишнего или потерянного байта. Отдельно от теста про seq — там проверяется АДРЕС, здесь
/// СОДЕРЖИМОЕ, и ломаются они по-разному.
#[test]
fn байты_сохраняются_при_склейке() {
    let whole = record(2267, 0x7F); // 2272 на проводе — полевой googlevideo
    let (head, tail) = whole.split_at(1400);

    let (assembler, _) = RecordAssembler::new(DEADLINE).step(chunk(0, head.to_vec()));
    let (_, signals) = assembler.step(chunk(1400, tail.to_vec()));

    let собрано = match signals.first() {
        Some(Assembly::Assembled { record, .. }) => record.clone(),
        other => panic!("ожидалась собранная запись, получено {other:?}"),
    };
    assert_eq!(собрано.len(), whole.len(), "длина записи");
    assert_eq!(собрано, whole, "побайтово");
}

/// Решение по первой записи принимается ОДИН раз: дальше поток нас не касается, и прикладные
/// данные не должны заново будить сборщик.
///
/// SEQ СЧИТАЕТСЯ, А НЕ БЕРЁТСЯ НА ГЛАЗ. Первая редакция брала 310 — «явно после записи», — но
/// запись занимает `[10, 10+5+300)`, и 310 лежит ВНУТРИ неё. Тест зеленел лишь потому, что
/// прежний код seq не различал вовсе; едва сборщик научился считать повторы, ложная предпосылка
/// вскрылась. Правится проба, а не код.
#[test]
fn после_решения_поток_идёт_мимо() {
    let вся = record(300, 0x22);
    let за_записью = 10 + вся.len() as u32;
    let (assembler, _) = RecordAssembler::new(DEADLINE).step(chunk(10, вся));
    let (_, signals) = assembler.step(chunk(за_записью, vec![0x17, 0x03, 0x03, 0x00, 0x10]));

    assert_eq!(signals.as_slice(), [Assembly::PassThrough]);
}

/// ПОВТОР СОБРАННОЙ ЗАПИСИ. Сервер не подтвердил наш эмит, клиент шлёт байты заново. Сборщик
/// обязан НАЗВАТЬ это, а не выдать за новый неполный hello: снаружи они выглядят одинаково, и
/// различает их только пролёт уже отданной записи.
#[test]
fn повтор_отданной_записи_называется_повтором() {
    let вся = record(1570, 0x33);
    let (голова, хвост) = вся.split_at(1400);

    let (сб, _) = RecordAssembler::new(DEADLINE).step(chunk(5000, голова.to_vec()));
    let (сб, _) = сб.step(chunk(5000 + 1400, хвост.to_vec()));

    // клиент повторяет ГОЛОВУ
    let (сб, first) = сб.step(chunk(5000, голова.to_vec()));
    assert_eq!(
        first.as_slice(),
        [
            Assembly::Retransmitted { seq: 5000, nth: 1 },
            Assembly::PassThrough
        ],
        "повтор назван, и пакет ПРОПУЩЕН — он единственный путь потока к восстановлению"
    );

    // и ХВОСТ — он законная часть той же потери, счёт продолжается
    let (_, second) = сб.step(chunk(5000 + 1400, хвост.to_vec()));
    assert_eq!(
        second.as_slice(),
        [
            Assembly::Retransmitted { seq: 5000, nth: 2 },
            Assembly::PassThrough
        ]
    );
}

/// Поток, ушедший ДАЛЬШЕ записи, повтором не считается: это прикладные данные, всё в порядке.
/// Без этой границы счётчик повторов считал бы обычный трафик и врал бы вверх.
#[test]
fn данные_за_записью_повтором_не_считаются() {
    let вся = record(500, 0x44);
    let (сб, _) = RecordAssembler::new(DEADLINE).step(chunk(100, вся.clone()));

    let (_, signals) = сб.step(chunk(
        100 + вся.len() as u32,
        vec![0x17, 0x03, 0x03, 0x00, 0x10],
    ));

    assert_eq!(signals.as_slice(), [Assembly::PassThrough]);
}
