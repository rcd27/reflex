//! ЛЕНТА: два алфавита и одна упорядоченность.
//!
//! Драйвер сливает в ленту наблюдения провода и отклики на спрошенное, и записывает её целиком.
//! Прибор при этом читает лишь провод: отклик до него не доходит §4-сужением, а не веткой «не моя
//! буква» в каждом приборе.

use reflex_core::detector::DetectorEvent;
use reflex_core::interleave::Interleave;
use reflex_core::stack::Reads;
use reflex_core::tape::{Answer, TapeLetter};
use std::time::{Duration, Instant};

const STEP: Duration = Duration::from_millis(100);

fn at(start: Instant, millis: u64) -> Instant {
    start + Duration::from_millis(millis)
}

/// Буквы ленты в виде, читаемом глазами.
fn shape<T, C>(letters: &[TapeLetter<T, C>], start: Instant) -> Vec<(char, u64)> {
    letters
        .iter()
        .map(|letter| {
            let millis = letter.at().saturating_duration_since(start).as_millis() as u64;
            let kind = match letter {
                TapeLetter::Event(DetectorEvent::Packet { .. }) => 'p',
                TapeLetter::Event(DetectorEvent::Tick { .. }) => 't',
                TapeLetter::Event(DetectorEvent::Opaque { .. }) => 'o',
                TapeLetter::Answer(_) => 'a',
            };
            (kind, millis)
        })
        .collect()
}

/// ТРИ ИСТОЧНИКА — ОДНА ЛЕНТА, УПОРЯДОЧЕННАЯ ВРЕМЕНЕМ.
///
/// Узлы, которые отклик перешагнул, выходят ПЕРЕД ним — как и у пакета. Порядок держит шов, а не
/// дисциплина зовущего: иначе прибор увидел бы отклик раньше закрытия окна, в которое тот не попал,
/// и лента перестала бы быть лентой.
#[test]
fn three_sources_make_one_tape_ordered_by_time() {
    let start = Instant::now();
    let seam = Interleave::started(start, STEP);

    let (seam, seen) = seam.saw("запрос", at(start, 50));
    let (seam, answered) = seam.answered::<&str, &str>("ответ контура", at(start, 250));
    let (_seam, idled) = seam.idle::<&str>(at(start, 420));

    let wire: Vec<TapeLetter<&str, &str>> = seen.into_iter().map(TapeLetter::Event).collect();
    let after: Vec<TapeLetter<&str, &str>> = idled.into_iter().map(TapeLetter::Event).collect();

    assert_eq!(shape(&wire, start), vec![('p', 50)], "пакет внутри окна тиков не родил");
    assert_eq!(
        shape(&answered, start),
        vec![('t', 100), ('t', 200), ('a', 250)],
        "узлы, перешагнутые откликом, выходят перед ним"
    );
    assert_eq!(shape(&after, start), vec![('t', 300), ('t', 400)]);

    let tape = [wire, answered, after].concat();
    let moments: Vec<Instant> = tape.iter().map(|letter| letter.at()).collect();
    assert!(
        moments.windows(2).all(|pair| pair[1] >= pair[0]),
        "лента неубывает по времени: {:?}",
        shape(&tape, start)
    );
}

/// ОТКЛИК ДО ПРИБОРА НЕ ДОХОДИТ — и роняет его СУЖЕНИЕ, а не ветка в приборе.
///
/// Прибор объявлен на трёх буквах провода. Будь отклик четвёртой буквой его алфавита, каждый прибор
/// дерева обязан был бы написать «не моя буква» — восемнадцать одинаковых веток, и девятнадцатая у
/// следующего. Буква, которую все обязаны отвергнуть, адресована не им.
#[test]
fn an_answer_never_reaches_an_instrument_that_does_not_read_it() {
    let start = Instant::now();
    let packet: TapeLetter<u8, &str> = TapeLetter::Event(DetectorEvent::Packet {
        input: 7,
        at: start,
    });
    let answer: TapeLetter<u8, &str> = TapeLetter::Answer(Answer {
        input: "контур сказал: блок",
        at: start,
    });

    assert!(
        matches!(
            <DetectorEvent<u8> as Reads<TapeLetter<u8, &str>>>::read(&packet),
            Some(DetectorEvent::Packet { input: 7, .. })
        ),
        "провод до прибора доходит"
    );
    assert!(
        <DetectorEvent<u8> as Reads<TapeLetter<u8, &str>>>::read(&answer).is_none(),
        "отклик до прибора не доходит — сужение его роняет"
    );
}

/// ОТКЛИК ДВИГАЕТ СЕТКУ, НО НЕ ОТМЕНЯЕТ ТИШИНЫ ПРОВОДА.
///
/// Сетку двигает, потому что лента упорядочена временем и узлы обязаны выйти вовремя. Тишину не
/// отменяет, потому что приборы отклика не видят: цель, отвечающая нашему контуру, пока провод
/// молчит, — это тихий дроп, и он обязан выглядеть тихим.
#[test]
fn an_answer_moves_the_grid_but_not_the_silence() {
    let start = Instant::now();
    let seam = Interleave::started(start, STEP);

    let (seam, answered) = seam.answered::<u8, &str>("блок", at(start, 250));
    let (_seam, idled) = seam.idle::<u8>(at(start, 320));

    assert_eq!(
        shape(&answered, start),
        vec![('t', 100), ('t', 200), ('a', 250)],
        "узлы до отклика выданы"
    );
    let after: Vec<TapeLetter<u8, &str>> = idled.into_iter().map(TapeLetter::Event).collect();
    assert_eq!(
        shape(&after, start),
        vec![('t', 300)],
        "сетка сдвинулась откликом: узлы 100 и 200 повторно не выдаются"
    );

    let seen_by_instrument: Vec<DetectorEvent<u8>> = answered
        .iter()
        .filter_map(<DetectorEvent<u8> as Reads<TapeLetter<u8, &str>>>::read)
        .collect();
    assert!(
        seen_by_instrument
            .iter()
            .all(|event| matches!(event, DetectorEvent::Tick { .. })),
        "прибору достались только узлы сетки — отклика он не видел"
    );
}
