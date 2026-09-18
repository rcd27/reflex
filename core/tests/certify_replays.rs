//! ВОСЬМОЙ ЗАКОН: решение восстановимо (§10, §12.3).
//!
//! Пере-подай ленту той же машине — она обязана сказать то же. Согласие двух прогонов есть
//! детерминированность по объявленному алфавиту; расхождение значит, что внутри есть вход, которого
//! в алфавите нет.

use reflex_core::certify::{replays, Replayed};
use reflex_core::interleave::Interleave;
use reflex_core::tape::{Mode, Tape, TapeLetter, To};
use std::time::{Duration, Instant};

const STEP: Duration = Duration::from_millis(100);

/// Лента живого прогона: пакет, отклик, тишина.
fn recorded(start: Instant) -> Tape<u8, u32, &'static str> {
    let mut tape = Tape::new();
    let seam = Interleave::started(start, STEP);
    let (seam, seen) = seam.saw(1u8, start + Duration::from_millis(50));
    tape.record(seen.into_iter().map(|event| TapeLetter::Event {
        to: To::One(1),
        event,
    }));
    let (seam, answered) =
        seam.answered::<u8, u32, &str>(7, "блок", start + Duration::from_millis(250));
    tape.record(answered);
    let (_seam, idled) = seam.idle::<u8>(start + Duration::from_millis(420));
    tape.record(idled.into_iter().map(|event| TapeLetter::Event {
        to: To::Each,
        event,
    }));
    tape
}

/// ЧИСТАЯ МАШИНА ВОСПРОИЗВОДИТ СЕБЯ.
///
/// Она читает только буквы: момент берёт из события, ничего своего не спрашивает. Два прогона одной
/// ленты обязаны согласиться — и согласие это есть то, ради чего весь драйвер строился.
#[test]
fn a_pure_machine_replays_itself() {
    let tape = recorded(Instant::now());

    // Прогон: машина говорит момент каждой буквы провода — всё из буквы, ничего извне.
    let run = |_mode: Mode, letters: &[TapeLetter<u8, u32, &str>]| -> Vec<u128> {
        letters
            .iter()
            .filter_map(|letter| match letter {
                TapeLetter::Event { event, .. } => {
                    Some(event.at().elapsed().as_nanos() / 1_000_000_000)
                }
                TapeLetter::Answer(_) => None,
            })
            .collect()
    };

    assert_eq!(replays(&tape, run), Replayed::Reproduced);
}

/// МАШИНА СО СКРЫТЫМ ВХОДОМ СЕБЯ НЕ ВОСПРОИЗВОДИТ — и закон называет БУКВУ, на которой разошлось.
///
/// «Скрытый вход» здесь — счётчик прогонов: то же, что часы или глобальное знание, только нагляднее.
/// Машина о нём в своём алфавите не заявляла, и потому её решение перестаёт быть восстановимым:
/// запись есть, а что по ней случится — не предскажешь.
#[test]
fn a_hidden_input_is_caught_as_instability() {
    let tape = recorded(Instant::now());

    let mut runs = 0u32;
    let run = |_mode: Mode, letters: &[TapeLetter<u8, u32, &str>]| -> Vec<u32> {
        runs += 1;
        letters.iter().map(|_letter| runs).collect()
    };

    assert_eq!(
        replays(&tape, run),
        Replayed::Unstable { at: 0 },
        "разошлись на первой же букве"
    );
}

/// ПУСТОЙ ЛЕНТЕ СУДИТЬ НЕ О ЧЕМ — беда стенда, не подопытного.
///
/// Как `Invalid` у семи прочих законов: поломку стенда нельзя предъявлять как нарушение
/// способности.
#[test]
fn an_empty_tape_is_not_a_verdict() {
    let tape: Tape<u8, u32, &str> = Tape::new();
    let run = |_mode: Mode, _letters: &[TapeLetter<u8, u32, &str>]| -> Vec<u8> { Vec::new() };

    assert_eq!(replays(&tape, run), Replayed::NoTape);
}

/// РАЗНАЯ ДЛИНА СКАЗАННОГО — ТОЖЕ РАСХОЖДЕНИЕ.
///
/// Машина, замолчавшая на переигровке, разошлась там, где перестала говорить: молчание не
/// «совпадение по всем сравнённым», а отсутствие слова, которое было.
#[test]
fn a_machine_that_falls_silent_on_replay_is_unstable() {
    let tape = recorded(Instant::now());

    let mut runs = 0u32;
    let run = |_mode: Mode, letters: &[TapeLetter<u8, u32, &str>]| -> Vec<u8> {
        runs += 1;
        match runs {
            1 => letters.iter().map(|_| 1u8).collect(),
            _fell_silent => Vec::new(),
        }
    };

    assert_eq!(replays(&tape, run), Replayed::Unstable { at: 0 });
}

/// СОГЛАСИЕ ДВУХ МОЛЧАНИЙ — НЕ СВИДЕТЕЛЬСТВО.
///
/// Машина, которой нечего сказать, «воспроизводится» тривиально: пустое равно пустому. Назови это
/// `Reproduced` — и закон станет зелёным ровно там, где не проверил ничего.
///
/// Оплачено ошибкой: на стенде с живым ядром окно ленты набралось из одних узлов сетки, живых машин в нём
/// не было, и под вердиктом «воспроизведено» спокойно прошла мутация «переигровка читает часы».
#[test]
fn silence_in_both_runs_is_not_evidence() {
    let tape = recorded(Instant::now());

    let mute = |_mode: Mode, _letters: &[TapeLetter<u8, u32, &str>]| -> Vec<u8> { Vec::new() };
    assert_eq!(
        replays(&tape, mute),
        Replayed::Silent,
        "сказать было нечего — свидетельства нет"
    );

    let speaking = |_mode: Mode, letters: &[TapeLetter<u8, u32, &str>]| -> Vec<usize> {
        letters.iter().map(|_letter| 1).collect()
    };
    assert_eq!(
        replays(&tape, speaking),
        Replayed::Reproduced,
        "сказано и повторено — вот теперь свидетельство"
    );
}
