//! СЛЕПОТА ДВИЖКА — законы, а не удобства.
//!
//! Переехало из `dataplane` (05.09.2026). Там это было свойством нашей плоскости; на деле это
//! свойство ВСЯКОГО перехватывающего движка: NFQUEUE роняет под нагрузкой, кольцо AF_PACKET
//! переполняется, WinDivert теряет по-своему. Движок, не умеющий сказать «я этого не видел»,
//! выдаёт своё молчание за молчание сети.

use reflex_core::sight::{added, no_counts, sighted, told, Counted, Sight, Told};

fn counts(up: u64, down: u64) -> Counted {
    Counted {
        up,
        up_bytes: 0,
        down,
        down_bytes: 0,
    }
}

#[test]
fn seeing_everything_the_kernel_saw_is_full_sight() {
    assert_eq!(sighted(counts(10, 7), counts(10, 7)), Sight::Full);
}

#[test]
fn what_the_kernel_saw_and_we_did_not_is_the_measure_of_blindness() {
    assert_eq!(
        sighted(counts(10, 7), counts(4, 7)),
        Sight::Partial {
            missed_up: 6,
            missed_down: 0
        },
        "пропущенное вверх обязано считаться отдельно от пропущенного вниз"
    );
}

/// ПЛОСКОСТЬ НЕ МОЖЕТ ВИДЕТЬ БОЛЬШЕ ЯДРА. Если счётчики так говорят — это расхождение приборов,
/// и отрицательная слепота была бы утверждением сильнее установленного.
#[test]
fn seeing_more_than_the_kernel_is_not_negative_blindness() {
    assert_eq!(sighted(counts(4, 7), counts(10, 7)), Sight::Full);
}

/// ГЛАВНЫЙ ЗАКОН ТИПА: пустая клетка значит РАЗНОЕ смотря по тому, могли ли мы вообще увидеть.
#[test]
fn nothing_seen_while_blind_is_not_the_same_as_nothing_happened() {
    let sighted_nothing: Told<u64> = told(Told::Nothing, Sight::Full);
    let blind_nothing: Told<u64> = told(
        Told::Nothing,
        Sight::Partial {
            missed_up: 1,
            missed_down: 0,
        },
    );

    assert_eq!(sighted_nothing, Told::Nothing, "зрячий и пусто — факт о СЕТИ");
    assert_eq!(blind_nothing, Told::Blind, "слепой и пусто — факт О НАС");
    assert_ne!(
        sighted_nothing, blind_nothing,
        "слить их значит выдать своё молчание за молчание сети"
    );
}

/// НАБЛЮДЁННОЕ СЛЕПОТОЙ НЕ ОТМЕНЯЕТСЯ: факт, добытый до того, как мы ослепли, остаётся фактом.
#[test]
fn blindness_does_not_erase_what_was_already_observed() {
    assert_eq!(
        told(
            Told::Told(42u64),
            Sight::Partial {
                missed_up: 9,
                missed_down: 9
            }
        ),
        Told::Told(42),
    );
}

#[test]
fn counting_two_stretches_of_one_conversation_adds_both_directions() {
    let first = Counted {
        up: 1,
        up_bytes: 100,
        down: 2,
        down_bytes: 200,
    };
    let second = Counted {
        up: 3,
        up_bytes: 30,
        down: 4,
        down_bytes: 40,
    };

    assert_eq!(
        added(first, second),
        Counted {
            up: 4,
            up_bytes: 130,
            down: 6,
            down_bytes: 240
        }
    );
    assert_eq!(added(first, no_counts()), first, "ноль обязан быть нейтралью");
}
