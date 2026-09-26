//! Проекции алфавита беды: сила утверждения, чем снимается, за сколько проявилась. Потребитель
//! судит по ним, а не выводит их заново своим `match` — иначе у одних битов было бы две правды.

use reflex_instrument::distress::{Assertion, Distress};
use reflex_instrument::edge_detect::Relief;
use std::time::Duration;

/// Сила утверждения — та, что названа в докблоках букв: подозрение даёт и здоровая сеть.
#[test]
fn the_alphabet_is_weighed_as_its_docblocks_say() {
    let suspicions = [
        Distress::Retransmit { after_ms: 300 },
        Distress::Silence { ms: 1_600 },
        Distress::Throttled { bps: 600 },
    ];
    assert!(suspicions
        .iter()
        .all(|word| word.assertion() == Assertion::Suspicion));

    let diagnoses = [
        Distress::Rst,
        Distress::NoBytes,
        Distress::Blackhole { after_ms: 1_000 },
        Distress::Unreached { retries: 3 },
        Distress::Swallowed { after_ms: 1_200 },
        Distress::Dismissed { after_ms: 30 },
        Distress::HelloDropped {
            retries: 3,
            after_ms: 1_220,
        },
        Distress::HelloMuted {
            rtt_ms: 2,
            after_ms: 400,
        },
        Distress::Poisoned,
    ];
    assert!(diagnoses
        .iter()
        .all(|word| word.assertion() == Assertion::Diagnosis));

    assert_eq!(
        Distress::Diverged { theirs: 1 }.assertion(),
        Assertion::Finding
    );
}

/// Снятие спрашивается у той же величины, которой мерила детекция: у соседних болезней открытия
/// оно разное.
#[test]
fn each_disease_of_the_opening_is_relieved_by_its_own_measure() {
    assert_eq!(
        Distress::Blackhole { after_ms: 1_000 }.relief(),
        Relief::Answered
    );
    assert_eq!(
        Distress::HelloDropped {
            retries: 3,
            after_ms: 1_220
        }
        .relief(),
        Relief::Acknowledged
    );
    assert_eq!(
        Distress::HelloMuted {
            rtt_ms: 2,
            after_ms: 400
        }
        .relief(),
        Relief::ServerHello,
        "подтверждение даёт и заглушённая цель — снятие только её приветствие (#348)"
    );
    assert_eq!(Distress::Poisoned.relief(), Relief::Unknown);
}

/// Время проявления — то, что буква несёт; у буквы без времени его нет, а не ноль.
#[test]
fn a_disease_carries_its_time_only_if_the_letter_does() {
    assert_eq!(
        Distress::HelloMuted {
            rtt_ms: 2,
            after_ms: 400
        }
        .after(),
        Some(Duration::from_millis(400))
    );
    assert_eq!(Distress::Unreached { retries: 3 }.after(), None);
}
