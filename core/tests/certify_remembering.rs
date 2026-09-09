//! Девятый закон на стенде-заглушке: `Bench` — терминал, принимающий вердикт; `Echo` — свидетель,
//! возвращающий заранее заданную марку (на живом ядре его место займёт `conntrack::Dump` — ДРУГАЯ
//! дверь). Здесь проверяется РАЗБОР исхода, живое ядро — в `linux/examples/certify.rs`.

use std::time::Instant;

use reflex_core::capability::CanRemember;
use reflex_core::certify::remembering::{remembers, Broken, Invalid, Recaller};
use reflex_core::certify::Verdict;
use reflex_core::held::{Answered, Delivered, Held, Refused, Terminal};

/// Терминал-заглушка: вердикт принимает всегда. Помнить умеет — `Answer` пустой, закону важно лишь,
/// что `apply` прошёл и свидетель что-то вернул.
struct Bench;

impl Bench {
    fn taking() -> Bench {
        Bench
    }
}

impl Terminal for Bench {
    type Carrier = ();
    type Answer = ();
    type Refusal = ();

    fn apply(
        &mut self,
        answered: Answered<(), ()>,
    ) -> Result<Delivered<()>, Refused<(), ()>> {
        Ok(Delivered {
            at: answered.at,
            answer: answered.answer,
        })
    }
}

impl CanRemember for Bench {
    fn remember(_state: u32, _accept: bool) {}
}

/// Свидетель-заглушка: возвращает заданную марку или молчит.
struct Echo(Option<u32>);

impl Echo {
    fn returning(mark: u32) -> Echo {
        Echo(Some(mark))
    }
    fn silent() -> Echo {
        Echo(None)
    }
}

impl Recaller for Echo {
    fn recall(&mut self) -> Option<u32> {
        self.0
    }
}

fn held() -> Held<()> {
    Held::new((), Instant::now())
}

/// Закон держится: отданное ядру вернулось (наши биты и чужие целы).
#[test]
fn kernel_remembers_what_was_told() {
    let mut recaller = Echo::returning(0x2000_1234);
    assert_eq!(
        remembers(
            &mut Bench::taking(),
            held(),
            0x0000_1234,
            0x2000_0000,
            &mut recaller
        ),
        Verdict::Held
    );
}

/// Вернулось не то — вина подопытного.
#[test]
fn a_lost_state_is_the_fault_of_the_device() {
    let mut recaller = Echo::returning(0x2000_0000);
    assert!(matches!(
        remembers(
            &mut Bench::taking(),
            held(),
            0x1234,
            0x2000_0000,
            &mut recaller
        ),
        Verdict::Broken(Broken::StateLost { .. })
    ));
}

/// Наши биты встали, чужие стёрты — отдельная вина, про соседей по машине.
#[test]
fn erasing_foreign_bits_is_its_own_fault() {
    let mut recaller = Echo::returning(0x0000_1234);
    assert!(matches!(
        remembers(
            &mut Bench::taking(),
            held(),
            0x1234,
            0x2000_0000,
            &mut recaller
        ),
        Verdict::Broken(Broken::Clobbered { .. })
    ));
}

/// Свидетель не увидел записи вовсе — беда стенда, не подопытного.
#[test]
fn a_silent_witness_invalidates_the_run() {
    assert!(matches!(
        remembers(
            &mut Bench::taking(),
            held(),
            0x1234,
            0,
            &mut Echo::silent()
        ),
        Verdict::Invalid(Invalid::NoConntrack)
    ));
}
