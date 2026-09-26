//! ХРОНОЛОГИЯ ФАКТОВ (#348): сводка прошлого свёрткой, сроки — формулы над ней. Каждое утверждение
//! закона (#348, «Закон среза 2») — тестом на случайных потоках: Т1 достаточность, Т2 точность
//! `due`, Т3 живость, Т4 безопасность, Т5 честная тишина и формула серии как второй оракул.

use std::time::{Duration, Instant};

use reflex_core::chronology::{due, Chronology, Runs, Since};
use reflex_core::sight::Told;

/// Генератор без зависимостей: одна и та же затравка — один и тот же поток.
fn xorshift(state: u64) -> u64 {
    let x = state ^ (state << 13);
    let x = x ^ (x >> 7);
    x ^ (x << 17)
}

fn stream(seed: u64, len: usize, kinds: u8) -> Vec<(u8, u64)> {
    (0..len)
        .scan((seed, 0u64), |(state, ms), _nth| {
            let next = xorshift(*state);
            *state = next;
            *ms += next % 700;
            Some(((next >> 32) as u8 % kinds, *ms))
        })
        .collect()
}

fn folded(base: Instant, events: &[(u8, u64)]) -> Chronology<u8> {
    events
        .iter()
        .fold(Chronology::default(), |chrono, (kind, ms)| {
            chrono.noted(*kind, base + Duration::from_millis(*ms))
        })
}

fn guards(seed: u64) -> Vec<Since<u8>> {
    (0..4u64)
        .map(|nth| {
            let r = xorshift(seed.wrapping_add(nth + 1));
            Since {
                from: (r % 5) as u8,
                after: Duration::from_millis(100 + r % 3_000),
            }
        })
        .collect()
}

fn truths(guards: &[Since<u8>], chrono: &Chronology<u8>, now: Instant) -> Vec<bool> {
    guards
        .iter()
        .map(|guard| guard.holds(chrono, now))
        .collect()
}

/// Т1: охрана читает только сводку — две разные истории с одной сводкой неразличимы.
#[test]
fn a_guard_depends_only_on_the_summary() {
    let base = Instant::now();
    let a = folded(base, &[(1, 10), (1, 500), (2, 700)]);
    let b = folded(base, &[(1, 40), (2, 300), (1, 500), (2, 700)]);
    let guard = Since {
        from: 1u8,
        after: Duration::from_millis(1_000),
    };
    (0..3_000u64).step_by(7).for_each(|ms| {
        let now = base + Duration::from_millis(ms);
        assert_eq!(guard.holds(&a, now), guard.holds(&b, now), "{ms} мс");
    });
}

/// Т2: между событиями охраны меняются ровно в `due` — ни раньше (проспали бы), ни позже.
#[test]
fn due_is_exactly_the_next_change_of_any_guard() {
    let base = Instant::now();
    (1..200u64).for_each(|seed| {
        let events = stream(seed, 12, 5);
        let chrono = folded(base, &events);
        let guards = guards(seed);
        let last_ms = events.last().map_or(0, |(_kind, ms)| *ms);
        let now = base + Duration::from_millis(last_ms);
        let before = truths(&guards, &chrono, now);
        let changed = (1..8_000u64)
            .map(|ms| now + Duration::from_millis(ms))
            .find(|moment| truths(&guards, &chrono, *moment) != before);
        assert_eq!(
            due(&guards, &chrono, now),
            changed,
            "затравка {seed}: due против перебора"
        );
    });
}

/// Охрана по событию, которого не было, ложна всегда и срока не рождает.
#[test]
fn a_guard_on_what_never_happened_never_holds_and_never_wakes() {
    let base = Instant::now();
    let chrono = folded(base, &[(1, 10)]);
    let guard = Since {
        from: 3u8,
        after: Duration::from_millis(10),
    };
    assert!(!guard.holds(&chrono, base + Duration::from_secs(3_600)));
    assert_eq!(due(&[guard], &chrono, base), None);
}

/// Т3 и Т4: приговор ровно на K-й своей неудаче подряд; свидетель обнуляет; тишина не трогает.
#[test]
fn a_run_is_counted_since_the_last_witness_and_nothing_else_resets_it() {
    const K: u32 = 10;
    let runs = (0..K - 1).fold(Runs::<&str>::default(), |runs, _nth| runs.bumped("s"));
    assert_eq!(runs.of(&"s"), K - 1, "до K приговора нет");
    let runs = runs.bumped("s");
    assert_eq!(runs.of(&"s"), K, "K-я своя неудача — приговор");
    assert_eq!(runs.clone().reset(&"s").of(&"s"), 0, "свидетель обнуляет");
    assert_eq!(runs.bumped("t").of(&"s"), K, "чужая страта счёт не трогает");
}

/// Т5: тишина утверждается только опросом после начала окна; без опроса — «не знаю».
#[test]
fn silence_is_asserted_only_by_a_probe_inside_the_window() {
    const TALK: u8 = 0;
    const PROBE: u8 = 1;
    let base = Instant::now();
    let now = base + Duration::from_secs(20);
    let window = Duration::from_secs(10);

    let talked = folded(base, &[(TALK, 15_000), (PROBE, 16_000)]);
    assert_eq!(
        talked.quiet(&TALK, &PROBE, window, now),
        Told::Told(base + Duration::from_secs(15))
    );

    let silent = folded(base, &[(TALK, 5_000), (PROBE, 16_000)]);
    assert_eq!(silent.quiet(&TALK, &PROBE, window, now), Told::Nothing);

    let unasked = folded(base, &[(TALK, 5_000), (PROBE, 6_000)]);
    assert_eq!(
        unasked.quiet(&TALK, &PROBE, window, now),
        Told::Blind,
        "опрос был до окна — о тишине в окне он не говорит"
    );
}

/// Второй оракул другой природы: средняя длина до первой серии из K неудач при доле успеха p
/// совпадает с формулой `E = (1/qᴷ − 1) / p` (#348, выбор K).
#[test]
fn the_expected_wait_for_a_run_matches_the_formula() {
    const K: u32 = 6;
    const P_PERMILLE: u64 = 500;
    const TRIALS: u64 = 20_000;
    let (total, _state) =
        (0..TRIALS).fold((0u64, 88_172_645_463_325_252u64), |(total, state), _| {
            let (talks, state, _run) = std::iter::repeat(())
                .scan((state, 0u32, 0u64), |(state, run, talks), ()| {
                    let next = xorshift(*state);
                    *state = next;
                    *talks += 1;
                    *run = match next % 1_000 < P_PERMILLE {
                        true => 0,
                        false => *run + 1,
                    };
                    Some((*talks, *state, *run))
                })
                .find(|(_talks, _state, run)| *run == K)
                .unwrap_or((0, state, 0));
            (total + talks, state)
        });
    let measured = total as f64 / TRIALS as f64;
    let p = P_PERMILLE as f64 / 1_000.0;
    let expected = (1.0 / (1.0 - p).powi(K as i32) - 1.0) / p;
    assert!(
        (measured - expected).abs() / expected < 0.05,
        "симуляция {measured:.1} против формулы {expected:.1}"
    );
}
