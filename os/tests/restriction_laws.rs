//! Законы структуры, а не поведения (#152).
//!
//! `Level<bool>` — это область определённости шага (`f̄` в терминах restriction-
//! категории Cockett–Lack). Аксиоматика требует, чтобы такие идемпотенты образовывали
//! ПОЛУРЕШЁТКУ по встрече: коммутативную, ассоциативную, идемпотентную. `and` обязан
//! быть этой встречей — не «функцией, которая склеивает два уровня», а операцией с
//! законами.
//!
//! Проверяем ИСЧЕРПЫВАЮЩЕ, а не случайно: миры здесь конечны (набор булевых ручек),
//! поэтому перебор всех 2^k состояний строже любого property-раннера и не требует
//! новой зависимости. Равенство — НАБЛЮДАТЕЛЬНОЕ: два уровня равны, если во всех
//! состояниях мира дают один ответ. Именно так и надо, потому что уровень владеет
//! дескрипторами и «равенства на носу» у него нет и быть не может.

use reflex_os::Level;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

const FLOOR: Duration = Duration::from_millis(5);

/// Ручка мира: булев атом, который тест волен крутить.
fn knob() -> Arc<AtomicBool> {
    Arc::new(AtomicBool::new(false))
}

/// Уровень, читающий одну ручку.
fn reads(k: &Arc<AtomicBool>) -> Level<bool> {
    let seen = k.clone();
    Level::polled(FLOOR, move || seen.load(Ordering::SeqCst))
}

/// Наблюдение уровня во ВСЕХ состояниях мира: 2^k присвоений ручкам.
fn observe_everywhere(level: &Level<bool>, world: &[Arc<AtomicBool>]) -> Vec<bool> {
    (0..(1u32 << world.len()))
        .map(|assignment| {
            world.iter().enumerate().for_each(|(bit, k)| {
                k.store(assignment & (1 << bit) != 0, Ordering::SeqCst);
            });
            level.get()
        })
        .collect()
}

// ИДЕМПОТЕНТНОСТЬ — закон, из-за которого вся рамка могла рассыпаться: уровень
// владеет дескрипторами, и «использовать дважды» для него не бесплатно. Если встреча
// уровня с самим собой наблюдается иначе, чем сам уровень, полурешётки нет.
#[test]
fn meet_is_idempotent() {
    let a = knob();
    let world = vec![a.clone()];

    let alone = observe_everywhere(&reads(&a), &world);
    let met = observe_everywhere(&reads(&a).and(reads(&a)), &world);

    assert_eq!(met, alone, "a ∧ a наблюдается иначе, чем a");

    // ТО ЖЕ на уровнях С ПОДСКАЗКАМИ — там, где я и ждал провала: уровень владеет
    // дескриптором, и «использовать дважды» для него не бесплатно. Два уровня над
    // ОДНОЙ истиной, каждый со своим netlink-сокетом: это и есть `a ∧ a` с точностью
    // до наблюдательной эквивалентности, единственное равенство, доступное владельцу
    // ресурса.
    let here = std::env::temp_dir();
    let one = reflex_os::link::present_at(here.clone(), FLOOR);
    let two = reflex_os::link::present_at(here.clone(), FLOOR);
    let solo = reflex_os::link::present_at(here, FLOOR);
    assert!(
        one.is_ok() && two.is_ok() && solo.is_ok(),
        "сокеты не завелись"
    );

    let hinted_met = one.and_then(|l| two.map(|r| l.and(r))).map(|m| m.get());
    let hinted_solo = solo.map(|l| l.get());
    assert_eq!(
        hinted_met.ok(),
        hinted_solo.ok(),
        "с подсказками a ∧ a наблюдается иначе, чем a"
    );
}

#[test]
fn meet_is_commutative() {
    let (a, b) = (knob(), knob());
    let world = vec![a.clone(), b.clone()];

    let ab = observe_everywhere(&reads(&a).and(reads(&b)), &world);
    let ba = observe_everywhere(&reads(&b).and(reads(&a)), &world);

    assert_eq!(ab, ba, "a ∧ b ≠ b ∧ a");
}

#[test]
fn meet_is_associative() {
    let (a, b, c) = (knob(), knob(), knob());
    let world = vec![a.clone(), b.clone(), c.clone()];

    let left = observe_everywhere(&reads(&a).and(reads(&b)).and(reads(&c)), &world);
    let right = observe_everywhere(&reads(&a).and(reads(&b).and(reads(&c))), &world);

    assert_eq!(left, right, "(a ∧ b) ∧ c ≠ a ∧ (b ∧ c)");
}

// ЕДИНИЦА полурешётки: всегда-истинный уровень ничего не меняет. Без неё встреча —
// полугруппа, а не моноид, и «шаг без предусловий» пришлось бы выражать особым случаем.
#[test]
fn always_true_level_is_the_unit_of_meet() {
    let a = knob();
    let world = vec![a.clone()];

    let alone = observe_everywhere(&reads(&a), &world);
    let with_unit = observe_everywhere(&reads(&a).and(Level::always(true)), &world);

    assert_eq!(with_unit, alone, "a ∧ ⊤ ≠ a");
}

// ФУНКТОРНОСТЬ: map(id) = id. Без неё `Level` не функтор, и говорить о структуре рано.
#[test]
fn map_preserves_identity() {
    let a = knob();
    let world = vec![a.clone()];

    let alone = observe_everywhere(&reads(&a), &world);
    let mapped = observe_everywhere(&reads(&a).map(|v| v), &world);

    assert_eq!(mapped, alone, "map(id) ≠ id");
}

// ФУНКТОРНОСТЬ: map(g ∘ f) = map(g) ∘ map(f).
#[test]
fn map_preserves_composition() {
    let a = knob();
    let world = vec![a.clone()];

    // Промежуточный тип НЕ булев намеренно: композиция должна проверяться на паре
    // разных функций, а не на двойном отрицании, которое компилятор схлопнет сам.
    let fused = observe_everywhere(&reads(&a).map(u8::from).map(|n| n == 1), &world);
    let composed = observe_everywhere(&reads(&a).map(|v| u8::from(v) == 1), &world);

    assert_eq!(fused, composed, "map(g) ∘ map(f) ≠ map(g ∘ f)");
}

// ПРОВЕРКА ГОТОВНОСТИ НИЧЕГО НЕ МЕНЯЕТ — аксиома f ∘ f̄ = f в исполнимом виде.
// Уровень, прочитанный дважды подряд в неизменном мире, обязан ответить одинаково;
// иначе «наблюдение» на самом деле действие, и вся рамка неприменима.
#[test]
fn observing_a_guard_is_free_of_effect() {
    let a = knob();
    let world = vec![a.clone()];
    let level = reads(&a).and(reads(&a));

    let first = observe_everywhere(&level, &world);
    let second = observe_everywhere(&level, &world);

    assert_eq!(first, second, "повторное наблюдение дало другой ответ");
}
