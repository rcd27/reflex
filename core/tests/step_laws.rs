//! ЗАКОНЫ КАТЕГОРИИ НА НОСИТЕЛЕ ЗНАЧЕНИЯ (шестой vision §9).
//!
//! Vision 3 §6 объявил ассоциативность и тождество для носителя-потока. Носитель сменился, и
//! законы обязаны быть предъявлены заново: у потока ассоциативность держалась тем, что операторы
//! не имели состояния, а у машины Мили состояние есть по определению — значит и сломать её можно
//! иначе (композит, пересобирающий второе звено из начального, выглядит исправным ровно до
//! второго входа).
//!
//! # Метод: исчерпывающий перебор, а не property-раннер
//!
//! Домашнее правило репы (`core/tests/category_laws.rs`): «перебор всех состояний строже любого
//! property-раннера и не требует новой зависимости». Мир конечен, равенство НАБЛЮДАТЕЛЬНОЕ: две
//! цепочки равны, если на всех входах дают один выход.
//!
//! # ЧТО ЭТОТ ЗАКОН СТОРОЖИТ НА САМОМ ДЕЛЕ — сказано прямо
//!
//! Сломать `Then`, СОХРАНИВ СИГНАТУРУ, невозможно: состояние второго звена переносится
//! семантикой перемещения, и попытка вернуть вместо него старое даёт
//! `E0382: use of moved value: self.1` (проверено 06.09.2026). То есть ассоциативность здесь
//! сторожит РЕГРЕССИЮ СИГНАТУРЫ, а не логику, и называть её обезоруженной было бы враньём —
//! ровно тем, которое `category_laws.rs` однажды у себя и поймал.
//!
//! Закон о жизни состояния уже предъявлен и здесь НЕ ПОВТОРЯЕТСЯ:
//! `core/tests/step.rs::composition_carries_the_state_of_both_links`.

use reflex_core::step::{Id, Step, StepExt};

/// МИР КОНЕЧЕН: все непустые последовательности длины ≤ 3 из трёх значений — 39 входов.
///
/// Длина три — минимальная, на которой видна разница между «состояние живёт» и «состояние
/// пересобирается»: на одном входе неисправный композит неотличим от исправного.
fn world() -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for a in 0..3u8 {
        out.push(vec![a]);
    }
    for a in 0..3u8 {
        for b in 0..3u8 {
            out.push(vec![a, b]);
        }
    }
    for a in 0..3u8 {
        for b in 0..3u8 {
            for c in 0..3u8 {
                out.push(vec![a, b, c]);
            }
        }
    }
    out
}

/// ПРОГНАТЬ ЦЕПОЧКУ ПО ВХОДАМ И СОБРАТЬ ВЫХОДЫ. Наблюдательное равенство меряется этим.
fn run<M: Step<From = u8, To = u8>>(machine: M, input: &[u8]) -> Vec<u8> {
    let mut machine = machine;
    let mut told = Vec::with_capacity(input.len());
    for byte in input {
        let (next, out) = machine.step(*byte);
        machine = next;
        told.push(out);
    }
    told
}

/// СУММАТОР: помнит всё, что прошло.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Adding(u8);

impl Step for Adding {
    type From = u8;
    type To = u8;

    fn step(self, input: u8) -> (Self, u8) {
        let sum = self.0.wrapping_add(input);
        (Adding(sum), sum)
    }
}

/// ЗАПАЗДЫВАЮЩИЙ УДВОИТЕЛЬ: отдаёт удвоенный вход плюс ПРЕДЫДУЩИЙ вход.
///
/// Состояние здесь не накопитель, а память об одном шаге назад: два разных вида памяти в одном
/// мире делают закон менее склонным к случайному прохождению.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Doubling(u8);

impl Step for Doubling {
    type From = u8;
    type To = u8;

    fn step(self, input: u8) -> (Self, u8) {
        let out = input.wrapping_mul(2).wrapping_add(self.0);
        (Doubling(input), out)
    }
}

/// РЕКОРДСМЕН: самое большое, что видел.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Maxing(u8);

impl Step for Maxing {
    type From = u8;
    type To = u8;

    fn step(self, input: u8) -> (Self, u8) {
        let top = self.0.max(input);
        (Maxing(top), top)
    }
}

/// ЗАКОН 1: `(f ∘ g) ∘ h ≡ f ∘ (g ∘ h)`.
///
/// Типы у двух сторон РАЗНЫЕ (`Then<Then<A,B>,C>` против `Then<A,Then<B,C>>`), и потому равенство
/// здесь может быть только наблюдательным — компилятор его не проверит и проверить не может.
#[test]
fn composition_is_associative() {
    for input in world() {
        let left = run(Adding(0).then(Doubling(0)).then(Maxing(0)), &input);
        let right = run(Adding(0).then(Doubling(0).then(Maxing(0))), &input);
        assert_eq!(left, right, "вход {input:?}");
    }
}

/// ЗАКОН 2: `id ∘ f ≡ f ≡ f ∘ id`.
///
/// Проверяется с ОБЕИХ сторон намеренно: тождество, пропускающее вход, но теряющее состояние
/// соседа, нарушило бы только одну из них.
///
/// Сила та же, что у ассоциативности: `Id` без состояния сломать, сохранив сигнатуру, нечем —
/// вернуть из `step` что-то, кроме входа, не из чего. Сторож регрессии сигнатуры, и это сказано,
/// а не подразумевается.
#[test]
fn identity_is_neutral_on_both_sides() {
    for input in world() {
        let bare = run(Adding(0), &input);
        let before = run(Id::new().then(Adding(0)), &input);
        let after = run(Adding(0).then(Id::new()), &input);

        assert_eq!(before, bare, "id слева, вход {input:?}");
        assert_eq!(after, bare, "id справа, вход {input:?}");
    }

    // НЕЙТРАЛЬНОСТЬ В ТИПАХ — ОТДЕЛЬНОЕ УТВЕРЖДЕНИЕ, и закон по выходам его не видит.
    // Цепочка с тождеством обязана нести то же, что несла без него; иначе `id` не нейтрален, а
    // обедняет соседа. Проверяется употреблением: не соберись эти строки — тест красный.
    fn needs_the_lot<M: Step + Copy + Clone + core::fmt::Debug + PartialEq + Eq>(_: M) {}
    needs_the_lot(Adding(0));
    needs_the_lot(Id::<u8>::new().then(Adding(0)));
    needs_the_lot(Adding(0).then(Id::<u8>::new()));
}
