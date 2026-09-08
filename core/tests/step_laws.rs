//! ЗАКОНЫ КАТЕГОРИИ НА НОСИТЕЛЕ ЗНАЧЕНИЯ (канон §3).
//!
//! Канон §3 объявил ассоциативность и тождество для носителя-потока. Носитель сменился, и
//! законы обязаны быть предъявлены заново: у потока ассоциативность держалась тем, что операторы
//! не имели состояния, а у машины Мили состояние есть по определению — значит и сломать её можно
//! иначе (композит, пересобирающий второе звено из начального, выглядит исправным ровно до
//! второго входа).
//!
//! # Метод: исчерпывающий перебор, а не property-раннер
//!
//! Домашнее правило репы, ранее сформулированное в снесённом до этой ветки файле законов
//! категории: «перебор всех состояний строже любого property-раннера и не требует новой
//! зависимости». Мир конечен, равенство НАБЛЮДАТЕЛЬНОЕ: две цепочки равны, если на всех входах
//! дают один выход.
//!
//! # ЧТО ЭТОТ ЗАКОН СТОРОЖИТ НА САМОМ ДЕЛЕ — сказано прямо
//!
//! Сломать `Compose`, СОХРАНИВ СИГНАТУРУ, невозможно: состояние второго звена переносится
//! семантикой перемещения, и попытка вернуть вместо него старое даёт
//! `E0382: use of moved value: self.1` (проверено 06.09.2026). То есть ассоциативность здесь
//! сторожит РЕГРЕССИЮ СИГНАТУРЫ, а не логику, и называть её обезоруженной было бы враньём —
//! ровно тем, которое прежние законы категории однажды у себя и поймали.
//!
//! Закон о жизни состояния уже предъявлен и здесь НЕ ПОВТОРЯЕТСЯ: см.
//! `composition_carries_the_state_of_both_links` в тестах шага.

use reflex_core::mealy::{Id, Mealy, MealyExt};
use reflex_core::word::{Base, Word};

/// ОБЛАСТЬ ЗАКОННОГО СТЕНДА.
///
/// Объявляется здесь, а не в фундаменте: закон обязан быть выразим для того, кто заводит свою
/// область снаружи, и стенд — первый такой заводящий.
struct Bench;
impl Base for Bench {}

/// СЛОВО СТЕНДА. Голое число словом быть не может: адрес объявляет ЗНАЧЕНИЕ, а число ничего никому
/// не говорит — и объявить за него область стенд не вправе, потому что число принадлежит не ему.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Beat(u8);

impl Word for Beat {
    type Of = Bench;
}

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
fn run<M: Mealy<In = Beat, Out = Beat>>(machine: M, input: &[u8]) -> Vec<Beat> {
    let mut machine = machine;
    let mut told = Vec::with_capacity(input.len());
    for byte in input {
        // Показания — не предмет закона категории: он о слове и о состоянии, а не о том, что
        // копится вбок.
        let (next, out, _notes) = machine.step(Beat(*byte));
        machine = next;
        told.push(out);
    }
    told
}

/// СУММАТОР: помнит всё, что прошло.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Adding(u8);

impl Mealy for Adding {
    type In = Beat;
    type Out = Beat;
    type Log = ();

    fn step(self, input: Beat) -> (Self, Beat, ()) {
        let sum = self.0.wrapping_add(input.0);
        (Adding(sum), Beat(sum), ())
    }
}

/// ЗАПАЗДЫВАЮЩИЙ УДВОИТЕЛЬ: отдаёт удвоенный вход плюс ПРЕДЫДУЩИЙ вход.
///
/// Состояние здесь не накопитель, а память об одном шаге назад: два разных вида памяти в одном
/// мире делают закон менее склонным к случайному прохождению.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Doubling(u8);

impl Mealy for Doubling {
    type In = Beat;
    type Out = Beat;
    type Log = ();

    fn step(self, input: Beat) -> (Self, Beat, ()) {
        let out = input.0.wrapping_mul(2).wrapping_add(self.0);
        (Doubling(input.0), Beat(out), ())
    }
}

/// РЕКОРДСМЕН: самое большое, что видел.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Maxing(u8);

impl Mealy for Maxing {
    type In = Beat;
    type Out = Beat;
    type Log = ();

    fn step(self, input: Beat) -> (Self, Beat, ()) {
        let top = self.0.max(input.0);
        (Maxing(top), Beat(top), ())
    }
}

/// ЗАКОН 1: `(f ∘ g) ∘ h ≡ f ∘ (g ∘ h)`.
///
/// Типы у двух сторон РАЗНЫЕ (`Compose<Compose<A,B>,C>` против `Compose<A,Compose<B,C>>`), и потому равенство
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
    fn needs_the_lot<M: Mealy + Copy + Clone + core::fmt::Debug + PartialEq + Eq>(_: M) {}
    needs_the_lot(Adding(0));
    needs_the_lot(Id::<Beat>::new().then(Adding(0)));
    needs_the_lot(Adding(0).then(Id::<Beat>::new()));
}

/// МОЛЧАЩИЙ НАБЛЮДАТЕЛЬ: слушает ту же букву, слова не говорит, копит показание.
///
/// `Out = ()` — не заглушка, а подпись: `()` адресовано `Nobody`, и звену с таким словом сказать
/// некому по построению. Счёт при этом уходит показанием, а не словом, — соседям он не адресован.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Watching(u32);

impl Mealy for Watching {
    type In = Beat;
    type Out = ();
    type Log = u32;

    fn step(self, _input: Beat) -> (Self, (), u32) {
        let seen = self.0 + 1;
        (Watching(seen), (), seen)
    }
}

/// СОСЕДСТВО НЕЙТРАЛЬНО В СЛОВАХ: приставленный наблюдатель не меняет НИ ОДНОГО выхода.
///
/// Это и есть закон, ради которого `Pair` отделён от [`reflex_core::detector::Both`]: у
/// `Both` слова обоих звеньев сливаются произведением и потому видны соседу, здесь же слово одно
/// — левого. Наблюдение, способное изменить сказанное, наблюдением не является.
#[test]
fn watching_alongside_changes_no_word() {
    for input in world() {
        let bare = run(Adding(0), &input);
        let watched = run(Adding(0).alongside(Watching(0)), &input);

        assert_eq!(
            bare, watched,
            "приставленный наблюдатель изменил слово на входе {input:?}"
        );
    }
}

/// ПОКАЗАНИЯ ИДУТ ПРОИЗВЕДЕНИЕМ, И СОСТОЯНИЕ НАБЛЮДАТЕЛЯ ЖИВЁТ.
///
/// Второе проверяется тремя буквами не случайно: наблюдатель, пересобираемый из начального на
/// каждом входе, отдавал бы единицу всякий раз и выглядел бы исправным ровно до второй буквы.
#[test]
fn watching_alongside_keeps_its_own_count() {
    let mut chain = Adding(0).alongside(Watching(0));
    let mut counts = Vec::new();

    for byte in [1u8, 2, 3] {
        let (next, _word, ((), seen)) = chain.step(Beat(byte));
        chain = next;
        counts.push(seen);
    }

    assert_eq!(counts, vec![1, 2, 3], "счёт наблюдателя обязан расти");
}
