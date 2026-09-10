//! ЗАМЕСТИТЕЛЬ ФОРМЫ СПОСОБНОСТЕЙ — не WinDivert. Назван заместителем здесь, в докблоке, а не
//! только в отчёте (по прямому требованию контролёра, 10.09.2026): следующий, кто откроет этот
//! файл, обязан узнать предел ДО того, как прочтёт зелёный тест как свидетельство про WinDivert.
//!
//! ПОЧЕМУ ЗАМЕСТИТЕЛЬ, А НЕ РЕАЛЬНЫЙ ТИП. Настоящая проверка гейта «спросить контур может только
//! носитель, заявивший [`CanAsk`]» живёт в `reflex::Act::<T>::ask` (`reflex/src/lib.rs`) — и
//! `compile_fail`-доктест НА `WinDivertHandle` (докблок `carrier.rs`) её называет, дословно, ради
//! будущей проверки на Windows. Но `compile_fail` — не грамматическая пометка, а утверждение,
//! которое ПРОВЕРЯЕТ ТОЛЬКО ПРОГОН (`cargo test --doc`, не `cargo check` — замерено экспериментом,
//! см. отчёт задачи 12: `cargo check` не трогает доктесты вовсе, ни на одной платформе). Прогнать
//! доктест НА `WinDivertHandle` здесь нечем: тип существует только под `#[cfg(windows)]`, а
//! MSVC-линковки для запуска доктестов в этой песочнице нет. Значит на РЕАЛЬНОМ типе гейт
//! ОБЪЯВЛЕН (текст доктеста в `carrier.rs` стоит), но НЕ ПРЕДЪЯВЛЕН прогоном.
//!
//! ПРЕДЪЯВЛЕН он ЗДЕСЬ — на [`GateWitness`], минимальном типе той же формы способностей
//! (`Terminal` + `CanHold` + `CanRefuse`, БЕЗ `CanAsk` — ровно то подмножество, что заявляет
//! `WinDivertHandle`), тем же приёмом, каким `reflex_core::capability` проверяет КАЖДУЮ способность
//! на придуманном минимальном типе (`struct Immediate;`, `struct Passing;` и т.д.), а не на боевом
//! бэкенде. Этот модуль НЕ гейтится `#[cfg(windows)]` — он собирается и ПРОГОНЯЕТСЯ на любой
//! платформе, и `cargo test --workspace` на Linux реально исполняет доктест ниже.

use reflex_core::capability::{CanAsk, CanHold, CanRefuse};
use reflex_core::held::{Answered, Delivered, Refused, Terminal};

/// Носитель формы `Terminal + CanHold + CanRefuse`, БЕЗ `CanAsk` — той же формы, что и
/// `WinDivertHandle` (`carrier.rs`: заявляет `Terminal`, `CanHold`, `CanRefuse`, `CanInject`,
/// `CanAsk` НЕ заявляет). Тела пустые — предмет проверки ГРАНИЦА (какие impl'ы ЕСТЬ), не логика.
pub struct GateWitness;

impl Terminal for GateWitness {
    type Carrier = ();
    type Answer = ();
    type Refusal = ();

    fn apply(&mut self, answered: Answered<(), ()>) -> Result<Delivered<()>, Refused<(), ()>> {
        Ok(Delivered {
            at: answered.at,
            answer: answered.answer,
        })
    }
}

impl CanHold for GateWitness {
    fn release() {}
}

impl CanRefuse for GateWitness {
    fn refuse() {}
}

/// Форма гейта `reflex::Act::<T>::ask` — ГРАНИЦА (bound `T: CanHold + CanAsk`),
/// не его код. С задачи 12¾ этот крейт ЗАВИСИТ от `reflex` (под `cfg(windows)`, `Cargo.toml`) —
/// но этот модуль НЕ гейтится `cfg(windows)` (докблок модуля выше) и обязан собираться на Linux
/// тоже, где `reflex` недостижим. Граница воспроизведена ЗДЕСЬ, СВОИМ кодом, а не переиспользованием
/// реального `Act`, ровно затем, чтобы над типом БЕЗ `CanAsk` эта функция не собралась — тем же
/// способом, каким не собрался бы `Act::<T>::ask` над таким же типом.
///
/// Над [`GateWitness`] (форма без `CanAsk`) граница не проходит — не рантайм-проверка: у типа без
/// нужной способности нет импликации, а не ложный результат (§9.1, тот же довод, каким `emit` в
/// `reflex/src/lib.rs` объясняет `Act::<NfqueueCarrier>::ask`):
///
/// ```compile_fail,E0277
/// use reflex_windivert::witness::{ask, GateWitness};
/// ask::<GateWitness>(1);
/// ```
///
/// МУТАЦИЯ (свидетельство в отчёте задачи 12, не здесь — сюда мутация не коммитится): добавление
/// `impl CanAsk for GateWitness { .. }` рядом со строками выше делает доктест ЗЕЛЁНЫМ вместо того,
/// чтобы остаться `compile_fail`-пройденным — то есть `cargo test --doc` перестаёт подтверждать
/// отказ и начинает ПАДАТЬ («expected compilation to fail… compilation succeeded»). Ровно так тест
/// ЗАМЕЧАЕТ исчезновение запрета, а не молчит о нём.
pub fn ask<T: Terminal + CanHold + CanAsk>(_token: u64) {}
