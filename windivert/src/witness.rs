//! Заместитель формы способностей — не WinDivert. `compile_fail` есть утверждение, проверяемое
//! ТОЛЬКО прогоном (§10.7), а прогнать его на настоящем `WinDivertHandle` здесь нечем: тип живёт под
//! `#[cfg(windows)]`, MSVC-линковщика в этом дереве нет, и `cargo check` доктестов не собирает ни
//! на одной платформе. Этот модуль гейтом не закрыт и бежит везде.
//!
//! ЗАМЕСТИТЕЛЬ ОБЯЗАН БЫТЬ БОГАЧЕ ПРОВЕРЯЕМОЙ СПОСОБНОСТИ, А НЕ БЕДНЕЕ. `compile_fail` на
//! `ask::<T>` доказывает отсутствие `CanAsk` лишь тогда, когда все ОСТАЛЬНЫЕ границы над `T`
//! выполнены: у бедного заместителя та же `E0277` родилась бы от недостающей `CanHold`, и отказ
//! был бы зелен по ложной причине — принадлежность классу «падает из-за `CanAsk`» держалась бы
//! именем проверки, а не её признаком (§10.9). Потому граница предъявляется ПАРОЙ: положительный
//! [`holds`] показывает выполненность прочих границ, `compile_fail` у [`ask`] — отсутствие
//! единственной оставшейся. Порознь ни один из двух прогонов класса не устанавливает.
//!
//! Это замерено, а не выведено: мутант «снять у заместителя `CanRefuse`» оставляет `compile_fail`
//! ЗЕЛЁНЫМ (он начинает падать от другой недостачи), и краснеет на нём только [`holds`].

use reflex_core::capability::{CanAsk, CanHold, CanRefuse};
use reflex_core::held::{Answered, Delivered, Refused, Terminal};

/// Носитель формы `Terminal + CanHold + CanRefuse`. Тела пустые — предмет проверки ГРАНИЦА (какие
/// impl'ы есть), не логика.
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

/// Первая половина пары: все границы гейта, КРОМЕ проверяемой. Зелёный прогон ниже и есть признак,
/// по которому отказ [`ask`] читается как отсутствие `CanAsk`, а не как нехватка чего-то ещё.
///
/// ```
/// use reflex_windivert::witness::{holds, GateWitness};
/// holds::<GateWitness>();
/// ```
pub fn holds<T: Terminal + CanHold + CanRefuse>() {}

/// Вторая половина пары: форма гейта `reflex::Act::<T>::ask` — ГРАНИЦА (`T: CanHold + CanAsk`), не
/// его код. Граница воспроизведена здесь СВОИМ кодом, а не импортом `Act`: фасад достижим только
/// под `cfg(windows)` (`Cargo.toml`), а модуль обязан бежать везде.
///
/// Над [`GateWitness`] граница не проходит — у типа без способности нет импликации, а не ложный
/// результат (§9.1):
///
/// ```compile_fail,E0277
/// use reflex_windivert::witness::{ask, GateWitness};
/// ask::<GateWitness>(1);
/// ```
///
/// Способность прогона дать красный (§10.7) показана мутантом: `impl CanAsk for GateWitness`,
/// дописанный рядом, роняет `cargo test --doc` — «expected compilation to fail… compilation
/// succeeded». Мутант в дерево не коммитится.
pub fn ask<T: Terminal + CanHold + CanAsk>(_token: u64) {}
