//! ЗАКОН ОТКАЗА: СКАЗАЛИ «НЕ ПРОПУСКАТЬ» — И НЕ ПРОШЛО.
//!
//! # Самый опасный из невыполненных ответов
//!
//! Отказ, который не исполнился, оставляет движок в уверенности, что он заблокировал: вердикт
//! вынесен, `Delivered` подтверждает доставку, спан записан, счётчик сдвинут. А человек видит, что
//! страница открылась. Различить эти два состояния изнутри процесса нечем совершенно — между «мы
//! ответили» и «мир послушался» лежит чужая машина.

use crate::capability::CanRefuse;
use crate::held::{Held, Observed, Terminal};

use super::{carries, Downstream, Verdict};

/// ПОЧЕМУ ЗАКОН НЕ ДЕРЖИТСЯ. Причина одна, потому что и беда одна: отказ не исполнился.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Broken {
    /// Ответили «не пропускать», а пакет пошёл дальше.
    PassedAnyway,
}

/// ПОЧЕМУ ВЕРДИКТА НЕТ.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Invalid {
    /// Дальний конец не показал НИ ОДНОГО кадра — ни нашего, ни чужого.
    ///
    /// «Не прошло» и «свидетель не смотрел» дают одинаково пустой ответ. Найдено ЖИВЬЁМ
    /// 05.09.2026: остановленный `dumpcap` — и закон отказа выдал `held`, то есть подтвердил
    /// способность, ничего не установив.
    ///
    /// Урок был выучен утром того же дня в законе инъекции и НЕ перенёсся сюда сам собой:
    /// правило, живущее в другом файле, компилятор не читает. На живом устройстве пустоту
    /// разгоняет МАЯК — кадр, который строит ядро, а не проверяемый бэкенд.
    WitnessSilent,
    /// Пакет ушёл ДО нашего ответа. Судить об отказе, когда удержания не было, значит предъявлять
    /// этой способности чужую беду: удержание — предмет закона
    /// [`holds`](super::holding::holds), и у него свой вердикт.
    NotHeld,
    /// Терминал честно сказал, что ответ не принят.
    AnswerNotTaken,
}

/// ЗАКОН ОТКАЗА.
///
/// Слово берётся у самой способности, а не приходит параметром: закон, которому ответ передают
/// снаружи, проверял бы согласие вызывающего с самим собой.
pub fn refuses<T, D>(
    dut: &mut T,
    held: Held<T::Carrier>,
    downstream: &mut D,
) -> Verdict<Broken, Invalid>
where
    T: Terminal + CanRefuse,
    T::Carrier: Observed,
    D: Downstream + ?Sized,
{
    let ours = held.seen().to_vec();

    match downstream.passed().iter().any(|gone| carries(gone, &ours)) {
        true => Verdict::Invalid(Invalid::NotHeld),
        false => match dut.apply(held.answered(T::refuse())) {
            Err(_not_taken) => Verdict::Invalid(Invalid::AnswerNotTaken),
            // ПУСТОЙ ОТВЕТ — НЕ СОБЛЮДЕНИЕ, А ОТСУТСТВИЕ ВЕРДИКТА. Свидетель, не увидевший
            // НИЧЕГО, не увидел и чужого шума, которого в живом стеке всегда хватает.
            Ok(_delivered) => match downstream.passed().as_slice() {
                [] => Verdict::Invalid(Invalid::WitnessSilent),
                seen => match seen.iter().any(|gone| carries(gone, &ours)) {
                    true => Verdict::Broken(Broken::PassedAnyway),
                    false => Verdict::Held,
                },
            },
        },
    }
}
