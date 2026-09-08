//! Закон отказа: сказали «не пропускать» — и не прошло. Самый опасный из невыполненных ответов:
//! между «мы ответили» и «мир послушался» лежит чужая машина. Свидетель — [`Downstream`].

use crate::capability::CanRefuse;
use crate::held::{Held, Observed, Terminal};

use super::{carries, Downstream, Verdict};

/// Почему закон не держится: отказ не исполнился.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Broken {
    /// Ответили «не пропускать», а пакет пошёл дальше.
    PassedAnyway,
}

/// Почему вердикта нет — беда стенда, не подопытного.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Invalid {
    /// Дальний конец не показал ни кадра: «не прошло» и «свидетель не смотрел» дают одинаково
    /// пустой ответ. Живому устройству пустоту разгоняет маяк — кадр от ядра, не от подопытного.
    WitnessSilent,
    /// Пакет ушёл ДО ответа: удержание — предмет закона [`holds`](super::holding::holds), у него
    /// свой вердикт.
    NotHeld,
    /// Терминал сказал, что ответ не принят.
    AnswerNotTaken,
}

/// Закон отказа. Слово берётся у способности [`CanRefuse`], а не параметром — иначе закон проверял
/// бы согласие вызывающего с самим собой. Ищется именно наш кадр (по байтам удержанного): чужой
/// трафик не обвиняет.
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
