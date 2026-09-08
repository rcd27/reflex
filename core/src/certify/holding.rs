//! Закон удержания: пока мы не ответили — пакет не идёт дальше. Главный закон боевого бэкенда: всё
//! на NFQUEUE стоит на посылке «ядро ждёт решения»; ложна она — движок комментирует вдогонку уже
//! ушедшему. Свидетель — [`Downstream`], спрашиваемый ДВАЖДЫ (до ответа и после): закон не о
//! количестве, а о ПОРЯДКЕ.

use crate::capability::CanHold;
use crate::held::{Held, Observed, Terminal};

use super::{carries, Downstream, Verdict};

/// Почему закон не держится. Две беды, противоположные по знаку.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Broken {
    /// Пакет ушёл ДО того, как у нас спросили решение: удержания нет, всё дальше — комментарий.
    PassedBeforeAnswer,
    /// Отпустили — а пакет так и не пошёл. Для человека неотличимо от дропа, только тише.
    NeverPassed,
}

/// Почему вердикта нет — беда стенда.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Invalid {
    /// Дальний конец не показал ни кадра: пустоту живому устройству разгоняет маяк от ядра.
    WitnessSilent,
    /// Терминал сказал, что ответ не принят — беда мира, о которой сообщили; предъявлять её как
    /// ложное заявление значило бы наказывать за честность.
    AnswerNotTaken,
}

/// Закон удержания. Порядок вопросов и есть предмет: (1) спросить дальний конец ДО ответа — нашего
/// там быть не должно; (2) отпустить словом [`CanHold::release`]; (3) спросить снова — наше обязано
/// быть. Чужой трафик не обвиняет: ищется именно наш, по байтам удержанного.
pub fn holds<T, D>(
    dut: &mut T,
    held: Held<T::Carrier>,
    downstream: &mut D,
) -> Verdict<Broken, Invalid>
where
    T: Terminal + CanHold,
    T::Carrier: Observed,
    D: Downstream + ?Sized,
{
    let ours = held.seen().to_vec();

    match downstream.passed().iter().any(|gone| carries(gone, &ours)) {
        true => Verdict::Broken(Broken::PassedBeforeAnswer),
        false => match dut.apply(held.answered(T::release())) {
            Err(_not_taken) => Verdict::Invalid(Invalid::AnswerNotTaken),
            Ok(_delivered) => match downstream.passed().as_slice() {
                [] => Verdict::Invalid(Invalid::WitnessSilent),
                seen => match seen.iter().any(|gone| carries(gone, &ours)) {
                    true => Verdict::Held,
                    false => Verdict::Broken(Broken::NeverPassed),
                },
            },
        },
    }
}
