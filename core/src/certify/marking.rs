//! Закон метки: пометили — и тот, кто ниже, это прочитал. Единственный закон, чей свидетель не
//! смотрит на провод: метка живёт в ядре, адресована правилам ниже по обходу, и свидетельствует
//! [`Reader`]. Свидетелей двое ([`Downstream`] про пакет, [`Reader`] про метку): счётчик читателя
//! молчит и когда пакет не дошёл вовсе — а это другая беда.

use crate::capability::CanMark;
use crate::held::{Held, Observed, Terminal};

use super::{carries, Downstream, Verdict};

/// Тот, ради кого метка ставится: в бою — счётчик правила `meta mark` ниже очереди, в памятном
/// мире — число. Метка передаётся параметром: читатель, отвечающий на любой вопрос одинаково, не
/// отличил бы нашу метку от чужой.
pub trait Reader {
    fn read(&mut self, mark: u32) -> usize;
}

/// Почему закон не держится.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Broken {
    /// Пакет прошёл, а читатель метки её не увидел — метка не встала или читатель стоит ВЫШЕ
    /// очереди. Чинить в обоих случаях одно: порядок правил.
    MarkUnread,
    /// Пометили — и пакет не пошёл. Метка ни при чём: отпускания не случилось.
    NotPassed,
}

/// Почему вердикта нет — беда стенда.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Invalid {
    /// Свидетель провода не показал ни кадра: без этого `NotPassed` предъявлялся бы при поломке
    /// стенда.
    WitnessSilent,
    /// Пакет ушёл ДО ответа: удержания не было, о метке судить не о чем.
    NotHeld,
    /// Терминал сказал, что ответ не принят.
    AnswerNotTaken,
}

/// Закон метки. Порядок опроса как у соседей; разница — мир отвечает двумя голосами, и в их
/// несогласии живёт находка.
pub fn marks<T, D, R>(
    dut: &mut T,
    held: Held<T::Carrier>,
    mark: u32,
    downstream: &mut D,
    reader: &mut R,
) -> Verdict<Broken, Invalid>
where
    T: Terminal + CanMark,
    T::Carrier: Observed,
    D: Downstream + ?Sized,
    R: Reader + ?Sized,
{
    let ours = held.seen().to_vec();

    match downstream.passed().iter().any(|gone| carries(gone, &ours)) {
        true => Verdict::Invalid(Invalid::NotHeld),
        false => match dut.apply(held.answered(T::mark(mark))) {
            Err(_not_taken) => Verdict::Invalid(Invalid::AnswerNotTaken),
            Ok(_delivered) => match downstream.passed().as_slice() {
                [] => Verdict::Invalid(Invalid::WitnessSilent),
                seen => {
                    let passed = seen.iter().any(|gone| carries(gone, &ours));
                    let counted = reader.read(mark) > 0;
                    match (passed, counted) {
                        (true, true) => Verdict::Held,
                        (true, false) => Verdict::Broken(Broken::MarkUnread),
                        // Метка увела пакет другим маршрутом, мимо свидетеля провода: прочитана —
                        // то есть ровно то, что закон утверждает.
                        (false, true) => Verdict::Held,
                        (false, false) => Verdict::Broken(Broken::NotPassed),
                    }
                }
            },
        },
    }
}
