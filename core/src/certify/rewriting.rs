//! Закон подмены: прошли именно те байты, которые мы подставили. Подмена случается дважды — в
//! значении (компилятор проверяет: слово несёт байты) и в мире (не проверяет никто). Подмена на то
//! же самое недействительна: проверка стоит первой, до вопроса к миру — это проверка аргумента.

use crate::capability::CanRewrite;
use crate::held::{Held, Observed, Terminal};

use super::{carries, Downstream, Verdict};

/// Почему закон не держится. Четыре исхода — вопросов к миру два, у каждого сочетания своя починка.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Broken {
    /// Прошли исходные байты: вердикт применён, подмена не случилась.
    OriginalPassed,
    /// Не прошло ничего: подмену приняли, пакет не отпустили.
    NothingPassed,
    /// Прошли и подменённые, и исходные — пакет размножился ниже по стеку: адресат получит оба.
    BothPassed,
}

/// Почему вердикта нет — беда стенда.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Invalid {
    /// Дальний конец не показал ни кадра: пустоту живому устройству разгоняет маяк от ядра.
    WitnessSilent,
    /// Подставленные байты совпадают с исходными — подменять было нечего.
    NotAChange,
    /// Пакет ушёл ДО ответа: удержания не было, о подмене судить не о чем.
    NotHeld,
    /// Терминал сказал, что ответ не принят.
    AnswerNotTaken,
}

/// Закон подмены.
pub fn rewrites<T, D>(
    dut: &mut T,
    held: Held<T::Carrier>,
    replacement: Vec<u8>,
    downstream: &mut D,
) -> Verdict<Broken, Invalid>
where
    T: Terminal + CanRewrite,
    T::Carrier: Observed,
    D: Downstream + ?Sized,
{
    let ours = held.seen().to_vec();

    match replacement == ours {
        true => Verdict::Invalid(Invalid::NotAChange),
        false => match downstream.passed().iter().any(|gone| carries(gone, &ours)) {
            true => Verdict::Invalid(Invalid::NotHeld),
            false => match dut.apply(held.answered(T::rewrite(replacement.clone()))) {
                Err(_not_taken) => Verdict::Invalid(Invalid::AnswerNotTaken),
                Ok(_delivered) => match downstream.passed().as_slice() {
                    [] => Verdict::Invalid(Invalid::WitnessSilent),
                    gone => {
                        let substituted = gone.iter().any(|one| carries(one, &replacement));
                        let untouched = gone.iter().any(|one| carries(one, &ours));
                        match (substituted, untouched) {
                            (true, false) => Verdict::Held,
                            (true, true) => Verdict::Broken(Broken::BothPassed),
                            (false, true) => Verdict::Broken(Broken::OriginalPassed),
                            (false, false) => Verdict::Broken(Broken::NothingPassed),
                        }
                    }
                },
            },
        },
    }
}
