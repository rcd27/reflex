//! ЗАКОН ПОДМЕНЫ: ПРОШЛИ ИМЕННО ТЕ БАЙТЫ, КОТОРЫЕ МЫ ПОДСТАВИЛИ.
//!
//! # Где здесь ложь, которую типы не видят
//!
//! Подмена случается ДВАЖДЫ: в нашем значении и в мире. Первое компилятор проверяет — слово
//! алфавита несёт байты, и построить его, не назвав их, нельзя. Второе не проверяет никто: ядро
//! может применить вердикт и оставить полезную нагрузку прежней, и всё останется зелёным —
//! `Delivered` честно скажет, ЧЕМ мы ответили.
//!
//! # Почему подмена на то же самое недействительна
//!
//! Ищи закон подставленные байты, не убедившись, что они ОТЛИЧАЮТСЯ от исходных, — и честная
//! очередь была бы неотличима от не подменяющей вовсе: искомое присутствует в обоих случаях.
//! Проверка стоит ПЕРВОЙ, до всякого вопроса к миру: это проверка аргумента, а не мира.

use crate::capability::CanRewrite;
use crate::held::{Held, Observed, Terminal};

use super::{carries, Downstream, Verdict};

/// ПОЧЕМУ ЗАКОН НЕ ДЕРЖИТСЯ. Четыре исхода, потому что вопросов к миру два, и у каждого сочетания
/// своя починка.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Broken {
    /// Прошли ИСХОДНЫЕ байты: вердикт применён, пакет пошёл, подмена не случилась.
    OriginalPassed,
    /// Не прошло ничего: подмену приняли, а пакет не отпустили.
    NothingPassed,
    /// Прошли И подменённые, И исходные — пакет размножился где-то ниже по стеку. Беда третьего
    /// рода: подмена сработала, но не отменила оригинала, и адресат получит оба.
    BothPassed,
}

/// ПОЧЕМУ ВЕРДИКТА НЕТ.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Invalid {
    /// Дальний конец не показал НИ ОДНОГО кадра — ни нашего, ни чужого.
    ///
    /// «Не прошло» и «свидетель не смотрел» дают одинаково пустой ответ. Найдено ЖИВЬЁМ
    /// 05.09.2026: остановленный `dumpcap` — и честная очередь была бы объявлена не отпускающей.
    ///
    /// Урок был выучен утром того же дня в законе инъекции и НЕ перенёсся сюда сам собой:
    /// правило, живущее в другом файле, компилятор не читает. На живом устройстве пустоту
    /// разгоняет МАЯК — кадр, который строит ядро, а не проверяемый бэкенд.
    WitnessSilent,
    /// Подставленные байты совпадают с исходными — подменять было нечего, и различить исполненную
    /// подмену от неисполненной нельзя по построению.
    NotAChange,
    /// Пакет ушёл ДО нашего ответа: удержания не было, и судить о подмене не о чем.
    NotHeld,
    /// Терминал честно сказал, что ответ не принят.
    AnswerNotTaken,
}

/// ЗАКОН ПОДМЕНЫ.
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
                    // ПУСТОЙ ОТВЕТ — НЕ ОБВИНЕНИЕ, А ОТСУТСТВИЕ ВЕРДИКТА: иначе честная очередь
                    // объявлялась бы не отпускающей всякий раз, когда сломался стенд.
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
