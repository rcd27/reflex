//! Закон обрыва: разговор не состоялся, и встречная сторона об этом знает. Не сумма отказа и
//! инъекции: у обрыва есть АДРЕСАТ, и вся разница между лечением и бедой — в нём. Два свидетеля:
//! [`Downstream`] по пути к цели, [`NearEnd`] на породившей стороне (один не различил бы «дошло
//! клиенту» и «дошло цели»).
//!
//! # Чего закон НЕ проверяет, и чего это стоит проверить
//!
//! ПОРЯДОК извещения — «обрыв дошёл раньше, чем цель успела ответить» — здесь невыразим, и причина
//! не в лени: у пакета, которого нет, нет метки времени, а свидетель видит только пришедшее.
//! Различить «цель промолчала» и «цель ответила, но позже нашего обрыва» нечем.
//!
//! Чтобы стало выразимо, нужна ЭХО-РОЛЬ цели: собеседник, который отвечает на всё и помечает ответ
//! своим моментом. Тогда порядок читается сравнением двух меток, а не выводится из отсутствия.
//! Цена — роль в стенде и живой собеседник в нём; предмет того стоит, но работа отдельная.
//!
//! Долг записан ЗДЕСЬ целиком, а не номером чужого тикета: номер переживает основание и обещает
//! учтённость, которой нет, — читатель идёт по ссылке и упирается в закрытое. Условие и цена, в
//! отличие от номера, не протухают.

use crate::backend::Sink;
use crate::capability::{CanInject, CanSever, Toward};
use crate::held::{Held, Observed, Terminal};

use super::{carries, Downstream, Verdict};

/// Свидетель на породившей разговор стороне. Отдельный трейт, не второй [`Downstream`]: стоят на
/// разных границах, перепутать местами — перевернуть вердикт.
pub trait NearEnd {
    /// Что пришло на эту сторону с прошлого вопроса.
    fn arrived(&mut self) -> Vec<Vec<u8>>;
}

/// Почему закон не держится. Четыре беды, лечатся в четырёх местах.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Broken {
    /// Ответили «не пропускать», а пакет пошёл дальше — движок уверен, что оборвал, а разговор идёт.
    PassedAnyway,
    /// Пакет удержан, а сказать забыли: молчаливый дроп, который обрыв и лечит.
    NoticeMissed,
    /// Извещение уехало ЦЕЛИ вместо породившей стороны — стороны перепутаны.
    NoticeToTarget,
    /// Ни отказа, ни извещения: решение не исполнено целиком (чинить путь решения до носителей).
    NeitherHappened,
    /// Извещение не из чего построить: заявив [`CanSever`], бэкенд обещал обрыв целиком.
    NoticeUnbuildable,
}

/// Почему вердикта нет — беда стенда.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Invalid {
    /// Пакет ушёл ДО ответа: предмет [`holds`](super::holding::holds).
    NotHeld,
    /// Терминал сказал, что ответ не принят.
    AnswerNotTaken,
    /// Сток отказался отправлять извещение.
    SinkRefused,
    /// Дальний свидетель не показал ни кадра.
    DownstreamMute,
    /// Ближний свидетель не показал ни кадра (различать с `DownstreamMute` обязательно: разные
    /// приборы, разные причины).
    NearEndMute,
}

/// Закон обрыва. Слова берутся у способностей ([`CanSever`] и [`CanSever::notice`]); `toward` —
/// параметром, ибо какой конец есть клиент, знает ВХОД, не бэкенд. «Сказать нечем» разбирается ДО
/// всякого действия: оборвать молча значило бы исполнить ту беду, что закон стережёт.
pub fn severs<T, B, D, N>(
    dut: &mut T,
    wire: &mut B,
    held: Held<T::Carrier>,
    toward: Toward,
    downstream: &mut D,
    near: &mut N,
) -> Verdict<Broken, Invalid>
where
    T: Terminal + CanSever,
    T::Carrier: Observed,
    B: Sink + CanInject,
    D: Downstream + ?Sized,
    N: NearEnd + ?Sized,
{
    let ours = held.seen().to_vec();

    match T::notice(held.seen(), toward) {
        None => Verdict::Broken(Broken::NoticeUnbuildable),
        Some(notice) => sever_and_judge(dut, wire, held, notice, &ours, downstream, near),
    }
}

/// Вторая половина закона — когда сказать ЕСТЬ чем. Отдельной функцией, чтобы решётка исходов не
/// ушла вправо и читалась.
fn sever_and_judge<T, B, D, N>(
    dut: &mut T,
    wire: &mut B,
    held: Held<T::Carrier>,
    notice: crate::command::InjectablePacket,
    ours: &[u8],
    downstream: &mut D,
    near: &mut N,
) -> Verdict<Broken, Invalid>
where
    T: Terminal + CanSever,
    T::Carrier: Observed,
    B: Sink + CanInject,
    D: Downstream + ?Sized,
    N: NearEnd + ?Sized,
{
    // Отпечаток снимается ДО отправки и IP-формой, не канальной: IP есть подстрока канальной,
    // потому вопрос «дошло ли НАШЕ» задаётся одинаково любому носителю (ср. `carries`).
    let stamp = notice.serialize_ip();

    match downstream.passed().iter().any(|gone| carries(gone, ours)) {
        true => Verdict::Invalid(Invalid::NotHeld),
        false => match dut.apply(held.answered(T::refuse())) {
            Err(_not_taken) => Verdict::Invalid(Invalid::AnswerNotTaken),
            // Отказ первым, извещение вторым: отдай пакет цели раньше обрыва — она ответит, и на
            // проводе появится второй, чужой RST.
            Ok(_delivered) => match wire.emit(B::inject(notice)) {
                Err(_refused) => Verdict::Invalid(Invalid::SinkRefused),
                Ok(()) => judge(downstream.passed(), near.arrived(), ours, &stamp),
            },
        },
    }
}

/// Свести два показания в вердикт. Решётка, не последовательность: восемь исходов трёх наблюдений,
/// каждый назван — цепочка `if` дала бы дыры, которых компилятор не покажет.
fn judge(
    beyond: Vec<Vec<u8>>,
    behind: Vec<Vec<u8>>,
    ours: &[u8],
    stamp: &[u8],
) -> Verdict<Broken, Invalid> {
    // Немота прибора разбирается первой: пустой ответ неотличим от «ничего не прошло».
    match (beyond.as_slice(), behind.as_slice()) {
        ([], _) => Verdict::Invalid(Invalid::DownstreamMute),
        (_, []) => Verdict::Invalid(Invalid::NearEndMute),
        (seen_beyond, seen_behind) => {
            let passed = seen_beyond.iter().any(|frame| carries(frame, ours));
            let at_target = seen_beyond.iter().any(|frame| carries(frame, stamp));
            let at_client = seen_behind.iter().any(|frame| carries(frame, stamp));

            // Приоритет бед: прошедший пакет страшнее промаха адресации, промах — страшнее молчания.
            match (passed, at_target, at_client) {
                (false, false, true) => Verdict::Held,
                (false, false, false) => Verdict::Broken(Broken::NoticeMissed),
                (false, true, true) => Verdict::Broken(Broken::NoticeToTarget),
                (false, true, false) => Verdict::Broken(Broken::NoticeToTarget),
                (true, false, true) => Verdict::Broken(Broken::PassedAnyway),
                (true, false, false) => Verdict::Broken(Broken::NeitherHappened),
                (true, true, true) => Verdict::Broken(Broken::PassedAnyway),
                (true, true, false) => Verdict::Broken(Broken::PassedAnyway),
            }
        }
    }
}
