//! Девятый закон: край ПОМНИТ отданное состояние. Ради него весь замысел — состояние уезжает в
//! ядро с вердиктом и возвращается следующим шагом того же потока. Свидетель — ДРУГАЯ ДВЕРЬ: пишем
//! очередью (`NFNL_SUBSYS_QUEUE`), читаем дампом ctnetlink (`NFNL_SUBSYS_CTNETLINK`). Разбор `CTA_*`
//! при этом общий, и это правильно: независимость свидетеля здесь в том, ОТКУДА взяты байты, а не
//! кем разобраны — второй разбор дал бы независимость ценой двух законов об одной марке.

use crate::capability::CanRemember;
use crate::held::{Held, Terminal};

use super::Verdict;

/// Свидетель марки — читает её другой дверью, чем писали. `None` — записи не увидел вовсе (у ядра
/// нет conntrack-вида): беда стенда, не подопытного.
pub trait Recaller {
    fn recall(&mut self) -> Option<u32>;
}

/// Почему закон не держится — вина ПОДОПЫТНОГО.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Broken {
    /// Отдали `asked`, а вернулось `found` без наших бит: состояние не доехало до ядра.
    StateLost { asked: u32, found: u32 },
    /// Наши биты встали, а ЧУЖИЕ (`asked` = чужая разметка) стёрты: read-modify-write сломан, и это
    /// нарушенное обещание соседям по машине, которых мы не знаем.
    Clobbered { asked: u32, found: u32 },
}

/// Почему вердикта нет — беда СТЕНДА, не подопытного (предъявлять её как нарушение способности
/// значило бы наказывать за честность).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Invalid {
    /// Свидетель не увидел записи: у ядра нет `NFQA_CT` (conntrack не ведёт вид), судить не о чем.
    NoConntrack,
    /// Терминал сказал, что вердикт не принят — беда мира, о которой сообщили.
    AnswerNotTaken,
}

/// Закон памяти. Отдаём состояние `state` вердиктом, заранее пометив чужими битами `foreign`; затем
/// спрашиваем свидетеля. Наши биты обязаны вернуться (`found & state == state`), чужие — пережить
/// (`found & foreign == foreign`). Порядок вин существен: молчание свидетеля — беда стенда, не потеря.
pub fn remembers<T, R>(
    dut: &mut T,
    held: Held<T::Carrier>,
    state: u32,
    foreign: u32,
    recaller: &mut R,
) -> Verdict<Broken, Invalid>
where
    T: Terminal + CanRemember,
    R: Recaller + ?Sized,
{
    match dut.apply(held.answered(T::remember(state, true))) {
        Err(_not_taken) => Verdict::Invalid(Invalid::AnswerNotTaken),
        Ok(_delivered) => match recaller.recall() {
            None => Verdict::Invalid(Invalid::NoConntrack),
            Some(found) if found & state != state => Verdict::Broken(Broken::StateLost {
                asked: state,
                found,
            }),
            Some(found) if found & foreign != foreign => Verdict::Broken(Broken::Clobbered {
                asked: foreign,
                found,
            }),
            Some(_found) => Verdict::Held,
        },
    }
}
