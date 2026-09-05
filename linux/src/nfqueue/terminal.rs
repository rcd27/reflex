//! ОЧЕРЕДЬ ЯДРА КАК ТЕРМИНАЛЬНЫЙ МОРФИЗМ — единственное место, где решение становится эффектом.
//!
//! # Что здесь чинится
//!
//! Прежде вердикт был ВЫЗОВОМ и стоял в четырёх местах:
//!
//! ```text
//! msg.set_verdict(Verdict::Accept);
//! let _ = self.queue.verdict(msg);      // ← и так четырежды
//! ```
//!
//! Две беды в одном выражении, и обе про то, что сведения покидали значение:
//!
//! 1. Вызов нельзя ни записать, ни сравнить, ни развернуть назад — после него не остаётся ничего,
//!    и расследование по такому шагу невозможно.
//! 2. `let _ =` выбрасывал ЕДИНСТВЕННЫЙ факт о доставке. Ядро отказывает — например, когда
//!    сообщение уже протухло по таймауту очереди, — и мы бы не узнали.
//!
//! Здесь решение отделено от эффекта: цепочка порождает
//! [`Answered`](reflex_core::held::Answered), а мира касается ровно [`Terminal::apply`]. Отказ
//! ядра становится значением [`Refused`](reflex_core::held::Refused), а не тишиной.
//!
//! # `&mut` остаётся, и это правильно
//!
//! Netlink-сокет один, отправка по нему последовательна по природе, и край — место для
//! performance-first. Вопрос был не в том, чтобы `&mut` убрать, а в том, чтобы он стоял В ОДНОМ
//! МЕСТЕ: выше него значения, ниже мир.

use nfq::Verdict;
use reflex_core::held::{Answered, Delivered, Refused, Terminal};

use super::backend::NfqueueBackend;

/// ЧЕМ МОЖНО ОТВЕТИТЬ ОЧЕРЕДИ — её собственный алфавит, а не общий на все носители.
///
/// Ровно четыре слова, потому что ровно столько умеет очередь. Пятого варианта здесь не завести
/// молча: он потребует ветки в [`Terminal::apply`], и компилятор это спросит.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer {
    /// Пропустить как есть.
    Pass,
    /// Пропустить, поставив метку. ПАКЕТ ПРОДОЛЖАЕТ ОБХОД С МЕСТА, ГДЕ ЕГО ЗАБРАЛИ: правило,
    /// читающее метку, обязано стоять НИЖЕ по цепочке, чем правило очереди. Поставь его выше —
    /// метка встанет и не будет прочитана никем, а прибор покажет «решение принято».
    Marked(u32),
    /// Не пропускать.
    Stop,
    /// Пропустить с подменёнными байтами.
    Modified(Vec<u8>),
}

/// ПОЧЕМУ ЯДРО НЕ ПРИНЯЛО ОТВЕТ. Отдельный тип, а не строка: у отказа есть причина, и она
/// приходит от операционной системы — терять её значило бы возвращаться к `let _ =`.
#[derive(Debug)]
pub struct NotTaken(pub std::io::Error);

impl Terminal for NfqueueBackend {
    type Carrier = nfq::Message;
    type Answer = Answer;
    type Refusal = NotTaken;

    fn apply(
        &mut self,
        answered: Answered<nfq::Message, Answer>,
    ) -> Result<Delivered<Answer>, Refused<Answer, NotTaken>> {
        let Answered {
            mut carrier,
            seen,
            at,
            answer,
        } = answered;

        match &answer {
            Answer::Pass => carrier.set_verdict(Verdict::Accept),
            Answer::Marked(mark) => {
                carrier.set_nfmark(*mark);
                carrier.set_verdict(Verdict::Accept);
            }
            Answer::Stop => carrier.set_verdict(Verdict::Drop),
            // КОПИЯ БАЙТОВ — ЦЕНА ТОГО, ЧТО НИЧЕГО НЕ СЪЕДАЕТСЯ, и она названа здесь, а не
            // обнаружена профилировщиком. Подменённые байты обязаны уехать И в ядро, И в дело:
            // отдай мы их ядру по владению, `Delivered` перестал бы говорить, ЧЕМ именно
            // ответили, — то есть шаг снова стал бы невосстановимым. Платит только эта ветвь,
            // самая редкая из четырёх; `Pass`, `Marked` и `Stop` не копируют ничего.
            Answer::Modified(bytes) => {
                carrier.set_payload(bytes.clone());
                carrier.set_verdict(Verdict::Accept);
            }
        }

        // ЕДИНСТВЕННОЕ МЕСТО, ГДЕ СЛУЧАЕТСЯ МИР — и единственное, где его отказ ловится.
        match self.send_verdict(carrier) {
            Ok(()) => Ok(Delivered { seen, at, answer }),
            Err(why) => Err(Refused {
                seen,
                at,
                answer,
                why: NotTaken(why),
            }),
        }
    }
}
