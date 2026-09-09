//! Терминал над сокетом очереди: `Answer` разбирается в один вызов `verdict`. `&mut` заперт в
//! `apply` — за ним ядро, выше него значения (канон §9). Способность помнить строится тем же словом,
//! что и вердикт: «отпустить и запомнить» неделимо, иначе состояние осталось бы прошлым при
//! отпущенном пакете.

use reflex_core::capability::CanRemember;
use reflex_core::held::{Answered, Delivered, Refused, Terminal};

use super::socket::{QueueError, QueueSocket};
use super::wire::Packet;

/// Носитель права ответить: пакет, чей `id` нужен вердикту. Отдельный тип, не голый `Packet` —
/// носитель едет к терминалу как ПРАВО ответить, а не как данные.
pub struct Held(pub Packet);

/// Чем ответить очереди. `Remembered` несёт следующее состояние в марку — тем же словом, что и
/// вердикт (см. [`CanRemember`]): раздельные слова допускали бы «ответили, но не запомнили».
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Answer {
    Pass,
    Stop,
    Remembered { accept: bool, state: u32 },
}

impl Terminal for QueueSocket {
    type Carrier = Held;
    type Answer = Answer;
    type Refusal = QueueError;

    fn apply(
        &mut self,
        answered: Answered<Held, Answer>,
    ) -> Result<Delivered<Answer>, Refused<Answer, QueueError>> {
        let id = answered.carrier.0.id;
        let done = match answered.answer {
            Answer::Pass => self.verdict(id, true, None),
            Answer::Stop => self.verdict(id, false, None),
            Answer::Remembered { accept, state } => self.verdict(id, accept, Some(state)),
        };
        match done {
            Ok(()) => Ok(Delivered {
                at: answered.at,
                answer: answered.answer,
            }),
            Err(why) => Err(Refused {
                at: answered.at,
                answer: answered.answer,
                why,
            }),
        }
    }
}

impl CanRemember for QueueSocket {
    fn remember(state: u32, accept: bool) -> Answer {
        Answer::Remembered { accept, state }
    }
}
