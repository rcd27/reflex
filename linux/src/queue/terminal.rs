//! Терминал над сокетом очереди: `Answer` разбирается в один вызов `verdict`. `&mut` заперт в
//! `apply` — за ним ядро, выше него значения (канон §9). Способность помнить строится тем же словом,
//! что и вердикт: «отпустить и запомнить» неделимо, иначе состояние осталось бы прошлым при
//! отпущенном пакете.

use reflex_core::capability::CanRemember;
use reflex_core::held::{Answered, Delivered, Edging, Refused, Terminal};

use crate::conntrack::{CtEdge, TimeoutBase};

use super::socket::{QueueError, QueueSocket};
use super::wire::Packet;

/// Носитель права ответить: пакет, чей `id` нужен вердикту, и база таймаутов, без которой `CtEdge`
/// не построить. База едет с носителем, а не с приборами: снимается РАЗ при открытии очереди (см.
/// `TimeoutBase::read`), а `Edging` спрашивают у сообщения — внутри `serve` бэкенд заимствован на
/// всё время решения, вторично взять базу у него уже нечем (та же `E0499`, из-за которой очередь
/// стала `Serves`, а не `Source`).
pub struct Held {
    packet: Packet,
    base: TimeoutBase,
}

impl Held {
    pub fn new(packet: Packet, base: TimeoutBase) -> Self {
        Self { packet, base }
    }
}

impl Edging for Held {
    type Edge = CtEdge;

    /// `None` — у пакета нет вида ядра (`NFQA_CT` не пришёл): поток ещё не в conntrack (первый
    /// `SYN` вне таблицы). Клетка §7: «не считали» обязано отличаться от «цель не ответила», и
    /// `map` этого не путает — оборачивает построенный край, не подставляет нулевой.
    fn edge(&self) -> Option<CtEdge> {
        self.packet.ct.map(|view| CtEdge::seen(view, self.base))
    }
}

/// Чем ответить очереди. `Remembered` несёт следующее состояние в марку — тем же словом, что и
/// вердикт (см. [`CanRemember`]): раздельные слова допускали бы «ответили, но не запомнили».
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Answer {
    Pass,
    Stop,
    Remembered { accept: bool, state: u32 },
}

/// Что уйдёт ядру по слову ответа: пропустить ли пакет и какое состояние оставить на разговоре.
/// Чистое решение, ОТДЕЛЁННОЕ от отправки — иначе перевод слова в байты вердикта свидетельствовало
/// бы только живое ядро (§9: выше значения, ниже мир). `apply` лишь исполняет это решение сокетом.
pub(crate) fn asked(answer: &Answer) -> (bool, Option<u32>) {
    match *answer {
        Answer::Pass => (true, None),
        Answer::Stop => (false, None),
        Answer::Remembered { accept, state } => (accept, Some(state)),
    }
}

impl Terminal for QueueSocket {
    type Carrier = Held;
    type Answer = Answer;
    type Refusal = QueueError;

    fn apply(
        &mut self,
        answered: Answered<Held, Answer>,
    ) -> Result<Delivered<Answer>, Refused<Answer, QueueError>> {
        let id = answered.carrier.packet.id;
        let (accept, state) = asked(&answered.answer);
        match self.verdict(id, accept, state) {
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Состояние доезжает до вердикта, а не теряется по дороге: `Remembered` обязано дать ядру и
    /// вердикт, и марку. Мутация `Some(state) → None` в `asked` краснит именно здесь — то, чего
    /// `remember` (строит слово) поймать не мог.
    #[test]
    fn remembering_reaches_the_verdict() {
        assert_eq!(
            asked(&Answer::Remembered {
                accept: true,
                state: 0x1234
            }),
            (true, Some(0x1234))
        );
        assert_eq!(asked(&Answer::Pass), (true, None));
        assert_eq!(asked(&Answer::Stop), (false, None));
    }
}

impl CanRemember for QueueSocket {
    fn remember(state: u32, accept: bool) -> Answer {
        Answer::Remembered { accept, state }
    }
}

/// Удержание: слово отпускания у очереди — «пропустить как есть». Сама способность держать пакет
/// есть у неё по построению — вердикт всегда отложен: ядро ждёт ответа, пока мы решаем.
impl reflex_core::capability::CanHold for QueueSocket {
    fn release() -> Answer {
        Answer::Pass
    }
}

/// Отказ: удержанный не пойдёт дальше. Слово ОДНОМУ пакету, не правило на поток — снимать нечего,
/// потому пары «снять обратно» у него нет.
impl reflex_core::capability::CanRefuse for QueueSocket {
    fn refuse() -> Answer {
        Answer::Stop
    }
}

/// Обрыв: не пропустить И сказать об этом. Таблица извещения живёт в ядре ([`reflex_core::notice`])
/// — предмет её протокол, а не носитель; здесь способность лишь называет её своим словом (§9.1).
/// Копия таблицы у второго носителя разошлась бы с первой молча: `RST` вне окна получатель
/// отбрасывает без звука, и «сказали» с «услышали» перестали бы различаться.
impl reflex_core::CanSever for QueueSocket {
    fn notice(
        seen: &[u8],
        toward: reflex_core::capability::Toward,
    ) -> Option<reflex_core::command::InjectablePacket> {
        reflex_core::notice::rst_for(seen, toward)
    }
}
