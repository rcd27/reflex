//! Терминал над сокетом очереди: `Answer` разбирается в один вызов `verdict`. `&mut` заперт в
//! `apply` — за ним ядро, выше него значения (канон §9). Способность помнить строится тем же словом,
//! что и вердикт: «отпустить и запомнить» неделимо, иначе состояние осталось бы прошлым при
//! отпущенном пакете.

use std::time::Instant;

use reflex_core::capability::CanRemember;
use reflex_core::held::{Answered, Delivered, Edging, Refused, Terminal};
use reflex_core::serves::Served;
use reflex_core::Serves;

use crate::conntrack::{CtEdge, TimeoutBase};
use crate::nfqueue::{millis_until, Waited};

use super::socket::{QueueError, QueueSocket};
use super::wire::{Incoming, Packet};

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

/// Что даёт входящее сообщение шву. Чистая функция, отделённая от сокета: перевод сообщения в исход
/// свидетельствовало бы иначе только живое ядро, а его в тесте нет.
pub(crate) enum Taken {
    Packet(Packet),
    Torn,
    Nothing,
}

/// `Failed` — ДЫРА (буква `Torn`, не тишина): ядро сказало, что пакеты потеряны, и `Overrun` здесь
/// честный источник — в отличие от старого пути (крейт `nfq` глушил `ENOBUFS`), `QueueSocket`
/// различает переполнение буквой (`socket.rs`), и здесь та буква доходит до шва. `Done` — конец
/// пачки, не потеря: `Nothing`, не `Torn`.
pub(crate) fn taken(incoming: Incoming) -> Taken {
    match incoming {
        Incoming::Packet(packet) => Taken::Packet(packet),
        Incoming::Failed(_errno) => Taken::Torn,
        Incoming::Done => Taken::Nothing,
    }
}

/// Очередь вошла в категорию как [`Serves`](reflex_core::Serves), не как `Source` — по той же
/// причине, что и `NfqueueBackend` (`nfqueue/terminal.rs`): вердикт требует ВЛАДЕНИЯ тем самым
/// сообщением, второй `&mut` внутри потока наблюдения не собрать (`E0499`).
///
/// `recv` отдаёт ПАЧКУ, `serve` — по одному: буфер `pending` живёт в `QueueSocket` (`socket.rs`),
/// момент штампуется ТАМ же, на приёме пачки — не здесь, при снятии с буфера. Сними его при снятии,
/// и второй, третий пакет буферизованной пачки получили бы момент позже своего фактического
/// прихода: монотонность букв (`core::interleave`) сломалась бы молча, а на ней стоит весь шов.
///
/// ЗАКОН СРОКА (§8, «не возвращаться раньше `until`, кроме как с работой») исполняется РОВНО в
/// одном месте — единственном `std::thread::sleep` внизу, за пределами цикла. Путь `Answered`/
/// `Torn` возвращается раньше него: у обоих есть работа (пакет решён либо ядро объявило дыру), и
/// закон её не касается. Все безответные исходы (`Waited::Idle`, `EAGAIN` при готовом дескрипторе,
/// `Waited::Blind`) не возвращаются сами — они лишь дают `loop` значение через `break`, а спит и
/// возвращает ровно один код ниже. Три копии сна — три копии закона, и четвёртая безответная ветка,
/// дописанная завтра, забыла бы о нём молча; один код обойти нельзя, не пройдя мимо `break`.
impl Serves for QueueSocket {
    fn serve<F>(
        &mut self,
        until: Instant,
        decide: F,
    ) -> Served<Delivered<Answer>, Refused<Answer, QueueError>>
    where
        F: FnOnce(&reflex_core::held::Held<Held>) -> Answer,
    {
        let outcome = loop {
            if let Some((incoming, at)) = self.pending.pop_front() {
                match taken(incoming) {
                    Taken::Packet(packet) => {
                        let held = reflex_core::held::Held::new(Held::new(packet, self.base), at);
                        let answer = decide(&held);
                        return Served::Answered(self.apply(held.answered(answer)));
                    }
                    Taken::Torn => return Served::Torn,
                    // Конец пачки — не потеря: снова к буферу (пуст — к `wait` ниже).
                    Taken::Nothing => continue,
                }
            }

            match self.wait(millis_until(until)) {
                // Дескриптор свой всегда (см. `socket.rs`) — на живой очереди сюда не попасть, но
                // ветка обязана обойтись с `Waited` тем же законом, что и `NfqueueBackend`, а не
                // сделать вид, что варианта нет.
                Waited::Blind => break Served::Blind,
                Waited::Idle => break Served::Idle,
                Waited::Ready => match self.recv() {
                    // Пусто при готовом дескрипторе — `EAGAIN`: работы не было, ждать есть на чём.
                    Err(_eagain) => break Served::Idle,
                    Ok(batch) => {
                        let at = Instant::now();
                        self.pending.extend(batch.into_iter().map(|one| (one, at)));
                    }
                },
            }
        };

        // Единственный сон на все безответные исходы — см. докблок `impl` выше.
        std::thread::sleep(until.saturating_duration_since(Instant::now()));
        outcome
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

    fn a_packet() -> Packet {
        Packet {
            id: 1,
            payload: Vec::new(),
            nfmark: 0,
            ct: None,
        }
    }

    /// Разбор входящего в исход шва — ЧИСТО, до всякого сокета. `Failed` есть ДЫРА, а не пустота:
    /// ядро сказало, что пакеты потеряны, и прибор вправе это знать. Прежде фасад её печатал.
    #[test]
    fn переполнение_читается_дырой_а_конец_пачки_пустотой() {
        assert!(matches!(taken(Incoming::Failed(105)), Taken::Torn));
        assert!(matches!(taken(Incoming::Done), Taken::Nothing));
        assert!(matches!(taken(Incoming::Packet(a_packet())), Taken::Packet(_)));
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
