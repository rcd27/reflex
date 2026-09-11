//! Терминал над сокетом очереди: `Answer` разбирается в один вызов `verdict`. `&mut` заперт в
//! `apply` — за ним ядро, выше него значения (канон §9). Способность помнить строится тем же словом,
//! что и вердикт: «отпустить и запомнить» неделимо, иначе состояние осталось бы прошлым при
//! отпущенном пакете.

use std::time::Instant;

use reflex_core::capability::CanRemember;
use reflex_core::held::{Answered, Delivered, Edging, Observed, Refused, Terminal};
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

/// Что наблюдено — байты кадра, как их отдало ядро. Заимствование, не выдача: байты принадлежат
/// сообщению, пока оно живо, и разбирающий смотрит на них, а не получает копию (§9: `Held` показывает
/// улику, а не владеет ею вторично).
///
/// Спрашивают у СООБЩЕНИЯ, а не у сокета, по той же причине, что и край: внутри `serve` бэкенд
/// заимствован на всё время решения, и второго `&mut` не будет.
impl Observed for Held {
    fn payload(&self) -> &[u8] {
        &self.packet.payload
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
///
/// `Copy` СНЯТ 11.09.2026 вместе с приходом `Rewritten`: новые байты пакета — владение, и
/// притворяться, что слово ответа по-прежнему копируется даром, значило бы лгать о цене. Слово
/// уходит по значению один раз за пакет, `Clone` остался — на путях, где его и правда копируют.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer {
    Pass,
    Stop,
    Remembered { accept: bool, state: u32 },
    /// Отпустить НЕ ТО, что взяли: ядро выпустит эти байты вместо исходного пакета
    /// (`NFQA_PAYLOAD` в том же сообщении вердикта). Предмет [`CanRewrite`].
    ///
    /// Способность была у прежнего бэкенда (`nfqueue::Answer::Modified`) и при переезде на свой
    /// сокет не переехала — боевой носитель молча стал уметь меньше, чем прежний, а канон §9.1
    /// продолжал числить `CanRewrite` за движком. Вернулась по правилу хозяина: что канон объявил,
    /// код обязан держать.
    ///
    /// ПРЕДЕЛ, названный вслух: «переписать И запомнить» одним словом сегодня НЕ выразимо —
    /// `CanRewrite::rewrite(bytes)` состояния не принимает, такова подпись закона. Пока переписать
    /// значит не запомнить, и это довод к хранителю, а не забывчивость: слить их — та же работа,
    /// что слила вердикт с памятью в `Remembered`.
    Rewritten(Vec<u8>),
}

/// Что уйдёт ядру по слову ответа: пропустить ли пакет и какое состояние оставить на разговоре.
/// Чистое решение, ОТДЕЛЁННОЕ от отправки — иначе перевод слова в байты вердикта свидетельствовало
/// бы только живое ядро (§9: выше значения, ниже мир). `apply` лишь исполняет это решение сокетом.
pub(crate) fn asked(answer: &Answer) -> (bool, Option<u32>, Option<&[u8]>) {
    match answer {
        Answer::Pass => (true, None, None),
        Answer::Stop => (false, None, None),
        Answer::Remembered { accept, state } => (*accept, Some(*state), None),
        // Подменённый пакет ОТПУСКАЕТСЯ: дропнуть его и одновременно подменить бессмысленно —
        // выпускать было бы нечего. Потому `accept` здесь не выбор вызывающего, а следствие слова.
        Answer::Rewritten(bytes) => (true, None, Some(bytes)),
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
        let (accept, state, payload) = asked(&answered.answer);
        match self.verdict(id, accept, state, payload) {
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

/// Что даёт входящее СООБЩЕНИЕ шву — уже РАЗОБРАННОЕ из буфера (`wire::incoming_of`). Переполнение
/// сюда не долетает: оно ловится раньше, на уровне сисколла (`after_recv`, ниже). Чистая функция,
/// отделённая от сокета: перевод сообщения в исход свидетельствовало бы иначе только живое ядро, а
/// его в тесте нет.
pub(crate) enum Taken {
    Packet(Packet),
    Nothing,
}

/// `Failed(code)` — НЕ дыра: это `NLMSG_ERROR` с ненулевым `code`, отказ ядра на НАШУ ЖЕ команду
/// (bind/params/conntrack-flag — см. `wire::incoming_of`), а не свидетельство потери пакетов. Прежний
/// фасад его пропускал (`let Incoming::Packet(packet) = incoming else { continue }`), тем же словом
/// отвечаем и здесь: пропуск, не дыра. Дыра о потере — отдельный предмет, живёт в `after_recv`, где
/// ей и место (`QueueError::Overrun`). `Done` — конец пачки, тоже пропуск, не потеря.
pub(crate) fn taken(incoming: Incoming) -> Taken {
    match incoming {
        Incoming::Packet(packet) => Taken::Packet(packet),
        Incoming::Failed(_errno) => Taken::Nothing,
        Incoming::Done => Taken::Nothing,
    }
}

/// Что говорит `recv()` о состоянии очереди — чисто, ДО времени (момент штампует `serve`, не
/// здесь). `Overrun` (`ENOBUFS`) — ДЫРА: ядро сказало, что пакеты потеряны между чтениями, и шов
/// обязан узнать об этом буквой `Torn`, не молчанием — докблок `queue/mod.rs` называет это прямо:
/// «крейт `nfq`... глушит `ENOBUFS` — а нам переполнение нужно буквой, не молчанием». Прочий отказ
/// `recv()` (например `EAGAIN` — дескриптор был готов, но взять было нечего) — обычная тишина: не
/// путать разные причины неудачи одним `Idle`.
pub(crate) enum AfterRecv {
    Torn,
    Idle,
    Filled(Vec<Incoming>),
}

pub(crate) fn after_recv(result: Result<Vec<Incoming>, QueueError>) -> AfterRecv {
    match result {
        Ok(batch) => AfterRecv::Filled(batch),
        Err(QueueError::Overrun) => AfterRecv::Torn,
        Err(_other) => AfterRecv::Idle,
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
/// одном месте — единственном `std::thread::sleep` внизу, за пределами цикла. Раньше срока
/// возвращается ОДИН путь: `Answered`. У него `return` прямо в теле цикла, он сон минует, и закон
/// его не касается — пакет решён, работа есть.
///
/// ВСЁ ОСТАЛЬНОЕ ДОСЫПАЕТ СРОК, `Served::Torn` В ТОМ ЧИСЛЕ. Это следствие единого выхода, а не
/// недосмотр: `Torn` уходит через `break`, как `Waited::Idle`, `AfterRecv::Idle` и `Waited::Blind`,
/// а спит и возвращает ровно один код ниже. Прежняя редакция этого докблока обещала обратное
/// («путь `Torn` возвращается раньше»), и обещание было ложным при верном коде — читать его не
/// стоит даже как описание намерения.
///
/// ЦЕНА НАЗВАНА, А НЕ СПРЯТАНА: буква дыры доезжает до приборов позже своего момента — на остаток
/// срока, то есть не более чем на шаг сетки. МОМЕНТ при этом не искажён: `Served::Torn` несёт
/// `Instant::now()` времени ОБНАРУЖЕНИЯ (раньше него о потере не знал никто), и узлы, которые дыра
/// перешагнула, шов выдаст перед нею. Опаздывает доставка, не показание.
///
/// Почему цена принята, а не убран `break`: ранний `return` для `Torn` вернул бы ВТОРОЙ выход из
/// закона срока — ровно тот род дефекта, который эта ветка закрывала ТРИЖДЫ (T3, T6, T12: `match`,
/// у которого несколько веток обязаны сделать одно перед возвратом, приглашает повторить это в
/// каждой, и компилятор не ловит). Менять поведение ради текста, вернув конструкцию, которая уже
/// трижды разошлась молча, дороже, чем доставить дыру на шаг позже.
impl Serves for QueueSocket {
    /// Свой край — ровно тот, что уже строил `Edging` (`impl Edging for Held` выше): перенос края
    /// на `Serves` (задача 10½) не тронул ГДЕ он вычисляется — только КТО его теперь отдаёт наружу.
    /// `held.carrier().edge()` вызывается здесь же, где раньше вызывался фасадом.
    type Edge = CtEdge;

    fn serve<F>(
        &mut self,
        until: Instant,
        decide: F,
    ) -> Served<Delivered<Answer>, Refused<Answer, QueueError>>
    where
        F: FnOnce(&reflex_core::held::Held<Held>, Option<CtEdge>) -> Answer,
    {
        let outcome = loop {
            if let Some((incoming, at)) = self.pending.pop_front() {
                match taken(incoming) {
                    Taken::Packet(packet) => {
                        let held = reflex_core::held::Held::new(Held::new(packet, self.base), at);
                        let edge = held.carrier().edge();
                        let answer = decide(&held, edge);
                        return Served::Answered(self.apply(held.answered(answer)));
                    }
                    // Конец пачки либо протокольный отказ на нашу команду — не потеря: снова к
                    // буферу (пуст — к `wait` ниже).
                    Taken::Nothing => continue,
                }
            }

            match self.wait(millis_until(until)) {
                // Дескриптор свой всегда (см. `socket.rs`) — на живой очереди сюда не попасть, но
                // ветка обязана обойтись с `Waited` тем же законом, что и `NfqueueBackend`, а не
                // сделать вид, что варианта нет.
                Waited::Blind => break Served::Blind,
                Waited::Idle => break Served::Idle,
                Waited::Ready => match after_recv(self.recv()) {
                    // Переполнение — ДЫРА, не тишина: см. докблок `after_recv`.
                    // Момент — там, где `Overrun` УВИДЕН: раньше него о потере не знал никто.
                    AfterRecv::Torn => break Served::Torn(Instant::now()),
                    // Прочий отказ при готовом дескрипторе — работы не было, ждать есть на чём.
                    AfterRecv::Idle => break Served::Idle,
                    AfterRecv::Filled(batch) => {
                        let at = Instant::now();
                        self.pending.extend(batch.into_iter().map(|one| (one, at)));
                        // Пачка вернулась пустой (только `Done`/`Failed`, без пакета), а срок уже
                        // прошёл: не крутить ещё один `wait` ради нуля — исход и так `Idle`.
                        if Instant::now() >= until && self.pending.is_empty() {
                            break Served::Idle;
                        }
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
            (true, Some(0x1234), None)
        );
        assert_eq!(asked(&Answer::Pass), (true, None, None));
        assert_eq!(asked(&Answer::Stop), (false, None, None));
    }

    /// ПОДМЕНА ДОЕЗЖАЕТ ДО ВЕРДИКТА, и доезжает ОТПУЩЕННОЙ. Дропнуть подменённый пакет
    /// бессмысленно — выпускать было бы нечего, — потому `accept` здесь не выбор вызывающего, а
    /// следствие слова, и это проверяется, а не подразумевается.
    #[test]
    fn rewriting_reaches_the_verdict() {
        let fresh = vec![0x45u8, 0x00, 0xAB, 0xCD];
        let answer = Answer::Rewritten(fresh.clone());
        let (accept, state, payload) = asked(&answer);

        assert!(accept, "подменённый пакет отпускается: дропать нечего");
        assert_eq!(payload, Some(&fresh[..]), "новые байты доезжают до вердикта");
        assert_eq!(
            state, None,
            "«переписать И запомнить» одним словом сегодня не выразимо — подпись `CanRewrite::rewrite` \
             состояния не принимает; предел назван в докблоке `Answer::Rewritten`, а не обойдён молча"
        );
    }

    fn a_packet() -> Packet {
        Packet {
            id: 1,
            payload: Vec::new(),
            nfmark: 0,
            ct: None,
        }
    }

    /// Разбор входящего в исход шва — ЧИСТО, до всякого сокета. `Failed` — протокольный отказ на
    /// НАШУ команду (`NLMSG_ERROR`), не дыра о потере пакетов: та ловится раньше, в `after_recv`.
    /// Прежний фасад пропускал такие сообщения — тем же словом отвечаем и здесь.
    #[test]
    fn протокольный_отказ_и_конец_пачки_читаются_пустотой() {
        assert!(matches!(taken(Incoming::Failed(105)), Taken::Nothing));
        assert!(matches!(taken(Incoming::Done), Taken::Nothing));
        assert!(matches!(
            taken(Incoming::Packet(a_packet())),
            Taken::Packet(_)
        ));
    }

    /// Переполнение — ДЫРА (буква `Torn`, не тишина): ядро сказало, что пакеты потеряны между
    /// чтениями, и прибор вправе это знать (докблок `queue/mod.rs`: крейт `nfq` глушил ровно этот
    /// случай, и уход от него был предметом переезда). Прочий отказ `recv()` — обычная тишина, не
    /// дыра: смешивать причины было бы недоверенным сравнением через необъявленный разрыв.
    #[test]
    fn переполнение_recv_читается_дырой_а_прочий_отказ_пустотой() {
        assert!(matches!(
            after_recv(Err(QueueError::Overrun)),
            AfterRecv::Torn
        ));
        assert!(matches!(
            after_recv(Err(QueueError::Recv(libc::EAGAIN))),
            AfterRecv::Idle
        ));
        match after_recv(Ok(vec![Incoming::Packet(a_packet())])) {
            AfterRecv::Filled(batch) => assert_eq!(batch.len(), 1),
            _ => panic!("ожидалась пачка"),
        }
    }
}

impl CanRemember for QueueSocket {
    fn remember(state: u32, accept: bool) -> Answer {
        Answer::Remembered { accept, state }
    }
}

/// ПЕРЕПИСАТЬ ПАКЕТ: ядро отпустит новые байты вместо взятых, одним сообщением с вердиктом.
///
/// Способность объявлена каноном §9.1 и была у прежнего бэкенда (`nfqueue::Answer::Modified`); при
/// переезде на свой сокет (10.09.2026) она не переехала, и боевой носитель молча стал уметь меньше.
/// Замер 11.09.2026 нашёл это не прогоном, а счётом «объявлено каноном / реализовано в дереве»:
/// `CanRewrite` числилась за движком и жила только на пути, переставшем быть боевым.
///
/// Сторож: `verdict_carries_new_payload`, `rewriting_reaches_the_verdict` (`linux/tests/queue_wire.rs`,
/// `linux/src/queue/terminal.rs`).
impl reflex_core::CanRewrite for QueueSocket {
    fn rewrite(bytes: Vec<u8>) -> Answer {
        Answer::Rewritten(bytes)
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
