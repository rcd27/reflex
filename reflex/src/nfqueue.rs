//! НОСИТЕЛЬ ОЧЕРЕДИ ЯДРА — и единственное место фасада, знающее про Linux.
//!
//! Отдельный модуль, а не часть `lib.rs`, потому что это ПРОВЕРЯЕМАЯ граница: `grep reflex_linux
//! src/lib.rs` обязан давать ноль. Пока носитель жил в общем файле, ведущий цикл дотягивался до
//! `QueueSocket`, `Waited`, `CtEdge` и `RawSender` мимо всякого закона — и WinDivert в ту же дверь
//! не встал бы, сколько бы обобщений ни объявили выше.
//!
//! Наружу отсюда торчит ровно рецепт [`Nfqueue`]: что открыть и под какой раскладкой писать
//! состояние. Всё прочее — способности, которыми носитель отвечает удержанному пакету и вводит
//! свои пакеты в сеть.

use reflex_core::backend::Sink;
use reflex_core::capability::{CanHold, CanInject, CanRefuse, CanRemember, CanSever, Toward};
use reflex_core::command::InjectablePacket;
use reflex_core::held::{Answered, Delivered, Refused, Terminal};
use reflex_core::serves::Served;
use reflex_core::Serves;
use reflex_instrument::edge::Layout;
use reflex_linux::conntrack::TimeoutBase;
use reflex_linux::queue::{Answer, QueueSocket};
use reflex_linux::rawsend::RawSender;

use crate::{Cause, IntoCarrier};

/// Носитель — очередь netfilter. `engine(Nfqueue::queue(200))` открывает движок над ней.
pub struct Nfqueue {
    queue: u16,
    layout: Layout,
}

/// НАШИ биты марки по умолчанию: 15 бит (тег 4 + фаза 3 + оттиск 8), сдвинутые в старшую половину.
/// Умолчание, а не константа закона: на машине мы не одни, и сосед вправе занимать своё. Кто знает
/// про соседа — говорит [`Nfqueue::marking`].
const MARK_MASK: u32 = 0x0FFF_E000;
/// Подпись писателя по умолчанию. Ненулевая: нулём подписан «никто», и по нему тег не отличить от
/// нетронутой марки.
const MARK_TAG: u8 = 0b101;

/// Метка на инъекциях движка: ядро ставит её (SO_MARK) на впрыснутый RST, чтобы он не вернулся в
/// свою же очередь. Правило очереди обязано пропускать помеченное (`meta mark != INJECT_MARK`).
pub const INJECT_MARK: u32 = 0xBB;

impl Nfqueue {
    /// Очередь netfilter с этим номером. Правило (`queue num N`) ставится снаружи — движок правил
    /// не ставит: кто поставил, тот и снимает.
    pub fn queue(num: u16) -> Nfqueue {
        Nfqueue {
            queue: num,
            layout: Layout::new(MARK_MASK, MARK_TAG).expect("умолчание: 15 бит, ненулевой тег"),
        }
    }

    /// Какие биты марки НАШИ и чем подписан их писатель. Нужно тому, кто делит машину с другим
    /// агентом: чужие биты вне маски переживают наш шаг (read-modify-write), а тег отличает нашу
    /// запись от чужой — по нему движок и узнаёт соседа (`Distress::Diverged`) вместо того, чтобы
    /// принять его слово за своё.
    ///
    /// `None` — маска не 15-битная либо тег нулевой: раскладка непредставима, и цепочка её не
    /// получит (предпосылку проверяет [`Layout::new`], а не отладочная проверка, исчезающая в
    /// release).
    pub fn marking(self, mask: u32, tag: u8) -> Option<Nfqueue> {
        Layout::new(mask, tag).map(|layout| Nfqueue { layout, ..self })
    }
}

/// Открытый носитель очереди: сокет очереди И сокет инъекции — оба поднимает [`Nfqueue::open`]
/// (через [`IntoCarrier`]), а не ведущий цикл. Сырой сокет живёт здесь ВСЕГДА, даже у цепочки,
/// которая инжектить не станет (`.on`, не `.act`): ленивое открытие на первом эффекте меняло бы
/// быстрый отказ на старте (`Report::not_started`) на отказ посреди боя — лишний сокет дешевле
/// потерянного отказа.
pub struct NfqueueCarrier {
    socket: QueueSocket,
    sender: RawSender,
}

/// Носитель отвечает удержанному тем же терминалом, что и голый `QueueSocket` — делегированием, не
/// второй реализацией: второй закон об одном и том же ответе разошёлся бы с первым молча.
impl Terminal for NfqueueCarrier {
    type Carrier = <QueueSocket as Terminal>::Carrier;
    type Answer = <QueueSocket as Terminal>::Answer;
    type Refusal = <QueueSocket as Terminal>::Refusal;

    fn apply(
        &mut self,
        answered: Answered<Self::Carrier, Self::Answer>,
    ) -> Result<Delivered<Self::Answer>, Refused<Self::Answer, Self::Refusal>> {
        self.socket.apply(answered)
    }
}

/// `Serves`ит тем же швом, что и голый сокет. `exhausted` не переопределяется: ядро конца не
/// обещает, и умолчание трейта — это и есть ответ очереди.
impl Serves for NfqueueCarrier {
    fn serve<F>(
        &mut self,
        until: std::time::Instant,
        decide: F,
    ) -> Served<Delivered<Self::Answer>, Refused<Self::Answer, Self::Refusal>>
    where
        F: FnOnce(&reflex_core::held::Held<Self::Carrier>) -> Self::Answer,
    {
        self.socket.serve(until, decide)
    }
}

/// Способности носителя — те же слова, что у сокета очереди, и по той же причине: слово ОДНО на
/// предмет. Пересказать их здесь своими константами значило бы завести вторую таблицу ответов,
/// расходящуюся с первой при зелёной сборке.
impl CanHold for NfqueueCarrier {
    fn release() -> Answer {
        <QueueSocket as CanHold>::release()
    }
}

impl CanRemember for NfqueueCarrier {
    fn remember(state: u32, accept: bool) -> Answer {
        <QueueSocket as CanRemember>::remember(state, accept)
    }
}

/// Отказ — предпосылка обрыва (`CanSever: CanRefuse`): сказать «разговора не будет» вправе тот, кто
/// умеет не пропустить.
impl CanRefuse for NfqueueCarrier {
    fn refuse() -> Answer {
        <QueueSocket as CanRefuse>::refuse()
    }
}

impl CanSever for NfqueueCarrier {
    fn notice(seen: &[u8], toward: Toward) -> Option<InjectablePacket> {
        <QueueSocket as CanSever>::notice(seen, toward)
    }
}

/// Ввод пакета в сеть — СЫРЫМ сокетом носителя, не очередью: очередь отвечает удержанному, а
/// инъекция создаёт новый кадр. Оттого сток и терминал у носителя разные двери, а носитель один.
impl Sink for NfqueueCarrier {
    type Command = InjectablePacket;
    type Error = std::io::Error;

    fn emit(&mut self, command: InjectablePacket) -> Result<(), std::io::Error> {
        self.sender.send(&command.serialize_ip())
    }
}

impl CanInject for NfqueueCarrier {
    fn inject(packet: InjectablePacket) -> InjectablePacket {
        packet
    }
}

impl IntoCarrier for Nfqueue {
    type Carrier = NfqueueCarrier;

    /// База таймаутов conntrack — предпосылка КРАЯ, и её читает РОВНО одно место: здесь.
    /// Обобщённый цикл знать о ней не может — предпосылка носителя есть дело носителя, а в цикле
    /// она была бы абсурдна (WinDivert про conntrack не слышал). Сырой сокет инъекции поднимается
    /// следом, тоже здесь и тоже безусловно (см. докблок [`NfqueueCarrier`]).
    fn open(self) -> Result<NfqueueCarrier, Cause> {
        let base = TimeoutBase::read().ok_or_else(|| {
            Cause(
                "нет базы таймаутов conntrack: включи nf_conntrack_acct и nf_conntrack_timestamp"
                    .to_string(),
            )
        })?;
        let socket = QueueSocket::open(self.queue, base).map_err(|why| Cause(format!("{why:?}")))?;
        let sender =
            RawSender::open(INJECT_MARK).map_err(|why| Cause(format!("сокет инъекции: {why}")))?;
        Ok(NfqueueCarrier { socket, sender })
    }

    fn layout(&self) -> Layout {
        self.layout
    }

    fn name(&self) -> String {
        format!("очередь {}", self.queue)
    }
}
