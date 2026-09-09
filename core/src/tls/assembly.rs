//! Сборка первой TLS-записи через границу TCP-сегмента. [`super::record_need`] отвечает «доколе
//! читать», но не читает; потребителю на проводе (NFQ, TUN, прокси) этого мало — чтобы увидеть
//! запись целиком, он снимает первый сегмент и держит, пока не придёт остаток. Снять байт — взять на
//! себя его доставку: отсюда два обязательства, которых у чистого парсера нет — вернуть всё снятое и
//! НЕ ПОЗЖЕ названного срока (удержанные и когда-нибудь отданные байты человек видит как вечную
//! загрузку). Оттого срок — обязательный аргумент конструктора. Примитив общий: это чтение записи
//! протокола из потока, разрезанного транспортом (тем же швом живут DNS-over-TCP и заголовок HTTP).

use std::time::{Duration, Instant};

use smallvec::SmallVec;

use crate::detector::DetectorEvent;
use crate::mealy::Mealy;

use super::{record_need, RecordNeed};

/// Кусок потока в том виде, в каком его видит сборщик. Ровно то, что ему нужно, и ничего сверх:
/// адрес байта в потоке и сами байты. Окна, опции и флаги TCP сборщика не касаются, и типа,
/// который их несёт, он не требует — иначе потребителю пришлось бы выдумывать значения,
/// которых он не наблюдал.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordChunk {
    /// Порядковый номер ПЕРВОГО байта этого куска в потоке.
    pub seq: u32,
    pub payload: Vec<u8>,
}

/// Что сборщик сообщает о пакете, который сейчас в руках, и о записи.
///
/// Алгебраический тип, а не пара «флаг + буфер»: у `Assembled` и `Abandoned` одинаковые ДАННЫЕ
/// (seq головы и байты) и противоположный СМЫСЛ — первую запись потребитель отдаёт технике,
/// вторую обязан вернуть на провод нетронутой. Флаг такое различение не выражает, и перепутать
/// их стоило бы человеку сломанного рукопожатия.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Assembly {
    /// Сборщику здесь делать нечего: это не начало TLS-рукопожатия либо запись уже решена.
    /// Пакет идёт как шёл.
    PassThrough,
    /// Пакет УДЕРЖАН: снят с провода, его байты у сборщика. Потребитель обязан дропнуть оригинал —
    /// иначе байты уедут дважды.
    Held,
    /// Запись собрана целиком. `seq` — номер первого байта ЗАПИСИ, то есть seq ГОЛОВЫ, не пакета, на
    /// котором она сомкнулась (перепутать — уложить всю запись правее и лишить сервер её начала).
    ///
    /// `held` — сколько байт записи УЖЕ снято с провода к этому мигу. Величина, а не флаг, и
    /// она меняет обязанность потребителя: `held = 0` значит «запись пришла одним пакетом,
    /// никто никому не должен»; `held > 0` значит «начало записи уже снято нами, и если техника
    /// за него не возьмётся, вернуть байты обязаны МЫ». Без этого числа два случая неразличимы,
    /// и отказ техники по собранной записи тихо съедал бы её.
    Assembled {
        seq: u32,
        record: Vec<u8>,
        held: usize,
    },
    /// Срок вышел либо поток пошёл не так. Удержанное отдаётся НЕТРОНУТЫМ, техника не зовётся:
    /// поведение равно поведению без сборщика.
    Abandoned { seq: u32, record: Vec<u8> },
    /// Клиент прислал ЗАНОВО байты записи, которую мы уже собрали и отдали. Значит сервер её не
    /// подтвердил, и клиент считает данные потерянными.
    ///
    /// Отдельный сигнал, не вывод потребителя: снаружи повтор неотличим от нового неполного hello
    /// (оба — префикс TLS-записи в пакете), отличает их одно знание — ПРОЛЁТ уже отданной записи, — и
    /// оно есть только здесь.
    ///
    /// `nth` — который это повтор по счёту. Величина, а не флаг: один повтор есть шум сети,
    /// восемь с удвоением интервала есть минута ожидания человека, и это разные новости.
    Retransmitted { seq: u32, nth: usize },
}

/// Сказано пакету, который сейчас в руках (§4). Почти всё велит, что делать (пропустить, удержать,
/// отдать, вернуть); `Retransmitted` называет, ЧТО ЭТОТ ПАКЕТ ЕСТЬ — те же байты заново. Отложить
/// нельзя ничего: провод держит байты до ответа.
impl crate::word::Word for Assembly {
    type Of = crate::word::Packet;
}

/// Состояние сборщика по ОДНОМУ потоку.
///
/// Отдельный тип вместо `Option<...>`-как-режима: у «ещё не смотрели», «держим» и «решено» разные
/// данные и переходы, `Option` их сплющивает.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Hold {
    /// Записи ещё не видели.
    Idle,
    /// Держим начало записи, ждём остаток.
    Holding {
        seq: u32,
        bytes: Vec<u8>,
        since: Instant,
    },
    /// Решение по первой записи принято, и сравнивать больше не с чем: запись мы не отдавали
    /// (не TLS, либо отказались от удержания).
    Settled,
    /// Запись собрана и отдана технике. Помним её ПРОЛЁТ — `[seq, seq+len)`, — потому что повтор
    /// именно этих байт означает, что сервер собранную запись не подтвердил. Без пролёта повтор
    /// неотличим от нового неполного hello.
    Delivered {
        seq: u32,
        len: usize,
        retransmits: usize,
    },
}

/// Сигналы одним выражением: `SmallVec` собирается из итератора — чистая функция события, без
/// накопления через мутабельную локальную.
fn one(signal: Assembly) -> SmallVec<[Assembly; 2]> {
    std::iter::once(signal).collect()
}

fn two(first: Assembly, second: Assembly) -> SmallVec<[Assembly; 2]> {
    [first, second].into_iter().collect()
}

/// Сборщик первой TLS-записи одного потока. Чистая машина состояний: `(state, event) → (state,
/// signals)`, часов не дёргает — время приходит в событии (контракт [`Mealy`](crate::mealy::Mealy)).
#[derive(Debug, Clone)]
pub struct RecordAssembler {
    hold_deadline: Duration,
    hold: Hold,
}

impl RecordAssembler {
    /// `hold_deadline` — сколько сборщику позволено держать байты. Аргумент обязателен: удержание
    /// без названного потолка есть вечная загрузка с чистой совестью.
    pub fn new(hold_deadline: Duration) -> Self {
        Self {
            hold_deadline,
            hold: Hold::Idle,
        }
    }

    /// Держит ли сборщик сейчас чужие байты. Нужен потребителю, чтобы знать, есть ли кого
    /// освобождать по сроку, не заглядывая внутрь состояния.
    pub fn is_holding(&self) -> bool {
        matches!(self.hold, Hold::Holding { .. })
    }

    fn with(&self, hold: Hold) -> Self {
        Self {
            hold_deadline: self.hold_deadline,
            hold,
        }
    }

    fn settled(&self, signal: Assembly) -> (Self, SmallVec<[Assembly; 2]>) {
        (self.with(Hold::Settled), one(signal))
    }

    /// Запись отдана: запоминаем её пролёт, чтобы отличить повтор ЭТИХ байт от нового содержимого.
    fn delivered(&self, seq: u32, record: Vec<u8>, held: usize) -> (Self, SmallVec<[Assembly; 2]>) {
        let len = record.len();
        (
            self.with(Hold::Delivered {
                seq,
                len,
                retransmits: 0,
            }),
            one(Assembly::Assembled { seq, record, held }),
        )
    }

    /// Пакет пришёл, когда запись уже отдана. Повтор её байт — новость: сервер не подтвердил.
    fn after_delivery(
        &self,
        seq: u32,
        len: usize,
        retransmits: usize,
        chunk: RecordChunk,
    ) -> (Self, SmallVec<[Assembly; 2]>) {
        // Сравнение по ПРОЛЁТУ, а не по равенству seq голове: клиент повторяет и хвостовой
        // сегмент тоже, и он законная часть той же потери.
        let внутри = chunk.seq.wrapping_sub(seq) < len as u32;
        match внутри {
            true => {
                let nth = retransmits + 1;
                (
                    self.with(Hold::Delivered {
                        seq,
                        len,
                        retransmits: nth,
                    }),
                    // Пакет ПРОПУСКАЕМ: наш эмит сервер не подтвердил, и повтор клиента —
                    // единственный путь потока к восстановлению. Дропнуть его значило бы
                    // добить соединение ради чистоты статистики.
                    two(Assembly::Retransmitted { seq, nth }, Assembly::PassThrough),
                )
            }
            // Поток ушёл дальше записи — наблюдать больше нечего.
            false => (self.with(Hold::Settled), one(Assembly::PassThrough)),
        }
    }

    fn holding(&self, seq: u32, bytes: Vec<u8>, since: Instant) -> (Self, SmallVec<[Assembly; 2]>) {
        (
            self.with(Hold::Holding { seq, bytes, since }),
            one(Assembly::Held),
        )
    }

    /// Первый взгляд на поток: решаем, стоит ли вообще держать.
    fn on_first(&self, chunk: RecordChunk, at: Instant) -> (Self, SmallVec<[Assembly; 2]>) {
        match record_need(&chunk.payload) {
            // Не рукопожатие — ждать продолжения нельзя, его не будет.
            RecordNeed::NotTls => self.settled(Assembly::PassThrough),
            // Запись уместилась в сегмент: держать нечего, отдаём сразу.
            RecordNeed::Complete => self.delivered(chunk.seq, chunk.payload, 0),
            RecordNeed::More { .. } => self.holding(chunk.seq, chunk.payload, at),
        }
    }

    /// Продолжение потока, пока держим начало записи.
    fn on_more(
        &self,
        seq: u32,
        bytes: Vec<u8>,
        since: Instant,
        chunk: RecordChunk,
        at: Instant,
    ) -> (Self, SmallVec<[Assembly; 2]>) {
        let expected = seq.wrapping_add(bytes.len() as u32);
        match (chunk.seq == expected, chunk.seq == seq) {
            (true, _) => self.on_contiguous(seq, bytes, since, chunk, at),
            // Повтор ГОЛОВЫ: клиент не дождался подтверждения снятого нами пакета и прислал его
            // снова. Держим прежнее и глотаем дубль — отдать его сейчас значило бы доставить те
            // же байты дважды.
            (false, true) => self.holding(seq, bytes, since),
            // Поток пошёл не туда (дыра, переупорядочение, чужой сегмент). Собирать вслепую
            // нельзя: склеим не то. Отдаём удержанное нетронутым, текущий пакет пропускаем.
            (false, false) => (
                self.with(Hold::Settled),
                two(
                    Assembly::Abandoned { seq, record: bytes },
                    Assembly::PassThrough,
                ),
            ),
        }
    }

    /// Кусок лёг ровно за удержанным — дочитываем запись.
    fn on_contiguous(
        &self,
        seq: u32,
        bytes: Vec<u8>,
        since: Instant,
        chunk: RecordChunk,
        at: Instant,
    ) -> (Self, SmallVec<[Assembly; 2]>) {
        let held = bytes.len();
        let joined = [bytes, chunk.payload].concat();
        match record_need(&joined) {
            RecordNeed::Complete => self.delivered(seq, joined, held),
            // Заголовок уже прочитан и сказал «handshake»; сюда попасть нельзя иначе как при
            // порче потока. Ветка существует ради тотальности и ведёт себя как отказ: чужого не
            // удерживаем.
            RecordNeed::NotTls => self.settled(Assembly::Abandoned {
                seq,
                record: joined,
            }),
            RecordNeed::More { .. } => match at.duration_since(since) >= self.hold_deadline {
                true => self.settled(Assembly::Abandoned {
                    seq,
                    record: joined,
                }),
                false => self.holding(seq, joined, since),
            },
        }
    }
}

impl Mealy for RecordAssembler {
    type In = DetectorEvent<RecordChunk>;
    type Out = SmallVec<[Assembly; 2]>;
    /// Показаний этот оператор не заводит: он говорит, что увидел, и не говорит, чем мерил.
    type Log = ();

    fn step(self, event: Self::In) -> (Self, Self::Out, ()) {
        let (assembler, signals) = match event {
            DetectorEvent::Packet { input, at } => match (&self.hold, input.payload.is_empty()) {
                // Голый ACK/FIN без данных записи не двигает — и не должен закрывать удержание.
                (_, true) => (self.with(self.hold.clone()), SmallVec::new()),
                (Hold::Settled, false) => (self.with(Hold::Settled), one(Assembly::PassThrough)),
                (
                    Hold::Delivered {
                        seq,
                        len,
                        retransmits,
                    },
                    false,
                ) => self.after_delivery(*seq, *len, *retransmits, input),
                (Hold::Idle, false) => self.on_first(input, at),
                (Hold::Holding { seq, bytes, since }, false) => {
                    self.on_more(*seq, bytes.clone(), *since, input, at)
                }
            },
            // ТИК — единственный способ разомкнуть удержание, когда остаток не придёт НИКОГДА.
            // Без него `Delivered` держится лишь на надежде, что поток ещё чем-нибудь дышит.
            DetectorEvent::Tick { at, .. } => match &self.hold {
                Hold::Holding { seq, bytes, since }
                    if at.duration_since(*since) >= self.hold_deadline =>
                {
                    self.settled(Assembly::Abandoned {
                        seq: *seq,
                        record: bytes.clone(),
                    })
                }
                Hold::Holding { .. } | Hold::Idle | Hold::Settled | Hold::Delivered { .. } => {
                    (self.with(self.hold.clone()), SmallVec::new())
                }
            },
            // СБОРЩИК ЖДЁТ БАЙТЫ ЗАПИСИ TLS, а непонятое их не несёт — оно родилось раньше, чем
            // разбор смог сказать даже то, что это TCP-сегмент нашего разговора. Удержание не
            // трогается: молчаливое продолжение того, что уже держим.
            DetectorEvent::Opaque { .. } => (self.with(self.hold.clone()), SmallVec::new()),
        };
        (assembler, signals, ())
    }
}
