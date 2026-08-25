//! Сборка первой TLS-записи через границу TCP-сегмента.
//!
//! ЗАЧЕМ. [`super::record_need`] отвечает на вопрос «доколе читать», но не читает. Потребителю,
//! стоящему на проводе (NFQ, TUN, прокси), этого мало: чтобы увидеть запись целиком, он обязан
//! СНЯТЬ с провода первый сегмент и подержать его, пока не придёт остаток. Снять байт — значит
//! взять на себя его доставку, и с этого мгновения появляются два обязательства, которых у
//! чистого парсера нет: вернуть всё снятое и вернуть НЕ ПОЗЖЕ названного срока.
//!
//! Оба выражены в `model/desync/RecordAssembly.tla` (`Delivered`, `BoundedHold`) и проверены TLC.
//! Второе без первого бессмысленно, но и первое без второго не спасает: удержанные и когда-нибудь
//! отданные байты человек видит как вечную загрузку. Оттого срок здесь — обязательный аргумент
//! конструктора, а не настройка со значением по умолчанию.
//!
//! ПОЧЕМУ ПРИМИТИВ ОБЩИЙ, А НЕ В ПОТРЕБИТЕЛЕ. Ни одной специфики обхода DPI тут нет: это чтение
//! записи протокола из потока, разрезанного транспортом. Тем же швом живут DNS-over-TCP и
//! заголовок HTTP. По мета-триггеру REFLEX-FIRST general-purpose примитив строится здесь и
//! тестируется в изоляции, а домен его потребляет.

use std::time::{Duration, Instant};

use smallvec::SmallVec;

use crate::detector::{Detector, DetectorEvent};

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
    /// Пакет УДЕРЖАН: он снят с провода, его байты у сборщика. Потребитель обязан дропнуть
    /// оригинал — иначе байты уедут дважды (`model/molecule/AssembledRecord.tla`, ось 2).
    Held,
    /// Запись собрана целиком. `seq` — номер первого байта ЗАПИСИ, то есть seq ГОЛОВЫ, а не того
    /// пакета, на котором она сомкнулась (там же, ось 1: перепутать эти два значит уложить всю
    /// запись правее и лишить сервер её начала).
    Assembled { seq: u32, record: Vec<u8> },
    /// Срок вышел либо поток пошёл не так. Удержанное отдаётся НЕТРОНУТЫМ, техника не зовётся:
    /// поведение равно поведению без сборщика.
    Abandoned { seq: u32, record: Vec<u8> },
}

/// Состояние сборщика по ОДНОМУ потоку.
///
/// Отдельный тип вместо `Option<...>`-как-режима: у «ещё не смотрели», «держим» и «решено» разные
/// данные и разные допустимые переходы, и `Option` их сплющивает (REFLEX-FIRST, триггер 4).
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
    /// Решение по первой записи принято — дальше поток нас не касается.
    Settled,
}

/// Сигналы одним выражением: `SmallVec` собирается из итератора, потому что накопление через
/// мутабельную локальную рвёт `F(N)=Y` (FP-выстёг) — а здесь ровно чистая функция события.
fn one(signal: Assembly) -> SmallVec<[Assembly; 2]> {
    std::iter::once(signal).collect()
}

fn two(first: Assembly, second: Assembly) -> SmallVec<[Assembly; 2]> {
    [first, second].into_iter().collect()
}

/// Сборщик первой TLS-записи одного потока. Чистая машина состояний: `(state, event) → (state,
/// signals)`, часов не дёргает — время приходит в событии (контракт [`Detector`]).
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
            RecordNeed::Complete => self.settled(Assembly::Assembled {
                seq: chunk.seq,
                record: chunk.payload,
            }),
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
        let joined = [bytes, chunk.payload].concat();
        match record_need(&joined) {
            RecordNeed::Complete => self.settled(Assembly::Assembled {
                seq,
                record: joined,
            }),
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

impl Detector for RecordAssembler {
    type Input = RecordChunk;
    type Signal = Assembly;

    fn step(self, event: DetectorEvent<Self::Input>) -> (Self, SmallVec<[Self::Signal; 2]>) {
        match event {
            DetectorEvent::Packet { input, at } => match (&self.hold, input.payload.is_empty()) {
                // Голый ACK/FIN без данных записи не двигает — и не должен закрывать удержание.
                (_, true) => (self.with(self.hold.clone()), SmallVec::new()),
                (Hold::Settled, false) => (self.with(Hold::Settled), one(Assembly::PassThrough)),
                (Hold::Idle, false) => self.on_first(input, at),
                (Hold::Holding { seq, bytes, since }, false) => {
                    self.on_more(*seq, bytes.clone(), *since, input, at)
                }
            },
            // ТИК — единственный способ разомкнуть удержание, когда остаток не придёт НИКОГДА.
            // Без него `Delivered` держится лишь на надежде, что поток ещё чем-нибудь дышит.
            DetectorEvent::Tick { at } => match &self.hold {
                Hold::Holding { seq, bytes, since }
                    if at.duration_since(*since) >= self.hold_deadline =>
                {
                    self.settled(Assembly::Abandoned {
                        seq: *seq,
                        record: bytes.clone(),
                    })
                }
                Hold::Holding { .. } | Hold::Idle | Hold::Settled => {
                    (self.with(self.hold.clone()), SmallVec::new())
                }
            },
        }
    }
}
