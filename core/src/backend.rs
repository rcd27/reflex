//! ФУНКТОР FRONTEND → BACKEND (#295, срез 4).
//!
//! # Что было
//!
//! Четыре бэкенда — `AfPacketBackend`, `TcAfPacketBackend`, `NfqueueBackend`,
//! `NfqAfPacketBackend` — не были связаны НИ ОДНИМ общим трейтом с методами. Совпадали только
//! имена inherent-функций (`open` / `packets` / `inject`) и тип ошибки. Смена бэкенда была
//! правкой кода потребителя, а не подстановкой типа; портируемость цепочек, обещанная §3.2,
//! структурно не поддерживалась.
//!
//! А пять маркерных трейтов (`CanObserve`, `CanInject`, `CanHold`, `CanModify`, `CanDrop`) были
//! объявлены и реализованы — **14 вхождений, из них 11 `impl`, 3 комментария и НОЛЬ ограничений**.
//! То есть цепочка, требующая вердикта, спокойно собиралась над наблюдательным бэкендом. Открытый
//! вопрос §7.1 был не то что не решён — он не был поставлен в типах.
//!
//! # Что здесь
//!
//! Два трейта — [`Source`] (откуда пакеты) и [`Sink`] (куда команды), — и морфизмы категории,
//! требующие СПОСОБНОСТИ, а не веры:
//!
//! * начать цепочку из бэкенда можно, только если он умеет наблюдать (`CanObserve`);
//! * закончить инъекцией — только если умеет вводить (`CanInject`).
//!
//! Маркер перестал быть пометкой и стал ограничением. Разница проверяемая: пометку можно не
//! заметить, ограничение — нельзя.
//!
//! ```compile_fail
//! use futures::stream;
//! use reflex_core::backend::Sink;
//! use reflex_core::capability::CanObserve;
//! use reflex_core::category::Pipeline;
//!
//! // Бэкенд, который умеет ТОЛЬКО наблюдать: вводить в сеть он не заявлен.
//! struct Mirror;
//! impl CanObserve for Mirror {}
//! impl Sink for Mirror {
//!     type Command = u8;
//!     type Error = ();
//!     fn emit(&mut self, _command: u8) -> Result<(), ()> { Ok(()) }
//! }
//!
//! // Инъекция в него не собирается: нет `CanInject`.
//! async fn broken() {
//!     Pipeline::of_packets(stream::iter([1u8]))
//!         .map_signals(|b| b)
//!         .classify(|b| b)
//!         .react(|b| b)
//!         .materialize(|b| b)
//!         .inject_into(Mirror)
//!         .drive()
//!         .await;
//! }
//! ```

use futures::Stream;

/// ОТКУДА БЕРУТСЯ ПАКЕТЫ.
///
/// Заимствующий `packets(&mut self)` — не уступка, а форма настоящих бэкендов: кольцо `mmap` и
/// очередь ядра принадлежат бэкенду, а поток лишь читает их. Требовать `self` значило бы
/// заставить каждый бэкенд отдать своё устройство наружу.
pub trait Source {
    type Packet;
    type Packets<'a>: Stream<Item = Self::Packet>
    where
        Self: 'a;

    fn packets(&mut self) -> Self::Packets<'_>;
}

/// КУДА УХОДЯТ КОМАНДЫ.
///
/// Ошибка — ассоциированный тип, а не общий `String`: у очереди ядра и у сырого сокета беды
/// разные, и сводить их к строке значило бы терять то единственное, по чему их различают.
pub trait Sink {
    type Command;
    type Error;

    fn emit(&mut self, command: Self::Command) -> Result<(), Self::Error>;
}
