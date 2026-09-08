//! Функтор носитель→драйвер: откуда пакеты (`Source`), куда команды (`Sink`). Канон §9. Способность
//! (`capability`) — ограничение образа: маркер, а не пометка.

use futures::Stream;

/// Откуда берутся пакеты. `packets(&mut self)` заимствует: кольцо mmap и очередь ядра принадлежат
/// бэкенду, поток лишь читает их.
pub trait Source {
    type Packet;
    type Packets<'a>: Stream<Item = Self::Packet>
    where
        Self: 'a;

    fn packets(&mut self) -> Self::Packets<'_>;
}

/// Куда уходят команды. Ошибка — ассоциированный тип, не общий `String`: у очереди ядра и сокета
/// беды разные.
pub trait Sink {
    type Command;
    type Error;

    fn emit(&mut self, command: Self::Command) -> Result<(), Self::Error>;
}

/// Дверь к наблюдениям — единственная, требует [`CanObserve`](crate::capability::CanObserve).
/// Канон §9.1. Потолка потока нет: обрезать умеет лишь тот, у кого часы (драйвер).
pub fn observing<B>(backend: &mut B) -> B::Packets<'_>
where
    B: Source + crate::capability::CanObserve,
{
    backend.packets()
}
