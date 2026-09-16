use std::sync::mpsc;

pub struct Tap<T> {
    tx: mpsc::SyncSender<T>,
}

/// ЧЕМ КОНЧИЛОСЬ ПОДНОШЕНИЕ — чтобы потеря наблюдения не выглядела как его отсутствие.
///
/// `emit` глотает отказ, и для отладочного лога это честно. Для прибора, по которому человек судит
/// «беды не было», — нет: полный канал и мёртвый читатель неотличимы от тишины. Два рода отказа
/// разделены, потому что лечатся в разных местах: `Full` — ёмкостью или темпом читателя, `Gone` —
/// тем, что читатель кончился.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Offered {
    Taken,
    Full,
    Gone,
}

impl<T> Tap<T> {
    pub fn new(tx: mpsc::SyncSender<T>) -> Self {
        Self { tx }
    }

    pub fn emit(&self, value: T) {
        let _ = self.tx.try_send(value);
    }

    /// Не ждёт никогда, как и `emit`, но говорит, дошло ли.
    pub fn offer(&self, value: T) -> Offered {
        match self.tx.try_send(value) {
            Ok(()) => Offered::Taken,
            Err(mpsc::TrySendError::Full(_)) => Offered::Full,
            Err(mpsc::TrySendError::Disconnected(_)) => Offered::Gone,
        }
    }
}

impl<T> Clone for Tap<T> {
    fn clone(&self) -> Self {
        Self {
            tx: self.tx.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emit_sends_value() {
        let (tx, rx) = mpsc::sync_channel(16);
        let tap = Tap::new(tx);
        tap.emit(42);
        tap.emit(99);
        assert_eq!(rx.try_recv().unwrap(), 42);
        assert_eq!(rx.try_recv().unwrap(), 99);
    }

    #[test]
    fn emit_drops_on_full_channel() {
        let (tx, rx) = mpsc::sync_channel(1);
        let tap = Tap::new(tx);
        tap.emit(1);
        tap.emit(2); // should not panic, silently dropped
        assert_eq!(rx.try_recv().unwrap(), 1);
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn offer_names_a_full_channel() {
        let (tx, rx) = mpsc::sync_channel(1);
        let tap = Tap::new(tx);
        assert_eq!(tap.offer(1), Offered::Taken);
        assert_eq!(tap.offer(2), Offered::Full);
        assert_eq!(rx.try_recv(), Ok(1));
    }

    #[test]
    fn offer_names_a_gone_reader() {
        let (tx, rx) = mpsc::sync_channel(1);
        let tap = Tap::new(tx);
        drop(rx);
        assert_eq!(tap.offer(1), Offered::Gone);
    }
}
