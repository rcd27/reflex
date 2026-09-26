use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc};

pub struct Tap<T> {
    tx: mpsc::SyncSender<T>,
    /// Уронено на полном канале — общий счёт всех клонов: отказ, выброшенный пишущим, читающему
    /// иначе не виден вовсе.
    lost: Arc<AtomicU64>,
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
        Self {
            tx,
            lost: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn emit(&self, value: T) {
        let _ = self.offer(value);
    }

    /// Не ждёт никогда, как и `emit`, но говорит, дошло ли.
    pub fn offer(&self, value: T) -> Offered {
        match self.tx.try_send(value) {
            Ok(()) => Offered::Taken,
            Err(mpsc::TrySendError::Full(_)) => {
                let _before = self.lost.fetch_add(1, Ordering::Relaxed);
                Offered::Full
            }
            Err(mpsc::TrySendError::Disconnected(_)) => Offered::Gone,
        }
    }

    /// Сколько уронено на полном канале с рождения крана — всеми его клонами.
    pub fn lost(&self) -> u64 {
        self.lost.load(Ordering::Relaxed)
    }
}

impl<T> Clone for Tap<T> {
    fn clone(&self) -> Self {
        Self {
            tx: self.tx.clone(),
            lost: Arc::clone(&self.lost),
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

    /// Кран помнит, сколько уронил на полном канале: выброшенный отказ `offer` иначе не виден никому.
    #[test]
    fn a_full_channel_is_counted() {
        let (tx, _rx) = mpsc::sync_channel(1);
        let tap = Tap::new(tx);
        assert_eq!(tap.lost(), 0);
        let _taken = tap.offer(1);
        let _full = tap.offer(2);
        tap.emit(3);
        assert_eq!(tap.lost(), 2);
    }

    /// Мёртвый читатель — другой род отказа: его счёт не смешивается с полным каналом.
    #[test]
    fn a_gone_reader_is_not_counted_as_full() {
        let (tx, rx) = mpsc::sync_channel(1);
        let tap = Tap::new(tx);
        drop(rx);
        let _gone = tap.offer(1);
        assert_eq!(tap.lost(), 0);
    }

    /// Клоны одного крана делят счёт: пайп роняет в свой клон, потребитель читает свой.
    #[test]
    fn clones_share_the_count() {
        let (tx, _rx) = mpsc::sync_channel(0);
        let tap = Tap::new(tx);
        let pipe = tap.clone();
        let _full = pipe.offer(1);
        assert_eq!(tap.lost(), 1);
    }
}
