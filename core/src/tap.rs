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

    /// Счёт потерь БЕЗ права писать в канал. Читающему потери нужен счёт, а не кран: клон крана
    /// держит канал открытым, и читатель, сосчитавший потери, не узнал бы, что пишущий кончился.
    pub fn lost_counter(&self) -> Lost {
        Lost(Arc::clone(&self.lost))
    }
}

/// Потери крана глазами читателя — только счёт, канал не держит (см. [`Tap::lost_counter`]).
#[derive(Debug, Clone)]
pub struct Lost(Arc<AtomicU64>);

impl Lost {
    /// Сколько уронено на полном канале с рождения крана.
    pub fn count(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
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

/// КРАН С ПЕРЕВОДОМ: пишущий подносит СВОЁ слово, в канал уходит слово ЧИТАТЕЛЯ.
///
/// Зачем: источник (пайп, прибор) знает только своё слово, а у читателя один входящий ящик на
/// много источников — без перевода у него столько каналов, сколько источников, и порядок между
/// ними держит комментарий, а не тип. Перевод — `From`: читатель объявляет, как его слово
/// рождается из слова источника, и источник о читателе не знает ничего.
///
/// Свой кран годится как есть: `Tap<T>` переводит `T` в `T` тем же правилом (`From<T> for T`).
pub struct Spout<T> {
    offer: Arc<dyn Fn(T) -> Offered + Send + Sync>,
    lost: Lost,
}

impl<T> Spout<T> {
    /// Не ждёт никогда, как и [`Tap::offer`], и говорит, дошло ли.
    pub fn offer(&self, value: T) -> Offered {
        (self.offer)(value)
    }

    /// Сколько уронено на полном канале — общий счёт с краном, из которого кран рождён.
    pub fn lost(&self) -> u64 {
        self.lost.count()
    }
}

impl<T> Clone for Spout<T> {
    fn clone(&self) -> Self {
        Self {
            offer: Arc::clone(&self.offer),
            lost: self.lost.clone(),
        }
    }
}

impl<T: 'static, L: From<T> + Send + 'static> From<Tap<L>> for Spout<T> {
    fn from(tap: Tap<L>) -> Spout<T> {
        let lost = tap.lost_counter();
        Spout {
            offer: Arc::new(move |value: T| tap.offer(L::from(value))),
            lost,
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

    /// Счёт потерь видит то же, что кран, но канал не держит: когда уходит последний кран,
    /// читатель узнаёт об этом, даже если у кого-то остался счёт.
    #[test]
    fn a_lost_counter_counts_without_keeping_the_channel_open() {
        let (tx, rx) = mpsc::sync_channel(1);
        let tap = Tap::new(tx);
        let lost = tap.lost_counter();
        let _taken = tap.offer(1);
        let _full = tap.offer(2);
        assert_eq!(lost.count(), 1);
        drop(tap);
        assert_eq!(rx.recv(), Ok(1));
        assert!(rx.recv().is_err(), "канал закрыт — счёт его не держит");
        assert_eq!(lost.count(), 1);
    }

    /// Слово источника.
    #[derive(Debug, PartialEq)]
    struct Spoken(u32);

    /// Слово читателя: ящик один на много источников, у каждого своё слово.
    #[derive(Debug, PartialEq)]
    enum Letter {
        Spoken(u32),
    }

    impl From<Spoken> for Letter {
        fn from(spoken: Spoken) -> Letter {
            Letter::Spoken(spoken.0)
        }
    }

    /// Источник подносит своё слово — в ящик уходит слово читателя.
    #[test]
    fn a_spout_speaks_the_readers_word() {
        let (tx, rx) = mpsc::sync_channel(4);
        let spout: Spout<Spoken> = Tap::new(tx).into();
        assert_eq!(spout.offer(Spoken(7)), Offered::Taken);
        assert_eq!(rx.try_recv(), Ok(Letter::Spoken(7)));
    }

    /// Свой кран — тот же кран: перевод `T` в `T`.
    #[test]
    fn a_tap_of_the_same_word_is_a_spout_as_is() {
        let (tx, rx) = mpsc::sync_channel::<u32>(4);
        let spout: Spout<u32> = Tap::new(tx).into();
        assert_eq!(spout.offer(5), Offered::Taken);
        assert_eq!(rx.try_recv(), Ok(5));
    }

    /// Полный ящик и мёртвый читатель называются, как у крана, и счёт потерь общий с ним.
    #[test]
    fn a_spout_names_its_refusals_and_shares_the_count() {
        let (tx, rx) = mpsc::sync_channel::<Letter>(1);
        let tap = Tap::new(tx);
        let spout: Spout<Spoken> = tap.clone().into();
        assert_eq!(spout.offer(Spoken(1)), Offered::Taken);
        assert_eq!(spout.offer(Spoken(2)), Offered::Full);
        assert_eq!(tap.lost(), 1);
        assert_eq!(spout.lost(), 1);
        drop(rx);
        assert_eq!(spout.offer(Spoken(3)), Offered::Gone);
    }

    /// Два источника — один ящик: порядок в нём — порядок подношения, а не очередь кранов.
    #[test]
    fn two_spouts_share_one_box_in_the_order_they_spoke() {
        let (tx, rx) = mpsc::sync_channel::<Letter>(4);
        let tap = Tap::new(tx);
        let first: Spout<Spoken> = tap.clone().into();
        let second: Spout<Spoken> = tap.into();
        let _taken = second.offer(Spoken(2));
        let _taken = first.offer(Spoken(1));
        assert_eq!(
            rx.try_iter().collect::<Vec<Letter>>(),
            vec![Letter::Spoken(2), Letter::Spoken(1)]
        );
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
