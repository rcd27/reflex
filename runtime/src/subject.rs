use std::sync::{Arc, PoisonError, RwLock};
use tokio::sync::broadcast;

/// Current-value + broadcast. Like RxJS BehaviourSubject.
///
/// - `get()` returns current value (clone)
/// - `set()` updates current + broadcasts to all subscribers
/// - `subscribe()` returns a broadcast receiver for future changes
pub struct Subject<T: Clone> {
    current: Arc<RwLock<T>>,
    tx: broadcast::Sender<T>,
}

impl<T: Clone> Subject<T> {
    pub fn new(initial: T) -> Self {
        let (tx, _) = broadcast::channel(64);
        Self {
            current: Arc::new(RwLock::new(initial)),
            tx,
        }
    }

    pub fn get(&self) -> T {
        self.current.read().unwrap().clone()
    }

    pub fn set(&self, value: T) {
        *self.current.write().unwrap() = value.clone();
        let _ = self.tx.send(value);
    }

    pub fn subscribe(&self) -> broadcast::Receiver<T> {
        self.tx.subscribe()
    }
}

impl<T: Clone + PartialEq> Subject<T> {
    /// `set`, подавляющий ПОВТОР: подписчик будится, только если значение действительно
    /// сменилось (Rx `distinct_until_changed`).
    ///
    /// ЗАЧЕМ ОТДЕЛЬНЫЙ МЕТОД, А НЕ ПОВЕДЕНИЕ `set`. Bound здесь УЖЕ, чем `T: Clone` у самого
    /// `Subject`: живому потребителю `Subject<Arc<Знание>>` в другом крейте
    /// сравнивать значения нечем, и глобальный bound отобрал бы у него примитив целиком.
    /// Выбор виден в типе — метод существует ровно там, где есть чем сравнивать, и потому
    /// «забыть про дедупликацию» нельзя молча: её отсутствие означает отсутствие `PartialEq`.
    ///
    /// ЗНАК ⟹ ЗЕМЛЯ (`model/law/Mark.tla`): уведомление — знак, смена значения — земля.
    /// Сравнение и запись идут под ОДНИМ write-замком не ради скорости: с двумя замками два
    /// писателя сверяются с одним и тем же снимком, оба видят «не изменилось», и уведомление о
    /// промежуточном значении теряется — знак без земли заменился бы землёй без знака.
    ///
    /// ПОТРЕБИТЕЛЯ У МЕТОДА ПОКА НЕТ, и это сказано вслух, чтобы не выглядело упущением. Оба живых
    /// `Subject` невода его не берут: у `Subject<Arc<Знание>>` сравнивать нечем, а счётчик живых
    /// флоу в другом крейте меняется на КАЖДОМ born/died — повтор там даёт
    /// разве что лишний `Died` при нуле. Метод стоит здесь по REFLEX-FIRST: примитив живёт и
    /// проверяется в изоляции, а первый настоящий потребитель придёт со своим замером.
    pub fn set_distinct(&self, value: T) {
        let notify = {
            let mut cur = self.current.write().unwrap_or_else(PoisonError::into_inner);
            (*cur != value).then(|| {
                *cur = value.clone();
                value
            })
        };
        let _ = notify.map(|v| self.tx.send(v));
    }
}

impl<T: Clone> Clone for Subject<T> {
    fn clone(&self) -> Self {
        Self {
            current: self.current.clone(),
            tx: self.tx.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_returns_initial() {
        let s = Subject::new(42);
        assert_eq!(s.get(), 42);
    }

    #[test]
    fn set_updates_current() {
        let s = Subject::new(0);
        s.set(99);
        assert_eq!(s.get(), 99);
    }

    #[test]
    fn subscribe_receives_updates() {
        let s = Subject::new(0);
        let mut rx = s.subscribe();
        s.set(1);
        s.set(2);
        assert_eq!(rx.try_recv().unwrap(), 1);
        assert_eq!(rx.try_recv().unwrap(), 2);
    }

    #[test]
    fn multiple_subscribers() {
        let s = Subject::new(0);
        let mut rx1 = s.subscribe();
        let mut rx2 = s.subscribe();
        s.set(42);
        assert_eq!(rx1.try_recv().unwrap(), 42);
        assert_eq!(rx2.try_recv().unwrap(), 42);
    }

    #[test]
    fn clone_shares_state() {
        let s1 = Subject::new(0);
        let s2 = s1.clone();
        s1.set(10);
        assert_eq!(s2.get(), 10);
    }

    #[test]
    fn subscriber_gets_only_future_values() {
        let s = Subject::new(0);
        s.set(1);
        let mut rx = s.subscribe();
        s.set(2);
        assert_eq!(rx.try_recv().unwrap(), 2);
    }

    #[test]
    fn set_distinct_suppresses_repeat() {
        let s = Subject::new(0);
        let mut rx = s.subscribe();
        s.set_distinct(1);
        s.set_distinct(1);
        assert_eq!(rx.try_recv().unwrap(), 1);
        assert!(
            rx.try_recv().is_err(),
            "повтор того же значения разбудил подписчика"
        );
    }

    #[test]
    fn set_distinct_passes_change() {
        let s = Subject::new(0);
        let mut rx = s.subscribe();
        s.set_distinct(1);
        s.set_distinct(2);
        assert_eq!(rx.try_recv().unwrap(), 1);
        assert_eq!(rx.try_recv().unwrap(), 2);
    }

    #[test]
    fn set_distinct_compares_with_initial() {
        let s = Subject::new(7);
        let mut rx = s.subscribe();
        s.set_distinct(7);
        assert!(
            rx.try_recv().is_err(),
            "значение, равное начальному, разбудило подписчика"
        );
    }

    #[test]
    fn set_distinct_wakes_on_return() {
        let s = Subject::new(0);
        let mut rx = s.subscribe();
        s.set_distinct(1);
        s.set_distinct(2);
        s.set_distinct(1);
        assert_eq!(rx.try_recv().unwrap(), 1);
        assert_eq!(rx.try_recv().unwrap(), 2);
        assert_eq!(rx.try_recv().unwrap(), 1);
    }

    #[test]
    fn set_distinct_keeps_current_readable() {
        let s = Subject::new(0);
        s.set_distinct(5);
        s.set_distinct(5);
        assert_eq!(s.get(), 5);
    }

    #[test]
    fn plain_set_still_wakes_on_repeat() {
        let s = Subject::new(0);
        let mut rx = s.subscribe();
        s.set(1);
        s.set(1);
        assert_eq!(rx.try_recv().unwrap(), 1);
        assert_eq!(rx.try_recv().unwrap(), 1);
    }
}
