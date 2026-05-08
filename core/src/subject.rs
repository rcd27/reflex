use std::sync::{Arc, RwLock};
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
}
