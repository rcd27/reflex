use std::sync::mpsc;

pub struct Tap<T> {
    tx: mpsc::SyncSender<T>,
}

impl<T> Tap<T> {
    pub fn new(tx: mpsc::SyncSender<T>) -> Self {
        Self { tx }
    }

    pub fn emit(&self, value: T) {
        let _ = self.tx.try_send(value);
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
}
