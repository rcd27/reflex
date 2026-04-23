use nfq::{Queue, Verdict};
use reflex_core::{CanDrop, CanHold, CanInject, CanModify, CanObserve};

pub struct NfqueueBackend {
    queue: Queue,
}

impl CanObserve for NfqueueBackend {}
impl CanInject for NfqueueBackend {}
impl CanHold for NfqueueBackend {}
impl CanModify for NfqueueBackend {}
impl CanDrop for NfqueueBackend {}

impl NfqueueBackend {
    pub fn open(queue_num: u16) -> Result<Self, String> {
        let mut queue = Queue::open().map_err(|e| format!("failed to open nfqueue: {e}"))?;
        queue
            .bind(queue_num)
            .map_err(|e| format!("failed to bind queue {queue_num}: {e}"))?;
        queue.set_nonblocking(true);
        queue
            .set_copy_range(queue_num, 0xFFFF)
            .map_err(|e| format!("failed to set copy range: {e}"))?;
        Ok(Self { queue })
    }

    pub fn recv(&mut self) -> Result<nfq::Message, String> {
        self.queue
            .recv()
            .map_err(|e| format!("nfqueue recv error: {e}"))
    }

    pub fn accept(&mut self, mut msg: nfq::Message) {
        msg.set_verdict(Verdict::Accept);
        let _ = self.queue.verdict(msg);
    }

    pub fn drop_packet(&mut self, mut msg: nfq::Message) {
        msg.set_verdict(Verdict::Drop);
        let _ = self.queue.verdict(msg);
    }

    pub fn modify(&mut self, mut msg: nfq::Message, new_payload: &[u8]) {
        msg.set_payload(new_payload.to_vec());
        msg.set_verdict(Verdict::Accept);
        let _ = self.queue.verdict(msg);
    }
}
