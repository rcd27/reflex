use reflex_core::{CanDrop, CanHold, CanModify};

use super::backend::NfqueueBackend;
use crate::capture::Capture;
use crate::inject::Injector;

pub struct NfqAfPacketBackend {
    nfqueue: NfqueueBackend,
    capture: Capture,
    injector: Injector,
}

// СНЯТО ПО ТОЙ ЖЕ ПРИЧИНЕ, ЧТО У `NfqueueBackend`: ни `Source`, ни `Sink` не реализованы, и
// заявления о вводе и наблюдении были высказываниями без предмета. Инжектор у типа есть
// (`self.injector`), и захват тоже (`self.capture`) —
// именно поэтому снятие здесь особенно уместно: способность выглядела обеспеченной полем, но
// категория до неё не дотягивалась.
// TODO(#326): подключить к категории вместе с `NfqueueBackend`.
impl CanHold for NfqAfPacketBackend {}
impl CanModify for NfqAfPacketBackend {}
impl CanDrop for NfqAfPacketBackend {}

impl NfqAfPacketBackend {
    pub fn open(capture_iface: &str, queue_num: u16, snaplen: usize) -> Result<Self, String> {
        let capture = Capture::open(capture_iface, snaplen, true)?;
        let injector = Injector::open(capture_iface)?;
        let nfqueue = NfqueueBackend::open(queue_num)?;
        Ok(Self {
            nfqueue,
            capture,
            injector,
        })
    }

    pub fn nfqueue(&mut self) -> &mut NfqueueBackend {
        &mut self.nfqueue
    }

    pub fn inject(&self, data: &[u8]) -> Result<(), String> {
        self.injector.send(data)
    }

    pub fn split(self) -> (crate::CaptureStream, Injector, NfqueueBackend) {
        (
            crate::CaptureStream {
                capture: self.capture,
            },
            self.injector,
            self.nfqueue,
        )
    }
}
