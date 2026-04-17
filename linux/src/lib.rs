mod capture;
mod inject;

use std::pin::Pin;
use std::task::{Context, Poll};

use futures::Stream;
use reflex_core::{CanInject, CanObserve};

pub use capture::Capture;
pub use inject::Injector;

pub struct AfPacketBackend {
    capture: Capture,
    injector: Injector,
}

impl CanObserve for AfPacketBackend {}
impl CanInject for AfPacketBackend {}

impl AfPacketBackend {
    pub fn open(interface: &str, snaplen: usize) -> Result<Self, String> {
        let capture = Capture::open(interface, snaplen, true)?;
        let injector = Injector::open(interface)?;
        Ok(Self { capture, injector })
    }

    pub fn packets(&mut self) -> PacketStream<'_> {
        PacketStream {
            capture: &mut self.capture,
        }
    }

    pub fn inject(&self, data: &[u8]) -> Result<(), String> {
        self.injector.send(data)
    }

    /// Split into separate capture stream and injector.
    /// Allows simultaneous read + write without borrow conflicts.
    pub fn split(self) -> (CaptureStream, Injector) {
        (CaptureStream { capture: self.capture }, self.injector)
    }
}

pub struct PacketStream<'a> {
    capture: &'a mut Capture,
}

impl<'a> Stream for PacketStream<'a> {
    type Item = Vec<u8>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.capture.next_packet() {
            Some(data) => Poll::Ready(Some(data.to_vec())),
            None => {
                // no packet right now — schedule immediate re-poll
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }
    }
}

/// Owned capture stream — for use after `split()`.
pub struct CaptureStream {
    capture: Capture,
}

impl Stream for CaptureStream {
    type Item = Vec<u8>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.capture.next_packet() {
            Some(data) => Poll::Ready(Some(data.to_vec())),
            None => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }
    }
}
