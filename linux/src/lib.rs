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
}

pub struct PacketStream<'a> {
    capture: &'a mut Capture,
}

impl<'a> Stream for PacketStream<'a> {
    type Item = Vec<u8>;

    fn poll_next(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.capture.next_packet() {
            Some(data) => Poll::Ready(Some(data.to_vec())),
            None => Poll::Pending,
        }
    }
}
