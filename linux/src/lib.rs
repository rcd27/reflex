mod capture;
mod inject;
#[cfg(feature = "xdp")]
pub mod xdp;

use std::pin::Pin;
use std::task::{Context, Poll};

use futures::Stream;
use reflex_core::{CanDrop, CanInject, CanModify, CanObserve};

pub use capture::Capture;
pub use inject::Injector;

// --- AF_PACKET backend: CanObserve + CanInject ---

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
        (
            CaptureStream {
                capture: self.capture,
            },
            self.injector,
        )
    }
}

// --- XDP + AF_PACKET backend: CanObserve + CanInject + CanDrop + CanModify ---

#[cfg(feature = "xdp")]
pub struct XdpAfPacketBackend {
    capture: Capture,
    injector: Injector,
    xdp: xdp::XdpProgram,
}

#[cfg(feature = "xdp")]
impl CanObserve for XdpAfPacketBackend {}
#[cfg(feature = "xdp")]
impl CanInject for XdpAfPacketBackend {}
#[cfg(feature = "xdp")]
impl CanDrop for XdpAfPacketBackend {}
#[cfg(feature = "xdp")]
impl CanModify for XdpAfPacketBackend {}

#[cfg(feature = "xdp")]
impl XdpAfPacketBackend {
    pub fn open(interface: &str, snaplen: usize, bpf_bytes: &[u8]) -> Result<Self, String> {
        let capture = Capture::open(interface, snaplen, true)?;
        let injector = Injector::open(interface)?;
        let xdp = xdp::XdpProgram::attach(interface, bpf_bytes)?;
        Ok(Self {
            capture,
            injector,
            xdp,
        })
    }

    pub fn packets(&mut self) -> PacketStream<'_> {
        PacketStream {
            capture: &mut self.capture,
        }
    }

    pub fn inject(&self, data: &[u8]) -> Result<(), String> {
        self.injector.send(data)
    }

    /// Set flow action in XDP BPF map (drop, copy+drop, pass).
    pub fn set_flow_action(
        &mut self,
        flow_hash: u32,
        action: reflex_linux_common::FlowAction,
    ) -> Result<(), String> {
        self.xdp.set_flow_action(flow_hash, action)
    }

    /// Clear flow action (revert to XDP_PASS).
    pub fn clear_flow_action(&mut self, flow_hash: u32) -> Result<(), String> {
        self.xdp.clear_flow_action(flow_hash)
    }

    pub fn split(self) -> (CaptureStream, Injector, xdp::XdpProgram) {
        (
            CaptureStream {
                capture: self.capture,
            },
            self.injector,
            self.xdp,
        )
    }
}

// --- Streams ---

pub struct PacketStream<'a> {
    capture: &'a mut Capture,
}

impl<'a> Stream for PacketStream<'a> {
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
