mod capture;
#[cfg(feature = "conntrack")]
pub mod conntrack;
mod inject;
#[cfg(feature = "nfqueue")]
pub mod nfqueue;
pub mod nfqws;
pub mod rawsend;
#[cfg(feature = "tc")]
pub mod tc;
#[cfg(feature = "tun")]
pub mod tun;
#[cfg(feature = "tun")]
pub mod tun_egress;
#[cfg(feature = "tun")]
pub mod tun_listen;

use std::pin::Pin;
use std::task::{Context, Poll};

use futures::Stream;
#[cfg(feature = "tc")]
use reflex_core::{CanDrop, CanModify};
use reflex_core::{CanInject, CanObserve};

pub use capture::Capture;
pub use inject::Injector;
pub use rawsend::RawSender;

// Контракт src-порт-метки анти-петли ловца (`SelfLoop.portmark`): eBPF-steer гейтит лифт по нему, а
// потребитель (nevod) биндит src-порт из `PROBE_PORT_LO..=PROBE_PORT_HI` на direct-пробу. Реэкспорт —
// nevod тянет `reflex-linux`, не `-common` напрямую.
#[cfg(feature = "tc")]
pub use reflex_linux_common::{
    is_probe_port, is_probe_sport_hibyte, PROBE_PORT_HI, PROBE_PORT_LO, PROBE_SPORT_HIBYTE,
};

// --- AF_PACKET backend: CanObserve + CanInject ---

pub struct AfPacketBackend {
    capture: Capture,
    injector: Injector,
}

impl CanObserve for AfPacketBackend {}
impl CanInject for AfPacketBackend {}

// ФУНКТОР В КАТЕГОРИЮ БЭКЕНДОВ (#295, срез 4). Реализация АДДИТИВНА: inherent-методы остаются,
// и ни один существующий вызов не тронут. Смена бэкенда становится подстановкой типа там, где
// цепочка написана через трейты, и остаётся правкой кода там, где через inherent, — переезд
// потребителей отдельным шагом.
impl reflex_core::backend::Source for AfPacketBackend {
    type Packet = Vec<u8>;
    type Packets<'a> = PacketStream<'a>;

    fn packets(&mut self) -> Self::Packets<'_> {
        AfPacketBackend::packets(self)
    }
}

impl reflex_core::backend::Sink for AfPacketBackend {
    type Command = Vec<u8>;
    type Error = String;

    fn emit(&mut self, command: Vec<u8>) -> Result<(), String> {
        AfPacketBackend::inject(self, &command)
    }
}

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

// --- TC-BPF + AF_PACKET backend: CanObserve + CanInject + CanDrop + CanModify ---

#[cfg(feature = "tc")]
pub struct TcAfPacketBackend {
    capture: Capture,
    injector: Injector,
    tc: tc::TcProgram,
}

#[cfg(feature = "tc")]
impl reflex_core::backend::Source for TcAfPacketBackend {
    type Packet = Vec<u8>;
    type Packets<'a> = PacketStream<'a>;

    fn packets(&mut self) -> Self::Packets<'_> {
        TcAfPacketBackend::packets(self)
    }
}

#[cfg(feature = "tc")]
impl reflex_core::backend::Sink for TcAfPacketBackend {
    type Command = Vec<u8>;
    type Error = String;

    fn emit(&mut self, command: Vec<u8>) -> Result<(), String> {
        TcAfPacketBackend::inject(self, &command)
    }
}

#[cfg(feature = "tc")]
impl CanObserve for TcAfPacketBackend {}
#[cfg(feature = "tc")]
impl CanInject for TcAfPacketBackend {}
#[cfg(feature = "tc")]
impl CanDrop for TcAfPacketBackend {}
#[cfg(feature = "tc")]
impl CanModify for TcAfPacketBackend {}

#[cfg(feature = "tc")]
impl TcAfPacketBackend {
    /// Open AF_PACKET on `capture_iface` (br0), attach TC-BPF on `tc_iface` (veth-rt-br egress).
    pub fn open(
        capture_iface: &str,
        tc_iface: &str,
        snaplen: usize,
        bpf_bytes: &[u8],
    ) -> Result<Self, String> {
        let capture = Capture::open(capture_iface, snaplen, true)?;
        let injector = Injector::open(capture_iface)?;
        let tc = tc::TcProgram::attach(tc_iface, bpf_bytes)?;
        Ok(Self {
            capture,
            injector,
            tc,
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

    /// Set flow action in TC BPF map (drop or pass).
    pub fn set_flow_action(
        &mut self,
        flow_hash: u32,
        action: reflex_linux_common::FlowAction,
    ) -> Result<(), String> {
        self.tc.set_flow_action(flow_hash, action)
    }

    /// Clear flow action (revert to TC_ACT_OK / pass).
    pub fn clear_flow_action(&mut self, flow_hash: u32) -> Result<(), String> {
        self.tc.clear_flow_action(flow_hash)
    }

    pub fn split(self) -> (CaptureStream, Injector, tc::TcProgram) {
        (
            CaptureStream {
                capture: self.capture,
            },
            self.injector,
            self.tc,
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
    pub(crate) capture: Capture,
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
