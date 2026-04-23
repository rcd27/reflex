use reflex_core::command::InjectablePacket;

use super::backend::NfqueueBackend;
use crate::rawsend::RawSender;

/// Пакет из NFQUEUE с pending verdict.
pub struct NfqPacket {
    /// Raw IP packet bytes (no ethernet header).
    pub payload: Vec<u8>,
    /// Firewall mark from iptables.
    pub fwmark: u32,
}

/// Что делать с оригинальным пакетом.
pub enum NfqVerdict {
    /// Пропустить без изменений.
    Accept,
    /// Дропнуть.
    Drop,
    /// Заменить payload и пропустить.
    Modify(Vec<u8>),
}

/// Generic handler: получает пакет, возвращает verdict + inject list.
pub trait NfqHandler {
    fn handle(&mut self, packet: &NfqPacket) -> (NfqVerdict, Vec<InjectablePacket>);
}

/// Verdict loop. Владеет NfqueueBackend + RawSender.
pub struct NfqPipeline<H> {
    nfq: NfqueueBackend,
    sender: RawSender,
    handler: H,
    our_fwmark: u32,
}

impl<H: NfqHandler> NfqPipeline<H> {
    pub fn new(queue_num: u16, fwmark: u32, handler: H) -> Result<Self, String> {
        let nfq = NfqueueBackend::open(queue_num)?;
        let sender = RawSender::open(fwmark).map_err(|e| format!("RawSender::open failed: {e}"))?;
        Ok(Self {
            nfq,
            sender,
            handler,
            our_fwmark: fwmark,
        })
    }

    /// Run one iteration: recv packet, handle, execute verdict + injects.
    /// Returns Ok(true) if a packet was processed, Ok(false) if no packet available.
    pub fn step(&mut self) -> Result<bool, String> {
        let msg = match self.nfq.recv() {
            Ok(msg) => msg,
            Err(e) => {
                if e.contains("EAGAIN") || e.contains("Resource temporarily unavailable") {
                    return Ok(false);
                }
                return Err(e);
            }
        };

        let mark = msg.get_nfmark();
        let payload = msg.get_payload().to_vec();

        // Skip our own injected packets
        if mark == self.our_fwmark {
            self.nfq.accept(msg);
            return Ok(true);
        }

        let nfq_packet = NfqPacket {
            payload: payload.clone(),
            fwmark: mark,
        };

        let (verdict, injects) = self.handler.handle(&nfq_packet);

        // Execute injects first (before verdict — so fragments arrive before/instead of original)
        for injectable in &injects {
            let ip_bytes = injectable.serialize_ip();
            if let Err(e) = self.sender.send(&ip_bytes) {
                tracing::warn!("RawSender inject failed: {e}");
            }
        }

        // Execute verdict on original packet
        match verdict {
            NfqVerdict::Accept => self.nfq.accept(msg),
            NfqVerdict::Drop => self.nfq.drop_packet(msg),
            NfqVerdict::Modify(new_payload) => self.nfq.modify(msg, &new_payload),
        }

        Ok(true)
    }

    /// Run verdict loop until error or shutdown.
    pub fn run_blocking(&mut self) -> Result<(), String> {
        loop {
            match self.step() {
                Ok(true) => {}
                Ok(false) => {
                    std::thread::sleep(std::time::Duration::from_micros(100));
                }
                Err(e) => return Err(e),
            }
        }
    }
}
