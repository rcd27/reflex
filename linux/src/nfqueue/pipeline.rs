use reflex_core::command::InjectablePacket;

use super::backend::NfqueueBackend;
use super::preflight;
use crate::rawsend::RawSender;

/// Packet from NFQUEUE with pending verdict.
pub struct NfqPacket {
    /// Raw IP packet bytes (no ethernet header).
    pub payload: Vec<u8>,
    /// Firewall mark from iptables.
    pub fwmark: u32,
}

/// What to do with the original packet.
pub enum NfqVerdict {
    Accept,
    Drop,
    Modify(Vec<u8>),
}

/// Generic handler: receives packet, returns verdict + inject list.
pub trait NfqHandler {
    fn handle(&mut self, packet: &NfqPacket) -> (NfqVerdict, Vec<InjectablePacket>);
}

/// NFQUEUE verdict loop.
///
/// Owns queue + raw sender. Firewall rules managed externally by FirewallGuard.
///
/// - `bind()`: preflight checks -> open queue + raw sender
/// - `run_while()`: verdict loop
pub struct NfqPipeline<H> {
    nfq: NfqueueBackend,
    sender: RawSender,
    handler: H,
    our_fwmark: u32,
}

impl<H: NfqHandler> NfqPipeline<H> {
    /// Bind NFQUEUE — no firewall rules.
    /// Use with FirewallGuard which manages rules separately.
    pub fn bind(queue_num: u16, fwmark: u32, handler: H) -> Result<Self, String> {
        preflight::check().map_err(|e| format!("preflight failed: {e}"))?;

        let nfq = NfqueueBackend::open(queue_num)?;
        let sender = RawSender::open(fwmark).map_err(|e| format!("RawSender::open: {e}"))?;

        Ok(Self {
            nfq,
            sender,
            handler,
            our_fwmark: fwmark,
        })
    }

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

        if mark == self.our_fwmark {
            self.nfq.accept(msg);
            return Ok(true);
        }

        let nfq_packet = NfqPacket {
            payload: payload.clone(),
            fwmark: mark,
        };

        let (verdict, injects) = self.handler.handle(&nfq_packet);

        for injectable in &injects {
            let ip_bytes = injectable.serialize_ip();
            if let Err(e) = self.sender.send(&ip_bytes) {
                tracing::warn!("RawSender inject failed: {e}");
            }
        }

        match verdict {
            NfqVerdict::Accept => self.nfq.accept(msg),
            NfqVerdict::Drop => self.nfq.drop_packet(msg),
            NfqVerdict::Modify(new_payload) => self.nfq.modify(msg, &new_payload),
        }

        Ok(true)
    }

    pub fn run_while(&mut self, alive: impl Fn() -> bool) -> Result<(), String> {
        while alive() {
            match self.step() {
                Ok(true) => {}
                Ok(false) => std::thread::sleep(std::time::Duration::from_micros(100)),
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
}
