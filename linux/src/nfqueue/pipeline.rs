use reflex_core::command::InjectablePacket;

use super::backend::NfqueueBackend;
use super::firewall::FirewallRules;
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

/// Pipeline configuration.
pub struct NfqConfig {
    pub queue_num: u16,
    pub fwmark: u32,
}

impl Default for NfqConfig {
    fn default() -> Self {
        Self {
            queue_num: 200,
            fwmark: 0xBB,
        }
    }
}

/// Self-contained NFQUEUE verdict loop.
///
/// Owns the full lifecycle:
/// - `new()`: preflight checks -> firewall rules (IPv4+IPv6) -> open queue
/// - `run_blocking()`: verdict loop
/// - `Drop`: removes firewall rules
pub struct NfqPipeline<H> {
    _firewall: FirewallRules,
    nfq: NfqueueBackend,
    sender: RawSender,
    handler: H,
    our_fwmark: u32,
}

impl<H: NfqHandler> NfqPipeline<H> {
    pub fn new(config: NfqConfig, handler: H) -> Result<Self, String> {
        preflight::check().map_err(|e| format!("preflight failed: {e}"))?;

        let firewall = FirewallRules::install(config.queue_num, config.fwmark)?;
        let nfq = NfqueueBackend::open(config.queue_num)?;
        let sender = RawSender::open(config.fwmark).map_err(|e| format!("RawSender::open: {e}"))?;

        Ok(Self {
            _firewall: firewall,
            nfq,
            sender,
            handler,
            our_fwmark: config.fwmark,
        })
    }

    /// Backward-compatible constructor.
    pub fn open(queue_num: u16, fwmark: u32, handler: H) -> Result<Self, String> {
        Self::new(NfqConfig { queue_num, fwmark }, handler)
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

    pub fn run_blocking(&mut self) -> Result<(), String> {
        loop {
            match self.step() {
                Ok(true) => {}
                Ok(false) => std::thread::sleep(std::time::Duration::from_micros(100)),
                Err(e) => return Err(e),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pipeline_config_default() {
        let config = NfqConfig::default();
        assert_eq!(config.queue_num, 200);
        assert_eq!(config.fwmark, 0xBB);
    }
}
