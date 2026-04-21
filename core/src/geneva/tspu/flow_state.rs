use std::time::Instant;

use crate::types::{Flow, TcpFlags, TcpSegment};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowPhase {
    SynSent,
    Established,
    Transferring,
    Finished,
}

#[derive(Debug, Clone)]
pub struct FlowState {
    phase: FlowPhase,
    ttl_baseline: Option<u8>,
    has_client_hello: bool,
    client_hello_at: Option<Instant>,
    sni: Option<String>,
    bytes_rx: u64,
    bytes_tx: u64,
    first_data_at: Option<Instant>,
    last_data_at: Option<Instant>,
    syn_at: Instant,
    retransmit_count: u32,
    server_retransmit_count: u32,
    rst_salvo_count: u32,
    last_seq_from_server: Option<u32>,
    pub timeout_signal_fired: bool,
}

impl FlowState {
    pub fn new(now: Instant) -> Self {
        Self {
            phase: FlowPhase::SynSent,
            ttl_baseline: None,
            has_client_hello: false,
            client_hello_at: None,
            sni: None,
            bytes_rx: 0,
            bytes_tx: 0,
            first_data_at: None,
            last_data_at: None,
            syn_at: now,
            retransmit_count: 0,
            server_retransmit_count: 0,
            rst_salvo_count: 0,
            last_seq_from_server: None,
            timeout_signal_fired: false,
        }
    }

    pub fn phase(&self) -> FlowPhase {
        self.phase
    }

    pub fn ttl_baseline(&self) -> Option<u8> {
        self.ttl_baseline
    }

    pub fn has_client_hello(&self) -> bool {
        self.has_client_hello
    }

    pub fn client_hello_at(&self) -> Option<Instant> {
        self.client_hello_at
    }

    pub fn sni(&self) -> Option<&str> {
        self.sni.as_deref()
    }

    pub fn bytes_rx(&self) -> u64 {
        self.bytes_rx
    }

    pub fn bytes_tx(&self) -> u64 {
        self.bytes_tx
    }

    pub fn first_data_at(&self) -> Option<Instant> {
        self.first_data_at
    }

    pub fn last_data_at(&self) -> Option<Instant> {
        self.last_data_at
    }

    pub fn syn_at(&self) -> Instant {
        self.syn_at
    }

    pub fn retransmit_count(&self) -> u32 {
        self.retransmit_count
    }

    pub fn server_retransmit_count(&self) -> u32 {
        self.server_retransmit_count
    }

    pub fn rst_salvo_count(&self) -> u32 {
        self.rst_salvo_count
    }

    pub fn update(&mut self, seg: &TcpSegment, client_flow: &Flow, now: Instant) {
        let from_server = is_from_server(seg, client_flow);
        if from_server {
            self.update_from_server(seg, now);
        } else {
            self.update_from_client(seg, now);
        }
    }

    fn update_from_server(&mut self, seg: &TcpSegment, now: Instant) {
        if seg.flags.is_syn_ack() && self.phase == FlowPhase::SynSent {
            self.phase = FlowPhase::Established;
            self.ttl_baseline = Some(seg.ttl);
            return;
        }
        if seg.flags.is_rst() {
            self.rst_salvo_count += 1;
            return;
        }
        if seg.flags.is_fin() && self.phase == FlowPhase::Transferring {
            self.phase = FlowPhase::Finished;
            return;
        }
        let payload_len = seg.payload.len() as u64;
        if payload_len > 0 {
            if let Some(last_seq) = self.last_seq_from_server {
                if seg.seq == last_seq {
                    self.server_retransmit_count += 1;
                }
            }
            self.last_seq_from_server = Some(seg.seq);
            self.bytes_rx += payload_len;
            self.last_data_at = Some(now);
            if self.first_data_at.is_none() {
                self.first_data_at = Some(now);
            }
            if self.phase == FlowPhase::Established {
                self.phase = FlowPhase::Transferring;
            }
        }
    }

    fn update_from_client(&mut self, seg: &TcpSegment, now: Instant) {
        let payload_len = seg.payload.len() as u64;
        if payload_len > 0 {
            self.bytes_tx += payload_len;
        }
        if is_tls_client_hello(&seg.payload) {
            if !self.has_client_hello {
                self.has_client_hello = true;
                self.client_hello_at = Some(now);
                self.sni = extract_sni(&seg.payload);
            } else {
                self.retransmit_count += 1;
            }
        }
        if seg.flags.is_syn() && self.phase == FlowPhase::SynSent {
            self.retransmit_count += 1;
        }
    }
}

fn is_from_server(seg: &TcpSegment, client_flow: &Flow) -> bool {
    if seg.flags.is_syn_ack() {
        return true;
    }
    if seg.flags.is_syn() && !seg.flags.contains(TcpFlags::ACK) {
        return false;
    }
    seg.flow.src == client_flow.dst
}

fn is_tls_client_hello(payload: &[u8]) -> bool {
    payload.len() >= 6 && payload[0] == 0x16 && payload[5] == 0x01
}

fn extract_sni(tls_data: &[u8]) -> Option<String> {
    if tls_data.len() < 43 {
        return None;
    }
    let mut pos = 43;
    if pos >= tls_data.len() {
        return None;
    }
    let session_id_len = tls_data[pos] as usize;
    pos += 1 + session_id_len;
    if pos + 2 > tls_data.len() {
        return None;
    }
    let cipher_suites_len = u16::from_be_bytes([tls_data[pos], tls_data[pos + 1]]) as usize;
    pos += 2 + cipher_suites_len;
    if pos >= tls_data.len() {
        return None;
    }
    let comp_len = tls_data[pos] as usize;
    pos += 1 + comp_len;
    if pos + 2 > tls_data.len() {
        return None;
    }
    let ext_len = u16::from_be_bytes([tls_data[pos], tls_data[pos + 1]]) as usize;
    pos += 2;
    let ext_end = (pos + ext_len).min(tls_data.len());
    while pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([tls_data[pos], tls_data[pos + 1]]);
        let this_len = u16::from_be_bytes([tls_data[pos + 2], tls_data[pos + 3]]) as usize;
        pos += 4;
        if ext_type == 0x0000 && this_len >= 5 && pos + this_len <= ext_end {
            let sni_data = &tls_data[pos..pos + this_len];
            if sni_data.len() >= 5 {
                let name_type = sni_data[2];
                let name_len = u16::from_be_bytes([sni_data[3], sni_data[4]]) as usize;
                if name_type == 0 && 5 + name_len <= sni_data.len() {
                    return String::from_utf8(sni_data[5..5 + name_len].to_vec()).ok();
                }
            }
        }
        pos += this_len;
    }
    None
}
