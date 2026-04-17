use std::collections::HashMap;
use std::time::{Duration, Instant};

use futures::StreamExt;
use reflex_core::{Detector, ReflexExt};
use reflex_linux::AfPacketBackend;

// --- Geneva primitives (AF_PACKET subset) ---

#[derive(Debug, Clone)]
enum GenevaAction {
    Duplicate {
        tamper: TamperOp,
        count: u8,
    },
}

#[derive(Debug, Clone)]
enum TamperOp {
    ShortTtl { ttl: u8 },
    WrongChecksum,
    TcpMd5,
    MultiDisorder { chunk_count: u8 },
}

#[derive(Debug, Clone)]
struct Strategy {
    actions: Vec<GenevaAction>,
    fitness: f32,
    generation: u32,
    attempts: u32,
    successes: u32,
}

impl Strategy {
    fn random(generation: u32) -> Self {
        // generate random strategy from available primitives
        let tamper = match generation % 4 {
            0 => TamperOp::ShortTtl { ttl: 3 },
            1 => TamperOp::WrongChecksum,
            2 => TamperOp::TcpMd5,
            3 => TamperOp::MultiDisorder { chunk_count: 3 },
            _ => unreachable!(),
        };

        Self {
            actions: vec![GenevaAction::Duplicate {
                tamper,
                count: 1,
            }],
            fitness: 0.0,
            generation,
            attempts: 0,
            successes: 0,
        }
    }

    fn mutate(&self, generation: u32) -> Self {
        let mut new = self.clone();
        new.generation = generation;
        new.attempts = 0;
        new.successes = 0;
        new.fitness = 0.0;

        // mutate: change tamper op or count
        if let Some(GenevaAction::Duplicate { tamper, count }) = new.actions.first_mut() {
            match generation % 3 {
                0 => {
                    // mutate TTL
                    *tamper = TamperOp::ShortTtl {
                        ttl: (generation % 5) as u8 + 1,
                    };
                }
                1 => {
                    // mutate chunk count
                    if let TamperOp::MultiDisorder { chunk_count } = tamper {
                        *chunk_count = (generation % 4) as u8 + 2;
                    } else {
                        *tamper = TamperOp::MultiDisorder {
                            chunk_count: (generation % 4) as u8 + 2,
                        };
                    }
                }
                2 => {
                    // mutate duplicate count
                    *count = (generation % 3) as u8 + 1;
                }
                _ => unreachable!(),
            }
        }

        new
    }
}

// --- detector signals ---

#[derive(Debug, Clone)]
enum Signal {
    ClientHello {
        domain: String,
        flow_key: FlowKey,
        raw: Vec<u8>,
        ip_start: usize,
        tcp_start: usize,
        payload_start: usize,
        timestamp: Instant,
    },
    ServerHelloSeen {
        flow_key: FlowKey,
        timestamp: Instant,
    },
    RstSeen {
        flow_key: FlowKey,
        ttl_anomaly: bool,
        timestamp: Instant,
    },
    Timeout {
        flow_key: FlowKey,
        timestamp: Instant,
    },
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct FlowKey {
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
}

// --- feedback detector: tracks full TLS handshake outcome ---

struct FeedbackDetector {
    server_ttl: Option<u8>,
    pending_flows: HashMap<FlowKey, PendingFlow>,
    blocked_domains: Vec<String>,
}

struct PendingFlow {
    domain: String,
    client_hello_ts: Instant,
    strategy_applied: bool,
}

impl FeedbackDetector {
    fn new(blocked_domains: Vec<String>) -> Self {
        Self {
            server_ttl: None,
            pending_flows: HashMap::new(),
            blocked_domains,
        }
    }
}

#[derive(Debug, Clone)]
struct ParsedPacket {
    raw: Vec<u8>,
    ip_start: usize,
    tcp_start: usize,
    payload_start: usize,
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    ttl: u8,
    tcp_flags: u8,
    is_client_hello: bool,
    is_server_hello: bool,
    is_rst: bool,
    is_syn_ack: bool,
    sni: Option<String>,
}

impl Detector for FeedbackDetector {
    type Input = ParsedPacket;
    type Signal = Signal;

    fn on_packet(&mut self, pkt: ParsedPacket, emit: &mut dyn FnMut(Self::Signal)) {
        let forward_key = FlowKey {
            src_ip: pkt.src_ip,
            dst_ip: pkt.dst_ip,
            src_port: pkt.src_port,
            dst_port: pkt.dst_port,
        };
        let reverse_key = FlowKey {
            src_ip: pkt.dst_ip,
            dst_ip: pkt.src_ip,
            src_port: pkt.dst_port,
            dst_port: pkt.src_port,
        };

        // learn server TTL
        if pkt.is_syn_ack {
            self.server_ttl = Some(pkt.ttl);
        }

        // ClientHello to blocked domain
        if pkt.is_client_hello {
            if let Some(ref domain) = pkt.sni {
                if self.blocked_domains.iter().any(|d| d == domain) {
                    let now = Instant::now();
                    self.pending_flows.insert(
                        forward_key.clone(),
                        PendingFlow {
                            domain: domain.clone(),
                            client_hello_ts: now,
                            strategy_applied: false,
                        },
                    );
                    emit(Signal::ClientHello {
                        domain: domain.clone(),
                        flow_key: forward_key,
                        raw: pkt.raw,
                        ip_start: pkt.ip_start,
                        tcp_start: pkt.tcp_start,
                        payload_start: pkt.payload_start,
                        timestamp: now,
                    });
                }
            }
        }

        // ServerHello — success! Strategy worked.
        if pkt.is_server_hello {
            if self.pending_flows.contains_key(&reverse_key) {
                let flow = self.pending_flows.remove(&reverse_key).unwrap();
                eprintln!(
                    "[feedback] ServerHello for {} — strategy SUCCEEDED ({}ms)",
                    flow.domain,
                    flow.client_hello_ts.elapsed().as_millis()
                );
                emit(Signal::ServerHelloSeen {
                    flow_key: reverse_key.clone(),
                    timestamp: Instant::now(),
                });
            }
        }

        // RST with TTL anomaly — strategy failed (or wasn't applied yet)
        if pkt.is_rst {
            let ttl_anomaly = if let Some(server_ttl) = self.server_ttl {
                (pkt.ttl as i16 - server_ttl as i16).abs() > 3
            } else {
                false
            };

            if ttl_anomaly {
                if self.pending_flows.contains_key(&reverse_key) {
                    let flow = self.pending_flows.remove(&reverse_key).unwrap();
                    eprintln!(
                        "[feedback] RST injection for {} — strategy FAILED ({}ms)",
                        flow.domain,
                        flow.client_hello_ts.elapsed().as_millis()
                    );
                    emit(Signal::RstSeen {
                        flow_key: reverse_key,
                        ttl_anomaly: true,
                        timestamp: Instant::now(),
                    });
                }
            }
        }
    }

    fn on_tick(&mut self, now: Instant, emit: &mut dyn FnMut(Self::Signal)) {
        // timeout pending flows after 5s
        let expired: Vec<FlowKey> = self
            .pending_flows
            .iter()
            .filter(|(_, f)| now.duration_since(f.client_hello_ts) > Duration::from_secs(5))
            .map(|(k, _)| k.clone())
            .collect();

        for key in expired {
            let flow = self.pending_flows.remove(&key).unwrap();
            eprintln!(
                "[feedback] timeout for {} — strategy FAILED (timeout)",
                flow.domain
            );
            emit(Signal::Timeout {
                flow_key: key,
                timestamp: now,
            });
        }
    }
}

// --- population management ---

struct Population {
    strategies: Vec<Strategy>,
    current_idx: usize,
    generation: u32,
}

impl Population {
    fn new(size: usize) -> Self {
        let strategies = (0..size).map(|i| Strategy::random(i as u32)).collect();
        Self {
            strategies,
            current_idx: 0,
            generation: 0,
        }
    }

    fn current(&self) -> &Strategy {
        &self.strategies[self.current_idx]
    }

    fn report_success(&mut self) {
        let s = &mut self.strategies[self.current_idx];
        s.attempts += 1;
        s.successes += 1;
        s.fitness = s.successes as f32 / s.attempts as f32;
        eprintln!(
            "[population] strategy #{} fitness: {:.2} ({}/{})",
            self.current_idx, s.fitness, s.successes, s.attempts
        );
    }

    fn report_failure(&mut self) {
        let s = &mut self.strategies[self.current_idx];
        s.attempts += 1;
        s.fitness = s.successes as f32 / s.attempts as f32;
        eprintln!(
            "[population] strategy #{} fitness: {:.2} ({}/{})",
            self.current_idx, s.fitness, s.successes, s.attempts
        );

        // after 3 failures, mutate and try next
        if s.attempts >= 3 && s.fitness < 0.5 {
            self.evolve();
        }
    }

    fn evolve(&mut self) {
        self.generation += 1;

        // find best strategy
        let best_idx = self
            .strategies
            .iter()
            .enumerate()
            .max_by(|(_, a), (_, b)| a.fitness.partial_cmp(&b.fitness).unwrap())
            .map(|(i, _)| i)
            .unwrap_or(0);

        let best = self.strategies[best_idx].clone();
        eprintln!(
            "[population] generation {} — best strategy #{} fitness {:.2}, mutating",
            self.generation, best_idx, best.fitness
        );

        // replace worst with mutation of best
        let worst_idx = self
            .strategies
            .iter()
            .enumerate()
            .min_by(|(_, a), (_, b)| a.fitness.partial_cmp(&b.fitness).unwrap())
            .map(|(i, _)| i)
            .unwrap_or(0);

        self.strategies[worst_idx] = best.mutate(self.generation);

        // advance to next strategy
        self.current_idx = (self.current_idx + 1) % self.strategies.len();
        eprintln!(
            "[population] now trying strategy #{}: {:?}",
            self.current_idx, self.strategies[self.current_idx].actions
        );
    }
}

// --- packet parser ---

fn parse_packet(raw: Vec<u8>) -> Option<ParsedPacket> {
    if raw.len() < 54 {
        return None;
    }
    if raw[12] != 0x08 || raw[13] != 0x00 {
        return None;
    }
    let ip_start = 14;
    if raw[ip_start + 9] != 6 {
        return None;
    }
    let ip_ihl = (raw[ip_start] & 0x0f) as usize * 4;
    let tcp_start = ip_start + ip_ihl;
    if raw.len() < tcp_start + 20 {
        return None;
    }

    let src_ip: [u8; 4] = raw[ip_start + 12..ip_start + 16].try_into().ok()?;
    let dst_ip: [u8; 4] = raw[ip_start + 16..ip_start + 20].try_into().ok()?;
    let ttl = raw[ip_start + 8];
    let src_port = u16::from_be_bytes([raw[tcp_start], raw[tcp_start + 1]]);
    let dst_port = u16::from_be_bytes([raw[tcp_start + 2], raw[tcp_start + 3]]);
    let tcp_flags = raw[tcp_start + 13];
    let is_syn_ack = tcp_flags & 0x12 == 0x12;
    let is_rst = tcp_flags & 0x04 != 0;

    let tcp_data_offset = (raw[tcp_start + 12] >> 4) as usize * 4;
    let payload_start = tcp_start + tcp_data_offset;

    let (is_client_hello, sni) = if raw.len() > payload_start + 6
        && raw[payload_start] == 0x16
        && raw[payload_start + 5] == 0x01
    {
        (true, extract_sni(&raw[payload_start..]))
    } else {
        (false, None)
    };

    // ServerHello: TLS handshake type 0x02
    let is_server_hello = if raw.len() > payload_start + 6 && raw[payload_start] == 0x16 {
        raw[payload_start + 5] == 0x02
    } else {
        false
    };

    Some(ParsedPacket {
        raw,
        ip_start,
        tcp_start,
        payload_start,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        ttl,
        tcp_flags,
        is_client_hello,
        is_server_hello,
        is_rst,
        is_syn_ack,
        sni,
    })
}

fn extract_sni(tls: &[u8]) -> Option<String> {
    if tls.len() < 44 {
        return None;
    }
    let session_id_offset = 5 + 1 + 3 + 2 + 32;
    if tls.len() <= session_id_offset {
        return None;
    }
    let session_id_len = tls[session_id_offset] as usize;
    let cipher_offset = session_id_offset + 1 + session_id_len;
    if tls.len() < cipher_offset + 2 {
        return None;
    }
    let cipher_len = u16::from_be_bytes([tls[cipher_offset], tls[cipher_offset + 1]]) as usize;
    let comp_offset = cipher_offset + 2 + cipher_len;
    if tls.len() < comp_offset + 1 {
        return None;
    }
    let comp_len = tls[comp_offset] as usize;
    let ext_offset = comp_offset + 1 + comp_len;
    if tls.len() < ext_offset + 2 {
        return None;
    }
    let ext_total = u16::from_be_bytes([tls[ext_offset], tls[ext_offset + 1]]) as usize;
    let mut pos = ext_offset + 2;
    let ext_end = pos + ext_total;
    while pos + 4 <= ext_end && pos + 4 <= tls.len() {
        let ext_type = u16::from_be_bytes([tls[pos], tls[pos + 1]]);
        let ext_len = u16::from_be_bytes([tls[pos + 2], tls[pos + 3]]) as usize;
        pos += 4;
        if ext_type == 0x0000 {
            if pos + 5 <= tls.len() {
                let name_len = u16::from_be_bytes([tls[pos + 3], tls[pos + 4]]) as usize;
                let name_start = pos + 5;
                if name_start + name_len <= tls.len() {
                    return String::from_utf8(tls[name_start..name_start + name_len].to_vec()).ok();
                }
            }
            return None;
        }
        pos += ext_len;
    }
    None
}

// --- inject based on strategy ---

fn execute_strategy(injector: &reflex_linux::Injector, strategy: &Strategy, signal: &Signal) {
    let Signal::ClientHello {
        raw,
        ip_start,
        tcp_start,
        payload_start,
        ..
    } = signal
    else {
        return;
    };

    for action in &strategy.actions {
        match action {
            GenevaAction::Duplicate { tamper, count } => {
                for i in 0..*count {
                    match tamper {
                        TamperOp::ShortTtl { ttl } => {
                            let fake = build_fake_with_ttl(raw, *ip_start, *tcp_start, *payload_start, *ttl);
                            if let Err(e) = injector.send(&fake) {
                                eprintln!("[inject] ShortTtl fake #{i} failed: {e}");
                            } else {
                                eprintln!("[inject] ShortTtl fake #{i} (TTL={ttl})");
                            }
                        }
                        TamperOp::WrongChecksum => {
                            let fake = build_fake_wrong_checksum(raw, *ip_start, *tcp_start, *payload_start);
                            if let Err(e) = injector.send(&fake) {
                                eprintln!("[inject] WrongChecksum fake #{i} failed: {e}");
                            } else {
                                eprintln!("[inject] WrongChecksum fake #{i}");
                            }
                        }
                        TamperOp::TcpMd5 => {
                            let fake = build_fake_tcp_md5(raw, *ip_start, *tcp_start, *payload_start);
                            if let Err(e) = injector.send(&fake) {
                                eprintln!("[inject] TcpMd5 fake #{i} failed: {e}");
                            } else {
                                eprintln!("[inject] TcpMd5 fake #{i}");
                            }
                        }
                        TamperOp::MultiDisorder { chunk_count } => {
                            execute_multi_disorder(injector, raw, *ip_start, *tcp_start, *payload_start, *chunk_count);
                        }
                    }
                }
            }
        }
    }
}

fn execute_multi_disorder(
    injector: &reflex_linux::Injector,
    raw: &[u8],
    ip_start: usize,
    tcp_start: usize,
    payload_start: usize,
    chunk_count: u8,
) {
    let payload_len = raw.len() - payload_start;
    if payload_len < chunk_count as usize {
        return;
    }

    let seq = u32::from_be_bytes(raw[tcp_start + 4..tcp_start + 8].try_into().unwrap());
    let chunk_size = payload_len / chunk_count as usize;

    // send in reverse order (disorder)
    for i in (0..chunk_count).rev() {
        let start = i as usize * chunk_size;
        let end = if i == chunk_count - 1 {
            payload_len
        } else {
            (i as usize + 1) * chunk_size
        };
        let chunk_data = &raw[payload_start + start..payload_start + end];
        let fake = build_fake_packet(raw, ip_start, tcp_start, seq + start as u32, chunk_data, 3);
        if let Err(e) = injector.send(&fake) {
            eprintln!("[inject] disorder chunk #{i} failed: {e}");
        }
    }
    eprintln!("[inject] multi-disorder: {chunk_count} chunks injected");
}

fn build_fake_with_ttl(
    original: &[u8],
    ip_start: usize,
    tcp_start: usize,
    payload_start: usize,
    ttl: u8,
) -> Vec<u8> {
    let payload = &original[payload_start..];
    let seq = u32::from_be_bytes(original[tcp_start + 4..tcp_start + 8].try_into().unwrap());
    build_fake_packet(original, ip_start, tcp_start, seq, payload, ttl)
}

fn build_fake_wrong_checksum(
    original: &[u8],
    ip_start: usize,
    tcp_start: usize,
    payload_start: usize,
) -> Vec<u8> {
    let mut fake = build_fake_with_ttl(original, ip_start, tcp_start, payload_start, 3);
    // corrupt TCP checksum
    let tcp_out = 14 + 20;
    if fake.len() > tcp_out + 18 {
        fake[tcp_out + 16] ^= 0xFF;
        fake[tcp_out + 17] ^= 0xFF;
    }
    fake
}

fn build_fake_tcp_md5(
    original: &[u8],
    ip_start: usize,
    tcp_start: usize,
    payload_start: usize,
) -> Vec<u8> {
    // TCP MD5 option: kind=19, length=18, then 16 bytes of "signature"
    // server rejects packets with MD5 option if it doesn't expect it
    let payload = &original[payload_start..];
    let seq = u32::from_be_bytes(original[tcp_start + 4..tcp_start + 8].try_into().unwrap());

    let tcp_header_len = 40; // 20 base + 20 options (MD5 = 18 + 2 NOP padding)
    let total_len = 14 + 20 + tcp_header_len + payload.len();
    let mut pkt = vec![0u8; total_len];

    // ethernet
    pkt[0..14].copy_from_slice(&original[0..14]);

    // IP
    let ip_out = 14;
    pkt[ip_out] = 0x45;
    let ip_total: u16 = (20 + tcp_header_len + payload.len()) as u16;
    pkt[ip_out + 2..ip_out + 4].copy_from_slice(&ip_total.to_be_bytes());
    pkt[ip_out + 6..ip_out + 8].copy_from_slice(&[0x40, 0x00]);
    pkt[ip_out + 8] = 3; // short TTL
    pkt[ip_out + 9] = 6;
    pkt[ip_out + 12..ip_out + 16].copy_from_slice(&original[ip_start + 12..ip_start + 16]);
    pkt[ip_out + 16..ip_out + 20].copy_from_slice(&original[ip_start + 16..ip_start + 20]);
    let csum = ip_checksum(&pkt[ip_out..ip_out + 20]);
    pkt[ip_out + 10..ip_out + 12].copy_from_slice(&csum.to_be_bytes());

    // TCP
    let tcp_out = 34;
    pkt[tcp_out..tcp_out + 2].copy_from_slice(&original[tcp_start..tcp_start + 2]);
    pkt[tcp_out + 2..tcp_out + 4].copy_from_slice(&original[tcp_start + 2..tcp_start + 4]);
    pkt[tcp_out + 4..tcp_out + 8].copy_from_slice(&seq.to_be_bytes());
    pkt[tcp_out + 8..tcp_out + 12].copy_from_slice(&original[tcp_start + 8..tcp_start + 12]);
    pkt[tcp_out + 12] = (tcp_header_len as u8 / 4) << 4; // data offset
    pkt[tcp_out + 13] = 0x18; // PSH+ACK
    pkt[tcp_out + 14..tcp_out + 16].copy_from_slice(&original[tcp_start + 14..tcp_start + 16]);

    // TCP MD5 option
    pkt[tcp_out + 20] = 19; // kind = TCP MD5
    pkt[tcp_out + 21] = 18; // length = 18
    // 16 bytes of fake signature (zeros — doesn't matter, server will reject)
    // padding NOPs
    pkt[tcp_out + 38] = 1; // NOP
    pkt[tcp_out + 39] = 1; // NOP

    // payload
    pkt[tcp_out + tcp_header_len..].copy_from_slice(payload);

    // TCP checksum
    let tcp_csum = tcp_checksum(
        &pkt[ip_out + 12..ip_out + 16],
        &pkt[ip_out + 16..ip_out + 20],
        &pkt[tcp_out..],
    );
    pkt[tcp_out + 16..tcp_out + 18].copy_from_slice(&tcp_csum.to_be_bytes());

    pkt
}

fn build_fake_packet(
    original: &[u8],
    ip_start: usize,
    tcp_start: usize,
    seq: u32,
    payload: &[u8],
    ttl: u8,
) -> Vec<u8> {
    let tcp_header_len = 20;
    let total_len = 14 + 20 + tcp_header_len + payload.len();
    let mut pkt = vec![0u8; total_len];
    pkt[0..14].copy_from_slice(&original[0..14]);
    let ip_out = 14;
    pkt[ip_out] = 0x45;
    let ip_total: u16 = (20 + tcp_header_len + payload.len()) as u16;
    pkt[ip_out + 2..ip_out + 4].copy_from_slice(&ip_total.to_be_bytes());
    pkt[ip_out + 4..ip_out + 6].copy_from_slice(&[0xDE, 0xAD]);
    pkt[ip_out + 6..ip_out + 8].copy_from_slice(&[0x40, 0x00]);
    pkt[ip_out + 8] = ttl;
    pkt[ip_out + 9] = 6;
    pkt[ip_out + 12..ip_out + 16].copy_from_slice(&original[ip_start + 12..ip_start + 16]);
    pkt[ip_out + 16..ip_out + 20].copy_from_slice(&original[ip_start + 16..ip_start + 20]);
    let csum = ip_checksum(&pkt[ip_out..ip_out + 20]);
    pkt[ip_out + 10..ip_out + 12].copy_from_slice(&csum.to_be_bytes());
    let tcp_out = 14 + 20;
    pkt[tcp_out..tcp_out + 2].copy_from_slice(&original[tcp_start..tcp_start + 2]);
    pkt[tcp_out + 2..tcp_out + 4].copy_from_slice(&original[tcp_start + 2..tcp_start + 4]);
    pkt[tcp_out + 4..tcp_out + 8].copy_from_slice(&seq.to_be_bytes());
    pkt[tcp_out + 8..tcp_out + 12].copy_from_slice(&original[tcp_start + 8..tcp_start + 12]);
    pkt[tcp_out + 12] = 0x50;
    pkt[tcp_out + 13] = 0x18;
    pkt[tcp_out + 14..tcp_out + 16].copy_from_slice(&original[tcp_start + 14..tcp_start + 16]);
    pkt[tcp_out + tcp_header_len..].copy_from_slice(payload);
    let tcp_csum = tcp_checksum(
        &pkt[ip_out + 12..ip_out + 16],
        &pkt[ip_out + 16..ip_out + 20],
        &pkt[tcp_out..],
    );
    pkt[tcp_out + 16..tcp_out + 18].copy_from_slice(&tcp_csum.to_be_bytes());
    pkt
}

fn ip_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for chunk in header.chunks(2) {
        let word = if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]])
        } else {
            u16::from_be_bytes([chunk[0], 0])
        };
        sum += word as u32;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn tcp_checksum(src_ip: &[u8], dst_ip: &[u8], tcp_segment: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for chunk in src_ip.chunks(2) {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    for chunk in dst_ip.chunks(2) {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    sum += 6u32;
    sum += tcp_segment.len() as u32;
    for chunk in tcp_segment.chunks(2) {
        let word = if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]])
        } else {
            u16::from_be_bytes([chunk[0], 0])
        };
        sum += word as u32;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

// --- main ---

#[tokio::main]
async fn main() {
    let iface = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "br0".to_string());

    let timeout_secs: u64 = std::env::args()
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(15);

    let blocked_domains = vec!["testserver.local".to_string()];

    eprintln!("[geneva] feedback loop on {iface}, timeout {timeout_secs}s");
    eprintln!("[geneva] protecting: {blocked_domains:?}");

    let backend = AfPacketBackend::open(&iface, 65535).unwrap_or_else(|e| {
        eprintln!("[geneva] FAIL: {e}");
        std::process::exit(1);
    });

    let (stream, injector) = backend.split();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(timeout_secs);

    let mut population = Population::new(4);
    let mut signals_processed = 0u32;

    eprintln!(
        "[geneva] initial strategy: {:?}",
        population.current().actions
    );

    // Floor 1: detect with feedback
    let mut pipeline = stream
        .filter_map(|raw| async move { parse_packet(raw) })
        .detect(FeedbackDetector::new(blocked_domains));

    tokio::pin!(pipeline);

    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }

        match tokio::time::timeout(Duration::from_millis(100), pipeline.next()).await {
            Ok(Some(signal)) => {
                signals_processed += 1;
                match &signal {
                    Signal::ClientHello { domain, .. } => {
                        eprintln!("[geneva] ClientHello for {domain} — applying strategy");
                        execute_strategy(&injector, population.current(), &signal);
                    }
                    Signal::ServerHelloSeen { .. } => {
                        population.report_success();
                    }
                    Signal::RstSeen { .. } => {
                        population.report_failure();
                    }
                    Signal::Timeout { .. } => {
                        population.report_failure();
                    }
                }
            }
            Ok(None) => break,
            Err(_) => continue,
        }
    }

    eprintln!("[geneva] done, processed {signals_processed} signals");
    eprintln!("[geneva] final population:");
    for (i, s) in population.strategies.iter().enumerate() {
        eprintln!(
            "  #{i}: fitness={:.2} attempts={} successes={} {:?}",
            s.fitness, s.attempts, s.successes, s.actions
        );
    }

    if signals_processed > 0 {
        let best = population
            .strategies
            .iter()
            .max_by(|a, b| a.fitness.partial_cmp(&b.fitness).unwrap())
            .unwrap();
        println!(
            "PASS: processed {signals_processed} signals, best fitness={:.2}",
            best.fitness
        );
    } else {
        println!("FAIL: no signals processed");
        std::process::exit(1);
    }
}
