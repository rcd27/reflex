use std::collections::HashMap;
use std::time::{Duration, Instant};

use futures::StreamExt;
use reflex_core::{Detector, ReflexExt};
use reflex_linux::AfPacketBackend;

// --- Geneva primitives (AF_PACKET subset) ---

#[derive(Debug, Clone)]
enum TamperOp {
    ShortTtl { ttl: u8 },
    WrongChecksum,
    TcpMd5,
    MultiDisorder { chunk_count: u8 },
}

#[derive(Debug, Clone)]
struct Strategy {
    tamper: TamperOp,
    duplicate_count: u8,
    fitness: f32,
    attempts: u32,
    successes: u32,
}

impl Strategy {
    fn describe(&self) -> String {
        format!(
            "{:?} x{} (fitness={:.2}, {}/{})",
            self.tamper, self.duplicate_count, self.fitness, self.successes, self.attempts
        )
    }
}

// --- population ---

struct Population {
    strategies: Vec<Strategy>,
    current: usize,
    generation: u32,
}

impl Population {
    fn new() -> Self {
        Self {
            strategies: vec![
                Strategy {
                    tamper: TamperOp::ShortTtl { ttl: 3 },
                    duplicate_count: 1,
                    fitness: 0.0,
                    attempts: 0,
                    successes: 0,
                },
                Strategy {
                    tamper: TamperOp::ShortTtl { ttl: 1 },
                    duplicate_count: 3,
                    fitness: 0.0,
                    attempts: 0,
                    successes: 0,
                },
                Strategy {
                    tamper: TamperOp::WrongChecksum,
                    duplicate_count: 1,
                    fitness: 0.0,
                    attempts: 0,
                    successes: 0,
                },
                Strategy {
                    tamper: TamperOp::TcpMd5,
                    duplicate_count: 1,
                    fitness: 0.0,
                    attempts: 0,
                    successes: 0,
                },
                Strategy {
                    tamper: TamperOp::MultiDisorder { chunk_count: 3 },
                    duplicate_count: 1,
                    fitness: 0.0,
                    attempts: 0,
                    successes: 0,
                },
            ],
            current: 0,
            generation: 0,
        }
    }

    fn current(&self) -> &Strategy {
        &self.strategies[self.current]
    }

    fn report_success(&mut self) {
        let s = &mut self.strategies[self.current];
        s.attempts += 1;
        s.successes += 1;
        s.fitness = s.successes as f32 / s.attempts as f32;
        eprintln!("[geneva] SUCCESS — {}", s.describe());
    }

    fn report_failure(&mut self) {
        let s = &mut self.strategies[self.current];
        s.attempts += 1;
        s.fitness = s.successes as f32 / s.attempts as f32;
        eprintln!("[geneva] FAILED — {}", s.describe());

        // after 2 attempts, move to next strategy
        if s.attempts >= 2 {
            self.current = (self.current + 1) % self.strategies.len();
            self.generation += 1;
            eprintln!(
                "[geneva] gen {} — switching to: {}",
                self.generation,
                self.strategies[self.current].describe()
            );
        }
    }

    fn print_summary(&self) {
        eprintln!("[geneva] === Population summary ===");
        for (i, s) in self.strategies.iter().enumerate() {
            let marker = if i == self.current { " ← current" } else { "" };
            eprintln!("[geneva]   #{i}: {}{marker}", s.describe());
        }
    }
}

// --- signals ---

#[derive(Debug, Clone)]
enum Signal {
    SynAckSeen {
        flow: FlowKey,
        rtt: Duration,
    },
    ClientHelloSeen {
        flow: FlowKey,
        raw: Vec<u8>,
        ip_start: usize,
        tcp_start: usize,
        payload_start: usize,
    },
    ServerHelloSeen {
        flow: FlowKey,
    },
    RstInjection {
        flow: FlowKey,
        confidence: f32,
    },
    Timeout {
        flow: FlowKey,
    },
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct FlowKey {
    client_ip: [u8; 4],
    server_ip: [u8; 4],
    client_port: u16,
    server_port: u16,
}

// --- detector ---

struct FlowState {
    syn_at: Instant,
    syn_ack_at: Option<Instant>,
    hello_at: Option<Instant>,
    rtt: Option<Duration>,
    server_ttl: Option<u8>,
    server_has_timestamps: bool,
    strategy_applied: bool,
    // store last SYN packet for building fakes
    last_client_packet: Option<Vec<u8>>,
}

struct LiveDetector {
    flows: HashMap<FlowKey, FlowState>,
}

impl LiveDetector {
    fn new() -> Self {
        Self {
            flows: HashMap::new(),
        }
    }
}

#[derive(Debug, Clone)]
struct ParsedPacket {
    raw: Vec<u8>,
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    ttl: u8,
    tcp_flags: u8,
    has_timestamps: bool,
    is_syn: bool,
    is_syn_ack: bool,
    is_rst: bool,
    is_client_hello: bool,
    is_server_hello: bool,
    ip_start: usize,
    tcp_start: usize,
    payload_start: usize,
}

impl Detector for LiveDetector {
    type Input = ParsedPacket;
    type Signal = Signal;

    fn on_packet(&mut self, pkt: ParsedPacket, emit: &mut dyn FnMut(Self::Signal)) {
        let now = Instant::now();

        // SYN from client
        if pkt.is_syn && pkt.dst_port == 443 {
            let key = FlowKey {
                client_ip: pkt.src_ip,
                server_ip: pkt.dst_ip,
                client_port: pkt.src_port,
                server_port: pkt.dst_port,
            };
            self.flows.insert(key, FlowState {
                syn_at: now,
                syn_ack_at: None,
                hello_at: None,
                rtt: None,
                server_ttl: None,
                server_has_timestamps: false,
                strategy_applied: false,
                last_client_packet: None,
            });
        }

        // SYN+ACK from server
        if pkt.is_syn_ack && pkt.src_port == 443 {
            let key = FlowKey {
                client_ip: pkt.dst_ip,
                server_ip: pkt.src_ip,
                client_port: pkt.dst_port,
                server_port: pkt.src_port,
            };
            if let Some(flow) = self.flows.get_mut(&key) {
                flow.syn_ack_at = Some(now);
                flow.server_ttl = Some(pkt.ttl);
                flow.server_has_timestamps = pkt.has_timestamps;
                flow.rtt = Some(now.duration_since(flow.syn_at));

                let rtt = flow.rtt.unwrap();
                emit(Signal::SynAckSeen {
                    flow: key,
                    rtt,
                });
            }
        }

        // ClientHello — track timing
        if pkt.is_client_hello && pkt.dst_port == 443 {
            let key = FlowKey {
                client_ip: pkt.src_ip,
                server_ip: pkt.dst_ip,
                client_port: pkt.src_port,
                server_port: pkt.dst_port,
            };
            if let Some(flow) = self.flows.get_mut(&key) {
                if flow.hello_at.is_none() {
                    flow.hello_at = Some(now);
                    flow.last_client_packet = Some(pkt.raw.clone());
                    emit(Signal::ClientHelloSeen {
                        flow: key,
                        raw: pkt.raw.clone(),
                        ip_start: pkt.ip_start,
                        tcp_start: pkt.tcp_start,
                        payload_start: pkt.payload_start,
                    });
                }
            }
        }

        // ServerHello — SUCCESS
        if pkt.is_server_hello && pkt.src_port == 443 {
            let key = FlowKey {
                client_ip: pkt.dst_ip,
                server_ip: pkt.src_ip,
                client_port: pkt.dst_port,
                server_port: pkt.src_port,
            };
            if let Some(flow) = self.flows.remove(&key) {
                if flow.strategy_applied {
                    emit(Signal::ServerHelloSeen { flow: key });
                }
            }
        }

        // RST — check if injection
        if pkt.is_rst && pkt.src_port == 443 {
            let key = FlowKey {
                client_ip: pkt.dst_ip,
                server_ip: pkt.src_ip,
                client_port: pkt.dst_port,
                server_port: pkt.src_port,
            };
            if let Some(flow) = self.flows.remove(&key) {
                let mut confidence: f32 = 0.0;

                // timing check
                if let (Some(hello_at), Some(rtt)) = (flow.hello_at, flow.rtt) {
                    let rst_ms = now.duration_since(hello_at).as_secs_f64() * 1000.0;
                    let rtt_ms = rtt.as_secs_f64() * 1000.0;
                    if rtt_ms > 0.0 && rst_ms < rtt_ms * 0.5 {
                        confidence += 0.5;
                    }
                }

                // timestamps check
                if flow.server_has_timestamps && !pkt.has_timestamps {
                    confidence += 0.3;
                }

                if confidence > 0.0 {
                    emit(Signal::RstInjection {
                        flow: key,
                        confidence,
                    });
                }
            }
        }
    }

    fn on_tick(&mut self, now: Instant, emit: &mut dyn FnMut(Self::Signal)) {
        let expired: Vec<FlowKey> = self.flows.iter()
            .filter(|(_, f)| {
                f.strategy_applied
                    && f.hello_at.is_some()
                    && now.duration_since(f.hello_at.unwrap()) > Duration::from_secs(5)
            })
            .map(|(k, _)| k.clone())
            .collect();

        for key in expired {
            self.flows.remove(&key);
            emit(Signal::Timeout { flow: key });
        }
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
    let tcp_data_offset = (raw[tcp_start + 12] >> 4) as usize * 4;
    let payload_start = tcp_start + tcp_data_offset;

    let has_timestamps = has_tcp_timestamp(
        &raw[tcp_start + 20..tcp_start + tcp_data_offset.min(raw.len() - tcp_start)],
    );

    let is_syn = tcp_flags & 0x3f == 0x02;
    let is_syn_ack = tcp_flags & 0x12 == 0x12;
    let is_rst = tcp_flags & 0x04 != 0;

    let is_client_hello = if raw.len() > payload_start + 6 {
        raw[payload_start] == 0x16 && raw[payload_start + 5] == 0x01
    } else {
        false
    };

    let is_server_hello = if raw.len() > payload_start + 6 {
        raw[payload_start] == 0x16 && raw[payload_start + 5] == 0x02
    } else {
        false
    };

    Some(ParsedPacket {
        raw,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        ttl,
        tcp_flags,
        has_timestamps,
        is_syn,
        is_syn_ack,
        is_rst,
        is_client_hello,
        is_server_hello,
        ip_start,
        tcp_start,
        payload_start,
    })
}

fn has_tcp_timestamp(options: &[u8]) -> bool {
    let mut pos = 0;
    while pos < options.len() {
        let kind = options[pos];
        if kind == 0 { break; }
        if kind == 1 { pos += 1; continue; }
        if pos + 1 >= options.len() { break; }
        let len = options[pos + 1] as usize;
        if kind == 8 { return true; }
        if len < 2 { break; }
        pos += len;
    }
    false
}

// --- inject logic ---

fn inject_strategy(
    injector: &reflex_linux::Injector,
    strategy: &Strategy,
    client_hello_raw: &[u8],
    ip_start: usize,
    tcp_start: usize,
    payload_start: usize,
) {
    let payload_len = client_hello_raw.len() - payload_start;
    if payload_len < 4 {
        return;
    }

    for dup in 0..strategy.duplicate_count {
        match &strategy.tamper {
            TamperOp::ShortTtl { ttl } => {
                let fake = build_fake(client_hello_raw, ip_start, tcp_start, payload_start, *ttl, false);
                let _ = injector.send(&fake);
            }
            TamperOp::WrongChecksum => {
                let mut fake = build_fake(client_hello_raw, ip_start, tcp_start, payload_start, 3, false);
                // corrupt TCP checksum
                let tcp_out = 14 + 20;
                if fake.len() > tcp_out + 18 {
                    fake[tcp_out + 16] ^= 0xFF;
                    fake[tcp_out + 17] ^= 0xFF;
                }
                let _ = injector.send(&fake);
            }
            TamperOp::TcpMd5 => {
                let fake = build_fake_md5(client_hello_raw, ip_start, tcp_start, payload_start);
                let _ = injector.send(&fake);
            }
            TamperOp::MultiDisorder { chunk_count } => {
                let seq = u32::from_be_bytes(
                    client_hello_raw[tcp_start + 4..tcp_start + 8].try_into().unwrap(),
                );
                let chunk_size = payload_len / *chunk_count as usize;

                for i in (0..*chunk_count).rev() {
                    let start = i as usize * chunk_size;
                    let end = if i == *chunk_count - 1 {
                        payload_len
                    } else {
                        (i as usize + 1) * chunk_size
                    };
                    let chunk = &client_hello_raw[payload_start + start..payload_start + end];
                    let fake = build_fake_chunk(
                        client_hello_raw, ip_start, tcp_start,
                        seq + start as u32, chunk, 3,
                    );
                    let _ = injector.send(&fake);
                }
            }
        }
    }
}

fn build_fake(
    orig: &[u8], ip_start: usize, tcp_start: usize, payload_start: usize,
    ttl: u8, _corrupt_checksum: bool,
) -> Vec<u8> {
    let payload = &orig[payload_start..];
    let seq = u32::from_be_bytes(orig[tcp_start + 4..tcp_start + 8].try_into().unwrap());
    build_fake_chunk(orig, ip_start, tcp_start, seq, payload, ttl)
}

fn build_fake_md5(
    orig: &[u8], ip_start: usize, tcp_start: usize, payload_start: usize,
) -> Vec<u8> {
    let payload = &orig[payload_start..];
    let seq = u32::from_be_bytes(orig[tcp_start + 4..tcp_start + 8].try_into().unwrap());
    let tcp_header_len = 40; // 20 + MD5(18) + NOP(2)
    let total = 14 + 20 + tcp_header_len + payload.len();
    let mut pkt = vec![0u8; total];

    pkt[0..14].copy_from_slice(&orig[0..14]);
    let ip_out = 14;
    pkt[ip_out] = 0x45;
    let ip_total: u16 = (20 + tcp_header_len + payload.len()) as u16;
    pkt[ip_out + 2..ip_out + 4].copy_from_slice(&ip_total.to_be_bytes());
    pkt[ip_out + 6..ip_out + 8].copy_from_slice(&[0x40, 0x00]);
    pkt[ip_out + 8] = 3;
    pkt[ip_out + 9] = 6;
    pkt[ip_out + 12..ip_out + 16].copy_from_slice(&orig[ip_start + 12..ip_start + 16]);
    pkt[ip_out + 16..ip_out + 20].copy_from_slice(&orig[ip_start + 16..ip_start + 20]);
    let csum = ip_checksum(&pkt[ip_out..ip_out + 20]);
    pkt[ip_out + 10..ip_out + 12].copy_from_slice(&csum.to_be_bytes());

    let tcp_out = 34;
    pkt[tcp_out..tcp_out + 2].copy_from_slice(&orig[tcp_start..tcp_start + 2]);
    pkt[tcp_out + 2..tcp_out + 4].copy_from_slice(&orig[tcp_start + 2..tcp_start + 4]);
    pkt[tcp_out + 4..tcp_out + 8].copy_from_slice(&seq.to_be_bytes());
    pkt[tcp_out + 8..tcp_out + 12].copy_from_slice(&orig[tcp_start + 8..tcp_start + 12]);
    pkt[tcp_out + 12] = (tcp_header_len as u8 / 4) << 4;
    pkt[tcp_out + 13] = 0x18;
    pkt[tcp_out + 14..tcp_out + 16].copy_from_slice(&orig[tcp_start + 14..tcp_start + 16]);
    pkt[tcp_out + 20] = 19; // TCP MD5 kind
    pkt[tcp_out + 21] = 18; // length
    pkt[tcp_out + 38] = 1; // NOP
    pkt[tcp_out + 39] = 1; // NOP
    pkt[tcp_out + tcp_header_len..].copy_from_slice(payload);
    let tcp_csum = tcp_checksum(
        &pkt[ip_out + 12..ip_out + 16],
        &pkt[ip_out + 16..ip_out + 20],
        &pkt[tcp_out..],
    );
    pkt[tcp_out + 16..tcp_out + 18].copy_from_slice(&tcp_csum.to_be_bytes());
    pkt
}

fn build_fake_chunk(
    orig: &[u8], ip_start: usize, tcp_start: usize,
    seq: u32, payload: &[u8], ttl: u8,
) -> Vec<u8> {
    let total = 14 + 20 + 20 + payload.len();
    let mut pkt = vec![0u8; total];
    pkt[0..14].copy_from_slice(&orig[0..14]);
    let ip_out = 14;
    pkt[ip_out] = 0x45;
    let ip_total: u16 = (20 + 20 + payload.len()) as u16;
    pkt[ip_out + 2..ip_out + 4].copy_from_slice(&ip_total.to_be_bytes());
    pkt[ip_out + 4..ip_out + 6].copy_from_slice(&[0xDE, 0xAD]);
    pkt[ip_out + 6..ip_out + 8].copy_from_slice(&[0x40, 0x00]);
    pkt[ip_out + 8] = ttl;
    pkt[ip_out + 9] = 6;
    pkt[ip_out + 12..ip_out + 16].copy_from_slice(&orig[ip_start + 12..ip_start + 16]);
    pkt[ip_out + 16..ip_out + 20].copy_from_slice(&orig[ip_start + 16..ip_start + 20]);
    let csum = ip_checksum(&pkt[ip_out..ip_out + 20]);
    pkt[ip_out + 10..ip_out + 12].copy_from_slice(&csum.to_be_bytes());
    let tcp_out = 34;
    pkt[tcp_out..tcp_out + 2].copy_from_slice(&orig[tcp_start..tcp_start + 2]);
    pkt[tcp_out + 2..tcp_out + 4].copy_from_slice(&orig[tcp_start + 2..tcp_start + 4]);
    pkt[tcp_out + 4..tcp_out + 8].copy_from_slice(&seq.to_be_bytes());
    pkt[tcp_out + 8..tcp_out + 12].copy_from_slice(&orig[tcp_start + 8..tcp_start + 12]);
    pkt[tcp_out + 12] = 0x50;
    pkt[tcp_out + 13] = 0x18;
    pkt[tcp_out + 14..tcp_out + 16].copy_from_slice(&orig[tcp_start + 14..tcp_start + 16]);
    pkt[tcp_out + 20..].copy_from_slice(payload);
    let tcp_csum = tcp_checksum(
        &pkt[ip_out + 12..ip_out + 16],
        &pkt[ip_out + 16..ip_out + 20],
        &pkt[tcp_out..],
    );
    pkt[tcp_out + 16..tcp_out + 18].copy_from_slice(&tcp_csum.to_be_bytes());
    pkt
}

fn ip_checksum(h: &[u8]) -> u16 {
    let mut s: u32 = 0;
    for c in h.chunks(2) {
        s += if c.len() == 2 { u16::from_be_bytes([c[0], c[1]]) as u32 } else { (c[0] as u32) << 8 };
    }
    while s >> 16 != 0 { s = (s & 0xffff) + (s >> 16); }
    !(s as u16)
}

fn tcp_checksum(src: &[u8], dst: &[u8], seg: &[u8]) -> u16 {
    let mut s: u32 = 0;
    for c in src.chunks(2) { s += u16::from_be_bytes([c[0], c[1]]) as u32; }
    for c in dst.chunks(2) { s += u16::from_be_bytes([c[0], c[1]]) as u32; }
    s += 6;
    s += seg.len() as u32;
    for c in seg.chunks(2) {
        s += if c.len() == 2 { u16::from_be_bytes([c[0], c[1]]) as u32 } else { (c[0] as u32) << 8 };
    }
    while s >> 16 != 0 { s = (s & 0xffff) + (s >> 16); }
    !(s as u16)
}

// --- main ---

#[tokio::main]
async fn main() {
    let iface = std::env::args().nth(1).unwrap_or_else(|| "br0".to_string());
    let timeout_secs: u64 = std::env::args().nth(2).and_then(|s| s.parse().ok()).unwrap_or(30);
    let domain = std::env::args().nth(3).unwrap_or_else(|| "rutracker.org".to_string());

    eprintln!("[geneva] live Geneva on {iface}, domain={domain}, timeout={timeout_secs}s");

    let backend = AfPacketBackend::open(&iface, 65535).unwrap_or_else(|e| {
        eprintln!("[geneva] FAIL: {e}");
        std::process::exit(1);
    });

    let (stream, injector) = backend.split();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(timeout_secs);

    let mut population = Population::new();
    let mut pending_hello: HashMap<FlowKey, Vec<u8>> = HashMap::new();

    eprintln!("[geneva] initial: {}", population.current().describe());

    let mut pipeline = stream
        .filter_map(|raw| async move { parse_packet(raw) })
        .detect(LiveDetector::new());

    tokio::pin!(pipeline);

    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }

        match tokio::time::timeout(Duration::from_millis(100), pipeline.next()).await {
            Ok(Some(signal)) => match signal {
                Signal::SynAckSeen { flow, rtt } => {
                    eprintln!(
                        "[geneva] SYN+ACK, RTT={:.1}ms",
                        rtt.as_secs_f64() * 1000.0
                    );
                }
                Signal::ClientHelloSeen { flow: _, raw, ip_start, tcp_start, payload_start } => {
                    eprintln!(
                        "[geneva] ClientHello — injecting: {}",
                        population.current().describe()
                    );
                    inject_strategy(
                        &injector,
                        population.current(),
                        &raw, ip_start, tcp_start, payload_start,
                    );
                    eprintln!("[geneva] injected, waiting for result...");
                }
                Signal::ServerHelloSeen { flow } => {
                    eprintln!("[geneva] ServerHello! Strategy WORKED!");
                    population.report_success();
                }
                Signal::RstInjection { flow, confidence } => {
                    eprintln!("[geneva] RST injection (confidence={:.2})", confidence);
                    population.report_failure();
                }
                Signal::Timeout { flow } => {
                    eprintln!("[geneva] timeout");
                    population.report_failure();
                }
            },
            Ok(None) => break,
            Err(_) => continue,
        }

        // check if detector has a ClientHello we need to inject for
        // (we do this by re-reading pending flows from detector state —
        //  but since we can't access detector internals from here,
        //  we use a simpler approach: inject on every SynAckSeen)
    }

    eprintln!("");
    population.print_summary();

    let best = population.strategies.iter()
        .max_by(|a, b| a.fitness.partial_cmp(&b.fitness).unwrap())
        .unwrap();

    if best.successes > 0 {
        println!("PASS: best strategy: {} — ТСПУ bypassed!", best.describe());
    } else {
        println!("RESULT: no strategy succeeded (fitness=0). ТСПУ not bypassed on AF_PACKET.");
        println!("NOTE: AF_PACKET cannot delay original ClientHello. XDP backend needed for full Geneva.");
    }
}
