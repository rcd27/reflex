use std::collections::HashMap;
use std::time::{Duration, Instant};

use futures::StreamExt;
use reflex_core::{Detector, DetectorEvent, ReflexExt};
use reflex_linux::AfPacketBackend;
use smallvec::SmallVec;

// --- domain types ---

#[derive(Debug, Clone)]
struct Packet {
    raw: Vec<u8>,
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    ttl: u8,
    tcp_flags: u8,
    has_timestamps: bool,
    window: u16,
    is_syn_ack: bool,
    is_rst: bool,
    is_client_hello: bool,
}

#[derive(Debug, Clone, PartialEq)]
struct RstSignal {
    evidence: Vec<Evidence>,
    confidence: f32,
    server_ttl: u8,
    rst_ttl: u8,
    rtt_ms: Option<f64>,
    rst_after_hello_ms: Option<f64>,
    rst_window: u16,
    rst_has_timestamps: bool,
    server_has_timestamps: bool,
}

#[derive(Debug, Clone, PartialEq)]
enum Evidence {
    TtlAnomaly { delta: i16 },
    TimingAnomaly { rst_ms: f64, rtt_ms: f64 },
    MissingTimestamps,
    WindowZero,
}

// --- per-flow state ---

#[derive(Debug, Clone)]
struct FlowState {
    syn_sent_at: Option<Instant>,
    syn_ack_at: Option<Instant>,
    client_hello_at: Option<Instant>,
    server_ttl: Option<u8>,
    server_has_timestamps: bool,
    rtt: Option<Duration>,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct FlowKey {
    client_ip: [u8; 4],
    server_ip: [u8; 4],
    client_port: u16,
    server_port: u16,
}

// --- parser ---

fn parse_packet(raw: Vec<u8>) -> Option<Packet> {
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
    let window = u16::from_be_bytes([raw[tcp_start + 14], raw[tcp_start + 15]]);

    let is_syn_ack = tcp_flags & 0x12 == 0x12;
    let is_rst = tcp_flags & 0x04 != 0;

    // check TCP options for timestamps (kind=8)
    let tcp_data_offset = (raw[tcp_start + 12] >> 4) as usize * 4;
    let has_timestamps = has_tcp_timestamp(
        &raw[tcp_start + 20..tcp_start + tcp_data_offset.min(raw.len() - tcp_start)],
    );

    let payload_start = tcp_start + tcp_data_offset;
    let is_client_hello = if raw.len() > payload_start + 6 {
        raw[payload_start] == 0x16 && raw[payload_start + 5] == 0x01
    } else {
        false
    };

    Some(Packet {
        raw,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        ttl,
        tcp_flags,
        has_timestamps,
        window,
        is_syn_ack,
        is_rst,
        is_client_hello,
    })
}

fn has_tcp_timestamp(options: &[u8]) -> bool {
    let mut pos = 0;
    while pos < options.len() {
        let kind = options[pos];
        if kind == 0 {
            break; // end of options
        }
        if kind == 1 {
            pos += 1; // NOP
            continue;
        }
        if pos + 1 >= options.len() {
            break;
        }
        let len = options[pos + 1] as usize;
        if kind == 8 {
            return true; // timestamp option
        }
        if len < 2 {
            break;
        }
        pos += len;
    }
    false
}

// --- detector ---

struct RstDetector {
    flows: HashMap<FlowKey, FlowState>,
}

impl RstDetector {
    fn new() -> Self {
        Self {
            flows: HashMap::new(),
        }
    }

    fn flow_key_from_client(pkt: &Packet) -> FlowKey {
        FlowKey {
            client_ip: pkt.src_ip,
            server_ip: pkt.dst_ip,
            client_port: pkt.src_port,
            server_port: pkt.dst_port,
        }
    }

    fn flow_key_from_server(pkt: &Packet) -> FlowKey {
        FlowKey {
            client_ip: pkt.dst_ip,
            server_ip: pkt.src_ip,
            client_port: pkt.dst_port,
            server_port: pkt.src_port,
        }
    }
}

impl Detector for RstDetector {
    type Input = Packet;
    type Signal = RstSignal;

    fn step(mut self, event: DetectorEvent<Packet>) -> (Self, SmallVec<[RstSignal; 2]>) {
        let mut signals = SmallVec::new();

        match event {
            DetectorEvent::Packet { input: pkt, at: now } => {
                // SYN from client (flags = 0x02, only SYN set)
                if pkt.tcp_flags & 0x3f == 0x02 && pkt.dst_port == 443 {
                    let key = Self::flow_key_from_client(&pkt);
                    self.flows.insert(
                        key,
                        FlowState {
                            syn_sent_at: Some(now),
                            syn_ack_at: None,
                            client_hello_at: None,
                            server_ttl: None,
                            server_has_timestamps: false,
                            rtt: None,
                        },
                    );
                }

                // SYN+ACK from server
                if pkt.is_syn_ack && pkt.src_port == 443 {
                    let key = Self::flow_key_from_server(&pkt);
                    if let Some(flow) = self.flows.get_mut(&key) {
                        flow.syn_ack_at = Some(now);
                        flow.server_ttl = Some(pkt.ttl);
                        flow.server_has_timestamps = pkt.has_timestamps;
                        if let Some(syn_at) = flow.syn_sent_at {
                            flow.rtt = Some(now.duration_since(syn_at));
                        }
                        eprintln!(
                            "[detector] SYN+ACK: TTL={}, timestamps={}, RTT={:.1}ms",
                            pkt.ttl,
                            pkt.has_timestamps,
                            flow.rtt.map(|r| r.as_secs_f64() * 1000.0).unwrap_or(0.0)
                        );
                    }
                }

                // ClientHello
                if pkt.is_client_hello && pkt.dst_port == 443 {
                    let key = Self::flow_key_from_client(&pkt);
                    if let Some(flow) = self.flows.get_mut(&key) {
                        flow.client_hello_at = Some(now);
                    }
                }

                // RST from server direction
                if pkt.is_rst && pkt.src_port == 443 {
                    let key = Self::flow_key_from_server(&pkt);
                    if let Some(flow) = self.flows.get(&key) {
                        let server_ttl = flow.server_ttl.unwrap_or(0);
                        let ttl_delta = pkt.ttl as i16 - server_ttl as i16;

                        let rst_after_hello_ms = flow
                            .client_hello_at
                            .map(|t| now.duration_since(t).as_secs_f64() * 1000.0);

                        let rtt_ms = flow.rtt.map(|r| r.as_secs_f64() * 1000.0);

                        // collect evidence
                        let mut evidence = Vec::new();
                        let mut confidence: f32 = 0.0;

                        // evidence 1: TTL anomaly
                        if ttl_delta.abs() > 3 {
                            evidence.push(Evidence::TtlAnomaly { delta: ttl_delta });
                            confidence += 0.4;
                        }

                        // evidence 2: timing — RST faster than half RTT
                        if let (Some(rst_ms), Some(rtt)) = (rst_after_hello_ms, rtt_ms) {
                            if rtt > 0.0 && rst_ms < rtt * 0.5 {
                                evidence.push(Evidence::TimingAnomaly {
                                    rst_ms,
                                    rtt_ms: rtt,
                                });
                                confidence += 0.5;
                            }
                        }

                        // evidence 3: RST missing timestamps but server had them
                        if flow.server_has_timestamps && !pkt.has_timestamps {
                            evidence.push(Evidence::MissingTimestamps);
                            confidence += 0.3;
                        }

                        // evidence 4: window zero
                        if pkt.window == 0 {
                            evidence.push(Evidence::WindowZero);
                            confidence += 0.2;
                        }

                        eprintln!(
                            "[detector] RST: TTL={} (server={}), window={}, timestamps={}, \
                             rst_after_hello={:.1?}ms, rtt={:.1?}ms, evidence={}, confidence={:.2}",
                            pkt.ttl,
                            server_ttl,
                            pkt.window,
                            pkt.has_timestamps,
                            rst_after_hello_ms,
                            rtt_ms,
                            evidence.len(),
                            confidence
                        );

                        if !evidence.is_empty() {
                            signals.push(RstSignal {
                                evidence,
                                confidence: confidence.min(1.0),
                                server_ttl,
                                rst_ttl: pkt.ttl,
                                rtt_ms,
                                rst_after_hello_ms,
                                rst_window: pkt.window,
                                rst_has_timestamps: pkt.has_timestamps,
                                server_has_timestamps: flow.server_has_timestamps,
                            });
                        }
                    }
                }
            }
            DetectorEvent::Tick { at: now } => {
                // cleanup flows older than 30s
                self.flows.retain(|_, f| {
                    f.syn_sent_at
                        .map(|t| now.duration_since(t) < Duration::from_secs(30))
                        .unwrap_or(false)
                });
            }
        }

        (self, signals)
    }
}

// --- main ---

#[tokio::main]
async fn main() {
    let iface = std::env::args().nth(1).unwrap_or_else(|| "br0".to_string());

    let timeout_secs: u64 = std::env::args()
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(10);

    eprintln!("[rst-det] opening AF_PACKET on {iface}, timeout {timeout_secs}s");

    let mut backend = AfPacketBackend::open(&iface, 65535).unwrap_or_else(|e| {
        eprintln!("[rst-det] FAIL: {e}");
        std::process::exit(1);
    });

    let deadline = tokio::time::Instant::now() + Duration::from_secs(timeout_secs);

    let signals: Vec<RstSignal> = backend
        .packets()
        .filter_map(|raw| async move { parse_packet(raw) })
        .detect(RstDetector::new())
        .take_until(tokio::time::sleep_until(deadline))
        .collect()
        .await;

    eprintln!("[rst-det] detected {} RST injection signals", signals.len());

    for (i, sig) in signals.iter().enumerate() {
        eprintln!(
            "[rst-det] signal #{}: confidence={:.2} evidence={:?}",
            i + 1,
            sig.confidence,
            sig.evidence
        );
    }

    if signals.is_empty() {
        println!("FAIL: no RST injection detected");
        std::process::exit(1);
    } else {
        println!(
            "PASS: detected {} RST injection(s), max confidence={:.2}",
            signals.len(),
            signals.iter().map(|s| s.confidence).fold(0.0f32, f32::max)
        );
    }
}
