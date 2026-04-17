use std::time::{Duration, Instant};

use futures::StreamExt;
use reflex_core::{Detector, ReflexExt};
use reflex_linux::AfPacketBackend;

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
    seq: u32,
    ack: u32,
    is_syn_ack: bool,
    is_rst: bool,
    is_client_hello: bool,
}

#[derive(Debug, Clone)]
struct RstSignal {
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    dst_port: u16,
    ttl_expected: u8,
    ttl_actual: u8,
    ttl_delta: i16,
    window_zero: bool,
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
    let seq = u32::from_be_bytes(raw[tcp_start + 4..tcp_start + 8].try_into().ok()?);
    let ack = u32::from_be_bytes(raw[tcp_start + 8..tcp_start + 12].try_into().ok()?);
    let tcp_flags = raw[tcp_start + 13];

    let is_syn_ack = tcp_flags & 0x12 == 0x12;
    let is_rst = tcp_flags & 0x04 != 0;

    // check for ClientHello
    let tcp_data_offset = (raw[tcp_start + 12] >> 4) as usize * 4;
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
        seq,
        ack,
        is_syn_ack,
        is_rst,
        is_client_hello,
    })
}

// --- detector ---

struct RstDetector {
    server_ttl: Option<u8>,
}

impl RstDetector {
    fn new() -> Self {
        Self { server_ttl: None }
    }
}

impl Detector for RstDetector {
    type Input = Packet;
    type Signal = RstSignal;

    fn on_packet(&mut self, pkt: Packet, emit: &mut dyn FnMut(Self::Signal)) {
        // learn server TTL from SYN+ACK
        if pkt.is_syn_ack && pkt.src_port == 443 {
            self.server_ttl = Some(pkt.ttl);
            eprintln!(
                "[detector] SYN+ACK from server, TTL baseline = {}",
                pkt.ttl
            );
        }

        // detect RST with anomalous TTL
        if pkt.is_rst && pkt.src_port == 443 {
            let window = u16::from_be_bytes([
                pkt.raw[14 + 20 + 14],
                pkt.raw[14 + 20 + 15],
            ]);

            if let Some(server_ttl) = self.server_ttl {
                let ttl_delta = pkt.ttl as i16 - server_ttl as i16;
                eprintln!(
                    "[detector] RST from :443, TTL={}, baseline={}, delta={}, window={}",
                    pkt.ttl, server_ttl, ttl_delta, window
                );

                if ttl_delta.abs() > 3 {
                    emit(RstSignal {
                        src_ip: pkt.src_ip,
                        dst_ip: pkt.dst_ip,
                        dst_port: pkt.dst_port,
                        ttl_expected: server_ttl,
                        ttl_actual: pkt.ttl,
                        ttl_delta,
                        window_zero: window == 0,
                    });
                }
            }
        }
    }

    fn on_tick(&mut self, _now: Instant, _emit: &mut dyn FnMut(Self::Signal)) {}
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
        .unwrap_or(10);

    eprintln!("[rst-det] opening AF_PACKET on {iface}, timeout {timeout_secs}s");

    let mut backend = AfPacketBackend::open(&iface, 65535).unwrap_or_else(|e| {
        eprintln!("[rst-det] FAIL: {e}");
        std::process::exit(1);
    });

    let deadline = tokio::time::Instant::now() + Duration::from_secs(timeout_secs);

    // Floor 1: detect RST injection
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
            "[rst-det] signal #{}: TTL expected={} actual={} delta={} window_zero={}",
            i + 1,
            sig.ttl_expected,
            sig.ttl_actual,
            sig.ttl_delta,
            sig.window_zero
        );
    }

    if signals.is_empty() {
        println!("FAIL: no RST injection detected");
        std::process::exit(1);
    } else {
        let all_anomalous = signals.iter().all(|s| s.ttl_delta.abs() > 3);
        let any_window_zero = signals.iter().any(|s| s.window_zero);

        if all_anomalous {
            println!(
                "PASS: detected {} RST injection(s), TTL anomaly confirmed, window_zero={}",
                signals.len(),
                any_window_zero
            );
        } else {
            println!("FAIL: RST detected but TTL not anomalous");
            std::process::exit(1);
        }
    }
}
