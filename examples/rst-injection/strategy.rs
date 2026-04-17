use std::time::{Duration, Instant};

use futures::StreamExt;
use reflex_core::{Detector, ReflexExt};
use reflex_linux::AfPacketBackend;

// --- types ---

#[derive(Debug, Clone)]
struct Packet {
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
    seq: u32,
    ack: u32,
    sni: Option<String>,
    is_syn_ack: bool,
    is_rst: bool,
    is_client_hello: bool,
}

#[derive(Debug, Clone)]
enum Signal {
    RstInjection {
        domain: String,
        ttl_delta: i16,
    },
    ClientHello {
        domain: String,
        flow: FlowId,
        raw: Vec<u8>,
        ip_start: usize,
        tcp_start: usize,
        payload_start: usize,
    },
}

#[derive(Debug, Clone)]
struct FlowId {
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
}

#[derive(Debug, Clone)]
enum Assessment {
    NeedsDesync { domain: String, signal: Signal },
    Clean,
}

#[derive(Debug, Clone)]
enum Command {
    MultiDisorder {
        original: Vec<u8>,
        ip_start: usize,
        tcp_start: usize,
        payload_start: usize,
        flow: FlowId,
    },
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

    Some(Packet {
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
        seq,
        ack,
        sni,
        is_syn_ack,
        is_rst,
        is_client_hello,
    })
}

fn extract_sni(tls: &[u8]) -> Option<String> {
    // TLS record: type(1) + version(2) + length(2) + handshake
    // Handshake: type(1) + length(3) + version(2) + random(32) + session_id(var) + ...
    if tls.len() < 44 {
        return None;
    }

    let handshake_start = 5;
    let session_id_offset = handshake_start + 1 + 3 + 2 + 32;
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
            // SNI extension
            if pos + 5 <= tls.len() && pos + 5 <= pos + ext_len {
                let name_len =
                    u16::from_be_bytes([tls[pos + 3], tls[pos + 4]]) as usize;
                let name_start = pos + 5;
                if name_start + name_len <= tls.len() {
                    return String::from_utf8(tls[name_start..name_start + name_len].to_vec())
                        .ok();
                }
            }
            return None;
        }

        pos += ext_len;
    }

    None
}

// --- detector: emits both RST signals and ClientHello events ---

struct DualDetector {
    server_ttl: Option<u8>,
    blocked_domains: Vec<String>,
}

impl DualDetector {
    fn new(blocked_domains: Vec<String>) -> Self {
        Self {
            server_ttl: None,
            blocked_domains,
        }
    }
}

impl Detector for DualDetector {
    type Input = Packet;
    type Signal = Signal;

    fn on_packet(&mut self, pkt: Packet, emit: &mut dyn FnMut(Self::Signal)) {
        if pkt.is_syn_ack && pkt.src_port == 443 {
            self.server_ttl = Some(pkt.ttl);
        }

        // emit RST injection signal
        if pkt.is_rst && pkt.src_port == 443 {
            if let (Some(server_ttl), Some(ref domain)) = (self.server_ttl, &pkt.sni) {
                let ttl_delta = pkt.ttl as i16 - server_ttl as i16;
                if ttl_delta.abs() > 3 {
                    emit(Signal::RstInjection {
                        domain: domain.clone(),
                        ttl_delta,
                    });
                }
            }
        }

        // emit ClientHello for domains that need desync
        if pkt.is_client_hello {
            if let Some(ref domain) = pkt.sni {
                if self.blocked_domains.iter().any(|d| d == domain) {
                    eprintln!("[strategy] ClientHello for blocked domain: {domain}");
                    emit(Signal::ClientHello {
                        domain: domain.clone(),
                        flow: FlowId {
                            src_ip: pkt.src_ip,
                            dst_ip: pkt.dst_ip,
                            src_port: pkt.src_port,
                            dst_port: pkt.dst_port,
                        },
                        raw: pkt.raw.clone(),
                        ip_start: pkt.ip_start,
                        tcp_start: pkt.tcp_start,
                        payload_start: pkt.payload_start,
                    });
                }
            }
        }
    }

    fn on_tick(&mut self, _now: Instant, _emit: &mut dyn FnMut(Self::Signal)) {}
}

// --- multi-disorder injection ---

fn execute_multi_disorder(injector: &reflex_linux::Injector, cmd: &Command) {
    let Command::MultiDisorder {
        original,
        ip_start,
        tcp_start,
        payload_start,
        flow,
    } = cmd;

    let payload_len = original.len() - payload_start;
    if payload_len < 10 {
        eprintln!("[strategy] payload too short for multi-disorder");
        return;
    }

    // split payload into 3 chunks, send as fake packets with:
    // - short TTL (won't reach server, but ТСПУ sees them)
    // - garbled SNI
    // - out of order (disorder)

    let seq = u32::from_be_bytes(
        original[*tcp_start + 4..*tcp_start + 8]
            .try_into()
            .unwrap(),
    );

    let chunk_size = payload_len / 3;
    let chunks = [
        (0, chunk_size),
        (chunk_size, chunk_size * 2),
        (chunk_size * 2, payload_len),
    ];

    // send in disorder order: chunk 2, chunk 0, chunk 1
    let disorder_order = [1, 2, 0];

    for (i, &chunk_idx) in disorder_order.iter().enumerate() {
        let (start, end) = chunks[chunk_idx];
        let chunk_data = &original[*payload_start + start..*payload_start + end];

        let fake = build_fake_packet(
            original,
            *ip_start,
            *tcp_start,
            seq + start as u32,
            chunk_data,
            3, // TTL = 3, won't reach server
        );

        if let Err(e) = injector.send(&fake) {
            eprintln!("[strategy] inject fake #{} failed: {e}", i + 1);
        } else {
            eprintln!(
                "[strategy] injected fake #{} (chunk {chunk_idx}, offset {start}, {} bytes, TTL=3)",
                i + 1,
                chunk_data.len()
            );
        }
    }

    eprintln!("[strategy] multi-disorder complete: 3 fakes injected");
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
    let ip_header_len = 20;
    let total_len = 14 + ip_header_len + tcp_header_len + payload.len();
    let mut pkt = vec![0u8; total_len];

    // ethernet: same as original (same direction)
    pkt[0..14].copy_from_slice(&original[0..14]);

    // IP header
    let ip_out = 14;
    pkt[ip_out] = 0x45;
    let ip_total: u16 = (ip_header_len + tcp_header_len + payload.len()) as u16;
    pkt[ip_out + 2..ip_out + 4].copy_from_slice(&ip_total.to_be_bytes());
    pkt[ip_out + 4..ip_out + 6].copy_from_slice(&[0xDE, 0xAD]); // identification
    pkt[ip_out + 6..ip_out + 8].copy_from_slice(&[0x40, 0x00]); // DF
    pkt[ip_out + 8] = ttl;
    pkt[ip_out + 9] = 6; // TCP
    // src/dst IP from original
    pkt[ip_out + 12..ip_out + 16].copy_from_slice(&original[ip_start + 12..ip_start + 16]);
    pkt[ip_out + 16..ip_out + 20].copy_from_slice(&original[ip_start + 16..ip_start + 20]);
    // IP checksum
    let csum = ip_checksum(&pkt[ip_out..ip_out + ip_header_len]);
    pkt[ip_out + 10..ip_out + 12].copy_from_slice(&csum.to_be_bytes());

    // TCP header
    let tcp_out = 14 + ip_header_len;
    // src/dst port from original
    pkt[tcp_out..tcp_out + 2].copy_from_slice(&original[tcp_start..tcp_start + 2]);
    pkt[tcp_out + 2..tcp_out + 4].copy_from_slice(&original[tcp_start + 2..tcp_start + 4]);
    // seq
    pkt[tcp_out + 4..tcp_out + 8].copy_from_slice(&seq.to_be_bytes());
    // ack from original
    pkt[tcp_out + 8..tcp_out + 12].copy_from_slice(&original[tcp_start + 8..tcp_start + 12]);
    // data offset = 5, flags = PSH+ACK
    pkt[tcp_out + 12] = 0x50;
    pkt[tcp_out + 13] = 0x18;
    // window from original
    pkt[tcp_out + 14..tcp_out + 16].copy_from_slice(&original[tcp_start + 14..tcp_start + 16]);

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
        .unwrap_or(10);

    // domains to protect with desync
    let blocked_domains = vec!["testserver.local".to_string()];

    eprintln!("[strategy] multi-disorder strategy on {iface}, timeout {timeout_secs}s");
    eprintln!("[strategy] protecting domains: {blocked_domains:?}");

    let backend = AfPacketBackend::open(&iface, 65535).unwrap_or_else(|e| {
        eprintln!("[strategy] FAIL: {e}");
        std::process::exit(1);
    });

    let (stream, injector) = backend.split();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(timeout_secs);

    let mut desync_count = 0u32;

    // Full pipeline: detect → assess → react
    let mut pipeline = stream
        .filter_map(|raw| async move { parse_packet(raw) })
        .detect(DualDetector::new(blocked_domains))
        // Floor 2: assess
        .filter_map(|signal| async move {
            match &signal {
                Signal::ClientHello { .. } => Some(Assessment::NeedsDesync {
                    domain: match &signal {
                        Signal::ClientHello { domain, .. } => domain.clone(),
                        _ => unreachable!(),
                    },
                    signal,
                }),
                Signal::RstInjection { domain, ttl_delta } => {
                    eprintln!(
                        "[strategy] RST injection detected for {domain} (delta={ttl_delta})"
                    );
                    None // logged, but doesn't trigger command in this example
                }
            }
        })
        // Floor 3: materialize command
        .map(|assessment| match assessment {
            Assessment::NeedsDesync { signal, .. } => match signal {
                Signal::ClientHello {
                    raw,
                    ip_start,
                    tcp_start,
                    payload_start,
                    flow,
                    ..
                } => Command::MultiDisorder {
                    original: raw,
                    ip_start,
                    tcp_start,
                    payload_start,
                    flow,
                },
                _ => unreachable!(),
            },
            Assessment::Clean => unreachable!(),
        });

    // consume pipeline, execute commands
    tokio::pin!(pipeline);

    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }

        match tokio::time::timeout(Duration::from_millis(100), pipeline.next()).await {
            Ok(Some(cmd)) => {
                execute_multi_disorder(&injector, &cmd);
                desync_count += 1;
            }
            Ok(None) => break,
            Err(_) => continue,
        }
    }

    eprintln!("[strategy] done, executed {desync_count} multi-disorder injections");

    if desync_count > 0 {
        println!("PASS: executed {desync_count} multi-disorder desync(s)");
    } else {
        println!("FAIL: no desync executed");
        std::process::exit(1);
    }
}
