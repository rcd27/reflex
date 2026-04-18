use std::time::Duration;

use futures::StreamExt;
use reflex_linux::AfPacketBackend;

/// RST injection emulator: watches for TLS ClientHello on br0,
/// injects a spoofed RST packet with anomalous TTL (like TSPU does).
#[tokio::main]
async fn main() {
    let iface = std::env::args().nth(1).unwrap_or_else(|| "br0".to_string());

    let timeout_secs: u64 = std::env::args()
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(10);

    eprintln!("[rst-emu] opening AF_PACKET on {iface}");

    let backend = AfPacketBackend::open(&iface, 65535).unwrap_or_else(|e| {
        eprintln!("[rst-emu] FAIL: {e}");
        std::process::exit(1);
    });

    let (mut stream, injector) = backend.split();

    let deadline = tokio::time::Instant::now() + Duration::from_secs(timeout_secs);
    let mut injected = 0u32;

    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }

        let pkt =
            match tokio::time::timeout(Duration::from_millis(100), StreamExt::next(&mut stream))
                .await
            {
                Ok(Some(p)) => p,
                Ok(None) => break,
                Err(_) => continue,
            };

        // need at least: ethernet(14) + ip(20) + tcp(20) = 54 bytes
        if pkt.len() < 54 {
            continue;
        }

        // check ethertype = IPv4 (0x0800)
        if pkt[12] != 0x08 || pkt[13] != 0x00 {
            continue;
        }

        // check IP protocol = TCP (6)
        let ip_header_start = 14;
        let ip_protocol = pkt[ip_header_start + 9];
        if ip_protocol != 6 {
            continue;
        }

        let ip_ihl = (pkt[ip_header_start] & 0x0f) as usize * 4;
        let tcp_start = ip_header_start + ip_ihl;

        if pkt.len() < tcp_start + 20 {
            continue;
        }

        // check TCP dst port = 443 (offset +2 in TCP header)
        let dst_port = u16::from_be_bytes([pkt[tcp_start + 2], pkt[tcp_start + 3]]);
        if dst_port != 443 {
            continue;
        }

        // check TCP flags: PSH+ACK (0x18) — likely ClientHello
        let tcp_flags = pkt[tcp_start + 13];
        if tcp_flags & 0x18 != 0x18 {
            continue;
        }

        // check TLS: content type 0x16 (handshake), then 0x01 (ClientHello)
        let tcp_data_offset = (pkt[tcp_start + 12] >> 4) as usize * 4;
        let payload_start = tcp_start + tcp_data_offset;

        if pkt.len() < payload_start + 6 {
            continue;
        }

        if pkt[payload_start] != 0x16 {
            continue;
        }

        // TLS handshake type at offset +5
        if pkt[payload_start + 5] != 0x01 {
            continue;
        }

        eprintln!("[rst-emu] ClientHello detected! Injecting RST with anomalous TTL");

        // build spoofed RST: from server to client
        let rst_packet = build_rst_packet(&pkt, ip_header_start, tcp_start);

        // inject via a separate backend instance (need separate fd for send)
        // for now, use the same backend's inject
        if let Err(e) = injector.send(&rst_packet) {
            eprintln!("[rst-emu] inject failed: {e}");
        } else {
            injected += 1;
            eprintln!("[rst-emu] RST injected (#{injected})");
        }
    }

    eprintln!("[rst-emu] done, injected {injected} RST packets");

    if injected > 0 {
        println!("PASS: injected {injected} RST packets");
    } else {
        println!("FAIL: no ClientHello seen, nothing injected");
        std::process::exit(1);
    }
}

/// Build a spoofed RST packet that looks like it came from the server.
/// Key: TTL is set to 128 (anomalously higher than real server TTL=64).
fn build_rst_packet(original: &[u8], ip_start: usize, tcp_start: usize) -> Vec<u8> {
    let mut pkt = vec![0u8; 54]; // ethernet(14) + ip(20) + tcp(20)

    // --- Ethernet header ---
    // dst MAC = original src MAC (send to client)
    pkt[0..6].copy_from_slice(&original[6..12]);
    // src MAC = original dst MAC (pretend to be server)
    pkt[6..12].copy_from_slice(&original[0..6]);
    // ethertype = IPv4
    pkt[12] = 0x08;
    pkt[13] = 0x00;

    // --- IP header ---
    let ip_out = 14;
    pkt[ip_out] = 0x45; // version=4, IHL=5
    pkt[ip_out + 1] = 0; // DSCP/ECN
    let ip_total_len: u16 = 40; // 20 IP + 20 TCP
    pkt[ip_out + 2..ip_out + 4].copy_from_slice(&ip_total_len.to_be_bytes());
    pkt[ip_out + 4..ip_out + 6].copy_from_slice(&[0x00, 0x01]); // identification
    pkt[ip_out + 6..ip_out + 8].copy_from_slice(&[0x40, 0x00]); // DF, no fragment
    pkt[ip_out + 8] = 128; // TTL = 128 ← ANOMALOUS (real server is 64)
    pkt[ip_out + 9] = 6; // protocol = TCP

    // src IP = original dst IP (server)
    pkt[ip_out + 12..ip_out + 16].copy_from_slice(&original[ip_start + 16..ip_start + 20]);
    // dst IP = original src IP (client)
    pkt[ip_out + 16..ip_out + 20].copy_from_slice(&original[ip_start + 12..ip_start + 16]);

    // IP checksum
    let ip_csum = ip_checksum(&pkt[ip_out..ip_out + 20]);
    pkt[ip_out + 10..ip_out + 12].copy_from_slice(&ip_csum.to_be_bytes());

    // --- TCP header ---
    let tcp_out = 34;
    // src port = original dst port (server 443)
    pkt[tcp_out..tcp_out + 2].copy_from_slice(&original[tcp_start + 2..tcp_start + 4]);
    // dst port = original src port (client ephemeral)
    pkt[tcp_out + 2..tcp_out + 4].copy_from_slice(&original[tcp_start..tcp_start + 2]);

    // seq = original ack (what server would send next)
    pkt[tcp_out + 4..tcp_out + 8].copy_from_slice(&original[tcp_start + 8..tcp_start + 12]);
    // ack = 0
    pkt[tcp_out + 8..tcp_out + 12].copy_from_slice(&[0, 0, 0, 0]);

    // data offset = 5 (20 bytes, no options), flags = RST+ACK (0x14)
    pkt[tcp_out + 12] = 0x50;
    pkt[tcp_out + 13] = 0x14; // RST + ACK
                              // window = 0 (characteristic of DPI-injected RST)
    pkt[tcp_out + 14..tcp_out + 16].copy_from_slice(&[0, 0]);

    // TCP checksum (pseudo-header + TCP)
    let tcp_csum = tcp_checksum(
        &pkt[ip_out + 12..ip_out + 16], // src IP
        &pkt[ip_out + 16..ip_out + 20], // dst IP
        &pkt[tcp_out..tcp_out + 20],
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

    // pseudo-header
    for chunk in src_ip.chunks(2) {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    for chunk in dst_ip.chunks(2) {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    sum += 6u32; // protocol TCP
    sum += tcp_segment.len() as u32;

    // TCP segment
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
