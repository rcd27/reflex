use std::time::Duration;

use futures::StreamExt;
use reflex_core::checksum;
use reflex_linux::AfPacketBackend;

/// Multi-disorder strategy: inject a fake packet with TTL=1 before ClientHello reaches DPI.
/// The fake dies at the first hop, confusing the DPI state machine.
#[tokio::main]
async fn main() {
    let iface = std::env::args().nth(1).unwrap_or_else(|| "br0".to_string());
    let timeout_secs: u64 = std::env::args()
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(10);

    eprintln!("[multi-disorder] opening AF_PACKET on {iface}");

    let backend = AfPacketBackend::open(&iface, 65535).unwrap_or_else(|e| {
        eprintln!("[multi-disorder] FAIL: {e}");
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

        if pkt.len() < 54 {
            continue;
        }
        if pkt[12] != 0x08 || pkt[13] != 0x00 {
            continue;
        }
        let ip_start = 14;
        if pkt[ip_start + 9] != 6 {
            continue;
        }

        // Skip our own injected packets (TTL=1)
        if pkt[ip_start + 8] <= 1 {
            continue;
        }

        let ip_ihl = (pkt[ip_start] & 0x0f) as usize * 4;
        let tcp_start = ip_start + ip_ihl;
        if pkt.len() < tcp_start + 20 {
            continue;
        }

        let dst_port = u16::from_be_bytes([pkt[tcp_start + 2], pkt[tcp_start + 3]]);
        let tcp_flags = pkt[tcp_start + 13];

        // Only intercept ClientHello (PSH+ACK to port 443 with TLS handshake)
        if dst_port != 443 || tcp_flags & 0x18 != 0x18 {
            continue;
        }

        let tcp_data_offset = (pkt[tcp_start + 12] >> 4) as usize * 4;
        let payload_start = tcp_start + tcp_data_offset;
        if pkt.len() < payload_start + 6 {
            continue;
        }
        if pkt[payload_start] != 0x16 || pkt[payload_start + 5] != 0x01 {
            continue;
        }

        eprintln!("[multi-disorder] ClientHello detected, injecting fake with short TTL");

        // Build fake packet: same as original but TTL=1 (dropped at first hop)
        let mut fake = pkt.clone();
        fake[ip_start + 8] = 1; // TTL = 1

        // Recompute IP checksum
        fake[ip_start + 10] = 0;
        fake[ip_start + 11] = 0;
        let ip_header_end = ip_start + ip_ihl;
        let ip_csum = checksum::ip_checksum(&fake[ip_start..ip_header_end]);
        fake[ip_start + 10] = (ip_csum >> 8) as u8;
        fake[ip_start + 11] = (ip_csum & 0xFF) as u8;

        // Inject fake BEFORE original (multi-disorder: confuse DPI state machine)
        if let Err(e) = injector.send(&fake) {
            eprintln!("[multi-disorder] inject failed: {e}");
        } else {
            injected += 1;
            eprintln!("[multi-disorder] fake injected (#{injected})");
        }
    }

    eprintln!("[multi-disorder] done, injected {injected} fake packets");

    if injected > 0 {
        println!("PASS: injected {injected} fake packets");
    } else {
        println!("FAIL: no ClientHello seen");
        std::process::exit(1);
    }
}
