use std::time::Duration;

use futures::StreamExt;
use reflex_linux::AfPacketBackend;

#[tokio::main]
async fn main() {
    let iface = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "br0".to_string());

    let timeout_secs: u64 = std::env::args()
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(5);

    eprintln!("[e2e] opening AF_PACKET on {iface}, timeout {timeout_secs}s");

    let mut backend = AfPacketBackend::open(&iface, 65535).unwrap_or_else(|e| {
        eprintln!("[e2e] FAIL: cannot open backend: {e}");
        std::process::exit(1);
    });

    eprintln!("[e2e] backend opened, capabilities: CanObserve + CanInject");

    // capture packets for timeout_secs, count them
    let deadline = tokio::time::Instant::now() + Duration::from_secs(timeout_secs);
    let mut count = 0u64;
    let mut bytes = 0u64;

    let mut stream = backend.packets();

    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }

        match tokio::time::timeout(Duration::from_millis(100), stream.next()).await {
            Ok(Some(pkt)) => {
                bytes += pkt.len() as u64;
                count += 1;
                if count <= 5 {
                    let eth_type = if pkt.len() >= 14 {
                        format!("0x{:02x}{:02x}", pkt[12], pkt[13])
                    } else {
                        "short".to_string()
                    };
                    eprintln!(
                        "[e2e] pkt #{count}: {len} bytes, ethertype {eth_type}",
                        len = pkt.len()
                    );
                }
            }
            Ok(None) => break,
            Err(_) => continue, // timeout on poll, retry
        }

        if tokio::time::Instant::now() >= deadline {
            break;
        }
    }

    eprintln!("[e2e] captured {count} packets, {bytes} bytes total");

    if count > 0 {
        println!("PASS: captured {count} packets ({bytes} bytes)");
    } else {
        println!("FAIL: no packets captured");
        std::process::exit(1);
    }
}
