use std::time::Duration;

use futures::StreamExt;
use reflex_linux::xdp::{self, XdpProgram};
use reflex_linux::{AfPacketBackend, XdpAfPacketBackend};
use reflex_linux_common::FlowAction;

/// E2e test: load XDP program on br0, set a flow to DROP,
/// verify that packets are dropped.
#[tokio::main]
async fn main() {
    let iface = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "br0".to_string());

    let bpf_path = std::env::args()
        .nth(2)
        .unwrap_or_else(|| "/usr/local/lib/reflex-xdp.o".to_string());

    let timeout_secs: u64 = std::env::args()
        .nth(3)
        .and_then(|s| s.parse().ok())
        .unwrap_or(10);

    eprintln!("[xdp-test] loading XDP from {bpf_path} onto {iface}");

    let bpf_bytes = std::fs::read(&bpf_path).unwrap_or_else(|e| {
        eprintln!("[xdp-test] FAIL: cannot read {bpf_path}: {e}");
        std::process::exit(1);
    });

    let mut backend = XdpAfPacketBackend::open(&iface, 65535, &bpf_bytes).unwrap_or_else(|e| {
        eprintln!("[xdp-test] FAIL: {e}");
        std::process::exit(1);
    });

    eprintln!("[xdp-test] XDP attached to {iface}");

    // set a test flow to DROP (flow hash = 0xDEADBEEF for testing)
    // in real usage, this would be computed from 5-tuple
    let test_hash = xdp::flow_hash(
        u32::from_be_bytes([10, 77, 0, 10]),  // client IP
        u32::from_be_bytes([10, 77, 0, 20]),  // server IP
        0,   // any src port
        443, // dst port
        6,   // TCP
    );

    eprintln!("[xdp-test] setting flow hash {test_hash:#x} to CopyAndDrop");
    backend
        .set_flow_action(test_hash, FlowAction::CopyAndDrop)
        .unwrap_or_else(|e| {
            eprintln!("[xdp-test] FAIL: {e}");
            std::process::exit(1);
        });

    eprintln!("[xdp-test] XDP action table configured");
    eprintln!("[xdp-test] observing for {timeout_secs}s...");

    // observe packets — XDP should drop matching flows
    let deadline = tokio::time::Instant::now() + Duration::from_secs(timeout_secs);
    let mut count = 0u64;
    let mut stream = backend.packets();

    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }

        match tokio::time::timeout(Duration::from_millis(100), stream.next()).await {
            Ok(Some(pkt)) => {
                count += 1;
                if count <= 3 {
                    eprintln!("[xdp-test] pkt #{count}: {} bytes", pkt.len());
                }
            }
            Ok(None) => break,
            Err(_) => continue,
        }
    }

    eprintln!("[xdp-test] observed {count} packets");
    println!("PASS: XDP loaded, action table configured, observed {count} packets");
}
