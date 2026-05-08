// reflex/linux/examples/nfq-passthrough.rs
//
// Usage (as root):
//   iptables -I OUTPUT -p tcp --dport 443 -m mark ! --mark 0xBB -j NFQUEUE --queue-num 200
//   cargo run --example nfq-passthrough --features nfqueue
//   # Open browser, visit any HTTPS site — should work normally
//   # Ctrl+C to stop
//   iptables -D OUTPUT -p tcp --dport 443 -m mark ! --mark 0xBB -j NFQUEUE --queue-num 200

use reflex_core::command::InjectablePacket;
use reflex_linux::nfqueue::{NfqHandler, NfqPacket, NfqPipeline, NfqVerdict};

struct PassthroughHandler {
    count: u64,
}

impl NfqHandler for PassthroughHandler {
    fn handle(&mut self, packet: &NfqPacket) -> (NfqVerdict, Vec<InjectablePacket>) {
        self.count += 1;

        if packet.payload.len() >= 20 {
            let proto = packet.payload[9];

            if proto == 6 {
                let src_ip = &packet.payload[12..16];
                let dst_ip = &packet.payload[16..20];
                let ihl = (packet.payload[0] & 0x0F) as usize * 4;
                if packet.payload.len() >= ihl + 4 {
                    let src_port =
                        u16::from_be_bytes([packet.payload[ihl], packet.payload[ihl + 1]]);
                    let dst_port =
                        u16::from_be_bytes([packet.payload[ihl + 2], packet.payload[ihl + 3]]);
                    println!(
                        "[{}] TCP {}.{}.{}.{}:{} → {}.{}.{}.{}:{} len={}",
                        self.count,
                        src_ip[0],
                        src_ip[1],
                        src_ip[2],
                        src_ip[3],
                        src_port,
                        dst_ip[0],
                        dst_ip[1],
                        dst_ip[2],
                        dst_ip[3],
                        dst_port,
                        packet.payload.len(),
                    );
                }
            }
        }

        (NfqVerdict::Accept, vec![])
    }
}

fn main() {
    println!("NFQ passthrough handler — accepting all TCP 443 packets");
    println!("Press Ctrl+C to stop");

    let handler = PassthroughHandler { count: 0 };
    let mut pipeline =
        NfqPipeline::bind(200, 0xBB, handler).expect("failed to bind NfqPipeline");

    if let Err(e) = pipeline.run_while(|| true) {
        eprintln!("Pipeline error: {e}");
    }
}
