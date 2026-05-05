// reflex/linux/examples/nfq-fragment.rs
//
// Intercepts ClientHello on TCP 443, splits into two TCP segments (disorder),
// drops original. Tests that HTTPS still works through fragmented ClientHello.
//
// Usage (as root):
//   iptables -I OUTPUT -p tcp --dport 443 -m mark ! --mark 0xBB -j NFQUEUE --queue-num 200
//   cargo run --example nfq-fragment --features nfqueue
//   curl -sI https://ya.ru | head -3
//   iptables -D OUTPUT -p tcp --dport 443 -m mark ! --mark 0xBB -j NFQUEUE --queue-num 200

use reflex_core::builder::TcpBuilder;
use reflex_core::command::InjectablePacket;
use reflex_core::types::{Flow, Protocol, TcpFlags};
use reflex_linux::nfqueue::{NfqConfig, NfqHandler, NfqPacket, NfqPipeline, NfqVerdict};
use std::net::{Ipv4Addr, SocketAddr};

struct FragmentHandler;

impl NfqHandler for FragmentHandler {
    fn handle(&mut self, packet: &NfqPacket) -> (NfqVerdict, Vec<InjectablePacket>) {
        // Parse IP header
        if packet.payload.len() < 20 {
            return (NfqVerdict::Accept, vec![]);
        }
        if packet.payload[9] != 6 {
            return (NfqVerdict::Accept, vec![]); // not TCP
        }

        let ihl = (packet.payload[0] & 0x0F) as usize * 4;
        if packet.payload.len() < ihl + 20 {
            return (NfqVerdict::Accept, vec![]);
        }

        let tcp = &packet.payload[ihl..];
        let src_port = u16::from_be_bytes([tcp[0], tcp[1]]);
        let dst_port = u16::from_be_bytes([tcp[2], tcp[3]]);
        let seq = u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]);
        let ack = u32::from_be_bytes([tcp[8], tcp[9], tcp[10], tcp[11]]);
        let data_offset = ((tcp[12] >> 4) as usize) * 4;
        let flags_byte = tcp[13];
        let window = u16::from_be_bytes([tcp[14], tcp[15]]);
        let ttl = packet.payload[8];

        let payload_start = ihl + data_offset;
        let payload = if packet.payload.len() > payload_start {
            &packet.payload[payload_start..]
        } else {
            return (NfqVerdict::Accept, vec![]);
        };

        // Check for TLS ClientHello
        let is_client_hello = payload.len() >= 6 && payload[0] == 0x16 && payload[5] == 0x01;
        if !is_client_hello {
            return (NfqVerdict::Accept, vec![]);
        }

        let src_ip = Ipv4Addr::new(
            packet.payload[12],
            packet.payload[13],
            packet.payload[14],
            packet.payload[15],
        );
        let dst_ip = Ipv4Addr::new(
            packet.payload[16],
            packet.payload[17],
            packet.payload[18],
            packet.payload[19],
        );

        println!(
            "ClientHello! {}:{} → {}:{} payload={} bytes",
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            payload.len()
        );

        // Split at offset 5, send second first (disorder)
        let split_at = 5.min(payload.len());
        let first_payload = &payload[..split_at];
        let second_payload = &payload[split_at..];

        let flow = Flow {
            src: SocketAddr::new(src_ip.into(), src_port),
            dst: SocketAddr::new(dst_ip.into(), dst_port),
            protocol: Protocol::Tcp,
        };
        let flags = TcpFlags::from_bits_truncate(flags_byte);

        // Fragment 2 first (disorder)
        let frag2 = TcpBuilder::new()
            .flow(&flow)
            .seq(seq.wrapping_add(split_at as u32))
            .ack(ack)
            .flags(flags | TcpFlags::PSH)
            .ttl(ttl)
            .window(window)
            .payload(second_payload)
            .build();

        // Fragment 1 second
        let frag1 = TcpBuilder::new()
            .flow(&flow)
            .seq(seq)
            .ack(ack)
            .flags(flags)
            .ttl(ttl)
            .window(window)
            .payload(first_payload)
            .build();

        println!(
            "  → frag2 (seq+{}, {} bytes) then frag1 ({} bytes), drop original",
            split_at,
            second_payload.len(),
            first_payload.len()
        );

        let injects = vec![InjectablePacket::Tcp(frag2), InjectablePacket::Tcp(frag1)];

        (NfqVerdict::Drop, injects)
    }
}

fn main() {
    println!("NFQ fragment handler — splitting ClientHello (disorder)");
    println!("Press Ctrl+C to stop");

    let handler = FragmentHandler;
    let mut pipeline =
        NfqPipeline::new(NfqConfig::default(), handler).expect("failed to create NfqPipeline");

    if let Err(e) = pipeline.run_blocking() {
        eprintln!("Pipeline error: {e}");
    }
}
