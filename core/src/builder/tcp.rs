use crate::types::{Flow, TcpFlags};
use std::net::Ipv4Addr;

#[derive(Debug, Clone)]
pub struct BuiltTcpPacket {
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: TcpFlags,
    ttl: u8,
    window: u16,
    payload: Vec<u8>,
}

impl BuiltTcpPacket {
    pub fn serialize(&self) -> Vec<u8> {
        let tcp_header_len = 20usize;
        let tcp_total = tcp_header_len + self.payload.len();
        let ip_total = 20 + tcp_total;
        let eth_total = 14 + ip_total;
        let mut buf = Vec::with_capacity(eth_total);

        // Ethernet header
        buf.extend_from_slice(&[0xFF; 6]); // dst mac broadcast
        buf.extend_from_slice(&[0x00; 6]); // src mac zero
        buf.extend_from_slice(&0x0800u16.to_be_bytes());

        // IPv4 header
        buf.push(0x45); // version=4, IHL=5
        buf.push(0x00);
        buf.extend_from_slice(&(ip_total as u16).to_be_bytes());
        buf.extend_from_slice(&[0x00, 0x00]); // identification
        buf.extend_from_slice(&[0x40, 0x00]); // DF
        buf.push(self.ttl);
        buf.push(6); // TCP
        buf.extend_from_slice(&[0x00, 0x00]); // checksum
        buf.extend_from_slice(&self.src_ip.octets());
        buf.extend_from_slice(&self.dst_ip.octets());

        // TCP header
        buf.extend_from_slice(&self.src_port.to_be_bytes());
        buf.extend_from_slice(&self.dst_port.to_be_bytes());
        buf.extend_from_slice(&self.seq.to_be_bytes());
        buf.extend_from_slice(&self.ack.to_be_bytes());
        buf.push(0x50); // data offset=5
        buf.push(self.flags.bits());
        buf.extend_from_slice(&self.window.to_be_bytes());
        buf.extend_from_slice(&[0x00, 0x00]); // checksum
        buf.extend_from_slice(&[0x00, 0x00]); // urgent

        buf.extend_from_slice(&self.payload);
        buf
    }
}

#[derive(Debug, Clone)]
pub struct TcpBuilder {
    src_ip: Option<Ipv4Addr>,
    dst_ip: Option<Ipv4Addr>,
    src_port: Option<u16>,
    dst_port: Option<u16>,
    seq: u32,
    ack: u32,
    flags: TcpFlags,
    ttl: u8,
    window: u16,
    payload: Vec<u8>,
}

impl Default for TcpBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl TcpBuilder {
    pub fn new() -> Self {
        TcpBuilder {
            src_ip: None,
            dst_ip: None,
            src_port: None,
            dst_port: None,
            seq: 0,
            ack: 0,
            flags: TcpFlags::empty(),
            ttl: 64,
            window: 29200,
            payload: Vec::new(),
        }
    }

    pub fn flow(mut self, flow: &Flow) -> Self {
        if let std::net::IpAddr::V4(ip) = flow.src.ip() {
            self.src_ip = Some(ip);
        }
        self.src_port = Some(flow.src.port());
        if let std::net::IpAddr::V4(ip) = flow.dst.ip() {
            self.dst_ip = Some(ip);
        }
        self.dst_port = Some(flow.dst.port());
        self
    }

    pub fn seq(mut self, seq: u32) -> Self {
        self.seq = seq;
        self
    }

    pub fn ack(mut self, ack: u32) -> Self {
        self.ack = ack;
        self
    }

    pub fn flags(mut self, flags: TcpFlags) -> Self {
        self.flags = flags;
        self
    }

    pub fn ttl(mut self, ttl: u8) -> Self {
        self.ttl = ttl;
        self
    }

    pub fn window(mut self, window: u16) -> Self {
        self.window = window;
        self
    }

    pub fn payload(mut self, data: &[u8]) -> Self {
        self.payload = data.to_vec();
        self
    }

    pub fn build(self) -> BuiltTcpPacket {
        BuiltTcpPacket {
            src_ip: self.src_ip.expect("flow must be set"),
            dst_ip: self.dst_ip.expect("flow must be set"),
            src_port: self.src_port.expect("flow must be set"),
            dst_port: self.dst_port.expect("flow must be set"),
            seq: self.seq,
            ack: self.ack,
            flags: self.flags,
            ttl: self.ttl,
            window: self.window,
            payload: self.payload,
        }
    }
}
