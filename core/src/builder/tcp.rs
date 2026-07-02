use crate::checksum;
use crate::types::{Flow, Mac, TcpFlags};
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
    options: Vec<u8>,
    src_mac: Mac,
    dst_mac: Mac,
}

/// Padding TCP-опций нулями (End Of Option List) до кратности 4 — иначе data offset
/// не выразим (он в 32-битных словах). Бизнес-агностик: стандарт TCP, не десинк.
fn pad_tcp_options(opts: &[u8]) -> Vec<u8> {
    let mut v = opts.to_vec();
    while v.len() % 4 != 0 {
        v.push(0x00);
    }
    v
}

impl BuiltTcpPacket {
    /// Serialize as IP packet (no ethernet header). For raw socket injection.
    pub fn serialize_ip(&self) -> Vec<u8> {
        let opts = pad_tcp_options(&self.options);
        let tcp_header_len = 20 + opts.len();
        let tcp_total = tcp_header_len + self.payload.len();
        let ip_total = 20 + tcp_total;
        let mut buf = Vec::with_capacity(ip_total);

        // IPv4 header
        buf.push(0x45);
        buf.push(0x00);
        buf.extend_from_slice(&(ip_total as u16).to_be_bytes());
        buf.extend_from_slice(&[0x00, 0x00]); // identification
        buf.extend_from_slice(&[0x40, 0x00]); // DF
        buf.push(self.ttl);
        buf.push(6); // TCP
        buf.extend_from_slice(&[0x00, 0x00]); // checksum placeholder
        buf.extend_from_slice(&self.src_ip.octets());
        buf.extend_from_slice(&self.dst_ip.octets());

        // TCP header
        buf.extend_from_slice(&self.src_port.to_be_bytes());
        buf.extend_from_slice(&self.dst_port.to_be_bytes());
        buf.extend_from_slice(&self.seq.to_be_bytes());
        buf.extend_from_slice(&self.ack.to_be_bytes());
        buf.push(((tcp_header_len / 4) << 4) as u8); // data offset (в 32-бит словах)
        buf.push(self.flags.bits());
        buf.extend_from_slice(&self.window.to_be_bytes());
        buf.extend_from_slice(&[0x00, 0x00]); // checksum placeholder
        buf.extend_from_slice(&[0x00, 0x00]); // urgent

        buf.extend_from_slice(&opts);
        buf.extend_from_slice(&self.payload);

        // IP checksum
        let ip_csum = checksum::ip_checksum(&buf[..20]);
        buf[10] = (ip_csum >> 8) as u8;
        buf[11] = (ip_csum & 0xFF) as u8;

        // TCP checksum
        let tcp_csum =
            checksum::tcp_checksum(&self.src_ip.octets(), &self.dst_ip.octets(), &buf[20..]);
        buf[36] = (tcp_csum >> 8) as u8;
        buf[37] = (tcp_csum & 0xFF) as u8;

        buf
    }

    pub fn serialize(&self) -> Vec<u8> {
        let opts = pad_tcp_options(&self.options);
        let tcp_header_len = 20 + opts.len();
        let tcp_total = tcp_header_len + self.payload.len();
        let ip_total = 20 + tcp_total;
        let eth_total = 14 + ip_total;
        let mut buf = Vec::with_capacity(eth_total);

        // Ethernet header
        buf.extend_from_slice(&self.dst_mac.0);
        buf.extend_from_slice(&self.src_mac.0);
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
        buf.push(((tcp_header_len / 4) << 4) as u8); // data offset (в 32-бит словах)
        buf.push(self.flags.bits());
        buf.extend_from_slice(&self.window.to_be_bytes());
        buf.extend_from_slice(&[0x00, 0x00]); // checksum
        buf.extend_from_slice(&[0x00, 0x00]); // urgent

        buf.extend_from_slice(&opts);
        buf.extend_from_slice(&self.payload);

        // Compute and write IP checksum
        let ip_csum = checksum::ip_checksum(&buf[14..34]);
        buf[24] = (ip_csum >> 8) as u8;
        buf[25] = (ip_csum & 0xFF) as u8;

        // Compute and write TCP checksum
        let tcp_csum =
            checksum::tcp_checksum(&self.src_ip.octets(), &self.dst_ip.octets(), &buf[34..]);
        buf[50] = (tcp_csum >> 8) as u8;
        buf[51] = (tcp_csum & 0xFF) as u8;

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
    options: Vec<u8>,
    src_mac: Mac,
    dst_mac: Mac,
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
            options: Vec::new(),
            src_mac: Mac([0x00; 6]),
            dst_mac: Mac([0xFF; 6]),
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

    /// Сырые TCP-опции (после фикс. 20-байтного заголовка). Padding до кратности 4
    /// и data offset — забота сериализатора. Бизнес-агностик: механизм TCP-опций,
    /// какая именно опция (MD5/timestamp/…) — забота потребителя.
    pub fn tcp_options(mut self, opts: &[u8]) -> Self {
        self.options = opts.to_vec();
        self
    }

    pub fn src_mac(mut self, mac: Mac) -> Self {
        self.src_mac = mac;
        self
    }

    pub fn dst_mac(mut self, mac: Mac) -> Self {
        self.dst_mac = mac;
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
            options: self.options,
            src_mac: self.src_mac,
            dst_mac: self.dst_mac,
        }
    }
}
