use crate::checksum;
use crate::types::{Flow, Mac};
use std::net::Ipv4Addr;

#[derive(Debug, Clone)]
pub struct BuiltUdpPacket {
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    ttl: u8,
    payload: Vec<u8>,
    src_mac: Mac,
    dst_mac: Mac,
}

impl BuiltUdpPacket {
    pub fn serialize(&self) -> Vec<u8> {
        let udp_total = 8 + self.payload.len();
        let ip_total = 20 + udp_total;
        let eth_total = 14 + ip_total;
        let mut buf = Vec::with_capacity(eth_total);

        // Ethernet
        buf.extend_from_slice(&self.dst_mac.0);
        buf.extend_from_slice(&self.src_mac.0);
        buf.extend_from_slice(&0x0800u16.to_be_bytes());

        // IPv4
        buf.push(0x45);
        buf.push(0x00);
        buf.extend_from_slice(&(ip_total as u16).to_be_bytes());
        buf.extend_from_slice(&[0x00; 4]); // id, flags
        buf.push(self.ttl);
        buf.push(17); // UDP
        buf.extend_from_slice(&[0x00; 2]); // checksum
        buf.extend_from_slice(&self.src_ip.octets());
        buf.extend_from_slice(&self.dst_ip.octets());

        // UDP
        buf.extend_from_slice(&self.src_port.to_be_bytes());
        buf.extend_from_slice(&self.dst_port.to_be_bytes());
        buf.extend_from_slice(&(udp_total as u16).to_be_bytes());
        buf.extend_from_slice(&[0x00; 2]); // checksum

        buf.extend_from_slice(&self.payload);

        // Compute and write IP checksum
        let ip_csum = checksum::ip_checksum(&buf[14..34]);
        buf[24] = (ip_csum >> 8) as u8;
        buf[25] = (ip_csum & 0xFF) as u8;

        // Compute and write UDP checksum
        let udp_csum =
            checksum::udp_checksum(&self.src_ip.octets(), &self.dst_ip.octets(), &buf[34..]);
        buf[40] = (udp_csum >> 8) as u8;
        buf[41] = (udp_csum & 0xFF) as u8;

        buf
    }
}

#[derive(Debug, Clone)]
pub struct UdpBuilder {
    src_ip: Option<Ipv4Addr>,
    dst_ip: Option<Ipv4Addr>,
    src_port: Option<u16>,
    dst_port: Option<u16>,
    ttl: u8,
    payload: Vec<u8>,
    src_mac: Mac,
    dst_mac: Mac,
}

impl Default for UdpBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl UdpBuilder {
    pub fn new() -> Self {
        UdpBuilder {
            src_ip: None,
            dst_ip: None,
            src_port: None,
            dst_port: None,
            ttl: 64,
            payload: Vec::new(),
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

    pub fn ttl(mut self, ttl: u8) -> Self {
        self.ttl = ttl;
        self
    }

    pub fn payload(mut self, data: &[u8]) -> Self {
        self.payload = data.to_vec();
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

    pub fn build(self) -> BuiltUdpPacket {
        BuiltUdpPacket {
            src_ip: self.src_ip.expect("flow must be set"),
            dst_ip: self.dst_ip.expect("flow must be set"),
            src_port: self.src_port.expect("flow must be set"),
            dst_port: self.dst_port.expect("flow must be set"),
            ttl: self.ttl,
            payload: self.payload,
            src_mac: self.src_mac,
            dst_mac: self.dst_mac,
        }
    }
}
