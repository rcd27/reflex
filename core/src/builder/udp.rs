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
    /// Serialize as IP packet (no ethernet header). For raw socket injection.
    /// Зеркало [`serialize`](Self::serialize) без 14-байтного ethernet-префикса:
    /// IP-заголовок на offset 0 (чек-сумма 10..12), UDP на 20 (чек-сумма 26..28).
    pub fn serialize_ip(&self) -> Vec<u8> {
        let udp_total = 8 + self.payload.len();
        let ip_total = 20 + udp_total;
        let mut buf = Vec::with_capacity(ip_total);

        // IPv4
        buf.push(0x45);
        buf.push(0x00);
        buf.extend_from_slice(&(ip_total as u16).to_be_bytes());
        buf.extend_from_slice(&[0x00; 4]); // id, flags/frag
        buf.push(self.ttl);
        buf.push(17); // UDP
        buf.extend_from_slice(&[0x00; 2]); // checksum placeholder
        buf.extend_from_slice(&self.src_ip.octets());
        buf.extend_from_slice(&self.dst_ip.octets());

        // UDP
        buf.extend_from_slice(&self.src_port.to_be_bytes());
        buf.extend_from_slice(&self.dst_port.to_be_bytes());
        buf.extend_from_slice(&(udp_total as u16).to_be_bytes());
        buf.extend_from_slice(&[0x00; 2]); // checksum placeholder

        buf.extend_from_slice(&self.payload);

        // IP checksum over 20-байтный заголовок
        let ip_csum = checksum::ip_checksum(&buf[0..20]);
        buf[10] = (ip_csum >> 8) as u8;
        buf[11] = (ip_csum & 0xFF) as u8;

        // UDP checksum над псевдо-заголовком + UDP-сегментом
        let udp_csum =
            checksum::udp_checksum(&self.src_ip.octets(), &self.dst_ip.octets(), &buf[20..]);
        buf[26] = (udp_csum >> 8) as u8;
        buf[27] = (udp_csum & 0xFF) as u8;

        buf
    }

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    fn flow() -> Flow {
        Flow {
            src: SocketAddr::new(Ipv4Addr::new(10, 0, 0, 2).into(), 55555),
            dst: SocketAddr::new(Ipv4Addr::new(1, 2, 3, 4).into(), 443),
            protocol: crate::types::Protocol::Udp,
        }
    }

    /// `serialize_ip` даёт валидный IP+UDP пакет: длины, протокол 17, IP-чек-сумма сходится.
    #[test]
    fn serialize_ip_valid_headers_and_checksum() {
        let pkt = UdpBuilder::new()
            .flow(&flow())
            .ttl(64)
            .payload(b"QUICINIT")
            .build();
        let ip = pkt.serialize_ip();

        assert_eq!(ip.len(), 20 + 8 + 8, "IP(20)+UDP(8)+payload(8)");
        assert_eq!(ip[0], 0x45, "IPv4 IHL=5");
        assert_eq!(ip[9], 17, "протокол UDP");
        assert_eq!(
            u16::from_be_bytes([ip[2], ip[3]]) as usize,
            ip.len(),
            "IP total len"
        );
        // UDP len = 8 + payload
        assert_eq!(u16::from_be_bytes([ip[24], ip[25]]), 16, "UDP len = 8+8");
        // IP чек-сумма над заголовком (со вписанной csum) сходится в 0.
        assert_eq!(checksum::ip_checksum(&ip[0..20]), 0, "IP-чек-сумма валидна");
        // dst порт 443
        assert_eq!(u16::from_be_bytes([ip[22], ip[23]]), 443);
    }
}
