use crate::types::protocol::IpProtocol;
use std::net::Ipv4Addr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv4Packet {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub ttl: u8,
    pub protocol: IpProtocol,
    pub id: u16,
    pub dont_fragment: bool,
    pub payload: Vec<u8>,
}

const IPV4_MIN_HEADER_LEN: usize = 20;

impl Ipv4Packet {
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < IPV4_MIN_HEADER_LEN {
            return None;
        }

        let version = data[0] >> 4;
        if version != 4 {
            return None;
        }

        let ihl = (data[0] & 0x0F) as usize;
        let header_len = ihl * 4;
        if data.len() < header_len {
            return None;
        }

        let total_length = u16::from_be_bytes([data[2], data[3]]) as usize;
        let actual_len = total_length.min(data.len());
        let id = u16::from_be_bytes([data[4], data[5]]);
        let flags_fragment = u16::from_be_bytes([data[6], data[7]]);
        let dont_fragment = (flags_fragment & 0x4000) != 0;
        let ttl = data[8];
        let protocol = IpProtocol::from_u8(data[9]);
        let src = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
        let dst = Ipv4Addr::new(data[16], data[17], data[18], data[19]);
        let payload = data[header_len..actual_len].to_vec();

        Some(Ipv4Packet {
            src,
            dst,
            ttl,
            protocol,
            id,
            dont_fragment,
            payload,
        })
    }
}
