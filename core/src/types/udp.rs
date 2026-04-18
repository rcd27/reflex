use crate::types::flow::{Flow, HasFlow};
use crate::types::protocol::Protocol;
use std::net::{Ipv4Addr, SocketAddr};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpDatagram {
    pub flow: Flow,
    pub ttl: u8,
    pub payload: Vec<u8>,
}

const UDP_HEADER_LEN: usize = 8;

impl UdpDatagram {
    pub fn parse(data: &[u8], src_ip: Ipv4Addr, dst_ip: Ipv4Addr, ttl: u8) -> Option<Self> {
        if data.len() < UDP_HEADER_LEN {
            return None;
        }

        let src_port = u16::from_be_bytes([data[0], data[1]]);
        let dst_port = u16::from_be_bytes([data[2], data[3]]);
        let length = u16::from_be_bytes([data[4], data[5]]) as usize;
        let actual_len = length.min(data.len());
        let payload = data[UDP_HEADER_LEN..actual_len].to_vec();

        let flow = Flow {
            src: SocketAddr::new(src_ip.into(), src_port),
            dst: SocketAddr::new(dst_ip.into(), dst_port),
            protocol: Protocol::Udp,
        };

        Some(UdpDatagram { flow, ttl, payload })
    }
}

impl HasFlow for UdpDatagram {
    fn flow(&self) -> &Flow {
        &self.flow
    }
}
