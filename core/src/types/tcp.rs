use crate::types::flow::{Flow, HasFlow};
use crate::types::protocol::Protocol;
use crate::types::tcp_flags::TcpFlags;
use crate::types::tcp_options::TcpOptions;
use std::net::{Ipv4Addr, SocketAddr};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpSegment {
    pub flow: Flow,
    pub seq: u32,
    pub ack: u32,
    pub flags: TcpFlags,
    pub window: u16,
    pub options: TcpOptions,
    pub ttl: u8,
    pub payload: Vec<u8>,
}

const TCP_MIN_HEADER_LEN: usize = 20;

impl TcpSegment {
    pub fn parse(data: &[u8], src_ip: Ipv4Addr, dst_ip: Ipv4Addr, ttl: u8) -> Option<Self> {
        if data.len() < TCP_MIN_HEADER_LEN {
            return None;
        }

        let src_port = u16::from_be_bytes([data[0], data[1]]);
        let dst_port = u16::from_be_bytes([data[2], data[3]]);
        let seq = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let ack = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
        let data_offset = ((data[12] >> 4) as usize) * 4;

        if data_offset < TCP_MIN_HEADER_LEN || data.len() < data_offset {
            return None;
        }

        let flags = TcpFlags::from_bits_truncate(data[13]);
        let window = u16::from_be_bytes([data[14], data[15]]);

        let options = if data_offset > TCP_MIN_HEADER_LEN {
            TcpOptions::parse(&data[TCP_MIN_HEADER_LEN..data_offset])
        } else {
            TcpOptions::default()
        };

        let payload = data[data_offset..].to_vec();

        let flow = Flow {
            src: SocketAddr::new(src_ip.into(), src_port),
            dst: SocketAddr::new(dst_ip.into(), dst_port),
            protocol: Protocol::Tcp,
        };

        Some(TcpSegment {
            flow,
            seq,
            ack,
            flags,
            window,
            options,
            ttl,
            payload,
        })
    }
}

impl HasFlow for TcpSegment {
    fn flow(&self) -> &Flow {
        &self.flow
    }
}
