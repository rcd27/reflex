use crate::types::ethertype::EtherType;
use crate::types::mac::Mac;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EthernetFrame {
    pub dst_mac: Mac,
    pub src_mac: Mac,
    pub ethertype: EtherType,
    pub payload: Vec<u8>,
}

const ETHERNET_HEADER_LEN: usize = 14;

impl EthernetFrame {
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < ETHERNET_HEADER_LEN {
            return None;
        }

        let dst_mac = Mac([data[0], data[1], data[2], data[3], data[4], data[5]]);
        let src_mac = Mac([data[6], data[7], data[8], data[9], data[10], data[11]]);
        let ethertype = EtherType::from_u16(u16::from_be_bytes([data[12], data[13]]));
        let payload = data[ETHERNET_HEADER_LEN..].to_vec();

        Some(EthernetFrame {
            dst_mac,
            src_mac,
            ethertype,
            payload,
        })
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(ETHERNET_HEADER_LEN + self.payload.len());
        buf.extend_from_slice(&self.dst_mac.0);
        buf.extend_from_slice(&self.src_mac.0);
        buf.extend_from_slice(&self.ethertype.to_u16().to_be_bytes());
        buf.extend_from_slice(&self.payload);
        buf
    }
}
