use crate::types::protocol::Protocol;
use std::net::SocketAddr;

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Flow {
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub protocol: Protocol,
}

impl Flow {
    pub fn reversed(&self) -> Self {
        Flow {
            src: self.dst,
            dst: self.src,
            protocol: self.protocol,
        }
    }
}

pub trait HasFlow {
    fn flow(&self) -> &Flow;
}
