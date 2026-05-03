use std::net::SocketAddr;

use super::flow::Flow;
use super::protocol::Protocol;
use super::tcp::TcpSegment;

/// Bidirectional TCP connection identity.
/// Canonical ordering: a <= b (by SocketAddr Ord).
/// One comparison per packet, no allocation, hashable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConnectionId {
    a: SocketAddr,
    b: SocketAddr,
    protocol: Protocol,
}

impl ConnectionId {
    pub fn new(x: SocketAddr, y: SocketAddr, protocol: Protocol) -> Self {
        let (a, b) = if x <= y { (x, y) } else { (y, x) };
        Self { a, b, protocol }
    }

    pub fn endpoints(&self) -> (SocketAddr, SocketAddr) {
        (self.a, self.b)
    }

    pub fn protocol(&self) -> Protocol {
        self.protocol
    }
}

impl Flow {
    pub fn connection_id(&self) -> ConnectionId {
        ConnectionId::new(self.src, self.dst, self.protocol)
    }
}

pub trait HasConnectionId {
    fn connection_id(&self) -> ConnectionId;
}

impl HasConnectionId for TcpSegment {
    fn connection_id(&self) -> ConnectionId {
        self.flow.connection_id()
    }
}

impl HasConnectionId for Flow {
    fn connection_id(&self) -> ConnectionId {
        ConnectionId::new(self.src, self.dst, self.protocol)
    }
}
