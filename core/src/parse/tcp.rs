use crate::types::{IpProtocol, Ipv4Packet, TcpSegment};
use futures::{Stream, StreamExt};

pub trait ParseTcpExt: Stream<Item = Ipv4Packet> + Sized {
    fn parse_tcp(self) -> impl Stream<Item = TcpSegment> {
        self.filter_map(|pkt| async move {
            if pkt.protocol != IpProtocol::Tcp {
                return None;
            }
            TcpSegment::parse(&pkt.payload, pkt.src, pkt.dst, pkt.ttl)
        })
    }
}

impl<S: Stream<Item = Ipv4Packet> + Sized> ParseTcpExt for S {}
