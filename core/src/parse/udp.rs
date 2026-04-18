use crate::types::{IpProtocol, Ipv4Packet, UdpDatagram};
use futures::{Stream, StreamExt};

pub trait ParseUdpExt: Stream<Item = Ipv4Packet> + Sized {
    fn parse_udp(self) -> impl Stream<Item = UdpDatagram> {
        self.filter_map(|pkt| async move {
            if pkt.protocol != IpProtocol::Udp {
                return None;
            }
            UdpDatagram::parse(&pkt.payload, pkt.src, pkt.dst, pkt.ttl)
        })
    }
}

impl<S: Stream<Item = Ipv4Packet> + Sized> ParseUdpExt for S {}
