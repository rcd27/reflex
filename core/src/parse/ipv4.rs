use crate::types::{EtherType, EthernetFrame, Ipv4Packet};
use futures::{Stream, StreamExt};

pub trait ParseIpv4Ext: Stream<Item = EthernetFrame> + Sized {
    fn parse_ipv4(self) -> impl Stream<Item = Ipv4Packet> {
        self.filter_map(|frame| async move {
            if frame.ethertype != EtherType::Ipv4 {
                return None;
            }
            Ipv4Packet::parse(&frame.payload)
        })
    }
}

impl<S: Stream<Item = EthernetFrame> + Sized> ParseIpv4Ext for S {}
