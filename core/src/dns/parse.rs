use crate::dns::DnsMessage;
use crate::types::UdpDatagram;
use futures::{Stream, StreamExt};

pub trait ParseDnsExt: Stream<Item = UdpDatagram> + Sized {
    fn parse_dns(self) -> impl Stream<Item = DnsMessage> {
        self.filter_map(|dgram| async move { DnsMessage::parse(&dgram.payload) })
    }
}

impl<S: Stream<Item = UdpDatagram> + Sized> ParseDnsExt for S {}
