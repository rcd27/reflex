use crate::types::EthernetFrame;
use futures::{Stream, StreamExt};

pub trait ParseEthernetExt: Stream<Item = Vec<u8>> + Sized {
    fn parse_ethernet(self) -> impl Stream<Item = EthernetFrame> {
        self.filter_map(|raw| async move { EthernetFrame::parse(&raw) })
    }
}

impl<S: Stream<Item = Vec<u8>> + Sized> ParseEthernetExt for S {}
