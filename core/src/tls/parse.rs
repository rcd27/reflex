use crate::tls::TlsRecord;
use crate::types::TcpSegment;
use futures::{Stream, StreamExt};

pub trait ParseTlsExt: Stream<Item = TcpSegment> + Sized {
    fn parse_tls(self) -> impl Stream<Item = TlsRecord> {
        self.filter_map(|seg| async move {
            if seg.payload.is_empty() {
                return None;
            }
            TlsRecord::parse(&seg.payload)
        })
    }
}

impl<S: Stream<Item = TcpSegment> + Sized> ParseTlsExt for S {}
