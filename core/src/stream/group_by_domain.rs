use std::collections::HashMap;
use std::marker::PhantomData;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures::Stream;
use pin_project_lite::pin_project;

use crate::types::TcpSegment;

pin_project! {
    /// Groups TCP segments by domain name and applies a per-domain operator.
    ///
    /// Domain is resolved via an external function (DNS cache, SNI, etc.).
    /// Packets that don't resolve to a domain are silently skipped.
    /// Domains live forever (no expiry) — suitable for client-side usage.
    ///
    /// Output: `(String, R)` — domain name paired with step result.
    pub struct GroupByDomainStream<S, State, Resolver, Init, Step, R> {
        #[pin]
        source: S,
        resolver: Resolver,
        init: Init,
        step: Step,
        domains: HashMap<String, State>,
        _phantom: PhantomData<R>,
    }
}

impl<S, State, Resolver, Init, Step, R> GroupByDomainStream<S, State, Resolver, Init, Step, R> {
    pub fn new(source: S, resolver: Resolver, init: Init, step: Step) -> Self {
        Self {
            source,
            resolver,
            init,
            step,
            domains: HashMap::new(),
            _phantom: PhantomData,
        }
    }
}

impl<S, State, Resolver, Init, Step, R> Stream
    for GroupByDomainStream<S, State, Resolver, Init, Step, R>
where
    S: Stream<Item = TcpSegment>,
    Resolver: Fn(&TcpSegment) -> Option<String>,
    Init: Fn() -> State,
    Step: FnMut(&mut State, TcpSegment) -> Option<R>,
{
    type Item = (String, R);

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.project();

        match this.source.poll_next(cx) {
            Poll::Ready(Some(segment)) => {
                let domain = match (this.resolver)(&segment) {
                    Some(d) => d,
                    None => {
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                };

                let state = this
                    .domains
                    .entry(domain.clone())
                    .or_insert_with(&*this.init);

                if let Some(result) = (this.step)(state, segment) {
                    Poll::Ready(Some((domain, result)))
                } else {
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
            }
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ext::ReflexExt;
    use crate::types::{Flow, Protocol, TcpFlags, TcpOptions};
    use futures::stream;
    use futures::StreamExt;
    use std::net::SocketAddr;

    fn make_segment(src_port: u16, dst_ip: &str, dst_port: u16) -> TcpSegment {
        TcpSegment {
            flow: Flow {
                src: SocketAddr::new("10.0.0.1".parse().unwrap(), src_port),
                dst: SocketAddr::new(dst_ip.parse().unwrap(), dst_port),
                protocol: Protocol::Tcp,
            },
            seq: 0,
            ack: 0,
            flags: TcpFlags::SYN,
            window: 65535,
            options: TcpOptions::default(),
            ttl: 64,
            payload: vec![],
        }
    }

    #[tokio::test]
    async fn groups_by_resolved_domain() {
        let packets = vec![
            make_segment(1000, "1.2.3.4", 443),
            make_segment(1001, "1.2.3.4", 443),
            make_segment(2000, "5.6.7.8", 443),
        ];

        let resolver = |seg: &TcpSegment| -> Option<String> {
            match seg.flow.dst.ip().to_string().as_str() {
                "1.2.3.4" => Some("example.com".to_string()),
                "5.6.7.8" => Some("other.org".to_string()),
                _ => None,
            }
        };

        let results: Vec<(String, usize)> = stream::iter(packets)
            .group_by_domain(
                resolver,
                || 0usize,
                |count, _seg| {
                    *count += 1;
                    Some(*count)
                },
            )
            .collect()
            .await;

        assert_eq!(
            results,
            vec![
                ("example.com".to_string(), 1),
                ("example.com".to_string(), 2),
                ("other.org".to_string(), 1),
            ]
        );
    }

    #[tokio::test]
    async fn unresolvable_packets_skipped() {
        let packets = vec![
            make_segment(1000, "1.2.3.4", 443),
            make_segment(2000, "9.9.9.9", 443),
        ];

        let resolver = |seg: &TcpSegment| -> Option<String> {
            if seg.flow.dst.ip().to_string() == "1.2.3.4" {
                Some("example.com".to_string())
            } else {
                None
            }
        };

        let results: Vec<(String, u32)> = stream::iter(packets)
            .group_by_domain(
                resolver,
                || 0u32,
                |count, _| {
                    *count += 1;
                    Some(*count)
                },
            )
            .collect()
            .await;

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, "example.com");
    }
}
