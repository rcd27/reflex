use std::net::SocketAddr;
use std::time::Duration;

use futures::StreamExt;
use reflex_core::stream::FlowConfig;
use reflex_core::types::{Flow, Protocol, TcpFlags, TcpOptions, TcpSegment};
use reflex_core::ReflexExt;

fn addr(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

fn segment(src: &str, dst: &str, flags: TcpFlags) -> TcpSegment {
    TcpSegment {
        flow: Flow {
            src: addr(src),
            dst: addr(dst),
            protocol: Protocol::Tcp,
        },
        seq: 0,
        ack: 0,
        flags,
        window: 65535,
        options: TcpOptions::default(),
        ttl: 64,
        payload: vec![],
    }
}

#[tokio::test]
async fn both_directions_same_group() {
    let packets = vec![
        segment("10.0.0.1:54321", "104.21.32.39:443", TcpFlags::SYN),
        segment(
            "104.21.32.39:443",
            "10.0.0.1:54321",
            TcpFlags::SYN | TcpFlags::ACK,
        ),
        segment("10.0.0.1:54321", "104.21.32.39:443", TcpFlags::ACK),
    ];

    let config = FlowConfig {
        expire_after: Duration::from_secs(60),
        max_flows: 100,
        sweep_interval: Duration::from_secs(60),
    };

    let results: Vec<u32> = tokio_stream::iter(packets)
        .group_by_connection(
            config,
            |_conn_id| 0u32,
            |count, _segment| {
                *count += 1;
                Some(*count)
            },
        )
        .collect()
        .await;

    assert_eq!(results, vec![1, 2, 3]);
}

#[tokio::test]
async fn different_connections_different_groups() {
    let packets = vec![
        segment("10.0.0.1:54321", "104.21.32.39:443", TcpFlags::SYN),
        segment("10.0.0.1:54322", "104.21.32.39:443", TcpFlags::SYN),
        segment(
            "104.21.32.39:443",
            "10.0.0.1:54321",
            TcpFlags::SYN | TcpFlags::ACK,
        ),
        segment(
            "104.21.32.39:443",
            "10.0.0.1:54322",
            TcpFlags::SYN | TcpFlags::ACK,
        ),
    ];

    let config = FlowConfig::default();

    let results: Vec<u32> = tokio_stream::iter(packets)
        .group_by_connection(
            config,
            |_conn_id| 0u32,
            |count, _segment| {
                *count += 1;
                Some(*count)
            },
        )
        .collect()
        .await;

    assert_eq!(results, vec![1, 1, 2, 2]);
}
