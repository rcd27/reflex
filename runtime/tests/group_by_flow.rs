use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use futures::StreamExt;
use reflex_core::types::{Flow, Protocol, TcpFlags, TcpOptions, TcpSegment};
use reflex_runtime::stream::FlowConfig;
use reflex_runtime::ReflexRuntimeExt;
use tokio_stream::iter;

fn tcp_seg(src_port: u16, dst_port: u16, seq: u32) -> TcpSegment {
    TcpSegment {
        flow: Flow {
            src: SocketAddr::new(Ipv4Addr::new(10, 0, 0, 1).into(), src_port),
            dst: SocketAddr::new(Ipv4Addr::new(10, 0, 0, 2).into(), dst_port),
            protocol: Protocol::Tcp,
        },
        seq,
        ack: 0,
        flags: TcpFlags::empty(),
        window: 65535,
        options: TcpOptions::default(),
        ttl: 64,
        payload: Vec::new(),
    }
}

#[tokio::test]
async fn group_by_flow_isolates_state_per_flow() {
    let packets = vec![
        tcp_seg(1000, 80, 100), // flow A
        tcp_seg(2000, 80, 200), // flow B
        tcp_seg(1000, 80, 101), // flow A again
        tcp_seg(2000, 80, 201), // flow B again
        tcp_seg(3000, 80, 300), // flow C
    ];

    let config = FlowConfig {
        expire_after: Duration::from_secs(60),
        max_flows: 100,
        sweep_interval: Duration::from_secs(60),
    };

    let results: Vec<(u16, usize)> = iter(packets)
        .group_by_flow(
            config,
            || 0usize,
            |count, seg: TcpSegment| {
                *count += 1;
                Some((seg.flow.src.port(), *count))
            },
        )
        .collect()
        .await;

    assert_eq!(results.len(), 5);

    // Flow A (port 1000): seen twice -> counts 1, 2
    let flow_a: Vec<usize> = results
        .iter()
        .filter(|(port, _)| *port == 1000)
        .map(|(_, c)| *c)
        .collect();
    assert_eq!(flow_a, vec![1, 2]);

    // Flow B (port 2000): seen twice -> counts 1, 2
    let flow_b: Vec<usize> = results
        .iter()
        .filter(|(port, _)| *port == 2000)
        .map(|(_, c)| *c)
        .collect();
    assert_eq!(flow_b, vec![1, 2]);

    // Flow C (port 3000): seen once -> count 1
    let flow_c: Vec<usize> = results
        .iter()
        .filter(|(port, _)| *port == 3000)
        .map(|(_, c)| *c)
        .collect();
    assert_eq!(flow_c, vec![1]);
}

#[tokio::test]
async fn group_by_flow_respects_max_flows() {
    // max_flows=2, send 3 distinct flows
    let packets = vec![
        tcp_seg(1000, 80, 1), // flow A
        tcp_seg(2000, 80, 1), // flow B
        tcp_seg(3000, 80, 1), // flow C — should evict oldest (A)
        tcp_seg(3000, 80, 2), // flow C again — count should be 2
        tcp_seg(1000, 80, 2), // flow A re-created — count restarts at 1
    ];

    let config = FlowConfig {
        expire_after: Duration::from_secs(60),
        max_flows: 2,
        sweep_interval: Duration::from_secs(60),
    };

    let results: Vec<(u16, usize)> = iter(packets)
        .group_by_flow(
            config,
            || 0usize,
            |count, seg: TcpSegment| {
                *count += 1;
                Some((seg.flow.src.port(), *count))
            },
        )
        .collect()
        .await;

    assert_eq!(results.len(), 5);

    // Flow A reappears after eviction -> count restarts
    let flow_a: Vec<usize> = results
        .iter()
        .filter(|(port, _)| *port == 1000)
        .map(|(_, c)| *c)
        .collect();
    assert_eq!(flow_a, vec![1, 1]); // first time count=1, after eviction+recreate count=1

    // Flow C: count 1, then 2
    let flow_c: Vec<usize> = results
        .iter()
        .filter(|(port, _)| *port == 3000)
        .map(|(_, c)| *c)
        .collect();
    assert_eq!(flow_c, vec![1, 2]);
}

#[tokio::test]
async fn group_by_flow_filters_via_none() {
    let packets = vec![
        tcp_seg(1000, 80, 100),
        tcp_seg(1000, 80, 101),
        tcp_seg(1000, 80, 102),
    ];

    let config = FlowConfig::default();

    // Only emit on every 2nd packet per flow
    let results: Vec<u32> = iter(packets)
        .group_by_flow(
            config,
            || 0usize,
            |count, seg: TcpSegment| {
                *count += 1;
                if *count % 2 == 0 {
                    Some(seg.seq)
                } else {
                    None
                }
            },
        )
        .collect()
        .await;

    assert_eq!(results, vec![101]); // only 2nd packet emitted
}

#[tokio::test]
async fn group_by_flow_empty_stream() {
    let config = FlowConfig::default();

    let results: Vec<TcpSegment> = iter(Vec::<TcpSegment>::new())
        .group_by_flow(config, || (), |_, seg| Some(seg))
        .collect()
        .await;

    assert!(results.is_empty());
}
