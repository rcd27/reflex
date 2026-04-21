use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use reflex_core::geneva::tspu::{BlockageSignal, TspuConfig};
use reflex_core::types::{Flow, Protocol};

fn test_flow() -> Flow {
    Flow {
        src: SocketAddr::new(Ipv4Addr::new(10, 0, 0, 1).into(), 12345),
        dst: SocketAddr::new(Ipv4Addr::new(93, 184, 216, 34).into(), 443),
        protocol: Protocol::Tcp,
    }
}

#[test]
fn rst_injection_signal() {
    let sig = BlockageSignal::RstInjection {
        flow: test_flow(),
        sni: Some("example.com".to_string()),
        ttl_expected: 52,
        ttl_actual: 128,
        salvo_count: 3,
    };
    assert!(matches!(sig, BlockageSignal::RstInjection { .. }));
}

#[test]
fn silent_drop_signal() {
    let sig = BlockageSignal::SilentDrop {
        flow: test_flow(),
        sni: Some("discord.com".to_string()),
        retransmit_count: 5,
    };
    assert!(matches!(
        sig,
        BlockageSignal::SilentDrop {
            retransmit_count: 5,
            ..
        }
    ));
}

#[test]
fn ip_blackhole_signal() {
    let sig = BlockageSignal::IpBlackhole {
        flow: test_flow(),
        sni: None,
        syn_retransmits: 3,
    };
    assert!(matches!(
        sig,
        BlockageSignal::IpBlackhole {
            syn_retransmits: 3,
            ..
        }
    ));
}

#[test]
fn throttle_cliff_signal() {
    let sig = BlockageSignal::ThrottleCliff {
        flow: test_flow(),
        sni: Some("youtube.com".to_string()),
        bytes_before: 16384,
    };
    assert!(matches!(
        sig,
        BlockageSignal::ThrottleCliff {
            bytes_before: 16384,
            ..
        }
    ));
}

#[test]
fn all_signal_variants_constructible() {
    let f = test_flow();
    let signals = vec![
        BlockageSignal::RstInjection {
            flow: f.clone(),
            sni: None,
            ttl_expected: 52,
            ttl_actual: 128,
            salvo_count: 1,
        },
        BlockageSignal::FinInjection {
            flow: f.clone(),
            sni: None,
            ttl_expected: 52,
            ttl_actual: 128,
        },
        BlockageSignal::WindowManipulation {
            flow: f.clone(),
            sni: None,
            window: 0,
        },
        BlockageSignal::IpBlackhole {
            flow: f.clone(),
            sni: None,
            syn_retransmits: 2,
        },
        BlockageSignal::SilentDrop {
            flow: f.clone(),
            sni: None,
            retransmit_count: 3,
        },
        BlockageSignal::ThrottleCliff {
            flow: f.clone(),
            sni: None,
            bytes_before: 8192,
        },
        BlockageSignal::ThrottleProbabilistic {
            flow: f.clone(),
            sni: None,
            retransmit_ratio: 0.4,
        },
        BlockageSignal::AckDrop {
            flow: f.clone(),
            sni: None,
            server_retransmits: 10,
        },
    ];
    assert_eq!(signals.len(), 8);
}

#[test]
fn config_default_values() {
    let cfg = TspuConfig::default();
    assert_eq!(cfg.syn_timeout, Duration::from_secs(5));
    assert_eq!(cfg.post_hello_timeout, Duration::from_secs(15));
    assert_eq!(cfg.ttl_tolerance, 2);
    assert_eq!(cfg.cliff_timeout, Duration::from_secs(3));
    assert_eq!(cfg.cliff_min_bytes, 8192);
    assert_eq!(cfg.cliff_max_bytes, 32768);
    assert_eq!(cfg.throttle_window, Duration::from_secs(10));
    assert!((cfg.retransmit_ratio - 0.3).abs() < 0.01);
}
