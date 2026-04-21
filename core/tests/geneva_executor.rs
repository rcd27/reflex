use std::net::{Ipv4Addr, SocketAddr};

use reflex_core::command::Command;
use reflex_core::geneva::executor::execute;
use reflex_core::geneva::{
    GenevaAction, GenevaStrategy, PacketField, StrategyNode, TamperOp, Trigger,
};
use reflex_core::types::{Flow, Mac, Protocol, TcpFlags, TcpOptions, TcpSegment};

fn test_segment(flags: TcpFlags, payload: &[u8]) -> TcpSegment {
    TcpSegment {
        flow: Flow {
            src: SocketAddr::new(Ipv4Addr::new(10, 0, 0, 1).into(), 12345),
            dst: SocketAddr::new(Ipv4Addr::new(93, 184, 216, 34).into(), 443),
            protocol: Protocol::Tcp,
        },
        seq: 1000,
        ack: 2000,
        flags,
        window: 65535,
        options: TcpOptions::default(),
        ttl: 64,
        payload: payload.to_vec(),
    }
}

fn tls_client_hello_payload() -> Vec<u8> {
    vec![0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00]
}

#[test]
fn trigger_no_match_returns_empty() {
    let strategy = GenevaStrategy {
        trigger: Trigger {
            protocol: Protocol::Tcp,
            flags: Some(TcpFlags::SYN),
            has_tls_hello: false,
        },
        tree: StrategyNode::Action {
            action: GenevaAction::Drop,
            then: vec![],
        },
    };
    let seg = test_segment(TcpFlags::PSH | TcpFlags::ACK, &[]);
    let cmds = execute(&strategy, &seg, &Mac([0; 6]), &Mac([0; 6]));
    assert!(cmds.is_empty());
}

#[test]
fn send_node_produces_accept() {
    let strategy = GenevaStrategy {
        trigger: Trigger {
            protocol: Protocol::Tcp,
            flags: None,
            has_tls_hello: false,
        },
        tree: StrategyNode::Send,
    };
    let seg = test_segment(TcpFlags::PSH | TcpFlags::ACK, &[]);
    let cmds = execute(&strategy, &seg, &Mac([0; 6]), &Mac([0; 6]));
    assert_eq!(cmds.len(), 1);
    assert!(matches!(cmds[0], Command::Accept(_)));
}

#[test]
fn drop_action_produces_drop_command() {
    let strategy = GenevaStrategy {
        trigger: Trigger {
            protocol: Protocol::Tcp,
            flags: Some(TcpFlags::PSH | TcpFlags::ACK),
            has_tls_hello: false,
        },
        tree: StrategyNode::Action {
            action: GenevaAction::Drop,
            then: vec![],
        },
    };
    let seg = test_segment(TcpFlags::PSH | TcpFlags::ACK, &[]);
    let cmds = execute(&strategy, &seg, &Mac([0; 6]), &Mac([0; 6]));
    assert_eq!(cmds.len(), 1);
    assert!(matches!(cmds[0], Command::DropFlow(_)));
}

#[test]
fn duplicate_produces_inject_and_accept() {
    let strategy = GenevaStrategy {
        trigger: Trigger {
            protocol: Protocol::Tcp,
            flags: None,
            has_tls_hello: false,
        },
        tree: StrategyNode::Action {
            action: GenevaAction::Duplicate { modify: None },
            then: vec![StrategyNode::Send, StrategyNode::Send],
        },
    };
    let seg = test_segment(TcpFlags::PSH | TcpFlags::ACK, &[]);
    let cmds = execute(&strategy, &seg, &Mac([0; 6]), &Mac([0; 6]));
    assert_eq!(cmds.len(), 2);
    assert!(matches!(cmds[0], Command::Inject(_)));
    assert!(matches!(cmds[1], Command::Accept(_)));
}

#[test]
fn tamper_ttl_on_duplicate_modifies_copy() {
    let strategy = GenevaStrategy {
        trigger: Trigger {
            protocol: Protocol::Tcp,
            flags: None,
            has_tls_hello: false,
        },
        tree: StrategyNode::Action {
            action: GenevaAction::Duplicate {
                modify: Some(Box::new(GenevaAction::Tamper {
                    field: PacketField::IpTtl,
                    op: TamperOp::Replace(vec![1]),
                })),
            },
            then: vec![StrategyNode::Send, StrategyNode::Send],
        },
    };
    let seg = test_segment(TcpFlags::PSH | TcpFlags::ACK, &[]);
    let cmds = execute(&strategy, &seg, &Mac([0; 6]), &Mac([0; 6]));
    assert_eq!(cmds.len(), 2);
    match &cmds[0] {
        Command::Inject(pkt) => {
            let bytes = pkt.serialize();
            assert_eq!(bytes[22], 1, "TTL should be 1 in injected copy");
        }
        _ => panic!("expected Inject, got something else"),
    }
}

#[test]
fn tls_hello_trigger_matches() {
    let strategy = GenevaStrategy {
        trigger: Trigger {
            protocol: Protocol::Tcp,
            flags: Some(TcpFlags::PSH | TcpFlags::ACK),
            has_tls_hello: true,
        },
        tree: StrategyNode::Action {
            action: GenevaAction::Drop,
            then: vec![],
        },
    };
    let payload = tls_client_hello_payload();
    let seg = test_segment(TcpFlags::PSH | TcpFlags::ACK, &payload);
    let cmds = execute(&strategy, &seg, &Mac([0; 6]), &Mac([0; 6]));
    assert_eq!(cmds.len(), 1);
}

#[test]
fn tls_hello_trigger_no_match_on_non_hello() {
    let strategy = GenevaStrategy {
        trigger: Trigger {
            protocol: Protocol::Tcp,
            flags: None,
            has_tls_hello: true,
        },
        tree: StrategyNode::Action {
            action: GenevaAction::Drop,
            then: vec![],
        },
    };
    let seg = test_segment(TcpFlags::PSH | TcpFlags::ACK, &[0x00, 0x01, 0x02]);
    let cmds = execute(&strategy, &seg, &Mac([0; 6]), &Mac([0; 6]));
    assert!(cmds.is_empty());
}
