use reflex_core::geneva::{
    GenevaAction, GenevaStrategy, PacketField, StrategyNode, TamperOp, Trigger,
};
use reflex_core::types::{Protocol, TcpFlags};

#[test]
fn trigger_matches_tcp_flags() {
    let trigger = Trigger {
        protocol: Protocol::Tcp,
        flags: Some(TcpFlags::PSH | TcpFlags::ACK),
        has_tls_hello: false,
    };
    assert!(trigger.matches(Protocol::Tcp, TcpFlags::PSH | TcpFlags::ACK, false));
    assert!(!trigger.matches(Protocol::Tcp, TcpFlags::SYN, false));
    assert!(!trigger.matches(Protocol::Udp, TcpFlags::PSH | TcpFlags::ACK, false));
}

#[test]
fn trigger_matches_tls_hello() {
    let trigger = Trigger {
        protocol: Protocol::Tcp,
        flags: None,
        has_tls_hello: true,
    };
    assert!(trigger.matches(Protocol::Tcp, TcpFlags::PSH | TcpFlags::ACK, true));
    assert!(!trigger.matches(Protocol::Tcp, TcpFlags::PSH | TcpFlags::ACK, false));
}

#[test]
fn trigger_any_flags() {
    let trigger = Trigger {
        protocol: Protocol::Tcp,
        flags: None,
        has_tls_hello: false,
    };
    assert!(trigger.matches(Protocol::Tcp, TcpFlags::SYN, false));
    assert!(trigger.matches(Protocol::Tcp, TcpFlags::RST, false));
}

#[test]
fn strategy_node_send() {
    let node = StrategyNode::Send;
    match node {
        StrategyNode::Send => {}
        _ => panic!("expected Send"),
    }
}

#[test]
fn strategy_tree_duplicate_tamper_send() {
    let tree = StrategyNode::Action {
        action: GenevaAction::Duplicate {
            modify: Some(Box::new(GenevaAction::Tamper {
                field: PacketField::IpTtl,
                op: TamperOp::Replace(vec![1]),
            })),
        },
        then: vec![StrategyNode::Send, StrategyNode::Send],
    };
    match tree {
        StrategyNode::Action {
            ref action,
            ref then,
        } => {
            assert!(matches!(action, GenevaAction::Duplicate { .. }));
            assert_eq!(then.len(), 2);
        }
        _ => panic!("expected Action"),
    }
}

#[test]
fn strategy_depth() {
    let leaf = StrategyNode::Send;
    assert_eq!(leaf.depth(), 0);

    let one_level = StrategyNode::Action {
        action: GenevaAction::Drop,
        then: vec![StrategyNode::Send],
    };
    assert_eq!(one_level.depth(), 1);

    let two_levels = StrategyNode::Action {
        action: GenevaAction::Duplicate { modify: None },
        then: vec![
            StrategyNode::Action {
                action: GenevaAction::Drop,
                then: vec![StrategyNode::Send],
            },
            StrategyNode::Send,
        ],
    };
    assert_eq!(two_levels.depth(), 2);
}

#[test]
fn strategy_node_count() {
    let tree = StrategyNode::Action {
        action: GenevaAction::Duplicate { modify: None },
        then: vec![
            StrategyNode::Action {
                action: GenevaAction::Drop,
                then: vec![StrategyNode::Send],
            },
            StrategyNode::Send,
        ],
    };
    assert_eq!(tree.node_count(), 4);
}

#[test]
fn geneva_strategy_construction() {
    let strategy = GenevaStrategy {
        trigger: Trigger {
            protocol: Protocol::Tcp,
            flags: Some(TcpFlags::PSH | TcpFlags::ACK),
            has_tls_hello: true,
        },
        tree: StrategyNode::Action {
            action: GenevaAction::Tamper {
                field: PacketField::IpTtl,
                op: TamperOp::Replace(vec![1]),
            },
            then: vec![StrategyNode::Send],
        },
    };
    assert!(strategy.trigger.has_tls_hello);
    assert_eq!(strategy.tree.depth(), 1);
}
