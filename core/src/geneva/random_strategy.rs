use rand::{Rng, RngExt};

use crate::geneva::action::{FragProtocol, GenevaAction, PacketField, TamperOp};
use crate::geneva::strategy::{GenevaStrategy, StrategyNode, Trigger};
use crate::types::{Protocol, TcpFlags};

/// Known-effective strategies against Russian TSPU.
pub fn seed_strategies() -> Vec<GenevaStrategy> {
    let tls_trigger = Trigger {
        protocol: Protocol::Tcp,
        flags: Some(TcpFlags::PSH | TcpFlags::ACK),
        has_tls_hello: true,
    };

    vec![
        // 1. Split ClientHello at byte 1 (in order) — SNI разрезан, ТСПУ не видит
        GenevaStrategy {
            trigger: tls_trigger.clone(),
            tree: StrategyNode::Action {
                action: GenevaAction::Fragment {
                    protocol: FragProtocol::Tcp,
                    offset: 1,
                    in_order: true,
                },
                then: vec![],
            },
        },
        // 2. Split ClientHello at byte 3 (in order)
        GenevaStrategy {
            trigger: tls_trigger.clone(),
            tree: StrategyNode::Action {
                action: GenevaAction::Fragment {
                    protocol: FragProtocol::Tcp,
                    offset: 3,
                    in_order: true,
                },
                then: vec![],
            },
        },
        // 3. Split ClientHello at byte 5 (disorder — second part first)
        GenevaStrategy {
            trigger: tls_trigger.clone(),
            tree: StrategyNode::Action {
                action: GenevaAction::Fragment {
                    protocol: FragProtocol::Tcp,
                    offset: 5,
                    in_order: false,
                },
                then: vec![],
            },
        },
        // 4. Fake + TTL1: duplicate, modify copy TTL=1, send before original
        GenevaStrategy {
            trigger: tls_trigger.clone(),
            tree: StrategyNode::Action {
                action: GenevaAction::Duplicate {
                    modify: Some(Box::new(GenevaAction::Tamper {
                        field: PacketField::IpTtl,
                        op: TamperOp::Replace(vec![1]),
                    })),
                },
                then: vec![StrategyNode::Send, StrategyNode::Send],
            },
        },
        // 5. Fake + TTL3: duplicate, TTL=3 (survives a few hops, dies before DPI)
        GenevaStrategy {
            trigger: tls_trigger.clone(),
            tree: StrategyNode::Action {
                action: GenevaAction::Duplicate {
                    modify: Some(Box::new(GenevaAction::Tamper {
                        field: PacketField::IpTtl,
                        op: TamperOp::Replace(vec![3]),
                    })),
                },
                then: vec![StrategyNode::Send, StrategyNode::Send],
            },
        },
        // 6. Fake with corrupted checksum + original
        GenevaStrategy {
            trigger: tls_trigger.clone(),
            tree: StrategyNode::Action {
                action: GenevaAction::Duplicate {
                    modify: Some(Box::new(GenevaAction::Tamper {
                        field: PacketField::TcpChecksum,
                        op: TamperOp::Corrupt,
                    })),
                },
                then: vec![StrategyNode::Send, StrategyNode::Send],
            },
        },
        // 7. Split at byte 2 (disorder)
        GenevaStrategy {
            trigger: tls_trigger.clone(),
            tree: StrategyNode::Action {
                action: GenevaAction::Fragment {
                    protocol: FragProtocol::Tcp,
                    offset: 2,
                    in_order: false,
                },
                then: vec![],
            },
        },
    ]
}

pub struct RandomStrategyGen {
    pub max_depth: usize,
}

impl RandomStrategyGen {
    pub fn generate(&self, rng: &mut impl Rng) -> GenevaStrategy {
        GenevaStrategy {
            trigger: random_trigger(rng),
            tree: random_node(rng, self.max_depth),
        }
    }
}

fn random_trigger(rng: &mut impl Rng) -> Trigger {
    Trigger {
        protocol: Protocol::Tcp,
        flags: Some(TcpFlags::PSH | TcpFlags::ACK),
        has_tls_hello: rng.random_bool(0.5),
    }
}

fn random_node(rng: &mut impl Rng, max_depth: usize) -> StrategyNode {
    if max_depth == 0 || rng.random_bool(0.3) {
        return StrategyNode::Send;
    }
    let action = random_action(rng);
    let child_count = match &action {
        GenevaAction::Duplicate { .. } => 2,
        GenevaAction::Fragment { .. } => 0,
        GenevaAction::Tamper { .. } => 1,
        GenevaAction::Drop => 0,
    };
    let then = (0..child_count)
        .map(|_| random_node(rng, max_depth - 1))
        .collect();
    StrategyNode::Action { action, then }
}

fn random_action(rng: &mut impl Rng) -> GenevaAction {
    match rng.random_range(0..4u8) {
        0 => GenevaAction::Duplicate {
            modify: if rng.random_bool(0.5) {
                Some(Box::new(GenevaAction::Tamper {
                    field: random_field(rng),
                    op: random_op(rng),
                }))
            } else {
                None
            },
        },
        1 => GenevaAction::Fragment {
            protocol: if rng.random_bool(0.7) {
                FragProtocol::Tcp
            } else {
                FragProtocol::Ip
            },
            offset: rng.random_range(1..64usize),
            in_order: rng.random_bool(0.5),
        },
        2 => GenevaAction::Tamper {
            field: random_field(rng),
            op: random_op(rng),
        },
        _ => GenevaAction::Drop,
    }
}

fn random_field(rng: &mut impl Rng) -> PacketField {
    match rng.random_range(0..7u8) {
        0 => PacketField::TcpFlags,
        1 => PacketField::IpTtl,
        2 => PacketField::TcpChecksum,
        3 => PacketField::TcpSeq,
        4 => PacketField::TcpAck,
        5 => PacketField::TcpWindow,
        _ => PacketField::TcpOptions,
    }
}

fn random_op(rng: &mut impl Rng) -> TamperOp {
    if rng.random_bool(0.5) {
        TamperOp::Corrupt
    } else {
        TamperOp::Replace(vec![rng.random_range(1..255u8)])
    }
}
