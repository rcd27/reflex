use crate::geneva::action::GenevaAction;
use crate::types::{Protocol, TcpFlags};

#[derive(Debug, Clone, PartialEq)]
pub struct Trigger {
    pub protocol: Protocol,
    pub flags: Option<TcpFlags>,
    pub has_tls_hello: bool,
}

impl Trigger {
    pub fn matches(&self, protocol: Protocol, flags: TcpFlags, has_tls_hello: bool) -> bool {
        if self.protocol != protocol {
            return false;
        }
        if let Some(required) = self.flags {
            if !flags.contains(required) {
                return false;
            }
        }
        if self.has_tls_hello && !has_tls_hello {
            return false;
        }
        true
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum StrategyNode {
    Send,
    Action {
        action: GenevaAction,
        then: Vec<StrategyNode>,
    },
}

impl StrategyNode {
    pub fn depth(&self) -> usize {
        match self {
            StrategyNode::Send => 0,
            StrategyNode::Action { then, .. } => {
                1 + then.iter().map(|n| n.depth()).max().unwrap_or(0)
            }
        }
    }

    pub fn node_count(&self) -> usize {
        match self {
            StrategyNode::Send => 1,
            StrategyNode::Action { then, .. } => {
                1 + then.iter().map(|n| n.node_count()).sum::<usize>()
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct GenevaStrategy {
    pub trigger: Trigger,
    pub tree: StrategyNode,
}
