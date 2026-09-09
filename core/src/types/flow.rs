use crate::types::protocol::Protocol;
use std::net::SocketAddr;

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
/// Личность разговора — четвёрка, которой область `Conversation` расслаивается (§4, `Base::Fibre`).
/// `Copy` и `Ord` не украшение: личность ездит по значению на горячем пути и служит ключом
/// упорядоченных карт. Порядок сравнения смысла не несёт — он нужен контейнеру, не разговору.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Flow {
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub protocol: Protocol,
}

impl Flow {
    pub fn reversed(&self) -> Self {
        Flow {
            src: self.dst,
            dst: self.src,
            protocol: self.protocol,
        }
    }
}

pub trait HasFlow {
    fn flow(&self) -> &Flow;
}
