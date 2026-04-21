use crate::builder::{BuiltTcpPacket, BuiltUdpPacket};
use crate::types::Flow;

/// Типизированная команда — терминальный морфизм категории.
pub enum Command {
    /// Инжектировать пакет в сеть.
    Inject(InjectablePacket),
    /// Дропнуть flow через backend (TC-BPF / XDP).
    DropFlow(Flow),
    /// Снять drop с flow.
    ClearFlow(Flow),
}

/// Пакет, готовый к инжекции. Фреймворк сериализует в байты.
pub enum InjectablePacket {
    /// Типизированный TCP-пакет с вычисленными чексуммами.
    Tcp(BuiltTcpPacket),
    /// Типизированный UDP-пакет с вычисленными чексуммами.
    Udp(BuiltUdpPacket),
    /// Escape hatch — explicit opt-out из типизации.
    Raw(Vec<u8>),
}

impl InjectablePacket {
    pub fn serialize(&self) -> Vec<u8> {
        match self {
            InjectablePacket::Tcp(pkt) => pkt.serialize(),
            InjectablePacket::Udp(pkt) => pkt.serialize(),
            InjectablePacket::Raw(bytes) => bytes.clone(),
        }
    }
}
