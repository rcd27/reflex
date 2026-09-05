use crate::builder::{BuiltTcpPacket, BuiltUdpPacket};
use crate::types::Flow;

/// Типизированная команда — терминальный морфизм категории.
pub enum Command {
    /// Инжектировать пакет в сеть (CanInject).
    Inject(InjectablePacket),
    /// Дропнуть flow через backend (CanDrop).
    DropFlow(Flow),
    /// Снять drop с flow.
    ClearFlow(Flow),
    /// Задержать пакет pending verdict (CanHold).
    Hold(Flow),
    /// Модифицировать оригинальный пакет и пропустить (CanModify).
    Modify(ModifyPacket),
    /// Принять/отпустить задержанный пакет.
    Accept(Flow),
}

/// Пакет, готовый к инжекции. Фреймворк сериализует в байты.
#[derive(Debug, Clone)]
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

    /// Serialize without ethernet header — for raw socket injection.
    pub fn serialize_ip(&self) -> Vec<u8> {
        match self {
            InjectablePacket::Tcp(pkt) => pkt.serialize_ip(),
            InjectablePacket::Udp(pkt) => pkt.serialize_ip(),
            InjectablePacket::Raw(bytes) => bytes.clone(),
        }
    }
}

/// Описание модификации оригинального пакета.
pub struct ModifyPacket {
    pub flow: Flow,
    pub new_data: Vec<u8>,
}
