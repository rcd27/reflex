#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EtherType {
    Ipv4,
    Ipv6,
    Arp,
    Other(u16),
}

impl EtherType {
    pub fn from_u16(value: u16) -> Self {
        match value {
            0x0800 => EtherType::Ipv4,
            0x86DD => EtherType::Ipv6,
            0x0806 => EtherType::Arp,
            other => EtherType::Other(other),
        }
    }

    pub fn to_u16(self) -> u16 {
        match self {
            EtherType::Ipv4 => 0x0800,
            EtherType::Ipv6 => 0x86DD,
            EtherType::Arp => 0x0806,
            EtherType::Other(v) => v,
        }
    }
}
