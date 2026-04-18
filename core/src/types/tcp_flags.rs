use bitflags::bitflags;

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct TcpFlags: u8 {
        const FIN = 0x01;
        const SYN = 0x02;
        const RST = 0x04;
        const PSH = 0x08;
        const ACK = 0x10;
        const URG = 0x20;
    }
}

impl TcpFlags {
    pub fn is_syn(self) -> bool {
        self.contains(TcpFlags::SYN) && !self.contains(TcpFlags::ACK)
    }

    pub fn is_syn_ack(self) -> bool {
        self.contains(TcpFlags::SYN | TcpFlags::ACK)
    }

    pub fn is_rst(self) -> bool {
        self.contains(TcpFlags::RST)
    }

    pub fn is_fin(self) -> bool {
        self.contains(TcpFlags::FIN)
    }

    pub fn is_psh_ack(self) -> bool {
        self.contains(TcpFlags::PSH | TcpFlags::ACK)
    }
}
