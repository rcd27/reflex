//! conntrack как НОСИТЕЛЬ закона `EdgeView` (core). Вид ядра (`CtView`) — то, что приехало с
//! пакетом; база таймаута — конфигурация машины, прочитанная при старте (не приезжает от ядра на
//! каждом пакете). `idle = база − остаток` есть знание conntrack о себе, потому живёт здесь, где оба
//! слагаемых на руках, а не в приборе: иначе второй край (eBPF) считал бы иначе — два закона об
//! одной величине.

use std::time::Duration;

use reflex_core::edge::EdgeView;

use super::wire::{CtTcp, CtView};

/// База таймаута ядра по состоянию TCP — sysctl `nf_conntrack_tcp_timeout_*`, снимается при старте.
/// Прочих состояний не держим: idle считаем там, где он осмыслен (ожидание ответа), — рукопожатие и
/// установленное соединение.
#[derive(Debug, Clone, Copy)]
pub struct TimeoutBase {
    pub syn_sent: Duration,
    pub established: Duration,
}

impl TimeoutBase {
    fn for_state(&self, tcp: Option<CtTcp>) -> Option<Duration> {
        match tcp {
            Some(CtTcp::SynSent) => Some(self.syn_sent),
            Some(CtTcp::Established) => Some(self.established),
            _other => None,
        }
    }
}

/// Носитель `EdgeView`: вид ядра плюс база таймаута, которой виду не хватает для `idle`.
pub struct CtEdge {
    pub view: CtView,
    pub base: TimeoutBase,
}

impl EdgeView for CtEdge {
    fn down_packets(&self) -> Option<u64> {
        Some(self.view.down.packets)
    }

    fn up_packets(&self) -> Option<u64> {
        Some(self.view.up.packets)
    }

    /// `база(состояние) − остаток`. `None`, если состояние не из тех, чью базу держим, или ядро
    /// остатка не дало. Пересчёт — знание conntrack о себе, приборам его знать незачем.
    fn idle(&self) -> Option<Duration> {
        let base = self.base.for_state(self.view.tcp)?;
        let remaining = self.view.expires_in?;
        base.checked_sub(remaining)
    }

    fn mark(&self) -> u32 {
        self.view.mark
    }
}
