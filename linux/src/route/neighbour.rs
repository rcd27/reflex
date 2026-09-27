//! СОСЕД, КОТОРОГО ЯДРО САМО НЕ ВЫУЧИТ: постоянная запись «адрес → MAC» на устройстве.
//!
//! Устройство без своего адреса (мост в разрыве провода) спрашивает ARP от чужого адреса, и шлюз
//! провайдера, отвечающий только своему абоненту, молчит — сосед навсегда `INCOMPLETE`, и всё, что
//! машина маршрутизирует через него, пропадает. Замер 27.09.2026 (nevod #354): три коробки из
//! трёх на IPoE, шлюз молчит на ARP коробки и в ту же минуту отвечает роутеру. MAC шлюза при этом
//! виден в самих кадрах человека — ставится записью, минуя ARP.
//!
//! Правила не свои: кто поставил соседа — тот и снимает ([`unsettle`]).

use std::fmt;
use std::net::Ipv4Addr;

use reflex_core::types::Mac;

use super::socket::{index_of, Router};
use super::wire::{neighbour_request, neighbour_withdrawal, Settled};

/// Чем запись соседа не состоялась.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unsettled {
    /// Устройства нет в этом сетевом пространстве.
    NoDevice(String),
    /// Маршрутизатор не спросить: errno сокета.
    Socket(i32),
    /// Ядро отказало: положительный errno.
    Refused(i32),
    /// Ни подтверждения, ни отказа.
    Unread,
}

impl fmt::Display for Unsettled {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoDevice(device) => {
                write!(f, "устройства «{device}» нет — соседа ставить некуда")
            }
            Self::Socket(code) => write!(f, "маршрутизатор ядра не спросить: errno {code}"),
            Self::Refused(code) => write!(f, "ядро отказало записать соседа: errno {code}"),
            Self::Unread => write!(f, "ядро не ответило на запись соседа"),
        }
    }
}

impl std::error::Error for Unsettled {}

fn written(device: &str, request: impl Fn(u32) -> Vec<u8>) -> Result<(), Unsettled> {
    let index = index_of(device).ok_or_else(|| Unsettled::NoDevice(device.to_string()))?;
    let router = Router::open().map_err(Unsettled::Socket)?;
    match router.written(&request(index)).map_err(Unsettled::Socket)? {
        Settled::Acked => Ok(()),
        Settled::Refused(code) => Err(Unsettled::Refused(code)),
        Settled::Unread => Err(Unsettled::Unread),
    }
}

/// Поставить постоянного соседа `hop` → `mac` на `device`, заменив прежнего.
pub fn settle(device: &str, hop: Ipv4Addr, mac: Mac) -> Result<(), Unsettled> {
    written(device, |index| neighbour_request(index, hop, mac, 1))
}

/// Снять соседа `hop` с `device`.
pub fn unsettle(device: &str, hop: Ipv4Addr) -> Result<(), Unsettled> {
    written(device, |index| neighbour_withdrawal(index, hop, 2))
}
