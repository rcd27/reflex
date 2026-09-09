//! Два крыла помечены устаревшими: `tc` и `tun`. Обе фичи включает только закрытая deprecated-ветка;
//! у живых потребителей в зависимостях лишь `nfqueue` и `conntrack`. Помечены, а не снесены: там
//! техника (eBPF-steering с картами действий, userspace-терминация TCP поверх smoltcp) — полезное
//! достанут разбором. Пометка атрибутом, а не только прозой: включивший фичу услышит компилятор.

mod capture;
#[cfg(feature = "conntrack")]
pub mod conntrack;
mod inject;
#[cfg(feature = "nfqueue")]
pub mod nfqueue;
pub mod rawsend;

/// Единственный потребитель закрыт. eBPF-загрузчик со steering-картами: 809 строк, 20 публичных
/// имён не зовёт никто. Полезное есть (быстрый датаплейн в ядре) — крыло помечено, не снесено.
#[cfg(feature = "tc")]
#[deprecated(
    since = "0.0.1",
    note = "фичу `tc` включает только невод 1 (закрыт); разбор техники отложен — см. заголовок lib.rs"
)]
pub mod tc;

/// Единственный потребитель закрыт. Общая часть терминации.
// Крыло помечено целиком, обращения его частей друг к другу — шум: пометку услышит включающий фичу.
#[cfg(feature = "tun")]
#[allow(deprecated)]
#[deprecated(
    since = "0.0.1",
    note = "фичу `tun` включает только невод 1 (закрыт); разбор техники отложен — см. заголовок lib.rs"
)]
pub mod tun;

/// Исходящая терминация поверх smoltcp (600 строк). Потребитель закрыт.
// Крыло помечено целиком, обращения его частей друг к другу — шум: пометку услышит включающий фичу.
#[cfg(feature = "tun")]
#[allow(deprecated)]
#[deprecated(
    since = "0.0.1",
    note = "фичу `tun` включает только невод 1 (закрыт); разбор техники отложен — см. заголовок lib.rs"
)]
pub mod tun_egress;

/// Входящая терминация поверх smoltcp (892 строки). Потребитель закрыт.
// Крыло помечено целиком, обращения его частей друг к другу — шум: пометку услышит включающий фичу.
#[cfg(feature = "tun")]
#[allow(deprecated)]
#[deprecated(
    since = "0.0.1",
    note = "фичу `tun` включает только невод 1 (закрыт); разбор техники отложен — см. заголовок lib.rs"
)]
pub mod tun_listen;

use std::pin::Pin;
use std::task::{Context, Poll};

use futures::Stream;
#[cfg(feature = "tc")]
#[allow(deprecated)]
use reflex_core::CanDrop;
use reflex_core::{CanInject, CanObserve};

pub use capture::Capture;
pub use inject::Injector;
pub use rawsend::RawSender;

// Контракт src-порт-метки анти-петли ловца (`SelfLoop.portmark`): eBPF-steer гейтит лифт по нему, а
// потребитель биндит src-порт из `PROBE_PORT_LO..=PROBE_PORT_HI` на direct-пробу. Реэкспорт —
// потребитель тянет `reflex-linux`, не `-common` напрямую.
#[cfg(feature = "tc")]
#[allow(deprecated)]
pub use reflex_linux_common::{
    is_probe_port, is_probe_sport_hibyte, PROBE_PORT_HI, PROBE_PORT_LO, PROBE_SPORT_HIBYTE,
};

// --- AF_PACKET backend: CanObserve + CanInject ---

pub struct AfPacketBackend {
    capture: Capture,
    injector: Injector,
}

impl CanObserve for AfPacketBackend {}

// Сериализация — дело функтора бэкенда, не потребителя (канон §9). Здесь полная, с ethernet-
// заголовком: сокет `AF_PACKET`/`SOCK_RAW`, `Injector::send` берёт dst MAC из первых шести байт
// кадра. `serialize_ip` дал бы корректный вызов, кладущий на провод мусор — зелёный код, молчащий провод.
impl CanInject for AfPacketBackend {
    fn inject(packet: reflex_core::command::InjectablePacket) -> Vec<u8> {
        packet.serialize()
    }
}

// Функтор в категорию бэкендов (#295, канон §9). Реализация аддитивна: inherent-методы остаются,
// ни один вызов не тронут — смена бэкенда становится подстановкой типа там, где цепочка через трейты.
impl reflex_core::backend::Source for AfPacketBackend {
    type Packet = Vec<u8>;
    type Packets<'a> = PacketStream<'a>;

    fn packets(&mut self) -> Self::Packets<'_> {
        AfPacketBackend::packets(self)
    }
}

impl reflex_core::backend::Sink for AfPacketBackend {
    type Command = Vec<u8>;
    type Error = String;

    fn emit(&mut self, command: Vec<u8>) -> Result<(), String> {
        AfPacketBackend::inject(self, &command)
    }
}

impl AfPacketBackend {
    pub fn open(interface: &str, snaplen: usize) -> Result<Self, String> {
        let capture = Capture::open(interface, snaplen, true)?;
        let injector = Injector::open(interface)?;
        Ok(Self { capture, injector })
    }

    pub fn packets(&mut self) -> PacketStream<'_> {
        PacketStream {
            capture: &mut self.capture,
        }
    }

    pub fn inject(&self, data: &[u8]) -> Result<(), String> {
        self.injector.send(data)
    }

    /// Split into separate capture stream and injector.
    /// Allows simultaneous read + write without borrow conflicts.
    pub fn split(self) -> (CaptureStream, Injector) {
        (
            CaptureStream {
                capture: self.capture,
            },
            self.injector,
        )
    }
}

// --- TC-BPF + AF_PACKET backend: CanObserve + CanInject + CanDrop + CanModify ---

#[cfg(feature = "tc")]
#[allow(deprecated)]
pub struct TcAfPacketBackend {
    capture: Capture,
    injector: Injector,
    tc: tc::TcProgram,
}

#[cfg(feature = "tc")]
#[allow(deprecated)]
impl reflex_core::backend::Source for TcAfPacketBackend {
    type Packet = Vec<u8>;
    type Packets<'a> = PacketStream<'a>;

    fn packets(&mut self) -> Self::Packets<'_> {
        TcAfPacketBackend::packets(self)
    }
}

/// Команда tc-бэкенда — алгебра, а не байты. Прежде сток брал `Vec<u8>`, и `CanDrop` было невыразимо
/// (механизм дропа существовал целиком, а сказать «дропни поток» было нечем — система позволяла
/// заявить невыразимое). Варианты ровно те, что бэкенд УМЕЕТ: общий `reflex_core::Command` нёс бы
/// `Hold`/`Accept`, которых у tc нет, и `emit` отвечал бы ошибкой в рантайме на то, что отсекает компилятор.
#[cfg(feature = "tc")]
#[allow(deprecated)]
#[derive(Debug, Clone)]
pub enum TcCommand {
    /// Отправить кадр в сеть через AF_PACKET.
    Inject(Vec<u8>),
    /// Перестать пропускать поток: `ACTION_TABLE[hash] = Drop`, и TC-BPF отвечает `TC_ACT_SHOT`.
    Drop(reflex_core::types::Flow),
    /// Снять дроп. Без снятия дроп есть состояние без выхода.
    Clear(reflex_core::types::Flow),
}

/// Ключ `ACTION_TABLE` из потока. Частична по IPv6, названо ошибкой, не молчанием: карта в ядре
/// ключуется четырьмя байтами адреса, IPv6-поток невыразим (#299). Молчаливый `Ok(())` означал бы
/// «дропнули», когда не дропнули.
#[cfg(feature = "tc")]
#[allow(deprecated)]
fn action_key(flow: &reflex_core::types::Flow) -> Result<u32, String> {
    match (flow.src.ip(), flow.dst.ip()) {
        (std::net::IpAddr::V4(src), std::net::IpAddr::V4(dst)) => Ok(tc::flow_hash(
            u32::from(src),
            u32::from(dst),
            flow.src.port(),
            flow.dst.port(),
            match flow.protocol {
                reflex_core::types::Protocol::Tcp => 6,
                reflex_core::types::Protocol::Udp => 17,
            },
        )),
        // Ветки перечислены, не свёрнуты в `_`: смешанная пара (V4→V6) бессмысленна как поток и
        // обязана быть названа — свёрнутая, она молча уехала бы в общую ошибку про IPv6.
        (std::net::IpAddr::V6(_), std::net::IpAddr::V6(_))
        | (std::net::IpAddr::V4(_), std::net::IpAddr::V6(_))
        | (std::net::IpAddr::V6(_), std::net::IpAddr::V4(_)) => Err(format!(
            "ACTION_TABLE ключуется IPv4 (#299), поток {} → {} невыразим",
            flow.src, flow.dst
        )),
    }
}

#[cfg(feature = "tc")]
#[allow(deprecated)]
impl reflex_core::backend::Sink for TcAfPacketBackend {
    type Command = TcCommand;
    type Error = String;

    fn emit(&mut self, command: TcCommand) -> Result<(), String> {
        match command {
            TcCommand::Inject(bytes) => TcAfPacketBackend::inject(self, &bytes),
            TcCommand::Drop(flow) => action_key(&flow)
                .and_then(|key| self.set_flow_action(key, reflex_linux_common::FlowAction::Drop)),
            TcCommand::Clear(flow) => action_key(&flow).and_then(|key| self.clear_flow_action(key)),
        }
    }
}

#[cfg(feature = "tc")]
#[allow(deprecated)]
impl CanObserve for TcAfPacketBackend {}
#[cfg(feature = "tc")]
#[allow(deprecated)]
impl CanInject for TcAfPacketBackend {
    fn inject(packet: reflex_core::command::InjectablePacket) -> TcCommand {
        TcCommand::Inject(packet.serialize())
    }
}
#[cfg(feature = "tc")]
#[allow(deprecated)]
impl CanDrop for TcAfPacketBackend {
    fn drop_flow(flow: reflex_core::types::Flow) -> TcCommand {
        TcCommand::Drop(flow)
    }

    fn clear_flow(flow: reflex_core::types::Flow) -> TcCommand {
        TcCommand::Clear(flow)
    }
}
// `CanModify` не заявляется — замер, а не забывчивость: у BPF-программы нет карты с байтами для
// подмены (`ACTION_TABLE`, `STEER_*`, `CLIENT_MACS`, `RETURN_*` — всё); единственное место, где
// кадр переписывается (`bpf_skb_store_bytes` в пути заворота), есть механика лифта, не команда.
// Прежнее заявление было неправдивым — в отличие от `CanDrop`, правдивого и лишь невыразимого.

#[cfg(feature = "tc")]
#[allow(deprecated)]
impl TcAfPacketBackend {
    /// Open AF_PACKET on `capture_iface` (br0), attach TC-BPF on `tc_iface` (veth-rt-br egress).
    pub fn open(
        capture_iface: &str,
        tc_iface: &str,
        snaplen: usize,
        bpf_bytes: &[u8],
    ) -> Result<Self, String> {
        let capture = Capture::open(capture_iface, snaplen, true)?;
        let injector = Injector::open(capture_iface)?;
        let tc = tc::TcProgram::attach(tc_iface, bpf_bytes)?;
        Ok(Self {
            capture,
            injector,
            tc,
        })
    }

    pub fn packets(&mut self) -> PacketStream<'_> {
        PacketStream {
            capture: &mut self.capture,
        }
    }

    pub fn inject(&self, data: &[u8]) -> Result<(), String> {
        self.injector.send(data)
    }

    /// Set flow action in TC BPF map (drop or pass).
    pub fn set_flow_action(
        &mut self,
        flow_hash: u32,
        action: reflex_linux_common::FlowAction,
    ) -> Result<(), String> {
        self.tc.set_flow_action(flow_hash, action)
    }

    /// Clear flow action (revert to TC_ACT_OK / pass).
    pub fn clear_flow_action(&mut self, flow_hash: u32) -> Result<(), String> {
        self.tc.clear_flow_action(flow_hash)
    }

    pub fn split(self) -> (CaptureStream, Injector, tc::TcProgram) {
        (
            CaptureStream {
                capture: self.capture,
            },
            self.injector,
            self.tc,
        )
    }
}

// --- Streams ---

pub struct PacketStream<'a> {
    capture: &'a mut Capture,
}

impl<'a> Stream for PacketStream<'a> {
    type Item = Vec<u8>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.capture.next_packet() {
            Some(data) => Poll::Ready(Some(data.to_vec())),
            None => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }
    }
}

/// Owned capture stream — for use after `split()`.
pub struct CaptureStream {
    pub(crate) capture: Capture,
}

impl Stream for CaptureStream {
    type Item = Vec<u8>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.capture.next_packet() {
            Some(data) => Poll::Ready(Some(data.to_vec())),
            None => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }
    }
}
