//! # ДВА КРЫЛА ПОМЕЧЕНЫ УСТАРЕВШИМИ (05.09.2026): `tc` и `tun`
//!
//! Перепись публичных имён показала: обе фичи включает ТОЛЬКО `nevod/` — первый невод, объявленный
//! владельцем deprecated и не собирающийся вовсе. У живых потребителей (zond, nevod2-runtime,
//! reflex-engine-nfq, tablo) в зависимостях лишь `nfqueue` и `conntrack`.
//!
//! Помечены, а НЕ СНЕСЕНЫ, и это решение владельца: там техника, а не обвязка — eBPF-steering с
//! картами действий и userspace-терминация TCP поверх smoltcp. Из 21 мёртвого публичного имени
//! reflex 20 живут в `tc/loader.rs`; полезное оттуда достанут разбором, а не сносом вслепую.
//!
//! Пометка сделана атрибутом, а не только этой прозой: включивший фичу услышит компилятор, а не
//! понадеется прочесть заголовок файла.

mod capture;
#[cfg(feature = "conntrack")]
pub mod conntrack;
mod inject;
#[cfg(feature = "nfqueue")]
pub mod nfqueue;
pub mod rawsend;

/// ЕДИНСТВЕННЫЙ ПОТРЕБИТЕЛЬ — ПЕРВЫЙ НЕВОД, И ОН ЗАКРЫТ.
///
/// eBPF-загрузчик со steering-картами: 809 строк, из них 20 публичных имён не зовёт никто вовсе.
/// Полезное здесь есть (быстрый датаплейн в ядре), и потому крыло помечено, а не снесено, — но
/// строить на нём новое, не разобрав, значит наследовать мёртвого потребителя.
#[cfg(feature = "tc")]
#[deprecated(
    since = "0.0.1",
    note = "фичу `tc` включает только невод 1 (закрыт); разбор техники отложен — см. заголовок lib.rs"
)]
pub mod tc;

/// ЕДИНСТВЕННЫЙ ПОТРЕБИТЕЛЬ — ПЕРВЫЙ НЕВОД, И ОН ЗАКРЫТ. Общая часть терминации.
// Крыло помечено ЦЕЛИКОМ, поэтому обращения его частей друг к другу — шум, а не находка: пометку
// обязан услышать тот, кто фичу ВКЛЮЧАЕТ, а не мы, читая собственный же модуль.
#[cfg(feature = "tun")]
#[allow(deprecated)]
#[deprecated(
    since = "0.0.1",
    note = "фичу `tun` включает только невод 1 (закрыт); разбор техники отложен — см. заголовок lib.rs"
)]
pub mod tun;

/// ИСХОДЯЩАЯ ТЕРМИНАЦИЯ поверх smoltcp (600 строк). Потребитель закрыт.
// Крыло помечено ЦЕЛИКОМ, поэтому обращения его частей друг к другу — шум, а не находка: пометку
// обязан услышать тот, кто фичу ВКЛЮЧАЕТ, а не мы, читая собственный же модуль.
#[cfg(feature = "tun")]
#[allow(deprecated)]
#[deprecated(
    since = "0.0.1",
    note = "фичу `tun` включает только невод 1 (закрыт); разбор техники отложен — см. заголовок lib.rs"
)]
pub mod tun_egress;

/// ВХОДЯЩАЯ ТЕРМИНАЦИЯ поверх smoltcp (892 строки). Потребитель закрыт.
// Крыло помечено ЦЕЛИКОМ, поэтому обращения его частей друг к другу — шум, а не находка: пометку
// обязан услышать тот, кто фичу ВКЛЮЧАЕТ, а не мы, читая собственный же модуль.
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
// потребитель (nevod) биндит src-порт из `PROBE_PORT_LO..=PROBE_PORT_HI` на direct-пробу. Реэкспорт —
// nevod тянет `reflex-linux`, не `-common` напрямую.
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

// СЕРИАЛИЗАЦИЯ — ДЕЛО ФУНКТОРА БЭКЕНДА, А НЕ ПОТРЕБИТЕЛЯ (vision §1.3). Здесь она полная,
// с ethernet-заголовком: сокет открыт `AF_PACKET`/`SOCK_RAW`, и `Injector::send` берёт
// dst MAC из ПЕРВЫХ ШЕСТИ БАЙТ кадра (`inject.rs:59`). `serialize_ip` дал бы синтаксически
// корректный вызов, кладущий на провод мусор, — то есть зелёный код и молчащий провод.
impl CanInject for AfPacketBackend {
    fn inject(packet: reflex_core::command::InjectablePacket) -> Vec<u8> {
        packet.serialize()
    }
}

// ФУНКТОР В КАТЕГОРИЮ БЭКЕНДОВ (#295, срез 4). Реализация АДДИТИВНА: inherent-методы остаются,
// и ни один существующий вызов не тронут. Смена бэкенда становится подстановкой типа там, где
// цепочка написана через трейты, и остаётся правкой кода там, где через inherent, — переезд
// потребителей отдельным шагом.
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

/// КОМАНДА TC-БЭКЕНДА — АЛГЕБРА, А НЕ БАЙТЫ.
///
/// Прежде сток брал `Vec<u8>`, и `CanDrop` было невыразимо: механизм дропа существовал целиком
/// (`ACTION_TABLE` в ядре, `set_flow_action` в userspace, совпадающий хеш), но сказать «дропни
/// этот поток» стоку было нечем. Заявление о способности при этом стояло — то есть система
/// позволяла заявить то, чего в ней нельзя выразить.
///
/// Варианты ровно те, что бэкенд УМЕЕТ. Общий `reflex_core::Command` здесь был бы хуже: он несёт
/// `Hold`/`Accept`, которых у tc нет, и `emit` пришлось бы отвечать ошибкой в рантайме на то, что
/// обязан отсекать компилятор.
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

/// Ключ `ACTION_TABLE` из потока. ЧАСТИЧНА ПО IPv6, и это названо ошибкой, а не молчанием:
/// карта в ядре ключуется четырьмя байтами адреса, и IPv6-поток в ней невыразим (#299).
/// Молчаливый `Ok(())` здесь означал бы «дропнули», когда не дропнули, — то есть ровно ту тихую
/// сторону, которую эта работа убирает.
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
        // ВЕТКИ ПЕРЕЧИСЛЕНЫ, А НЕ СВЁРНУТЫ В `_`: смешанная пара (V4→V6) бессмысленна как поток,
        // и именно поэтому она обязана быть НАЗВАНА — свёрнутая, она молча уехала бы в общую
        // ошибку про IPv6 и спрятала бы то, что поток собран неверно.
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
// `CanModify` НЕ ЗАЯВЛЯЕТСЯ, И ЭТО ЗАМЕР, А НЕ ЗАБЫВЧИВОСТЬ (05.09.2026). У BPF-программы нет
// карты с байтами для подмены: `ACTION_TABLE`, `STEER_*`, `CLIENT_MACS`, `RETURN_*` — всё. То
// единственное место, где кадр переписывается (`bpf_skb_store_bytes`, вписывающий ethernet-
// заголовок в пути заворота), есть механика лифта, а не команда пользователя.
//
// Прежнее заявление было НЕПРАВДИВЫМ — в отличие от `CanDrop`, который был правдив и лишь
// невыразим. Пустой маркер эти два состояния не различал.

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
