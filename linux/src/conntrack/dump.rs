//! Сокет к ctnetlink. Всё IO — здесь, и только здесь. Мутация буфера неизбежна на границе
//! системного вызова и заперта в ней: разбор того, что легло, живёт в `wire` и мутации не знает.

use super::wire::{chunk_of, Chunk, Entry, Tuple};
use crate::netlink::{errno, nested, tlv};
use libc::{c_int, c_void, close, recv, send, socket, AF_NETLINK, SOCK_RAW};

const NETLINK_NETFILTER: c_int = 12;
const NFNL_SUBSYS_CTNETLINK: u16 = 1;
const IPCTNL_MSG_CT_GET: u16 = 1;
const IPCTNL_MSG_CT_DELETE: u16 = 2;
const NLM_F_REQUEST: u16 = 0x001;
const NLM_F_ACK: u16 = 0x004;
const CTA_TUPLE_ORIG: u16 = 1;
const CTA_TUPLE_IP: u16 = 1;
const CTA_TUPLE_PROTO: u16 = 2;
const CTA_IP_V4_SRC: u16 = 1;
const CTA_IP_V4_DST: u16 = 2;
const CTA_PROTO_NUM: u16 = 1;
const CTA_PROTO_SRC_PORT: u16 = 2;
const CTA_PROTO_DST_PORT: u16 = 3;
const NLM_F_DUMP: u16 = 0x300;
const AF_INET_FAMILY: u8 = 2;
const REQUEST_LEN: u32 = 20;
const BUFFER: usize = 64 * 1024;

/// Чем дамп может кончиться, кроме записей. `Kernel(-2)` — обычный исход: модуль `nf_conntrack` не
/// загружен, факт о машине, не поломка прибора; звать его ошибкой сокета значило бы смешать два
/// разговора с человеком.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DumpError {
    Socket(i32),
    Send(i32),
    Recv(i32),
    Kernel(i32),
}

pub struct Dump {
    fd: c_int,
}

fn request(seq: u32) -> [u8; REQUEST_LEN as usize] {
    let kind = (NFNL_SUBSYS_CTNETLINK << 8) | IPCTNL_MSG_CT_GET;
    let flags = NLM_F_REQUEST | NLM_F_DUMP;
    let (len, kind, flags, seq) = (
        REQUEST_LEN.to_ne_bytes(),
        kind.to_ne_bytes(),
        flags.to_ne_bytes(),
        seq.to_ne_bytes(),
    );
    [
        len[0],
        len[1],
        len[2],
        len[3],
        kind[0],
        kind[1],
        flags[0],
        flags[1],
        seq[0],
        seq[1],
        seq[2],
        seq[3],
        0,
        0,
        0,
        0,
        AF_INET_FAMILY,
        0,
        0,
        0,
    ]
}

/// Просьба забыть запись по её исходной четвёрке. Ядро ищет запись ровно по `CTA_TUPLE_ORIG`, так
/// что просьба не может задеть соседний разговор того же адреса.
fn forgetting(seq: u32, tuple: &Tuple) -> Vec<u8> {
    let ends: Vec<u8> = tlv(CTA_IP_V4_SRC, &tuple.src.to_be_bytes())
        .into_iter()
        .chain(tlv(CTA_IP_V4_DST, &tuple.dst.to_be_bytes()))
        .collect();
    let ports: Vec<u8> = tlv(CTA_PROTO_NUM, &[tuple.proto])
        .into_iter()
        .chain(tlv(CTA_PROTO_SRC_PORT, &tuple.src_port.to_be_bytes()))
        .chain(tlv(CTA_PROTO_DST_PORT, &tuple.dst_port.to_be_bytes()))
        .collect();
    let orig = nested(
        CTA_TUPLE_ORIG,
        &nested(CTA_TUPLE_IP, &ends)
            .into_iter()
            .chain(nested(CTA_TUPLE_PROTO, &ports))
            .collect::<Vec<u8>>(),
    );
    let len = (crate::netlink::HDR + 4 + orig.len()) as u32;
    let kind = (NFNL_SUBSYS_CTNETLINK << 8) | IPCTNL_MSG_CT_DELETE;
    len.to_ne_bytes()
        .into_iter()
        .chain(kind.to_ne_bytes())
        .chain((NLM_F_REQUEST | NLM_F_ACK).to_ne_bytes())
        .chain(seq.to_ne_bytes())
        .chain(0u32.to_ne_bytes())
        .chain([AF_INET_FAMILY, 0, 0, 0])
        .chain(orig)
        .collect()
}

impl Dump {
    /// Забыть одну запись. Ответ ядра — подтверждение (`NLMSG_ERROR` с нулём) или отказ с кодом;
    /// `Kernel(-2)` значит «записи уже нет», и зовущему решать, беда ли это (обычно нет: запись
    /// успела истечь сама).
    pub fn forget(&self, tuple: &Tuple) -> Result<(), DumpError> {
        let asked = forgetting(2, tuple);
        match unsafe { send(self.fd, asked.as_ptr() as *const c_void, asked.len(), 0) } {
            below if below < 0 => Err(DumpError::Send(errno())),
            _sent => self.drain(Vec::new()).map(|_nothing| ()),
        }
    }

    /// Без явного `bind`: netlink привязывает сокет сам при первой отправке (`netlink_autobind`),
    /// назначая pid. Явная привязка потребовала бы `sockaddr_nl` с приватным полем выравнивания —
    /// кода ради обхода чужой видимости.
    pub fn open() -> Result<Dump, DumpError> {
        match unsafe { socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER) } {
            below if below < 0 => Err(DumpError::Socket(errno())),
            fd => Ok(Dump { fd }),
        }
    }

    /// Все записи conntrack на этот момент. Дамп приходит несколькими порциями, конец объявляет ЯДРО
    /// (`NLMSG_DONE`), не пустая порция: остановка по пустоте читала бы обрыв как конец.
    pub fn entries(&self) -> Result<Vec<Entry>, DumpError> {
        let asked = request(1);
        match unsafe { send(self.fd, asked.as_ptr() as *const c_void, asked.len(), 0) } {
            below if below < 0 => Err(DumpError::Send(errno())),
            _sent => self.drain(Vec::new()),
        }
    }

    fn drain(&self, so_far: Vec<Entry>) -> Result<Vec<Entry>, DumpError> {
        // Мутация живёт ровно здесь: ядру нужен буфер, в который оно пишет.
        let mut buffer = vec![0u8; BUFFER];
        match unsafe { recv(self.fd, buffer.as_mut_ptr() as *mut c_void, BUFFER, 0) } {
            below if below < 0 => Err(DumpError::Recv(errno())),
            0 => Ok(so_far),
            got => match chunk_of(&buffer[..got as usize]) {
                Chunk::Failed(code) => Err(DumpError::Kernel(code)),
                Chunk::Done(last) => Ok(so_far.into_iter().chain(last).collect()),
                Chunk::More(more) => self.drain(so_far.into_iter().chain(more).collect()),
            },
        }
    }
}

impl Drop for Dump {
    fn drop(&mut self) {
        unsafe { close(self.fd) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conntrack::view_of;

    /// Просьба забыть читается нашим же разбором в ту же четвёрку: сборка и чеканщик одни байты
    /// понимают одинаково, иначе ядро искало бы чужую запись и отвечало «нет такой».
    #[test]
    fn a_forget_request_names_the_same_tuple_the_dump_reads() {
        let tuple = Tuple {
            src: u32::from(std::net::Ipv4Addr::new(10, 77, 0, 15)),
            dst: u32::from(std::net::Ipv4Addr::new(87, 245, 220, 78)),
            src_port: 32838,
            dst_port: 443,
            proto: 6,
        };
        let asked = forgetting(7, &tuple);
        assert_eq!(
            crate::netlink::u32_at(&asked, 0).map(|len| len as usize),
            Some(asked.len()),
            "длина в заголовке — всё сообщение"
        );
        assert_eq!(
            crate::netlink::u16_at(&asked, 4),
            Some((NFNL_SUBSYS_CTNETLINK << 8) | IPCTNL_MSG_CT_DELETE)
        );
        assert_eq!(
            view_of(&asked[crate::netlink::HDR + 4..]).tuple,
            Some(tuple)
        );
    }
}
