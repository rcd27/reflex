//! СОКЕТ К CTNETLINK. Всё IO — здесь, и только здесь.
//!
//! Мутация буфера неизбежна на границе системного вызова и потому заперта в ней: разбор того, что
//! в буфер легло, живёт в `wire` и мутации не знает вовсе.

use super::wire::{chunk_of, Chunk, Entry};
use libc::{c_int, c_void, close, recv, send, socket, AF_NETLINK, SOCK_RAW};

const NETLINK_NETFILTER: c_int = 12;
const NFNL_SUBSYS_CTNETLINK: u16 = 1;
const IPCTNL_MSG_CT_GET: u16 = 1;
const NLM_F_REQUEST: u16 = 0x001;
const NLM_F_DUMP: u16 = 0x300;
const AF_INET_FAMILY: u8 = 2;
const REQUEST_LEN: u32 = 20;
const BUFFER: usize = 64 * 1024;

/// ЧЕМ ДАМП МОЖЕТ КОНЧИТЬСЯ, КРОМЕ ЗАПИСЕЙ.
///
/// `Kernel(-2)` — обычный и ожидаемый исход: модуль `nf_conntrack` не загружен. Это не поломка
/// прибора, а факт о машине, и звать его ошибкой сокета значило бы смешать два разных разговора
/// с человеком.
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

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
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

impl Dump {
    /// БЕЗ ЯВНОГО `bind`, И ЭТО НЕ УПУЩЕНИЕ: netlink привязывает сокет сам при первой отправке
    /// (`netlink_autobind`), назначая pid. Явная привязка потребовала бы `sockaddr_nl`, у которого
    /// поле выравнивания приватно, — то есть кода, существующего ради обхода чужой видимости.
    pub fn open() -> Result<Dump, DumpError> {
        match unsafe { socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER) } {
            below if below < 0 => Err(DumpError::Socket(errno())),
            fd => Ok(Dump { fd }),
        }
    }

    /// ВСЕ ЗАПИСИ CONNTRACK НА ЭТОТ МОМЕНТ. Дамп приходит несколькими порциями, и конец объявляет
    /// ЯДРО (`NLMSG_DONE`), а не пустая порция: остановка по пустоте читала бы обрыв как конец.
    pub fn entries(&self) -> Result<Vec<Entry>, DumpError> {
        let asked = request(1);
        match unsafe { send(self.fd, asked.as_ptr() as *const c_void, asked.len(), 0) } {
            below if below < 0 => Err(DumpError::Send(errno())),
            _sent => self.drain(Vec::new()),
        }
    }

    fn drain(&self, so_far: Vec<Entry>) -> Result<Vec<Entry>, DumpError> {
        // МУТАЦИЯ ЖИВЁТ РОВНО ЗДЕСЬ: ядру нужен буфер, в который оно пишет.
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
