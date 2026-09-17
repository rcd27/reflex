//! Сокет подписки на события conntrack. Всё IO — здесь; разбор — `wire::events_of`.

use super::dump::DumpError;
use super::wire::{events_of, CtEvent};
use crate::netlink::errno;
use libc::{bind, c_int, c_void, close, recv, sockaddr, socket, AF_NETLINK, SOCK_RAW};

const NETLINK_NETFILTER: c_int = 12;
/// `NFNLGRP_CONNTRACK_NEW` (1), `_UPDATE` (2), `_DESTROY` (3) — битами маски `nl_groups`.
const GROUPS: u32 = 0b111;
const BUFFER: usize = 64 * 1024;

/// `sockaddr_nl` байтами: семейство, выравнивание, `nl_pid` = 0 (ядро назначит), маска групп. Байтами, а
/// не структурой `libc`: у той приватное поле выравнивания, и собрать её пришлось бы в обход видимости.
fn address() -> [u8; 12] {
    [
        (AF_NETLINK as u16).to_ne_bytes().as_slice(),
        &[0, 0],
        &0u32.to_ne_bytes(),
        &GROUPS.to_ne_bytes(),
    ]
    .concat()
    .try_into()
    .unwrap_or([0; 12])
}

/// Подписка.
///
/// ПРИВЯЗКА ОБЯЗАТЕЛЬНА, и это проверено живым ядром 17.09 (6.8): членство через `setsockopt` без
/// `bind` подписывало молча, а событий не приходило ни одного. Ядро шлёт их от `portid` 0, а рассылка
/// пропускает сокет с тем же `portid`, считая его отправителем, — у неподвязанного он как раз 0.
///
/// ЦЕНА НАЗВАНА: не успел прочесть — ядро роняет события и говорит об этом `ENOBUFS` (`Recv(105)`).
/// Потерянное не вернуть: разговор, чья смерть утонула, для подписчика не кончится никогда.
#[derive(Debug)]
pub struct Events {
    fd: c_int,
}

impl Events {
    pub fn open() -> Result<Events, DumpError> {
        let addr = address();
        match unsafe { socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER) } {
            below if below < 0 => Err(DumpError::Socket(errno())),
            fd => match unsafe {
                bind(
                    fd,
                    addr.as_ptr() as *const sockaddr,
                    addr.len() as libc::socklen_t,
                )
            } {
                below if below < 0 => {
                    let why = errno();
                    unsafe { close(fd) };
                    Err(DumpError::Socket(why))
                }
                _bound => Ok(Events { fd }),
            },
        }
    }

    /// Ждать события и отдать всё, что пришло одним чтением.
    pub fn next(&self) -> Result<Vec<CtEvent>, DumpError> {
        // Мутация живёт ровно здесь: ядру нужен буфер, в который оно пишет.
        let mut buffer = vec![0u8; BUFFER];
        match unsafe { recv(self.fd, buffer.as_mut_ptr() as *mut c_void, BUFFER, 0) } {
            below if below < 0 => Err(DumpError::Recv(errno())),
            got => Ok(events_of(&buffer[..got as usize])),
        }
    }
}

impl Drop for Events {
    fn drop(&mut self) {
        unsafe { close(self.fd) };
    }
}
