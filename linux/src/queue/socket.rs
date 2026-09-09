//! Свой сокет к NFNL_SUBSYS_QUEUE. Всё IO — здесь; сборка и разбор сообщений живут в `wire` и мутации
//! не знают. Автобинд, как в `conntrack/dump.rs` (явная привязка потребовала бы `sockaddr_nl` с
//! приватным полем выравнивания). `NETLINK_NO_ENOBUFS` НЕ трогаем — умолчание ядра сообщать о
//! переполнении нам и нужно: не сообщённое переполнение стало бы ложной бедой (см. связку рисков).

use libc::{c_int, c_void, close, poll, pollfd, recv, send, socket, AF_NETLINK, POLLIN, SOCK_RAW};

use super::wire::{
    bind_request, conntrack_flag_request, incoming_of, params_request, verdict_message, Incoming,
};
use crate::netlink::errno;
use crate::nfqueue::Waited;

const NETLINK_NETFILTER: c_int = 12;
const COPY_RANGE: u16 = 0xFFFF;
const BUFFER: usize = 64 * 1024;

/// Чем сокет очереди может отказать. `Overrun` (`ENOBUFS`) — не «ошибка приёма», а буква: ядро
/// сказало, что очередь переполнилась и пакеты потеряны. Прибору это знание нужно — сравнение оттиска
/// через необъявленный разрыв было бы недоверенным. `Kernel` — отказ, объявленный `NLMSG_ERROR`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueueError {
    Socket(i32),
    Send(i32),
    Recv(i32),
    Overrun,
    Kernel(i32),
}

impl QueueError {
    /// `ENOBUFS` — переполнение (буква `Overrun`); прочее errno приёма — обычный отказ.
    pub fn from_errno(errno: i32) -> QueueError {
        match errno {
            libc::ENOBUFS => QueueError::Overrun,
            other => QueueError::Recv(other),
        }
    }
}

/// Сокет к очереди `queue`. Хранит СВОЙ дескриптор — `/proc/self/fd` не нужен (в отличие от старой
/// двери через крейт `nfq`, добывавшей fd разницей множеств).
pub struct QueueSocket {
    fd: c_int,
    queue: u16,
}

impl QueueSocket {
    /// Открыть и настроить очередь: bind, copy-packet, включение `NFQA_CT`. Три конфигурационных
    /// сообщения подряд (ответа-ack не ждём: netlink к очереди их не шлёт по умолчанию).
    pub fn open(queue: u16) -> Result<QueueSocket, QueueError> {
        let fd = unsafe { socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER) };
        if fd < 0 {
            return Err(QueueError::Socket(errno()));
        }
        let sock = QueueSocket { fd, queue };
        sock.send(&bind_request(queue, 1))?;
        sock.send(&params_request(queue, 2, COPY_RANGE))?;
        sock.send(&conntrack_flag_request(queue, 3))?;
        Ok(sock)
    }

    fn send(&self, message: &[u8]) -> Result<(), QueueError> {
        match unsafe { send(self.fd, message.as_ptr() as *const c_void, message.len(), 0) } {
            below if below < 0 => Err(QueueError::Send(errno())),
            _sent => Ok(()),
        }
    }

    /// Ждать на дескрипторе, а не крутиться. Свой fd есть всегда — `Waited::Blind` тут не рождается.
    pub fn wait(&self, millis: i32) -> Waited {
        let mut watched = pollfd {
            fd: self.fd,
            events: POLLIN,
            revents: 0,
        };
        match unsafe { poll(&mut watched, 1, millis) } {
            ready if ready > 0 => Waited::Ready,
            _nothing => Waited::Idle,
        }
    }

    /// Принять порцию из очереди. `ENOBUFS` отдаётся буквой `Overrun`, не глушится: провал приёма
    /// обязан стать величиной, иначе потерянные пакеты прочтутся как тишина цели.
    pub fn recv(&self) -> Result<Vec<Incoming>, QueueError> {
        // Мутация живёт ровно здесь: ядру нужен буфер, в который оно пишет.
        let mut buffer = vec![0u8; BUFFER];
        match unsafe { recv(self.fd, buffer.as_mut_ptr() as *mut c_void, BUFFER, 0) } {
            below if below < 0 => Err(QueueError::from_errno(errno())),
            got => Ok(incoming_of(&buffer[..got as usize])),
        }
    }

    /// Вердикт пакету `id`. `ct_mark` при `Some` уезжает вложенным `NFQA_CT{CTA_MARK}`.
    pub fn verdict(&self, id: u32, accept: bool, ct_mark: Option<u32>) -> Result<(), QueueError> {
        self.send(&verdict_message(self.queue, id, id, accept, ct_mark))
    }
}

impl Drop for QueueSocket {
    fn drop(&mut self) {
        unsafe { close(self.fd) };
    }
}
