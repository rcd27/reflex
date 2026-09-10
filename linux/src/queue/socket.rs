//! Свой сокет к NFNL_SUBSYS_QUEUE. Всё IO — здесь; сборка и разбор сообщений живут в `wire` и мутации
//! не знают. Автобинд, как в `conntrack/dump.rs` (явная привязка потребовала бы `sockaddr_nl` с
//! приватным полем выравнивания). `NETLINK_NO_ENOBUFS` НЕ трогаем — умолчание ядра сообщать о
//! переполнении нам и нужно: не сообщённое переполнение стало бы ложной бедой (см. связку рисков).

use std::collections::VecDeque;
use std::time::Instant;

use libc::{c_int, c_void, close, poll, pollfd, recv, send, socket, AF_NETLINK, POLLIN, SOCK_RAW};

use super::wire::{
    bind_request, conntrack_flag_request, incoming_of, params_request, queue_maxlen_request,
    verdict_message, Incoming,
};
use crate::conntrack::TimeoutBase;
use crate::netlink::errno;
use crate::nfqueue::Waited;

const NETLINK_NETFILTER: c_int = 12;
const COPY_RANGE: u16 = 0xFFFF;
const BUFFER: usize = 64 * 1024;

/// Мутант ЗАМЕРА №1 (Д8, T13): сузить ёмкость очереди, чтобы `queue_dropped` мог доказанно уйти
/// от нуля. Читается ОДИН раз, при открытии, — не публичная величина, а щель в оснастку стенда.
fn tiny_queue_mutant() -> Option<u32> {
    std::env::var("REFLEX_LAB_TINY_QUEUE")
        .ok()
        .and_then(|value| value.parse().ok())
}

/// Мутант ЗАМЕРА №2 (Д8, T13): сузить приёмный буфер СВОЕГО сокета, чтобы `user_dropped` мог
/// доказанно уйти от нуля — оракул, зеркальный первому (ядро роняет ДО очереди против роняет ДО
/// нашего чтения). Возвращает `c_int`: ровно то, что просит `setsockopt(SO_RCVBUF)`.
fn tiny_rcvbuf_mutant() -> Option<c_int> {
    std::env::var("REFLEX_LAB_TINY_RCVBUF")
        .ok()
        .and_then(|value| value.parse().ok())
}

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
/// двери через крейт `nfq`, добывавшей fd разницей множеств). Хранит и `base`: `Held::new` у
/// каждого взятого пакета нуждается в ней, а читать её здесь заново значило бы завести второго
/// читателя одной величины рядом с тем единственным, что уже читает её при открытии цепочки (§9 —
/// два закона об одном предмете расходятся молча). `pending` — пачка, которую вернул `recv`: он
/// отдаёт МНОГО, `Serves::serve` отдаёт по одному, и разница живёт здесь же, у источника.
pub struct QueueSocket {
    fd: c_int,
    queue: u16,
    pub(crate) base: TimeoutBase,
    /// `(Incoming, Instant)` — момент ОБЯЗАН ехать вместе с сообщением, а не сниматься заново при
    /// разборе: он штампуется в `recv` на ПРИЁМЕ пачки (см. `Serves::serve` в `terminal.rs`). Сними
    /// его при снятии из буфера — и второй, третий пакет пачки получили бы момент позже своего
    /// прихода, а монотонность букв (`core::interleave`) сломалась бы молча.
    pub(crate) pending: VecDeque<(Incoming, Instant)>,
}

impl QueueSocket {
    /// Открыть и настроить очередь: bind, copy-packet, включение `NFQA_CT`. Три конфигурационных
    /// сообщения подряд (ответа-ack не ждём: netlink к очереди их не шлёт по умолчанию). `base`
    /// приходит АРГУМЕНТОМ: снимает её ровно один читатель выше по цепочке (`Nfqueue::open`),
    /// `TimeoutBase::read()` здесь не зовётся — вторым чтением этот сокет развёл бы с ним закон об
    /// одной величине внутри одного прогона.
    ///
    /// ПОСЛЕ трёх — два мутанта ЗАМЕРА (Д8, T13), оба за флагом окружения и оба МОЛЧА отсутствуют
    /// без него: боевой путь этих строк не видит. `REFLEX_LAB_TINY_QUEUE=N` сужает ёмкость очереди
    /// до `N` (`queue_dropped` — «до очереди не дошло»); `REFLEX_LAB_TINY_RCVBUF=N` сужает приёмный
    /// буфер СВОЕГО сокета (`user_dropped` — «мы не забрали», роняет ядро при `ENOBUFS`, минуя
    /// очередь). Оба нужны РАЗНЫМ оракулам: замер частоты `ENOBUFS` на боевой очереди (ёмкость
    /// 1024, ~15 п/с) дал ноль, и без доказанной способности хотя бы одного оракула показать
    /// ненуль этот ноль был бы «не измерено», выданным за «измерено и пусто». Публичной ручкой
    /// фасада не становятся (YAGNI) — настраиваемой длины очереди никто не просил.
    pub fn open(queue: u16, base: TimeoutBase) -> Result<QueueSocket, QueueError> {
        let fd = unsafe { socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER) };
        if fd < 0 {
            return Err(QueueError::Socket(errno()));
        }
        if let Some(bytes) = tiny_rcvbuf_mutant() {
            let ret = unsafe {
                libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_RCVBUF,
                    &bytes as *const libc::c_int as *const c_void,
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                )
            };
            if ret < 0 {
                let why = errno();
                unsafe { close(fd) };
                return Err(QueueError::Socket(why));
            }
        }
        let sock = QueueSocket {
            fd,
            queue,
            base,
            pending: VecDeque::new(),
        };
        sock.send(&bind_request(queue, 1))?;
        sock.send(&params_request(queue, 2, COPY_RANGE))?;
        sock.send(&conntrack_flag_request(queue, 3))?;
        if let Some(maxlen) = tiny_queue_mutant() {
            sock.send(&queue_maxlen_request(queue, 4, maxlen))?;
        }
        Ok(sock)
    }

    /// База таймаутов, с которой сокет открыт. Читающий ведущий цикл строит по ней `CtEdge` на
    /// каждом пакете (`CtEdge::seen(view, base)`) — и это ЧТЕНИЕ уже взятого значения, а не второй
    /// вызов `TimeoutBase::read()`: тот остаётся единственным читателем sysctl в цепочке
    /// (`Nfqueue::open`), эта дверь лишь отдаёт то, что он уже снял.
    pub fn base(&self) -> TimeoutBase {
        self.base
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
