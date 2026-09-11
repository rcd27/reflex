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
/// Ёмкость очереди в пакетах — подушка на время, пока потребитель думает над показанием. Довод и
/// числа при заявке (`open`).
const QUEUE_MAXLEN: u32 = 8192;
const BUFFER: usize = 64 * 1024;

/// Мутант ЗАМЕРА №1 (Д8, T13): сузить ёмкость очереди, чтобы `queue_dropped` мог доказанно уйти
/// от нуля. Читается ОДИН раз, при открытии, — не публичная величина, а щель в оснастку стенда.
/// СКОЛЬКО ПАКЕТОВ ЯДРО УРОНИЛО, не сумев положить их в нашу очередь.
///
/// Читается из `/proc/net/netfilter/nfnetlink_queue`: строка на очередь, седьмое поле —
/// `queue_user_dropped`. Имя поля ядерное и означает «уронено, потому что ПОТРЕБИТЕЛЬ не забрал
/// вовремя» — то есть ровно нашу вину, а не беду сети.
///
/// `None` — файла нет либо строка не разобралась: клетка незнания (§7), а не ноль. Ноль здесь
/// означал бы «смотрели и потерь не было», и на машине без этого файла мы объявляли бы себя
/// непогрешимыми.
pub(crate) fn user_dropped(queue: u16) -> Option<u64> {
    let text = std::fs::read_to_string("/proc/net/netfilter/nfnetlink_queue").ok()?;
    dropped_in(&text, queue)
}

/// Разбор отдельной функцией — чтобы закон проверялся строкой, а не живой очередью: чтение файла
/// есть дело машины, а разбор полей — наше, и ломается именно он (порядок полей ядерный, менять его
/// никто нам не обещал).
fn dropped_in(text: &str, queue: u16) -> Option<u64> {
    text.lines().find_map(|line| {
        let mut fields = line.split_whitespace();
        let number: u16 = fields.next()?.parse().ok()?;
        match number == queue {
            false => None,
            // Поля: номер · порт · всего · режим копии · длина копии · дропов очереди ·
            // ДРОПОВ ПОТРЕБИТЕЛЯ · номер последовательности · единица.
            true => fields.nth(5)?.parse().ok(),
        }
    })
}

#[cfg(test)]
mod dropped_tests {
    use super::dropped_in;

    /// Строка настоящего вида — снята с работающей машины, поля в ядерном порядке.
    const REAL: &str = "  200  12345  17  2  65535  0  740  4242  1\n                        \x20 201  12346   3  2  65535  0    0  4243  1";

    /// ПРЕДМЕТ: седьмое поле есть ДРОПЫ ПОТРЕБИТЕЛЯ — пакеты, которые ядро уронило, не сумев
    /// положить их в очередь. Ошибись мы полем, движок объявлял бы дыру по чужому числу: `0` в
    /// шестом (дропы очереди) читался бы как «мы не роняли», а `4242` в восьмом — как непрерывная
    /// потеря.
    #[test]
    fn седьмое_поле_есть_наши_потери() {
        assert_eq!(dropped_in(REAL, 200), Some(740));
        assert_eq!(dropped_in(REAL, 201), Some(0), "чужая очередь своё число");
    }

    /// Очереди нет в файле — `None`, а не ноль: ноль означал бы «смотрели, потерь не было», и
    /// движок объявил бы себя непогрешимым там, где просто не смотрел (§7).
    #[test]
    fn незнакомая_очередь_даёт_незнание_а_не_ноль() {
        assert_eq!(dropped_in(REAL, 999), None);
        assert_eq!(dropped_in("", 200), None);
    }

    /// Строка испорчена — тоже незнание. Разбор, отдающий ноль на мусоре, врал бы тем же способом.
    #[test]
    fn испорченная_строка_даёт_незнание() {
        assert_eq!(dropped_in("200 12345 17", 200), None, "полей меньше, чем нужно");
        assert_eq!(dropped_in("200 a b c d e f g h", 200), None, "поле не число");
    }
}

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
    pub(crate) queue: u16,
    pub(crate) base: TimeoutBase,
    /// `(Incoming, Instant)` — момент ОБЯЗАН ехать вместе с сообщением, а не сниматься заново при
    /// разборе: он штампуется в `recv` на ПРИЁМЕ пачки (см. `Serves::serve` в `terminal.rs`). Сними
    /// его при снятии из буфера — и второй, третий пакет пачки получили бы момент позже своего
    /// прихода, а монотонность букв (`core::interleave`) сломалась бы молча.
    pub(crate) pending: VecDeque<(Incoming, Instant)>,
    /// Сколько пакетов ЯДРО уронило, не сумев положить их в очередь, — на момент последнего
    /// взгляда. Не наш счёт: ядро ведёт его само и знает о потере, о которой мы иначе не узнаём
    /// НИКОГДА.
    ///
    /// Зачем он здесь. Переполнение приёмного буфера нашего сокета мы видим (`ENOBUFS` → дыра), а
    /// переполнение САМОЙ ОЧЕРЕДИ — нет: пакет не доехал даже до сокета, и для нас он неотличим от
    /// того, что его не было. Цена этой неразличимости замерена в поле: потерянный `SYN+ACK`
    /// превращается в `Blackhole` по здоровой цели, продукт уводит её в обход и ломает то, что
    /// работало. Прибор при этом прав по тому, что видел; видел он НАШУ потерю.
    ///
    /// `None` — счётчик не читается (нет файла, нет прав): это клетка незнания, а не ноль, и на
    /// такой машине дыра просто не рождается — как было до сих пор.
    pub(crate) dropped: Option<u64>,
    /// Когда счётчик смотрели в последний раз. Читать его на каждом пакете значило бы платить
    /// открытием файла за каждый кадр; предмет же меняется редко и заметен с задержкой в окно.
    pub(crate) looked: Instant,
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
            dropped: user_dropped(queue),
            looked: Instant::now(),
        };
        sock.send(&bind_request(queue, 1))?;
        sock.send(&params_request(queue, 2, COPY_RANGE))?;
        sock.send(&conntrack_flag_request(queue, 3))?;
        // ЁМКОСТЬ ОЧЕРЕДИ ПРОСИМ ЯВНО, а не берём умолчание ядра (1024 пакета).
        //
        // Замер потребителя на браузерной нагрузке: одна загрузка страницы даёт 7119 пакетов в
        // очереди и 740 ЮЗЕРДРОПОВ — 10,4%. Юзердроп есть пакет, на который мы не выдали вердикт
        // вовремя: ядру некуда его положить, и оно роняет. Для человека это не «медленно», а
        // «страница не грузится»: на странице из двадцати доменов при десяти процентах потерь
        // какой-нибудь ресурс не доедет почти наверняка, и браузер ждёт его до таймаута.
        //
        // Своя цена обработки при этом НЕ ПРИЧИНА — она замерена: 678 тысяч пакетов в секунду на
        // пяти приборах. Причина в том, что ведущий цикл отдан потребителю (`heard()`), и пока он
        // думает над показанием, очередь не разбирается. Ёмкость и есть подушка на это время:
        // восемь тысяч пакетов против тысячи покрывают четыре секунды его работы при двух тысячах
        // пакетов в секунду.
        //
        // Не бесконечность: очередь живёт в памяти ядра, и заявка на миллион означала бы, что при
        // зависшем потребителе ядро держит его память вместо того, чтобы честно ронять.
        let maxlen = tiny_queue_mutant().unwrap_or(QUEUE_MAXLEN);
        sock.send(&queue_maxlen_request(queue, 4, maxlen))?;
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

    /// Вердикт пакету `id`. Три необязательных довода — три РАЗНЫХ предмета, и сливать их нельзя:
    /// * `ct_mark` — состояние разговора (`NFQA_CT{CTA_MARK}`), переживает пакет и читается на
    ///   следующем пакете того же разговора: это дом автомата Мили;
    /// * `payload` — новые байты (`NFQA_PAYLOAD`): ядро отпустит их вместо взятых;
    /// * `skb_mark` — метка ПАКЕТА (`NFQA_MARK`), живёт до конца его пути по ядру и читается
    ///   правилами маршрутизации (`ip rule fwmark`). Разговора она не переживает.
    ///
    /// Две метки — не дубль. Первая помнит, вторая ПРИКАЗЫВАЕТ, и разговор с ядром у них разный:
    /// перепутав их, получишь либо состояние, стёртое следующим пакетом, либо приказ, не дошедший
    /// до маршрутизатора.
    pub fn verdict(
        &self,
        id: u32,
        accept: bool,
        ct_mark: Option<u32>,
        payload: Option<&[u8]>,
        skb_mark: Option<u32>,
    ) -> Result<(), QueueError> {
        self.send(&verdict_message(
            self.queue, id, id, accept, ct_mark, payload, skb_mark,
        ))
    }
}

impl Drop for QueueSocket {
    fn drop(&mut self) {
        unsafe { close(self.fd) };
    }
}
