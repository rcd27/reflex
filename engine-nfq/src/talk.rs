//! ПАМЯТЬ О РАЗГОВОРЕ РАДИ НАБЛЮДЕНИЯ — и перевод пакета в показание прибора.
//!
//! # Почему это отдельный предмет, а не часть плоскости
//!
//! Плоскость решает, ЧТО ДЕЛАТЬ с пакетом; здесь решается, ЧТО ПАКЕТ ПОКАЗАЛ. Два разных вопроса
//! о том же пакете, и у них разные потребители: вердикт нужен ядру, показание — приборам. Пока
//! перевод жил внутри `Plane`, взять его мог только тот, кто берёт всю плоскость целиком — то
//! есть край не мог, и написал СВОЙ. Две памяти о разговоре расходятся молча: оплачено 1136 флоу
//! из 1136 мимо памяти (#317) и шестнадцатью повторами вместо шести на `sag` (#320).
//!
//! # ПРАВИЛО СТОРОН СЮДА НЕ ВХОДИТ
//!
//! Кто из двоих клиент — вопрос ВХОДА, и у входов ответ разный: очередь знает его из правила
//! (через неё идёт только `SERVER_PORT`), запись `tcpdump` — из улики (`SYN` без `ACK`). Оба
//! ответа уже вложены в `dir` тем, кто собирал [`Wire`] (`parse::wired`), и здесь читаются
//! одинаково. Держать здесь второе правило значило бы вернуть ровно ту развилку, ради снятия
//! которой перевод и переехал.

use std::collections::BTreeMap;

use reflex_engine::{Dir, FlowKey};
use reflex_instrument::wire::{ResetBy, Seen, SeenTcp};

use crate::parse::{Datagram, Wire};

/// ЧТО ПЛОСКОСТЬ ПОМНИТ О РАЗГОВОРЕ РАДИ НАБЛЮДЕНИЯ — и только ради него.
///
/// Отдельно от `cursors` (там состояние ЛЕЧЕНИЯ) намеренно: у этих двух памятей разные хозяева и
/// разные сроки жизни. Курсор ведёт закон, `Talk` — прибор, и сливать их значило бы отдать закону
/// право уронить наблюдение своим шагом.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct Talk {
    /// НАИБОЛЬШИЙ `seq + длина`, отправленный КЛИЕНТОМ. Сегмент, начинающийся раньше, есть
    /// ПОВТОР — просьба ушла второй раз, потому что ответа не было. Для человека это «страница не
    /// грузится», а не «страница грузится дальше».
    frontier: Option<u32>,
    /// ВЫДАНА ЛИ УЖЕ ГОЛОВА ПОТОКА — по направлению (к серверу, от сервера).
    ///
    /// Первый сегмент с данными несёт то, по чему узнаётся протокол; последующие — просто объём.
    /// Выдавать голову каждый раз значило бы звать опознание на каждом пакете, а оно работает по
    /// началу разговора и один раз.
    head_out: (bool, bool),
    /// Сколько содержательных пакетов пришло ОТ КЛИЕНТА. Нужен только датаграммам: у QUIC
    /// приветствие разбито на два `Initial`, и на первом имени ещё нет.
    from_client_seen: u32,
}

/// ЗНАЕМ ЛИ МЫ УЖЕ ИМЯ ЦЕЛИ на этом разговоре — вход правила «пора ли отдавать голову датаграммы».
///
/// Не `bool`: на месте вызова `false` не говорит ничего, а разница здесь содержательная. Край
/// добывает имя из QUIC-`Initial` и потому знает его иногда раньше, чем кончится терпение;
/// плоскость QUIC-приветствие не разбирает вовсе и отвечает [`Named::Awaited`] всегда. Это
/// названная дыра плоскости, а не умолчание типа.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Named {
    Known,
    Awaited,
}

/// СКОЛЬКО КЛИЕНТСКИХ ПАКЕТОВ ЖДАТЬ ИМЕНИ. Три — с запасом к наблюдавшемуся: Chrome укладывает
/// `ClientHello` в два `Initial`. Величина НЕ ЗАМЕРЕНА на широкой выборке, и это названо: больше
/// — задержим опознание у целей, чьё имя не соберётся; меньше — отдадим голову раньше имени.
const NAME_PATIENCE: u32 = 3;

/// Пора ли отдавать голову датаграммы: у QUIC-`Initial` имя может лежать в следующем пакете, и
/// голова, выданная раньше, уходит с неполной личностью.
fn ready_to_name(payload: &[u8], from_client_seen: u32, named: Named) -> bool {
    match named {
        // Имя уже есть — личность полна, ждать нечего.
        Named::Known => true,
        Named::Awaited => match payload.first().is_some_and(|first| first & 0xf0 == 0xc0) {
            // Не QUIC-`Initial`: имя, если оно есть, лежит в этом же пакете.
            false => true,
            true => from_client_seen >= NAME_PATIENCE,
        },
    }
}

/// ПОВТОР ЛИ ЭТО: сегмент несёт данные и начинается СТРОГО ПОЗАДИ пройденной границы.
///
/// «Строго», а не «не дальше»: сегмент, продолжающий поток, начинается РОВНО с границы, и разница
/// даёт ноль. Первая редакция в краю считала его повтором и насчитала 16 там, где `tshark` видит
/// 6 — нашлось сверкой с чужим оракулом, сама бы не заметила.
///
/// Расстояние меряется с обёрткой: `seq` — 32-битный счётчик, переполняющийся на четырёх
/// гигабайтах потока, и прямое `<` соврало бы ровно один раз за переполнение.
fn behind_frontier(seq: u32, payload: &[u8], frontier: Option<u32>) -> bool {
    match (frontier, payload.is_empty()) {
        (None, _) | (_, true) => false,
        (Some(frontier), false) => {
            let back = frontier.wrapping_sub(seq);
            back > 0 && back < u32::MAX / 2
        }
    }
}

/// Куда сдвинулась граница клиента после этого сегмента. Только вперёд: повтор границы не двигает,
/// иначе второй повтор перестал бы считаться повтором.
fn moved(seq: u32, payload: &[u8], from_client: bool, frontier: Option<u32>) -> Option<u32> {
    match from_client && !payload.is_empty() {
        false => frontier,
        true => {
            let end = seq.wrapping_add(payload.len() as u32);
            match frontier {
                None => Some(end),
                Some(known) => match end.wrapping_sub(known) < u32::MAX / 2 {
                    true => Some(end),
                    false => Some(known),
                },
            }
        }
    }
}

/// ГОЛОВА ЛИ ЭТО — сегмент, по которому цель будет опознана.
///
/// Ожидание сборки приветствия сюда не входит: у TLS поверх TCP имя лежит в первом же сегменте,
/// первый и есть опознанный. Ждать приходится только датаграммам, и там ожидание стоит явной
/// строкой у вызова ([`ready_to_name`]), а не спрятано здесь.
fn heads(payload: &[u8], from_client: bool, out: (bool, bool)) -> bool {
    let already = match from_client {
        true => out.0,
        false => out.1,
    };
    !already && !payload.is_empty()
}

/// ОБЩАЯ ЧАСТЬ ОБОИХ АЛФАВИТОВ — байты и голова потока. Одна на два протокола, потому что и факт
/// один: человек попросил, цель отдала.
///
/// Пустой сегмент без флагов — чистое подтверждение (`ACK`), и события из него нет: человек ничего
/// не просил и ничего не получил.
fn anywhere(payload: &[u8], from_client: bool, repeat: bool, head: bool) -> Option<Seen> {
    match (!payload.is_empty(), head, from_client) {
        // ГОЛОВА ПОТОКА ИДЁТ ОТДЕЛЬНЫМ ФАКТОМ, а не вдобавок к объёму: она и есть тот самый
        // сегмент, только названный так, чтобы опознание протокола его увидело. Двух событий на
        // один сегмент не выпускаем — объём посчитался бы дважды.
        (true, true, _) => Some(Seen::Payload {
            head: payload.to_vec(),
            from_client,
        }),
        (true, false, true) => Some(match repeat {
            true => Seen::Resent {
                count: payload.len() as u32,
            },
            false => Seen::Sent {
                count: payload.len() as u32,
            },
        }),
        (true, false, false) => Some(Seen::Received {
            count: payload.len() as u32,
        }),
        (false, _, _) => None,
    }
}

/// ЧТО ВИДНО НА СОЕДИНЕНИИ — в словаре TCP.
///
/// Порядок ветвей не косметический. Просьба подождать проверяется ПОСЛЕ сброса и рукопожатия, но
/// ДО полезной нагрузки: у сегмента с нулевым окном данных обычно нет вовсе, и без отдельной ветки
/// он был бы отброшен как чистое подтверждение — а это ровно тот факт, который объясняет
/// медленность человеку.
fn seen_of_tcp(wire: &Wire<'_>, from_client: bool, repeat: bool, head: bool) -> Option<SeenTcp> {
    match (wire.resets, wire.opens, wire.handshakes) {
        // АВТОР СБРОСА СОХРАНЯЕТСЯ: наш собственный сброс не есть беда цели (#287).
        (true, _, _) => Some(SeenTcp::Rst {
            by: match from_client {
                true => ResetBy::Person,
                // НЕ `Target`: со стороны цели приходит и её отказ, и инжект ТСПУ от её имени, а
                // различитель (TTL, фингерпринт) здесь не читается — Н10 эпика #320.
                false => ResetBy::TargetSide,
            },
        }),
        // СТУК КЛИЕНТА И ОТВЕТ ЦЕЛИ — РАЗНЫЕ СОБЫТИЯ. Прежде оба давали `Syn`, и «рукопожатие
        // состоялось» было невыразимо; из-за этого блокировка по адресу и блокировка по имени
        // сливались в одну картину.
        (_, true, _) => Some(SeenTcp::Syn),
        (_, _, true) => Some(SeenTcp::Handshaken),
        // Нулевое окно приёма: «мне некуда, подожди». Шлёт его тот, КОМУ шлют.
        _ if wire.header.window == 0 => Some(SeenTcp::AskedToWait {
            by_client: from_client,
        }),
        // ПРОЩАНИЕ — ТОЛЬКО НА СЕГМЕНТЕ БЕЗ ДАННЫХ, и цена названа замером (#294). Правило «одно
        // событие на сегмент» вынуждает выбирать, когда `FIN` несёт данные: считаем данные,
        // прощание пропускаем — закрытие TCP двустороннее, и второй `FIN` почти всегда чист.
        _ if wire.closes && wire.payload.is_empty() => Some(SeenTcp::closed(from_client)),
        // ОСТАТОК НАЗВАН ЯВНО, а не `_`: три верхних ветви разобрали свои флаги, и что здесь
        // остаётся — видно из кортежа. Новый флаг в разборе сломает эту строку, а не проскочит
        // молча в общий случай.
        (false, false, false) => {
            anywhere(wire.payload, from_client, repeat, head).map(SeenTcp::Anywhere)
        }
    }
}

/// ПАМЯТЬ О ВСЕХ ИДУЩИХ РАЗГОВОРАХ, из которой рождаются показания.
///
/// Уборку ведёт ХОЗЯИН, а не эта карта: у плоскости разговор кончается вместе с курсором, у края
/// — вместе с записью. Заведи здесь свой потолок — их стало бы два, и тот, что сработает первым,
/// уронил бы наблюдение у второго молча.
#[derive(Debug, Clone, Default)]
pub struct Talks {
    talks: BTreeMap<FlowKey, Talk>,
}

impl Talks {
    pub fn new() -> Talks {
        Talks {
            talks: BTreeMap::new(),
        }
    }

    /// СНЯТЬ ПОКАЗАНИЕ С СЕГМЕНТА — и подвинуть память разговора тем же шагом.
    ///
    /// Обе стороны здесь неразделимы: повтор узнаётся сравнением с границей, а граница двигается
    /// этим же сегментом. Разнеси их по двум вызовам — и порядок стал бы предметом дисциплины,
    /// то есть однажды разъехался бы.
    ///
    /// Отдаёт `SeenTcp`, а не `Reading`: протокол здесь известен ВХОДОМ — метод принимает
    /// сегмент. Заворачивать в `Reading` обязан тот, кто складывает показания обоих транспортов
    /// в одно поле; делай это здесь — и тип пообещал бы датаграмму там, где её быть не может.
    pub fn read(&mut self, wire: &Wire<'_>) -> Option<SeenTcp> {
        let from_client = matches!(wire.dir, Dir::Up);
        let talk = self.talks.get(&wire.flow).copied().unwrap_or_default();
        let repeat = from_client && behind_frontier(wire.header.seq, wire.payload, talk.frontier);
        let head = heads(wire.payload, from_client, talk.head_out);
        self.talks.insert(
            wire.flow,
            Talk {
                frontier: moved(wire.header.seq, wire.payload, from_client, talk.frontier),
                head_out: marked(talk.head_out, head, from_client),
                // У СОЕДИНЕНИЯ ЖДАТЬ НЕЧЕГО: имя лежит в первом же сегменте открытым текстом.
                // Счётчик ведётся всё равно — разговор может сменить транспорт на том же ключе.
                from_client_seen: talk.from_client_seen
                    + u32::from(from_client && !wire.payload.is_empty()),
            },
        );
        seen_of_tcp(wire, from_client, repeat, head)
    }

    /// СНЯТЬ ПОКАЗАНИЕ С ДАТАГРАММЫ.
    ///
    /// Словарь у датаграмм ровно общий: ни стука, ни рукопожатия, ни сброса, ни окна приёма — это
    /// свойство транспорта, а не «пока не сделано».
    pub fn watch(&mut self, datagram: &Datagram<'_>, named: Named) -> Option<Seen> {
        let from_client = matches!(datagram.dir, Dir::Up);
        let talk = self.talks.get(&datagram.flow).copied().unwrap_or_default();
        // ПОРЯДОК ЗНАЧИМ: счётчик клиентских пакетов растёт ДО решения о голове. Наоборот — и
        // третий `Initial`, тот самый, на котором имя уже собрано, считался бы вторым.
        let from_client_seen =
            talk.from_client_seen + u32::from(from_client && !datagram.payload.is_empty());
        let head = heads(datagram.payload, from_client, talk.head_out)
            && (!from_client || ready_to_name(datagram.payload, from_client_seen, named));
        self.talks.insert(
            datagram.flow,
            Talk {
                // ГРАНИЦЫ У ДАТАГРАММ НЕТ: номеров нет, и повтор по ним не узнать. QUIC свои
                // номера шифрует — их не видно даже теоретически. Признак молчит, а не гадает.
                frontier: talk.frontier,
                head_out: marked(talk.head_out, head, from_client),
                from_client_seen,
            },
        );
        anywhere(datagram.payload, from_client, false, head)
    }

    /// РАЗГОВОРА БОЛЬШЕ НЕТ — память о нём уходит.
    ///
    /// Зовётся и на открытии: четвёрка переиспользуется, и граница прошлого разговора объявила бы
    /// повтором первый сегмент нового.
    pub fn forget(&mut self, flow: FlowKey) {
        self.talks.remove(&flow);
    }

    /// Сколько разговоров под наблюдением. Витнес потолка памяти: карта, растущая числом
    /// ВИДЕННЫХ соединений, а не живых, есть утечка, неотличимая от нагрузки.
    pub fn len(&self) -> usize {
        self.talks.len()
    }

    pub fn is_empty(&self) -> bool {
        self.talks.is_empty()
    }
}

/// Отметить выданную голову на своей стороне разговора.
fn marked(out: (bool, bool), head: bool, from_client: bool) -> (bool, bool) {
    match (head, from_client) {
        (true, true) => (true, out.1),
        (true, false) => (out.0, true),
        (false, _) => out,
    }
}

/// ПРОВЕРКИ ПЕРЕЕХАЛИ ВМЕСТЕ С ПОВЕДЕНИЕМ (#320, задача 6).
///
/// Жили в другом крейте, где стерегли вторую реализацию перевода. Реализация теперь
/// одна — и покрытие обязано было приехать сюда, иначе оно исчезло бы молча: ровно тот класс
/// потери, ради которого эпик приборов и заведён.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::{datagrammed, wired, Ends, Header, Payload, Segment};

    /// 192.168.1.10 и 1.2.3.4 — те же концы, что были у переехавших проверок.
    const CLIENT_IP: u32 = 0xC0A8_010A;
    const SERVER_IP: u32 = 0x0102_0304;
    const CLIENT_PORT: u16 = 44428;
    const SERVER_PORT: u16 = 443;
    /// Окно, при котором просьбы подождать нет: любое ненулевое.
    const OPEN_WINDOW: u16 = 502;

    fn ends(from_client: bool) -> Ends {
        match from_client {
            true => Ends {
                src_ip: CLIENT_IP,
                dst_ip: SERVER_IP,
                src_port: CLIENT_PORT,
                dst_port: SERVER_PORT,
            },
            false => Ends {
                src_ip: SERVER_IP,
                dst_ip: CLIENT_IP,
                src_port: SERVER_PORT,
                dst_port: CLIENT_PORT,
            },
        }
    }

    /// Сегмент с данными: обычный `PSH+ACK`, окно открыто.
    fn tcp(seq: u32, payload: &[u8], from_client: bool) -> Wire<'_> {
        windowed(seq, payload, from_client, OPEN_WINDOW, false)
    }

    /// Сегмент с заданным окном и флагом сброса — для проверок старшинства ветвей.
    fn windowed(
        seq: u32,
        payload: &[u8],
        from_client: bool,
        window: u16,
        resets: bool,
    ) -> Wire<'_> {
        wired(
            Segment {
                header: Header {
                    ends: ends(from_client),
                    seq,
                    ack: 0,
                    window,
                },
                opens: false,
                handshakes: false,
                closes: false,
                resets,
                payload,
            },
            from_client,
        )
    }

    fn udp(payload: &[u8], from_client: bool) -> Datagram<'_> {
        datagrammed(
            Payload {
                ends: ends(from_client),
                payload,
            },
            from_client,
        )
    }

    /// Первый клиентский QUIC-`Initial`: длинный заголовок, имени ещё нет.
    const INITIAL: &[u8] = &[0xc0, 0x00, 0x00, 0x00, 0x01, 0x08];

    /// ПРОДОЛЖЕНИЕ ПОТОКА — НЕ ПОВТОР.
    ///
    /// Сегмент, идущий следом, начинается РОВНО с границы, и разница даёт ноль. Первая редакция
    /// считала такой повтором и насчитала 16 там, где `tshark` видит 6 — нашлось сверкой с чужим
    /// оракулом, самому заметить было нечем.
    #[test]
    fn a_continuing_segment_is_not_a_repeat() {
        let frontier = moved(1000, b"hello", true, None);
        assert_eq!(frontier, Some(1005));
        assert!(!behind_frontier(1005, b"more", frontier));
    }

    /// ПОВТОР ТОГО ЖЕ — ПОВТОР: та же просьба ушла второй раз.
    #[test]
    fn the_same_segment_sent_again_is_a_repeat() {
        let frontier = moved(1000, b"hello", true, None);
        assert!(behind_frontier(1000, b"hello", frontier));
    }

    /// ПОВТОР ГРАНИЦУ НЕ ОТКАТЫВАЕТ — иначе следующий повтор перестал бы считаться повтором, и
    /// длинная серия ретрансмиссий свелась бы к одной.
    ///
    /// ПРОВЕРЯТЬ НАДО ПОСЛЕ ПРОДВИЖЕНИЯ. Первая редакция повторяла ЕДИНСТВЕННЫЙ отправленный
    /// сегмент — тогда граница совпадает при любом правиле, и тест зеленел со сломанным кодом.
    /// Найдено обезоруживанием.
    #[test]
    fn a_repeat_does_not_move_the_frontier_back() {
        let first = moved(1000, b"hello", true, None);
        let advanced = moved(1005, b"world!", true, first);
        assert_eq!(advanced, Some(1011), "граница не продвинулась");

        // Повтор ПЕРВОГО сегмента: он позади границы и откатывать её не смеет.
        let after_repeat = moved(1000, b"hello", true, advanced);
        assert_eq!(
            after_repeat, advanced,
            "повтор откатил границу: следующая ретрансмиссия сойдёт за новую просьбу"
        );
        assert!(behind_frontier(1005, b"world!", after_repeat));
    }

    /// ГРАНИЦУ ДВИГАЕТ ТОЛЬКО КЛИЕНТ: ответы цели идут своей нумерацией, и смешать их значило бы
    /// объявлять повторами всё подряд.
    #[test]
    fn the_servers_bytes_do_not_move_the_clients_frontier() {
        let frontier = moved(1000, b"hello", true, None);
        assert_eq!(moved(7000, b"answer", false, frontier), frontier);
    }

    /// ГОЛОВА ПОТОКА ВЫДАЁТСЯ ОДИН РАЗ НА НАПРАВЛЕНИЕ.
    ///
    /// Опознание протокола работает по НАЧАЛУ разговора: `ClientHello` у TLS, начальный блок у
    /// MTProto. Выдавать голову на каждом сегменте значило бы звать распознавание на всём потоке
    /// подряд — и опознавать середину шифрованных данных, где узнавать нечего.
    #[test]
    fn the_head_of_a_stream_is_handed_out_once_per_direction() {
        let hello = tcp(1000, b"\x16\x03\x01hello", true);
        let more = tcp(1008, b"more", true);
        assert!(matches!(
            seen_of_tcp(
                &hello,
                true,
                false,
                heads(hello.payload, true, (false, false))
            ),
            Some(SeenTcp::Anywhere(Seen::Payload {
                from_client: true,
                ..
            }))
        ));

        // Голова уже выдана — дальше идёт объём.
        assert!(matches!(
            seen_of_tcp(&more, true, false, heads(more.payload, true, (true, false))),
            Some(SeenTcp::Anywhere(Seen::Sent { .. }))
        ));
    }

    /// ГОЛОВА QUIC ЖДЁТ, ПОКА ИМЯ СОБЕРЁТСЯ.
    ///
    /// `ClientHello` разбит на два `Initial`, и на первом имени ЕЩЁ НЕТ. Выдав голову там, мы
    /// отдаём её с неполной личностью — и цель опознаётся под сетевым ключом, хотя имя соберётся
    /// через пакет.
    #[test]
    fn a_quic_head_waits_for_the_name() {
        assert!(
            !ready_to_name(INITIAL, 1, Named::Awaited),
            "голова отдана до того, как собралось имя"
        );
        // Имя собралось — личность полна, ждать нечего. Это и есть разница между краем, который
        // QUIC-приветствие разбирает, и плоскостью, которая его не разбирает.
        assert!(ready_to_name(INITIAL, 1, Named::Known));
    }

    /// ПРЕДОХРАНИТЕЛЬ: `ClientHello` может не собраться НИКОГДА — пакет потерян, версия чужая,
    /// куски не встык. Ждать вечно значит не выдать голову вовсе, и опознание протокола пропадёт
    /// вместе с именем, хотя `Proto::Quic` виден уже по первому пакету.
    #[test]
    fn the_wait_for_a_name_has_a_ceiling() {
        assert!(
            ready_to_name(INITIAL, NAME_PATIENCE, Named::Awaited),
            "ожидание имени не кончается — опознание пропадёт совсем"
        );
    }

    /// НЕ-QUIC ГОЛОВУ НЕ ЖДЁТ: у TLS поверх TCP имя лежит в этом же сегменте открытым текстом,
    /// и откладывать нечего.
    #[test]
    fn a_tls_head_is_not_postponed() {
        assert!(ready_to_name(b"\x16\x03\x01hello", 1, Named::Awaited));
    }

    /// ОТВЕТ ЦЕЛИ НЕ ЖДЁТ ВОВСЕ: имя приходит от КЛИЕНТА, и к серверной голове оно либо уже
    /// собрано, либо не соберётся.
    #[test]
    fn a_servers_head_never_waits() {
        let answer = udp(INITIAL, false);
        assert!(
            Talks::new().watch(&answer, Named::Awaited).is_some(),
            "ответ цели ждёт имени, которого от него и не бывает"
        );
    }

    /// У КАЖДОГО НАПРАВЛЕНИЯ СВОЯ ГОЛОВА: ответ цели — тоже начало разговора, только с её
    /// стороны, и признак «клиент уже назвался» его не отменяет.
    #[test]
    fn each_direction_has_its_own_head() {
        let answer = tcp(5000, b"\x16\x03\x03server", false);
        assert!(matches!(
            seen_of_tcp(
                &answer,
                false,
                false,
                heads(answer.payload, false, (true, false))
            ),
            Some(SeenTcp::Anywhere(Seen::Payload {
                from_client: false,
                ..
            }))
        ));
    }

    /// ПУСТОЙ СЕГМЕНТ ГОЛОВОЙ НЕ БЫВАЕТ: опознавать в нём нечего, а признак «голова выдана» он бы
    /// израсходовал — и настоящее начало разговора прошло бы уже как объём.
    #[test]
    fn an_empty_segment_is_never_a_head() {
        assert!(!heads(b"", true, (false, false)));
    }

    /// НУЛЕВОЕ ОКНО — ПРОСЬБА ПОДОЖДАТЬ, А НЕ ПУСТОЕ ПОДТВЕРЖДЕНИЕ.
    ///
    /// У такого сегмента данных обычно нет вовсе, и без отдельной ветки он был бы отброшен как
    /// чистый `ACK` — а это ровно тот факт, который объясняет медленность соединения.
    #[test]
    fn a_zero_window_is_a_request_to_wait() {
        let ack = windowed(1000, b"", true, 0, false);
        assert_eq!(
            seen_of_tcp(&ack, true, false, false),
            Some(SeenTcp::AskedToWait { by_client: true })
        );
    }

    /// КТО ПРОСИТ — СУЩЕСТВЕННО: просьбу шлёт тот, КОМУ шлют, и от этого зависит, кого не
    /// обвинять. Клиент притормозил сам — цель ни при чём; цель притормозила — отговорка ей не
    /// засчитывается.
    #[test]
    fn who_asks_to_wait_is_recorded() {
        let from_target = windowed(9000, b"", false, 0, false);
        assert_eq!(
            seen_of_tcp(&from_target, false, false, false),
            Some(SeenTcp::AskedToWait { by_client: false })
        );
    }

    /// СБРОС СИЛЬНЕЕ НУЛЕВОГО ОКНА: у сегмента с `RST` окно тоже нулевое, но это конец
    /// соединения, а не просьба подождать. Порядок разбора значим.
    #[test]
    fn a_reset_outranks_a_zero_window() {
        let reset = windowed(1000, b"", true, 0, true);
        assert_eq!(
            seen_of_tcp(&reset, true, false, false),
            Some(SeenTcp::Rst {
                by: ResetBy::Person
            })
        );
    }

    /// ПУСТОЙ СЕГМЕНТ (чистый `ACK`) НЕ ПОВТОР И ГРАНИЦЫ НЕ ДВИГАЕТ.
    #[test]
    fn a_bare_ack_is_neither_a_repeat_nor_progress() {
        let frontier = moved(1000, b"hello", true, None);
        assert!(!behind_frontier(1000, b"", frontier));
        assert_eq!(moved(1000, b"", true, frontier), frontier);
    }

    /// ОБЁРТКА НОМЕРОВ ПЕРЕЖИВАЕТСЯ: `seq` — 32-битный счётчик, и на четырёх гигабайтах потока он
    /// начинается заново. Прямое сравнение соврало бы ровно один раз за переполнение — на живом
    /// трафике это выглядело бы как внезапный шквал «повторов» посреди здоровой закачки.
    #[test]
    fn the_sequence_wrap_is_survived() {
        let near_end = u32::MAX - 2;
        let frontier = moved(near_end, b"abcde", true, None);
        // Продолжение после обёртки: 4294967293 + 5 = 2 (mod 2^32).
        assert_eq!(frontier, Some(2));
        assert!(!behind_frontier(2, b"next", frontier));
        assert!(behind_frontier(near_end, b"abcde", frontier));
    }

    /// ПАМЯТЬ О РАЗГОВОРЕ УХОДИТ ПО ПРИКАЗУ ХОЗЯИНА, а не сама.
    ///
    /// Четвёрка переиспользуется, и граница прошлого разговора объявила бы повтором первый
    /// сегмент нового. Проверка на потолок памяти здесь же: карта, растущая числом ВИДЕННЫХ
    /// разговоров, а не живых, есть утечка, неотличимая от нагрузки.
    #[test]
    fn a_conversation_is_forgotten_when_its_owner_says_so() {
        let hello = tcp(1000, b"hello", true);
        let flow = hello.flow;
        let mut talks = Talks::new();
        talks.read(&hello);
        assert_eq!(talks.len(), 1);
        assert!(
            talks.read(&tcp(1000, b"hello", true))
                == Some(SeenTcp::Anywhere(Seen::Resent { count: 5 })),
            "повтор не узнан — граница разговора не запомнилась"
        );

        talks.forget(flow);
        assert!(talks.is_empty(), "память разговора пережила приказ забыть");
        assert!(
            talks.read(&tcp(1000, b"hello", true))
                == Some(SeenTcp::Anywhere(Seen::Payload {
                    head: b"hello".to_vec(),
                    from_client: true
                })),
            "забытый разговор помнит границу: новый разговор на той же четвёрке начнётся повтором"
        );
    }
}
