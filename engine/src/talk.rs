//! Память о разговоре ради наблюдения — и перевод пакета в показание прибора. Отдельный предмет, не
//! часть плоскости: плоскость решает, ЧТО ДЕЛАТЬ с пакетом, здесь — ЧТО ПАКЕТ ПОКАЗАЛ (вердикт
//! нужен ядру, показание — приборам). Пока перевод жил в `Plane`, край не мог его взять и завёл
//! свой; две памяти расходятся молча (1136 флоу из 1136 мимо, #317; 16 повторов вместо 6 на `sag`,
//! #320). Правило сторон сюда не входит: кто клиент — вопрос ВХОДА (порт у очереди, улика у записи),
//! оба ответа уже вложены в `dir` сборщиком [`Wire`] (`parse::wired`) и читаются одинаково.

use std::collections::BTreeMap;

use crate::{Dir, Flow};
use reflex_instrument::wire::{ResetBy, Seen, SeenTcp};

use crate::parse::{Datagram, Wire};

/// Что плоскость помнит о разговоре ради наблюдения — и только ради него. Отдельно от `cursors`
/// (состояние ЛЕЧЕНИЯ) намеренно: разные хозяева и сроки жизни; слить значило бы отдать закону право
/// уронить наблюдение своим шагом.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct Talk {
    /// Наибольший `seq + длина` от КЛИЕНТА. Сегмент раньше него — ПОВТОР (просьба ушла второй раз):
    /// для человека это «страница не грузится», а не «грузится дальше».
    frontier: Option<u32>,
    /// Выдана ли уже голова потока — по направлению. Первый сегмент с данными несёт то, по чему
    /// узнаётся протокол; последующие — объём. Опознание работает по началу разговора, один раз.
    head_out: (bool, bool),
    /// Сколько содержательных пакетов от КЛИЕНТА. Нужен датаграммам: у QUIC приветствие разбито на
    /// два `Initial`, на первом имени ещё нет.
    from_client_seen: u32,
}

/// Знаем ли уже имя цели — вход правила «пора ли отдавать голову датаграммы». Не `bool`: край
/// добывает имя из QUIC-`Initial` и знает раньше конца терпения, плоскость QUIC-приветствие не
/// разбирает и отвечает [`Named::Awaited`] всегда. Названная дыра плоскости, а не умолчание типа.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Named {
    Known,
    Awaited,
}

/// Сколько клиентских пакетов ждать имени. Три — с запасом (Chrome укладывает `ClientHello` в два
/// `Initial`). Не замерено на широкой выборке: больше — задержим опознание у целей без имени, меньше
/// — отдадим голову раньше имени.
const NAME_PATIENCE: u32 = 3;

/// Пора ли отдавать голову датаграммы: у QUIC-`Initial` имя может лежать в следующем пакете.
fn ready_to_name(payload: &[u8], from_client_seen: u32, named: Named) -> bool {
    match named {
        Named::Known => true,
        Named::Awaited => match payload.first().is_some_and(|first| first & 0xf0 == 0xc0) {
            // Не QUIC-`Initial`: имя, если есть, лежит в этом же пакете.
            false => true,
            true => from_client_seen >= NAME_PATIENCE,
        },
    }
}

/// Повтор ли: сегмент несёт данные и начинается СТРОГО позади границы. «Строго», не «не дальше»:
/// продолжение потока начинается ровно с границы (первая редакция считала его повтором — 16 вместо
/// 6 у `tshark`). Расстояние с обёрткой: `seq` 32-битен, прямое `<` соврало бы раз за переполнение.
fn behind_frontier(seq: u32, payload: &[u8], frontier: Option<u32>) -> bool {
    match (frontier, payload.is_empty()) {
        (None, _) | (_, true) => false,
        (Some(frontier), false) => {
            let back = frontier.wrapping_sub(seq);
            back > 0 && back < u32::MAX / 2
        }
    }
}

/// Куда сдвинулась граница клиента. Только вперёд: повтор границы не двигает, иначе второй повтор
/// перестал бы считаться повтором.
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

/// Голова ли это — сегмент, по которому цель будет опознана. Ожидание сборки сюда не входит: у TLS
/// поверх TCP имя лежит в первом сегменте; ждать приходится датаграммам, и там ожидание — явной
/// строкой у вызова ([`ready_to_name`]).
fn heads(payload: &[u8], from_client: bool, out: (bool, bool)) -> bool {
    let already = match from_client {
        true => out.0,
        false => out.1,
    };
    !already && !payload.is_empty()
}

/// Общая часть обоих алфавитов — байты и голова потока. Одна на два протокола: факт один (человек
/// попросил, цель отдала). Пустой сегмент без флагов — чистый `ACK`, события из него нет.
fn anywhere(payload: &[u8], from_client: bool, repeat: bool, head: bool) -> Option<Seen> {
    match (!payload.is_empty(), head, from_client) {
        // Голова потока — отдельным фактом, не вдобавок к объёму (тот же сегмент, названный так,
        // чтобы опознание его увидело). Двух событий на сегмент не выпускаем — объём посчитался бы
        // дважды.
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

/// Что видно на соединении — в словаре TCP. Порядок ветвей не косметичен: просьба подождать
/// проверяется после сброса и рукопожатия, но до нагрузки (у сегмента с нулевым окном данных обычно
/// нет, без отдельной ветки он был бы отброшен как `ACK` — а это факт, объясняющий медленность).
fn seen_of_tcp(wire: &Wire<'_>, from_client: bool, repeat: bool, head: bool) -> Option<SeenTcp> {
    match (wire.resets, wire.opens, wire.handshakes) {
        // Автор сброса сохраняется: наш собственный сброс не есть беда цели (#287).
        (true, _, _) => Some(SeenTcp::Rst {
            by: match from_client {
                true => ResetBy::Person,
                // Не `Target`: со стороны цели приходит и её отказ, и инжект постороннего от её
                // имени, а различитель (TTL, фингерпринт) здесь не читается — Н10 #320.
                false => ResetBy::TargetSide,
            },
        }),
        // Стук клиента и ответ цели — разные события. Прежде оба давали `Syn`, «рукопожатие
        // состоялось» было невыразимо, блокировка по адресу и по имени сливались.
        (_, true, _) => Some(SeenTcp::Syn),
        (_, _, true) => Some(SeenTcp::Handshaken),
        // Нулевое окно приёма: «мне некуда, подожди». Шлёт его тот, КОМУ шлют.
        _ if wire.header.window == 0 => Some(SeenTcp::AskedToWait {
            by_client: from_client,
        }),
        // Прощание — только на сегменте без данных (#294): правило «одно событие на сегмент»
        // вынуждает выбирать при `FIN` с данными — считаем данные (закрытие двустороннее, второй
        // `FIN` почти всегда чист).
        _ if wire.closes && wire.payload.is_empty() => Some(SeenTcp::closed(from_client)),
        // Остаток назван явно, не `_`: новый флаг в разборе сломает эту строку, а не проскочит молча.
        (false, false, false) => {
            anywhere(wire.payload, from_client, repeat, head).map(SeenTcp::Anywhere)
        }
    }
}

/// Память о всех идущих разговорах, из которой рождаются показания. Уборку ведёт ХОЗЯИН, не эта карта
/// (у плоскости разговор кончается с курсором, у края — с записью): заведи здесь свой потолок — их
/// стало бы два, и сработавший первым уронил бы наблюдение у второго молча.
#[derive(Debug, Clone, Default)]
pub struct Talks {
    talks: BTreeMap<Flow, Talk>,
}

impl Talks {
    pub fn new() -> Talks {
        Talks {
            talks: BTreeMap::new(),
        }
    }

    /// Снять показание с сегмента — и подвинуть память тем же шагом. Стороны неразделимы: повтор
    /// узнаётся сравнением с границей, а граница двигается этим же сегментом. Отдаёт `SeenTcp`, не
    /// `Reading`: протокол известен ВХОДОМ — обернуть в `Reading` пообещало бы датаграмму там, где
    /// её быть не может.
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
                // У соединения ждать нечего: имя в первом сегменте открытым текстом. Счётчик ведётся
                // всё равно — разговор может сменить транспорт на том же ключе.
                from_client_seen: talk.from_client_seen
                    + u32::from(from_client && !wire.payload.is_empty()),
            },
        );
        seen_of_tcp(wire, from_client, repeat, head)
    }

    /// Снять показание с датаграммы. Словарь ровно общий: ни стука, ни рукопожатия, ни сброса, ни
    /// окна — это свойство транспорта, а не «пока не сделано».
    pub fn watch(&mut self, datagram: &Datagram<'_>, named: Named) -> Option<Seen> {
        let from_client = matches!(datagram.dir, Dir::Up);
        let talk = self.talks.get(&datagram.flow).copied().unwrap_or_default();
        // Порядок значим: счётчик клиентских пакетов растёт ДО решения о голове. Наоборот — и третий
        // `Initial`, на котором имя собрано, считался бы вторым.
        let from_client_seen =
            talk.from_client_seen + u32::from(from_client && !datagram.payload.is_empty());
        let head = heads(datagram.payload, from_client, talk.head_out)
            && (!from_client || ready_to_name(datagram.payload, from_client_seen, named));
        self.talks.insert(
            datagram.flow,
            Talk {
                // Границы у датаграмм нет: номеров нет, повтор по ним не узнать (QUIC их шифрует).
                // Признак молчит, а не гадает.
                frontier: talk.frontier,
                head_out: marked(talk.head_out, head, from_client),
                from_client_seen,
            },
        );
        anywhere(datagram.payload, from_client, false, head)
    }

    /// Разговора больше нет — память о нём уходит. Зовётся и на открытии: четвёрка переиспользуется,
    /// граница прошлого разговора объявила бы повтором первый сегмент нового.
    pub fn forget(&mut self, flow: Flow) {
        self.talks.remove(&flow);
    }

    /// Сколько разговоров под наблюдением. Витнес потолка памяти: карта, растущая числом ВИДЕННЫХ
    /// соединений, а не живых, есть утечка, неотличимая от нагрузки.
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

/// Проверки переехали вместе с поведением (#320): жили в другом крейте, стерегли вторую реализацию
/// перевода. Реализация теперь одна — покрытие обязано было приехать сюда, иначе исчезло бы молча.
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

    /// Продолжение потока — не повтор: следующий сегмент начинается ровно с границы (разница ноль).
    #[test]
    fn a_continuing_segment_is_not_a_repeat() {
        let frontier = moved(1000, b"hello", true, None);
        assert_eq!(frontier, Some(1005));
        assert!(!behind_frontier(1005, b"more", frontier));
    }

    /// Повтор того же — повтор: та же просьба ушла второй раз.
    #[test]
    fn the_same_segment_sent_again_is_a_repeat() {
        let frontier = moved(1000, b"hello", true, None);
        assert!(behind_frontier(1000, b"hello", frontier));
    }

    /// Повтор границу не откатывает (иначе следующий повтор перестал бы считаться). Проверять надо
    /// после продвижения: на единственном сегменте граница совпадает при любом правиле.
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

    /// Границу двигает только клиент: ответы цели идут своей нумерацией.
    #[test]
    fn the_servers_bytes_do_not_move_the_clients_frontier() {
        let frontier = moved(1000, b"hello", true, None);
        assert_eq!(moved(7000, b"answer", false, frontier), frontier);
    }

    /// Голова потока выдаётся один раз на направление: опознание работает по началу разговора.
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

    /// Голова QUIC ждёт, пока имя соберётся: `ClientHello` разбит на два `Initial`.
    #[test]
    fn a_quic_head_waits_for_the_name() {
        assert!(
            !ready_to_name(INITIAL, 1, Named::Awaited),
            "голова отдана до того, как собралось имя"
        );
        // Имя собралось — ждать нечего. Разница между краем (разбирает QUIC) и плоскостью (нет).
        assert!(ready_to_name(INITIAL, 1, Named::Known));
    }

    /// Предохранитель: `ClientHello` может не собраться никогда (потерян, чужая версия) — ждать
    /// вечно значит не выдать голову вовсе, и опознание пропадёт, хотя `Proto::Quic` виден сразу.
    #[test]
    fn the_wait_for_a_name_has_a_ceiling() {
        assert!(
            ready_to_name(INITIAL, NAME_PATIENCE, Named::Awaited),
            "ожидание имени не кончается — опознание пропадёт совсем"
        );
    }

    /// Не-QUIC голову не ждёт: у TLS поверх TCP имя лежит в этом же сегменте открытым текстом.
    #[test]
    fn a_tls_head_is_not_postponed() {
        assert!(ready_to_name(b"\x16\x03\x01hello", 1, Named::Awaited));
    }

    /// Ответ цели не ждёт: имя приходит от КЛИЕНТА, к серверной голове оно либо собрано, либо нет.
    #[test]
    fn a_servers_head_never_waits() {
        let answer = udp(INITIAL, false);
        assert!(
            Talks::new().watch(&answer, Named::Awaited).is_some(),
            "ответ цели ждёт имени, которого от него и не бывает"
        );
    }

    /// У каждого направления своя голова: ответ цели — тоже начало разговора, с её стороны.
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

    /// Пустой сегмент головой не бывает: опознавать нечего, а признак «голова выдана» он бы
    /// израсходовал — и настоящее начало прошло бы уже как объём.
    #[test]
    fn an_empty_segment_is_never_a_head() {
        assert!(!heads(b"", true, (false, false)));
    }

    /// Нулевое окно — просьба подождать, а не пустое подтверждение (иначе отброшено как `ACK`).
    #[test]
    fn a_zero_window_is_a_request_to_wait() {
        let ack = windowed(1000, b"", true, 0, false);
        assert_eq!(
            seen_of_tcp(&ack, true, false, false),
            Some(SeenTcp::AskedToWait { by_client: true })
        );
    }

    /// Кто просит — существенно: просьбу шлёт тот, КОМУ шлют, и от этого зависит, кого не обвинять.
    #[test]
    fn who_asks_to_wait_is_recorded() {
        let from_target = windowed(9000, b"", false, 0, false);
        assert_eq!(
            seen_of_tcp(&from_target, false, false, false),
            Some(SeenTcp::AskedToWait { by_client: false })
        );
    }

    /// Сброс сильнее нулевого окна: у сегмента с `RST` окно тоже нулевое, но это конец соединения.
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

    /// Пустой сегмент (чистый `ACK`) не повтор и границы не двигает.
    #[test]
    fn a_bare_ack_is_neither_a_repeat_nor_progress() {
        let frontier = moved(1000, b"hello", true, None);
        assert!(!behind_frontier(1000, b"", frontier));
        assert_eq!(moved(1000, b"", true, frontier), frontier);
    }

    /// Обёртка номеров переживается: `seq` 32-битен, на 4 ГБ потока начинается заново. Прямое
    /// сравнение соврало бы раз за переполнение — шквал «повторов» посреди здоровой закачки.
    #[test]
    fn the_sequence_wrap_is_survived() {
        let near_end = u32::MAX - 2;
        let frontier = moved(near_end, b"abcde", true, None);
        // Продолжение после обёртки: 4294967293 + 5 = 2 (mod 2^32).
        assert_eq!(frontier, Some(2));
        assert!(!behind_frontier(2, b"next", frontier));
        assert!(behind_frontier(near_end, b"abcde", frontier));
    }

    /// Память о разговоре уходит по приказу хозяина, а не сама. Четвёрка переиспользуется, граница
    /// прошлого объявила бы повтором первый сегмент нового; потолок памяти проверяется здесь же.
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
