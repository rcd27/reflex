//! РЕЗОЛВ УВЕДЁН — прибор о третьем случае из трёх, названных эпиком #320.
//!
//! Формулировка тикета: «его резолв уводят на НСДИ, и мы об этом не знаем: DNS не наблюдается
//! ничем, перехват видели руками один раз (#313)».
//!
//! # Почему это срез 1, а не срез 4
//!
//! Разбор DNS у нас БЫЛ — `reflex_core::dns::DnsMessage` с очередями, ответами и направлением.
//! Замер подключённости показал у него НОЛЬ читателей: механизм построен, покрыт своими тестами
//! и не зовётся из продукта ни разу. То есть дыра была не в том, что нечем разобрать, а в том,
//! что разобранное никто не смотрит.
//!
//! Ровно тот множитель, ради которого заведён эпик: прибор с нулевой подключённостью по своему
//! выходу неотличим от исправного.
//!
//! # Что здесь НЕ строится заново
//!
//! Разбор. Он взят целиком, и это не экономия, а закон: вторая реализация того же разбора
//! разъедется с первой молча, и мы получим два ответа на один вопрос.

use reflex_core::dns::{DnsDirection, DnsMessage};

/// Тип записи `A` — адрес IPv4. Другие типы прибору не предмет: домен держит адрес четырьмя
/// байтами.
const A_RECORD: u16 = 1;
/// `RCODE` «имени не существует».
const NXDOMAIN: u8 = 3;

/// КУДА УВЕЛИ РЕЗОЛВ — и уводили ли.
///
/// Не `bool`: «подмена есть» без адреса не даёт ни назвать беду человеку, ни сверить её с землёй,
/// а третий случай («ответ пуст») лечится иначе, чем первые два.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolved {
    /// Имя разрешилось в адрес, и адрес выглядит настоящим.
    Honest { name: String, addr: [u8; 4] },
    /// ПУБЛИЧНОЕ ИМЯ РАЗРЕШИЛОСЬ В ЧАСТНЫЙ АДРЕС. Так выглядит увод на заглушку внутри сети —
    /// и так же выглядит наша собственная земля `dns_spoof`.
    Hijacked { name: String, to: [u8; 4] },
    /// ОТВЕТ ЕСТЬ, АДРЕСА В НЁМ НЕТ. Отдельно от подмены, потому что лечение другое: здесь имя
    /// не увели, его СТЁРЛИ, и клиент останется без цели вовсе.
    Erased { name: String },
}

/// ПАСПОРТ ПРИБОРА РАЗРЕШЕНИЯ ИМЕНИ.
#[derive(Debug, Clone, Copy)]
pub struct ResolutionInstrument;

impl ResolutionInstrument {
    fn read(&self, message: &DnsMessage, _now_ms: u64) -> Option<Resolved> {
        // ЗАПРОС УЛИКИ НЕ НЕСЁТ. Судить его значило бы отвечать на вопрос, которого ещё не задали.
        match message.direction {
            DnsDirection::Query => return None,
            DnsDirection::Response => (),
        }

        // ВОПРОС НЕ ПРО АДРЕС — НЕ ПРЕДМЕТ ПРИБОРА. Клиент спрашивает `A` и `AAAA` разом, и в
        // ответе на `AAAA` записей `A` нет по построению: прибор говорил на это «адрес стёрт»,
        // выдавая свою слепоту за факт о мире (найдено живым прогоном 02.09).
        let name = match message.queries.first() {
            None => return None,
            Some(query) if query.qtype != A_RECORD => return None,
            Some(query) => query.name.clone(),
        };

        // ИМЕНИ НЕ СУЩЕСТВУЕТ — НЕ БЕДА: поиск по суффиксам (`search lan`) законно получает
        // `NXDOMAIN` на каждое имя. ЦЕНА: настоящий перехват ТСПУ отвечает тем же `NXDOMAIN`, но
        // с флагом `aa` от неавторитетного резолвера, и эта улика не построена — здесь прибор
        // МОЛЧИТ, а не выбирает между двумя догадками.
        match message.rcode {
            NXDOMAIN => return None,
            _answered => (),
        }

        // ТОЛЬКО ЗАПИСИ `A` (тип 1) И ТОЛЬКО ЧЕТЫРЁХБАЙТОВЫЕ. `AAAA`, `CNAME` и прочее сюда не
        // попадают намеренно: домен держит адрес четырьмя байтами, и притворяться, что прибор
        // умеет больше, вреднее молчания.
        let addresses: Vec<[u8; 4]> = message
            .answers
            .iter()
            .filter(|answer| answer.rtype == 1 && answer.rdata.len() == 4)
            .map(|answer| {
                [
                    answer.rdata[0],
                    answer.rdata[1],
                    answer.rdata[2],
                    answer.rdata[3],
                ]
            })
            .collect();

        match addresses.first() {
            // ОТВЕТ БЕЗ АДРЕСА — имя стёрли, а не увели.
            None => Some(Resolved::Erased { name }),
            Some(&addr) => match private(addr) && !internal_name(&name) {
                true => Some(Resolved::Hijacked { name, to: addr }),
                false => Some(Resolved::Honest { name, addr }),
            },
        }
    }
}

impl reflex_core::step::Step for ResolutionInstrument {
    /// НАБЛЮДЕНИЕ, которое подают прибору.
    type From = reflex_core::DetectorEvent<DnsMessage>;

    /// ПОКАЗАНИЕ. Отсутствие показания сигналом не является: прибор высказывается, когда есть что
    /// сказать, и «ничего не случилось» не занимает места в ленте.
    type To = smallvec::SmallVec<[Resolved; 2]>;

    fn step(self, event: Self::From) -> (Self, Self::To) {
        match event {
            reflex_core::DetectorEvent::Packet { input, .. } => {
                let reading = self.read(&input, 0);
                (self, reading.into_iter().collect())
            }
            reflex_core::DetectorEvent::Tick { .. } => (self, smallvec::SmallVec::new()),
            // Прибор мерит РАЗОБРАННЫЙ домен; непонятое им не является и молчит так же, как тик.
            reflex_core::DetectorEvent::Opaque { .. } => (self, smallvec::SmallVec::new()),
        }
    }
}

impl crate::Instrument for ResolutionInstrument {
    type Signal = Resolved;

    const INSTRUMENT: &'static str = "resolve";

    const SUBJECT: crate::Subject = crate::Subject::World;

    /// УРОВЕНЬ ПРИЛОЖЕНИЯ: улика лежит в содержимом ответа, а не в адресах и портах. Транспортный
    /// прибор её не увидит ни при каком разборе — там просто UDP-датаграмма к порту 53.
    const LAYER: crate::Layer = crate::Layer::Application;
    const PROTOCOLS: &'static [crate::Protocol] = &[crate::Protocol::Dns];

    /// СТУПЕНЬ «ТО ЛИ ПРИШЛО»: вопрос тот же, что у содержимого HTTP, улика — своя.
    const RUNG: Option<crate::Rung> = Some(crate::Rung::Authentic);

    /// ЧУЖОЙ ТЕМП: прибор высказывается, когда пришёл ответ, и молчит, пока никто не спрашивал.
    /// Для его предмета это законно — подмены не существует без запроса.
    const CADENCE: crate::Cadence = crate::Cadence::Foreign;

    const SHAPE: crate::Shape = crate::Shape::Verdict;

    /// НЕ СМОТРЕЛ, А НЕ НЕ НАШЁЛ: на запрос (а не ответ) прибор не отвечает вовсе — это `Nothing`,
    /// потому что в запросе улики нет по построению, а не потому что он ослеп.
    const SILENCE: Option<crate::Silence> = Some(crate::Silence::Nothing);

    const LIES: &'static [&'static str] = &[
        "УВОД НА ПУБЛИЧНЫЙ АДРЕС НЕ ЛОВИТСЯ. Признак — частный адрес у публичного имени, и \
         реальный перехват ТСПУ уводит на НСДИ 195.208.5.1, который ПУБЛИЧЕН. Замер 28.08 назвал \
         тамошнюю улику иначе: `NXDOMAIN` с флагом `aa` от резолвера, который не является \
         авторитетным. Эта вторая улика здесь НЕ построена, и потому поле прибор увидит хуже стенда.",
        "ЧАСТНЫЙ АДРЕС БЫВАЕТ ЗАКОННЫМ. Внутренние имена компании, `*.local`, split-horizon DNS — \
         всё это честно разрешается в 10/8 и 192.168/16. Прибор объявит подмену, и будет неправ; \
         различает их только знание о том, чьё это имя, а такого знания у него нет.",
        "ОТВЕТ ОТ НЕ ТОГО РЕЗОЛВЕРА НЕ ПРОВЕРЯЕТСЯ. Классическая подмена приходит от адреса, \
         которого клиент не спрашивал, — здесь это не смотрится вовсе: прибор судит содержимое, \
         а не отправителя.",
    ];

    const ORACLES: &'static [&'static str] = &["dns_spoof(rutracker.org,10.77.0.99)", "udp_dns"];

    /// СМЕРТЬ: заведена вторая улика — `NXDOMAIN` с `aa` от неавторитетного резолвера. Тогда
    /// прибор начнёт видеть перехват НСДИ, то есть ровно тот случай, ради которого он и нужен.
    const DEATH: &'static str = "построена улика NXDOMAIN+aa; прибор видит увод на публичный адрес";

    /// ПУБЛИЧНЫЕ ИМЕНА СОБЫТИЙ — реестр, снятый с типа: за границей процесса имя показания не
    /// сторожит компилятор, и `Debug` сменил бы метку молча (#321).
    const EVENTS: &'static [&'static str] =
        &["resolve_honest", "resolve_hijacked", "resolve_erased"];

    fn name(signal: &Self::Signal) -> &'static str {
        match signal {
            Resolved::Honest { .. } => "resolve_honest",
            Resolved::Hijacked { .. } => "resolve_hijacked",
            Resolved::Erased { .. } => "resolve_erased",
        }
    }

    fn about(signal: &Self::Signal) -> Option<String> {
        Some(match signal {
            Resolved::Honest { name, .. }
            | Resolved::Hijacked { name, .. }
            | Resolved::Erased { name } => name.clone(),
        })
    }

    fn alarming(signal: &Self::Signal) -> bool {
        match signal {
            Resolved::Honest { .. } => false,
            Resolved::Hijacked { .. } | Resolved::Erased { .. } => true,
        }
    }

    fn detail(signal: &Self::Signal) -> String {
        match signal {
            Resolved::Honest { addr, .. } => {
                format!("{}.{}.{}.{}", addr[0], addr[1], addr[2], addr[3])
            }
            Resolved::Hijacked { to, .. } => {
                format!("уведён на {}.{}.{}.{}", to[0], to[1], to[2], to[3])
            }
            Resolved::Erased { .. } => "адреса нет в ответе".to_string(),
        }
    }
}

/// ЧАСТНЫЙ ДИАПАЗОН — та же таблица, что у [`crate::initiator`], и это НЕ дубль по недосмотру:
/// там она отвечает на «кто из двоих клиент», здесь — на «мог ли публичный сайт жить по этому
/// адресу». Вопросы разные, и слить их значило бы связать два прибора общей правкой.
fn private(addr: [u8; 4]) -> bool {
    match addr {
        [10, _, _, _] => true,
        [172, second, _, _] if (16..32).contains(&second) => true,
        [192, 168, _, _] => true,
        [127, _, _, _] => true,
        [0, _, _, _] => true,
        _ => false,
    }
}

/// ИМЯ, КОТОРОЕ ЗАКОННО ЖИВЁТ ВНУТРИ. Список короткий и признан неполным: полного не существует,
/// потому что split-horizon DNS делает внутренним любое имя по решению владельца сети.
fn internal_name(name: &str) -> bool {
    name.ends_with(".local")
        || name.ends_with(".lan")
        || name.ends_with(".internal")
        || !name.contains('.')
}

#[cfg(test)]
mod tests {
    use super::*;
    use reflex_core::dns::{DnsAnswer, DnsDirection, DnsQuery};

    /// Ответ с названными вопросом, кодом и записями.
    fn answer(qtype: u16, rcode: u8, answers: Vec<DnsAnswer>) -> DnsMessage {
        DnsMessage {
            id: 1,
            direction: DnsDirection::Response,
            rcode,
            queries: vec![DnsQuery {
                name: "rutracker.org".to_string(),
                qtype,
                qclass: 1,
            }],
            answers,
        }
    }

    fn a_record(addr: [u8; 4]) -> DnsAnswer {
        DnsAnswer {
            name: "rutracker.org".to_string(),
            rtype: 1,
            rclass: 1,
            ttl: 300,
            rdata: addr.to_vec(),
        }
    }

    /// ВОПРОС НЕ ПРО АДРЕС — НЕ ПРЕДМЕТ ПРИБОРА.
    ///
    /// Клиент спрашивает `A` и `AAAA` разом; в ответе на `AAAA` записей `A` нет по построению.
    /// Прибор говорил на это «адрес стёрт», то есть выдавал собственную слепоту за факт о мире.
    /// Найдено живым прогоном 02.09: каждая цель давала ложную беду.
    #[test]
    fn a_question_about_ipv6_is_not_this_instruments_business() {
        let said = crate::says(ResolutionInstrument, answer(28, 0, vec![]));

        assert_eq!(said.as_slice(), &[]);
    }

    /// ИМЕНИ НЕ СУЩЕСТВУЕТ — НЕ БЕДА.
    ///
    /// Поиск по суффиксам (`resolv.conf search lan`) спрашивает `rutracker.org.lan` и законно
    /// получает `NXDOMAIN`. Прибор объявлял это уводом адреса.
    ///
    /// ЦЕНА НАЗВАНА: настоящий перехват ТСПУ отвечает `NXDOMAIN` с флагом `aa` от неавторитетного
    /// резолвера — эта улика не построена, и здесь прибор теперь молчит вместо ложной тревоги.
    #[test]
    fn a_name_that_does_not_exist_is_not_trouble() {
        let said = crate::says(ResolutionInstrument, answer(1, 3, vec![]));

        assert_eq!(said.as_slice(), &[]);
    }

    /// ОТВЕТ ЕСТЬ, АДРЕСА В НЁМ НЕТ — вот это беда: имя стёрли.
    #[test]
    fn an_answer_without_an_address_is_an_erasure() {
        let said = crate::says(ResolutionInstrument, answer(1, 0, vec![]));

        assert_eq!(
            said.as_slice(),
            &[Resolved::Erased {
                name: "rutracker.org".to_string()
            }]
        );
    }

    /// ЧЕСТНЫЙ ОТВЕТ И УВОД НА ЧАСТНЫЙ АДРЕС различаются по-прежнему.
    #[test]
    fn an_honest_answer_and_a_hijack_are_still_told_apart() {
        let honest = crate::says(
            ResolutionInstrument,
            answer(1, 0, vec![a_record([104, 21, 32, 39])]),
        );
        let hijacked = crate::says(
            ResolutionInstrument,
            answer(1, 0, vec![a_record([10, 77, 0, 99])]),
        );

        assert!(matches!(honest.first(), Some(Resolved::Honest { .. })));
        assert!(matches!(hijacked.first(), Some(Resolved::Hijacked { .. })));
    }
}
