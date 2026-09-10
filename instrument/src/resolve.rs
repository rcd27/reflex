//! Резолв уведён — прибор о подмене DNS. Разбор (`reflex_core::dns::DnsMessage`) у нас был, но с
//! нулём читателей — дыра была не в том, что нечем разобрать, а в том, что разобранное никто не
//! смотрит. Разбор взят целиком (вторая реализация разошлась бы молча).

use reflex_core::dns::{DnsDirection, DnsMessage};

/// Тип записи `A` — адрес IPv4.
const A_RECORD: u16 = 1;
/// `RCODE` «имени не существует».
const NXDOMAIN: u8 = 3;

/// Куда увели резолв — и уводили ли. Не `bool`: без адреса беду не назвать, а «ответ пуст» лечится
/// иначе, чем подмена.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolved {
    /// Имя разрешилось в адрес, и адрес выглядит настоящим.
    Honest { name: String, addr: [u8; 4] },
    /// Публичное имя разрешилось в частный адрес — так выглядит увод на заглушку (и наша земля
    /// `dns_spoof`).
    Hijacked { name: String, to: [u8; 4] },
    /// Ответ есть, адреса нет — имя не увели, а стёрли: клиент останется без цели.
    Erased { name: String },
}

/// Сказано цели: чем разрешилось её имя. Разговора ещё нет — по этому адресу его собираются заводить.
impl reflex_core::word::Word for Resolved {
    type Of = reflex_core::word::Target;
}

/// Прибор разрешения имени.
#[derive(Debug, Clone, Copy)]
pub struct ResolutionInstrument;

impl ResolutionInstrument {
    fn read(&self, message: &DnsMessage, _now_ms: u64) -> Option<Resolved> {
        // Запрос улики не несёт: судить его — отвечать на незаданный вопрос.
        match message.direction {
            DnsDirection::Query => return None,
            DnsDirection::Response => (),
        }

        // Вопрос не про адрес — не предмет: в ответе на `AAAA` записей `A` нет по построению,
        // прибор говорил на это «адрес стёрт», выдавая свою слепоту за факт (найдено 02.09).
        let name = match message.queries.first() {
            None => return None,
            Some(query) if query.qtype != A_RECORD => return None,
            Some(query) => query.name.clone(),
        };

        // Имени не существует — не беда: поиск по суффиксам законно получает `NXDOMAIN`. Настоящий
        // перехват отвечает тем же, но с флагом `aa` — эта улика не построена, потому здесь молчим.
        match message.rcode {
            NXDOMAIN => return None,
            _answered => (),
        }

        // Только записи `A` (тип 1), только четырёхбайтовые: домен держит адрес четырьмя байтами.
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
            // Ответ без адреса — имя стёрли, не увели.
            None => Some(Resolved::Erased { name }),
            Some(&addr) => match private(addr) && !internal_name(&name) {
                true => Some(Resolved::Hijacked { name, to: addr }),
                false => Some(Resolved::Honest { name, addr }),
            },
        }
    }
}

impl reflex_core::mealy::Mealy for ResolutionInstrument {
    type In = reflex_core::DetectorEvent<DnsMessage>;
    /// Слово. Молчание сигналом не является.
    type Out = smallvec::SmallVec<[Resolved; 2]>;
    type Log = ();

    fn step(self, event: Self::In) -> (Self, Self::Out, ()) {
        match event {
            reflex_core::DetectorEvent::Packet { input, .. } => {
                let reading = self.read(&input, 0);
                (self, reading.into_iter().collect(), ())
            }
            // Состояния у прибора НЕТ (`PhantomData`): показание есть функция одной буквы, и от
            // полноты входа не зависит вовсе. Прячущей букве тут нечего исказить — тождество
            // доказано ТИПОМ, а не рассуждением (§7, Д7).
            reflex_core::DetectorEvent::Tick { .. }
            | reflex_core::DetectorEvent::Opaque { .. }
            | reflex_core::DetectorEvent::Torn { .. } => (self, smallvec::SmallVec::new(), ()),
        }
    }
}

impl crate::Instrument for ResolutionInstrument {
    type Signal = Resolved;

    const INSTRUMENT: &'static str = "resolve";

    const SUBJECT: crate::Subject = crate::Subject::World;

    /// Уровень приложения: улика в содержимом ответа. Транспортный прибор видит лишь UDP к порту 53.
    const LAYER: crate::Layer = crate::Layer::Application;
    const PROTOCOLS: &'static [crate::Protocol] = &[crate::Protocol::Dns];

    /// Ступень «то ли пришло»: вопрос как у содержимого HTTP, улика — своя.
    const RUNG: Option<crate::Rung> = Some(crate::Rung::Authentic);

    /// Чужой темп: подмены не существует без запроса.
    const CADENCE: crate::Cadence = crate::Cadence::Foreign;

    const SHAPE: crate::Shape = crate::Shape::Verdict;

    /// Не смотрел, а не не нашёл: на запрос прибор не отвечает — `Nothing`, улики в запросе нет.
    const SILENCE: Option<crate::Silence> = Some(crate::Silence::Nothing);

    const LIES: &'static [&'static str] = &[
        "УВОД НА ПУБЛИЧНЫЙ АДРЕС НЕ ЛОВИТСЯ. Признак — частный адрес у публичного имени, и \
         реальный перехват уводит на подставной резолвер, который ПУБЛИЧЕН. Замер 28.08 назвал \
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

    const DEATH: &'static str = "построена улика NXDOMAIN+aa; прибор видит увод на публичный адрес";

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

/// Частный диапазон. Та же таблица, что у `initiator`, но не дубль: там про «кто из двоих клиент»,
/// здесь про «мог ли публичный сайт жить по этому адресу» — слить значило бы связать два прибора.
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

/// Имя, законно живущее внутри. Список неполон: split-horizon DNS делает внутренним любое имя.
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

    /// Вопрос не про адрес — не предмет прибора (в ответе на `AAAA` записей `A` нет).
    #[test]
    fn a_question_about_ipv6_is_not_this_instruments_business() {
        let said = crate::says(ResolutionInstrument, answer(28, 0, vec![]));

        assert_eq!(said.as_slice(), &[]);
    }

    /// Имени не существует — не беда: поиск по суффиксам законно получает `NXDOMAIN`.
    #[test]
    fn a_name_that_does_not_exist_is_not_trouble() {
        let said = crate::says(ResolutionInstrument, answer(1, 3, vec![]));

        assert_eq!(said.as_slice(), &[]);
    }

    /// Ответ есть, адреса нет — имя стёрли.
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

    /// Честный ответ и увод на частный адрес различаются.
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
