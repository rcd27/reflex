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
    /// Имя разрешилось, и адреса выглядят настоящими. ВСЕ адреса ответа, а не первый.
    ///
    /// Отдавать первый значило терять остальные молча, и цена этого замерена на живом трафике:
    /// потребитель лечит цель, помечая её адреса, а к первому пакету разговора известен только
    /// адрес — имя приходит позже, когда путь уже выбран. Значит лечение доезжает до человека
    /// только когда помечены ВСЕ адреса имени. `discord.com` отдаёт в одном ответе пять адресов,
    /// потребитель видел один: 1–2 удачных захода из 8 при потолке 8 из 8. У имён с одним адресом
    /// в ответе — 6–8 из 8. Разрыв шёл ровно по числу потерянных адресов.
    Honest { name: String, addrs: Vec<[u8; 4]> },
    /// Публичное имя разрешилось в ЧАСТНЫЙ адрес — так выглядит увод на заглушку (и наша земля
    /// `dns_spoof`).
    ///
    /// Два списка, а не один, и не четвёртая клетка: предмет ОДИН («чем разрешилось имя»), а
    /// деление внутри него. Ответ, где частный адрес приписан к настоящим, встречается —
    /// объяви мы его просто уводом, потеряли бы настоящие адреса, то есть чинили бы потерю
    /// потерей. `to` — куда увели, `alongside` — что в том же ответе выглядит настоящим.
    Hijacked {
        name: String,
        to: Vec<[u8; 4]>,
        alongside: Vec<[u8; 4]>,
    },
    /// Имя не разрешилось: клиент останется без цели. Дорог сюда ДВЕ, и они разной силы —
    /// потому способ назван в слове, а не потерян (см. [`Erasure`]).
    Erased { name: String, how: Erasure },
}

/// КАК имя перестало разрешаться. Не `bool` и не потерянная подробность: две дороги к одному
/// последствию имеют РАЗНУЮ силу улики, и продукт судит по ней.
///
/// Пустой ответ уликой вмешательства не является вовсе: имя без записи `A` бывает честным (только
/// `AAAA`, только `MX`), и прибор здесь говорит «цели нет», а не «цель отняли». Отказ с присвоенной
/// авторитетностью — улика: рекурсор не хозяин чужой зоны и так не отвечает.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Erasure {
    /// Ответ пришёл, записи `A` в нём нет.
    NoAddress,
    /// «Имени не существует», сказанное от имени хозяина зоны, которым отвечающий не является.
    Denied,
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

        // ИМЕНИ НЕ СУЩЕСТВУЕТ — беда ровно тогда, когда отвечающий ПРИСВОИЛ СЕБЕ АВТОРИТЕТНОСТЬ.
        //
        // Поиск по суффиксам (`resolv.conf search`) получает `NXDOMAIN` законно и на каждое имя по
        // разу: `rutracker.org.lan`, `rutracker.org.местный-домен` — имён этих нет, и рекурсор так
        // и говорит, БЕЗ `aa`: он не хозяин чужой зоны и хозяином не притворяется. Подделка на пути
        // обязана выглядеть окончательным ответом, иначе клиент пойдёт спрашивать дальше, — и
        // ставит `aa`, присваивая авторитетность, которой у отвечающего нет. Один бит и делит.
        //
        // Стирание названо словом `Erased`, а не своей клеткой: для человека это ТО ЖЕ САМОЕ —
        // ответ пришёл, цели в нём нет, разговор не начнётся. Различие способа (пустой ответ
        // против отказа) лечения не меняет, а буква под одно сочетание удвоила бы алфавит.
        // Внутреннее имя судится честным ЦЕЛИКОМ — тот же закон, что ниже для частных адресов:
        // резолвер организации ДЕЙСТВИТЕЛЬНО хозяин своей зоны и отказывает в ней по праву.
        match (message.rcode, message.authoritative && !internal_name(&name)) {
            (NXDOMAIN, true) => {
                return Some(Resolved::Erased {
                    name,
                    how: Erasure::Denied,
                })
            }
            (NXDOMAIN, false) => return None,
            (_answered, _) => (),
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

        if addresses.is_empty() {
            // Ответ без адреса — цели нет, но вмешательства это ещё не доказывает.
            return Some(Resolved::Erased {
                name,
                how: Erasure::NoAddress,
            });
        }
        // Частные адреса ищутся по ВСЕМУ ответу, а не по первому: увод, приписанный вторым
        // адресом, первым не виден вовсе — а увидеть его надо, порядок записей в ответе никем не
        // обещан. Внутреннее имя судится честным целиком: split-horizon законно отдаёт частное.
        let (to, alongside): (Vec<[u8; 4]>, Vec<[u8; 4]>) = match internal_name(&name) {
            true => (Vec::new(), addresses),
            false => addresses.into_iter().partition(|addr| private(*addr)),
        };
        match to.is_empty() {
            true => Some(Resolved::Honest {
                name,
                addrs: alongside,
            }),
            false => Some(Resolved::Hijacked {
                name,
                to,
                alongside,
            }),
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
        "АВТОРИТЕТНОСТЬ — УЛИКА, А НЕ ДОКАЗАТЕЛЬСТВО. Спросивший авторитетный сервер НАПРЯМУЮ \
         (`dig @ns1.зоны`) законно получает `aa` на несуществующее имя, и прибор объявит стирание. \
         Внутренние зоны выведены списком суффиксов, а список неполон по построению: split-horizon \
         делает внутренним любое имя. Цена выбрана сознательно — обратное (молчать на всякий \
         `NXDOMAIN`) не видит стирания ВООБЩЕ, а именно им клиента и держат вне сети.",
        "ПУСТОЙ ОТВЕТ ВМЕШАТЕЛЬСТВА НЕ ДОКАЗЫВАЕТ. Имя, у которого есть только `AAAA` или только \
         `MX`, честно отвечает `NOERROR` без записей `A`. Прибор говорит `Erasure::NoAddress` — \
         «цели нет», и это правда; читать это как «цель отняли» нельзя, и слово именно поэтому \
         несёт способ.",
        "УВОД НА ПУБЛИЧНЫЙ АДРЕС НЕ ЛОВИТСЯ. Признак увода — частный адрес у публичного имени, а \
         реальный перехват уводит на подставной резолвер, который ПУБЛИЧЕН. В положительном ответе \
         присвоенная авторитетность не смотрится: у домашних форвардеров она встречается и без \
         вмешательства, а цена ложного обвинения выше цены пропуска.",
        "ЧАСТНЫЙ АДРЕС БЫВАЕТ ЗАКОННЫМ. Внутренние имена компании, `*.local`, split-horizon DNS — \
         всё это честно разрешается в 10/8 и 192.168/16. Прибор объявит подмену, и будет неправ; \
         различает их только знание о том, чьё это имя, а такого знания у него нет.",
        "ОТВЕТ ОТ НЕ ТОГО РЕЗОЛВЕРА НЕ ПРОВЕРЯЕТСЯ. Классическая подмена приходит от адреса, \
         которого клиент не спрашивал, — здесь это не смотрится вовсе: прибор судит содержимое, \
         а не отправителя.",
    ];

    const ORACLES: &'static [&'static str] = &["dns_spoof(rutracker.org,10.77.0.99)", "udp_dns"];

    const DEATH: &'static str =
        "прибор видит увод на ПУБЛИЧНЫЙ адрес: улика увода перестала быть частностью адреса";

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
            | Resolved::Erased { name, .. } => name.clone(),
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
            Resolved::Honest { addrs, .. } => listed(addrs),
            // Настоящие адреса называются рядом с уводом, а не прячутся: человеку, читающему
            // отчёт, нужно знать, осталось ли имя достижимым помимо заглушки.
            Resolved::Hijacked { to, alongside, .. } => match alongside.is_empty() {
                true => format!("уведён на {}", listed(to)),
                false => format!("уведён на {}, рядом настоящие {}", listed(to), listed(alongside)),
            },
            // Сила улики названа человеку прямо: одно дело «в ответе нет адреса», другое —
            // «отказано от имени хозяина зоны, которым отвечающий не является».
            Resolved::Erased { how, .. } => match how {
                Erasure::NoAddress => "адреса нет в ответе".to_string(),
                Erasure::Denied => "отказ с присвоенной авторитетностью".to_string(),
            },
        }
    }
}

/// Адреса человеку — через запятую. Отдельной функцией, а не выражением в ветке: печать адреса
/// живёт в одном месте, иначе два способа разошлись бы в нуле ведущих байт.
fn listed(addrs: &[[u8; 4]]) -> String {
    addrs
        .iter()
        .map(|a| format!("{}.{}.{}.{}", a[0], a[1], a[2], a[3]))
        .collect::<Vec<String>>()
        .join(", ")
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
            authoritative: false,
            queries: vec![DnsQuery {
                name: "rutracker.org".to_string(),
                qtype,
                qclass: 1,
            }],
            answers,
        }
    }

    /// Ответ, ОБЪЯВИВШИЙ СЕБЯ АВТОРИТЕТНЫМ, — та же почта, но с печатью «я тут хозяин».
    fn claiming_authority(message: DnsMessage) -> DnsMessage {
        DnsMessage {
            authoritative: true,
            ..message
        }
    }

    /// Отказ на ИМЕННОЕ имя, с присвоенной авторитетностью.
    fn denial_for(name: &str) -> DnsMessage {
        let mut message = claiming_authority(answer(1, NXDOMAIN, Vec::new()));
        message.queries[0].name = name.to_string();
        message
    }

    /// Внутреннее имя судится честным ЦЕЛИКОМ — тот же закон, что и для частных адресов, и здесь
    /// он нужен второй раз: резолвер организации ДЕЙСТВИТЕЛЬНО хозяин своей зоны и на несущест-
    /// вующее внутреннее имя ставит `aa` по праву. Обвинить его значило бы объявить подделкой
    /// каждую опечатку во внутреннем имени.
    #[test]
    fn хозяин_своей_зоны_отказывает_по_праву() {
        assert_eq!(
            ResolutionInstrument.read(&denial_for("printer.lan"), 0),
            None,
            "внутреннюю зону резолвер держит сам, и отказ в ней — его право"
        );
    }

    /// ПРЕДМЕТ: имя СТЁРТО на пути. Рекурсор не авторитетен для чужой зоны и `aa` не ставит;
    /// подделка ставит, имитируя хозяина зоны, — и этим единственным битом себя выдаёт.
    ///
    /// Замер потребителя: `dig rutracker.org @<резолвер> → NXDOMAIN`, за весь день прибор не
    /// сказал НИ СЛОВА. Клиент до транспорта не доходит вовсе, потому и транспортным приборам
    /// сказать нечего: разговора нет. Человек видит «сайта не существует», продукт молчит.
    #[test]
    fn стёртое_имя_выдаёт_себя_присвоенной_авторитетностью() {
        let denied = claiming_authority(answer(1, NXDOMAIN, Vec::new()));

        assert_eq!(
            ResolutionInstrument.read(&denied, 0),
            Some(Resolved::Erased {
                name: "rutracker.org".to_string(),
                how: Erasure::Denied,
            }),
            "NXDOMAIN с присвоенной авторитетностью — стирание имени, а не его отсутствие"
        );
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

    /// ПРЕДМЕТ: ответ доезжает ЦЕЛИКОМ. Прежде прибор брал первый адрес и терял остальные молча.
    ///
    /// Цена замерена потребителем на живом трафике: он лечит цель, помечая её адреса, а к первому
    /// пакету разговора известен только адрес — имя приходит позже, когда путь уже выбран. Значит
    /// лечение доезжает до человека, только когда помечены ВСЕ адреса имени. Имя с пятью адресами
    /// давало 1–2 удачных захода из восьми при потолке восемь из восьми; имена с одним адресом —
    /// шесть-восемь. Разрыв шёл ровно по числу потерянных адресов.
    #[test]
    fn весь_ответ_доезжает_а_не_первый_адрес() {
        let five = vec![
            a_record([1, 1, 1, 1]),
            a_record([2, 2, 2, 2]),
            a_record([3, 3, 3, 3]),
            a_record([4, 4, 4, 4]),
            a_record([5, 5, 5, 5]),
        ];

        match ResolutionInstrument.read(&answer(1, 0, five), 0) {
            Some(Resolved::Honest { addrs, .. }) => assert_eq!(
                addrs,
                vec![[1, 1, 1, 1], [2, 2, 2, 2], [3, 3, 3, 3], [4, 4, 4, 4], [5, 5, 5, 5]],
                "все пять адресов ответа, и в порядке ответа"
            ),
            other => panic!("честный ответ обязан назвать все адреса, а вышло {other:?}"),
        }
    }

    /// ВТОРОЙ ДЕФЕКТ, НАЙДЕННЫЙ ТЕМ ЖЕ: увод, приписанный НЕ ПЕРВЫМ адресом, прибор не видел вовсе.
    /// Порядок записей в ответе не обещан никем, и censor, дописавший заглушку второй, проходил
    /// мимо — прибор объявлял ответ честным.
    #[test]
    fn увод_вторым_адресом_виден_так_же_как_первым() {
        let sneaky = vec![a_record([93, 184, 216, 34]), a_record([10, 0, 0, 1])];

        match ResolutionInstrument.read(&answer(1, 0, sneaky), 0) {
            Some(Resolved::Hijacked { to, alongside, .. }) => {
                assert_eq!(to, vec![[10, 0, 0, 1]], "частный адрес назван уводом");
                assert_eq!(
                    alongside,
                    vec![[93, 184, 216, 34]],
                    "а настоящий — не потерян: чинить потерю потерей нельзя"
                );
            }
            other => panic!("увод вторым адресом обязан быть виден, а вышло {other:?}"),
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
    /// Вторая половина пары к [`стёртое_имя_выдаёт_себя_присвоенной_авторитетностью`]: честный
    /// `NXDOMAIN` приходит БЕЗ `aa`, и прибор обязан молчать. Поиск по суффиксам получает его на
    /// каждое имя по разу — прибор, кричащий на всякое «нет такого имени», был бы шумом. Без этой
    /// половины правило зелено и на приборе, который объявляет бедой любой отказ.
    fn a_name_that_does_not_exist_is_not_trouble() {
        let said = crate::says(ResolutionInstrument, answer(1, 3, vec![]));

        assert_eq!(said.as_slice(), &[]);
    }

    /// Ответ есть, адреса нет — цели у клиента не будет. Способ назван СЛАБЫМ: имя с одними
    /// `AAAA` отвечает так же честно, и обвинять тут некого.
    #[test]
    fn an_answer_without_an_address_is_an_erasure() {
        let said = crate::says(ResolutionInstrument, answer(1, 0, vec![]));

        assert_eq!(
            said.as_slice(),
            &[Resolved::Erased {
                name: "rutracker.org".to_string(),
                how: Erasure::NoAddress,
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
