//! Строка (цель × узел) — закон сборки. Одна запись, читаемая и решением, и показом: второй путь к
//! правде (ключ, добываемый на каждой стороне своим способом) дал 1136 флоу из 1136 мимо памяти.
//! Крейт `no_std` без `alloc`; имя входит параметром типа — закон группировки знает лишь, назвалась
//! ли цель, ширину и представление подставляет оболочка (`narrow: fn(&str) -> &str`).

use crate::{Addr, Cursor, Plan, Said, Span, Tick};

/// Слепота — расхождение двух счётов (§10). Закон описывает всякий перехватывающий движок (очередь
/// ядра, кольцо `AF_PACKET`, WinDivert теряют по-своему), потому живёт в фундаменте; здесь — реэкспорт.
pub use reflex_core::sight::{
    added, later, no_counts, sighted, sooner, told, Counted, Sight, Told,
};

/// Сказала ли цель, кто она (§5, полурешётка `Awaited ⊑ Silent ⊑ Spoken`). Псевдоним
/// [`reflex_core::disclosure::Disclosed`]: порядок и три его закона — форма всякого сведения из
/// разговора (шифр, версия, id соединения), а не свойство имени. `Spoken` — имя из `ClientHello`
/// этого разговора; `Silent` — приветствие прошло без имени (не-TLS, IP, MTProto, ECH, битый SNI);
/// `Awaited` — о личности не сказано ничего (третье слово — знаменатель слепой зоны именного ключа).
/// Знание растёт join'ом, снимок «на чём стоял план» замерзает в `stood_on`.
pub type Naming<N> = reflex_core::disclosure::Disclosed<N>;

/// Чем ключуется цель (§4, слой расслоения). Тип один, применения расходятся ШИРИНОЙ безымянной
/// ветви: строке нужна сеть (человек видит `91.108.56.0/24` одной целью), действию — точный адрес
/// (лечить /24 применило бы знание к 256 хозяевам). Ширина приходит снаружи (`net_of`/`host_of`),
/// как `narrow` для имён: один тип с названной проекцией ловит расхождение компилятором.
pub use reflex_core::word::TargetKey;

/// Что остаётся от разговора, когда он закрылся. Два поля, не одно: слепота считается расхождением
/// счётов (`sighted(kernel, plane)`), а счёт плоскости у завершённого разговора обнулялся вместе с
/// `Run` — и `told(…, Partial)` перекрывал сохранённый ответ (`Blind`). Сохраняется ровно то, что
/// делает разговор знакомым: сколько видели и ответила ли цель.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Closed {
    pub answered: Answered,
    /// Счёт плоскости на момент закрытия — второй оракул слепоты.
    pub counted: Counted,
}

/// Ответила ли цель, и через сколько от начала. Про наблюдённое плоскостью: «не ответила» = «не
/// видели ответа». Отличить от «ответила, а мы ослепли» — работа `Told`, снаружи: шаг о своей
/// слепоте не знает по построению.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Answered {
    NotYet,
    After(Span),
}

/// Наблюдение шага — в клетку строки, где слепота выразима (§7).
pub fn answering(answered: Answered, sight: Sight) -> Told<Span> {
    match answered {
        Answered::After(span) => told(Told::Told(span), sight),
        Answered::NotYet => told(Told::Nothing, sight),
    }
}

/// Ширина записи: /24. Единственная честная единица накопления для коннекта по IP — у такой цели
/// нет ничего, кроме адреса, а соседние адреса одного хозяина ведут себя одинаково.
pub fn net_of(dst: Addr) -> Addr {
    Addr(dst.0 & 0xFF_FF_FF_00)
}

/// Ширина действия: точный адрес. Лечить сеть нельзя — знание применилось бы к чужим хозяевам.
pub fn host_of(dst: Addr) -> Addr {
    dst
}

/// Проекция наблюдения в ключ — тотальная и названная (§4). Наблюдение трёхчленно (различать
/// обязано), ключ двухчленен (сходиться обязан: в момент действия имя либо есть, либо нет). Разная
/// арность слоёв законна ровно при условии, что переход между ними — одна функция.
pub fn keyed<N>(naming: Naming<N>, dst: Addr, width: fn(Addr) -> Addr) -> TargetKey<N> {
    match naming {
        Naming::Spoken(name) => TargetKey::Named(name),
        Naming::Silent | Naming::Awaited => TargetKey::Unnamed(width(dst)),
    }
}

/// Ответила ли цель, и через сколько — в единице, у которой слепота выразима.
pub type Spoke = Told<Span>;

/// Что плоскость знает о разговоре, который ядро уже нашло. `Never` — не пограничный случай, а
/// обычный: через очередь идёт не всё. Слить с `Lost` (курсор был и вытеснен) значило бы выдать
/// нашу уборку за чужой трафик.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Watched {
    Never,
    Seen {
        plan: Plan,
        /// На чём стоит нога — читается прямо из личности: план принят ⟺ она известна (`Spoken`
        /// либо `Silent`). Отдельный `Standing` снят разбором алгебры (#300) как вторая ось,
        /// державшая незаконные клетки представимыми.
        naming: Said,
        counted: Counted,
        answered: Answered,
    },
    /// Разговор закрылся штатно: состояния нет, но оно и не терялось. Ответ цели переживает
    /// закрытие — без него завершённый разговор приходил слепым (83 цели из 86 на полевом прогоне).
    Ended(Closed),
    Lost,
}

/// Узел цели — то, что человек видит подстрокой. Личности здесь нет, и это проверено (#320): поле
/// `Named(k)` тождественно ключу строки, `Unnamed(net)` — хуже дубля (`Silent` и `Awaited` дают
/// один ключ, слияние взяло бы первый = порядок conntrack). Цель узла читается из ключа СТРОКИ;
/// понадобится узел отдельно — дешёвая форма это пара `(&TargetKey<N>, &Node)`, не поле (пара не
/// заводит второго перехода через границу арности).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Node {
    pub dst: Addr,
    pub flows: u32,
    /// Счёт ядра: переживает метку, ногу и всякое удешевление горячего пути.
    pub kernel: Counted,
    /// Счёт плоскости: столько мы видели сами.
    pub plane: Counted,
    /// Расхождение двух счётов и есть замеренная слепота.
    pub sight: Sight,
    /// Когда плоскость видела узел в последний раз — второй род слепоты, которого `Sight` не ловит:
    /// счета сошлись, а наблюдения прекратились (живая строка и застывшая перестают выглядеть
    /// одинаково). `Blind` — не видели вовсе; `Nothing` — видели, момент не сохранён (§7).
    pub plane_seen: Told<Tick>,
    pub watched: Watched,
    pub spoke: Told<Span>,
}

/// Что плоскость знает о разговоре — из её курсора, и только из него. Тип и закон живут здесь (не у
/// добычи счёта ядра, netfilter): standalone-показ собирается и поверяется на машине без conntrack
/// (#320, Т4). Половина предмета, доступная одной ОС, есть случайность истории, не граница слоя.
pub fn watched_of(cursor: Cursor) -> Watched {
    match cursor {
        Cursor::Fresh => Watched::Never,
        Cursor::Ended(closed) => Watched::Ended(closed),
        Cursor::Lost => Watched::Lost,
        Cursor::Running(run) => Watched::Seen {
            plan: run.plan,
            naming: run.naming,
            counted: Counted {
                up: run.up as u64,
                up_bytes: run.up_bytes,
                down: run.down as u64,
                down_bytes: run.down_bytes,
            },
            answered: run.answered,
        },
    }
}

/// Узел из двух счётов. Чистая часть сборки: откуда счёт ядра — здесь не спрашивается, потому узел
/// собирается и там, где ядра нет. Личность приходит снаружи (её знает плоскость, не запись ядра).
pub fn node_of(dst: Addr, kernel: Counted, cursor: Cursor, seen: Option<Tick>) -> Node {
    let watched = watched_of(cursor);
    let plane = match watched {
        Watched::Seen { counted, .. } => counted,
        // Счёт завершённого разговора переживает его: обнули — и `sighted` объявит слепотой
        // разницу с ядром, а сохранённый ответ окажется перекрыт (`Blind`).
        Watched::Ended(closed) => closed.counted,
        Watched::Never | Watched::Lost => no_counts(),
    };
    let sight = sighted(kernel, plane);
    Node {
        dst,
        flows: 1,
        kernel,
        plane,
        sight,
        // Момента нет у того, кого не видели: `Never` значит «через очередь не шёл» — «наблюдений
        // не было» было бы правдой о ЦЕЛИ вместо правды о НАС.
        plane_seen: match (watched, seen) {
            (Watched::Never, _) => Told::Blind,
            (_, Some(at)) => Told::Told(at),
            (_, None) => Told::Nothing,
        },
        watched,
        spoke: match watched {
            Watched::Seen { answered, .. } => answering(answered, sight),
            // Завершённый разговор не слеп: видели целиком, ответ пережил закрытие.
            Watched::Ended(closed) => answering(closed.answered, sight),
            // Не видели вовсе либо забыли — про ответ сказать нечего, и это слепота, не молчание.
            Watched::Never | Watched::Lost => Told::Blind,
        },
    }
}

/// Слияние двух узлов одной цели. Ни одно поле не зависит от порядка — требование, не свойство:
/// узлы приходят в порядке записей conntrack (произвольном), и всякое «у первого» молча становится
/// выборкой из мультимножества (так погибло поле личности, #320). Счета складываются, ответ ранний
/// (`sooner`), наблюдение позднее (`later`) — все три коммутативны.
pub fn merged(into: Node, plus: Node) -> Node {
    let kernel = added(into.kernel, plus.kernel);
    let plane = added(into.plane, plus.plane);
    Node {
        dst: into.dst,
        // Видели — значит позже из двух: узел жив, если жив хоть один разговор.
        plane_seen: later(into.plane_seen, plus.plane_seen),
        flows: into.flows + plus.flows,
        kernel,
        plane,
        sight: sighted(kernel, plane),
        watched: match (into.watched, plus.watched) {
            (Watched::Never, held) => held,
            (held, _other) => held,
        },
        spoke: sooner(into.spoke, plus.spoke),
    }
}

/// Паспорт слепоты — свидетель предъявимости (§10). Единственный прибор, чей предмет — МЫ САМИ в
/// момент наблюдения: не «что с целью», а «имеем ли право говорить о цели». Третье состояние `Told`
/// и есть весь смысл (§7): у зрячей плоскости «ничего не приходило» — факт о ЦЕЛИ, у ослепшей — о НАС.
pub struct BlindnessInstrument;

impl BlindnessInstrument {
    fn read(&self, sight: &Sight, _now_ms: u64) -> Told<()> {
        match sight {
            Sight::Full => Told::Nothing,
            Sight::Partial { .. } => Told::Blind,
        }
    }
}

impl reflex_core::mealy::Mealy for BlindnessInstrument {
    type In = reflex_core::DetectorEvent<Sight>;

    /// Слово `()` (`Nobody`): суждение о НАШЕМ праве судить области не имеет — ни пакет, ни разговор,
    /// ни цель его не ждут. Адресуется суждение, а не пустая начинка, в которую завёрнуто.
    type Out = ();

    /// Показание. Отсутствие показания сигналом не является — прибор высказывается, когда есть что.
    type Log = smallvec::SmallVec<[Told<()>; 2]>;

    fn step(self, event: Self::In) -> (Self, (), Self::Log) {
        match event {
            reflex_core::DetectorEvent::Packet { input, .. } => {
                let reading = self.read(&input, 0);
                (self, (), smallvec::smallvec![reading])
            }
            reflex_core::DetectorEvent::Tick { .. } => (self, (), smallvec::SmallVec::new()),
            reflex_core::DetectorEvent::Opaque { .. } => (self, (), smallvec::SmallVec::new()),
            // Слепота этого прибора — про `Sight`, уже посчитанный сравнением ядра и плоскости
            // (`sighted` в свёртке строки); дыра в ЭТОМ потоке событий такого сравнения не несёт и
            // не подменяет его — прибор остаётся немым, как на тике.
            reflex_core::DetectorEvent::Torn { .. } => (self, (), smallvec::SmallVec::new()),
        }
    }
}

impl reflex_instrument::Instrument for BlindnessInstrument {
    type Signal = Told<()>;

    const INSTRUMENT: &'static str = "blindness";

    const SUBJECT: reflex_instrument::Subject = reflex_instrument::Subject::Ourselves;

    /// Уровень: видим ли поток вообще — вопрос транспортной видимости, не содержимого.
    const LAYER: reflex_instrument::Layer = reflex_instrument::Layer::Transport;
    /// Транспорты: предмет — видим ли поток вообще, а поток есть у обоих.
    const PROTOCOLS: &'static [reflex_instrument::Protocol] = &[
        reflex_instrument::Protocol::Tcp,
        reflex_instrument::Protocol::Udp,
    ];
    const RUNG: Option<reflex_instrument::Rung> = None;

    /// Пакет: полнота считается по ходу разговора, из счётчиков ядра.
    const CADENCE: reflex_instrument::Cadence = reflex_instrument::Cadence::Foreign;

    /// Состояние: у полноты есть равенство, переход «зрячи → ослепли» осмыслен.
    const SHAPE: reflex_instrument::Shape = reflex_instrument::Shape::State;

    /// Клетка молчания всего парка: `Blind` — не отсутствие показания, а показание об отсутствии
    /// права. Слить с `Nothing` значило бы дать прочитать «цель молчит» там, где молчим МЫ.
    const SILENCE: Option<reflex_instrument::Silence> = Some(reflex_instrument::Silence::Blind);

    const LIES: &'static [&'static str] = &[
        "ПОСТРОЕН И НЕ ПОДКЛЮЧЁН. Единственный читатель — `dataplane-nfq::record`, который сам не \
         стоит на пути байтов; вес по живым бинарям равен единице и получен ОТ МЁРТВОГО ЧИТАТЕЛЯ. \
         То есть прибор, назначенный охранять честность всех остальных, сегодня не охраняет \
         никого.",
        "ПОЛНОТА СЧИТАЕТСЯ ПО НАШИМ СЧЁТЧИКАМ, А НЕ ПО ЧУЖИМ. Пакет, не дошедший до очереди вовсе \
         (правила стоят на `output`/`input`, транзитный трафик идёт через `forward`), в `missed` \
         не попадает: слепота такого рода прибору невидима — он видит только то, что потерял \
         ПОСЛЕ того, как получил.",
    ];

    const ORACLES: &'static [&'static str] = &["pass", "throttle(250kbit,6%)"];

    /// Смерть: `record` встал на путь байтов — прибор получает живого читателя, первый режим лжи
    /// умирает.
    const DEATH: &'static str = "`record` на пути байтов; у слепоты появился живой читатель";

    /// Публичные имена событий — реестр, снятый с типа: за границей процесса имя показания
    /// компилятор не сторожит, и `Debug` сменил бы метку молча.
    const EVENTS: &'static [&'static str] = &["blindness"];

    fn name(signal: &Self::Signal) -> &'static str {
        let _ = signal;
        "blindness"
    }

    fn alarming(signal: &Self::Signal) -> bool {
        let _ = signal;
        true
    }
}

/// Тип строки читается без netfilter (#320, Т4). Проверка живёт в `dataplane`: крейт `no_std` без
/// `reflex-linux` и conntrack — уедь тип или закон обратно к добыче, файл перестанет компилироваться.
#[cfg(test)]
mod row_needs_no_kernel_tests {
    use super::*;
    use crate::{Basis, Epoch, Interest, Programme, Run};

    fn counted(up: u64, down: u64) -> Counted {
        Counted {
            up,
            up_bytes: up * 100,
            down,
            down_bytes: down * 100,
        }
    }

    fn running(up: u16, down: u16) -> Cursor {
        Cursor::Running(Run {
            plan: Plan {
                programme: Programme::Pass,
                epoch: Epoch(1),
                basis: Basis::Seeded,
                interest: Interest::Idle,
            },
            naming: Naming::Spoken(()),
            up,
            down,
            up_bytes: up as u64 * 100,
            down_bytes: down as u64 * 100,
            began: crate::Tick(0),
            last_up: crate::Tick(0),
            last_down: crate::Tick(0),
            answered: Answered::After(Span(30)),
            announced: crate::Announced::Never,
            ordered: crate::Ordered::Nothing,
        })
    }

    /// Узел собирается из двух счётов, счёт ядра приходит значением, не из conntrack.
    #[test]
    fn a_node_is_built_from_two_counts_without_asking_the_kernel() {
        let node = node_of(
            Addr(0x0A00_0001),
            counted(10, 10),
            running(10, 10),
            Some(Tick(1_000)),
        );
        assert_eq!(node.flows, 1);
        assert_eq!(
            node.sight,
            Sight::Full,
            "счета сошлись, а слепота объявлена"
        );
        assert!(
            matches!(node.watched, Watched::Seen { .. }),
            "разговор виден плоскостью, а узел говорит обратное"
        );
    }

    /// Расхождение счётов есть замеренная слепота, не ошибка округления. Пара к предыдущему: без неё
    /// тест зеленел бы у сборки, всегда объявляющей `Full`.
    #[test]
    fn counts_that_disagree_are_measured_blindness() {
        let node = node_of(
            Addr(0x0A00_0001),
            counted(100, 100),
            running(10, 10),
            Some(Tick(1_000)),
        );
        assert_ne!(
            node.sight,
            Sight::Full,
            "ядро видело вдесятеро больше плоскости, а узел объявил себя зрячим"
        );
    }

    /// Разговор, до очереди не дошедший, — не потерянный. `Never` и `Lost` различаются лечением:
    /// первое — «через очередь идёт не всё», второе — «наша уборка вытеснила курсор».
    #[test]
    fn a_conversation_that_never_reached_the_queue_is_not_a_lost_one() {
        let never = node_of(
            Addr(0x0A00_0001),
            counted(5, 5),
            Cursor::Fresh,
            Some(Tick(1_000)),
        );
        let lost = node_of(
            Addr(0x0A00_0001),
            counted(5, 5),
            Cursor::Lost,
            Some(Tick(1_000)),
        );
        assert_eq!(never.watched, Watched::Never);
        assert_eq!(lost.watched, Watched::Lost);
        assert_eq!(
            never.spoke,
            Told::Blind,
            "о цели, которой мы не видели, сказано как о молчащей"
        );
    }

    /// Слияние не зависит от порядка — требование, не наблюдение. Поле «у первого» молча становится
    /// выборкой из мультимножества (так погибло поле личности, #320); проверка красит следующее.
    #[test]
    fn merging_does_not_depend_on_the_order_the_kernel_listed_them() {
        let early = node_of(
            Addr(0x0A00_0001),
            counted(3, 3),
            running(3, 3),
            Some(Tick(1_000)),
        );
        let late = node_of(
            Addr(0x0A00_0001),
            counted(7, 7),
            running(7, 7),
            Some(Tick(9_000)),
        );

        let one = merged(early.clone(), late.clone());
        let other = merged(late, early);

        // Всё коммутативное перечислено поимённо, а не сравнением узлов целиком: одно поле сегодня
        // выборкой ЯВЛЯЕТСЯ (см. TODO ниже).
        assert_eq!(
            (
                one.flows,
                one.kernel,
                one.plane,
                one.sight,
                one.plane_seen,
                one.spoke
            ),
            (
                other.flows,
                other.kernel,
                other.plane,
                other.sight,
                other.plane_seen,
                other.spoke
            ),
            "слияние зависит от очерёдности записей ядра — поле стало выборкой"
        );

        // TODO(#320): `watched` — ВЫБОРКА, а не свойство узла. Узел агрегирует разговоры, `Watched`
        // описывает один: при двух наблюдавшихся берётся первый по conntrack. Лечится агрегатом
        // вместо образца либо снятием поля в пользу счётчиков по личности — выбор за постановкой.
        assert_ne!(
            one.watched, other.watched,
            "выборка перестала быть выборкой — снять `TODO(#320)` и сравнивать узлы целиком"
        );
    }

    /// Наблюдение позднее, ответ ранний — не симметрия ради симметрии. Узел жив, если жив хоть один
    /// разговор (ранний момент объявил бы цель застывшей); цель ответила, если ответила хоть раз.
    #[test]
    fn the_node_is_seen_as_late_as_its_liveliest_conversation() {
        assert_eq!(
            later(Told::Told(Tick(1_000)), Told::Told(Tick(9_000))),
            Told::Told(Tick(9_000)),
            "узел объявлен застывшим по самому старому разговору"
        );
        assert_eq!(
            later(Told::Blind, Told::Told(Tick(9_000))),
            Told::Told(Tick(9_000)),
            "слепота одного разговора ослепила узел, который видели"
        );
    }

    /// Разговор, до очереди не дошедший, момента не имеет — и это `Blind`, не «давно». Второй род
    /// слепоты, которого `Sight` не ловит: счета сошлись, а наблюдений не было.
    #[test]
    fn a_node_the_plane_never_watched_has_no_moment_at_all() {
        let never = node_of(
            Addr(0x0A00_0001),
            counted(5, 5),
            Cursor::Fresh,
            Some(Tick(1_000)),
        );
        assert_eq!(
            never.plane_seen,
            Told::Blind,
            "узлу, которого плоскость не видела, приписан момент наблюдения"
        );
    }

    /// Ответ цели берётся самый ранний: она ответила, если ответила хоть одному разговору.
    #[test]
    fn merging_nodes_keeps_the_earliest_answer() {
        assert_eq!(
            sooner(Told::Told(Span(70)), Told::Told(Span(30))),
            Told::Told(Span(30)),
            "слияние взяло поздний ответ — цель выглядит медленнее, чем была"
        );
        assert_eq!(
            sooner(Told::Blind, Told::Told(Span(30))),
            Told::Told(Span(30)),
            "слепота одного узла стёрла ответ, который другой узел видел"
        );
    }
}

#[cfg(test)]
mod blindness_passport_tests {
    use super::*;
    use reflex_instrument::Instrument;

    /// Зрячая плоскость и ослепшая дают разное право говорить. Витнес в паре обязателен: прибор,
    /// всегда отвечающий `Blind`, честен и бесполезен.
    #[test]
    fn full_sight_permits_speech_and_partial_forbids_it() {
        assert_eq!(BlindnessInstrument.read(&Sight::Full, 0), Told::Nothing);
        assert_eq!(
            BlindnessInstrument.read(
                &Sight::Partial {
                    missed_up: 3,
                    missed_down: 0
                },
                0
            ),
            Told::Blind
        );
    }

    /// Прибор — клетка молчания парка, и его собственная клетка обязана быть `Blind`.
    #[test]
    fn the_blindness_passport_calls_itself_blind() {
        assert_eq!(
            BlindnessInstrument::SILENCE,
            Some(reflex_instrument::Silence::Blind)
        );
        assert!(BlindnessInstrument::LIES
            .iter()
            .any(|lie| lie.contains("НЕ ПОДКЛЮЧЁН")));
    }
}
