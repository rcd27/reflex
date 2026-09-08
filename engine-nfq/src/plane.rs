use std::collections::{BTreeMap, BTreeSet, HashMap};

use reflex_core::mealy::{Mealy, MealyExt, Pair};
use reflex_engine::meter::{
    applied, charge, charged_target, empty_ring, expired, fresh_target, horizon, Counting, Pace,
    Pressure, Ring, Tally, Target,
};
use reflex_engine::row::{host_of, keyed, Naming, TargetKey};
use reflex_engine::step::{sever, Advancing};
use reflex_engine::watch::{watched, Watch};
use reflex_engine::{
    About, Act, Addr, Basis, Cursor, Dir, Epoch, FlowKey, Interest, Lost, Noted, Noticed, Packet,
    Plan, Programme, Said, Sighting, Tick,
};

/// Ключ цели, как его видит плоскость: имя сужено `narrow`, безымянная ветвь — ТОЧНЫЙ адрес
/// (`host_of`), не сеть. Ширина здесь у ДЕЙСТВИЯ: лечить /24 применило бы знание к 256 хозяевам.
/// Запись строки человеку берёт ту же алгебру с другой шириной (`net_of`), расхождение ловит компилятор.
type Key = TargetKey<Box<str>>;

use crate::parse::{Datagram, Head, Wire};
use crate::talk::{Named, Talks};
use reflex_instrument::wire::Reading;

pub const CURSORS: usize = 8192;
pub const TARGETS: usize = 4096;
pub const SIGHTINGS: usize = 4096;
const SWEEP_EVERY: u64 = 4096;
/// Сколько записей уборка смотрит за раз. Без потолка она обходила карту целиком — работу,
/// пропорциональную числу целей, амортизированно на каждый пакет.
pub const SWEEP_BUDGET: usize = 256;
/// Эпоха цели, о которой движок ещё не учил. Строго ниже всякой настоящей (`teach` начинает с
/// первой). Промах несёт её, а не живой счётчик: разговор, промахнувшийся в окне между сдвигом эпохи
/// и вписью плана, иначе унёс бы эпоху настоящего плана и остался бы «свежим» на мёртвом маршруте.
const NO_KNOWLEDGE: Epoch = Epoch(0);

/// Сколько горизонтов помним закрытый разговор. Держится не ради него, а ради ХВОСТА: последний
/// `ACK` и ретрансмиссия приходят после прощания, ответить им «не видели» значило бы соврать про
/// разговор, по которому выносили вердикт. Срок жизни хвоста — свойство транспорта, не частота уборки.
pub const RETENTION_HORIZONS: u64 = 2;

/// Что вышло из одного пакета. `opened` отделяет НОВЫЙ разговор от продолжения: они стоят разного
/// (две вставки в карты против поиска), смешивать значит мерить состав трафика, а не плоскость.
/// `Copy` снят с приходом наблюдения: `SeenTcp` его не имеет (у сброса автор, у имени длина).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fed {
    pub act: Act,
    pub opened: bool,
    /// Что пакет показал — наблюдение в словаре приборов, из ТОГО ЖЕ разбора, что и вердикт (прежде
    /// разбор шёл трижды, две памяти расходились молча — 1136 флоу мимо). `None` — пакет наблюдения
    /// не дал (`ACK`), не то же, что «ничего не случилось» (тишина видна тиком). Протокол назван:
    /// `Option<SeenTcp>` фиксировал бы TCP, датаграмму не положить.
    pub seen: Option<reflex_instrument::wire::Reading>,
    /// Выпускать ли разговор в ядро. Считает плоскость: только она знает все три величины (личность,
    /// вердикт, интерес), оболочке нечего сводить.
    pub watch: Watch,
}

pub struct Plane {
    /// Знание о цели (#317) — ОДНА карта на обе ветви алгебры (#300). Прежде две, между ними
    /// `Option<Box<str>>`, у которого `None` значил «имени не будет» и «имени ещё нет». Именованная
    /// ветвь применяется, когда цель назвалась (не зависит от адреса разговора); безымянная законна
    /// там, где имени не будет.
    plans: BTreeMap<Key, Plan>,
    /// Чем сужается имя до ключа. Снаружи, без умолчания намеренно: ключ на каждой стороне своим
    /// способом расходится молча. Указатель на функцию, не `dyn`: у знания о ширине есть имя.
    narrow: fn(&str) -> &str,
    fallback: Programme,
    epoch: Epoch,
    cursors: HashMap<FlowKey, Cursor>,
    /// Память ради наблюдения — граница клиента и выданные головы. Убирается той же уборкой, что и
    /// курсоры (иначе работа стала бы пропорциональна числу целей). Тот же тип, что у края (#320):
    /// перевод пакета в показание жил здесь, край не мог его взять и написал свой; теперь один.
    talks: Talks,
    seen_at: BTreeMap<FlowKey, Tick>,
    targets: BTreeMap<Addr, Target>,
    ring: Ring,
    tally: Tally,
    sightings: Vec<Noted>,
    dropped_sightings: u64,
    evicted_cursors: u64,
    evicted_targets: u64,
    unapplied: BTreeMap<&'static str, u64>,
    names: BTreeMap<String, u64>,
    /// Что известно о личности цели в этом разговоре. Ключ — ФЛОУ, не адрес: имя из `ClientHello`
    /// принадлежит соединению (на общем адресе CDN каждый разговор носит своё имя). Три состояния
    /// (#300): `Silent` («приветствие без имени») — знаменатель слепой зоны именного ключа, который
    /// #317 требует печатать числом; сводным счётчиком его знать по коробке, а не по разговору.
    flow_names: BTreeMap<FlowKey, Naming<Box<str>>>,
    /// Как зовут цель по этому адресу (#302). Отдельно от `names` (там счётчик имён): здесь
    /// соответствие, без которого беда по адресу не ложится на знание, ключёванное именем. Одна
    /// запись на цель, тот же потолок и вытеснение, что у `targets`.
    named: BTreeMap<Addr, Box<str>>,
    /// Сколько раз по одному адресу говорило другое имя. До счётчика перезапись молчала, частота её
    /// была неизвестна — подсказка врала, и мы не знали как часто. Заведён прежде спора о годности.
    name_collisions: u64,
    /// Сколько раз один разговор назвался двумя разными именами (#300). В полной решётке это ⊤:
    /// чужой split-hello либо наш промах разбора. Типа под ⊤ нет намеренно (частота не замерена,
    /// тип под неизмеренное не снимается). Отличается от `name_collisions`: тот про АДРЕС, этот про
    /// РАЗГОВОР.
    name_conflicts: u64,
    /// Сколько разговоров чем кончились по личности — знаменатель слепой зоны именного ключа.
    /// Счётчики накопительные, не по живым флоу: доля безымянных — свойство потока, не мгновения.
    /// Переход `Silent → Spoken` законен (знание растёт join'ом), разговор ПЕРЕЕЗЖАЕТ — иначе сумма
    /// превысила бы число разговоров.
    flows_spoken: u64,
    flows_silent: u64,
    unnamed_hellos: u64,
    offered: u64,
    unparsed: u64,
    marked: BTreeSet<Addr>,
    /// Сколько пакетов пометили и какой меткой. Множество отвечает «кого», счётчик — «сколько раз»;
    /// без второго «плоскость не пометила» неотличимо от «пометила, а ядро не увело». По меткам, не
    /// одним числом: метки ведут в разные места, сумма по ним не сверяется ни с одним счётчиком ядра.
    marked_packets: BTreeMap<u32, u64>,
    /// С какого места продолжить обход — иначе потолок смотрел бы вечно первые записи, а хвост не
    /// убирался бы никогда.
    sweep_from: FlowKey,
    sweep_from_target: Addr,
    swept: u64,
    sweeps: u64,
    /// Сколько записей осталось за пределами бюджета на последнем проходе.
    backlog: usize,
}

/// Различитель без имени — то, что нужно ядру.
fn said_of(naming: &Naming<Box<str>>) -> Said {
    match naming {
        Naming::Spoken(_) => Naming::Spoken(()),
        Naming::Silent => Naming::Silent,
        Naming::Awaited => Naming::Awaited,
    }
}

impl Plane {
    /// `narrow` — чем имя с провода сужается до ключа (eTLD+1 у продукта, тождество там, где ширину
    /// выбирает вызывающий). Отдельным аргументом: ширина ключа есть ПОЛИТИКА, умолчание завело бы
    /// вторую правду о ней.
    pub fn new(fallback: Programme, narrow: fn(&str) -> &str) -> Plane {
        Plane {
            plans: BTreeMap::new(),
            narrow,
            fallback,
            epoch: NO_KNOWLEDGE,
            cursors: HashMap::with_capacity(CURSORS),
            talks: Talks::new(),
            seen_at: BTreeMap::new(),
            targets: BTreeMap::new(),
            ring: empty_ring(),
            tally: Counting::fresh().0,
            sightings: Vec::with_capacity(SIGHTINGS),
            dropped_sightings: 0,
            evicted_cursors: 0,
            evicted_targets: 0,
            unapplied: BTreeMap::new(),
            names: BTreeMap::new(),
            flow_names: BTreeMap::new(),
            named: BTreeMap::new(),
            name_collisions: 0,
            name_conflicts: 0,
            flows_spoken: 0,
            flows_silent: 0,
            unnamed_hellos: 0,
            offered: 0,
            unparsed: 0,
            marked: BTreeSet::new(),
            marked_packets: BTreeMap::new(),
            sweep_from: FlowKey(0),
            sweep_from_target: Addr(0),
            swept: 0,
            sweeps: 0,
            backlog: 0,
        }
    }

    /// Научить про именованную цель. Имя сужается ТЕМ ЖЕ `narrow`, что и наблюдённое с провода —
    /// иначе движок учил бы под одним ключом, а плоскость искала под другим.
    pub fn teach_name(
        &mut self,
        name: &str,
        programme: Programme,
        basis: Basis,
        interest: Interest,
    ) {
        self.epoch = Epoch(self.epoch.0 + 1);
        self.plans.insert(
            TargetKey::Named((self.narrow)(name).into()),
            Plan {
                programme,
                epoch: self.epoch,
                basis,
                interest,
            },
        );
    }

    /// Научить про безымянную цель — адресом, законно там, где имени не будет: коннект по IP,
    /// MTProto, синтетический засев замера. Для цели с именем тот же вызов применил бы знание ко
    /// всем её соседям по адресу.
    pub fn teach_unnamed(
        &mut self,
        dst: Addr,
        programme: Programme,
        basis: Basis,
        interest: Interest,
    ) {
        self.epoch = Epoch(self.epoch.0 + 1);
        self.plans.insert(
            TargetKey::Unnamed(host_of(dst)),
            Plan {
                programme,
                epoch: self.epoch,
                basis,
                interest,
            },
        );
    }

    /// Цель, о которой не учили. Интереса нет — цена, названная в `WatchedInstrument`: беда на
    /// незнакомой цели видна только до решения о выпуске.
    fn unknown(&self) -> Plan {
        Plan {
            programme: self.fallback,
            epoch: NO_KNOWLEDGE,
            basis: Basis::Default,
            interest: Interest::Idle,
        }
    }

    /// План по ключу — один вход на обе ветви алгебры. Разойдись на два метода — вызывающему снова
    /// пришлось бы ветвиться самому.
    fn plan_by(&self, key: &Key) -> Plan {
        match self.plans.get(key) {
            Some(known) => *known,
            None => self.unknown(),
        }
    }

    pub fn feed(&mut self, wire: Wire<'_>, now: Tick) -> Fed {
        // Личность читается ДО шага: прежде записывалась следом за вердиктом, и `ClientHello`,
        // единственный пакет, которому страта нужна, уходил по плану, взятому на SYN по адресу.
        // Открытие стирает имя прошлого разговора на этой четвёрке (карта ключуется флоу, четвёрка
        // переиспользуется): без стирания новый разговор носил бы чужую личность, и с выпуском по
        // состоянию был бы выпущен на SYN — приветствие новой цели не доедет (lift-leak.sh: 59 КБ
        // мимо userspace под именем предыдущего).
        match wire.opens {
            true => {
                self.flow_names.remove(&wire.flow);
                // Память наблюдения стирается вместе с именем и по той же причине: граница прошлого
                // разговора объявила бы повтором первый сегмент нового.
                self.talks.forget(wire.flow);
            }
            false => (),
        };
        // Наблюдение снимается ДО вердикта и из того же разбора. Порядок важен: `advance` ниже
        // двигает курсор и может выселить разговор, а показание относится к ПРИШЕДШЕМУ пакету.
        // Протокол называется здесь: `Fed::seen` складывает показания обоих транспортов в одно поле.
        let reading = self.talks.read(&wire).map(Reading::Tcp);
        let said = self.note_name(&wire);
        let known = match self.flow_names.get(&wire.flow) {
            Some(held) => held.clone(),
            None => Naming::Awaited,
        };
        // Знание растёт join'ом, решение замораживается снимком — разные величины (#300). Здесь
        // первое: что известно о личности; оно обязано расти и не зависеть от порядка. Снимок «на
        // чём стоял план» живёт в ядре (`stood_on`) и от порядка зависит по определению.
        let says = said_of(&said);
        let was = said_of(&known);
        let naming = self.joined_named(known, said);
        self.note_naming(was, said_of(&naming));
        match naming == Naming::Awaited {
            true => (),
            false => {
                self.flow_names.insert(wire.flow, naming.clone());
            }
        };

        let key = keyed(naming.clone(), wire.dst, host_of);
        let plan = self.plan_by(&key);
        // Устаревание сверяется с планом, который сейчас в силе для ЭТОГО разговора, а не с планом
        // адреса: у именованного флоу знание живёт под именем.
        let cursor = match self.cursors.get(&wire.flow) {
            Some(held) => *held,
            None => Cursor::Fresh,
        };
        let packet = Packet {
            flow: wire.flow,
            dst: wire.dst,
            dir: wire.dir,
            opens: wire.opens,
            closes: wire.closes,
            resets: wire.resets,
            payload_len: wire.payload.len(),
            says,
        };

        // Горячий путь идёт через алгебру, не мимо: прежде здесь стоял рукописный `advance`,
        // собранный потому, что морфизм не выражал заимствованный пакет. Заимствования нет, и
        // композиция берётся у фундамента: `Advancing` говорит вердикт, `Counting` молчит и копит.
        let (Pair(advanced, _counting), act, (sighting, tally)) = Advancing::new(cursor)
            .alongside(Counting(self.tally))
            .step((plan, packet, now));

        self.tally = tally;
        self.note_marked(&act, wire.dst, wire.dir);
        self.remember(wire.flow, advanced.cursor, now);
        self.charge_channel(wire.dir, wire.payload.len() as u64, now);
        self.charge_target(&wire, now);
        let opened = matches!(
            sighting.map(|noted| noted.what),
            Some(Noticed::Talk(Sighting::Opened { .. }))
        );
        // Ключ больше не приделывается снаружи: прежде край приписывал наблюдению `wire.flow` сам, и
        // всякий второй потребитель изобретал бы связь «наблюдение ↔ разговор» заново.
        sighting.into_iter().for_each(|told| self.tell(told));
        self.sweep(now);
        Fed {
            act,
            opened,
            seen: reading,
            watch: watched(self.naming_of_flow(wire.flow), act, plan),
        }
    }

    /// Показание с датаграммы. Вердикта нет намеренно: правило очереди заворачивает только
    /// соединения, приговор транспорту, который до нас не доезжает, был бы отчётом о несделанном.
    /// Словарь ровно общий: ни стука, ни рукопожатия, ни сброса, ни окна — свойство транспорта.
    pub fn watch_datagram(&mut self, datagram: &Datagram<'_>) -> Option<Reading> {
        // Имя всегда ждётся: плоскость QUIC-приветствие не разбирает, голова уходит по потолку
        // терпения. Названная дыра — край на том же типе отвечает `Named::Known`, когда имя есть.
        self.talks.watch(datagram, Named::Awaited).map(Reading::Udp)
    }

    /// Адрес попадает в множество один раз, не на каждый пакет: запись в ядро — в темпе смены знания,
    /// чтение — в темпе пакета. Считается только исходящее — условие сверки: ядерный счётчик стоит на
    /// пути ВВЕРХ (`postrouting`), обратный трафик уводит `ct mark` мимо него; считай обе стороны —
    /// два конца витнеса расходились бы систематически (замер 31.08: ядро 15 против плоскости 27).
    fn note_marked(&mut self, act: &Act, dst: Addr, dir: Dir) {
        match act {
            Act::Marked(mark) => {
                match dir {
                    Dir::Up => *self.marked_packets.entry(mark.0).or_insert(0) += 1,
                    Dir::Down => (),
                };
                self.marked.insert(dst);
            }
            // Обрыв не метит: он кончает разговор, а не ведёт. Считать его меченым завысило бы наш
            // счёт против ядерного и назвало это расхождением мира.
            Act::Pass | Act::Drop | Act::Sever => (),
        }
    }

    pub fn marked_held(&self) -> usize {
        self.marked.len()
    }

    /// Сколько пакетов плоскость пометила КАЖДОЙ меткой — наша сторона витнеса доставки.
    pub fn marked_packets(&self) -> Vec<(u32, u64)> {
        self.marked_packets
            .iter()
            .map(|(mark, n)| (*mark, *n))
            .collect()
    }

    /// Что пакет сказал о личности цели. Возвращает `Spoken` с КЛЮЧОМ (суженным именем), не с
    /// проводным: под ключом лежит знание, добывать его дважды разными способами — способ разойтись
    /// молча. `Silent` — приветствие прошло, имени нет (не-TLS, ECH, битый SNI): факт о ЦЕЛИ.
    /// `Awaited` — пакет о личности не сказал ничего: факт о ВРЕМЕНИ. Слить — потерять знаменатель.
    fn note_name(&mut self, wire: &Wire<'_>) -> Naming<Box<str>> {
        match wire.head {
            Head::Opaque => Naming::Awaited,
            Head::HelloWithoutName => {
                self.unnamed_hellos += 1;
                Naming::Silent
            }
            Head::Hello { sni_at, sni_len } => {
                let from = sni_at as usize;
                match wire.payload.get(from..from + sni_len as usize) {
                    None => {
                        self.unnamed_hellos += 1;
                        Naming::Silent
                    }
                    Some(raw) => match std::str::from_utf8(raw) {
                        Err(_not_text) => {
                            self.unnamed_hellos += 1;
                            Naming::Silent
                        }
                        Ok(name) => {
                            *self.names.entry(name.to_string()).or_insert(0) += 1;
                            let key: Box<str> = (self.narrow)(name).into();
                            // Коллизия имён считается, не молчит (#317): прежде `insert`
                            // перезаписывал молча, на общем адресе CDN подсказка хранила последнего
                            // (таких имён там ≥69). Знать частоту раньше, чем решать о годности.
                            match self.named.get(&wire.dst) {
                                Some(before) if before.as_ref() != key.as_ref() => {
                                    self.name_collisions += 1
                                }
                                _same_or_first => (),
                            }
                            // Имя пишется по адресу только когда оно есть: соединение без hello
                            // (докачка, заход по IP) не должно отбирать знание предыдущего — оттого
                            // запись, а не замена на `None`.
                            self.named.insert(wire.dst, key.clone());
                            Naming::Spoken(key)
                        }
                    },
                }
            }
        }
    }

    /// Что плоскость знает об этом разговоре. `Cursor::Fresh` значит «не видели вовсе» — законный, не
    /// пограничный случай: разговор, не дошедший до очереди, существует, и строка обязана его показать.
    pub fn cursor_of(&self, flow: FlowKey) -> Cursor {
        match self.cursors.get(&flow) {
            Some(held) => *held,
            None => Cursor::Fresh,
        }
    }

    /// Оборвать живые разговоры с этой целью. Возвращает, скольким приказ лёг в состояние. Подъём
    /// приказа с цели на её разговоры (#326): приказ адресован ЦЕЛИ (маршрут изменился), рвутся
    /// РАЗГОВОРЫ (слой над ней) — двери между ними у плоскости не было, оттого `Ordered::Sever` год
    /// не производился. Имя сужается тем же `narrow`, что и планы (иначе приказ о `youtube.com` не
    /// нашёл бы `…googlevideo.com`). Приказ ложится в СОСТОЯНИЕ, исполнит следующий пакет (тогда же
    /// соберётся RST) — обрыв остаётся свойством шага (`step::sever` чистая).
    pub fn sever_named(&mut self, name: &str) -> usize {
        let narrowed = (self.narrow)(name);
        let doomed: Vec<FlowKey> = self
            .flow_names
            .iter()
            .filter(|(_, said)| match said {
                Naming::Spoken(held) => (self.narrow)(held) == narrowed,
                Naming::Awaited | Naming::Silent => false,
            })
            .map(|(flow, _)| *flow)
            .collect();

        doomed
            .into_iter()
            .filter(|flow| match self.cursors.get(flow) {
                // Рвать нечего — не отказ: приказ мог опоздать ровно на конец разговора.
                None => false,
                Some(cursor) => {
                    let severed = sever(*cursor);
                    let ordered = severed != *cursor;
                    self.cursors.insert(*flow, severed);
                    ordered
                }
            })
            .count()
    }

    /// Когда плоскость видела этот разговор в последний раз. Нужен строке для слепоты второго рода,
    /// которую счёт не ловит: счета сошлись, а наблюдения прекратились (живая и застывшая строки
    /// выглядят одинаково).
    pub fn seen_at_of(&self, flow: FlowKey) -> Option<Tick> {
        self.seen_at.get(&flow).copied()
    }

    /// Как зовут цель в этом разговоре. `None` — имени нет; две причины различает `naming_of_flow`,
    /// здесь слиты намеренно (вызывающему, которому нужно имя, обе одинаковы).
    pub fn name_of_flow(&self, flow: FlowKey) -> Option<&str> {
        match self.flow_names.get(&flow) {
            Some(Naming::Spoken(name)) => Some(name.as_ref()),
            Some(Naming::Silent) | Some(Naming::Awaited) | None => None,
        }
    }

    /// Что известно о личности цели в этом разговоре — все три состояния. Отсюда доля безымянных ПО
    /// РАЗГОВОРУ, а не сводным счётчиком по коробке.
    pub fn naming_of_flow(&self, flow: FlowKey) -> Naming<Box<str>> {
        match self.flow_names.get(&flow) {
            Some(known) => known.clone(),
            None => Naming::Awaited,
        }
    }

    /// Как звали говорившего по этому адресу последним — ПОДСКАЗКА, не основание (#317). Годится для
    /// безымянного трафика, явное имя обязано её перебивать: на общем адресе CDN за одной записью
    /// десятки имён. Частота расхождения не гадается, а считается (`name_collisions`).
    pub fn name_hint_of(&self, dst: Addr) -> Option<&str> {
        self.named.get(&dst).map(|name| name.as_ref())
    }

    /// Сколько раз подсказка по адресу сменила имя на другое.
    pub fn name_collisions(&self) -> u64 {
        self.name_collisions
    }

    /// Переезд разговора по личности. Считается ПЕРЕХОД, а не состояние: ушедший из `Silent` в
    /// `Spoken` обязан покинуть первую долю, иначе сумма превысит число разговоров.
    fn note_naming(&mut self, was: Said, now: Said) {
        match (was, now) {
            (Naming::Awaited, Naming::Spoken(())) => self.flows_spoken += 1,
            (Naming::Awaited, Naming::Silent) => self.flows_silent += 1,
            (Naming::Silent, Naming::Spoken(())) => {
                self.flows_silent = self.flows_silent.saturating_sub(1);
                self.flows_spoken += 1;
            }
            _no_move => (),
        }
    }

    /// Доли личности по разговорам: назвались · приветствие без имени · так и не сказали ничего.
    /// Третье — вычитанием из числа ОТКРЫТЫХ разговоров, так у прибора есть знаменатель. Цена:
    /// знаменатель считает разговоры, чей SYN мы видели; подхваченный с середины в него не попадает,
    /// и третья доля упирается в ноль вместо отрицательного (прибор молчит, а не утверждает
    /// невозможное). Занижение видно сравнением с `cursors`.
    pub fn naming_shares(&self) -> (u64, u64, u64) {
        let known = self.flows_spoken + self.flows_silent;
        (
            self.flows_spoken,
            self.flows_silent,
            self.tally.flows_opened.saturating_sub(known),
        )
    }

    /// Сколько разговоров назвались двумя разными именами — величина ⊤, которой нет типом.
    pub fn name_conflicts(&self) -> u64 {
        self.name_conflicts
    }

    /// Join знания о личности разговора — тот же порядок по информации, что у ядра (`Awaited ⊑ Silent
    /// ⊑ Spoken`), с именем в верхнем элементе. Закон 3 здесь НЕ тотален: два разных имени на одном
    /// разговоре несравнимы (в полной решётке ⊤), коммутативности на этой паре нет — держится
    /// пришедшее первым. Формулировка: коммутативно на цепочке; в конфликте — нет, частота замеряется
    /// (`name_conflicts`). Детерминированный разрешатель был бы решением ДО замера. Сперва число.
    fn joined_named(
        &mut self,
        known: Naming<Box<str>>,
        said: Naming<Box<str>>,
    ) -> Naming<Box<str>> {
        match (known, said) {
            (Naming::Spoken(first), Naming::Spoken(other)) => {
                match first.as_ref() == other.as_ref() {
                    true => (),
                    false => self.name_conflicts += 1,
                };
                Naming::Spoken(first)
            }
            (Naming::Spoken(name), _lower) | (_lower, Naming::Spoken(name)) => Naming::Spoken(name),
            (Naming::Silent, _) | (_, Naming::Silent) => Naming::Silent,
            (Naming::Awaited, Naming::Awaited) => Naming::Awaited,
        }
    }

    /// Сколько имён держится сейчас. Публично ради закона о форме роста: без этого числа «карта имён
    /// ограничена целями» проверялось бы только чтением кода.
    pub fn named_held(&self) -> usize {
        self.named.len()
    }

    pub fn names(&self) -> Vec<(String, u64)> {
        self.names
            .iter()
            .map(|(name, n)| (name.clone(), *n))
            .collect()
    }

    pub fn unnamed_hellos(&self) -> u64 {
        self.unnamed_hellos
    }

    /// Законченный разговор уходит в `Lost`, а не в пустоту. Освободив запись на `FIN`, оболочка
    /// превращала хвост разрыва в НОВЫЕ разговоры (замер: «открыт 3» при одном флоу). Запись держится
    /// до подметания по горизонту. Перевода больше нет (#320): прежде шаг отдавал при закрытии
    /// `Cursor::Fresh`, оболочка переводила в `Ended` — у `Fresh` было два смысла, державшихся
    /// комментарием, и с ним терялся ответ цели. Теперь шаг называет закрытие сам, оболочка кладёт
    /// что получила; `Fresh` сюда не приходит вовсе.
    fn remember(&mut self, flow: FlowKey, cursor: Cursor, now: Tick) {
        match cursor {
            Cursor::Fresh => (),
            Cursor::Running(_) | Cursor::Ended(_) | Cursor::Lost => {
                self.cursors.insert(flow, cursor);
                self.seen_at.insert(flow, now);
            }
        }
    }

    fn charge_channel(&mut self, dir: Dir, bytes: u64, now: Tick) {
        match dir {
            Dir::Down => self.ring = applied(self.ring, charge(self.ring.last, now, bytes)),
            Dir::Up => (),
        }
    }

    fn charge_target(&mut self, wire: &Wire<'_>, now: Tick) {
        let held = match self.targets.get(&wire.dst) {
            Some(known) => *known,
            None => fresh_target(now),
        };
        let packet = Packet {
            flow: wire.flow,
            dst: wire.dst,
            dir: wire.dir,
            opens: wire.opens,
            closes: wire.closes,
            resets: wire.resets,
            payload_len: wire.payload.len(),
            // Счёту байтов личность цели безразлична: здесь меряется темп, а не решается план.
            says: Naming::Awaited,
        };
        let charged = charged_target(held, &packet, now);
        self.targets.insert(wire.dst, charged.target);
        match charged.peaked {
            false => (),
            true => self.tell(Noted {
                at: now,
                about: About::Talk(wire.flow),
                // Различитель, а не имя: имя добавит `drain`, одним местом на все наблюдения.
                target: said_of(&self.naming_of_flow(wire.flow)),
                what: Noticed::Talk(Sighting::Peaked {
                    dst: wire.dst,
                    pace: charged.target.best,
                }),
            }),
        }
    }

    fn tell(&mut self, told: Noted) {
        match self.sightings.len() < SIGHTINGS {
            true => self.sightings.push(told),
            false => self.dropped_sightings += 1,
        }
    }

    /// Наблюдение отдаётся вместе с разговором, в котором случилось (#317) — иначе потребитель пошёл
    /// бы спрашивать имя по адресу (карта адрес→имя основанием действия через заднюю дверь). Имя
    /// добавляется здесь, и только здесь (#320, Т5): ядро имён не знает, потребитель их
    /// восстанавливать не вправе; обогащение стоит на выходе, где знание полное (наблюдение копилось
    /// с различителем, имя берётся ТЕКУЩЕЕ). Цена: имя, названное позже наблюдения, приезжает с ним
    /// — верно для таблицы (предмет — цель), неточно для ленты (различить можно `Recognised`). Клон
    /// — только у `Spoken`. Сводка копится у показа, не здесь: плоскость отдаёт ВЕЛИЧИНЫ, заведи она
    /// сводку — появилось бы второе суждение рядом с суждением показа, и разошлись бы молча.
    pub fn drain(&mut self) -> Vec<Noted<Box<str>>> {
        let names = &self.flow_names;
        self.sightings
            .drain(..)
            .map(|noted| {
                let flow = match noted.about {
                    reflex_engine::About::Talk(flow) => Some(flow),
                    // У наблюдения о ЦЕЛИ разговора нет, спрашивать имя не у кого: её разговоры
                    // выселены раньше. Подсказка по адресу вернула бы то, что врёт на общем адресе.
                    reflex_engine::About::Target => None,
                };
                noted.named(
                    |said| match (flow.and_then(|flow| names.get(&flow)), said) {
                        (Some(known), _) => known.clone(),
                        // Имени у разговора нет — различитель ядра говорит, ПОЧЕМУ. `Silent` и
                        // `Awaited` переживают потерю карты: обе причины установлены ядром.
                        (None, Naming::Silent) => Naming::Silent,
                        (None, Naming::Spoken(())) | (None, Naming::Awaited) => Naming::Awaited,
                    },
                )
            })
            .collect()
    }

    pub fn note_unapplied(&mut self, what: &'static str) {
        *self.unapplied.entry(what).or_insert(0) += 1;
    }

    /// Время идёт — единственный вход, не требующий пакета. Всё, чем плоскость судит о ТИШИНЕ
    /// (`expired`, `Freshness::Silent`, `Sighting::Stale`, [`Lost`]), прежде двигалось чужим пакетом
    /// и уборка висела на счёте пакетов, хотя решает вопрос временной — нет трафика, и время стоит.
    /// Мёртвая нога умирает В ТИШИНЕ: прибор, которого будит чужой пакет, слеп именно к своему
    /// случаю. `Lost` рождается здесь, а не в шаге: потеря есть событие ОТСУТСТВИЯ, шаг видит только
    /// присутствие — бывает время, в которое ничего не произошло, и его замечает уборка по часам.
    pub fn tick(&mut self, now: Tick) -> Vec<Noted<Box<str>>> {
        self.wipe(now);
        self.drain()
    }

    fn sweep(&mut self, now: Tick) {
        match self.tally.packets % SWEEP_EVERY == 0 {
            false => (),
            true => self.wipe(now),
        }
    }

    /// Один проход уборки — с потолком и с места, где остановились. Отделён от [`Plane::sweep`] тем,
    /// что не спрашивает о ПАКЕТАХ: у уборки два повода (амортизация на горячем пути и ход времени),
    /// условие принадлежит поводу, а не работе.
    fn wipe(&mut self, now: Tick) {
        {
            {
                self.sweeps += 1;

                let looked: Vec<FlowKey> = self
                    .seen_at
                    .range(self.sweep_from..)
                    .take(SWEEP_BUDGET)
                    .map(|(flow, _seen)| *flow)
                    .collect();
                self.swept += looked.len() as u64;
                self.backlog = self.seen_at.len().saturating_sub(looked.len());
                self.sweep_from = match looked.last() {
                    Some(FlowKey(last)) => FlowKey(last.saturating_add(1)),
                    None => FlowKey(0),
                };
                let stale: Vec<FlowKey> = looked
                    .into_iter()
                    .filter(|flow| match self.seen_at.get(flow) {
                        Some(seen) => expired(*seen, now),
                        None => false,
                    })
                    .collect();
                // Счёт `evicted_cursors` — за забыванием, и только за ним. Забывание — переход
                // `Running → Lost` (состояние снято, не знаем, что применяли). Удаление `Ended` по
                // истечении удержания забыванием не является (закрылся штатно, всё было известно),
                // удаление уже `Lost` тем более. Оттого инкремент стоит РОВНО в одной точке —
                // там, где случается само забывание, не на попадании в `stale` и не на удалении.
                //
                // Выселение двухфазное (#320): прежде первая фаза удаляла курсор, `record()` находил
                // запись conntrack без курсора и ставил `Watched::Never` — таблица печатала «не
                // видели» про наблюдавшийся разговор (37 пакетов на 8 флоу, все три строки слепы).
                // `Never` и `Lost` — разные факты: «не смотрели» и «смотрели и забыли». Цена: карта
                // держит забытый ещё горизонт (потолок `CURSORS` покрывает вдвое меньше живых) —
                // дешевле лжи в главном числе; мерить долю `Lost` среди курсоров.
                stale.iter().for_each(|flow| {
                    match self.cursors.get(flow) {
                        // Умер молча: закрытия не объявлял, состояние снимаем — честно говорим, что
                        // не знаем, что применяли (иначе хвостовой пакет получил бы решение заново
                        // поверх применённого).
                        Some(Cursor::Running(_)) => {
                            self.cursors.insert(*flow, Cursor::Lost);
                            self.seen_at.insert(*flow, now);
                            self.evicted_cursors += 1;
                        }
                        // Закрылся буквой: знание получено и не устаревает от хода времени —
                        // `seen_at` не двигаем (иначе срок отсчитывался бы от каждого прохода). Он
                        // от ЗАКРЫТИЯ, удержание — своя величина (`RETENTION_HORIZONS`), а не
                        // горизонт уборки. Истекло — запись удаляется (дальше о ней скажется
                        // `Never`), не истекло — оставляем.
                        Some(Cursor::Ended(_)) => {
                            let closed = self.seen_at.get(flow).copied().unwrap_or(now);
                            let held = now.0.saturating_sub(closed.0);
                            match held >= RETENTION_HORIZONS * horizon().0 {
                                false => (),
                                true => {
                                    self.cursors.remove(flow);
                                    self.seen_at.remove(flow);
                                    self.flow_names.remove(flow);
                                }
                            }
                        }
                        // Вторая фаза: забытый пережил ещё горизонт — исчезает совсем. Дальше о нём
                        // честно скажется `Never`: столько времени спустя мы и правда не знаем, шёл
                        // ли он через нас.
                        Some(Cursor::Lost) | Some(Cursor::Fresh) | None => {
                            self.cursors.remove(flow);
                            self.seen_at.remove(flow);
                            // Имя разговора уходит вместе с разговором: переживи оно курсор — карта
                            // росла бы числом виденных соединений, потолок перестал бы ограничивать.
                            self.flow_names.remove(flow);
                        }
                    };
                    // Память наблюдения уходит на первой же фазе: граница прошлого разговора на
                    // переиспользованной четвёрке объявила бы повтором первый сегмент нового.
                    self.talks.forget(*flow);
                });

                let looked: Vec<Addr> = self
                    .targets
                    .range(self.sweep_from_target..)
                    .take(SWEEP_BUDGET)
                    .map(|(dst, _target)| *dst)
                    .collect();
                self.swept += looked.len() as u64;
                self.sweep_from_target = match looked.last() {
                    Some(Addr(last)) => Addr(last.saturating_add(1)),
                    None => Addr(0),
                };
                let gone: Vec<Addr> = looked
                    .into_iter()
                    .filter(|dst| match self.targets.get(dst) {
                        Some(target) => expired(target.last_seen, now),
                        None => false,
                    })
                    .collect();
                self.evicted_targets += gone.len() as u64;
                gone.iter().for_each(|dst| {
                    self.targets.remove(dst);
                    // Имя уходит вместе с целью: переживи оно её — карта росла бы числом виденных
                    // адресов, потолок `TARGETS` перестал бы ограничивать (утечка, выглядящая как
                    // исправная работа).
                    self.named.remove(dst);
                });
                // Цель потеряна — и об этом говорят, а не только забывают. Прежде выселение было
                // чистой уборкой памяти, следом оставался лишь счётчик `evicted_targets` (ни ЧТО, ни
                // КОГДА), оттого у `Lost` не было производителя. Разговора у наблюдения нет, сказано
                // БУКВОЙ (`About::Target`): потеряна ЦЕЛЬ, её разговоры выселены выше; прежний
                // `FlowKey(0)` был честен по смыслу и неотличим по типу от настоящего ключа.
                gone.into_iter().for_each(|dst| {
                    self.tell(Noted {
                        at: now,
                        about: About::Target,
                        // Разговора нет — и различителя личности тоже: цель потеряна целиком.
                        // `Awaited` честен: о личности не сказано ничего, сказать больше некому.
                        target: Naming::Awaited,
                        what: Noticed::Loss(Lost { dst }),
                    })
                });
            }
        }
    }

    pub fn swept(&self) -> u64 {
        self.swept
    }

    pub fn sweeps(&self) -> u64 {
        self.sweeps
    }

    /// Сколько записей осталось неосмотренными на последнем проходе. Растущий остаток значит, что
    /// круг удлиняется: тревоги ещё не опаздывают, но начнут. Показание о ЗАПАСЕ, не счётчик работы.
    pub fn backlog(&self) -> usize {
        self.backlog
    }

    pub fn pressure(&self) -> Pressure {
        Pressure {
            held: self.cursors.len() as u32,
            capacity: CURSORS as u32,
            evicted: self.evicted_cursors,
        }
    }

    pub fn channel(&self, back: u8) -> Pace {
        reflex_engine::meter::paced(&self.ring, back)
    }

    pub fn ceiling(&self) -> Pace {
        reflex_engine::meter::ceiling(&self.ring)
    }

    pub fn tally(&self) -> Tally {
        self.tally
    }

    pub fn targets_held(&self) -> usize {
        self.targets.len()
    }

    pub fn dropped_sightings(&self) -> u64 {
        self.dropped_sightings
    }

    pub fn evicted_targets(&self) -> u64 {
        self.evicted_targets
    }

    /// Сколько разговоров забыто уборкой. Едет в снимок: без него человек не отличит нашу СЛЕПОТУ
    /// («не смотрели») от нашей ЗАБЫВЧИВОСТИ («смотрели и забыли»), а доля «не видели» перестаёт
    /// что-либо мерить.
    pub fn evicted_cursors(&self) -> u64 {
        self.evicted_cursors
    }

    pub fn unapplied(&self) -> Vec<(&'static str, u64)> {
        self.unapplied.iter().map(|(what, n)| (*what, *n)).collect()
    }

    pub fn offer(&mut self) {
        self.offered += 1;
    }

    pub fn note_unparsed(&mut self) {
        self.unparsed += 1;
    }

    pub fn snapshot(&self) -> String {
        format!(
            "packets={} up={} down={} flows={} cursors={} targets={} ring_1s={} ceiling={} evicted_cursors={} evicted_targets={} dropped_sightings={} named={} unnamed={} offered={} unparsed={} marked={} name_collisions={} name_conflicts={} spoken={} silent={} awaited={}\n",
            self.tally.packets,
            self.tally.up_bytes,
            self.tally.down_bytes,
            self.tally.flows_opened,
            self.cursors.len(),
            self.targets.len(),
            self.channel(7).bytes,
            self.ceiling().bytes,
            self.evicted_cursors,
            self.evicted_targets,
            self.dropped_sightings,
            self.names.len(),
            self.unnamed_hellos,
            self.offered,
            self.unparsed,
            self.marked.len(),
            self.name_collisions,
            self.name_conflicts,
            self.naming_shares().0,
            self.naming_shares().1,
            self.naming_shares().2,
        )
    }

    pub fn horizon_span(&self) -> u64 {
        horizon().0
    }
}
