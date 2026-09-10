#![no_std]
// Обещание имени в докблоке ([`Name`]) держит компилятор, не читатель: битая ссылка — ошибка сборки
// документации, а не молчаливое предупреждение, которое ловят люди постфактум.
#![deny(rustdoc::broken_intra_doc_links)]

// БЫЛО только под тест — стало безусловно (задача 12½, перевоз `parse`/`talk` из `engine-nfq`):
// разбор провода строит `Flow` через `std::net::SocketAddr` (тип пришёл из `reflex-core`, который
// `std` и не прячет), а таблица разговоров (`Talks`) держит `BTreeMap`. Оба чужие `no_std` и раньше
// — зависимость (`reflex-core` → `futures`) уже тянула `std` в сборку, атрибут был дисциплиной
// стиля без свойства сборки (см. ниже). Дисциплина осталась для СОБСТВЕННОГО кода модулей, не
// унаследовавших `std`-типов (`interpret`, `meter`, `row`, `step`, `watch`) — только `parse`/`talk`
// названы явно.
extern crate std;

pub mod interpret;
pub mod meter;
pub mod name;
// РАЗБОР ПРОВОДА (задача 12½, переезд из `engine-nfq`) — код ЧИСТЫЙ: не зовёт netlink, не знает
// очереди. Прежний дом, `reflex-engine-nfq`, безусловно зависел от `reflex-linux` (сырой
// `AF_NETLINK`, крейт `nfq`, не собирающийся на `windows-msvc`) — и потому кросс-сборку фасада
// (`reflex`, единственный потребитель) валил чужой закон, а не свой. Здесь у разбора нет соседей,
// тянущих Linux: переезд, не переписывание, форма и тела функций не тронуты.
//
// Того дома больше НЕТ (снесён 10.09.2026): после переезда в нём осталась одна `Plane` — четвёртый
// дом состояния, где состояние машины живёт в драйвере. Законы разбора уехали сюда же, в
// `engine/tests/`; закон согласия проводного и ядерного ключа — в `linux/tests/flow_identity.rs`,
// потому что его предмет не разбор, а СОГЛАСИЕ двух источников, и знает обоих только тот крейт.
pub mod parse;
pub mod row;
pub mod step;
// ТАБЛИЦА РАЗГОВОРОВ (задача 12½, переезд из `engine-nfq`) — по той же причине, что и `parse`:
// знает только `Dir`/`Flow` (отсюда же) и словарь провода (`reflex-instrument`), Linux не знает.
pub mod talk;
pub mod watch;

// Адрес переехал в `reflex-core` (09.09.2026): им ключуется область цели (`Base::Fibre`), а ключ
// области не может ссылаться вверх по зависимостям. Здесь — реэкспорт: потребители не тронуты.
pub use reflex_core::types::Addr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Tick(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Span(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Epoch(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mark(pub u32);

// Личность разговора — четвёрка (`reflex_core::types::Flow`), а не её отпечаток: ключ области есть
// то, чем она расслаивается (§4). Отпечаток `FlowKey(u64)` был лосси — две четвёрки с одним хэшем
// давали один слой, то есть одну машину на два разговора, и молча. Снят 09.09.2026 по замеру:
// карта по четвёрке дороже карты по отпечатку на 1–4 нс при микросекундах на пакет.
pub use reflex_core::types::Flow;

/// Направление — понятие всякого инлайн-движка, не нашего продукта; живёт в фундаменте. Реэкспорт,
/// не переименование: 60+ употреблений в четырёх крейтах, churn ради нуля смысла не платится.
pub use reflex_core::types::Dir;

/// Буква горячего пути — без заимствования (§10). Поле было `payload: &'a [u8]`, лайфтайм уходил в
/// `Advancing<'a>` и в `Mealy::In`, у которого своего лайфтайма нет: все пакеты одной машины делили
/// бы одну область заимствования, а байты ядра живут до вердикта — цикл не собирался (`E0597`).
/// Заменено длиной, читалась только она (`.len()`/`.is_empty()`, ни одного индексирования). Цена:
/// байты из буквы недостижимы — кому нужно содержимое, разбирает ДО, в краю ([`parse`], соседний
/// модуль этого же крейта).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Packet {
    pub flow: Flow,
    pub dst: Addr,
    pub dir: Dir,
    pub opens: bool,
    pub closes: bool,
    pub resets: bool,
    /// Сколько байтов нёс — не сами байты.
    pub payload_len: usize,
    /// Что пакет сказал о личности. Ядро имён не знает — оно знает МОМЕНТ, в который личность стала
    /// известна, и этого хватает, чтобы принять план по ней.
    pub says: Said,
}

/// Что пакет сказал о личности цели (#317). План разрешался на `Cursor::Fresh` (SYN), когда о цели
/// известен только адрес — отсюда круг #317: на общем адресе CDN знание накрывало 69 посторонних
/// имён. Разрывается переносом МОМЕНТА, не таблицей адрес→имя (она врёт, где имён десятки, и её
/// источник под контролем противника). Тип не свой, а `row::Naming`: понятие, записанное дважды,
/// расходится молча (оплачено ключом памяти, 1136 флоу мимо). Ядру довольно различителя без имени.
pub type Said = row::Naming<()>;

/// Что знает о личности разговор целиком после этого пакета — JOIN (§5), не «правило обновления».
/// Знание — элемент ЧУ по информации, `Awaited = ⊥`, событие провода монотонно: `Awaited ⊑ Silent
/// ⊑ Spoken`. `Silent` ниже `Spoken` по информации, не важности. Три закона (все под тестом):
/// монотонность `k ⊑ joined(k,e)`, идемпотентность, независимость от порядка (провод переставляет
/// пакеты, а userspace видит подмножество событий — вердикт, зависящий от порядка, недетерминирован
/// на таком проводе). ⊤ («два имени») здесь нет намеренно: частота не замерена, считается
/// счётчиком `Plane::name_conflicts`; на `Said` случай невыразим, законы 1–3 тотальны. Правило
/// разрешения расхождения вырождено: значений нет, выбирать не из чего.
pub fn joined(known: Said, said: Said) -> Said {
    reflex_core::disclosure::joined_with(known, said, |mine, _theirs| mine)
}

/// На чём стоял план при принятии — другая величина, не то же знание. Знание обязано только расти и
/// не зависеть от порядка; запись о ПРОШЛОМ решении обязана зависеть (действовали пришедшим первым,
/// переставить задним числом нельзя). Функция ЗАМОРАЖИВАЕТ: первое непустое слово остаётся навсегда
/// — разговор без имени в приветствии закрывает вопрос сразу, позднее имя не двигает страту. Ось
/// одна (личность): здесь её снимок, берётся ровно когда ось покидает ⊥.
pub use reflex_core::disclosure::stood_on;

/// Что велено сделать с разговором.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ordered {
    /// Ничего сверх плана — обычная жизнь.
    Nothing,
    /// Оборвать при первом же пакете.
    Sever,
}

/// Разговор (§4): слово живёт до его конца.
impl reflex_core::word::Word for Ordered {
    type Of = reflex_core::word::Conversation;
}

/// Приказ разговора, сказанный пакету — `Option<Act>`, `None` там, где приказа не было (§5,
/// поглощающий ноль). Спуск обязан уметь промолчать: отдай `Nothing` какой-нибудь `Act::Pass`, и
/// обычная жизнь разговора стала бы решением, перебивающим план цели, — молчание выиграло бы
/// произведение.
impl reflex_core::word::Descends<Option<Act>> for Ordered {
    fn descends(self) -> Option<Act> {
        match self {
            Ordered::Sever => Some(Act::Sever),
            Ordered::Nothing => None,
        }
    }
}

/// Рассказывали ли МЫ об устаревании, и когда. Состояние, а не флаг: флаг делал предикат
/// устаревания зависимым от истории, и в лоссовом канале ломался с первой потери (приказ не доехал,
/// повтора нет). Со временем последнего рассказа предикат снова функция состояния, потеря
/// вырождается в задержку. Переименовано из `Told` (одно слово называло два типа в крейте;
/// переименован меньший — 7 употреблений против 85).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Announced {
    /// Ещё ни разу — рассказывать пора.
    Never,
    /// Рассказали в этот момент; повторим не раньше горизонта.
    At(Tick),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Basis {
    Measured,
    Seeded,
    Default,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Plan {
    pub programme: Programme,
    pub epoch: Epoch,
    pub basis: Basis,
    /// Нужны ли по этой цели показания приборов. Поле плана, а не отдельный приказ: приедь интерес
    /// своим путём, он проиграл бы гонку пакету.
    pub interest: Interest,
}

/// Нужны ли показания. Псевдоним [`reflex_core::watch::Interest`]: выбор «платить ли полную цену
/// дороги ради наблюдений» есть у всякого перехватывающего движка. Цена `Watching` наша,
/// замеренная: 3,88 мкс на пакет вместо 238 нс.
pub use reflex_core::watch::Interest;

/// План для пакетов разговора. Отвода здесь нет (#326): `Divert(Executor)` снят, исполнителя не
/// существует (`edge-quic` написан и не подключён), а «принято и не применено» было законным
/// состоянием. Пока исполнителя нет, отвод невыразим, а не молчаливо неисполнен:
///
/// ```compile_fail
/// // Отвод снят вместе с исполнителем: назвать его нечем.
/// let _ = reflex_engine::Programme::Divert(reflex_engine::Executor::QuicStep);
/// ```
///
/// Обрыва здесь тоже нет — по другой причине (об АДРЕСАТЕ, не исполнителе): три алгебры действия
/// различаются адресатом — `Programme`→ЦЕЛИ (переживает разговор), [`Ordered`]→РАЗГОВОРУ (умирает с
/// ним), [`Act`]→ПАКЕТУ (один шаг). Обрывать нечего, пока разговора нет — у приказа нет носителя:
///
/// ```compile_fail
/// // Обрыв адресуется разговору (`Ordered::Sever`), а не цели: здесь его назвать нечем.
/// let _ = reflex_engine::Programme::Sever;
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Programme {
    Pass,
    Mark(Mark),
}

/// Цель (§4): слово живёт до смены плана.
impl reflex_core::word::Word for Programme {
    type Of = reflex_core::word::Target;
}

/// План цели, сказанный пакету — спуск по охвату. Обрыва нет: он адресуется разговору, не цели
/// (прежняя `Programme::Sever => Act::Pass` молча подменяла наибольшую силу наименьшей).
impl reflex_core::word::Descends<Act> for Programme {
    fn descends(self) -> Act {
        match self {
            Programme::Pass => Act::Pass,
            Programme::Mark(mark) => Act::Marked(mark),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Run {
    pub plan: Plan,
    /// На чём стоит план разговора — снимок личности на момент принятия (`stood_on`), НЕ текущее
    /// знание (оно растёт join'ом в плоскости). Заменило `Standing { Provisional, Settled }` —
    /// снятие незаконного состояния (#300): `Standing` был второй осью, произведение держало
    /// представимыми «принято по личности, которой ещё нет» и «ждём имени, которого не будет».
    /// Ось одна: план принят ⟺ личность известна (`Spoken` либо `Silent`).
    pub naming: Said,
    pub up: u16,
    pub down: u16,
    pub up_bytes: u64,
    pub down_bytes: u64,
    pub began: Tick,
    pub last_up: Tick,
    pub last_down: Tick,
    /// Ответила ли цель, и через сколько. Одним полем, не флагом рядом с меткой: два поля
    /// кодировали бы один факт, и «ответила, но когда — неизвестно» стало бы выразимым.
    pub answered: row::Answered,
    /// Когда в последний раз рассказали об устаревании. Не `bool`/`Option`: «никогда» и «в момент
    /// t» — разные состояния, `Option` позволил бы забыть, что `None` значит «пора», не «нечего».
    pub announced: Announced,
    /// Приказ, ждущий пакета (#318). Не `Option<Programme>`: приказ на живой разговор ровно один по
    /// природе — оборвать. Прочие программы адресуются ЦЕЛИ и подхватываются следующим разговором,
    /// этот адресован разговору и умирает с ним.
    pub ordered: Ordered,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cursor {
    Fresh,
    Running(Run),
    /// Разговор закрылся штатно: состояния нет, но знание о цели цело — план в силе, хвостовые
    /// пакеты (последний `ACK`, ретрансмиссия) его несут; нового `Run` не заводится. Ответ цели
    /// переживает закрытие (#320): прежде вариант был пуст, `Run` выбрасывался, и `node_of` красил
    /// всякий завершённый разговор в `Told::Blind` — 83 слепые цели из 86. Ответ — единственное,
    /// что из `Run` переживает осмысленно: план известен, счёт у ядра, а величина ответа ниоткуда
    /// не восстанавливается (из счёта ядра — только ФАКТ, не величина).
    Ended(row::Closed),
    /// Разговор, о конце которого не было сказано — умолк молча. Закрывшийся буквой сюда не
    /// попадает (исход известен). Отсюда `Act::Pass` — единственное безопасное при неизвестном
    /// прошлом: страта могла уйти с приветствием, решать заново значило бы применить полторы.
    Lost,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Act {
    Pass,
    Drop,
    Marked(Mark),
    /// Оборвать: пакет дальше не идёт, клиенту сказано.
    Sever,
}

/// Пакет в руках ядра (§2): ответ обязан быть дан на этом же шаге.
impl reflex_core::word::Word for Act {
    type Of = reflex_core::word::Packet;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sighting {
    Opened {
        dst: Addr,
        basis: Basis,
    },
    TargetSpoke {
        dst: Addr,
        after: Span,
    },
    Reset {
        dst: Addr,
        by_client: bool,
        target_spoke: bool,
    },
    Closed {
        dst: Addr,
        lasted: Span,
        up: u16,
        down: u16,
        /// Сколько байтов пришло вниз — отдельно от `down` (пакетов): заблокированная цель отвечает
        /// на SYN и молчит после `ClientHello` (пакеты вниз есть, нагрузки нет). Считай молчание по
        /// пакетам — и самый частый у человека случай читался бы как здоровый разговор.
        down_bytes: u64,
    },
    /// Приветствие прошло — разговор узнал, кто цель (#317). Момент, в который личность становится
    /// известной, — единственное место, где ключ доезжает вовремя. `Silent` («имени в приветствии
    /// не было»: не-TLS, IP, MTProto, ECH, битый SNI) ≠ `Awaited` («приветствия ещё не было»):
    /// первое — окончательное знание, второе — его отсутствие. Наблюдение с `Awaited` не
    /// выпускается: «клиент назвался ничем» объявило бы фактом ожидание.
    Recognised {
        dst: Addr,
        said: Said,
    },
    Stale {
        dst: Addr,
        was: Epoch,
    },
    Peaked {
        dst: Addr,
        pace: meter::Pace,
    },
    /// Приказ оборвать исполнен. Свидетельство с провода, не из журнала: «мы послали сброс» —
    /// намерение, а «разговор кончился» — наблюдение.
    Severed {
        dst: Addr,
    },
}

/// Разговор (§4): открылся, отозвался, оборвали, закрылся, узнали имя, устарело, исполнен. Разговор
/// ожидание терпит — сказать можно и позже шага. Цена: `Peaked` говорит величиной шире разговора
/// (темп копится по адресу, высказывается одному, на чьём пакете потолок взят); адресат тот же,
/// читающий обязан знать, что число мерено не по нему.
impl reflex_core::word::Word for Sighting {
    type Of = reflex_core::word::Conversation;
}

/// Цель потеряна целиком — отдельное слово, не вариант рядом с наблюдениями разговора (§4). Адресат
/// иной (цель, не разговор); слово, объявившее одну область на оба, не говорит, кому сказано, и
/// молчит вдвойне — обе области ожидание терпят, расхождение не выпадает ни на одной проверке.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Lost {
    pub dst: Addr,
}

impl Lost {
    /// Публичное имя события — снято с ТИПА, не написано у места сборки: за границей процесса имя
    /// показания компилятор не сторожит, второе написание разошлось бы молча.
    pub const EVENT: &'static str = "lost";
}

/// Цель (§4): разговоров у неё к этому мигу нет — кончились раньше потери.
impl reflex_core::word::Word for Lost {
    type Of = reflex_core::word::Target;
}

/// Что увидено — разделено по адресату буквой (§4). Держи слова один тип — подпись перестала бы
/// называть адресата; здесь он виден буквой, а каждое слово при своей области.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Noticed {
    /// О разговоре.
    Talk(Sighting),
    /// О цели целиком.
    Loss(Lost),
}

impl core::fmt::Display for Basis {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Basis::Measured => "measured",
            Basis::Seeded => "seeded",
            Basis::Default => "default",
        })
    }
}

// Печать судьбы личности уехала с решёткой — теперь `Disclosed::rung()`. `impl Display for
// row::Naming<()>` осиротел при переезде типа (E0117): и трейт, и тип чужие. Взамен метод у типа, а
// не `Display`: печатать ступень и молчать о значении — ловушка для `Disclosed<String>`.

/// Улика, а не только имя (#325). Паспорт даёт ИМЯ события (довольно метрике); делу разметчика
/// имени мало — `closed` без `down_bytes` не отличит замолчавшую после приветствия цель от честно
/// закрытого разговора, а на этом различии вся таксономия блокировок. Здесь, а не у потребителя:
/// знание, записанное дважды, расходится молча (перевод `Sighting` уже жил отдельной функцией в
/// `plane-queue`). Единица времени названа в имени поля (`_ns`): `Span` — разность тиков, кормящий
/// часы кормит наносекундами обеими дверями. Первое слово обязано совпасть с паспортным именем
/// (сторожит `the_evidence_opens_with_the_passport_name`).
impl core::fmt::Display for Sighting {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Sighting::Opened { dst, basis } => write!(f, "opened dst={dst} basis={basis}"),
            Sighting::TargetSpoke { dst, after } => {
                write!(f, "target_spoke dst={dst} after_ns={}", after.0)
            }
            Sighting::Reset {
                dst,
                by_client,
                target_spoke,
            } => write!(
                f,
                "reset dst={dst} by_client={by_client} target_spoke={target_spoke}"
            ),
            Sighting::Closed {
                dst,
                lasted,
                up,
                down,
                down_bytes,
            } => write!(
                f,
                "closed dst={dst} lasted_ns={} up={up} down={down} down_bytes={down_bytes}",
                lasted.0
            ),
            Sighting::Recognised { dst, said } => {
                write!(f, "recognised dst={dst} said={}", said.rung())
            }
            Sighting::Stale { dst, was } => write!(f, "stale dst={dst} was_epoch={}", was.0),
            Sighting::Peaked { dst, pace } => write!(
                f,
                "peaked dst={dst} bytes={} over_ns={}",
                pace.bytes, pace.over_nanos
            ),
            Sighting::Severed { dst } => write!(f, "severed dst={dst}"),
        }
    }
}

/// Первое слово улики — то же, что [`Lost::EVENT`]: имя события одно, где бы ни печаталось.
impl core::fmt::Display for Lost {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{} dst={}", Lost::EVENT, self.dst)
    }
}

/// Улику печатает увиденное слово; буква адресата ничего к ней не добавляет.
impl core::fmt::Display for Noticed {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Noticed::Talk(sighting) => write!(f, "{sighting}"),
            Noticed::Loss(lost) => write!(f, "{lost}"),
        }
    }
}

/// К чему относится наблюдение (§4). Буквой, а не выдуманным «нулевым» разговором: наблюдение о ЦЕЛИ разговора не имеет
/// (её разговоры кончились раньше); ноль честен по смыслу и неотличим по типу от настоящего ключа —
/// буква снимает соглашение, она не читается по ошибке.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum About {
    /// Разговор — лента ставит строку в его ряд.
    Talk(Flow),
    /// Цель целиком, без разговора.
    Target,
}

/// Наблюдение вместе с тем, о чём оно и когда случилось. `Sighting` нёс только предмет: момент знал
/// только вызывающий и приблизительно (наблюдения копятся пачкой), адресата не было — связь
/// «наблюдение ↔ разговор» приделывал снаружи край, и всякий второй потребитель изобретал бы её
/// заново (класс, за который репа заплатила ключом памяти). Имя цели едет параметром, не отдельным
/// запросом (#320, Т5): восстанавливать имя на стороне потребителя запрещено (второй источник
/// правды), но ядро имён не знает и крейт `no_std` без `alloc` — ядро производит `Noted<()>`,
/// плоскость обогащает до `Noted<Box<str>>` (тот же приём, что у [`row::Naming`]/[`row::TargetKey`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Noted<N = ()> {
    pub at: Tick,
    pub about: About,
    /// Что известно о личности цели на момент наблюдения. Три состояния, не `Option`: «имя такое»,
    /// «имени не будет», «имени ещё нет» лечатся по-разному, и `None` с двумя смыслами в приёмочном
    /// приборе дороже всего.
    pub target: row::Naming<N>,
    pub what: Noticed,
}

impl<N> Noted<N> {
    /// Обогатить наблюдение именем — переход `Noted<()> → Noted<Box<str>>` у того, кто имена знает.
    /// Функция принимает различитель и возвращает имя: обогащающий видит, что установило ядро
    /// (`Spoken` против `Silent`), и не может выдать имя там, где приветствие прошло без него
    /// (подстановка имени по адресу и есть подсказка, врущая на общем адресе CDN).
    pub fn named<M>(self, name: impl FnOnce(&row::Naming<N>) -> row::Naming<M>) -> Noted<M> {
        Noted {
            at: self.at,
            about: self.about,
            target: name(&self.target),
            what: self.what,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stepped {
    pub act: Act,
    pub cursor: Cursor,
    pub sighting: Option<Noted>,
}

/// Паспорт наблюдения плоскости — прибор о НАС: что плоскость увидела и сделала, а не какова цель.
pub struct SightingInstrument;

/// Плоскость отвечает на вопросы прибора, не отдавая ему свой тип (инверсия зависимости, §9). Трейт
/// чужой, тип наш — правило сирот разрешает связать их владельцу одного из двух; на вопросы о
/// наблюдении отвечает тот, кто его производит. Прибор (`reflex_instrument::departure`) про
/// `Sighting` не знает, спрашивает два факта; зависимость идёт домен → прибор, и прибор поверяем в
/// изоляции.
impl reflex_instrument::ask::SeveredByPerson for Sighting {
    /// Человек ли оборвал. Ответ из `by_client` — булева флага, и это оставшаяся мина: в словаре
    /// провода флаг заменён на `ResetBy` (человек / сторона цели / мы сами), в наблюдении плоскости
    /// ещё живёт. Пока флаг здесь, «оборвали мы сами» неотличимо от «оборвала цель».
    fn severed_by_person(&self) -> bool {
        matches!(
            self,
            Sighting::Reset {
                by_client: true,
                ..
            }
        )
    }
}

/// Второй вопрос — отдельной реализацией: атомарные вопросы отвечаются по одному, и видно, на какие
/// плоскость отвечать УМЕЕТ. Прибор, попросивший неизвестного ей, не соберётся — вместо выдуманного
/// ответа.
impl reflex_instrument::ask::TargetDelivered for Sighting {
    /// У `Reset` факт назван полем; прочие наблюдения к вопросу об уходе не относятся, и прибор до
    /// них не доходит — второй вопрос только после утвердительного ответа на первый.
    fn target_delivered(&self) -> bool {
        match self {
            Sighting::Reset { target_spoke, .. } => *target_spoke,
            Sighting::Severed { .. }
            | Sighting::Closed { .. }
            | Sighting::Stale { .. }
            | Sighting::Opened { .. }
            | Sighting::Recognised { .. }
            | Sighting::TargetSpoke { .. }
            | Sighting::Peaked { .. } => false,
        }
    }
}

impl SightingInstrument {
    /// Наблюдение уже снято плоскостью — прибор его докладывает, не пересчитывая; момент вшит в само
    /// наблюдение.
    fn read(&self, observation: &Sighting, _now_ms: u64) -> Sighting {
        *observation
    }
}

impl reflex_core::mealy::Mealy for SightingInstrument {
    type In = reflex_core::DetectorEvent<Sighting>;

    /// Слово. Отсутствие слова сигналом не является — прибор высказывается, когда есть что.
    type Out = smallvec::SmallVec<[Sighting; 2]>;

    /// Показаний не заводит: говорит, что увидел, и не говорит, чем мерил.
    type Log = ();

    fn step(self, event: Self::In) -> (Self, Self::Out, ()) {
        match event {
            reflex_core::DetectorEvent::Packet { input, .. } => {
                let reading = self.read(&input, 0);
                (self, smallvec::smallvec![reading], ())
            }
            reflex_core::DetectorEvent::Tick { .. } => (self, smallvec::SmallVec::new(), ()),
            reflex_core::DetectorEvent::Opaque { .. } => (self, smallvec::SmallVec::new(), ()),
            // Прибор докладывает готовое `Sighting`, ничего не считая сам; дыра его не несёт —
            // молчит, как на тике.
            reflex_core::DetectorEvent::Torn { .. } => (self, smallvec::SmallVec::new(), ()),
        }
    }
}

impl reflex_instrument::Instrument for SightingInstrument {
    type Signal = Sighting;

    const INSTRUMENT: &'static str = "sighting";

    const SUBJECT: reflex_instrument::Subject = reflex_instrument::Subject::Ourselves;

    /// Уровень: интерпретация по имени цели — тот же уровень, что у знания.
    const LAYER: reflex_instrument::Layer = reflex_instrument::Layer::Session;
    /// TCP: наблюдения плоскости (стук, ответ, сброс) — улики соединения.
    const PROTOCOLS: &'static [reflex_instrument::Protocol] = &[reflex_instrument::Protocol::Tcp];
    const RUNG: Option<reflex_instrument::Rung> = None;

    /// Пакет: плоскость не имеет состояния, меняющегося САМО — всё, что она знает, приходит с
    /// пакетом. Цена: `Stale`/`Peaked` — исключения (их предмет живёт во времени и в тишине не
    /// наблюдается), решётка у них нулевая, паспорт этого не различает.
    const CADENCE: reflex_instrument::Cadence = reflex_instrument::Cadence::Foreign;

    /// Состояние: у наблюдения есть равенство, `distinct_until_changed` осмыслен (повторный `Peaked`
    /// с тем же темпом сообщения не несёт).
    const SHAPE: reflex_instrument::Shape = reflex_instrument::Shape::State;

    /// Молчание здесь — признание, не пустота: состояние разговора бывает потеряно, и тогда
    /// неизвестно, что применяли. `Blind`, а не `Nothing`: `Nothing` разрешает действовать, `Blind`
    /// требует безопасного умолчания (`Act::Pass`).
    const SILENCE: Option<reflex_instrument::Silence> = Some(reflex_instrument::Silence::Blind);

    const LIES: &'static [&'static str] = &[
        "ОДИН ТЕМП НА ВЕСЬ СЛОВАРЬ. `Stale` и `Peaked` про время, а не про пакет; в тишине они \
         не наступают, хотя предмет их меняется сам. Паспорт этого не выражает, и клетка \
         наблюдаемости перехода у них нулевая при исправной у соседей.",
        "НАБЛЮДЕНИЕ О НАС ЧИТАЕТСЯ КАК НАБЛЮДЕНИЕ О МИРЕ. `Reset` несёт обе половины различения \
         (`by_client`, `target_spoke`), и мост `trouble` берёт из них беду ноги, а мост `left` — \
         переживание человека. Прибор один, предметов два: не назвать это значит однажды \
         вменить цели наш собственный обрыв.",
    ];

    /// Сценарии стенда на разные исходы: чистый проход, тишина цели, обрыв рукопожатия, стойло.
    const ORACLES: &'static [&'static str] = &[
        "pass",
        "sni_drop(rutracker.org)",
        "syn_drop(1.2.3.4)",
        "fatflow(1.2.3.4,16,reply,drop)",
    ];

    /// Смерть: клетка наблюдаемости перехода у `Stale`/`Peaked` перестанет быть нулевой — паспорт
    /// различит темп по каждому исходу, режим лжи снимется.
    const DEATH: &'static str = "клетка наблюдаемости перехода у `Stale`/`Peaked` отлична от нуля";

    /// Публичные имена событий — реестр, снятый с типа: `Debug` сменил бы метку молча. Имя было
    /// одно на девять исходов, а различающая способность, потерянная в последнем шаге, неотличима
    /// от отсутствующей. Перевод существовал в `plane-queue` отдельной функцией; знание, записанное
    /// дважды, расходится молча — теперь оно здесь, журнал зовёт паспорт.
    const EVENTS: &'static [&'static str] = &[
        "opened",
        "target_spoke",
        "reset",
        "closed",
        "recognised",
        "stale",
        "peaked",
        "severed",
    ];

    fn name(signal: &Self::Signal) -> &'static str {
        match signal {
            Sighting::Opened { .. } => "opened",
            Sighting::TargetSpoke { .. } => "target_spoke",
            Sighting::Reset { .. } => "reset",
            Sighting::Closed { .. } => "closed",
            Sighting::Recognised { .. } => "recognised",
            Sighting::Stale { .. } => "stale",
            Sighting::Peaked { .. } => "peaked",
            Sighting::Severed { .. } => "severed",
        }
    }

    fn alarming(signal: &Self::Signal) -> bool {
        let _ = signal;
        false
    }
}

#[cfg(test)]
mod sighting_passport_tests {
    use super::*;
    use reflex_instrument::Instrument;

    /// Паспорт докладывает наблюдение, не пересчитывая. Два исхода: одного мало, чтобы поймать
    /// прибор, возвращающий константу.
    #[test]
    fn the_passport_reports_what_the_plane_saw() {
        let opened = Sighting::Opened {
            dst: Addr(0x0A00_0001),
            basis: Basis::Measured,
        };
        let severed = Sighting::Severed {
            dst: Addr(0x0A00_0002),
        };

        assert_eq!(SightingInstrument.read(&opened, 0), opened);
        assert_eq!(SightingInstrument.read(&severed, 0), severed);
    }

    /// Потеря цели зовётся тем же словом, что печатается, и её имени нет в реестре наблюдений
    /// разговора: адресат иной.
    #[test]
    fn the_loss_opens_with_its_own_name() {
        let evidence = std::format!(
            "{}",
            Lost {
                dst: Addr(0x0A00_0002)
            }
        );
        let word = evidence.split(' ').next().unwrap_or_default();

        assert_eq!(word, Lost::EVENT, "улика и имя события разошлись");
        assert!(
            !SightingInstrument::EVENTS.contains(&Lost::EVENT),
            "потеря цели адресована не разговору — её имени в реестре наблюдений разговора быть \
             не должно"
        );
    }

    /// Клетка молчания — `Blind`, не `Nothing`: `Nothing` разрешает действовать, `Blind` требует
    /// безопасного умолчания. У `Sighting` молчание = «состояние потеряно» — отказ, не пустота.
    #[test]
    fn the_passport_calls_its_silence_blindness() {
        assert_eq!(
            SightingInstrument::SILENCE,
            Some(reflex_instrument::Silence::Blind)
        );
    }

    /// Улика открывается паспортным именем (#325). Разойдись слова — публичный круг получит два
    /// имени одного события. Сверяются ВСЕ исходы: образец-другой пропустил бы расхождение в редкой
    /// ветке, а редкие ветки здесь и есть предмет.
    #[test]
    fn the_evidence_opens_with_the_passport_name() {
        let dst = Addr(0x0A00_0001);
        let alphabet = [
            Sighting::Opened {
                dst,
                basis: Basis::Measured,
            },
            Sighting::TargetSpoke {
                dst,
                after: Span(21),
            },
            Sighting::Reset {
                dst,
                by_client: false,
                target_spoke: true,
            },
            Sighting::Closed {
                dst,
                lasted: Span(9),
                up: 3,
                down: 4,
                down_bytes: 31_744,
            },
            Sighting::Recognised {
                dst,
                said: row::Naming::Spoken(()),
            },
            Sighting::Stale { dst, was: Epoch(2) },
            Sighting::Peaked {
                dst,
                pace: meter::Pace {
                    bytes: 1_024,
                    over_nanos: 1_000,
                },
            },
            Sighting::Severed { dst },
        ];

        assert_eq!(
            alphabet.len(),
            SightingInstrument::EVENTS.len(),
            "образцов столько же, сколько имён в паспорте: иначе сверка молчит о новой ветке"
        );
        alphabet.iter().for_each(|sighting| {
            let evidence = std::format!("{sighting}");
            let word = evidence.split(' ').next().unwrap_or_default();
            assert!(
                SightingInstrument::EVENTS.contains(&word),
                "улика «{evidence}» открывается словом «{word}», которого нет в паспорте"
            );
            assert_eq!(
                word,
                SightingInstrument::name(sighting),
                "улика и паспорт назвали одно наблюдение по-разному"
            );
        });
    }

    /// Улика несёт величину, а не только имя: потеряй `Display` поле `down_bytes`, и цель,
    /// замолчавшая после приветствия, станет неотличима от честно закрытого разговора.
    #[test]
    fn the_evidence_carries_the_number_the_marker_judges_by() {
        let silent = Sighting::Closed {
            dst: Addr(0x8EFA_0101),
            lasted: Span(1_500_000_000),
            up: 7,
            down: 2,
            down_bytes: 0,
        };
        let talked = Sighting::Closed {
            dst: Addr(0x8EFA_0101),
            lasted: Span(1_500_000_000),
            up: 7,
            down: 2,
            down_bytes: 31_744,
        };

        assert_eq!(
            std::format!("{silent}"),
            "closed dst=142.250.1.1 lasted_ns=1500000000 up=7 down=2 down_bytes=0"
        );
        assert_ne!(std::format!("{silent}"), std::format!("{talked}"));
    }
}
