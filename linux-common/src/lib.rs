#![no_std]

/// Action that XDP program should take for a given flow.
/// Stored in BPF hash map, written by userspace, read by XDP.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FlowAction {
    /// Pass packet through to bridge (default)
    Pass = 0,
    /// Drop packet silently
    Drop = 1,
    /// Copy packet to userspace via perf ring, then drop
    CopyAndDrop = 2,
    /// Заворот целевого флоу в локальную несущую (прозрачный L2-редирект).
    /// Ставится userspace-контролем ЛИШЬ когда несущая готова принять владение
    /// (`steer_fate` Guarded). Механизм заворота в eBPF (bpf_sk_assign/TPROXY vs
    /// veth-redirect) валидируется на R2S-стенде — TODO(BL-215); до валидации eBPF
    /// трактует Steer как Pass (fail-open, чёрной дыры нет).
    Steer = 3,
}

/// Судьба кадра на шве прозрачного L2-перехвата — проекция `model/wire/TransparentIntercept`.
///
/// `Orphaned` (чёрная дыра: снят-с-транзита-но-невладеемый) НЕВЫРАЗИМА типом: инвариант
/// `NoBlackHole` держится конструкцией (Правило 4), не рантайм-сторожем.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Fate {
    /// Остаётся на прозрачном L2-транзите: не-цель, ЛИБО fail-open при неготовой несущей.
    Transit,
    /// Завёрнут в локальную несущую — она приняла владение (→ ByteFlowFloor гарантирует поток).
    Owned,
}

impl Fate {
    /// Проекция судьбы в действие data-plane, что userspace-контроль ставит в ACTION_TABLE.
    pub fn action(self) -> FlowAction {
        match self {
            Fate::Owned => FlowAction::Steer,
            Fate::Transit => FlowAction::Pass,
        }
    }
}

/// Режим лифта (#227) — ЧТО вообще входит в датаплейн. Троичный, а не булев: прежний `STEER_ALL`
/// различал только «всё» и «лишь выученное», и середины — «лишь то, что на карте» — выразить было
/// нечем.
///
/// Тип алгебраический, а не `u8`, хотя в карте лежит именно байт: у байта 256 значений, у решения
/// три смысла, и `match` по числу обязан нести ветку-заглушку, которая молча проглотит опечатку.
/// Разбор вынесен в `steer_mode_of` — там заглушка ровно одна и она НАЗВАНА.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SteerMode {
    /// Лифт лишь для `dst ∈ STEER_TARGETS` — выученного Ловцом. Прежний `STEER_ALL_443=0`.
    Surgical = 0,
    /// Лифт ВСЕГО HTTPS: имя видно только внутри соединения, поэтому вердикт по SNI требует
    /// перехватить всё. Прежний `STEER_ALL_443=1`, и он же FAIL-SAFE (см. `steer_mode_of`).
    All443 = 1,
    /// Лифт по КАРТЕ: `dst ∈ STEER_MAP` (реестр) ∨ `dst ∈ STEER_TARGETS` (выученное). Не на карте —
    /// в датаплейн не входит вовсе: остаётся в L2-мосте на скорости провода, не терминируется нашим
    /// smoltcp, не платит окном гонки.
    ByMap = 2,
}

/// Разбор сырого байта из карты в режим.
///
/// Неизвестный код — `All443`, и это FAIL-SAFE В СТОРОНУ НАЗНАЧЕНИЯ ПРОДУКТА, а не «безопасное
/// значение по умолчанию». Откат в `Surgical` при пустых `STEER_TARGETS` означал бы, что коробка
/// тихо перестала лифтить что-либо: заблокированное не открывается, при этом всё выглядит исправным.
/// Потеря скорости — приемлемый отказ, потеря доступа — нет.
///
/// Ветвление `if`, а не `match`: у `u8` нет исчерпывающего разбора без wildcard, и заглушка,
/// написанная явно и с названной причиной, честнее той же заглушки под видом `_ =>`.
pub fn steer_mode_of(raw: u8) -> SteerMode {
    if raw == SteerMode::Surgical as u8 {
        SteerMode::Surgical
    } else if raw == SteerMode::ByMap as u8 {
        SteerMode::ByMap
    } else {
        SteerMode::All443
    }
}

/// Слоты datapath-счётчиков заворота (`STEER_STATS` Array) — общий контракт eBPF↔userspace
/// (Правило 9: типизированная композиция, не магические индексы). Каждый слот = стадия конвейера
/// `try_steer`; разность соседних слотов показывает, ГДЕ кадры теряются на проводе (Правило 17:
/// наблюдаемость datapath). Порядок = поток кадра сверху вниз.
#[repr(u32)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SteerStat {
    /// Кадр дошёл до ingress-хука вообще (главный неизвестный на мосту: видит ли хук клиентский трафик).
    Seen = 0,
    /// Распарсен как IPv4 + TCP с валидными границами заголовков.
    Ipv4Tcp = 1,
    /// dst ∈ STEER_TARGETS — это целевой (блокируемый) домен (`isTarget`).
    TargetHit = 2,
    /// dst-MAC переписан на MAC моста → кадр уходит НАВЕРХ в L3-стек (там nft DNAT доставит несущей).
    /// Без этого мост форвардит цель по чужому MAC. Разница `TargetHit − Rewritten` = цели, что не
    /// удалось переписать (сбой `bpf_skb_store_bytes`).
    Rewritten = 3,
    /// ЗРЕНИЕ (#249): транзитный (НЕлифтнутый) кадр, чей payload начинается как TLS-рукопожатие —
    /// то есть имя в этом флоу вообще БЫЛО. Знаменатель всей наблюдаемости зрения.
    SightGated = 4,
    /// Копия начала рукопожатия уехала в кольцо — наблюдение состоялось и ждёт разбора.
    SightCopied = 5,
    /// Наблюдение ПОТЕРЯНО на краю: кольцо полно либо копия сорвалась. Отдельный слот, потому что
    /// «имени не было» и «имя было, да мы его не донесли» — РАЗНЫЕ болезни с разным лечением, а
    /// выглядят одинаково: тишина наверху (`SightBeforeSeizure`, витнес обязан различать).
    SightLost = 6,
}

/// Число слотов `STEER_STATS` (размер Array-карты, общий eBPF↔userspace).
pub const STEER_STAT_SLOTS: u32 = 7;

impl SteerStat {
    /// Человекочитаемая метка слота — userspace-поллер печатает её в лог рига.
    pub fn label(self) -> &'static str {
        match self {
            SteerStat::Seen => "seen",
            SteerStat::Ipv4Tcp => "ipv4_tcp",
            SteerStat::TargetHit => "target_hit",
            SteerStat::Rewritten => "rewritten",
            SteerStat::SightGated => "sight_gated",
            SteerStat::SightCopied => "sight_copied",
            SteerStat::SightLost => "sight_lost",
        }
    }

    /// Все слоты по порядку — userspace итерирует для дампа снапшота.
    pub const ALL: [SteerStat; STEER_STAT_SLOTS as usize] = [
        SteerStat::Seen,
        SteerStat::Ipv4Tcp,
        SteerStat::TargetHit,
        SteerStat::Rewritten,
        SteerStat::SightGated,
        SteerStat::SightCopied,
        SteerStat::SightLost,
    ];
}

/// ── АНТИ-ПЕТЛЯ ловца по ЗАРЕЗЕРВИРОВАННОМУ src-порту (проекция `model/wire/SelfLoop.tla` `portmark`,
/// TLC GREEN) ── Direct-проба ловца уходит вниз через роутер-потребитель (default route); тот NAT'ит её
/// и заворачивает обратно в мост (хэйрпин) → она RE-входит в `reflex_steer` на клиент-ingress. Без метки
/// steer лифтит её заново (dst ∈ STEER_TARGETS) → self-loop (шторм, риск брика). МЕТКА: невод биндит
/// пробе src-порт из [`PROBE_PORT_LO`..=`PROBE_PORT_HI`], steer узнаёт хэйрпин-пробу по нему и ПРОПУСКАЕТ.
///
/// ПОЧЕМУ ПОРТ, А НЕ TTL (замер рига 2026-07-08, `SelfLoop.perlegmark-ttl` RED): роутер ДЕКРЕМЕНТИРУЕТ
/// TTL на форварде → сентинел-TTL не переживал NAT-хоп → проба не узнавалась → шторм. А src-порт роутер
/// СОХРАНЯЕТ (замер tcpdump: 39168→39168, port-preserve). `MarkReliable` держится: (1) порт переживает
/// NAT; (2) диапазон [0xFF00..=0xFFFF] ВЫШЕ клиентского эфемерного (`ip_local_port_range` max 60999) →
/// коллизия с клиентом крайне редка (`SelfLoop.portmark-collision` — граница очерчена, не в дизайне;
/// `portmark-symmetric-nat` — если роутер порт НЕ сохранит, гейт на целевом железе перепроверить).
pub const PROBE_PORT_LO: u16 = 0xFF00; // 65280 — низ зарезервированного диапазона пробы
pub const PROBE_PORT_HI: u16 = 0xFFFF; // 65535 — верх

/// Старший байт src-порта пробы НА ПРОВОДЕ (big-endian): весь диапазон [0xFF00..=0xFFFF] имеет hi=0xFF.
/// eBPF сравнивает СЫРОЙ байт (как dport-443) — без `from_ne_bytes`-неоднозначности на bpfel.
pub const PROBE_SPORT_HIBYTE: u8 = 0xFF;

/// userspace-узнавание порта пробы (симметрия контракта eBPF↔nevod; nevod биндит в диапазон).
pub fn is_probe_port(sport: u16) -> bool {
    sport >= PROBE_PORT_LO
}

/// eBPF-узнавание хэйрпин-пробы по СЫРОМУ старшему байту src-порта (big-endian) на проводе. Общий
/// контракт eBPF (гейт лифта) ↔ userspace (nevod биндит src-порт из диапазона `PROBE_PORT_LO..=HI`).
pub fn is_probe_sport_hibyte(hi: u8) -> bool {
    hi == PROBE_SPORT_HIBYTE
}

/// Направление наблюдённого кадра относительно клиента — берётся ИЗ ХУКА, не из эвристики по
/// подсети: на клиент-порту `ingress` = от клиента (Upstream), `egress` = к клиенту (Downstream).
/// Общий контракт eBPF↔userspace (`FlowEvent.dir`).
pub const DIR_UPSTREAM: u8 = 0; // клиент → сервер (SYN, ClientHello)
pub const DIR_DOWNSTREAM: u8 = 1; // сервер → клиент (SYN-ACK, данные, RST)

/// Маски TCP-флагов в `FlowEvent.flags` (общий контракт eBPF↔userspace). Ровно те флаги, что
/// `inline_reach` фолдит в `Wire`: SYN (рукопожатие), ACK, RST (reset), FIN (закрытие).
pub const TCP_SYN: u8 = 1 << 0;
pub const TCP_ACK: u8 = 1 << 1;
pub const TCP_RST: u8 = 1 << 2;
pub const TCP_FIN: u8 = 1 << 3;

/// Событие наблюдённого TCP-кадра проходящего флоу — общий wire-тип eBPF↔userspace, эмитится
/// `reflex_observe` в `RingBuf`, потребляется userspace-witness'ом (`inline_witness` в неводе).
/// `#[repr(C)]` + фикс-раскладка (16 байт, без padding): eBPF пишет байты, userspace читает тем же
/// типом. Один backend, ДВА фолда (Правило 9): `flags`+`payload_len>0` → `inline_reach` (достижимость
/// сейчас); `payload_len` суммарно → `ByteFlow`/троттлинг (throughput позже).
///
/// Все многобайтовые поля — network order (`__be`, как на проводе): userspace канонизирует при чтении.
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct FlowEvent {
    pub src: u32,         // __be32 client-IP (Upstream) / server-IP (Downstream) — src кадра
    pub dst: u32,         // __be32 — dst кадра; вердикт агрегируется по цели у потребителя
    pub sport: u16,       // __be16
    pub dport: u16,       // __be16
    pub payload_len: u16, // L7-байты сегмента (0 = чистый ACK/handshake); суммарно = throughput
    pub flags: u8,        // TCP_SYN|TCP_ACK|TCP_RST|TCP_FIN
    pub dir: u8,          // DIR_UPSTREAM | DIR_DOWNSTREAM (из хука)
}

impl FlowEvent {
    pub fn has_syn(&self) -> bool {
        self.flags & TCP_SYN != 0
    }
    pub fn has_ack(&self) -> bool {
        self.flags & TCP_ACK != 0
    }
    pub fn has_rst(&self) -> bool {
        self.flags & TCP_RST != 0
    }
    pub fn has_payload(&self) -> bool {
        self.payload_len > 0
    }
    pub fn is_upstream(&self) -> bool {
        self.dir == DIR_UPSTREAM
    }
}

/// Сколько байт начала рукопожатия копирует ЗРЕНИЕ.
///
/// БЫЛО 512 И ЭТО ОКАЗАЛОСЬ ДОПУЩЕНИЕМ, А НЕ ЗАМЕРОМ (13.08.2026, коробка владельца): исходный
/// довод звучал как «у живого браузера имя лежит в пределах первых ~300 байт», и он не выдержал
/// поля — при ТОЧНОМ гейте ClientHello доля наблюдений без имени осталась половиной (21 из 45).
/// Порядок расширений в ClientHello у современных браузеров СЛУЧАЕН, а post-quantum `key_share`
/// (X25519MLKEM768) весит больше килобайта: попав перед SNI, он уносит имя за любой потолок,
/// выбранный «на глаз».
///
/// 2048 — тоже потолок, а не гарантия, и потому рядом живёт счётчик `sight_truncated`: наблюдение,
/// скопированное РОВНО до потолка, помечается как возможно урезанное. Без него «имя зашифровано
/// (ECH)» и «имя не поместилось» неразличимы, а от их суммы зависит условие смерти механизма.
pub const SIGHT_BYTES: usize = 2048;

/// Ниже этого копировать нечего: TLS-запись с ClientHello и SNI короче 64 байт не бывает
/// (одни только record+handshake-заголовки и random занимают 43). Кадр короче — рукопожатие,
/// разорванное по сегментам; наблюдается как потеря, а не как «имени не было».
pub const SIGHT_MIN: usize = 64;

/// НАБЛЮДЕНИЕ (`model/molecule/SightBeforeSeizure`, переменная `sightings`) — копия начала
/// рукопожатия ТРАНЗИТНОГО флоу, того самого, который мы решили НЕ лифтить. Наш «лист 0» из канона
/// ТСПУ (`docs/tspu-docs/chapters/08.md`): распознаём, фиксируем, кадр не трогаем.
///
/// ОТДЕЛЬНЫЙ тип и ОТДЕЛЬНОЕ кольцо, а не поле в `FlowEvent`: тот несёт два фолда (достижимость и
/// ByteFlow), его `repr(C)`-раскладка в 16 байт зафиксирована тестом, и полкилобайта на КАЖДЫЙ
/// наблюдённый кадр — это тот же лифт, только в кольце.
///
/// Наблюдение ПЕРЕЖИВАЕТ флоу (найдено моделью: `tobe` краснел, пока наблюдение уходило вместе с
/// закрывшимся соединением). Оттого здесь лежит цель, а не ссылка на живой флоу: знание добыто и
/// потоку больше не принадлежит.
///
/// Все многобайтовые поля — network order (`__be`, как на проводе): userspace канонизирует.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct Sighting {
    pub dst: u32,   // __be32 — цель
    pub src: u32,   // __be32 — КЛИЕНТ: адресат лечения (см. `DeadHandshakeReopen`, ось Cure)
    pub seq: u32,   // __be32 — seq этого ClientHello
    pub ack: u32,   // __be32 — номер, которого КЛИЕНТ ждёт от сервера
    pub dport: u16, // __be16 — порт цели (443; поле есть, чтобы не додумывать)
    pub sport: u16, // __be16 — эфемерный порт клиента: вторая половина 4-tuple
    pub len: u16,   // сколько байт из `bytes` РЕАЛЬНО скопировано (≤ SIGHT_BYTES)
    // Padding ЯВНЫЙ: выравнивание структуры 4, заголовок без него весит 22 байта, и компилятор
    // добил бы хвост молча. Молчаливый padding в типе, который eBPF пишет, а userspace читает, —
    // это разъезжающийся `bytes` и мусор вместо имени.
    pub _pad: u16,
    pub bytes: [u8; SIGHT_BYTES], // сырое начало upstream-payload: TLS-запись с ClientHello
}

impl Sighting {
    /// Скопированные байты — ровно `len`, не весь буфер. Хвост буфера не инициализирован ничем
    /// осмысленным, и отдать его разборщику значило бы кормить парсер мусором прошлой записи.
    pub fn payload(&self) -> &[u8] {
        let end = if (self.len as usize) < SIGHT_BYTES {
            self.len as usize
        } else {
            SIGHT_BYTES
        };
        &self.bytes[..end]
    }
}

/// ГЕЙТ ЗРЕНИЯ (eBPF, горячий путь): начинается ли payload именно с ClientHello. Три байта из
/// шести: тип записи (0x16 = Handshake), старший байт версии (0x03) и тип рукопожатия на пятом
/// байте (0x01 = ClientHello).
///
/// ПЯТЫЙ БАЙТ ДОБАВЛЕН ПО ЗАМЕРУ В ПОЛЕ (13.08.2026, коробка владельца, 0.3.5): без него гейт
/// пропускал наверх ЛЮБУЮ handshake-запись клиента, и `sight_unnamed` составил 23 из 45 — больше
/// половины наблюдений. Цена была названа заранее («разборщик её отбросит и посчитает как имя не
/// извлеклось»), но в бумаге она выглядела краевым случаем, а в поле съела половину предмета: у
/// TLS 1.2 клиент шлёт ClientKeyExchange и Finished тем же типом 0x16.
///
/// Различение здесь НЕ косметика: пока в `unnamed` смешаны «это была не та запись» и «имя
/// зашифровано (ECH)», условие смерти механизма («доля извлечённых имён ниже половины») меряется
/// по замусоренному знаменателю и сработает по ложной причине.
pub fn looks_like_client_hello(payload: &[u8]) -> bool {
    payload.len() >= 6 && payload[0] == 0x16 && payload[1] == 0x03 && payload[5] == 0x01
}

/// Guarded-решение перехвата (`model/wire/TransparentIntercept`, `.tobe` GREEN): снимаем кадр
/// с транзита ЛИШЬ при готовой несущей; не-цель никогда не снимаем (Surgical); не готова —
/// fail-open на транзит (закон невода). Чистая функция свежих наблюдений, без снапшота-веры.
pub fn steer_fate(is_target: bool, carrier_ready: bool) -> Fate {
    match (is_target, carrier_ready) {
        (false, _) => Fate::Transit, // Surgical: не-цель НИКОГДА не снимается с транзита
        (true, true) => Fate::Owned, // цель + несущая готова → заворот в движок
        (true, false) => Fate::Transit, // fail-open: несущая не готова → транзит, не дыра
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Проекция `model/wire/TransparentIntercept` (`.tobe` Guarded GREEN). Таблица
    // истинности атома — те же 4 строки, что исчерпывающе обошёл TLC.

    /// Три режима — три смысла, и код читается из карты как СЫРОЙ байт. Разбор обязан быть
    /// тотальным, потому что у байта 256 значений, а смыслов три.
    #[test]
    fn each_known_code_means_its_own_mode() {
        assert_eq!(steer_mode_of(0), SteerMode::Surgical);
        assert_eq!(steer_mode_of(1), SteerMode::All443);
        assert_eq!(steer_mode_of(2), SteerMode::ByMap);
    }

    /// FAIL-SAFE В СТОРОНУ НАЗНАЧЕНИЯ: неизвестный код (опечатка конфига, старый userspace против
    /// нового eBPF) — это `All443`, а НЕ `Surgical`. Разница не стилистическая: `Surgical` при пустой
    /// карте не лифтит ничего, то есть коробка тихо перестаёт открывать заблокированное и выглядит
    /// исправной. Потеря скорости — приемлемый отказ, потеря доступа — нет.
    #[test]
    fn an_unknown_code_falls_back_to_lifting_everything() {
        assert_eq!(steer_mode_of(3), SteerMode::All443);
        assert_eq!(steer_mode_of(255), SteerMode::All443);
    }

    #[test]
    fn surgical_non_target_always_transit() {
        // Surgical: не-цель НИКОГДА не снимается с прозрачного транзита (урок BL-108).
        assert_eq!(steer_fate(false, false), Fate::Transit);
        assert_eq!(steer_fate(false, true), Fate::Transit);
    }

    #[test]
    fn guarded_fail_open_when_carrier_not_ready() {
        // NoBlackHole: цель при НЕготовой несущей → транзит (fail-open), не чёрная дыра.
        assert_eq!(steer_fate(true, false), Fate::Transit);
    }

    #[test]
    fn target_owned_when_carrier_ready() {
        // Reach: цель + готовая несущая → заворот (несущая владеет).
        assert_eq!(steer_fate(true, true), Fate::Owned);
    }

    #[test]
    fn steer_stat_slots_are_dense_and_ordered() {
        // Контракт eBPF↔userspace: ALL перечисляет ровно STEER_STAT_SLOTS слотов, а дискриминант
        // каждого = его позиция (плотная индексация Array-карты, без дыр).
        assert_eq!(SteerStat::ALL.len(), STEER_STAT_SLOTS as usize);
        for (idx, stat) in SteerStat::ALL.iter().enumerate() {
            assert_eq!(
                *stat as u32,
                idx as u32,
                "слот {} не на своём индексе",
                stat.label()
            );
        }
    }

    #[test]
    fn fate_projects_to_flow_action() {
        // Owned → Steer (eBPF заворачивает); Transit → Pass (fast-path транзит).
        assert_eq!(Fate::Owned.action(), FlowAction::Steer);
        assert_eq!(Fate::Transit.action(), FlowAction::Pass);
    }

    #[test]
    fn probe_port_range_recognizes_hairpin_not_clients() {
        // Проба биндит src-порт из [PROBE_PORT_LO..=PROBE_PORT_HI]; роутер СОХРАНЯЕТ порт через NAT
        // (замер: 39168→39168) → узнаётся по нему на хэйрпине.
        assert!(is_probe_port(PROBE_PORT_LO), "низ диапазона");
        assert!(is_probe_port(PROBE_PORT_HI), "верх диапазона");
        assert!(is_probe_port(65400), "внутри диапазона");
        // Весь диапазон имеет старший байт провода 0xFF — eBPF матчит его сырым.
        assert!(is_probe_sport_hibyte(PROBE_SPORT_HIBYTE));
        assert_eq!((PROBE_PORT_LO >> 8) as u8, PROBE_SPORT_HIBYTE);
        assert_eq!((PROBE_PORT_HI >> 8) as u8, PROBE_SPORT_HIBYTE);
        // Клиентские эфемерные порты (ip_local_port_range, дефолт 32768..60999) НИКОГДА не в диапазоне
        // (иначе резали бы клиента — ClientStillSteered). Их старший байт < 0xFF.
        assert!(!is_probe_port(32768) && !is_probe_port(60999));
        assert!(!is_probe_sport_hibyte((60999 >> 8) as u8)); // 0xEE ≠ 0xFF
        assert!(
            !is_probe_port(PROBE_PORT_LO - 1),
            "ниже диапазона — не проба"
        );
    }

    #[test]
    fn sighting_layout_is_fixed() {
        // Тот же контракт, что у FlowEvent: eBPF пишет байты, userspace читает ТЕМ ЖЕ типом.
        // Заголовок 24 байта + буфер, padding ЯВНЫЙ (`_pad`), иначе `bytes` разъедется между
        // сторонами: у структуры выравнивание 4, и неявный хвост компилятор вставил бы молча.
        assert_eq!(core::mem::size_of::<Sighting>(), 24 + SIGHT_BYTES);
        assert_eq!(core::mem::align_of::<Sighting>(), 4);
    }

    /// НАБЛЮДЕНИЕ АДРЕСУЕТ ПОТОК, А НЕ ЦЕЛЬ (#249, срез 1).
    ///
    /// Замер 14.08 показал: у GGC-кэша цензор решает ОДИН РАЗ НА ПОТОК, и проигравший поток мёртв
    /// навсегда (13 из 20 флоу молчали 20 секунд при ~85 ретрансмитах). Значит лечение обращается
    /// не к цели, а к КЛИЕНТУ в его собственном потоке — а для этого нужны обе стороны 4-tuple.
    ///
    /// Номер, которого клиент ждёт от сервера, достаётся ДАРОМ: это поле `ack` того самого
    /// ClientHello. Без него любой кадр, посланный клиенту от имени сервера, лёг бы вне окна и был
    /// бы отброшен молча — то есть лечение выглядело бы применённым и не применялось.
    #[test]
    fn sighting_addresses_the_flow_not_just_the_target() {
        let s = Sighting {
            // `.to_be()` — потому что поле хранит ПРОВОДНОЙ порядок (`__be32`), ровно как его
            // кладёт eBPF. Собрать значение «как в жизни» и забыть про это — обычный способ
            // получить зелёный тест на данных, которых на проводе не бывает.
            dst: u32::from_be_bytes([128, 75, 236, 12]).to_be(),
            src: u32::from_be_bytes([192, 168, 2, 50]).to_be(),
            seq: 1000u32.to_be(),
            ack: 7777u32.to_be(),
            dport: 443u16.to_be(),
            sport: 51000u16.to_be(),
            len: 0,
            _pad: 0,
            bytes: [0; SIGHT_BYTES],
        };

        assert_eq!(
            (u32::from_be(s.src), u16::from_be(s.sport)),
            (u32::from_be_bytes([192, 168, 2, 50]), 51000),
            "адресат лечения — клиент, и он обязан быть в наблюдении"
        );
        assert_eq!(
            u32::from_be(s.ack),
            7777,
            "номер, которого клиент ждёт от сервера: кадр вне окна клиент отбросит молча"
        );
    }

    #[test]
    fn sighting_payload_is_only_what_was_copied() {
        // Короткое рукопожатие: отдаём ровно скопированное, а не весь буфер. Хвост — мусор
        // прошлой записи кольца, и скормить его парсеру значило бы читать чужое имя.
        let head = [0x16u8, 0x03, 0x01];
        let s = Sighting {
            dst: 0,
            src: 0,
            seq: 0,
            ack: 0,
            dport: 0,
            sport: 0,
            len: 3,
            _pad: 0,
            // Хвост заполнен мусором намеренно: тест обязан отличить «скопировано 3» от «отдали всё».
            bytes: core::array::from_fn(|i| match head.get(i) {
                Some(b) => *b,
                None => 0xAA,
            }),
        };
        assert_eq!(s.payload(), &head);

        // Битая запись (len врёт больше буфера) не должна ронять разборщик: обрезаем по буферу.
        let broken = Sighting {
            dst: 0,
            src: 0,
            seq: 0,
            ack: 0,
            dport: 0,
            sport: 0,
            len: u16::MAX,
            _pad: 0,
            bytes: [0; SIGHT_BYTES],
        };
        assert_eq!(broken.payload().len(), SIGHT_BYTES);
    }

    #[test]
    fn sight_gate_admits_client_hello_and_rejects_the_rest() {
        // ClientHello: запись 0x16, версия 0x03xx, тип рукопожатия 0x01 на пятом байте.
        assert!(looks_like_client_hello(&[
            0x16, 0x03, 0x01, 0x02, 0x00, 0x01
        ]));
        // ЗАМЕР В ПОЛЕ (0.3.5): клиентские записи TLS 1.2 — ClientKeyExchange (0x10) и Finished
        // (0x14) — идут ТЕМ ЖЕ типом 0x16 и раньше проходили гейт, давая половину `unnamed`.
        assert!(!looks_like_client_hello(&[
            0x16, 0x03, 0x03, 0x00, 0x46, 0x10
        ]));
        assert!(!looks_like_client_hello(&[
            0x16, 0x03, 0x03, 0x00, 0x20, 0x14
        ]));
        // ApplicationData (0x17) — уже установленная сессия, имени там нет.
        assert!(!looks_like_client_hello(&[
            0x17, 0x03, 0x03, 0x00, 0x20, 0x01
        ]));
        // 0x16 без версии TLS — не рукопожатие, а совпадение первого байта.
        assert!(!looks_like_client_hello(&[
            0x16, 0x00, 0x01, 0x02, 0x00, 0x01
        ]));
        // Короче шести байт: тип рукопожатия ещё не виден — судить не о чем.
        assert!(!looks_like_client_hello(&[]));
        assert!(!looks_like_client_hello(&[0x16, 0x03, 0x01, 0x02, 0x00]));
    }

    #[test]
    fn flow_event_layout_is_fixed_16_bytes() {
        // Контракт eBPF↔userspace: eBPF пишет байты, userspace читает тем же типом — раскладка
        // обязана быть фиксированной и без padding (иначе поля разъедутся между сторонами).
        assert_eq!(core::mem::size_of::<FlowEvent>(), 16);
        assert_eq!(core::mem::align_of::<FlowEvent>(), 4);
    }

    #[test]
    fn flow_event_reads_flags_and_dir() {
        // SYN-ACK downstream с payload=0 (рукопожатие): has_syn+has_ack, не upstream, нет payload.
        let synack = FlowEvent {
            src: 0,
            dst: 0,
            sport: 0,
            dport: 0,
            payload_len: 0,
            flags: TCP_SYN | TCP_ACK,
            dir: DIR_DOWNSTREAM,
        };
        assert!(synack.has_syn() && synack.has_ack());
        assert!(!synack.has_rst() && !synack.has_payload());
        assert!(!synack.is_upstream());

        // ClientHello upstream (payload>0): upstream, payload есть, флаг ACK.
        let hello = FlowEvent {
            src: 0,
            dst: 0,
            sport: 0,
            dport: 0,
            payload_len: 517,
            flags: TCP_ACK,
            dir: DIR_UPSTREAM,
        };
        assert!(hello.is_upstream() && hello.has_payload());
        assert!(!hello.has_syn());
    }
}
