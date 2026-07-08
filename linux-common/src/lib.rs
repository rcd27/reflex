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
}

/// Число слотов `STEER_STATS` (размер Array-карты, общий eBPF↔userspace).
pub const STEER_STAT_SLOTS: u32 = 4;

impl SteerStat {
    /// Человекочитаемая метка слота — userspace-поллер печатает её в лог рига.
    pub fn label(self) -> &'static str {
        match self {
            SteerStat::Seen => "seen",
            SteerStat::Ipv4Tcp => "ipv4_tcp",
            SteerStat::TargetHit => "target_hit",
            SteerStat::Rewritten => "rewritten",
        }
    }

    /// Все слоты по порядку — userspace итерирует для дампа снапшота.
    pub const ALL: [SteerStat; STEER_STAT_SLOTS as usize] = [
        SteerStat::Seen,
        SteerStat::Ipv4Tcp,
        SteerStat::TargetHit,
        SteerStat::Rewritten,
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
