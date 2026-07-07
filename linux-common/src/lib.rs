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
}
