//! Счёт цели и коробки. Кольцо временны́х корзин уехало в фундамент (это механизм измерения темпа
//! по окну, нужный всякому наблюдателю потока); здесь — обёртки, знающие наш предмет: `Target`,
//! `Tally` и правила начисления по `Packet`/`Run`.

use crate::{Dir, Packet, Plan, Run, Span, Tick};

pub use reflex_core::meter::{
    applied, ceiling, empty_ring, faster, freshness_of, merged, paced, rolled, room, slot,
    slower_than, Bucket, Charge, Freshness, Pace, Pressure, Ring, BUCKETS, BUCKET_SHIFT,
};

/// Ширина корзины в нашей единице времени. Фундамент считает наносекундами (не знает, от чего мы
/// считаем начало); адаптер один и здесь.
pub fn bucket_span() -> Span {
    Span(reflex_core::meter::bucket_span_nanos())
}

pub fn horizon() -> Span {
    Span(reflex_core::meter::horizon_nanos())
}

/// Адаптеры нашей единицы времени: три функции, принимающие `Tick` — те, что зовутся снаружи (иначе
/// `.0` расползлось бы по вызывающим).
pub fn bucket_of(now: Tick) -> Bucket {
    reflex_core::meter::bucket_of(now.0)
}

pub fn charge(last: Bucket, now: Tick, bytes: u64) -> Charge {
    reflex_core::meter::charge(last, now.0, bytes)
}

pub fn expired(last_seen: Tick, now: Tick) -> bool {
    reflex_core::meter::expired(last_seen.0, now.0)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Target {
    pub up_bytes: u64,
    pub down_bytes: u64,
    pub bucket: Bucket,
    pub bucket_bytes: u64,
    pub settled_bytes: u64,
    pub best: Pace,
    pub last_seen: Tick,
    pub flows: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Charged {
    pub target: Target,
    pub peaked: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tally {
    pub up_bytes: u64,
    pub down_bytes: u64,
    pub packets: u64,
    pub flows_opened: u64,
    pub flows_lost: u64,
    pub since: Tick,
}

/// Счёт коробки — молчащий наблюдатель горячего пути. Слово `()` (счёт не адресован никому,
/// `Nobody`), счёт уходит показанием. Буква та же, что у решения: байты считаются с того же пакета,
/// что несёт вердикт, — своя буква разошлась бы с решением. План в букве не читается, но стоит в
/// подписи: соседство требует одной буквы ([`reflex_core::mealy::Pair`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Counting(pub Tally);

impl Counting {
    /// Пустой счёт.
    pub fn fresh() -> Counting {
        Counting(Tally {
            up_bytes: 0,
            down_bytes: 0,
            packets: 0,
            flows_opened: 0,
            flows_lost: 0,
            since: Tick(0),
        })
    }
}

impl reflex_core::mealy::Mealy for Counting {
    type In = (Plan, Packet, Tick);
    type Out = ();
    type Log = Tally;

    fn step(self, (_plan, packet, now): Self::In) -> (Self, (), Tally) {
        let tally = self.0;
        let size = packet.payload_len as u64;
        let counted = Tally {
            up_bytes: match packet.dir {
                Dir::Up => tally.up_bytes + size,
                Dir::Down => tally.up_bytes,
            },
            down_bytes: match packet.dir {
                Dir::Up => tally.down_bytes,
                Dir::Down => tally.down_bytes + size,
            },
            packets: tally.packets + 1,
            flows_opened: tally.flows_opened + u64::from(packet.opens),
            // Потери считает не эта буква: разговор теряется на тике уборки, не на пакете.
            flows_lost: tally.flows_lost,
            // Момент первого пакета — начало отсчёта, дальше не двигается.
            since: match tally.packets == 0 {
                true => now,
                false => tally.since,
            },
        };
        (Counting(counted), (), counted)
    }
}

pub fn fresh_target(now: Tick) -> Target {
    Target {
        up_bytes: 0,
        down_bytes: 0,
        bucket: bucket_of(now),
        bucket_bytes: 0,
        settled_bytes: 0,
        best: Pace {
            bytes: 0,
            over_nanos: bucket_span().0,
        },
        last_seen: now,
        flows: 0,
    }
}

pub fn charged_target(target: Target, packet: &Packet, now: Tick) -> Charged {
    let size = packet.payload_len as u64;
    let down = match packet.dir {
        Dir::Down => size,
        Dir::Up => 0,
    };
    let up = match packet.dir {
        Dir::Up => size,
        Dir::Down => 0,
    };
    let bucket = bucket_of(now);
    let (settled, opening) = match freshness_of(bucket.0.saturating_sub(target.bucket.0)) {
        Freshness::Live => (target.settled_bytes, target.bucket_bytes),
        Freshness::Settled => (target.bucket_bytes, 0),
        Freshness::Silent => (0, 0),
    };
    let best = faster(
        target.best,
        Pace {
            bytes: settled,
            over_nanos: bucket_span().0,
        },
    );
    Charged {
        target: Target {
            up_bytes: target.up_bytes + up,
            down_bytes: target.down_bytes + down,
            bucket,
            bucket_bytes: opening + down,
            settled_bytes: settled,
            best,
            last_seen: now,
            flows: match packet.opens {
                true => target.flows + 1,
                false => target.flows,
            },
        },
        peaked: best > target.best,
    }
}

pub fn closed_target(target: Target) -> Target {
    Target {
        flows: target.flows.saturating_sub(1),
        ..target
    }
}

pub fn target_pace(target: &Target, now: Tick) -> Pace {
    Pace {
        bytes: match freshness_of(bucket_of(now).0.saturating_sub(target.bucket.0)) {
            Freshness::Live => target.settled_bytes,
            Freshness::Settled => target.bucket_bytes,
            Freshness::Silent => 0,
        },
        over_nanos: bucket_span().0,
    }
}

pub fn flow_pace(run: &Run, now: Tick) -> Pace {
    Pace {
        bytes: run.down_bytes,
        over_nanos: now.0.saturating_sub(run.began.0),
    }
}
