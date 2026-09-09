//! Темп по окну — кольцо временны́х корзин. Сумма и длительность вместе не отвечают на «когда стало
//! плохо»: мегабайт за две минуты и за две секунды с последующим молчанием неразличимы по обеим
//! величинам. Кольцо хранит байты по корзинам времени, окно любой ширины читается сложением. Темп —
//! ТОЧНАЯ ДРОБЬ ([`Pace`] хранит числитель и знаменатель, сравнивается перекрёстным умножением): два
//! байта за три наносекунды и один за две — разные темпы, а целочисленное частное у обоих ноль.
//! Оттого нет и «делим на `max(1)`»: нулевое окно значит бесконечный темп, законно обгоняющий всякий
//! конечный. Время — наносекунды в `u64`, не `Instant`/`Duration` (горячий путь без аллокаций;
//! обёртка мгновения принадлежит потребителю, знающему своё начало отсчёта). Ширина корзины
//! ([`BUCKET_SHIFT`] ≈134 мс) и глубина ([`BUCKETS`], горизонт ≈8,6 с) — ВЫБРАННЫЕ числа, замера в
//! дереве нет; сказано, чтобы не принять их за установленные.

use core::cmp::Ordering;

/// Ширина корзины: `1 << 27` наносекунд ≈ 134 мс.
pub const BUCKET_SHIFT: u32 = 27;

/// Глубина кольца в корзинах. Вместе с [`BUCKET_SHIFT`] даёт горизонт ≈8,6 с.
pub const BUCKETS: usize = 64;

/// Номер корзины — монотонный, не по кругу. По кругу ходит только [`slot`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Bucket(pub u64);

/// Сколько байт за какое время — дробь, не частное. Сравнение перекрёстным умножением в `u128`:
/// деление потеряло бы различие близких темпов, `u64`-произведение переполнилось бы на больших окнах.
#[derive(Debug, Clone, Copy)]
pub struct Pace {
    pub bytes: u64,
    pub over_nanos: u64,
}

impl Pace {
    fn crossed(&self, other: &Pace) -> (u128, u128) {
        (
            self.bytes as u128 * other.over_nanos as u128,
            other.bytes as u128 * self.over_nanos as u128,
        )
    }
}

impl PartialEq for Pace {
    fn eq(&self, other: &Pace) -> bool {
        let (mine, theirs) = self.crossed(other);
        mine == theirs
    }
}

impl Eq for Pace {}

impl Ord for Pace {
    fn cmp(&self, other: &Pace) -> Ordering {
        let (mine, theirs) = self.crossed(other);
        mine.cmp(&theirs)
    }
}

impl PartialOrd for Pace {
    fn partial_cmp(&self, other: &Pace) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Насколько свежо наблюдение — в корзинах, не в секундах. `Settled` отделён от `Silent`: «корзина
/// только что закрылась» (величина УЖЕ полная) и «корзин прошло несколько» (поток замолчал) — разные
/// основания.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Freshness {
    Live,
    Settled,
    Silent,
}

/// Начисление в кольцо: куда, сколько и сколько корзин по дороге обязано обнулиться.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Charge {
    pub bucket: Bucket,
    pub clear_back: u8,
    pub bytes: u64,
}

/// Кольцо корзин. Ячейки переиспользуются по кругу, потому проход по молчанию обязан ЧИСТИТЬ —
/// иначе ячейка отдаёт величину прошлого круга как свежую.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ring {
    pub cells: [u64; BUCKETS],
    pub last: Bucket,
}

/// Заполненность хранилища — сколько держим, сколько влезает, сколько вытеснили.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pressure {
    pub held: u32,
    pub capacity: u32,
    pub evicted: u64,
}

pub fn bucket_span_nanos() -> u64 {
    1u64 << BUCKET_SHIFT
}

pub fn horizon_nanos() -> u64 {
    BUCKETS as u64 * bucket_span_nanos()
}

pub fn bucket_of(at_nanos: u64) -> Bucket {
    Bucket(at_nanos >> BUCKET_SHIFT)
}

/// Место корзины в кольце. Здесь и только здесь номер идёт по кругу.
pub fn slot(bucket: Bucket) -> usize {
    (bucket.0 % BUCKETS as u64) as usize
}

pub fn freshness_of(gap: u64) -> Freshness {
    match gap.cmp(&1) {
        Ordering::Less => Freshness::Live,
        Ordering::Equal => Freshness::Settled,
        Ordering::Greater => Freshness::Silent,
    }
}

pub fn charge(last: Bucket, now_nanos: u64, bytes: u64) -> Charge {
    let bucket = bucket_of(now_nanos);
    Charge {
        bucket,
        clear_back: bucket.0.saturating_sub(last.0).min(BUCKETS as u64) as u8,
        bytes,
    }
}

pub fn empty_ring() -> Ring {
    Ring {
        cells: [0u64; BUCKETS],
        last: Bucket(0),
    }
}

/// Начислить, по дороге обнулив пройденное в молчании. Кольцо строится целиком новым: результат —
/// функция входа, это и делает его проверяемым таблицей.
pub fn applied(ring: Ring, charge: Charge) -> Ring {
    let head = slot(charge.bucket);
    Ring {
        cells: core::array::from_fn(|i| {
            let back = (head + BUCKETS - i) % BUCKETS;
            let carried = match back < charge.clear_back as usize {
                true => 0,
                false => ring.cells[i],
            };
            match i == head {
                true => carried + charge.bytes,
                false => carried,
            }
        }),
        last: charge.bucket,
    }
}

/// Прокрутить кольцо вперёд без трафика. Молчание — тоже наблюдение, обязано двигать голову.
pub fn rolled(ring: Ring, to: Bucket) -> Ring {
    applied(
        ring,
        Charge {
            bucket: to,
            clear_back: to.0.saturating_sub(ring.last.0).min(BUCKETS as u64) as u8,
            bytes: 0,
        },
    )
}

/// Сложить два кольца. Оба сперва прокручиваются к общей голове — иначе складывались бы корзины
/// разных моментов, а результат зависел бы от того, чьё кольцо свежее.
pub fn merged(one: Ring, other: Ring) -> Ring {
    let last = one.last.max(other.last);
    let left = rolled(one, last);
    let right = rolled(other, last);
    Ring {
        cells: core::array::from_fn(|i| left.cells[i] + right.cells[i]),
        last,
    }
}

/// Темп за окно в `back + 1` корзин, считая от головы. Окно шире кольца зажимается: больше
/// сведений оно не даёт, а знаменатель вырос бы и темп вышел бы заниженным.
pub fn paced(ring: &Ring, back: u8) -> Pace {
    let head = slot(ring.last);
    let reach = back.min(BUCKETS as u8 - 1);
    Pace {
        bytes: (0..=reach)
            .map(|step| ring.cells[(head + BUCKETS - step as usize) % BUCKETS])
            .sum(),
        over_nanos: (reach as u64 + 1) * bucket_span_nanos(),
    }
}

/// Самая полная одна корзина — потолок, которого поток достигал.
pub fn ceiling(ring: &Ring) -> Pace {
    Pace {
        bytes: ring.cells.iter().copied().fold(0u64, u64::max),
        over_nanos: bucket_span_nanos(),
    }
}

pub fn faster(one: Pace, other: Pace) -> Pace {
    one.max(other)
}

/// Отстаёт ли подопытный от эталона более чем во столько-то раз. Умножается ЧИСЛИТЕЛЬ подопытного,
/// не делится эталон: деление снова потеряло бы точность, в сохранении которой весь смысл.
pub fn slower_than(subject: Pace, reference: Pace, times: u32) -> bool {
    let scaled = (subject.bytes as u128) * (reference.over_nanos as u128) * (times as u128);
    scaled < (reference.bytes as u128) * (subject.over_nanos as u128)
}

/// Вышло ли наблюдение за горизонт кольца. За ним кольцо о нём уже ничего не помнит.
pub fn expired(last_seen_nanos: u64, now_nanos: u64) -> bool {
    now_nanos.saturating_sub(last_seen_nanos) > horizon_nanos()
}

pub fn room(pressure: &Pressure) -> u32 {
    pressure.capacity.saturating_sub(pressure.held)
}
