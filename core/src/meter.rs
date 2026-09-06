//! ТЕМП ПО ОКНУ — кольцо временны́х корзин.
//!
//! # Что этим меряется
//!
//! Сумма и длительность вместе не отвечают на вопрос «когда стало плохо»: поток, отдавший мегабайт
//! за две минуты, и поток, отдавший тот же мегабайт за две секунды и потом замерший, неразличимы по
//! обеим величинам — а переживаются противоположно. Кольцо хранит байты по корзинам времени, и
//! окно любой ширины читается из него сложением.
//!
//! # Темп — ТОЧНАЯ ДРОБЬ, а не частное
//!
//! [`Pace`] хранит числитель и знаменатель и сравнивается перекрёстным умножением. Деление здесь
//! было бы не «упрощением», а потерей различающей способности: два байта за три наносекунды и один
//! за две — разные темпы (0,667 против 0,5), а целочисленное частное у обоих ноль, и всякий выбор
//! «кто быстрее» после этого случаен.
//!
//! Оттого же нет и защиты вида «делим на `max(1)`»: она отвечает «за одну наносекунду» там, где
//! честный ответ — «неопределено». Здесь нулевое окно значит бесконечный темп, и он законно
//! обгоняет всякий конечный.
//!
//! # Время — наносекунды в `u64`
//!
//! Не `Instant` и не `Duration`: механизм рассчитан на горячий путь без аллокаций, а обёртывание
//! мгновения в тип принадлежит потребителю, который знает своё начало отсчёта. [`crate::clock`]
//! отвечает на другой вопрос — ОТКУДА берётся время; здесь оно уже пришло значением.
//!
//! # Ширина корзины и глубина кольца — ВЫБРАННЫЕ числа
//!
//! [`BUCKET_SHIFT`] даёт корзину ≈134 мс, [`BUCKETS`] — горизонт ≈8,6 с. Приехали как есть из
//! `dataplane` невода, где стояли без обоснования: замера, из которого они выведены, в дереве
//! нет. Сказано вслух, чтобы читатель не принял их за установленные. Второму потребителю с другим
//! окном понадобится параметризация кольца по длине — она дёшева (`Ring<const N: usize>`), но
//! заводить её под единственного потребителя значило бы платить за неслучившееся.
//!
//! # Откуда приехало (05.09.2026)
//!
//! Из `dataplane` невода, где 20 элементов из 30 не знали о продукте ничего. Продуктовые
//! обёртки (счёт цели, счёт разговора) остались там.

use core::cmp::Ordering;

/// Ширина корзины: `1 << 27` наносекунд ≈ 134 мс.
pub const BUCKET_SHIFT: u32 = 27;

/// Глубина кольца в корзинах. Вместе с [`BUCKET_SHIFT`] даёт горизонт ≈8,6 с.
pub const BUCKETS: usize = 64;

/// НОМЕР КОРЗИНЫ — монотонный, не по кругу. По кругу ходит только [`slot`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Bucket(pub u64);

/// СКОЛЬКО БАЙТ ЗА КАКОЕ ВРЕМЯ — дробь, не частное.
///
/// Сравнение перекрёстным умножением в `u128`: деление потеряло бы различие между близкими
/// темпами, а `u64`-произведение переполнилось бы на больших окнах.
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

/// НАСКОЛЬКО СВЕЖО НАБЛЮДЕНИЕ — в корзинах, а не в секундах.
///
/// `Settled` отделён от `Silent` потому, что «корзина только что закрылась» и «корзин прошло
/// несколько» суть разные основания: по первому величина УЖЕ полная, по второму поток замолчал.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Freshness {
    Live,
    Settled,
    Silent,
}

/// НАЧИСЛЕНИЕ В КОЛЬЦО: куда, сколько и сколько корзин по дороге обязано обнулиться.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Charge {
    pub bucket: Bucket,
    pub clear_back: u8,
    pub bytes: u64,
}

/// КОЛЬЦО КОРЗИН. Ячейки переиспользуются по кругу, поэтому проход по молчанию обязан ЧИСТИТЬ —
/// иначе ячейка отдаёт величину прошлого круга как свежую.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ring {
    pub cells: [u64; BUCKETS],
    pub last: Bucket,
}

/// ЗАПОЛНЕННОСТЬ ХРАНИЛИЩА — сколько держим, сколько влезает, сколько вытеснили.
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

/// Место корзины в кольце. ЗДЕСЬ и только здесь номер идёт по кругу.
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

/// НАЧИСЛИТЬ, ПО ДОРОГЕ ОБНУЛИВ ПРОЙДЕННОЕ В МОЛЧАНИИ.
///
/// Кольцо строится целиком новым, а не правится на месте: результат — функция входа, и это
/// единственное, что делает его проверяемым таблицей.
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

/// ПРОКРУТИТЬ КОЛЬЦО ВПЕРЁД БЕЗ ТРАФИКА. Молчание — тоже наблюдение, и оно обязано двигать голову.
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

/// СЛОЖИТЬ ДВА КОЛЬЦА. Оба сперва прокручиваются к общей голове — иначе складывались бы корзины
/// разных моментов, а результат зависел бы от того, чьё кольцо оказалось свежее.
pub fn merged(one: Ring, other: Ring) -> Ring {
    let last = one.last.max(other.last);
    let left = rolled(one, last);
    let right = rolled(other, last);
    Ring {
        cells: core::array::from_fn(|i| left.cells[i] + right.cells[i]),
        last,
    }
}

/// ТЕМП ЗА ОКНО В `back + 1` КОРЗИН, считая от головы.
///
/// Окно шире кольца зажимается: больше сведений, чем в кольце есть, оно не даёт, а знаменатель
/// вырос бы и темп вышел бы заниженным.
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

/// САМАЯ ПОЛНАЯ ОДНА КОРЗИНА — потолок, которого поток достигал.
pub fn ceiling(ring: &Ring) -> Pace {
    Pace {
        bytes: ring.cells.iter().copied().fold(0u64, u64::max),
        over_nanos: bucket_span_nanos(),
    }
}

pub fn faster(one: Pace, other: Pace) -> Pace {
    one.max(other)
}

/// ОТСТАЁТ ЛИ ПОДОПЫТНЫЙ ОТ ЭТАЛОНА БОЛЕЕ ЧЕМ ВО СТОЛЬКО-ТО РАЗ.
///
/// Умножается ЧИСЛИТЕЛЬ подопытного, а не делится эталон: деление снова потеряло бы точность там,
/// где весь смысл в её сохранении.
pub fn slower_than(subject: Pace, reference: Pace, times: u32) -> bool {
    let scaled = (subject.bytes as u128) * (reference.over_nanos as u128) * (times as u128);
    scaled < (reference.bytes as u128) * (subject.over_nanos as u128)
}

/// ВЫШЛО ЛИ НАБЛЮДЕНИЕ ЗА ГОРИЗОНТ КОЛЬЦА. За ним кольцо о нём уже ничего не помнит.
pub fn expired(last_seen_nanos: u64, now_nanos: u64) -> bool {
    now_nanos.saturating_sub(last_seen_nanos) > horizon_nanos()
}

pub fn room(pressure: &Pressure) -> u32 {
    pressure.capacity.saturating_sub(pressure.held)
}
