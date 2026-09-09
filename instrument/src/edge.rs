//! Кодек марки края: фаза, оттиск и тег писателя под МАСКОЙ-ПАРАМЕТРОМ. Фреймворк не знает соседа
//! по машине — маска приходит снаружи, чужие биты вне неё переживают наш шаг (read-modify-write).
//!
//! Раскладка внутри маски, от её младшего бита вверх: **тег 4, фаза 3, оттиск 8** — итого 15 бит.
//! Тег внизу не произвол: он читается первым и решает, доверять ли остальным полям; лежи он сверху,
//! у младшей границы маски оказался бы оттиск, где чужая запись «на бит мимо» тихо испортила бы
//! точку отсчёта вместо того, чтобы объявиться чужой. У границы стоит то, чья порча немедленно видна.

const TAG_BITS: u32 = 4;
const PHASE_BITS: u32 = 3;
const IMPRINT_BITS: u32 = 8;
/// Все 15 бит полей (тег+фаза+оттиск) от нулевого бита — до сдвига на младший бит маски.
const FIELD: u32 = (1 << (TAG_BITS + PHASE_BITS + IMPRINT_BITS)) - 1;

/// Раскладка марки: какие биты наши (`mask`) и чем подписан их писатель (`tag`, 4 бита, ненулевой).
/// Маска — параметр цепочки, не константа фреймворка.
#[derive(Debug, Clone, Copy)]
pub struct Layout {
    pub mask: u32,
    pub tag: u8,
}

/// Фаза наблюдения за разговором. Значения плотные от нуля — укладываются в 3 бита.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Quiet,
    Suspected,
    Confirmed,
    Released,
}

/// Что мы оставили на разговоре: фаза и оттиск (младшие биты счётчика ответов на момент постановки).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Memo {
    pub phase: Phase,
    pub imprint: u8,
}

/// Что прочли из марки. `Foreign` — не ошибка и не пустота, а заселённая клетка входа: по нашим
/// битам писал другой агент (тег не наш), и это наблюдение, на которое прибор вправе среагировать.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Recall {
    Ours(Memo),
    Foreign { theirs: u32 },
}

impl Phase {
    fn code(self) -> u32 {
        match self {
            Phase::Quiet => 0,
            Phase::Suspected => 1,
            Phase::Confirmed => 2,
            Phase::Released => 3,
        }
    }

    fn of_code(code: u32) -> Phase {
        match code {
            1 => Phase::Suspected,
            2 => Phase::Confirmed,
            3 => Phase::Released,
            // 0 и неназванные 4..7 — «ничего не сказано»: наши записи дают лишь 0..3, тег уже сверен.
            _quiet_or_unnamed => Phase::Quiet,
        }
    }
}

impl Layout {
    fn shift(&self) -> u32 {
        self.mask.trailing_zeros()
    }

    /// Предпосылки раскладки — не тихое обрезание, а отказ (`debug_assert`, как согласовано): тег
    /// ненулевой и 4-битный, маска вмещает все 15 бит полей от своего младшего бита.
    fn checked(&self) {
        debug_assert!(
            self.tag != 0 && (self.tag as u32) < (1 << TAG_BITS),
            "тег писателя обязан быть ненулевым и 4-битным: нулевой прочёл бы пустое слово \
             «нашим», широкий залез бы в фазу"
        );
        let field = FIELD << self.shift();
        debug_assert!(
            field & self.mask == field,
            "маска обязана вмещать 15 бит (тег 4 + фаза 3 + оттиск 8); у́же — молча обрезала бы \
             старший бит оттиска"
        );
    }

    /// Записать памятку под маской, сохранив чужие биты (read-modify-write). Тег писателя — наш.
    pub fn write(&self, word: u32, memo: Memo) -> u32 {
        self.checked();
        let packed = (self.tag as u32)
            | (memo.phase.code() << TAG_BITS)
            | ((memo.imprint as u32) << (TAG_BITS + PHASE_BITS));
        (word & !self.mask) | ((packed << self.shift()) & self.mask)
    }

    /// Прочесть марку. Сперва тег: не наш — `Foreign` (остальным полям веры нет, они чужие).
    pub fn read(&self, word: u32) -> Recall {
        self.checked();
        let packed = (word & self.mask) >> self.shift();
        let tag = (packed & ((1 << TAG_BITS) - 1)) as u8;
        if tag != self.tag {
            return Recall::Foreign { theirs: word };
        }
        let phase = Phase::of_code((packed >> TAG_BITS) & ((1 << PHASE_BITS) - 1));
        let imprint = ((packed >> (TAG_BITS + PHASE_BITS)) & ((1 << IMPRINT_BITS) - 1)) as u8;
        Recall::Ours(Memo { phase, imprint })
    }
}
