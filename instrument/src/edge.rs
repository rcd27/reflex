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
/// Маска — параметр цепочки, не константа фреймворка. Поля приватны: единственная дверь — [`new`],
/// проверяющая предпосылки. `Layout { .. }` мимо неё непредставимо, потому `write`/`read` чисты и
/// невозможного состояния не встречают (в отличие от `debug_assert`, исчезающего в release).
///
/// [`new`]: Layout::new
#[derive(Debug, Clone, Copy)]
pub struct Layout {
    mask: u32,
    tag: u8,
}

/// Фаза наблюдения за разговором. Значения плотные от нуля — укладываются в 3 бита.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Quiet,
    Suspected,
    Confirmed,
    Released,
}

/// Что мы оставили на разговоре: фаза, оттиск (младшие биты счётчика ответов) и РАСКЛАДКА, под
/// которой они лягут. Раскладку памятка носит с собой: спуск `descends` параметра не принимает, а
/// упаковать без маски нельзя — зато кодек остаётся ОДИН (`under_bits`), и два входа (`Layout::write`
/// и `descends`) не разойдутся молча.
///
/// Сравнение НЕ смотрит на раскладку: две памятки, отличающиеся лишь маской, для `Changes` (повтор
/// наблюдения) — одна и та же, иначе смена соседа по машине читалась бы как новое наблюдение.
#[derive(Debug, Clone, Copy)]
pub struct Memo {
    layout: Layout,
    pub phase: Phase,
    pub imprint: u8,
}

impl PartialEq for Memo {
    fn eq(&self, other: &Self) -> bool {
        self.phase == other.phase && self.imprint == other.imprint
    }
}

impl Eq for Memo {}

impl Memo {
    /// Памятка под конкретной раскладкой.
    pub fn new(layout: Layout, phase: Phase, imprint: u8) -> Memo {
        Memo {
            layout,
            phase,
            imprint,
        }
    }

    /// Наши биты, уложенные под маской (без чужого слова — его добавит `apply_to` read-modify-write).
    pub fn under(&self) -> u32 {
        under_bits(&self.layout, self.phase, self.imprint)
    }

    /// Маска, под которой лежат наши биты.
    pub fn mask(&self) -> u32 {
        self.layout.mask
    }

    /// Наложить памятку на прочитанное слово (read-modify-write): чужие биты вне маски целы.
    /// Пишет ПАМЯТКА, не `Layout`: раскладка одна — та, с которой памятка родилась, второй взяться
    /// неоткуда, потому разойтись нечему (прежний `Layout::write` держал две — свою и памятки).
    pub fn apply_to(self, word: u32) -> u32 {
        (word & !self.mask()) | self.under()
    }
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

/// Все 15 бит полей (тег+фаза+оттиск).
const FIELD_BITS: u32 = TAG_BITS + PHASE_BITS + IMPRINT_BITS;

/// ЕДИНЫЙ кодек: наши биты (тег+фаза+оттиск), уложенные под маской. Один — потому что второй
/// разошёлся бы молча; его зовут оба входа — `Layout::write` и спуск `Memo::descends` (через
/// `Memo::under`).
fn under_bits(layout: &Layout, phase: Phase, imprint: u8) -> u32 {
    let packed = (layout.tag as u32)
        | (phase.code() << TAG_BITS)
        | ((imprint as u32) << (TAG_BITS + PHASE_BITS));
    (packed << layout.shift()) & layout.mask
}

impl Layout {
    /// Единственная дверь. Отказ — ЗНАЧЕНИЕ (`None`), не тихое обрезание: тег обязан быть ненулевым
    /// и 4-битным (иначе пустое слово прочлось бы «нашим», а широкий тег залез бы в фазу); маска
    /// обязана вмещать все 15 бит полей ОДНИМ куском от своего младшего бита. `field & mask == field`
    /// ловит и узкую маску, и ПРЕРЫВИСТУЮ (дырка в маске — данные писались бы мимо, читались мусором).
    /// Проверка здесь, а не в `write`/`read`: это свойство ПАРАМЕТРА, проверяемое при рождении, а не
    /// на каждом пакете горячего пути.
    pub fn new(mask: u32, tag: u8) -> Option<Layout> {
        let tag_ok = tag != 0 && (tag as u32) < (1 << TAG_BITS);
        let shift = mask.trailing_zeros();
        // 15 бит обязаны уместиться выше младшего бита маски, иначе сдвиг вышел бы за `u32`.
        let fits = shift + FIELD_BITS <= u32::BITS;
        let mask_ok = fits && {
            let field = FIELD << shift;
            field & mask == field
        };
        (tag_ok && mask_ok).then_some(Layout { mask, tag })
    }

    /// Наши биты марки — для края (сохранить чужое вне маски он умеет по этому же числу).
    pub fn mask(&self) -> u32 {
        self.mask
    }

    fn shift(&self) -> u32 {
        self.mask.trailing_zeros()
    }

    /// Прочесть марку. Сперва тег: не наш — `Foreign` (остальным полям веры нет, они чужие).
    pub fn read(&self, word: u32) -> Recall {
        let packed = (word & self.mask) >> self.shift();
        let tag = (packed & ((1 << TAG_BITS) - 1)) as u8;
        if tag != self.tag {
            return Recall::Foreign { theirs: word };
        }
        let phase = Phase::of_code((packed >> TAG_BITS) & ((1 << PHASE_BITS) - 1));
        let imprint = ((packed >> (TAG_BITS + PHASE_BITS)) & ((1 << IMPRINT_BITS) - 1)) as u8;
        Recall::Ours(Memo::new(*self, phase, imprint))
    }
}
