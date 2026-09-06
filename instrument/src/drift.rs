//! ДРЕЙФ ВО ВРЕМЕНИ — сдвинулось ли покрытие против собственного ряда наблюдений.
//!
//! # Что переехало, а что осталось
//!
//! Сюда — ТОЧКА, ВЕРДИКТ и СРАВНЕНИЕ: они чисты и проверяются таблицей. В `zond` остались чтение
//! и запись ряда: файл есть хранилище, а прибор хранилищем не занимается — иначе его нельзя
//! поверить, не заведя файловой системы.
//!
//! Граница проходит ровно там, где кончается вычисление и начинается IO, и она же есть ответ на
//! вопрос «почему прибор не читает свой ряд сам»: читатель ряда может быть каким угодно, а
//! правило сравнения — одно.

/// Одна точка ряда: что мерили и что получили.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Point {
    /// Секунды эпохи — прибор не толкует часовые пояса, толкует читатель.
    pub at: u64,
    pub technique: String,
    pub profile: String,
    /// Знаменатель — цели с живым DNS на момент прогона. Он тоже плывёт, и сравнивать доли
    /// без него значило бы принять смену выборки за смену ТСПУ.
    pub alive: usize,
    pub pierced: usize,
    pub clean: usize,
    pub content: usize,
}

impl Point {
    pub fn to_row(&self) -> String {
        format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}",
            self.at,
            self.technique,
            self.profile,
            self.alive,
            self.pierced,
            self.clean,
            self.content
        )
    }

    pub fn from_row(row: &str) -> Option<Point> {
        let fields: Vec<&str> = row.split('\t').collect();
        match fields.as_slice() {
            [at, technique, profile, alive, pierced, clean, content] => Some(Point {
                at: at.parse().ok()?,
                technique: (*technique).to_string(),
                profile: (*profile).to_string(),
                alive: alive.parse().ok()?,
                pierced: pierced.parse().ok()?,
                clean: clean.parse().ok()?,
                content: content.parse().ok()?,
            }),
            _не_та_арность => None,
        }
    }
}

/// Вердикт сравнения свежей точки с рядом.
///
/// `Eq` здесь нет намеренно: вердикт несёт разброс — величину с плавающей точкой, у которой
/// равенства не бывает. Тесты сравнивают вердикт по варианту, а не по числу.
#[derive(Debug, Clone, PartialEq)]
pub enum Shift {
    /// Ряда нет или он короче двух точек — сравнивать не с чем, и это НЕ «всё хорошо».
    NoSeries { points_count: usize },
    /// Отклонение в пределах наблюдаемого разброса. Дрейфом не называется.
    WithinNoise { deviation: i64, spread: f64 },
    /// Отклонение превышает утроенный разброс — вот это уже стоит смотреть.
    Shifted { deviation: i64, spread: f64 },
}

/// Сравнить свежее покрытие с рядом ПО ТОЙ ЖЕ технике и профилю.
///
/// Сравнивается доля, а не абсолют: знаменатель (живых целей) меняется от прогона к прогону, и
/// абсолютное число упало бы вместе с ним, не сказав ничего о ТСПУ.
pub fn compare(series: &[Point], fresh: &Point) -> Shift {
    let own: Vec<f64> = series
        .iter()
        .filter(|t| t.technique == fresh.technique && t.profile == fresh.profile && t.alive > 0)
        .map(|t| t.clean as f64 / t.alive as f64)
        .collect();
    match own.len() < 2 {
        true => Shift::NoSeries {
            points_count: own.len(),
        },
        false => {
            let mean = own.iter().sum::<f64>() / own.len() as f64;
            let variance = own.iter().map(|d| (d - mean).powi(2)).sum::<f64>() / own.len() as f64;
            let spread = variance.sqrt();
            let fresh_share = fresh.clean as f64 / fresh.alive.max(1) as f64;
            let deviation = ((fresh_share - mean) * fresh.alive as f64).round() as i64;
            // ТРИ СИГМЫ, и порог назван здесь, а не в голове читателя отчёта. При нулевом
            // разбросе (ряд из одинаковых точек) любое отличие — уже сдвиг.
            let threshold = 3.0 * spread * fresh.alive as f64;
            match (deviation.abs() as f64) > threshold.max(0.5) {
                true => Shift::Shifted { deviation, spread },
                false => Shift::WithinNoise { deviation, spread },
            }
        }
    }
}

/// ПАСПОРТ РЯДА ПРОГОНОВ — проекция `model/law/Instrument.tla`.
///
/// ЕДИНСТВЕННЫЙ ПРИБОР ПАРКА, ЧЕЙ ПРЕДМЕТ ЕСТЬ СМЕНА, А НЕ СОСТОЯНИЕ. Все прочие отвечают «как
/// сейчас»; этот — «меняется ли со временем». Одиночный прогон на второй вопрос ответить не может
/// НИКАК, и ровно поэтому спор о дрейфе ТСПУ был спором о вере: у обеих сторон не было ряда.
pub struct HistoryInstrument;

impl HistoryInstrument {
    /// Момент не используется: ряд сам есть время. Отличие от прочих приборов в том, что здесь
    /// время выражено ПОРЯДКОМ точек, а не отметкой.
    fn read(&self, observation: &(Vec<Point>, Point), _now_ms: u64) -> Shift {
        let (series, fresh) = observation;
        compare(series, fresh)
    }
}

impl reflex_core::step::Step for HistoryInstrument {
    /// НАБЛЮДЕНИЕ, которое подают прибору.
    type From = reflex_core::DetectorEvent<(Vec<Point>, Point)>;

    /// ПОКАЗАНИЕ. Отсутствие показания сигналом не является: прибор высказывается, когда есть что
    /// сказать, и «ничего не случилось» не занимает места в ленте.
    type To = smallvec::SmallVec<[Shift; 2]>;

    fn step(self, event: Self::From) -> (Self, Self::To) {
        match event {
            reflex_core::DetectorEvent::Packet { input, .. } => {
                let reading = self.read(&input, 0);
                (self, smallvec::smallvec![reading])
            }
            reflex_core::DetectorEvent::Tick { .. } => (self, smallvec::SmallVec::new()),
        }
    }
}

impl crate::Instrument for HistoryInstrument {
    type Signal = Shift;

    const INSTRUMENT: &'static str = "history";

    const SUBJECT: crate::Subject = crate::Subject::World;

    /// УРОВЕНЬ: ряд вердиктов по цели во времени: ключ ряда — имя, то есть сеансовый уровень.
    const LAYER: crate::Layer = crate::Layer::Session;
    /// УЛИКИ НА ПРОВОДЕ НЕТ: предмет — ряд вердиктов по цели во времени, а вердикт не пакет.
    const PROTOCOLS: &'static [crate::Protocol] = &[];
    const RUNG: Option<crate::Rung> = None;

    /// РЯД МЕЖДУ ПРОГОНАМИ — единственный такой темп в парке. Дрейф ТСПУ меняется в часах, и
    /// суточный прогон его ловит: наблюдаемость перехода здесь исправна, потому что темп прибора
    /// НЕ МЕДЛЕННЕЕ темпа предмета.
    const CADENCE: crate::Cadence = crate::Cadence::Series;

    /// РЯД: композиция есть конкатенация, и одна точка не значит ничего.
    const SHAPE: crate::Shape = crate::Shape::Series;

    /// `NoSeries` — «сравнивать не с чем», и это `Blind`, а не `Nothing`: отсутствие ряда есть
    /// факт О ПРИБОРЕ. Прочитать его как «дрейфа нет» значило бы выдать собственную немоту за
    /// спокойствие мира.
    const SILENCE: Option<crate::Silence> = Some(crate::Silence::Blind);

    const LIES: &'static [&'static str] = &[
        "СРАВНИВАЕТ ДОЛЮ, А НЕ АБСОЛЮТ, и это лечение прошлой беды: знаменатель (живых целей) \
         меняется от прогона к прогону, и абсолютное число упало бы вместе с ним, не сказав о ТСПУ \
         ничего.",
        "ПОРОГ — УТРОЕННЫЙ РАЗБРОС, и он не защищает от СВЕРХБИНОМИАЛЬНОСТИ. Замер показал \
         дисперсию ×1,55 против биномиальной: изменчивость сидит во ВРЕМЕНИ, а не в пробах, и \
         больше проб её не лечат. Порог, поставленный по разбросу проб, окажется у́же настоящего.",
        "РЯД ЖИВЁТ ФАЙЛОМ И ПЕРЕЖИВАЕТ КОД. Точка, записанная старой техникой под тем же именем, \
         сравнивается со свежей как своя — а измеряют они разное. Сверка идёт по имени техники и \
         профиля, но не по их версии.",
    ];

    const ORACLES: &'static [&'static str] = &["pass", "sni_drop(rutracker.org)"];

    /// СМЕРТЬ: точка ряда несёт версию техники — тогда третий режим лжи умирает, и ряд перестаёт
    /// склеивать несравнимое.
    const DEATH: &'static str = "точка ряда несёт версию техники, а не только её имя";

    /// ПУБЛИЧНЫЕ ИМЕНА СОБЫТИЙ — реестр, снятый с типа: за границей процесса имя показания не
    /// сторожит компилятор, и `Debug` сменил бы метку молча (#321).
    const EVENTS: &'static [&'static str] =
        &["drift_no_series", "drift_within_noise", "drift_shifted"];

    fn name(signal: &Self::Signal) -> &'static str {
        match signal {
            Shift::NoSeries { .. } => "drift_no_series",
            Shift::WithinNoise { .. } => "drift_within_noise",
            Shift::Shifted { .. } => "drift_shifted",
        }
    }

    fn alarming(signal: &Self::Signal) -> bool {
        match signal {
            Shift::Shifted { .. } => true,
            Shift::WithinNoise { .. } | Shift::NoSeries { .. } => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn point(at: u64, clean: usize) -> Point {
        Point {
            at,
            technique: "prepend-disorder".to_string(),
            profile: "default".to_string(),
            alive: 289,
            pierced: clean,
            clean,
            content: 163,
        }
    }

    /// Строка ряда переживает круг «записал — прочитал». Формат — контракт с будущим собой:
    /// ряд читается через недели, когда о его устройстве уже никто не помнит.
    #[test]
    fn a_point_survives_write_and_read() {
        let original = point(1_756_000_000, 259);
        let parsed = Point::from_row(&original.to_row());
        assert_eq!(parsed, Some(original));
        assert_eq!(
            Point::from_row("at\tтехника\tпрофиль\tживых\tпробито\tчисто\tресурс"),
            None
        );
        assert_eq!(Point::from_row("мусор"), None);
    }

    /// РЯД КОРОЧЕ ДВУХ ТОЧЕК — это «сравнивать не с чем», а НЕ «всё хорошо». Слить два состояния
    /// значило бы объявить стабильность в первый же день наблюдения.
    #[test]
    fn an_empty_series_claims_no_stability() {
        assert!(matches!(
            compare(&[], &point(3, 259)),
            Shift::NoSeries { points_count: 0 }
        ));
        assert!(matches!(
            compare(&[point(1, 259)], &point(2, 259)),
            Shift::NoSeries { points_count: 1 }
        ));
    }

    /// Колебание в пределах наблюдённого разброса дрейфом НЕ называется.
    #[test]
    fn a_swing_within_the_noise_is_not_drift() {
        let series = vec![point(1, 259), point(2, 261), point(3, 258), point(4, 260)];
        let verdict = compare(&series, &point(5, 260));
        assert!(matches!(verdict, Shift::WithinNoise { .. }), "{verdict:?}");
    }

    /// Падение вдесятеро больше разброса — сдвиг. Именно это и есть предмет спора о дрейфе:
    /// прибор обязан уметь его ПОКАЗАТЬ, иначе спор остаётся спором о вере.
    #[test]
    fn a_drop_far_beyond_the_noise_is_a_shift() {
        let series = vec![point(1, 259), point(2, 260), point(3, 259), point(4, 260)];
        let verdict = compare(&series, &point(5, 120));
        match verdict {
            Shift::Shifted { deviation, .. } => {
                assert!(deviation < -100, "{deviation}")
            }
            otherwise => panic!("ожидался сдвиг, получено {otherwise:?}"),
        }
    }

    /// Точки ЧУЖОЙ техники в сравнение не входят: у каждой свой уровень, и смешать их значило бы
    /// объявить дрейфом смену страты.
    #[test]
    fn a_foreign_technique_is_not_compared() {
        let foreign_one = Point {
            technique: "multisplit".to_string(),
            clean: 38,
            ..point(1, 38)
        };
        assert!(matches!(
            compare(&[foreign_one.clone(), foreign_one], &point(2, 259)),
            Shift::NoSeries { points_count: 0 }
        ));
    }
}

#[cfg(test)]
mod history_passport_tests {
    use super::*;
    use crate::Instrument;

    fn point(pierced: usize) -> Point {
        Point {
            at: 0,
            technique: "split".into(),
            profile: "default".into(),
            alive: 100,
            pierced,
            clean: pierced,
            content: pierced,
        }
    }

    /// ПУСТОЙ РЯД — НЕ «ВСЁ ХОРОШО». Прибор обязан сказать, что сравнивать не с чем: прочитать
    /// его немоту как спокойствие мира — ровно та подмена, ради которой клетка `Blind` заведена.
    #[test]
    fn an_empty_series_is_blindness_not_calm() {
        let reading = HistoryInstrument.read(&(Vec::new(), point(50)), 0);
        assert!(matches!(reading, Shift::NoSeries { .. }));
        assert_eq!(HistoryInstrument::SILENCE, Some(crate::Silence::Blind));
    }

    /// ЕДИНСТВЕННЫЙ ПРИБОР ПАРКА С ТЕМПОМ «РЯД». Его наблюдаемость перехода исправна не по
    /// случайности: дрейф ТСПУ меняется в часах, суточный прогон не медленнее предмета.
    #[test]
    fn the_series_instrument_is_the_only_one_of_its_cadence() {
        assert_eq!(HistoryInstrument::CADENCE, crate::Cadence::Series);
        assert!(HistoryInstrument::LIES
            .iter()
            .any(|lie| lie.contains("СВЕРХБИНОМИАЛЬНОСТИ")));
    }
}
