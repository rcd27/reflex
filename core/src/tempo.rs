//! ТЕМП ПОТОКА — как события шли во времени, а не сколько их было.
//!
//! # Зачем примитив
//!
//! Сумма и длительность вместе НЕ отвечают на вопрос «когда стало плохо». Поток, отдавший
//! мегабайт за две минуты, и поток, отдавший тот же мегабайт за две секунды и потом замерший,
//! неразличимы по обеим величинам — а переживаются противоположно.
//!
//! # Что меряется
//!
//! * `first_at` — момент первого события (от него считается время до первого отклика);
//! * `max_gap` — самая длинная пауза МЕЖДУ событиями;
//! * темп по окнам — минимум и максимум, чтобы «всегда медленно» отличалось от «просело».
//!
//! # Чистый
//!
//! Ни IO, ни часов внутри: момент приходит аргументом, состояние возвращается новым. Оттого
//! прибор проверяется таблицей, без рантайма и без ожидания.
//!
//! # Чего здесь нет
//!
//! Понятия «запрос» и «ответ»: пауза при молчащем потребителе и пауза при ждущем — разные вещи,
//! но различить их можно, только зная, кто чего просил. Это знание домена, и `Tempo` его не
//! имеет; потребитель надстраивает его сверху.

use std::time::{Duration, Instant};

/// Наблюдение за темпом одного потока. Значение, а не машина с мутацией.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tempo {
    started: Instant,
    first_at: Option<Instant>,
    last_event: Instant,
    max_gap: Duration,
    window: Duration,
    window_start: Instant,
    window_units: u64,
    windows: u32,
    min_rate: Option<u64>,
    max_rate: u64,
}

impl Tempo {
    /// Прибор заводится в момент начала наблюдения.
    ///
    /// Пауза до первого события считается ОТСЮДА: иначе время до первого отклика было бы
    /// неотличимо от нуля у потока, молчавшего с рождения.
    ///
    /// `window` — за сколько считается темп. Меньше — шум пакетизации, больше — теряется пауза,
    /// которую потребитель уже почувствовал.
    pub fn started(at: Instant, window: Duration) -> Self {
        Self {
            started: at,
            first_at: None,
            last_event: at,
            max_gap: Duration::ZERO,
            window,
            window_start: at,
            window_units: 0,
            windows: 0,
            min_rate: None,
            max_rate: 0,
        }
    }

    /// Пришло `units` единиц (байт, сообщений — чего угодно) в момент `at`.
    pub fn saw(self, units: u64, at: Instant) -> Self {
        let gap = at.saturating_duration_since(self.last_event);
        Self {
            first_at: self.first_at.or(Some(at)),
            last_event: at,
            max_gap: match gap > self.max_gap {
                true => gap,
                false => self.max_gap,
            },
            window_units: self.window_units + units,
            ..self
        }
        .close_due_windows(at)
    }

    /// Время идёт, событий нет.
    ///
    /// Без этого пауза становилась бы видна лишь ПОСЛЕ того, как поток наконец ожил, — то есть
    /// ровно тогда, когда потребитель уже ушёл.
    pub fn idle(self, at: Instant) -> Self {
        let gap = at.saturating_duration_since(self.last_event);
        Self {
            max_gap: match gap > self.max_gap {
                true => gap,
                false => self.max_gap,
            },
            ..self
        }
        .close_due_windows(at)
    }

    /// Единицы, добытые ДО начала наблюдения. Поток уже отвечал — значит первого события
    /// потребитель дождался, и приписывать ему ожидание с нуля нельзя.
    pub fn with_prefix(self, units: u64) -> Self {
        match units == 0 {
            true => self,
            false => Self {
                first_at: self.first_at.or(Some(self.started)),
                window_units: self.window_units + units,
                ..self
            },
        }
    }

    /// Закрыть ВСЕ окна, чей срок вышел, — а не одно.
    ///
    /// ЦЕНА ОДНОГО ОКНА, оплаченная полем: редакция, закрывавшая по одному, схлопывала
    /// сорокасекундную паузу в ОДНО окно, куда попадали единицы и до паузы, и после. Прибор
    /// показывал высокий темп ровно там, где потребитель смотрел на замерший экран. Пустые окна
    /// паузы обязаны быть посчитаны: они и есть провал.
    fn close_due_windows(self, at: Instant) -> Self {
        match at.saturating_duration_since(self.window_start) >= self.window {
            false => self,
            true => {
                let rate = self.window_units * 1000 / self.window.as_millis().max(1) as u64;
                Self {
                    window_start: self.window_start + self.window,
                    window_units: 0,
                    windows: self.windows + 1,
                    min_rate: Some(match self.min_rate {
                        Some(m) if m <= rate => m,
                        Some(_) | None => rate,
                    }),
                    max_rate: match rate > self.max_rate {
                        true => rate,
                        false => self.max_rate,
                    },
                    ..self
                }
                // Хвост паузы длиннее окна закроет следующее — пустым, и так до текущего момента.
                .close_due_windows(at)
            }
        }
    }

    /// Сколько ждали первого события.
    ///
    /// `None` — событий не было вовсе, и это ДРУГОЙ факт, чем «ждали долго»: подменять его
    /// числом значило бы стереть разницу между «медленно» и «никогда».
    pub fn time_to_first(&self) -> Option<Duration> {
        self.first_at
            .map(|t| t.saturating_duration_since(self.started))
    }

    /// Самая длинная пауза, ЗАФИКСИРОВАННАЯ к концу наблюдения.
    pub fn max_gap(&self) -> Duration {
        self.max_gap
    }

    /// Пауза с учётом ТЕКУЩЕГО момента: хвостовая тишина, ещё не закрытая событием.
    pub fn max_gap_now(&self, now: Instant) -> Duration {
        let tail = now.saturating_duration_since(self.last_event);
        match tail > self.max_gap {
            true => tail,
            false => self.max_gap,
        }
    }

    /// Минимальный и максимальный темп по закрытым окнам, единиц в секунду.
    ///
    /// `None` — ни одно окно не закрылось: наблюдение короче окна, и говорить о темпе нечего.
    pub fn rate_range(&self) -> Option<(u64, u64)> {
        self.min_rate.map(|min| (min, self.max_rate))
    }

    /// Сколько окон закрыто. Нужно тому, кто отличает «мерили мало» от «темп ровный».
    pub fn windows(&self) -> u32 {
        self.windows
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const W: Duration = Duration::from_millis(1500);

    fn at(base: Instant, ms: u64) -> Instant {
        base + Duration::from_millis(ms)
    }

    /// Время до первого события считается от НАЧАЛА наблюдения, а не от первого события.
    #[test]
    fn time_to_first_counts_from_the_start_of_watching() {
        let base = Instant::now();
        let t = Tempo::started(base, W).saw(100, at(base, 400));
        assert_eq!(t.time_to_first(), Some(Duration::from_millis(400)));
    }

    /// СОБЫТИЙ НЕ БЫЛО — это не «ждали ноль», а другой факт, и тип его называет.
    #[test]
    fn no_events_is_not_a_zero_wait() {
        let base = Instant::now();
        let t = Tempo::started(base, W).idle(at(base, 9000));
        assert_eq!(t.time_to_first(), None);
    }

    /// ГЛАВНОЕ: длинная пауза закрывает ВСЕ просроченные окна, а не одно.
    ///
    /// Редакция, закрывавшая по одному, схлопывала паузу в единственное окно вместе с единицами
    /// до и после — и показывала высокий темп там, где поток стоял.
    #[test]
    fn a_long_pause_closes_every_window_it_spans() {
        let base = Instant::now();
        let t = Tempo::started(base, W)
            .saw(1_500_000, at(base, 100))
            // Сорок секунд тишины.
            .idle(at(base, 40_000));

        assert!(
            t.windows() >= 26,
            "закрыто окон: {} — пауза схлопнулась",
            t.windows()
        );
        assert_eq!(
            t.rate_range().map(|(min, _)| min),
            Some(0),
            "среди окон обязано быть пустое: оно и есть провал"
        );
    }

    /// КОНТРОЛЬ: ровный поток пустых окон не даёт.
    #[test]
    fn a_steady_stream_has_no_empty_windows() {
        let base = Instant::now();
        let steady = (1..=20).fold(Tempo::started(base, W), |t, n| {
            t.saw(1_500_000, at(base, n * 500))
        });
        assert!(steady.rate_range().is_some_and(|(min, _)| min > 0));
    }

    /// Темпа нет, пока не закрылось ни одно окно: говорить о скорости по огрызку нельзя.
    #[test]
    fn no_rate_before_the_first_window_closes() {
        let base = Instant::now();
        let t = Tempo::started(base, W).saw(100, at(base, 10));
        assert_eq!(t.rate_range(), None);
    }

    /// Хвостовая тишина видна ДО того, как поток ожил.
    #[test]
    fn the_tail_of_silence_is_visible_before_the_stream_revives() {
        let base = Instant::now();
        let t = Tempo::started(base, W).saw(10, at(base, 100));
        assert_eq!(t.max_gap(), Duration::from_millis(100));
        assert_eq!(
            t.max_gap_now(at(base, 5_000)),
            Duration::from_millis(4_900),
            "пауза, которая ЕЩЁ идёт, обязана быть видна"
        );
    }

    /// Единицы, добытые до начала наблюдения, не дают приписать ожидание с нуля.
    #[test]
    fn a_prefix_means_the_first_event_was_already_seen() {
        let base = Instant::now();
        let t = Tempo::started(base, W).with_prefix(4096);
        assert_eq!(t.time_to_first(), Some(Duration::ZERO));
    }
}
