//! Часы — единственный источник времени и единственный источник тика. Закон уже был записан для
//! записи (`crate::pcap::with_ticks`: «живой провод тиков не несёт… часы добавляет источник, иначе
//! всякий потребитель напишет своё»), но не для живого провода — замер нашёл СЕМНАДЦАТЬ мест вне
//! тестов, порождающих время самостоятельно, в пяти формах. Следствие у человека: где `Tick`
//! вычисляется внутри обработчика пакета, нет пакетов — время стоит, и всё, что заводилось ради
//! тишины (`Freshness::Silent`, `meter::expired`, устаревание, потеря цели), в тишине не срабатывает
//! — мёртвая нога умирает именно тогда, когда трафика нет. Часы здесь — трейт, системные живут в
//! `reflex-runtime` (ядро не знает рантайма). Ловушка виртуальных часов названа, потому что оплачена
//! (#287): виртуальное время доказывает «сколько прошло», но не «оператор проснулся» — рядом с
//! проверкой на [`TestClock`] обязан стоять контроль на РЕАЛЬНЫХ часах (здесь его нет: реальных часов
//! в этом крейте нет вовсе).

use core::time::Duration;
use std::time::Instant;

use futures::Stream;

/// Откуда берётся время и кто порождает его в тишине. `now` отвечает «который час» тому, у кого уже
/// есть повод спросить; `ticks` порождает повод в молчании. Часы отдаются потребителю ЗНАЧЕНИЕМ, не
/// из глобального `Instant::now()` — иначе тест не может двигать время.
pub trait Clock: Clone {
    fn now(&self) -> Instant;
}

/// Часы, будящие поток — для живущих в асинхронном рантайме. Отдельно от [`Beats`]: ждать можно двумя
/// несовместимыми способами (отдав управление рантайму или заняв поток); часы, умеющие оба, тянут
/// рантайм, а плоскость его не тянет (синхронна, performance-first).
pub trait Ticks: Clock {
    /// Поток моментов с шагом `every` — время, порождаемое в тишине. Бесконечен: часы не кончаются
    /// оттого, что кончился трафик; заканчивает его потребитель, роняя приёмник. Поток берёт у часов
    /// КОПИЮ (`use<Self>` захватывает только тип часов, без `&self`): часы отдаются значением,
    /// реализация, которой понадобилось бы `&self` внутри потока, сломается здесь же, у объявления.
    fn ticks(&self, every: Duration) -> impl Stream<Item = Instant> + Unpin + use<Self>;
}

/// Часы, будящие поток исполнения — для тех, у кого рантайма нет. Итератор, не поток: у синхронного
/// потребителя некому отдать управление, ожидание есть занятие своего потока (так живёт плоскость —
/// тред, чьё единственное дело двигать время).
pub trait Beats: Clock {
    /// Моменты сетки по мере наступления. Бесконечны по той же причине, что и [`Ticks::ticks`].
    fn beats(&self, every: Duration) -> impl Iterator<Item = Instant>;
}

/// Часы, которые двигает тест. Спать не умеют: сценарий во времени пишется как сценарий
/// (`сделал → продвинул → проверил`), прогон занимает столько, сколько вычисление. Тики идут по
/// сетке ОТ НАЧАЛА, не от последнего продвижения (иначе два продвижения по полшага не дают тика,
/// хотя шаг прошёл).
#[derive(Clone)]
pub struct TestClock {
    began: Instant,
    /// Сколько времени продвинуто с начала. Состояние разделяемое: тест двигает, поток читает.
    ///
    /// ЗАМКОМ, А НЕ АТОМИКОМ, и `Duration`, а не наносекундами. Здесь стоял `AtomicU64` — и он
    /// уносил ВЕСЬ КРЕЙТ на целях без 64-битных атомиков: `mips`, `mipsel`, `powerpc`. Модуль
    /// публичный (рядом боевой [`OsClock`]), поэтому тестовый дубль компилировался в каждой
    /// релизной сборке потребителя и отнимал у него три архитектуры — ради кода, который тот не
    /// исполняет никогда. Воспроизведено 12.09.2026: `cargo check -p reflex-core --target
    /// powerpc-unknown-linux-gnu` → `cannot find AtomicU64 in atomic`.
    ///
    /// Наносекунды были СЛЕДСТВИЕМ атомика («`Duration` не атомарен») — со снятием атомика повод
    /// считать в них исчез, и хранится теперь сам `Duration`: пропало приведение `as u64` заодно.
    /// Замок здесь ничего не стоит: часы тестовые, а спор за них идёт раз в продвижение.
    ///
    /// НЕ `AtomicUsize`, хотя он напрашивается первым: на 32-битной цели это 32 бита, и счётчик
    /// наносекунд переполнится через 4,3 секунды модельного времени. Сборка позеленела бы, а тесты
    /// стали бы тихо неверными — цена хуже той, что чинили.
    passed: std::sync::Arc<std::sync::Mutex<Duration>>,
}

impl TestClock {
    pub fn new() -> TestClock {
        TestClock {
            began: Instant::now(),
            passed: std::sync::Arc::new(std::sync::Mutex::new(Duration::ZERO)),
        }
    }

    /// Начало отсчёта этих часов. Нужен тому, кто проверяет ПОЛОЖЕНИЕ событий на сетке: без начала
    /// моменты сравнивать не с чем, а `Instant::now()` рядом мерил бы сценарий двумя часами.
    pub fn began(&self) -> Instant {
        self.began
    }

    /// Продвинуть время. Всё, что должно случиться за `span`, случается.
    pub fn advance(&self, span: Duration) {
        *self.passed.lock().expect("часы теста не отравлены") += span;
    }

    fn elapsed(&self) -> Duration {
        *self.passed.lock().expect("часы теста не отравлены")
    }
}

impl Default for TestClock {
    fn default() -> TestClock {
        TestClock::new()
    }
}

impl Clock for TestClock {
    fn now(&self) -> Instant {
        self.began + self.elapsed()
    }
}

impl TestClock {
    /// Сколько тиков сетки наступило к этому моменту. Закон сетки общий для всех часов ([`crate::grid`]);
    /// здесь была своя копия, отвечавшая на нулевой шаг `u64::MAX` («очень много» вместо «сетки нет»).
    fn due(&self, every: Duration) -> u64 {
        crate::grid::due(self.began, self.now(), every)
    }

    /// Момент `n`-го тика сетки. От начала: два тика одним продвижением обязаны иметь разное время,
    /// иначе интервал между ними станет нулём.
    fn beat_at(&self, every: Duration, nth: u64) -> Instant {
        crate::grid::node(self.began, every, nth)
    }
}

impl Beats for TestClock {
    /// Тики уже наступившие, и ни одного сверх. Итератор КОНЧАЕТСЯ, когда время догнало сетку — в
    /// отличие от системных, которым ждать некого. Сценарий не страдает: пишется как «продвинул,
    /// потом собрал».
    fn beats(&self, every: Duration) -> impl Iterator<Item = Instant> {
        let clock = self.clone();
        (1..=self.due(every)).map(move |nth| clock.beat_at(every, nth))
    }
}

impl Ticks for TestClock {
    fn ticks(&self, every: Duration) -> impl Stream<Item = Instant> + Unpin + use<> {
        Box::pin(futures::stream::unfold(
            (self.clone(), 0u64),
            move |(clock, handed)| async move {
                // Сколько тиков сетки наступило. Ждать нечего: время двигает тест, ещё не наступивший
                // тик — повод отдать управление, а не крутиться.
                let due = crate::grid::due(clock.began, clock.now(), every);
                match due > handed {
                    true => {
                        let at = crate::grid::node(clock.began, every, handed + 1);
                        Some((at, (clock, handed + 1)))
                    }
                    // Время ещё не пришло — поток ЗАКАНЧИВАЕТСЯ, не висит. Виснуть честнее по смыслу,
                    // но требовало бы будильника (рантайма, которого нет). Цена: потребитель берёт
                    // наступившие тики, и берёт их снова после следующего `advance`.
                    false => None,
                }
            },
        ))
    }
}

/// Системные часы для синхронного потребителя. Живут в ядре, не в рантайме: `std::thread::sleep`
/// рантайма не требует (его требует только асинхронное пробуждение) — положи их в рантайм, и
/// плоскость потянула бы tokio целиком. Пустой тип: у системных часов нет состояния, два экземпляра
/// показывают одно; значение существует, чтобы часы ПЕРЕДАВАЛИСЬ (только переданные подменяются в тесте).
#[derive(Debug, Clone, Copy, Default)]
pub struct OsClock;

impl Clock for OsClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

impl Beats for OsClock {
    /// Сетка отмеряется от начала, а сон — до следующего её узла. Спать ровно `every` было бы неверно:
    /// работа потребителя добавляется к каждому шагу, сетка уезжает тем быстрее, чем он занятее.
    /// Отставшие узлы схлопываются, не выдаются залпом: залп есть ошибка событийная (выглядит бедой
    /// под нагрузкой), сдвиг сетки — ошибка величины (видна как величина).
    fn beats(&self, every: Duration) -> impl Iterator<Item = Instant> {
        let began = Instant::now();
        // Вырожденная сетка пуста, не бесконечна: у шага в ноль узлов нет (прежняя редакция крутила
        // бы поток без сна, выдавая один момент).
        let nodes = match every.is_zero() {
            true => 1u64..1,
            false => 1u64..u64::MAX,
        };
        nodes.filter_map(move |nth| {
            let due = crate::grid::node(began, every, nth);
            match due.checked_duration_since(Instant::now()) {
                // Узел позади — отстали; выдаём без сна, но без залпа: следующий вызов возьмёт
                // следующий узел, не все пропущенные разом.
                None => Some(due),
                Some(left) => {
                    std::thread::sleep(left);
                    Some(due)
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::StreamExt;

    /// Часы, которые не двигали, не идут: иначе тест доказывал бы «прошло время прогона».
    #[test]
    fn a_clock_nobody_advanced_does_not_move() {
        let clock = TestClock::new();
        let first = clock.now();
        assert_eq!(clock.now(), first, "время пошло само");
    }

    #[test]
    fn advancing_moves_the_clock_by_exactly_that_much() {
        let clock = TestClock::new();
        let began = clock.now();
        clock.advance(Duration::from_secs(5));
        assert_eq!(clock.now() - began, Duration::from_secs(5));
    }

    /// Синхронный потребитель получает ту же сетку, что и потоковый. Разойдись они — плоскость и лента
    /// мерили бы окна разной длины, оставаясь каждая по-своему правой.
    #[test]
    fn the_synchronous_consumer_sees_the_same_grid() {
        let clock = TestClock::new();
        let began = clock.now();
        clock.advance(Duration::from_millis(250));
        assert_eq!(
            clock
                .beats(Duration::from_millis(100))
                .map(|at| at - began)
                .collect::<Vec<Duration>>(),
            vec![Duration::from_millis(100), Duration::from_millis(200)],
            "синхронные удары разошлись с потоковыми тиками"
        );
    }

    /// Системные часы будят синхронный поток сами — контроль на РЕАЛЬНЫХ часах. Без него виртуальное
    /// время доказывает «сколько прошло», но не «нас разбудили» (оплачено #287, потерянный waker).
    #[test]
    fn the_os_clock_wakes_a_thread_by_itself() {
        let began = Instant::now();
        let beats: Vec<Instant> = OsClock.beats(Duration::from_millis(10)).take(3).collect();
        assert_eq!(beats.len(), 3, "часы не разбудили поток сами");
        assert!(
            began.elapsed() >= Duration::from_millis(30),
            "три удара по 10 мс пришли быстрее тридцати — часы не ждали"
        );
    }

    /// Тиков ровно столько, сколько шагов уложилось.
    #[tokio::test]
    async fn a_silent_advance_yields_the_ticks_that_fit() {
        let clock = TestClock::new();
        clock.advance(Duration::from_millis(250));
        let ticks: Vec<Instant> = clock.ticks(Duration::from_millis(100)).collect().await;
        assert_eq!(ticks.len(), 2, "тик выдан не за каждый прошедший шаг");
    }

    /// Сетка отмеряется от начала, не от последнего продвижения: два продвижения по полшага дают ОДИН
    /// тик (шаг прошёл). Считай от последнего — не дали бы ни одного, окно не закрылось бы.
    #[tokio::test]
    async fn the_grid_is_measured_from_the_start_not_from_the_last_advance() {
        let clock = TestClock::new();
        clock.advance(Duration::from_millis(60));
        clock.advance(Duration::from_millis(60));
        let ticks: Vec<Instant> = clock.ticks(Duration::from_millis(100)).collect().await;
        assert_eq!(ticks.len(), 1, "полшага плюс полшага не дали шага");
    }

    /// Тики несут момент сетки, а не момент выдачи: иначе два тика одним продвижением получили бы одно
    /// время, интервал между ними стал бы нулём.
    #[tokio::test]
    async fn every_tick_carries_its_own_moment_on_the_grid() {
        let clock = TestClock::new();
        let began = clock.now();
        clock.advance(Duration::from_millis(250));
        let ticks: Vec<Instant> = clock.ticks(Duration::from_millis(100)).collect().await;
        assert_eq!(
            ticks
                .iter()
                .map(|at| *at - began)
                .collect::<Vec<Duration>>(),
            vec![Duration::from_millis(100), Duration::from_millis(200)],
            "два тика пришли с одним временем — интервал между ними стал нулём"
        );
    }
}
