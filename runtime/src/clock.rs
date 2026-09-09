//! Системные часы — реализация [`reflex_core::clock::Clock`] на настоящем времени. Живут здесь, а не
//! в `reflex-core`: тикать значит СПАТЬ, а спать умеет только край (ядро держит контракт и
//! виртуальные часы, рантайм добавляет будильник). Заводилось затем, что замер нашёл семнадцать мест
//! вне тестов, порождавших время сами, — «часы добавляет ИСТОЧНИК, иначе всякий потребитель напишет
//! своё». Здесь источник один.

use core::time::Duration;
use std::time::Instant;

use futures::Stream;
use reflex_core::clock::{Clock, OsClock, Ticks};

/// Часы ОС, будящие поток событий. Не второй тип системных часов, а вторая ФОРМА ОЖИДАНИЯ у тех же:
/// `now` делегируется ядерному [`OsClock`], разойтись показаниям неоткуда; здесь добавляется
/// асинхронное пробуждение (рантайм). Разделение по крейтам следует за этим: синхронному потребителю
/// нужен `std::thread::sleep`, тянуть tokio ради одного треда со сном — платить за неиспользуемое.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        OsClock.now()
    }
}

impl Ticks for SystemClock {
    /// Тики идут по сетке [`reflex_core::grid`] — той же, что у записи, теста и
    /// [`Beats`](reflex_core::clock::Beats). Прежний `tokio::time::interval` с
    /// `MissedTickBehavior::Delay` отсчитывал следующий шаг от ОПОЗДАВШЕГО тика: при шаге 100 мс и
    /// заминке 350 мс узлы шли на `0,100,450,550,650` вместо `0,100,200,300,400` — сетка уехала на 50
    /// мс навсегда, а `Ticks` и `Beats` объявлены двумя ФОРМАМИ ОЖИДАНИЯ одних часов (разная сетка
    /// делает объявление ложным). Отставшие узлы теперь выдаются по ОДНОМУ НА ОПРОС (как `Beats`),
    /// залпа в одном пробуждении нет; цена — после долгой заминки очередь узлов вместо одного.
    fn ticks(&self, every: Duration) -> impl Stream<Item = Instant> + Unpin + use<> {
        let began = Instant::now();
        Box::pin(futures::stream::unfold(
            None::<u64>,
            move |handed| async move {
                match (every.is_zero(), handed) {
                    // Вырожденная сетка пуста, не бесконечна: у шага в ноль узлов нет, выдавать их
                    // значило бы крутиться без сна, выдумывая моменты.
                    (true, _) => None,
                    (false, handed) => {
                        let nth = handed.map_or(0, |already| already + 1);
                        let due = reflex_core::grid::node(began, every, nth);
                        match due.checked_duration_since(Instant::now()) {
                            // Узел уже позади — отдаём без сна: мы отстали, но сетку не двигаем.
                            None => (),
                            Some(left) => tokio::time::sleep(left).await,
                        }
                        Some((due, Some(nth)))
                    }
                }
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::StreamExt;

    /// Контроль на РЕАЛЬНЫХ часах — без него виртуальное время лжёт (#287: три зелёных теста на
    /// `tokio::time::pause` не поймали потерянный waker). Поток обязан отдать тик САМ, без события извне.
    #[tokio::test]
    async fn the_stream_wakes_itself_on_a_real_clock() {
        let ticks: Vec<Instant> = SystemClock
            .ticks(Duration::from_millis(10))
            .take(3)
            .collect()
            .await;
        assert_eq!(ticks.len(), 3, "часы не разбудили поток сами");
        assert!(
            ticks[2] > ticks[0],
            "тики пришли с неубывающим временем — часы стоят"
        );
    }

    /// Заминка потребителя не сдвигает сетку. `MissedTickBehavior::Delay` отсчитывал шаг от
    /// опоздавшего тика и двигал сетку вперёд навсегда; три другие реализации (запись, тестовые,
    /// синхронные `Beats`) считают от начала. Утверждение про ОСТАТОК, а не момент: между
    /// `Instant::now()` и часами tokio есть постоянное смещение эпохи (~24 мкс), `tick == began +
    /// step` краснел бы не на свою причину — остаток от деления берётся относительно первого узла.
    #[tokio::test(start_paused = true)]
    async fn a_stall_does_not_shift_the_grid() {
        let step = Duration::from_millis(100);
        let mut ticks = SystemClock.ticks(step);

        let Some(origin) = ticks.next().await else {
            panic!("часы не отдали первый тик");
        };

        // Потребитель занят: сетка успевает уйти на три с половиной шага вперёд.
        tokio::time::advance(Duration::from_millis(350)).await;

        for nth in 1..=4u32 {
            let Some(at) = ticks.next().await else {
                panic!("часы замолчали после заминки");
            };
            assert_eq!(
                at.saturating_duration_since(origin).as_nanos() % step.as_nanos(),
                0,
                "узел {nth} лёг мимо сетки — она сдвинулась заминкой"
            );
        }
    }

    /// Первый тик не ждёт шага (так устроен `interval` у tokio): на это опирается всякий, кто хочет
    /// снять состояние сразу после подписки — смена реализации сломает это громко, не тихо.
    #[tokio::test]
    async fn the_first_tick_does_not_wait_a_full_step() {
        let began = Instant::now();
        let _first = SystemClock
            .ticks(Duration::from_secs(3600))
            .next()
            .await
            .expect("часы отдали первый тик");
        assert!(
            began.elapsed() < Duration::from_secs(1),
            "первый тик ждал целый шаг — состояние не снять раньше периода"
        );
    }
}
