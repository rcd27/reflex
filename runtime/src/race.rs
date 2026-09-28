//! ГОНКА — попытки со ступенчатым стартом, где побеждает первая удача (happy eyeballs, RFC 8305).
//!
//! Чем отличается от `ladder::climb`: лестница перебирает кандидатов ради ЗНАНИЯ и дожидается
//! каждого, кто в полёте; гонке нужен ПЕРВЫЙ годный, а остальные после него — мусор. Отдельный
//! примитив, а не флаг лестницы: у них разный закон останова, и флаг держал бы две машины в одной.
//!
//! Отказ запускает следующего сразу, не дожидаясь ступени: ступень нужна против молчания (потерянный
//! SYN), а отказ — уже ответ, и ждать после него значит жечь бюджет, которого у клиента 5 с.

use futures::stream::{FuturesUnordered, StreamExt};
use std::future::Future;
use std::time::Duration;
use tokio::time::{sleep_until, Instant};

/// Исход одного кандидата. Алфавит закрыт: у читателя не будет `_ =>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Attempt {
    /// Победил.
    Won,
    /// Мир отказал (с причиной).
    Refused(String),
    /// Был в полёте, когда гонка кончилась (победой другого или сроком).
    Abandoned,
    /// Не запускали вовсе.
    NotRun,
}

/// Итог: победитель, если был, и исход КАЖДОГО кандидата в порядке подачи.
#[derive(Debug)]
pub struct Raced<K, T> {
    pub won: Option<(K, T)>,
    pub tried: Vec<(K, Attempt)>,
}

/// Что делать на этом шаге: три исхода, а не пара вложенных `if` — сила отдана `match`, а не
/// булевым парам (`pair_types` не терпит их без имени; здесь имя есть).
enum Step {
    /// Запустить кандидата с этим индексом немедленно — ступень и ширина позволяют.
    Launch(usize),
    /// Ждать: либо кто-то в полёте ответит, либо сработает будильник (ступень или срок).
    Wait(Instant),
    /// Ни в полёте, ни в очереди никого не осталось раньше срока — ждать нечего.
    Exhausted,
}

/// ГОНКА: пробовать кандидатов со ступенью `stagger`, не более чем `width` ветвями сразу, до
/// первой удачи или до общего срока `deadline`.
///
/// `attempt` отвечает `Result<T, String>`: `Ok` — победа, `Err(причина)` — отказ. Ступень между
/// запусками — защита от МОЛЧАНИЯ (потерянный SYN); отказ уже несёт ответ, и следующий кандидат не
/// ждёт после него ни миллисекунды (докблок модуля).
///
/// Кандидаты, оставшиеся в полёте к моменту победы или срока, размечаются `Abandoned` — они
/// состоялись как попытки, и выбросить их из отчёта значило бы солгать «не запускали» о том, что
/// запускали (тот же закон, что у `ladder::climb`).
///
/// # Почему есть `Step::Exhausted`, а не только `Launch`/`Wait`
///
/// Точный триггер — вход в ИТЕРАЦИЮ, где в полёте никого нет и запускать больше некого (список
/// кандидатов исчерпан или, что и есть боевой случай, пуст с самого начала). Без этой ветки такая
/// итерация уходит в `select!`, где ветка `flight.next()` выключена условием `if !flight.is_empty()`
/// и бодрствует только будильник срока — цикл проспит весь `deadline`, хотя решать уже нечего.
/// У НЕПУСТОГО списка это состояние само по себе не опасно: оно наступает только СРАЗУ ПОСЛЕ того,
/// как `select!` разобрал последнее событие в полёте (победу или отказ), и в тот же миг доступна
/// свежая информация — ждать до будильника незачем, но и звать его не пришлось бы: цикл увидит это
/// на следующем обороте и остановится, не вызывая `select!` второй раз. Опасен ровно ПУСТОЙ вход:
/// `candidates` пуст ⟹ `flight` никогда не наполнится, событий в `select!` не будет НИКОГДА, и без
/// этой ветки первый же оборот сел бы на голый `sleep_until(deadline)` — гонка длиной в 4,5 с при
/// нуле кандидатов. Замерено прогоном эталона брифа: `race(vec![], …, ms(4500), …)` у него стоит
/// ровно 4,5 с виртуального времени; тот же запрос на этой реализации возвращается при `elapsed`
/// `Duration::ZERO`.
pub async fn race<K, T, F, Fut>(
    candidates: Vec<K>,
    stagger: Duration,
    width: usize,
    deadline: Duration,
    attempt: F,
) -> Raced<K, T>
where
    K: Clone,
    F: Fn(K) -> Fut,
    Fut: Future<Output = Result<T, String>>,
{
    let end = Instant::now() + deadline;
    // Ширина ноль — не «без ограничения», а вырожденный случай (канон `ladder.rs`): `max(1)` держит
    // гонку ходячей вместо молчаливого превращения нуля в безграничность.
    let width = width.max(1);
    let mut outcome: Vec<Attempt> = candidates.iter().map(|_| Attempt::NotRun).collect();
    let mut flight = FuturesUnordered::new();
    let mut next = 0usize;
    let mut next_at = Instant::now();
    let mut won: Option<(usize, T)> = None;

    while won.is_none() {
        let now = Instant::now();
        if now >= end {
            break;
        }
        let room = next < candidates.len() && flight.len() < width;
        let step = match (room && now >= next_at, flight.is_empty() && !room) {
            (true, _) => Step::Launch(next),
            (false, true) => Step::Exhausted,
            (false, false) => Step::Wait(match room {
                true => next_at.min(end),
                false => end,
            }),
        };
        match step {
            Step::Launch(index) => {
                let trying = attempt(candidates[index].clone());
                flight.push(async move { (index, trying.await) });
                // Пока не решилось иначе — кандидат брошен: победа или отказ перезапишут клетку, а
                // если гонка кончится, пока он в полёте, `Abandoned` и есть верный исход.
                outcome[index] = Attempt::Abandoned;
                next += 1;
                next_at = now + stagger;
            }
            Step::Exhausted => break,
            Step::Wait(wake) => {
                tokio::select! {
                    landed = flight.next(), if !flight.is_empty() => match landed {
                        Some((index, Ok(value))) => {
                            outcome[index] = Attempt::Won;
                            won = Some((index, value));
                        }
                        Some((index, Err(why))) => {
                            outcome[index] = Attempt::Refused(why);
                            // Отказ — уже ответ: следующего не держат ступенью (докблок модуля).
                            next_at = Instant::now();
                        }
                        None => {}
                    },
                    _ = sleep_until(wake) => {}
                }
            }
        }
    }
    // Проигравшие будущие уничтожаются здесь вместе с `flight`: их сокеты закрываются дропом.
    drop(flight);
    Raced {
        won: won.map(|(index, value)| (candidates[index].clone(), value)),
        tried: candidates.into_iter().zip(outcome).collect(),
    }
}
