//! Состояние ОС как УРОВНИ (#152).
//!
//! Референт: `model/infra/WitnessSource.tla` (атом) + `model/infra/WitnessedAttach.tla`
//! (молекула `WitnessSource × AttachGate`) в репозитории `nevod`.
//!
//! Примитив — не «сервис» и не «событие», а `Level<T>`: три поля, из которых ровно
//! одно необязательное, и минимальность эта ДОКАЗАНА прогонами TLC, а не заявлена:
//!
//! - `resync` — истина. Тотальная функция, читается когда угодно. Убери её, оставь
//!   события — мир `EventOnly`, RED (гонка подписки, контрпример в 3 состояния).
//! - `floor` — пол. Максимум между двумя принудительными `resync`. Убери — мир
//!   `nofloor`, RED, причём стуттером: зависание, которое `procd` не лечит.
//! - `hint` — подсказка. Убери — мир `poll`, GREEN: медленно, но корректно.
//!
//! Отсюда закон примитива: **корректность никогда не зависит от события; событие
//! покупает только латентность.**

use std::sync::Arc;
use std::time::Duration;

/// Исход ожидания уровня. Алгебраический тип, а не `Option`: «дождались» несёт
/// ЗНАЧЕНИЕ уровня на момент витнеса, «не дождались» — не несёт ничего, и путать
/// их нечем.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome<T> {
    Witnessed(T),
    TimedOut,
}

/// Наблюдаемый уровень состояния ОС.
pub struct Level<T> {
    resync: Arc<dyn Fn() -> T + Send + Sync>,
    /// Ноль, одна или много подсказок. Вырожденный случай (подсказки нет) и
    /// составной (`both` склеил чужие) — ОДНА форма, потому `Vec`, а не `Option`.
    hints: Vec<std::os::fd::OwnedFd>,
    floor: Duration,
}

impl<T> Level<T> {
    /// Уровень БЕЗ подсказки — вырожденный случай (например «пол слушает :8888»:
    /// push-канала не существует). Корректен, просто медленнее на величину пола.
    pub fn polled(floor: Duration, resync: impl Fn() -> T + Send + Sync + 'static) -> Level<T> {
        Level {
            resync: Arc::new(resync),
            hints: Vec::new(),
            floor,
        }
    }

    /// Уровень с подсказкой. Дескриптор обязан быть УЖЕ ВООРУЖЁН до вызова — и это
    /// не соглашение, а свойство типа: `Level` читает истину только внутри
    /// `wait_until`/`get`, то есть строго ПОСЛЕ конструктора. Гонку подписки здесь
    /// выразить нечем.
    pub fn hinted(
        hint: std::os::fd::OwnedFd,
        floor: Duration,
        resync: impl Fn() -> T + Send + Sync + 'static,
    ) -> Level<T> {
        Level {
            resync: Arc::new(resync),
            hints: vec![hint],
            floor,
        }
    }

    /// Истина прямо сейчас.
    pub fn get(&self) -> T {
        (self.resync)()
    }

    /// Ждать, пока уровень удовлетворит предикату, но не дольше `deadline`.
    ///
    /// Порядок шагов — не деталь реализации, а контракт молекулы `WitnessedAttach`:
    /// перечитка ПЕРВОЙ (гонка подписки), потом проверка дедлайна, и только потом
    /// ожидание. Дедлайн обязан быть кратно больше пола — иначе пол не срабатывает
    /// ни разу за окно и не существует (`SF_vars(ResyncTick)` молекулы).
    pub fn wait_until(&self, pred: impl Fn(&T) -> bool, deadline: Duration) -> Outcome<T> {
        let expires_at = std::time::Instant::now() + deadline;
        std::iter::repeat(())
            .find_map(|()| {
                let value = self.get();
                if pred(&value) {
                    Some(Outcome::Witnessed(value))
                } else if std::time::Instant::now() >= expires_at {
                    Some(Outcome::TimedOut)
                } else {
                    self.park(expires_at);
                    None
                }
            })
            .unwrap_or(Outcome::TimedOut)
    }

    /// Склейка двух уровней в уровень пары.
    pub fn both<U: 'static>(self, other: Level<U>) -> Level<(T, U)>
    where
        T: 'static,
    {
        let mine = self.resync.clone();
        let theirs = other.resync.clone();
        Level {
            resync: Arc::new(move || (mine(), theirs())),
            // Подсказки = ОБЪЕДИНЕНИЕ: все дескрипторы обеих сторон в один poll.
            // Владение переезжает в склейку — потому `both` потребляет оба уровня,
            // а не заимствует: два владельца одного fd закрыли бы его дважды.
            hints: self.hints.into_iter().chain(other.hints).collect(),
            // Пол = МИНИМУМ: иначе быстрая сторона наследует медлительность соседа.
            floor: self.floor.min(other.floor),
        }
    }

    /// Ждать повода перечитать: подсказка ИЛИ пол — что раньше. Без подсказки
    /// `poll(2)` с нулём дескрипторов вырождается в сон, то есть в поллинг — и это
    /// не два разных пути в коде, а один. Никогда не ждём дольше остатка до дедлайна.
    ///
    /// Исход `poll` СОЗНАТЕЛЬНО игнорируется: разбудила подсказка, истёк пол или
    /// пришла ошибка — дальше в любом случае перечитка уровня. Событие есть повод,
    /// не истина (`WitnessSource`: во всех событийных мирах `observed' = up`).
    ///
    /// TODO(#152): подсказка НЕ ДРЕНИРУЕТСЯ, и это дыра. `poll` уровневый: пока
    /// данные в дескрипторе не вычитаны, `POLLIN` держится, и если предикат всё ещё
    /// ложен — цикл крутится вхолостую до дедлайна, сжигая ядро. На модели этого не
    /// видно (там нет понятия «стоимость перечитки»), а на риге видно будет сразу.
    /// Лечение требует решения: дренаж специфичен источнику (netlink — `recv` очереди,
    /// inotify — чтение записей), значит `Level` обязан нести дренаж рядом с fd, а не
    /// вместо resync. Тест на это ещё не написан — писать первым.
    fn park(&self, expires_at: std::time::Instant) {
        let left = expires_at.saturating_duration_since(std::time::Instant::now());
        let wait = self.floor.min(left);
        let ms = i32::try_from(wait.as_millis()).unwrap_or(i32::MAX);
        // Край FFI: poll(2) пишет revents В буфер, потому он изменяем.
        let mut fds: Vec<libc::pollfd> = self
            .hints
            .iter()
            .map(|hint| libc::pollfd {
                fd: std::os::fd::AsRawFd::as_raw_fd(hint),
                events: libc::POLLIN,
                revents: 0,
            })
            .collect();
        let _parked = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, ms) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::{FromRawFd, OwnedFd};

    // Пайп как ПОДСКАЗКА: тот же контракт, что у netlink-сокета (fd становится
    // читаемым, когда истина МОГЛА измениться), только управляемый из теста.
    fn pipe_pair() -> (OwnedFd, libc::c_int) {
        let raw = [0 as libc::c_int; 2];
        // Край FFI: pipe(2) пишет пару дескрипторов В буфер, потому он изменяем.
        let mut slots = raw;
        let rc = unsafe { libc::pipe(slots.as_mut_ptr()) };
        assert_eq!(rc, 0, "pipe(2) не завёлся");
        (unsafe { OwnedFd::from_raw_fd(slots[0]) }, slots[1])
    }

    fn poke(fd: libc::c_int) -> bool {
        let byte = [1u8; 1];
        let written = unsafe { libc::write(fd, byte.as_ptr() as *const libc::c_void, byte.len()) };
        written == 1
    }

    // ГОНКА ПОДПИСКИ, закрытая по построению (контрпример `race` атома: устройство
    // поднялось между bind() и первым recv() → события не будет НИКОГДА). Уровень
    // читает истину ДО всякого ожидания, поэтому уже-истинный предикат обязан
    // вернуться немедленно — при отсутствующей подсказке и заведомо недостижимом поле.
    #[test]
    fn resync_precedes_any_waiting() {
        let level = Level::polled(Duration::from_secs(3600), || true);
        let outcome = level.wait_until(|v| *v, Duration::from_secs(3600));
        assert_eq!(outcome, Outcome::Witnessed(true));
    }

    // ПОЛ держит сходимость БЕЗ всякой подсказки (мир `poll` атома: GREEN, медленно
    // но корректно). Истина меняется извне; узнать о ней можно только перечиткой.
    #[test]
    fn converges_through_floor_without_any_hint() {
        let truth = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flip = truth.clone();
        // JoinHandle удерживаем и join'им (MEM: брошенный handle = «поток без витнеса»).
        let mover = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(60));
            flip.store(true, std::sync::atomic::Ordering::SeqCst);
        });

        let seen = truth.clone();
        let level = Level::polled(Duration::from_millis(5), move || {
            seen.load(std::sync::atomic::Ordering::SeqCst)
        });

        let outcome = level.wait_until(|v| *v, Duration::from_secs(2));
        let joined = mover.join();
        assert!(joined.is_ok());
        assert_eq!(outcome, Outcome::Witnessed(true));
    }

    // ПОДСКАЗКА покупает ЛАТЕНТНОСТЬ — и только её. Проверяем именно временем: пол
    // заведомо больше дедлайна, так что без подсказки уровень доедет лишь к дедлайну.
    // Если тест зелен по значению, но красен по времени — подсказки нет, есть поллинг.
    #[test]
    fn hint_wakes_far_earlier_than_floor() {
        let (reader, writer) = pipe_pair();
        let truth = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flip = truth.clone();
        let mover = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(30));
            flip.store(true, std::sync::atomic::Ordering::SeqCst);
            poke(writer)
        });

        let seen = truth.clone();
        let level = Level::hinted(reader, Duration::from_secs(10), move || {
            seen.load(std::sync::atomic::Ordering::SeqCst)
        });

        let started = std::time::Instant::now();
        let outcome = level.wait_until(|v| *v, Duration::from_secs(5));
        let elapsed = started.elapsed();
        let joined = mover.join();
        assert!(joined.is_ok());
        assert_eq!(outcome, Outcome::Witnessed(true));
        assert!(
            elapsed < Duration::from_secs(1),
            "подсказка не разбудила: ждали {elapsed:?} при поле 10с"
        );
    }

    // СКЛЕЙКА: два уровня дают уровень пары. Истина составного — обе истины разом,
    // прочитанные в момент перечитки (а не запомненные по отдельности когда-то).
    #[test]
    fn both_reads_truth_of_each_side() {
        let left = Level::polled(Duration::from_millis(5), || 7u8);
        let right = Level::polled(Duration::from_millis(5), || "готов");
        let pair = left.both(right);
        assert_eq!(pair.get(), (7u8, "готов"));
    }

    // ПОЛ СКЛЕЙКИ = МИНИМУМ. Иначе быстрая сторона наследует медлительность соседа:
    // склеил уровень с полом 5мс и уровень с полом 10с — и потерял оба.
    #[test]
    fn both_takes_the_smaller_floor() {
        let truth = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flip = truth.clone();
        let mover = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(60));
            flip.store(true, std::sync::atomic::Ordering::SeqCst);
        });

        let slow = Level::polled(Duration::from_secs(10), || ());
        let seen = truth.clone();
        let quick = Level::polled(Duration::from_millis(5), move || {
            seen.load(std::sync::atomic::Ordering::SeqCst)
        });

        let started = std::time::Instant::now();
        let outcome = slow
            .both(quick)
            .wait_until(|(_, r)| *r, Duration::from_secs(3));
        let elapsed = started.elapsed();
        let joined = mover.join();
        assert!(joined.is_ok());
        assert_eq!(outcome, Outcome::Witnessed(((), true)));
        assert!(
            elapsed < Duration::from_secs(1),
            "пол склейки взят не минимумом: ждали {elapsed:?}"
        );
    }

    // ПОДСКАЗКИ СКЛЕЙКИ = ОБЪЕДИНЕНИЕ, все дескрипторы в один poll. Здесь подсказка
    // есть ТОЛЬКО у правой стороны, а полы у обоих заведомо недостижимы — значит
    // разбудить может лишь чужой fd. Это ровно та работа, которую руками пишут
    // правильно один раз и ломают на третьей склейке.
    #[test]
    fn both_watches_hints_of_every_side() {
        let (reader, writer) = pipe_pair();
        let truth = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flip = truth.clone();
        let mover = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(30));
            flip.store(true, std::sync::atomic::Ordering::SeqCst);
            poke(writer)
        });

        let blind = Level::polled(Duration::from_secs(10), || ());
        let seen = truth.clone();
        let watched = Level::hinted(reader, Duration::from_secs(10), move || {
            seen.load(std::sync::atomic::Ordering::SeqCst)
        });

        let started = std::time::Instant::now();
        let outcome = blind
            .both(watched)
            .wait_until(|(_, r)| *r, Duration::from_secs(5));
        let elapsed = started.elapsed();
        let joined = mover.join();
        assert!(joined.is_ok());
        assert_eq!(outcome, Outcome::Witnessed(((), true)));
        assert!(
            elapsed < Duration::from_secs(1),
            "подсказка соседа потеряна при склейке: ждали {elapsed:?}"
        );
    }
}
