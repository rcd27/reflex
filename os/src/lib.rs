// Обещание имени в докблоке ([`Name`]) держит компилятор, не читатель: битая ссылка — ошибка сборки
// документации, а не молчаливое предупреждение, которое ловят люди постфактум.
#![deny(rustdoc::broken_intra_doc_links)]

//! Состояние ОС как УРОВНИ. Примитив — `Level<T>`: три поля, минимальность доказана прогонами TLC:
//! `resync` (истина, тотальная функция) — убери, мир `EventOnly` RED (гонка подписки); `floor`
//! (пол, максимум между принудительными resync) — убери, мир `nofloor` RED (зависание); `hint`
//! (подсказка) — убери, мир `poll` GREEN (медленно, но корректно). Закон примитива: **корректность
//! никогда не зависит от события; событие покупает только латентность.**

pub mod link;
pub mod step;

pub use step::{Step, StepOutcome};

use std::sync::Arc;
use std::time::Duration;

/// Исход ожидания уровня. Алгебраический тип, не `Option`: «дождались» несёт значение уровня на
/// момент витнеса, «не дождались» — ничего.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome<T> {
    Witnessed(T),
    TimedOut,
}

/// Наблюдаемый уровень состояния ОС.
pub struct Level<T> {
    resync: Arc<dyn Fn() -> T + Send + Sync>,
    /// Ноль, одна или много подсказок. Вырожденный (нет) и составной (`both` склеил) — одна форма,
    /// потому `Vec`.
    hints: Vec<std::os::fd::OwnedFd>,
    floor: Duration,
}

impl<T> Level<T> {
    /// Уровень без подсказки — вырожденный случай (push-канала нет). Корректен, медленнее на пол.
    pub fn polled(floor: Duration, resync: impl Fn() -> T + Send + Sync + 'static) -> Level<T> {
        Level {
            resync: Arc::new(resync),
            hints: Vec::new(),
            floor,
        }
    }

    /// Уровень с подсказкой. Дескриптор обязан быть уже вооружён до вызова (`Level` читает истину
    /// строго после конструктора — гонку подписки выразить нечем). Неблокирующий режим ставится
    /// здесь: дренаж читает до `EAGAIN`, блокирующий fd повесил бы ожидание намертво.
    pub fn hinted(
        hint: std::os::fd::OwnedFd,
        floor: Duration,
        resync: impl Fn() -> T + Send + Sync + 'static,
    ) -> Level<T> {
        let raw = std::os::fd::AsRawFd::as_raw_fd(&hint);
        let flags = unsafe { libc::fcntl(raw, libc::F_GETFL) };
        let _armed = unsafe { libc::fcntl(raw, libc::F_SETFL, flags | libc::O_NONBLOCK) };
        Level {
            resync: Arc::new(resync),
            hints: vec![hint],
            floor,
        }
    }

    /// Уровень, не зависящий от мира. Единица встречи: пол `Duration::MAX` нейтрален к `min`,
    /// подсказок нет, `a ∧ ⊤` наблюдается как `a`. «Шаг без предусловий» обязан выражаться в той же
    /// алгебре, не особым случаем.
    pub fn always(value: T) -> Level<T>
    where
        T: Clone + Send + Sync + 'static,
    {
        Level {
            resync: Arc::new(move || value.clone()),
            hints: Vec::new(),
            floor: Duration::MAX,
        }
    }

    /// Истина прямо сейчас.
    pub fn get(&self) -> T {
        (self.resync)()
    }

    /// Функтор: истина преобразуется, наблюдение остаётся. Подсказки и пол переезжают нетронутыми —
    /// `map` меняет ЧТО знаем, не ОТКУДА узнаём.
    pub fn map<U: 'static>(self, f: impl Fn(T) -> U + Send + Sync + 'static) -> Level<U>
    where
        T: 'static,
    {
        let inner = self.resync.clone();
        Level {
            resync: Arc::new(move || f(inner())),
            hints: self.hints,
            floor: self.floor,
        }
    }

    /// Ждать, пока уровень удовлетворит предикату, но не дольше `deadline`. Порядок: перечитка
    /// первой (гонка подписки), потом дедлайн, потом ожидание. Дедлайн обязан быть кратно больше
    /// пола, иначе пол не срабатывает за окно.
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
            // Подсказки = объединение (все fd в один poll); владение переезжает в склейку — два
            // владельца одного fd закрыли бы его дважды.
            hints: self.hints.into_iter().chain(other.hints).collect(),
            // Пол = минимум: иначе быстрая сторона наследует медлительность соседа.
            floor: self.floor.min(other.floor),
        }
    }

    /// Ждать повода перечитать: подсказка или пол — что раньше. Без подсказки `poll(2)` с нулём fd
    /// вырождается в сон. Исход `poll` сознательно игнорируется: дальше всё равно перечитка
    /// (событие есть повод, не истина).
    fn park(&self, expires_at: std::time::Instant) {
        let left = expires_at.saturating_duration_since(std::time::Instant::now());
        let wait = self.floor.min(left);
        // Округление вверх, минимум 1мс: остаток меньше миллисекунды дал бы `poll` таймаут 0 и
        // busy-loop на хвост окна (поймано тестом дренажа: 500-700 перечиток там, где ждали 7).
        let ms = i32::try_from(wait.as_micros().div_ceil(1000))
            .unwrap_or(i32::MAX)
            .max(1);
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
        fds.iter()
            .filter(|slot| slot.revents & libc::POLLIN != 0)
            .for_each(|slot| drain(slot.fd));
    }
}

/// Область определённости шага: уровень «готов / не готов». Встреча (`∧`) не пишется отдельно — она
/// выводится из моноидального `both` и функтора `map`. Это проверка, что структура настоящая:
/// законы наследуются от `both`, а не обеспечиваются руками.
impl Level<bool> {
    pub fn and(self, other: Level<bool>) -> Level<bool> {
        self.both(other).map(|(left, right)| left && right)
    }
}

/// Потолок чтений за дренаж: без него быстрый писатель держал бы в дренаже бесконечно (busy-loop
/// уровнем ниже). Недовычитанный хвост не теряется: `POLLIN` останется, следующий `poll` вернётся
/// сразу — ровно один лишний виток.
const DRAIN_READS_MAX: usize = 64;

/// Вычитать и выбросить накопившееся в подсказке. Содержимое не читается: событие есть повод,
/// истину даёт `resync`. Потому дренаж универсален (netlink, inotify, пайп — одинаково), и `Level`
/// не знает, чей у него дескриптор. Побочно выбрасывается `ENOBUFS` netlink — не потеря: пол держит
/// сходимость и в лоссовом мире.
fn drain(fd: libc::c_int) {
    let empty = [0u8; 512];
    let _drained = (0..DRAIN_READS_MAX).find_map(|_| {
        // Край FFI: read(2) пишет В буфер, потому он изменяем.
        let mut scratch = empty;
        let got =
            unsafe { libc::read(fd, scratch.as_mut_ptr() as *mut libc::c_void, scratch.len()) };
        if got > 0 {
            None
        } else {
            Some(())
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::{FromRawFd, OwnedFd};

    // Пайп как подсказка: тот же контракт, что у netlink (fd читаем, когда истина могла измениться).
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

    // Гонка подписки закрыта по построению: уровень читает истину ДО ожидания, потому уже-истинный
    // предикат возвращается немедленно (без подсказки, при недостижимом поле).
    #[test]
    fn resync_precedes_any_waiting() {
        let level = Level::polled(Duration::from_secs(3600), || true);
        let outcome = level.wait_until(|v| *v, Duration::from_secs(3600));
        assert_eq!(outcome, Outcome::Witnessed(true));
    }

    // Пол держит сходимость без подсказки (мир `poll`: GREEN). Истина меняется извне, узнаётся
    // перечиткой.
    #[test]
    fn converges_through_floor_without_any_hint() {
        let truth = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flip = truth.clone();
        // JoinHandle удерживаем и join'им (брошенный handle = «поток без витнеса»).
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

    // Подсказка покупает латентность — и только её. Проверяем временем: пол больше дедлайна, без
    // подсказки уровень доедет лишь к дедлайну.
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

    // Склейка: два уровня дают уровень пары, истина читается в момент перечитки.
    #[test]
    fn both_reads_truth_of_each_side() {
        let left = Level::polled(Duration::from_millis(5), || 7u8);
        let right = Level::polled(Duration::from_millis(5), || "готов");
        let pair = left.both(right);
        assert_eq!(pair.get(), (7u8, "готов"));
    }

    // Пол склейки = минимум: иначе быстрая сторона наследует медлительность соседа.
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

    // Подсказки склейки = объединение: подсказка только у правой стороны, полы недостижимы —
    // разбудить может лишь чужой fd.
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

    // Дренаж. `poll` уровневый: пока данные не вычитаны, `POLLIN` держится. Если подсказка
    // сработала, а предикат всё ещё ложен (событие не про нас — на netlink норма), недренированный
    // fd превращает ожидание в busy-loop. Оракул — число перечиток, не время.
    #[test]
    fn hint_is_drained_so_a_stale_wake_does_not_spin() {
        let (reader, writer) = pipe_pair();
        let poked = poke(writer);
        assert!(poked, "подсказка не записалась");

        let resyncs = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counted = resyncs.clone();
        // Истина никогда не наступает: событие было, повод ложный — ровно случай дренажа.
        let level = Level::hinted(reader, Duration::from_millis(50), move || {
            counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            false
        });

        let outcome = level.wait_until(|v| *v, Duration::from_millis(300));
        let count = resyncs.load(std::sync::atomic::Ordering::SeqCst);
        assert_eq!(outcome, Outcome::TimedOut);
        assert!(
            count <= 20,
            "подсказка не дренирована: {count} перечиток за 300мс при поле 50мс (ждали ≈7)"
        );
    }
}
