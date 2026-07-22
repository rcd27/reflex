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
    ///
    /// Дескриптор переводится в неблокирующий режим ЗДЕСЬ, а не требованием к
    /// вызывающему: дренаж читает до `EAGAIN`, и блокирующий fd повесил бы ожидание
    /// намертво. Ручка, которую легко забыть, — не ручка, а ловушка.
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
    fn park(&self, expires_at: std::time::Instant) {
        let left = expires_at.saturating_duration_since(std::time::Instant::now());
        let wait = self.floor.min(left);
        // Округление ВВЕРХ, минимум 1мс. `as_millis` отбрасывает дробь, и остаток
        // меньше миллисекунды давал бы `poll` таймаут 0 — то есть возврат мгновенно
        // и busy-loop на весь хвост окна. Поймано тестом дренажа: он мерил перечитки
        // и увидел 500-700 там, где ждали 7. Пересып не дольше миллисекунды, а
        // дедлайн всё равно проверяется сразу после возврата.
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

/// Потолок чтений за один дренаж. Без него быстрый писатель держал бы нас в
/// дренаже бесконечно — то есть busy-loop переехал бы этажом ниже, а не исчез.
/// Недовычитанный хвост не теряется: `POLLIN` останется, следующий `poll` вернётся
/// сразу, и это ровно один лишний виток, а не отказ.
const DRAIN_READS_MAX: usize = 64;

/// Вычитать и ВЫБРОСИТЬ накопившееся в подсказке.
///
/// Содержимое сообщений не читается никогда — в этом весь примитив: событие есть
/// повод, истину даёт `resync`. Потому дренаж УНИВЕРСАЛЕН: netlink, inotify, пайп
/// обслуживаются одинаково, и `Level` не обязан знать, чей у него дескриптор.
/// Ровно поэтому подписи `drain` в конструкторе нет — источник её не поставляет.
///
/// Побочно вместе с сообщениями выбрасывается и `ENOBUFS` netlink. Это не потеря:
/// пол держит сходимость и в лоссовом мире (`WitnessSource.tobe` GREEN), а строить
/// корректность на доставке сигнала о потере — та же ошибка, что верить событию.
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

    // ДРЕНАЖ. `poll` уровневый: пока данные в дескрипторе не вычитаны, `POLLIN`
    // держится. Если подсказка сработала, а предикат ВСЁ ЕЩЁ ложен (событие было не
    // про нас — на netlink это норма: наш сокет слышит все link-события подряд), то
    // недренированный fd превращает ожидание в busy-loop на всё окно дедлайна.
    //
    // Оракул — ЧИСЛО ПЕРЕЧИТОК, а не время: время тут одинаково в обоих случаях
    // (дедлайн истечёт всё равно), а вот сожжённое ядро видно только счётчиком.
    // При честном дренаже перечиток ≈ дедлайн/пол; без него — тысячи.
    #[test]
    fn hint_is_drained_so_a_stale_wake_does_not_spin() {
        let (reader, writer) = pipe_pair();
        let poked = poke(writer);
        assert!(poked, "подсказка не записалась");

        let resyncs = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counted = resyncs.clone();
        // Истина НИКОГДА не наступает: событие было, повод ложный — ровно тот случай,
        // ради которого дренаж и нужен.
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
