//! ПРОСЬБА УЙТИ, УСЛЫШАННАЯ СИНХРОННО — близнец `reflex-runtime::shutdown_signal` для потребителя
//! без асинхронного рантайма.
//!
//! Сигнал здесь не ПРЕРЫВАЕТ, а ЖДЁТ, пока его спросят: штатные просьбы блокируются для доставки,
//! и цикл потребителя забирает их своим темпом (`sigtimedwait` с нулевым сроком). Обработчика нет и
//! глобального флага нет: просьба уйти приходит тем же путём, что и время сеткой, — её читают на
//! обороте, а не принимают в произвольной точке шага.
//!
//! Набор просьб тот же, что у асинхронной двери: `SIGINT`, `SIGTERM`, `SIGHUP`. Две двери с разными
//! наборами разошлись бы молча — демон, уходящий по одной, не уходил бы по другой.

/// Какую просьбу уйти прислали. Закрытый алфавит: штатные сигналы и ничего сверх.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Plea {
    Interrupt,
    Terminate,
    Hangup,
}

impl Plea {
    const ALL: [Plea; 3] = [Plea::Interrupt, Plea::Terminate, Plea::Hangup];

    fn signal(self) -> libc::c_int {
        match self {
            Plea::Interrupt => libc::SIGINT,
            Plea::Terminate => libc::SIGTERM,
            Plea::Hangup => libc::SIGHUP,
        }
    }

    /// Номер сигнала в просьбу. Отказ `sigtimedwait` (`-1`: ничего не пришло) — `None`.
    fn of(signal: libc::c_int) -> Option<Plea> {
        Plea::ALL.into_iter().find(|plea| plea.signal() == signal)
    }
}

/// Штатные просьбы уйти, заблокированные для доставки: они ждут вопроса.
pub struct Leaving {
    pleas: libc::sigset_t,
}

impl Leaving {
    /// Заблокировать штатные просьбы для ЭТОЙ нити и всех, что она породит.
    ///
    /// ЗВАТЬ ПЕРВЫМ, ДО ПЕРВОЙ НИТИ: маска наследуется от порождающей. Нить, заведённая раньше,
    /// оставила бы сигнал доставляемым — и ядро отдало бы его ей, а действие по умолчанию убило бы
    /// процесс, так и не спросив.
    pub fn blocked() -> Result<Leaving, String> {
        // Выходной параметр FFI: `sigset_t` заполняется по месту, иначе его не построить.
        let mut pleas: libc::sigset_t = unsafe { std::mem::zeroed() };
        let emptied = unsafe { libc::sigemptyset(&mut pleas) };
        let added: Vec<libc::c_int> = Plea::ALL
            .iter()
            .map(|plea| unsafe { libc::sigaddset(&mut pleas, plea.signal()) })
            .collect();

        match (emptied, added.iter().all(|code| *code == 0)) {
            (0, true) => (),
            (_emptied, _added) => return Err("набор штатных сигналов не собрался".to_string()),
        }

        match unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &pleas, std::ptr::null_mut()) } {
            0 => Ok(Leaving { pleas }),
            code => Err(format!("штатные сигналы не заблокировались: код {code}")),
        }
    }

    /// Просили ли уйти. НЕ ЖДЁТ: оборот спрашивает своим темпом, и ответ «нет» приходит сразу.
    ///
    /// Просьба забирается вопросом: спрошенная, она больше не висит, — второй вопрос ответит
    /// «нет», если новой не пришло.
    pub fn asked(&self) -> Option<Plea> {
        let now = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        Plea::of(unsafe { libc::sigtimedwait(&self.pleas, std::ptr::null_mut(), &now) })
    }
}
