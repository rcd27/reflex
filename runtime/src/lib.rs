// Обещание имени в докблоке ([`Name`]) держит компилятор, не читатель: битая ссылка — ошибка сборки
// документации, а не молчаливое предупреждение, которое ловят люди постфактум.
#![deny(rustdoc::broken_intra_doc_links)]

//! Runtime adapters for reflex-core.
//!
//! This crate holds everything that depends on a concrete async runtime (tokio),
//! OS facilities (libc, std::fs, signals, pid files), or other system primitives.
//! reflex-core itself stays pure: types, parsing, building, detection combinators, pure
//! stream operators. Anything that needs a clock, an OS signal, or a process-wide channel
//! lives here.

// ЛЕСТНИЦА ПРОБ — вторая ось: `core` держит шаг, `runtime` держит конкурентность. Докблок модуля
// объясняет, почему она не в фундаменте, и под каким условием эта ось вообще заводится.
pub mod ladder;

pub mod clock;
pub mod pid;
pub mod signal;
pub mod subject;
pub mod timed;

pub use clock::SystemClock;
pub use pid::{PidError, PidGuard};
pub use signal::shutdown_signal;
pub use subject::Subject;
