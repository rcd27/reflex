//! ОЧЕРЕДЬ ЯДРА — БОЕВОЙ БЭКЕНД ПРОДУКТА.
//!
//! # Что отсюда вынесено 05.09.2026 и почему
//!
//! Модуль был вдвое больше: `guard`/`nft_guard` (1052 строки) ставили правила netfilter,
//! `typed`/`witness`/`combined` — разбирали провод и сводили две калитки. Замер показал, что ВСЁ
//! это зовёт только закрытая ветка, объявленная владельцем deprecated и не собирающаяся
//! (`NfqVerdict::AcceptMarked` не покрыт в её `match` с 31.08).
//!
//! Потребитель правила ставит СНАРУЖИ — скриптами стенда, — а из
//! очереди берёт `NfqHandler`/`NfqPacket`/`NfqPipeline`. Комментарий в его `Cargo.toml` уверял,
//! будто нужны `WirePacket`/`WireHandler`; в коде их нет ни одного вхождения.
//!
//! Фундамент, несущий обвязку мёртвого потребителя, — не фундамент, а музей. Знание не потеряно:
//! оно в истории, и путь до него назван в коммите сноса.

mod backend;
mod pipeline;
mod preflight;
mod terminal;

pub use backend::{NfqueueBackend, Waited};
pub use pipeline::{
    NfqCounts, NfqHandler, NfqPacket, NfqPipeline, NfqShared, NfqStep, NfqVerdict, NfqVerdictKind,
};
pub use terminal::{Answer, NotTaken, Queued};
