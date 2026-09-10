//! Очередь ядра. Модуль ужимался дважды: сперва ушли `guard`/`nft_guard`/`typed`/`witness`, потом
//! (10.09.2026) — `pipeline` с `NfqPipeline`/`NfqStep`/`NfqVerdictKind`. Второй снос по правилу
//! хозяина: код без живого потребителя либо уходит, либо обзаводится примером, который его
//! употребляет. У `pipeline` пример был (`nfq-passthrough`), но держал он сам труп, а не живое —
//! боевой путь ходит через `queue::QueueSocket`, и три алфавита вердикта на одни четыре слова
//! (`NfqVerdict`, `NfqVerdictKind`, `Answer`) с ним ушли тоже.
//!
//! Потребитель правила netfilter ставит СНАРУЖИ (скриптами стенда), а из очереди берёт `Answer`.
//! Знание не потеряно: оно в истории, путь до него — этот коммит.

mod backend;
mod preflight;
mod terminal;

pub use backend::{NfqueueBackend, Waited};
pub use terminal::{Answer, NotTaken, Queued};
// Только внутри крейта: `millis_until` — закон округления остатка до `poll`, общий с
// `queue::terminal` (второй бэкенд на своём netlink-сокете, тот же предмет).
pub(crate) use terminal::millis_until;
