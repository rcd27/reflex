//! Очередь ядра — боевой бэкенд продукта. Модуль был вдвое больше: `guard`/`nft_guard` ставили
//! правила netfilter, `typed`/`witness`/`combined` разбирали провод — всё это звала только закрытая
//! deprecated-ветка, не собиравшаяся. Потребитель правила ставит СНАРУЖИ (скриптами стенда), а из
//! очереди берёт `NfqHandler`/`NfqPacket`/`NfqPipeline`. Фундамент, несущий обвязку мёртвого
//! потребителя, — музей; знание в истории, путь до него назван в коммите сноса.

mod backend;
mod pipeline;
mod preflight;
mod terminal;

pub use backend::{NfqueueBackend, Waited};
pub use pipeline::{
    NfqCounts, NfqHandler, NfqPacket, NfqPipeline, NfqShared, NfqStep, NfqVerdictKind,
};
pub use terminal::{Answer, NotTaken, Queued};
// Только внутри крейта: `millis_until` — закон округления остатка до `poll`, общий с
// `queue::terminal` (второй бэкенд на своём netlink-сокете, тот же предмет).
pub(crate) use terminal::millis_until;
