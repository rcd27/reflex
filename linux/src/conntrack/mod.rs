//! Чтение conntrack ядра — счёт пакетов и байт по каждому разговору, в обе стороны. Величину,
//! дорогую на горячем пути, берут там, где её уже считают даром: ядро ведёт этот счёт независимо от
//! пути разговора (через очередь, мимо по метке, через ногу) и переживает всякое действие, которым
//! мы себя ослепляем. Читается ДАМПОМ, в темпе показа: `pull` третьего канала, не `push`.

mod dump;
mod edge;
mod wire;

pub use dump::{Dump, DumpError};
pub use edge::{CtEdge, TimeoutBase};
pub use wire::{
    chunk_of, entry_of, view_of, Chunk, Counts, CtEnds, CtTcp, CtView, Entry, Tuple,
};
