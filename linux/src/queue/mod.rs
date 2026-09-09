//! Свой сокет к NFNL_SUBSYS_QUEUE. Разбор и сборка сообщений (`wire`) отделены от IO (`socket`),
//! чтобы проверяться без root; терминал (`terminal`) разбирает ответ в вердикт. Крейт `nfq` с этого
//! пути срезается: он не разбирает `NFQA_CT` и не кладёт его в вердикт (оба PR у апстрима неприняты
//! с 2023-го), и глушит `ENOBUFS` — а нам переполнение нужно буквой, не молчанием.

mod socket;
mod terminal;
mod wire;

pub use socket::{QueueError, QueueSocket};
pub use terminal::{Answer, Held};
pub use wire::{
    bind_request, cmd_body, conntrack_flag_request, incoming_of, params_body, params_request,
    verdict_body, verdict_message, Incoming, Packet,
};
