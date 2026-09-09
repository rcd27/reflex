//! Свой сокет к NFNL_SUBSYS_QUEUE. Разбор и сборка сообщений отделены от IO (`wire`), чтобы
//! проверяться без root; сам сокет — Task 4. Крейт `nfq` с этого пути срезается: он не разбирает
//! `NFQA_CT` и не кладёт его в вердикт (оба PR у апстрима неприняты с 2023-го).

mod wire;

pub use wire::{
    bind_request, cmd_body, conntrack_flag_request, incoming_of, params_body, params_request,
    verdict_body, verdict_message, Incoming, Packet,
};
