//! # IP-blackhole на NFQUEUE — отдельный пайп
//!
//! Цензор роняет `SYN` по АДРЕСУ: `SYN+ACK` не приходит, соединение не состоится вовсе. Так
//! блокируют то, у чего нет домена в открытом виде, — Телеграм (MTProto к IP датацентра), коннект
//! по чистому IP. Через `SilentBlock` это НЕ выразить: там соединение уже открыто, а здесь его нет.
//! Отдельный феномен — отдельный прибор, отдельный пайп.
//!
//! Имени у такой цели нет (нет `ClientHello`), и `extract(Sni)` опознаёт её по АДРЕСУ — цель не
//! теряется молча.
//!
//! ## Запуск
//!
//! ```sh
//! sudo nft 'add table inet reflex_demo'
//! sudo nft 'add chain inet reflex_demo out { type filter hook output priority -150; }'
//! sudo nft 'add rule inet reflex_demo out tcp dport 443 queue num 200'
//! cargo run -p detect-syn-drop
//! # снять правила: sudo nft 'delete table inet reflex_demo'
//! ```

use reflex::*;

fn main() -> Report {
    engine(Nfqueue::queue(200))
        .from(Tcp)
        .extract(Sni)
        .detect(SynDrop::unreachable())
        // Один прибор — один сигнал: `if let`, не `match`.
        .on(|target, distress| {
            if let Distress::Blackhole { after_ms } = distress {
                report!("IP-blackhole: {target} (SYN без ответа, повтор через {after_ms}мс)")
            }
        })
        .run()
}
