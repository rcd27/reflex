//! # Тихий дроп на NFQUEUE
//!
//! Цензор роняет пакеты к цели молча: RST не приходит, соединение открыто, а байтов вниз нет.
//! Человек видит «страница висит». Этот пример ловит ровно это — и показывает, как устроено
//! использование `reflex`: одна цепочка, ни одного примитива движка наружу.
//!
//! ## Запуск
//!
//! ```sh
//! sudo nft 'add table inet reflex_demo'
//! sudo nft 'add chain inet reflex_demo out { type filter hook output priority -150; }'
//! sudo nft 'add rule inet reflex_demo out tcp dport 443 queue num 200'
//! cargo run -p detect-silent-drop
//! # снять правила: sudo nft 'delete table inet reflex_demo'
//! ```

use reflex::*;

fn main() -> Report {
    engine(Nfqueue::queue(200))
        .from(Tcp)
        .extract(Sni)
        .detect(Silence::after(secs(5)))
        .on(|target, silence| report!("тихий дроп: {target} молчит {}мс", silence.ms))
        .run()
}
