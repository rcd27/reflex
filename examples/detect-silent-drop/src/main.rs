//! # Тихий дроп на NFQUEUE — двумя приборами разной скорости
//!
//! Цензор роняет пакеты к цели молча: RST не приходит, соединение открыто, байтов вниз нет.
//! Ловим это ДВУМЯ приборами над одним проводом:
//!
//! * `Retransmit` — быстрое ПОДОЗРЕНИЕ: клиент повторил `ClientHello`, ответа нет (порог — RTO
//!   ядра клиента, ~сотни мс; обычная потеря даёт тот же повтор, потому это подозрение);
//! * `Silence` — медленное ПОДТВЕРЖДЕНИЕ: за окном тишины цель так и не ответила.
//!
//! Склейку «подозрение → подтверждение» пишем здесь, в реакции: фреймворк отдаёт слова беды,
//! вывод делает потребитель.
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
        .detect(Retransmit::unanswered()) // быстрое подозрение — по повтору клиента
        .detect(Silence::after(secs(5))) // медленное подтверждение — по окну тишины
        .on(|target, distress| match distress {
            Distress::Retransmit { after_ms } => {
                report!("подозрение на тихий дроп: {target} (повтор через {after_ms}мс)")
            }
            Distress::Silence { ms } => report!("подтверждено: {target} молчит {ms}мс"),
            Distress::NoBytes => report!("подтверждено: {target} не ответил вовсе"),
            // IP-blackhole — другой пайп (detect-syn-drop): здесь его приборы не стоят.
            Distress::Rst | Distress::Throttled { .. } | Distress::Blackhole { .. } => {}
        })
        .run()
}
