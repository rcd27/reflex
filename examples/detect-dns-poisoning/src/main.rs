//! # Отравление DNS на NFQUEUE — транспорт `Udp`
//!
//! Цензор инжектит поддельный DNS-ответ (`NXDOMAIN`/пустой) на запрос заблокированного домена
//! вместо настоящего адреса. Здесь движок впервые смотрит НЕ TCP, а `Udp` (порт 53) — это и есть
//! полиморфизм `.from`: другой транспорт, другой словарь провода (разобранное DNS-сообщение).
//!
//! Подозрение, не приговор: легитимный `NXDOMAIN` даёт то же. Точный признак — кросс-резолвер
//! (тот же запрос к другому DNS даёт адрес), но это активная проба, живёт у потребителя.
//!
//! ## Запуск
//!
//! ```sh
//! sudo nft 'add table inet reflex_demo'
//! sudo nft 'add chain inet reflex_demo out { type filter hook output priority -150; }'
//! sudo nft 'add rule inet reflex_demo out udp dport 53 queue num 200'
//! sudo nft 'add chain inet reflex_demo inp { type filter hook input priority -150; }'
//! sudo nft 'add rule inet reflex_demo inp udp sport 53 queue num 200'
//! cargo run -p detect-dns-poisoning
//! # снять правила: sudo nft 'delete table inet reflex_demo'
//! ```

use reflex::*;

fn main() -> Report {
    engine(Nfqueue::queue(200))
        .from(Udp)
        .extract(Sni)
        .detect(DnsPoison::injected())
        // Один прибор — один сигнал: `if let`, не `match`.
        .on(|target, distress| {
            if let Distress::Poisoned = distress {
                report!("подозрение на отравление DNS: {target} (инжект NXDOMAIN/пустой ответ)")
            }
        })
        .run()
}
