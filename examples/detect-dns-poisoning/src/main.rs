//! # Отравление DNS на NFQUEUE — транспорт `Udp`
//!
//! Цензор инжектит поддельный DNS-ответ (`NXDOMAIN`/пустой) на запрос заблокированного домена
//! вместо настоящего адреса. Здесь движок впервые смотрит НЕ TCP, а `Udp` (порт 53) — это и есть
//! полиморфизм `.from`: другой транспорт, другой словарь провода (разобранное DNS-сообщение).
//!
//! Подозрение, не приговор: легитимный `NXDOMAIN` даёт то же. Точный признак — кросс-резолвер
//! (тот же запрос к другому DNS даёт адрес), но это активная проба, живёт у потребителя.
//!
//! Копредел (`.about` → `.on_target`) стоит и здесь — тем и показателен: оператор один и тот же на
//! обоих транспортах. Разговор для него — датаграмма-запрос, цель — имя из неё, и повтор запроса
//! (другой резолвер, ретрай) даёт ВТОРОЙ разговор той же цели.
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
        // Тот же оператор поверх ДРУГОГО транспорта: копредел не знает ни про TCP, ни про UDP — он
        // сводит слова разговоров под ключ цели, а что за разговоры, решил `.from`. Здесь разговор
        // — датаграмма-запрос, цель — имя из него; два запроса того же имени (повтор резолвера,
        // второй резолвер) суть два разговора одной цели.
        //
        // Одиночный `NXDOMAIN` легитимен — имени может и не быть. Оракулом его делает ПОВТОР: имя
        // не отвечает никому, сколько ни спрашивай.
        .about(|words| {
            let all_injected = words
                .iter()
                .all(|distress| matches!(distress, Distress::Poisoned));
            (words.len() >= 2 && all_injected).then_some(Distress::Poisoned)
        })
        .on_target(|target, voiced| {
            if voiced.since < secs(1) {
                report!("имя не резолвится ни одним запросом: {target} — похоже на оракул")
            }
        })
        // Один прибор — один сигнал: `if let`, не `match`.
        .on(|target, distress| {
            if let Distress::Poisoned = distress {
                report!("подозрение на отравление DNS: {target} (инжект NXDOMAIN/пустой ответ)")
            }
        })
        .run()
}
