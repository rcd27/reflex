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
        // Слово о ЦЕЛИ поверх слов о её разговорах. Двадцать потоков к молчащему сайту дают одно
        // высказывание вместо двадцати; ЧТО именно оно значит, решаем здесь: «молчат все» строже
        // «молчит хоть один» и врёт реже, когда часть потоков просто закрылась.
        .about(|words| {
            words
                .iter()
                .all(|distress| matches!(distress, Distress::NoBytes | Distress::Silence { .. }))
                .then_some(Distress::NoBytes)
        })
        // Слово о цели приходит СВОЕЙ дверью: область у него другая, и путать его со словами
        // разговоров нельзя — иначе двадцать высказываний и итог по ним читались бы одинаково.
        // Возраст даёт фреймворк, годность судим мы: свежее прошлого тика — новость, старее —
        // то же самое молчание, о котором уже сказано.
        .on_target(|target, voiced| {
            if voiced.since < secs(1) {
                report!("цель молчит целиком: {target} ({})", voiced.distress.detail())
            }
        })
        .on(|target, distress| match distress {
            Distress::Retransmit { after_ms } => {
                report!("подозрение на тихий дроп: {target} (повтор через {after_ms}мс)")
            }
            Distress::Silence { ms } => report!("подтверждено: {target} молчит {ms}мс"),
            Distress::NoBytes => report!("подтверждено: {target} не ответил вовсе"),
            // Прочие беды — не этому пайпу: здесь стоят только приборы тишины и повтора.
            _ => {}
        })
        .run()
}
