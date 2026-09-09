//! # Оборвать тихий дроп RST'ом — путь ЭФФЕКТА
//!
//! Тихий дроп заставляет клиента крутить вечную крутилку: `SYN+ACK` пришёл, `ClientHello` ушёл, а
//! ответа нет — браузер ждёт 2–12с, повторяя запрос. Мы видим повтор уже через ~300мс (RTO ядра) и
//! отвечаем ДЕЙСТВИЕМ: инжектим клиенту RST от имени цели. Браузер получает «соединение сброшено» и
//! падает быстро — человек видит ошибку и уходит на обход, а не смотрит на крутилку.
//!
//! Отличие от `detect-silent-drop`: там `.on` (наблюдать), здесь `.act` (действовать). Реакция
//! возвращает [`Act`], движок исполняет — сборка RST и инъекция замкнуты в нём.
//!
//! Копредела (`.about` → `.on_target`) здесь НЕТ, и это запрещено типом, а не забыто: слово о цели
//! рождается тиком, а рвать по тику нечем — у тика нет пакета, от чьего имени слать RST. Свёртка в
//! этой цепочке молчала бы всегда, и компилятор не даёт её поставить. Обрыв идёт по улике, пришедшей
//! С ПАКЕТОМ, — по повтору клиента.
//!
//! ## Запуск
//!
//! ```sh
//! sudo nft 'add table inet reflex_demo'
//! sudo nft 'add chain inet reflex_demo out { type filter hook output priority -150; }'
//! # пропускаем свои инъекции (метка reflex), остальной :443 — в очередь
//! sudo nft 'add rule inet reflex_demo out tcp dport 443 meta mark != 0xBB queue num 200'
//! cargo run -p sever-silent-drop
//! # снять правила: sudo nft 'delete table inet reflex_demo'
//! ```

use reflex::*;

fn main() -> Report {
    engine(Nfqueue::queue(200))
        .from(Tcp)
        .extract(Sni)
        .detect(Retransmit::unanswered()) // повтор клиента — ранняя улика тихого дропа
        .act(|target, distress| match distress {
            Distress::Retransmit { after_ms } => {
                report!(
                    "обрываю тихий дроп: {target} (RST через {after_ms}мс вместо вечной крутилки)"
                );
                Act::Sever
            }
            _ => Act::Observe,
        })
        .run()
}
