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
//! Сверх того здесь стоит копредел (`.about` → `.on_target`): один утонувший `SYN` — ещё не
//! блокировка, а вот три независимых потока к тому же адресу подряд — уже она. Слово о цели
//! рождается из слов её разговоров, и цель эта БЕЗЫМЯННА — ключом ей служит адрес.
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
        // Blackhole — свойство АДРЕСА, а не разговора: один утонувший `SYN` бывает и от обычной
        // потери. Копредел отвечает на настоящий вопрос — тонут ли ВСЕ попытки к этому адресу.
        // Порог здесь наш: три независимых потока, а не один; свёртка видит множество слов, и её
        // мощность — законное основание для суждения.
        .about(|words| {
            // Величина берётся у самой БЫСТРОЙ попытки: столько адрес молчит наверняка. Своё число
            // здесь выдумывать нельзя — оно ушло бы в отчёт наравне с измеренными.
            let waited: Vec<u32> = words
                .iter()
                .map(|distress| match distress {
                    Distress::Blackhole { after_ms } => Some(*after_ms),
                    _ => None,
                })
                .collect::<Option<Vec<u32>>>()?;
            match waited.len() >= 3 {
                true => waited
                    .into_iter()
                    .min()
                    .map(|after_ms| Distress::Blackhole { after_ms }),
                false => None,
            }
        })
        // Имя цели здесь обычно ПУСТО, и это не пробел: `SYN` тонет до `ClientHello`, то есть до
        // всякого SNI. Ключ §4 подставляет адрес — потому цель и названа, хотя имени не было.
        .on_target(|target, voiced| {
            if voiced.since < secs(1) {
                report!("адрес в блэкхоле целиком: {target} (все попытки соединиться тонут)")
            }
        })
        // Один прибор — один сигнал: `if let`, не `match`.
        .on(|target, distress| {
            if let Distress::Blackhole { after_ms } = distress {
                report!("IP-blackhole: {target} (SYN без ответа, повтор через {after_ms}мс)")
            }
        })
        .run()
}
