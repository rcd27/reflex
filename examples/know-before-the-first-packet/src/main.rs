//! # Знать до первого пакета
//!
//! Гео-заглушка ChatGPT лежит внутри TLS, и по байтам её не отличить от ответа: прибору нечего
//! увидеть. Банк, увидевший чужую страну, ломается раньше, чем прибор успеет передумать. Такое
//! знание приходит заранее, и наблюдение его не перебивает.
//!
//! Адрес из ответа на известное имя наследует его знание — и тогда решение ложится уже на `SYN`.
//!
//! ## Запуск
//!
//! ```sh
//! sudo nft 'add table inet reflex_demo'
//! sudo nft 'add chain inet reflex_demo out { type filter hook output priority -150; }'
//! sudo nft 'add rule inet reflex_demo out udp dport 53 queue num 202'
//! sudo nft 'add chain inet reflex_demo inp { type filter hook input priority -150; }'
//! sudo nft 'add rule inet reflex_demo inp udp sport 53 queue num 202'
//! cargo run -p know-before-the-first-packet
//! # снять правила: sudo nft 'delete table inet reflex_demo'
//! ```

use std::net::Ipv4Addr;

use reflex::telling::{Known, Region, Telling};
use reflex::*;

const STRAIGHT: u32 = 0x1;
const CONTOUR: u32 = 0xC;

fn main() -> Result<Report, Box<dyn std::error::Error>> {
    let leg = Region::new(0x0000_0F00).ok_or("область решений обязана быть связной")?;
    let telling = Telling::over(leg)
        .knowing(Known::suffixes(["gosuslugi.ru", "alfabank.ru"]).marked(STRAIGHT))?
        .knowing(Known::suffixes(["chatgpt.com", "openai.com"]).marked(CONTOUR))?;
    let answers = telling.clone();

    Ok(engine(Nfqueue::queue(202))
        .from(Udp)
        .extract(Sni)
        .detect(Resolve::names())
        .telling(telling)
        .on(move |name, resolved| match resolved {
            Resolved::Honest { addrs, .. } => {
                addrs.into_iter().map(Ipv4Addr::from).for_each(|addr| {
                    match answers.bind(addr.to_string(), name) {
                        Some(STRAIGHT) => report!("{name} → {addr}: всегда прямо"),
                        Some(CONTOUR) => report!("{name} → {addr}: в контур с первого пакета"),
                        Some(other) => report!("{name} → {addr}: решено заранее {other:#x}"),
                        None => (),
                    }
                })
            }
            Resolved::Hijacked { .. } | Resolved::Erased { .. } => (),
        })
        .run())
}
