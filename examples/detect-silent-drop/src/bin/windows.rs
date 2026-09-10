//! ВИТРИНА ВТОРОГО НОСИТЕЛЯ: та же цепочка, что у очереди, — разница в ПЕРВОЙ СТРОКЕ.
//!
//! Это и есть предъявление DoD ветки. Ниже `engine(…)` код совпадает с `src/main.rs` дословно:
//! те же приборы, тот же словарь бедствия, та же реакция. Отличается носитель, и только он.
//!
//! # Что здесь ПРОВЕРЕНО, а что нет — по факту, не по обещанию
//!
//! ПРОВЕРЕНО: `cargo check -p detect-silent-drop --target x86_64-pc-windows-msvc` собирает этот
//! бинарь. Форма цепочки над WinDivert годна — компилятор сказал это, а не докблок.
//!
//! Прежде такой проверки не было НИ У ЧЕГО: форма была названа доктестом в
//! `reflex_windivert::WinDivert::filter`, помеченным `ignore` — и помеченным честно, с причиной
//! («`cargo check` доктестов не собирает вовсе, `cargo test --doc` под MSVC отсюда не запустить»).
//! Бинарь снимает ровно этот предел: он не доктест, его кросс-сборка собирает.
//!
//! НЕ ПРОВЕРЕНО и отсюда проверено не будет: запуск. Здесь нет Windows и нет драйвера WinDivert.
//! Годна ФОРМА; работает ли она — скажет первый живой прогон, а не эта сборка.
//!
//! ЧЛЕН ВОРКСПЕЙСА НАРОЧНО: на Linux бинарь пуст (`#[cfg(not(windows))] fn main() {}`) и ВИДЕН —
//! исключённый гнил бы молча.

#[cfg(windows)]
fn main() -> reflex::Report {
    use reflex::*;
    use reflex_windivert::WinDivert;

    engine(WinDivert::filter("outbound and tcp.DstPort == 443"))
        .from(Tcp)
        .extract(Sni)
        .detect(Retransmit::unanswered()) // быстрое подозрение — по повтору клиента
        .detect(Silence::after(secs(5)))  // медленное подтверждение — по окну тишины
        .on(|target, distress| match distress {
            Distress::Retransmit { after_ms } => {
                report!("подозрение на тихий дроп: {target} (повтор через {after_ms}мс)")
            }
            Distress::Silence { ms } => report!("подтверждено: {target} молчит {ms}мс"),
            Distress::NoBytes => report!("подтверждено: {target} не ответил вовсе"),
            _ => {}
        })
        .run()
}

#[cfg(not(windows))]
fn main() {}
