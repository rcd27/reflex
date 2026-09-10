//! Прямое использование носителя WinDivert — НЕ цепочка фасада: `reflex-windivert` (задача 12) не
//! реализует `reflex::IntoCarrier` буквально (докблок `reflex_windivert`, раздел «предел
//! IntoCarrier» — дом трейта, крейт `reflex`, сегодня не кросс-проверяется на Windows по причине,
//! не связанной с WinDivert). Значит `engine(WinDivert::filter(..)).from(Tcp)...` здесь НЕ
//! СОБЕРЁТСЯ — а `WinDivert::filter(..).open()` и `Serves::serve` в цикле СОБИРАЮТСЯ: это
//! настоящий API крейта, не фасад над ним. Ниже — он, напрямую, один оборот.
//!
//! НИЧЕМ НЕ ПРОВЕРЕНО В ЭТОМ ПРОГОНЕ: ни `cargo check --target x86_64-pc-windows-msvc` (он смотрит
//! только на `-p reflex-windivert`, не на этот бинарь), ни тем более запуском — здесь нет Windows.
//! Названо прямо, чтобы зелёная сборка Linux (где тело ниже попросту не компилируется,
//! `#[cfg(windows)]`) не читалась как проверка этого текста.
//!
//! ЧЛЕН ВОРКСПЕЙСА НАРОЧНО, НЕ ИСКЛЮЧЁН — та же причина, что и у крейта `reflex-windivert`: пустой
//! (`#[cfg(not(windows))] fn main() {}`) бинарь на Linux ВИДЕН и собирается вместе со всем прочим,
//! исключённый гнил бы молча.

#[cfg(windows)]
fn main() {
    use reflex_core::serves::Served;
    use reflex_core::Serves;
    use reflex_windivert::WinDivert;

    let mut carrier = match WinDivert::filter("outbound and tcp.DstPort == 443").open() {
        Ok(carrier) => carrier,
        Err(why) => {
            eprintln!("WinDivert не открылся: {why:?}");
            return;
        }
    };

    // Один оборот ведущего цикла, вручную — то, что после связывания `IntoCarrier` сделает `drive`
    // фасада (`reflex/src/lib.rs`) сам, отдавая `decide` детекторам. Здесь решение тривиальное
    // (пропустить всё) — предмет иллюстрации носитель, не приборы.
    let until = std::time::Instant::now() + std::time::Duration::from_millis(500);
    match carrier.serve(until, |_held, _edge| reflex_core::local::Answer::Pass) {
        Served::Answered(outcome) => eprintln!("пакет отпущен: {outcome:?}"),
        Served::Idle => eprintln!("тишина за оборот"),
        Served::Blind => eprintln!("дескриптор не добыт"),
        Served::Torn(at) => eprintln!("носитель объявил дыру: {at:?}"),
    }
}

#[cfg(not(windows))]
fn main() {}
