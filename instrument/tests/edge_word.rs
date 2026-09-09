//! Слово края: беда и памятка разговора образуют пару (одна область), а прибор провода сужает
//! широкое слово `(Reading, V)` к своему множителю, не трогая вид края `V`.

use reflex_core::word::{Descends, Word};
use reflex_core::Reads;
use reflex_instrument::distress::Distress;
use reflex_instrument::edge::{Layout, Memo, Phase};
use reflex_instrument::edge_word::{Edged, Told};
use reflex_instrument::wire::{Reading, Seen, SeenTcp};

fn layout() -> Layout {
    Layout::new(0x0FFF_E000, 0b101).expect("15-битная маска, ненулевой тег")
}

/// Пара слов одной области — слово: беда и памятка края обе сказаны о разговоре.
#[test]
fn distress_and_memo_pair_up() {
    fn takes<W: Word>() {}
    takes::<(Distress, Memo)>();
}

/// Сужение широкого слова: прибор провода видит провод из пары `(Reading, V)`, вид края `V` ему
/// безразличен (здесь `V = ()` — любой). Буква провода читается, независимо от того, что за край.
#[test]
fn a_wire_instrument_narrows_past_the_edge_view() {
    let wide = (Reading::Udp(Seen::Sent { count: 1 }), ());
    assert!(
        matches!(
            <Seen as Reads<(Reading, ())>>::read(&wide),
            Some(Seen::Sent { count: 1 })
        ),
        "провод читается сквозь пару"
    );
}

/// И TCP-прибор так же сужает пару к своему алфавиту.
#[test]
fn a_tcp_instrument_narrows_past_the_edge_view() {
    let wide = (Reading::Tcp(SeenTcp::Syn), ());
    assert_eq!(
        <SeenTcp as Reads<(Reading, ())>>::read(&wide),
        Some(SeenTcp::Syn)
    );
}

/// Спуск сохраняет чужие биты: `Told` несёт наши биты и маску, край применит их RMW, чужая разметка
/// вне маски цела. Мутация «descends теряет маску» (mask = !0) затрёт чужое — тест краснеет.
#[test]
fn descent_preserves_foreign_bits() {
    let told = Memo::new(layout(), Phase::Suspected, 3).descends();
    let foreign = 0x2000_00FF;
    let written = (foreign & !told.mask) | told.under;
    assert_eq!(
        written & !told.mask,
        foreign,
        "вне маски спуска чужие биты целы"
    );
}

/// `Edged` несёт ОБЕ половины: провод (`narrow`) и вид края (`edge`). Прибору тишины нужны обе.
#[test]
fn edged_carries_both_wire_and_view() {
    let wide = (Reading::Udp(Seen::Sent { count: 1 }), 42u32);
    let edged = <Edged<Option<Seen>, u32> as Reads<(Reading, u32)>>::read(&wide).expect("сузилось");
    assert!(
        matches!(edged.narrow, Some(Seen::Sent { count: 1 })),
        "провод взят"
    );
    assert_eq!(edged.edge, 42, "вид края взят");
}

/// КРАЙ ВИДЕН ДАЖЕ ТАМ, ГДЕ ПРОВОД НЕВЫРАЗИМ — урок боевого регресса.
///
/// `SYN` есть буква ТРАНСПОРТА (`SeenTcp::Syn`), в общий словарь (`Seen`) она не сужается. Потребуй
/// краевой прибор провод целым — он не увидел бы ни одного пакета блэкхол-потока, где кроме `SYN`
/// ничего и нет: не «пропустил наблюдение», а не получил ни одного, и фаза не сдвинулась бы никогда.
/// Стенд блэкхола после переезда дал ровно это — ноль находок при живом дропе.
#[test]
fn край_доходит_даже_когда_провод_не_сужается() {
    let syn = (Reading::Tcp(SeenTcp::Syn), 7u32);
    let edged =
        <Edged<Option<Seen>, u32> as Reads<(Reading, u32)>>::read(&syn).expect("край доходит");

    assert!(
        edged.narrow.is_none(),
        "провод невыразим в общем словаре — и сказано это пустотой, а не потерей всей буквы"
    );
    assert_eq!(edged.edge, 7, "край на месте: прибор увидит пакет");
}
