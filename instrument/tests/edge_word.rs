//! Слово края: беда и памятка разговора образуют пару (одна область), а прибор провода сужает
//! широкое слово `(Reading, V)` к своему множителю, не трогая вид края `V`.

use reflex_core::word::Word;
use reflex_core::Reads;
use reflex_instrument::distress::Distress;
use reflex_instrument::edge::Memo;
use reflex_instrument::wire::{Reading, Seen, SeenTcp};

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
