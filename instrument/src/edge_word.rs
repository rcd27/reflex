//! Слово края в области разговора и расслоение носителя. `Memo` — состояние как СЛОВО разговора
//! (`Of = Conversation`); `Told` — та же величина, сказанная о ПАКЕТЕ (`Of = Packet`); мост между
//! областями — `Descends` (спуск §5), не преобразование руками. Широкое слово транспорта становится
//! парой `(Reading, V)`, где `V: EdgeView` — вид края (носитель снаружи, §4); прибор провода
//! проецирует первый множитель, вид края не трогая.

use reflex_core::word::{Conversation, Packet, Word};
use reflex_core::Reads;

use crate::edge::Memo;
use crate::wire::{Reading, Seen, SeenTcp};

/// Памятка края — слово РАЗГОВОРА: состояние принадлежит потоку (ct-запись живёт весь разговор), не
/// пакету. Потому пара `(Distress, Memo)` собирается законом пары — обе половины об одном разговоре.
impl Word for Memo {
    type Of = Conversation;
}

/// То же состояние, сказанное о ПАКЕТЕ, — спуск с разговора на пакет, где оно встречается с
/// вердиктом. Область пакетная: пара с вердиктом собирается, а с бедой разговора без спуска — нет.
pub struct Told(pub u32);

impl Word for Told {
    type Of = Packet;
}

/// Прибор провода читает провод из широкого слова `(Reading, V)`, проецируя первый множитель. Вид
/// края `V` ему безразличен — расслоение носителя (§4): каждый прибор сужает до своего множителя.
impl<V> Reads<(Reading, V)> for Seen {
    fn read(wide: &(Reading, V)) -> Option<Seen> {
        <Seen as Reads<Reading>>::read(&wide.0)
    }
}

impl<V> Reads<(Reading, V)> for SeenTcp {
    fn read(wide: &(Reading, V)) -> Option<SeenTcp> {
        <SeenTcp as Reads<Reading>>::read(&wide.0)
    }
}

/// Смешение областей не собирается: беда/памятка разговора (`Of = Conversation`) не склеивается со
/// словом о пакете (`Told`, `Of = Packet`) без спуска. Закон пары (`word.rs`) требует одной области.
///
/// ```compile_fail,E0277
/// use reflex_core::word::Word;
/// use reflex_instrument::edge::Memo;
/// use reflex_instrument::edge_word::Told;
/// fn takes<W: Word>() {}
/// // `Memo`(Conversation) и `Told`(Packet) — разные области: пара не есть слово.
/// takes::<(Memo, Told)>();
/// ```
#[allow(dead_code)]
struct AreasDoNotMix;
