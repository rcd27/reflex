//! Слово края в области разговора и расслоение носителя. `Memo` — состояние как СЛОВО разговора
//! (`Of = Conversation`); `Told` — та же величина, сказанная о ПАКЕТЕ (`Of = Packet`); мост между
//! областями — `Descends` (спуск §5), не преобразование руками. Широкое слово транспорта становится
//! парой `(Reading, V)`, где `V: EdgeView` — вид края (носитель снаружи, §4); прибор провода
//! проецирует первый множитель, вид края не трогая.

use reflex_core::word::{Conversation, Descends, Packet, Word};
use reflex_core::Reads;

use crate::edge::Memo;
use crate::wire::{Reading, Seen, SeenTcp};

/// Памятка края — слово РАЗГОВОРА: состояние принадлежит потоку (ct-запись живёт весь разговор), не
/// пакету. Потому пара `(Distress, Memo)` собирается законом пары — обе половины об одном разговоре.
impl Word for Memo {
    type Of = Conversation;
}

/// То же состояние, сказанное о ПАКЕТЕ: НАШИ биты (`under`) и маска, под которой они лежат. Не
/// готовое слово ядра — его из памятки разговора произвести НЕЛЬЗЯ: запись есть read-modify-write,
/// а старое слово знает только край, читающий его из `NFQA_CT`. Край применяет одной операцией:
/// `(word & !told.mask) | told.under`.
pub struct Told {
    pub under: u32,
    pub mask: u32,
}

impl Word for Told {
    type Of = Packet;
}

/// Спуск памятки разговора в слово о пакете. Кодек ОДИН: `descends` зовёт ту же упаковку
/// (`Memo::under`/`mask`), что и `Layout::write` — два входа, одна упаковка, разойтись не могут.
impl Descends<Told> for Memo {
    fn descends(self) -> Told {
        Told {
            under: self.under(),
            mask: self.mask(),
        }
    }
}

/// Прибор провода читает провод из широкого слова `(Reading, V)`, проецируя первый множитель. Вид
/// края `V` ему безразличен — расслоение носителя (§4): каждый прибор сужает до своего множителя.
impl<V> Reads<(Reading, V)> for Seen {
    fn read(wide: &(Reading, V)) -> Option<Seen> {
        <Seen as Reads<Reading>>::read(&wide.0)
    }
}

/// ТРАНСПОРТ, ЧЕЙ СЛОВАРЬ ПРОВОДА УЖЕ ЕСТЬ ОБЩИЙ СЛОВАРЬ (QUIC), даёт широкое слово `(Seen, V)` —
/// и сужение здесь вырожденное: переводить нечего, словарь тот же. Не «лишний impl ради одного
/// транспорта»: без него прибор, читающий `Seen`, в такую цепочку не собирается ВООБЩЕ, и это
/// читалось бы как «прибор не годится для QUIC», хотя предмет у него транспортно-независимый.
impl<V> Reads<(Seen, V)> for Seen {
    fn read(wide: &(Seen, V)) -> Option<Seen> {
        Some(wide.0.clone())
    }
}

impl<V> Reads<(Reading, V)> for SeenTcp {
    fn read(wide: &(Reading, V)) -> Option<SeenTcp> {
        <SeenTcp as Reads<Reading>>::read(&wide.0)
    }
}

/// Сужение сквозь пару для приборов, которым нужны ОБЕ половины: провод и вид края. Тишине, скажем,
/// нужен и край (`up_packets == 0`), и провод (`Closed` уводит наблюдение в `Ended`). Локальный тип,
/// а не кортеж `(N, V)`: `impl Reads for (N, V)` в instrument запретило бы орфан-правило (`E0117` —
/// и трейт, и кортеж чужие), а `Self = Edged` локален.
pub struct Edged<N, V> {
    pub narrow: N,
    pub edge: V,
}

/// Сужение к паре: край берётся ВСЕГДА, провод — если он выразим в словаре прибора.
///
/// `narrow: Option<N>` не педантизм, а урок боя: `SYN` есть буква ТРАНСПОРТА (`SeenTcp::Syn`), в
/// общий словарь (`Seen`) она не сужается — и прибор, потребовавший провод целым, не увидел бы ни
/// одного пакета блэкхол-потока, где кроме `SYN` ничего и нет. Наблюдения он бы не пропустил, а
/// вовсе не получил: переход фазы не случился бы никогда.
///
/// Отсюда закон: краевой прибор обязан видеть КАЖДЫЙ пакет своего разговора, ибо предмет его —
/// состояние разговора в ядре, а не отдельное слово провода. Провод ему добавка, и добавка может
/// отсутствовать.
impl<N: Reads<Reading>, V: Clone> Reads<(Reading, V)> for Edged<Option<N>, V> {
    fn read(wide: &(Reading, V)) -> Option<Edged<Option<N>, V>> {
        Some(Edged {
            narrow: N::read(&wide.0),
            edge: wide.1.clone(),
        })
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
