//! СЕГМЕНТ ПРОГЛОЧЕН В ЖИВОМ РАЗГОВОРЕ — выборочный дроп, невидимый каждому прибору по отдельности.
//!
//! # Класс, который не видит никто
//!
//! Замер потребителя на живом трафике (цель воспроизводится стабильно, каждый заход та же картина):
//!
//! ```text
//! SYN · SYN-ACK · ACK          рукопожатие состоялось
//! seq=1     len=1388           голова приветствия — ДОШЛА
//! seq=1389  len=174            хвост, в нём конец имени
//! ACK                          ЦЕЛЬ ПОДТВЕРЖДАЕТ: разговор живой
//! seq=1389  len=174  ×6        клиент повторяет ТОЛЬКО ХВОСТ, и так до конца
//! ```
//!
//! Для человека это глухой таймаут. Для батареи — здоровый разговор, и каждый прибор молчит
//! ЗАКОННО: тишина не видит беды (цель отвечает), повтор цели — про другую сторону, а прибор
//! повтора клиента судит по БАЙТАМ вниз, которых здесь нет вовсе: цель шлёт только подтверждения.
//!
//! # Почему буквы не понадобилось
//!
//! Половина улики живёт в проводе («клиент повторяет»), половина — на КРАЮ («цель жива»):
//! подтверждения без данных события не рождают (чистый `ACK` — не наблюдение о содержимом), зато
//! край считает их пакетами. Прибор, читающий ОБЕ половины, видит то, чего не видит ни одна.
//!
//! Это и есть смысл `Edged`: не «удобно получить всё», а предметы, которые НЕ ВЫРАЗИМЫ ни в одной
//! половине. Здесь такой предмет впервые и появился.
//!
//! # Чем отличается от подозрения на тихий дроп
//!
//! Прибор повтора говорит «просили, вниз ничего» — подозрение, которое обычная сетевая потеря даёт
//! тоже. Здесь утверждение СИЛЬНЕЕ и уже: цель ДОКАЗАННО жива (подтвердила предыдущие байты) и при
//! этом именно этот сегмент не проходит. Обычная потеря так себя не ведёт: она бьёт по любому
//! сегменту, а не по одному и тому же раз за разом.
//!
//! Два слова об одном разговоре — не дубль: у них разная сила и разное лечение. Слить их значило бы
//! потерять либо раннее подозрение, либо точный диагноз.

use smallvec::{smallvec, SmallVec};

use reflex_core::edge::EdgeView;

use crate::distress::Distress;
use crate::edge_word::Edged;
use crate::wire::Seen;

/// Сколько повторов ОДНОГО сегмента при живой цели считаем выборочным дропом.
///
/// Два, а не один: первый повтор бывает от обычной потери, и кричать по нему значило бы обвинять
/// сеть в цензуре на каждой пачке. Ряд повторов при живой цели — уже заявление пути.
const ENOUGH: u32 = 2;

/// Прибор выборочного дропа: клиент повторяет, цель жива.
///
/// Род края — в фантоме, как у прибора тишины: экземпляр от `V` не зависит, а подпись `Mealy`
/// требует его связать. Без фантома `V` в `impl` не связан ничем (`E0207`).
// `Clone`/`Copy` руками, без бонда на `V`: род края живёт в фантоме, экземпляр от него не зависит,
// а `derive` приписал бы `V: Copy` и потребовал копируемости у того, чего мы не храним.
#[derive(Debug)]
pub struct SwallowInstrument<V> {
    /// Повторов клиента подряд, пока цель подтверждает.
    repeats: u32,
    /// Момент первого повтора — величина в слове есть ожидание человека с него.
    since: Option<std::time::Instant>,
    /// Уже сказали.
    fired: bool,
    edge: std::marker::PhantomData<fn() -> V>,
}

impl<V> Clone for SwallowInstrument<V> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<V> Copy for SwallowInstrument<V> {}

impl<V> Default for SwallowInstrument<V> {
    fn default() -> SwallowInstrument<V> {
        SwallowInstrument::new()
    }
}

impl<V> SwallowInstrument<V> {
    pub fn new() -> SwallowInstrument<V> {
        SwallowInstrument {
            repeats: 0,
            since: None,
            fired: false,
            edge: std::marker::PhantomData,
        }
    }
}

/// Жива ли цель НА ТРАНСПОРТНОМ уровне: ответила ли она хоть чем-то сверх рукопожатия.
///
/// Порог `>= 2` — тот же, что у прибора тишины, и по той же причине: один пакет вверх есть
/// `SYN+ACK`, то есть согласие ядра, а не собеседника. Второй — уже её работа.
fn alive<V: EdgeView>(edge: &V) -> bool {
    matches!(edge.up_packets(), Some(packets) if packets >= 2)
}

impl<V: EdgeView> reflex_core::mealy::Mealy for SwallowInstrument<V> {
    type In = reflex_core::DetectorEvent<Edged<Option<Seen>, Option<V>>>;
    type Out = SmallVec<[Distress; 2]>;
    type Log = ();

    fn step(self, event: Self::In) -> (Self, Self::Out, ()) {
        // Прячущая буква гасит счёт: дыра могла забрать ответ цели, и повтор через неё уже не
        // свидетельство пути, а наша слепота (§7).
        if event.hides_observation() {
            return (
                SwallowInstrument {
                    repeats: 0,
                    since: None,
                    ..self
                },
                SmallVec::new(),
                (),
            );
        }
        let (input, at) = match event {
            reflex_core::DetectorEvent::Packet { input, at } => (input, at),
            // Своих часов у прибора нет: порог даёт RTO клиентского ядра. Узел сетки ему нечего
            // сказать — тождество, не забывчивость.
            reflex_core::DetectorEvent::Tick { .. }
            | reflex_core::DetectorEvent::Opaque { .. }
            | reflex_core::DetectorEvent::Torn { .. } => return (self, SmallVec::new(), ()),
        };
        // Края нет — судить нечем: «цель жива» есть половина улики, и без неё вторая половина
        // (повтор) значит лишь подозрение, о котором говорит другой прибор.
        let Some(edge) = input.edge.as_ref() else {
            return (self, SmallVec::new(), ());
        };

        match input.narrow {
            // ПОВТОР КЛИЕНТА ПРИ ЖИВОЙ ЦЕЛИ — предмет. Живость спрашивается у КРАЯ, потому что
            // подтверждения без данных в проводе события не рождают.
            Some(Seen::Resent { .. }) if alive(edge) => {
                let repeats = self.repeats.saturating_add(1);
                let since = self.since.or(Some(at));
                match (repeats >= ENOUGH, self.fired) {
                    (true, false) => (
                        SwallowInstrument {
                            repeats,
                            since,
                            fired: true,
                            ..self
                        },
                        smallvec![Distress::Swallowed {
                            after_ms: at
                                .saturating_duration_since(since.unwrap_or(at))
                                .as_millis() as u32,
                        }],
                        (),
                    ),
                    _ => (
                        SwallowInstrument {
                            repeats,
                            since,
                            ..self
                        },
                        SmallVec::new(),
                        (),
                    ),
                }
            }
            // ЦЕЛЬ ОТДАЛА БАЙТЫ — сегмент прошёл, счёт с нуля. Иначе долгая закачка с редкими
            // потерями однажды дала бы ложную тревогу.
            Some(Seen::Received { .. })
            | Some(Seen::Restated { .. })
            | Some(Seen::Payload {
                from_client: false, ..
            }) => (
                SwallowInstrument {
                    repeats: 0,
                    since: None,
                    ..self
                },
                SmallVec::new(),
                (),
            ),
            // Прочее счёта не трогает: свежая просьба клиента — не повтор, прощание кончает
            // разговор, а повтор при МЁРТВОЙ цели есть предмет прибора повтора, не наш.
            Some(Seen::Resent { .. })
            | Some(Seen::Sent { .. })
            | Some(Seen::Closed { .. })
            | Some(Seen::Payload {
                from_client: true, ..
            })
            | None => (self, SmallVec::new(), ()),
        }
    }
}

impl<V: EdgeView> crate::Instrument for SwallowInstrument<V> {
    type Signal = Distress;

    const INSTRUMENT: &'static str = "swallow";

    /// О МИРЕ: предмет — путь между клиентом и целью, а не наша способность смотреть.
    const SUBJECT: crate::Subject = crate::Subject::World;

    const LAYER: crate::Layer = crate::Layer::Transport;
    /// Только TCP: предмет стоит на ПОВТОРЕ КОНКРЕТНОГО СЕГМЕНТА, а у датаграмм ни номеров, ни
    /// подтверждений нет — повтор там неразличим по построению.
    const PROTOCOLS: &'static [crate::Protocol] = &[crate::Protocol::Tcp];
    const RUNG: Option<crate::Rung> = None;

    /// Часы ЧУЖИЕ: порог даёт RTO клиентского ядра под фактический RTT, а не наш тик. Свой шаг
    /// здесь означал бы, что мы решаем, когда клиенту повторять.
    const CADENCE: crate::Cadence = crate::Cadence::Foreign;

    /// СОБЫТИЕ: «сегмент перестал проходить» — уже переход, и говорится оно один раз. Не величина:
    /// `after_ms` объясняет, сколько человек ждал, но новость не в числе, а в том, что это
    /// случилось.
    const SHAPE: crate::Shape = crate::Shape::Event;

    /// Молчание — ПУСТОТА, не слепота: пока повтора при живой цели нет, говорить не о чем, и это
    /// факт о разговоре, а не о нас. Своя слепота у прибора названа отдельно — прячущая буква
    /// гасит счёт.
    const SILENCE: Option<crate::Silence> = Some(crate::Silence::Nothing);

    const LIES: &'static [&'static str] = &[
        "ПРИЧИНЫ НЕ ЗНАЕТ. Выборочный дроп по сигнатуре, потеря на перегруженном канале, битый \
         MTU-путь без ICMP — дают ОДНУ картину: клиент повторяет, цель подтверждает прежнее. \
         Прибор говорит «этот сегмент не проходит, а разговор жив», и это всё, что он \
         устанавливает.",
        "ЖИВОСТЬ БЕРЁТСЯ У КРАЯ, значит наследует его предел: край, ведущий счёт по дошедшим до \
         НАС кадрам (`Local`), при нашей же дыре занизит `up_packets` — и прибор промолчит там, \
         где цель на самом деле отвечала. Ошибка в сторону молчания, не в сторону обвинения.",
        "ПОРОГ В ДВА ПОВТОРА ВЫБРАН ПО РОДУ, А НЕ ПО ЗАМЕРУ. Одиночный повтор — обычная потеря, \
         это известно; сколько повторов отличают цензуру от плохого канала — не замерено, и \
         число будет уточняться первой же записью, где путь просто плох.",
    ];

    /// Оракулы: выборочный дроп хвоста при живом разговоре — и контроль, где повторы идут при
    /// МЁРТВОЙ цели (там говорить обязан прибор повтора, а этот молчать).
    const ORACLES: &'static [&'static str] = &["swallow(tail,alive)", "silentdrop(1.2.3.4)"];

    const DEATH: &'static str =
        "выборочный дроп получил причину: прибор отличает цензуру пути от плохого канала";

    const EVENTS: &'static [&'static str] = &["swallowed"];

    fn name(signal: &Self::Signal) -> &'static str {
        signal.name()
    }

    fn alarming(signal: &Self::Signal) -> bool {
        let _ = signal;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reflex_core::mealy::Mealy;
    use reflex_core::DetectorEvent;
    use std::time::{Duration, Instant};

    /// Край сценария: столько пакетов вверх, сколько сказано. Прочее приборy безразлично.
    #[derive(Debug, Clone, Copy)]
    struct Edge {
        up: u64,
    }

    impl EdgeView for Edge {
        fn down_packets(&self) -> Option<u64> {
            None
        }
        fn up_packets(&self) -> Option<u64> {
            Some(self.up)
        }
        fn down_bytes(&self) -> Option<u64> {
            None
        }
        fn up_bytes(&self) -> Option<u64> {
            None
        }
        fn idle(&self) -> Option<Duration> {
            None
        }
        fn age(&self) -> Option<Duration> {
            None
        }
        fn mark(&self) -> u32 {
            0
        }
    }

    fn letter(narrow: Option<Seen>, up: u64, at: Instant) -> DetectorEvent<Edged<Option<Seen>, Option<Edge>>> {
        DetectorEvent::Packet {
            input: Edged {
                narrow,
                edge: Some(Edge { up }),
            },
            at,
        }
    }

    fn resent() -> Option<Seen> {
        Some(Seen::Resent { count: 174 })
    }

    /// ПРЕДМЕТ: клиент повторяет один и тот же сегмент, а цель ПОДТВЕРЖДАЕТ (жива на транспорте).
    /// Ни один прибор по отдельности этого не видит: провод не знает о подтверждениях, край не
    /// знает о повторе.
    #[test]
    fn a_repeat_while_the_target_acknowledges_is_a_swallowed_segment() {
        let now = Instant::now();
        let instrument = SwallowInstrument::<Edge>::new();

        let (instrument, said, ()) = instrument.step(letter(resent(), 3, now));
        assert!(said.is_empty(), "первый повтор — обычная потеря");

        let (_instrument, said, ()) =
            instrument.step(letter(resent(), 3, now + Duration::from_millis(250)));
        assert_eq!(
            said.as_slice(),
            [Distress::Swallowed { after_ms: 250 }],
            "ряд повторов при живой цели обязан быть назван, и величина — ожидание человека"
        );
    }

    /// Вторая половина пары: цель НЕ ЖИВА (только `SYN+ACK`) — это предмет прибора повтора, не наш.
    /// Без этой половины первый тест зелен и на приборе, который кричит на всяком повторе.
    #[test]
    fn a_repeat_while_the_target_is_mute_is_not_ours() {
        let now = Instant::now();
        let instrument = SwallowInstrument::<Edge>::new();

        let (instrument, _, ()) = instrument.step(letter(resent(), 1, now));
        let (_instrument, said, ()) =
            instrument.step(letter(resent(), 1, now + Duration::from_millis(250)));

        assert!(
            said.is_empty(),
            "один пакет вверх — это `SYN+ACK` ядра, а не работа собеседника"
        );
    }

    /// Байты вниз означают, что сегмент прошёл: счёт с нуля. Иначе долгая закачка с редкими
    /// потерями однажды дала бы ложную тревогу.
    #[test]
    fn bytes_from_the_target_clear_the_count() {
        let now = Instant::now();
        let instrument = SwallowInstrument::<Edge>::new();

        let (instrument, _, ()) = instrument.step(letter(resent(), 3, now));
        let (instrument, _, ()) = instrument.step(letter(Some(Seen::Received { count: 1400 }), 4, now));
        let (_instrument, said, ()) =
            instrument.step(letter(resent(), 4, now + Duration::from_millis(250)));

        assert!(said.is_empty(), "после прохода сегмента счёт начинается заново");
    }

    /// Своя слепота счёт гасит: дыра могла забрать ответ цели, и повтор через неё — не улика пути.
    #[test]
    fn a_hiding_letter_clears_the_count() {
        let now = Instant::now();
        let instrument = SwallowInstrument::<Edge>::new();

        let (instrument, _, ()) = instrument.step(letter(resent(), 3, now));
        let (instrument, _, ()) = instrument.step(DetectorEvent::Torn { at: now });
        let (_instrument, said, ()) =
            instrument.step(letter(resent(), 3, now + Duration::from_millis(250)));

        assert!(said.is_empty(), "через дыру счёт не копится");
    }
}
