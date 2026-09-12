//! ЦЕЛЬ ОТВЕЧАЕТ, А ОТВЕТЫ НЕ ДОХОДЯТ — прибор о фильтре «в обратную сторону».
//!
//! # Класс, который был невидим
//!
//! Всякая блокировка ответов выглядит одинаково: клиент доволен, цель старается, прогресса нет.
//! Наблюдателю она неотличима от медленного канала, а человеку — от сломанного сайта. Замер,
//! которым прибор оплачен (запись лаборатории, земля «дроп ответов после 16-го пакета»): цель шлёт
//! ОДИН И ТОТ ЖЕ сегмент с интервалами 0,5 · 0,9 · 1,8 · 3,4 · 6,7 секунды — это её RTO, — потом
//! клиент прощается.
//!
//! Батарея из пяти приборов молчала вся, и каждый молчал ЗАКОННО:
//!
//! * тишина и захлёбывание не видят беды — байты ИДУТ;
//! * троттлинг видит скорость, а не отсутствие прогресса: 1248 байт каждые несколько секунд есть
//!   скорость;
//! * повтор клиента ловит другую сторону, а её здесь нет вовсе;
//! * сброса нет — разговор кончается прощанием.
//!
//! Беда была не в приборах, а в АЛФАВИТЕ: повтор цели схлопывался в обычное «цель отдала». Сперва
//! заведена буква ([`crate::wire::Seen::Restated`]), теперь тот, кто ею судит.
//!
//! # Порог — РЯД, а не первый повтор
//!
//! Одиночный повтор бывает от обычной потери, и обвинять по нему значило бы кричать на всяком
//! здоровом разговоре (тот же довод, по которому прибор просадки ждёт двух окон подряд). Ряд
//! повторов БЕЗ ПРОДВИЖЕНИЯ — уже заявление стороны: цель не получает подтверждений и пробует
//! снова.
//!
//! # Продвижение сбрасывает счёт, и это существенно
//!
//! Свежие байты цели означают, что ответы доходят: потеря была обычной. Не сбрось — прибор копил бы
//! повторы за всю жизнь долгой закачки и однажды выстрелил бы на здоровом разговоре.
//!
//! # Своя слепота счёт тоже сбрасывает
//!
//! Прячущая буква ([`reflex_core::DetectorEvent::hides_observation`]) могла забрать ровно те свежие
//! байты, которые сняли бы подозрение. Копить через дыру значит обвинять цель за наш пропуск —
//! ровно тот класс, который §7 и держит клеткой.

use smallvec::{smallvec, SmallVec};

use crate::distress::Distress;
use crate::wire::Seen;

/// Сколько повторов подряд без продвижения считаем заявлением стороны. Два, а не один: одиночный
/// повтор — обычная потеря.
const ENOUGH: u32 = 2;

/// Прибор: цель повторяет ответ, прогресса нет.
#[derive(Debug, Clone, Copy, Default)]
pub struct UnreachedInstrument {
    /// Повторов цели подряд, без свежих байт между ними.
    retries: u32,
    /// Уже сказали — второй раз о том же не говорим.
    fired: bool,
}

impl UnreachedInstrument {
    pub fn new() -> UnreachedInstrument {
        UnreachedInstrument::default()
    }
}

impl reflex_core::mealy::Mealy for UnreachedInstrument {
    type In = reflex_core::DetectorEvent<Seen>;
    type Out = SmallVec<[Distress; 2]>;
    type Log = ();

    fn step(self, event: Self::In) -> (Self, Self::Out, ()) {
        // ЗАКОН СЛЕПОТЫ ПЕРЕД РАЗБОРОМ: прячущая буква могла забрать свежие байты, которые сняли бы
        // подозрение, — счёт начинается заново. Зовётся по имени, а не перечислением букв: не
        // всякое непонятое прячет наблюдение.
        if event.hides_observation() {
            return (
                UnreachedInstrument { retries: 0, ..self },
                SmallVec::new(),
                (),
            );
        }
        match event {
            reflex_core::DetectorEvent::Packet { input, .. } => match input {
                // Повтор цели без продвижения — счёт растёт; на пороге говорим ОДИН раз.
                Seen::Restated { .. } => {
                    let retries = self.retries.saturating_add(1);
                    match (retries >= ENOUGH, self.fired) {
                        (true, false) => (
                            UnreachedInstrument {
                                retries,
                                fired: true,
                            },
                            smallvec![Distress::Unreached { retries }],
                            (),
                        ),
                        _ => (
                            UnreachedInstrument { retries, ..self },
                            SmallVec::new(),
                            (),
                        ),
                    }
                }
                // ПРОДВИЖЕНИЕ: свежие байты цели говорят, что ответы доходят. Счёт с нуля — иначе
                // долгая закачка с редкими потерями однажды дала бы ложную тревогу.
                Seen::Received { .. }
                | Seen::Payload {
                    from_client: false, ..
                } => (UnreachedInstrument { retries: 0, ..self }, SmallVec::new(), ()),
                // Клиент здесь ни при чём: предмет — сторона ЦЕЛИ. Его просьбы и повторы счёта не
                // трогают, прощание тоже (разговор кончился, судить больше не о чем).
                Seen::Sent { .. }
                | Seen::Resent { .. }
                | Seen::Closed { .. }
                | Seen::Payload {
                    from_client: true, ..
                } => (self, SmallVec::new(), ()),
            },
            // Своих часов у прибора нет: порог даёт RTO ЦЕЛИ, а не наш тик. Узел сетки ему нечего
            // сказать — и это тождество, а не забывчивость.
            reflex_core::DetectorEvent::Tick { .. }
            | reflex_core::DetectorEvent::Opaque { .. }
            | reflex_core::DetectorEvent::Torn { .. } => (self, SmallVec::new(), ()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reflex_core::mealy::Mealy;
    use reflex_core::DetectorEvent;

    fn packet(input: Seen) -> DetectorEvent<Seen> {
        DetectorEvent::packet_now(input)
    }

    fn restated() -> Seen {
        Seen::Restated { count: 1248 }
    }

    /// ПРЕДМЕТ: ряд повторов цели без продвижения — заявление стороны, и прибор его называет.
    /// Величина в слове — сколько раз цель повторила: одиночная потеря и пятикратная попытка
    /// достучаться суть разные новости.
    #[test]
    fn a_run_of_target_repeats_without_progress_is_named() {
        let instrument = UnreachedInstrument::new();
        let (instrument, said, ()) = instrument.step(packet(restated()));
        assert!(said.is_empty(), "одиночный повтор — обычная потеря");

        let (_instrument, said, ()) = instrument.step(packet(restated()));
        assert_eq!(said.as_slice(), [Distress::Unreached { retries: 2 }]);
    }

    /// Вторая половина пары: ПРОДВИЖЕНИЕ снимает подозрение. Без неё тест выше зелен и на приборе,
    /// который кричит на всякой долгой закачке с редкими потерями.
    #[test]
    fn fresh_bytes_from_the_target_clear_the_count() {
        let instrument = UnreachedInstrument::new();
        let (instrument, _, ()) = instrument.step(packet(restated()));
        let (instrument, _, ()) = instrument.step(packet(Seen::Received { count: 1448 }));
        let (_instrument, said, ()) = instrument.step(packet(restated()));

        assert!(
            said.is_empty(),
            "после свежих байт счёт начинается заново — ответы доходят"
        );
    }

    /// Своя слепота счёт тоже сбрасывает: дыра могла забрать ровно те свежие байты, которые сняли
    /// бы подозрение. Копить через дыру значит обвинять цель за наш пропуск.
    #[test]
    fn a_hiding_letter_clears_the_count_too() {
        let instrument = UnreachedInstrument::new();
        let (instrument, _, ()) = instrument.step(packet(restated()));
        let (instrument, _, ()) = instrument.step(DetectorEvent::Torn {
            at: std::time::Instant::now(),
        });
        let (_instrument, said, ()) = instrument.step(packet(restated()));

        assert!(said.is_empty(), "через дыру счёт не копится");
    }

    /// Сказали один раз. Повторов у цели бывает пять-семь, следствие одно — и человеку незачем
    /// читать о нём пять раз.
    #[test]
    fn the_trouble_is_told_once() {
        let instrument = UnreachedInstrument::new();
        let (instrument, _, ()) = instrument.step(packet(restated()));
        let (instrument, said, ()) = instrument.step(packet(restated()));
        assert_eq!(said.len(), 1);

        let (_instrument, again, ()) = instrument.step(packet(restated()));
        assert!(again.is_empty(), "второй раз о том же не говорим");
    }
}

/// ПАСПОРТ. Дописан 11.09.2026 отдельной рукой: прибор был заведён без него, и сторож
/// (`instrument/tests/passport.rs`) это поймал. Всё ниже взято из докблока прибора и его тестов —
/// ничего не выведено догадкой; строки, которые знает только автор замера, названы пустыми честно.
impl crate::Instrument for UnreachedInstrument {
    type Signal = Distress;

    const INSTRUMENT: &'static str = "unreached";

    /// О мире: ответы цели не доходят — свойство пути, а не наше.
    const SUBJECT: crate::Subject = crate::Subject::World;

    /// Транспорт: улика — повтор ОДНОГО И ТОГО ЖЕ сегмента, а тождество сегмента даёт номер
    /// последовательности TCP.
    const LAYER: crate::Layer = crate::Layer::Transport;

    /// Только TCP, и по той же причине, что у прибора повтора КЛИЕНТА: у QUIC повтора номера нет
    /// (RFC 9000) — потерянное едет с новым номером, и `Restated` там не родится.
    const PROTOCOLS: &'static [crate::Protocol] = &[crate::Protocol::Tcp];

    /// Отвечала ли цель — прибор судит ровно об этом, но с ДРУГОЙ стороны, чем весь остальной парк:
    /// цель отвечает, ответы не доходят.
    const RUNG: Option<crate::Rung> = Some(crate::Rung::Answered);

    /// Чужой темп: порог задаёт RTO ЦЕЛИ (замер записи — 0,5 · 0,9 · 1,8 · 3,4 · 6,7 секунды).
    /// Свои часы сделали бы прибор второй копией прибора тишины.
    const CADENCE: crate::Cadence = crate::Cadence::Foreign;

    /// Событие: ряд повторов уже случился.
    const SHAPE: crate::Shape = crate::Shape::Event;

    /// Прибор смотрел: повторов подряд не было либо между ними шли свежие байты.
    const SILENCE: Option<crate::Silence> = Some(crate::Silence::Nothing);

    const LIES: &'static [&'static str] = &[
        "НЕ РАЗЛИЧАЕТ БЛОКИРОВКУ ОТВЕТОВ ОТ ОБЫЧНЫХ ПОТЕРЬ НА ОБРАТНОМ ПУТИ — зеркальный близнец          главной лжи прибора повтора клиента. Канал с потерями даёт тот же ряд повторов цели без          продвижения. Показание есть ПОДОЗРЕНИЕ, и действие по нему обязано иметь своё предусловие.",
        "ПОРОГ В ДВА ПОВТОРА НЕ ИЗМЕРЕН КАК ОПТИМУМ. Он взят по доводу соседа (прибор просадки ждёт          двух окон подряд): одиночный повтор бывает от обычной потери. Записи, на которой порог          сверялся бы с землёй, у этой константы нет.",
        "СЛЕПОТА И ПРОДВИЖЕНИЕ СБРАСЫВАЮТ СЧЁТ ОДИНАКОВО, а причины у них разные. Прячущая буква          могла забрать ровно те свежие байты, что сняли бы подозрение, — и прибор, сбросив счёт,          молчит там, где беда была. Это сознательный выбор (§7: обвинять цель за НАШ пропуск          дороже), но пропуск он и есть.",
    ];

    /// ПУСТО, И ЭТО НЕ ЗАБЫВЧИВОСТЬ. Прибор оплачен записью лаборатории (докблок: земля «дроп
    /// ответов после 16-го пакета»), но ИМЕНИ сценария с параметрами — того, что ведёт к земле и
    /// годится вторым оракулом, — знает автор замера, не дописывающий паспорт. Пустой список
    /// читается «второго оракула нет», и это сегодня правда.
    const ORACLES: &'static [&'static str] = &[];

    const DEATH: &'static str =
        "цель перестала повторять один и тот же сегмент — либо ответы дошли, либо разговор кончился";

    const EVENTS: &'static [&'static str] = &["unreached"];

    fn name(signal: &Self::Signal) -> &'static str {
        signal.name()
    }

    fn alarming(signal: &Self::Signal) -> bool {
        signal.alarming()
    }

    fn detail(signal: &Self::Signal) -> String {
        signal.detail()
    }
}
