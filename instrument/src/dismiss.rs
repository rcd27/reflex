//! ЦЕЛЬ ЗАКРЫЛА РАЗГОВОР, НЕ СКАЗАВ НИ БАЙТА — отказ, который выглядит штатным завершением.
//!
//! # Класс, невидимый всей батарее
//!
//! Замер потребителя на живом трафике (цель воспроизводится стабильно):
//!
//! ```text
//! клиент  seq=1     len=1388   приветствие (1575 всего, двумя сегментами)
//! ЦЕЛЬ    seq=1     len=0      ···A···F   ← FIN, и seq=1: ни одного байта данных не было
//! клиент  seq=1575  len=0      ACK
//! ЦЕЛЬ    seq=1     len=0      FIN снова
//! клиент  seq=1     len=1388   повтор приветствия
//! ```
//!
//! Ни одного `RST` во всей записи, ни одного байта данных от цели. Клиент падает МГНОВЕННО — три
//! сотых секунды, не таймаут, — а браузер переоткрывает и получает то же самое по кругу. Человек
//! видит вечную крутилку; продукт за весь день не сказал об этой цели НИ СЛОВА.
//!
//! Почему молчит каждый прибор, и каждый ЗАКОННО:
//!
//! * сброс — `RST` нет вовсе, закрытие штатное;
//! * тишина — цель не молчит, она отвечает, причём немедленно;
//! * повтор клиента — повтор есть, но и ответ на разговор есть;
//! * проглоченный сегмент — сегмент не проглочен: приветствие подтверждено целиком;
//! * повтор цели — повторяет клиент, не цель.
//!
//! # Буквы не понадобилось, и это важно
//!
//! `Seen::Closed { by_client }` в алфавите БЫЛ с самого начала — прощание отделено от сброса
//! («сброс — беда, прощание — норма»). Не было того, кто заметит: прощание нормально, когда байты
//! отданы, и ненормально, когда их ноль. Предмет не в букве, а в ПАРЕ «прощание · ничего не
//! сказано», и заводить под него новую букву значило бы удвоить алфавит ради одного сочетания.
//!
//! # Чем отличается от сброса
//!
//! Способом и последствием. `RST` обрывает мгновенно и виден как беда; `FIN` после приветствия
//! выглядит вежливым завершением — и потому проходит мимо всякого, кто судит по грубым признакам.
//! Для человека разница нулевая: страница не открылась. Для лечения — существенная: сброс бывает
//! нашим собственным (у него есть автор), а вежливый отказ всегда чужой.
//!
//! # Что НЕ предмет: прощание после отданных байтов
//!
//! Обычное дело — keep-alive кончился, сервер закрыл соединение. Прибор молчит, и молчание верно.
//! Предмет тут ровно НОЛЬ байтов данных: цель приняла приветствие и ушла, ничего не сказав.

use smallvec::{smallvec, SmallVec};

use crate::distress::Distress;
use crate::wire::Seen;

/// Прибор вежливого отказа: цель закрылась, не отдав данных.
#[derive(Debug, Clone, Copy, Default)]
pub struct DismissInstrument {
    /// Момент, когда клиент попросил, — от него и меряется ожидание человека.
    asked: Option<std::time::Instant>,
    /// Отдала ли цель хоть байт ДАННЫХ. Подтверждения сюда не входят: они не ответ, а согласие
    /// ядра принять байты.
    spoke: bool,
    /// Ослепли на букве, прячущей наблюдения: байты цели могли пройти мимо нас.
    blinded: bool,
    /// Уже сказали.
    fired: bool,
}

impl DismissInstrument {
    pub fn new() -> DismissInstrument {
        DismissInstrument::default()
    }
}

impl reflex_core::mealy::Mealy for DismissInstrument {
    type In = reflex_core::DetectorEvent<Seen>;
    type Out = SmallVec<[Distress; 2]>;
    type Log = ();

    fn step(self, event: Self::In) -> (Self, Self::Out, ()) {
        // ОСЛЕПШИЙ О МОЛЧАНИИ ЦЕЛИ НЕ СУДИТ: обвинение строится из пары «просили · вниз ничего», а
        // прячущая буква могла забрать вторую половину. Снять слепоту нечем — утверждение
        // историческое; положительное наблюдение (байты цели) снимает подозрение своей веткой.
        if event.hides_observation() {
            return (
                DismissInstrument {
                    blinded: true,
                    ..self
                },
                SmallVec::new(),
                (),
            );
        }
        let (input, at) = match event {
            reflex_core::DetectorEvent::Packet { input, at } => (input, at),
            // Своих часов нет: предмет — прощание, а оно приходит буквой провода.
            reflex_core::DetectorEvent::Tick { .. }
            | reflex_core::DetectorEvent::Opaque { .. }
            | reflex_core::DetectorEvent::Torn { .. } => return (self, SmallVec::new(), ()),
        };

        match input {
            // Просьба клиента открывает отсчёт. Повтор не сдвигает: величина — ожидание человека с
            // ПЕРВОЙ отправки.
            Seen::Sent { .. }
            | Seen::Resent { .. }
            | Seen::Payload {
                from_client: true, ..
            } => (
                DismissInstrument {
                    asked: self.asked.or(Some(at)),
                    ..self
                },
                SmallVec::new(),
                (),
            ),
            // ЦЕЛЬ СКАЗАЛА — дальше её прощание есть обычный конец разговора.
            Seen::Received { .. }
            | Seen::Restated { .. }
            | Seen::Payload {
                from_client: false, ..
            } => (
                DismissInstrument {
                    spoke: true,
                    ..self
                },
                SmallVec::new(),
                (),
            ),
            // ПРОЩАНИЕ. Предмет — только от ЦЕЛИ, только при живой просьбе и только если она не
            // сказала ничего. Клиент, закрывший сам, ни в чём цель не обвиняет.
            Seen::Closed { by_client } => {
                match (by_client, self.spoke || self.blinded, self.asked, self.fired) {
                    (false, false, Some(asked), false) => (
                        DismissInstrument {
                            fired: true,
                            ..self
                        },
                        smallvec![Distress::Dismissed {
                            after_ms: at.saturating_duration_since(asked).as_millis() as u32,
                        }],
                        (),
                    ),
                    _ => (self, SmallVec::new(), ()),
                }
            }
        }
    }
}

impl crate::Instrument for DismissInstrument {
    type Signal = Distress;

    const INSTRUMENT: &'static str = "dismiss";

    /// О МИРЕ: предмет — поведение цели, а не наша способность смотреть.
    const SUBJECT: crate::Subject = crate::Subject::World;

    const LAYER: crate::Layer = crate::Layer::Transport;
    /// Только TCP: прощание есть состояние соединения, у датаграмм его нет вовсе — и это предел
    /// транспорта, названный в словаре провода, а не наша недоделка.
    const PROTOCOLS: &'static [crate::Protocol] = &[crate::Protocol::Tcp];
    const RUNG: Option<crate::Rung> = None;

    /// Часы ЧУЖИЕ: момент даёт сама цель своим `FIN`. Своего шага у прибора нет — ждать ему нечего.
    const CADENCE: crate::Cadence = crate::Cadence::Foreign;

    /// Событие: «закрыла, не сказав» — уже переход, и говорится один раз.
    const SHAPE: crate::Shape = crate::Shape::Event;

    /// Молчание — пустота: разговор либо не кончился, либо цель успела сказать. Своя слепота
    /// названа отдельно и гасит обвинение, а не превращается в него.
    const SILENCE: Option<crate::Silence> = Some(crate::Silence::Nothing);

    const LIES: &'static [&'static str] = &[
        "ПРИЧИНЫ НЕ ЗНАЕТ. Отказ по SNI, исчерпание ресурсов у сервера, ошибка приложения до \
         первого байта ответа — дают ОДНУ картину: приветствие принято, данных нет, соединение \
         закрыто вежливо. Прибор говорит «цель ушла, не сказав», и это всё.",
        "ПОДТВЕРЖДЕНИЯ ЗА ОТВЕТ НЕ СЧИТАЮТСЯ, и это выбор, а не упущение: `ACK` есть согласие ядра \
         принять байты, а не слово собеседника. Сервер, успевший отдать хоть байт и закрывшийся, \
         прибору не предмет — там обычное завершение.",
        "СЛЕПОТА ГАСИТ ОБВИНЕНИЕ НАВСЕГДА. Прячущая буква могла унести те самые байты, что сняли \
         бы подозрение, и снять слепоту нечем: утверждение историческое. Цена — пропущенный \
         отказ на потоке, где была дыра; обратное дало бы обвинение цели за нашу потерю.",
    ];

    const ORACLES: &'static [&'static str] = &["dismiss(sni,fin)", "keepalive(close_after_bytes)"];

    const DEATH: &'static str =
        "вежливый отказ получил причину: прибор отличает отказ по имени от исчерпания сервера";

    const EVENTS: &'static [&'static str] = &["dismissed"];

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

    fn at(start: Instant, ms: u64) -> Instant {
        start + Duration::from_millis(ms)
    }

    fn packet(input: Seen, when: Instant) -> DetectorEvent<Seen> {
        DetectorEvent::Packet { input, at: when }
    }

    fn hello() -> Seen {
        Seen::Payload {
            head: b"\x16\x03\x01hello".to_vec(),
            from_client: true,
        }
    }

    /// ПРЕДМЕТ: цель приняла приветствие и закрылась, не отдав НИ БАЙТА данных.
    #[test]
    fn a_target_that_closes_without_a_word_is_named() {
        let start = Instant::now();
        let instrument = DismissInstrument::new();

        let (instrument, said, ()) = instrument.step(packet(hello(), start));
        assert!(said.is_empty(), "просьба сама по себе бедой не является");

        let (_instrument, said, ()) =
            instrument.step(packet(Seen::Closed { by_client: false }, at(start, 30)));
        assert_eq!(
            said.as_slice(),
            [Distress::Dismissed { after_ms: 30 }],
            "прощание при нуле сказанного — отказ, и величина есть ожидание человека"
        );
    }

    /// Вторая половина пары: цель ОТДАЛА байты и закрылась — обычное завершение, не беда. Без неё
    /// первый тест зелен и на приборе, который кричит на каждом закрытом соединении.
    #[test]
    fn a_target_that_spoke_and_closed_is_not_trouble() {
        let start = Instant::now();
        let instrument = DismissInstrument::new();

        let (instrument, _, ()) = instrument.step(packet(hello(), start));
        let (instrument, _, ()) =
            instrument.step(packet(Seen::Received { count: 1400 }, at(start, 20)));
        let (_instrument, said, ()) =
            instrument.step(packet(Seen::Closed { by_client: false }, at(start, 30)));

        assert!(said.is_empty(), "сказала и ушла — обычное завершение");
    }

    /// Закрылся КЛИЕНТ — цель ни в чём не виновата. Человек закрыл вкладку, и объявлять это отказом
    /// значило бы послать лечить то, что не болит.
    #[test]
    fn a_client_that_closes_accuses_nobody() {
        let start = Instant::now();
        let instrument = DismissInstrument::new();

        let (instrument, _, ()) = instrument.step(packet(hello(), start));
        let (_instrument, said, ()) =
            instrument.step(packet(Seen::Closed { by_client: true }, at(start, 30)));

        assert!(said.is_empty(), "уход человека не обвиняет цель");
    }

    /// Своя слепота гасит обвинение: дыра могла унести те самые байты, что сняли бы подозрение.
    #[test]
    fn a_hiding_letter_silences_the_accusation() {
        let start = Instant::now();
        let instrument = DismissInstrument::new();

        let (instrument, _, ()) = instrument.step(packet(hello(), start));
        let (instrument, _, ()) = instrument.step(DetectorEvent::Torn { at: at(start, 10) });
        let (_instrument, said, ()) =
            instrument.step(packet(Seen::Closed { by_client: false }, at(start, 30)));

        assert!(said.is_empty(), "через дыру цель не обвиняем");
    }
}
