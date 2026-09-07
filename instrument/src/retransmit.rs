//! ПОВТОР БЕЗ ОТВЕТА — самая ранняя улика молчаливого дропа, и единственный прибор парка,
//! которому часы не нужны вовсе.
//!
//! # Предмет: чьим порогом мы судим
//!
//! Соседи по батарее ([`crate::detect::SilenceInstrument`], [`crate::detect::ChokedInstrument`])
//! ждут НАШИМ терпением: константа кода, одна на цель за океаном и цель в соседней стойке — это
//! прямо записано в их режимах лжи. Здесь порог не наш: клиентское ядро уже отмерило RTO под
//! фактический RTT ИМЕННО ЭТОГО пути и высказалось повтором. Мы читаем чужие часы, откалиброванные
//! под каждую цель отдельно.
//!
//! Замер 04.09.2026 назвал цену разницы: первый повтор `ClientHello` приходит через ~360 мс, наше
//! терпение — 1500 мс, а без вмешательства человек ждёт от 2,3 до 12 секунд.
//!
//! # Что этот прибор НЕ утверждает
//!
//! Он не говорит «нас цензурируют». Документация ТСПУ (гл. 17.1.2, параметр `send RST off`,
//! «в проекте ТСПУ всегда должен быть в режиме off») описывает ровно ту картину, которую мы
//! замерили: соединение «отбрасывается молча», сессия висит до тайм-аута. Но НАЗВАТЬ автора —
//! работа расследования (`Finding::DpiSniGate` в стороннем крейте), а не
//! прибора: обычная потеря пакета в сети даёт ровно тот же повтор. Здесь говорится только то,
//! что видно на проводе.

use crate::distress::Distress;
use crate::wire::Seen;
use std::time::Instant;

/// ПРИБОР ПОВТОРА БЕЗ ОТВЕТА.
///
/// Состояние — три величины, и каждая отвечает на свой вопрос: когда человек попросил впервые
/// (отсюда величина показания), отдала ли цель хоть байт (иначе повтор законен) и жаловались ли
/// уже (второй раз о том же не жалуемся — следствие и так заведено).
#[derive(Debug, Clone, Copy)]
pub struct RetransmitInstrument {
    /// Когда человек попросил ВПЕРВЫЕ. `None` — просьбы ещё не видели.
    first_asked: Option<Instant>,
    /// Сколько байт цель отдала вниз. Ненуль снимает подозрение навсегда.
    down: u32,
    fired: bool,
}

impl Default for RetransmitInstrument {
    fn default() -> Self {
        Self::new()
    }
}

impl RetransmitInstrument {
    pub fn new() -> Self {
        Self {
            first_asked: None,
            down: 0,
            fired: false,
        }
    }
}

impl reflex_core::step::Step for RetransmitInstrument {
    type From = reflex_core::DetectorEvent<Seen>;
    type To = smallvec::SmallVec<[Distress; 2]>;

    /// Показаний этот прибор не заводит: он говорит, что увидел, и не говорит, чем мерил.
    type Notes = ();

    fn step(self, event: Self::From) -> (Self, Self::To, ()) {
        let (state, signals) = match event {
            reflex_core::DetectorEvent::Packet { input, at } => match input {
                // ПРОСЬБА ОТКРЫВАЕТ ОТСЧЁТ, и повторная его не сдвигает: величина показания есть
                // ожидание ЧЕЛОВЕКА, а он ждёт с первой отправки, а не с последней.
                Seen::Sent { .. } => (
                    Self {
                        first_asked: self.first_asked.or(Some(at)),
                        ..self
                    },
                    smallvec::SmallVec::new(),
                ),
                // ГОЛОВА КЛИЕНТА — ТОЖЕ ПРОСЬБА: `ClientHello` есть первое, чего он ждёт ответа,
                // и на нашем вантаже именно он и дропается.
                Seen::Payload { head, from_client } => match from_client {
                    true => (
                        Self {
                            first_asked: self.first_asked.or(Some(at)),
                            ..self
                        },
                        smallvec::SmallVec::new(),
                    ),
                    false => (
                        Self {
                            down: self.down + head.len() as u32,
                            ..self
                        },
                        smallvec::SmallVec::new(),
                    ),
                },
                Seen::Received { count } => (
                    Self {
                        down: self.down + count,
                        ..self
                    },
                    smallvec::SmallVec::new(),
                ),
                Seen::Resent { .. } => match (self.fired, self.down, self.first_asked) {
                    // ПРЕДМЕТ: повторили, а вниз не пришло ничего.
                    (false, 0, Some(asked)) => (
                        Self {
                            fired: true,
                            ..self
                        },
                        smallvec::smallvec![Distress::Retransmit {
                            after_ms: at.saturating_duration_since(asked).as_millis() as u32,
                        }],
                    ),
                    // ПРОСЬБЫ НЕ ВИДЕЛИ — поток подхвачен с середины, и величины у показания нет.
                    // Сказать «повтор через 0 мс» значило бы выдать свою слепоту за факт о мире.
                    (false, 0, None) => (self, smallvec::SmallVec::new()),
                    // Цель отдавала байты: повтор есть обычная сетевая потеря.
                    (false, 1.., _seen) => (self, smallvec::SmallVec::new()),
                    // Уже сообщали: ретрансмиссий на цель бывает 5–7, следствие заводится одно.
                    (true, _down, _seen) => (self, smallvec::SmallVec::new()),
                },
                // Прощание подозрения не снимает и не подтверждает: кто и почему закрыл разговор,
                // читают другие приборы.
                Seen::Closed { .. } => (self, smallvec::SmallVec::new()),
            },
            // ЧАСОВ НЕТ ВОВСЕ: порог этому прибору даёт RTO клиентского ядра, а не наш тик.
            reflex_core::DetectorEvent::Tick { .. } => (self, smallvec::SmallVec::new()),
            // Прибор мерит РАЗОБРАННЫЙ `Seen`; непонятое им не является — не сдвигает отсчёт
            // просьбы и не снимает подозрения, как и голый ACK/FIN.
            reflex_core::DetectorEvent::Opaque { .. } => (self, smallvec::SmallVec::new()),
        };
        (state, signals, ())
    }
}

impl crate::Instrument for RetransmitInstrument {
    type Signal = Distress;

    const INSTRUMENT: &'static str = "retransmit";

    /// О МИРЕ: утверждается, что цель не отвечает на просьбу, — свойство пути, а не наше и не
    /// человека.
    const SUBJECT: crate::Subject = crate::Subject::World;

    /// УРОВЕНЬ ТРАНСПОРТА: повтор опознаётся номером последовательности, а номер есть поле
    /// заголовка TCP.
    const LAYER: crate::Layer = crate::Layer::Transport;

    /// ТОЛЬКО TCP, и это не упущение. У QUIC ретрансмиссии не существует как наблюдаемого явления:
    /// RFC 9000 запрещает повтор номера пакета — потерянные кадры едут заново в пакете с НОВЫМ
    /// номером, и снаружи повтор неотличим от новых данных.
    const PROTOCOLS: &'static [crate::Protocol] = &[crate::Protocol::Tcp];

    /// ОТВЕТИЛИ ЛИ — прибор отвечает ровно на этот вопрос, и отвечает раньше всех в парке.
    const RUNG: Option<crate::Rung> = Some(crate::Rung::Answered);

    /// ЧУЖОЙ ТЕМП, И ЗДЕСЬ ОН НЕ КОМПРОМИСС, А ПРЕДМЕТ. Соседи по батарее ждут нашим терпением
    /// (константа кода); порог этого прибора — RTO клиентского ядра, отмеренный под RTT именно
    /// этого пути. Заведи ему свои часы — и он превратится в третью копию прибора тишины.
    const CADENCE: crate::Cadence = crate::Cadence::Foreign;

    /// СОБЫТИЕ: повтор уже случился, состояния тут нет.
    const SHAPE: crate::Shape = crate::Shape::Event;

    /// Прибор СМОТРЕЛ: повтора не было либо цель отвечала. Клетка `Blind` у него тоже есть — она
    /// названа в режимах лжи (поток, подхваченный с середины), но основной режим молчания этот.
    const SILENCE: Option<crate::Silence> = Some(crate::Silence::Nothing);

    const LIES: &'static [&'static str] = &[
        "НЕ РАЗЛИЧАЕТ БЛОКИРОВКУ ОТ ОБЫЧНОЙ ПОТЕРИ ПАКЕТА, и это главный его режим лжи. \
         Перегруженный канал даёт ровно тот же повтор при нулевом ответе. Отсюда следует, что \
         показание есть ПОДОЗРЕНИЕ, а не приговор: действие по нему (обрыв) обязано иметь \
         собственное предусловие, а не опираться на эту улику одну.",
        "ПОВТОР ЛЮБОГО СЕГМЕНТА, А НЕ ТОЛЬКО ПРИВЕТСТВИЯ. На нашем вантаже дропается `ClientHello` \
         (замер 04.09.2026, 9 целей), но прибор не проверяет, ЧТО повторили: повтор середины \
         запроса при нулевом ответе он назовёт тем же словом.",
        "ПОТОК, ПОДХВАЧЕННЫЙ С СЕРЕДИНЫ, ОСТАЁТСЯ НЕВИДИМЫМ. Просьбы прибор не видел, величины у \
         показания нет, и он молчит — это `Blind`, а не `Nothing`, и лечится оно другим прибором, \
         а не понижением порога здесь.",
        "ЧУЖИЕ ЧАСЫ НЕ НАБЛЮДАЕМЫ. Величина показания есть ожидание человека, но САМ RTO (когда \
         клиентское ядро решило повторить) нам не виден: два клиента с разной настройкой дадут \
         разные величины на одной и той же беде.",
    ];

    /// Сценарии стенда, где земля известна: дроп приветствия обязан дать повтор, чистый проход —
    /// не дать ни одного.
    const ORACLES: &'static [&'static str] = &["sni_drop(rutracker.org)", "pass"];

    /// СМЕРТЬ: если различитель «блокировка против сетевой потери» заведён (по TTL, по поведению
    /// соседних потоков к тому же узлу), подозрение станет приговором — и этот прибор либо
    /// поглотится им, либо перестанет быть отдельной буквой.
    const DEATH: &'static str =
        "заведён различитель «дроп цензора против потери в канале»; подозрение стало приговором";

    /// ПУБЛИЧНОЕ ИМЯ — одно, и оно уезжает меткой за границу процесса.
    const EVENTS: &'static [&'static str] = &["retransmit"];

    // ИМЯ, ТРЕВОЖНОСТЬ И ВЕЛИЧИНА — свойства БУКВЫ, и прибор их только передаёт. Первая редакция
    // этого файла (05.09.2026, часом раньше) несла все три таблицы своими копиями: заводя букву,
    // я воспроизвёл ровно то размазывание, на которое сам же и жаловался владельцу.
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

#[cfg(test)]
mod tests {
    use super::*;
    use reflex_core::step::Step;
    use reflex_core::DetectorEvent;
    use std::time::Duration;

    fn at(ms: u64) -> Instant {
        // Общее начало отсчёта на весь тест: `Instant` не конструируется из числа, и единственный
        // способ получить два сравнимых момента — оттолкнуться от одного.
        START.with(|start| *start + Duration::from_millis(ms))
    }

    thread_local! {
        static START: Instant = Instant::now();
    }

    fn packet(seen: Seen, ms: u64) -> DetectorEvent<Seen> {
        DetectorEvent::Packet {
            input: seen,
            at: at(ms),
        }
    }

    fn hello() -> Seen {
        Seen::Payload {
            head: b"\x16\x03\x01hello".to_vec(),
            from_client: true,
        }
    }

    /// ПРЕДМЕТ ПРИБОРА: человек попросил, цель не отдала ни байта, клиент повторил.
    #[test]
    fn a_repeat_with_nothing_back_is_the_suspicion() {
        let instrument = RetransmitInstrument::new();
        let (instrument, quiet, _) = instrument.step(packet(hello(), 0));
        assert!(quiet.is_empty(), "первая просьба бедой не является");

        let (_instrument, said, _) = instrument.step(packet(Seen::Resent { count: 517 }, 360));

        assert_eq!(
            said.as_slice(),
            [Distress::Retransmit { after_ms: 360 }],
            "повтор при нулевом ответе обязан быть уликой, и величина — ожидание человека"
        );
    }

    /// ВТОРАЯ ПОЛОВИНА ПАРЫ: тот же повтор, но цель успела ответить. Без этой проверки прибор
    /// объявлял бы бедой всякую сетевую потерю на живом соединении.
    #[test]
    fn a_repeat_after_the_target_answered_is_not_trouble() {
        let instrument = RetransmitInstrument::new();
        let (instrument, _, _) = instrument.step(packet(hello(), 0));
        let (instrument, _, _) = instrument.step(packet(Seen::Received { count: 1400 }, 120));

        let (_instrument, said, _) = instrument.step(packet(Seen::Resent { count: 517 }, 480));

        assert!(
            said.is_empty(),
            "цель отдала байты — повтор есть обычная потеря, а не блокировка"
        );
    }

    /// ЖАЛУЕМСЯ ОДИН РАЗ: следствие заводится однажды, а ретрансмиссий на цель бывает 5–7.
    #[test]
    fn only_the_first_repeat_speaks() {
        let instrument = RetransmitInstrument::new();
        let (instrument, _, _) = instrument.step(packet(hello(), 0));
        let (instrument, first, _) = instrument.step(packet(Seen::Resent { count: 517 }, 360));
        let (_instrument, second, _) = instrument.step(packet(Seen::Resent { count: 517 }, 1080));

        assert_eq!(first.len(), 1, "первый повтор говорит");
        assert!(second.is_empty(), "второй повтор о том же молчит");
    }

    /// ЧАСОВ У ПРИБОРА НЕТ, и это его паспорт: тик не порождает показания ни в каком состоянии.
    #[test]
    fn a_tick_says_nothing() {
        let instrument = RetransmitInstrument::new();
        let (instrument, _, _) = instrument.step(packet(hello(), 0));

        let (_instrument, said, _) = instrument.step(DetectorEvent::Tick {
            node: 9_000,
            at: at(9_000),
        });

        assert!(said.is_empty(), "прибор с чужим темпом в тишине нем");
    }
}
