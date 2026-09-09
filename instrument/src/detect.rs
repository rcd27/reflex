//! Пять приборов провода: сброс, тишина, троттлинг, захлёбывание, IP-blackhole. Каждый — машина Мили `Mealy`:
//! состояние в подписи, часы буквой `DetectorEvent::Tick`, доменное знание надевается снаружи
//! комбинаторами (`lmap`/`contextual`). Слово у всех — `Distress` (что видно, без слова о лечении),
//! адресовано разговору. Отсутствие беды сигналом не является: прибор молчит.

use crate::distress::Distress;
use crate::wire::{ResetBy, Seen, SeenTcp};
use std::time::{Duration, Instant};

// Имя беды живёт у буквы (`Distress::name`), не здесь: сторожит
// `distress::tests::the_alphabet_of_trouble_is_spelled_out_in_exactly_one_file`.

/// Детектор сброса. Прибор о мире: путь ломают снаружи. Ось `answered` (отдала ли цель байт до
/// сброса) отделяет перехват от прощания.
#[derive(Debug, Clone, Copy, Default)]
pub struct RstInstrument {
    /// Уже жаловались.
    fired: bool,
    /// Отдала ли цель хоть байт до сброса.
    answered: bool,
}

impl RstInstrument {
    pub fn new() -> Self {
        Self::default()
    }
}

impl reflex_core::mealy::Mealy for RstInstrument {
    /// Словарь соединения: сброс — улика TCP, прибор в поток датаграмм не собирается.
    type In = reflex_core::DetectorEvent<SeenTcp>;
    /// Беда. `Option` в сигнале сделал бы «всё в порядке» сообщением в ленте.
    type Out = smallvec::SmallVec<[Distress; 2]>;
    type Log = ();

    /// Подпись перехвата: сброс от цели ДО первого её байта (так отвечают на `ClientHello`). Замер
    /// 29.08: 23 сброса — 17 наших, 6 от цели после байтов, бед ноль, движок объявил 12. Цена:
    /// сброс посреди живой сессии пропускается (от штатного закрытия неотличим).
    fn step(self, event: Self::In) -> (Self, Self::Out, ()) {
        let (state, signals) = match event {
            reflex_core::DetectorEvent::Packet { input, .. } => {
                match (&input, self.fired, self.answered) {
                    (
                        SeenTcp::Rst {
                            by: ResetBy::TargetSide,
                        },
                        false,
                        false,
                    ) => (
                        Self {
                            fired: true,
                            ..self
                        },
                        smallvec::smallvec![Distress::Rst],
                    ),
                    // Цель заговорила — дальше её сброс неотличим от конца разговора.
                    (SeenTcp::Anywhere(Seen::Received { .. }), _fired, _answered) => (
                        Self {
                            answered: true,
                            ..self
                        },
                        smallvec::SmallVec::new(),
                    ),
                    (SeenTcp::Anywhere(Seen::Payload { from_client, .. }), _fired, _answered) => (
                        Self {
                            answered: self.answered || !from_client,
                            ..self
                        },
                        smallvec::SmallVec::new(),
                    ),
                    // Ни человек, ни наш приказ бедой цели не являются.
                    (SeenTcp::Rst { .. }, _fired, _answered)
                    | (SeenTcp::Syn, _fired, _answered)
                    | (SeenTcp::Handshaken, _fired, _answered)
                    | (SeenTcp::AskedToWait { .. }, _fired, _answered)
                    | (SeenTcp::Anywhere(Seen::Sent { .. }), _fired, _answered)
                    | (SeenTcp::Anywhere(Seen::Resent { .. }), _fired, _answered)
                    | (SeenTcp::Anywhere(Seen::Closed { .. }), _fired, _answered) => {
                        (self, smallvec::SmallVec::new())
                    }
                }
            }
            // Сброс сам есть момент: часы не нужны. Непонятое — не улика TCP.
            reflex_core::DetectorEvent::Tick { .. } | reflex_core::DetectorEvent::Opaque { .. } => {
                (self, smallvec::SmallVec::new())
            }
        };
        (state, signals, ())
    }
}

impl crate::Instrument for RstInstrument {
    type Signal = Distress;

    const INSTRUMENT: &'static str = "rst";

    const SUBJECT: crate::Subject = crate::Subject::World;

    /// Сброс существует только у TCP (у QUIC обрыв в шифре).
    const LAYER: crate::Layer = crate::Layer::Transport;
    const PROTOCOLS: &'static [crate::Protocol] = &[crate::Protocol::Tcp];
    const RUNG: Option<crate::Rung> = Some(crate::Rung::Severed);

    /// Пакет: сброс сам есть событие.
    const CADENCE: crate::Cadence = crate::Cadence::Foreign;

    const SHAPE: crate::Shape = crate::Shape::Event;

    /// Событие приходит готовым, клетки `Blind` нет.
    const SILENCE: Option<crate::Silence> = Some(crate::Silence::Nothing);

    const LIES: &'static [&'static str] = &[
        "НЕ РАЗЛИЧАЕТ ОТКАЗ СЕРВЕРА ОТ ИНЖЕКТА ПОСТОРОННЕГО (#320, Н10). Оба приходят как \
         `ResetBy::TargetSide` и оба дают `Distress::Rst`, а лечение противоположно: в первом \
         случае цель не работает и техника бесполезна, во втором работает и техника нужна. \
         Различитель есть на проводе (TTL, фингерпринт окна и флагов) и не читается ничем.",
        "СБРОС ПОСРЕДИ ЖИВОЙ СЕССИИ ПРОПУСКАЕТСЯ: от штатного закрытия он неотличим ничем, что \
         видно на проводе. Цена названа в докстринге детектора с 29.08.",
        "ОДНО РАЗЛИЧЕНИЕ ВСЁ ЕЩЁ ЗАПИСАНО ДВАЖДЫ — но копий стало не три, а две. Копия в \
         `domain::wire::Rst` СНЯТА 02.09 (#320): она и была тем разъездом, который этот пункт \
         предсказал. Остался мост `app::distress::trouble` над наблюдением ПЛОСКОСТИ: у него другой \
         вход (`Sighting`, не `Seen`), потому механической сверки нет. Совпадают сегодня и \
         разойдутся молча.",
        "ПИТАНИЕ КАНАЛА НЕ ИЗМЕРЕНО НИ ОДНИМ ПРИБОРОМ. Компилятор видит связь, стенд — различение; \
         идут ли по каналу пакеты — не видит никто. Правила ядра на `output`/`input` не покрывают \
         транзитный клиентский трафик.",
    ];

    const ORACLES: &'static [&'static str] = &["sni_rst(rutracker.org)", "syn_drop(1.2.3.4)"];

    const DEATH: &'static str = "различитель инжекта по TTL заведён; `Distress::Rst` расщеплён";

    const EVENTS: &'static [&'static str] = &["rst"];

    fn name(signal: &Self::Signal) -> &'static str {
        signal.name()
    }

    fn alarming(signal: &Self::Signal) -> bool {
        signal.alarming()
    }
}

/// Детектор тишины. Первый прибор парка со своими часами: предмет — отсутствие событий, пакета
/// ждать не может (пакет и есть то, чего нет).
#[derive(Debug, Clone, Copy)]
pub struct SilenceInstrument {
    /// Сколько молчания терпим (тратит наше время, не человека — он уже обслужен).
    after: Duration,
    /// Момент последнего события. `None` — мерить не от чего.
    last: Option<Instant>,
    /// Байт от цели вниз. Ось, различающая `NoBytes` и `Silence`.
    bytes: u32,
    watch: Watch,
    /// Ждёт ли человек прямо сейчас (просьба ушла, ответа не было). Молчание есть беда, только если
    /// его кто-то ждёт (замер 29.08: `vk.com` за 296 мс получал `Silence` от простаивающего
    /// keep-alive).
    awaiting: bool,
}

/// Что делает наблюдение за разговором. Вариант типа, не два флага (четвёртая комбинация
/// бессмысленна). Открыт, ибо входит в показание: две клетки из трёх глушат прибор навсегда.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Watch {
    /// Смотрим и готовы пожаловаться.
    Open,
    /// Уже пожаловались.
    Fired,
    /// Разговор окончен: молчание попрощавшегося — не улика (тики идут, но их порождает чужой
    /// трафик).
    Ended,
}

impl SilenceInstrument {
    pub fn after(after: Duration) -> Self {
        Self {
            after,
            last: None,
            bytes: 0,
            watch: Watch::Open,
            awaiting: false,
        }
    }
}

/// Чем мерили — величины, по которым принято решение. Четыре оси несущие: сколько молчали, байт от
/// цели, ждёт ли человек, смотрит ли прибор ещё (`Watch`: `Fired`/`Ended` глушат навсегда). Порога
/// нет: `after` — настройка прибора, а показание несёт наблюдённое.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Measured {
    pub since_ms: u32,
    pub bytes: u32,
    pub awaiting: bool,
    /// Смотрит ли прибор ещё.
    pub watch: Watch,
}

impl reflex_core::mealy::Mealy for SilenceInstrument {
    type In = reflex_core::DetectorEvent<Seen>;
    /// Две беды: `NoBytes` (не ответила вовсе) и `Silence` (поток встал) — различает счётчик байтов.
    type Out = smallvec::SmallVec<[Distress; 2]>;
    /// `None` — мерить не от чего.
    type Log = Option<Measured>;

    fn step(self, event: Self::In) -> (Self, Self::Out, Option<Measured>) {
        // Четыре величины ДО шага: тик, заводящий отсчёт впервые (`last: None`), решает по тому же
        // `self`, и показание обязано назвать те же значения, а не пересчитанные.
        let before_last = self.last;
        let before_bytes = self.bytes;
        let before_awaiting = self.awaiting;
        let before_watch = self.watch;
        let at = event.at();
        let (state, signals) = match event {
            reflex_core::DetectorEvent::Packet { input, at } => {
                // Тишина меряется по ответу ЦЕЛИ.
                let bytes = match &input {
                    Seen::Received { count } => self.bytes + count,
                    Seen::Payload { head, from_client } => match from_client {
                        true => self.bytes,
                        false => self.bytes + head.len() as u32,
                    },
                    Seen::Sent { .. } | Seen::Resent { .. } | Seen::Closed { .. } => self.bytes,
                };
                // Просьба вверх открывает ожидание, ответ вниз закрывает.
                let awaiting = match &input {
                    Seen::Sent { .. } | Seen::Resent { .. } => true,
                    Seen::Payload { from_client, .. } => *from_client,
                    Seen::Received { .. } => false,
                    Seen::Closed { .. } => self.awaiting,
                };
                let watch = match &input {
                    Seen::Closed { .. } => Watch::Ended,
                    Seen::Sent { .. }
                    | Seen::Resent { .. }
                    | Seen::Received { .. }
                    | Seen::Payload { .. } => self.watch,
                };
                // Часы молчания НЕ двигает клиентский ПОВТОР: ретрансмиссия той же просьбы есть
                // симптом тишины, а не её разрыв. Считай повтор активностью — и при тихом дропе,
                // где клиент шлёт `ClientHello` заново каждую секунду, окно тишины не набралось бы
                // никогда (замер на боевом трафике: `rutracker.org` за ТСПУ). Первую засечку повтор
                // всё же ставит (`or`): если разговор увиден с середины, мерить надо от него.
                let last = match &input {
                    Seen::Resent { .. } => self.last.or(Some(at)),
                    Seen::Sent { .. }
                    | Seen::Received { .. }
                    | Seen::Payload { .. }
                    | Seen::Closed { .. } => Some(at),
                };
                (
                    Self {
                        last,
                        bytes,
                        watch,
                        awaiting,
                        ..self
                    },
                    smallvec::SmallVec::new(),
                )
            }
            reflex_core::DetectorEvent::Tick { at, .. } => match (self.last, self.watch) {
                // Цель, не ответившая вовсе, уличается и без просьбы: соединение открыто, байтов нет.
                (Some(last), Watch::Open)
                    if at.duration_since(last) >= self.after
                        && (self.awaiting || self.bytes == 0) =>
                {
                    let distress = match self.bytes {
                        0 => Distress::NoBytes,
                        _seen => Distress::Silence {
                            ms: at.duration_since(last).as_millis() as u32,
                        },
                    };
                    (
                        Self {
                            watch: Watch::Fired,
                            ..self
                        },
                        smallvec::smallvec![distress],
                    )
                }
                // Часы заводит первый тик, не первое событие: у потока с дропом `SYN` общих букв нет
                // вовсе, и наблюдением часы остались бы `None` навсегда.
                (None, Watch::Open) => (
                    Self {
                        last: Some(at),
                        ..self
                    },
                    smallvec::SmallVec::new(),
                ),
                // Порог не истёк, либо следствие заведено, либо разговор окончен.
                (Some(_), Watch::Open)
                | (Some(_), Watch::Fired)
                | (Some(_), Watch::Ended)
                | (None, Watch::Fired)
                | (None, Watch::Ended) => (self, smallvec::SmallVec::new()),
            },
            // Непонятое не есть ответ цели; часы заводит тик, Opaque состояние не трогает.
            reflex_core::DetectorEvent::Opaque { .. } => (self, smallvec::SmallVec::new()),
        };
        let noted = before_last.map(|last| Measured {
            since_ms: at.duration_since(last).as_millis() as u32,
            bytes: before_bytes,
            awaiting: before_awaiting,
            watch: before_watch,
        });
        (state, signals, noted)
    }
}

impl crate::Instrument for SilenceInstrument {
    type Signal = Distress;

    const INSTRUMENT: &'static str = "silence";

    const SUBJECT: crate::Subject = crate::Subject::World;

    /// Тишина после просьбы видна на любом транспорте (отсутствие байтов вниз, не флага).
    const LAYER: crate::Layer = crate::Layer::Transport;
    const PROTOCOLS: &'static [crate::Protocol] = &[crate::Protocol::Tcp, crate::Protocol::Udp];
    const RUNG: Option<crate::Rung> = Some(crate::Rung::Answered);

    /// Свои часы: шаг задаётся раннером, потому в значении (один прибор на очереди и записи тикает
    /// по-разному).
    const CADENCE: crate::Cadence = crate::Cadence::Own { step_ms: 0 };

    const SHAPE: crate::Shape = crate::Shape::Event;

    /// Порог не достигнут — тишины ещё нет.
    const SILENCE: Option<crate::Silence> = Some(crate::Silence::Nothing);

    const LIES: &'static [&'static str] = &[
        "ШАГ РЕШЁТКИ В КОНСТАНТЕ ПАСПОРТА РАВЕН НУЛЮ, а настоящий приходит от раннера. Паспорт \
         здесь ОБЪЯВЛЯЕТ форму, а не величину: свериться с выведенным нечем, пока аудит не читает \
         аргумент конструктора. Ровно тот разрыв, который закон слоя запрещает у других.",
        "ТИШИНА ЦЕЛИ И ТИШИНА КАНАЛА НЕРАЗЛИЧИМЫ. Прибор видит отсутствие байтов вниз и не знает, \
         дошла ли просьба вверх: `Silence` при мёртвом аплинке и при живом дают одно показание.",
    ];

    const ORACLES: &'static [&'static str] = &["sni_drop(rutracker.org)", "syn_drop(1.2.3.4)"];

    const DEATH: &'static str = "аудит выводит шаг решётки из конструктора, а не из константы";

    const EVENTS: &'static [&'static str] = &["no_bytes", "silence"];

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

/// Детектор троттлинга. Прибор о мире; единственный в парке, чьё показание — ВЕЛИЧИНА («столько
/// байт в секунду против стольких доказанных»).
#[derive(Debug, Clone, Copy)]
pub struct ThrottledInstrument {
    /// Огибающая: сколько цель доказала за окно. Только вверх.
    baseline: u64,
    /// Байты вниз за окно.
    down: u64,
    /// Спрос клиента за окно.
    up: u64,
    /// Сколько окон подряд просело.
    degraded_run: u32,
    /// Просил ли клиент хоть раз (за всё наблюдение): при скачивании он просит ОДИН раз, дальше
    /// подтверждает — требование спроса в каждом окне ослепило бы прибор.
    asked_ever: bool,
    /// Разговор окончен: после прощания падение до нуля — норма (файл докачан).
    finished: bool,
    /// Просил ли клиент подождать — предохранитель «не сами ли мы виноваты».
    client_paused: bool,
    /// Длина окна — назвать беду в единице человека.
    window: Duration,
    fired: bool,
}

/// Сколько окон подряд считать приговором. Три — меньшее давало ложные обвинения на джиттере.
const DEGRADED_RUN: u32 = 3;

impl ThrottledInstrument {
    pub fn over(window: Duration) -> Self {
        Self {
            baseline: 0,
            down: 0,
            up: 0,
            degraded_run: 0,
            asked_ever: false,
            finished: false,
            client_paused: false,
            window,
            fired: false,
        }
    }

    /// Скорость просевшего окна в байтах за секунду.
    fn bps(&self) -> u32 {
        let ms = self.window.as_millis().max(1);
        u32::try_from(u128::from(self.down) * 1000 / ms).unwrap_or(u32::MAX)
    }
}

impl reflex_core::mealy::Mealy for ThrottledInstrument {
    /// Словарь соединения: предохранитель `client_paused` — улика TCP (нулевое окно приёма). У QUIC
    /// управление потоком за шифром — предохранителя нет, и выбор в сторону молчания: троттлинг на
    /// QUIC не слышен никем (ложное обвинение хуже пропуска).
    type In = reflex_core::DetectorEvent<SeenTcp>;
    type Out = smallvec::SmallVec<[Distress; 2]>;
    type Log = ();

    fn step(self, event: Self::In) -> (Self, Self::Out, ()) {
        let (state, signals) = match event {
            reflex_core::DetectorEvent::Packet { input, .. } => {
                let next = match input {
                    // Повтор — тот же спрос.
                    SeenTcp::Anywhere(Seen::Sent { count })
                    | SeenTcp::Anywhere(Seen::Resent { count }) => Self {
                        up: self.up + count as u64,
                        asked_ever: true,
                        ..self
                    },
                    SeenTcp::Anywhere(Seen::Received { count }) => Self {
                        down: self.down + count as u64,
                        ..self
                    },
                    SeenTcp::Anywhere(Seen::Payload { head, from_client }) => match from_client {
                        true => Self {
                            up: self.up + head.len() as u64,
                            asked_ever: true,
                            ..self
                        },
                        false => Self {
                            down: self.down + head.len() as u64,
                            ..self
                        },
                    },
                    // Клиент притормозил сам — медленность объяснена на всё наблюдение.
                    SeenTcp::AskedToWait { by_client } => Self {
                        client_paused: self.client_paused || by_client,
                        ..self
                    },
                    // Прощание кончает наблюдение: докачанный файл бедой не является.
                    SeenTcp::Anywhere(Seen::Closed { .. }) => Self {
                        finished: true,
                        ..self
                    },
                    SeenTcp::Syn | SeenTcp::Handshaken | SeenTcp::Rst { .. } => self,
                };
                (next, smallvec::SmallVec::new())
            }
            // Окно закрывается тиком: просадка есть отсутствие байтов там, где они были.
            reflex_core::DetectorEvent::Tick { .. } => {
                // Планка берётся ДО суждения: иначе здоровое окно подняло бы её и объявило себя
                // просевшим относительно себя.
                let baseline_before = self.baseline;
                // Предмет — просадка, не тишина: байты идут, но меньше доказанного (полный ноль —
                // предмет соседа).
                let degraded = self.asked_ever
                    && !self.finished
                    && self.down > 0
                    && self.down < baseline_before;
                let closed = Self {
                    baseline: baseline_before.max(self.down),
                    degraded_run: match degraded {
                        true => self.degraded_run + 1,
                        false => 0,
                    },
                    ..self
                };
                let accuse = !closed.fired
                    && closed.degraded_run >= DEGRADED_RUN
                    // Планка не доказана — предмет `ChokedInstrument`.
                    && baseline_before > 0
                    // Получатель тормозил сам — цель ни при чём.
                    && !closed.client_paused;
                let bps = closed.bps();
                let emptied = Self {
                    down: 0,
                    up: 0,
                    fired: closed.fired || accuse,
                    ..closed
                };
                match accuse {
                    false => (emptied, smallvec::SmallVec::new()),
                    true => (emptied, smallvec::smallvec![Distress::Throttled { bps }]),
                }
            }
            // Непонятое не несёт ни направления, ни длины — окно закрывает только тик.
            reflex_core::DetectorEvent::Opaque { .. } => (self, smallvec::SmallVec::new()),
        };
        (state, signals, ())
    }
}

impl crate::Instrument for ThrottledInstrument {
    type Signal = Distress;

    const INSTRUMENT: &'static str = "throttled";

    const SUBJECT: crate::Subject = crate::Subject::World;

    /// Только TCP: предохранитель (нулевое окно приёма) существует лишь здесь.
    const LAYER: crate::Layer = crate::Layer::Transport;
    const PROTOCOLS: &'static [crate::Protocol] = &[crate::Protocol::Tcp];
    const RUNG: Option<crate::Rung> = None;

    /// Закрытие окна (отложенный трафик): троттлинг существует, пока байты идут.
    const CADENCE: crate::Cadence = crate::Cadence::Foreign;

    /// Величина: `bps` складывается, перехода нет — `distinct_until_changed` подавил бы повтор того
    /// же темпа, который и есть новость.
    const SHAPE: crate::Shape = crate::Shape::Quantity;

    const SILENCE: Option<crate::Silence> = Some(crate::Silence::Nothing);

    const LIES: &'static [&'static str] = &[
        "ОГИБАЮЩАЯ ХРАПОВИКОМ ВВЕРХ — против кипящей лягушки, и она же режим лжи: цель, впервые \
         увиденная на плохом канале, объявит своей планкой плохое, и просадка от неё не отсчитается \
         никогда. Планка честна ровно настолько, насколько ХОРОШИЙ момент попал в наблюдение.",
        "МЕДЛЕННЫЙ КАНАЛ НЕОТЛИЧИМ ОТ ТРОТТЛИНГА. Прибор меряет темп и не знает его причины; \
         `netem 250кбит потери 6%` даст тот же вердикт, что перехват. Чужой детектор на этой клетке \
         доложил 33 цели «via DPI» — у нас сток тот же, просто мы его назвали.",
    ];

    const ORACLES: &'static [&'static str] =
        &["throttle(250kbit,6%)", "fatflow(1.2.3.4,16,reply,drop)"];

    const DEATH: &'static str = "алфавит получил клетку «канал медленный»; сток назван явно";

    const EVENTS: &'static [&'static str] = &["throttled"];

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

/// Детектор захлёбывания. Прибор о мире: клиент просит, цель не отдаёт, планки не доказывала.
/// Отличается от [`SilenceInstrument`] требованием ДОКАЗАННОГО СПРОСА — без просьбы молчание законно.
#[derive(Debug, Clone, Copy)]
pub struct ChokedInstrument {
    /// Сколько ждать ответа, прежде чем обвинять. Срок тот же, что у прибора тишины (две правды об
    /// одном сроке хуже одной): без порога `nalog.ru` ответил за 348 мс и был помечен задушенным.
    after: Duration,
    /// Когда попросили впервые — отсюда отсчёт терпения.
    asked_at: Option<Instant>,
    /// Байт вверх за наблюдение.
    sent: u64,
    /// Байт вниз.
    received: u64,
    /// Доказанная планка: сколько цель уже умела отдавать. Ноль — не доказывала.
    proven_ceiling: u64,
    fired: bool,
}

impl ChokedInstrument {
    /// `proven_ceiling` извне — знание о прошлом цели. Ноль — «не доказывала никогда».
    pub fn after(proven_ceiling: u64, after: Duration) -> Self {
        Self {
            after,
            asked_at: None,
            sent: 0,
            received: 0,
            proven_ceiling,
            fired: false,
        }
    }

    /// Вышло ли терпение с первой просьбы.
    fn patience_over(&self, now: Instant) -> bool {
        match self.asked_at {
            None => false,
            Some(asked) => now.saturating_duration_since(asked) >= self.after,
        }
    }
}

impl reflex_core::mealy::Mealy for ChokedInstrument {
    /// Общий словарь: предмет «просил, не отдала» есть на любом транспорте, окон приёма прибор не
    /// читает.
    type In = reflex_core::DetectorEvent<Seen>;
    type Out = smallvec::SmallVec<[Distress; 2]>;
    type Log = ();

    fn step(self, event: Self::In) -> (Self, Self::Out, ()) {
        let (state, signals) = match event {
            reflex_core::DetectorEvent::Packet { input, at } => {
                // Момент первой просьбы — начало отсчёта; повторная не сдвигает.
                let asked_at = match (self.asked_at, &input) {
                    (Some(first), _seen) => Some(first),
                    (None, Seen::Sent { .. } | Seen::Resent { .. }) => Some(at),
                    (None, Seen::Payload { from_client, .. }) => match from_client {
                        true => Some(at),
                        false => None,
                    },
                    (None, _seen) => None,
                };
                let waiting = Self { asked_at, ..self };
                let next = match input {
                    // Повтор — спрос наравне с первой просьбой.
                    Seen::Sent { count } | Seen::Resent { count } => Self {
                        sent: waiting.sent + count as u64,
                        ..waiting
                    },
                    Seen::Received { count } => Self {
                        received: waiting.received + count as u64,
                        ..waiting
                    },
                    Seen::Payload { head, from_client } => match from_client {
                        true => Self {
                            sent: waiting.sent + head.len() as u64,
                            ..waiting
                        },
                        false => Self {
                            received: waiting.received + head.len() as u64,
                            ..waiting
                        },
                    },
                    // Прощание спросом не является и наблюдения не кончает.
                    Seen::Closed { .. } => waiting,
                };
                (next, smallvec::SmallVec::new())
            }
            // Терпение входит в условие: улика не раньше, чем истечёт срок.
            reflex_core::DetectorEvent::Tick { at, .. } => match (
                self.fired,
                self.sent > 0 && self.patience_over(at),
                self.received > 0,
            ) {
                // Байты идут — лечить нечего.
                (_fired, _waited, true) => (self, smallvec::SmallVec::new()),
                // Тишина с обеих сторон: цель молчит законно, её не просят.
                (_fired, false, false) => (self, smallvec::SmallVec::new()),
                // Уже сообщали.
                (true, true, false) => (self, smallvec::SmallVec::new()),
                // Живая, но замолчавшая — не наш случай: доказывала планку, молчание может быть
                // паузой (ошибка стоит ноги).
                (false, true, false) if self.proven_ceiling > 0 => {
                    (self, smallvec::SmallVec::new())
                }
                // Мёртвая с рождения: клиент просит, цель не отдавала ни разу.
                (false, true, false) => (
                    Self {
                        fired: true,
                        ..self
                    },
                    smallvec::smallvec![Distress::NoBytes],
                ),
            },
            // Непонятое ни просьбой, ни ответом не является.
            reflex_core::DetectorEvent::Opaque { .. } => (self, smallvec::SmallVec::new()),
        };
        (state, signals, ())
    }
}

impl crate::Instrument for ChokedInstrument {
    type Signal = Distress;

    const INSTRUMENT: &'static str = "choked";

    const SUBJECT: crate::Subject = crate::Subject::World;

    /// Транспорт: «просил и не получил» есть факт о байтах, а байты есть у обоих (окна прибор не
    /// читает — прежнее `Tcp` описывало соседа).
    const LAYER: crate::Layer = crate::Layer::Transport;
    const PROTOCOLS: &'static [crate::Protocol] = &[crate::Protocol::Tcp, crate::Protocol::Udp];
    const RUNG: Option<crate::Rung> = None;

    /// Свои часы: отсутствие ответа пакетом не дождаться.
    const CADENCE: crate::Cadence = crate::Cadence::Own { step_ms: 0 };

    const SHAPE: crate::Shape = crate::Shape::Event;

    const SILENCE: Option<crate::Silence> = Some(crate::Silence::Nothing);

    const LIES: &'static [&'static str] = &[
        "ПРИГОВОР НА ПЕРВОМ ЖЕ ТИКЕ — беда, которую прибор уже пережил и вылечил терпением. \
         В тестах она не всплывала два месяца: там тик подаётся ОДИН и заведомо поздний, а на \
         проводе они идут каждые 300 мс. Витнес обязан быть В ПАРЕ — тот же поток с ответом и без.",
        "ШАГ РЕШЁТКИ В ПАСПОРТЕ РАВЕН НУЛЮ, как у соседа по тику: настоящий приходит от раннера, \
         и сверить объявленное с выведенным нечем.",
        "ТЕРПЕНИЕ ОДНО НА ВСЕ ЦЕЛИ. Цель за океаном и цель в соседней стойке судятся одним \
         порогом; RTT в наблюдение не входит.",
    ];

    const ORACLES: &'static [&'static str] = &["sni_drop(rutracker.org)", "throttle(250kbit,6%)"];

    const DEATH: &'static str = "терпение выводится из RTT цели, а не задаётся одной константой";

    const EVENTS: &'static [&'static str] = &["no_bytes"];

    fn name(signal: &Self::Signal) -> &'static str {
        signal.name()
    }

    fn alarming(signal: &Self::Signal) -> bool {
        signal.alarming()
    }
}

#[cfg(test)]
mod silence_tests {
    use super::*;
    use reflex_core::mealy::Mealy;
    use reflex_core::DetectorEvent;
    use std::time::{Duration, Instant};

    /// Прогнать прибор по наблюдениям и тикам с заданным временем (реальные часы в поверке не
    /// участвуют).
    fn run(instrument: SilenceInstrument, script: Vec<(Option<Seen>, u64)>) -> Vec<Distress> {
        let start = Instant::now();
        script
            .into_iter()
            .fold(
                (instrument, Vec::new()),
                |(state, said), (seen, after_ms)| {
                    let at = start + Duration::from_millis(after_ms);
                    let event = match seen {
                        Some(seen) => DetectorEvent::Packet { input: seen, at },
                        None => DetectorEvent::Tick { node: after_ms, at },
                    };
                    let (stepped, signals, _) = state.step(event);
                    (stepped, said.into_iter().chain(signals).collect())
                },
            )
            .1
    }

    /// Цель не ответила вовсе — `NoBytes`, а не «поток встал». (Заодно поверяется дроп `SYN`:
    /// сценарий без наблюдений, только часы — если бы часы заводились буквой, прибор молчал бы
    /// вечно на той земле, ради которой заведён.)
    #[test]
    fn a_target_that_never_answered_is_not_the_same_as_a_stalled_stream() {
        let said = run(
            SilenceInstrument::after(Duration::from_millis(1_500)),
            vec![(None, 0), (None, 2_000)],
        );

        assert_eq!(said, vec![Distress::NoBytes]);
    }

    /// Клиентский ПОВТОР не рушит окно тишины. При тихом дропе клиент шлёт `ClientHello` заново
    /// каждую секунду; сбрасывай часы на повторе — окно не набралось бы никогда, и тихий дроп с
    /// ретрансмиссией остался бы непойман (замер на боевом трафике: `rutracker.org` за ТСПУ).
    #[test]
    fn a_client_retransmit_does_not_reset_the_silence_clock() {
        let said = run(
            SilenceInstrument::after(Duration::from_millis(1_500)),
            vec![
                // ClientHello ушёл — ждём ответа.
                (
                    Some(Seen::Payload {
                        head: vec![0x16, 0x03, 0x01],
                        from_client: true,
                    }),
                    0,
                ),
                (None, 500),
                // Повтор той же просьбы: ответа не было. Часы молчания он двигать не смеет.
                (Some(Seen::Resent { count: 517 }), 1_000),
                (None, 1_600),
            ],
        );

        assert_eq!(
            said,
            vec![Distress::NoBytes],
            "повтор клиента сбросил часы молчания — тихий дроп с ретрансмиссией не пойман"
        );
    }

    /// Поток встал на середине — байты были и кончились, пока их ждут.
    #[test]
    fn a_stream_that_stopped_while_awaited_is_silence() {
        let said = run(
            SilenceInstrument::after(Duration::from_millis(1_500)),
            vec![
                (Some(Seen::Received { count: 4_096 }), 0),
                (Some(Seen::Sent { count: 100 }), 10),
                (None, 2_000),
            ],
        );

        assert_eq!(said, vec![Distress::Silence { ms: 1_990 }]);
    }

    /// Молчание есть беда, только если его кто-то ждёт (`vk.com` за 296 мс получал `Silence` от
    /// keep-alive).
    #[test]
    fn an_idle_keepalive_is_not_trouble() {
        let said = run(
            SilenceInstrument::after(Duration::from_millis(1_500)),
            vec![
                (Some(Seen::Sent { count: 100 }), 0),
                (Some(Seen::Received { count: 4_096 }), 10),
                (None, 2_000),
            ],
        );

        assert_eq!(said, Vec::<Distress>::new());
    }

    /// Прощание кончает наблюдение: молчание попрощавшегося — не улика.
    #[test]
    fn after_a_goodbye_the_ticks_accuse_no_one() {
        let said = run(
            SilenceInstrument::after(Duration::from_millis(1_500)),
            vec![
                (Some(Seen::Sent { count: 100 }), 0),
                (Some(Seen::Closed { by_client: true }), 10),
                (None, 2_000),
            ],
        );

        assert_eq!(said, Vec::<Distress>::new());
    }

    /// Один раз на разговор: следствие заведено, второй жалобы не нужно.
    #[test]
    fn it_complains_once_per_conversation() {
        let said = run(
            SilenceInstrument::after(Duration::from_millis(1_500)),
            vec![(None, 0), (None, 2_000), (None, 4_000)],
        );

        assert_eq!(said, vec![Distress::NoBytes]);
    }
}

#[cfg(test)]
mod throttled_and_choked_tests {
    use super::*;
    use reflex_core::mealy::Mealy;
    use reflex_core::DetectorEvent;
    use std::time::Instant;

    /// Прогон со сценарием. Алфавит берётся у прибора (`In`): соседи по модулю на разных
    /// протоколах, общий хелпер с прибитым словарём поверял бы одного чужим входом.
    fn run<D, In>(instrument: D, script: Vec<(Option<In>, u64)>) -> Vec<Distress>
    where
        D: Mealy<In = DetectorEvent<In>, Out = smallvec::SmallVec<[Distress; 2]>>,
    {
        let start = Instant::now();
        script
            .into_iter()
            .fold(
                (instrument, Vec::new()),
                |(state, said), (seen, after_ms)| {
                    let at = start + Duration::from_millis(after_ms);
                    let event = match seen {
                        Some(seen) => DetectorEvent::Packet { input: seen, at },
                        None => DetectorEvent::Tick { node: after_ms, at },
                    };
                    let (stepped, signals, _) = state.step(event);
                    (stepped, said.into_iter().chain(signals).collect())
                },
            )
            .1
    }

    /// Троттлинг судится против доказанной планки, не против нуля. Величина едет в показании.
    #[test]
    fn a_target_that_slowed_below_its_own_proven_rate_is_trouble() {
        let said = run(
            ThrottledInstrument::over(Duration::from_secs(1)),
            vec![
                (Some(SeenTcp::sent(100)), 0),
                (Some(SeenTcp::received(1_000_000)), 10),
                (None, 1_000),
                (Some(SeenTcp::received(40_000)), 1_100),
                (None, 2_000),
                (Some(SeenTcp::received(40_000)), 2_100),
                (None, 3_000),
                (Some(SeenTcp::received(40_000)), 3_100),
                (None, 4_000),
            ],
        );

        assert_eq!(said, vec![Distress::Throttled { bps: 40_000 }]);
    }

    /// Тот же темп при той же планке бедой не является (иначе всякая медленная цель задушена).
    #[test]
    fn a_steadily_slow_target_is_not_accused() {
        let said = run(
            ThrottledInstrument::over(Duration::from_secs(1)),
            vec![
                (Some(SeenTcp::sent(100)), 0),
                (Some(SeenTcp::received(40_000)), 10),
                (None, 1_000),
                (Some(SeenTcp::received(40_000)), 1_100),
                (None, 2_000),
                (Some(SeenTcp::received(40_000)), 2_100),
                (None, 3_000),
                (Some(SeenTcp::received(40_000)), 3_100),
                (None, 4_000),
            ],
        );

        assert_eq!(said, Vec::<Distress>::new());
    }

    /// Захлёбывание требует и спроса, и терпения. Средний случай оплачен: `nalog.ru` за 348 мс был
    /// помечен задушенным.
    #[test]
    fn choking_needs_both_demand_and_patience() {
        // Не просили вовсе — «спроса не было» есть отсутствие событий.
        let no_demand = run(
            ChokedInstrument::after(0, Duration::from_millis(1_000)),
            vec![(None, 0), (None, 5_000)],
        );
        let too_early = run(
            ChokedInstrument::after(0, Duration::from_millis(1_000)),
            vec![(Some(Seen::Sent { count: 100 }), 0), (None, 348)],
        );
        let waited = run(
            ChokedInstrument::after(0, Duration::from_millis(1_000)),
            vec![(Some(Seen::Sent { count: 100 }), 0), (None, 1_500)],
        );

        assert_eq!(no_demand, Vec::<Distress>::new());
        assert_eq!(too_early, Vec::<Distress>::new());
        assert_eq!(waited, vec![Distress::NoBytes]);
    }

    /// Цель, доказывавшая планку, щадится: её молчание может быть паузой (ошибка стоит ноги).
    #[test]
    fn a_target_that_once_proved_itself_is_spared() {
        let said = run(
            ChokedInstrument::after(1_000_000, Duration::from_millis(1_000)),
            vec![(Some(Seen::Sent { count: 100 }), 0), (None, 5_000)],
        );

        assert_eq!(said, Vec::<Distress>::new());
    }
}

#[cfg(test)]
mod rst_tests {
    use super::*;
    use reflex_core::mealy::Mealy;
    use reflex_core::DetectorEvent;

    fn saw(seen: SeenTcp) -> DetectorEvent<SeenTcp> {
        DetectorEvent::packet_now(seen)
    }

    fn run(instrument: RstInstrument, seen: Vec<SeenTcp>) -> Vec<Distress> {
        seen.into_iter()
            .fold((instrument, Vec::new()), |(state, said), seen| {
                let (stepped, signals, _) = state.step(saw(seen));
                (stepped, said.into_iter().chain(signals).collect())
            })
            .1
    }

    /// Подпись перехвата — сброс от цели ДО первого её байта.
    #[test]
    fn a_reset_before_the_target_ever_answered_is_trouble() {
        let said = run(
            RstInstrument::new(),
            vec![
                SeenTcp::Syn,
                SeenTcp::Handshaken,
                SeenTcp::Rst {
                    by: ResetBy::TargetSide,
                },
            ],
        );

        assert_eq!(said, vec![Distress::Rst]);
    }

    /// Сброс после отданных байтов — штатное закрытие (замер 29.08: 23 сброса, бед ноль, движок
    /// объявил 12).
    #[test]
    fn a_reset_after_the_target_answered_is_an_ordinary_goodbye() {
        let said = run(
            RstInstrument::new(),
            vec![
                SeenTcp::Syn,
                SeenTcp::received(4096),
                SeenTcp::Rst {
                    by: ResetBy::TargetSide,
                },
            ],
        );

        assert_eq!(said, Vec::<Distress>::new());
    }

    /// Один раз на соединение.
    #[test]
    fn it_says_it_once_however_many_resets_arrive() {
        let said = run(
            RstInstrument::new(),
            vec![
                SeenTcp::Rst {
                    by: ResetBy::TargetSide,
                },
                SeenTcp::Rst {
                    by: ResetBy::TargetSide,
                },
            ],
        );

        assert_eq!(said, vec![Distress::Rst]);
    }

    /// Ни человек, ни наш приказ бедой цели не являются.
    #[test]
    fn neither_the_person_nor_our_own_order_is_the_targets_fault() {
        let ours = run(
            RstInstrument::new(),
            vec![SeenTcp::Rst {
                by: ResetBy::Ourselves,
            }],
        );
        let person = run(
            RstInstrument::new(),
            vec![SeenTcp::Rst {
                by: ResetBy::Person,
            }],
        );

        assert_eq!(ours, Vec::<Distress>::new());
        assert_eq!(person, Vec::<Distress>::new());
    }

    /// Голова цели тоже есть ответ: после неё сброс — прощание.
    #[test]
    fn a_head_from_the_target_counts_as_having_answered() {
        let said = run(
            RstInstrument::new(),
            vec![
                SeenTcp::payload(vec![1, 2, 3], false),
                SeenTcp::Rst {
                    by: ResetBy::TargetSide,
                },
            ],
        );

        assert_eq!(said, Vec::<Distress>::new());
    }
}

/// Детектор IP-blackhole. Читает `SeenTcp` (там `Syn`/`Handshaken`) — `Seen`-приборам это
/// невыразимо: соединения ещё нет. `SYN` ушёл, `SYN+ACK` не пришёл, клиент повторяет `SYN` — блок по
/// АДРЕСУ, до всякого имени. Отдельный прибор, отдельный пайп: через `SilentBlock` не выразить.
/// Порог — RTO ядра клиента (повтор SYN), не наш тик. Подозрение, не приговор: перегруженный канал
/// теряет `SYN` так же.
#[derive(Debug, Clone, Copy, Default)]
pub struct SynDropInstrument {
    /// Первый `SYN`. `None` — стука не видели.
    asked: Option<Instant>,
    /// `SYN+ACK` пришёл — путь жив, подозрение снято навсегда.
    handshaken: bool,
    fired: bool,
}

impl SynDropInstrument {
    pub fn new() -> Self {
        Self::default()
    }
}

impl reflex_core::mealy::Mealy for SynDropInstrument {
    /// Словарь соединения: стук и рукопожатие — улики TCP; в поток датаграмм прибор не собирается.
    type In = reflex_core::DetectorEvent<SeenTcp>;
    type Out = smallvec::SmallVec<[Distress; 2]>;
    type Log = ();

    fn step(self, event: Self::In) -> (Self, Self::Out, ()) {
        let (state, signals) = match event {
            reflex_core::DetectorEvent::Packet { input, at } => match input {
                // Стук открывает отсчёт; повтор стука без рукопожатия — предмет.
                SeenTcp::Syn => match (self.asked, self.handshaken || self.fired) {
                    (None, _) => (
                        Self {
                            asked: Some(at),
                            ..self
                        },
                        smallvec::SmallVec::new(),
                    ),
                    // Путь жив либо уже сообщали.
                    (Some(_), true) => (self, smallvec::SmallVec::new()),
                    // Повторил стук, а рукопожатия так и нет — IP-blackhole.
                    (Some(asked), false) => (
                        Self {
                            fired: true,
                            ..self
                        },
                        smallvec::smallvec![Distress::Blackhole {
                            after_ms: at.saturating_duration_since(asked).as_millis() as u32,
                        }],
                    ),
                },
                // Цель ответила на стук — путь жив, подозрение снято.
                SeenTcp::Handshaken => (
                    Self {
                        handshaken: true,
                        ..self
                    },
                    smallvec::SmallVec::new(),
                ),
                // Сброс, окно, полезная нагрузка — не про достижимость адреса.
                SeenTcp::Rst { .. } | SeenTcp::AskedToWait { .. } | SeenTcp::Anywhere(_) => {
                    (self, smallvec::SmallVec::new())
                }
            },
            // Порог даёт RTO клиентского ядра, не наш тик.
            reflex_core::DetectorEvent::Tick { .. } | reflex_core::DetectorEvent::Opaque { .. } => {
                (self, smallvec::SmallVec::new())
            }
        };
        (state, signals, ())
    }
}

impl crate::Instrument for SynDropInstrument {
    type Signal = Distress;

    const INSTRUMENT: &'static str = "syn_drop";

    /// О мире: адрес недостижим — свойство пути.
    const SUBJECT: crate::Subject = crate::Subject::World;

    /// Транспорт: стук и рукопожатие — флаги TCP.
    const LAYER: crate::Layer = crate::Layer::Transport;

    /// Только TCP: у датаграмм рукопожатия нет.
    const PROTOCOLS: &'static [crate::Protocol] = &[crate::Protocol::Tcp];

    /// Раньше ответа: прибор о том, состоялось ли рукопожатие вообще.
    const RUNG: Option<crate::Rung> = None;

    /// Чужой темп: порог — RTO ядра клиента. Свои часы сделали бы третью копию прибора тишины.
    const CADENCE: crate::Cadence = crate::Cadence::Foreign;

    /// Событие: повтор стука уже случился.
    const SHAPE: crate::Shape = crate::Shape::Event;

    /// Прибор смотрел: стук был, повтора без рукопожатия не случилось.
    const SILENCE: Option<crate::Silence> = Some(crate::Silence::Nothing);

    const LIES: &'static [&'static str] = &[
        "НЕ РАЗЛИЧАЕТ БЛОКИРОВКУ ОТ ПОТЕРИ SYN В КАНАЛЕ. Перегруженный путь роняет `SYN` так же, и \
         повтор при отсутствии `SYN+ACK` выйдет тем же словом. Показание — ПОДОЗРЕНИЕ: действие по \
         нему обязано иметь своё предусловие.",
        "СТУК, ПОДХВАЧЕННЫЙ С СЕРЕДИНЫ, ДАЁТ ЛОЖНУЮ ВЕЛИЧИНУ. Первый `SYN` мы могли не видеть \
         (правило встало после), и `after_ms` тогда мерен от повтора, а не от начала — занижен.",
    ];

    const ORACLES: &'static [&'static str] = &["syn_drop(149.154.167.50)", "pass"];

    const DEATH: &'static str =
        "заведён различитель «блок по адресу против потери SYN в канале»; подозрение стало приговором";

    const EVENTS: &'static [&'static str] = &["blackhole"];

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
mod syn_drop_tests {
    use super::*;
    use reflex_core::mealy::Mealy;
    use reflex_core::DetectorEvent;
    use std::time::{Duration, Instant};

    fn run(script: Vec<(Option<SeenTcp>, u64)>) -> Vec<Distress> {
        let start = Instant::now();
        script
            .into_iter()
            .fold(
                (SynDropInstrument::new(), Vec::new()),
                |(state, said), (seen, ms)| {
                    let at = start + Duration::from_millis(ms);
                    let event = match seen {
                        Some(seen) => DetectorEvent::Packet { input: seen, at },
                        None => DetectorEvent::Tick { node: ms, at },
                    };
                    let (stepped, signals, ()) = state.step(event);
                    (stepped, said.into_iter().chain(signals).collect())
                },
            )
            .1
    }

    /// Повтор стука без рукопожатия — IP-blackhole, и величина от первого стука.
    #[test]
    fn a_repeated_syn_without_handshake_is_a_blackhole() {
        let said = run(vec![(Some(SeenTcp::Syn), 0), (Some(SeenTcp::Syn), 1_000)]);
        assert_eq!(said, vec![Distress::Blackhole { after_ms: 1_000 }]);
    }

    /// Рукопожатие состоялось — путь жив, повтор потом беды не даёт.
    #[test]
    fn a_completed_handshake_clears_the_suspicion() {
        let said = run(vec![
            (Some(SeenTcp::Syn), 0),
            (Some(SeenTcp::Handshaken), 30),
            (Some(SeenTcp::Syn), 1_000),
        ]);
        assert!(said.is_empty(), "путь жив, а прибор объявил blackhole");
    }

    /// Один стук — ещё не беда: повтора не было.
    #[test]
    fn a_single_syn_is_not_yet_a_blackhole() {
        let said = run(vec![(Some(SeenTcp::Syn), 0), (None, 5_000)]);
        assert!(said.is_empty());
    }
}
