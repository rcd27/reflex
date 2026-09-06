//! ЧЕТЫРЕ ПРИБОРА ПРОВОДА: сброс, тишина, троттлинг, захлёбывание.
//!
//! # Переезд завершён вместе с ПАМЯТЬЮ (#320, 02.09)
//!
//! Первая половина переезда (01.09) взяла отсюда ИНТЕРПРЕТАЦИЮ — какая беда следует из
//! наблюдения, — и оставила МЕХАНИЗМ в другом крейте: поля `fired`, `answered`, `bytes`,
//! `watch`. Одно понятие получило две реализации, и они разъехались в тот же день:
//! прежняя реализация считала бедой только сброс ДО первого отданного байта, здешний прибор —
//! любой. По живой очереди работал первый, фикстурами поверялся второй.
//!
//! Прибор есть машина Мили `Step`: `(State, Event) → (State, Signals)`. Состояние стоит в подписи,
//! часы приходят буквой входного алфавита (`DetectorEvent::Tick`), а доменное знание (чьё
//! соединение, какая нога) надевается СНАРУЖИ комбинаторами `lmap`/`contextual`.
//!
//! Показание у всех четверых — `Distress`: описание того, что видно, без слова о том, что мы
//! предпримем. Отсутствие беды сигналом не является — прибор молчит.

use crate::distress::Distress;
use crate::wire::{ResetBy, Seen, SeenTcp};
use std::time::{Duration, Instant};

// ИМЯ БЕДЫ ЖИВЁТ У БУКВЫ, А НЕ ЗДЕСЬ (#326, 05.09.2026).
//
// Здесь стояла `name_of` — вторая таблица имён, совпадавшая с `Distress::name` буква в букву, и у
// обеих докстринг объяснял, что таблица объявлена отдельно, «чтобы не разъехалось». Механизм
// против разъезда сам был записан дважды.
//
// Закон владельца: одна беда детектится в одном месте, и посмотреть на него можно ровно в
// `distress.rs`. Сторожит `distress::tests::the_alphabet_of_trouble_is_spelled_out_in_exactly_one_file`.

/// ПАСПОРТ ДЕТЕКТОРА СБРОСА — проекция `model/law/Instrument.tla`.
///
/// Прибор о МИРЕ: он утверждает, что путь ломают снаружи. Из четырёх множителей годности три
/// названы здесь, четвёртый (питание) не измеряется кодом вовсе — см. `LIES`.
#[derive(Debug, Clone, Copy, Default)]
pub struct RstInstrument {
    /// Уже жаловались. Второй раз о том же не жалуемся — следствие и так заведено.
    fired: bool,
    /// ОТДАЛА ЛИ ЦЕЛЬ ХОТЬ БАЙТ до сброса. Ось, без которой прибор объявляет бедой прощание.
    answered: bool,
}

impl RstInstrument {
    pub fn new() -> Self {
        Self::default()
    }
}

impl reflex_core::step::Step for RstInstrument {
    /// СЛОВАРЬ СОЕДИНЕНИЯ, А НЕ ОБЩИЙ: сброс есть улика TCP, и прибор, читающий её, в поток
    /// датаграмм не собирается — равенство `PROTOCOLS: Tcp` ниже держится тем же словарём.
    type From = reflex_core::DetectorEvent<SeenTcp>;

    /// Беда. Отсутствие беды сигналом НЕ ЯВЛЯЕТСЯ: прибор высказывается, когда есть что сказать,
    /// а `Option` в сигнале сделал бы «всё в порядке» отдельным сообщением в ленте.
    type To = smallvec::SmallVec<[Distress; 2]>;

    /// # ПОДПИСЬ ТСПУ УЗНАЁТСЯ ДВУМЯ ПРИЗНАКАМИ РАЗОМ
    ///
    /// Сброс пришёл ОТ ЦЕЛИ и ДО того, как она отдала хоть байт: так отвечают на `ClientHello`, а
    /// не на конец разговора. Замер живой записи 29.08: 23 сброса — 17 наших собственных, 6 от
    /// цели и все шесть после отданных байтов. Настоящих бед не было ни одной, движок объявил 12.
    ///
    /// ЦЕНА НАЗВАНА: сброс посреди живой сессии пропускается — от штатного закрытия он неотличим
    /// ничем, что видно на проводе.
    fn step(self, event: Self::From) -> (Self, Self::To) {
        match event {
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
                    // НИ ЧЕЛОВЕК, НИ МЫ САМИ бедой цели не являются: вменить цели наш собственный
                    // приказ значило бы понизить оценку ноги за то, что сделали мы.
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
            // Сброс сам есть момент: часы прибору не нужны.
            reflex_core::DetectorEvent::Tick { .. } => (self, smallvec::SmallVec::new()),
        }
    }
}

impl crate::Instrument for RstInstrument {
    type Signal = Distress;

    const INSTRUMENT: &'static str = "rst";

    const SUBJECT: crate::Subject = crate::Subject::World;

    /// УРОВЕНЬ: сброс существует только у TCP: у QUIC обрыв объявляется шифрованным кадром, снаружи он неотличим от молчания.
    const LAYER: crate::Layer = crate::Layer::Transport;
    const PROTOCOLS: &'static [crate::Protocol] = &[crate::Protocol::Tcp];
    const RUNG: Option<crate::Rung> = Some(crate::Rung::Severed);

    /// ПАКЕТ, и это законно: сброс САМ есть событие. Опрашивать нечего.
    const CADENCE: crate::Cadence = crate::Cadence::Foreign;

    const SHAPE: crate::Shape = crate::Shape::Event;

    /// Наблюдение не про сброс — прибор смотрел и установил это. Клетки `Blind` у него нет:
    /// событие приходит готовым.
    const SILENCE: Option<crate::Silence> = Some(crate::Silence::Nothing);

    const LIES: &'static [&'static str] = &[
        "НЕ РАЗЛИЧАЕТ ОТКАЗ СЕРВЕРА ОТ ИНЖЕКТА ТСПУ (#320, Н10). Оба приходят как \
         `ResetBy::TargetSide` и оба дают `Distress::Rst`, а лечение противоположно: в первом \
         случае цель не работает и техника бесполезна, во втором работает и техника нужна. \
         Различитель есть на проводе (TTL, фингерпринт окна и флагов) и не читается ничем.",
        "СБРОС ПОСРЕДИ ЖИВОЙ СЕССИИ ПРОПУСКАЕТСЯ: от штатного закрытия он неотличим ничем, что \
         видно на проводе. Цена названа в докстринге детектора с 29.08.",
        "ОДНО РАЗЛИЧЕНИЕ ВСЁ ЕЩЁ ЗАПИСАНО ДВАЖДЫ — но копий стало не три, а две. Копия в \
         `domain::wire::Rst` СНЯТА 02.09 (#320): она и была тем разъездом, который этот пункт \
         предсказал, и предсказание сбылось в тот же день — детектор требовал сброса ДО первого \
         отданного байта, прибор объявлял бедой любой. Осталcя мост \
         `app::distress::trouble` над наблюдением ПЛОСКОСТИ: у него другой вход (`Sighting`, \
         не `Seen`) и другой вход в продукт (`edge-loop` против `edge-queue`), потому механической \
         сверки между ними нет. Совпадают они сегодня и разойдутся молча.",
        "ПИТАНИЕ КАНАЛА НЕ ИЗМЕРЕНО НИ ОДНИМ ИЗ НАШИХ ПРИБОРОВ. Компилятор видит связь, стенд \
         видит различение; идут ли по каналу пакеты — не видит никто. Правила ядра стоят на \
         `output`/`input` и не покрывают транзитный клиентский трафик.",
    ];

    /// Сценарии целиком: способ казни — часть беды, сброс и тишина судятся по-разному.
    const ORACLES: &'static [&'static str] = &["sni_rst(rutracker.org)", "syn_drop(1.2.3.4)"];

    /// СМЕРТЬ: различитель инжекта заведён (Н10) — тогда прибор расщепляется надвое, и этот
    /// паспорт умирает вместе с общим `Distress::Rst`.
    const DEATH: &'static str = "различитель инжекта по TTL заведён; `Distress::Rst` расщеплён";

    /// ПУБЛИЧНЫЕ ИМЕНА: одно, и оно СОСТАВНОЕ по природе — «сброс от цели до первого байта».
    /// Расщепится, когда заведётся различитель инжекта (Н10), и тогда имён станет два.
    const EVENTS: &'static [&'static str] = &["rst"];

    fn name(signal: &Self::Signal) -> &'static str {
        signal.name()
    }

    fn alarming(signal: &Self::Signal) -> bool {
        signal.alarming()
    }
}

/// ПАСПОРТ ДЕТЕКТОРА ТИШИНЫ — проекция `model/law/Instrument.tla`.
///
/// ПЕРВЫЙ ПРИБОР ПАРКА СО СВОИМИ ЧАСАМИ. Предмет его — отсутствие событий, и по построению он не
/// может ждать пакета: пакет и есть то, чего нет.
#[derive(Debug, Clone, Copy)]
pub struct SilenceInstrument {
    /// Сколько молчания терпим, прежде чем заводить следствие.
    ///
    /// ПОРОГ НЕ ТРАТИТ ВРЕМЯ ЧЕЛОВЕКА: он уже обслужен, байты у него текут. Здесь отмеряется,
    /// когда заводить СЛЕДСТВИЕ, и потому величина может быть щедрой — она тратит наше время.
    after: Duration,
    /// Момент последнего события. `None` — событий ещё не было, и мерить не от чего.
    last: Option<Instant>,
    /// Сколько байт цель отдала вниз. Ось, различающая `NoBytes` и `Silence`.
    bytes: u32,
    watch: Watch,
    /// ЖДЁТ ЛИ ЧЕЛОВЕК ПРЯМО СЕЙЧАС: просьба ушла, ответа на неё ещё не было.
    ///
    /// Ось найдена стендом на живых байтах 29.08: `vk.com` открылся у человека за 296 мс,
    /// `mail.yandex.ru` — за 424 мс, и на обоих движок объявил `Silence`. Тишина мерилась от
    /// ЛЮБОГО события, и простаивающее keep-alive через полторы секунды становилось бедой.
    /// Молчание есть беда, только если его КТО-ТО ЖДЁТ.
    awaiting: bool,
}

/// ЧТО ДЕЛАЕТ НАБЛЮДЕНИЕ ЗА РАЗГОВОРОМ. Вариант типа, а не два флага.
///
/// Прежде здесь стоял `fired: bool`. Добавить рядом второй флаг («разговор окончен») значило бы
/// завести четыре комбинации, из которых одна бессмысленна, — а бессмысленное состояние рано или
/// поздно наступает. Состояний ровно три, и они взаимоисключающи.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Watch {
    /// Смотрим и готовы пожаловаться.
    Open,
    /// Уже пожаловались. Второй раз о том же не жалуемся — следствие и так заведено.
    Fired,
    /// РАЗГОВОР ОКОНЧЕН. Молчание того, кто попрощался, — не улика: тики идут дальше, но их
    /// порождает чужой трафик, а не эта цель.
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

impl reflex_core::step::Step for SilenceInstrument {
    type From = reflex_core::DetectorEvent<Seen>;

    /// ДВЕ БЕДЫ, А НЕ ОДНА: «цель не ответила вовсе» (`NoBytes`) и «поток встал на середине»
    /// (`Silence`) расследуются и лечатся по-разному. Невод 1 звал обе молчанием — оттого и лечил
    /// обходом упавшие серверы.
    ///
    /// РАЗЛИЧАЕТ ИХ СЧЁТЧИК БАЙТОВ, то есть ПАМЯТЬ.
    type To = smallvec::SmallVec<[Distress; 2]>;

    fn step(self, event: Self::From) -> (Self, Self::To) {
        match event {
            reflex_core::DetectorEvent::Packet { input, at } => {
                // Тишина меряется по ответу ЦЕЛИ: сколько напросил человек, к делу не относится.
                let bytes = match &input {
                    Seen::Received { count } => self.bytes + count,
                    Seen::Payload { head, from_client } => match from_client {
                        true => self.bytes,
                        false => self.bytes + head.len() as u32,
                    },
                    Seen::Sent { .. } | Seen::Resent { .. } | Seen::Closed { .. } => self.bytes,
                };
                // Просьба вверх открывает ожидание, ответ вниз его закрывает. Голова клиента —
                // тоже просьба: `ClientHello` есть первое, чего он ждёт ответа.
                let awaiting = match &input {
                    Seen::Sent { .. } | Seen::Resent { .. } => true,
                    Seen::Payload { from_client, .. } => *from_client,
                    Seen::Received { .. } => false,
                    // Прощание ожидания не закрывает: ждали или нет — решает `Watch`.
                    Seen::Closed { .. } => self.awaiting,
                };
                let watch = match &input {
                    Seen::Closed { .. } => Watch::Ended,
                    Seen::Sent { .. }
                    | Seen::Resent { .. }
                    | Seen::Received { .. }
                    | Seen::Payload { .. } => self.watch,
                };
                (
                    Self {
                        last: Some(at),
                        bytes,
                        watch,
                        awaiting,
                        ..self
                    },
                    smallvec::SmallVec::new(),
                )
            }
            reflex_core::DetectorEvent::Tick { at } => match (self.last, self.watch) {
                // ЦЕЛЬ, НЕ ОТВЕТИВШАЯ ВОВСЕ, уличается и без просьбы: соединение открыто, байтов
                // нет — ждать тут нечего и некому, это уже отказ.
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
                // ЧАСЫ ЗАВОДЯТСЯ ПЕРВЫМ ТИКОМ, а не первым событием (#320, 02.09).
                //
                // Прежде отсчёт начинался с любой буквы, включая улики TCP, — и расщепление
                // алфавита ослепило бы прибор ровно там, ради чего он заведён: у потока с дропом
                // `SYN` общих букв НЕТ ВОВСЕ (клиент стучится, ответа нет), `last` оставался
                // `None`, и `NoBytes` не наступал никогда. Найдено фикстурами `syn_drop`.
                //
                // Заводить их наблюдением было ошибкой и до расщепления: прибор мерит молчание
                // ПОТОКА, а поток начался тогда, когда край его завёл, — то есть до первой буквы,
                // которую этот прибор умеет прочесть.
                (None, Watch::Open) => (
                    Self {
                        last: Some(at),
                        ..self
                    },
                    smallvec::SmallVec::new(),
                ),
                // Порог не истёк, либо следствие уже заведено, либо разговор окончен.
                (Some(_), Watch::Open)
                | (Some(_), Watch::Fired)
                | (Some(_), Watch::Ended)
                | (None, Watch::Fired)
                | (None, Watch::Ended) => (self, smallvec::SmallVec::new()),
            },
        }
    }
}

impl crate::Instrument for SilenceInstrument {
    type Signal = Distress;

    const INSTRUMENT: &'static str = "silence";

    const SUBJECT: crate::Subject = crate::Subject::World;

    /// УРОВЕНЬ: тишина после просьбы видна на любом транспорте — это отсутствие байтов вниз, а не отсутствие флага.
    ///
    /// ТРАНСПОРТЫ, А НЕ «ЛЮБОЙ ПРОТОКОЛ» (#320, разминирование): прибор читает общий словарь, и
    /// общий словарь снимается с TCP и UDP. Прежнее `Any` числило его отвечающим и на TLS, и на
    /// HTTP — записей которых он не видел ни одной.
    const LAYER: crate::Layer = crate::Layer::Transport;
    const PROTOCOLS: &'static [crate::Protocol] = &[crate::Protocol::Tcp, crate::Protocol::Udp];
    const RUNG: Option<crate::Rung> = Some(crate::Rung::Answered);

    /// СВОИ ЧАСЫ, и здесь это единственно возможное. Шаг задаётся раннером и потому лежит в
    /// значении, а не в константе: один и тот же прибор на живой очереди и на записи тикает
    /// по-разному, и паспорт обязан говорить о конкретном экземпляре.
    const CADENCE: crate::Cadence = crate::Cadence::Own { step_ms: 0 };

    const SHAPE: crate::Shape = crate::Shape::Event;

    /// Порог не достигнут — прибор смотрел и установил, что тишины ещё нет.
    const SILENCE: Option<crate::Silence> = Some(crate::Silence::Nothing);

    const LIES: &'static [&'static str] = &[
        "ШАГ РЕШЁТКИ В КОНСТАНТЕ ПАСПОРТА РАВЕН НУЛЮ, а настоящий приходит от раннера. Паспорт \
         здесь ОБЪЯВЛЯЕТ форму, а не величину: свериться с выведенным нечем, пока аудит не читает \
         аргумент конструктора. Ровно тот разрыв, который закон слоя запрещает у других.",
        "ТИШИНА ЦЕЛИ И ТИШИНА КАНАЛА НЕРАЗЛИЧИМЫ. Прибор видит отсутствие байтов вниз и не знает, \
         дошла ли просьба вверх: `Silence` при мёртвом аплинке и при живом дают одно показание.",
    ];

    const ORACLES: &'static [&'static str] = &["sni_drop(rutracker.org)", "syn_drop(1.2.3.4)"];

    /// СМЕРТЬ: аудит научился читать шаг из конструктора — тогда объявленная решётка сверяется с
    /// выведенной, и паспорт перестаёт быть словом.
    const DEATH: &'static str = "аудит выводит шаг решётки из конструктора, а не из константы";

    /// ПУБЛИЧНЫЕ ИМЕНА: две беды, и различает их счётчик байтов внутри прибора.
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

/// ПАСПОРТ ДЕТЕКТОРА ТРОТТЛИНГА.
///
/// Прибор о МИРЕ, и единственный в парке, чьё показание есть ВЕЛИЧИНА, а не состояние: он говорит
/// не «плохо», а «столько байт в секунду против стольких доказанных».
#[derive(Debug, Clone, Copy)]
pub struct ThrottledInstrument {
    /// ОГИБАЮЩАЯ: сколько цель уже доказала за окно. Только вверх.
    baseline: u64,
    /// Байты вниз за текущее окно.
    down: u64,
    /// Спрос клиента за текущее окно.
    up: u64,
    /// Сколько окон подряд просело.
    degraded_run: u32,
    /// ПРОСИЛ ЛИ КЛИЕНТ ХОТЬ РАЗ — за всё наблюдение, а не за текущее окно.
    ///
    /// Прежде спрос требовался В КАЖДОМ окне, и это делало прибор слепым ровно там, ради чего он
    /// заведён: при скачивании клиент просит ОДИН раз, дальше только подтверждает, а чистые
    /// подтверждения событий не порождают. Замер с контролируемым перепадом полосы: темп упал с
    /// 10,6 МБ/с до 42 КБ/с — в двести пятьдесят раз, — и детектор не сказал ничего.
    asked_ever: bool,
    /// РАЗГОВОР ОКОНЧЕН. После прощания падение темпа до нуля есть норма, а не беда: файл
    /// докачан. Без этого обвинялась бы каждая завершённая загрузка.
    finished: bool,
    /// ПРОСИЛ ЛИ КЛИЕНТ ПОДОЖДАТЬ — предохранитель «а не сами ли мы виноваты» для ЭТОГО
    /// соединения: если получатель притормаживал сам, скорость упирается в него.
    client_paused: bool,
    /// Длина окна — нужна, чтобы назвать беду в единице человека (байты в секунду).
    window: Duration,
    fired: bool,
}

/// СКОЛЬКО ОКОН ПОДРЯД СЧИТАТЬ ПРИГОВОРОМ. Три — из невода 1, где меньшее давало ложные
/// обвинения на джиттере.
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

    /// Скорость просевшего окна в байтах за секунду — чтобы беда называла величину, а не факт.
    fn bps(&self) -> u32 {
        let ms = self.window.as_millis().max(1);
        u32::try_from(u128::from(self.down) * 1000 / ms).unwrap_or(u32::MAX)
    }
}

impl reflex_core::step::Step for ThrottledInstrument {
    /// СЛОВАРЬ СОЕДИНЕНИЯ, А НЕ ОБЩИЙ.
    ///
    /// Предмет прибора от транспорта не зависит — байты во времени есть у всех. Но его
    /// ПРЕДОХРАНИТЕЛЬ — улика TCP: `client_paused` ставится нулевым окном приёма, и без него
    /// прибор обвиняет цель за медленность, устроенную НАШИМ ЖЕ получателем. У QUIC управление
    /// потоком существует, но лежит за шифром — то есть предохранителя там нет НЕ по недоделке, а
    /// нечем.
    ///
    /// Выбор сделан в сторону молчания: ложное обвинение уводит трафик на ногу зря и учит систему
    /// о пути, которого не было, а пропуск лишь оставляет вопрос открытым. Цена названа —
    /// ТРОТТЛИНГ НА QUIC НЕ СЛЫШЕН НИКЕМ. Снимется, когда предохранитель станет отдельным звеном
    /// цепочки (он и есть отдельное правило), а не веткой внутри прибора.
    type From = reflex_core::DetectorEvent<SeenTcp>;
    type To = smallvec::SmallVec<[Distress; 2]>;

    fn step(self, event: Self::From) -> (Self, Self::To) {
        match event {
            reflex_core::DetectorEvent::Packet { input, .. } => {
                let next = match input {
                    // Повтор — тот же спрос: человек по-прежнему хочет, просто просит заново.
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
                    // Клиент притормозил сам — запоминаем на всё наблюдение: медленность этого
                    // соединения объяснена, и обвинять цель по нему больше нельзя.
                    SeenTcp::AskedToWait { by_client } => Self {
                        client_paused: self.client_paused || by_client,
                        ..self
                    },
                    // ПРОЩАНИЕ КОНЧАЕТ НАБЛЮДЕНИЕ: докачанный файл перестаёт идти по причине,
                    // которая бедой не является.
                    SeenTcp::Anywhere(Seen::Closed { .. }) => Self {
                        finished: true,
                        ..self
                    },
                    SeenTcp::Syn | SeenTcp::Handshaken | SeenTcp::Rst { .. } => self,
                };
                (next, smallvec::SmallVec::new())
            }
            // ОКНО ЗАКРЫВАЕТСЯ ТИКОМ. Просадка есть отсутствие байтов там, где они были, и без
            // часов она не наступает никогда.
            reflex_core::DetectorEvent::Tick { .. } => {
                // ПЛАНКА БЕРЁТСЯ ДО СУЖДЕНИЯ: обновив её первой, здоровое окно подняло бы её же и
                // объявило себя просевшим относительно себя.
                let baseline_before = self.baseline;
                // ПРЕДМЕТ — ПРОСАДКА, А НЕ ТИШИНА. Байты идут, но меньше доказанного: цель «стала
                // еле-еле». Полный ноль — предмет соседнего прибора, и обвинять его здесь значило
                // бы завести два следствия об одном.
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
                    // Планка не доказана — это предмет `ChokedInstrument`, не наш.
                    && baseline_before > 0
                    // Получатель тормозил САМ — медленность объяснена, цель ни при чём.
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
        }
    }
}

impl crate::Instrument for ThrottledInstrument {
    type Signal = Distress;

    const INSTRUMENT: &'static str = "throttled";

    const SUBJECT: crate::Subject = crate::Subject::World;

    /// УРОВЕНЬ: объём во времени считается по байтам, и байты есть у всех; на вопрос из четырёх не отвечает — меряет величину.
    ///
    /// ПРОТОКОЛ ИСПРАВЛЕН С `Any` НА `Tcp` (#320): не потому, что предмет сузился, а потому, что
    /// предохранитель (нулевое окно приёма) существует только здесь. Паспорт объявлял вход,
    /// которого прибор не имеет права принять, — теперь объявление выведено из типа.
    const LAYER: crate::Layer = crate::Layer::Transport;
    const PROTOCOLS: &'static [crate::Protocol] = &[crate::Protocol::Tcp];
    const RUNG: Option<crate::Rung> = None;

    /// ЗАКРЫТИЕ ОКНА — то есть отложенный трафик, а не свои часы. В тишине окно не закрывается,
    /// и прибор молчит; для его предмета это законно: троттлинг существует, только пока байты
    /// идут.
    const CADENCE: crate::Cadence = crate::Cadence::Foreign;

    /// ВЕЛИЧИНА: `bps` складывается и сравнивается, но перехода не имеет —
    /// `distinct_until_changed` над ней подавил бы повтор того же темпа, который как раз и есть
    /// новость.
    const SHAPE: crate::Shape = crate::Shape::Quantity;

    const SILENCE: Option<crate::Silence> = Some(crate::Silence::Nothing);

    const LIES: &'static [&'static str] = &[
        "ОГИБАЮЩАЯ ХРАПОВИКОМ ВВЕРХ — против кипящей лягушки, и она же режим лжи: цель, впервые \
         увиденная на плохом канале, объявит своей планкой плохое, и просадка от неё не отсчитается \
         никогда. Планка честна ровно настолько, насколько ХОРОШИЙ момент попал в наблюдение.",
        "МЕДЛЕННЫЙ КАНАЛ НЕОТЛИЧИМ ОТ ТРОТТЛИНГА. Прибор меряет темп и не знает его причины; \
         `netem 250кбит потери 6%` даст тот же вердикт, что ТСПУ. Чужой детектор на этой клетке \
         доложил 33 цели «via DPI» — у нас сток тот же, просто мы его назвали.",
    ];

    const ORACLES: &'static [&'static str] =
        &["throttle(250kbit,6%)", "fatflow(1.2.3.4,16,reply,drop)"];

    /// СМЕРТЬ: заведена клетка «канал медленный» — тогда сток неназванного перестаёт втекать
    /// сюда, и порог станет различением, а не границей корзины.
    const DEATH: &'static str = "алфавит получил клетку «канал медленный»; сток назван явно";

    /// ПУБЛИЧНЫЕ ИМЕНА: одно — просадка. Величина едет В СОБЫТИИ, а не в имени.
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

/// ПАСПОРТ ДЕТЕКТОРА ЗАХЛЁБЫВАНИЯ.
///
/// Прибор о МИРЕ: клиент просит, цель не отдаёт, планки она не доказывала. Отличается от
/// [`SilenceInstrument`] тем, что требует ДОКАЗАННОГО СПРОСА — без просьбы молчание цели законно.
#[derive(Debug, Clone, Copy)]
pub struct ChokedInstrument {
    /// СКОЛЬКО ЖДАТЬ ОТВЕТА, ПРЕЖДЕ ЧЕМ ОБВИНЯТЬ.
    ///
    /// Порога не было вовсе: приговор выносился на ПЕРВОМ ЖЕ тике после просьбы. Живая запись
    /// показала цену — `nalog.ru` ответил через 348 мс и был помечен задушенным, тогда как у
    /// человека страница открылась за 240 мс. В тестах это не всплывало: там тик подаётся один и
    /// заведомо поздний, а на живом проводе они идут каждые 300 мс.
    ///
    /// Срок тот же, что у прибора тишины, и это не совпадение: оба отвечают на вопрос «сколько
    /// молчания считать бедой», и две разные правды об одном сроке были бы хуже любой одной.
    after: Duration,
    /// Когда человек попросил впервые. Отсюда идёт отсчёт терпения.
    asked_at: Option<Instant>,
    /// Сколько клиент отправил вверх за наблюдение.
    sent: u64,
    /// Сколько цель отдала вниз.
    received: u64,
    /// Доказанная планка: сколько цель УЖЕ умела отдавать. Ноль — не доказывала никогда.
    proven_ceiling: u64,
    fired: bool,
}

impl ChokedInstrument {
    /// `proven_ceiling` приходит извне: это знание о ПРОШЛОМ цели, а прибор видит только текущее
    /// наблюдение. Ноль значит «не доказывала никогда».
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

    /// Вышло ли терпение с момента первой просьбы.
    fn patience_over(&self, now: Instant) -> bool {
        match self.asked_at {
            None => false,
            Some(asked) => now.saturating_duration_since(asked) >= self.after,
        }
    }
}

impl reflex_core::step::Step for ChokedInstrument {
    /// ОБЩИЙ СЛОВАРЬ, А НЕ СЛОВАРЬ СОЕДИНЕНИЯ.
    ///
    /// Предмет прибора — «клиент просил, цель не отдала ни разу», и он существует на любом
    /// транспорте: окна приёма этот прибор не читает вовсе, и потому вход не требует улик
    /// соединения.
    type From = reflex_core::DetectorEvent<Seen>;
    type To = smallvec::SmallVec<[Distress; 2]>;

    fn step(self, event: Self::From) -> (Self, Self::To) {
        match event {
            reflex_core::DetectorEvent::Packet { input, at } => {
                // МОМЕНТ ПЕРВОЙ ПРОСЬБЫ — начало отсчёта терпения. Повторная просьба его не
                // сдвигает: человек ждёт один раз, а не заново с каждым повтором.
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
                    // Повтор считается спросом наравне с первой просьбой: цель, которой шлют
                    // ВТОРОЙ раз и которая молчит, задушена тем более.
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
                    // Прощание спросом не является и наблюдения не кончает: цель, попрощавшаяся
                    // не отдав ничего, задушена ровно так же.
                    Seen::Closed { .. } => waiting,
                };
                (next, smallvec::SmallVec::new())
            }
            // ТЕРПЕНИЕ ВХОДИТ В УСЛОВИЕ: «просили и не ответили» становится уликой не раньше, чем
            // истечёт срок. Иначе обвиняется всякий, кто отвечает медленнее одного тика.
            reflex_core::DetectorEvent::Tick { at } => match (
                self.fired,
                self.sent > 0 && self.patience_over(at),
                self.received > 0,
            ) {
                // Байты идут — лечить нечего.
                (_fired, _waited, true) => (self, smallvec::SmallVec::new()),
                // Тишина с обеих сторон: цель молчит законно, её никто не просит.
                (_fired, false, false) => (self, smallvec::SmallVec::new()),
                // Уже сообщали.
                (true, true, false) => (self, smallvec::SmallVec::new()),
                // ЖИВАЯ, НО ЗАМОЛЧАВШАЯ — не наш случай: доказывала планку, значит молчание может
                // быть паузой. Ошибка здесь стоит не одного потока, а ноги.
                (false, true, false) if self.proven_ceiling > 0 => {
                    (self, smallvec::SmallVec::new())
                }
                // МЁРТВАЯ С РОЖДЕНИЯ: клиент просит, цель не отдавала НИ РАЗУ.
                (false, true, false) => (
                    Self {
                        fired: true,
                        ..self
                    },
                    smallvec::smallvec![Distress::NoBytes],
                ),
            },
        }
    }
}

impl crate::Instrument for ChokedInstrument {
    type Signal = Distress;

    const INSTRUMENT: &'static str = "choked";

    const SUBJECT: crate::Subject = crate::Subject::World;

    /// УРОВЕНЬ: «просил и не получил» есть факт о байтах, а байты есть у любого транспорта.
    ///
    /// ПРОТОКОЛ ИСПРАВЛЕН С `Tcp` НА `Any` (#320): прежнее обоснование («окно приёма — поле
    /// заголовка TCP») описывало соседа, а не этот прибор — окна он не читает ни разу. Держалось
    /// два месяца потому, что объявление не сверялось ни с чем; теперь его сверяет тип входа.
    /// ТРАНСПОРТЫ: «просил и не получил» есть факт о байтах, а байты есть у обоих.
    const LAYER: crate::Layer = crate::Layer::Transport;
    const PROTOCOLS: &'static [crate::Protocol] = &[crate::Protocol::Tcp, crate::Protocol::Udp];
    const RUNG: Option<crate::Rung> = None;

    /// СВОИ ЧАСЫ: предмет — отсутствие ответа, и его нельзя дождаться пакетом.
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

    /// СМЕРТЬ: терпение стало функцией от RTT цели — тогда порог перестанет быть общим, и этот
    /// паспорт перепишется вместе с ним.
    const DEATH: &'static str = "терпение выводится из RTT цели, а не задаётся одной константой";

    /// ПУБЛИЧНЫЕ ИМЕНА: одно — цель не отдала ничего при доказанном спросе.
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
    use reflex_core::step::Step;
    use reflex_core::DetectorEvent;
    use std::time::{Duration, Instant};

    /// Прогнать прибор по наблюдениям и тикам с ЗАДАННЫМ временем: реальные часы в поверке
    /// приборов не участвуют — иначе тест зеленеет через раз.
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
                        None => DetectorEvent::Tick { at },
                    };
                    let (stepped, signals) = state.step(event);
                    (stepped, said.into_iter().chain(signals).collect())
                },
            )
            .1
    }

    /// ЦЕЛЬ НЕ ОТВЕТИЛА ВОВСЕ — это `NoBytes`, а не «поток встал».
    ///
    /// Две беды, а не одна: они расследуются и лечатся по-разному. Невод 1 звал обе молчанием и
    /// оттого лечил обходом упавшие серверы. Прибор до сегодняшнего дня различения не имел вовсе:
    /// по одной длительности `NoBytes` не выводится ничем.
    ///
    /// # ЗДЕСЬ ЖЕ ПОВЕРЯЕТСЯ ДРОП `SYN` (#320, 02.09)
    ///
    /// Сценарий не содержит НИ ОДНОГО наблюдения — только часы. Прежде первым шёл `Seen::Syn`, и
    /// расщепление алфавита эту улику у прибора отобрало: она принадлежит соединению, а прибор
    /// живёт на любом транспорте. Поток, где клиент стучится в пустоту, не порождает ни одной
    /// ОБЩЕЙ буквы — и, если бы часы заводились наблюдением, прибор молчал бы вечно ровно на той
    /// земле, ради которой заведён.
    #[test]
    fn a_target_that_never_answered_is_not_the_same_as_a_stalled_stream() {
        let said = run(
            SilenceInstrument::after(Duration::from_millis(1_500)),
            vec![(None, 0), (None, 2_000)],
        );

        assert_eq!(said, vec![Distress::NoBytes]);
    }

    /// ПОТОК ВСТАЛ НА СЕРЕДИНЕ — байты были и кончились, пока их ждут.
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

    /// МОЛЧАНИЕ ЕСТЬ БЕДА, ТОЛЬКО ЕСЛИ ЕГО КТО-ТО ЖДЁТ.
    ///
    /// Оплачено стендом 29.08 оракулом человека: `vk.com` открылся за 296 мс и получил `Silence`,
    /// потому что тишина мерилась от любого события — простаивающее keep-alive через полторы
    /// секунды объявлялось бедой. Цена ложной беды не в отчёте, а в пробах: расследование уходит
    /// проверять здоровую цель, пока настоящая ждёт.
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

    /// ПРОЩАНИЕ КОНЧАЕТ НАБЛЮДЕНИЕ: молчание того, кто попрощался, — не улика.
    ///
    /// Тики после этого идут (их порождает чужой трафик), но уличать уже некого.
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

    /// ОДИН РАЗ НА РАЗГОВОР: следствие уже заведено, второй жалобы не нужно.
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
    use reflex_core::step::Step;
    use reflex_core::DetectorEvent;
    use std::time::Instant;

    /// Прогон со сценарием: наблюдение либо тик (`None`), и смещение времени от начала.
    ///
    /// Алфавит берётся У ПРИБОРА (`In`), а не задаётся хелпером: соседи по модулю стоят теперь на
    /// РАЗНЫХ протоколах, и общий хелпер с прибитым словарём заставил бы одного из них поверяться
    /// чужим входом.
    fn run<D, In>(instrument: D, script: Vec<(Option<In>, u64)>) -> Vec<Distress>
    where
        D: Step<From = DetectorEvent<In>, To = smallvec::SmallVec<[Distress; 2]>>,
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
                        None => DetectorEvent::Tick { at },
                    };
                    let (stepped, signals) = state.step(event);
                    (stepped, said.into_iter().chain(signals).collect())
                },
            )
            .1
    }

    /// ТРОТТЛИНГ СУДИТСЯ ПРОТИВ ДОКАЗАННОЙ ПЛАНКИ, А НЕ ПРОТИВ НУЛЯ.
    ///
    /// Цель отдала мегабайт за первое окно, дальше отдаёт по сорок килобайт. Три просевших окна
    /// подряд — приговор; величина едет в самом показании, чтобы беда называлась в единице
    /// человека, а не флагом.
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

    /// ТОТ ЖЕ ТЕМП ПРИ ТОЙ ЖЕ ПЛАНКЕ БЕДОЙ НЕ ЯВЛЯЕТСЯ — иначе прибор объявлял бы задушенной
    /// всякую медленную цель. Витнес в паре к предыдущему: разница только в планке.
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

    /// ЗАХЛЁБЫВАНИЕ ТРЕБУЕТ И СПРОСА, И ТЕРПЕНИЯ. Три случая в одном предмете: не просили — не
    /// беда; просили, но ждём меньше порога — не беда; просили и ждём дольше — беда.
    ///
    /// Средний случай оплачен полем: `nalog.ru` ответил через 348 мс и был помечен задушенным,
    /// тогда как у человека страница открылась за 240 мс.
    #[test]
    fn choking_needs_both_demand_and_patience() {
        // НЕ ПРОСИЛИ ВОВСЕ — ни одной буквы спроса. Прежде здесь стоял `Seen::Syn` (стук без
        // просьбы); после расщепления алфавита эта улика прибору вообще не видна, и «спроса не
        // было» выражается тем, чем оно и является, — отсутствием событий.
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

    /// ЦЕЛЬ, КОТОРАЯ УЖЕ ДОКАЗЫВАЛА ПЛАНКУ, ЩАДИТСЯ: её молчание может быть паузой, и ошибка
    /// здесь стоит не одного потока, а ноги.
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
    use reflex_core::step::Step;
    use reflex_core::DetectorEvent;

    fn saw(seen: SeenTcp) -> DetectorEvent<SeenTcp> {
        DetectorEvent::packet_now(seen)
    }

    /// Прогнать прибор по наблюдениям, собрать сказанное.
    fn run(instrument: RstInstrument, seen: Vec<SeenTcp>) -> Vec<Distress> {
        seen.into_iter()
            .fold((instrument, Vec::new()), |(state, said), seen| {
                let (stepped, signals) = state.step(saw(seen));
                (stepped, said.into_iter().chain(signals).collect())
            })
            .1
    }

    /// ПОДПИСЬ ТСПУ — сброс от цели ДО того, как она отдала хоть байт.
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

    /// СБРОС ПОСЛЕ ОТДАННЫХ БАЙТОВ — ШТАТНОЕ ЗАКРЫТИЕ, А НЕ БЕДА.
    ///
    /// Оплачено замером живой записи 29.08: 23 сброса, из них 17 наших собственных и 6 от цели —
    /// и все шесть ПОСЛЕ отданных байтов. Настоящих бед в чистой записи не было ни одной, а
    /// движок объявил 12.
    ///
    /// Ровно это различение и разъехалось между двумя реализациями одного понятия: детектор в
    /// домене его имел, прибор — нет, и прибор объявлял бедой конец разговора.
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

    /// ОДИН РАЗ НА СОЕДИНЕНИЕ: тысяча флоу к одному сервису не должна заводить тысячу следствий.
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

    /// НИ ЧЕЛОВЕК, НИ МЫ САМИ БЕДОЙ ЦЕЛИ НЕ ЯВЛЯЕМСЯ.
    ///
    /// Вменить цели наш собственный приказ значило бы понизить оценку ноги за то, что сделали мы:
    /// приказ на обрыв лечил бы и калечил одним движением.
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

    /// ГОЛОВА ЦЕЛИ ТОЖЕ ЕСТЬ ОТВЕТ: после неё сброс — прощание, а не улика.
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
