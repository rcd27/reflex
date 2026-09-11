// Обещание имени в докблоке ([`Name`]) держит компилятор, не читатель: битая ссылка — ошибка сборки
// документации, а не молчаливое предупреждение, которое ловят люди постфактум.
#![deny(rustdoc::broken_intra_doc_links)]

//! Паспорт прибора. Прибор — тип, дающий СИГНАЛ (элемент + интерпретация); новый прибор рождается
//! новой интерпретацией, не сложением приборов. Приборы о человеке — композиты, и закон композита:
//! **различение(композит) ≤ различению частей** (слепота ступени поднимается наверх целиком).
//!
//! Четыре множителя годности, ноль в любом обнуляет всё: прибор, проваливший любую ось, остаётся
//! ЧЕСТНЫМ по выходу — различить его от исправного можно только паспортом. Половина паспорта — в
//! типе (решётка, форма, «не знаю»), половина — константами, что печатает аудит. Закон слоя:
//! ВЫВЕДЕННОЕ СИЛЬНЕЕ ОБЪЯВЛЕННОГО.

#![forbid(unsafe_code)]

// Каждый прибор — свой модуль, все здесь, а не по месту потребления (прежде детекция жила в пяти
// крейтах, ответ на «что мы видим» был свой в каждом). Прибор возвращает своё ПОКАЗАНИЕ, не беду
// продукта: перевод в Distress/Sighting/Finding — работа потребителя.
pub mod agreement;
pub mod ask;
pub mod departure;
pub mod detect;
pub mod dismiss;
pub mod distress;
pub mod drift;
pub mod edge;
pub mod edge_detect;
pub mod edge_word;
pub mod episode;
pub mod fate;
pub mod leg;
pub mod pace;
pub mod park;
pub mod poison;
pub mod resolve;
pub mod retransmit;
pub mod sag;
pub mod swallow;
pub mod trust;
pub mod unreached;
pub mod wire;

/// О чём прибор говорит и кому служит ответ. Ось A переписи.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Subject {
    /// О мире — что делают цензор и цель.
    World,
    /// О нас — применилось ли действие, не ослепли ли мы.
    Ourselves,
    /// О человеке — что он пережил. Единственная ось, где беда напрямую.
    Person,
    /// О нашей работе — дисциплина.
    OurWork,
}

/// Что заставляет прибор высказаться. Ось B; наблюдаемость перехода есть свойство ПАРЫ, не прибора.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cadence {
    /// Чужой запрос: пакет, закрытие окна, вопрос человека. Для предмета, меняющегося сам, — ноль.
    Foreign,
    /// Свои часы. Шаг в мс: часы с шагом больше терпения человека не лечат.
    Own { step_ms: u64 },
    /// Ряд между прогонами. Единственный темп, чей предмет — смена, не состояние.
    Series,
}

/// Форма выхода. Решает, какие операторы законны: переход — на состоянии, сложение — на величине,
/// не на вердикте.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shape {
    /// Величина: складывается, усредняется, перехода нет.
    Quantity,
    /// Состояние: имеет переход, требует равенства.
    State,
    /// Событие: уже переход.
    Event,
    /// Вердикт: сужает круг судеб.
    Verdict,
    /// Ряд: композиция — конкатенация.
    Series,
}

/// Что прибор говорит, когда сказать нечего. Обязанность: алфавит без клетки «не смог» превращает
/// дефект прибора в улику против мира (оплачено — пять доменов из сорока шести доложены
/// заблокированными из-за склейки строк). «Хорошо» недопустимо: так молча отказавший контроль
/// становится вердиктом «всё в порядке».
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Silence {
    /// Смотрел и не увидел: показание пусто, наблюдение состоялось.
    Nothing,
    /// Не смог: контрольное плечо молчит, вход не пришёл. Лечение противоположно `Nothing`.
    Blind,
}

/// Четыре множителя годности. Разведены: у `Offers` подключённость 1 при нулевом питании, у
/// `admits` — 0 при максимальном различении; не разведи — оба читаются как «не подключён» и чинятся
/// не тем.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fitness {
    /// Сужает ли показание круг так, что разные беды ведут к разному лечению.
    pub discriminates: bool,
    /// Есть ли читатель в живом входе — не в тесте.
    pub read: bool,
    /// Приходят ли читателю значения, отличные от пустого.
    pub fed: bool,
    /// Успевает ли прибор высказаться в пределах терпения ждущего. Выводится арифметикой (шаг
    /// решётки — константа, терпение — число), не прогоном.
    pub timely: bool,
}

impl Fitness {
    /// Годен ли. Произведение: ноль в любом множителе обнуляет всё.
    pub fn sound(self) -> bool {
        self.discriminates && self.read && self.fed && self.timely
    }

    /// Что сломано — для аудита. Порядок от дешёвого лечения к дорогому (провод < потребитель < часы).
    pub fn broken(self) -> &'static [&'static str] {
        match (self.fed, self.read, self.discriminates, self.timely) {
            (false, _, _, _) => &["питание: читатель есть, значения не приходят"],
            (_, false, _, _) => &["подключённость: показание никто не читает в живом входе"],
            (_, _, false, _) => &["различение: разные беды дают одно показание"],
            (_, _, _, false) => &["срок: прибор высказывается позже, чем человек уходит"],
            (true, true, true, true) => &[],
        }
    }
}

/// Уровень, на котором лежит улика. Ось E. `Ord` намеренно: **прибор уровня `L` видит улики
/// уровней `≤ L`**, верхний видит нижние, нижний верхние — никогда; композит наследует максимум.
/// Имена, не номера (номер зависит от модели).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Layer {
    /// Кадр (OSI 2): интерфейс, MAC. Пока не наблюдается — вариант для полноты порядка.
    Link,
    /// Адрес (OSI 3): IP, TTL. Здесь блокировка ПО АДРЕСУ.
    Network,
    /// Транспорт (OSI 4): порт, рукопожатие, сброс, окно. У TCP их четыре, у UDP — ни одной.
    Transport,
    /// Сеанс (OSI 5–6): TLS/QUIC — имя, версия, личность. Здесь блокировка ПО ИМЕНИ и граница
    /// шифрования.
    Session,
    /// Приложение (OSI 7): метод, заголовки, тело. Всё, что различает «то ли пришло».
    Application,
}

/// Протокол, на котором улика существует или нет. Вторая ось, без неё первая врёт: на `Transport` у
/// TCP четыре улики, у QUIC — две. Варианта `Any` нет: он молча покрывал бы будущие протоколы —
/// «любой» есть перечисление ([`Instrument::PROTOCOLS`]), не отдельное значение.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Udp,
    Quic,
    Tls,
    Http,
    Dns,
}

impl Protocol {
    /// Чем этот протокол несётся — спуск по стеку значением (там, где тип неизвестен компилятору:
    /// «кто отвечает на ступень у TLS-потока»). Список: отношение — решётка (HTTP несётся и TCP, и
    /// TLS).
    pub const fn carriers(self) -> &'static [Protocol] {
        match self {
            Protocol::Tcp | Protocol::Udp => &[],
            Protocol::Quic => &[Protocol::Udp],
            Protocol::Dns => &[Protocol::Udp],
            Protocol::Tls => &[Protocol::Tcp],
            Protocol::Http => &[Protocol::Tcp, Protocol::Tls],
        }
    }

    /// Всё, чем несётся, вниз до транспорта: улика ступени лежит ниже протокола («отозвалась ли»
    /// у TLS читается на транспорте).
    pub fn beneath(self) -> Vec<Protocol> {
        self.carriers()
            .iter()
            .flat_map(|under| std::iter::once(*under).chain(under.beneath()))
            .collect()
    }
}

impl Layer {
    /// Сравнение в `const`-контексте.
    pub const fn same(self, other: Layer) -> bool {
        self as u8 == other as u8
    }
}

/// Ступень — вопрос, на который отвечает детектор. Ось F. Вопрос одинаков на любом транспорте,
/// улика специфична: **детектор = ступень ∘ (улика уровня и протокола)**.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rung {
    /// Дошло ли — клиент добрался до цели и попросил.
    Reached,
    /// Ответили ли — цель отозвалась хоть чем-то.
    Answered,
    /// Оборвано ли, и кем — разговор прекращён насильно, у обрыва есть автор.
    Severed,
    /// То ли пришло — содержимое соответствует запросу.
    Authentic,
}

impl Rung {
    /// Где лежит улика ступени на протоколе. `None` — улики НЕ существует (`Blind`, не `Nothing`).
    /// Таблица замерена (каждая строка про QUIC оплачена фикстурой).
    pub const fn evidence(self, protocol: Protocol) -> Option<Layer> {
        match self {
            // Байты вверх/вниз видны на любом транспорте — унифицированная часть детектора.
            Rung::Reached | Rung::Answered => Some(Layer::Transport),
            // Обрыв транспортный и только у TCP: у QUIC он внутри шифра.
            Rung::Severed => match protocol {
                Protocol::Tcp => Some(Layer::Transport),
                Protocol::Udp | Protocol::Quic | Protocol::Tls | Protocol::Http | Protocol::Dns => {
                    None
                }
            },
            // Содержимое: у TLS улика на уровне сеанса (прибор `trust` читает тревогу клиента),
            // у HTTP/DNS — прикладная.
            Rung::Authentic => match protocol {
                Protocol::Http | Protocol::Dns => Some(Layer::Application),
                Protocol::Tls => Some(Layer::Session),
                Protocol::Tcp | Protocol::Udp | Protocol::Quic => None,
            },
        }
    }
}

/// Сторона разговора. Не `bool`: третий ответ («различить нечем») — `Option`, не флаг.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    /// Начал тот, кто в источнике пакета.
    Source,
    /// Начал тот, кто в назначении.
    Destination,
}

/// Две стороны пакета — вход улики «кто начал».
pub struct Endpoints<'a> {
    pub src: [u8; 4],
    pub dst: [u8; 4],
    pub src_port: u16,
    pub dst_port: u16,
    /// Нужна только самому верхнему уровню.
    pub payload: &'a [u8],
}

/// Известные серверные порты. Список, не «меньше 1024»: у QUIC/STUN серверные порты выше тысячи.
const SERVER_PORTS: &[u16] = &[53, 80, 123, 443, 853, 3478, 5349, 8080, 8443];

/// Кто начал разговор — улика на самом низком уровне, который различает. Лестница `Network` →
/// `Transport` → `Session`: ниже по стеку улика универсальнее (адрес есть у любого пакета). Лучше
/// «первой датаграммы» (запись с середины назначила бы клиентом сервер). `None` — различить нечем
/// (`Blind`): честнее не заводить разговор, чем с перевёрнутыми направлениями.
pub fn initiator(ends: &Endpoints) -> Option<(Side, Layer)> {
    let private = |addr: [u8; 4]| match addr {
        [10, _, _, _] => true,
        [172, second, _, _] if (16..32).contains(&second) => true,
        [192, 168, _, _] => true,
        // CGNAT: там живёт наш mesh.
        [100, second, _, _] if (64..128).contains(&second) => true,
        _ => false,
    };
    let known = |port: u16| SERVER_PORTS.contains(&port);

    // Уровень адреса: ровно одна сторона частная ⟹ она пришла.
    match (private(ends.src), private(ends.dst)) {
        (true, false) => return Some((Side::Source, Layer::Network)),
        (false, true) => return Some((Side::Destination, Layer::Network)),
        (true, true) | (false, false) => (),
    }

    // Уровень порта: ровно один известен как серверный ⟹ вторая сторона клиентская.
    match (known(ends.src_port), known(ends.dst_port)) {
        (false, true) => return Some((Side::Source, Layer::Transport)),
        (true, false) => return Some((Side::Destination, Layer::Transport)),
        (true, true) | (false, false) => (),
    }

    // Уровень сеанса: клиентский `Initial` QUIC — длинный заголовок и набивка до 1200 байт.
    let long_header = ends
        .payload
        .first()
        .map(|first| first & 0x80 != 0)
        .unwrap_or(false);
    match long_header && ends.payload.len() >= 1_200 {
        true => Some((Side::Source, Layer::Session)),
        false => None,
    }
}

/// Где у пары лежит речь прибора — таблица из двух строк. Прибор высказывается в одной букве пары,
/// в какой решает АДРЕС значения: есть область — слово соседу, нет — слово пусто (`()`), речь вбок
/// показанием. Реализуется на паре (а не на шаге): две строки различаются первой буквой, а на шаге
/// они перекрылись бы.
pub trait Spoken {
    /// Пачка, об одном элементе которой паспорт умеет сказать имя.
    type Signals;
}

/// Слово есть пачка: прибор говорит соседу, показания какие угодно.
impl<S, N> Spoken for (smallvec::SmallVec<[S; 2]>, N) {
    type Signals = smallvec::SmallVec<[S; 2]>;
}

/// Слова нет: области у значения нет, вся речь — показание.
impl<S> Spoken for ((), smallvec::SmallVec<[S; 2]>) {
    type Signals = smallvec::SmallVec<[S; 2]>;
}

/// Паспорт прибора. Половина выводится типами, половина объявляется и сверяется аудитом. Навешен на
/// [`Mealy`](reflex_core::mealy::Mealy); граница [`Spoken`] связывает объявленный `Signal` с выходом
/// шага — расхождение ловит компилятор.
pub trait Instrument: reflex_core::mealy::Mealy
where
    (Self::Out, Self::Log): Spoken<Signals = smallvec::SmallVec<[<Self as Instrument>::Signal; 2]>>,
{
    /// Сигнал — то, о чём прибор говорит по одному разу. Элемент той буквы пары, в которой прибор
    /// высказывается (какой — говорит [`Spoken`]).
    type Signal;

    /// О чём прибор говорит.
    const SUBJECT: Subject;

    /// На каком уровне стоит. Видит улики `≤ LAYER`; спрашивать выше — получать `Blind` за факт.
    const LAYER: Layer;

    /// На каких протоколах живёт его улика. Отдельно от уровня (уровень без протокола врёт). Список,
    /// не `Any`. Пустой список законен — «улики нет на проводе» (счётчик netfilter, вклады
    /// соединений, имя цели).
    const PROTOCOLS: &'static [Protocol];

    /// На какой вопрос отвечает. `None` — не детектор ступени (вопросов четыре, приборов больше).
    const RUNG: Option<Rung>;

    /// Что заставляет высказаться.
    const CADENCE: Cadence;

    /// Форма выхода.
    const SHAPE: Shape;

    /// Что говорит, когда сказать нечего. `None` — паспорт неполон (дефект за факт о мире).
    const SILENCE: Option<Silence>;

    /// Как врёт — известные режимы лжи, каждый оплаченный наблюдением. Пустой список — «не
    /// поверялся», не «не врёт».
    const LIES: &'static [&'static str];

    /// Второй оракул — имена сценариев стенда, устроенных ИНАЧЕ. Имя сценария (ведёт к земле), с
    /// параметрами целиком (`fatflow(...)`, не `fatflow`: четыре разные беды под одним именем).
    const ORACLES: &'static [&'static str];

    /// Условие смерти — рядом с телом, не в отдельном реестре (объявление вдали разъезжается).
    const DEATH: &'static str;

    /// Имя прибора в публичном круге. Им подписываются его показания ([`MealyExt::by`](reflex_core::mealy::MealyExt::by)).
    const INSTRUMENT: &'static str;

    /// Публичные имена событий — реестр, снятый с типа: `Debug` сменил бы метку молча (#321).
    const EVENTS: &'static [&'static str];

    /// Как называется это показание в публичном круге. Не `Debug`.
    fn name(signal: &Self::Signal) -> &'static str;

    /// Требует ли показание внимания. Знание прибора (= элементы + интерпретация), не потребителя.
    fn alarming(signal: &Self::Signal) -> bool;

    /// О ком показание, если прибор знает (резолв знает имя; сброс — нет). `None` — «спроси у
    /// наблюдения».
    fn about(signal: &Self::Signal) -> Option<String> {
        let _ = signal;
        None
    }

    /// Величина показания в единице человека. Пусто — показание есть само событие.
    fn detail(signal: &Self::Signal) -> String {
        let _ = signal;
        String::new()
    }
}

/// Паспорт сверяется с таблицей улик компилятором: прибор, объявивший ступень, обязан стоять там,
/// где улика лежит, на каждом названном протоколе. Зовётся в [`park::of`] `const`-блоком (ассоц.
/// константой не выражается — ссылка из обычной функции её не форсирует). Ловит РАСХОЖДЕНИЕ двух
/// объявлений, не правду добычи улики.
pub const fn passport_holds(
    rung: Option<Rung>,
    protocols: &'static [Protocol],
    layer: Layer,
) -> bool {
    let rung = match rung {
        None => return true,
        Some(rung) => rung,
    };
    // Ступень без протокола есть вопрос без места, где на него смотрят.
    if protocols.is_empty() {
        return false;
    }
    let mut i = 0;
    while i < protocols.len() {
        match rung.evidence(protocols[i]) {
            // Улики ступени на этом протоколе нет, а прибор её объявил.
            None => return false,
            // Улика есть, но лежит не там, где стоит прибор.
            Some(where_it_lies) => {
                if !where_it_lies.same(layer) {
                    return false;
                }
            }
        }
        i += 1;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Произведение: любой одиночный ноль обнуляет годность.
    #[test]
    fn any_single_zero_kills_fitness() {
        let whole = Fitness {
            discriminates: true,
            read: true,
            fed: true,
            timely: true,
        };
        assert!(whole.sound());

        let zeros = [
            Fitness {
                discriminates: false,
                ..whole
            },
            Fitness {
                read: false,
                ..whole
            },
            Fitness {
                fed: false,
                ..whole
            },
            Fitness {
                timely: false,
                ..whole
            },
        ];
        assert!(zeros.iter().all(|f| !f.sound()));
    }

    /// Подключённость и питание — разные множители. `Offers`: читатель есть, значения не идут.
    #[test]
    fn read_but_unfed_reports_the_wire_not_the_reader() {
        let offers = Fitness {
            discriminates: true,
            read: true,
            fed: false,
            timely: true,
        };
        assert!(!offers.sound());
        assert!(offers.broken()[0].starts_with("питание"));
    }

    /// `admits`: различение максимальное, читателя нет.
    #[test]
    fn unread_reports_the_reader() {
        let admits = Fitness {
            discriminates: true,
            read: false,
            fed: true,
            timely: true,
        };
        assert!(admits.broken()[0].starts_with("подключённость"));
    }

    /// Часы есть, но их шаг больше терпения человека.
    #[test]
    fn own_clock_that_ticks_too_slowly_is_still_untimely() {
        let episode = Fitness {
            discriminates: true,
            read: true,
            fed: true,
            timely: false,
        };
        assert!(!episode.sound());
        assert!(episode.broken()[0].starts_with("срок"));
    }
}

#[cfg(test)]
mod ladder {
    use super::*;

    fn plain(src: [u8; 4], dst: [u8; 4], src_port: u16, dst_port: u16) -> Endpoints<'static> {
        Endpoints {
            src,
            dst,
            src_port,
            dst_port,
            payload: &[],
        }
    }

    /// Клиентский `Initial` QUIC: длинный заголовок и набивка до 1200 байт.
    const CLIENT_INITIAL: [u8; 1200] = {
        let mut bytes = [0u8; 1200];
        bytes[0] = 0xC0;
        bytes
    };

    #[test]
    fn the_address_floor_answers_first_when_one_side_is_private() {
        let answer = initiator(&plain([192, 168, 1, 10], [142, 251, 155, 119], 51234, 443));
        assert_eq!(answer, Some((Side::Source, Layer::Network)));

        // И в обратную сторону: без этой половины прибор зеленел бы, всегда отвечая «источник».
        let back = initiator(&plain([142, 251, 155, 119], [192, 168, 1, 10], 443, 51234));
        assert_eq!(back, Some((Side::Destination, Layer::Network)));
    }

    #[test]
    fn the_port_floor_answers_when_both_sides_are_private() {
        // DNS внутри стенда: обе стороны частные, различает порт.
        let answer = initiator(&plain([10, 77, 0, 11], [10, 77, 0, 2], 45678, 53));
        assert_eq!(answer, Some((Side::Source, Layer::Transport)));
    }

    /// Уровень содержимого покрыт здесь, и только здесь (на записях не работает ни разу — все QUIC
    /// решаются адресом; поверяется таблицей, иначе непроверенный код).
    #[test]
    fn the_content_floor_answers_when_neither_address_nor_port_can() {
        let quic = Endpoints {
            src: [203, 0, 113, 7],
            dst: [198, 51, 100, 9],
            src_port: 40000,
            dst_port: 40001,
            payload: &CLIENT_INITIAL,
        };
        assert_eq!(initiator(&quic), Some((Side::Source, Layer::Session)));
    }

    /// Слепота называется, а не заменяется догадкой.
    #[test]
    fn nothing_answers_when_no_floor_discriminates() {
        let neither = initiator(&plain([203, 0, 113, 7], [198, 51, 100, 9], 40000, 40001));
        assert_eq!(neither, None, "сторона названа там, где различить её нечем");
    }

    /// Порядок уровней существенен: нижний отвечает первым, даже когда верхний тоже мог бы.
    #[test]
    fn the_lowest_floor_wins_even_when_a_higher_one_would_agree() {
        let both = Endpoints {
            src: [192, 168, 1, 10],
            dst: [142, 251, 155, 119],
            src_port: 51234,
            dst_port: 443,
            payload: &CLIENT_INITIAL,
        };
        assert_eq!(
            initiator(&both),
            Some((Side::Source, Layer::Network)),
            "ответ пришёл не с самого низкого различающего уровня"
        );
    }
}

/// Снять СЛОВО с одного наблюдения — для поверок и потребителей без потока. Спрашивается тем же
/// `step`, что и на живом потоке (разойтись не могут). Прибор со своими часами так не поверяется —
/// его предмет есть ход времени; такие поверяются подачей `Tick`.
///
/// # Половина случаев, на которой этот помощник НЕ РАБОТАЕТ
///
/// Слово (`Out`) адресовано соседу по цепочке, и у прибора, чьё слово адресата не имеет
/// (`Out = ()`, а показание живёт в `Log`), `says` вернёт пустоту — не «прибор промолчал», а
/// «спросили не то». Для таких есть [`heard`]. Пара названа здесь, потому что молчание помощника
/// неотличимо от молчания прибора, и разбираться в этом каждый поверяющий будет заново.
pub fn says<D, In>(instrument: D, observation: In) -> D::Out
where
    D: reflex_core::mealy::Mealy<In = reflex_core::DetectorEvent<In>>,
{
    instrument
        .step(reflex_core::DetectorEvent::packet_now(observation))
        .1
}

/// Снять ПОКАЗАНИЕ с одного наблюдения — вторая половина пары к [`says`].
///
/// Слово и показание — разные предметы (§5): слово адресовано соседу и обязано быть скупым,
/// показание адресовано человеку и несёт величины, которыми прибор работал. У части приборов слова
/// нет вовсе, и `says` на них отдаёт пустоту, ничего этим не сообщая; `heard` спрашивает у тех же
/// приборов то, что у них ЕСТЬ.
///
/// Заведено по замеру потребителя: пять его приборов не поверялись `says`, и он написал свою
/// обёртку — то есть помощник, не работающий на половине случаев, стоил ему трёх строк, а нам
/// молчаливого расхождения двух способов поверки.
pub fn heard<D, In>(instrument: D, observation: In) -> D::Log
where
    D: reflex_core::mealy::Mealy<In = reflex_core::DetectorEvent<In>>,
{
    instrument
        .step(reflex_core::DetectorEvent::packet_now(observation))
        .2
}
