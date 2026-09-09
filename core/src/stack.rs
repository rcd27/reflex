//! Протокол как тип: наблюдение, снятое не с того протокола, не собирается в цепочку. Объявление
//! протокола паспортом (`PROTOCOLS: &[Tcp]`) на уровне типов ничего не запрещает: датаграмма,
//! поданная прибору TCP, повисла бы «соединением» и копила молчание. Здесь протокол — параметр типа
//! НАБЛЮДЕНИЯ: прибор объявляет входом свой алфавит (`DetectorEvent<In>`), сборщик требует `In:
//! Reads<Widest>`, и поток, из которого алфавит не читается, в прибор не соберётся. Словарь —
//! комьюнити: `Protocol`, а не «транспорт» (OSI 4, где QUIC не живёт) и не «этаж». `Layer` здесь не
//! живёт: он ось переписи парка приборов, полон знанием о цензуре — принадлежит продукту.

/// Протокол, на котором снято наблюдение. Объект стека — тип, а не значение.
pub trait Protocol {
    const NAME: &'static str;
}

/// TCP: рукопожатие, сброс, окно приёма — улики, которых у датаграмм нет.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tcp;

/// UDP: датаграммы. Всё, что поверх них, — отдельные объекты: у QUIC свои улики, у DNS свои.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Udp;

/// QUIC: поверх UDP. Рукопожатие есть, но объявлено длинным заголовком, а обрыв зашифрован.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Quic;

/// TLS: поверх TCP. Имя цели открытым текстом в `ClientHello`, тревоги клиента — в рукопожатии.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tls;

/// DNS: обычно поверх UDP. Содержимое открыто, и потому здесь видно то, чего не видно нигде выше.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Dns;

/// HTTP: поверх TCP, голова открыта.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Http;

/// Протокол безразличен — предмет наблюдателя существует на любом (объём, ожидание, уход человека).
/// Не «неизвестно», а утверждение: улика не зависит от протокола.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AnyProtocol;

impl Protocol for Tcp {
    const NAME: &'static str = "tcp";
}

impl Protocol for Udp {
    const NAME: &'static str = "udp";
}

impl Protocol for Quic {
    const NAME: &'static str = "quic";
}

impl Protocol for Tls {
    const NAME: &'static str = "tls";
}

impl Protocol for Dns {
    const NAME: &'static str = "dns";
}

impl Protocol for Http {
    const NAME: &'static str = "http";
}

impl Protocol for AnyProtocol {
    const NAME: &'static str = "любой";
}

/// Спуск по стеку: всякое наблюдение `Self` есть также наблюдение `Under`. Морфизм ТОТАЛЬНЫЙ
/// (забывание, определено всегда: QUIC-пакет есть датаграмма) — оттого у трейта нет методов. Отношение
/// не дерево, а решётка: один протокол несётся несколькими (HTTP и прямо по TCP, и внутри TLS) —
/// оттого параметр, не ассоциированный тип, и второй `impl` для того же `Self` законен.
pub trait CarriedIn<Under: Protocol>: Protocol {}

/// Подъём по стеку: наблюдение `Under` МОЖЕТ оказаться наблюдением `Self`. Морфизм ЧАСТИЧНЫЙ —
/// свойство мира (датаграмма может быть QUIC, а может чем угодно); композиция частичных частична,
/// оттого протокол нельзя носить значением как установленный факт. `CarriedIn` — надтрейт: распознать
/// можно лишь то, что этим протоколом несётся (`Tls` не поднимается из `Udp` — там его нет), ловит
/// компилятор:
///
/// ```compile_fail
/// use reflex_core::stack::{Dissects, Tls, Udp};
///
/// fn from_datagrams<P: Dissects<Udp>>(_: &[u8]) {}
///
/// // TLS в датаграммах не несётся: поднимать его оттуда нечем.
/// from_datagrams::<Tls>(&[]);
/// ```
///
/// А законный подъём собирается:
///
/// ```
/// use reflex_core::stack::{Dissects, Quic, Udp};
///
/// fn from_datagrams<P: Dissects<Udp>>(payload: &[u8]) -> bool {
///     P::dissect(payload)
/// }
///
/// // Клиентский `Initial`: длинный заголовок и версия 1.
/// assert!(from_datagrams::<Quic>(&[0xc0, 0x00, 0x00, 0x00, 0x01]));
/// assert!(!from_datagrams::<Quic>(b"\x16\x03\x01hello"));
/// ```
///
/// Несомый, но не распознаваемый — законная клетка: [`CarriedIn`] без `Dissects` есть «несётся, а
/// увидеть нельзя» (HTTP внутри TLS зашифрован, DNS поверх UDP узнаётся портом). Слить два трейта в
/// один значило бы объявить эти клетки несуществующими.
pub trait Dissects<Under: Protocol>: CarriedIn<Under> {
    /// Похоже ли содержимое `Under` на этот протокол.
    ///
    /// Улика, а не догадка по номеру порта: порт есть соглашение, и цензор его не спрашивает.
    fn dissect(payload: &[u8]) -> bool;
}

impl CarriedIn<Udp> for Quic {}

impl Dissects<Udp> for Quic {
    /// Длинный заголовок и известная версия. Одного признака формы мало (под «старшие два бита
    /// единицы» подходит каждый четвёртый байт). Версий две: 1 (RFC 9000) и черновая 29; Version
    /// Negotiation (0) не входит — это ответ сервера, не разговор.
    fn dissect(payload: &[u8]) -> bool {
        match payload {
            [first, v0, v1, v2, v3, ..] => {
                first & 0xf0 == 0xc0
                    && matches!(
                        u32::from_be_bytes([*v0, *v1, *v2, *v3]),
                        0x0000_0001 | 0xff00_001d
                    )
            }
            _short => false,
        }
    }
}

impl CarriedIn<Tcp> for Tls {}

impl Dissects<Tcp> for Tls {
    /// Запись типа `handshake` (0x16) и версия 3.x. Версия не для порядка: один 0x16 встречается в
    /// произвольных данных каждый 256-й раз.
    fn dissect(payload: &[u8]) -> bool {
        matches!(payload, [0x16, 0x03, minor, ..] if *minor <= 0x04)
    }
}

impl CarriedIn<Tcp> for Http {}

impl Dissects<Tcp> for Http {
    /// Метод открытым текстом. Список короткий и явный: эвристика «похоже на текст» назвала бы
    /// HTTP всякий читаемый поток.
    fn dissect(payload: &[u8]) -> bool {
        [b"GET ".as_slice(), b"POST ", b"HEAD ", b"PUT ", b"OPTIONS "]
            .iter()
            .any(|method| payload.starts_with(method))
    }
}

/// HTTP внутри TLS несётся, а распознаётся ничем: содержимое зашифровано. Клетка «несомый без
/// распознавания» занята здесь намеренно — она и есть причина, по которой трейтов два.
impl CarriedIn<Tls> for Http {}

/// DNS несётся датаграммами, а узнаётся портом. `Dissects` не реализован намеренно: содержимое DNS
/// разбирается (`crate::dns`), но по одному пакету «это DNS» отличается от «похожего заголовка»
/// ненадёжно — пока улика порт 53, свидетель слабее, и тип это говорит.
impl CarriedIn<Udp> for Dns {}

/// Узкий алфавит читается из широкого, и не всякая буква читается. Тип, а не [`lmap`](crate::mealy::MealyExt::lmap):
/// `lmap` берёт сужение ЗАМЫКАНИЕМ (на каждой стройке заново), и «прибор читает вот эти буквы» есть
/// свойство ВЫЗОВА, а не прибора. Здесь сужение — свойство ПАРЫ ТИПОВ: прибор, чей алфавит из потока
/// не читается, не компилируется. Частичность существенна: `Option` не ошибка — буквы, которых на
/// узком алфавите нет, просто не события для его читателя. Тождество даётся даром: всякий алфавит
/// читается сам из себя.
///
/// ```
/// use reflex_core::stack::Reads;
///
/// #[derive(Clone, Debug, PartialEq)]
/// enum Wide { Общая(u8), Своя }
/// #[derive(Clone, Debug, PartialEq)]
/// struct Narrow(u8);
///
/// impl Reads<Wide> for Narrow {
///     fn read(wide: &Wide) -> Option<Self> {
///         match wide {
///             Wide::Общая(n) => Some(Narrow(*n)),
///             // «Своя» на узком алфавите не существует — читателю сказать нечего.
///             Wide::Своя => None,
///         }
///     }
/// }
///
/// assert_eq!(Narrow::read(&Wide::Общая(7)), Some(Narrow(7)));
/// assert_eq!(Narrow::read(&Wide::Своя), None);
/// // Тождество — из общей реализации, писать его не нужно.
/// assert_eq!(Wide::read(&Wide::Своя), Some(Wide::Своя));
/// ```
pub trait Reads<Wide>: Sized {
    /// Прочитать своё из широкого. `None` — этой буквы на узком алфавите нет.
    fn read(wide: &Wide) -> Option<Self>;
}

/// Тождество: алфавит читается сам из себя целиком. Общей реализацией: тождественный морфизм есть у
/// каждого объекта, забытая строка выглядела бы как «прибор своему потоку не годится».
impl<A: Clone> Reads<A> for A {
    fn read(wide: &A) -> Option<A> {
        Some(wide.clone())
    }
}
