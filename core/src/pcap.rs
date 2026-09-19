//! Чтение записанного провода — симуляционный источник фреймворка (канон §9). Здесь, а не у
//! носителя: без записанного трафика законы операторов проверять нечем, и фреймворк остаётся слоем
//! без воспроизводимого входа — операторы поверяются на `stream::iter`, данных, сочинённых
//! автором. Цена измерена: первый прогон движка на настоящих байтах нашёл ДВА дефекта, невидимых
//! 217 зелёным тестам — оба рождались взаимодействием двух целей в одном потоке. Файл даёт
//! повторяемость (один провод дважды — один ответ) и снимается где угодно. Формат — классический
//! `pcap`: заголовок 24 байта, записи по 16 байт заголовка и тело; читается вручную (формат
//! стабилен тридцать лет, зависимость ради сорока строк потянула бы чужую модель ошибок).
//!
//! ФОРМАТ, А НЕ НОСИТЕЛЬ. Одноимённая комната фасада (`reflex::pcap`) — про другое: там дверь
//! движка над записью (`pcap("файл")`, `Recording`), здесь байты файла и кадры. Обратная сторона
//! той же ловушки описана у неё в шапке; кто пришёл сюда за носителем, пусть идёт туда, и наоборот.

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Один снятый кадр.
#[derive(Debug, Clone)]
pub struct Frame {
    /// Для интервалов: отсчитан от начала записи и приложен к основанию вызывающего.
    pub at: Instant,
    /// Для показа человеку: `Instant` в календарь не переводится.
    pub wall: SystemTime,
    pub bytes: Vec<u8>,
    /// Каким канальным слоем обёрнут кадр. Хранится У КАДРА, а не выводится читателем: род объявлен
    /// в заголовке файла ровно раз, и всякий, кто выводил бы смещение сам, разошёлся бы с записью
    /// молча — а расходится он в сторону тишины (см. [`Frame::network`]).
    pub link: Link,
    /// Сколько байт было в кадре НА ПРОВОДЕ (`orig_len` записи), не меньше снятого. Больше снятого
    /// бывает, когда писатель урезал тело (см. [`Frame::restored`]).
    pub original: usize,
}

/// Канальный слой записи — те роды, что этот читатель разбирает.
///
/// `Sll`/`Sll2` здесь не ради полноты: `tcpdump -i any` — самый частый способ снять запись, и он
/// пишет НЕ Ethernet. Отказ читать такой файл означал бы, что дверь есть, а войти в неё обычным
/// способом нельзя.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Link {
    /// `LINKTYPE_ETHERNET`: две марки и род, 14 байт, плюс возможные метки VLAN.
    Ethernet,
    /// `LINKTYPE_LINUX_SLL` (113): «cooked» заголовок ядра, 16 байт, род в конце.
    Sll,
    /// `LINKTYPE_LINUX_SLL2` (276): то же второй редакции, 20 байт, род в НАЧАЛЕ.
    Sll2,
    /// `LINKTYPE_RAW` (101): канального слоя нет, первым байтом IP. Так пишет сам движок — очередь
    /// ядра отдаёт ему голый пакет (см. [`opening`]).
    Raw,
}

/// Канальный слой Ethernet: две марки и род содержимого.
const LINK_HEADER: usize = 14;
/// Метка VLAN: род «дальше метка» и сама метка (802.1Q, 802.1ad).
const VLAN_TAG: usize = 4;
const VLAN: [u16; 2] = [0x8100, 0x88a8];

impl Frame {
    /// СЕТЕВОЙ ПАКЕТ ВНУТРИ КАДРА — то, что ест разбор провода: `framed` ждёт первым байтом
    /// IP-заголовок, а `bytes` хранит кадр как он снят, вместе с канальным слоем.
    ///
    /// Снимается ЗДЕСЬ, потому что здесь и только здесь известен род канального слоя: [`read`]
    /// пропускает четыре рода ([`Link`]) с РАЗНЫМИ смещениями, а прочие не доводит до кадров вовсе
    /// ([`Broken::UnsupportedLink`]). Кто снимал бы смещение у себя, выводил бы его заново — и
    /// разошёлся бы молча на первой же записи, снятой не тем родом, на который он рассчитывал.
    ///
    /// Цена ошибки здесь заплачена красным: движок, читающий кадр вместе с канальным слоем, видит
    /// КАЖДУЮ запись как чужой протокол (первый байт MAC-адреса — не `4` в старшей тетраде),
    /// приборы молчат, и молчание читается как «блокировок нет». Пустой отчёт лжёт по построению.
    ///
    /// Метки VLAN снимаются стопкой (QinQ — тоже стопка), обрезанный кадр даёт пустой срез, а не
    /// панику: пустое разбор назовёт обрывом, и это правда о нём.
    pub fn network(&self) -> &[u8] {
        let after = match self.link {
            // Род содержимого лежит на 12-м байте; всякая метка VLAN отодвигает его на свою длину.
            Link::Ethernet => {
                let kind = |at: usize| {
                    self.bytes
                        .get(at..at + 2)
                        .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
                };
                let at = std::iter::successors(Some(LINK_HEADER - 2), |at| match kind(*at) {
                    Some(kind) if VLAN.contains(&kind) => Some(at + VLAN_TAG),
                    _ => None,
                })
                .last()
                .unwrap_or(LINK_HEADER - 2);
                at + 2
            }
            // У «cooked» заголовков длина постоянная, а метки VLAN ядро в них не кладёт: оно уже
            // сняло их, разбирая пакет, и род сети в поле протокола стоит настоящий.
            Link::Sll => SLL_HEADER,
            Link::Sll2 => SLL2_HEADER,
            Link::Raw => 0,
        };

        self.bytes.get(after..).unwrap_or(&[])
    }

    /// СЕТЕВОЙ ПАКЕТ ДЛИНЫ, КОТОРУЮ ОН ИМЕЛ НА ПРОВОДЕ: снятое как есть, недостающий хвост — нулями.
    ///
    /// Нужен затем, что приборы считают байты ДЛИНОЙ ТЕЛА, а не полем IP-заголовка. Писатель движка
    /// оставляет у ответов цели одни заголовки (тело ответа не читает никто, кроме счёта), и без
    /// восстановления такой кадр читался бы пустым подтверждением: троттлинг на записи стал бы
    /// невыразим, а тишина — ложной.
    ///
    /// ЦЕНА НАЗВАНА: длины честные, содержимое хвоста — нет. Прибор, который начнёт читать тело
    /// ответа цели, на урезанной записи увидит нули.
    pub fn restored(&self) -> Vec<u8> {
        let missing = self.original.saturating_sub(self.bytes.len());
        self.network()
            .iter()
            .copied()
            .chain(std::iter::repeat_n(0, missing))
            .collect()
    }
}

/// Что не так с файлом. «Файл не прочитан» и «прочитан наполовину» — разные беды, вторая тише.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Broken {
    TooShort,
    NotPcap {
        magic: u32,
    },
    /// Канальный слой не Ethernet — разбирать нечем, и гадать нельзя.
    UnsupportedLink {
        link_type: u32,
    },
    /// Запись оборвана на середине: столько-то байт обещано, столько-то есть.
    Truncated {
        want: usize,
        have: usize,
    },
}

const GLOBAL_HEADER: usize = 24;
const RECORD_HEADER: usize = 16;
/// `LINKTYPE_ETHERNET`.
const ETHERNET: u32 = 1;
/// `LINKTYPE_LINUX_SLL` — `tcpdump -i any` до второй редакции.
const LINUX_SLL: u32 = 113;
/// `LINKTYPE_LINUX_SLL2` — он же сегодня.
const LINUX_SLL2: u32 = 276;
/// `LINKTYPE_RAW` — голый IP, так пишет сам движок.
const RAW: u32 = 101;
/// Потолок кадра, объявляемый писателем движка: пакет из очереди ядра длиннее не бывает.
const SNAPLEN: u32 = 65_535;
/// Длина «cooked»-заголовка первой редакции: род пакета, род адреса, длина адреса, адрес, протокол.
const SLL_HEADER: usize = 16;
/// Длина второй редакции: протокол, резерв, индекс устройства, род адреса, род пакета, длина, адрес.
const SLL2_HEADER: usize = 20;

/// Время кадра отсчитывается от ПЕРВОЙ записи и прикладывается к `base`: в файле лежит календарь,
/// а приборам нужны промежутки, и основание вправе назначить только читающий.
///
/// Обрыв в конце не отменяет прочитанного: `tcpdump`, убитый сигналом, оставляет хвост, а выбросить
/// из-за него сутки записи значило бы терять данные из-за того, КАК их перестали снимать. Оттого
/// кадры и беда отдаются вместе, а не через `Result`: судит вызывающий.
/// ЧТЕНИЕ ПО КАДРУ — ЗАПИСЬ В ПАМЯТИ ОДИН РАЗ, А НЕ ДВА.
///
/// [`read`] отдаёт все кадры разом, и каждый несёт СВОЮ копию тела: на пике в памяти лежат и файл,
/// и его разобранная копия, то есть около 2× веса записи. Замер 18.09.2026: запись 43,68 МБ давала
/// 90,4 МБ пика на голой цепочке, и это ДО первого разобранного пакета. Гигабайтная запись дала бы
/// два.
///
/// Хуже того, это врало всякому, кто мерил память переигровкой: вес прибора рос линейно с числом
/// кадров — неотличимо от утечки. На этом сгорело два вечерних вывода, наш и потребителя.
///
/// Здесь состояние без заимствования (`data` подаётся на каждый шаг): курсор, а не итератор. Иначе
/// носитель, владеющий байтами и отдающий срезы в них же, стал бы самоссылочным — а он владеет
/// байтами по необходимости (файл читается один раз и живёт весь прогон).
#[derive(Debug, Clone, Copy)]
pub struct Cursor {
    base: Instant,
    first: u64,
    swapped: bool,
    link: Link,
    at: usize,
}

/// Открыть запись под чтение по кадру: разобрать заголовок, найти первый штамп (от него считаются
/// интервалы) и ОСМОТРЕТЬ ХВОСТ. Осмотр здесь, а не при исчерпании, потому что обрыв — свойство
/// записи, и сказать о нём надо тому, кто её открывает; тел он при этом не копирует.
pub fn opened(data: &[u8], base: Instant) -> Result<(Cursor, Option<Broken>), Broken> {
    let (swapped, link) = header(data)?;
    let first = offsets(data, swapped)
        .next()
        .and_then(|offset| record_at(data, offset, swapped))
        .map(|(stamp, _bytes, _original)| stamp);
    // Пустая запись — не ошибка чтения: заголовок цел, кадров нет. Курсор отдаёт `None` с первого
    // же шага, и решает об этом тот, кто открывал, — ему видно, чем такое молчание назвать.
    Ok((
        Cursor {
            base,
            first: first.unwrap_or(0),
            swapped,
            link,
            at: GLOBAL_HEADER,
        },
        tail_of(data, swapped),
    ))
}

impl Cursor {
    /// Следующий кадр записи. Копируется ровно одно тело — то, которое сейчас поедет в разбор.
    pub fn next(&mut self, data: &[u8]) -> Option<Frame> {
        let (stamp, bytes, original) = record_at(data, self.at, self.swapped)?;
        let frame = Frame {
            at: self.base + Duration::from_micros(stamp.saturating_sub(self.first)),
            wall: UNIX_EPOCH + Duration::from_micros(stamp),
            bytes: bytes.to_vec(),
            link: self.link,
            original,
        };
        self.at += RECORD_HEADER + bytes.len();
        Some(frame)
    }
}

pub fn read(data: &[u8], base: Instant) -> (Vec<Frame>, Option<Broken>) {
    match header(data) {
        Err(broken) => (Vec::new(), Some(broken)),
        Ok((swapped, link)) => records(data, base, swapped, link),
    }
}

fn header(data: &[u8]) -> Result<(bool, Link), Broken> {
    let magic = match data.get(..4) {
        None => return Err(Broken::TooShort),
        Some(bytes) => u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
    };

    // Порядок байтов записан самим magic: файл, снятый на машине другой архитектуры, читается тем
    // же кодом. Микросекундная и наносекундная разновидности различаются последней цифрой.
    let swapped = match magic {
        0xa1b2_c3d4 | 0xa1b2_3c4d => false,
        0xd4c3_b2a1 | 0x4d3c_b2a1 => true,
        other => return Err(Broken::NotPcap { magic: other }),
    };

    match data.len() >= GLOBAL_HEADER {
        false => Err(Broken::TooShort),
        true => match word(&data[20..24], swapped) {
            ETHERNET => Ok((swapped, Link::Ethernet)),
            LINUX_SLL => Ok((swapped, Link::Sll)),
            LINUX_SLL2 => Ok((swapped, Link::Sll2)),
            RAW => Ok((swapped, Link::Raw)),
            link_type => Err(Broken::UnsupportedLink { link_type }),
        },
    }
}

/// Разбор записей.
///
/// Без изменяемого состояния и без рекурсии: смещения порождаются `successors` (ленивая
/// последовательность). Рекурсия была бы хуже цикла (кадров сотни тысяч, стек не резиновый), `let
/// mut` — хуже обоих: открывает место для правки, невидимой в сигнатуре.
fn records(data: &[u8], base: Instant, swapped: bool, link: Link) -> (Vec<Frame>, Option<Broken>) {
    let taken: Vec<(u64, &[u8], usize)> = offsets(data, swapped)
        .filter_map(|offset| record_at(data, offset, swapped))
        .collect();

    let first = taken.first().map(|(stamp, _, _)| *stamp).unwrap_or(0);

    let frames: Vec<Frame> = taken
        .iter()
        .map(|(stamp, bytes, original)| Frame {
            at: base + Duration::from_micros(stamp.saturating_sub(first)),
            wall: UNIX_EPOCH + Duration::from_micros(*stamp),
            bytes: bytes.to_vec(),
            link,
            original: *original,
        })
        .collect();

    (frames, tail_of(data, swapped))
}

/// Смещения записей, пока они помещаются в файл.
fn offsets(data: &[u8], swapped: bool) -> impl Iterator<Item = usize> + '_ {
    std::iter::successors(Some(GLOBAL_HEADER), move |offset| {
        let captured = captured_at(data, *offset, swapped)?;
        let next = offset + RECORD_HEADER + captured;
        (next + RECORD_HEADER <= data.len()).then_some(next)
    })
}

/// Сколько байт кадра обещает запись по этому смещению.
fn captured_at(data: &[u8], offset: usize, swapped: bool) -> Option<usize> {
    data.get(offset..offset + RECORD_HEADER)
        .map(|head| word(&head[8..12], swapped) as usize)
}

/// Штамп, тело и длина на проводе, если запись помещается целиком.
fn record_at(data: &[u8], offset: usize, swapped: bool) -> Option<(u64, &[u8], usize)> {
    let head = data.get(offset..offset + RECORD_HEADER)?;
    let seconds = word(&head[0..4], swapped) as u64;
    let fraction = word(&head[4..8], swapped) as u64;
    let captured = word(&head[8..12], swapped) as usize;
    // Не меньше снятого: запись, обещающая на проводе меньше, чем в ней лежит, врёт о себе, и
    // верить здесь можно только байтам.
    let original = (word(&head[12..16], swapped) as usize).max(captured);
    let body = offset + RECORD_HEADER;

    // Доли секунды считаем микросекундами: наносекундная разновидность встречается редко и даёт
    // лишь более грубый шаг, а порядок событий от этого не меняется.
    data.get(body..body + captured)
        .map(|bytes| (seconds * 1_000_000 + fraction.min(999_999), bytes, original))
}

/// Обрыв в конце, если он есть. `tcpdump`, убитый сигналом, оставляет хвост — выбросить из-за него
/// всю запись значило бы терять данные из-за того, КАК их перестали снимать.
fn tail_of(data: &[u8], swapped: bool) -> Option<Broken> {
    let after_last = offsets(data, swapped)
        .last()
        .and_then(|offset| captured_at(data, offset, swapped).map(|c| offset + RECORD_HEADER + c))
        .unwrap_or(GLOBAL_HEADER);

    // Сравнение честное, не через `saturating_sub`: вычитание с насыщением давало на «запись
    // обещала больше, чем в файле» (ровно обрыв) ноль, читавшийся как «кончилось ровно».
    match after_last.cmp(&data.len()) {
        std::cmp::Ordering::Equal => None,
        // Обещано больше, чем есть: запись оборвана на середине.
        std::cmp::Ordering::Greater => Some(Broken::Truncated {
            want: after_last - GLOBAL_HEADER,
            have: data.len() - GLOBAL_HEADER,
        }),
        // Осталось меньше, чем нужно на заголовок следующей записи, — тоже хвост.
        std::cmp::Ordering::Less => Some(Broken::Truncated {
            want: RECORD_HEADER,
            have: data.len() - after_last,
        }),
    }
}

fn word(bytes: &[u8], swapped: bool) -> u32 {
    let raw = [bytes[0], bytes[1], bytes[2], bytes[3]];
    match swapped {
        true => u32::from_be_bytes(raw),
        false => u32::from_le_bytes(raw),
    }
}

/// ЗАГОЛОВОК ЗАПИСИ ДВИЖКА: классический `pcap`, микросекунды, канальный слой `LINKTYPE_RAW`.
///
/// Писатель живёт рядом с читателем, а не у потребителя: формат, записанный одной рукой и
/// прочитанный другой, расходится молча, а здесь их сверяет один тест. Чистые функции без IO —
/// куда класть байты, решает носитель.
pub fn opening() -> Vec<u8> {
    0xa1b2_c3d4u32
        .to_le_bytes()
        .into_iter()
        .chain(2u16.to_le_bytes())
        .chain(4u16.to_le_bytes())
        .chain([0; 8])
        .chain(SNAPLEN.to_le_bytes())
        .chain(RAW.to_le_bytes())
        .collect()
}

/// ОДНА ЗАПИСЬ. `original` меньше снятого не пишется — длина на проводе не бывает короче того, что
/// с провода сняли.
///
/// Момент раньше эпохи (часы машины без RTC до NTP) пишется нулём, а не паникой: запись с неверным
/// календарём всё ещё несёт верные ПРОМЕЖУТКИ, а по ним и работают приборы.
pub fn entry(wall: SystemTime, kept: &[u8], original: usize) -> Vec<u8> {
    let since = wall.duration_since(UNIX_EPOCH).unwrap_or(Duration::ZERO);
    let seconds = u32::try_from(since.as_secs()).unwrap_or(u32::MAX);
    let captured = u32::try_from(kept.len()).unwrap_or(u32::MAX);
    let on_wire = u32::try_from(original.max(kept.len())).unwrap_or(u32::MAX);
    seconds
        .to_le_bytes()
        .into_iter()
        .chain(since.subsec_micros().to_le_bytes())
        .chain(captured.to_le_bytes())
        .chain(on_wire.to_le_bytes())
        .chain(kept.iter().copied())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Собрать файл из записей `(секунды, микросекунды, тело)`.
    fn pcap_of(records: &[(u32, u32, &[u8])]) -> Vec<u8> {
        let header: Vec<u8> = [0xd4u32, 0xc3, 0xb2, 0xa1]
            .iter()
            .map(|b| *b as u8)
            .collect::<Vec<u8>>();
        // magic (LE), версия 2.4, зона 0, точность 0, snaplen, канальный слой Ethernet.
        let head: Vec<u8> = header
            .into_iter()
            .chain([2, 0, 4, 0])
            .chain([0; 8])
            .chain(65535u32.to_le_bytes())
            .chain(1u32.to_le_bytes())
            .collect();

        records.iter().fold(head, |acc, (secs, micros, body)| {
            acc.into_iter()
                .chain(secs.to_le_bytes())
                .chain(micros.to_le_bytes())
                .chain((body.len() as u32).to_le_bytes())
                .chain((body.len() as u32).to_le_bytes())
                .chain(body.iter().copied())
                .collect()
        })
    }

    /// Собрать Ethernet-кадр вокруг сетевого пакета.
    fn framed(ethertype: u16, tags: &[u16], packet: &[u8]) -> Vec<u8> {
        let head: Vec<u8> = [0xff; 12].into_iter().collect();
        let tagged: Vec<u8> = tags.iter().fold(head, |acc, tag| {
            acc.into_iter()
                .chain(0x8100u16.to_be_bytes())
                .chain(tag.to_be_bytes())
                .collect()
        });
        tagged
            .into_iter()
            .chain(ethertype.to_be_bytes())
            .chain(packet.iter().copied())
            .collect()
    }

    /// ПРЕДМЕТ: разбор провода ждёт первым байтом IP-заголовок, а запись хранит кадр с канальным
    /// слоем. Некому снять канальный слой — и движок читает КАЖДЫЙ кадр записи как чужой протокол,
    /// а молчание приборов означает не «блокировок нет», а «не разобрано ничего».
    #[test]
    fn a_frame_offers_the_network_packet_without_the_link_layer() {
        let packet = b"\x45\x00\x00\x28ip";
        let (frames, _broken) = read(
            &pcap_of(&[(1, 0, &framed(0x0800, &[], packet))]),
            Instant::now(),
        );

        assert_eq!(
            frames.first().map(|frame| frame.network()),
            Some(&packet[..]),
            "сетевой пакет обязан начинаться с IP-заголовка"
        );
    }

    /// VLAN снимается тоже — и стопкой: запись с магистрального порта иначе выглядела бы чужой
    /// целиком, а «чужое на каждом кадре» неотличимо от «сеть чиста».
    #[test]
    fn vlan_tags_are_not_mistaken_for_the_network_packet() {
        let packet = b"\x45\x00\x00\x28ip";
        let (frames, _broken) = read(
            &pcap_of(&[(1, 0, &framed(0x0800, &[100, 200], packet))]),
            Instant::now(),
        );

        assert_eq!(
            frames.first().map(|frame| frame.network()),
            Some(&packet[..]),
            "две метки VLAN — всё ещё канальный слой, а не пакет"
        );
    }

    /// Кадр короче канального слоя не даёт сетевого пакета — и не паникует: обрыв записи назван
    /// пустотой, которую разбор провода прочитает как `Truncated`, а не как чужой протокол.
    #[test]
    fn a_frame_shorter_than_the_link_layer_offers_nothing() {
        let (frames, _broken) = read(&pcap_of(&[(1, 0, b"\xff\xff\xff")]), Instant::now());

        assert_eq!(frames.first().map(|frame| frame.network()), Some(&[][..]));
    }

    /// Запись помнит, когда снята. `Instant` монотонный, в календарь не переводится (лента не
    /// скажет «18:42:07»); штамп в файле есть, до сих пор отбрасывался на входе.
    #[test]
    fn a_frame_keeps_the_calendar_moment_it_was_captured_at() {
        let (frames, _broken) = read(
            &pcap_of(&[(1_756_000_000, 250_000, b"aaa")]),
            Instant::now(),
        );

        assert_eq!(
            frames.first().map(|frame| frame.wall),
            Some(std::time::UNIX_EPOCH + Duration::from_micros(1_756_000_000_250_000))
        );
    }

    /// Время отсчитывается от первой записи, промежутки сохраняются: абсолютный штамп к монотонным
    /// часам не привязать, а по промежуткам закрываются окна и считается темп.
    #[test]
    fn gaps_between_frames_survive_the_reading() {
        let base = Instant::now();
        let (frames, broken) = read(
            &pcap_of(&[(100, 0, b"aaa"), (100, 250_000, b"bb"), (101, 0, b"c")]),
            base,
        );

        assert_eq!(broken, None);
        assert_eq!(frames.len(), 3);
        assert_eq!(frames[0].at, base);
        assert_eq!(frames[1].at, base + Duration::from_millis(250));
        assert_eq!(frames[2].at, base + Duration::from_secs(1));
    }

    /// Чужой формат называется чужим, а не читается наугад.
    #[test]
    fn a_foreign_file_is_named_not_guessed() {
        match read(b"not a pcap at all, really", Instant::now()) {
            (frames, Some(Broken::NotPcap { .. })) => assert!(frames.is_empty()),
            other => panic!("чужой файл принят за свой: {other:?}"),
        }
    }

    /// Незнакомый канальный слой не разбирается, и отказ НАЗЫВАЕТ его номером: гадать о смещении
    /// нечем, а промолчать значило бы объявить весь файл чужим протоколом. Род взят настоящий
    /// (`LINKTYPE_IEEE802_11`, 105) — тот, что этот читатель и правда не умеет.
    #[test]
    fn an_unknown_link_layer_is_refused_by_name() {
        let mut file = pcap_of(&[]);
        file.splice(20..24, 105u32.to_le_bytes());
        assert!(matches!(
            read(&file, Instant::now()),
            (_, Some(Broken::UnsupportedLink { link_type: 105 }))
        ));
    }

    /// `tcpdump -i any` пишет «cooked»-заголовок, а не Ethernet — и это САМЫЙ ЧАСТЫЙ способ снять
    /// запись. Обе редакции дают тот же сетевой пакет, что Ethernet: длина заголовка другая, поле
    /// рода стоит в другом месте, а предмет один.
    #[test]
    fn cooked_captures_offer_the_same_network_packet() {
        let packet = b"\x45\x00\x00\x28ip";

        // SLL: 16 байт, род в конце (14..16).
        let sll: Vec<u8> = [0u8; 14]
            .into_iter()
            .chain(0x0800u16.to_be_bytes())
            .chain(packet.iter().copied())
            .collect();
        let mut file = pcap_of(&[(1, 0, &sll)]);
        file.splice(20..24, 113u32.to_le_bytes());
        let (frames, _broken) = read(&file, Instant::now());
        assert_eq!(
            frames.first().map(|frame| frame.network()),
            Some(&packet[..]),
            "SLL: сетевой пакет начинается после шестнадцати байт"
        );

        // SLL2: 20 байт, род в НАЧАЛЕ (0..2).
        let sll2: Vec<u8> = 0x0800u16
            .to_be_bytes()
            .into_iter()
            .chain([0u8; 18])
            .chain(packet.iter().copied())
            .collect();
        let mut file = pcap_of(&[(1, 0, &sll2)]);
        file.splice(20..24, 276u32.to_le_bytes());
        let (frames, _broken) = read(&file, Instant::now());
        assert_eq!(
            frames.first().map(|frame| frame.network()),
            Some(&packet[..]),
            "SLL2: сетевой пакет начинается после двадцати байт"
        );
    }

    /// Обрыв в конце не отменяет прочитанного: `tcpdump`, убитый сигналом, оставляет хвост.
    #[test]
    fn a_truncated_tail_does_not_discard_what_was_read() {
        let whole = pcap_of(&[(1, 0, b"first"), (2, 0, b"second")]);
        let cut = &whole[..whole.len() - 3];

        let (frames, broken) = read(cut, Instant::now());
        assert_eq!(frames.len(), 1, "первая запись потеряна из-за хвоста");
        assert!(broken.is_some(), "обрыв не назван");
    }

    /// Пустая запись — не поломка: `tcpdump`, не увидевший ни кадра, оставляет ровно заголовок.
    #[test]
    fn an_empty_capture_is_not_broken() {
        let (frames, broken) = read(&pcap_of(&[]), Instant::now());
        assert!(frames.is_empty());
        assert_eq!(broken, None);
    }

    /// ПРЕДМЕТ: запись, которую пишет сам движок, читается обратно ТЕМИ ЖЕ пакетами. Очередь ядра
    /// отдаёт голый IP, и канальный слой у такой записи `LINKTYPE_RAW`: приписать ей Ethernet
    /// значило бы записать то, чего движок не видел.
    #[test]
    fn the_engines_own_recording_reads_back_as_the_same_packets() {
        let packet = b"\x45\x00\x00\x28ip-packet".to_vec();
        let wall = UNIX_EPOCH + Duration::from_micros(1_756_000_000_250_000);
        let file: Vec<u8> = opening()
            .into_iter()
            .chain(entry(wall, &packet, packet.len()))
            .collect();

        let (frames, broken) = read(&file, Instant::now());

        assert_eq!(broken, None);
        assert_eq!(
            frames.first().map(|frame| frame.network().to_vec()),
            Some(packet)
        );
        assert_eq!(frames.first().map(|frame| frame.wall), Some(wall));
    }

    /// ПРЕДМЕТ: урезанный кадр помнит, СКОЛЬКО В НЁМ БЫЛО. Приборы считают байты длиной тела, и
    /// кадр, у которого от тела остались одни заголовки, без восстановления читался бы как пустое
    /// подтверждение — троттлинг на такой записи стал бы невыразим.
    #[test]
    fn a_cut_frame_is_restored_to_its_declared_length() {
        let headers = b"\x45\x00\x05\xdcheaders".to_vec();
        let file: Vec<u8> = opening()
            .into_iter()
            .chain(entry(UNIX_EPOCH, &headers, 1500))
            .collect();

        let (frames, _broken) = read(&file, Instant::now());
        let restored = frames.first().map(Frame::restored);

        assert_eq!(restored.as_ref().map(Vec::len), Some(1500));
        assert_eq!(
            restored.map(|bytes| bytes.starts_with(&headers)),
            Some(true),
            "восстановление обязано дорастить хвост, не трогая снятого"
        );
    }

    /// Целый кадр восстанавливается в себя: доращивать нечего, и чужая запись не меняется ни байтом.
    #[test]
    fn a_whole_frame_is_restored_as_it_is() {
        let packet = b"\x45\x00\x00\x28ip";
        let (frames, _broken) = read(
            &pcap_of(&[(1, 0, &framed(0x0800, &[], packet))]),
            Instant::now(),
        );

        assert_eq!(frames.first().map(Frame::restored), Some(packet.to_vec()));
    }
}

/// Досыпать тики в паузы — то, чем записанный провод становится эквивалентен живому. Живой провод
/// тиков не несёт (молчание есть ОТСУТСТВИЕ событий); часы добавляет читающий провод, и для записи
/// это обязан источник, иначе всякий потребитель напишет своё. Только ВНУТРИ записи: досыпка после
/// последнего кадра дала бы «молчание 10 000 мс» у цели, чьё соединение кончилось вместе с файлом —
/// конец записи есть НЕИЗВЕСТНОСТЬ, не тишина. Порядок сохраняется построением: тик встаёт сразу за
/// событием, после которого возник.
pub fn with_ticks<T: Clone>(
    events: &[crate::detector::DetectorEvent<T>],
    window: Duration,
) -> Vec<crate::detector::DetectorEvent<T>> {
    let start = events.first().and_then(moment);
    events
        .windows(2)
        .flat_map(|pair| {
            let tail = match (moment(&pair[0]), moment(&pair[1])) {
                (Some(before), Some(after)) => on_grid(before, after, window, start),
                (_, _) => Vec::new(),
            };
            std::iter::once(pair[0].clone()).chain(tail)
        })
        .chain(events.last().cloned())
        .collect()
}

/// Момент события, каким бы оно ни было.
fn moment<T>(event: &crate::detector::DetectorEvent<T>) -> Option<Instant> {
    match event {
        crate::detector::DetectorEvent::Packet { at, .. } => Some(*at),
        crate::detector::DetectorEvent::Tick { at, .. } => Some(*at),
        // Провод виден целиком: непонятый кадр занял место в записи и раздвигает сетку тиков так
        // же, как понятый, — иначе плотный поток из одних Opaque читался бы как тишина.
        crate::detector::DetectorEvent::Opaque { at, .. } => Some(*at),
        // Дыра — тоже место на ленте, не пустота: тот же довод, что у Opaque, иначе плотный поток
        // дыр читался бы как тишина ровно там, где сетка обязана продолжать идти.
        crate::detector::DetectorEvent::Torn { at } => Some(*at),
    }
}

/// Тики сетки, попавшие между двумя событиями. Часы идут ОТ НАЧАЛА записи, не от предыдущего
/// события: отмеряй тики от паузы — на плотном потоке (пакеты каждые 30 мс при окне 300 мс) пауз
/// нужной длины нет, часы не шли бы вовсе, и приборы троттлинга/просадки молчали бы всегда. Так
/// тикает и поле (`edge-queue` берёт тики от своих часов). Прочие законы сетки целы: пауза короче
/// окна тиков не рождает, после последнего события ничего не дописывается.
fn on_grid<T>(
    before: Instant,
    after: Instant,
    window: Duration,
    start: Option<Instant>,
) -> Vec<crate::detector::DetectorEvent<T>> {
    // Закон сетки один на все часы — [`crate::grid`]. Своего счёта узлов нет: сетка, посчитанная
    // дважды, есть две сетки, расходящиеся молча.
    match start {
        None => Vec::new(),
        Some(start) => crate::grid::nodes_between(start, before, after, window)
            .map(|at| crate::detector::DetectorEvent::Tick {
                node: crate::grid::due(start, at, window),
                at,
            })
            .collect(),
    }
}

#[cfg(test)]
mod tick_tests {
    use super::*;
    use crate::detector::DetectorEvent;

    fn packet(at: Instant) -> DetectorEvent<u8> {
        DetectorEvent::Packet { input: 1, at }
    }

    fn is_tick(e: &DetectorEvent<u8>) -> bool {
        matches!(e, DetectorEvent::Tick { .. })
    }

    /// Пауза рождает тики — иначе детектор тишины не сработает никогда.
    #[test]
    fn a_gap_becomes_ticks() {
        let t0 = Instant::now();
        let window = Duration::from_millis(100);
        let got = with_ticks(
            &[packet(t0), packet(t0 + Duration::from_millis(350))],
            window,
        );
        assert_eq!(got.iter().filter(|e| is_tick(e)).count(), 3);
    }

    /// Короткая пауза тиков не рождает — иначе окна закрывались бы на ровном месте.
    #[test]
    fn a_gap_shorter_than_the_window_yields_nothing() {
        let t0 = Instant::now();
        let got = with_ticks(
            &[packet(t0), packet(t0 + Duration::from_millis(30))],
            Duration::from_millis(100),
        );
        assert_eq!(got.iter().filter(|e| is_tick(e)).count(), 0);
    }

    /// Плотный поток тоже получает часы — главный случай, не крайний. Часы, идущие только в
    /// паузах длиннее окна, на записи скачивания (2004 наблюдения) дают НОЛЬ тиков: пауз такой
    /// длины там нет. Приборы троттлинга/просадки молчат всегда, и приёмка слепа к тому самому
    /// классу бед (цель отдаёт втрое меньше доказанного), ради которого они заведены — а поле
    /// (`edge-queue` берёт тики от своих часов) с записью при этом расходится.
    #[test]
    fn a_busy_stream_still_gets_its_clock() {
        let t0 = Instant::now();
        let window = Duration::from_millis(100);
        // Десять пакетов по 30 мс — три секунды плотного потока без единой паузы в окно.
        let dense: Vec<_> = (0..100)
            .map(|n| packet(t0 + Duration::from_millis(30 * n)))
            .collect();

        let got = with_ticks(&dense, window);

        let ticks = got.iter().filter(|e| is_tick(e)).count();
        assert!(
            ticks >= 28,
            "на трёх секундах плотного потока часы обязаны тикнуть около тридцати раз, а тикнули {ticks}"
        );
    }

    /// Конец записи — неизвестность, не тишина: досыпка после последнего кадра давала «молчание 10
    /// секунд» живой цели, чьё соединение кончилось вместе с файлом.
    #[test]
    fn the_end_of_the_recording_yields_no_silence() {
        let t0 = Instant::now();
        let got = with_ticks(&[packet(t0)], Duration::from_millis(1));
        assert_eq!(
            got.len(),
            1,
            "после последнего кадра дописано лишнее: {got:?}"
        );
    }

    /// Номер узла — тот же, что называет [`crate::grid::due`], а не порядковый счёт тиков.
    #[test]
    fn tick_node_numbers_match_the_one_law_of_the_grid() {
        let t0 = Instant::now();
        let window = Duration::from_millis(100);
        let got = with_ticks(
            &[packet(t0), packet(t0 + Duration::from_millis(350))],
            window,
        );

        let nodes: Vec<u64> = got
            .iter()
            .filter_map(|e| match e {
                DetectorEvent::Tick { node, .. } => Some(*node),
                DetectorEvent::Packet { .. }
                | DetectorEvent::Opaque { .. }
                | DetectorEvent::Torn { .. } => None,
            })
            .collect();

        assert_eq!(nodes, vec![1, 2, 3]);
    }

    /// Порядок сохраняется: тик стоит ЗА событием, после которого возник.
    #[test]
    fn ticks_follow_the_event_they_came_after() {
        let t0 = Instant::now();
        let window = Duration::from_millis(100);
        let got = with_ticks(
            &[packet(t0), packet(t0 + Duration::from_millis(250))],
            window,
        );
        assert!(matches!(got.first(), Some(DetectorEvent::Packet { .. })));
        assert!(matches!(got.last(), Some(DetectorEvent::Packet { .. })));
        assert!(
            got.windows(2)
                .all(|p| moment(&p[0]).unwrap() <= moment(&p[1]).unwrap()),
            "тики встали не по времени"
        );
    }
}
