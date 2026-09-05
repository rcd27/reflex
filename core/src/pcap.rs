//! ЧТЕНИЕ ЗАПИСАННОГО ПРОВОДА — симуляционный источник фреймворка.
//!
//! # Почему это здесь, а не у потребителя (#295, срез 0)
//!
//! Переехал из `nevod2-edge`, где был написан 29.08. Место было неверным: vision называет
//! симуляционный бэкенд поверх записи ВТОРЫМ приоритетом (§3.3), и не по прихоти — **без прогона
//! записанного трафика законы операторов проверить нечем**. Пока чтение записи жило у
//! потребителя, сам фреймворк оставался единственным слоем без воспроизводимого входа: его
//! операторы проверялись на `stream::iter`, то есть на данных, которые сочинил автор теста.
//!
//! Цена этого измерена в тот же день: первый прогон движка на настоящих байтах нашёл ДВА дефекта,
//! невидимых 217 зелёным тестам (#294). Оба рождались взаимодействием двух целей в одном потоке —
//! паузы одной становились уликами против другой, — а в сочинённом входе цель всегда одна.
//!
//! # Зачем файл, а не живой интерфейс
//!
//! До сих пор все прогоны движка начинались с ВЫДУМАННОЙ беды: «положим, пришёл сброс». Целый
//! кусок пути — как настоящий трафик становится событием и рождает беду — не проверялся ничем.
//!
//! Файл даёт то, чего не даёт живой интерфейс: **повторяемость**. Один и тот же провод, поданный
//! дважды, обязан дать один и тот же ответ, и расхождение здесь — находка, а не погода. Живой
//! интерфейс этого не умеет по определению.
//!
//! И второе, ради чего это затевалось: файл снимается ГДЕ УГОДНО. Снятый на коробке, он несёт её
//! вантаж — а прогоняется на dev-машине за секунды. Возражение «замер с dev не про Игоря» этим и
//! снимается: среда его, петля наша.
//!
//! # Формат
//!
//! Классический `pcap` (не `pcapng`): заголовок 24 байта, дальше записи по 16 байт заголовка и
//! тело кадра. Читается вручную — формат стабилен тридцать лет, а зависимость ради сорока строк
//! потянула бы за собой чужую модель ошибок.

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Один снятый кадр.
#[derive(Debug, Clone)]
pub struct Frame {
    /// Для интервалов: отсчитан от начала записи и приложен к основанию вызывающего.
    pub at: Instant,
    /// Для показа человеку: `Instant` в календарь не переводится.
    pub wall: SystemTime,
    pub bytes: Vec<u8>,
}

/// ЧТО НЕ ТАК С ФАЙЛОМ. Причина названа: «файл не прочитан» и «файл прочитан наполовину» —
/// разные беды, и вторая тише.
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

/// Разобрать файл в кадры. Время отсчитывается от первой записи и прикладывается к `base`.
///
/// ОБРЫВ В КОНЦЕ НЕ ОТМЕНЯЕТ ПРОЧИТАННОГО: `tcpdump`, убитый сигналом, оставляет хвост, и
/// выбрасывать из-за него сутки записи значило бы терять данные из-за того, как их перестали
/// снимать. Возвращаются и кадры, и беда — решает вызывающий.
pub fn read(data: &[u8], base: Instant) -> (Vec<Frame>, Option<Broken>) {
    match header(data) {
        Err(broken) => (Vec::new(), Some(broken)),
        Ok(swapped) => records(data, base, swapped),
    }
}

/// Разбор глобального заголовка. Возвращает признак обратного порядка байтов.
fn header(data: &[u8]) -> Result<bool, Broken> {
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
            ETHERNET => Ok(swapped),
            link_type => Err(Broken::UnsupportedLink { link_type }),
        },
    }
}

/// Разбор записей.
///
/// БЕЗ ИЗМЕНЯЕМОГО СОСТОЯНИЯ и без рекурсии: смещения порождаются `successors` — ленивой
/// последовательностью, где следующее вычисляется из предыдущего. Рекурсия здесь была бы хуже
/// цикла (кадров бывают сотни тысяч, стек не резиновый), а `let mut` — хуже обоих: он открывает
/// в разборе место для правки, которой не видно в сигнатуре.
fn records(data: &[u8], base: Instant, swapped: bool) -> (Vec<Frame>, Option<Broken>) {
    let taken: Vec<(u64, &[u8])> = offsets(data, swapped)
        .filter_map(|offset| record_at(data, offset, swapped))
        .collect();

    let first = taken.first().map(|(stamp, _)| *stamp).unwrap_or(0);

    let frames: Vec<Frame> = taken
        .iter()
        .map(|(stamp, bytes)| Frame {
            at: base + Duration::from_micros(stamp.saturating_sub(first)),
            wall: UNIX_EPOCH + Duration::from_micros(*stamp),
            bytes: bytes.to_vec(),
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

/// Штамп и тело записи, если она помещается целиком.
fn record_at(data: &[u8], offset: usize, swapped: bool) -> Option<(u64, &[u8])> {
    let head = data.get(offset..offset + RECORD_HEADER)?;
    let seconds = word(&head[0..4], swapped) as u64;
    let fraction = word(&head[4..8], swapped) as u64;
    let captured = word(&head[8..12], swapped) as usize;
    let body = offset + RECORD_HEADER;

    // Доли секунды считаем микросекундами: наносекундная разновидность встречается редко и даёт
    // лишь более грубый шаг, а порядок событий от этого не меняется.
    data.get(body..body + captured)
        .map(|bytes| (seconds * 1_000_000 + fraction.min(999_999), bytes))
}

/// ОБРЫВ В КОНЦЕ, если он есть. `tcpdump`, убитый сигналом, оставляет хвост — и выбрасывать
/// из-за него всю запись значило бы терять данные из-за того, КАК их перестали снимать.
fn tail_of(data: &[u8], swapped: bool) -> Option<Broken> {
    let after_last = offsets(data, swapped)
        .last()
        .and_then(|offset| captured_at(data, offset, swapped).map(|c| offset + RECORD_HEADER + c))
        .unwrap_or(GLOBAL_HEADER);

    // СРАВНЕНИЕ ЧЕСТНОЕ, А НЕ ЧЕРЕЗ `saturating_sub`: первая редакция вычитала с насыщением, и
    // случай «запись обещала БОЛЬШЕ, чем в файле есть» — то есть ровно обрыв — давал ноль и
    // читался как «кончилось ровно». Поймано тестом на обрезанный хвост.
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

    /// ЗАПИСЬ ПОМНИТ, КОГДА СНЯТА.
    ///
    /// `Instant` монотонный: в календарь он не переводится, и лента по нему не скажет человеку
    /// «18:42:07». Штамп в файле есть — до сих пор он отбрасывался на входе.
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

    /// ВРЕМЯ ОТСЧИТЫВАЕТСЯ ОТ ПЕРВОЙ ЗАПИСИ, а промежутки сохраняются.
    ///
    /// Абсолютный штамп к монотонным часам не привязать, а промежутки — единственное, что для
    /// проигрыша существенно: по ним закрываются окна и считается темп.
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

    /// ЧУЖОЙ ФОРМАТ НАЗЫВАЕТСЯ ЧУЖИМ, а не читается наугад.
    #[test]
    fn a_foreign_file_is_named_not_guessed() {
        match read(b"not a pcap at all, really", Instant::now()) {
            (frames, Some(Broken::NotPcap { .. })) => assert!(frames.is_empty()),
            other => panic!("чужой файл принят за свой: {other:?}"),
        }
    }

    /// НЕ-ETHERNET НЕ РАЗБИРАЕТСЯ: гадать о канальном слое нечем.
    #[test]
    fn a_non_ethernet_capture_is_refused() {
        let mut file = pcap_of(&[]);
        // Подменяем тип канального слоя на Linux SLL.
        file.splice(20..24, 113u32.to_le_bytes());
        assert!(matches!(
            read(&file, Instant::now()),
            (_, Some(Broken::UnsupportedLink { link_type: 113 }))
        ));
    }

    /// ОБРЫВ В КОНЦЕ НЕ ОТМЕНЯЕТ ПРОЧИТАННОГО.
    ///
    /// `tcpdump`, убитый сигналом, оставляет хвост. Выбросить из-за него всю запись значило бы
    /// потерять данные из-за того, КАК их перестали снимать.
    #[test]
    fn a_truncated_tail_does_not_discard_what_was_read() {
        let whole = pcap_of(&[(1, 0, b"first"), (2, 0, b"second")]);
        let cut = &whole[..whole.len() - 3];

        let (frames, broken) = read(cut, Instant::now());
        assert_eq!(frames.len(), 1, "первая запись потеряна из-за хвоста");
        assert!(broken.is_some(), "обрыв не назван");
    }

    /// ПУСТАЯ ЗАПИСЬ — НЕ ПОЛОМКА: `tcpdump`, не увидевший ни кадра, оставляет ровно заголовок.
    #[test]
    fn an_empty_capture_is_not_broken() {
        let (frames, broken) = read(&pcap_of(&[]), Instant::now());
        assert!(frames.is_empty());
        assert_eq!(broken, None);
    }
}

/// ДОСЫПАТЬ ТИКИ В ПАУЗЫ — то, чем записанный провод становится эквивалентен живому.
///
/// # Зачем это в источнике, а не у потребителя
///
/// Живой провод тиков не несёт: молчание есть ОТСУТСТВИЕ событий, а отсутствие событий не
/// порождает элементов потока. Часы добавляет тот, кто читает провод, — и для записи это делать
/// обязан источник, иначе всякий потребитель напишет своё, по-разному.
///
/// # ТОЛЬКО ВНУТРИ ЗАПИСИ, и это оплачено первым же прогоном
///
/// Первая редакция (в продукте) досыпала тики ПОСЛЕ последнего кадра, чтобы закрылись окна, — и
/// получила «молчание 10 000 мс» у живой цели, чьё соединение просто кончилось вместе с файлом.
/// **Конец записи есть НЕИЗВЕСТНОСТЬ, а не тишина**: выводить из него молчание значит обвинять
/// цель в том, что мы перестали смотреть.
///
/// Порядок сохраняется построением: тик встаёт сразу за событием, после которого возник, — и
/// сортировать потом ничего не надо (а сортировка требовала бы изменяемого состояния).
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
        crate::detector::DetectorEvent::Tick { at } => Some(*at),
    }
}

/// ТИКИ СЕТКИ, ПОПАВШИЕ МЕЖДУ ДВУМЯ СОБЫТИЯМИ.
///
/// # Часы идут ОТ НАЧАЛА ЗАПИСИ, а не от предыдущего события
///
/// Прежняя редакция отмеряла тики от паузы: сколько окон уложилось между соседними событиями.
/// На плотном потоке (скачивание — пакеты каждые 30 мс при окне 300 мс) пауз нужной длины нет ни
/// одной, и часы не шли ВОВСЕ. Приборы, чей предмет виден только при идущем трафике — троттлинг,
/// просадка, — молчали на таких записях всегда, и молчание это неотличимо от «беды нет» (#320).
///
/// Сетка отмеряется от первого события записи и не зависит от того, густо ли идут пакеты. Так
/// тикает и поле: `edge-queue` берёт тики от собственных часов, а не от трафика. Прежде запись и
/// поле расходились — то есть поверка и исполнение мерили разное.
///
/// Прежние законы при этом целы: пауза короче окна тиков по-прежнему не рождает (сетка в неё не
/// попадает), а после последнего события ничего не дописывается — конец записи есть
/// неизвестность, а не тишина.
fn on_grid<T>(
    before: Instant,
    after: Instant,
    window: Duration,
    start: Option<Instant>,
) -> Vec<crate::detector::DetectorEvent<T>> {
    // ЗАКОН СЕТКИ ОДИН НА ВСЕ ЧАСЫ (05.09.2026) — [`crate::grid`]. Здесь он был написан впервые,
    // и отсюда же разошёлся по трём другим реализациям; теперь все они зовут одну.
    match start {
        None => Vec::new(),
        Some(start) => crate::grid::nodes_between(start, before, after, window)
            .map(|at| crate::detector::DetectorEvent::Tick { at })
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

    /// ПАУЗА РОЖДАЕТ ТИКИ — иначе детектор тишины не сработает никогда.
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

    /// КОРОТКАЯ ПАУЗА ТИКОВ НЕ РОЖДАЕТ — иначе окна закрывались бы на ровном месте.
    #[test]
    fn a_gap_shorter_than_the_window_yields_nothing() {
        let t0 = Instant::now();
        let got = with_ticks(
            &[packet(t0), packet(t0 + Duration::from_millis(30))],
            Duration::from_millis(100),
        );
        assert_eq!(got.iter().filter(|e| is_tick(e)).count(), 0);
    }

    /// ПЛОТНЫЙ ПОТОК ТОЖЕ ПОЛУЧАЕТ ЧАСЫ — и это главный случай, а не крайний.
    ///
    /// # Чем оплачено (#320, 02.09)
    ///
    /// Прежняя редакция рождала тики ТОЛЬКО в паузах длиннее окна. На записи скачивания
    /// (`lab/instrument/fixtures/sag`, 2004 наблюдения) пауз такой длины нет ни одной — и тиков
    /// выходило НОЛЬ. Приборы со своими часами (троттлинг, просадка) молчали на ней всегда, а
    /// молчание это неотличимо от «беды нет».
    ///
    /// Беда там ровно та, что случается ПРИ ИДУЩЕМ ТРАФИКЕ: цель отдаёт, но втрое меньше
    /// доказанного. То есть приёмка на записях была слепа именно к тому классу бед, ради которого
    /// эти приборы заведены, — и слепа молча.
    ///
    /// В ПОЛЕ такого не было: `edge-queue` берёт тики от настоящих часов (`sleep(TICK)` в своей
    /// ветке) и от трафика не зависит. Расходились ЗАПИСЬ и ПОЛЕ, то есть поверка и исполнение.
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

    /// КОНЕЦ ЗАПИСИ — НЕИЗВЕСТНОСТЬ, А НЕ ТИШИНА.
    ///
    /// Оплачено: первая редакция досыпала тики после последнего кадра, и живая цель, чьё
    /// соединение кончилось вместе с файлом, получала «молчание 10 секунд».
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

    /// ПОРЯДОК СОХРАНЯЕТСЯ: тик стоит ЗА событием, после которого возник.
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
