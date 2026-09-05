//! СЕРТИФИКАЦИЯ КАЛИТКИ НА ЖИВОМ ЯДРЕ — вердикт в коде, свидетель независим.
//!
//! # Как устроено свидетельство
//!
//! Подопытный вводит кадр с НОНСОМ. Наблюдает не он и не мы: рядом работает `tshark`, пишущий
//! `pcap` в общий том. Бинарь читает эту запись через [`reflex_core::pcap`] и считает закон
//! [`reflex_core::certify::injects`].
//!
//! Независимость свидетеля здесь по КОДУ: libpcap — чужая реализация, и «мы отправили» больше не
//! доказывается тем же кодом, что отправлял. Названная цена: на Linux libpcap работает через тот
//! же `PF_PACKET`, что и `AfPacketBackend`, — то есть дефект самого механизма ядра оба увидят
//! одинаково. Второй прибор ИНОЙ природы (счётчики `/proc/net/dev`) — следующий срез.
//!
//! # Почему бинарь, а не bash
//!
//! Прежний стенд (`tests/e2e/run-e2e.sh`) держал вердикт в оболочке: `run_test "name" bash -c '…'`
//! судил по коду возврата. Наблюдение шло в контейнере, а утверждение — на хосте, и связь между
//! ними была честным словом. Здесь утверждение стоит рядом с наблюдением и говорит, ЧТО именно
//! проверено.

use std::time::{Duration, Instant};

use futures::StreamExt;
use reflex_core::certify::holding::{self, holds, Downstream};
use reflex_core::certify::injection::{self, FarEnd};
use reflex_core::certify::observation::{self, observes, watching, Origin};
use reflex_core::certify::{carries, injects, Verdict};
use reflex_core::command::InjectablePacket;
use reflex_core::held::{Held, Observed, Terminal};
use reflex_linux::nfqueue::{Answer, NfqueueBackend, Queued, Waited};
use reflex_linux::AfPacketBackend;

/// СОБСТВЕННЫЙ ETHERTYPE ИЗ ЭКСПЕРИМЕНТАЛЬНОГО ДИАПАЗОНА.
///
/// `0x88B5` отведён IEEE под опытное использование. Чужой стек его не разбирает и не отвечает на
/// него — значит кадр не заденет ничей трафик и не будет ни съеден, ни переписан по дороге.
const OUR_ETHERTYPE: [u8; 2] = [0x88, 0xB5];

/// Широковещательный адресат: кадр обязан дойти до всякого, кто слушает сегмент.
const BROADCAST: [u8; 6] = [0xFF; 6];

/// ИСТОЧНИК — ЛОКАЛЬНО АДМИНИСТРИРУЕМЫЙ АДРЕС, А НЕ ШИРОКОВЕЩАТЕЛЬНЫЙ.
///
/// Первая редакция ставила источником `FF:FF:FF:FF:FF:FF`, и кадр не доходил НИКУДА: мост законно
/// роняет кадр, чей отправитель широковещателен, — такого отправителя не бывает. Найдено первым
/// живым прогоном, и найти это на памятном мире было нельзя в принципе: там нет моста.
///
/// Бит `0x02` в первом байте означает «адрес назначен локально» — по стандарту он не может
/// совпасть ни с одним заводским, то есть чужой машины мы не изображаем.
const OUR_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x0C, 0xE7, 0x01];

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let code = match args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        [_, "inject", iface, capture, nonce] => announce(
            "injects",
            "AfPacketBackend",
            certify_injects(iface, capture, nonce.as_bytes()),
        ),
        [_, "observe", iface, nonce, report, window] => announce(
            "observes",
            "AfPacketBackend",
            certify_observes(iface, nonce.as_bytes(), report, window),
        ),
        // РОЛЬ МИРА, А НЕ ЗАКОН. Отправитель ничего не утверждает о подопытном — он порождает
        // трафик и оставляет отчёт о том, сколько ушло. Вердикт выносит тот, кого проверяют.
        [_, "hold", queue, capture, nonce, target] => announce(
            "holds",
            "NfqueueBackend",
            certify_holds(queue, capture, nonce.as_bytes(), target),
        ),
        // ТОЛЬКО ПОСЛАТЬ, НИЧЕГО НЕ УТВЕРЖДАЯ. Нужна, чтобы спросить мир без подопытного: если
        // датаграмма уходит, когда очередь НИКТО не слушает, — значит удержание мнимо, и все
        // вердикты закона были бы о другом.
        [_, "probe", target, nonce] => match probe(target, nonce.as_bytes()) {
            Err(why) => {
                eprintln!("проба не ушла: {why}");
                2
            }
            Ok(()) => {
                println!(r#"{{"role":"probe","sent":"{nonce}","to":"{target}"}}"#);
                0
            }
        },
        [_, "emit", iface, nonce, count, report] => {
            emit_world(iface, nonce.as_bytes(), count, report)
        }
        other => {
            eprintln!("не понято: {other:?}");
            eprintln!("употребление:");
            eprintln!("  certify inject  <интерфейс> <путь-к-записи> <нонс>");
            eprintln!("  certify observe <интерфейс> <нонс> <путь-к-отчёту> <окно-мс>");
            eprintln!("  certify emit    <интерфейс> <нонс> <сколько> <путь-к-отчёту>");
            eprintln!("  certify hold    <номер-очереди> <путь-к-записи> <нонс> <хост:порт>");
            eprintln!("  certify probe   <хост:порт> <нонс>");
            2
        }
    };
    std::process::exit(code);
}

/// ВЕРДИКТ ОДНОЙ ФОРМОЙ ДЛЯ ВСЕХ ЗАКОНОВ И ВСЕХ БЭКЕНДОВ.
///
/// ИМЯ БЭКЕНДА — ПАРАМЕТР, А НЕ КОНСТАНТА В СТРОКЕ. Первая редакция печатала `AfPacketBackend`
/// всегда, и первый же живой прогон закона удержания выдал отчёт, приписывающий очередь ядра
/// чужому бэкенду. Тот самый класс, ради которого весь этот модуль и заведён: свидетельство
/// утверждало не то, что установлено, и снаружи это было не видно.
///
/// Печать вынесена сюда, а не переписана под каждый закон, ровно потому, что `Verdict` обобщён:
/// причины у законов свои, а три состояния — общие. Читателю отчёта (человеку или скрипту) не
/// придётся знать, какой закон он читает, чтобы понять, был ли вердикт вообще.
fn announce<B: std::fmt::Debug, I: std::fmt::Debug>(
    law: &str,
    backend: &str,
    outcome: Result<Verdict<B, I>, String>,
) -> i32 {
    match outcome {
        // Беда устройства, до закона дело не дошло. Тот же код, что у `Invalid`: вердикта нет ни
        // там, ни здесь, и разница — в том, кто это установил.
        Err(why) => {
            println!(
                r#"{{"law":"{law}","backend":"{backend}","verdict":"invalid","why":"{why}"}}"#
            );
            2
        }
        Ok(Verdict::Held) => {
            println!(r#"{{"law":"{law}","backend":"{backend}","verdict":"held"}}"#);
            0
        }
        Ok(Verdict::Broken(because)) => {
            println!(
                r#"{{"law":"{law}","backend":"{backend}","verdict":"broken","because":"{because:?}"}}"#
            );
            1
        }
        // ВЕРДИКТА НЕТ, И ЭТО ГОВОРИТ САМ ЗАКОН. Прежде недействительность вычислялась в
        // устройстве, вторым чтением записи; закон её не знал, и всякий следующий закон изобретал
        // бы её заново по-своему.
        Ok(Verdict::Invalid(why)) => {
            println!(
                r#"{{"law":"{law}","backend":"{backend}","verdict":"invalid","why":"{why:?}"}}"#
            );
            2
        }
    }
}

/// ЗАКОН ИНЪЕКЦИИ НА ЖИВОМ ЯДРЕ.
///
/// ПРОГОН, В КОТОРОМ ПРИБОР МОЛЧАЛ, НЕДЕЙСТВИТЕЛЕН, А НЕ ЧИСТ. Отличать «свидетель не работал» от
/// «подопытный солгал» — половина смысла всей затеи, и держат это различие двое: маяк доказывает,
/// что прибор жив, а [`Verdict::Invalid`] называет случай, когда он всё-таки нем.
fn certify_injects(
    iface: &str,
    capture: &str,
    nonce: &[u8],
) -> Result<Verdict<injection::Broken, injection::Invalid>, String> {
    let mut dut = AfPacketBackend::open(iface, 65535)?;
    let frame = frame_with(nonce);
    let mut far_end = Recording {
        path: capture,
        awaited: nonce.to_vec(),
        trouble: None,
    };

    beacon()?;
    let outcome = injects(&mut dut, InjectablePacket::Raw(frame), &mut far_end);

    // ТОЧНАЯ ПРИЧИНА СИЛЬНЕЕ ОБЩЕЙ. Закон видит лишь «кадров ноль» и говорит `WitnessSilent`;
    // устройство знает, БЫЛА ЛИ при этом беда чтения, и подставляет её вместо общего слова.
    match far_end.trouble {
        Some(why) => Err(why),
        None => Ok(outcome),
    }
}

/// МАЯК: КАДР, ПОСТРОЕННЫЙ ЯДРОМ, А НЕ ПОДОПЫТНЫМ.
///
/// # Зачем он понадобился
///
/// Свидетель ловит по фильтру, сужающему видимое до нашего опытного ethertype, — иначе он считал
/// бы чужой трафик за наш. Но у сужения есть цена, и она вскрылась ровно тогда, когда закон
/// научился называть недействительность: при ЛЖИВОМ бэкенде запись пуста, и «прибор мёртв» снова
/// неотличимо от «подопытный солгал». Первый живой прогон обезоруживания этого не показал только
/// потому, что в томе лежал кадр ПРЕДЫДУЩЕГО, удачного прогона: действительность держалась на
/// остатке, а не на наблюдении.
///
/// # Почему именно широковещательная датаграмма
///
/// Заголовки ей строит ЯДРО: наш код лишь просит сокет, а кадр на провод кладёт чужой механизм.
/// Пошли маяк тот же `AfPacketBackend` — при лживом бэкенде не ушло бы и маяка, всякое нарушение
/// стало бы недействительностью, и проверка сама себя ослепила бы.
///
/// Порт 9 — `discard` по RFC 863: у него по определению нет слушателя, которому мы помешаем.
fn beacon() -> Result<(), String> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").map_err(|why| format!("маяк: {why}"))?;
    socket
        .set_broadcast(true)
        .map_err(|why| format!("маяк: {why}"))?;
    socket
        .send_to(b"certify-beacon", "255.255.255.255:9")
        .map_err(|why| format!("маяк: {why}"))
        .map(|_sent| ())
}

/// ЗАПИСЬ СВИДЕТЕЛЯ КАК ДАЛЬНИЙ КОНЕЦ.
///
/// Тип, а не замыкание, ровно ради поля `trouble`: беда чтения возникает ВНУТРИ ответа дальнего
/// конца, а вернуть он обязан кадры. Прежняя редакция беду там же и роняла (`Err(_why) =>
/// Vec::new()`), после чего читала запись ВТОРОЙ раз — и второе чтение могло дать другое, потому
/// что `dumpcap` дописывает файл всё это время.
struct Recording<'a> {
    path: &'a str,
    /// ЧЕГО ЖДЁМ — критерий ОЖИДАНИЯ, а не суждения.
    ///
    /// Дальний конец знает искомое, но не решает: он возвращает ВСЁ прочитанное, чем бы ожидание
    /// ни кончилось, а вердикт по этим кадрам выносит закон. Знай он только «дождаться хоть
    /// чего-нибудь» — маяк, приходящий первым, завершал бы ожидание раньше предмета; ровно это и
    /// произошло на первом же прогоне с маяком, и честный бэкенд был объявлен нарушителем.
    awaited: Vec<u8>,
    trouble: Option<String>,
}

impl FarEnd for Recording<'_> {
    fn arrived(&mut self) -> Vec<Vec<u8>> {
        match read_capture(self.path, &self.awaited) {
            Err(why) => {
                self.trouble = Some(why);
                Vec::new()
            }
            Ok(frames) => frames,
        }
    }
}

/// КАДР С НОНСОМ. Заголовок собирается руками: подопытный обязан получить ровно те байты, что мы
/// потом ищем, — иначе искали бы чужую работу.
fn frame_with(nonce: &[u8]) -> Vec<u8> {
    BROADCAST
        .iter()
        .chain(OUR_MAC.iter())
        .chain(OUR_ETHERTYPE.iter())
        .copied()
        .chain(nonce.iter().copied())
        .collect()
}

/// ЧТО УВИДЕЛ СВИДЕТЕЛЬ. Читается через разбор записи, а не через наш захват: прибор обязан быть
/// устроен иначе, чем подопытный.
///
/// ЖДЁМ ЗАПИСЬ, А НЕ ЧИТАЕМ СРАЗУ: `tshark` пишет буферами, и кадр появляется в файле не в тот же
/// миг. Ожидание с потолком, а не сон наугад.
///
/// # Ждём ПРЕДМЕТ, а не «хоть что-нибудь»
///
/// Первая редакция ждала появления ЛЮБОГО кадра, и это было верно ровно до тех пор, пока в записи
/// не мог оказаться никто, кроме подопытного. С приходом маяка условие рассыпалось: маяк доезжает
/// первым, ожидание завершалось на нём, наш кадр ещё не был записан — и честный бэкенд получил
/// `broken` на живом прогоне. Условие ожидания перестало быть про предмет в тот самый момент,
/// когда в записи появился кто-то ещё.
///
/// Потолок отдаёт ВСЁ прочитанное, а не пустоту: судит закон, и отнимать у него улики — значит
/// подменять «нашего нет» на «прибор молчал».
fn read_capture(path: &str, awaited: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match std::fs::read(path) {
            Err(why) if Instant::now() >= deadline => {
                return Err(format!("запись свидетеля не прочитана: {why}"))
            }
            Err(_not_yet) => std::thread::sleep(Duration::from_millis(100)),
            Ok(bytes) => {
                let (frames, broken) = reflex_core::pcap::read(&bytes, Instant::now());
                let seen: Vec<Vec<u8>> = frames.into_iter().map(|frame| frame.bytes).collect();
                let found = seen.iter().any(|frame| carries(frame, awaited));
                match (found, Instant::now() >= deadline) {
                    (true, _) => return Ok(seen),
                    (false, false) => std::thread::sleep(Duration::from_millis(100)),
                    (false, true) => match broken {
                        None => return Ok(seen),
                        Some(what) => return Err(format!("запись повреждена: {what:?}")),
                    },
                }
            }
        }
    }
}

// --- ЗАКОН НАБЛЮДЕНИЯ: РОЛИ ПЕРЕВЁРНУТЫ ---

/// ЗАКОН НАБЛЮДЕНИЯ НА ЖИВОМ ЯДРЕ.
///
/// # Кто здесь кто
///
/// У инъекции подопытный отправлял, а свидетельствовал `dumpcap` в чужом сетевом пространстве.
/// Здесь наоборот: подопытный СЛУШАЕТ, а свидетельствует соседний контейнер — он порождает трафик
/// и оставляет отчёт о том, сколько кадров ушло по счётчику ядра.
///
/// # Окно задаёт УСТРОЙСТВО, а не закон
///
/// Поток `AfPacketBackend` бесконечен, и всякий потолок есть ЧАСЫ. Закон часов не имеет намеренно
/// — иначе он мерил бы время, а не способность, — поэтому обрезка стоит здесь, где часы известны.
fn certify_observes(
    iface: &str,
    nonce: &[u8],
    report: &str,
    window: &str,
) -> Result<Verdict<observation::Broken, observation::Invalid>, String> {
    let millis: u64 = window
        .parse()
        .map_err(|_bad| format!("окно не число: {window}"))?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .map_err(|why| format!("рантайм: {why}"))?;

    runtime.block_on(async {
        let mut dut = AfPacketBackend::open(iface, 65535)?;
        let mut world = Reported { path: report };
        // ПОТОК СОЗДАЁТСЯ ДО ЗАКОНА, а мир порождает трафик внутри него. Иначе проверялось бы,
        // успел ли наблюдатель подписаться, — вопрос законный, но другой.
        let seen = watching(&mut dut).take_until(tokio::time::sleep(Duration::from_millis(millis)));
        Ok(observes(&mut world, nonce, seen).await)
    })
}

/// МИР, ЧЕЙ ОТЧЁТ ЛЕЖИТ В ОБЩЕМ ТОМЕ.
///
/// Порождает трафик не он, а соседний контейнер: `Origin::emit` здесь ЖДЁТ чужого отчёта. Форма
/// трейта это позволяет — он спрашивает «сколько ушло», а не «пошли и скажи».
struct Reported<'a> {
    path: &'a str,
}

impl Origin for Reported<'_> {
    fn emit(&mut self, _nonce: &[u8]) -> usize {
        match await_report(self.path) {
            // ОТЧЁТА НЕТ ⟹ МИР МОЛЧАЛ. Ноль здесь честен: закон обязан сказать `WorldSilent`, а не
            // предъявить наблюдателю, что он не увидел того, чего не посылали.
            None => 0,
            Some((asked, tx_delta)) => match tx_delta >= asked {
                true => asked,
                // СЧЁТЧИК ЯДРА — ВЕТО, А НЕ ИСТОЧНИК ЧИСЛА. Он считает ВЕСЬ трафик интерфейса, и
                // взять его дельту за `sent` значило бы записать чужой фоновый кадр в наши — то
                // есть обвинить честного наблюдателя в потере. Поэтому число даёт отправитель, а
                // независимый прибор может его лишь ОПРОВЕРГНУТЬ: ушло меньше обещанного —
                // прогон недействителен. ЦЕНА НАЗВАНА: отправитель, пославший БОЛЬШЕ, чем сказал,
                // так не ловится.
                false => 0,
            },
        }
    }
}

/// ОТЧЁТ МИРА: сколько кадров просили и на сколько сдвинулся счётчик ядра.
///
/// Ждём с потолком: отправитель стартует после наблюдателя, и файла в первый миг ещё нет. Формат
/// — два числа через пробел; ни serde, ни json здесь не нужны, а лишняя зависимость в устройстве
/// сертификации означала бы ещё один чужой механизм между наблюдением и вердиктом.
fn await_report(path: &str) -> Option<(usize, usize)> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match std::fs::read_to_string(path) {
            Ok(text) => match parse_report(&text) {
                Some(pair) => return Some(pair),
                None => match Instant::now() >= deadline {
                    true => return None,
                    false => std::thread::sleep(Duration::from_millis(50)),
                },
            },
            Err(_not_yet) => match Instant::now() >= deadline {
                true => return None,
                false => std::thread::sleep(Duration::from_millis(50)),
            },
        }
    }
}

fn parse_report(text: &str) -> Option<(usize, usize)> {
    match text.split_whitespace().collect::<Vec<_>>().as_slice() {
        [asked, delta] => match (asked.parse(), delta.parse()) {
            (Ok(asked), Ok(delta)) => Some((asked, delta)),
            (_asked, _delta) => None,
        },
        _incomplete => None,
    }
}

/// РОЛЬ МИРА: ПОРОДИТЬ ТРАФИК И ОТЧИТАТЬСЯ, СКОЛЬКО УШЛО.
///
/// Отчёт содержит ОБА числа — сколько просили и на сколько сдвинулся счётчик ядра, — потому что у
/// них разная природа: первое наше слово, второе показание прибора. Свести их в одно значило бы
/// потерять ровно то, чем они друг друга проверяют.
fn emit_world(iface: &str, nonce: &[u8], count: &str, report: &str) -> i32 {
    match emit_frames(iface, nonce, count) {
        Err(why) => {
            eprintln!("мир не смог: {why}");
            2
        }
        Ok((asked, delta)) => match std::fs::write(report, format!("{asked} {delta}")) {
            Err(why) => {
                eprintln!("отчёт не записан: {why}");
                2
            }
            Ok(()) => {
                println!(r#"{{"role":"world","asked":{asked},"tx_delta":{delta}}}"#);
                0
            }
        },
    }
}

fn emit_frames(iface: &str, nonce: &[u8], count: &str) -> Result<(usize, usize), String> {
    let asked: usize = count
        .parse()
        .map_err(|_bad| format!("сколько — не число: {count}"))?;
    let world = AfPacketBackend::open(iface, 65535)?;
    let before = tx_packets(iface)?;

    (0..asked).try_fold((), |(), _n| world.inject(&frame_with(nonce)))?;

    let after = tx_packets(iface)?;
    Ok((asked, after.saturating_sub(before)))
}

/// СЧЁТЧИК ЯДРА — ПРИБОР ИНОЙ ПРИРОДЫ.
///
/// Ни libpcap, ни наш бэкенд к нему отношения не имеют: это учёт самого сетевого устройства. Тем
/// он и ценен — заявление «я отправил» перестаёт доказываться тем же кодом, что отправлял.
fn tx_packets(iface: &str) -> Result<usize, String> {
    let path = format!("/sys/class/net/{iface}/statistics/tx_packets");
    std::fs::read_to_string(&path)
        .map_err(|why| format!("счётчик {path} не прочитан: {why}"))?
        .trim()
        .parse()
        .map_err(|_bad| format!("счётчик {path} не число"))
}

// --- ЗАКОН УДЕРЖАНИЯ: ЕДИНСТВЕННЫЙ БЭКЕНД, НА КОТОРОМ РАБОТАЕТ ПРОДУКТ ---

/// ЗАКОН УДЕРЖАНИЯ НА ЖИВОМ ЯДРЕ.
///
/// # Устройство пробы
///
/// Подопытный сам порождает пакет — датаграмму с нонсом соседу — и сам же ловит её из очереди:
/// правило netfilter стоит на ИСХОДЯЩИХ, поэтому пакет застревает, не покинув машины. Свидетелем
/// служит сосед в чужом сетевом пространстве: он видит датаграмму тогда и только тогда, когда её
/// отпустили.
///
/// Порождать трафик самому здесь можно, и это не та поблажка, что была бы в законе наблюдения:
/// проверяется не «дошло ли», а ПОРЯДОК — прошло ли ДО нашего решения. На этот вопрос отвечает
/// только сосед, и подопытный на его ответ повлиять не может.
fn certify_holds(
    queue: &str,
    capture: &str,
    nonce: &[u8],
    target: &str,
) -> Result<Verdict<holding::Broken, holding::Invalid>, String> {
    let number: u16 = queue
        .parse()
        .map_err(|_bad| format!("номер очереди не число: {queue}"))?;
    let mut dut = NfqueueBackend::open(number)?;
    let mut below = Recorded {
        path: capture,
        taken: 0,
    };

    probe(target, nonce)?;
    let held = await_queued(&mut dut, nonce)?;

    Ok(holds(&mut dut, held, &mut below))
}

/// ДАТАГРАММА С НОНСОМ СОСЕДУ. Уходит в стек и застревает в очереди: `sendto` возвращает `Ok`,
/// потому что ядро приняло пакет у приложения — а не потому, что он покинул машину. Эти два факта
/// закон и разводит.
fn probe(target: &str, nonce: &[u8]) -> Result<(), String> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").map_err(|why| format!("проба: {why}"))?;
    socket
        .send_to(nonce, target)
        .map_err(|why| format!("проба: {why}"))
        .map(|_sent| ())
}

/// ДОЖДАТЬСЯ ИМЕННО НАШЕГО ПАКЕТА В ОЧЕРЕДИ.
///
/// Чужие, если такие придут, ОТПУСКАЮТСЯ, а не игнорируются: пакет, о котором мы промолчали,
/// висит в ядре до таймаута очереди и держит чужое соединение. Стенд, ломающий машину, на которой
/// стоит, — плохой стенд.
fn await_queued(dut: &mut NfqueueBackend, nonce: &[u8]) -> Result<Held<Queued>, String> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match dut.wait(200) {
            Waited::Blind => return Err("дескриптор очереди не добыт — ждать не на чем".into()),
            Waited::Idle => match Instant::now() >= deadline {
                true => {
                    return Err("наш пакет в очередь не пришёл — правило не заворачивает".into())
                }
                false => (),
            },
            Waited::Ready => {
                let message = dut.recv()?;
                let queued = Queued(message);
                match carries(queued.payload(), nonce) {
                    true => return Ok(Held::new(queued, Instant::now())),
                    false => {
                        let passing = Held::new(queued, Instant::now());
                        dut.apply(passing.answered(Answer::Pass))
                            .map_err(|refused| {
                                format!("чужой пакет не отпущен: {:?}", refused.why)
                            })?;
                    }
                }
            }
        }
    }
}

/// ЗАПИСЬ СВИДЕТЕЛЯ КАК ТО, ЧТО НИЖЕ ПО СТЕКУ.
///
/// # Выдержка обязательна, и она одинакова для обоих вопросов
///
/// `dumpcap` пишет буферами, и прочитанное сразу после вопроса ещё не отражает случившегося.
/// Спроси мы дальний конец мгновенно — «пусто» значило бы «не успел записать», а не «не прошло»,
/// и текущая очередь получила бы `held`. Выдержка равная намеренно: разная означала бы, что закон
/// даёт утечке меньше шансов проявиться, чем доставке.
///
/// `taken` помнит, сколько кадров уже отдано: трейт спрашивает «с прошлого раза», и свидетель,
/// отвечающий одно и то же, показал бы прошедшее ДО ответа ещё раз ПОСЛЕ — то есть превратил бы
/// утечку в законную доставку.
struct Recorded<'a> {
    path: &'a str,
    taken: usize,
}

impl Downstream for Recorded<'_> {
    fn passed(&mut self) -> Vec<Vec<u8>> {
        std::thread::sleep(Duration::from_millis(700));
        match std::fs::read(self.path) {
            Err(_no_record) => Vec::new(),
            Ok(bytes) => {
                let (frames, _broken) = reflex_core::pcap::read(&bytes, Instant::now());
                let fresh: Vec<Vec<u8>> = frames
                    .into_iter()
                    .skip(self.taken)
                    .map(|frame| frame.bytes)
                    .collect();
                self.taken += fresh.len();
                fresh
            }
        }
    }
}
