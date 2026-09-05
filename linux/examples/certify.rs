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

use reflex_core::certify::{injects, Verdict};
use reflex_core::command::InjectablePacket;
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
    let (iface, capture, nonce) = match args.as_slice() {
        [_, iface, capture, nonce] => (iface.clone(), capture.clone(), nonce.clone()),
        _ => {
            eprintln!("употребление: certify <интерфейс> <путь-к-записи> <нонс>");
            std::process::exit(2);
        }
    };

    match certify_injects(&iface, &capture, nonce.as_bytes()) {
        Err(why) => {
            println!(
                r#"{{"law":"injects","backend":"AfPacketBackend","verdict":"invalid","why":"{why}"}}"#
            );
            std::process::exit(2);
        }
        Ok(Verdict::Held) => {
            println!(r#"{{"law":"injects","backend":"AfPacketBackend","verdict":"held"}}"#);
        }
        Ok(Verdict::Broken(because)) => {
            println!(
                r#"{{"law":"injects","backend":"AfPacketBackend","verdict":"broken","because":"{because:?}"}}"#
            );
            std::process::exit(1);
        }
    }
}

/// ЗАКОН ИНЪЕКЦИИ НА ЖИВОМ ЯДРЕ.
///
/// ПРОГОН, В КОТОРОМ ПРИБОР МОЛЧАЛ, НЕДЕЙСТВИТЕЛЕН, А НЕ ЧИСТ. Если записи нет или она пуста,
/// ответом будет `Err`, а не «закон нарушен»: отличать «свидетель не работал» от «подопытный
/// солгал» — половина смысла всей затеи.
fn certify_injects(iface: &str, capture: &str, nonce: &[u8]) -> Result<Verdict, String> {
    let mut dut = AfPacketBackend::open(iface, 65535)?;
    let frame = frame_with(nonce);

    let outcome = injects(
        &mut dut,
        InjectablePacket::Raw(frame),
        || match read_capture(capture) {
            Err(_why) => Vec::new(),
            Ok(frames) => frames,
        },
    );

    match read_capture(capture) {
        Err(why) => Err(why),
        Ok(frames) if frames.is_empty() => {
            Err("свидетель не увидел НИ ОДНОГО кадра — прогон недействителен".into())
        }
        Ok(_seen) => Ok(outcome),
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
/// ЖДЁМ ЗАПИСЬ, А НЕ ЧИТАЕМ СРАЗУ: `tshark` пишет буферами, и первый кадр появляется в файле не в
/// тот же миг. Ожидание с потолком, а не сон наугад.
fn read_capture(path: &str) -> Result<Vec<Vec<u8>>, String> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match std::fs::read(path) {
            Err(why) if Instant::now() >= deadline => {
                return Err(format!("запись свидетеля не прочитана: {why}"))
            }
            Err(_not_yet) => std::thread::sleep(Duration::from_millis(100)),
            Ok(bytes) => {
                let (frames, broken) = reflex_core::pcap::read(&bytes, Instant::now());
                match (frames.is_empty(), Instant::now() >= deadline) {
                    (true, false) => std::thread::sleep(Duration::from_millis(100)),
                    (true, true) => match broken {
                        None => return Ok(Vec::new()),
                        Some(what) => return Err(format!("запись повреждена: {what:?}")),
                    },
                    (false, _) => return Ok(frames.into_iter().map(|frame| frame.bytes).collect()),
                }
            }
        }
    }
}
