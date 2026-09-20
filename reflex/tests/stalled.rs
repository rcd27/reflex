//! ЦЕЛЬ, ЗАМОЛЧАВШАЯ ПОСРЕДИ РАЗГОВОРА, — класс беды, который весь парк пропускал.
//!
//! Запись снята с провода 18.09.2026: клиент открыл TLS к цели за фильтром, получил сертификат,
//! отправил запрос, цель подтвердила его `ACK`-ом БЕЗ ДАННЫХ и замолчала на 19,4 секунды, после
//! чего ответила `301`. Блокировка сменила род: тихого дропа по имени больше нет, есть задержка.
//!
//! Восемь приборов парка на этой записи молчали. Краевая половина двери [`reflex::Silence`] видит
//! отданные целью байты, считает её живой и отпускает разговор навсегда; истории «речь шла и
//! встала» край не выражает вовсе — она видна только тому, кто ТИКАЕТ.

use reflex::*;
use std::time::Duration;

fn recording() -> String {
    format!(
        "{}/tests/fixtures/stalled-after-reply.pcap",
        env!("CARGO_MANIFEST_DIR")
    )
}

fn heard_with(patience: Duration) -> Vec<Distress> {
    let heard = std::sync::Mutex::new(Vec::new());
    pcap(recording())
        .from(Tcp)
        .extract(Sni)
        .detect(Silence::after(patience))
        .on(|_target: &str, distress| heard.lock().expect("журнал цел").push(distress))
        .run();
    heard.into_inner().expect("журнал цел")
}

/// ШТАТНАЯ ДВЕРЬ НАЗЫВАЕТ БЕДУ, а не молчит: цель приняла просьбу и не отвечает дольше терпения.
#[test]
fn a_target_that_went_quiet_after_replying_is_named_by_the_regular_door() {
    let said = heard_with(Duration::from_secs(5));

    assert!(
        matches!(said.as_slice(), [Distress::Silence { ms }] if *ms >= 5_000),
        "19 секунд тишины при ждущем клиенте обязаны быть названы: {said:?}"
    );
}

/// ТЕРПЕНИЕ — ВЕЛИЧИНА ДОМЕННОЙ ЛОГИКИ, и беда называется тем раньше, чем оно короче. Полсекунды
/// терпения — полсекунды до слова, а не пять секунд ожидания.
#[test]
fn shorter_patience_names_the_trouble_sooner() {
    let said_quickly = heard_with(Duration::from_millis(500));

    assert!(
        matches!(said_quickly.as_slice(), [Distress::Silence { ms }] if *ms < 1_000),
        "при пороге 500 мс слово обязано прийти в пределах секунды: {said_quickly:?}"
    );
}

/// СЛОВО ОДНО, А НЕ ДВА: половины двери говорят о разном, и `NoBytes` остаётся за краем —
/// единственным, кто знает историю разговора до нашего рождения.
#[test]
fn the_two_halves_of_the_door_do_not_repeat_each_other() {
    let said = heard_with(Duration::from_millis(500));

    assert_eq!(said.len(), 1, "одна беда — одно слово: {said:?}");
    assert!(
        !said.iter().any(|w| matches!(w, Distress::NoBytes)),
        "цель отдала сертификат — `NoBytes` о ней был бы ложью: {said:?}"
    );
}

mod paper;

/// ТОТ ЖЕ ЗАКОН НА ВХОДЕ, ГДЕ ПОЛОВИНЫ МОГЛИ БЫ СТОЛКНУТЬСЯ: цель не отдала НИ БАЙТА, и `NoBytes`
/// — слово обеих по существу. Говорит его КРАЙ: он один знает историю разговора до нашего
/// рождения (счёт ведёт ядро), а провод свидетелем той истории не является.
///
/// Предыдущий закон этого не ловит и не может: на записи с ответом цели проводная половина
/// `NoBytes` не говорит вовсе, и снятый фильтр там не краснеет — проверка была бы слепа к своему
/// предмету (§10.7).
#[test]
fn when_the_target_is_wholly_silent_only_the_edge_speaks_the_word() {
    use paper::{request, Paper, PaperEdge};

    let heard = std::sync::Mutex::new(Vec::new());
    engine(
        Paper::new()
            // Край говорит то, что на живой очереди сказал бы conntrack: цель ответила ОДНИМ
            // пакетом (`SYN+ACK`), данных не дала, клиент свой запрос отправил, разговор старше терпения.
            .edging(Some(PaperEdge {
                up_packets: 1,
                // Один кадр `SYN+ACK` с опциями — заголовки, и ничего сверх них.
                up_bytes: 60,
                down_packets: 2,
                down_bytes: 1_500,
                age: Duration::from_secs(7),
                mark: 0,
            }))
            // ДВА наблюдения: первое берёт разговор под подозрение (фаза ложится в марку),
            // второе приходит, когда возраст перешагнул терпение, — на нём край и высказывается.
            .then_packet(request(40001))
            .then_packet_after(Duration::from_secs(7), request(40001))
            .then_stop(),
    )
    .from(Tcp)
    .extract(Sni)
    .detect(Silence::after(Duration::from_secs(5)))
    .on(|_t: &str, d| heard.lock().expect("журнал цел").push(d))
    .run();

    let said = heard.into_inner().expect("журнал цел");
    assert_eq!(
        said.len(),
        1,
        "«не отдала ни байта» — одна беда, и слово о ней одно: {said:?}"
    );
    assert!(
        matches!(said.as_slice(), [Distress::NoBytes]),
        "историю разговора называет край: {said:?}"
    );
}

/// ЦЕЛЬ ПОДТВЕРЖДАЕТ И НЕ ОТДАЁТ НИ БАЙТА — и это не «предел носителя», а вопрос, заданный краю не
/// о том.
///
/// Картина снята с провода 20.09.2026 (линия Москвы, rutracker.org): рукопожатие состоялось,
/// `ClientHello` ушёл и был ПОДТВЕРЖДЁН, а дальше цель не сказала ничего — клиент повторял голову с
/// растущим RTO (0,29 · 0,58 · 1,15 · 2,3 · 4,7 с) и сдался через десять секунд. Дверь тишины
/// молчала обеими половинами, и молчание было круговым: проводная половина отдаёт `NoBytes` краю
/// (он один знает историю разговора), а край считал цель ЖИВОЙ, потому что мерил её ПАКЕТАМИ —
/// подтверждение без данных пакет и есть.
///
/// Слово о БАЙТАХ нельзя выводить из счёта ПАКЕТОВ: у conntrack есть обе величины, и та же
/// арифметика «сверх заголовков», которой прибор уже мерил просьбу клиента, отвечает и про ответ
/// цели. Пока она стояла только на одной стороне, целый род блокировки (подтверждающее устройство
/// на пути) был записан в непреодолимые пределы conntrack — замером это опровергнуто.
#[test]
fn a_target_that_acknowledges_without_a_single_byte_is_named() {
    use paper::{acknowledgement, handshake, segment, syn, Paper, PaperEdge};

    /// Голова приветствия: первый сегмент клиента, по нему цель и опознаётся.
    fn hello(len: usize) -> Vec<u8> {
        let mut bytes = vec![0x16, 0x03, 0x01, 0x05, 0x40];
        bytes.resize(len, 0x41);
        bytes
    }

    const PORT: u16 = 40001;
    const HEAD: u32 = 107;

    let mut dump = Paper::new()
        // Край говорит то, что на живой очереди сказал бы conntrack: цель прислала ТРИ пакета
        // (`SYN+ACK` и два подтверждения) и ровно столько байт, сколько весят их заголовки, —
        // данных в них нет. Клиент своё приветствие отдал, разговор старше терпения.
        .edging(Some(PaperEdge {
            up_packets: 3,
            up_bytes: 3 * 56,
            down_packets: 9,
            down_bytes: 9 * 52 + 1_348 * 6 + 225,
            age: Duration::from_secs(7),
            mark: 0,
        }))
        .then_packet(syn(PORT))
        .then_packet_after(Duration::from_millis(10), handshake(PORT))
        .then_packet_after(Duration::from_millis(10), segment(PORT, HEAD, &hello(1_348)))
        // ВОТ ЭТОТ КАДР И БЫЛ РАЗНИЦЕЙ между бумагой и проводом: события провода из него не
        // рождается (пустой сегмент — не буква), а краю он приходит пакетом.
        .then_packet_after(Duration::from_millis(5), acknowledgement(PORT));
    for rto in [290u64, 580, 1_150, 2_300, 4_700] {
        dump = dump.then_packet_after(Duration::from_millis(rto), segment(PORT, HEAD, &hello(1_348)));
    }

    let heard = std::sync::Mutex::new(Vec::new());
    engine(dump.then_stop_after(Duration::from_millis(500)))
        .from(Tcp)
        .extract(Sni)
        .detect(Silence::after(Duration::from_millis(1_600)))
        .on(|_target: &str, distress| heard.lock().expect("журнал цел").push(distress))
        .run();

    let said = heard.into_inner().expect("журнал цел");
    assert!(
        matches!(said.as_slice(), [Distress::NoBytes]),
        "цель за десять секунд не отдала ни байта данных — беда обязана быть названа один раз: {said:?}"
    );
}
