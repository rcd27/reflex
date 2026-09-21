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
                age: Some(Duration::from_secs(7)),
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
            age: Some(Duration::from_secs(7)),
            mark: 0,
        }))
        .then_packet(syn(PORT))
        .then_packet_after(Duration::from_millis(10), handshake(PORT))
        .then_packet_after(
            Duration::from_millis(10),
            segment(PORT, HEAD, &hello(1_348)),
        )
        // ВОТ ЭТОТ КАДР И БЫЛ РАЗНИЦЕЙ между бумагой и проводом: события провода из него не
        // рождается (пустой сегмент — не буква), а краю он приходит пакетом.
        .then_packet_after(Duration::from_millis(5), acknowledgement(PORT));
    for rto in [290u64, 580, 1_150, 2_300, 4_700] {
        dump = dump.then_packet_after(
            Duration::from_millis(rto),
            segment(PORT, HEAD, &hello(1_348)),
        );
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

/// ОТНЯТОЕ СЛОВО НЕ ТРАТИТ ЕДИНСТВЕННЫЙ ВЫСТРЕЛ ДВЕРИ.
///
/// Проводная половина говорит однажды (`Watch::Fired` глушит её навсегда) — и это правильно: одна
/// беда, одно слово. Но пока слово об истории отнимали ФИЛЬТРОМ ЗА ПРИБОРОМ, выстрел тратился на
/// высказывание, которого никто не слышал: всякий разговор, где цель молчала дольше порога ДО
/// первого своего байта, глох целиком. Медленная цель (первый байт позже порога) делала дверь
/// немой на весь сеанс — а это самый обычный разговор, не редкая клетка.
///
/// Замер на сочинённом проводе при пороге 1,5 с: цель молчит две секунды, отвечает, клиент
/// спрашивает снова, цель встаёт на шесть секунд. До починки сказано НОЛЬ слов; после — беда
/// названа, и названа ровно та же, что называется без первой паузы. Пара клеток обязательна:
/// одиночный прогон был бы зелен и на автомате, который просто не глохнет никогда.
#[test]
fn a_confiscated_word_does_not_spend_the_doors_one_shot() {
    use paper::{handshake, log, reply, segment, syn, taken, Paper, PaperEdge};

    fn ask(len: usize) -> Vec<u8> {
        let mut bytes = vec![0x16, 0x03, 0x01, 0x05, 0x40];
        bytes.resize(len, 0x41);
        bytes
    }

    const PORT: u16 = 40001;

    let said = |first_gap: u64| -> Vec<Distress> {
        let heard = log::<Distress>();
        engine(
            Paper::new()
                // Цель ЖИВА и отдала данные — краю сказать нечего, и всё услышанное здесь
                // принадлежит проводной половине.
                .edging(Some(PaperEdge {
                    up_packets: 3,
                    up_bytes: 3 * 56 + 1_400,
                    down_packets: 4,
                    down_bytes: 4 * 52 + 1_348,
                    age: Some(Duration::from_secs(9)),
                    mark: 0,
                }))
                .then_packet(syn(PORT))
                .then_packet_after(Duration::from_millis(10), handshake(PORT))
                .then_packet_after(Duration::from_millis(10), segment(PORT, 107, &ask(1_348)))
                .then_packet_after(Duration::from_millis(first_gap), reply(PORT, 1_400))
                .then_packet_after(Duration::from_millis(100), segment(PORT, 1_455, &ask(100)))
                .silent_for(Duration::from_secs(6))
                .then_stop(),
        )
        .from(Tcp)
        .extract(Sni)
        .detect(Silence::after(Duration::from_millis(1_500)))
        .on(move |_target: &str, distress| heard.lock().expect("журнал цел").push(distress))
        .run();
        taken(heard)
    };

    let after_a_confiscated_word = said(2_000);
    let without_one = said(200);
    assert!(
        matches!(after_a_confiscated_word.as_slice(), [Distress::Silence { ms }] if *ms >= 1_500),
        "первая пауза слова не родила — значит и выстрела не потратила: {after_a_confiscated_word:?}"
    );
    assert_eq!(
        after_a_confiscated_word, without_one,
        "молчавшая сперва цель обязана быть слышна так же, как заговорившая сразу"
    );
}

/// СВИДЕТЕЛЬ БЕЗ ЧАСОВ СЛОВА НЕ БЕРЁТ.
///
/// Замер потребителя с боевой коробки (NanoPi R2S, OpenWrt 6.12.71, 20.09.2026): счётчики
/// conntrack приходят — `conntrack -L` по висящему разговору даёт у цели `packets=1 bytes=60`,
/// то есть один `SYN+ACK` и ничего сверх заголовков, — а метки времени в ядре нет вовсе
/// (`nf_conntrack_timestamp` не существует как ключ, ядро собрано без неё). Порог краевой
/// половины держит ВОЗРАСТ потока, возраста нет — фаза не уходит из подозрения никогда.
///
/// Слово, отданное такому свидетелю, не говорит никто — та же беда, что чинилась утром, но
/// этажом выше: прежде край отвечал не о том, теперь не может ответить вовсе. Отсюда и закон:
/// отдавать слово не «потому что это TCP», а потому что виден край, СПОСОБНЫЙ его сказать.
#[test]
fn a_witness_without_a_clock_does_not_take_the_word() {
    use paper::{handshake, log, segment, syn, taken, Paper, PaperEdge};

    const PORT: u16 = 40001;

    let said = |age: Option<Duration>| -> Vec<Distress> {
        let heard = log::<Distress>();
        let mut dump = Paper::new()
            .edging(Some(PaperEdge {
                up_packets: 1,
                up_bytes: 60,
                down_packets: 8,
                down_bytes: 8 * 52 + 1_348 * 6,
                age,
                mark: 0,
            }))
            .then_packet(syn(PORT))
            .then_packet_after(Duration::from_millis(10), handshake(PORT))
            .then_packet_after(
                Duration::from_millis(10),
                segment(PORT, 107, &[0x16, 0x03, 0x01, 0x05, 0x40]),
            );
        for rto in [290u64, 580, 1_150, 2_300] {
            dump = dump.then_packet_after(
                Duration::from_millis(rto),
                segment(PORT, 107, &[0x16, 0x03, 0x01, 0x05, 0x40]),
            );
        }
        engine(dump.then_stop_after(Duration::from_millis(500)))
            .from(Tcp)
            .extract(Sni)
            .detect(Silence::after(Duration::from_millis(1_600)))
            .on(move |_target: &str, distress| heard.lock().expect("журнал цел").push(distress))
            .run();
        taken(heard)
    };

    let clockless = said(None);
    assert!(
        matches!(clockless.as_slice(), [Distress::NoBytes]),
        "у края нет часов — слово остаётся у того, чьи часы свои: {clockless:?}"
    );
    // ПАРА ОБЯЗАТЕЛЬНА: с часами слово говорит КРАЙ, и говорит его ОДИН раз. Без этой половины
    // проверка была бы зелена и на приборе, который просто говорит всегда и дважды.
    let clocked = said(Some(Duration::from_secs(7)));
    assert_eq!(
        clocked.len(),
        1,
        "одна беда — одно слово, кто бы его ни сказал: {clocked:?}"
    );
}

/// НОСИТЕЛЬ БЕЗ КРАЯ ВОВСЕ — та же клетка, другой её край: отдавать слово некому, и провод его
/// сохраняет. Прежде условие звучало «это TCP — значит свидетель есть», то есть принимало догадку
/// о носителе за наблюдение (§7); запись и местный трафик под эту догадку не подходили никогда.
#[test]
fn without_an_edge_the_wire_keeps_the_word() {
    use paper::{handshake, log, segment, syn, taken, Paper};

    const PORT: u16 = 40001;

    let heard = log::<Distress>();
    engine(
        Paper::new()
            .edging(None)
            .then_packet(syn(PORT))
            .then_packet_after(Duration::from_millis(10), handshake(PORT))
            .then_packet_after(
                Duration::from_millis(10),
                segment(PORT, 107, &[0x16, 0x03, 0x01, 0x05, 0x40]),
            )
            .then_packet_after(
                Duration::from_millis(2_300),
                segment(PORT, 107, &[0x16, 0x03, 0x01, 0x05, 0x40]),
            )
            .then_stop_after(Duration::from_millis(500)),
    )
    .from(Tcp)
    .extract(Sni)
    .detect(Silence::after(Duration::from_millis(1_600)))
    .on(move |_target: &str, distress| heard.lock().expect("журнал цел").push(distress))
    .run();

    let said = taken(heard);
    assert!(
        matches!(said.as_slice(), [Distress::NoBytes]),
        "края нет — некому отдать слово, и оно остаётся сказанным: {said:?}"
    );
}
