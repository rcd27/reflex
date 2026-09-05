//! ЗАПИСЬ СТРОКИ (цель × узел) — джойн двух источников, у каждого своя роль.
//!
//! Ядро отвечает «сколько», плоскость — «кто, чем и на каком основании». Главный тест здесь —
//! приёмка среза: строка обязана отдать полный счёт разговора, когда плоскость видела ЛИШЬ ЕГО
//! НАЧАЛО. Именно это случится, если удешевить горячий путь (`ct mark` в #317 выводит userspace
//! из потока со второго пакета), и посчитанная в плоскости колонка тогда покажет ноль МОЛЧА.

use reflex_engine::row::{Naming, Sight, TargetKey, Told};
use reflex_engine::{Programme, Tick};
use reflex_engine_nfq::parse::{read, Read, SERVER_PORT};
use reflex_engine_nfq::plane::Plane;
use reflex_engine_nfq::record::{as_lines, record, Watched};
use reflex_linux::conntrack::{Counts, Entry, Tuple};

const CLIENT: u32 = 0xC0A8_0164;
const SERVER: u32 = 0x8EFA_BD0E;
const TWIN: u32 = 0x8EFA_BD0F;
const MTPROTO: u32 = 0x5B6C_388C;

fn as_seen(host: &str) -> &str {
    host
}

fn frame(src: u32, dst: u32, sport: u16, dport: u16, flags: u8, body: &[u8]) -> Vec<u8> {
    let total = (40 + body.len()) as u16;
    [
        &[0x45u8, 0x00][..],
        &total.to_be_bytes(),
        &[0x00, 0x01, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00],
        &src.to_be_bytes(),
        &dst.to_be_bytes(),
        &sport.to_be_bytes(),
        &dport.to_be_bytes(),
        &[0, 0, 0, 1, 0, 0, 0, 1],
        &[0x50, flags, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00],
        body,
    ]
    .concat()
}

fn feed(plane: &mut Plane, bytes: &[u8], at: u64) {
    match read(bytes, SERVER_PORT) {
        Read::Tcp(wire) => {
            plane.feed(wire, Tick(at));
        }
        other => panic!("кадр не разобран: {other:?}"),
    }
}

fn hello_bytes(extensions: &[u8]) -> Vec<u8> {
    let body = [
        &[0x03u8, 0x03][..],
        &[0x11; 32],
        &[32],
        &[0x22; 32],
        &[0x00, 0x04],
        &[0x13, 0x01, 0x13, 0x02],
        &[0x01, 0x00],
        &(extensions.len() as u16).to_be_bytes(),
        extensions,
    ]
    .concat();
    let handshake = [
        &[0x01u8][..],
        &(body.len() as u32).to_be_bytes()[1..4],
        &body,
    ]
    .concat();
    [
        &[0x16u8, 0x03, 0x01][..],
        &(handshake.len() as u16).to_be_bytes(),
        &handshake,
    ]
    .concat()
}

fn sni_ext(name: &[u8]) -> Vec<u8> {
    let entry = [&[0x00u8][..], &(name.len() as u16).to_be_bytes(), name].concat();
    let list = (entry.len() as u16).to_be_bytes();
    let payload = [&list[..], &entry].concat();
    [
        &[0x00u8, 0x00][..],
        &(payload.len() as u16).to_be_bytes(),
        &payload,
    ]
    .concat()
}

/// Разговор, назвавшийся в приветствии: SYN, затем hello с именем.
fn named_flow(plane: &mut Plane, dst: u32, port: u16, name: &str, at: u64) {
    feed(plane, &frame(CLIENT, dst, port, SERVER_PORT, 0x02, b""), at);
    feed(
        plane,
        &frame(
            CLIENT,
            dst,
            port,
            SERVER_PORT,
            0x18,
            &hello_bytes(&sni_ext(name.as_bytes())),
        ),
        at + 1,
    );
}

fn ct(src_port: u16, dst: u32, up: u64, up_bytes: u64, down: u64, down_bytes: u64) -> Entry {
    Entry {
        orig: Tuple {
            src: CLIENT,
            dst,
            src_port,
            dst_port: SERVER_PORT,
            proto: 6,
        },
        orig_counts: Counts {
            packets: up,
            bytes: up_bytes,
        },
        reply_counts: Counts {
            packets: down,
            bytes: down_bytes,
        },
        mark: 0,
    }
}

// ── ПРИЁМКА СРЕЗА ──────────────────────────────────────────────────────────────────────────────

/// ГЛАВНЫЙ ТЕСТ. Плоскость видела начало разговора (2 пакета), ядро — весь (488). Строка обязана
/// назвать ПОЛНЫЙ счёт и НАЗВАТЬ ВЕЛИЧИНУ СЛЕПОТЫ. Посчитанная в плоскости колонка сказала бы
/// «2 пакета» и промолчала бы о том, что это не весь разговор.
#[test]
fn stroka_otdayot_polnyy_schyot_kogda_ploskost_videla_lish_nachalo() {
    let mut plane = Plane::new(Programme::Pass, as_seen);
    named_flow(&mut plane, SERVER, 51100, "rutracker.org", 1);

    let found = record(
        &plane,
        &[ct(51100, SERVER, 488, 402_000, 900, 1_400_000)],
        SERVER_PORT,
    );
    let node = &found.rows[0].nodes[0];

    assert_eq!(node.kernel.up, 488, "строка обязана нести счёт ЯДРА");
    assert_eq!(node.kernel.down_bytes, 1_400_000);
    assert_eq!(node.plane.up, 2, "плоскость видела только начало");
    assert_eq!(
        node.sight,
        Sight::Partial {
            missed_up: 486,
            missed_down: 900
        },
        "слепота обязана быть НАЗВАНА величиной, а не подразумеваться"
    );
    assert_eq!(
        node.spoke,
        Told::Blind,
        "цель не отвечала НАМ, но ядро видело 900 пакетов вниз: клетка обязана сказать \"молчим мы\", \
         а не \"молчит цель\" — иначе человек прочитает нашу слепоту как беду цели"
    );
}

/// ПРИ ПОЛНОМ ЗРЕНИИ ТА ЖЕ ПУСТАЯ КЛЕТКА ЗНАЧИТ ДРУГОЕ: цель действительно не ответила. Пара с
/// тестом выше — предмет проверяется РАЗНИЦЕЙ, а не одним значением.
#[test]
fn pri_polnom_zrenii_pustaya_kletka_govorit_o_tseli() {
    let mut plane = Plane::new(Programme::Pass, as_seen);
    named_flow(&mut plane, SERVER, 51100, "rutracker.org", 1);

    let found = record(&plane, &[ct(51100, SERVER, 2, 1400, 0, 0)], SERVER_PORT);
    let node = &found.rows[0].nodes[0];

    assert_eq!(node.sight, Sight::Full, "ядро и плоскость сосчитали одно");
    assert_eq!(
        node.spoke,
        Told::Nothing,
        "видели весь разговор и ответа не было — это факт о ЦЕЛИ"
    );
}

/// РАЗГОВОР, ДО ОЧЕРЕДИ НЕ ДОШЕДШИЙ ВОВСЕ, ВСЁ РАВНО ЕСТЬ В ЗАПИСИ. Это закрывает «видно только
/// завёрнутое»: строка про то, что происходит на коробке, а не про то, что попало к нам.
#[test]
fn razgovor_mimo_ocheredi_vsyo_ravno_daot_stroku() {
    let plane = Plane::new(Programme::Pass, as_seen);
    let found = record(
        &plane,
        &[ct(51101, SERVER, 40, 30_000, 60, 90_000)],
        SERVER_PORT,
    );

    assert_eq!(found.rows.len(), 1);
    assert_eq!(found.rows[0].nodes[0].watched, Watched::Never);
    assert_eq!(found.rows[0].nodes[0].kernel.up, 40);
    assert_eq!(
        found.rows[0].nodes[0].spoke,
        Told::Blind,
        "про ответ цели сказать нечего — и это факт о НАС, а не о цели"
    );
}

// ── ИДЕНТИЧНОСТЬ СТРОКИ ────────────────────────────────────────────────────────────────────────

/// ДВА ИМЕНИ НА ОДНОМ АДРЕСЕ — ДВЕ СТРОКИ. Ключуй по адресу или по подсказке адрес→имя — и человек
/// увидел бы чужой узел под знакомой целью.
#[test]
fn dva_imeni_na_odnom_adrese_dayut_dve_stroki() {
    let mut plane = Plane::new(Programme::Pass, as_seen);
    named_flow(&mut plane, SERVER, 51100, "rutracker.org", 1);
    named_flow(&mut plane, SERVER, 51200, "x.com", 10);

    let found = record(
        &plane,
        &[
            ct(51100, SERVER, 7, 1400, 0, 0),
            ct(51200, SERVER, 9, 1800, 4, 300),
        ],
        SERVER_PORT,
    );
    assert_eq!(found.rows.len(), 2, "одна цель на строку, а не один адрес");
    let names: Vec<_> = found
        .rows
        .iter()
        .map(|row| match &row.key {
            TargetKey::Named(name) => name.to_string(),
            TargetKey::Unnamed(addr) => format!("{:?}", addr),
        })
        .collect();
    assert!(names.contains(&"rutracker.org".to_string()));
    assert!(names.contains(&"x.com".to_string()));
}

/// ОДНА ЦЕЛЬ НА ДВУХ УЗЛАХ — ОДНА СТРОКА, ДВА УЗЛА. Разница между узлами видна только здесь.
#[test]
fn odna_tsel_na_dvuh_uzlah_daot_dva_uzla_odnoy_stroki() {
    let mut plane = Plane::new(Programme::Pass, as_seen);
    named_flow(&mut plane, SERVER, 51100, "www.youtube.com", 1);
    named_flow(&mut plane, TWIN, 51300, "www.youtube.com", 5);

    let found = record(
        &plane,
        &[
            ct(51100, SERVER, 64, 41_000, 204, 1_100_000),
            ct(51300, TWIN, 22, 14_000, 788, 892_000),
        ],
        SERVER_PORT,
    );
    assert_eq!(found.rows.len(), 1);
    assert_eq!(found.rows[0].nodes.len(), 2);
}

/// НЕСКОЛЬКО РАЗГОВОРОВ К ОДНОМУ УЗЛУ СКЛАДЫВАЮТСЯ В ОДНУ СТРОКУ УЗЛА.
#[test]
fn razgovory_k_odnomu_uzlu_skladyvayutsya() {
    let mut plane = Plane::new(Programme::Pass, as_seen);
    named_flow(&mut plane, SERVER, 51100, "web.telegram.org", 1);
    named_flow(&mut plane, SERVER, 51101, "web.telegram.org", 3);

    let found = record(
        &plane,
        &[
            ct(51100, SERVER, 10, 5000, 20, 30_000),
            ct(51101, SERVER, 5, 2000, 8, 9000),
        ],
        SERVER_PORT,
    );
    assert_eq!(found.rows[0].nodes.len(), 1);
    assert_eq!(found.rows[0].nodes[0].flows, 2);
    assert_eq!(found.rows[0].nodes[0].kernel.up, 15);
    assert_eq!(found.rows[0].nodes[0].kernel.down_bytes, 39_000);
}

/// БЕЗЫМЯННАЯ ЦЕЛЬ КЛЮЧУЕТСЯ СЕТЬЮ, А УЗЛЫ ОСТАЮТСЯ ТОЧНЫМИ. Ключуй её хозяином — и человек увидел
/// бы россыпь строк там, где у него один Telegram.
#[test]
fn bezymyannaya_tsel_daot_odnu_stroku_seti_s_tochnymi_uzlami() {
    let plane = Plane::new(Programme::Pass, as_seen);
    let found = record(
        &plane,
        &[
            ct(51500, MTPROTO, 140, 66_000, 402, 1_400_000),
            ct(51501, MTPROTO + 1, 12, 3000, 30, 40_000),
        ],
        SERVER_PORT,
    );
    assert_eq!(found.rows.len(), 1, "сеть — одна цель");
    assert_eq!(found.rows[0].nodes.len(), 2, "узлы остаются раздельными");
    assert!(matches!(found.rows[0].key, TargetKey::Unnamed(_)));
}

// ── ЧТО В ЗАПИСЬ НЕ ПОПАДАЕТ ───────────────────────────────────────────────────────────────────

#[test]
fn chuzhoy_port_i_ne_tcp_v_zapis_ne_popadayut() {
    let plane = Plane::new(Programme::Pass, as_seen);
    let udp = Entry {
        orig: Tuple {
            proto: 17,
            ..ct(51600, SERVER, 1, 100, 1, 100).orig
        },
        ..ct(51600, SERVER, 1, 100, 1, 100)
    };
    let ssh = Entry {
        orig: Tuple {
            dst_port: 22,
            ..ct(51601, SERVER, 1, 100, 1, 100).orig
        },
        ..ct(51601, SERVER, 1, 100, 1, 100)
    };
    assert_eq!(record(&plane, &[udp, ssh], SERVER_PORT).rows.len(), 0);
}

// ── ЛОССОВЫЙ КАНАЛ НАЗЫВАЕТ СЕБЯ ───────────────────────────────────────────────────────────────

/// Счётчик потерь наблюдений доезжает до записи. Без него лента событий врала бы умолчанием:
/// «сброса не было» и «сброс потерян» выглядели бы одинаково.
#[test]
fn poteri_nablyudeniy_doezzhayut_do_zapisi() {
    let plane = Plane::new(Programme::Pass, as_seen);
    assert_eq!(record(&plane, &[], SERVER_PORT).lost_sightings, 0);
}

/// РАЗЛИЧЕНИЕ ДВУХ ПРИЧИН БЕЗЫМЯННОСТИ ДОЕЗЖАЕТ ДО СТРОКИ.
///
/// В КЛЮЧЕ они совпадают намеренно: обе безымянны, обе копятся по сети — иначе строка меняла бы
/// личность в момент приветствия и теряла накопленное. Но в ЗАПИСИ узла они обязаны расходиться:
/// «приветствие прошло без имени» есть знаменатель слепой зоны именного ключа (сколько целей мы
/// не умеем лечить по имени в принципе), а «приветствие впереди» — просто время, и складывать их
/// в один знаменатель значило бы завышать слепоту на весь молодой трафик.
#[test]
fn dve_prichiny_bezymyannosti_razlichayutsya_v_zapisi_uzla() {
    let mut plane = Plane::new(Programme::Pass, as_seen);
    // Приветствие прошло, имени в нём нет — вопрос закрыт.
    feed(
        &mut plane,
        &frame(CLIENT, SERVER, 51700, SERVER_PORT, 0x02, b""),
        1,
    );
    feed(
        &mut plane,
        &frame(CLIENT, SERVER, 51700, SERVER_PORT, 0x18, &hello_bytes(&[])),
        2,
    );
    // Приветствие ещё впереди — только SYN.
    feed(
        &mut plane,
        &frame(CLIENT, TWIN, 51701, SERVER_PORT, 0x02, b""),
        3,
    );

    let found = record(
        &plane,
        &[
            ct(51700, SERVER, 2, 600, 0, 0),
            ct(51701, TWIN, 1, 60, 0, 0),
        ],
        SERVER_PORT,
    );

    let namings: Vec<_> = found
        .rows
        .iter()
        .flat_map(|row| row.nodes.iter())
        .map(|node| match node.watched {
            Watched::Seen { naming, .. } => naming,
            Watched::Never | Watched::Ended(_) | Watched::Lost => Naming::Awaited,
        })
        .collect();

    assert!(
        namings.contains(&Naming::Silent),
        "приветствие без имени обязано читаться как ЗАКРЫТЫЙ вопрос, а не как ожидание: {namings:?}"
    );
    assert!(
        namings.contains(&Naming::Awaited),
        "разговор до приветствия обязан остаться ожиданием: {namings:?}"
    );
}

/// ЦЕЛЬ, НАЗВАВШАЯСЯ ПОЗДНО, ПЕРЕЕЗЖАЕТ ИЗ БЕЗЫМЯННОЙ СТРОКИ В ИМЕННУЮ — И НЕ ТЕРЯЕТ СЧЁТА.
///
/// Ключ строки уточняется вместе со знанием: пока приветствие впереди, цель безымянна и копится по
/// сети; назвалась — строка становится именной. Переезд неизбежен по построению, и вопрос не в том,
/// случится ли он, а в том, что станет с накопленным.
///
/// Здесь он бесплатен, и это свойство КОНСТРУКЦИИ, а не везения: счёт живёт в conntrack, а запись
/// пересобирается снимком целиком. Накапливай мы инкрементально — пришлось бы переносить копилку из
/// строки в строку, и вот тогда переезд стал бы событием, которое можно потерять.
#[test]
fn pozdno_nazvavshayasya_tsel_pereezzhaet_ne_teryaya_schyota() {
    let mut plane = Plane::new(Programme::Pass, as_seen);
    feed(
        &mut plane,
        &frame(CLIENT, SERVER, 51800, SERVER_PORT, 0x02, b""),
        1,
    );

    let before = record(
        &plane,
        &[ct(51800, SERVER, 40, 30_000, 60, 90_000)],
        SERVER_PORT,
    );
    assert!(
        matches!(before.rows[0].key, TargetKey::Unnamed(_)),
        "приветствие впереди — цель безымянна"
    );
    assert_eq!(before.rows[0].nodes[0].kernel.up, 40);

    feed(
        &mut plane,
        &frame(
            CLIENT,
            SERVER,
            51800,
            SERVER_PORT,
            0x18,
            &hello_bytes(&sni_ext(b"rutracker.org")),
        ),
        2,
    );

    let after = record(
        &plane,
        &[ct(51800, SERVER, 41, 31_400, 60, 90_000)],
        SERVER_PORT,
    );
    assert_eq!(
        after.rows[0].key,
        TargetKey::Named(Box::<str>::from("rutracker.org")),
        "назвалась — строка обязана стать именной"
    );
    assert_eq!(
        after.rows[0].nodes[0].kernel.up, 41,
        "накопленное переезд пережило: счёт живёт в ядре, а не в строке"
    );
}

/// СНИМОК ЕДЕТ ПОКАЗУ СТРОКОЙ, И ТРИ СОСТОЯНИЯ В НЕЙ РАЗЛИЧЕНЫ (#320).
///
/// `null` для «цель не ответила» и для «мы не имели права судить» — одно значение с двумя
/// смыслами, и у приёмочного прибора это дороже всего: пустая клетка есть ВЕРДИКТ о датаплейне,
/// а не пропуск в показе. Формат обязан различать их так же, как различает тип.
#[test]
fn the_snapshot_tells_apart_what_the_type_tells_apart() {
    let mut plane = Plane::new(Programme::Pass, as_seen);
    feed(
        &mut plane,
        &frame(CLIENT, SERVER, 51700, SERVER_PORT, 0x02, b""),
        1,
    );
    // СЧЁТ ЯДРА РАВЕН СЧЁТУ ПЛОСКОСТИ — иначе узел зряч наполовину, и `spoke` честно приедет
    // `blind`: не имеем права судить о цели, которую видели не всю. Здесь предмет другой —
    // трёхзначность самого формата, и слепоту надо убрать, чтобы она не подменила ответ.
    let found = record(&plane, &[ct(51700, SERVER, 1, 60, 0, 0)], SERVER_PORT);

    let lines = as_lines(&found, Tick(1_700));

    // ЧИСЛА СНИМКА — первое, на что смотрит читатель: без них пустая таблица не отличается от
    // неоткрывшегося снимка.
    assert!(
        lines.starts_with("snapshot targets=1 nodes=1 "),
        "снимок не сказал первой строкой, сколько в нём целей и узлов: {lines}"
    );
    // ЦЕЛЬ БЕЗЫМЯННА — ключ обязан приехать СЕТЬЮ С МАСКОЙ: ширина записи есть свойство ключа, и
    // умолчать её значит соврать о предмете строки.
    assert!(
        lines.contains("target 142.250.189.0/24"),
        "ключ цели не доехал либо приехал без ширины — показу нечем собрать строку: {lines}"
    );
    // ТРЁХЗНАЧНОСТЬ: цель не отвечала, но плоскость смотрела — это `nothing`, а не пропуск поля и
    // не `blind`.
    assert!(
        lines.contains("spoke=nothing"),
        "молчание цели приехало не своим именем: {lines}"
    );
    assert!(
        lines.contains("seen=") && lines.contains("sight="),
        "узел приехал без слепоты либо без момента наблюдения: {lines}"
    );
}

/// ИМЯ С ПРОВОДА НЕ ЛОМАЕТ СНИМОК: `ClientHello` присылает противник.
///
/// В построчном формате опасны две вещи — перевод строки (хвост имени стал бы новой записью) и
/// пробел (поля разделены им, и разбор сдвинулся бы). Ослепить показ содержимым чужого пакета —
/// дешёвая атака, если о ней не подумать. Защищается тот, кто ПИШЕТ: читателю нечем отличить
/// испорченную строку от настоящей.
#[test]
fn a_name_from_the_wire_cannot_break_the_snapshot() {
    let mut plane = Plane::new(Programme::Pass, as_seen);
    named_flow(&mut plane, SERVER, 51701, "evil name\nnode 6.6.6.6", 1);

    let lines = as_lines(
        &record(&plane, &[ct(51701, SERVER, 3, 400, 0, 0)], SERVER_PORT),
        Tick(1),
    );

    assert_eq!(
        lines
            .lines()
            .filter(|line| line.starts_with("node "))
            .count(),
        1,
        "имя с провода породило лишнюю строку узла — читатель принял чужие байты за запись: \
         {lines}"
    );
    assert!(
        !lines.contains("evil name"),
        "пробел из имени уехал в снимок — разбор полей сдвинется: {lines}"
    );
}
