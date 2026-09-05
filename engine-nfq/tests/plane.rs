use reflex_engine::{Act, Addr, Basis, Cursor, FlowKey, Interest, Mark, Programme, Sighting, Tick};
use reflex_engine_nfq::parse::{keyed, read, Read, SERVER_PORT};
use reflex_engine_nfq::plane::Plane;

const CLIENT: u32 = 0xC0A8_0164;
const SERVER: u32 = 0x8EFA_BD0E;
const OTHER: u32 = 0x0808_0808;

/// СУЖЕНИЕ ДЛЯ ТЕСТА: имя берётся как есть. Ширина ключа здесь не предмет — предмет плоскость.
fn as_seen(host: &str) -> &str {
    host
}

/// Ключ разговора считается ТЕМ ЖЕ способом, что и в плоскости: посчитай тест его по-своему —
/// проверял бы он свою арифметику, а не её память.
fn flow_of(port: u16) -> FlowKey {
    keyed(CLIENT, port, SERVER, SERVER_PORT)
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

fn feed(plane: &mut Plane, bytes: &[u8], at: u64) -> Act {
    match read(bytes, SERVER_PORT) {
        Read::Tcp(wire) => plane.feed(wire, Tick(at)).act,
        other => panic!("кадр не разобран: {other:?}"),
    }
}

fn syn(port: u16) -> Vec<u8> {
    frame(CLIENT, SERVER, port, SERVER_PORT, 0x02, b"")
}

fn asks(port: u16, body: &[u8]) -> Vec<u8> {
    frame(CLIENT, SERVER, port, SERVER_PORT, 0x18, body)
}

fn answers(port: u16, body: &[u8]) -> Vec<u8> {
    frame(SERVER, CLIENT, SERVER_PORT, port, 0x18, body)
}

fn fin(port: u16) -> Vec<u8> {
    frame(CLIENT, SERVER, port, SERVER_PORT, 0x11, b"")
}

#[test]
fn the_tail_of_a_closed_conversation_is_not_told_as_a_new_one() {
    let mut plane = Plane::new(Programme::Pass, as_seen);

    feed(&mut plane, &syn(51000), 1);
    feed(&mut plane, &asks(51000, b"hello"), 2);
    feed(&mut plane, &fin(51000), 3);
    plane.drain();

    feed(&mut plane, &answers(51000, b""), 4);
    feed(&mut plane, &fin(51000), 5);

    assert!(!plane
        .drain()
        .iter()
        .any(|noted| matches!(noted.what, Sighting::Opened { .. })));
    assert_eq!(plane.pressure().held, 1);
}

#[test]
fn teaching_the_plane_makes_live_conversations_stale_exactly_once() {
    let mut plane = Plane::new(Programme::Pass, as_seen);
    feed(&mut plane, &syn(51000), 1);
    plane.drain();

    plane.teach_unnamed(
        Addr(SERVER),
        Programme::Pass,
        Basis::Measured,
        Interest::Idle,
    );

    feed(&mut plane, &asks(51000, b"one"), 2);
    let first = plane.drain();
    feed(&mut plane, &asks(51000, b"two"), 3);
    let second = plane.drain();

    assert!(first
        .iter()
        .any(|noted| matches!(noted.what, Sighting::Stale { .. })));
    assert!(!second
        .iter()
        .any(|noted| matches!(noted.what, Sighting::Stale { .. })));
}

#[test]
fn a_conversation_opened_after_teaching_is_never_stale() {
    let mut plane = Plane::new(Programme::Pass, as_seen);
    plane.teach_unnamed(
        Addr(SERVER),
        Programme::Pass,
        Basis::Measured,
        Interest::Idle,
    );

    feed(&mut plane, &syn(51000), 1);
    feed(&mut plane, &asks(51000, b"one"), 2);

    assert!(!plane
        .drain()
        .iter()
        .any(|noted| matches!(noted.what, Sighting::Stale { .. })));
}

#[test]
fn teaching_another_target_leaves_a_live_conversation_alone() {
    let mut plane = Plane::new(Programme::Pass, as_seen);
    plane.teach_unnamed(
        Addr(SERVER),
        Programme::Pass,
        Basis::Measured,
        Interest::Idle,
    );
    feed(&mut plane, &syn(51000), 1);
    plane.drain();

    plane.teach_unnamed(
        Addr(OTHER),
        Programme::Pass,
        Basis::Measured,
        Interest::Idle,
    );

    feed(&mut plane, &asks(51000, b"one"), 2);
    assert!(!plane
        .drain()
        .iter()
        .any(|noted| matches!(noted.what, Sighting::Stale { .. })));
}

#[test]
fn the_channel_ring_counts_what_came_down_not_what_we_asked_for() {
    let mut plane = Plane::new(Programme::Pass, as_seen);

    feed(&mut plane, &syn(51000), 1);
    feed(&mut plane, &asks(51000, &[0u8; 500]), 2);
    assert_eq!(plane.channel(0).bytes, 0);

    feed(&mut plane, &answers(51000, &[0u8; 1400]), 3);
    assert_eq!(plane.channel(0).bytes, 1400);
    assert_eq!(plane.tally().up_bytes, 500);
    assert_eq!(plane.tally().down_bytes, 1400);
}

#[test]
fn two_conversations_to_one_target_share_the_target_and_not_the_cursor() {
    let mut plane = Plane::new(Programme::Pass, as_seen);

    feed(&mut plane, &syn(51000), 1);
    feed(&mut plane, &syn(51001), 2);

    assert_eq!(plane.pressure().held, 2);
    assert_eq!(plane.targets_held(), 1);
}

#[test]
fn the_peak_of_a_target_is_told_upward_so_that_forgetting_it_costs_nothing() {
    let mut plane = Plane::new(Programme::Pass, as_seen);
    let bucket = 1u64 << reflex_engine::meter::BUCKET_SHIFT;

    feed(&mut plane, &syn(51000), 1);
    feed(&mut plane, &answers(51000, &[0u8; 1400]), 2);
    feed(&mut plane, &answers(51000, &[0u8; 1400]), bucket + 1);

    assert!(plane
        .drain()
        .iter()
        .any(|noted| matches!(noted.what, Sighting::Peaked { .. })));
}

#[test]
fn a_flow_the_box_did_not_see_open_is_carried_untouched() {
    let mut plane = Plane::new(Programme::Pass, as_seen);

    let joined = feed(&mut plane, &answers(51000, &[0u8; 1400]), 1);
    let asking = feed(&mut plane, &asks(51000, &[0u8; 500]), 2);

    assert_eq!(joined, Act::Pass);
    assert_eq!(asking, Act::Pass);
}

// ── ИМЯ ЦЕЛИ ПО АДРЕСУ (#302, срез 3) ────────────────────────────────────────────────────────
//
// Плоскость наблюдает бедой по АДРЕСУ (`Sighting` несёт `dst`), а знание невода ключуется ИМЕНЕМ
// (eTLD+1). Без моста между ними петля познания не замыкается: беда приходит, а записать её не
// на что. Считать имя второй раз в оболочке значило бы завести вторую правду о том, как зовут
// цель, — а ключ, добываемый на каждой стороне по-своему, расходится молча.
//
// Построители кадра скопированы из `tests/parse.rs` намеренно: интеграционные тесты в Rust кода
// не делят, а заводить ради двух функций общий модуль дороже, чем держать их рядом с предметом.

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

/// ПЛОСКОСТЬ ПОМНИТ, КАК ЗОВУТ ЦЕЛЬ ПО ЭТОМУ АДРЕСУ — подсказкой для безымянного трафика.
#[test]
fn the_plane_can_name_the_target_behind_an_address() {
    let mut plane = Plane::new(Programme::Pass, as_seen);
    feed(&mut plane, &syn(51100), 1);
    feed(
        &mut plane,
        &asks(51100, &hello_bytes(&sni_ext(b"rutracker.org"))),
        2,
    );

    assert_eq!(
        plane.name_hint_of(Addr(SERVER)),
        Some("rutracker.org"),
        "плоскость разобрала имя и не связала его с адресом"
    );
}

/// ПРО НЕЗНАКОМЫЙ АДРЕС ПЛОСКОСТЬ МОЛЧИТ, а не выдумывает.
///
/// Молчание здесь — знание о нас («имени не видели»), и путать его с именем нельзя: назначить
/// ногу не той цели хуже, чем не назначить вовсе.
#[test]
fn an_address_never_seen_has_no_name_rather_than_a_guessed_one() {
    let mut plane = Plane::new(Programme::Pass, as_seen);
    feed(&mut plane, &syn(51101), 1);
    feed(
        &mut plane,
        &asks(51101, &hello_bytes(&sni_ext(b"rutracker.org"))),
        2,
    );

    assert_eq!(plane.name_hint_of(Addr(OTHER)), None);
}

/// СОЕДИНЕНИЕ БЕЗ ИМЕНИ НЕ СТИРАЕТ УЖЕ ИЗВЕСТНОЕ. К одному адресу ходят и с hello, и без него
/// (докачка, повторное соединение по IP), и второе не должно отбирать знание, добытое первым.
#[test]
fn a_nameless_connection_does_not_erase_a_name_already_learned() {
    let mut plane = Plane::new(Programme::Pass, as_seen);
    feed(&mut plane, &syn(51102), 1);
    feed(
        &mut plane,
        &asks(51102, &hello_bytes(&sni_ext(b"rutracker.org"))),
        2,
    );
    feed(&mut plane, &syn(51103), 3);
    feed(&mut plane, &asks(51103, b"opaque bytes"), 4);

    assert_eq!(plane.name_hint_of(Addr(SERVER)), Some("rutracker.org"));
}

/// ГЛАВНЫЙ ЗАКОН #317, ПРОВЕРЕННЫЙ НА ЖИВЫХ БАЙТАХ ПЛОСКОСТИ: знание, записанное под ИМЕНЕМ,
/// применяется к соединению, которое пошло на ДРУГОЙ адрес той же цели.
///
/// Это ровно тот эпизод, которым живой прогон 31.08 опроверг подъём адреса: беда наблюдалась на
/// `104.21.32.39`, туда же ушёл подъём, а следующий хендшейк отправился на `172.67.182.196` —
/// мимо ноги, при исправной петле и записанном знании («пакетов ногой 0»).
#[test]
fn knowledge_taught_by_name_reaches_a_conversation_on_another_address() {
    let mut plane = Plane::new(Programme::Pass, as_seen);
    plane.teach_name(
        "rutracker.org",
        Programme::Mark(Mark(0x2000_0001)),
        Basis::Measured,
        Interest::Idle,
    );

    // ДРУГОЙ АДРЕС ТОЙ ЖЕ ЦЕЛИ: про него плоскость не слышала вовсе.
    let syn_other = frame(CLIENT, OTHER, 51200, SERVER_PORT, 0x02, b"");
    let hello_other = frame(
        CLIENT,
        OTHER,
        51200,
        SERVER_PORT,
        0x18,
        &hello_bytes(&sni_ext(b"rutracker.org")),
    );

    assert_eq!(
        feed(&mut plane, &syn_other, 1),
        Act::Pass,
        "на SYN имени ещё нет — знание неприменимо"
    );
    assert_eq!(
        feed(&mut plane, &hello_other, 2),
        Act::Marked(Mark(0x2000_0001)),
        "имя названо — знание обязано примениться НА ЭТОМ ЖЕ пакете"
    );
}

/// КОНТРОЛЬ К ПРЕДЫДУЩЕМУ: на общем адресе CDN знание об одном имени НЕ накрывает другое.
///
/// Это вторая половина вреда, названного в #317: подъём адреса `188.114.96.1` применил бы страту
/// к 69 посторонним доменам (замер `dig` 31.08). Здесь два разговора идут на ОДИН адрес и
/// получают разное — потому что решает имя, а не адрес.
#[test]
fn a_shared_address_does_not_spread_knowledge_to_a_stranger() {
    let mut plane = Plane::new(Programme::Pass, as_seen);
    plane.teach_name(
        "rutracker.org",
        Programme::Mark(Mark(0x2000_0001)),
        Basis::Measured,
        Interest::Idle,
    );

    feed(&mut plane, &syn(51300), 1);
    let ours = feed(
        &mut plane,
        &asks(51300, &hello_bytes(&sni_ext(b"rutracker.org"))),
        2,
    );

    feed(&mut plane, &syn(51301), 3);
    let stranger = feed(
        &mut plane,
        &asks(51301, &hello_bytes(&sni_ext(b"example.com"))),
        4,
    );

    assert_eq!(ours, Act::Marked(Mark(0x2000_0001)));
    assert_eq!(
        stranger,
        Act::Pass,
        "сосед по адресу получил чужую страту — ровно то, чем #317 назван"
    );
}

/// ИМЯ ПРИНАДЛЕЖИТ РАЗГОВОРУ, А НЕ АДРЕСУ. Два соединения на один адрес носят каждое своё имя, и
/// подсказка по адресу (та, что хранит последнего говорившего) им не указ.
#[test]
fn each_conversation_carries_its_own_name_on_a_shared_address() {
    let mut plane = Plane::new(Programme::Pass, as_seen);
    feed(&mut plane, &syn(51400), 1);
    feed(
        &mut plane,
        &asks(51400, &hello_bytes(&sni_ext(b"rutracker.org"))),
        2,
    );
    feed(&mut plane, &syn(51401), 3);
    feed(
        &mut plane,
        &asks(51401, &hello_bytes(&sni_ext(b"example.com"))),
        4,
    );

    let first = flow_of(51400);
    let second = flow_of(51401);
    assert_eq!(plane.name_of_flow(first), Some("rutracker.org"));
    assert_eq!(plane.name_of_flow(second), Some("example.com"));
    // ПОДСКАЗКА ПО АДРЕСУ ХРАНИТ ПОСЛЕДНЕГО — и теперь об этом есть ЧИСЛО, а не молчание.
    assert_eq!(plane.name_hint_of(Addr(SERVER)), Some("example.com"));
    assert_eq!(plane.name_collisions(), 1);
}

/// ЗНАМЕНАТЕЛЬ СЛЕПОЙ ЗОНЫ СЧИТАЕТСЯ ПО РАЗГОВОРАМ (#317, условие смерти тикета).
///
/// «Имени нет» имеет две причины, и они разведены: приветствие прошло без имени (`Silent`) против
/// «о личности не сказано ничего» (`Awaited`).
#[test]
fn the_denominator_of_the_blind_zone_is_counted_per_conversation() {
    let mut plane = Plane::new(Programme::Pass, as_seen);

    feed(&mut plane, &syn(52000), 1);
    feed(
        &mut plane,
        &asks(52000, &hello_bytes(&sni_ext(b"rutracker.org"))),
        2,
    );

    // Приветствие есть, имени в нём нет: ECH, вырезанный SNI, чужой разрез.
    feed(&mut plane, &syn(52001), 3);
    feed(&mut plane, &asks(52001, &hello_bytes(&[])), 4);

    feed(&mut plane, &syn(52002), 5);

    let (spoken, silent, awaited) = plane.naming_shares();
    assert_eq!(spoken, 1, "назвавшийся разговор не посчитан");
    assert_eq!(silent, 1, "приветствие без имени не посчитано");
    assert_eq!(awaited, 1, "разговор, не сказавший ничего, не посчитан");
    assert_eq!(
        spoken + silent + awaited,
        3,
        "сумма долей разошлась с числом разговоров: {spoken}/{silent}/{awaited}"
    );
}

/// ГРАНИЦА ПРИБОРА, НАЗВАННАЯ ТЕСТОМ: разговор, не говорящий TLS, в долю безымянных НЕ ПОПАДАЕТ.
///
/// Он остаётся в `Awaited` навсегда — и это честно ровно в одном смысле: плоскость не может знать,
/// что приветствия НЕ БУДЕТ, она может знать лишь, что его ещё не было. Отличить «не-TLS» от
/// «приветствие впереди» можно только порогом по времени или числу пакетов, а порог ставится в
/// разрыве замера, которого у нас нет.
///
/// ЦЕНА НАЗВАНА, И ОНА ТА САМАЯ, ПРО КОТОРУЮ СПРАШИВАЛ ВЛАДЕЛЕЦ: звонки Telegram и всякий коннект
/// по чистому IP попадают сюда, а не в `Silent`. Значит числитель слепой зоны СЕГОДНЯ ЗАНИЖЕН, и
/// величина занижения неизвестна — она и есть та доля, которую надо мерить в поле, а не выводить.
#[test]
fn a_conversation_that_never_speaks_tls_stays_in_the_awaited_share() {
    let mut plane = Plane::new(Programme::Pass, as_seen);

    feed(&mut plane, &syn(52050), 1);
    feed(&mut plane, &asks(52050, b"not a tls record at all"), 2);
    feed(&mut plane, &asks(52050, b"still not"), 3);

    let (spoken, silent, awaited) = plane.naming_shares();
    assert_eq!((spoken, silent, awaited), (0, 0, 1));
}

/// ПЕРЕЕЗД ПО ЛИЧНОСТИ НЕ УДВАИВАЕТ РАЗГОВОР. Знание растёт join'ом, значит `Silent → Spoken`
/// законен; посчитай мы состояние вместо перехода — сумма долей превысила бы число разговоров, и
/// «доля» перестала бы быть долей.
#[test]
fn a_conversation_that_names_itself_late_leaves_the_silent_share() {
    let mut plane = Plane::new(Programme::Pass, as_seen);

    feed(&mut plane, &syn(52100), 1);
    // Приветствие без имени: TLS-запись есть, SNI в ней нет.
    feed(&mut plane, &asks(52100, &hello_bytes(&[])), 2);
    let after_silence = plane.naming_shares();

    // Позднее имя — пересборка разреза либо ретрансмиссия.
    feed(
        &mut plane,
        &asks(52100, &hello_bytes(&sni_ext(b"rutracker.org"))),
        3,
    );
    let (spoken, silent, awaited) = plane.naming_shares();

    assert_eq!(after_silence.1, 1, "безымянное приветствие не посчитано");
    assert_eq!(spoken, 1);
    assert_eq!(
        silent, 0,
        "разговор остался в доле безымянных после того, как назвался"
    );
    assert_eq!(spoken + silent + awaited, 1);
}

/// ХВОСТ ЗАКРЫВШЕГОСЯ РАЗГОВОРА ОБЯЗАН НЕСТИ ТО ЖЕ РЕШЕНИЕ (#300, утверждение 1 DoD).
///
/// После `FIN` шаг возвращает `Cursor::Fresh`, а плоскость запоминает `Cursor::Lost`, и на `Lost`
/// шаг отвечает `Act::Pass` безусловно. Значит последний `ACK` (и всякая ретрансмиссия) уходит
/// МИМО ноги, хотя цель выучена и решение по ней принято.
///
/// Прежний механизм этого не имел: решение исполняло ядро по членству адреса в множестве, а
/// членство состояния курсора не знает. Перенос решения в плоскость (`df7b3e78`) сделал его
/// зависимым от автомата, у которого есть терминальное состояние.
#[test]
fn hvost_zakryvshegosya_razgovora_neset_to_zhe_reshenie() {
    let mut plane = Plane::new(Programme::Mark(Mark(0xCC)), as_seen);
    plane.teach_unnamed(
        Addr(SERVER),
        Programme::Mark(Mark(0xCC)),
        Basis::Measured,
        Interest::Idle,
    );

    assert_eq!(feed(&mut plane, &syn(51900), 1), Act::Marked(Mark(0xCC)));
    assert_eq!(
        feed(&mut plane, &asks(51900, b"hello"), 2),
        Act::Marked(Mark(0xCC))
    );
    assert_eq!(feed(&mut plane, &fin(51900), 3), Act::Marked(Mark(0xCC)));

    assert_eq!(
        feed(&mut plane, &asks(51900, b""), 4),
        Act::Marked(Mark(0xCC)),
        "последний ACK ушёл БЕЗ метки: решение перестаёт применяться на хвосте разговора"
    );
}

/// «СМОТРЕЛИ И ЗАБЫЛИ» ОТЛИЧАЕТСЯ ОТ «НЕ СМОТРЕЛИ» (#320, найдено ЖИВОЙ ТАБЛИЦЕЙ 03.09).
///
/// Уборка удаляла курсор, и дальше запись строки находила conntrack без курсора — то есть ставила
/// `Watched::Never`, «через очередь не шёл». Таблица честно печатала «не видели» про разговоры,
/// которые плоскость наблюдала: 37 пакетов на 8 флоу, и все три строки объявили нас слепыми.
///
/// `Never` и `Lost` — разные факты, и человек читает разницу: первое про нашу СЛЕПОТУ, второе про
/// нашу ЗАБЫВЧИВОСТЬ. Слив их, доля «не видели» — главное число приёмки — завышается на все
/// короткие разговоры, и мерить ею нельзя ничего.
#[test]
fn a_conversation_we_watched_and_forgot_is_not_one_we_never_saw() {
    let mut plane = Plane::new(Programme::Pass, as_seen);
    feed(&mut plane, &syn(43000), 0);
    let flow = flow_of(43000);
    assert!(
        matches!(plane.cursor_of(flow), Cursor::Running(_)),
        "предпосылка: разговор наблюдается"
    );

    // ТИШИНА ДЛИННЕЕ ГОРИЗОНТА — уборка обязана забыть разговор, но НЕ обязана забыть, что
    // видела его.
    plane.tick(Tick(reflex_engine::meter::horizon().0 * 2));
    assert_eq!(
        plane.cursor_of(flow),
        Cursor::Lost,
        "выселенный курсор исчез бесследно — запись скажет «через очередь не шёл» про разговор, \
         который мы видели"
    );

    // ВТОРОЙ ГОРИЗОНТ — забытый уходит совсем, и вот ТОГДА `Never` честен: столько времени спустя
    // мы и правда не знаем, шёл ли он через нас.
    //
    // ТИКОВ НЕСКОЛЬКО, И ЭТО СВОЙСТВО УБОРКИ, а не слабость проверки: она идёт ПО КРУГУ с
    // потолком (`SWEEP_BUDGET`), продолжая с сохранённого ключа. Один проход осматривает часть
    // карты, и до нашего разговора очередь доходит не сразу. Ждать «немедленно» значило бы
    // требовать обхода всей карты на каждом шаге — той самой работы, пропорциональной числу
    // целей, которой невод 1 сжигал ядро.
    (0..3).for_each(|_pass| {
        plane.tick(Tick(reflex_engine::meter::horizon().0 * 5));
    });
    assert_eq!(
        plane.cursor_of(flow),
        Cursor::Fresh,
        "забытый разговор держится в карте вечно — потолок перестал ограничивать память"
    );
}

/// ИМЯ ЦЕЛИ ДОЕЗЖАЕТ С НАБЛЮДЕНИЕМ, а не спрашивается отдельно (#320, Т5).
///
/// Потребитель, получивший наблюдение, обязан знать, о КОМ оно, — иначе таблица печатает адрес
/// вместо имени. Восстанавливать имя на его стороне запрещено: своя карта адрес→имя есть второй
/// источник правды о цели, и им уже оплачен ключ памяти (1136 флоу из 1136 мимо).
#[test]
fn the_name_travels_with_the_sighting() {
    let mut plane = Plane::new(Programme::Pass, as_seen);
    feed(&mut plane, &syn(41000), 0);
    feed(
        &mut plane,
        &asks(41000, &hello_bytes(&sni_ext(b"rutracker.org"))),
        1,
    );

    let told = plane.drain();
    assert!(
        told.iter().any(|noted| matches!(
            &noted.target,
            reflex_engine::row::Naming::Spoken(name) if name.as_ref() == "rutracker.org"
        )),
        "наблюдение приехало без имени — потребителю остаётся адрес: {told:?}"
    );
}

/// ТРИ СОСТОЯНИЯ ЛИЧНОСТИ НЕ СЛИВАЮТСЯ В `None`.
///
/// «Имени не будет» (`Silent` — коннект по IP, MTProto, ECH) и «имени ещё нет» (`Awaited`)
/// лечатся по-разному, и в приёмочном приборе пустая клетка есть ВЕРДИКТ о датаплейне, а не
/// пропуск в показе. `Option<&str>` отдал бы `None` на оба — та же болезнь, что уже лечилась у
/// `Naming` в самом ядре.
#[test]
fn a_nameless_hello_is_not_the_same_as_no_hello_yet() {
    let mut plane = Plane::new(Programme::Pass, as_seen);
    feed(&mut plane, &syn(42000), 0);
    // Приветствие прошло, имени в нём нет: полезная нагрузка не похожа на `ClientHello`.
    feed(&mut plane, &asks(42000, b"not a hello at all"), 1);

    let told = plane.drain();
    assert!(
        !told.is_empty(),
        "предпосылка: наблюдения на разговоре были"
    );
    assert!(
        told.iter()
            .all(|noted| !matches!(&noted.target, reflex_engine::row::Naming::Spoken(_))),
        "разговор без имени приехал названным: {told:?}"
    );
}

/// ВРЕМЯ ИДЁТ БЕЗ ЕДИНОГО ПАКЕТА — и плоскость наконец это замечает (#323, срез 3 эпика #320).
///
/// # Что здесь доказывается, и почему это не «ещё один тест уборки»
///
/// Мёртвая нога умирает В ТИШИНЕ: цель перестаёт отвечать ровно тогда, когда трафика нет.
/// Плоскость до сих пор двигалась чужим пакетом — `Tick` вычислялся внутри обработчика, а уборка
/// вдобавок висела на СЧЁТЕ пакетов. Значит всё, что судит о тишине, в тишине и не срабатывало:
/// у `Sighting::Lost` не было производителя в живом коде ВОВСЕ, и это записано в его собственном
/// паспорте («восемь исходов, достижимы семь»).
///
/// Ниже — ровно тот сценарий, который прежде выразить было нечем: разговор состоялся, ПАКЕТЫ
/// КОНЧИЛИСЬ, время прошло. Ни одного `feed` после первого.
#[test]
fn a_target_lost_in_silence_is_spoken_about() {
    let mut plane = Plane::new(Programme::Pass, as_seen);
    feed(&mut plane, &syn(40000), 0);
    plane.drain();

    // ТИШИНА ДЛИННЕЕ ГОРИЗОНТА. Часы идут, пакетов нет — ход, невозможный до этого среза.
    let told = plane.tick(Tick(reflex_engine::meter::horizon().0 * 2));

    assert!(
        told.iter()
            .any(|noted| matches!(noted.what, Sighting::Lost { dst } if dst == Addr(SERVER))),
        "цель пропала молча: за горизонтом тишины плоскость не сказала о ней ничего, {told:?}"
    );
}

/// ЧАСЫ, КОТОРЫЕ ПРОШЛИ НЕ ВЕСЬ ГОРИЗОНТ, НИКОГО НЕ ХОРОНЯТ.
///
/// Пара к предыдущему, и без неё тот зеленел бы у плоскости, объявляющей потерянным кого угодно.
/// Различение здесь и есть предмет: `Lost` обязан значить «цель замолчала надолго», а не «была
/// уборка».
#[test]
fn a_target_still_within_the_horizon_is_not_buried() {
    let mut plane = Plane::new(Programme::Pass, as_seen);
    feed(&mut plane, &syn(40000), 0);
    plane.drain();

    let told = plane.tick(Tick(reflex_engine::meter::horizon().0 / 2));

    assert!(
        !told
            .iter()
            .any(|noted| matches!(noted.what, Sighting::Lost { .. })),
        "живую цель похоронили на половине горизонта: {told:?}"
    );
}

/// ПРИКАЗ ОБОРВАТЬ ДОЕЗЖАЕТ ДО РАЗГОВОРОВ ЦЕЛИ — первая дверь к обрыву (#326).
///
/// `Ordered::Sever` был выражен в законе шага целиком — от приказа до наблюдения его исполнения —
/// и НЕ ПРОИЗВОДИЛСЯ НИКЕМ: поставить его было некому, потому что приказ адресован ЦЕЛИ, а рвутся
/// РАЗГОВОРЫ, и двери между ними у плоскости не существовало.
///
/// Контроль в том же тесте обязателен: сосед, о котором приказа не было, продолжает жить. Без
/// него проверка прошла бы и у реализации, рвущей всё подряд, — а рвать живое чужой цели значит
/// делать ровно то, чем нас бьёт ТСПУ.
#[test]
fn an_order_to_sever_reaches_the_conversations_of_that_target() {
    let mut plane = Plane::new(Programme::Pass, as_seen);

    feed(&mut plane, &syn(51300), 1);
    feed(
        &mut plane,
        &asks(51300, &hello_bytes(&sni_ext(b"rutracker.org"))),
        2,
    );
    feed(&mut plane, &syn(51301), 3);
    feed(
        &mut plane,
        &asks(51301, &hello_bytes(&sni_ext(b"habr.com"))),
        4,
    );

    assert_eq!(
        plane.sever_named("rutracker.org"),
        1,
        "приказ не нашёл ни одного разговора цели — подъём с цели на её разговоры не работает"
    );

    assert_eq!(
        feed(&mut plane, &asks(51300, b"next"), 5),
        Act::Sever,
        "приказ лёг в состояние, но следующий пакет разговора его не унёс"
    );
    assert_ne!(
        feed(&mut plane, &asks(51301, b"next"), 6),
        Act::Sever,
        "оборван сосед, о котором приказа не было"
    );
}

/// ПРИКАЗ О ЦЕЛИ, С КОТОРОЙ НИКТО НЕ ГОВОРИТ, НИЧЕГО НЕ РВЁТ — И ГОВОРИТ ОБ ЭТОМ ЧИСЛОМ.
///
/// Ноль здесь законный: приказ мог опоздать ровно на конец разговора. Важно, что он ОТЛИЧИМ от
/// единицы, иначе «оборвали» и «рвать было нечего» слились бы в одну строку журнала.
#[test]
fn an_order_about_a_silent_target_severs_nothing() {
    let mut plane = Plane::new(Programme::Pass, as_seen);
    feed(&mut plane, &syn(51400), 1);
    feed(
        &mut plane,
        &asks(51400, &hello_bytes(&sni_ext(b"rutracker.org"))),
        2,
    );

    assert_eq!(plane.sever_named("example.com"), 0);
}
