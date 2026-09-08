//! Запись: строка на (цель × узел). Обход идёт по записям ЯДРА, плоскость лишь украшает найденное.
//! Наоборот нельзя: плоскость не знает адреса разговора (`Run` не носит четвёрку, conntrack носит)
//! и видит лишь дошедшее до очереди — обход от неё оставил бы строку только у завёрнутого трафика.
//! Ключ считает `parse::keyed` здесь же, не переписывается: ключ на каждой стороне своим способом
//! разошёлся бы молча (1136 флоу из 1136 мимо памяти).

use std::collections::BTreeMap;

use reflex_engine::row::{keyed, net_of, Counted, Naming, Sight, TargetKey, Told};
use reflex_engine::{Addr, Cursor, Tick};
use reflex_linux::conntrack::Entry;

use crate::parse;
use crate::plane::Plane;

const TCP: u8 = 6;

/// Тип узла и закон его сборки переехали за дверь (#320, Т4). Здесь — только добыча, ради которой
/// нужен netfilter; рядом с ней тип заставлял всякого, кому надо знать вид строки, зависеть от Linux.
pub use reflex_engine::row::{merged, node_of, sooner, watched_of, Node, Watched};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    pub key: TargetKey<Box<str>>,
    /// Узлы имени не несут — оно в ключе строки. На именной ветви поле было бы тождественно ключу,
    /// на безымянной — недетерминированная выборка (см. `row::Node`).
    pub nodes: Vec<Node>,
}

/// Снимок целиком. `lost_sightings` живёт здесь, а не в строке: канал наблюдений лоссовый, счётчик
/// потерь общий на коробку, разложить по строкам нечем — приписать строке значило бы утверждать
/// больше установленного, убрать вовсе — дать ленте врать умолчанием.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub rows: Vec<Row>,
    pub lost_sightings: u64,
    /// Сколько разговоров плоскость забыла — величина, а не вердикт. Отвечает, сколько «не видели»
    /// есть наша СЛЕПОТА, а сколько — ЗАБЫВЧИВОСТЬ; вывод делает оператор рядом с долей слепых строк.
    pub evicted_cursors: u64,
    /// То же про цели: карта целей тоже с потолком, её уборка тоже видна в таблице пустотой.
    pub evicted_targets: u64,
}

fn counted_of(entry: &Entry) -> Counted {
    Counted {
        up: entry.orig_counts.packets,
        up_bytes: entry.orig_counts.bytes,
        down: entry.reply_counts.packets,
        down_bytes: entry.reply_counts.bytes,
    }
}

/// Узел из записи ядра. Вся добыча здесь и только здесь: `Entry` даёт адрес и счёт, дальше общий
/// закон, netfilter его не знает. Момент последнего наблюдения приходит от плоскости (conntrack его
/// не отдаёт) — расхождение «сейчас» и актуального по построению момента ядра и есть слепота второго
/// рода, которую счёт не ловит.
fn node_from(entry: &Entry, cursor: Cursor, seen: Option<Tick>) -> Node {
    node_of(Addr(entry.orig.dst), counted_of(entry), cursor, seen)
}

/// Запись из двух источников: ядро отвечает «сколько», плоскость — «кто, чем и на каком основании».
pub fn record(plane: &Plane, seen: &[Entry], server_port: u16) -> Record {
    let grouped = seen
        .iter()
        .filter(|entry| entry.orig.proto == TCP && entry.orig.dst_port == server_port)
        .fold(
            BTreeMap::<TargetKey<Box<str>>, BTreeMap<Addr, Node>>::new(),
            |mut so_far, entry| {
                let flow = parse::keyed(
                    entry.orig.src,
                    entry.orig.src_port,
                    entry.orig.dst,
                    entry.orig.dst_port,
                );
                // Различитель берётся целиком, а не через имя. Для КЛЮЧА это сегодня всё равно
                // (`keyed` проецирует `Silent` и `Awaited` в один `Unnamed` — теорема, краснеет
                // тестом `ozhidanie_imeni_i_ego_otsutstvie_dayut_odnu_stroku`). Целиком тем не
                // менее: `name_of_flow` сливает две причины безымянности необратимо, и разойдись
                // ширина/арность ключа — подмена стала бы враньём молча. Различение доезжает до
                // узла через `Watched`.
                let key = keyed(plane.naming_of_flow(flow), Addr(entry.orig.dst), net_of);
                let node = node_from(entry, plane.cursor_of(flow), plane.seen_at_of(flow));
                let nodes = so_far.entry(key).or_default();
                let held = nodes.remove(&node.dst);
                nodes.insert(
                    node.dst,
                    match held {
                        Some(already) => merged(already, node),
                        None => node,
                    },
                );
                so_far
            },
        );
    Record {
        rows: grouped
            .into_iter()
            .map(|(key, nodes)| Row {
                key,
                nodes: nodes.into_values().collect(),
            })
            .collect(),
        lost_sightings: plane.dropped_sightings(),
        evicted_cursors: plane.evicted_cursors(),
        evicted_targets: plane.evicted_targets(),
    }
}

/// Снимок построчно — то, что показ читает с другого конца канала (#320). Формат выбран заказчиком:
/// JSON потребовал бы `serde` с обеих сторон, построчное читается тридцатью строками без единой
/// зависимости. Вложенность — префиксом (`target`, за ним его `node`-строки); глубже двух уровней
/// нет. `Told` приезжает тремя словами (`told:<величина>` · `nothing` · `blind`), никогда пропуском
/// поля: у приёмочного прибора пустая клетка — вердикт, «цель молчала» и «мы не смотрели» путать
/// нельзя. Числа снимка первыми: пустая таблица иначе неотличима — «целей нет» или «не собрался».
pub fn as_lines(record: &Record, at: Tick) -> String {
    let nodes: usize = record.rows.iter().map(|row| row.nodes.len()).sum();
    let head = format!(
        "snapshot targets={} nodes={} lost_sightings={} evicted_cursors={} evicted_targets={} at={}",
        record.rows.len(),
        nodes,
        record.lost_sightings,
        record.evicted_cursors,
        record.evicted_targets,
        at.0
    );
    core::iter::once(head)
        .chain(record.rows.iter().flat_map(row_lines))
        .collect::<Vec<String>>()
        .join("\n")
}

/// Строки одной цели: сама цель, за ней её узлы.
fn row_lines(row: &Row) -> Vec<String> {
    // Ключ едет готовым: считает его плоскость. Показ, вычисляющий ключ у себя, завёл бы вторую
    // проекцию имя→цель — то, чем оплачен ключ памяти.
    let key = match &row.key {
        TargetKey::Named(name) => safe(name),
        // Сеть пишется с маской: человек должен видеть, что строка о /24. Ширина — свойство ключа
        // (`net_of`), умолчать её значит соврать о предмете.
        TargetKey::Unnamed(Addr(net)) => format!("{}/24", dotted(*net)),
    };
    core::iter::once(format!("target {key}"))
        .chain(row.nodes.iter().map(node_line))
        .collect()
}

/// Счёт в строке узла — ЯДРА, а не плоскости: человеку важно, сколько прошло на самом деле.
/// Насколько видела плоскость, сказано отдельно (`sight`) — иначе «прошло ноль» смешается с «не
/// смотрели».
fn node_line(node: &Node) -> String {
    format!(
        "node {} spoke={} seen={} up={}/{} down={}/{} sight={} watched={} flows={}",
        dotted(node.dst.0),
        told_word(&node.spoke, |span| span.0.to_string()),
        told_word(&node.plane_seen, |at| at.0.to_string()),
        node.kernel.up,
        node.kernel.up_bytes,
        node.kernel.down,
        node.kernel.down_bytes,
        sight_word(&node.sight),
        watched_word(&node.watched),
        node.flows
    )
}

fn sight_word(sight: &Sight) -> String {
    match sight {
        Sight::Full => "full".to_string(),
        Sight::Partial {
            missed_up,
            missed_down,
        } => format!("partial:{missed_up}/{missed_down}"),
    }
}

/// Состояние разговора — четыре слова, у `Seen` названа личность.
///
/// TODO(#320): при двух наблюдавшихся разговорах на одном адресе сюда попадает ПЕРВЫЙ по порядку
/// записей ядра — `Watched` в узле есть выборка, а не свойство (см. `row::merged`); лечится там же.
fn watched_word(watched: &Watched) -> String {
    match watched {
        Watched::Never => "never".to_string(),
        Watched::Ended(_) => "ended".to_string(),
        Watched::Lost => "lost".to_string(),
        Watched::Seen { naming, .. } => match naming {
            Naming::Spoken(()) => "seen:spoken".to_string(),
            Naming::Silent => "seen:silent".to_string(),
            Naming::Awaited => "seen:awaited".to_string(),
        },
    }
}

/// Три состояния — три слова, ни одно не есть пропуск поля.
fn told_word<T>(told: &Told<T>, value: impl FnOnce(&T) -> String) -> String {
    match told {
        Told::Told(held) => format!("told:{}", value(held)),
        Told::Nothing => "nothing".to_string(),
        Told::Blind => "blind".to_string(),
    }
}

/// Адрес словами человека.
fn dotted(addr: u32) -> String {
    addr.to_be_bytes()
        .iter()
        .map(|octet| octet.to_string())
        .collect::<Vec<String>>()
        .join(".")
}

/// Имя обезвреживается: приходит с провода (`ClientHello` присылает противник). Опасны две вещи —
/// перевод строки (хвост имени прочёлся бы как новая запись) и пробел (сдвинул бы разбор полей).
/// Заменяем, а не отбрасываем: имя с молча вырезанными символами читается как настоящее.
fn safe(text: &str) -> String {
    text.chars()
        .map(|letter| match letter {
            ' ' | '\t' => '_',
            control if control.is_control() => '?',
            plain => plain,
        })
        .collect()
}
