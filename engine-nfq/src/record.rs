//! ЗАПИСЬ: строка на (цель × узел).
//!
//! # Почему спина — conntrack, а не плоскость
//!
//! Обход идёт по записям ЯДРА, и плоскость только украшает найденное. Наоборот было бы нельзя по
//! двум причинам, и вторая важнее первой:
//!
//! 1. плоскость не знает адреса разговора вовсе — `Run` его не носит, а conntrack носит четвёрку;
//! 2. плоскость видит лишь то, что дошло до очереди. Пойди обход от неё — строка существовала бы
//!    только у завёрнутого трафика, и таблица «что вообще происходит на коробке» осталась бы
//!    обещанием. Ядро видит всё, чем бы мы себя ни ослепили.
//!
//! # Ключ считает ТА ЖЕ функция
//!
//! `parse::keyed` вызывается здесь, а не переписывается: ключ, добываемый на каждой стороне своим
//! способом, расходится молча — оплачено 1136 флоу из 1136 мимо памяти.

use std::collections::BTreeMap;

use reflex_engine::row::{keyed, net_of, Counted, Naming, Sight, TargetKey, Told};
use reflex_engine::{Addr, Cursor, Tick};
use reflex_linux::conntrack::Entry;

use crate::parse;
use crate::plane::Plane;

const TCP: u8 = 6;

/// ТИП УЗЛА И ЗАКОН ЕГО СБОРКИ ПЕРЕЕХАЛИ ЗА ДВЕРЬ (#320, Т4).
///
/// Здесь остаётся только ДОБЫЧА — то, ради чего нужен netfilter. Прежде рядом с ней лежал и тип,
/// и всякий, кому надо было ЗНАТЬ, КАК ВЫГЛЯДИТ СТРОКА, обязан был зависеть от Linux.
pub use reflex_engine::row::{merged, node_of, sooner, watched_of, Node, Watched};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    pub key: TargetKey<Box<str>>,
    /// УЗЛЫ ИМЕНИ НЕ НЕСУТ — оно в ключе строки, внутри которой они и приходят. Заведённое было
    /// поле снято в тот же день: на именной ветви оно тождественно ключу, на безымянной —
    /// недетерминированная выборка (см. докблок `row::Node`).
    pub nodes: Vec<Node>,
}

/// СНИМОК ЦЕЛИКОМ.
///
/// `lost_sightings` живёт ЗДЕСЬ, а не в строке, и это не мелочь: канал наблюдений лоссовый, счётчик
/// потерь общий на коробку, и разложить его по строкам нечем. Приписать его строке значило бы
/// утверждать больше установленного; убрать вовсе — дать ленте событий врать умолчанием.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub rows: Vec<Row>,
    pub lost_sightings: u64,
    /// СКОЛЬКО РАЗГОВОРОВ ПЛОСКОСТЬ ЗАБЫЛА — величина, а не вердикт.
    ///
    /// Едет в снимок рядом со строками, потому что отвечает на вопрос, который иначе задать
    /// некому: сколько «не видели» в таблице есть наша СЛЕПОТА, а сколько — наша ЗАБЫВЧИВОСТЬ.
    /// Число само по себе ничего не объявляет; вывод делает оператор, глядя на него рядом с долей
    /// слепых строк.
    pub evicted_cursors: u64,
    /// То же про цели: карта целей тоже с потолком, и её уборка тоже видна в таблице пустотой.
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

/// УЗЕЛ ИЗ ЗАПИСИ ЯДРА. Вся добыча здесь и только здесь: `Entry` даёт адрес и счёт, дальше
/// работает общий закон, который netfilter не знает.
///
/// МОМЕНТ ПОСЛЕДНЕГО НАБЛЮДЕНИЯ ПРИХОДИТ ОТ ПЛОСКОСТИ: conntrack его не отдаёт (в `Entry` только
/// четвёрка, счётчики и метка), а запись ядра актуальна на момент снимка по построению — значит
/// расхождение «сейчас» и этого момента и есть слепота второго рода, которую счёт не ловит.
fn node_from(entry: &Entry, cursor: Cursor, seen: Option<Tick>) -> Node {
    node_of(Addr(entry.orig.dst), counted_of(entry), cursor, seen)
}

/// ЗАПИСЬ ИЗ ДВУХ ИСТОЧНИКОВ, каждый в своей роли: ядро отвечает «сколько», плоскость — «кто, чем
/// и на каком основании».
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
                // РАЗЛИЧИТЕЛЬ БЕРЁТСЯ ЦЕЛИКОМ, А НЕ ЧЕРЕЗ ИМЯ. Для КЛЮЧА это сегодня всё равно:
                // `keyed` проецирует `Silent` и `Awaited` в один `Unnamed` (теорема, краснеет
                // тестом `ozhidanie_imeni_i_ego_otsutstvie_dayut_odnu_stroku`), и обезоруживание
                // подмены здесь ничего не красит — сказано, чтобы не считалось проверенным.
                // Взято тем не менее целиком: `name_of_flow` сливает две причины безымянности
                // НЕОБРАТИМО, и разойдись ширина ключа или его арность — подмена стала бы враньём
                // молча. Различение при этом не пропадает: оно доезжает до узла через `Watched`.
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

/// СНИМОК ПОСТРОЧНО — то, что показ читает с другого конца канала (#320).
///
/// # Почему построчно, а не JSON
///
/// Формат выбран ЗАКАЗЧИКОМ показа, и довод его: разбор JSON на его стороне потребовал бы
/// `serde`, то есть согласования зависимости с владельцем — а ждать согласования там, где нужен
/// результат, дороже разницы форматов. Построчное читается тридцатью строками без единой
/// зависимости с обеих сторон.
///
/// Вложенность выражена ПРЕФИКСОМ строки: `target`, за ним его `node`-строки. Глубже двух уровней
/// в снимке нет, и городить синтаксис под несуществующую глубину незачем.
///
/// # `Told` ПРИЕЗЖАЕТ ТРЁМЯ СЛОВАМИ, и это главное требование к формату
///
/// Пропуск поля для «не ответила» и для «не имеем права судить» — одно значение с двумя смыслами,
/// та же болезнь, что `Option<&str>` у имени. У приёмочного прибора пустая клетка есть ВЕРДИКТ о
/// датаплейне: «цель молчала» и «мы не смотрели» путать нельзя. Отсюда `told:<величина>` ·
/// `nothing` · `blind` — всегда одно из трёх, никогда пропуск.
///
/// # ЧИСЛА СНИМКА — ПЕРВОЕ, ЧТО СМОТРИТ ЧИТАТЕЛЬ
///
/// `targets` и `nodes` отвечают на вопрос, который иначе неотличим: пустая таблица значит «целей
/// нет» или «снимок не собрался»? Та же роль, что у `Feed::observed` в ленте.
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
    // КЛЮЧ ЕДЕТ ГОТОВЫМ, потому что считает его ПЛОСКОСТЬ. Показ, вычисляющий ключ у себя, завёл
    // бы вторую проекцию имя→цель — ровно то, чем оплачен ключ памяти.
    let key = match &row.key {
        TargetKey::Named(name) => safe(name),
        // СЕТЬ ПИШЕТСЯ С МАСКОЙ: человек должен видеть, что строка о /24, а не об одном адресе.
        // Ширина записи — свойство ключа (`net_of`), и умолчать её значит соврать о предмете.
        TargetKey::Unnamed(Addr(net)) => format!("{}/24", dotted(*net)),
    };
    core::iter::once(format!("target {key}"))
        .chain(row.nodes.iter().map(node_line))
        .collect()
}

/// СЧЁТ В СТРОКЕ УЗЛА — ЯДРА, а не плоскости: человеку важно, сколько прошло на самом деле.
/// Насколько при этом видела плоскость, сказано отдельно (`sight`), и умолчать её нельзя — иначе
/// «прошло ноль» смешается с «мы не смотрели».
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

/// СОСТОЯНИЕ РАЗГОВОРА — четыре слова, и у `Seen` названа личность.
///
/// TODO(#320): при двух наблюдавшихся разговорах на одном адресе сюда попадает ПЕРВЫЙ по порядку
/// записей ядра — `Watched` в узле есть выборка, а не свойство (см. `row::merged`). В снимке это
/// видно так же, как в памяти, и лечится там же.
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

/// ТРИ СОСТОЯНИЯ — ТРИ СЛОВА, и ни одно не есть пропуск поля.
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

/// ИМЯ ОБЕЗВРЕЖИВАЕТСЯ, потому что приходит С ПРОВОДА.
///
/// `ClientHello` присылает противник, и в построчном формате опасны ровно две вещи: ПЕРЕВОД
/// СТРОКИ (строка снимка перестала бы быть одной строкой, и читатель принял бы хвост имени за
/// новую запись) и ПРОБЕЛ (поля разделены им, и имя с пробелом сдвинуло бы разбор). Ослепить
/// показ содержимым чужого пакета — дешёвая атака, если о ней не подумать.
///
/// Заменяем, а не отбрасываем: имя, из которого молча вырезали символы, читается как настоящее.
fn safe(text: &str) -> String {
    text.chars()
        .map(|letter| match letter {
            ' ' | '\t' => '_',
            control if control.is_control() => '?',
            plain => plain,
        })
        .collect()
}
