# Полный входной алфавит — план работ

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** достроить входной алфавит до полного — и шов между очередью и цепочкой схлопнется сам, потому что половина того, что там стоит, существует ради невыразимого.

**Architecture:** буква `Opaque` («пришло, разобрать не смог») делает ненужным второй разбор пакета и счётчик в краю. Тик рождается только сеткой и несёт номер узла вместе с моментом. Всё, что прибывает, — буква одного алфавита; ничто не прибывает мимо него.

**Tech Stack:** Rust 2021, `smallvec`, `futures`, `tokio` (в тестах и в асинхронном драйвере).

**Spec:** `docs/superpowers/specs/2026-09-06-total-alphabet-and-pair-design.md`

---

## Global Constraints

* **Докблок не имеет права утверждать факт о текущем состоянии дерева.** Нельзя: счёт, адрес (`файл:строка`, `crate::модуль::имя`, тем более в чужой репе), «что где лежит», «снесено тогда-то», датированные замеры. Можно: контракт, закон, смысл границы, замысел. Всё счётное и адресное — **в тело коммита**. Метки тикетов (`#295`) — не нарушение: указатель на неизменяемую внешнюю запись.
* **Замер — только прогоном.** Число, полученное грепом, не идёт ни в отчёт, ни в приёмку, пока предмет не запущен: тест — прогнать, форма — скомпилировать. Подстрочный греп на предыдущей ветке четырежды давал ложные числа.
* **Приёмочный критерий прогоняется автором до отправки.** Критерий — тоже утверждение; на предыдущей ветке трижды он значил не то, что имелось в виду.
* **Тела переносятся дословно** там, где меняются только границы и подписи. Это доказательство того, что сдвинулись типы, а не поведение.
* **Снос только по инвентарю, никогда по имени файла.**
* **Три инструмента в приёмке, каждый со своей замеренной базой:** `cargo check` (база **0**), `cargo doc` (база **18** по воркспейсу), `cargo fmt --all --check` (база **11**, все в `engine`/`engine-nfq`). Ниже базы не опускать — это значило бы залезть в чужое.
* **Пока идёт исполнитель, рабочее дерево не трогает никто другой.** Замеры на других коммитах — `git show <rev>:<path>`, `git grep <rev>`, `git archive`.

---

## Замер, из которого растёт план

Все числа получены 06.09.2026 на `main` после слияния впитывания `Detector`.

| что | сколько | как |
|---|---|---|
| упоминаний `DetectorEvent` | **298** | греп по дереву |
| из них `type From = DetectorEvent…` | **27** | то же |
| крейтов затронуто | 4 (`core` 22 файла, `instrument` 15, `runtime` 6, `engine` 2) | то же |
| употреблений `Interleave` вне его тестов | **1** (`runtime/src/timed.rs`) | греп |
| употреблений `Interleave` у потребителя | **0** | греп по `nevod`, без вендоренных копий |
| разборов пакета на пути очередь → цепочка (продукт) | **2** | чтение `drive.rs` и `wire.rs` |

**Главное из замера:** правильный путь **уже написан** и почти никем не взят. `core/src/interleave.rs` вычисляет узлы сетки между пакетами и будит только в тишине; `runtime/src/timed.rs` его поднимает. Продукт вместо этого крутит `sleep(period)` после работы и накапливает дрейф.

Значит первая задача — **не построить, а сделать обязательным**.

---

## Структура файлов

| файл | ответственность после плана |
|---|---|
| `core/src/detector.rs` | входной алфавит: к `Packet`/`Tick` добавляется `Opaque` |
| `core/src/grid.rs` | узлы сетки; добавляется номер узла |
| `core/src/interleave.rs` | шов пакетов и сетки; выдаёт номер узла вместе с моментом |
| `runtime/src/timed.rs` | единственный законный источник тиков для асинхронного драйвера |
| `core/src/parse.rs` (новый) | причина непонимания как значение — общая для бэкендов |

## Порядок задач

Задачи 1–2 **аддитивны**: ничего не ломают, дерево зелёное после каждой. Задача 3 добавляет вариант перечисления и потому ломает всякий исчерпывающий `match` — компилятор находит их все, и это ожидаемо. Задача 4 живёт в **чужой репе** и выполняется последней.

---

## Задача 1: сетка перестаёт быть необязательной

**Files:**
- Modify: `runtime/src/timed.rs`
- Test: `runtime/tests/grid.rs` (создать)

**Interfaces:**
- Consumes: `reflex_core::interleave::Interleave`, `reflex_core::grid::node`
- Produces: `runtime::timed::on_grid(source, began, every) -> impl Stream<Item = DetectorEvent<T>>` — единственный способ получить поток с тиками

- [ ] **Шаг 1: снять контрольные числа**

```bash
cd /home/rcd/Workspace/reflex
cargo test --workspace --all-features 2>&1 | grep "^test result" | awk '{p+=$4; f+=$6} END {print "наборов:", NR, "прошло:", p, "провалов:", f}'
grep -rn "Interleave" --include=*.rs . --exclude-dir=target | grep -v "core/src/interleave.rs" | grep -vc "core/tests"
```
Сохранить оба числа — второе показывает, сколько мест берут шов сегодня.

- [ ] **Шаг 2: написать падающий тест — N узлов дают ровно N тиков**

Создать `runtime/tests/grid.rs`:

```rust
//! СЕТКА НЕ ЗАВИСИТ ОТ НАГРУЗКИ.
//!
//! Тик, рождённый цепочкой задержек (`sleep(шаг)` ПОСЛЕ работы), имеет период
//! `шаг + сколько работали`, и ошибка накапливается. Линейка машины растягивается тем сильнее,
//! чем выше нагрузка, — то есть окна закрываются позже именно тогда, когда это важнее всего.
//!
//! Здесь проверяется противоположное: сколько бы работы ни легло между узлами, узлов за отрезок
//! ровно столько, сколько их в отрезке.
use std::time::{Duration, Instant};

use futures::StreamExt;
use reflex_core::detector::DetectorEvent;

const STEP: Duration = Duration::from_millis(10);

/// Наблюдение с провода — свой тип, чтобы тест не зависел от словаря продукта.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Seen(u8);

#[tokio::test(start_paused = true)]
async fn nodes_do_not_depend_on_load() {
    let began = Instant::now();

    // ПАКЕТЫ ИДУТ ГУСТО И НЕРОВНО: три подряд, потом пусто. Ровно та неровность, на которой
    // цепочка задержек и разъезжается.
    let packets = futures::stream::iter(vec![
        (Seen(1), began + Duration::from_millis(1)),
        (Seen(2), began + Duration::from_millis(2)),
        (Seen(3), began + Duration::from_millis(3)),
        (Seen(4), began + Duration::from_millis(45)),
    ]);

    let mixed: Vec<DetectorEvent<Seen>> = reflex_runtime::timed::on_grid(packets, began, STEP)
        .take_until(tokio::time::sleep(Duration::from_millis(50)))
        .collect()
        .await;

    let ticks = mixed
        .iter()
        .filter(|event| matches!(event, DetectorEvent::Tick { .. }))
        .count();

    // За 45 мс при шаге 10 мс узлов ровно четыре: 10, 20, 30, 40.
    assert_eq!(ticks, 4, "узлов за отрезок столько, сколько их в отрезке");

    let seen = mixed
        .iter()
        .filter(|event| matches!(event, DetectorEvent::Packet { .. }))
        .count();
    assert_eq!(seen, 4, "ни один пакет не потерян и не задвоен");
}

#[tokio::test(start_paused = true)]
async fn silence_still_produces_nodes() {
    // МОЛЧАНИЕ — ЗАКОННЫЙ ВХОД. Без пакетов узлы обязаны идти всё равно, иначе «замолчал»
    // неотличимо от «мы не смотрели».
    let began = Instant::now();
    let empty = futures::stream::iter(Vec::<(Seen, Instant)>::new());

    let mixed: Vec<DetectorEvent<Seen>> = reflex_runtime::timed::on_grid(empty, began, STEP)
        .take_until(tokio::time::sleep(Duration::from_millis(35)))
        .collect()
        .await;

    assert_eq!(mixed.len(), 3, "в тишине узлы идут по сетке: 10, 20, 30");
}
```

- [ ] **Шаг 3: прогнать — убедиться, что не собирается**

```bash
cargo test -p reflex-runtime --test grid 2>&1 | tail -20
```
Ожидается отказ сборки: `on_grid` не существует.

- [ ] **Шаг 4: прочитать существующее, прежде чем писать**

```bash
sed -n '1,80p' runtime/src/timed.rs
```
Там уже поднимается `Interleave::started(began, every)` через `.scan(...)`. **Твоя задача — не написать заново, а дать этому имя и сделать единственным путём.** Если существующая функция уже делает то, что нужно, — переименуй и экспортируй её, а не пиши вторую. Второй правильный путь хуже одного: они разъедутся.

- [ ] **Шаг 5: дать сетке имя и сделать её единственным путём**

В `runtime/src/timed.rs`:

```rust
/// ПОТОК С ТИКАМИ — ЕДИНСТВЕННЫЙ СПОСОБ ИХ ПОЛУЧИТЬ.
///
/// # Почему источник тиков не принимается аргументом
///
/// Приняв его, мы позволили бы подать цепочку задержек: «поспать шаг ПОСЛЕ работы». У такой
/// последовательности период есть `шаг + сколько работали`, и ошибка накапливается — линейка
/// машины растягивается тем сильнее, чем выше нагрузка. Окна закрываются позже ровно тогда,
/// когда это важнее всего.
///
/// Здесь узлы ВЫЧИСЛЯЮТСЯ от начала отсчёта, а не отсчитываются от предыдущего срабатывания.
/// Заминка сдвигает узел, но не сдвигает сетку: следующий узел стоит там, где стоял.
///
/// # Отставшие узлы схлопываются
///
/// Залп из пропущенных узлов есть ошибка СОБЫТИЙНАЯ — пачка закрытий окна с одинаковым смыслом,
/// выглядящая как настоящая беда ровно под нагрузкой. Сдвиг сетки при заминке есть ошибка
/// ВЕЛИЧИНЫ, и она видна как величина.
pub fn on_grid<S, T>(
    source: S,
    began: Instant,
    every: Duration,
) -> impl futures::Stream<Item = DetectorEvent<T>>
where
    S: futures::Stream<Item = (T, Instant)>,
{
    // ТЕЛО: то, что уже стоит в этом файле. Переносится дословно.
}
```

Тело берётся из существующей реализации без изменений. Если в файле уже есть публичная функция того же смысла — **сделай `on_grid` её именем**, а старое имя убери, чтобы путей не стало два.

- [ ] **Шаг 6: прогнать**

```bash
cargo test -p reflex-runtime --test grid 2>&1 | grep "^test result"
cargo test --workspace --all-features 2>&1 | grep "^test result" | awk '{p+=$4; f+=$6} END {print "наборов:", NR, "прошло:", p, "провалов:", f}'
cargo check --workspace --all-features 2>&1 | grep -c "^warning"
cargo doc --workspace --no-deps --all-features 2>&1 | grep -c "^warning"
cargo fmt --all --check 2>&1 | grep -c "^Diff"
```
Оба набора зелёные; воркспейс не потерял ни одного теста; `check` **0**; `doc` **18**; `fmt` **11**.

- [ ] **Шаг 7: коммит**

```bash
git add runtime/src/timed.rs runtime/tests/grid.rs
git commit
```
Сообщение называет: сколько мест брали шов до, сколько после, и почему источник тиков не принимается аргументом.

---

## Задача 2: тик несёт номер узла и момент

**Files:**
- Modify: `core/src/grid.rs` — номер узла наружу
- Modify: `core/src/detector.rs` — вариант `Tick`
- Modify: `core/src/interleave.rs` — выдача номера
- Test: `core/tests/interleave.rs` (дополнить)

**Interfaces:**
- Produces: `DetectorEvent::Tick { node: u64, at: Instant }` вместо `Tick { at: Instant }`

- [ ] **Шаг 1: инвентарь — сколько мест читают `Tick`**

```bash
grep -rn "DetectorEvent::Tick" --include=*.rs . --exclude-dir=target | wc -l
grep -rn "Tick {" --include=*.rs . --exclude-dir=target | wc -l
```
Оба числа — в сообщение коммита.

- [ ] **Шаг 2: написать падающий тест**

Дописать в `core/tests/interleave.rs`:

```rust
/// НОМЕР УЗЛА И МОМЕНТ — ОБА, А НЕ ОДИН ИЗ ДВУХ.
///
/// Номер даёт воспроизводимость: при переигровке он тот же, тогда как момент зависит от того,
/// когда прогон случился. Момент даёт сравнимость с чужими часами — с журналом ядра, с записью
/// провода, с отчётом человека.
///
/// Выбирать между ними значило бы терять одно из двух, а стоят они одно машинное слово.
#[test]
fn tick_carries_node_and_moment() {
    let start = Instant::now();
    let seam = Interleave::started(start, STEP);

    let (_, told) = seam.idle(start + STEP * 3);

    let nodes: Vec<u64> = told
        .iter()
        .filter_map(|event| match event {
            DetectorEvent::Tick { node, .. } => Some(*node),
            DetectorEvent::Packet { .. } => None,
        })
        .collect();

    assert_eq!(nodes, vec![1, 2, 3], "номера идут подряд от начала отсчёта");

    let moments: Vec<Instant> = told
        .iter()
        .filter_map(|event| match event {
            DetectorEvent::Tick { at, .. } => Some(*at),
            DetectorEvent::Packet { .. } => None,
        })
        .collect();

    assert_eq!(
        moments,
        vec![start + STEP, start + STEP * 2, start + STEP * 3],
        "момент есть момент УЗЛА, а не момент выдачи"
    );
}
```

**Внимание:** имя метода `idle` и его подпись взяты из шапки `interleave.rs`. Проверь их **чтением файла** до написания теста; если подпись иная — правь тест под дерево, а не дерево под тест, и скажи об этом в отчёте.

- [ ] **Шаг 3: прогнать — убедиться, что не собирается**

```bash
cargo test -p reflex-core --test interleave 2>&1 | tail -20
```
Ожидается: поле `node` не существует.

- [ ] **Шаг 4: дать номер узла наружу из `grid`**

`core/src/grid.rs` уже считает `node(start, every, nth) -> Instant`. Нужен обратный: по моменту — номер.

```rust
/// НОМЕР УЗЛА, В КОТОРЫЙ ПОПАДАЕТ МОМЕНТ.
///
/// Обратна [`node`] при НЕНУЛЕВОМ шаге: `nth_of(start, every, node(start, every, n)) == n`.
/// Закон проверяется тестом, а не обещается докблоком.
///
/// Вырожденный шаг исключён из закона намеренно: `node` при нулевом шаге отдаёт начало отсчёта
/// для любого `n`, то есть отображение перестаёт быть обратимым — восстановить `n` неоткуда.
/// Здесь нулевой шаг даёт ноль: у сетки без шага узлов нет, и номера у них тоже нет.
pub fn nth_of(start: Instant, every: Duration, moment: Instant) -> u64 {
    match every.is_zero() {
        true => 0,
        false => (moment.saturating_duration_since(start).as_nanos() / every.as_nanos()) as u64,
    }
}
```

- [ ] **Шаг 5: расширить вариант `Tick`**

`core/src/detector.rs`:

```rust
    /// УЗЕЛ СЕТКИ — единственная буква, говорящая, что ничего не произошло.
    ///
    /// Несёт и номер, и момент. Номер тот же при переигровке; момент сравним с чужими часами.
    Tick { node: u64, at: Instant },
```

Компилятор найдёт все места, где `Tick` строится или разбирается. Строящие получают номер из `grid::nth_of`; разбирающие, которым номер не нужен, пишут `Tick { at, .. }`.

- [ ] **Шаг 6: прогнать**

```bash
cargo test --workspace --all-features 2>&1 | grep "^test result" | awk '{p+=$4; f+=$6} END {print "наборов:", NR, "прошло:", p, "провалов:", f}'
cargo check --workspace --all-features 2>&1 | grep -c "^warning"
cargo fmt --all --check 2>&1 | grep -c "^Diff"
```
Провалов **0**, `check` **0**, `fmt` **11**.

- [ ] **Шаг 7: коммит**

---

## Задача 3: буква `Opaque`

**Files:**
- Create: `core/src/parse.rs` — причина непонимания как значение
- Modify: `core/src/detector.rs` — вариант `Opaque`
- Modify: `core/src/lib.rs` — объявление модуля
- Test: `core/tests/opaque.rs` (создать)

**Interfaces:**
- Produces: `core::parse::Unread` (`NotIpv4 | NotOurProtocol | Truncated`) и `DetectorEvent::Opaque { why: Unread, at: Instant }`

- [ ] **Шаг 1: прочитать существующее и НЕ заводить второе**

```bash
sed -n "$(grep -n 'pub enum Framed' engine-nfq/src/parse.rs | cut -d: -f1),+10p" engine-nfq/src/parse.rs
```
`Framed` в `engine-nfq` уже несёт ровно эти три причины (`NotIpv4`, `NotOurProtocol`, `Truncated`) вперемешку с успешными вариантами (`Tcp`, `Udp`).

**Решение:** `core::parse::Unread` держит только причины отказа. `Framed` НЕ переносится в `core` — он тянет за собой типы разбора, а `core` о проводе знать не должен. `engine-nfq` получает `impl From<&Framed<'_>> for Option<Unread>`.

- [ ] **Шаг 2: написать падающий тест**

Создать `core/tests/opaque.rs`:

```rust
//! «НЕ РАЗОБРАЛОСЬ» — БУКВА, А НЕ СЧЁТЧИК В КРАЮ.
//!
//! Пока такой буквы нет, наблюдение «пришло, но разобрать не смог» выразить нечем, и его
//! приходится считать руками ДО того, как родится событие. Ради этого счётчика держится второй
//! разбор пакета и переезд сырых байтов через шов.
//!
//! С буквой счётчик встаёт на цепочку — обычным звеном, считающим то, что видит.
use std::time::Instant;

use reflex_core::detector::DetectorEvent;
use reflex_core::parse::Unread;
use reflex_core::step::Step;
use smallvec::SmallVec;

/// Звено, считающее непонятое. Ровно то, ради чего буква заводится.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Counting {
    seen: u32,
    unread: u32,
}

impl Step for Counting {
    type From = DetectorEvent<u8>;
    type To = SmallVec<[(u32, u32); 2]>;

    fn step(self, event: Self::From) -> (Self, Self::To) {
        let next = match event {
            DetectorEvent::Packet { .. } => Counting {
                seen: self.seen + 1,
                ..self
            },
            DetectorEvent::Opaque { .. } => Counting {
                unread: self.unread + 1,
                ..self
            },
            DetectorEvent::Tick { .. } => self,
        };
        (next, SmallVec::from_slice(&[(next.seen, next.unread)]))
    }
}

fn opaque(why: Unread) -> DetectorEvent<u8> {
    DetectorEvent::Opaque {
        why,
        at: Instant::now(),
    }
}

#[test]
fn unread_is_counted_by_the_chain_not_by_the_edge() {
    let events = vec![
        DetectorEvent::Packet {
            input: 1u8,
            at: Instant::now(),
        },
        opaque(Unread::NotIpv4),
        opaque(Unread::Truncated),
    ];

    let (counted, _) = events.into_iter().fold(
        (Counting::default(), SmallVec::new()),
        |(machine, _), event| machine.step(event),
    );

    assert_eq!(counted.seen, 1, "разобранное сосчитано");
    assert_eq!(counted.unread, 2, "непонятое сосчитано ТАМ ЖЕ, а не в краю");
}

#[test]
fn the_reason_survives_the_seam() {
    // ПРИЧИНА — ЗНАЧЕНИЕ, А НЕ ФЛАГ. «Не наш протокол» и «обрезан» лечатся по-разному:
    // первое законно и вечно, второе означает потерю и может чиниться.
    let (_, told) = Counting::default().step(opaque(Unread::Truncated));
    assert_eq!(&told[..], &[(0, 1)]);

    let reasons = [Unread::NotIpv4, Unread::NotOurProtocol, Unread::Truncated];
    assert_eq!(
        reasons.len(),
        3,
        "причин ровно три: перечисление закрыто и его полноту сторожит компилятор"
    );
}
```

- [ ] **Шаг 3: прогнать — убедиться, что не собирается**

```bash
cargo test -p reflex-core --test opaque 2>&1 | tail -20
```
Ожидается: модуля `parse` и варианта `Opaque` нет.

- [ ] **Шаг 4: завести причину как значение**

Создать `core/src/parse.rs`:

```rust
//! ПОЧЕМУ НАБЛЮДЕНИЕ НЕ СОСТОЯЛОСЬ.
//!
//! # Почему причина, а не флаг
//!
//! «Не разобралось» одним битом сливает вещи, которые лечатся по-разному: «не наш протокол» есть
//! законное и вечное свойство трафика, «обрезан» есть потеря и может чиниться настройкой съёма.
//! Слитые в один счётчик, они дают величину, по которой нельзя решить ничего.
//!
//! # Почему в фундаменте, а не у бэкенда
//!
//! Причина едет буквой входного алфавита, а алфавит один на всех бэкендов. Живи она у бэкенда,
//! цепочка не смогла бы принять её, не зная, кто её кормит.
//!
//! Сам РАЗБОР остаётся у бэкенда: фундамент о проводе не знает и знать не должен. Сюда приезжает
//! только исход разбора.

/// ЧТО ПОМЕШАЛО ПРОЧЕСТЬ НАБЛЮДЕНИЕ.
///
/// Перечисление закрыто: полноту сторожит компилятор, и новый вид непонимания не появится молча.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unread {
    /// Не IPv4. Ни адреса, ни протокола выше взять неоткуда.
    NotIpv4,
    /// IPv4, но ни TCP, ни UDP: ICMP, SCTP, что угодно ещё. Разбирать нечем и гадать нельзя.
    NotOurProtocol,
    /// Обрезан: заголовок не поместился целиком. ПОТЕРЯ, а не свойство трафика.
    Truncated,
}
```

- [ ] **Шаг 5: добавить букву**

`core/src/detector.rs`:

```rust
    /// ПРИШЛО, НО РАЗОБРАТЬ НЕ СМОГЛИ.
    ///
    /// «Не знаю» на стороне входа. Без этой буквы наблюдение выразить нечем, и считать его
    /// приходится до того, как родится событие, — то есть в краю, вторым разбором.
    Opaque { why: crate::parse::Unread, at: Instant },
```

Объявить модуль в `core/src/lib.rs`. Компилятор найдёт все исчерпывающие `match` — их правка механическая: непонятое либо считается, либо пропускается явно.

- [ ] **Шаг 6: дать бэкенду перевод**

В `engine-nfq/src/parse.rs`:

```rust
impl Framed<'_> {
    /// ИСХОД РАЗБОРА КАК ПРИЧИНА, ЕСЛИ РАЗБОР НЕ СОСТОЯЛСЯ.
    ///
    /// `None` значит «разобралось» — успешные варианты причины не имеют.
    pub fn unread(&self) -> Option<reflex_core::parse::Unread> {
        match self {
            Framed::Tcp(_) | Framed::Udp(_) => None,
            Framed::NotIpv4 => Some(reflex_core::parse::Unread::NotIpv4),
            Framed::NotOurProtocol => Some(reflex_core::parse::Unread::NotOurProtocol),
            Framed::Truncated => Some(reflex_core::parse::Unread::Truncated),
        }
    }
}
```

- [ ] **Шаг 7: прогнать**

```bash
cargo test --workspace --all-features 2>&1 | grep "^test result" | awk '{p+=$4; f+=$6} END {print "наборов:", NR, "прошло:", p, "провалов:", f}'
cargo check --workspace --all-features 2>&1 | grep -c "^warning"
cargo doc --workspace --no-deps --all-features 2>&1 | grep -c "^warning"
cargo fmt --all --check 2>&1 | grep -c "^Diff"
```

- [ ] **Шаг 8: коммит**

Сообщение называет: сколько исчерпывающих `match` пришлось дополнить, и почему `Framed` не переехал в фундамент.

---

## Задача 4: шов схлопывается — демонстрация в продукте

**ВНИМАНИЕ: эта задача работает в ДРУГОМ репозитории** — `/home/rcd/Workspace/nevod`. Ветку там заводит исполнитель; в `reflex` при этом не правится ничего.

**Files:**
- Modify: `nevod/app/src/drive.rs` — снос `parsable`, снос второго разбора, буква через шов
- Modify: `nevod/app/src/wire.rs` — приём буквы вместо байтов
- Modify: `nevod/app/Cargo.toml` — если потребуется путь к `reflex`

**Interfaces:**
- Consumes: `reflex_core::detector::DetectorEvent::Opaque`, `reflex_runtime::timed::on_grid`, `Framed::unread`

- [ ] **Шаг 1: снять контрольные числа ДО правки**

```bash
cd /home/rcd/Workspace/nevod
cargo test --workspace 2>&1 | grep "^test result" | awk '{p+=$4; f+=$6} END {print "наборов:", NR, "прошло:", p, "провалов:", f}'
grep -c "to_vec()" app/src/drive.rs
grep -n "fn parsable" app/src/drive.rs
grep -n "sleep(period)" app/src/drive.rs
```
Все четыре — в сообщение коммита.

- [ ] **Шаг 2: разбор переезжает в край, через шов идёт буква**

В `app/src/drive.rs`, `impl NfqHandler for Feeder::handle`: вместо `parsable()` + `payload.to_vec()` — **один** разбор и отправка буквы:

```rust
        // РАЗБОР ОДИН И ОН ЗДЕСЬ. Через шов идёт БУКВА, а не байты: край прячет байтовую работу
        // внутри себя, а цепочка видит наблюдение либо причину, по которой его нет.
        let framed = reflex_engine_nfq::parse::framed(&packet.payload);
        let letter = match framed.unread() {
            Some(why) => Observed::opaque(why, now),
            None => /* сборка `Observed` из `framed` — то, что сегодня делает дальняя сторона */,
        };
        match self.tx.try_send(letter) {
            Ok(()) => { self.meters.to_engine.fetch_add(1, Ordering::Relaxed); }
            Err(_) => { self.meters.dropped_in.fetch_add(1, Ordering::Relaxed); }
        }
```

**ЧТО ИМЕННО ЕДЕТ ЧЕРЕЗ ШОВ — УЖЕ ИЗВЕСТНО, ПРИДУМЫВАТЬ НЕ НАДО.** Проверено чтением `app/src/wire.rs`: дальняя сторона производит

```rust
pub enum Observed {
    Tcp(DetectorEvent<Wire<reflex_core::Tcp>>),
    Udp(DetectorEvent<Wire<reflex_core::Udp>>),
}
```

то есть **уже букву**. Цепочка и сегодня говорит буквами — просто буква строится ПОСЛЕ канала, а до канала едут байты.

Значит правка не «придумать, что класть», а **перенести сборку `Observed` с дальней стороны канала на ближнюю**. Канал начинает нести `Observed` вместо `(Vec<u8>, Instant)`; `wire::events` теряет разбор и оставляет себе только то, что разбором не является.

**Разграничение, по которому резать:** в краю остаётся всё, что читает БАЙТЫ (`parse::framed` и построение `Wire<P>`); на цепочке остаётся всё, что читает уже разобранное (`Ledger`, доменное обогащение, `Leg`). Если окажется, что `step(ledger, &ip, at, leg)` перемешивает то и другое неразделимо — **остановись и доложи BLOCKED:** значит граница проходит не там, где мы думали, и это находка, а не препятствие.

- [ ] **Шаг 2а: `Observed` получает третью ветвь**

После задачи 3 у входного алфавита три буквы, а `Observed::tcp()` разбирает две:

```rust
    pub fn tcp(self) -> Option<DetectorEvent<Wire<reflex_core::Tcp>>> {
        match self {
            Observed::Tcp(event) => Some(event),
            Observed::Udp(DetectorEvent::Tick { at }) => Some(DetectorEvent::Tick { at }),
            Observed::Udp(DetectorEvent::Packet { .. }) => None,
        }
    }
```

Компилятор потребует ветвь для `Opaque`. Решение по образцу тика: **непонятое проходит в ОБЕ ветви**, потому что «пакет пришёл и не разобрался» верно для приборов обоих протоколов — оно про провод, а не про протокол.

- [ ] **Шаг 3: счётчик «не разобралось» уезжает на цепочку**

Поле `meters.parsed` снимается. Вместо него — звено цепочки, считающее `Opaque`. Величина остаётся в отчёте: формат строки `Meters::line` читается скриптами стенда, и терять поле нельзя. Если поле обязано остаться в строке — оно наполняется **из цепочки**, а не из края.

- [ ] **Шаг 4: тики берутся сеткой**

`ticks(TICK)` с `tokio::time::sleep(period)` заменяется на `reflex_runtime::timed::on_grid(...)`. Счётчик тиков сохраняется — он различает «тик не родился» и «тик не дошёл».

- [ ] **Шаг 5: прогнать и сверить**

```bash
cargo test --workspace 2>&1 | grep "^test result" | awk '{p+=$4; f+=$6} END {print "наборов:", NR, "прошло:", p, "провалов:", f}'
grep -c "to_vec()" app/src/drive.rs        # ожидается 0
grep -c "fn parsable" app/src/drive.rs      # ожидается 0
grep -c "sleep(period)" app/src/drive.rs    # ожидается 0
```
Число тестов обязано совпасть с контрольным из шага 1.

- [ ] **Шаг 6: коммит**

---

## Приёмка плана

| что | до | после |
|---|---|---|
| разборов пакета на пути очередь → цепочка | 2 | **1** |
| `payload.to_vec()` в краю | есть | **0** |
| `fn parsable` в краю | есть | **0** |
| источник тиков | `sleep(period)` после работы | **сетка** |
| буква «не разобралось» | нет | **есть** |
| `Tick` несёт номер узла | нет | **да** |
| употреблений сетки у потребителя | 0 | **1** |
| тестов в `reflex` | не меньше, чем было | сверяется числом |

## Что этот план НЕ делает

* **Пара на выходе** — отдельный план: 44 места `type To`, и это столько же работы, сколько весь этот план.
* **Буквы `Taught` и `Commanded`** — внешняя петля и приказ снаружи. Их форма зависит от вопросов, которые спека оставила открытыми осознанно.
* **Ограничение работы на тик** (`ExpiringSet`, `FlowTable`) — зависит от пары: остаток обязан быть показанием.
* **Синтаксис `engine(NFQ) { … }`** и словарь бэкенда через удерживаемые области — следующий срез после пары.
* **Переименование `DetectorEvent` → `Arrived`**, предложенное спекой. 298 мест ради имени, без выгоды в этом плане. Имя вернётся тогда, когда алфавит перестанет быть «событием детектора» по существу, — то есть вместе с буквами `Taught`/`Commanded`.
