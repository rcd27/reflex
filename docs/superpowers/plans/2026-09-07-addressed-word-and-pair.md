# Адресное слово и пара на выходе — план работ

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** сделать адресность слова проверяемой компилятором и дать каждому шагу второй выход — показания, которые копятся вбок и не читаются никем.

**Architecture:** `Word` объявляет область значения, `Region` — саму область; `Step` получает третий ассоциированный тип `Notes` и отдаёт тройку. Композиция цепляет слова и **перемножает** показания: двадцати частным словарям сходиться не нужно, а «кто сказал» называет позиция в типе.

**Tech Stack:** Rust 2021, `smallvec`, `futures`, `tokio` (в тестах и асинхронном драйвере).

**Spec:** `docs/superpowers/specs/2026-09-07-addressed-word-and-pair-design.md`

---

## Global Constraints

* **Докблок не имеет права утверждать факт о текущем состоянии дерева.** Нельзя: счёт, адрес (`файл:строка`, `crate::модуль::имя`), «что где лежит», «раньше было так», «уже делают там-то», датированные замеры. Можно: контракт, закон, смысл границы, замысел. Всё счётное и адресное — **в тело коммита**. Метки тикетов (`#326`) — не нарушение.
* **Замер — только прогоном.** Число, добытое грепом, не идёт ни в отчёт, ни в приёмку, пока предмет не запущен.
* **Приёмочный критерий прогоняется автором до отправки.**
* **Тела переносятся дословно** там, где меняются только границы и подписи.
* **`_ => …` в разборе алфавита запрещён** — он проглотит буквы, которые заведут после (`Taught`, `Commanded`).
* **Три инструмента в приёмке, с замеренной базой:** `cargo test --workspace --all-features` — **92 набора / 822 прошло / 0 провалов**; `cargo check --workspace --all-features` — **0** предупреждений; `cargo doc --workspace --no-deps --all-features` — **18**; `cargo fmt --all --check` — **11** (все в `engine`/`engine-nfq`). Ниже базы не опускать, тестов не терять.
* **`git stash`, `git checkout`, `git rebase` в рабочем дереве — НЕЛЬЗЯ.** Сравнить с другим коммитом: `git show <rev>:<путь>`, `git archive`, либо отдельный `git worktree add --detach`.
* **Репозиторий `nevod` не трогать.** Миграция потребителя в этот срез не входит.

---

## Замер, из которого растёт план

Снят 07.09.2026 на `main` после слияния полного входного алфавита.

| что | сколько | как |
|---|---|---|
| `impl Step` в дереве | **55** | греп по `impl … Step for` |
| файлов с ними | **33** | то же |
| крейтов затронуто | 5 (`core` 12 файлов, `instrument` 12, `engine` 4, `runtime` 4, `engine-nfq` 1) | то же |
| `type To` | **44** в **28** формах | греп |
| шагов с выходом-парой | **1** (`engine/src/step.rs`, `Advancing`) | чтение |
| примитивы в позиции слова | `core/tests/step_laws.rs` (3), `core/tests/lifting.rs`, `engine/tests/lifting.rs` | греп |

Числа получены грепом и потому **в приёмку не идут**: каждая задача сверяет своё прогоном.

## Структура файлов

| файл | ответственность после плана |
|---|---|
| `core/src/word.rs` (новый) | закон адресности: `Region`, `Word`, области, `CanDefer`, страж ожидания |
| `core/src/step.rs` | носитель: `To: Word`, `Notes`, тройка на выходе; `Then` перемножает показания; `Id` отмечает пустоту; `Over` выпускает пару наружу |
| `core/src/detector.rs` | комбинаторы проносят показания насквозь; `Both` даёт произведение слов |
| `engine/src/lib.rs` | `Act`, `Ordered`, `Programme` объявляют свои области |
| `instrument/src/distress.rs` | `Distress` объявляет область разговора |
| `instrument/src/detect.rs` | первый прибор с настоящими показаниями |

## Порядок задач

Задачи 1–2 **аддитивны**: дерево зелёное после каждой. Задача 3 вводит ограничение `To: Word` и ломает сборку у всех, кто не объявил адрес. Задача 4 меняет подпись `step` и ломает всё разом — это два **разных** прохода по одним файлам, и разделены они намеренно: первый отвечает на вопрос «кому адресовано», второй — «что при этом видел». Рецензент вправе отвергнуть один, приняв другой.

---

## Задача 1: закон адресности

**Files:**
- Create: `core/src/word.rs`
- Modify: `core/src/lib.rs` — объявление модуля
- Test: `core/tests/word.rs` (создать)

**Interfaces:**
- Produces: `reflex_core::word::{Region, Word, CanDefer, may_wait, Packet, Conversation, Target, Nobody}`; `impl Word for ()`; `impl Word for SmallVec<A> where A::Item: Word`; `impl Word for (A, B) where B: Word<Of = A::Of>`

- [ ] **Шаг 1: снять контрольные числа**

```bash
cd /home/rcd/Workspace/reflex
cargo test --workspace --all-features 2>&1 | grep "^test result" | awk '{p+=$4; f+=$6} END {print "наборов:", NR, "прошло:", p, "провалов:", f}'
```
Ожидается `наборов: 92 прошло: 822 провалов: 0`. Число — в тело коммита.

- [ ] **Шаг 2: написать падающий тест**

Создать `core/tests/word.rs`:

```rust
//! АДРЕС ЕСТЬ У СЛОВА, И ОН ПРОВЕРЯЕТСЯ ТИПОМ.
//!
//! Слово — значение, объявившее свою область. Область даёт срок, срок даёт отложимость: пакет
//! держит ядро, и ждать на нём нельзя физически; разговор ожидание терпит.
//!
//! Здесь проверяется, что закон выражен типами, а не уговором: объявить область обязан всякий,
//! кто хочет стоять в позиции слова, и своя область объявляется без правки фундамента.
use reflex_core::word::{may_wait, Conversation, Nobody, Region, Word};
use smallvec::SmallVec;

/// СВОЯ ОБЛАСТЬ, ОБЪЯВЛЕННАЯ СНАРУЖИ ФУНДАМЕНТА — то, ради чего закон вводится трейтом, а не
/// перечислением трёх слов движка.
struct Tunnel;
impl Region for Tunnel {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Reroute;
impl Word for Reroute {
    type Of = Tunnel;
}

#[test]
fn nothing_to_say_is_a_word_addressed_to_nobody() {
    // «Сказать нечего» видно на подписи, а не после запуска: терминальный объект категории.
    fn addressed<W: Word>() -> &'static str {
        core::any::type_name::<W::Of>()
    }
    assert!(
        addressed::<()>().ends_with("Nobody"),
        "пустое слово обязано быть адресовано никому"
    );
}

#[test]
fn a_collection_of_words_keeps_their_address() {
    // Пачка слов адресована туда же, куда каждое: сложение не меняет адресата.
    fn same_address<A: Word, B: Word<Of = A::Of>>() {}
    same_address::<Reroute, SmallVec<[Reroute; 2]>>();
}

#[test]
fn a_pair_of_words_merges_only_within_one_region() {
    // Два звена, адресованные РАЗНЫМ областям, сложить в одно слово нельзя: их слова едут в
    // разные места, и склейка была бы ложью о том, кому сказано.
    fn merged<A: Word, B: Word<Of = A::Of>>() {}
    merged::<Reroute, Reroute>();
}

#[test]
fn waiting_is_allowed_where_the_region_tolerates_it() {
    // Страж берёт слово и требует от его области терпения. Здесь оно есть.
    struct Sever;
    impl Word for Sever {
        type Of = Conversation;
    }
    may_wait::<Sever>();
    may_wait::<()>();
    let _ = core::any::type_name::<Nobody>();
}
```

- [ ] **Шаг 3: прогнать — убедиться, что не собирается**

```bash
cargo test -p reflex-core --test word 2>&1 | tail -20
```
Ожидается отказ сборки: модуля `word` не существует.

- [ ] **Шаг 4: написать закон**

Создать `core/src/word.rs`:

```rust
//! АДРЕСНОСТЬ: КОМУ СКАЗАНО.
//!
//! # Что отличает слово от показания
//!
//! Слово адресовано ОБЛАСТИ и потребляется соседом; показание не адресовано никому и не
//! потребляется никем — оно копится. Различает их адрес, а НЕ наклонение: суждение «этот разговор
//! в беде» ничего не велит, но говорит о разговоре, и потому у него есть область, срок и право
//! быть словом.
//!
//! # Зачем область типом
//!
//! Из области берётся срок, из срока — отложимость. Ядро держит пакет, пока цепочка не ответила;
//! значит ожидание на пакетной цепочке невыразимо, а не нежелательно. Живи область в списке трёх
//! слов, всякая новая область требовала бы правки фундамента — а строят на фундаменте другие.

/// ОБЛАСТЬ — то, чему адресуется слово.
///
/// Пустой трейт намеренно: область есть ИМЯ адресата, и всё, что о ней известно фундаменту, —
/// терпит ли она ожидание ([`CanDefer`]).
pub trait Region {}

/// СЛОВО — значение, объявившее свою область.
pub trait Word {
    /// Кому это сказано.
    type Of: Region;
}

/// ОБЛАСТЬ, РЕШЕНИЕ О КОТОРОЙ МОЖНО ОТЛОЖИТЬ.
///
/// Маркер, а не градация: сегодняшний запрет ровно один — ждать нельзя там, где ждать нельзя
/// физически. Градации заведутся тогда, когда появится второй запрет, и не раньше.
pub trait CanDefer: Region {}

/// ПАКЕТ В РУКАХ ЯДРА. Ждать нельзя: очередь держит его до ответа.
pub struct Packet;
/// РАЗГОВОР. Живёт до своего конца и ожидание терпит.
pub struct Conversation;
/// ЦЕЛЬ. Живёт до смены плана; откладывать можно свободно.
pub struct Target;
/// НИКОМУ. Адресат пустого слова.
pub struct Nobody;

impl Region for Packet {}
impl Region for Conversation {}
impl Region for Target {}
impl Region for Nobody {}

impl CanDefer for Conversation {}
impl CanDefer for Target {}
/// Сказать нечего — значит некому и держать: ждать можно сколько угодно.
impl CanDefer for Nobody {}

/// СКАЗАТЬ НЕЧЕГО — терминальный объект категории.
impl Word for () {
    type Of = Nobody;
}

/// Пачка слов адресована туда же, куда каждое.
impl<A: smallvec::Array> Word for smallvec::SmallVec<A>
where
    A::Item: Word,
{
    type Of = <A::Item as Word>::Of;
}

/// ДВА СЛОВА ОДНОЙ ОБЛАСТИ — одно слово той же области.
///
/// Разным областям слиться нельзя: их слова едут в разные места, и склейка была бы ложью о том,
/// кому сказано.
impl<A: Word, B: Word<Of = A::Of>> Word for (A, B) {
    type Of = A::Of;
}

/// ЖДАТЬ МОЖНО ТОЛЬКО ТАМ, ГДЕ ОБЛАСТЬ ЭТО ТЕРПИТ.
///
/// Страж существует ради границы, которую нельзя перейти молча: всякий будущий оператор ожидания
/// обязан потребовать этот же баунд, и тогда ожидание на пакетной цепочке не соберётся.
///
/// ```
/// reflex_core::word::may_wait::<()>();
/// ```
///
/// ```compile_fail
/// use reflex_core::word::{may_wait, Packet, Word};
/// struct Verdict;
/// impl Word for Verdict {
///     type Of = Packet;
/// }
/// // Ядро держит пакет: ожидание здесь невыразимо, а не нежелательно.
/// may_wait::<Verdict>();
/// ```
pub fn may_wait<W: Word>()
where
    W::Of: CanDefer,
{
}
```

Объявить модуль в `core/src/lib.rs` рядом с прочими (`pub mod word;`).

- [ ] **Шаг 5: прогнать**

```bash
cargo test -p reflex-core --test word 2>&1 | grep "^test result"
cargo test -p reflex-core --doc word 2>&1 | grep "^test result"
cargo test --workspace --all-features 2>&1 | grep "^test result" | awk '{p+=$4; f+=$6} END {print "наборов:", NR, "прошло:", p, "провалов:", f}'
cargo check --workspace --all-features 2>&1 | grep -c "^warning"
cargo doc --workspace --no-deps --all-features 2>&1 | grep -c "^warning"
cargo fmt --all --check 2>&1 | grep -c "^Diff"
```
Оба набора зелёные (док-тест `compile_fail` считается пройденным, когда пример НЕ собрался); воркспейс не потерял тестов; `check` **0**, `doc` **18**, `fmt` **11**.

- [ ] **Шаг 6: коммит**

Сообщение называет: почему область — трейт, а не перечисление трёх слов, и что `compile_fail` в док-тесте есть исполняемая форма запрета.

---

## Задача 2: существующие слова объявляют адрес

**Files:**
- Modify: `engine/src/lib.rs` — `Act`, `Ordered`, `Programme`
- Modify: `instrument/src/distress.rs` — `Distress`
- Test: `engine/tests/addressing.rs` (создать)

**Interfaces:**
- Consumes: `reflex_core::word::{Word, Packet, Conversation, Target, CanDefer, may_wait}`
- Produces: `impl Word for Act { type Of = Packet; }`, `impl Word for Ordered { type Of = Conversation; }`, `impl Word for Programme { type Of = Target; }`, `impl Word for Distress { type Of = Conversation; }`

- [ ] **Шаг 1: написать падающий тест**

Создать `engine/tests/addressing.rs`:

```rust
//! СЛОВА ДВИЖКА ОБЪЯВЛЯЮТ, КОМУ ОНИ СКАЗАНЫ.
//!
//! Три слова устроены одинаково, и это не совпадение: у каждого есть область, у области срок, из
//! срока следует отложимость. Пакет ждать не может — его держит ядро; разговор и цель могут.
use reflex_core::word::{may_wait, Word};
use reflex_engine::{Act, Ordered, Programme};

#[test]
fn each_word_names_its_region() {
    fn region_of<W: Word>() -> &'static str {
        core::any::type_name::<W::Of>()
    }
    assert!(region_of::<Act>().ends_with("Packet"), "Act адресован пакету");
    assert!(
        region_of::<Ordered>().ends_with("Conversation"),
        "Ordered адресован разговору"
    );
    assert!(
        region_of::<Programme>().ends_with("Target"),
        "Programme адресован цели"
    );
}

#[test]
fn waiting_is_allowed_on_the_conversation_and_the_target() {
    // Ожидание на этих двух законно; на пакетной цепочке оно не собирается вовсе, и это
    // проверяется док-тестом стража в фундаменте, а не здесь: провал сборки тестом не выражается.
    may_wait::<Ordered>();
    may_wait::<Programme>();
}
```

- [ ] **Шаг 2: прогнать — убедиться, что не собирается**

```bash
cargo test -p reflex-engine --test addressing 2>&1 | tail -20
```
Ожидается: трейт `Word` для `Act` не реализован.

- [ ] **Шаг 3: объявить адреса**

В `engine/src/lib.rs`, рядом с каждым словом:

```rust
/// ПАКЕТ В РУКАХ ЯДРА: ответ обязан быть дан на этом же шаге.
impl reflex_core::word::Word for Act {
    type Of = reflex_core::word::Packet;
}

/// РАЗГОВОР: слово живёт до его конца.
impl reflex_core::word::Word for Ordered {
    type Of = reflex_core::word::Conversation;
}

/// ЦЕЛЬ: слово живёт до смены плана.
impl reflex_core::word::Word for Programme {
    type Of = reflex_core::word::Target;
}
```

В `instrument/src/distress.rs`:

```rust
/// БЕДА СКАЗАНА О РАЗГОВОРЕ, А НЕ О МИРЕ ВООБЩЕ.
///
/// Наклонение здесь изъявительное — беда ничего не велит, — но адресат есть, и потому это слово, а
/// не показание. Различает слово и показание АДРЕС, а не наклонение.
impl reflex_core::word::Word for Distress {
    type Of = reflex_core::word::Conversation;
}
```

- [ ] **Шаг 4: прогнать**

```bash
cargo test -p reflex-engine --test addressing 2>&1 | grep "^test result"
cargo test --workspace --all-features 2>&1 | grep "^test result" | awk '{p+=$4; f+=$6} END {print "наборов:", NR, "прошло:", p, "провалов:", f}'
cargo check --workspace --all-features 2>&1 | grep -c "^warning"
cargo fmt --all --check 2>&1 | grep -c "^Diff"
```
Провалов **0**; `check` **0**; `fmt` **11**.

- [ ] **Шаг 5: коммит**

Сообщение называет, почему `Distress` — слово, хотя ничего не велит.

---

## Задача 3: слово обязано быть адресным

**Files:**
- Modify: `core/src/step.rs` — баунд `type To: Word`, `Id<T: Word>`
- Modify: всё, что компилятор найдёт (ожидаются `core/src/detector.rs`, `core/src/flow_table.rs`, `core/src/tls/assembly.rs`, `instrument/src/*.rs`, `engine/src/*.rs`, тесты во всех крейтах)
- Test: `core/tests/step_laws.rs` — объявляет свою область

**Interfaces:**
- Consumes: `reflex_core::word::{Word, Region}`
- Produces: `trait Step { type To: crate::word::Word; … }`

- [ ] **Шаг 1: снять инвентарь ДО правки**

```bash
grep -rc "impl .*Step for\|impl.*step::Step for" --include=*.rs . --exclude-dir=target | grep -v ":0" | awk -F: '{s+=$2} END {print "impl Step:", s}'
grep -rn "type To = " --include=*.rs . --exclude-dir=target | wc -l
```
Оба числа — в тело коммита.

- [ ] **Шаг 2: научить законный тест объявлять свою область**

`core/tests/step_laws.rs` держит три машины со словом `u8`. Дописать в него:

```rust
/// ОБЛАСТЬ ЗАКОННОГО СТЕНДА.
///
/// Объявляется здесь, а не в фундаменте: закон обязан быть выразим для того, кто заводит свою
/// область снаружи, и стенд — первый такой заводящий.
struct Bench;
impl reflex_core::word::Region for Bench {}

impl reflex_core::word::Word for u8 {
    type Of = Bench;
}
```

Тела трёх машин и обоих законов (`composition_is_associative`, `identity_is_neutral_on_both_sides`) **переносятся дословно**: меняются только границы, а не поведение.

- [ ] **Шаг 3: прогнать — убедиться, что не собирается**

```bash
cargo check --workspace --all-features 2>&1 | tail -20
```
Ожидается зелено: баунда ещё нет, объявление адреса лишним не является.

- [ ] **Шаг 4: ввести баунд**

`core/src/step.rs`:

```rust
pub trait Step: Sized {
    /// Стадия-источник.
    type From;
    /// СЛОВО: адресовано области и потребляется соседом.
    ///
    /// Баунд несущий: значение без объявленного адреса в позицию слова не встаёт. Без него закон
    /// остаётся уговором, а нарушают уговор первыми тесты — им адресат кажется неважным.
    type To: crate::word::Word;

    fn step(self, input: Self::From) -> (Self, Self::To);
}
```

И тождество:

```rust
impl<T: crate::word::Word> Step for Id<T> {
    type From = T;
    type To = T;

    fn step(self, input: T) -> (Self, T) {
        (self, input)
    }
}
```

Баунд ставится на **реализацию**, а не на объявление структуры `Id<T>`: `PhantomData` адреса не требует, и требовать его там значило бы навесить ограничение, ложное по построению.

- [ ] **Шаг 5: починить всё, что найдёт компилятор**

Правило одно: **у значения смотрится, о чём оно говорит, а не как оно названо.** Есть область — объявить её; нет — слово есть `()`, а бывшее слово уезжает в показания задачей 4 (до тех пор оно остаётся выходом, просто с объявленным адресом).

Отдельно про `Sighting` (`engine/src/lib.rs`): спека оставила его область открытым вопросом сознательно. Часть вариантов несёт адрес цели (`Opened { dst }`, `TargetSpoke { dst }`), часть говорит о разговоре. Разбери его **чтением вариантов**, а не по имени: если окажется, что варианты адресованы разным областям, значение обязано разделиться на два — и это находка, о которой сказать в отчёте, а не препятствие.

Тестовые типы (`u32` в `core/tests/lifting.rs` и `engine/tests/lifting.rs`) объявляют свою область по образцу стенда из шага 2.

- [ ] **Шаг 6: прогнать**

```bash
cargo test --workspace --all-features 2>&1 | grep "^test result" | awk '{p+=$4; f+=$6} END {print "наборов:", NR, "прошло:", p, "провалов:", f}'
cargo check --workspace --all-features 2>&1 | grep -c "^warning"
cargo doc --workspace --no-deps --all-features 2>&1 | grep -c "^warning"
cargo fmt --all --check 2>&1 | grep -c "^Diff"
```
Провалов **0**, тестов не меньше **822**; `check` **0**; `doc` **18**; `fmt` **11**.

- [ ] **Шаг 7: коммит**

Сообщение называет: сколько `type To` объявили область, сколько стали `()`, и сколько областей завелось снаружи фундамента.

---

## Задача 4: пара

**Files:**
- Modify: `core/src/step.rs` — `type Notes`, тройка, `Then`, `Id`, `Over`
- Modify: `core/src/detector.rs` — комбинаторы проносят показания насквозь
- Modify: всё, что найдёт компилятор
- Test: `core/tests/pair.rs` (создать)

**Interfaces:**
- Produces: `trait Step { type Notes; fn step(self, input: Self::From) -> (Self, Self::To, Self::Notes); }`; `Then::Notes = (A::Notes, B::Notes)`; `Id::Notes = ()`; `Over::Item = (K::To, K::Notes)`

- [ ] **Шаг 1: написать падающий тест**

Создать `core/tests/pair.rs`:

```rust
//! ВЫХОД ШАГА ЕСТЬ ПАРА: СЛОВО И ПОКАЗАНИЯ.
//!
//! Слово уходит соседу по стрелке; показание уходит вбок и не читается никем. Композиция цепляет
//! слова и ПЕРЕМНОЖАЕТ показания: двум звеньям не нужно говорить на одном языке, чтобы их
//! показания сложились, — а кто сказал, называет позиция в типе.
use reflex_core::step::{Id, Step, StepExt};
use reflex_core::word::{Region, Word};

struct Bench;
impl Region for Bench {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Count(u8);
impl Word for Count {
    type Of = Bench;
}

/// СЧИТАЕТ ВХОДЫ И ОТМЕЧАЕТ, СКОЛЬКО ИХ БЫЛО ДО ЭТОГО.
#[derive(Debug, Clone, Copy)]
struct Counting(u8);

impl Step for Counting {
    type From = Count;
    type To = Count;
    type Notes = u8;

    fn step(self, input: Count) -> (Self, Count, u8) {
        (Counting(self.0 + 1), Count(input.0 + 1), self.0)
    }
}

/// УДВАИВАЕТ И НЕ ОТМЕЧАЕТ НИЧЕГО — «нечего сказать» выражено ТИПОМ.
#[derive(Debug, Clone, Copy)]
struct Doubling;

impl Step for Doubling {
    type From = Count;
    type To = Count;
    type Notes = ();

    fn step(self, input: Count) -> (Self, Count, ()) {
        (self, Count(input.0 * 2), ())
    }
}

#[test]
fn composition_multiplies_the_notes() {
    let chain = Counting(0).then(Doubling);
    let (_, said, notes) = chain.step(Count(1));

    assert_eq!(said, Count(4), "слова сцепились: (1+1)*2");
    assert_eq!(notes, (0u8, ()), "показания перемножились, и позиция называет автора");
}

#[test]
fn nothing_to_note_weighs_nothing() {
    // «Пусто» здесь по ТИПУ, а не по проверке в работе: пустые показания не занимают памяти.
    assert_eq!(
        core::mem::size_of::<<Doubling as Step>::Notes>(),
        0,
        "пустое показание обязано быть бесплатным"
    );
}

#[test]
fn identity_notes_nothing() {
    // Звено, отмечающее что-либо, соседям не безразлично — значит тождеством не является.
    let (_, said, notes) = Id::<Count>::new().step(Count(7));
    assert_eq!(said, Count(7));
    assert_eq!(notes, ());
}
```

- [ ] **Шаг 2: прогнать — убедиться, что не собирается**

```bash
cargo test -p reflex-core --test pair 2>&1 | tail -20
```
Ожидается: `Step` не имеет `Notes`, `step` возвращает пару, а не тройку.

- [ ] **Шаг 3: дать носителю второй выход**

`core/src/step.rs`:

```rust
pub trait Step: Sized {
    /// Стадия-источник.
    type From;
    /// СЛОВО: адресовано области и потребляется соседом.
    type To: crate::word::Word;
    /// ПОКАЗАНИЯ: не адресованы никому и не читаются никем — копятся вбок.
    ///
    /// Тройкой, а не парой в `To`: будь пара одним типом, композиция заставила бы соседа ЕСТЬ
    /// чужие показания. Ход вбок обязан быть невыразим иначе, а не оговорён прозой.
    type Notes;

    /// Один шаг: вход → слово и показания, и НОВОЕ состояние машины.
    fn step(self, input: Self::From) -> (Self, Self::To, Self::Notes);
}
```

```rust
impl<A, B> Step for Then<A, B>
where
    A: Step,
    B: Step<From = A::To>,
{
    type From = A::From;
    type To = B::To;
    /// ПРОИЗВЕДЕНИЕ, А НЕ ОБЩИЙ СЛОВАРЬ: два звена не обязаны говорить на одном языке, чтобы их
    /// показания сложились, а позиция в типе называет автора вернее всякой метки.
    type Notes = (A::Notes, B::Notes);

    fn step(self, input: A::From) -> (Self, B::To, (A::Notes, B::Notes)) {
        let (first, middle, said) = self.0.step(input);
        let (second, out, also) = self.1.step(middle);
        (Then(first, second), out, (said, also))
    }
}
```

```rust
impl<T: crate::word::Word> Step for Id<T> {
    type From = T;
    type To = T;
    /// Тождество обязано быть нейтральным и в показаниях: отмечающее звено соседям не безразлично.
    type Notes = ();

    fn step(self, input: T) -> (Self, T, ()) {
        (self, input, ())
    }
}
```

И подъём — единственное место, где показания покидают цепочку:

```rust
impl<S, K> futures::Stream for Over<S, K>
where
    S: futures::Stream<Item = K::From>,
    K: Step,
{
    /// ПАРА НАРУЖУ: за границей цепочки показания читает лента, отчёт, расследование.
    type Item = (K::To, K::Notes);
```

Тело `poll_next` переносится дословно; меняется только распаковка тройки.

- [ ] **Шаг 4: комбинаторы проносят показания насквозь**

`core/src/detector.rs`: `RMap`, `LMap`, `Contextual`, `Changes`, `Timed`, `By` переименовывают и сужают **слово**; показания идут сквозь без изменений:

```rust
type Notes = D::Notes;
```

Комбинатор, добавляющий показание от себя, комбинатором не является — он звено, и объявляется звеном.

`Both` в этой задаче **не трогается**: его слово меняет форму в задаче 5.

- [ ] **Шаг 5: починить всё, что найдёт компилятор**

Каждой машине дать `type Notes = ();` и вернуть тройку. **Тела переносятся дословно** — это доказательство того, что сдвинулись типы, а не поведение. Настоящие показания заводятся задачей 6, не здесь.

- [ ] **Шаг 6: прогнать**

```bash
cargo test -p reflex-core --test pair 2>&1 | grep "^test result"
cargo test --workspace --all-features 2>&1 | grep "^test result" | awk '{p+=$4; f+=$6} END {print "наборов:", NR, "прошло:", p, "провалов:", f}'
cargo check --workspace --all-features 2>&1 | grep -c "^warning"
cargo doc --workspace --no-deps --all-features 2>&1 | grep -c "^warning"
cargo fmt --all --check 2>&1 | grep -c "^Diff"
```

- [ ] **Шаг 7: коммит**

Сообщение называет: сколько машин получили `Notes = ()`, и почему тройка, а не пара в `To`.

---

## Задача 5: `Both` даёт произведение

**Files:**
- Modify: `core/src/detector.rs` — `Both`
- Modify: `core/src/step.rs` — баунд метода `and`
- Test: `core/tests/detector_combinators.rs` — дополнить

**Interfaces:**
- Produces: `Both::To = (A::To, B::To)` при `B::To: Word<Of = <A::To as Word>::Of>`; `Both::Notes = (A::Notes, B::Notes)`

- [ ] **Шаг 1: написать падающий тест**

Дописать в `core/tests/detector_combinators.rs`:

```rust
/// ПОСЛЕ СЛОЖЕНИЯ ВИДНО, КТО СКАЗАЛ — ПОЗИЦИЯ В ТИПЕ И ЕСТЬ ИМЯ.
///
/// Прежде два прибора с общим словарём давали неразличимые показания при разном лечении, и
/// различить их можно было только меткой в работе. Произведение решает это типом: левое слово
/// пришло от левого звена, и перепутать их нечем.
#[test]
fn both_keeps_the_authors_apart_by_position() {
    let watchers = Both(Rst, Clock);
    let (_, said, _) = watchers.step(DetectorEvent::Packet {
        input: SeenRst,
        at: Instant::now(),
    });

    let (from_rst, from_clock) = said;
    assert!(!from_rst.is_empty(), "левое звено сказало своё слово");
    assert!(from_clock.is_empty(), "правое промолчало, и это видно отдельно");
}
```

**Внимание:** имена `Rst`, `Clock`, `SeenRst` взяты из шапки существующего файла. Проверь их **чтением файла** до написания теста; если имена иные — правь тест под дерево, а не дерево под тест, и скажи в отчёте.

- [ ] **Шаг 2: прогнать — убедиться, что не собирается**

```bash
cargo test -p reflex-core --test detector_combinators 2>&1 | tail -20
```
Ожидается: `said` не кортеж — сегодня оба слова слиты в один `SmallVec`.

- [ ] **Шаг 3: переписать `Both`**

`core/src/detector.rs`:

```rust
impl<A, B, I> crate::step::Step for Both<A, B>
where
    A: crate::step::Step<From = DetectorEvent<I>>,
    B: crate::step::Step<From = DetectorEvent<I>>,
    B::To: crate::word::Word<Of = <A::To as crate::word::Word>::Of>,
    I: Clone,
{
    type From = DetectorEvent<I>;
    /// СЛОВА ОДНОЙ ОБЛАСТИ, СЛОЖЕННЫЕ ПРОИЗВЕДЕНИЕМ.
    ///
    /// Разным областям слиться нельзя: их слова едут в разные места, и склейка была бы ложью о
    /// том, кому сказано.
    type To = (A::To, B::To);
    type Notes = (A::Notes, B::Notes);

    fn step(self, event: Self::From) -> (Self, Self::To, Self::Notes) {
        let (first, said, noted) = self.0.step(event.clone());
        let (second, also, marked) = self.1.step(event);
        (Both(first, second), (said, also), (noted, marked))
    }
}
```

Баунд метода `StepExt::and` привести в соответствие: он сегодня требует `To = Self::To` у обоих; теперь требуется общая **область**, а не общий тип.

- [ ] **Шаг 4: починить потребителей `and`**

Компилятор найдёт места, ждавшие один слитый `SmallVec`. Каждое разбирается на пару явно.

- [ ] **Шаг 5: прогнать**

```bash
cargo test --workspace --all-features 2>&1 | grep "^test result" | awk '{p+=$4; f+=$6} END {print "наборов:", NR, "прошло:", p, "провалов:", f}'
cargo check --workspace --all-features 2>&1 | grep -c "^warning"
cargo fmt --all --check 2>&1 | grep -c "^Diff"
```

- [ ] **Шаг 6: коммит**

Сообщение называет цену, снятую с докблока `Both`, и сколько мест разбирали слитый вектор.

---

## Задача 6: первые настоящие показания и функтор забывания

**Files:**
- Modify: `instrument/src/detect.rs` — `SilenceInstrument` отмечает, чем мерил
- Modify: `core/src/detector.rs` — комбинатор `Muted`
- Modify: `core/src/step.rs` — метод `mute`
- Test: `instrument/tests/notes.rs` (создать)

**Interfaces:**
- Produces: `instrument::detect::Measured { since_ms: u32, bytes: u32, awaiting: bool }`; `SilenceInstrument::Notes = Option<Measured>`; `reflex_core::detector::Muted<D>` с `Notes = ()`; `StepExt::mute()`

- [ ] **Шаг 1: написать падающий тест**

Создать `instrument/tests/notes.rs`:

```rust
//! ПОКАЗАНИЕ НЕСЁТ ЗНАЧЕНИЯ, КОТОРЫМИ ШАГ РАБОТАЛ, А НЕ ОПИСАНИЕ ИХ.
//!
//! Значение не может разойтись с собой; строка может. Прибор тишины решает по трём величинам —
//! сколько молчали, сколько байт пришло и ждёт ли человек прямо сейчас, — и ровно они обязаны
//! выйти показанием, иначе решение непредъявимо: чтобы понять его, придётся лезть внутрь машины.
//!
//! Здесь же проверяется закон забывания: показания не читаются никем, значит снятие их не меняет
//! НИ ОДНОГО слова. Это не обещание докблока, а проверка.
use std::fmt::Debug;
use std::time::{Duration, Instant};

use reflex_core::step::{Step, StepExt};
use reflex_core::DetectorEvent;
use reflex_instrument::detect::SilenceInstrument;
use reflex_instrument::wire::Seen;

const PATIENCE: Duration = Duration::from_millis(1_500);

/// СЦЕНАРИЙ ВСТАВШЕГО ПОТОКА: байты были и кончились, пока их ждут.
///
/// Взят дословно из поверки прибора, живущей рядом с ним: цель отдала четыре килобайта, клиент
/// попросил ещё, дальше две секунды тишины при терпении в полторы.
fn a_stalled_stream(start: Instant) -> Vec<DetectorEvent<Seen>> {
    vec![
        (Some(Seen::Received { count: 4_096 }), 0u64),
        (Some(Seen::Sent { count: 100 }), 10),
        (None, 2_000),
    ]
    .into_iter()
    .map(|(seen, after_ms)| {
        let at = start + Duration::from_millis(after_ms);
        match seen {
            Some(seen) => DetectorEvent::Packet { input: seen, at },
            None => DetectorEvent::Tick {
                node: after_ms,
                at,
            },
        }
    })
    .collect()
}

/// Прогнать машину по входам и собрать ТОЛЬКО слова.
fn words<M>(machine: M, inputs: Vec<M::From>) -> Vec<M::To>
where
    M: Step,
    M::To: Debug + PartialEq,
{
    let mut machine = machine;
    let mut said = Vec::new();
    for input in inputs {
        let (next, word, _) = machine.step(input);
        machine = next;
        said.push(word);
    }
    said
}

#[test]
fn nothing_measured_before_the_first_observation() {
    let start = Instant::now();
    let (_, _, noted) = SilenceInstrument::after(PATIENCE).step(DetectorEvent::Tick {
        node: 1,
        at: start + PATIENCE,
    });
    assert_eq!(
        noted, None,
        "мерить не от чего: наблюдений ещё не было, и показание пусто"
    );
}

#[test]
fn the_measurement_leaves_as_a_value() {
    let start = Instant::now();
    let noted: Vec<_> = a_stalled_stream(start)
        .into_iter()
        .scan(SilenceInstrument::after(PATIENCE), |machine, event| {
            let (next, _, noted) = (*machine).step(event);
            *machine = next;
            Some(noted)
        })
        .flatten()
        .collect();

    let last = noted.last().expect("прибор обязан отметить, чем мерил");
    assert_eq!(last.bytes, 4_096, "показание несёт ЗНАЧЕНИЕ, которым решали");
    assert!(last.awaiting, "и ось, без которой решение необъяснимо");
}

#[test]
fn forgetting_the_notes_changes_no_word() {
    let start = Instant::now();

    let with_notes = words(SilenceInstrument::after(PATIENCE), a_stalled_stream(start));
    let without = words(
        SilenceInstrument::after(PATIENCE).mute(),
        a_stalled_stream(start),
    );

    assert_eq!(
        with_notes, without,
        "показания не читаются никем — значит снятие их не меняет ни одного слова"
    );
}
```

**Внимание:** сценарий `a_stalled_stream` перенесён из поверки, живущей в `instrument/src/detect.rs` (модуль тестов рядом с прибором). Сверь **чтением файла**, что варианты `Seen` и величины не разошлись с деревом; если разошлись — правь тест под дерево, а не дерево под тест, и скажи об этом в отчёте. `SilenceInstrument` реализует `Copy`, оттого `(*machine).step(event)` законно; если это перестало быть верным — бери машину по значению через `Option::take`, как это делает `Over`.

- [ ] **Шаг 2: прогнать — убедиться, что не собирается**

```bash
cargo test -p reflex-instrument --test notes 2>&1 | tail -20
```
Ожидается: `mute` не существует, `step` не отдаёт показаний.

- [ ] **Шаг 3: завести функтор забывания**

`core/src/detector.rs`:

```rust
/// ЗВЕНО, ЧЬИ ПОКАЗАНИЯ СНЯТЫ.
///
/// Забывание показаний есть ФУНКТОР: тождественный на объектах и на словах. Оттого он и выразим —
/// показания не читаются никем, и снять их значит не изменить ни одного решения. Читаемое
/// показание сделало бы этот комбинатор ложью, и потому его существование есть проверка закона, а
/// не удобство.
pub struct Muted<D> {
    inner: D,
}

impl<D> Muted<D> {
    pub(crate) fn new(inner: D) -> Self {
        Self { inner }
    }
}

impl<D: crate::step::Step> crate::step::Step for Muted<D> {
    type From = D::From;
    type To = D::To;
    type Notes = ();

    fn step(self, input: Self::From) -> (Self, Self::To, ()) {
        let (stepped, said, _) = self.inner.step(input);
        (Self { inner: stepped }, said, ())
    }
}
```

`core/src/step.rs`, в `StepExt`:

```rust
    /// Снять показания звена. См. [`crate::detector::Muted`].
    fn mute(self) -> crate::detector::Muted<Self> {
        crate::detector::Muted::new(self)
    }
```

- [ ] **Шаг 4: прибор отмечает, чем мерил**

`instrument/src/detect.rs`:

```rust
/// ЧЕМ МЕРИЛИ — величины, по которым принято решение.
///
/// Три оси, и все три несущие: сколько молчали, сколько байт отдала цель и ждёт ли человек прямо
/// сейчас. Молчание есть беда, только если его КТО-ТО ЖДЁТ; без третьей оси показание не
/// объясняет решения.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Measured {
    pub since_ms: u32,
    pub bytes: u32,
    pub awaiting: bool,
}
```

```rust
    /// `None` — мерить не от чего: наблюдений ещё не было.
    type Notes = Option<Measured>;
```

Тело `step` переносится дословно; добавляется сборка `Measured` из тех же полей, по которым решение уже принимается. **Ни одна ветвь решения не меняется** — это и проверяет тест забывания.

- [ ] **Шаг 5: прогнать**

```bash
cargo test -p reflex-instrument --test notes 2>&1 | grep "^test result"
cargo test --workspace --all-features 2>&1 | grep "^test result" | awk '{p+=$4; f+=$6} END {print "наборов:", NR, "прошло:", p, "провалов:", f}'
cargo check --workspace --all-features 2>&1 | grep -c "^warning"
cargo doc --workspace --no-deps --all-features 2>&1 | grep -c "^warning"
cargo fmt --all --check 2>&1 | grep -c "^Diff"
```

- [ ] **Шаг 6: коммит**

Сообщение называет: какие три величины уехали показанием и почему решение от этого не изменилось.

---

## Приёмка плана

| что | до | после |
|---|---|---|
| шагов с выходом-парой | **1** | все |
| `type To`, не объявивших области | **44** | **0** |
| «кто сказал» после `Both` | метка в работе | **позиция в типе** |
| ожидание на пакетной цепочке | нежелательно | **не собирается** (док-тест `compile_fail`) |
| снятие показаний меняет слова | не проверялось | **не меняет** (тест) |
| пустое показание весит | не проверялось | **ноль байт** (тест) |
| тестов в воркспейсе | 822 | не меньше |

## Отличие от спеки, названное вслух

Спека (§10) требует замера горячего пути **до и после на одной записи провода**. В этом репозитории такого замера поставить не на чем: инфраструктуры бенчей нет (`criterion` не подключён, каталога `benches/` не существует), а цифра 3,88 мкс снята на стенде продукта — то есть за границей среза, куда миграция потребителя не входит.

**Решение:** внутри фреймворка предъявляется то, что фреймворк может доказать сам, — «пусто по типу» весит ноль байт. Замер на записи провода остаётся работой продукта и в приёмку этого плана не входит. Если такое замещение неприемлемо, замер обязан стать отдельным планом с постановкой бенчей, а не строкой в этом.

## Что этот план НЕ делает

* **Второй этаж** — цепочка, чьим входным алфавитом служит поток показаний предыдущей.
* **Уплощение показаний** в один поток для ленты; вложенные кортежи остаются как есть.
* **Буквы `Taught` и `Commanded`**, оператор ожидания (`.async()`) — страж написан, потребителя у него пока нет по построению.
* **Ограничение работы на тик** (`ExpiringSet`, `FlowTable`).
* **Миграция потребителя.**
