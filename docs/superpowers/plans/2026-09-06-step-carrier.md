# Единый носитель: диалекты машины Мили входят в `core::step::Step`

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Сделать `core::step::Step` доказанным общим носителем: детектор, реактор и движок входят в него подъёмом, категория получает тождество и проверенную ассоциативность, седьмой диалект (`runtime::stage::Stage`) сносится.

**Architecture:** Подъём делается **обёртками** (`Detecting<D>`, `Reacting<R>`, `Advancing<'a>`), а не blanket-impl'ами. Blanket'ы не складываются: `impl<D: Detector> Step for D` и `impl<R: Reactor> Step for R` перекрываются по когерентности, потому что тип может реализовать оба трейта. Обёртка складывается со всем и не трогает ни одной из 17 существующих реализаций `Detector`. Ни один диалект в этом плане не удаляется, кроме `Stage`, у которого ноль потребителей: план доказывает, что носитель общий, и не ломает работающее.

**Tech Stack:** Rust 2021, без новых зависимостей. Законы проверяются **исчерпывающим перебором конечного мира** — домашнее правило репы (`core/tests/category_laws.rs`: «перебор всех состояний строже любого property-раннера и не требует новой зависимости»).

**Spec:** `docs/vision/2026-09-06-reflex-investigable-step-vision.md`, разделы 2 (обязательство A), 3 (единая подпись), 9 (что отменяется).

## Что в план НЕ входит и почему

- **`Plane::feed(&mut self, …)`** — переезд на `self` был бы работой, которую план №4 («расслоение `Plane` по ключам») переделает: плоскость держит два ключа и обязана стать двумя машинами прежде, чем становиться одной.
- **`NfqHandler::handle`** — по vision §3 это **драйвер**, а не морфизм; его предмет — план №2 («доставка тишины и функтор способностей»).
- **`CanReplay::seed()`** — по vision §8.4 поглощает `Reactor::start()`, но заводится вместе с восьмым законом, план №3. Здесь `start()` остаётся как есть.

## Global Constraints

- **Новых зависимостей не добавлять.** Ни `proptest`, ни `quickcheck`: законы — исчерпывающим перебором.
- **`Step` не получает `Clone` в баунды.** `core/src/step.rs` объявил это намеренно: «таблица потоков клонируется дорого, и цена платилась бы на каждом пакете».
- **`engine` пишется в стиле `#![no_std]`**: `core::marker::PhantomData`, не `std::marker::PhantomData`.
- **Комментарии и сообщения коммитов — по-русски**, в голосе репы: назвать, что чинится, и назвать цену. Прописные — для несущего утверждения.
- **Каждый коммит оставляет `cargo check --workspace --all-targets` зелёным.**
- Сообщения коммитов оканчиваются:
  ```
  Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01ShUeKABPB2PovYEPdVd4d4
  ```

---

### Task 1: `Detecting<D>` — детектор входит в категорию шага

**Files:**
- Create: `core/src/lifting.rs`
- Modify: `core/src/lib.rs` — вставить `pub mod lifting;` непосредственно перед строкой `pub mod meter;`
- Modify: `core/tests/step.rs:8` — протухшая ссылка на несуществующий `lifting.rs`
- Test: `core/tests/lifting.rs`

**Interfaces:**
- Consumes: `reflex_core::detector::{Detector, DetectorEvent}`, `reflex_core::step::{Step, StepExt}`
- Produces: `reflex_core::lifting::Detecting<D>` — кортежная структура с одним публичным полем; `impl<D: Detector> Step for Detecting<D>` с `From = DetectorEvent<D::Input>`, `To = SmallVec<[D::Signal; 2]>`

- [ ] **Step 1: Написать падающий тест**

Создать `core/tests/lifting.rs`:

```rust
//! ДИАЛЕКТЫ ВХОДЯТ В КАТЕГОРИЮ ШАГА — проверкой, а не заявлением.
//!
//! Vision §3 утверждает: сводить нечего, подпись уже написана, диалекты входят в неё дисциплиной
//! на алфавиты. Утверждение проверяемо ровно одним способом — собрать цепочку, где звено из
//! чужого диалекта стоит рядом с обычным шагом. Соберётся — носитель общий; не соберётся —
//! совпадение подписей было косметическим.

use reflex_core::detector::{Detector, DetectorEvent};
use reflex_core::lifting::Detecting;
use reflex_core::step::{Step, StepExt};
use smallvec::{smallvec, SmallVec};
use std::time::Instant;

/// СЧЁТЧИК ПАКЕТОВ: отдаёт порядковый номер и молчит на тике.
///
/// Тик обязан быть в алфавите и обязан НЕ порождать сигнала: тишина есть наблюдение, а не
/// выдуманное событие.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Counting(u32);

impl Detector for Counting {
    type Input = u8;
    type Signal = u32;

    fn step(self, event: DetectorEvent<u8>) -> (Self, SmallVec<[u32; 2]>) {
        match event {
            DetectorEvent::Packet { .. } => (Counting(self.0 + 1), smallvec![self.0]),
            DetectorEvent::Tick { .. } => (self, SmallVec::new()),
        }
    }
}

/// ВТОРОЕ ЗВЕНО — обычный шаг, не детектор. В этом и предмет теста.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Summing(u32);

impl Step for Summing {
    type From = SmallVec<[u32; 2]>;
    type To = u32;

    fn step(self, input: SmallVec<[u32; 2]>) -> (Self, u32) {
        let total = self.0 + input.iter().sum::<u32>();
        (Summing(total), total)
    }
}

/// ДЕТЕКТОР СТАНОВИТСЯ ЗВЕНОМ ЦЕПОЧКИ, и состояние живёт у обоих.
#[test]
fn detector_enters_the_step_category() {
    let chain = Detecting(Counting(0)).then(Summing(0));

    let (chain, first) = chain.step(DetectorEvent::Packet {
        input: 1,
        at: Instant::now(),
    });
    let (chain, second) = chain.step(DetectorEvent::Packet {
        input: 2,
        at: Instant::now(),
    });
    let (_chain, on_tick) = chain.step(DetectorEvent::Tick { at: Instant::now() });

    assert_eq!(first, 0, "первый пакет: номер 0, сумма 0");
    assert_eq!(second, 1, "второй: номер 1, сумма 0+1");
    assert_eq!(on_tick, 1, "тик сигнала не дал — сумма не сдвинулась");
}
```

- [ ] **Step 2: Прогнать тест и убедиться, что он падает**

Run: `cargo test -p reflex-core --test lifting`
Expected: FAIL со сборкой — `unresolved import reflex_core::lifting` / `could not find lifting in reflex_core`.

- [ ] **Step 3: Написать минимальную реализацию**

Создать `core/src/lifting.rs`:

```rust
//! ПОДЪЁМ ДИАЛЕКТОВ В КАТЕГОРИЮ ШАГА (#326, шестой vision §3).
//!
//! # Что этим лечится
//!
//! Машина Мили написана в репе шесть раз, в шести несовместимых подписях. Замер 06.09.2026:
//! `Detector::step`, `Reactor::step`, `step::Step::step`, `engine::step::step`, `Plane::feed`,
//! `NfqHandler::handle`. Шесть диалектов означают, что цепочка из звеньев разных крейтов не
//! собирается вовсе, — и оттого сшивка кончалась императивщиной.
//!
//! Сводить при этом нечего: подпись уже написана ([`crate::step::Step`]). Диалекты входят в неё
//! ДИСЦИПЛИНОЙ НА АЛФАВИТЫ — много выходов есть одно значение, необязательность есть `Option`, —
//! и здесь эта дисциплина применяется.
//!
//! # Почему обёртка, а не blanket-impl
//!
//! `impl<D: Detector> Step for D` выглядит короче и НЕ СКЛАДЫВАЕТСЯ: реактор захотел бы такого же
//! blanket'а, а тип вправе реализовать оба трейта — когерентность разводит их отказом сборки.
//! Обёртка складывается со всем и не трогает ни одной из существующих реализаций: 17 приборов
//! остаются как были.
//!
//! ЦЕНА НАЗВАНА: одно перемещение структуры на шаг. Поле единственное, представление
//! прозрачное — оптимизатор его снимает, но обещать это без замера мы не будем.

use smallvec::SmallVec;

use crate::detector::{Detector, DetectorEvent};
use crate::step::Step;

/// ДЕТЕКТОР КАК МОРФИЗМ КАТЕГОРИИ ШАГА.
///
/// Алфавит входа — `Packet | Tick`, и это не украшение: тик есть буква, а не сервис, и потому
/// детектор, судящий о тишине, выражается без часов (см. [`crate::interleave`]).
///
/// Алфавит выхода — `SmallVec` до двух сигналов. Много выходов есть ОДНО значение, и потому
/// многовыходность не требует от подписи ничего.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Detecting<D>(pub D);

impl<D: Detector> Step for Detecting<D> {
    type From = DetectorEvent<D::Input>;
    type To = SmallVec<[D::Signal; 2]>;

    fn step(self, input: Self::From) -> (Self, Self::To) {
        let (next, told) = self.0.step(input);
        (Detecting(next), told)
    }
}
```

Вставить в `core/src/lib.rs` строку `pub mod lifting;` непосредственно ПЕРЕД строкой `pub mod meter;`.

- [ ] **Step 4: Прогнать тест и убедиться, что он проходит**

Run: `cargo test -p reflex-core --test lifting`
Expected: PASS, 1 тест.

- [ ] **Step 5: Убрать протухшую ссылку**

`core/tests/step.rs`, строка 8, сегодня гласит:

```
//! Здесь заводится БАЗА: морфизм как машина Мили. Поток получается из неё функтором, обратно —
//! нет, и это не пробел, а несущая стена (см. `lifting.rs`).
```

Файла `lifting.rs` на момент написания той строки не существовало, и ссылка вела в пустоту. Теперь файл есть, но он про ДРУГОЕ направление подъёма (диалекты → шаг), а функтор шаг → поток живёт в `step.rs`. Заменить хвост строки на точный адрес:

```
//! Здесь заводится БАЗА: морфизм как машина Мили. Поток получается из неё функтором, обратно —
//! нет, и это не пробел, а несущая стена (`step::StepExt::over`). Обратное направление —
//! подъём чужих диалектов В категорию шага — живёт в `lifting.rs`.
```

- [ ] **Step 6: Проверить, что весь воркспейс цел**

Run: `cargo check --workspace --all-targets`
Expected: exit 0.

- [ ] **Step 7: Коммит**

```bash
git add core/src/lifting.rs core/src/lib.rs core/tests/lifting.rs core/tests/step.rs
git commit -F - <<'EOF'
feat(step): детектор входит в категорию шага — `Detecting<D>`

Диалектов машины Мили в репе шесть, и оттого цепочка из звеньев разных крейтов не
собиралась вовсе. Сводить при этом нечего: подпись написана (`step::Step`), диалекты
входят в неё дисциплиной на алфавиты.

ОБЁРТКА, А НЕ BLANKET-IMPL, и это не вкус: `impl<D: Detector> Step for D` не
складывается с таким же для реактора — тип вправе реализовать оба трейта, и
когерентность разводит их отказом сборки. Обёртка складывается со всем и не трогает
ни одной из 17 существующих реализаций `Detector`.

ЦЕНА НАЗВАНА: одно перемещение структуры на шаг.

Заодно убрана ссылка на `lifting.rs` из `core/tests/step.rs:8` — файла не было на
момент, когда ссылку писали, и вела она в пустоту.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01ShUeKABPB2PovYEPdVd4d4
EOF
```

---

### Task 2: `Reacting<R>` — реактор входит в категорию шага

**Files:**
- Modify: `core/src/lifting.rs` — дописать в конец
- Test: `core/tests/lifting.rs` — дописать в конец

**Interfaces:**
- Consumes: `reflex_core::Reactor`, `reflex_core::lifting::Detecting` (из Task 1), `reflex_core::step::{Step, StepExt}`
- Produces: `reflex_core::lifting::Reacting<R>` — кортежная структура с одним публичным полем; `impl<R: Reactor> Step for Reacting<R>` с `From = R::Event`, `To = Option<R::Effect>`; ассоциированная функция `Reacting::<R>::started() -> (Reacting<R>, Option<R::Effect>)`

- [ ] **Step 1: Написать падающий тест**

Дописать в конец `core/tests/lifting.rs`:

```rust
use reflex_core::lifting::Reacting;
use reflex_core::Reactor;

/// ПЕРЕКЛЮЧАТЕЛЬ: каждое событие меняет состояние и объявляет новое.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Toggle(bool);

impl Reactor for Toggle {
    type Event = ();
    type Effect = bool;

    /// РОЖДЕНИЕ САМО ПО СЕБЕ ДЕЙСТВИЕМ НЕ ЯВЛЯЕТСЯ — эффекта нет.
    fn start() -> (Self, Option<bool>) {
        (Toggle(false), None)
    }

    fn step(self, _event: ()) -> (Self, Option<bool>) {
        (Toggle(!self.0), Some(!self.0))
    }
}

/// РЕАКТОР, ЧЬЁ РОЖДЕНИЕ ЕСТЬ ДЕЙСТВИЕ. Второй случай нужен затем, что `started` обязан эффект
/// рождения ОТДАТЬ, а не проглотить: `group_by_reactor` его сегодня отбрасывает, и это названная
/// потеря, которую подъём повторять не должен.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Announcing(u8);

impl Reactor for Announcing {
    type Event = u8;
    type Effect = u8;

    fn start() -> (Self, Option<u8>) {
        (Announcing(0), Some(255))
    }

    fn step(self, event: u8) -> (Self, Option<u8>) {
        (Announcing(self.0.wrapping_add(event)), Some(self.0))
    }
}

/// РЕАКТОР СТАНОВИТСЯ ЗВЕНОМ ЦЕПОЧКИ.
#[test]
fn reactor_enters_the_step_category() {
    let (machine, birth) = Reacting::<Toggle>::started();
    assert_eq!(birth, None, "рождение переключателя действием не является");

    let (machine, first) = machine.step(());
    let (_machine, second) = machine.step(());

    assert_eq!(first, Some(true));
    assert_eq!(second, Some(false));
}

/// ЭФФЕКТ РОЖДЕНИЯ ОТДАЁТСЯ, А НЕ ГЛОТАЕТСЯ.
#[test]
fn birth_effect_is_returned_not_swallowed() {
    let (_machine, birth) = Reacting::<Announcing>::started();
    assert_eq!(
        birth,
        Some(255),
        "эффект рождения обязан выйти наружу: проглотив его, подъём повторил бы \
         названную потерю group_by_reactor"
    );
}
```

- [ ] **Step 2: Прогнать тесты и убедиться, что они падают**

Run: `cargo test -p reflex-core --test lifting`
Expected: FAIL со сборкой — `cannot find type Reacting in module reflex_core::lifting`.

- [ ] **Step 3: Написать минимальную реализацию**

Дописать в конец `core/src/lifting.rs`:

```rust
use crate::reactor::Reactor;

/// РЕАКТОР КАК МОРФИЗМ КАТЕГОРИИ ШАГА.
///
/// Алфавит выхода — `Option<Effect>`: «переход состоялся, действия не требует» есть законный
/// исход, а не пустота. Необязательность выражается значением и потому от подписи ничего не
/// требует.
///
/// # Начальное состояние остаётся у реактора
///
/// [`Reactor::start`] здесь не поглощается: его место — способность `CanReplay::seed`, которая
/// заводится вместе с восьмым законом эталона (шестой vision §8.4). До тех пор [`Self::started`]
/// лишь ПРОНОСИТ рождение наружу, ничего не решая за вызывающего.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reacting<R>(pub R);

impl<R: Reactor> Reacting<R> {
    /// РОДИТЬ МАШИНУ ВМЕСТЕ С ЭФФЕКТОМ РОЖДЕНИЯ.
    ///
    /// Эффект возвращается, а не отбрасывается. `group_by_reactor` его сегодня глотает — с
    /// названной причиной («единственный текущий потребитель его не производит»), — но повторять
    /// потерю в общем подъёме значило бы сделать её умолчанием вместо частного случая.
    pub fn started() -> (Self, Option<R::Effect>) {
        let (initial, birth) = R::start();
        (Reacting(initial), birth)
    }
}

impl<R: Reactor> Step for Reacting<R> {
    type From = R::Event;
    type To = Option<R::Effect>;

    fn step(self, input: Self::From) -> (Self, Self::To) {
        let (next, effect) = self.0.step(input);
        (Reacting(next), effect)
    }
}
```

- [ ] **Step 4: Прогнать тесты и убедиться, что они проходят**

Run: `cargo test -p reflex-core --test lifting`
Expected: PASS, 3 теста.

- [ ] **Step 5: Проверить воркспейс**

Run: `cargo check --workspace --all-targets`
Expected: exit 0.

- [ ] **Step 6: Коммит**

```bash
git add core/src/lifting.rs core/tests/lifting.rs
git commit -F - <<'EOF'
feat(step): реактор входит в категорию шага — `Reacting<R>`

Второй из шести диалектов. Алфавит выхода — `Option<Effect>`: «переход состоялся,
действия не требует» есть законный исход, а не пустота.

ЭФФЕКТ РОЖДЕНИЯ ОТДАЁТСЯ, А НЕ ГЛОТАЕТСЯ. `group_by_reactor` его отбрасывает с
названной причиной («текущий потребитель его не производит»); повторить это в ОБЩЕМ
подъёме значило бы сделать частный случай умолчанием. `started` возвращает пару.

`Reactor::start` при этом не поглощается: его место — `CanReplay::seed` вместе с
восьмым законом эталона (шестой vision §8.4), и забирать его раньше закона незачем.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01ShUeKABPB2PovYEPdVd4d4
EOF
```

---

### Task 3: Ассоциативность композиции — исчерпывающим перебором

**Files:**
- Test: `core/tests/step_laws.rs` (создать)

**Interfaces:**
- Consumes: `reflex_core::step::{Step, StepExt}`
- Produces: ничего для последующих задач — это чистый закон, публичного API не заводит

- [ ] **Step 1: Написать падающий тест**

Создать `core/tests/step_laws.rs`:

```rust
//! ЗАКОНЫ КАТЕГОРИИ НА НОСИТЕЛЕ ЗНАЧЕНИЯ (шестой vision §9).
//!
//! Vision 3 §6 объявил ассоциативность и тождество для носителя-потока. Носитель сменился, и
//! законы обязаны быть предъявлены заново: у потока ассоциативность держалась тем, что операторы
//! не имели состояния, а у машины Мили состояние есть по определению — значит и сломать её можно
//! иначе (композит, пересобирающий второе звено из начального, выглядит исправным ровно до
//! второго входа).
//!
//! # Метод: исчерпывающий перебор, а не property-раннер
//!
//! Домашнее правило репы (`core/tests/category_laws.rs`): «перебор всех состояний строже любого
//! property-раннера и не требует новой зависимости». Мир конечен, равенство НАБЛЮДАТЕЛЬНОЕ: две
//! цепочки равны, если на всех входах дают один выход.
//!
//! # ЧТО ЭТОТ ЗАКОН СТОРОЖИТ НА САМОМ ДЕЛЕ — сказано прямо
//!
//! Сломать `Then`, СОХРАНИВ СИГНАТУРУ, невозможно: состояние второго звена переносится
//! семантикой перемещения, и попытка вернуть вместо него старое даёт
//! `E0382: use of moved value: self.1` (проверено 06.09.2026). То есть ассоциативность здесь
//! сторожит РЕГРЕССИЮ СИГНАТУРЫ, а не логику, и называть её обезоруженной было бы враньём —
//! ровно тем, которое `category_laws.rs` однажды у себя и поймал.
//!
//! Закон о жизни состояния уже предъявлен и здесь НЕ ПОВТОРЯЕТСЯ:
//! `core/tests/step.rs::composition_carries_the_state_of_both_links`.

use reflex_core::step::{Step, StepExt};

/// МИР КОНЕЧЕН: все непустые последовательности длины ≤ 3 из трёх значений — 39 входов.
///
/// Длина три — минимальная, на которой видна разница между «состояние живёт» и «состояние
/// пересобирается»: на одном входе неисправный композит неотличим от исправного.
fn world() -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for a in 0..3u8 {
        out.push(vec![a]);
    }
    for a in 0..3u8 {
        for b in 0..3u8 {
            out.push(vec![a, b]);
        }
    }
    for a in 0..3u8 {
        for b in 0..3u8 {
            for c in 0..3u8 {
                out.push(vec![a, b, c]);
            }
        }
    }
    out
}

/// ПРОГНАТЬ ЦЕПОЧКУ ПО ВХОДАМ И СОБРАТЬ ВЫХОДЫ. Наблюдательное равенство меряется этим.
fn run<M: Step<From = u8, To = u8>>(machine: M, input: &[u8]) -> Vec<u8> {
    let mut machine = machine;
    let mut told = Vec::with_capacity(input.len());
    for byte in input {
        let (next, out) = machine.step(*byte);
        machine = next;
        told.push(out);
    }
    told
}

/// СУММАТОР: помнит всё, что прошло.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Adding(u8);

impl Step for Adding {
    type From = u8;
    type To = u8;

    fn step(self, input: u8) -> (Self, u8) {
        let sum = self.0.wrapping_add(input);
        (Adding(sum), sum)
    }
}

/// ЗАПАЗДЫВАЮЩИЙ УДВОИТЕЛЬ: отдаёт удвоенный вход плюс ПРЕДЫДУЩИЙ вход.
///
/// Состояние здесь не накопитель, а память об одном шаге назад: два разных вида памяти в одном
/// мире делают закон менее склонным к случайному прохождению.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Doubling(u8);

impl Step for Doubling {
    type From = u8;
    type To = u8;

    fn step(self, input: u8) -> (Self, u8) {
        let out = input.wrapping_mul(2).wrapping_add(self.0);
        (Doubling(input), out)
    }
}

/// РЕКОРДСМЕН: самое большое, что видел.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Maxing(u8);

impl Step for Maxing {
    type From = u8;
    type To = u8;

    fn step(self, input: u8) -> (Self, u8) {
        let top = self.0.max(input);
        (Maxing(top), top)
    }
}

/// ЗАКОН 1: `(f ∘ g) ∘ h ≡ f ∘ (g ∘ h)`.
///
/// Типы у двух сторон РАЗНЫЕ (`Then<Then<A,B>,C>` против `Then<A,Then<B,C>>`), и потому равенство
/// здесь может быть только наблюдательным — компилятор его не проверит и проверить не может.
#[test]
fn composition_is_associative() {
    for input in world() {
        let left = run(Adding(0).then(Doubling(0)).then(Maxing(0)), &input);
        let right = run(Adding(0).then(Doubling(0).then(Maxing(0))), &input);
        assert_eq!(left, right, "вход {input:?}");
    }
}

```

- [ ] **Step 2: Прогнать и убедиться, что тесты ПРОХОДЯТ**

Run: `cargo test -p reflex-core --test step_laws`
Expected: PASS, 1 тест.

Это единственная задача плана, где тест зелёный сразу, и это законно: закон не заводит поведения, он предъявляет уже существующее.

- [ ] **Step 3: Попытаться обезоружить и записать ЧЕСТНЫЙ исход**

Тест, которого нельзя сломать, силы не имеет — а тест, чей слом не компилируется, имеет силу ИНУЮ, чем кажется. Репа за смешение этих двух случаев уже платила (`category_laws.rs`: «ложное обезоруживание случилось здесь же и было поймано только проверкой самой сборки»). Проверяем сборкой.

Временно испортить `core/src/step.rs`, в `impl Step for Then` заменить строку

```rust
        (Then(first, second), out)
```

на

```rust
        (Then(first, self.1), out)
```

Run: `cargo check -p reflex-core`

Expected — НЕ падение теста, а отказ сборки:

```
error[E0382]: use of moved value: `self.1`
  --> core/src/step.rs:69:22
   |
68 |         let (second, out) = self.1.step(middle);
   |                                    ------------ `self.1` moved due to this method call
69 |         (Then(first, self.1), out)
   |                      ^^^^^^ value used here after move
```

Это и есть искомый результат: **жизнь состояния держит не тест, а семантика перемещения.** Закон остаётся сторожем регрессии сигнатуры — и ровно так он и описан в шапке файла, без преувеличения его силы.

**Немедленно вернуть строку обратно:**

Run: `cargo check -p reflex-core && cargo test -p reflex-core --test step_laws`
Expected: exit 0; PASS, 1 тест.

- [ ] **Step 4: Коммит**

```bash
git add core/tests/step_laws.rs
git commit -F - <<'EOF'
test(step): ассоциативность композиции на носителе значения

Vision 3 §6 объявил законы для носителя-потока. Носитель сменился, и предъявлять их
надо заново: у потока ассоциативность держалась тем, что операторы не имели состояния,
а у машины Мили состояние есть по определению.

МЕТОД — ИСЧЕРПЫВАЮЩИЙ ПЕРЕБОР, а не property-раннер: 39 входов, все
последовательности длины ≤ 3 из трёх значений. Домашнее правило репы, и новой
зависимости оно не просит.

СИЛА ЗАКОНА НАЗВАНА ЧЕСТНО. Сломать `Then`, сохранив сигнатуру, невозможно: состояние
второго звена переносится семантикой перемещения, и попытка вернуть старое даёт
`E0382: use of moved value: self.1` — проверено сборкой, а не рассуждением. Значит
закон сторожит РЕГРЕССИЮ СИГНАТУРЫ, а не логику, и так он и описан. Выдать его за
логический было бы тем самым ложным обезоруживанием, которое `category_laws.rs`
однажды поймал у себя.

Закон о жизни состояния не дублируется: он уже предъявлен в
`core/tests/step.rs::composition_carries_the_state_of_both_links`.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01ShUeKABPB2PovYEPdVd4d4
EOF
```

---

### Task 4: Тождественный морфизм `Id<T>` и закон тождества

**Files:**
- Modify: `core/src/step.rs` — дописать после определения `Then`
- Test: `core/tests/step_laws.rs` — дописать в конец

**Interfaces:**
- Consumes: `reflex_core::step::{Step, StepExt}`, `world()` и `run()` из Task 3
- Produces: `reflex_core::step::Id<T>` — `Id::<T>::new() -> Id<T>`, `impl<T> Step for Id<T>` с `From = T`, `To = T`; также `impl<T> Default for Id<T>`

- [ ] **Step 1: Написать падающий тест**

Дописать в конец `core/tests/step_laws.rs`:

```rust
use reflex_core::step::Id;

/// ЗАКОН 2: `id ∘ f ≡ f ≡ f ∘ id`.
///
/// Проверяется с ОБЕИХ сторон намеренно: тождество, пропускающее вход, но теряющее состояние
/// соседа, нарушило бы только одну из них.
///
/// Сила та же, что у ассоциативности: `Id` без состояния сломать, сохранив сигнатуру, нечем —
/// вернуть из `step` что-то, кроме входа, не из чего. Сторож регрессии сигнатуры, и это сказано,
/// а не подразумевается.
#[test]
fn identity_is_neutral_on_both_sides() {
    for input in world() {
        let bare = run(Adding(0), &input);
        let before = run(Id::new().then(Adding(0)), &input);
        let after = run(Adding(0).then(Id::new()), &input);

        assert_eq!(before, bare, "id слева, вход {input:?}");
        assert_eq!(after, bare, "id справа, вход {input:?}");
    }
}
```

- [ ] **Step 2: Прогнать и убедиться, что падает**

Run: `cargo test -p reflex-core --test step_laws`
Expected: FAIL со сборкой — `cannot find type Id in module reflex_core::step`.

- [ ] **Step 3: Написать минимальную реализацию**

Дописать в `core/src/step.rs` сразу после `impl<A, B> Step for Then<A, B> { … }`:

```rust
/// ТОЖДЕСТВЕННЫЙ МОРФИЗМ `id_X : X → X` — второй закон категории (vision 3 §6.2).
///
/// # Почему он существует, если ничего не делает
///
/// Категория определяется объектами, морфизмами И тождеством. Без него композиция есть
/// полугруппа, а не категория, и второй закон предъявить не на чем. Здесь он к тому же не
/// украшение: необязательное звено цепочки, выключенное настройкой, обязано выражаться В ТОЙ ЖЕ
/// алгебре, а не особым случаем у вызывающего.
///
/// Состояния нет по построению, и это ровно то, что делает его нейтральным: звено с памятью
/// нейтральным быть не может, потому что меняет то, что видят соседи.
pub struct Id<T>(std::marker::PhantomData<T>);

impl<T> Id<T> {
    pub fn new() -> Self {
        Id(std::marker::PhantomData)
    }
}

impl<T> Default for Id<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> Step for Id<T> {
    type From = T;
    type To = T;

    fn step(self, input: T) -> (Self, T) {
        (self, input)
    }
}
```

- [ ] **Step 4: Прогнать и убедиться, что проходит**

Run: `cargo test -p reflex-core --test step_laws`
Expected: PASS, 3 теста.

- [ ] **Step 5: Проверить воркспейс и линтер**

Run: `cargo check --workspace --all-targets && cargo clippy -p reflex-core --all-targets`
Expected: exit 0, без предупреждений о `new_without_default` (для этого и заведён `Default`).

- [ ] **Step 6: Коммит**

```bash
git add core/src/step.rs core/tests/step_laws.rs
git commit -F - <<'EOF'
feat(step): тождественный морфизм `Id<T>` и второй закон категории

Без тождества композиция есть полугруппа, а не категория, и предъявить второй закон
не на чем. Заводится вместе с законом, а не до него.

НЕ УКРАШЕНИЕ: необязательное звено, выключенное настройкой, обязано выражаться в ТОЙ ЖЕ
алгебре — иначе оно становится особым случаем у каждого вызывающего. Ровно эту роль
`Step::optional` играет у restriction-категории в `reflex-os` (`f ⊔ id`).

Состояния нет по построению, и это и делает морфизм нейтральным: звено с памятью
нейтральным быть не может, потому что меняет то, что видят соседи. Закон проверяется
С ОБЕИХ сторон: тождество, теряющее состояние соседа, нарушило бы только одну.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01ShUeKABPB2PovYEPdVd4d4
EOF
```

---

### Task 5: `Advancing<'a>` — движок входит в категорию шага

**Files:**
- Modify: `engine/src/step.rs` — дописать в конец
- Test: `engine/tests/lifting.rs` (создать)

**Interfaces:**
- Consumes: `reflex_core::step::{Step, StepExt}`, `reflex_engine::step::step` (свободная функция, остаётся как есть), `reflex_engine::{Act, Cursor, Epoch, Noted, Packet, Plan, Tick}`
- Produces: `reflex_engine::step::Advancing<'a>` — публичные поля `cursor: Cursor` и `epoch: Epoch`; `Advancing::new(cursor: Cursor, epoch: Epoch) -> Advancing<'a>`; `impl<'a> Step for Advancing<'a>` с `From = (Plan, Packet<'a>, Tick)`, `To = (Act, Option<Noted>)`

- [ ] **Step 1: Написать падающий тест**

Создать `engine/tests/lifting.rs`:

```rust
//! ДВИЖОК ВХОДИТ В КАТЕГОРИЮ ШАГА (шестой vision §3).
//!
//! Третий из шести диалектов и единственный, у которого вход НЕ БЫЛ ЗАМКНУТ: знание о цели
//! приходило Reader'ом (`look_up: Fn(&Packet) -> Plan`), то есть незаписанным входом. Здесь оно
//! становится БУКВОЙ входного алфавита, и этим переигровка одного разговора замыкается: чтобы
//! прогнать его заново, не нужна вся таблица целей — довольно того, что `look_up` ответил.

use reflex_core::step::{Step, StepExt};
use reflex_engine::row::Naming;
use reflex_engine::step::Advancing;
use reflex_engine::{
    Act, Addr, Basis, Cursor, Dir, Epoch, FlowKey, Interest, Noted, Packet, Plan, Programme, Tick,
};

fn plan() -> Plan {
    Plan {
        programme: Programme::Pass,
        epoch: Epoch(1),
        basis: Basis::Default,
        interest: Interest::Idle,
    }
}

fn opening(payload: &[u8]) -> Packet<'_> {
    Packet {
        flow: FlowKey(7),
        dst: Addr(0x0A00_0001),
        dir: Dir::Up,
        opens: true,
        closes: false,
        resets: false,
        payload,
        says: Naming::Awaited,
    }
}

/// ДВИЖОК СТАНОВИТСЯ МОРФИЗМОМ: курсор — состояние, вердикт и наблюдение — выход.
#[test]
fn engine_enters_the_step_category() {
    let machine = Advancing::new(Cursor::Fresh, Epoch(1));
    let bytes = [1u8, 2, 3];

    let (machine, (act, told)) = machine.step((plan(), opening(&bytes), Tick(1)));

    assert_eq!(act, Act::Pass, "план говорит пропускать");
    assert!(told.is_some(), "открытие разговора есть наблюдение");
    assert!(
        matches!(machine.cursor, Cursor::Running(_)),
        "курсор обязан переехать в состояние машины, а не остаться в выходе"
    );
}

/// СЧЁТЧИК НАБЛЮДЕНИЙ — обычное звено, не движок. В этом и предмет теста: носитель ОБЩИЙ.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CountingSightings(u32);

impl Step for CountingSightings {
    type From = (Act, Option<Noted>);
    type To = u32;

    fn step(self, (_act, told): Self::From) -> (Self, u32) {
        let seen = self.0 + u32::from(told.is_some());
        (CountingSightings(seen), seen)
    }
}

/// ЦЕПОЧКА «ДВИЖОК → ЧУЖОЕ ЗВЕНО» СОБИРАЕТСЯ.
///
/// Не собралась бы — совпадение подписей было бы косметическим, и §3 vision пришлось бы
/// переписывать.
#[test]
fn engine_composes_with_a_foreign_link() {
    let chain = Advancing::new(Cursor::Fresh, Epoch(1)).then(CountingSightings(0));
    let bytes = [1u8, 2, 3];

    let (_chain, seen) = chain.step((plan(), opening(&bytes), Tick(1)));

    assert_eq!(seen, 1, "открытие дало одно наблюдение");
}

/// ЛАЙФТАЙМ НЕ ТЕЧЁТ НАРУЖУ: машина переживает пакет, чьи байты заимствованы.
#[test]
fn machine_outlives_the_borrowed_packet() {
    let mut machine = Advancing::new(Cursor::Fresh, Epoch(1));
    for tick in 1..4u64 {
        let bytes = [tick as u8; 3];
        let (next, _told) = machine.step((plan(), opening(&bytes), Tick(tick)));
        machine = next;
    }
    assert!(matches!(machine.cursor, Cursor::Running(_)));
}
```

- [ ] **Step 2: Прогнать и убедиться, что падает**

Run: `cargo test -p reflex-engine --test lifting`
Expected: FAIL со сборкой — `cannot find type Advancing in module reflex_engine::step`.

- [ ] **Step 3: Написать минимальную реализацию**

Дописать в конец `engine/src/step.rs`:

```rust
/// ДВИЖОК КАК МОРФИЗМ КАТЕГОРИИ ШАГА (шестой vision §3).
///
/// # Что этим лечится
///
/// Свободная функция [`step`] уже была машиной Мили, но в СВОЕЙ подписи: состояние отдельным
/// аргументом, знание — Reader'ом, выход — тройкой в `Stepped`. Цепочка из неё и чужого звена не
/// собиралась, потому что общего носителя не существовало.
///
/// # Знание входит БУКВОЙ, а не Reader'ом, и это несущее
///
/// `look_up: Fn(&Packet) -> Plan` есть НЕЗАПИСАННЫЙ ВХОД: прогнав шаг заново, мы обязаны иметь
/// ту же таблицу целей в том же состоянии — то есть переигровка одного разговора требует
/// восстановить глобальное знание на тот момент. Приняв `Plan` буквой алфавита, мы записываем
/// ОТВЕТ, а не источник, и запись одного разговора становится замкнутой.
///
/// Верности продукту это не нарушает: `Plane::feed` уже зовёт `step` с постоянным замыканием
/// (`|_asked| plan`), разрешив план ДО шага. Буква записывает ровно то, что плоскость разрешила.
///
/// # Курсор переезжает в СОСТОЯНИЕ, а не остаётся в выходе
///
/// `Stepped` несёт `cursor` рядом с `act` и `sighting`. Для морфизма это смешение: состояние
/// принадлежит машине, выход — потребителю. Оттого `To` здесь пара `(Act, Option<Noted>)`, а
/// курсор уезжает в `Self`. Свободная функция при этом остаётся нетронутой: у неё свои
/// потребители, и ломать их ради формы незачем.
///
/// # Лайфтайм в подписи — цена заимствованных байтов
///
/// `Packet<'a>` держит `payload: &'a [u8]`, и ассоциированный тип обязан этот лайфтайм назвать.
/// Свободным параметром импла его оставить нельзя (E0207), поэтому он живёт на структуре
/// [`PhantomData`]. Машина при этом переживает любой отдельный пакет: лайфтайм ковариантен и
/// сужается до самого короткого заимствования в цепочке вызовов.
pub struct Advancing<'a> {
    /// СОСТОЯНИЕ РАЗГОВОРА. Публично: живая интроспекция есть обязательство A шестого vision —
    /// спросить у машины, где она, обязано быть можно, не выполняя шага.
    pub cursor: Cursor,
    /// ЭПОХА, С КОТОРОЙ СВЕРЯЕТСЯ УСТАРЕВАНИЕ ПЛАНА.
    pub epoch: Epoch,
    wire: core::marker::PhantomData<&'a ()>,
}

impl<'a> Advancing<'a> {
    pub fn new(cursor: Cursor, epoch: Epoch) -> Advancing<'a> {
        Advancing {
            cursor,
            epoch,
            wire: core::marker::PhantomData,
        }
    }
}

impl<'a> reflex_core::step::Step for Advancing<'a> {
    type From = (Plan, Packet<'a>, Tick);
    type To = (Act, Option<Noted>);

    fn step(self, (plan, packet, now): Self::From) -> (Self, Self::To) {
        let stepped = step(
            |_asked: &Packet<'a>| plan,
            self.epoch,
            self.cursor,
            &packet,
            now,
        );
        (
            Advancing::new(stepped.cursor, self.epoch),
            (stepped.act, stepped.sighting),
        )
    }
}
```

- [ ] **Step 4: Прогнать и убедиться, что проходит**

Run: `cargo test -p reflex-engine --test lifting`
Expected: PASS, 3 теста.

- [ ] **Step 5: Убедиться, что старые тесты движка целы**

Run: `cargo test -p reflex-engine`
Expected: PASS, все тесты `advance`, `merge`, `row`, `step`, `target`, `watch` зелёные — свободная функция не тронута.

- [ ] **Step 6: Проверить воркспейс**

Run: `cargo check --workspace --all-targets`
Expected: exit 0.

- [ ] **Step 7: Коммит**

```bash
git add engine/src/step.rs engine/tests/lifting.rs
git commit -F - <<'EOF'
feat(engine): движок входит в категорию шага — `Advancing<'a>`

Третий из шести диалектов и единственный, у которого вход НЕ БЫЛ ЗАМКНУТ.

ЗНАНИЕ ВХОДИТ БУКВОЙ, А НЕ READER'ОМ. `look_up: Fn(&Packet) -> Plan` есть
незаписанный вход: прогнав шаг заново, пришлось бы восстановить глобальную таблицу
целей на тот момент — то есть переигровка ОДНОГО разговора требовала бы всего знания.
Приняв `Plan` буквой алфавита, мы записываем ОТВЕТ, а не источник, и запись разговора
становится замкнутой. Продукту это верно: `Plane::feed` уже зовёт `step` с постоянным
замыканием, разрешив план ДО шага.

КУРСОР ПЕРЕЕЗЖАЕТ В СОСТОЯНИЕ. `Stepped` несёт его рядом с `act` и `sighting`; для
морфизма это смешение — состояние принадлежит машине, выход потребителю.

ЦЕНА НАЗВАНА: лайфтайм в подписи. `Packet<'a>` держит заимствованные байты,
свободным параметром импла лайфтайм не оставить (E0207), потому он на структуре
через `PhantomData`. Свободная функция `step` не тронута — у неё свои потребители.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01ShUeKABPB2PovYEPdVd4d4
EOF
```

---

### Task 6: Снос `runtime::stage::Stage` — седьмой диалект и второй `Then`

**Files:**
- Delete: `runtime/src/stage.rs`
- Modify: `runtime/src/lib.rs` — убрать `pub mod stage;` и строку `pub use stage::{Stage, StageExt, StageOutcome, Then};`
- Modify: `runtime/Cargo.toml` — убрать `async-trait = "0.1"`

**Interfaces:**
- Consumes: ничего
- Produces: ничего. Задача только удаляет; после неё `Then` в репе остаётся ровно один — `core::step::Then`

- [ ] **Step 1: Доказать, что потребителей нет**

Run:
```bash
grep -rn "Stage\b\|StageExt\|StageOutcome" --include=*.rs . \
  | grep -v '^./target' | grep -v 'runtime/src/stage.rs' | grep -v '^./docs'
```

Expected: единственная строка — `runtime/src/lib.rs:26: pub use stage::{Stage, StageExt, StageOutcome, Then};`

Совпадения в `core/src/category.rs` — ДРУГОЙ `Stage`: это имя обобщённого параметра `Pipeline<Stage, S>`, а не трейт. Если grep покажет их, они не в счёт; проверить глазами, что путь `core/src/category.rs`.

Если найдётся настоящий потребитель — **остановиться и доложить**: значит замер 06.09.2026 устарел и задача требует пересмотра.

- [ ] **Step 2: Удалить модуль**

```bash
git rm runtime/src/stage.rs
```

В `runtime/src/lib.rs` удалить две строки:
```rust
pub mod stage;
```
```rust
pub use stage::{Stage, StageExt, StageOutcome, Then};
```

- [ ] **Step 3: Убедиться, что `async-trait` больше никому не нужен**

Run: `grep -rn "async_trait" --include=*.rs runtime/ | grep -v target`
Expected: пусто.

Удалить из `runtime/Cargo.toml` строку:
```toml
async-trait = "0.1"
```

- [ ] **Step 4: Прогнать весь воркспейс**

Run: `cargo test --workspace`
Expected: PASS, все тесты зелёные. Ни один тест `Stage` не покрывал — его не существовало, и это часть основания для сноса.

- [ ] **Step 5: Проверить, что `Then` в репе остался один**

Run: `grep -rn "pub struct Then" --include=*.rs . | grep -v '^./target'`
Expected: ровно одна строка — `core/src/step.rs:53:pub struct Then<A, B>(pub A, pub B);`

- [ ] **Step 6: Коммит**

```bash
git add -A runtime/
git commit -F - <<'EOF'
chore(runtime): снос `Stage` — седьмой диалект и второй `Then`

Замер 06.09.2026: у `runtime::stage::Stage` НОЛЬ потребителей — ни в одном крейте, ни
в одном тесте. Тестов у него нет вовсе, то есть механизм существовал и ни разу не
проверялся; снаружи это неотличимо от работающего.

По шестому vision §3 он и не нужен: состояния у него нет, `async` уезжает в драйвер, а
`StageOutcome { Advance, Settle }` выражается выходным алфавитом `Step`. Держал он при
этом ВТОРОЙ тип `Then` в репе — то есть платили мы за него не только строками, но и
вторым ответом на вопрос «что такое композиция».

Уходит вместе с ним `async-trait`: единственным его потребителем был этот модуль.

После правки `Then` в репе один.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01ShUeKABPB2PovYEPdVd4d4
EOF
```

---

## Приёмка плана

После шестой задачи обязаны держаться все утверждения:

- [ ] `cargo test --workspace` зелёный
- [ ] `grep -rn "pub struct Then" --include=*.rs . | grep -v target` — ровно одна строка
- [ ] Детектор, реактор и движок собираются в цепочку с чужим звеном (три теста)
- [ ] Ассоциативность и тождество предъявлены перебором 39 входов; сила обоих названа
      честно — сторожа регрессии сигнатуры, слом не компилируется (`E0382`)
- [ ] Ни одна из 17 реализаций `Detector` не тронута:
      `git diff --stat <база>..HEAD -- instrument/` — пусто
- [ ] Свободная функция `engine::step::step` не тронута:
      её потребители (`Plane::feed`, `engine/tests/step.rs`) зелены

## Что план сознательно оставляет как было

- **Шесть диалектов остаются шестью.** План доказывает, что носитель ОБЩИЙ, и не удаляет
  работающего. Удаление `Detector`/`Reactor` как отдельных трейтов — отдельное решение,
  которое стоит принимать после того, как комбинаторы `DetectorExt` (`Both`, `By`, `Changes`,
  `Contextual`, `LMap`, `RMap`, `Timed`, `Told`) получат форму на носителе шага. Сегодня их
  восемь, и переписывать их вслепую значило бы менять работающее на непроверенное.
- **`Stepped` остаётся тройкой.** Морфизм её расщепляет, свободная функция — нет.
- **`Reactor::start` остаётся на месте** до восьмого закона (план №3).
