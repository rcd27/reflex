# Один носитель: снос `category` и `Reactor`

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Убрать из репы две записи одной идеи — стадийную категорию над потоком и диалект реактора, — оставив `core::step::Step` единственным носителем машины Мили.

**Architecture:** Чистое удаление плюс два переноса. `category::from_source` сводится с уже существующим дублем `certify::observation::watching` в одну дверь, сохраняя проверку `CanObserve` компилятором. Два драйвера рантайма (`expand_effects`, `drive_owned`) — единственное в репе выражение ВНЕШНЕЙ петли — переносятся с `Reactor` на `Step` механически: оба зовут только `step` и `start`, и `start` заменяется явным семенем. После этого `Reactor`, три его драйвера, обёртка `Reacting` и весь модуль `category` удаляются.

**Tech Stack:** Rust 2021, без новых зависимостей. Законы — исчерпывающим перебором конечного мира (домашнее правило `core/tests/category_laws.rs`).

**Spec:** `docs/superpowers/specs/2026-09-06-alphabet-and-absorption-design.md`, §3 «Впитывание: одна идея — одна запись».

## Что этот план НЕ делает

- **`Detector` не трогается.** Его впитывание — 29 реализаций в `src`, восемь комбинаторов и `detect_per`; это отдельный план (2B), крупнее настоящего.
- **`Tap` не сносится.** Его последний потребитель — `with_tap` на фасаде `NfqPipeline`, и умрёт он вместе с фасадом в плане 3.
- **Алфавит не расширяется.** `Packet | Tick | Taught | Ordered` — план 3.

## Названная потеря, которую этот план допускает сознательно

`category::Injection` держал ТИПОМ запрет «оператор после инъектора»: он не реализует `Stream`, и потому ни `StreamExt`, ни `ReflexExt` до него не дотягивались.

После сноса гарантии нет **до плана 3**, и там она возвращается сильнее: в `engine(NFQ) { … }` инъекция не является морфизмом цепочки вовсе — цепочка отдаёт СЛОВО, а применяет его драйвер. Продолжать нечего, потому что продолжать не за чем.

Междуцарствие названо здесь намеренно: молчаливая потеря гарантии — тот самый дефект, который репа ловит у себя. Названная — предмет следующего плана.

## Global Constraints

- **Новых зависимостей не добавлять.**
- **`Step` не получает `Clone` в баунды** — `core/src/step.rs` отказывает намеренно.
- **`engine` пишется в стиле `#![no_std]`**: `core::marker::PhantomData`. `core` и `runtime` — std-крейты.
- Комментарии и сообщения коммитов **по-русски**, в голосе репы: назвать, что чинится, и назвать цену. Прописные — для несущего утверждения.
- **Цена называется ВЫБОРОМ, а не свойством.** Замер 06.09.2026: из 35 докблоков, называющих цену, выбором её формулирует один. Свойство не пересматривается никогда; выбор пересматривается на первом чтении.
- Каждый коммит оставляет `cargo test --workspace` зелёным.
- Сообщения коммитов оканчиваются:
  ```
  Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01ShUeKABPB2PovYEPdVd4d4
  ```

---

### Task 1: Одна дверь к наблюдениям вместо двух

**Files:**
- Modify: `core/src/backend.rs` — дописать функцию и её `use`
- Modify: `core/src/certify/observation.rs` — `watching` становится реэкспортом
- Test: `core/tests/backend.rs` — заменить употребление `from_source`

**Interfaces:**
- Consumes: `reflex_core::backend::Source`, `reflex_core::capability::CanObserve`
- Produces: `reflex_core::backend::observing<B>(&mut B) -> B::Packets<'_> where B: Source + CanObserve`

**Почему это первая задача.** `category::from_source` и `certify::observation::watching` делают одно и то же — берут `packets()` и требуют `CanObserve`. Второй при этом объявляет себя «дверью к наблюдениям этого бэкенда — и единственной». Две записи одной идеи: снести `category`, не сведя их, значило бы унести проверку способности в модуль законов.

- [ ] **Step 1: Написать падающий тест**

В `core/tests/backend.rs` заменить строку импорта

```rust
use reflex_core::category::{from_source, Terminal};
```

на

```rust
use reflex_core::backend::observing;
```

и дописать в конец файла:

```rust
/// ДВЕРЬ К НАБЛЮДЕНИЯМ ТРЕБУЕТ ЗАЯВЛЕННОЙ СПОСОБНОСТИ, и это проверяет компилятор.
///
/// Прежде проверка стояла в двух местах — `category::from_source` и
/// `certify::observation::watching`, — и делала одно и то же. Две записи одной идеи расходятся
/// молча; здесь она одна.
#[tokio::test]
async fn observing_takes_packets_from_a_declared_observer() {
    let mut backend = Mirror::new(vec![vec![1u8, 2], vec![3]]);
    let seen: Vec<Vec<u8>> = observing(&mut backend).collect().await;

    assert_eq!(seen, vec![vec![1u8, 2], vec![3]], "все пакеты дошли до потребителя");
}
```

Если в файле нет памятного бэкенда с именем `Mirror`, использовать тот, что там уже есть, — имя взять из файла, поведение теста не менять.

- [ ] **Step 2: Прогнать и убедиться, что падает**

Run: `cargo test -p reflex-core --test backend`
Expected: FAIL со сборкой — `unresolved import reflex_core::backend::observing`.

- [ ] **Step 3: Написать реализацию**

Дописать в конец `core/src/backend.rs`:

```rust
/// ДВЕРЬ К НАБЛЮДЕНИЯМ ЭТОГО БЭКЕНДА — И ЕДИНСТВЕННАЯ.
///
/// # Что этим чинится
///
/// Дверей было две: `category::from_source` и `certify::observation::watching`. Обе брали
/// `packets()` и обе требовали [`CanObserve`](crate::capability::CanObserve) — то есть одна идея
/// была записана дважды, а такие записи расходятся молча (оплачено ключом, добываемым на каждой
/// стороне по-своему: 1136 флоу из 1136 мимо).
///
/// # Функция ничего не делает сверх `packets()`, и в этом её смысл
///
/// Она требует ЗАЯВЛЕННОЙ способности. Поток, поданный дальше, не подсунуть от типа, который
/// наблюдать не заявлял; а раз `CanObserve` требует [`Source`], заявить его пустым тоже нельзя.
///
/// # Ограничение потока сюда НЕ входит
///
/// ВЫБОР, а не свойство: у живого бэкенда поток бесконечен, и обрезать его умеет только тот, у
/// кого есть часы. Дай мы потолок здесь — дверь мерила бы время, а не способность. Альтернатива
/// (принимать предел аргументом) отвергнута затем, что предел принадлежит ведущему циклу и меняется
/// без ведома двери.
pub fn observing<B>(backend: &mut B) -> B::Packets<'_>
where
    B: Source + crate::capability::CanObserve,
{
    backend.packets()
}
```

- [ ] **Step 4: Свести второй экземпляр**

В `core/src/certify/observation.rs` заменить тело `watching` реэкспортом. Найти определение

```rust
pub fn watching<B>(dut: &mut B) -> B::Packets<'_>
```

и заменить всю функцию (вместе с её докблоком) на:

```rust
/// ДВЕРЬ К НАБЛЮДЕНИЯМ — ОДНА НА ВЕСЬ КРЕЙТ.
///
/// Прежде здесь стояла вторая её копия. Закон обязан входить ровно той дверью, которой входит
/// боевой путь: разойдись они — стенд начал бы измерять сам себя.
pub use crate::backend::observing as watching;
```

Если после этого в файле остаются неупотреблённые импорты (`Source`, `CanObserve`, `Observed`), удалить только те, что перестали употребляться; остальные оставить.

- [ ] **Step 5: Прогнать тесты**

Run: `cargo test -p reflex-core --test backend --test certify_observation`
Expected: PASS, оба набора.

- [ ] **Step 6: Проверить воркспейс**

Run: `cargo test --workspace`
Expected: PASS, 0 упавших.

- [ ] **Step 7: Коммит**

```bash
git add core/src/backend.rs core/src/certify/observation.rs core/tests/backend.rs
git commit -F - <<'EOF'
feat(backend): одна дверь к наблюдениям вместо двух — `observing`

`category::from_source` и `certify::observation::watching` делали ОДНО И ТО ЖЕ: брали
`packets()` и требовали `CanObserve`. При этом второй объявлял себя «дверью к
наблюдениям этого бэкенда — и единственной», будучи вторым.

Две записи одной идеи расходятся молча, и репа за это уже платила ключом, добываемым
на каждой стороне по-своему: 1136 флоу из 1136 мимо.

ДВЕРЬ ТЕПЕРЬ ОДНА, и закон входит ею же. Разойдись они — стенд начал бы измерять сам
себя, а не подопытного.

ЦЕНА НАЗВАНА ВЫБОРОМ: потолка потока у двери нет, хотя принять его аргументом можно
было. Отвергнуто затем, что предел принадлежит ведущему циклу и меняется без ведома
двери; дверь мерила бы время вместо способности.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01ShUeKABPB2PovYEPdVd4d4
EOF
```

---

### Task 2: `Transition` переезжает к `Tap`

**Files:**
- Modify: `core/src/tap.rs` — принять тип
- Modify: `core/src/reactor.rs` — убрать определение
- Modify: `core/src/lib.rs:63` — поправить реэкспорт

**Interfaces:**
- Consumes: ничего
- Produces: `reflex_core::tap::Transition<E, F>` с полями `event: E`, `effect: Option<F>`; реэкспорт `reflex_core::Transition` сохраняется, путь меняется

**Почему отдельной задачей.** `Transition` — полезная нагрузка `Tap`, а не часть реактора: оба драйвера рантайма эмитят её именно в `Tap`. Пока она живёт в `reactor.rs`, снести реактор нельзя, не задев драйверы. Переезд развязывает задачи 3 и 4.

- [ ] **Step 1: Перенести тип**

Вырезать из `core/src/reactor.rs` определение вместе с докблоком:

```rust
/// Наблюдаемый переход атома: событие-вход + эффект-исход (типизированный). Join-point аспекта
/// наблюдаемости — атом его НЕ производит, аспект вплетён в драйвер ([`drive_observed`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Transition<E, F> {
    pub event: E,
    pub effect: Option<F>,
}
```

и вставить в конец `core/src/tap.rs`, заменив докблок на:

```rust
/// НАБЛЮДАЕМЫЙ ПЕРЕХОД: что вошло и что из этого вышло.
///
/// Живёт рядом с [`Tap`], а не рядом с машиной, и это адрес, а не вкус: переход есть ПОЛЕЗНАЯ
/// НАГРУЗКА наблюдения. Машина его не производит — она делает шаг; переход собирает тот, кто
/// смотрит. Пока тип лежал у одного из диалектов, наблюдение выглядело его свойством.
///
/// `effect` — `Option`, потому что «переход состоялся, действия не требует» есть законный исход,
/// а не пустота.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Transition<E, F> {
    pub event: E,
    pub effect: Option<F>,
}
```

- [ ] **Step 2: Поправить реэкспорт**

В `core/src/lib.rs` строка 63 сегодня:

```rust
pub use reactor::{drive, drive_observed, group_by_reactor, Reactor, Transition};
```

Заменить на:

```rust
pub use reactor::{drive, drive_observed, group_by_reactor, Reactor};
```

и в строке рядом с `pub use tap::Tap;` заменить её на:

```rust
pub use tap::{Tap, Transition};
```

- [ ] **Step 3: Прогнать воркспейс**

Run: `cargo test --workspace`
Expected: PASS, 0 упавших. Употребления `reflex_core::Transition` не меняются — путь реэкспорта тот же.

- [ ] **Step 4: Коммит**

```bash
git add core/src/tap.rs core/src/reactor.rs core/src/lib.rs
git commit -F - <<'EOF'
refactor(core): `Transition` переезжает к `Tap` — это нагрузка наблюдения, а не свойство диалекта

Переход есть полезная нагрузка НАБЛЮДЕНИЯ: машина его не производит, она делает шаг;
переход собирает тот, кто смотрит. Пока тип лежал в `reactor.rs`, наблюдаемость
выглядела свойством одного диалекта — и держала реактор за руку у обоих драйверов
рантайма, которые эмитят её в `Tap`.

Реэкспорт `reflex_core::Transition` сохранён, путь сменился. Употребления не тронуты.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01ShUeKABPB2PovYEPdVd4d4
EOF
```

---

### Task 3: Драйверы внешней петли переезжают с `Reactor` на `Step`

**Files:**
- Modify: `runtime/src/expand.rs` — целиком подпись и тело `Loop`/`expand_effects`
- Modify: `runtime/src/drive_owned.rs` — подпись и тело `drive_owned`
- Test: `runtime/tests/expand.rs` — фикстура становится `Step`
- Test: `runtime/src/drive_owned.rs` — его собственный `#[cfg(test)] mod tests`

**Interfaces:**
- Consumes: `reflex_core::step::Step`, `reflex_core::{Tap, Transition}` (Task 2)
- Produces:
  - `expand_effects<K, Ev, Fx, S, Edge, Fut>(machine: K, birth: Option<Fx>, seed: S, edge: Edge, tap: Tap<Transition<Ev, Fx>>) -> impl Stream<Item = Fx>` где `K: Step<From = Ev, To = Option<Fx>>`
  - `drive_owned<K, Ev, Fx, Ctx, Out, Interp, Fut>(machine: K, ctx: Ctx, first_event: Ev, interp: Interp, tap: Tap<Transition<Ev, Fx>>) -> Option<Out>` где `K: Step<From = Ev, To = Option<Fx>>`

**Почему их НЕ сносят вместе с реактором.** Это единственное в репе выражение ВНЕШНЕЙ петли — «решил → сделал IO → увидел исход → решил». Шестой vision её признаёт законной при условии гварда; гварда у них нет, и это записывается здесь, а не чинится: окно оседания — §7.4 спеки, отдельный предмет. Снести форму на том основании, что у неё нет гварда, значило бы потерять единственное, на чём гвард потом строить.

**Замена `R::start()` на явное семя.** У `Step` начального состояния нет — по шестому vision §8.4 его место в способности `CanReplay::seed`, которая заводится вместе с восьмым законом. До тех пор машина и эффект рождения приходят аргументами: вызывающий и так их имел, просто раньше их прятал трейт.

- [ ] **Step 1: Переписать фикстуру теста на `Step`**

В `runtime/tests/expand.rs` заменить импорт

```rust
use reflex_core::{Reactor, Tap, Transition};
```

на

```rust
use reflex_core::step::Step;
use reflex_core::{Tap, Transition};
```

и заменить реализацию фикстуры. Найти `impl Reactor for TinyCatcher` и заменить весь блок на:

```rust
impl Step for TinyCatcher {
    type From = Ev;
    type To = Option<Fx>;

    fn step(self, ev: Ev) -> (Self, Option<Fx>) {
        match (self, ev) {
            // Приход флоу → запрос async-гонки (эффект-запрос).
            (TinyCatcher::Idle, Ev::Arrived) => (TinyCatcher::Racing, Some(Fx::OpenLegs)),
            // Исход гонки вернулся событием → терминальный эффект (унести победителя).
            (TinyCatcher::Racing, Ev::Raced { direct }) => {
                (TinyCatcher::Done, Some(Fx::Serve { direct }))
            }
            (s, _) => (s, None),
        }
    }
}
```

Тело `step` перенесено дословно; изменились только ассоциированные типы (`Event` → `From`,
`Effect` → `To = Option<Fx>`). Метод `fn start()` удаляется целиком — он возвращал
`(TinyCatcher::Idle, None)`, и это значение переезжает в вызов (шаг 4).

- [ ] **Step 2: Прогнать и убедиться, что падает**

Run: `cargo test -p reflex-runtime --test expand`
Expected: FAIL со сборкой — `expand_effects` ещё ждёт `Reactor`.

- [ ] **Step 3: Переписать `expand_effects`**

В `runtime/src/expand.rs` заменить импорт и определения. Импорт:

```rust
use reflex_core::step::Step;
use reflex_core::{Tap, Transition};
```

Структура состояния:

```rust
struct Loop<K, Ev, Fx, S, Edge> {
    machine: Option<K>,
    seed: S,
    pending: VecDeque<Ev>,
    start_fx: Option<Fx>,
    edge: Edge,
    tap: Tap<Transition<Ev, Fx>>,
}
```

Машина хранится изымаемой (`Option`), потому что [`Step::step`] берёт состояние ПО ЗНАЧЕНИЮ — та же причина, по которой изымаема машина в `core::step::Over`. Так перенос не требует от морфизма `Clone`.

Сигнатура и тело:

```rust
/// Разворачивает эффекты машины: каждый эффект `edge` либо ОБСЛУЖИВАЕТ (async → следующее
/// событие, обратная подача), либо помечает терминальным (`None`) — тот выходит в поток исходов.
/// Внешние события (`seed`) и обратная подача (исходы `edge`) сливаются в один фолд, который
/// крутится, пока `seed` не иссякнет и петля не опустеет.
///
/// # ЭТО ВНЕШНЯЯ ПЕТЛЯ, И ГВАРДА У НЕЁ НЕТ
///
/// Петля через МИР структурой не гвардирована: задержка живёт в миллисекундах, а не в тактах
/// (шестой vision §6.3 в редакции 06.09.2026). Окно оседания обязано быть объявленным аргументом,
/// и здесь его нет — предмет §7.4 спеки алфавита, отдельный.
///
/// ЦЕНА НАЗВАНА ВЫБОРОМ: пока окна нет, ничто не мешает вызывающему замкнуть петлю быстрее, чем
/// доезжает эффект, и получить локально обоснованные решения, глобально осциллирующие. Отвергнута
/// альтернатива «не отдавать конструкцию, пока нет гварда»: тогда форма внешней петли исчезла бы
/// из репы вовсе, и строить гвард стало бы не на чем.
///
/// # МАШИНА И РОЖДЕНИЕ ПРИХОДЯТ АРГУМЕНТАМИ
///
/// У `Step` начального состояния нет: его место — способность `CanReplay::seed` вместе с восьмым
/// законом (шестой vision §8.4). До тех пор вызывающий подаёт и машину, и эффект рождения — он и
/// так их имел, просто прежде их прятал трейт.
pub fn expand_effects<K, Ev, Fx, S, Edge, Fut>(
    machine: K,
    birth: Option<Fx>,
    seed: S,
    edge: Edge,
    tap: Tap<Transition<Ev, Fx>>,
) -> impl Stream<Item = Fx>
where
    K: Step<From = Ev, To = Option<Fx>>,
    Ev: Copy,
    Fx: Copy,
    S: Stream<Item = Ev> + Unpin,
    Edge: Fn(Fx) -> Option<Fut>,
    Fut: Future<Output = Ev>,
{
    let init = Loop {
        machine: Some(machine),
        seed,
        pending: VecDeque::new(),
        start_fx: birth,
        edge,
        tap,
    };

    futures::stream::unfold(init, |mut st| async move {
        loop {
            // Эффект рождения — до первого события; события нет, tap не бьём.
            if let Some(fx) = st.start_fx.take() {
                match (st.edge)(fx) {
                    Some(fut) => st.pending.push_back(fut.await),
                    None => return Some((fx, st)),
                }
                continue;
            }

            // Следующее событие: обратная подача (pending) вперёд внешнего потока (seed).
            let ev = match st.pending.pop_front() {
                Some(e) => e,
                None => match st.seed.next().await {
                    Some(e) => e,
                    None => return None, // seed иссяк и петля пуста → поток исходов закрыт
                },
            };

            // Машины нет — значит прошлый шаг её не вернул. Наблюдаемо лишь при панике между
            // изъятием и возвратом; поток честно кончается, а не выдаёт чужой ответ.
            let fx = match st.machine.take() {
                None => return None,
                Some(machine) => {
                    let (next, fx) = machine.step(ev);
                    st.machine = Some(next);
                    fx
                }
            };

            st.tap.emit(Transition { event: ev, effect: fx });

            if let Some(fx) = fx {
                match (st.edge)(fx) {
                    Some(fut) => st.pending.push_back(fut.await), // обратная подача
                    None => return Some((fx, st)),                // терминал → наружу
                }
            }
        }
    })
}
```

- [ ] **Step 4: Поправить вызовы в тесте**

В `runtime/tests/expand.rs` каждый вызов вида

```rust
expand_effects::<TinyCatcher, _, _, _>(seed, edge, tap)
```

заменить на явную подачу машины и рождения. Значение, которое прежде возвращал `TinyCatcher::start()`, поставить сюда буквально — взять его из удалённого `fn start` фикстуры:

```rust
expand_effects(TinyCatcher::Idle, None, seed, edge, tap)
```

`TinyCatcher::Idle` и `None` — это ровно то, что возвращал удалённый `start()`. Турбофиш больше
не нужен: типы выводятся из аргументов.

- [ ] **Step 5: Прогнать тест `expand`**

Run: `cargo test -p reflex-runtime --test expand`
Expected: PASS, все тесты набора.

- [ ] **Step 6: Переписать `drive_owned`**

В `runtime/src/drive_owned.rs` заменить импорт

```rust
use reflex_core::{Reactor, Tap, Transition};
```

на

```rust
use reflex_core::step::Step;
use reflex_core::{Tap, Transition};
```

и заменить сигнатуру с телом:

```rust
pub async fn drive_owned<K, Ev, Fx, Ctx, Out, Interp, Fut>(
    machine: K,
    ctx: Ctx,
    first_event: Ev,
    interp: Interp,
    tap: Tap<Transition<Ev, Fx>>,
) -> Option<Out>
where
    K: Step<From = Ev, To = Option<Fx>>,
    Ev: Copy,
    Fx: Copy,
    Interp: Fn(Ctx, Fx) -> Fut,
    Fut: Future<Output = InterpStep<Ev, Ctx, Out>>,
{
    let mut machine = machine;
    let mut ctx = ctx;
    let mut event = first_event;
    loop {
        let (next, effect) = machine.step(event);
        machine = next;
        tap.emit(Transition { event, effect });
        // Нет эффекта → нечего исполнять и события нет → пайп встал (видимый `None`, не тихо-полу).
        let effect = effect?;
        match interp(ctx, effect).await {
            InterpStep::Feed { event: ev, ctx: c } => {
                event = ev;
                ctx = c;
            }
            InterpStep::Done(out) => return Some(out),
        }
    }
}
```

В докблоке функции заменить всякое упоминание `Reactor` на `Step`, сохранив смысл; добавить в него абзац:

```
/// # ВНЕШНЯЯ ПЕТЛЯ БЕЗ ГВАРДА — НАЗВАНО, А НЕ СКРЫТО
///
/// Здесь замыкается «решил → сделал IO над владеемым ресурсом → увидел исход → решил». Задержка
/// живёт в миллисекундах, значит структура петлю не гвардирует, и объявленного окна оседания у
/// конструкции нет. Предмет §7.4 спеки алфавита.
```

- [ ] **Step 7: Поправить его собственный тест**

В `#[cfg(test)] mod tests` того же файла заменить `impl Reactor for St` на:

```rust
    impl Step for St {
        type From = Ev;
        type To = Option<Fx>;

        fn step(self, ev: Ev) -> (Self, Option<Fx>) {
            match (self, ev) {
                (St::Idle, Ev::Arrived) => (St::Racing, Some(Fx::OpenLegs)),
                (St::Racing, Ev::Raced { direct }) => (St::Done, Some(Fx::Serve { direct })),
                (s, _) => (s, None),
            }
        }
    }
```

`fn start()` возвращал `(St::Idle, None)` и удаляется: первым аргументом вызова уже стоит
`St::Idle`, а эффекта рождения `drive_owned` не принимает — он начинает с события. Вызов

```rust
let out = drive_owned(St::Idle, socket, Ev::Arrived, interp, tap).await;
```

остаётся как есть — первый аргумент уже был машиной.

- [ ] **Step 8: Прогнать рантайм целиком**

Run: `cargo test -p reflex-runtime`
Expected: PASS, все наборы.

- [ ] **Step 9: Проверить воркспейс**

Run: `cargo test --workspace`
Expected: PASS, 0 упавших.

- [ ] **Step 10: Коммит**

```bash
git add runtime/src/expand.rs runtime/src/drive_owned.rs runtime/tests/expand.rs
git commit -F - <<'EOF'
refactor(runtime): драйверы внешней петли переезжают с `Reactor` на `Step`

`expand_effects` и `drive_owned` — ЕДИНСТВЕННОЕ в репе выражение внешней петли:
«решил → сделал IO → увидел исход → решил». Снести их вместе с диалектом реактора
значило бы потерять форму, на которой потом строить гвард.

ПЕРЕНОС МЕХАНИЧЕСКИЙ: оба зовут только `step` и `start`. `R::Event` → `From`,
`Option<R::Effect>` → `To`, а `start()` заменяется явными аргументами — машиной и
эффектом рождения. У `Step` начального состояния нет намеренно: его место в
`CanReplay::seed` вместе с восьмым законом.

ГВАРДА У ПЕТЛИ НЕТ, И ЭТО ЗАПИСАНО, А НЕ ПОЧИНЕНО. Петля через мир структурой не
гвардируется — задержка живёт в миллисекундах, а не в тактах. Окно оседания обязано
быть объявленным аргументом; это §7.4 спеки алфавита, отдельный предмет.

ЦЕНА НАЗВАНА ВЫБОРОМ: пока окна нет, вызывающий волен замкнуть петлю быстрее, чем
доезжает эффект, и получить локально обоснованные решения, глобально осциллирующие.
Альтернатива — не отдавать конструкцию до гварда — отвергнута: тогда форма внешней
петли исчезла бы из репы вовсе.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01ShUeKABPB2PovYEPdVd4d4
EOF
```

---

### Task 4: Снос `Reactor` и трёх его драйверов

**Files:**
- Delete: `core/src/reactor.rs`
- Delete: `core/tests/reactor.rs`
- Modify: `core/src/lib.rs` — убрать `pub mod reactor;` и строку реэкспорта
- Modify: `core/src/lifting.rs` — убрать `Reacting` и его импорт
- Modify: `core/tests/lifting.rs` — убрать всё, что стоит на `Reactor`

**Interfaces:**
- Consumes: ничего
- Produces: ничего. После задачи `Step` — единственный трейт машины Мили в репе, кроме `Detector` (его предмет — план 2B)

**Обезоруживание задачи 3 стоит здесь.** Если задача 3 сделана верно, драйверы рантайма к этому моменту от `Reactor` не зависят, и удаление модуля их не задевает. Если сборка рантайма красная — задача 3 не завершена, и это надо доложить, а не чинить здесь.

- [ ] **Step 1: Доказать, что потребителей не осталось**

Run:
```bash
grep -rn "Reactor" --include=*.rs core engine engine-nfq instrument linux runtime os \
  | grep -v target | grep -vE ":[0-9]+:\s*(//|///|//!)" \
  | grep -v "^core/src/reactor.rs" | grep -v "^core/tests/reactor.rs"
```

Expected: только `core/src/lib.rs` (реэкспорт), `core/src/lifting.rs` (обёртка `Reacting`) и `core/tests/lifting.rs` (фикстуры). Всё это удаляется ниже.

Если найдётся ЧТО-ТО ещё — **остановиться и доложить**: перепись устарела, и задача требует пересмотра.

- [ ] **Step 2: Удалить модуль и его тест**

```bash
git rm core/src/reactor.rs core/tests/reactor.rs
```

- [ ] **Step 3: Убрать из `lib.rs`**

Удалить строку `pub mod reactor;` и строку

```rust
pub use reactor::{drive, drive_observed, group_by_reactor, Reactor};
```

- [ ] **Step 4: Убрать `Reacting` из `lifting.rs`**

Удалить импорт `use crate::reactor::Reactor;`, структуру `Reacting<R>`, блок `impl<R: Reactor> Reacting<R>` (с `started`) и `impl<R: Reactor> Step for Reacting<R>` — вместе с их докблоками.

В шапке модуля `core/src/lifting.rs` заменить абзац, объясняющий выбор обёрток вместо blanket-impl'ов, на:

```
//! # ЧТО ЗДЕСЬ ОСТАЛОСЬ ПОСЛЕ ВПИТЫВАНИЯ
//!
//! Обёртка `Reacting` снята вместе с диалектом реактора: обёртка существует ради того, чтобы
//! чужой трейт вошёл в категорию шага, и умирает вместе с трейтом. Довод про несложимость
//! blanket-impl'ов остаётся верным и относится теперь к одному оставшемуся диалекту.
```

- [ ] **Step 5: Убрать реакторные фикстуры из теста подъёма**

В `core/tests/lifting.rs` удалить: импорт `use reflex_core::Reactor;` и `use reflex_core::lifting::Reacting;`, фикстуры `Toggle`, `Announcing`, `TogglingOnSignals` с их `impl Reactor`, и тесты `reactor_enters_the_step_category`, `birth_effect_is_returned_not_swallowed`, `two_foreign_dialects_compose_with_each_other`.

Тест `detector_enters_the_step_category` и фикстуры `Counting`, `Summing` остаются: их предмет — детектор, и его черёд в плане 2B.

**Churn назван честно:** `two_foreign_dialects_compose_with_each_other` добавлен утром того же дня
как починка находки широкого ревью — «докблок обещает цепочку, которой нет». Он своё сделал:
предъявил, что два чужих диалекта складываются. Сносится он не потому, что был не нужен, а потому,
что чужой диалект после этой задачи остаётся ОДИН, и предъявлять композицию двух больше не на чем.

Шапку файла поправить: убрать обещание проверить композицию ДВУХ чужих диалектов — после сноса реактора чужой диалект остался один, и обещание стало бы невыполнимым.

- [ ] **Step 6: Прогнать воркспейс**

Run: `cargo test --workspace`
Expected: PASS, 0 упавших.

- [ ] **Step 7: Проверить, что диалект исчез**

Run: `grep -rn "Reactor" --include=*.rs . | grep -v target | grep -vE ":[0-9]+:\s*(//|///|//!)"`
Expected: пусто.

- [ ] **Step 8: Коммит**

```bash
git add -A core/
git commit -F - <<'EOF'
chore(core): снос `Reactor` и трёх его драйверов

Диалект машины Мили, чьё содержание целиком выражается `Step`: `step(self, Ev) ->
(Self, Option<Fx>)` есть шаг с `To = Option<Fx>`, а `start()` — начальное состояние,
чьё место в `CanReplay::seed` (шестой vision §8.4).

Три драйвера уходят вместе с ним и не теряются: `drive` есть `StepExt::over`,
`group_by_reactor` есть `group_by` над шагом, `drive_observed` — тот же `over` плюс
`Tap`, и умрёт вместе с `Tap` в следующем плане.

Обёртка `Reacting` из плана №1 снята: она существовала ради того, чтобы чужой трейт
вошёл в категорию шага, и умирает вместе с трейтом. Свою работу она сделала —
доказала, что носитель общий; доказанное не нуждается в подпорке.

Употреблений `Reactor` в продукте — ноль (перепись 06.09.2026).

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01ShUeKABPB2PovYEPdVd4d4
EOF
```

---

### Task 5: Снос `category` — стадийной категории над потоком

**Files:**
- Delete: `core/src/category.rs`
- Delete: `core/tests/category.rs`
- Delete: `core/tests/category_laws.rs`
- Modify: `core/src/lib.rs` — убрать `pub mod category;` и комментарий над ним
- Modify: `core/tests/backend.rs` — снять оставшееся употребление `Terminal`

**Interfaces:**
- Consumes: `reflex_core::backend::observing` (Task 1)
- Produces: ничего. После задачи в репе ровно один способ выразить стадию — ассоциированные типы `Step::From` / `Step::To`

**Названная потеря.** `Injection` держал типом запрет «оператор после инъектора». До плана 3 гарантии нет; там она возвращается сильнее, потому что инъекция перестаёт быть морфизмом цепочки вовсе. Междуцарствие названо в шапке плана.

**Что НЕ теряется:** законы ассоциативности и тождества уже предъявлены на носителе значения (`core/tests/step_laws.rs`, план №1). `category_laws.rs` проверял их на носителе-потоке и уходит вместе с ним.

- [ ] **Step 1: Доказать, что потребителей в `src` нет**

Run:
```bash
grep -rn "category::" --include=*.rs core/src engine/src engine-nfq/src instrument/src linux/src runtime/src os/src \
  | grep -v target
```

Expected: пусто. Если что-то найдётся — **остановиться и доложить**.

- [ ] **Step 2: Снять последнее употребление в тесте бэкенда**

В `core/tests/backend.rs` удалить: остаток импорта `Terminal`, вспомогательную функцию
`async fn run_over<B>(backend: &mut B) -> Terminal` (она собирает цепочку через `from_source` и
кончает `Terminal`) и тест `the_same_chain_runs_over_two_different_backends`, который её зовёт и
утверждает `assert_eq!(end, Terminal)`.

**Это ВТОРАЯ названная потеря плана**, и она крупнее первой: тест предъявлял ПЕРЕНОСИМОСТЬ —
«одна и та же цепочка идёт над двумя разными бэкендами», то есть обещание третьего vision §3.2.
Предъявлял он её на носителе-потоке; на носителе значения она возвращается в плане алфавита, где
цепочка есть значение, а бэкенды — драйверы. До тех пор заявка не проверяется ничем.

В шапку файла дописать:

```rust
//! ТЕРМИНАЛЬНОСТЬ ЗДЕСЬ БОЛЬШЕ НЕ ПРОВЕРЯЕТСЯ, и это названо, а не забыто.
//!
//! `category::Injection` держал типом запрет «оператор после инъектора»: он не реализовывал
//! `Stream`, и операторы до него не дотягивались. Вместе с категорией стадий уходит и он.
//!
//! Гарантия возвращается в плане алфавита, и возвращается СИЛЬНЕЕ: в замыкании движка инъекция
//! перестаёт быть морфизмом цепочки вовсе — цепочка отдаёт СЛОВО, применяет его драйвер.
//! Продолжать нечего, потому что продолжать не за чем.
//!
//! ВМЕСТЕ С НЕЙ УХОДИТ ЗАЯВКА НА ПЕРЕНОСИМОСТЬ — «одна и та же цепочка над двумя разными
//! бэкендами» (третий vision §3.2). Предъявлялась она на носителе-потоке; на носителе значения
//! возвращается тем же планом, где цепочка есть значение, а бэкенды — драйверы.
```

- [ ] **Step 3: Удалить модуль и два теста**

```bash
git rm core/src/category.rs core/tests/category.rs core/tests/category_laws.rs
```

- [ ] **Step 4: Убрать из `lib.rs`**

Удалить строку `pub mod category;` вместе со стоящим над ней комментарием

```rust
// ОБЪЕКТЫ И МОРФИЗМЫ КАТЕГОРИИ (#295, срез 2): стадия — тип, морфизм — метод на своей стадии.
```

- [ ] **Step 5: Прогнать воркспейс**

Run: `cargo test --workspace`
Expected: PASS, 0 упавших.

- [ ] **Step 6: Приёмка плана — числами**

Run:
```bash
grep -rn "pub trait Step" --include=*.rs . | grep -v target
grep -rn "pub struct Then" --include=*.rs . | grep -v target
grep -rn "Reactor\|category::" --include=*.rs . | grep -v target | grep -vE ":[0-9]+:\s*(//|///|//!)"
```

Expected:
- `pub trait Step` — две строки: `core/src/step.rs` и `os/src/step.rs`. Второй — restriction-категория, ортогональная ось, а не диалект Мили (шестой vision §4.4);
- `pub struct Then` — одна строка: `core/src/step.rs`;
- третий grep — пусто.

- [ ] **Step 7: Коммит**

```bash
git add -A core/
git commit -F - <<'EOF'
chore(core): снос `category` — стадийной категории над потоком

Стадия как ФАНТОМНЫЙ ЯРЛЫК поверх `futures::Stream` и стадия как ассоциированный тип
`Step::From`/`To` — одна идея, записанная дважды. Первая живёт над чужой алгеброй, и
её морфизмы суть `self.inner.map(f)`; вторая живёт на носителе значения, который
шестой vision выбрал и план №1 доказал.

Употреблений в `src` — НОЛЬ, ни в одном крейте фундамента. Единственные потребители —
три собственных теста и две строки продукта.

НАЗВАННАЯ ПОТЕРЯ: `Injection` держал типом запрет «оператор после инъектора». До плана
алфавита гарантии нет. Там она возвращается СИЛЬНЕЕ: инъекция перестаёт быть морфизмом
цепочки — цепочка отдаёт слово, применяет его драйвер, и продолжать нечего, потому что
продолжать не за чем. Междуцарствие названо в шапке `core/tests/backend.rs`, а не
оставлено молчаливым.

Законы ассоциативности и тождества не теряются: они предъявлены на носителе значения
в `core/tests/step_laws.rs`. `category_laws.rs` проверял их на потоке и уходит с ним.

После этого коммита `Then` в репе один, `Step` — один трейт машины Мили (второй `Step`
в крейте `os` есть restriction-категория, ортогональная ось).

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01ShUeKABPB2PovYEPdVd4d4
EOF
```

---

## Приёмка плана

- [ ] `cargo test --workspace` зелёный, 0 упавших
- [ ] `grep -rn "Reactor" --include=*.rs . | grep -v target` — только упоминания в комментариях истории, если остались
- [ ] `grep -rn "category::" --include=*.rs . | grep -v target` — пусто
- [ ] `pub struct Then` — ровно одна строка
- [ ] Дверь к наблюдениям одна: `backend::observing`, и `certify::observation::watching` есть её реэкспорт
- [ ] `expand_effects` и `drive_owned` живы, стоят на `Step`, и отсутствие гварда названо в их докблоках
- [ ] Строк удалено больше, чем добавлено

## Что план оставляет следующему

- **План 2B:** впитывание `Detector` — 29 реализаций в `src`, восемь комбинаторов, `detect_per`.
- **План 3:** алфавит `Packet | Tick | Taught | Ordered`, `engine(NFQ) { … }`, снос фасада и `Tap`, возврат гарантии терминальности.
- **§7.4 спеки:** окно оседания как гвард внешней петли — предмет, названный в докблоках обоих драйверов.
