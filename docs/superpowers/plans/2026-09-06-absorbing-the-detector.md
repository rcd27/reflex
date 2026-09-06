# Впитывание `Detector` — план 2B

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** снести трейт `Detector` и `DetectorExt`, впитав их в `Step`, — второй диалект машины Мили из пяти оставшихся.

**Architecture:** `Detector::step(self, DetectorEvent<Input>) -> (Self, SmallVec<[Signal; 2]>)` и `Step::step(self, From) -> (Self, To)` — одна подпись при `From = DetectorEvent<Input>`, `To = SmallVec<[Signal; 2]>`. Комбинаторы получают форму алфавита **конкретными равенствами в своих границах**, без единого нового трейта. Обёртка `Detecting<D>` исчезает: она существовала только потому, что имён было два и блэнкет `impl<D: Detector> Step for D` невозможен из-за конфликта реализаций.

**Tech Stack:** Rust 2021, `smallvec`, `futures::Stream`, `tokio` (только в тестах).

**Spec:** `docs/superpowers/specs/2026-09-06-alphabet-and-absorption-design.md`, §3 строка 2 таблицы впитывания и §3.2 (цена).

---

## Global Constraints

* **Форма связи — конкретные равенства в границах, НОЛЬ новых трейтов.** Отвергнутая альтернатива (`Observed`/`Told` как трейты структуры алфавита) записана как отвергнутая: она заводит два имени под один употребляющий алфавит, то есть ровно ту болезнь, которую лечим. Решено пользователем 06.09.2026.
* **Проза не обещает больше, чем держит дерево.** На прошлой ветке девять ложных утверждений в докблоках, ни одного не нашёл автор текста. Всякое утверждение вида «здесь есть X» проверяется командой ПЕРЕД записью.
* **Датированный замер не переписывается.** Число в записи вида «Замер ДД.ММ.ГГГГ: N» верно на свою дату. Если оно разошлось с сегодняшним — рядом пишется, что разошлось и почему; само число остаётся.
* **Цена называется ВЫБОРОМ, а не свойством.** Формулировка «отвергнуто X, потому что Y», а не «здесь дорого».
* **Снос — только по инвентарю, никогда по имени файла.** Перед удалением файла его содержимое перечисляется поимённо (тесты, функции, типы), и сообщение коммита отчитывается за КАЖДЫЙ пункт. Основание: на ветке `work/alphabet` снос `core/tests/category_laws.rs` по имени унёс три теста закона 3, к снесённой категории отношения не имевших.
* **Русские докблоки переносятся дословно.** Комбинаторы несут прозу, объясняющую цену и отвергнутые альтернативы; она не пересказывается своими словами и не сокращается.
* **МЁРТВО ТО, ЧТО НЕ ЛЕЗЕТ В КАТЕГОРИЮ, а не то, что редко зовут.** Правило пользователя 06.09.2026, и оно отменяет прежний критерий этого плана. Счёт вызовов меряет популярность; принадлежность к категории меряет ПРАВО СУЩЕСТВОВАТЬ. Комбинатор с нулём вызовов, выражающийся морфизмом, — жив; тысяча вызовов кода, который морфизмом не выражается, его не спасают.

  Не всякий `&mut self` — выпадение. Спека §3.1 называет вторую законную роль: **драйвер** — то, что подаёт `In` и потребляет `Out`. Драйвер стоит вне категории потому, что кормит её, а не потому, что не дорос. Третья законная роль — **эталон** (`certify`): он свидетельствует то, что типом невыразимо. Выпадает лишь то, что и не морфизм, и не драйвер, и не эталон: машина Мили, написанная руками через `&mut` и время аргументом.

* **Ни одного нового предупреждения сборки.** На момент старта плана `cargo check --workspace --all-features` даёт **ноль** предупреждений (проверено на чистой сборке 06.09.2026). Вывод обязан остаться чистым.

---

## Замер, из которого растёт план

Все числа получены командами 06.09.2026 на `main@5c0c355`; команда приводится, чтобы исполнитель мог перепроверить, а не поверить.

| что | сколько | как считано |
|---|---|---|
| `impl … Detector for …` всего | **42** | `grep -rn "Detector for" --include=*.rs .` |
| из них в `instrument/src` + `engine/src` | **17** | те же строки, фильтр по каталогу |
| из них в `core/src` | **12** | то же |
| из них в тестах | **13** | то же |
| упоминаний `::Input`/`::Signal` в `reflex/*/src` | **132** | `grep -rn '::Input\b\|::Signal\b'` |
| то же у потребителя (`nevod`, `nevod-tablo`) | **153** | тот же поиск, минус `/reflex/`, минус `/target/` |

**Осторожно с замером потребителя.** Внутри суперпроекта лежат вендоренные копии самого reflex (`nevod/reflex/`, `nevod-tablo/reflex/`). Без их исключения собственные тесты reflex засчитываются за употребление потребителем, и вердикт переворачивается. Правильный фильтр: `| grep -v "/reflex/" | grep -v "/target/"`.

### Семь комбинаторов: все семь ЛЕЗУТ В КАТЕГОРИЮ, значит все семь живы

Приговор выносит **принадлежность**, а не счёт. Проверка одна: выражается ли морфизмом `(состояние, вход) → (состояние, выход)` с состоянием по значению и временем буквой алфавита.

| комбинатор | морфизм | состояние | судьба |
|---|---|---|---|
| `and` | `DetectorEvent<I> → SmallVec<[S; 2]>` | пара звеньев по значению | портируется |
| `rmap` | `DetectorEvent<I> → SmallVec<[Renamed; 2]>` | звено + функция | портируется |
| `lmap` | `DetectorEvent<Wide> → SmallVec<[S; 2]>` | звено + сужение | портируется |
| `contextual` | `DetectorEvent<I> → SmallVec<[Dressed; 2]>` | звено + `Option<Ctx>` | портируется |
| `timed` | `DetectorEvent<I> → SmallVec<[(Instant, S); 2]>` | звено; момент берётся у события | портируется |
| `by` | `DetectorEvent<I> → SmallVec<[Told<S>; 2]>` | звено + имя | портируется |
| `changes` | `DetectorEvent<I> → SmallVec<[S; 2]>` | звено + `Option<S>` | портируется |

**Счёт вызовов у потребителя записан ниже как СВЕДЕНИЕ, а не как приговор** — он говорит, где ждать поломки при правке, и ничего не говорит о праве на существование.

| комбинатор | `.and` | `.lmap` | `.timed` | `.contextual` | `.rmap` | `.by` | `.changes` |
|---|---|---|---|---|---|---|---|
| у потребителя | 35 | 8 | 6 | 4 | 2 | 0 | 0 |

`by` и `changes` с нулём вызовов **не сносятся**. Прежняя редакция этого плана их сносила по счёту — правило пользователя 06.09.2026 эту редакцию отменило. `by` вдобавок есть единственное лекарство от неотличимости, которую vision называет 63 раза; снести его по счёту значило бы выкинуть лекарство за то, что болезнь не лечат.

---

## Форма ПРЕДЪЯВЛЕНА, а не предположена

Центральная посылка плана скомпилирована и прогнана 06.09.2026 до его написания. Обе пробы прошли; проба удалена, её результат записан здесь.

**Что проверялось и что подтвердилось:**

1. **`E0207` не кусается.** Параметры `I` и `S`, не встречающиеся ни в типе, ни в трейт-ссылке, связываются равенством ассоциированного типа `D: Step<From = DetectorEvent<I>, To = SmallVec<[S; 2]>>`. Компилятор их принимает.
2. **Вложение выводится.** `RMap { inner: Both(Rst, Rst), f: … }` — комбинатор над комбинатором собирается без единой аннотации.
3. **Проекция в поле структуры выражается через ОДИН лишний параметр.** `In` живёт только в границах `impl`, `Sig` — в поле `pending`. Место вызова `PerKey::new(events, |k: &u8| *k, Counting::default)` вывелось без единого написанного типа — ровно та форма, что стоит в `core/tests/composition_domain.rs`.

**Чего проба НЕ проверяла и что остаётся риском задачи 4:** супертрейт `Instrument: Step<To = SmallVec<[<Self as Instrument>::Signal; 2]>>` — равенство ассоциированного типа, ссылающееся на другой ассоциированный тип того же `Self`. Задача 4 начинается с его предъявления.

---

## Что находится сверх спеки

**`instrument::Instrument` — третье имя, и оно НЕ синоним.** Спека §3 его не называет. `pub trait Instrument: reflex_core::Detector` навешивает паспорт: `SUBJECT`, `LAYER`, `PROTOCOLS`, `name`. Это настоящее уточнение — объявленные константы, сверяемые аудитом с выведенными типами.

Но `fn name(signal: &Self::Signal) -> &'static str` **проецирует сигнал**, которого у `Step` нет. Значит `Instrument` обязан объявить свой `type Signal` сам и связать его с `Step::To`. 17 реализаций.

**`runtime` тоже держит границы `Detector`** — `runtime/src/stream/detect.rs` (3 места) и `runtime/src/ext.rs` (2 места). Спека их не называла.

---

## Структура файлов

| файл | ответственность после плана |
|---|---|
| `core/src/detector.rs` | пять живых комбинаторов как `Step` и `DetectorEvent`. Трейтов `Detector`/`DetectorExt` нет; `By`/`Told`/`Changes` снесены |
| `core/src/step.rs` | `Step`, `Then`, `Id`, `StepExt` — и пять методов-комбинаторов, переехавших из `DetectorExt` |
| `core/src/lifting.rs` | `Detecting<D>` снесён; файл остаётся ради прозы о подъёме диалектов |
| `core/src/stream/detect_per.rs` | `DetectPer` получает параметр `Sig`; границы на `Step` |
| `core/src/flow_table.rs` | границы на `Step` |
| `instrument/src/lib.rs` | `Instrument: Step` со своим `type Signal` |
| `runtime/src/stream/detect.rs`, `runtime/src/ext.rs` | границы на `Step` |

## Порядок задач и почему он такой

Трейт и его потребители **обязаны перевернуться вместе**: если реализации стали `Step`, а машинерия требует `Detector`, дерево красное, и наоборот. Держать оба имени временно — завести ровно ту болезнь, которую лечим.

Поэтому воркспейс **красен между задачами 3 и 6**, и это выбор, а не упущение. Взамен каждая задача имеет свои ворота: `cargo test -p <крейт>` для своего крейта. Отвергнутая альтернатива — один гигантский коммит на 42 места: он непроверяем по частям, и ревью его не берёт.

Задача 1 и 2 воркспейс зелёным **оставляют** — они трогают то, чего в `src` никто не употребляет.

---

## Задача 1: семь комбинаторов переезжают в `Step`

**Files:**
- Modify: `core/src/detector.rs` — комбинаторы `Both`, `RMap`, `LMap`, `Contextual`, `Timed`, `By`, `Changes`
- Modify: `core/src/step.rs` — семь методов-комбинаторов в `StepExt`
- Modify: `core/src/lib.rs:54-56` — реэкспорт
- Modify: `core/src/ext.rs:81` — доклинк на `DetectorExt::and`
- Rewrite: `core/tests/detector_combinators.rs`

**Interfaces:**
- Consumes: `reflex_core::step::{Step, StepExt}`, `reflex_core::detector::DetectorEvent`, `smallvec::SmallVec`
- Produces: пять типов-комбинаторов, реализующих `Step`, и пять методов на `StepExt`:
  - `Both<A, B>` : `Step<From = DetectorEvent<I>, To = SmallVec<[S; 2]>>`
  - `RMap<D, F>` : `Step<From = DetectorEvent<I>, To = SmallVec<[Renamed; 2]>>`
  - `LMap<D, F, Wide>` : `Step<From = DetectorEvent<Wide>, To = SmallVec<[S; 2]>>`
  - `Contextual<D, Ctx, Pick, Dress>` : `Step<From = DetectorEvent<I>, To = SmallVec<[Dressed; 2]>>`
  - `Timed<D>` : `Step<From = DetectorEvent<I>, To = SmallVec<[(Instant, S); 2]>>`
  - `StepExt::and`, `::rmap`, `::lmap`, `::contextual`, `::timed`

- [ ] **Шаг 1: сверить замер — ничего не сносится, всё переносится**

Задача не удаляет ни одного типа и ни одного теста. Сверка нужна, чтобы убедиться, что переносить придётся ровно семь комбинаторов и что список тестов совпал с замером:

```bash
cd /home/rcd/Workspace/reflex
grep -c "^fn " core/tests/detector_combinators.rs
grep -n "^    fn and<\|^    fn rmap<\|^    fn lmap<\|^    fn contextual<\|^    fn by(\|^    fn timed(\|^    fn changes(" core/src/detector.rs
```

Ожидается: 20 тестовых функций; семь методов в `DetectorExt`. **Если число иное — остановиться и доложить: замер устарел, и план опирается на устаревшее.**

- [ ] **Шаг 2: написать падающий тест формы**

Создать `core/tests/alphabet_form.rs`. Он сторожит то, что проба доказала: форма собирается, вложение выводится, тождество нейтрально в этой же форме.

```rust
//! ФОРМА АЛФАВИТА ПРЕДЪЯВЛЕНА, А НЕ ОБЕЩАНА.
//!
//! Комбинаторы получают форму конкретными равенствами в границах, без единого нового трейта.
//! Отвергнуто: трейты `Observed`/`Told` на структуру алфавита — они заводят два имени под один
//! употребляющий алфавит, то есть ровно ту болезнь, которую впитывание лечит.
//!
//! Здесь проверяется не поведение комбинаторов (это `detector_combinators.rs`), а то, что форма
//! ВЫРАЗИМА и ВЫВОДИМА: `E0207` не кусается, вложение собирается без аннотаций.
use reflex_core::detector::DetectorEvent;
use reflex_core::step::{Step, StepExt};
use smallvec::SmallVec;
use std::time::Instant;

#[derive(Clone, Copy)]
struct Rst;

impl Step for Rst {
    type From = DetectorEvent<u8>;
    type To = SmallVec<[u8; 2]>;

    fn step(self, event: Self::From) -> (Self, Self::To) {
        match event {
            DetectorEvent::Packet { input: 1, .. } => (self, SmallVec::from_slice(&[7])),
            _ => (self, SmallVec::new()),
        }
    }
}

fn packet(input: u8) -> DetectorEvent<u8> {
    DetectorEvent::Packet {
        input,
        at: Instant::now(),
    }
}

#[test]
fn оба_слушателя_говорят_в_один_словарь() {
    let (_, told) = Rst.and(Rst).step(packet(1));
    assert_eq!(&told[..], &[7, 7], "событие дошло до обоих");
}

#[test]
fn вложение_комбинаторов_выводится_без_единой_аннотации() {
    // САМОЕ ХРУПКОЕ ДЛЯ ВЫВОДА: комбинатор над комбинатором. Если форма выражена неверно,
    // падает именно здесь, а не на одиночном звене.
    let (_, told) = Rst.and(Rst).rmap(|s: u8| s as u32 * 10).step(packet(1));
    assert_eq!(&told[..], &[70u32, 70], "переименование прошло сквозь сложение");
}

#[test]
fn тождество_нейтрально_и_в_этой_форме() {
    // Второй закон категории на алфавите детектора: `id ∘ f` даёт то же, что `f`.
    use reflex_core::step::Id;
    let (_, прямо) = Rst.step(packet(1));
    let (_, через_тождество) = Id::<DetectorEvent<u8>>::new().then(Rst).step(packet(1));
    assert_eq!(прямо, через_тождество, "тождество ничего не изменило");
}
```

- [ ] **Шаг 3: прогнать — убедиться, что не собирается**

```bash
cargo test -p reflex-core --test alphabet_form 2>&1 | tail -20
```

Ожидается: **отказ сборки**. `StepExt` не имеет ни `and`, ни `rmap` — методы ещё живут в `DetectorExt`, а `Rst` реализует `Step`, а не `Detector`. Ошибка вида `no method named 'and' found for struct 'Rst'`.

- [ ] **Шаг 4: перевести `Both` на `Step`**

В `core/src/detector.rs` заменить блок `impl<A, B> Detector for Both<A, B>` (строки 75-91) на:

```rust
impl<A, B, I, S> crate::step::Step for Both<A, B>
where
    A: crate::step::Step<From = DetectorEvent<I>, To = SmallVec<[S; 2]>>,
    B: crate::step::Step<From = DetectorEvent<I>, To = SmallVec<[S; 2]>>,
    I: Clone,
{
    type From = DetectorEvent<I>;
    type To = SmallVec<[S; 2]>;

    fn step(self, event: Self::From) -> (Self, Self::To) {
        let (first, mut signals) = self.0.step(event.clone());
        let (second, more) = self.1.step(event);
        signals.extend(more);
        (Both(first, second), signals)
    }
}
```

**Внимание на импорт.** `crate::step::Step` пишется полным путём в границах, а не импортируется голым именем: в файле уже есть `Step`-подобные имена, и голый импорт сделал бы границу неразличимой на глаз. Если исполнитель предпочтёт импорт — он идёт в ВЕРХНИЙ блок `use` файла: `use` в середине файла законен, но в этой репе не встречается ни разу.

Докблок над `pub struct Both<A, B>` переносится дословно: он называет две цены — «событие клонируется по разу на детектор; цепочка из N звеньев клонирует N раз» и «словарь сигналов общий, поэтому после сложения не видно, кто сказал». Вторая цена — та самая неотличимость, лекарство от которой сносится шагом 9.

- [ ] **Шаг 5: перевести `RMap` на `Step`**

Заменить `impl<D, F, Renamed> Detector for RMap<D, F>` (строки 99-114) на:

```rust
impl<D, F, I, S, Renamed> crate::step::Step for RMap<D, F>
where
    D: crate::step::Step<From = DetectorEvent<I>, To = SmallVec<[S; 2]>>,
    F: Fn(S) -> Renamed,
{
    type From = DetectorEvent<I>;
    type To = SmallVec<[Renamed; 2]>;

    fn step(self, event: Self::From) -> (Self, Self::To) {
        let Self { inner, f } = self;
        let (stepped, signals) = inner.step(event);
        let renamed = signals.into_iter().map(&f).collect();
        (Self { inner: stepped, f }, renamed)
    }
}
```

- [ ] **Шаг 6: перевести `LMap` на `Step`**

Заменить `impl<D, F, Wide> Detector for LMap<D, F, Wide>` (строки 126-166) на границы ниже. **Тело не меняется ни на строку** — включая ветку `DetectorEvent::Tick`, которая проходит всегда:

```rust
impl<D, F, Wide, I, S> crate::step::Step for LMap<D, F, Wide>
where
    D: crate::step::Step<From = DetectorEvent<I>, To = SmallVec<[S; 2]>>,
    F: Fn(&Wide) -> Option<I>,
{
    type From = DetectorEvent<Wide>;
    type To = SmallVec<[S; 2]>;

    fn step(self, event: Self::From) -> (Self, Self::To) {
        let Self { inner, f, wide } = self;
        match event {
            DetectorEvent::Packet { input, at } => match f(&input) {
                Some(narrowed) => {
                    let (stepped, signals) = inner.step(DetectorEvent::Packet {
                        input: narrowed,
                        at,
                    });
                    (
                        Self {
                            inner: stepped,
                            f,
                            wide,
                        },
                        signals,
                    )
                }
                None => (Self { inner, f, wide }, SmallVec::new()),
            },
            DetectorEvent::Tick { at } => {
                let (stepped, signals) = inner.step(DetectorEvent::Tick { at });
                (
                    Self {
                        inner: stepped,
                        f,
                        wide,
                    },
                    signals,
                )
            }
        }
    }
}
```

Докблок `LMap` (строки 118-121) переносится дословно: «Тик проходит ВСЕГДА: сужение фильтрует наблюдения, а не время. Съеденный тик остановил бы часы прибору молча, и он выглядел бы исправным.»

- [ ] **Шаг 7: перевести `Contextual` на `Step`**

Заменить `impl<D, Ctx, Pick, Dress, Dressed> Detector for Contextual<…>` (строки 191-228) на границы ниже; тело не меняется:

```rust
impl<D, Ctx, Pick, Dress, Dressed, I, S> crate::step::Step for Contextual<D, Ctx, Pick, Dress>
where
    D: crate::step::Step<From = DetectorEvent<I>, To = SmallVec<[S; 2]>>,
    I: Clone,
    Pick: Fn(&I) -> Ctx,
    Dress: Fn(Option<&Ctx>, S) -> Option<Dressed>,
{
    type From = DetectorEvent<I>;
    type To = SmallVec<[Dressed; 2]>;

    fn step(self, event: Self::From) -> (Self, Self::To) {
        let Self {
            inner,
            pick,
            dress,
            context,
        } = self;
        // ДО шага: сигнал этого наблюдения одевается в него, а не в предыдущее.
        let context = match &event {
            DetectorEvent::Packet { input, .. } => Some(pick(input)),
            DetectorEvent::Tick { .. } => context,
        };
        let (stepped, signals) = inner.step(event);
        let dressed = signals
            .into_iter()
            .filter_map(|signal| dress(context.as_ref(), signal))
            .collect();
        (
            Self {
                inner: stepped,
                pick,
                dress,
                context,
            },
            dressed,
        )
    }
}
```

- [ ] **Шаг 8: перевести `Timed` на `Step`**

Заменить `impl<D: Detector> Detector for Timed<D>` (строки 274-283) на:

```rust
impl<D, I, S> crate::step::Step for Timed<D>
where
    D: crate::step::Step<From = DetectorEvent<I>, To = SmallVec<[S; 2]>>,
{
    type From = DetectorEvent<I>;
    type To = SmallVec<[(Instant, S); 2]>;

    fn step(self, event: Self::From) -> (Self, Self::To) {
        let at = event.at();
        let (stepped, signals) = self.inner.step(event);
        let stamped = signals.into_iter().map(|signal| (at, signal)).collect();
        (Self { inner: stepped }, stamped)
    }
}
```

- [ ] **Шаг 9: перевести `By` и `Changes` на `Step`**

Оба лезут в категорию, значит оба переносятся. Прежняя редакция плана сносила их по счёту вызовов у потребителя (`0` и `0`); правило пользователя 06.09.2026 этот критерий отменило: мёртво то, что не лезет в категорию.

`By<D>` — морфизм `DetectorEvent<I> → SmallVec<[Told<S>; 2]>`, состояние — звено и имя:

```rust
impl<D, I, S> crate::step::Step for By<D>
where
    D: crate::step::Step<From = DetectorEvent<I>, To = SmallVec<[S; 2]>>,
{
    type From = DetectorEvent<I>;
    type To = SmallVec<[Told<S>; 2]>;

    fn step(self, event: Self::From) -> (Self, Self::To) {
        let Self { inner, by } = self;
        let (stepped, signals) = inner.step(event);
        let told = signals
            .into_iter()
            .map(|signal| Told { by, signal })
            .collect();
        (Self { inner: stepped, by }, told)
    }
}
```

`Changes<D>` — морфизм `DetectorEvent<I> → SmallVec<[S; 2]>`, состояние — звено и последнее сказанное. **Граница `D: Detector` с ОБЪЯВЛЕНИЯ структуры убирается**: `pub struct Changes<D: Detector> { inner: D, said: Option<D::Signal> }` не выражается через `Step`, потому что `Signal` проекцией больше не берётся. Поле типизируется параметром:

```rust
/// Переход вместо значения, НА КЛЮЧ: оператор потока
/// ([`crate::stream::DistinctUntilChangedStream`]) считает смену по всему потоку, и две цели,
/// чередуясь, прошли бы его насквозь.
///
/// Сравнение с ПОСЛЕДНИМ показанием, а не со всеми виденными: возврат к прежнему есть событие.
///
/// # ПОЧЕМУ У СТРУКТУРЫ ПОЯВИЛСЯ `S` (06.09.2026)
///
/// Прежде тип показания брался проекцией `D::Signal`. Проекции нет: `Step` держит алфавит целиком
/// (`To = SmallVec<[S; 2]>`), а вынуть из него элемент нечем. Тип был здесь всегда — изменилось
/// лишь то, что теперь его обязаны назвать.
pub struct Changes<D, S> {
    inner: D,
    /// Первое показание проходит всегда: ему не с чем совпадать.
    said: Option<S>,
}

impl<D, S> Changes<D, S> {
    pub(crate) fn new(inner: D) -> Self {
        Self { inner, said: None }
    }
}

impl<D, I, S> crate::step::Step for Changes<D, S>
where
    D: crate::step::Step<From = DetectorEvent<I>, To = SmallVec<[S; 2]>>,
    S: PartialEq + Clone,
{
    type From = DetectorEvent<I>;
    type To = SmallVec<[S; 2]>;

    fn step(self, event: Self::From) -> (Self, Self::To) {
        let Self { inner, said } = self;
        let (stepped, signals) = inner.step(event);
        // Повтор внутри одного шага — тоже повтор.
        let (last, fresh) =
            signals
                .into_iter()
                .fold(
                    (said, SmallVec::new()),
                    |(previous, passed), signal| match previous.as_ref() == Some(&signal) {
                        true => (previous, passed),
                        false => (
                            Some(signal.clone()),
                            passed.into_iter().chain(core::iter::once(signal)).collect(),
                        ),
                    },
                );
        (
            Self {
                inner: stepped,
                said: last,
            },
            fresh,
        )
    }
}
```

**`Changes<D, S>` получил параметр — это правка ПУБЛИЧНОЙ формы типа.** Она видна потребителю в возвращаемом типе `.changes()`; вывод её закрывает, аннотаций у места вызова не требуется. Проверяется тестом `changes_is_idempotent`, где `.changes().changes()` — вложение того же комбинатора в себя.

`Told<S>` остаётся как есть — он `#[derive(Debug, Clone, Copy, PartialEq, Eq)]` и от трейта не зависел никогда.

- [ ] **Шаг 10: перенести семь методов в `StepExt`**

В `core/src/step.rs`, внутрь `pub trait StepExt`, добавить семь методов. Границы называют форму алфавита там же, где употребляются:

```rust
    /// Наблюдать обоими. См. [`crate::detector::Both`].
    ///
    /// Не конвейер: событие идёт в оба звена, а не из одного в другое. Имя `and` — речь цепочки,
    /// а не логическое «и»: в логике `A AND B` значит «сработали оба», здесь — «слушают оба».
    fn and<B, I, S>(self, other: B) -> crate::detector::Both<Self, B>
    where
        Self: Step<From = crate::detector::DetectorEvent<I>, To = smallvec::SmallVec<[S; 2]>>,
        B: Step<From = Self::From, To = Self::To>,
        I: Clone,
    {
        crate::detector::Both(self, other)
    }

    /// Переименовать сигнал. См. [`crate::detector::RMap`].
    fn rmap<F, I, S, Renamed>(self, f: F) -> crate::detector::RMap<Self, F>
    where
        Self: Step<From = crate::detector::DetectorEvent<I>, To = smallvec::SmallVec<[S; 2]>>,
        F: Fn(S) -> Renamed,
    {
        crate::detector::RMap::new(self, f)
    }

    /// Сузить вход. См. [`crate::detector::LMap`].
    fn lmap<Wide, F, I, S>(self, f: F) -> crate::detector::LMap<Self, F, Wide>
    where
        Self: Step<From = crate::detector::DetectorEvent<I>, To = smallvec::SmallVec<[S; 2]>>,
        F: Fn(&Wide) -> Option<I>,
    {
        crate::detector::LMap::new(self, f)
    }

    /// Одеть сигнал в контекст наблюдения. См. [`crate::detector::Contextual`].
    fn contextual<Ctx, Pick, Dress, Dressed, I, S>(
        self,
        pick: Pick,
        dress: Dress,
    ) -> crate::detector::Contextual<Self, Ctx, Pick, Dress>
    where
        Self: Step<From = crate::detector::DetectorEvent<I>, To = smallvec::SmallVec<[S; 2]>>,
        Pick: Fn(&I) -> Ctx,
        Dress: Fn(Option<&Ctx>, S) -> Option<Dressed>,
    {
        crate::detector::Contextual::new(self, pick, dress)
    }

    /// Вынести наружу момент, в который звено высказалось. См. [`crate::detector::Timed`].
    fn timed<I, S>(self) -> crate::detector::Timed<Self>
    where
        Self: Step<From = crate::detector::DetectorEvent<I>, To = smallvec::SmallVec<[S; 2]>>,
    {
        crate::detector::Timed::new(self)
    }

    /// Приписать показаниям автора. См. [`crate::detector::Told`].
    ///
    /// `and` складывает наблюдателей в один поток, и без имени два прибора с общим словарём
    /// (`Silence` и `Choked` оба говорят «байтов нет») дают неразличимые показания при разном
    /// лечении. Имя берётся из паспорта прибора, а не пишется у места сборки.
    fn by<I, S>(self, by: &'static str) -> crate::detector::By<Self>
    where
        Self: Step<From = crate::detector::DetectorEvent<I>, To = smallvec::SmallVec<[S; 2]>>,
    {
        crate::detector::By::new(self, by)
    }

    /// Говорить только о смене показания. См. [`crate::detector::Changes`].
    fn changes<I, S>(self) -> crate::detector::Changes<Self, S>
    where
        Self: Step<From = crate::detector::DetectorEvent<I>, To = smallvec::SmallVec<[S; 2]>>,
        S: PartialEq + Clone,
    {
        crate::detector::Changes::new(self)
    }
```

Поля `RMap`, `LMap`, `Contextual`, `Timed` приватны, поэтому `step.rs` не может собрать их литералом. Добавить в `core/src/detector.rs` конструкторы:

```rust
impl<D, F> RMap<D, F> {
    pub(crate) fn new(inner: D, f: F) -> Self {
        Self { inner, f }
    }
}

impl<D, F, Wide> LMap<D, F, Wide> {
    pub(crate) fn new(inner: D, f: F) -> Self {
        Self {
            inner,
            f,
            wide: core::marker::PhantomData,
        }
    }
}

impl<D, Ctx, Pick, Dress> Contextual<D, Ctx, Pick, Dress> {
    pub(crate) fn new(inner: D, pick: Pick, dress: Dress) -> Self {
        Self {
            inner,
            pick,
            dress,
            context: None,
        }
    }
}

impl<D> Timed<D> {
    pub(crate) fn new(inner: D) -> Self {
        Self { inner }
    }
}

impl<D> By<D> {
    pub(crate) fn new(inner: D, by: &'static str) -> Self {
        Self { inner, by }
    }
}
```

Конструктор `Changes::new` дан вместе с самим типом в шаге 9 — там же, где у структуры появился параметр `S`.

**`DetectorExt` НЕ удаляется в этой задаче** — трейт `Detector` ещё жив и его реализуют 42 типа; удаление ext-трейта сейчас ничего не ломает, но и ничего не даёт. Из него уезжают все семь методов, после чего он остаётся пустым и сносится в задаче 3 вместе с `Detector`.

- [ ] **Шаг 11: починить доклинк**

`core/src/ext.rs:81` ссылается на `[crate::DetectorExt::and]`. Заменить на `[crate::step::StepExt::and]`.

- [ ] **Шаг 12: переписать тесты комбинаторов**

В `core/tests/detector_combinators.rs`:
1. Фикстуры `Rst`, `Clock`, `Level` — с `impl Detector` на `impl Step` (`type From = DetectorEvent<…>`, `type To = SmallVec<[…; 2]>`).
2. Импорт `use reflex_core::{Detector, DetectorExt}` → `use reflex_core::step::{Step, StepExt}`.
3. **Ни один тест не удаляется.** Все 20 переписываются под новые границы; тела ассертов не менять ни на символ. Шесть из них сторожат `by` и `changes` (`changes_says_it_once_however_often_it_is_seen`, `changes_reports_a_return_to_a_previous_reading`, `changes_is_idempotent`, `changes_lets_the_very_first_reading_through`, `attribution_survives_composition`, `attribution_changes_nothing_but_the_name`) — прежняя редакция плана их сносила; теперь они остаются, и `changes_is_idempotent` вдобавок работает приёмкой параметра `S`: `.changes().changes()` обязан вывестись без аннотации.
4. Остальные четырнадцать — та же механическая правка импортов и фикстур.

- [ ] **Шаг 13: прогнать**

```bash
cargo test -p reflex-core --test alphabet_form --test detector_combinators 2>&1 | tail -20
cargo test --workspace --all-features 2>&1 | grep "^test result" | awk '{p+=$4; f+=$6} END {print "наборов:", NR, "прошло:", p, "провалов:", f}'
cargo check --workspace --all-features 2>&1 | grep -c "^warning"
```

Ожидается: оба набора зелёные; воркспейс зелёный целиком (комбинаторы в `src` никто не звал); предупреждений **0**.

- [ ] **Шаг 14: коммит**

```bash
git add core/src/detector.rs core/src/step.rs core/src/lib.rs core/src/ext.rs \
        core/tests/alphabet_form.rs core/tests/detector_combinators.rs
git commit
```

Сообщение называет: семь комбинаторов перенесены, ноль снесено, 20 тестов переписаны, ноль удалено. И причину, по которой прежняя редакция плана сносила два: критерий был счёт вызовов, а стал — принадлежность к категории.

---

## Задача 2: `Detecting` снят — обёртка была налогом за второе имя

**Files:**
- Modify: `core/src/lifting.rs` — снос `Detecting<D>`
- Modify: `core/src/lib.rs:20` — если `lifting` реэкспортирует `Detecting`
- Rewrite: `core/tests/lifting.rs`

**Interfaces:**
- Consumes: `Step` из задачи 1 (методы `StepExt`)
- Produces: ничего нового; удаляет `reflex_core::lifting::Detecting`

- [ ] **Шаг 1: перечислить, что сторожит `core/tests/lifting.rs`**

```bash
grep -n "^fn \|^async fn \|#\[test\]\|#\[tokio::test\]" core/tests/lifting.rs
grep -rn "Detecting" --include=*.rs core engine engine-nfq instrument runtime
```

Сохранить вывод: он идёт в сообщение коммита. **Тесты, сторожащие подъём вообще (а не обёртку), переписываются, а не сносятся.**

- [ ] **Шаг 2: написать тест, доказывающий, что обёртка больше не нужна**

Дописать в `core/tests/lifting.rs`:

```rust
/// ОБЁРТКА БЫЛА НАЛОГОМ ЗА ВТОРОЕ ИМЯ, И НАЛОГ СНЯТ.
///
/// `Detecting<D>` существовал не ради подъёма, а ради того, что блэнкет
/// `impl<D: Detector> Step for D` невозможен: он конфликтует со всякой другой реализацией
/// `Step`. Одно имя — конфликта нет, и прибор входит в цепочку НАПРЯМУЮ.
#[test]
fn прибор_входит_в_цепочку_без_обёртки() {
    let at = Instant::now();
    let цепочка = Counting::default().then(Counting::default());
    let (_, told) = цепочка.step(DetectorEvent::Packet { input: 1u8, at });
    assert_eq!(
        &told[..],
        &[1u32],
        "второе звено сосчитало то, что сказало первое"
    );
}
```

Фикстура `Counting` в этом файле уже есть (`core/tests/lifting.rs`, `impl Detector for Counting`); её `type From`/`type To` меняются вместе с переходом на `Step`. Её `To` обязан совпасть с `From` второго звена — если это не так, тест не соберётся, и это правильный сигнал: цепочка должна стыковаться по типам, а не по вере.

**Если типы не стыкуются** (`Counting::To = SmallVec<[u32; 2]>`, а `Counting::From = DetectorEvent<u8>`) — цепочка из двух `Counting` невозможна, и тест обязан быть переписан на два РАЗНЫХ звена, где выход первого есть вход второго. Собрать такую пару в этом же файле: звено, отдающее `DetectorEvent<u32>`, — и `Counting` над ним. Имя теста при этом не меняется, потому что проверяется то же утверждение.

- [ ] **Шаг 3: прогнать — убедиться, что падает**

```bash
cargo test -p reflex-core --test lifting 2>&1 | tail -20
```

Ожидается отказ сборки: `Counting` реализует `Detector`, а `.then` требует `Step`.

- [ ] **Шаг 4: снести `Detecting` и перевести фикстуру**

Удалить из `core/src/lifting.rs` объявление `pub struct Detecting<D>(pub D);` и `impl<D: Detector> Step for Detecting<D>`. Докблок модуля **остаётся**: он несёт датированный замер шести диалектов и уже несёт поправку о том, что число замера и число сегодня разошлись. Дописать к поправке, что `Detecting` снят и почему.

- [ ] **Шаг 5: прогнать**

```bash
cargo test -p reflex-core 2>&1 | grep "^test result"
```

- [ ] **Шаг 6: коммит**

```bash
git add core/src/lifting.rs core/src/lib.rs core/tests/lifting.rs
git commit
```

---

## Задача 3: `core` переворачивается целиком — трейт `Detector` умирает

**Files:**
- Modify: `core/src/timeout.rs:106` — `impl Detector for Timeout<T>`
- Modify: `core/src/debounce.rs` — `impl Detector for Debounce<T>`
- Modify: `core/src/tls/assembly.rs` — `impl Detector for RecordAssembler`
- Modify: `core/src/flow_table.rs:8,22,32,114` — границы
- Modify: `core/src/stream/detect_per.rs:74,90,106-114` — параметр `Sig`, границы
- Modify: `core/src/ext.rs:91` — граница `detect_per`
- Modify: `core/src/detector.rs` — снос `pub trait Detector` и `pub trait DetectorExt`
- Modify: `core/src/lib.rs:54-56` — реэкспорт
- Rewrite: `core/tests/detect_per.rs`, `core/tests/flow_table.rs`, `core/tests/composition_domain.rs`

**Interfaces:**
- Consumes: `Step`, `StepExt` и пять комбинаторов из задачи 1
- Produces:
  - `DetectPer<S, D, K, KeyFn, Factory, Sig>` — **на один параметр больше**, чем было
  - `FlowTable<D>` с границей `D: Step<From = DetectorEvent<I>, To = SmallVec<[S; 2]>>`
  - `ReflexExt::detect_per` с той же сигнатурой снаружи (параметр `Sig` выводится)
  - трейтов `Detector` и `DetectorExt` больше нет

- [ ] **Шаг 1: инвентарь трёх тестовых файлов**

```bash
for f in core/tests/detect_per.rs core/tests/flow_table.rs core/tests/composition_domain.rs; do
  echo "=== $f"; grep -n "^fn \|^async fn " $f
done
```

`composition_domain.rs` — **приёмка эпика #294, закон 3**, три теста на `#[tokio::test]`. Они восстанавливались один раз после сноса по имени файла. Ни один из них не удаляется; они только переписываются под новые границы, и их ассерты не меняются ни на символ.

- [ ] **Шаг 2: перевести три простые реализации**

`core/src/timeout.rs`, `core/src/debounce.rs`, `core/src/tls/assembly.rs`. В каждой замена механическая:

```rust
// БЫЛО
impl<T> Detector for Timeout<T> {
    type Input = T;
    type Signal = Expired;
    fn step(self, event: DetectorEvent<Self::Input>) -> (Self, SmallVec<[Self::Signal; 2]>) { … }
}

// СТАЛО
impl<T> crate::step::Step for Timeout<T> {
    type From = DetectorEvent<T>;
    type To = SmallVec<[Expired; 2]>;
    fn step(self, event: Self::From) -> (Self, Self::To) { … }
}
```

Тело не меняется. Если внутри тела встречается `Self::Input` или `Self::Signal` — заменить на конкретный тип, который стоял в `type Input`/`type Signal`.

- [ ] **Шаг 3: перевести `flow_table`**

`core/src/flow_table.rs`: `use crate::Detector;` → `use crate::step::Step;`.

**Параметр `Sig` здесь НЕ нужен, и это проверено, а не предположено.** Поля `FlowTable` — `flows: HashMap<Flow, D>`, `last_seen: HashMap<Flow, Instant>`, `idle_timeout: Duration`, `make_detector: Box<dyn Fn(Flow) -> D + Send>`. Ни одно не типизировано сигналом, в отличие от `DetectPer::pending`. Сигнал здесь только протекает через возврат метода.

Границы на ОБЪЯВЛЕНИИ структуры убираются совсем:

```rust
// БЫЛО — граница на объявлении, известный анти-образец: при употреблении она не проверяется,
// зато обязывает повторять себя в каждом `impl`.
pub struct FlowTable<D: Detector>
where
    D::Input: HasFlow + Clone,
{ … }

// СТАЛО
pub struct FlowTable<D> { … }
```

Границы переезжают в `impl`, где `In` связывается равенством:

```rust
impl<D, In, S> FlowTable<D>
where
    D: crate::step::Step<From = DetectorEvent<In>, To = SmallVec<[S; 2]>>,
    In: HasFlow + Clone,
{ … }
```

Две реализации в том же файле (`Counter`, `TickPing`) переводятся по образцу шага 2.

- [ ] **Шаг 4: перевести `detect_per` — параметр `Sig`**

Это единственное место, где меняется ПУБЛИЧНАЯ форма типа. Приём предъявлен пробой 06.09.2026: `In` живёт только в границах `impl`, `Sig` — в поле.

```rust
/// `Unpin` у источника требуется намеренно, вместо `pin_project`: поле с сигналом
/// (`VecDeque<(K, Sig)>`) макрос не разбирает. Ограничение необременительно — источники
/// событий его удовлетворяют, а взамен разбор структуры остаётся читаемым.
///
/// # ПОЧЕМУ У СТРУКТУРЫ ПОЯВИЛСЯ `Sig`
///
/// Прежде тип сигнала брался проекцией `D::Signal`. Проекции больше нет: `Step` держит алфавит
/// целиком (`To = SmallVec<[Sig; 2]>`), а вынуть из него элемент нечем. Тип был здесь всегда —
/// изменилось лишь то, что теперь его обязаны НАЗВАТЬ.
///
/// `In` параметром НЕ стал: он не встречается ни в одном поле, и `PhantomData` ради него был бы
/// платой за красоту подписи. Он живёт в границах `impl`, где равенство `From = DetectorEvent<In>`
/// его связывает.
pub struct DetectPer<S, D, K, KeyFn, Factory, Sig> {
    source: S,
    key_fn: KeyFn,
    factory: Factory,
    /// `BTreeMap`, а не `HashMap`: порядок доставки `Tick` обязан быть детерминированным,
    /// иначе тест, где два детектора сработали на один тик, зеленеет через раз.
    ///
    /// Рядом с детектором — момент ПОСЛЕДНЕГО события по ключу: без него нечем отмерить простой.
    states: BTreeMap<K, (D, Instant)>,
    pending: VecDeque<(K, Sig)>,
    lifetime: Lifetime,
}

impl<S, D, K, KeyFn, Factory, Sig> DetectPer<S, D, K, KeyFn, Factory, Sig> {
    pub fn new(source: S, key_fn: KeyFn, factory: Factory, lifetime: Lifetime) -> Self {
        Self {
            source,
            key_fn,
            factory,
            states: BTreeMap::new(),
            pending: VecDeque::new(),
            lifetime,
        }
    }
}

impl<S, D, K, KeyFn, Factory, In, Sig> Stream for DetectPer<S, D, K, KeyFn, Factory, Sig>
where
    D: crate::step::Step<From = DetectorEvent<In>, To = SmallVec<[Sig; 2]>> + Unpin,
    S: Stream<Item = DetectorEvent<In>> + Unpin,
    In: Clone,
    Sig: Unpin,
    K: Ord + Clone + Unpin,
    KeyFn: Fn(&In) -> K + Unpin,
    Factory: Fn() -> D + Unpin,
{
    type Item = (K, Sig);

    // ТЕЛО `poll_next` НЕ МЕНЯЕТСЯ. Внутри `D::Input` заменяется на `In`, `D::Signal` — на `Sig`.
```

Прежняя граница `where D: Detector` на объявлении структуры и на `impl … new` **убирается совсем**: границы на объявлении структуры — известный анти-образец Rust, они не проверяются при употреблении и лишь заставляют повторять себя.

- [ ] **Шаг 5: перевести `ReflexExt::detect_per`**

`core/src/ext.rs:91`: граница `D: Detector + Unpin` → форма. Сигнатура снаружи не меняется — `Sig` выводится из `Factory: Fn() -> D` и равенства `D: Step<To = SmallVec<[Sig; 2]>>`. Возвращаемый тип получает `Sig` шестым параметром: `DetectPer<Self, D, K, KeyFn, Factory, Sig>`.

- [ ] **Шаг 6: снести `Detector` и `DetectorExt`**

Удалить из `core/src/detector.rs` объявления `pub trait Detector` и `pub trait DetectorExt` вместе с `impl<D: Detector> DetectorExt for D {}`. `DetectorEvent` **остаётся** — это буква входного алфавита, а не диалект.

Обновить `core/src/lib.rs:54-56`, убрав `Detector` и `DetectorExt` из реэкспорта.

Докблок трейта (строки 47-60) — знание о том, ЧЕМ была эта форма и почему она возникла, — переносится в шапку модуля отдельным абзацем «что здесь было», а не удаляется вместе с кодом. Код живёт в дереве, знание — в истории.

- [ ] **Шаг 7: переписать три тестовых файла**

`core/tests/detect_per.rs` (6 фикстур), `core/tests/flow_table.rs` (1), `core/tests/composition_domain.rs` (1). В каждой — `impl Detector` → `impl Step` по образцу шага 2. Импорты `reflex_core::{Detector, DetectorEvent}` → `reflex_core::{detector::DetectorEvent, step::Step}`.

Тела тестов и ассерты не трогать. В `composition_domain.rs` цепочка `.detect_per(|k: &u8| *k, Counting::default, Lifetime::UntilIdle(limit)).group_by(…)` обязана собраться **без единой новой аннотации типа** — это и есть проверка того, что `Sig` выводится. Если потребуется аннотация — остановиться и доложить: форма из задачи 1 неверна.

- [ ] **Шаг 8: прогнать**

```bash
cargo test -p reflex-core --all-features 2>&1 | grep "^test result"
cargo check -p reflex-core --all-features 2>&1 | grep -c "^warning"
```

Ожидается: `reflex-core` зелёный целиком, предупреждений 0. **Воркспейс в этот момент КРАСНЫЙ** — `instrument`, `engine`, `runtime` ещё требуют снесённый трейт. Это ожидаемо и объяснено в разделе «Порядок задач».

- [ ] **Шаг 9: коммит**

```bash
git add core/
git commit
```

---

## Задача 4: `instrument` — паспорт получает свой `type Signal`

**Files:**
- Modify: `instrument/src/lib.rs:480-560` — трейт `Instrument`
- Modify: `instrument/src/lib.rs:815` — `pub fn says`
- Modify: `instrument/src/park.rs:94` — `pub fn of<I: Instrument>`
- Modify: 13 файлов с реализациями: `agreement.rs`, `trust.rs`, `departure.rs`, `detect.rs` (4 шт.), `leg.rs`, `drift.rs`, `fate.rs`, `resolve.rs`, `pace.rs`, `episode.rs`, `sag.rs`, `retransmit.rs`
- Modify: `instrument/src/detect.rs:926` — граница `D: Detector<Signal = Distress>`

**Interfaces:**
- Consumes: `reflex_core::step::Step`, `reflex_core::detector::DetectorEvent` (задача 3)
- Produces: `pub trait Instrument: Step` с `type Signal`; `Instrument::name(&Self::Signal)` сохраняет подпись

- [ ] **Шаг 1: ПРЕДЪЯВИТЬ границу супертрейта, прежде чем на неё опереться**

Это единственная непроверенная посылка плана. Создать `instrument/tests/zz_passport_probe.rs`:

```rust
//! ПРОБА ГРАНИЦЫ ПАСПОРТА — временный файл, удаляется шагом 3.
//!
//! Вопрос: принимает ли компилятор равенство ассоциированного типа, ссылающееся на ДРУГОЙ
//! ассоциированный тип того же `Self`.
use reflex_core::detector::DetectorEvent;
use reflex_core::step::Step;
use smallvec::SmallVec;

trait Паспорт: Step<To = SmallVec<[<Self as Паспорт>::Signal; 2]>> {
    type Signal;
    const ИМЯ: &'static str;
    fn назвать(signal: &Self::Signal) -> &'static str;
}

struct Проба;

impl Step for Проба {
    type From = DetectorEvent<u8>;
    type To = SmallVec<[u16; 2]>;
    fn step(self, _event: Self::From) -> (Self, Self::To) {
        (self, SmallVec::new())
    }
}

impl Паспорт for Проба {
    type Signal = u16;
    const ИМЯ: &'static str = "проба";
    fn назвать(_signal: &Self::Signal) -> &'static str {
        "сигнал"
    }
}

#[test]
fn граница_паспорта_выразима() {
    assert_eq!(Проба::назвать(&7u16), "сигнал");
    assert_eq!(Проба::ИМЯ, "проба");
}
```

- [ ] **Шаг 2: прогнать пробу**

```bash
cargo test -p reflex-instrument --test zz_passport_probe 2>&1 | tail -30
```

**Если проба ЗЕЛЁНАЯ** — шаг 4 идёт по варианту А.
**Если проба ОТКАЗЫВАЕТСЯ СОБИРАТЬСЯ** — идти по варианту Б (шаг 5) и записать точный текст ошибки в отчёт: это факт о языке, и он ценнее, чем обход.

- [ ] **Шаг 3: удалить пробу**

```bash
rm instrument/tests/zz_passport_probe.rs
```

Проба своё дело сделала: её результат идёт в докблок трейта, а сама она не поставка.

- [ ] **Шаг 4 (вариант А, если проба зелёная): связать паспорт со `Step` в границе**

```rust
/// ПАСПОРТ ПРИБОРА. Половина выводится компилятором (типы), половина объявляется здесь и
/// сверяется аудитом с выведенным.
///
/// # ПОЧЕМУ У ПАСПОРТА СВОЙ `Signal`, ХОТЯ ОН НАВЕШЕН НА `Step` (06.09.2026)
///
/// `Step` держит выходной алфавит целиком (`To = SmallVec<[S; 2]>`), и вынуть из него элемент
/// нечем: проекции у типа-контейнера нет. А `name` обязан говорить об ОДНОМ показании, а не о
/// пачке. Поэтому паспорт объявляет `Signal` сам, а граница супертрейта СВЯЗЫВАЕТ объявленное с
/// выходом шага — расхождение ловит компилятор, а не аудит.
///
/// Отвергнуто: `fn name(told: &Self::To)`. Он принимал бы пачку и обязывал бы каждый прибор
/// решать, о котором из показаний говорить, — то есть переносил бы выбор с автора на вызывающего.
pub trait Instrument: reflex_core::step::Step<To = SmallVec<[<Self as Instrument>::Signal; 2]>> {
    /// О ЧЁМ ПРИБОР ГОВОРИТ ПО ОДНОМУ ПОКАЗАНИЮ. Прежде брался проекцией `Detector::Signal`.
    type Signal;

    const SUBJECT: Subject;
    const LAYER: Layer;
    const PROTOCOLS: &'static [Protocol];

    fn name(signal: &Self::Signal) -> &'static str;
    // остальные члены без изменений
}
```

- [ ] **Шаг 5 (вариант Б, только если проба красная): паспорт без границы на `Step::To`**

```rust
pub trait Instrument: reflex_core::step::Step {
    /// О ЧЁМ ПРИБОР ГОВОРИТ ПО ОДНОМУ ПОКАЗАНИЮ.
    ///
    /// # СВЯЗЬ С `Step::To` НЕ ДЕРЖИТСЯ ТИПАМИ, И ЭТО НАЗВАНО (06.09.2026)
    ///
    /// Хотелось `Instrument: Step<To = SmallVec<[Self::Signal; 2]>>`, но компилятор его не берёт:
    /// <точный текст ошибки из шага 2>. Значит прибор может объявить `Signal`, не совпадающий с
    /// тем, что он отдаёт, и НИКТО ЭТОГО НЕ ЗАМЕТИТ.
    ///
    /// Дыра закрыта аудитом (`park.rs`), а не типом, и это слабее. Долг записан.
    type Signal;
    …
}
```

И в `instrument/src/park.rs` добавить к аудиту проверку совпадения объявленного `Signal` с элементом `To` — тем же способом, каким аудит уже сверяет `LAYER` с выведенным.

- [ ] **Шаг 6: перевести 15 реализаций**

В каждом из 13 файлов заменить `impl Detector for X` на `impl Step for X` по образцу задачи 3 шага 2, и в парном `impl Instrument for X` добавить строку `type Signal = <тот тип, что стоял в Detector::Signal>;`.

`instrument/src/departure.rs`, `leg.rs`, `episode.rs` несут границы (`impl<S> … for DepartureInstrument<S>`, `impl<L> …`, `impl<W: OpenedAt + …> …`) — их границы сохраняются как есть, меняется только имя трейта и форма ассоциированных типов.

- [ ] **Шаг 7: перевести `says` и `of`**

`instrument/src/lib.rs:815` `pub fn says<D: reflex_core::Detector>(…)` — граница на форму. `instrument/src/detect.rs:926` `D: Detector<Signal = Distress>` → `D: Step<From = DetectorEvent<In>, To = SmallVec<[Distress; 2]>>`, где `In` добавляется параметром функции.

`instrument/src/park.rs:94` `pub fn of<I: crate::Instrument>() -> Passport` — читает только константы, менять не требуется. **Проверить, а не предположить**: `grep -n "fn of" -A15 instrument/src/park.rs`.

- [ ] **Шаг 8: прогнать**

```bash
cargo test -p reflex-instrument --all-features 2>&1 | grep "^test result"
cargo check -p reflex-instrument --all-features 2>&1 | grep -c "^warning"
```

Ожидается: `reflex-instrument` зелёный, предупреждений 0. Воркспейс всё ещё красный (`engine`, `runtime`).

**Особое внимание к `park.rs:159`.** Его докблок сообщает, что первая редакция аудита искала подстроку `"impl crate::Instrument for"` и дала 12 вместо 14, потому что подстрока не ловит реализации с границами. Аудит после этой задачи обязан по-прежнему находить ВСЕ 15. Если число упало — это не «тест сломался», это аудит ослеп, и чинить надо аудит.

- [ ] **Шаг 9: коммит**

```bash
git add instrument/
git commit
```

---

## Задача 5: `engine` и `engine-nfq`

**Files:**
- Modify: `engine/src/lib.rs:674` — `SightingInstrument`
- Modify: `engine/src/row.rs:381` — `BlindnessInstrument`
- Modify: `engine/src/lib.rs:777`, `engine/src/interpret.rs:305`, `engine/src/row.rs:668` — импорты в тестах
- Modify: `engine-nfq/src/bin/plane-queue.rs:138` — вызов `Instrument::name`

**Interfaces:**
- Consumes: `Instrument` с `type Signal` (задача 4)
- Produces: ничего нового

- [ ] **Шаг 1: перевести две реализации**

Обе — `impl Detector for X` + `impl reflex_instrument::Instrument for X`. По образцу задачи 4 шага 6.

- [ ] **Шаг 2: проверить вызов в `plane-queue.rs`**

`<reflex_engine::SightingInstrument as reflex_instrument::Instrument>::name(told)` — подпись `name` не менялась, вызов обязан остаться как есть. Если не собирается — значит `told` имел тип `D::Signal` через проекцию `Detector`; заменить на конкретный тип сигнала `SightingInstrument`.

- [ ] **Шаг 3: прогнать**

```bash
cargo test -p reflex-engine -p reflex-engine-nfq --all-features 2>&1 | grep "^test result"
cargo check -p reflex-engine -p reflex-engine-nfq --all-features 2>&1 | grep -c "^warning"
```

- [ ] **Шаг 4: коммит**

```bash
git add engine/ engine-nfq/
git commit
```

---

## Задача 6: `runtime` — последний крейт, воркспейс зеленеет

**Files:**
- Modify: `runtime/src/stream/detect.rs:15,28,43` — границы
- Modify: `runtime/src/ext.rs:4,14,21` — импорт и две границы
- Rewrite: `runtime/tests/detector_v2.rs`, `runtime/tests/rst_detector.rs`

**Interfaces:**
- Consumes: всё предыдущее
- Produces: зелёный воркспейс

- [ ] **Шаг 1: инвентарь двух тестовых файлов**

```bash
for f in runtime/tests/detector_v2.rs runtime/tests/rst_detector.rs; do
  echo "=== $f"; grep -n "^fn \|^async fn " $f
done
```

**Имя `detector_v2.rs` — след прежней миграции.** Проверить, что он сторожит: если то же, что `rst_detector.rs`, это дубль, и снос одного из них — отдельное решение, которое надо доложить, а не принять молча.

- [ ] **Шаг 2: перевести границы**

`runtime/src/ext.rs:4` `use reflex_core::detector::Detector;` → `use reflex_core::step::Step;`. Строки 14 и 21: `D: Detector<Input = Self::Item>` → `D: Step<From = DetectorEvent<Self::Item>, To = SmallVec<[Sig; 2]>>` с `Sig` параметром метода.

`runtime/src/stream/detect.rs:15,28,43` — по тому же образцу.

- [ ] **Шаг 3: перевести фикстуры тестов**

`SimpleRstDetector` и `RstDetector` — `impl Detector` → `impl Step`.

- [ ] **Шаг 4: прогнать ВЕСЬ воркспейс**

```bash
cargo test --workspace --all-features 2>&1 | grep "^test result" \
  | awk '{p+=$4; f+=$6} END {print "наборов:", NR, "прошло:", p, "провалов:", f}'
cargo clean && cargo check --workspace --all-features 2>&1 | grep -cE "^(warning|error)"
```

Ожидается: провалов **0**; предупреждений и ошибок **0** на чистой сборке. Число наборов может отличаться от 87 — задача 1 сносит тесты `by`/`changes`, задача 6 может снести дубль. Разница обязана быть ОБЪЯСНЕНА поимённо в сообщении коммита, а не списана на «примерно столько же».

- [ ] **Шаг 5: приёмка сноса**

```bash
echo "Detector/DetectorExt в коде: $(grep -rn 'Detector\b' --include=*.rs core engine engine-nfq instrument runtime os linux linux-common | grep -v DetectorEvent | grep -v '//' | wc -l)"
echo "Detecting: $(grep -rn 'Detecting' --include=*.rs . | grep -v '/target/' | wc -l)"
echo "диалектов Мили: $(grep -rn 'fn step(self' --include=*.rs core/src | wc -l)"
```

Ожидается: `Detector` вне `DetectorEvent` и вне прозы — **0**; `Detecting` — 0.

- [ ] **Шаг 6: коммит**

```bash
git add runtime/
git commit
```

---

## Самопроверка плана

**1. Покрытие спеки.** §3 строка 2 («`Detector`, `DetectorExt` и восемь комбинаторов» → `Step` + комбинаторы шага) — задачи 1, 3. §3.2 (цена: 17 реализаций) — задачи 4, 5; замер уточнил, что 17 — это `instrument`+`engine`, и полное число мест 42.

**Расхождение со спекой, названное, а не сглаженное:** спека говорит «восемь комбинаторов», их **семь** (`and`, `rmap`, `contextual`, `by`, `timed`, `changes`, `lmap`). Восьмым, вероятно, числился `then`, который живёт в `StepExt` и к `DetectorExt` отношения не имеет. Спека не правится — она датирована; расхождение записано здесь.

**Пробел спеки, найденный планом:** `instrument::Instrument` — третье имя той же оси, спекой не названное. Не синоним (несёт паспорт), но требует своего `type Signal`. 17 реализаций сверх посчитанного спекой.

**2. Заглушки.** Ни одного «TBD». Два места дают ветвление по РЕЗУЛЬТАТУ проверки, а не по вкусу: задача 2 шаг 2 (стыкуются ли типы двух `Counting`) и задача 4 шаги 4/5 (берёт ли компилятор границу паспорта). Оба ветвления описаны обоими вариантами полностью.

**3. Согласованность типов.** `DetectPer` получает `Sig` шестым параметром в задаче 3 и употребляется с ним в `ext.rs` там же. `Instrument::Signal` заводится в задаче 4 и употребляется в задаче 5. Форма `Step<From = DetectorEvent<I>, To = SmallVec<[S; 2]>>` записана одинаково во всех задачах.

---

## Что этот план НЕ делает

* **Не расширяет алфавит** до `Packet | Tick | Taught | Ordered` — это план 3. `DetectorEvent` остаётся двухбуквенным.
* **Не делает атрибуцию обязательной.** `by` переносится и остаётся НЕОБЯЗАТЕЛЬНЫМ, а неотличимость лечится, только когда имя приходит всегда. Долг: атрибуция обязана стать частью выходного слова (спека §2, `Out = (word, observations)`). Здесь она сохранена, но не вылечена.

* **Не трогает `ExpiringSet` — четвёртый диалект, найденный категорным аудитом.** `mark(&mut self, key, now) -> Marking` и `sweep(&mut self, now) -> Vec<K>` суть машина Мили с выходным алфавитом `Marking{Fresh, Renewed, Rejected}`, написанная руками через `&mut` и время аргументом. Не драйвер (никого не кормит) и не эталон. Предмет отдельного среза — вместе с `FlowTable` и `DetectPer`, которые, наоборот, ДРАЙВЕРЫ и вне категории стоят законно.
* **Не чинит потребителя.** 153 места у соседки ломаются. Рулинг пользователя 06.09.2026: «Соседка — потребитель нашего решения и будет делать так, как мы реализуем свой фрэймворк».
