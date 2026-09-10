# Функтор носителя — план реализации

> **ПЛАН УСТАРЕЛ — ЧИТАТЬ КАК ЗАМЫСЕЛ, НЕ КАК КАРТУ ДЕРЕВА.** По ходу исполнения замеры
> пересматривались трижды, задачи T7½, T7¾, T12½ и T12¾ заведены сверх плана и в нём отсутствуют, а
> дельт вышло девять вместо заявленных. Что и почему разошлось — в журнале решений
> `.superpowers/sdd/2026-09-10-carrier-functor/progress.md`; он же старше этого файла по правоте.


> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** фасад `reflex` перестаёт знать типы `reflex-linux`; носитель становится параметром, и WinDivert встаёт в ту же дверь, что NFQ.

**Architecture:** доводим до фасада уже построенный функтор §9 (`Terminal`+способности) вместо второго шва рядом. `Serves::serve` получает СРОК (`until`), ведущий цикл переезжает на `core::interleave` (потреблён ноль раз, оттого буквы немонотонны), край уходит из слова в параметр (`Wide<W, E>`), дом состояния остаётся там, где уже есть, — внутри `Terminal::apply`. Свидетель — `Local<QueueSocket>` (та же очередь, край и дом в юзерспейсе = форма WinDivert) и дифференциальный стенд.

**Tech Stack:** Rust 2021, `cargo test --workspace`, docker compose для боевых стендов, `x86_64-pc-windows-msvc` для кросс-проверки формы.

**Spec:** `docs/superpowers/specs/2026-09-10-carrier-functor-design.md`

## Global Constraints

- **Докблок говорит «почему».** Заменимое типом или проверкой обязано быть заменено; остаются причина, цена и оплаченный опыт. Комментариев вида «что делает код» не писать.
- **Один предмет — один закон.** Перед правкой искать дубли; копии расходятся молча при зелёной сборке.
- **Ломать межкрейтовые сборки можно** без отдельной санкции: область задачи задана смыслом, а не списком файлов.
- **Замер прогоном, а не грепом.** Всякое «работает» подтверждается запуском команды с показанным выводом.
- **Зелёный без доказанной способности краснеть не считается.** Каждый новый закон проверяется мутацией: сломать → тест обязан покраснеть → починить.
- Язык кода и докблоков — русский, как в дереве. Имена идентификаторов — английские.
- Атрибуция коммитов:
  ```
  Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01UnSSqN2bGikPZC8x4EBm7G
  ```
- Дельты канона (Д1–Д6 спеки) в `docs/vision/2026-09-08-reflex-one-machine-vision.md` **не вносить**: они ждут гейта хранителя `reflex-e1`. Код опережает канон осознанно; сводка это называет.

---

### Task 1: `Torn` — четвёртая буква входного алфавита

Носитель умеет объявить потерю (`ENOBUFS`). §2 требует полноты: `Собралось(f) ⇒ ∀ буква b, которую f может встретить: b ∈ In(f)`. Сегодня дыру печатает фасад — писатель знания вне алфавита.

**Files:**
- Modify: `core/src/detector.rs:10-33` (перечисление и `at()`)
- Modify: `core/src/interleave.rs` (дверь `torn`)
- Modify: все матчи `DetectorEvent::` — сборка покажет список (≈38 файлов в `core`/`engine`/`engine-nfq`/`instrument`/`reflex`)
- Test: `core/tests/torn.rs` (создать)

**Interfaces:**
- Produces: `DetectorEvent::Torn { at: Instant }`; `Interleave::torn<T>(self, at: Instant) -> (Self, Vec<DetectorEvent<T>>)`

- [ ] **Step 1: Написать падающий тест**

```rust
// core/tests/torn.rs
//! Дыра — БУКВА, а не запись в журнал. Пока носитель был один, потерю печатал фасад: знание о
//! входе получал писатель вне алфавита, и §2 (полнота) нарушался молча.

use core::time::Duration;
use std::time::Instant;

use reflex_core::interleave::Interleave;
use reflex_core::DetectorEvent;

/// Дыра несёт свой момент — иначе её нельзя поставить в последовательность.
#[test]
fn дыра_несёт_момент() {
    let at = Instant::now();
    let torn: DetectorEvent<()> = DetectorEvent::Torn { at };
    assert_eq!(torn.at(), at);
}

/// Дыра двигает сетку так же, как непонятое: шов про МОМЕНТЫ, не про содержимое. Не двигай она
/// сетку — поток из одних дыр не закрывал бы окон, и молчание стало бы неотличимо от «пакетов нет».
#[test]
fn перешагнутые_узлы_выходят_перед_дырой() {
    let start = Instant::now();
    let seam = Interleave::started(start, Duration::from_millis(100));
    let (_seam, letters) = seam.torn::<()>(start + Duration::from_millis(250));

    assert!(matches!(
        letters.as_slice(),
        [
            DetectorEvent::Tick { node: 1, .. },
            DetectorEvent::Tick { node: 2, .. },
            DetectorEvent::Torn { .. }
        ]
    ));
}
```

- [ ] **Step 2: Прогнать, убедиться что падает**

Run: `cargo test -p reflex-core --test torn`
Expected: FAIL — `no variant named Torn`, `no method named torn`.

- [ ] **Step 3: Ввести букву**

```rust
// core/src/detector.rs — в enum DetectorEvent<T>
    /// Наблюдения были и до нас не дошли — носитель объявил потерю (`ENOBUFS` у очереди ядра,
    /// переполнение у чужой ОС). Не `Opaque`: там пакет ПРИШЁЛ и не разобрался, здесь он не
    /// приходил вовсе. Слить их значило бы объявить дыру непонятым пакетом — соврать о наблюдении,
    /// которого не было. Без этой буквы прибор сравнивает наблюдения через необъявленную дыру.
    Torn { at: Instant },
```

В `at()` добавить арм `DetectorEvent::Torn { at } => *at`.

```rust
// core/src/interleave.rs — рядом с unread
    /// Дыра объявлена. Симметрична [`Interleave::unread`]: узлы, которые дыра перешагнула, выходят
    /// ПЕРЕД ней — порядок держит конструкция, а не дисциплина зовущего.
    pub fn torn<T>(self, at: Instant) -> (Self, Vec<DetectorEvent<T>>) {
        let at = at.max(self.last);
        let events = self
            .nodes_up_to(at)
            .chain(core::iter::once(DetectorEvent::Torn { at }))
            .collect();
        (Self { last: at, ..self }, events)
    }
```

- [ ] **Step 4: Починить сборку по всему дереву**

Run: `cargo build --workspace 2>&1 | grep -E '^error' | head -50`

Каждый неисчерпывающий матч дополнить армом. Правило выбора арма: прибор, который уже объединяет `Tick | Opaque` одним поведением, получает `Torn` в ту же группу; прибор, у которого дыра меняет исход, получает свой арм с докблоком «почему». Прибор, считающий пакеты подряд (`Retransmit`, `edge_detect`), обязан после дыры **не считать пропуск за наблюдение** — если у прибора есть счётчик подряд идущих, дыра его сбрасывает.

- [ ] **Step 5: Прогнать всё**

Run: `cargo test --workspace 2>&1 | tail -20`
Expected: PASS, тестов не меньше 875.

- [ ] **Step 6: Мутация**

Убрать `nodes_up_to` из `torn` (оставить только саму букву) — `перешагнутые_узлы_выходят_перед_дырой` обязан покраснеть. Вернуть.

- [ ] **Step 7: Коммит**

```bash
git add -A
git commit -m "$(cat <<'EOF'
feat(core): дыра — буква входа, а не запись в журнал (§2, Д1)

Носитель умеет объявить потерю; машина её встречает. Пока носитель был один, дыру печатал
фасад — то есть знание о ВХОДЕ получал писатель вне алфавита, и полнота §2 нарушалась молча.
`Torn` отдельна от `Opaque` предметом: там пакет пришёл и не разобрался, здесь не приходил.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01UnSSqN2bGikPZC8x4EBm7G
EOF
)"
```

---

### Task 2: `Interleave::next_node` — срок для шва

Драйверу нужен момент следующего узла, чтобы отдать его носителю сроком. Без него цикл заводит своё ожидание мимо шва — и завёл (`reflex/src/lib.rs:1105`).

**Files:**
- Modify: `core/src/interleave.rs`
- Test: `core/tests/interleave.rs`

**Interfaces:**
- Consumes: `grid::node`, `grid::due` (`core/src/grid.rs:26,35`)
- Produces: `Interleave::next_node(&self) -> Instant`

- [ ] **Step 1: Написать падающий тест**

```rust
// core/tests/interleave.rs — добавить

/// Срок для носителя — момент СЛЕДУЮЩЕГО узла, отсчитанный от последнего выданного. Не «сейчас
/// плюс шаг»: тогда каждый пакет продлевал бы ожидание, и тик уезжал бы вправо тем сильнее, чем
/// плотнее трафик — часы приборов молчания зависели бы от трафика, что §8 запрещает.
#[test]
fn срок_есть_момент_следующего_узла() {
    let start = Instant::now();
    let every = Duration::from_millis(100);
    let seam = Interleave::started(start, every);

    assert_eq!(seam.next_node(), start + Duration::from_millis(100));

    let (seam, _) = seam.idle::<()>(start + Duration::from_millis(250));
    assert_eq!(seam.next_node(), start + Duration::from_millis(300));
}
```

- [ ] **Step 2: Прогнать, убедиться что падает**

Run: `cargo test -p reflex-core --test interleave срок_есть`
Expected: FAIL — `no method named next_node`.

- [ ] **Step 3: Реализовать**

```rust
// core/src/interleave.rs
    /// Момент следующего узла сетки. Чист: часов не спрашивает, считает от последнего выданного
    /// момента — оттого срок не плывёт от того, когда его спросили.
    pub fn next_node(&self) -> Instant {
        crate::grid::node(
            self.start,
            self.every,
            crate::grid::due(self.start, self.last, self.every) + 1,
        )
    }
```

- [ ] **Step 4: Прогнать**

Run: `cargo test -p reflex-core --test interleave`
Expected: PASS.

- [ ] **Step 5: Мутация**

Заменить `+ 1` на `+ 0` — тест обязан покраснеть на первом же `assert_eq!`. Вернуть.

- [ ] **Step 6: Коммит**

```bash
git add core/src/interleave.rs core/tests/interleave.rs
git commit -m "$(cat <<'EOF'
feat(core): срок шва — момент следующего узла (§8)

Считается от последнего выданного момента, а не от «сейчас»: иначе каждый пакет продлевал бы
ожидание, и часы приборов молчания зависели бы от плотности трафика.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01UnSSqN2bGikPZC8x4EBm7G
EOF
)"
```

---

### Task 3: `Serves::serve` получает срок (Д3)

Ждать умеет только тот, у кого дескриптор; знать сколько — только тот, у кого часы. Пока они не могли договориться, цикл ждал мимо шва, и оттуда же пришёл регресс `3202628`.

**Files:**
- Modify: `core/src/serves.rs` (подпись, `Served::Torn`)
- Modify: `linux/src/nfqueue/terminal.rs:151-175`
- Modify: `linux/src/nfqueue/pipeline.rs:171,238-262`
- Test: `core/tests/serves.rs`

**Interfaces:**
- Produces: `Served { Answered, Idle, Blind, Torn }`; `Serves::serve<F>(&mut self, until: Instant, decide: F)`

- [ ] **Step 1: Написать падающий тест**

```rust
// core/tests/serves.rs — добавить к существующему фейку `Memo`

/// Закон шва: не возвращаться раньше срока, кроме как с работой. Не будь его, ведущий цикл
/// крутился бы вхолостую на пустой очереди — и завёл бы своё ожидание мимо шва, что и случилось.
#[test]
fn пустой_носитель_держит_срок() {
    let mut carrier = Memo::empty();
    let until = Instant::now() + Duration::from_millis(50);

    let outcome = carrier.serve(until, |_held| unreachable!("работы не было"));

    assert!(matches!(outcome, Served::Idle));
    assert!(Instant::now() >= until, "вернулся раньше срока");
}

/// Работа не ждёт срока: пакет отдаётся сразу, иначе задержка решения равнялась бы шагу сетки.
#[test]
fn работа_возвращается_сразу() {
    let mut carrier = Memo::with_one_packet();
    let until = Instant::now() + Duration::from_secs(60);

    let outcome = carrier.serve(until, |_held| Answer::Pass);

    assert!(matches!(outcome, Served::Answered(Ok(_))));
    assert!(Instant::now() < until, "ждал срока, имея работу");
}
```

- [ ] **Step 2: Прогнать, убедиться что падает**

Run: `cargo test -p reflex-core --test serves`
Expected: FAIL — `serve` takes 1 argument.

- [ ] **Step 3: Править подпись и фейк**

```rust
// core/src/serves.rs
pub enum Served<D, R> {
    Answered(Result<D, R>),
    /// Работы не было. Не ошибка: к сроку очередь осталась пуста.
    Idle,
    /// Ждать не на чем — дескриптор не добыт. Со сроком в подписи носитель обязан ПРОСПАТЬ до
    /// него: иначе ведущий цикл сожжёт ядро, а прежде это держалось соглашением с циклом.
    Blind,
    /// Носитель объявил потерю: наблюдения были и до нас не дошли. Клетка отдельная от `Idle` —
    /// «пусто» и «дыра» чинятся по-разному, и сравнивать наблюдения через необъявленную дыру нельзя.
    Torn,
}

pub trait Serves: Terminal {
    /// Взять пакет, решить, отдать решение — неделимо. **Не возвращается раньше `until`, кроме
    /// как с работой**: ждать умеет только владелец дескриптора, знать сколько — только владелец
    /// часов (§8). Пока эти двое не могли договориться, ведущий цикл заводил ожидание мимо шва.
    fn serve<F>(
        &mut self,
        until: std::time::Instant,
        decide: F,
    ) -> Served<Delivered<Self::Answer>, Refused<Self::Answer, Self::Refusal>>
    where
        F: FnOnce(&Held<Self::Carrier>) -> Self::Answer;
}
```

`NfqueueBackend::serve`: `self.wait(0)` → `self.wait(millis_until(until))`, где

```rust
// linux/src/nfqueue/terminal.rs
/// Остаток до срока в миллисекундах для `poll`. Прошедший срок — ноль, не отрицательное:
/// `poll` с отрицательным ждёт вечно, и опоздавший цикл встал бы навсегда.
fn millis_until(until: Instant) -> i32 {
    i32::try_from(until.saturating_duration_since(Instant::now()).as_millis()).unwrap_or(i32::MAX)
}
```

`Waited::Blind` → перед возвратом `Served::Blind` проспать остаток: `std::thread::sleep(until.saturating_duration_since(Instant::now()))`.

`pipeline.rs`: зовущий передаёт `Instant::now()` (поведение сохраняется — прежний `wait(0)`), добавить арм `Served::Torn` со своим счётчиком `torn` рядом с `again`/`blind`.

- [ ] **Step 4: Прогнать**

Run: `cargo test --workspace 2>&1 | tail -5`
Expected: PASS.

- [ ] **Step 5: Мутация**

В `Blind`-ветке убрать сон — `пустой_носитель_держит_срок` на слепом фейке обязан покраснеть. Вернуть.

- [ ] **Step 6: Коммит**

```bash
git add -A
git commit -m "$(cat <<'EOF'
feat(core,linux): срок в подписи шва — ждёт тот, у кого дескриптор (§9.3, Д3)

`Serves::serve` получает `until` и закон «не возвращаться раньше срока, кроме как с работой».
Прежде носитель звал `wait(0)`, а сколько крутиться — «знал ведущий цикл», которому ждать было
не на чем: дескриптор внутри бэкенда. Оттуда и регресс 3202628.

`Served` получает клетку `Torn`: «пусто» и «дыра» чинятся по-разному.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01UnSSqN2bGikPZC8x4EBm7G
EOF
)"
```

---

### Task 4: закон `EdgeView` сужается до кадров (Д6)

Закон обещает нагрузку, единственный `impl` отдаёт кадры, прибор молча компенсирует их через `HDR = 60`. Сходится ровно потому, что край один.

**Files:**
- Modify: `core/src/edge.rs:17-24` (докблоки `down_bytes`/`up_bytes`)
- Modify: `instrument/src/edge_detect.rs` (докблок модуля + предикат + `#[cfg(test)] mod tests`)

**Где тест:** ВНУТРИ `instrument/src/edge_detect.rs`, а не в `instrument/tests/`. Предикат
`pub(crate)`, и интеграционный тест его не видит; делать его `pub` ради теста значило бы
расширить поверхность крейта ради удобства проверки.

**Interfaces:**
- Produces: контракт «`down_bytes`/`up_bytes` — байты КАДРОВ (L3+L4+нагрузка)»

- [ ] **Step 1: Написать падающий тест**

```rust
// instrument/src/edge_detect.rs — в конец файла
#[cfg(test)]
mod tests {
    use super::*;

    /// Край, у которого известны только эти две величины: остальное — «не считали» (§7).
    struct Frames { packets: u64, bytes: u64 }

    impl EdgeView for Frames {
        fn down_packets(&self) -> Option<u64> { Some(self.packets) }
        fn down_bytes(&self) -> Option<u64> { Some(self.bytes) }
        fn up_packets(&self) -> Option<u64> { None }
        fn up_bytes(&self) -> Option<u64> { None }
        fn idle(&self) -> Option<Duration> { None }
        fn age(&self) -> Option<Duration> { None }
        fn mark(&self) -> u32 { 0 }
    }

    /// Порог «клиент отдал запрос» считает КАДРЫ, и это контракт, а не совпадение с conntrack.
    /// Считай край нагрузку — порог завысился бы на заголовок каждого пакета, и запрос перестал
    /// бы наблюдаться. Мера: conntrack нагрузки не знает и знать не может.
    #[test]
    fn порог_запроса_считает_кадры_а_не_нагрузку() {
        // Три пакета вниз, кроме заголовков — ничего: запроса не было.
        assert!(!asked_for_something(&Frames { packets: 3, bytes: 3 * HDR }));
        // Те же три пакета, но сверх заголовков 200 байт: запрос отдан.
        assert!(asked_for_something(&Frames { packets: 3, bytes: 3 * HDR + 200 }));
    }

    /// Учёт выключен — не «ноль запроса», а «не считали». Иначе край без учёта выглядел бы как
    /// клиент, не отправивший ничего, и прибор судил бы о мире по собственной слепоте.
    #[test]
    fn край_без_учёта_не_считается_отсутствием_запроса() {
        struct Blind;
        impl EdgeView for Blind {
            fn down_packets(&self) -> Option<u64> { None }
            fn down_bytes(&self) -> Option<u64> { None }
            fn up_packets(&self) -> Option<u64> { None }
            fn up_bytes(&self) -> Option<u64> { None }
            fn idle(&self) -> Option<Duration> { None }
            fn age(&self) -> Option<Duration> { None }
            fn mark(&self) -> u32 { 0 }
        }
        assert!(!asked_for_something(&Blind));
    }
}
```

- [ ] **Step 2: Прогнать, убедиться что падает**

Run: `cargo test -p reflex-instrument --lib edge_detect`
Expected: FAIL — `asked_for_something` не существует.

- [ ] **Step 3: Вынести предикат и починить закон**

В `instrument/src/edge_detect.rs` выделить чистую функцию из места, где сегодня стоит выражение `down.bytes > down.packets * HDR + FLOOR`:

```rust
/// Отдал ли клиент что-то сверх заголовков. Отдельной функцией, а не выражением в ветке: это
/// ЗАКОН о величинах края, и его проверяют таблицей, а не прогоном автомата целиком.
pub(crate) fn asked_for_something<E: EdgeView>(edge: &E) -> bool {
    match (edge.down_bytes(), edge.down_packets()) {
        (Some(bytes), Some(packets)) => bytes > packets.saturating_mul(HDR) + FLOOR,
        _ => false,
    }
}
```

В `core/src/edge.rs` докблоки:

```rust
    /// Байт КАДРОВ от клиента к цели (L3+L4+нагрузка), не нагрузки. Кадры, а не нагрузка, потому
    /// что conntrack нагрузки не знает и знать не может: обещать её значило бы обещать
    /// невыполнимое, а прибор всё равно компенсировал бы заголовки — и компенсация была бы верна
    /// по совпадению с одним носителем, а не по контракту. `None` — учёт выключен.
    fn down_bytes(&self) -> Option<u64>;
```

Симметрично `up_bytes`.

- [ ] **Step 4: Прогнать**

Run: `cargo test -p reflex-instrument`
Expected: PASS.

- [ ] **Step 5: Мутация**

Убрать `+ FLOOR` — `порог_запроса_считает_кадры_а_не_нагрузку` обязан покраснеть на первом случае.
Отдельно: заменить `_ => false` на `_ => true` — `край_без_учёта_не_считается_отсутствием_запроса`
обязан покраснеть. Вернуть обе.

- [ ] **Step 6: Коммит**

```bash
git add core/src/edge.rs instrument/src/edge_detect.rs
git commit -m "$(cat <<'EOF'
fix(core,instrument): закон края обещал невыполнимое — байты суть КАДРЫ (Д6)

`EdgeView::down_bytes` обещал «полезную нагрузку»; conntrack отдаёт счётчик кадров, а прибор
молча компенсировал заголовки через HDR=60. Пока край один, сходилось. Второй край, считающий
нагрузку честно, завысил бы порог на 60 байт на пакет.

Закон сужен до исполнимого — то же правило, что сняло вчера `impl CanAsk`: обещание, которое
никогда не исполняется, законом не является.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01UnSSqN2bGikPZC8x4EBm7G
EOF
)"
```

---

### Task 5: `Edging` — край спрашивается у носителя

Край обязан уехать из слова в параметр; спрашивать его надо у носителя СООБЩЕНИЯ, а не у бэкенда: внутри `serve` бэкенд заимствован, второго `&mut` не будет (та же `E0499`, из-за которой очередь стала `Serves`).

**Files:**
- Modify: `core/src/held.rs` (трейт рядом с `Observed`)
- Modify: `linux/src/queue/terminal.rs` (`Held` несёт `TimeoutBase`, `impl Edging`)
- Modify: `linux/src/queue/mod.rs` (реэкспорт)
- Test: `linux/tests/queue_terminal.rs`

**Interfaces:**
- Produces: `core::held::Edging { type Edge: EdgeView; fn edge(&self) -> Option<Self::Edge> }`; `queue::Held::new(packet, base)`

- [ ] **Step 1: Написать падающий тест**

```rust
// linux/tests/queue_terminal.rs — добавить

/// Край спрашивается у носителя сообщения. `None` — поток ещё не в conntrack (первый `SYN` вне
/// таблицы): «не считали», а не «не ответила» (§7). Ноль здесь соврал бы о тишине.
#[test]
fn край_берётся_у_носителя_а_вне_учтённый_поток_даёт_none() {
    let base = TimeoutBase { syn_sent: Duration::from_secs(120), established: Duration::from_secs(432000) };

    let counted = Held::new(packet_with_ct(0xDEAD_BEEF), base);
    assert_eq!(counted.edge().map(|edge| edge.mark()), Some(0xDEAD_BEEF));

    let uncounted = Held::new(packet_without_ct(), base);
    assert!(uncounted.edge().is_none());
}
```

- [ ] **Step 2: Прогнать, убедиться что падает**

Run: `cargo test -p reflex-linux --test queue_terminal край_берётся`
Expected: FAIL — `Held::new` takes 1 argument, `edge` not found.

- [ ] **Step 3: Реализовать**

```rust
// core/src/held.rs — рядом с Observed
/// Что край ведёт о РАЗГОВОРЕ, у которого пришёл этот пакет. Пара к [`Observed`]: тот показывает
/// провод, этот — величины края. Спрашивают НОСИТЕЛЯ СООБЩЕНИЯ, а не бэкенд: внутри `serve`
/// бэкенд заимствован, и второго `&mut` не будет.
pub trait Edging {
    type Edge: crate::edge::EdgeView;
    /// `None` — край о разговоре ничего не ведёт (потока ещё нет в его таблице). Клетка §7:
    /// «не считали» обязано отличаться от «не ответила».
    fn edge(&self) -> Option<Self::Edge>;
}
```

```rust
// linux/src/queue/terminal.rs
/// Носитель права ответа. Несёт базу таймаутов, потому что край строится ЗДЕСЬ: база снимается
/// раз при открытии, а `Edging` спрашивают у сообщения — взять её оттуда больше неоткуда.
pub struct Held {
    packet: Packet,
    base: TimeoutBase,
}

impl reflex_core::held::Edging for Held {
    type Edge = CtEdge;
    fn edge(&self) -> Option<CtEdge> {
        self.packet.ct.map(|view| CtEdge::seen(view, self.base))
    }
}
```

- [ ] **Step 4: Прогнать**

Run: `cargo test -p reflex-linux && cargo build --workspace`
Expected: PASS.

- [ ] **Step 5: Мутация**

Заменить `self.packet.ct.map(...)` на `Some(CtEdge::seen(CtView::default(), self.base))` — второй `assert!` обязан покраснеть. Вернуть.

- [ ] **Step 6: Коммит**

```bash
git add -A
git commit -m "$(cat <<'EOF'
feat(core,linux): край спрашивается у носителя сообщения (Edging)

Пара к `Observed`: тот показывает провод, этот — величины края. У сообщения, а не у бэкенда:
внутри `serve` бэкенд заимствован, и второго `&mut` не будет — та же E0499, из-за которой
очередь стала `Serves`, а не `Source`.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01UnSSqN2bGikPZC8x4EBm7G
EOF
)"
```

---

### Task 6: `QueueSocket` входит в шов

Новый путь фасада стоит на `QueueSocket`, у которого `Terminal` есть, а `Serves` нет — оттого фасад и звал `recv`/`verdict` руками.

**Files:**
- Modify: `linux/src/queue/socket.rs` (буфер пачки)
- Modify: `linux/src/queue/terminal.rs` (`impl Serves for QueueSocket`)
- Test: `linux/tests/queue_terminal.rs`

**Interfaces:**
- Consumes: `Served`, `Serves::serve` (Task 3), `queue::Held::new` (Task 5)
- Produces: `impl Serves for QueueSocket`; `pub(crate) fn taken(incoming: Incoming) -> Taken`

- [ ] **Step 1: Написать падающий тест**

```rust
// linux/tests/queue_terminal.rs — добавить

/// Разбор входящего в исход шва — ЧИСТО, до всякого сокета. `Failed` есть ДЫРА, а не пустота:
/// ядро сказало, что пакеты потеряны, и прибор вправе это знать. Прежде фасад её печатал.
#[test]
fn переполнение_читается_дырой_а_конец_пачки_пустотой() {
    assert!(matches!(taken(Incoming::Failed(105)), Taken::Torn));
    assert!(matches!(taken(Incoming::Done), Taken::Nothing));
    assert!(matches!(taken(Incoming::Packet(a_packet())), Taken::Packet(_)));
}
```

- [ ] **Step 2: Прогнать, убедиться что падает**

Run: `cargo test -p reflex-linux --test queue_terminal переполнение_читается`
Expected: FAIL — `taken`/`Taken` не существуют.

- [ ] **Step 3: Реализовать**

```rust
// linux/src/queue/terminal.rs
/// Что даёт входящее сообщение шву. Чистая функция, отделённая от сокета: перевод сообщения в
/// исход свидетельствовало бы иначе только живое ядро, а его в тесте нет.
pub(crate) enum Taken { Packet(Packet), Torn, Nothing }

pub(crate) fn taken(incoming: Incoming) -> Taken {
    match incoming {
        Incoming::Packet(packet) => Taken::Packet(packet),
        Incoming::Failed(_errno) => Taken::Torn,
        Incoming::Done => Taken::Nothing,
    }
}
```

`QueueSocket` получает поле `pending: VecDeque<Incoming>`; `serve` снимает с него по одному, добирая `recv()` когда пусто. **Момент наблюдения штампуется при ПРИЁМЕ, не при снятии** — буферизованный пакет иначе получил бы момент позже своего прихода, и монотонность букв сломалась бы молча. Поэтому буфер хранит `(Incoming, Instant)`.

```rust
impl Serves for QueueSocket {
    fn serve<F>(&mut self, until: Instant, decide: F) -> Served<…>
    where F: FnOnce(&Held<queue::Held>) -> Answer {
        loop {
            if let Some((incoming, at)) = self.pending.pop_front() {
                match taken(incoming) {
                    Taken::Packet(packet) => {
                        let held = Held::new(queue::Held::new(packet, self.base), at);
                        let answer = decide(&held);
                        return Served::Answered(self.apply(held.answered(answer)));
                    }
                    Taken::Torn => return Served::Torn,
                    Taken::Nothing => continue,
                }
            }
            match self.wait(millis_until(until)) {
                Waited::Blind => { sleep_until(until); return Served::Blind }
                Waited::Idle => return Served::Idle,
                Waited::Ready => match self.recv() {
                    Err(_eagain) => return Served::Idle,
                    Ok(batch) => {
                        let at = Instant::now();
                        self.pending.extend(batch.into_iter().map(|one| (one, at)));
                    }
                },
            }
            if Instant::now() >= until && self.pending.is_empty() {
                return Served::Idle;
            }
        }
    }
}
```

`QueueSocket::open` снимает `TimeoutBase` и держит её полем (нужна `Held::new`).

- [ ] **Step 4: Прогнать**

Run: `cargo test -p reflex-linux && cargo build --workspace`
Expected: PASS.

- [ ] **Step 5: Мутация**

`Incoming::Failed(_) => Taken::Nothing` — тест обязан покраснеть. Вернуть.

- [ ] **Step 6: Коммит**

```bash
git add -A
git commit -m "$(cat <<'EOF'
feat(linux): очередь входит в шов — Serves на QueueSocket

Буфер пачки внутри носителя: `recv` отдаёт много, шов отдаёт по одному. Момент штампуется на
ПРИЁМЕ, не на снятии — иначе буферизованный пакет получил бы момент позже своего прихода, и
монотонность букв сломалась бы молча. Побочно честнее прежнего: пачка штамповалась одним `now`.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01UnSSqN2bGikPZC8x4EBm7G
EOF
)"
```

---

### Task 7: `IntoCarrier` — дверь отдаёт носителя, а не число

`TimeoutBase::read()` стоит в `run()` фасада, который вот-вот станет обобщённым: предпосылка conntrack в обобщённом цикле абсурдна уже сейчас.

**Files:**
- Modify: `reflex/src/lib.rs` (`Nfqueue`, `engine`, трейт)
- Test: `reflex/tests/carrier.rs` (создать)

**Interfaces:**
- Produces: `IntoCarrier { type Carrier: Serves + Edging; fn open(self) -> Result<Self::Carrier, Cause>; fn layout(&self) -> Layout; fn name(&self) -> String }`; `Cause(String)`

- [ ] **Step 1: Написать падающий тест**

```rust
// reflex/tests/carrier.rs
//! Дверь отдаёт НОСИТЕЛЯ, а не число очереди: предпосылки носителя — дело носителя.

use reflex::*;

/// Раскладка приходит от носителя, а не от цепочки: у очереди 15 наших бит среди чужих, и кто
/// делит машину с соседом, говорит это здесь.
#[test]
fn раскладка_приходит_от_носителя() {
    let default = Nfqueue::queue(200);
    assert_eq!(default.layout().mask(), 0x0FFF_E000);

    let shared = Nfqueue::queue(200).marking(0x0000_7FFF, 0b011).expect("15 бит, ненулевой тег");
    assert_eq!(shared.layout().mask(), 0x0000_7FFF);
}

/// Имя носителя — то, чем `Report` назовёт несостоявшийся запуск. Число очереди больше не
/// единственная форма: у WinDivert его нет вовсе.
#[test]
fn носитель_называет_себя_для_отчёта() {
    assert_eq!(Nfqueue::queue(200).name(), "очередь 200");
}
```

- [ ] **Step 2: Прогнать, убедиться что падает**

Run: `cargo test -p reflex --test carrier`
Expected: FAIL — методов нет.

- [ ] **Step 3: Реализовать**

```rust
// reflex/src/lib.rs
/// Причина, по которой носитель не открылся — ЗНАЧЕНИЕ, а не печать: отказ мира есть знание,
/// и `Report` его показывает, а не журнал.
pub struct Cause(pub String);

/// Рецепт носителя: что открыть и под какой раскладкой писать состояние. Дверь `engine(…)` берёт
/// именно рецепт — открытие случается в `run`, чтобы несостоявшийся запуск был ЗНАЧЕНИЕМ.
pub trait IntoCarrier {
    type Carrier: Serves + Edging;
    fn open(self) -> Result<Self::Carrier, Cause>;
    fn layout(&self) -> Layout;
    fn name(&self) -> String;
}
```

`impl IntoCarrier for Nfqueue`: `open` делает `QueueSocket::open(queue)`, затем `TimeoutBase::read()` с прежним дословным сообщением, затем `RawSender::open(INJECT_MARK)` — и складывает всё в носителя. `engine` меняет подпись на `pub fn engine<C: IntoCarrier>(carrier: C) -> Engine<C>`.

**Цена, выбранная явно:** сырой сокет поднимается всегда, даже для наблюдающей цепочки. Ленивое открытие на первом `emit` потеряло бы быстрый отказ — сегодня он на старте, стал бы на первом обрыве в бою.

- [ ] **Step 4: Прогнать**

Run: `cargo test -p reflex --test carrier && cargo build --workspace`
Expected: PASS (примеры пока не собираются — их чинит Task 8; если ломается, `--exclude` примеры до Task 8).

- [ ] **Step 5: Коммит**

```bash
git add -A
git commit -m "$(cat <<'EOF'
feat(reflex): дверь отдаёт носителя, а не число очереди (IntoCarrier)

`TimeoutBase::read()` уезжает из `run()` в `Nfqueue::open`: предпосылка носителя есть дело
носителя, и в обобщённом цикле она была бы абсурдна. `Layout` приходит оттуда же — раскладка
дома состояния свойство носителя, не цепочки.

Сырой сокет поднимается всегда: ленивое открытие потеряло бы быстрый отказ.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01UnSSqN2bGikPZC8x4EBm7G
EOF
)"
```

---

### Task 8: ведущий цикл `.on` — обобщение и переезд на шов

Самая крупная задача. Здесь умирают: дубль закона `asked`, ручной `wait`, `TICK`/`POLL_MS`/`last_tick`, `Tick { node: 0 }`, `CtEdge` в слове.

**Files:**
- Modify: `reflex/src/lib.rs` — `Wide`, `Engine`/`Watching`/`Keyed`/`Detecting`/`Folding`/`Speaking`/`Running`, `Running::run`, `Report`
- Modify: `core/src/serves.rs` — `Serves::exhausted` (со значением по умолчанию)
- Create: `reflex/tests/paper/mod.rs` — бумажный носитель
- Test: `reflex/tests/driver.rs` (создать) — **первый тест ведущего цикла в истории проекта**

**Interfaces:**
- Consumes: `IntoCarrier` (Task 7), `Serves::serve` (Task 3), `Interleave::{next_node,saw,idle,torn}` (Tasks 1-2), `Edging::edge` (Task 5)
- Produces: `Wide<W, E> = (W, Option<E>)`; `Running<C, T, F>`; `Report::not_started(name: String, why: Cause)`

- [ ] **Step 1: Написать падающий тест на бумажном носителе**

```rust
// reflex/tests/driver.rs
//! Ведущий цикл на бумажном носителе. До этого теста петля не проверялась НИЧЕМ — оба регресса
//! переезда (невидимый SYN, блокирующий recv) нашли боевые стенды, а не 873 теста.

use reflex::*;

/// Узлы сетки выходят ПЕРЕД пакетом, который их перешагнул. Прежде фасад гонял всю пачку, потом
/// смотрел тик: детектор видел пакет раньше закрытия окна, в которое пакет не попал, и относил
/// его байты не к тому окну (§8, дословно).
#[test]
fn перешагнутые_узлы_доходят_до_прибора_раньше_пакета() {
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let paper = Paper::new()
        .silent_for(secs(1))          // тишина шире шага сетки — узлы обязаны наступить
        .then_packet(client_hello_to("example.org"))
        .then_stop();

    engine(paper)
        .from(Tcp)
        .extract(Sni)
        .detect(Recorder::into(seen.clone()))   // прибор, пишущий буквы, которые ему пришли
        .on(|_target, _distress| {})
        .run();

    let letters = seen.lock().unwrap();
    let packet_at = letters.iter().position(|l| l == "packet").expect("пакет дошёл");
    let ticks_before = letters[..packet_at].iter().filter(|l| *l == "tick").count();
    assert!(ticks_before >= 4, "узлы не наступили до пакета: {letters:?}");
}

/// Дыра доходит до прибора буквой, а не печатью. Носитель объявил потерю — прибор обязан знать.
#[test]
fn дыра_доходит_до_прибора() {
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let paper = Paper::new().then_tear().then_stop();

    engine(paper).from(Tcp).extract(Sni)
        .detect(Recorder::into(seen.clone()))
        .on(|_, _| {})
        .run();

    assert!(seen.lock().unwrap().contains(&"torn".to_string()));
}

/// Памятка уезжает домой ТЕМ ЖЕ словом, что и вердикт (§5: «отпустить и запомнить» неделимо), и
/// уезжает через `Terminal::apply`, а не мимо него. Прежде фасад переписывал таблицу `asked`
/// руками — и таблица жила в двух копиях при зелёной сборке.
#[test]
fn памятка_доезжает_до_терминала_одним_словом_с_вердиктом() {
    let paper = Paper::new().then_packet(syn_to("10.0.0.1")).then_stop();
    let applied = paper.applied();       // ручка на журнал `apply`

    engine(paper).from(Tcp).extract(Sni)
        .detect(SynDrop::unreachable())
        .on(|_, _| {})
        .run();

    assert!(matches!(applied.lock().unwrap().as_slice(),
        [PaperAnswer::Remembered { accept: true, .. }]));
}
```

Бумажный носитель `Paper` живёт в `reflex/tests/paper/mod.rs` — вот его поверхность целиком:

```rust
/// Носитель-сценарий: заранее записанные шаги вместо сети. Не «мок ради теста», а НОСИТЕЛЬ с
/// линейностью владения — тот же `Serves`, что у очереди: иначе он проверял бы не тот шов.
pub struct Paper { steps: VecDeque<Step>, at: Instant, applied: Log<PaperAnswer>, injected: Log<Vec<u8>>, counts: HashMap<Flow, Counts> }

enum Step { Silence(Duration), Packet(Vec<u8>), Tear, Stop }

impl Paper {
    pub fn new() -> Paper;
    pub fn silent_for(self, how_long: Duration) -> Paper;   // двигает свои часы, работы не даёт
    pub fn then_packet(self, bytes: Vec<u8>) -> Paper;
    pub fn then_tear(self) -> Paper;                         // Served::Torn
    pub fn then_stop(self) -> Paper;                         // сценарий кончился
    pub fn applied(&self) -> Log<PaperAnswer>;               // ручка на журнал apply
    pub fn injected(&self) -> Log<Vec<u8>>;                  // ручка на журнал инъекций
}

pub enum PaperAnswer { Pass, Stop, Remembered { accept: bool, state: u32 } }

// impl: IntoCarrier (Carrier = Paper), Serves, Terminal, Edging, Observed,
//       CanHold, CanRefuse, CanRemember, CanSever, Sink, CanInject
```

**Часы у `Paper` свои, а не `Instant::now()`**: `silent_for` двигает их скачком. Иначе тест на
сетку пришлось бы гнать реальную секунду, и он стал бы медленным и хрупким — а §8 как раз
и говорит, что время есть буква входа, значит подделать его законно.

Прибор `Recorder` (пишет имена дошедших букв) живёт там же и встаёт в цепочку через
`own(…)` — публичную дверь чужой машины. Своей двери для тестов не заводим: если `own`
для этого не годится, это дефект `own`, а не повод строить вторую дверь.

- [ ] **Step 2: Прогнать, убедиться что падает**

Run: `cargo test -p reflex --test driver`
Expected: FAIL — `Paper` нет, `engine` не берёт чужого носителя.

- [ ] **Step 3: Обобщить типы и переписать цикл**

Порядок правок:
1. `pub type Wide<W, E> = (W, Option<E>);` — `CtEdge` уходит.
2. Все звенья цепочки получают параметр `C`: `Engine<C>`, `Watching<C, T>`, `Keyed<C, T>`, `Detecting<C, T>`, `Folding<C, T>`, `Speaking<C, T>`, `Running<C, T, F>`, `Acting<C, T, F>`. Поле `queue: u16` заменяется на `carrier: C` (рецепт) во всех.
3. `Running::run` переписывается:

Ядро цикла — ОДНА функция, гоняющая буквы; её зовут обе ветки (`Answered`, `Idle`/`Torn`), и
оттого «что делает буква» описано один раз, а не по разу на исход:

```rust
/// Прогнать буквы через приборы: проводные — по ключу, краевые — одним экземпляром. Возвращает
/// памятку (её кладёт домой терминал) и слова, ушедшие в реакцию. Отдельной функцией, а не телом
/// ветки: буквы приходят из ЧЕТЫРЁХ мест (пакет, тик, дыра, простой), и четыре копии разошлись бы.
fn walk<T: Transport, E: EdgeView>(
    letters: Vec<DetectorEvent<Wide<T::Wire, E>>>,
    whose: Option<(Flow, TargetKey<Box<str>>)>,
    table: &mut FlowTable<Probes<Wide<T::Wire, E>>, Flow>,
    at_edge: &mut [Box<dyn EdgeProbe<Wide<T::Wire, E>>>],
    layer: &mut Layer<Conversation, Target, Distress>,
    targets: &mut HashMap<Flow, TargetKey<Box<str>>>,
    react: &mut impl FnMut(&str, Distress),
    tape: &mut Recorded<T, E>,
    certify: bool,
) -> Option<Memo>;
```

Тело `walk` целиком переносится из нынешних строк `reflex/src/lib.rs:1120‥1215` — там уже
написано и то, как буква идёт в `table.process`, и фанаут краевых, и запись ленты, и
`layer.saw`. Меняется одно: буква приходит **готовой из шва**, а не собирается на месте, и
адрес (`To::One`/`To::Each`) выводится из `whose`, а не из ветки.

```rust
pub fn run(mut self) -> Report {
    let name = self.carrier.name();
    let layout = self.carrier.layout();
    let mut carrier = match self.carrier.open() {
        Ok(carrier) => carrier,
        Err(Cause(why)) => return Report::not_started(name, why),
    };
    let mut seam = Interleave::started(Instant::now(), TICK);
    // idle / seeds / templates / table / state / tape / targets / layer — дословно как сейчас
    loop {
        let until = seam.next_node();
        let outcome = carrier.serve(until, |held| {
            let at = held.at();
            let edge = held.carrier().edge();
            let mark = edge.as_ref().map(EdgeView::mark).unwrap_or(0);
            let memo = match T::observe(&mut state, parse::read(held.seen(), T::PORT)) {
                Some(observed) => {
                    let whose = (observed.flow, observed.key.clone());
                    let (moved, letters) = seam.saw((observed.wire, edge), at);
                    seam = moved;
                    walk::<T, _>(letters, Some(whose), &mut table, &mut at_edge, &mut layer,
                                 &mut targets, &mut self.react, &mut tape, self.certify)
                }
                // Не наш кадр — но момент его прихода СЕТКУ ДВИГАЕТ: иначе поток чужого трафика
                // выглядел бы тишиной, и приборы молчания подтверждали бы дроп на живой машине.
                None => {
                    let (moved, letters) = seam.idle(at);
                    seam = moved;
                    walk::<T, _>(letters, None, /* …то же… */)
                }
            };
            match memo {
                Some(memo) => <C::Carrier as CanRemember>::remember(memo.apply_to(mark), true),
                None => <C::Carrier as CanHold>::release(),
            }
        });
        let now = Instant::now();
        match outcome {
            Served::Answered(Ok(_)) => {}
            Served::Answered(Err(refused)) => report!("вердикт не ушёл: {:?}", refused.why),
            Served::Torn => {
                let (moved, letters) = seam.torn(now);
                seam = moved;
                walk::<T, _>(letters, None, /* …то же… */);
            }
            Served::Idle | Served::Blind => {
                let (moved, letters) = seam.idle(now);
                seam = moved;
                walk::<T, _>(letters, None, /* …то же… */);
            }
        }
        // Слово О ЦЕЛИ — там же, где было: после букв, на границе узла.
        if let Some((fold, voice)) = &mut self.about {
            for (target, said) in voiced(&mut layer, fold, idle, now) { voice(&target, said); }
        }
        if carrier.exhausted() { return Report::finished(name); }
    }
}
```

4. `TICK` остаётся константой шага СЕТКИ (не «как часто будим»); `POLL_MS`, `last_tick`, `Waited` уходят.
5. `Report { name: String, why: Option<String> }`, плюс `Report::finished(name)`.
6. Границы `Running`: `C: IntoCarrier`, `C::Carrier: CanHold + CanRemember`, `<C::Carrier as Terminal>::Refusal: std::fmt::Debug`.

**Останов цикла — способность носителя, а не флаг фасада.** `Serves` получает

```rust
    /// Больше работы не будет НИКОГДА — сценарий кончился. У живой очереди всегда `false`:
    /// ядро не обещает конца. Признак носителя, а не фасада: знает о конце тот, у кого источник.
    fn exhausted(&self) -> bool { false }
```

Значение по умолчанию — не удобство, а закон: живой носитель конца не знает, и заставлять
каждый его писать значило бы требовать ответа на вопрос, которого у него нет.

- [ ] **Step 4: Прогнать**

Run: `cargo test -p reflex --test driver -- --nocapture`
Expected: PASS, все три теста.

- [ ] **Step 5: Прогнать всё дерево и примеры**

Run: `cargo test --workspace 2>&1 | tail -10 && cargo build --workspace --examples`
Expected: PASS. Примеры не меняются ни строкой — это тест готовности фасада.

- [ ] **Step 6: Замер, обещанный потребителю**

Run:
```bash
git show HEAD~1:reflex/src/lib.rs | sed -n '/pub fn run(mut self) -> Report {/,/^    }$/p' | wc -l
sed -n '/pub fn run(mut self) -> Report {/,/^    }$/p' reflex/src/lib.rs | wc -l
grep -c reflex_linux reflex/src/lib.rs
grep -c interleave reflex/src/lib.rs
```
Expected: второе число МЕНЬШЕ первого (закон потребителя «новое связывание обязано выйти короче»); `reflex_linux` — 0; `interleave` — не 0.

- [ ] **Step 7: Мутация**

В `seam.saw` поменять порядок: пакет перед узлами — `перешагнутые_узлы_доходят_до_прибора_раньше_пакета` обязан покраснеть. Вернуть.

- [ ] **Step 8: Коммит**

```bash
git add -A
git commit -m "$(cat <<'EOF'
feat(reflex): ведущий цикл на шве — фасад перестал знать Linux (§8, §9.4, Д5)

Цикл переезжает на `Serves::serve(until, …)` + `core::interleave` + `Terminal::apply`. Умирают
разом: дубль таблицы `Answer → (accept, state)` (жила в queue/terminal.rs и переписанной копией
в фасаде), ручной `wait(POLL_MS)`, `last_tick`, `Tick { node: 0 }` — номер узла был захардкожен
нулём, то есть сетки не было вовсе.

`interleave` потреблён впервые с постройки: прежде фасад гонял пачку пакетов, ПОТОМ смотрел тик,
и пакет доходил до прибора раньше перешагнутого узла — §8 называет это причиной дословно.

Первый тест ведущего цикла в истории проекта (бумажный носитель): оба регресса переезда нашли
боевые стенды, а не 873 теста.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01UnSSqN2bGikPZC8x4EBm7G
EOF
)"
```

---

### Task 9: ведущий цикл `.act` — инжект уезжает к носителю

**Files:**
- Modify: `reflex/src/lib.rs` — `Acting::run`, `Act<C::Carrier>`
- Test: `reflex/tests/driver.rs`

**Interfaces:**
- Consumes: всё из Task 8; `emit<T: CanHold>` (`reflex/src/lib.rs:767`)
- Produces: `Acting<C, T, F>` с `F: FnMut(&str, Distress) -> Act<C::Carrier>`

- [ ] **Step 1: Написать падающий тест**

```rust
// reflex/tests/driver.rs — добавить

/// Обрыв уходит СОКЕТОМ НОСИТЕЛЯ, а не отдельным сокетом в петле: фасад про инъекцию не знает.
/// Прежде `Acting::run` открывал `RawSender` сам — то самое, что докблок `emit` объявляет изжитым.
#[test]
fn обрыв_уходит_сокетом_носителя() {
    let paper = Paper::new()
        .then_packet(retransmitted_hello_to("example.org"))
        .then_stop();
    let injected = paper.injected();

    engine(paper).from(Tcp).extract(Sni)
        .detect(Retransmit::unanswered())
        .act(|_target, _distress| Act::sever())
        .run();

    assert_eq!(injected.lock().unwrap().len(), 1, "RST не ушёл носителем");
}

/// Носитель без способности рвать акта не построит — гейт §9.1 стоит на конструкторе, и
/// обобщение он переживает без расширения.
///
/// ```compile_fail,E0599
/// use reflex::Act;
/// struct Blind;                       // носитель без CanSever
/// let _ = Act::<Blind>::sever();
/// ```
#[test]
fn гейт_способности_переживает_обобщение() {}
```

- [ ] **Step 2: Прогнать, убедиться что падает**

Run: `cargo test -p reflex --test driver обрыв_уходит`
Expected: FAIL.

- [ ] **Step 3: Реализовать**

`Acting::run` строится тем же телом, что `Running::run` (общая часть выносится в приватную функцию — один предмет, один закон), отличаясь лишь тем, что реакция возвращает `Act`, и эффекты исполняются после возврата из `serve`:

```rust
for effect in effects.drain(..) {
    match effect {
        Effect::Inject(packet) => {
            if let Err(why) = carrier.emit(<C::Carrier as CanInject>::inject(packet)) {
                report!("инъекция не ушла: {why:?}");
            }
        }
    }
}
```

`RawSender` уезжает внутрь `Nfqueue::open` и живёт полем носителя; `impl Sink + CanInject for` носителя очереди делегирует ему.

- [ ] **Step 4: Прогнать**

Run: `cargo test -p reflex && cargo build --workspace --examples`
Expected: PASS.

- [ ] **Step 5: Мутация**

Выбросить `Effect::Inject` в никуда — `обрыв_уходит_сокетом_носителя` обязан покраснеть. Вернуть.

- [ ] **Step 6: Коммит**

```bash
git add -A
git commit -m "$(cat <<'EOF'
feat(reflex): инжект — способность носителя, а не второй сокет в петле

`Acting::run` открывал `RawSender` сам, то есть фасад знал про сокет инъекции — ровно то, что
докблок `emit` объявляет изжитым. Теперь эффекты исполняет носитель, а сокет живёт у него.
Общее тело двух циклов вынесено: один предмет — один закон.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01UnSSqN2bGikPZC8x4EBm7G
EOF
)"
```

---

### Task 10: `Local<C>` — край и дом состояния в юзерспейсе

Форма, которую получит WinDivert. Один раз, а не по разу в каждом безъядерном крейте.

**Files:**
- Create: `core/src/local.rs`
- Modify: `core/src/lib.rs` (модуль)
- Test: `core/tests/local.rs` (создать)

**Interfaces:**
- Consumes: `EdgeView`, `Edging`, `Terminal`, `Serves`, `CanRemember`, `core::flow_table::FlowTable`
- Produces: `Local<C>`; `LocalEdge` (`impl EdgeView`)

- [ ] **Step 1: Написать падающий тест**

```rust
// core/tests/local.rs
//! Край в юзерспейсе: то же, что ведёт ядро, но своим счётом. Предел назван прямо — возраст
//! разговора, начавшегося ДО запуска, неизвестен, и `age()` отдаёт `None`, а не ноль.

/// Счёт ведётся в КАДРАХ — так велит закон `EdgeView` (Д6). Считай `Local` нагрузку, порог
/// «клиент отдал запрос» завысился бы на заголовок каждого пакета.
#[test]
fn местный_край_считает_кадры() {
    let mut local = Local::new(Paper::new());
    local.saw_down(a_frame_of(1500));
    local.saw_down(a_frame_of(1500));

    let edge = local.edge_of(FLOW).expect("разговор заведён");
    assert_eq!(edge.down_packets(), Some(2));
    assert_eq!(edge.down_bytes(), Some(3000));
}

/// Возраст потока, начатого до нас, неизвестен. `None`, а не ноль: ноль означал бы «только что
/// открылся», и прибор тишины подтвердил бы дроп на живом разговоре. Это предел НОСИТЕЛЯ, не закона.
#[test]
fn возраст_потока_начатого_до_нас_неизвестен() {
    let mut local = Local::new(Paper::new());
    local.saw_down(a_mid_stream_ack());     // не SYN: начала мы не видели

    assert_eq!(local.edge_of(FLOW).unwrap().age(), None);
}

/// Памятка ложится домой ТЕМ ЖЕ словом, что и вердикт, и читается обратно маркой — интерфейс тот
/// же, что у ct_mark. Куда легли 32 бита, фасад не знает и знать не должен.
#[test]
fn памятка_ложится_домой_и_читается_маркой() {
    let mut local = Local::new(Paper::new());
    local.saw_down(a_syn());
    local.apply_answer(FLOW, Local::<Paper>::remember(0xABCD, true));

    assert_eq!(local.edge_of(FLOW).unwrap().mark(), 0xABCD);
}
```

- [ ] **Step 2: Прогнать, убедиться что падает**

Run: `cargo test -p reflex-core --test local`
Expected: FAIL — модуля нет.

- [ ] **Step 3: Реализовать**

`Local<C>` — декоратор над носителем `C: Serves`:
- поле `FlowTable<Counts, Flow>` со сроком простоя;
- `Counts { down_packets, up_packets, down_bytes, up_bytes, opened: Option<Instant>, mark: u32 }`;
- `opened` заполняется только когда виден `SYN` — иначе `None`, и `age()` честно `None`;
- `impl Serves for Local<C>` — делегирует `serve`, попутно обновляя счёт и подставляя свой `Edging`;
- `impl Terminal for Local<C>` — `Answer::Remembered { state, accept }` кладёт `state` в свою карту и передаёт вниз `C`'ово слово отпускания/отказа;
- **цена названа в докблоке:** `apply` разбирает пятёрку из своего же пакета, чтобы найти ключ дома — носитель без ядерного дома платит разбором за то, что ядру даётся даром.

- [ ] **Step 4: Прогнать**

Run: `cargo test -p reflex-core --test local && cargo test --workspace 2>&1 | tail -5`
Expected: PASS.

- [ ] **Step 5: Мутация**

`opened: Some(Instant::now())` безусловно — `возраст_потока_начатого_до_нас_неизвестен` обязан покраснеть. Вернуть.

- [ ] **Step 6: Коммит**

```bash
git add -A
git commit -m "$(cat <<'EOF'
feat(core): Local — край и дом состояния в юзерспейсе, один на всех безъядерных

Форма, которую получит WinDivert: счёт по разговору вместо conntrack, карта вместо ct_mark.
Декоратор, а не носитель — иначе счёт писался бы по разу в каждом безъядерном крейте.

Цена названа: `apply` разбирает пятёрку из своего же пакета, чтобы найти ключ дома. Носитель
без ядерного дома платит разбором за то, что ядру даётся даром — вот чего стоит ct_mark.

Предел назван: возраст разговора, начатого до запуска, неизвестен (`age() == None`, не ноль).

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01UnSSqN2bGikPZC8x4EBm7G
EOF
)"
```

---

### Task 11: `Nfqueue::local` и дифференциальный стенд

Свидетель прогоном. Различие с первым носителем ровно одно — край и дом; при красном стенде причину искать негде, кроме как в нём.

**Files:**
- Modify: `reflex/src/lib.rs` (`Nfqueue::local(num)`)
- Create: `examples/detect-silent-drop/lab/edges/{compose.yml,Dockerfile,run.sh,compare.sh}`
- Modify: `examples/detect-silent-drop/lab/README.md`

**Interfaces:**
- Consumes: `Local` (Task 10), `IntoCarrier` (Task 7)
- Produces: `Nfqueue::local(num: u16) -> LocalNfqueue`

- [ ] **Step 1: Написать падающий тест**

```rust
// reflex/tests/carrier.rs — добавить

/// Носитель без ядерного учёта — законный носитель, а не костыль для теста: на машине без
/// `nf_conntrack_acct` фасад сегодня не поднимается вовсе.
#[test]
fn местная_очередь_не_требует_учёта_conntrack() {
    let local = Nfqueue::local(201);
    assert_eq!(local.name(), "очередь 201 (местный край)");
    // Вся 32-битная ячейка наша: соседей в своей карте нет.
    assert_eq!(local.layout().mask(), u32::MAX);
}
```

- [ ] **Step 2: Прогнать, убедиться что падает**

Run: `cargo test -p reflex --test carrier местная_очередь`
Expected: FAIL.

- [ ] **Step 3: Реализовать дверь**

`Nfqueue::local(num)` отдаёт рецепт, чей `open` строит `Local<QueueSocket>` и **не** зовёт `TimeoutBase::read()`. `layout()` — полная маска.

- [ ] **Step 4: Собрать дифференциальный стенд**

`examples/detect-silent-drop/lab/edges/compose.yml` поднимает два движка на одном трафике:
`engine-ct` (очередь 200) и `engine-local` (очередь 201). Правила nft ставятся ОБА в одну
цепочку, вторым `queue num 201` после первого — так один и тот же пакет проходит оба движка,
и сравниваются наблюдения о ТОМ ЖЕ трафике, а не о похожем.

```sh
# examples/detect-silent-drop/lab/edges/compare.sh
# Сверка двух краёв: множества «цель + беда» обязаны совпасть. Сравниваются МНОЖЕСТВА, не
# последовательности: порядок между двумя процессами не определён, и требовать его значило бы
# краснеть на планировщике вместо расхождения о мире.
set -eu
extract() { grep -oE '(подтверждено|подозрение)[^«]*«[^»]+»' "$1" | sort -u; }
extract "$1" > /tmp/ct.set
extract "$2" > /tmp/local.set
if diff -u /tmp/ct.set /tmp/local.set; then
  echo "совпали: $(wc -l < /tmp/ct.set) наблюдений"
else
  echo "РАСХОЖДЕНИЕ краёв — улика против закона EdgeView, а не против стенда" >&2
  exit 1
fi
```

**Порог пустоты.** Если оба множества ПУСТЫ, стенд зелёный не считается: он согласовал два
молчания. `compare.sh` обязан требовать хотя бы одно наблюдение — иначе повторится ошибка,
уже оплаченная однажды («закон был зелен на пустом окне», §10).

- [ ] **Step 5: Прогнать живьём**

Run: `sh examples/detect-silent-drop/lab/edges/run.sh`
Expected: оба движка называют одни и те же цели; `compare.sh` печатает `совпали`.

- [ ] **Step 6: Мутация (обязательна до отправки)**

В `Local` считать нагрузку вместо кадра. Прогнать стенд — обязан покраснеть расхождением (`engine-local` перестанет видеть «клиент отдал запрос»). Вернуть, прогнать снова — зелено.

- [ ] **Step 7: Коммит**

```bash
git add -A
git commit -m "$(cat <<'EOF'
feat(reflex,examples): местный край и дифференциальный стенд — два края согласны о мире

`Nfqueue::local(N)` — законный носитель для машины без `nf_conntrack_acct`, где фасад сегодня
не поднимается вовсе. Стенд гоняет оба края на ОДНОМ боевом трафике: одиночный прогон говорит
«работает», дифференциал — «два независимых края согласны».

Мутант (нагрузка вместо кадра) покраснел расхождением до отправки.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01UnSSqN2bGikPZC8x4EBm7G
EOF
)"
```

---

### Task 12: скелет WinDivert — свидетель формы

Живьём не бежит, и это сказано вслух. Его предмет — доказать, что форма годна для Windows, а не что она работает.

**Files:**
- Create: `windivert/{Cargo.toml,src/lib.rs,src/ffi.rs,src/carrier.rs}`
- Modify: `Cargo.toml` (член воркспейса с пометкой)
- Create: `examples/detect-silent-drop/src/bin/windows.rs` (цепочка под `#[cfg(windows)]`)

**Interfaces:**
- Consumes: `Serves`, `Terminal`, `Edging`, `CanHold`, `CanRefuse`, `CanInject`, `Local` (Tasks 3-10)
- Produces: `WinDivert::filter(&str) -> WinDivert` (`impl IntoCarrier`, `Carrier = Local<WinDivertHandle>`)

- [ ] **Step 1: Написать падающий тест формы**

```rust
// windivert/src/lib.rs — доктесты, проверяемые кросс-сборкой
//! Носитель WinDivert. **Живьём здесь не бежит** — свидетель ФОРМЫ: если цепочка собирается под
//! Windows, значит фасад от Linux не зависит. Что он работает, покажет только Windows.
//!
//! Линейность — ВЛАДЕНИЕ, как у очереди ядра: `WinDivertRecv` изымает пакет из стека, `Send`
//! возвращает, не послать = уронить. Оттого `Serves`, а не `Source`.
//!
//! ```no_run
//! use reflex::*;
//! use reflex_windivert::WinDivert;
//!
//! fn main() -> Report {
//!     engine(WinDivert::filter("outbound and tcp.DstPort == 443"))
//!         .from(Tcp)
//!         .extract(Sni)
//!         .detect(Retransmit::unanswered())
//!         .detect(Silence::after(secs(5)))
//!         .on(|target, distress| report!("{target}: {distress:?}"))
//!         .run()
//! }
//! ```
//!
//! Спросить WinDivert не умеет — дверь у него одна, как у очереди. `CanAsk` не заявлен, и это
//! сказано ОТСУТСТВИЕМ impl, а не константным `None` в нём:
//!
//! ```compile_fail,E0599
//! use reflex::Act;
//! use reflex_windivert::WinDivertHandle;
//! let _ = Act::<WinDivertHandle>::ask(1);
//! ```
```

- [ ] **Step 2: Прогнать кросс-проверку, убедиться что падает**

Run: `rustup target add x86_64-pc-windows-msvc && cargo check -p reflex-windivert --target x86_64-pc-windows-msvc`
Expected: FAIL — крейта нет.

- [ ] **Step 3: Написать скелет**

`ffi.rs` — `extern "system"` подписи `WinDivertOpen`/`WinDivertRecv`/`WinDivertSend`/`WinDivertClose`, `WINDIVERT_ADDRESS` как `#[repr(C)]`.
`carrier.rs` — `WinDivertHandle` (`Terminal::Carrier = Recved { packet: Vec<u8>, addr: WINDIVERT_ADDRESS }`), `impl Serves` со сроком (`WinDivertRecvEx` с таймаутом либо `WaitForSingleObject`), `impl Observed`, `CanHold` (Send обратно), `CanRefuse` (не слать), `CanInject` (тот же хэндл), `impl IntoCarrier for WinDivert { type Carrier = Local<WinDivertHandle>; }`.

Тела FFI-вызовов реальные; **заглушек `unimplemented!()` в путях, которые называет доктест, быть не должно** — иначе это не свидетель формы, а обещание.

- [ ] **Step 4: Прогнать кросс-проверку**

Run: `cargo check -p reflex-windivert --target x86_64-pc-windows-msvc 2>&1 | tail -5`
Expected: `Finished`, ноль предупреждений.

- [ ] **Step 5: Убедиться, что Linux не пострадал**

Run: `cargo test --workspace 2>&1 | tail -5`
Expected: PASS.

- [ ] **Step 6: Коммит**

```bash
git add -A
git commit -m "$(cat <<'EOF'
feat(windivert): скелет носителя — свидетель ФОРМЫ, не работы

Линейность у WinDivert та же, что у очереди ядра: Recv изымает пакет из стека, Send возвращает,
не послать = уронить. Оттого `Serves`, а не `Source` — и оттого AF_PACKET на роль свидетеля не
годился бы (копия против владения).

Живьём не бежит, и это сказано вслух. Что форма годна для Windows, показывает
`cargo check --target x86_64-pc-windows-msvc`; что она работает — покажет только Windows.

`CanAsk` не заявлен ОТСУТСТВИЕМ impl: дверь у WinDivert одна, как у очереди.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01UnSSqN2bGikPZC8x4EBm7G
EOF
)"
```

---

### Task 13: замеры приёмки и сводка

Зелёный без замера — вера, а не знание.

**Files:**
- Modify: `docs/superpowers/specs/2026-09-10-carrier-functor-design.md` (таблица замеров заполняется фактами)
- Modify: `README.md` (если дверь показана там)

- [ ] **Step 1: Прогнать все замеры и записать ФАКТЫ**

```bash
grep -c reflex_linux reflex/src/lib.rs                       # ждём 0
grep -c interleave reflex/src/lib.rs                         # ждём не 0
grep -rn 'reflex-linux' examples/*/Cargo.toml                # ждём пусто
cargo test --workspace 2>&1 | grep -E 'test result' | tail -3
cargo build --workspace 2>&1 | grep -c warning                # ждём 0
cargo check -p reflex-windivert --target x86_64-pc-windows-msvc 2>&1 | tail -1
```

- [ ] **Step 2: Прогнать все шесть боевых стендов плюс дифференциальный**

```bash
for lab in examples/*/lab/verify.sh; do echo "== $lab"; sh "$lab" || echo "КРАСНЫЙ: $lab"; done
sh examples/detect-silent-drop/lab/edges/run.sh
```
Expected: все зелены. Красный — стоп, чинить, не отправлять.

- [ ] **Step 3: Замер «связывание короче»**

```bash
git log --oneline --reverse | grep 'ведущий цикл на шве'      # найти коммит Task 8
git show <sha>~1:reflex/src/lib.rs | wc -l
wc -l reflex/src/lib.rs
```
Записать обе цифры в спеку. Если фасад ВЫРОС — форма плоха, и об этом сказать прямо, а не замолчать: закон потребителя нарушен, и это находка, а не мелочь.

- [ ] **Step 4: Заполнить таблицу замеров спеки фактами**

Заменить пороги на измеренные значения с датой прогона.

- [ ] **Step 5: Коммит**

```bash
git add -A
git commit -m "$(cat <<'EOF'
docs(spec): замеры приёмки — фактами прогона, а не порогами

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01UnSSqN2bGikPZC8x4EBm7G
EOF
)"
```

- [ ] **Step 6: Письмо хранителю канона**

Дельты Д1–Д6 (спека, §3) отправить `reflex-e1` с указанием, что КОД их уже воплотил, а канон — ещё нет, и что расхождение осознанное. Не вносить правки в `docs/vision/…` до ответа.

---

## Порядок и зависимости

```
1 (Torn) ─┬─▶ 3 (срок+Served::Torn) ─┬─▶ 6 (QueueSocket: Serves) ─┐
2 (next_node) ─────────────────────┘                              ├─▶ 8 (.on) ─▶ 9 (.act) ─▶ 10 (Local) ─▶ 11 (стенд) ─▶ 12 (WinDivert) ─▶ 13
4 (закон кадров) ──────────────────────────────────────────────────┤
5 (Edging) ────────────────────────────────────────────────────────┤
7 (IntoCarrier) ───────────────────────────────────────────────────┘
```

Задачи 1–7 независимы попарно, кроме `1 → 3` и `5 → 6`; их можно раздать параллельно. Задачи 8–13 строго последовательны.

## Чего этот план не делает

* Не сносит старый путь A/B (`nfqueue/pipeline.rs`, `NfqVerdict`, `edge_main.rs`) — он держится как независимый свидетель, снос отдельным решением rcd.
* Не трогает §10: лента как шов закрыла бы переигровку краевых приборов даром, но требует правки канона, по которому письмо у хранителя без ответа.
* Не трогает IPv6 и кросс-процессную ленту.
* Не вносит Д1–Д6 в `docs/vision/…` — гейт хранителя.
