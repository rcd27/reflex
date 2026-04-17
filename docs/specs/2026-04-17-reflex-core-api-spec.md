# Reflex-core: API спецификация

*Spec. 2026-04-17.*

## Отношение к предыдущим документам

Настоящий документ следует за vision-документами 1–5 и
[доменной моделью](2026-04-17-reflex-domain-model-spec.md),
выведенной из use-case-driven моделирования. Он определяет
конкретный Rust API фреймворка reflex-core: трейты, сигнатуры
операторов, capabilities backend.

## 1. Фундамент: Stream

### 1.1. Решение: extension trait над futures::Stream

Reflex не вводит собственный тип потока. Объект категории
`Stream<T>` реализуется стандартным `futures::Stream`. Доменные
операторы добавляются через extension trait:

```rust
use futures::Stream;

pub trait ReflexExt: Stream + Sized {
    // операторы определены в разделах 3–4
}

impl<T: Stream + Sized> ReflexExt for T {}
```

Blanket implementation: любой `futures::Stream` автоматически
получает все reflex-операторы. Нет обёрток, нет наследования,
нет боксинга на границе.

### 1.2. Обоснование

- `futures::Stream` — де-факто стандарт async-потоков в Rust.
- Extension trait — идиоматический Rust-паттерн (как `StreamExt`,
  `IteratorExt`).
- Полная совместимость с tokio, async-stream, и всей экосистемой.
- Доменные методы `.detect()`, `.classify()`, `.inject()` доступны
  через `use reflex::ReflexExt`.

## 2. Detector

### 2.1. Трейт

```rust
pub trait Detector {
    type Input;
    type Signal;

    fn on_packet(&mut self, input: Self::Input, emit: &mut dyn FnMut(Self::Signal));
    fn on_tick(&mut self, now: Instant, emit: &mut dyn FnMut(Self::Signal));
}
```

### 2.2. Контракт

- `on_packet` — вызывается на каждый входящий элемент потока.
  Детектор обновляет internal state и вызывает `emit` ноль или
  более раз.
- `on_tick` — вызывается по таймеру от scheduler (tokio runtime).
  Для window-based (throttle) и timeout-based (blackhole, silent
  drop) детекторов.
- `emit` — callback, zero-alloc. Произвольное количество вызовов
  за один `on_packet`/`on_tick`.

### 2.3. Internal state

Детектор владеет своим state (HashMap flow-таблиц, счётчики,
окна). Кросс-flow корреляция (blackhole, silent drop) —
internal state детектора, не отдельный поток. Причина:
производительность (O(1) lookup в локальной HashMap vs
синхронизация потоков).

Это соответствует 2-му vision, раздел 2.1: «внутренняя
реактивность детектора — его личное дело».

### 2.4. Детектор пишет пользователь

Трейт `Detector` — часть фреймворка. Конкретные реализации
(`RstInjectionDetector`, `ThrottleDetector`, ...) — часть
приложения (BridgeBox), не фреймворка.

## 3. Операторы

### 3.1. Реэкспорт из futures

Стандартные операторы `futures::StreamExt`, доступные через
`ReflexExt` без изменений:

| Оператор | Сигнатура | Семантика |
|----------|-----------|-----------|
| `map` | `Stream<A> → Stream<B>` | Чистое преобразование |
| `filter` | `Stream<A> → Stream<A>` | Фильтрация по предикату |
| `filter_map` | `Stream<A> → Stream<B>` | Фильтрация + преобразование |
| `merge` | `Stream<A> × Stream<A> → Stream<A>` | Объединение потоков |
| `tap` | `Stream<A> → Stream<A>` | Наблюдение (реэкспорт `inspect`) |

Эти операторы не требуют реализации в reflex — они уже
существуют в `futures::StreamExt`. Reflex может реэкспортировать
их или полагаться на то, что пользователь импортирует
`StreamExt` наряду с `ReflexExt`.

### 3.2. Операторы reflex-core

Операторы, которых нет в `futures` и которые reflex-core
реализует:

#### detect

```rust
fn detect<D>(self, detector: D) -> impl Stream<Item = D::Signal>
where
    D: Detector<Input = Self::Item>;
```

Применяет `Detector` к каждому элементу потока. Scheduler
вызывает `on_tick` по интервалу, задаваемому детектором.
Морфизм категории: `PacketStream → SignalStream<S>`.

#### group_by

```rust
fn group_by<K, F>(self, key: F) -> GroupByStream<Self, K, F>
where
    F: FnMut(&Self::Item) -> K,
    K: Hash + Eq + Clone;
```

Разбивает поток на подпотоки по ключу. Каждый подпоток —
независимый `Stream` с элементами, имеющими одинаковый ключ.
Ключ — пользовательское решение: domain, IP, flow_id.

#### debounce

```rust
fn debounce(self, duration: Duration) -> impl Stream<Item = Self::Item>;
```

Подавляет повторные элементы в пределах временно́го окна.
Scheduler-dependent: использует `tokio::time::sleep` внутри.
В тестах с `start_paused = true` — детерминирован.

#### scan

```rust
fn scan<State, F>(self, initial: State, f: F) -> impl Stream<Item = State>
where
    F: FnMut(&mut State, Self::Item),
    State: Clone;
```

Накопление state по потоку. Как `fold`, но эмитит промежуточные
состояния. Ключевой оператор этажа 2 — накопление evidence.

#### switch_map

```rust
fn switch_map<F, S>(self, f: F) -> impl Stream<Item = S::Item>
where
    F: FnMut(Self::Item) -> S,
    S: Stream;
```

При каждом новом элементе: отменяет предыдущий inner-поток,
подписывается на новый. Атомарное переключение стратегий
без race condition. Ключевой оператор этажа 3.

#### with_latest_from

```rust
fn with_latest_from<Other, F, R>(
    self,
    other: Other,
    f: F,
) -> impl Stream<Item = R>
where
    Other: Stream,
    F: FnMut(Self::Item, &Other::Item) -> R;
```

Обогащает каждый элемент основного потока последним значением
из другого потока. Используется для dynamic config (strategy
table, domain lists).

#### inject

```rust
fn inject<F>(self, sink: F)
where
    F: FnMut(Self::Item);
```

Терминальный морфизм. Потребляет поток, передаёт каждый
элемент в sink. После `inject` цепочка заканчивается —
соответствует терминальному объекту `1` категории.

## 4. Scheduler

### 4.1. Решение: неявный через tokio runtime

Scheduler не присутствует в сигнатурах операторов. Операторы,
зависящие от времени (`debounce`, `detect` с `on_tick`),
используют `tokio::time` внутри.

Это Rust-аналог `CoroutineContext` в Kotlin: runtime живёт
неявно, оператор берёт его из thread-local. Цена: нулевая.

### 4.2. Виртуальное время для тестов

```rust
#[tokio::test(start_paused = true)]
async fn test_debounce() {
    // tokio::time::advance() продвигает время
    // все операторы детерминированы
}
```

`tokio::time::pause()` + `tokio::time::advance()` — полный
аналог `TestScheduler` из RxJava / `runTest` из Kotlin
coroutines. Код операторов не меняется между production и
тестами.

## 5. Backend capabilities

### 5.1. Маркерные трейты

```rust
pub trait CanObserve {}
pub trait CanInject {}
pub trait CanHold {}
pub trait CanModify {}
pub trait CanDrop {}
```

Каждая capability — пустой маркерный трейт. Backend реализует
те, которые поддерживает.

### 5.2. Перечень capabilities

| Capability | Семантика | AF_PACKET | NFQUEUE | WinDivert | Sim |
|------------|-----------|-----------|---------|-----------|-----|
| `CanObserve` | Чтение копии пакета без вмешательства | да | да | да | да |
| `CanInject` | Отправка нового пакета в сеть | да | да | да | нет |
| `CanHold` | Задержка пакета до вердикта | нет | да | да | нет |
| `CanModify` | Модификация пакета in-place | нет | да | да | нет |
| `CanDrop` | Отбрасывание пакета | нет | да | да | нет |

5 capabilities выведены из анализа backend-семантик (3-й vision,
раздел 3.4) и подтверждены моделированием: все 5 use-case
BridgeBox работают на `CanObserve` + `CanInject`.

### 5.3. Backend трейт

```rust
pub trait Backend: CanObserve {
    type Packet;

    fn packets(&self) -> impl Stream<Item = Self::Packet>;
}

pub trait InjectBackend: Backend + CanInject {
    fn inject_packet(&self, packet: Self::Packet);
}
```

Минимальный backend — `CanObserve` (может читать пакеты).
`CanInject` — расширение для backend'ов, способных отправлять.

### 5.4. Backend реализации

```rust
// AF_PACKET — наблюдение + инъекция
pub struct AfPacketBackend { /* ... */ }
impl CanObserve for AfPacketBackend {}
impl CanInject for AfPacketBackend {}
impl Backend for AfPacketBackend { /* ... */ }
impl InjectBackend for AfPacketBackend { /* ... */ }

// Simulation — только наблюдение (pcap replay)
pub struct SimBackend { /* ... */ }
impl CanObserve for SimBackend {}
impl Backend for SimBackend { /* ... */ }
// НЕ impl CanInject — inject() не скомпилируется

// NFQUEUE — все capabilities
pub struct NfqueueBackend { /* ... */ }
impl CanObserve for NfqueueBackend {}
impl CanInject for NfqueueBackend {}
impl CanHold for NfqueueBackend {}
impl CanModify for NfqueueBackend {}
impl CanDrop for NfqueueBackend {}
impl Backend for NfqueueBackend { /* ... */ }
impl InjectBackend for NfqueueBackend { /* ... */ }
```

### 5.5. Compile-time проверка

Попытка вызвать `inject()` с `SimBackend`:

```rust
fn run<B: Backend>(backend: B) {
    backend.packets()
        .detect(my_detector)
        .inject(|cmd| backend.inject_packet(cmd));
        //                    ^^^^^^^^^^^^^^^^
        // ERROR: SimBackend does not implement CanInject
}
```

Ошибка компиляции. Ни runtime-паники, ни fallback. Ровно как
в 4-м vision: «некомпилируемая цепочка — единственно допустимое
поведение при несовместимости».

## 6. Структура crate

```
reflex/
├── reflex-core/        ← ReflexExt, Detector, operators, capabilities
├── reflex-linux/       ← AfPacketBackend, NfqueueBackend
├── reflex-sim/         ← SimBackend (pcap replay)
├── reflex-win/         ← WinDivertBackend (перспективный)
└── reflex-mac/         ← BpfBackend (перспективный)
```

`reflex-core` не зависит от платформы. Backend-crate реализуют
capabilities для конкретных платформ.

## 7. Полный пример: RST-детектор на reflex

```rust
use reflex_core::{ReflexExt, Detector, Backend, InjectBackend};
use reflex_linux::AfPacketBackend;

struct RstDetector { /* internal state */ }

impl Detector for RstDetector {
    type Input = Packet;
    type Signal = RstInjectionSignal;

    fn on_packet(&mut self, pkt: Packet, emit: &mut dyn FnMut(Self::Signal)) {
        // парсинг, state update, emit при обнаружении RST-аномалии
    }

    fn on_tick(&mut self, now: Instant, emit: &mut dyn FnMut(Self::Signal)) {
        // cleanup старых flow
    }
}

async fn run(backend: AfPacketBackend, strategy_table: StrategyTable) {
    backend.packets()
        // Этаж 1
        .detect(RstDetector::new())

        // Этаж 2
        .group_by(|s| s.domain.clone())
        .debounce(Duration::from_secs(5))
        .scan(AssessmentState::new(), |state, signal| state.update(signal))
        .map(|state| state.assess())

        // Этаж 3
        .filter_map(|a| a.disruption())
        .with_latest_from(strategy_table.stream(), |disruption, table| {
            table.select_strategy(&disruption)
        })
        .switch_map(|strategy| strategy.materialize())
        .inject(|cmd| backend.inject_packet(cmd.into()));
}
```

## 8. Что этот документ не определяет

- Конкретные типы `Packet` (зависит от backend)
- Конкретные реализации детекторов (пользовательский код)
- Интервал `on_tick` (конфигурация детектора)
- Формат сериализации для межпроцессного транспорта
- Диагностические сообщения компилятора при ошибках capabilities
- Hold/Modify/Drop операторы (будут добавлены при реализации
  NFQUEUE backend)

## 9. Следующие шаги

1. **Прототип reflex-core** — минимальная реализация ReflexExt
   с `detect`, `debounce`, `switch_map`.
2. **reflex-linux (AF_PACKET)** — первый backend.
3. **reflex-sim** — pcap-replay backend для тестов.
4. **RST-детектор** — первое приложение на reflex.
