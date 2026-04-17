# Geneva-стратегии на reflex

*Spec. 2026-04-17.*

## Контекст

Geneva (Genetic Evasion) — академический проект University of Maryland,
демонстрирующий автоматическое обнаружение стратегий обхода DPI через
генетические алгоритмы. Авторы: Kevin Bock et al.
[https://geneva.cs.umd.edu/](https://geneva.cs.umd.edu/)

Geneva определяет набор примитивов работы с пакетами, комбинирует их
в деревья действий и эволюционирует через мутацию и отбор по fitness-функции
(«соединение к заблокированному ресурсу успешно?»).

Настоящий документ описывает, как Geneva-модель реализуется как набор
стратегий на reflex, и почему reflex-архитектура устраняет ключевое
ограничение оригинальной Geneva.

## 1. Geneva: примитивы и модель

### 1.1. Примитивы (actions)

Geneva определяет четыре примитива:

| Примитив | Семантика | Модифицирует оригинал? |
|----------|-----------|----------------------|
| `duplicate` | Создать копию пакета (с возможной модификацией копии) | нет |
| `fragment` | Разрезать пакет на части (TCP segmentation / IP fragmentation) | да |
| `tamper` | Изменить поле пакета (TTL, flags, checksum, payload) | да |
| `drop` | Не отправлять пакет | да |

### 1.2. Strategy tree

Geneva-стратегия — дерево действий, применяемое к пакету при
срабатывании триггера:

```
trigger [TCP:flags:PA] -->
  duplicate(
    tamper{TCP:flags:replace:R}(send),
    fragment{tcp:8:True}(send, send)
  )
```

Читается: при PSH+ACK — создать копию, в копии заменить flags на RST
и отправить, оригинал фрагментировать на 8-байтных границах и отправить
оба фрагмента.

### 1.3. Генетический алгоритм

- **Популяция**: N деревьев стратегий
- **Мутация**: случайное добавление/удаление/замена узлов дерева
- **Crossover**: обмен поддеревьями между двумя стратегиями
- **Fitness**: попытка соединения к заблокированному ресурсу, бинарный
  результат (прошло / не прошло)
- **Отбор**: стратегии с высоким fitness выживают, остальные мутируют

### 1.4. Ключевое ограничение оригинальной Geneva

Geneva использует **внешний scaffolding** для fitness-оценки:
Python-процесс запускает curl/wget к заблокированному ресурсу,
проверяет результат, передаёт fitness обратно в генетический алгоритм.
Контур обратной связи — не встроенный в систему, а внешний.

Следствия:
- Медленная итерация (секунды на каждую оценку)
- Зависимость от внешнего приложения (браузер, curl)
- Невозможность реактивной адаптации в реальном времени
- Невозможность использования в production-контуре

## 2. Geneva на reflex

### 2.1. Примитивы как enum

```rust
enum GenevaAction {
    Duplicate {
        modify: Option<Box<GenevaAction>>,
    },
    Fragment {
        protocol: FragProtocol,  // TCP / IP
        offset: usize,
        in_order: bool,          // или disorder
    },
    Tamper {
        field: PacketField,
        operation: TamperOp,     // Replace / Add / Remove
    },
    Drop,
}

enum FragProtocol { Tcp, Ip }

enum PacketField {
    TcpFlags,
    IpTtl,
    TcpChecksum,
    TcpSeq,
    TcpAck,
    TcpWindow,
    TcpOptions,
    // расширяемо
}

enum TamperOp {
    Replace(Vec<u8>),
    Corrupt,
}
```

Стратегии — значения пользовательского типа (5-й vision, раздел 2).
Geneva-примитивы — обычный Rust enum, exhaustive match,
composability через вложенность.

### 2.2. Strategy tree как рекурсивная структура

```rust
enum StrategyNode {
    Send,
    Action {
        action: GenevaAction,
        then: Vec<StrategyNode>,  // поддеревья для каждого результата
    },
}

struct GenevaStrategy {
    trigger: Trigger,
    tree: StrategyNode,
}
```

### 2.3. Pipeline с замкнутым контуром

```rust
// Этаж 1: detect блокировку
packets.detect(block_detector)

// Этаж 2: classify
    .group_by(|s| s.domain.clone())
    .scan_state(state, accumulate_evidence)
    .map(assess)

// Этаж 3: Geneva — выбрать/мутировать стратегию, применить
    .filter_map(disruption_only)
    .with_latest_from(population_stream, |disruption, population| {
        population.select_strategy(&disruption)
    })
    .switch_map(|strategy| apply_geneva_tree(strategy))
    .inject(command_sink)

// Замыкание контура: детектор продолжает наблюдать
// Если блокировка пропала → fitness +1
// Если блокировка осталась → мутация стратегии
```

**Ключевое отличие от оригинальной Geneva**: обратная связь — не
внешний scaffolding, а тот же detector на том же pipeline. Detector
после inject продолжает наблюдать пакеты. Если RST-инъекция
прекратилась — стратегия сработала (fitness +1). Если продолжается —
стратегия провалилась (мутация).

Это **реактивная Geneva**: адаптация в реальном времени, на каждом
соединении, без внешних зависимостей.

### 2.4. Генетический алгоритм как dynamic config

Популяция стратегий — динамическая конфигурация (5-й vision,
раздел 4.3):

```rust
let population_stream: Stream<Population> = ...;
// обновляется при каждой fitness-оценке
// population.mutate() / population.crossover() / population.select()
```

`population_stream` — объект категории, композируемый через
`with_latest_from`. Генетический алгоритм работает как отдельный
реактивный поток, не как внешний процесс.

## 3. Capabilities

### 3.1. Какие capabilities нужны Geneva-примитивам

| Примитив | Capability | AF_PACKET | NFQUEUE |
|----------|-----------|-----------|---------|
| `duplicate` | `CanInject` | да | да |
| `fragment` | `CanHold` + `CanModify` | **нет** | да |
| `tamper` (копии) | `CanInject` | да | да |
| `tamper` (оригинала) | `CanModify` | **нет** | да |
| `drop` | `CanDrop` | **нет** | да |

### 3.2. Что доступно на AF_PACKET

На AF_PACKET (`CanObserve` + `CanInject`) доступно подмножество:

- `duplicate` с `tamper` на копии — инжектировать модифицированную
  копию пакета (fake packet injection). Это наш multi-disorder.
- `tamper` с TTL/checksum на копии — то же, инъекция fake с коротким
  TTL или неверной checksum.

Это покрывает значительную часть практически эффективных
Geneva-стратегий: fake packet injection с различными модификациями.

### 3.3. Что требует NFQUEUE

Для полного набора Geneva-примитивов нужен NFQUEUE backend:

- `fragment` оригинального пакета — задержать пакет, разрезать,
  отправить части
- `drop` оригинального пакета — задержать и не отправлять
- `tamper` оригинального пакета — модифицировать in-place

Реализация NFQUEUE backend — отдельная задача. Когда он будет
готов, полный набор Geneva-стратегий станет доступен без
изменения pipeline.

### 3.4. Compile-time проверка

Стратегия, использующая `fragment`, на AF_PACKET backend — ошибка
компиляции:

```rust
// AF_PACKET: CanObserve + CanInject
// fragment требует CanHold — не скомпилируется
```

Это означает что генетический алгоритм на AF_PACKET backend
автоматически ограничен подмножеством примитивов, не требующих
`CanHold`/`CanModify`/`CanDrop`. Ограничение проверяется
компилятором, не runtime.

## 4. Эволюция fitness-функции

### 4.1. Оригинальная Geneva: бинарный fitness

Geneva использует бинарный fitness: соединение прошло (1) или
нет (0). Это грубая метрика, требующая много итераций.

### 4.2. Reflex: continuous fitness

Reflex-детекторы дают **богатую** обратную связь:

- RST-детектор: TTL delta, window, timing, count
- Throttle-детектор: throughput ratio, retransmit ratio, RTT
- SilentDrop-детектор: silence duration, retransmit count

Fitness-функция может быть **градиентной**: не "работает/не работает",
а "насколько хуже стало". Это ускоряет сходимость генетического
алгоритма.

```rust
fn fitness(before: &Assessment, after: &Assessment) -> f32 {
    // не бинарно, а continuous
    // учитывает severity, confidence, timing
}
```

### 4.3. Multi-objective fitness

Reflex может оптимизировать по нескольким целям одновременно:

- **Эффективность**: блокировка обойдена?
- **Скрытность**: стратегия не вызывает аномалий, видимых ТСПУ?
- **Стоимость**: сколько дополнительных пакетов инжектировано?

Multi-objective генетические алгоритмы (NSGA-II, MOEA/D)
применимы напрямую.

## 5. Что этот документ фиксирует

- Geneva-примитивы реализуемы как enum в Rust, composability
  через вложенность
- Geneva strategy tree — рекурсивная структура данных, значение
  пользовательского типа
- Обратная связь — встроенная через reflex pipeline, не внешний
  scaffolding
- AF_PACKET покрывает `duplicate` + `tamper` (копии) —
  подмножество, достаточное для fake packet injection
- Полный набор примитивов требует NFQUEUE backend (`CanHold`,
  `CanModify`, `CanDrop`)
- Генетический алгоритм — dynamic config stream, объект категории
- Fitness может быть continuous и multi-objective

## 6. Что не фиксирует

- Конкретную реализацию генетического алгоритма
- Параметры мутации/crossover
- Размер популяции и критерии сходимости
- NFQUEUE backend (отдельная spec)
- Взаимодействие Geneva-стратегий с ручными стратегиями
  (multi-disorder, fake+TTL)
- Механизм persistence популяции между перезапусками

## 7. Следующие шаги

1. **AF_PACKET Geneva subset**: реализовать `duplicate` + `tamper`
   примитивы как стратегии на текущем backend
2. **Fitness через detector**: замкнуть контур — detector после
   inject оценивает результат
3. **Простой GA**: tournament selection + point mutation,
   популяция в памяти
4. **NFQUEUE backend**: для полного набора примитивов
5. **Benchmarks**: сравнить сходимость reflex-Geneva vs
   оригинальной Geneva на одинаковых DPI-условиях
