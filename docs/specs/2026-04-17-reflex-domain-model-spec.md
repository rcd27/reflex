# Reflex: доменная модель — результат use-case-driven моделирования

*Spec. 2026-04-17.*

## Отношение к vision-документам

Настоящий документ является первой спецификацией, выведенной из
vision-документов 1–5 методом use-case-driven моделирования. Пять
конкретных use-case (RST-инъекция, throttling, DNS-подмена,
IP blackhole, silent drop) были промоделированы end-to-end через
три этажа композиции (детекция → классификация → реакция).

Результат: структура pipeline **не менялась** между кейсами.
Отличаются только пользовательские типы `T` и логика внутри
пользовательских функций. Это подтверждает жизнеспособность
reflex как generic-фреймворка сетевой реактивности.

## 1. Архитектура pipeline

### 1.1. Три этажа

Pipeline reflex состоит из трёх этажей, каждый со своей
ответственностью:

- **Этаж 1 — детекция.** Ответственность: *что считать сигналом*.
  `PacketStream → Signal<T>`. Детектор наблюдает пакетный поток,
  ведёт internal state, эмитит типизированные сигналы.

- **Этаж 2 — классификация.** Ответственность: *что сигнал означает*.
  `Signal<T> → Assessment`. Группировка, debounce, накопление
  evidence, вынесение вердикта.

- **Этаж 3 — реакция.** Ответственность: *что в ответ сделать*.
  `Assessment → Strategy → Command → 1`. Выбор стратегии,
  материализация в команды, отправка инъектору.

### 1.2. Canonical pipeline

```
// Этаж 1
packets.detect(detector)

// Этаж 2
    .group_by(|s| key(s))
    .debounce(debounce_window)
    .scan(state, accumulate)
    .map(assess)

// Этаж 3
    .filter_map(disruption_only)
    .with_latest_from(strategy_table)
    .map(select_strategy)
    .switch_map(materialize)
    .inject(command_sink)
```

Эта структура **идентична** для всех пяти промоделированных
use-case. Конкретные типы и функции (`detector`, `key`,
`accumulate`, `assess`, `select_strategy`, `materialize`) —
пользовательский код, не часть фреймворка.

## 2. Граница фреймворк / приложение

### 2.1. Фреймворк (reflex-core)

Типы и операторы, предоставляемые фреймворком:

| Артефакт | Вид | Семантика |
|----------|-----|-----------|
| `Stream<T>` | тип | Типизированный поток значений — объект категории |
| `detect` | оператор | `PacketStream → Signal<T>` — stateful детекция |
| `group_by` | оператор | Разбиение потока по ключу |
| `debounce` | оператор | Подавление повторов за временно́е окно |
| `scan` | оператор | Накопление state по потоку |
| `map` | оператор | Чистое преобразование |
| `filter_map` | оператор | Фильтрация с преобразованием |
| `with_latest_from` | оператор | Обогащение последним значением другого потока |
| `switch_map` | оператор | Переключение на новый inner-поток при каждом элементе |
| `inject` | оператор | Терминальный морфизм — отправка в сеть |
| `tap` | оператор | Ответвление наблюдателя без изменения потока |
| `merge` | оператор | Объединение нескольких потоков |

Scheduler — контекст исполнения, предоставляемый фреймворком:
production (монотонные часы) и test (виртуальное время).

### 2.2. Приложение (BridgeBox)

Конкретные типы и функции, которые пишет пользователь фреймворка:

| Артефакт | Вид | Пример |
|----------|-----|--------|
| `Signal<T>` конкретные `T` | тип | `RstInjectionSignal`, `ThrottleSignal`, ... |
| `Assessment` | тип | `Disruption { kind, ... }` / `Normal` / `Inconclusive` |
| `Strategy` | тип (enum) | `Desync` / `Tunnel` / `DesyncThenTunnel` / `SecureDns` |
| `Command` | тип (enum) | `InjectFakePacket` / `RedirectToTunnel` / ... |
| `detector` | функция | Логика детекции конкретного паттерна |
| `assess` | функция | Логика классификации |
| `select_strategy` | функция | Логика выбора стратегии |
| `materialize` | функция | Преобразование стратегии в поток команд |

## 3. Типы сигналов: результат моделирования

Пять промоделированных детекторов и свойства их сигналов:

### 3.1. RstInjectionSignal

Паттерн: ТСПУ инжектирует TCP RST после ClientHello с запрещённым SNI.

```
RstInjectionSignal {
    flow_id: FiveTuple,
    domain: String,                 // SNI из ClientHello
    timestamp: Instant,
    time_since_hello: Duration,
    rtt_estimate: Option<Duration>,

    // улики из RST-пакета
    rst_ttl: u8,
    rst_ip_id: u16,
    rst_seq: u32,
    rst_tcp_flags: TcpFlags,
    rst_window: u16,
    rst_has_tcp_options: bool,
    rst_has_timestamps: bool,
    rst_ip_tos: u8,

    // baseline сервера (из SYN+ACK)
    server_ttl: u8,
    server_tcp_options: TcpOptionsSummary,

    // паттерн
    ttl_delta: i16,
    rst_count: u8,
    rst_directions: RstDirection,
    server_hello_received: bool,

    // TLS контекст
    tls_version: TlsVersion,
}
```

Trigger: событие (аномальный пакет). Scheduler: опционален.
Кросс-flow: нет. Группировка: по domain.

### 3.2. ThrottleSignal

Паттерн: ТСПУ замедляет поток через дроп ACK или data-пакетов.
Классический кейс — YouTube.

```
ThrottleSignal {
    flow_id: FiveTuple,
    domain: String,

    // окно наблюдения
    window_start: Instant,
    window_duration: Duration,

    // throughput
    bytes_server_to_client: u64,
    bytes_client_to_server: u64,
    throughput_drop_ratio: f32,

    // ACK-анализ
    acks_sent_by_client: u32,
    acks_received_by_server: u32,
    ack_loss_ratio: f32,

    // retransmit
    retransmit_count: u32,
    retransmit_ratio: f32,

    // RTT-деградация
    rtt_initial: Duration,
    rtt_current: Duration,
    rtt_ratio: f32,

    // паттерн деградации
    degradation_onset: Option<Instant>,
    time_to_degradation: Option<Duration>,

    // baseline
    peak_throughput: u64,
    current_throughput: u64,
}
```

Trigger: окно (статистика за период). Scheduler: обязателен.
Кросс-flow: нет. Группировка: по domain.

### 3.3. DnsSpoofSignal

Паттерн: ТСПУ инжектирует поддельный DNS-ответ быстрее настоящего.

```
DnsSpoofSignal {
    flow_id: FiveTuple,
    domain: String,
    query_type: DnsQueryType,
    transaction_id: u16,
    timestamp: Instant,
    time_since_query: Duration,
    rtt_estimate: Option<Duration>,

    // поддельный ответ
    spoofed_ip: IpAddr,
    spoofed_ttl_dns: u32,
    spoofed_ip_ttl: u8,
    spoofed_response_flags: DnsFlags,
    spoofed_answer_count: u16,

    // настоящий ответ
    real_response_seen: bool,
    real_ip: Option<IpAddr>,
    real_ip_ttl: Option<u8>,
    real_response_delay: Option<Duration>,

    // улики
    ip_ttl_delta: Option<i16>,
    duplicate_response: bool,
    spoofed_ip_is_known_blockpage: bool,
    response_before_plausible_rtt: bool,

    // контекст
    dns_server_ip: IpAddr,
    dns_protocol: DnsProtocol,
}
```

Trigger: событие + короткий state (query → response корреляция).
Scheduler: нужен (таймаут второго ответа). Кросс-flow: нет.
Группировка: по domain.

### 3.4. IpBlackholeSignal

Паттерн: SYN-пакеты дропаются на маршруте (BGP blackhole / Eco Highway).
TCP handshake не проходит.

```
IpBlackholeSignal {
    flow_id: FiveTuple,
    dst_ip: IpAddr,
    dst_port: u16,
    domain: Option<String>,

    // SYN-паттерн
    syn_count: u32,
    syn_first_ts: Instant,
    syn_last_ts: Instant,
    syn_retransmit_intervals: Vec<Duration>,
    total_wait: Duration,

    // что НЕ пришло
    syn_ack_received: bool,
    any_response_received: bool,
    icmp_unreachable_received: bool,
    icmp_type: Option<u8>,

    // кросс-flow корреляция (internal state детектора)
    other_flows_to_same_ip: u32,
    other_flows_to_same_subnet: u32,
    dst_ip_previously_reachable: bool,
    time_since_last_success: Option<Duration>,

    // AS/IP контекст
    dst_ip_is_known_blocked_range: bool,

    // DNS-корреляция
    dns_resolved_ips: Vec<IpAddr>,
    all_resolved_ips_blackholed: bool,
}
```

Trigger: отсутствие ответа (timeout-based). Scheduler: обязателен.
Кросс-flow: да (internal state). Группировка: по IP.

### 3.5. SilentDropSignal

Паттерн: TCP handshake проходит, но после ClientHello — тишина.
ТСПУ дропает после классификации SNI.

```
SilentDropSignal {
    flow_id: FiveTuple,
    dst_ip: IpAddr,
    dst_port: u16,
    domain: String,

    // handshake прошёл
    syn_ack_received: bool,
    handshake_rtt: Duration,

    // момент обрыва
    last_client_payload_ts: Instant,
    silence_duration: Duration,

    // retransmit-паттерн
    client_hello_retransmits: u32,
    retransmit_intervals: Vec<Duration>,

    // что НЕ пришло
    server_hello_received: bool,
    any_server_data_after_hello: bool,
    server_acks_after_hello: u32,

    // TLS контекст
    tls_version: u16,
    client_hello_size: u16,

    // кросс-flow корреляция (internal state детектора)
    other_flows_to_same_ip_ok: bool,
    same_domain_other_ip_ok: bool,
    server_was_reachable_before: bool,

    // drop-паттерн
    drop_is_bidirectional: bool,
    server_sees_client_hello: bool,
}
```

Trigger: отсутствие ответа после успешного handshake.
Scheduler: обязателен. Кросс-flow: да (internal state).
Группировка: по domain.

## 4. Сводная таблица свойств детекторов

| Свойство | RST | Throttle | DNS | Blackhole | SilentDrop |
|----------|-----|----------|-----|-----------|------------|
| Trigger | пакет | окно | пакет+state | отсутствие | отсутствие после handshake |
| Scheduler | опционален | обязателен | нужен | обязателен | обязателен |
| Группировка | domain | domain | domain | IP | domain |
| Кросс-flow state | нет | нет | нет | да | да |
| Desync применим | да | да | нет | нет | да |
| Tunnel применим | да | да | да | да | да |

## 5. Стратегии (уровень приложения)

```
enum Strategy {
    Desync { method: DesyncMethod },
    Tunnel,
    DesyncThenTunnel { timeout: Duration },
    SecureDns { protocol: SecureDnsProtocol },
    AlternativeIp,
}
```

Стратегии — обычные значения пользовательского типа (5-й vision,
раздел 2). Composability — через enum/ADT в пользовательском коде.
Фреймворк не знает о стратегиях; он предоставляет операторы для
их передачи и переключения в потоке.

## 6. Архитектурные выводы, подтверждённые моделированием

### 6.1. Pipeline universal

Структура трёх этажей **идентична** для всех пяти use-case.
Операторы фреймворка не менялись. Это подтверждает
жизнеспособность reflex как generic-библиотеки: фреймворк
предоставляет структуру, приложение наполняет её доменной логикой.

### 6.2. Scheduler — контекст, не измерение

4 из 5 детекторов используют scheduler (таймеры, окна, таймауты).
Решение A1 из 5-го vision (время — контекст через scheduler)
подтверждено практикой моделирования.

### 6.3. Кросс-flow — internal state детектора

Blackhole и SilentDrop требуют данных о соседних потоках. Эти
данные — internal state детектора (`HashMap` в памяти процесса),
не отдельный поток. Причина: производительность. В сетевом стеке
lookup в локальной HashMap за O(1) критически быстрее
синхронизации двух потоков через `with_latest_from`.

Это соответствует 2-му vision, раздел 2.1: «внутренняя
реактивность детектора — его личное дело».

### 6.4. Стратегии переиспользуются

`Desync`, `Tunnel`, `DesyncThenTunnel` применимы к нескольким типам
disruption. Стратегии — значения, не привязанные к конкретному
детектору. Это подтверждает решение B1 из 5-го vision.

### 6.5. Обратная связь замыкается естественно

После применения стратегии детекторы продолжают наблюдать. Если
disruption сохраняется — assessment обновляется, confidence растёт,
стратегия эскалируется. Контур обратной связи из 1-го vision
реализуется штатными средствами pipeline без специальных механизмов.

## 7. Что этот документ не определяет

- Конкретный Rust API (трейты, сигнатуры методов)
- Конкретные capabilities backend
- Конкретную модель ошибок в Assessment
- Транспорт между компонентами
- Нейминг типов (рабочие имена, финализация при написании кода)

Эти вопросы — предмет следующих спецификаций.

## 8. Следующие шаги

1. **Spec: reflex-core API** — трейты, сигнатуры операторов,
   trait bounds для capabilities.
2. **Spec: backend AF_PACKET** — первый backend, capabilities,
   отображение frontend-операторов.
3. **Прототип** — минимальная реализация RST-детектора на
   reflex-core + AF_PACKET backend.
