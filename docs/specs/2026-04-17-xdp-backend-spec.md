# Reflex: XDP + AF_PACKET backend

*Spec. 2026-04-17.*

## Мотивация

Geneva требует 5 примитивов: `duplicate`, `tamper` (копии),
`tamper` (оригинала), `fragment`, `drop`. AF_PACKET backend
покрывает первые два. Для полного набора нужен механизм
перехвата оригинального пакета до bridge forwarding.

NFQUEUE — традиционное решение, но оно:
- требует `br_netfilter` (хрупко, ломает прозрачность L2 bridge)
- добавляет ~100μs latency (userspace round-trip на каждый пакет)
- ограничено throughput NFQUEUE capacity

XDP (eXpress Data Path) — eBPF программа на входе интерфейса,
до сетевого стека. Решение в single pass, latency ~1-5μs,
line-rate throughput, нативно совместимо с bridge.

## 1. Архитектура: два слоя

### 1.1. XDP слой (eBPF, в ядре)

eBPF программа, загружаемая на сетевой интерфейс. Работает
synchronously на каждом входящем пакете. Принимает одно из
решений:

| Verdict | Семантика |
|---------|-----------|
| `XDP_PASS` | Пропустить пакет в сетевой стек (bridge forwarding) |
| `XDP_DROP` | Уничтожить пакет |
| `XDP_TX` | Отправить (модифицированный) пакет обратно в тот же интерфейс |
| `XDP_REDIRECT` | Перенаправить пакет на другой интерфейс |

XDP программа **не принимает сложных решений**. Она:
- Классифицирует пакет по простым критериям (TCP port 443,
  TLS ClientHello signature)
- Если пакет не интересен → `XDP_PASS`
- Если интересен → копирует в userspace через perf event ring
  buffer, затем `XDP_DROP` или `XDP_PASS` (по флагу из
  userspace BPF map)

### 1.2. Userspace слой (Rust, reflex pipeline)

Получает копии интересных пакетов через perf ring buffer.
Применяет Geneva strategy tree. Инжектирует результат через
AF_PACKET.

### 1.3. Координация

Userspace управляет поведением XDP через BPF maps:

```
BPF map: "action_table"
  key: flow 5-tuple hash
  value: { action: PASS | DROP | REDIRECT_TO_USERSPACE }
```

По умолчанию: `XDP_PASS` (прозрачный мост). Когда reflex
pipeline решает что для конкретного flow нужен Geneva —
записывает в action_table `DROP` (или `REDIRECT`). XDP
программа при следующем пакете этого flow дропнет его, а
userspace инжектирует модифицированную версию.

## 2. Реализация Geneva primitives

| Примитив | Реализация |
|----------|-----------|
| `duplicate` | AF_PACKET inject копии. XDP не участвует. |
| `tamper` (копии) | AF_PACKET inject модифицированной копии. XDP не участвует. |
| `tamper` (оригинала) | XDP modify packet buffer + `XDP_PASS`. Ограничено простыми модификациями (TTL, flags, checksum). |
| `fragment` | XDP `XDP_DROP` оригинал. Userspace через AF_PACKET inject фрагменты. |
| `drop` | XDP `XDP_DROP`. |

### 2.1. fragment через XDP_DROP + re-inject

Сценарий: Geneva strategy tree говорит "фрагментировать
ClientHello на 3 части в disorder-порядке".

1. Userspace записывает в action_table: flow X → DROP
2. Клиент отправляет ClientHello
3. XDP видит ClientHello, flow X → DROP. Копирует пакет в
   perf ring, дропает оригинал.
4. Userspace получает копию, разрезает на 3 фрагмента,
   переупорядочивает, инжектирует через AF_PACKET.
5. Фрагменты идут к серверу — сервер собирает.
   ТСПУ видит фрагменты в disorder — не может собрать SNI.

### 2.2. tamper оригинала через XDP modify

Сценарий: Geneva strategy tree говорит "заменить TTL на 1
в оригинальном пакете".

Два варианта:
- **Простые модификации** (TTL, flags, checksum) — XDP
  модифицирует packet buffer in-place, `XDP_PASS`. Быстро,
  zero-copy.
- **Сложные модификации** (изменение длины пакета, вставка
  TCP options) — XDP `XDP_DROP` + userspace re-inject
  модифицированной версии. Медленнее, но универсально.

## 3. Frontend не меняется

### 3.1. Принцип непрозрачности (4-й vision)

**Frontend pipeline идентичен для AF_PACKET и XDP backend.**
Пользователь пишет:

```rust
packets
    .detect(detector)
    .map(assess)
    .switch_map(|a| materialize(a))
    .inject(sink);
```

Разница — в том что `inject(sink)` на XDP backend может
выполнять `fragment` и `drop`, а на AF_PACKET — не может.
Это проверяется compile-time через capabilities.

### 3.2. Никаких XDP-специфичных типов в pipeline

В pipeline **нет** типов `XdpVerdict`, `BpfMap`, `PerfEvent`.
Это backend-детали. Пользователь работает с `Command::Fragment`,
`Command::Drop` — доменными командами. Backend транслирует их
в XDP verdicts.

### 3.3. Capabilities

```rust
pub struct XdpAfPacketBackend { /* ... */ }

impl CanObserve for XdpAfPacketBackend {}  // perf ring + AF_PACKET
impl CanInject for XdpAfPacketBackend {}   // AF_PACKET sendto
impl CanDrop for XdpAfPacketBackend {}     // XDP_DROP
impl CanModify for XdpAfPacketBackend {}   // XDP modify or DROP+re-inject

// CanHold — НЕ реализован. XDP synchronous, не буферизирует.
```

### 3.4. Что CanHold означает и почему не нужен

`CanHold` = "задержать пакет, дождаться решения userspace,
потом forward или drop". Это NFQUEUE-семантика.

Для Geneva `CanHold` не нужен:
- `fragment` = DROP + re-inject (не hold)
- `tamper` = modify in-place или DROP + re-inject (не hold)
- `drop` = DROP (мгновенно, не hold)

`CanHold` нужен только если стратегия требует: "подождать
результат другого события прежде чем решить что делать с этим
пакетом". Geneva так не работает — решение принимается на
основе trigger, не на основе будущих событий.

## 4. Структура crate

```
reflex/
├── core/               ← без изменений
├── linux/
│   ├── src/
│   │   ├── capture.rs  ← AF_PACKET capture (без изменений)
│   │   ├── inject.rs   ← AF_PACKET inject (без изменений)
│   │   ├── xdp.rs      ← XDP program loader + BPF map management
│   │   └── lib.rs      ← AfPacketBackend + XdpAfPacketBackend
│   └── bpf/
│       └── xdp_classifier.c  ← eBPF program (C, compiled to BPF bytecode)
```

XDP backend живёт в том же `linux/` crate, потому что это
Linux-специфичный код. Два backend в одном crate:

- `AfPacketBackend` — `CanObserve` + `CanInject`
- `XdpAfPacketBackend` — `CanObserve` + `CanInject` + `CanDrop` + `CanModify`

## 5. eBPF программа

### 5.1. Минимальная XDP программа

```c
// xdp_classifier.c — загружается на eth0/eth1

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);    // flow hash
    __type(value, __u8);   // action: 0=PASS, 1=DROP, 2=COPY+DROP
} action_table SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} events SEC(".maps");

SEC("xdp")
int xdp_classify(struct xdp_md *ctx) {
    // 1. parse ethernet + IP + TCP headers
    // 2. compute flow hash from 5-tuple
    // 3. lookup flow hash in action_table
    //    - not found → XDP_PASS
    //    - PASS → XDP_PASS
    //    - DROP → XDP_DROP
    //    - COPY+DROP → copy to perf event ring, XDP_DROP
    // 4. for non-classified TCP:443 packets, always copy
    //    to perf ring (for detector observation) + XDP_PASS
}
```

### 5.2. Rust userspace: BPF map management

```rust
impl XdpAfPacketBackend {
    fn set_flow_action(&self, flow_hash: u32, action: FlowAction);
    fn clear_flow_action(&self, flow_hash: u32);
}

enum FlowAction {
    Pass,
    Drop,
    CopyAndDrop,
}
```

### 5.3. Зависимости

- `libbpf-rs` — Rust bindings for libbpf (load eBPF programs)
- `aya` — альтернатива, pure Rust BPF loader

Выбор между `libbpf-rs` и `aya` — инженерное решение при
реализации. `aya` предпочтительнее (pure Rust, no C
dependencies), но `libbpf-rs` более зрелый.

## 6. Ограничения

### 6.1. XDP hardware offload

XDP может работать в трёх режимах:
- **Generic** — в ядре, после driver. Всегда доступен.
- **Native** — в driver, до kernel network stack. Быстрее.
  Требует поддержки driver.
- **Hardware** — на сетевой карте (SmartNIC). Самый быстрый.
  Требует поддержки hardware.

NanoPi R2S/R3S (rockchip ethernet) — скорее всего только
generic mode. Это всё равно быстрее NFQUEUE, но не line-rate.
Для домашнего канала (100Mbps-1Gbps) достаточно.

### 6.2. Timing: XDP_DROP + re-inject

Между `XDP_DROP` оригинала и AF_PACKET inject фрагментов
есть задержка (userspace round-trip, ~10-100μs). Сервер не
видит пакет в этот период. Для TCP это не проблема —
retransmit timeout >> 100μs. Но порядок пакетов может
нарушиться если клиент шлёт следующий пакет быстрее чем
userspace успевает re-inject.

Mitigation: записывать в action_table `DROP` **заранее**
(при виде SYN к blocked domain), до ClientHello. Тогда
к моменту ClientHello XDP уже знает что дропать.

### 6.3. eBPF verifier

eBPF программы проверяются ядерным verifier при загрузке.
Verifier ограничивает: нет циклов (кроме bounded), нет
произвольного доступа к памяти, ограниченный размер стека.
Это означает что XDP программа должна быть простой —
классификация, не логика стратегии. Вся логика — в userspace.

## 7. Что этот документ фиксирует

- XDP + AF_PACKET покрывает все 5 Geneva primitives
- Frontend pipeline не меняется (непрозрачность backend)
- XDP backend — два новых capability: `CanDrop`, `CanModify`
- `CanHold` не нужен для Geneva
- Координация через BPF maps (action_table)
- eBPF программа минимальна — классификация, не логика
- Живёт в `linux/` crate рядом с AF_PACKET backend

## 8. Что не фиксирует

- Выбор `aya` vs `libbpf-rs`
- Конкретный BPF map layout
- Стратегию preemptive DROP (записывать action при SYN)
- Тестирование eBPF программы (BPF test framework)
- Поддержка XDP native mode на конкретном hardware

## 9. Следующие шаги

1. **PoC**: минимальная XDP программа (generic mode) +
   загрузка через aya + BPF map management
2. **fragment через DROP + re-inject** в testbed
3. **Geneva с полным набором primitives** на XDP backend
4. **Benchmarks**: XDP vs NFQUEUE latency на R2S
