# Reflex: TC-BPF вместо XDP — amendment к backend spec

*Amendment. 2026-04-17.*

## Проблема

XDP hook на bridge работает **до** AF_PACKET capture. Пакет,
дропнутый XDP, не виден AF_PACKET. Geneva не получает
ClientHello signal и не может построить fakes.

Обнаружено при live тестировании: XDP загружается на br0,
BPF map обновляется, но Geneva не видит ClientHello — signal
не эмитится.

## Решение: TC-BPF

TC (traffic control) hook работает **после** AF_PACKET и
**после** bridge forwarding:

```
client → veth-cl-br → br0
  AF_PACKET видит пакет (Geneva читает ClientHello) ← ТУТ
  → tc-egress на veth-rt-br
  TC-BPF дропает оригинал ← ТУТ
  → (оригинал не доходит до router → не доходит до ТСПУ)

Geneva inject fakes через AF_PACKET на br0
  → fakes идут через bridge → veth-rt-br
  → TC-BPF НЕ дропает fakes (другой flow hash или whitelist)
  → fakes доходят до router → до ТСПУ

Geneva re-inject оригинал через AF_PACKET
  → оригинал идёт ПОСЛЕ fakes
  → ТСПУ видит: fakes → real ClientHello
```

## Порядок hook-ов (подтверждённый)

```
Ingress (пакет от клиента):
  1. AF_PACKET (наблюдение) — видит копию
  2. Bridge forwarding — пакет идёт от veth-cl-br к veth-rt-br
  3. TC egress на veth-rt-br — TC-BPF решает: drop или pass
  4. Пакет уходит к router (если pass)

AF_PACKET inject:
  → пакет вставляется на уровне link layer
  → проходит bridge forwarding
  → TC egress: проходит (whitelist по IP ID или другому маркеру)
```

## Что меняется в backend

### Было (XDP)
```rust
pub struct XdpAfPacketBackend {
    capture: Capture,      // AF_PACKET на br0
    injector: Injector,    // AF_PACKET sendto на br0
    xdp: XdpProgram,       // XDP на br0
}
```

### Стало (TC-BPF)
```rust
pub struct TcAfPacketBackend {
    capture: Capture,      // AF_PACKET на br0 (без изменений)
    injector: Injector,    // AF_PACKET sendto на br0 (без изменений)
    tc: TcProgram,         // TC-BPF на veth-rt-br (egress)
}
```

### Capabilities — те же
```rust
impl CanObserve for TcAfPacketBackend {}
impl CanInject for TcAfPacketBackend {}
impl CanDrop for TcAfPacketBackend {}
impl CanModify for TcAfPacketBackend {}
```

## eBPF программа

TC-BPF программа структурно идентична XDP, но:
- Аннотация `#[classifier]` вместо `#[xdp]`
- Context: `TcContext` вместо `XdpContext`
- Verdicts: `TC_ACT_OK` (pass), `TC_ACT_SHOT` (drop)
  вместо `XDP_PASS`, `XDP_DROP`
- Attach через `SchedClassifier` вместо `Xdp`

BPF map (ACTION_TABLE) — идентичный.

## Маркировка inject-пакетов

TC-BPF не должен дропать пакеты, инжектированные Geneva.
Два варианта маркировки:

1. **IP Identification field**: Geneva ставит IP ID = 0xDEAD
   на fakes. TC-BPF: если IP ID == 0xDEAD → pass.
2. **BPF map whitelist**: Geneva записывает SEQ числа
   инжектированных пакетов в BPF map. TC-BPF проверяет.

Вариант 1 проще и достаточен — ТСПУ не проверяет IP ID.

## Что не меняется

- Frontend pipeline — идентичный
- Geneva primitives — идентичные
- Capabilities — идентичные
- Detector — идентичный
- Fitness logic — идентичная
- AF_PACKET capture + inject — идентичные
- Тестовая топология — идентичная

Меняется только: **где** стоит BPF program (TC egress на
veth-rt-br вместо XDP на br0) и **тип** BPF program
(classifier вместо xdp).

## Следующие шаги

1. Переписать eBPF: `#[classifier]` + `TcContext` + `TC_ACT_SHOT`
2. Переписать loader: `SchedClassifier` attach на veth-rt-br egress
3. Добавить IP ID маркировку в inject
4. Прогнать Geneva TC-BPF на реальном ТСПУ
