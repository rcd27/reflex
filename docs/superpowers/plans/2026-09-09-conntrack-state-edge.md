# Состояние в IO-край: план реализации

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Перенести состояние приборов из юзерспейсных таблиц в conntrack ядра: юзерспейс zero-state, состояние приезжает с пакетом в `NFQA_CT` и уезжает с вердиктом в `NFQA_CT{CTA_MARK}`.

**Architecture:** Свой netlink-сокет к `NFNL_SUBSYS_QUEUE` вместо крейта `nfq` (тот не разбирает `CTA_MARK` и не кладёт `NFQA_CT` в вердикт). Ядерный вид края входит расслоением носителя — `DetectorEvent<(Wire, CtView)>`, сужение существующими `Reads`/`lmap`. Следующее состояние — слово области `Conversation`, едущее в ядро спуском `Packet: Within<Conversation>` вместе с вердиктом. Собственное `S` прибора вырождается в `()`.

**Tech Stack:** Rust 2021, `libc` (netlink руками, без новых зависимостей), существующие `reflex-core` (`Mealy`, `Word`, `Reads`, `certify`), `reflex-linux` (`conntrack/wire.rs`, `nfqueue/`).

**Spec:** `docs/superpowers/specs/2026-09-09-conntrack-state-edge-design.md`

## Global Constraints

- **Новых зависимостей нет.** Netlink пишется на `libc`, как уже сделано в `linux/src/conntrack/dump.rs` («зависимостей сверх `libc` нет намеренно»).
- **Закон одного чеканщика.** `CTA_*` разбирает ровно один код — `linux/src/conntrack/wire.rs`. Горячий путь идёт через него; второго разбора той же марки не заводить.
- **Обход TLV — одно место.** `Attrs`/`aligned` переезжают в `linux/src/netlink.rs` и используются обоими подсистемами (`ctnetlink`, `queue`).
- **Закон носитель-независим.** `CtView` — вид КРАЯ: поля называют величины («сколько прошло вниз», «как давно»), а не атрибуты netlink. `certify::remembering` формулируется над `Terminal`, не над очередью.
- **IO отдельно от разбора.** Сокет — в своём модуле, разбор байтов — чистые функции, тестируемые без root.
- **Докблок = имя конструкции + закон + `§N` канона.** Проза-рассказ о боли не пишется; тесты-законы (`compile_fail`, property) остаются.
- **Порог сноса.** Ни одна строка работающей детекции не удаляется раньше зелёного боевого гейта (Задача 9).
- Прогон после каждой задачи: `cargo test --workspace`.
- **Предупреждение допустимо внутри куска, но обязано погаснуть к его концу.** Задачи 1–3 едут вместе, и звено, написанное в первой для потребителя из третьей, законно висит `dead_code` два коммита. Глушить `#[allow]` НЕЛЬЗЯ: глушение переживёт кусок, и мёртвый код останется в дереве незамеченным. Проверяется на гейте задачи 3: `cargo build -p reflex-linux --features conntrack` и `--features nfqueue` — ноль предупреждений.
- **Мёртвый модуль гейтится фичей, а не объявляется безусловно.** Модуль, чьи потребители все под фичами, объявляется `#[cfg(any(...))]` — иначе сборка без фич тащит код, которого никто не зовёт.
- **Тест обязан уметь упасть.** Прежде чем считать задачу готовой, сломай проверяемое место нарочно и убедись, что тест краснеет. Тест, зелёный на сломанном коде, хуже отсутствующего: он выдаёт ложную уверенность и переживает рефакторинг, охраняя пустоту.

---

### Task 0: Ключ потока рождается из четвёрки ядра

**Files:**
- Modify: `engine-nfq/src/parse.rs:363` — там живёт единственная ковка (`pub fn keyed(client: u32, client_port: u16, server: u32, server_port: u16) -> FlowKey`, дальше `mixed`)
- Test: `engine-nfq/tests/flow_key_matches_tuple.rs`

**Interfaces:**
- Consumes: `keyed` (существующая, `engine-nfq/src/parse.rs:363`); `Tuple` из `conntrack::wire`.
- Produces: `pub fn keyed_of_orig(orig: Tuple) -> FlowKey` в том же модуле — обёртка НАД `keyed`, а не второе правило. Принимает кортеж ЦЕЛИКОМ и называет, какой именно: подать `CTA_TUPLE_REPLY` по ошибке можно, но имя об этом кричит, а тест ловит.

**Осторожно: ключ несимметричен.** `keyed` различает клиента и сервера (`mixed(mixed(tuple) ^ server)`), а `CTA_TUPLE_ORIG` даёт четвёрку «как завели»: `src` — инициатор. Значит orig-кортеж кладётся как есть, а reply-кортеж обязан быть развёрнут перед ковкой. Тест на это — второй ниже.

**Зависимость крейтов.** `reflex-engine-nfq` уже зависит от `reflex-linux` с фичей `conntrack`, так что `Tuple` там виден; обратного ребра заводить не нужно.

Нулевой шаг спеки, в усиленной формулировке: ключ не «сверяется» с четвёркой ядра, а **рождается** из неё. `CTA_TUPLE_ORIG` приложен к каждому пакету и уже нормализован (инициатор — `src`), поэтому на основной ветви эвристика направления для ключа не работает: две ковки не согласуются, а не рождаются.

**Фолбэк остаётся, и это не вторая ковка.** `NFQA_CT` есть не у всякого пакета: поток может быть `INVALID` для ядра, а `nf_conntrack` — не загружен вовсе. Ковка одна (`keyed`), источник четвёрки — предпочтительно `CTA_TUPLE_ORIG`, при его отсутствии провод с существующей эвристикой `upward`. Закон, который это держит: там, где есть оба источника, ключи совпадают — тест ниже.

**Отсюда точный статус `upward`:** для ключа он нужен ТОЛЬКО на фолбэк-ветви (четвёрки ядра нет — направление приходится угадывать по портам, как сегодня). На основной ветви он в ковке не участвует. Вне ключа он остаётся при своём всегда: `Dir` и чтение головы (`ClientHello` шлёт клиент) от него зависят независимо от источника четвёрки.

**Протокол в ключ НЕ входит, и это намеренно.** `keyed` берёт четыре поля и роняет `proto` (`parse.rs:364`); докблок `datagrammed` (`parse.rs:263`) объявляет это законом: «разговор по QUIC и по TCP к одной цели ключуются одинаково, иначе знание о цели разъедется по транспортам». Ковка из кортежа этого не нарушает — `keyed_of_orig` берёт из `Tuple` те же четыре поля и `proto` не трогает. Претензия докблока остаётся живой; снимать её не нужно.

- [ ] **Step 1: Написать падающий тест**

```rust
use reflex_engine_nfq::parse::{datagrammed, keyed, keyed_of_orig, wired};
use reflex_linux::conntrack::Tuple;

/// Ключ, выкованный из разобранного провода, и ключ из четвёрки ядра — один и тот же ключ.
/// Иначе беда, найденная по ядерному состоянию, не найдёт имени, заведённого по проводу.
#[test]
fn kernel_tuple_and_wire_forge_the_same_key() {
    let wire_key = keyed(0x0A00_0001, 44321, 0x5DB8_D822, 443);
    let tuple = Tuple { src: 0x0A00_0001, dst: 0x5DB8_D822, src_port: 44321, dst_port: 443, proto: 6 };
    assert_eq!(keyed_of_orig(tuple), wire_key);
}

/// Подмена ORIG на REPLY ловится, а не проходит молча: ключ несимметричен, и кортеж ответного
/// направления даёт ДРУГОЙ ключ. Тест охраняет не арифметику, а то, что мы всегда куём из ORIG —
/// единственного кортежа, который `NFQA_CT` даёт нормализованным.
#[test]
fn feeding_the_reply_tuple_changes_the_key() {
    let orig = Tuple { src: 0x0A00_0001, dst: 0x5DB8_D822, src_port: 44321, dst_port: 443, proto: 6 };
    let reply = Tuple { src: orig.dst, dst: orig.src, src_port: orig.dst_port, dst_port: orig.src_port, proto: 6 };
    assert_ne!(
        keyed_of_orig(reply),
        keyed_of_orig(orig),
        "ключ несимметричен: перепутать направления — получить второй разговор"
    );
}
```

```rust
/// Два источника четвёрки дают один ключ: пока это так, фолбэк на провод не заводит второго
/// понятия «какой это поток».
#[test]
fn both_sources_agree_while_both_exist() {
    let segment = syn_from(0x0A00_0001, 44321, 0x5DB8_D822, 443);
    let from_wire = wired(segment, true).flow;
    let tuple = Tuple { src: 0x0A00_0001, dst: 0x5DB8_D822, src_port: 44321, dst_port: 443, proto: 6 };
    assert_eq!(
        keyed_of_orig(tuple),
        from_wire,
        "ORIG-инициатор и upward-клиент — одно лицо"
    );
}

/// Протокол в ключ не входит — и проверяется это ТАМ, ГДЕ ПРОТОКОЛ ЕСТЬ: ключ TCP-сегмента и
/// ключ UDP-датаграммы к одной цели совпадают, как объявляет докблок `datagrammed` («иначе знание
/// о цели разъедется по транспортам»). Сравнивать два вызова ковки, которая протокол не
/// принимает, — тавтология: такой тест зелен и на сломанной обёртке.
#[test]
fn tcp_and_udp_to_one_target_share_the_conversation() {
    let ends = (0x0A00_0001, 44321, 0x5DB8_D822, 443);
    let over_tcp = wired(syn_from(ends.0, ends.1, ends.2, ends.3), true).flow;
    let over_udp = datagrammed(payload_from(ends.0, ends.1, ends.2, ends.3), true).flow;
    assert_eq!(over_tcp, over_udp, "один разговор, два транспорта");
    assert_eq!(keyed_of_orig(Tuple { src: ends.0, dst: ends.2, src_port: ends.1, dst_port: ends.3, proto: 17 }), over_tcp);
}
```

- [ ] **Step 2: Прогнать — обязан упасть**

Run: `cargo test -p reflex-engine-nfq --test flow_key_matches_tuple`
Expected: FAIL — `keyed_of_orig` не найден.

- [ ] **Step 3: Реализовать**

`keyed_of_orig` зовёт `keyed` и ничего не считает сама. Правило «кто клиент» не дублируется: у `CTA_TUPLE_ORIG` инициатор — `src`, и это единственное знание, которое обёртка добавляет.

- [ ] **Step 4: Прогнать**

Run: `cargo test --workspace`
Expected: PASS.

- [ ] **Step 5: Коммит**

```bash
git add engine-nfq/src/parse.rs engine-nfq/tests/flow_key_matches_tuple.rs
git commit -m "refactor(engine): ключ потока куётся одной функцией из четвёрки"
```

---

### Task 1: Общий обход TLV

**Files:**
- Create: `linux/src/netlink.rs`
- Modify: `linux/src/lib.rs` (объявить модуль под `#[cfg(any(feature = "conntrack", feature = "nfqueue"))]`)
- Modify: `linux/src/conntrack/wire.rs` (снять свои `Attrs`/`aligned`, взять из `netlink`)
- Test: `linux/src/netlink.rs` (`#[cfg(test)] mod tests`)

**Interfaces:**
- Consumes: ничего.
- Produces: `pub(crate) fn aligned(len: usize) -> usize`; `pub(crate) fn attrs(body: &[u8]) -> Attrs<'_>`; `pub(crate) struct Attrs<'a>` — `Iterator<Item = (u16, &'a [u8])>`, тип атрибута уже без бита `NESTED`; `pub(crate) fn u16_at/be16_at/be32_at/be64_at/i32_at(bytes, at) -> Option<_>`; `pub(crate) fn tlv(kind: u16, body: &[u8]) -> Vec<u8>` — сборка одного атрибута с выравниванием, длина БЕЗ паддинга; `pub(crate) fn nested(kind: u16, body: &[u8]) -> Vec<u8>` — то же с битом `NESTED`.

- [ ] **Step 1: Написать падающий тест на сборку атрибута**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    /// Длина в заголовке атрибута считает заголовок и тело, но НЕ паддинг: у ядра эта разница
    /// стоила апстриму крейта `nfq` отдельного исправления (июнь 2026).
    #[test]
    fn attribute_length_excludes_padding() {
        let built = tlv(7, &[0xAA, 0xBB, 0xCC]);
        assert_eq!(built.len(), 8, "тело выровнено до четырёх");
        assert_eq!(u16_at(&built, 0), Some(7), "длина = 4 заголовка + 3 тела");
        assert_eq!(u16_at(&built, 2), Some(7), "тип на месте");
        assert_eq!(&built[4..7], &[0xAA, 0xBB, 0xCC]);
    }

    /// Сборка и обход — обратны друг другу.
    #[test]
    fn built_attributes_read_back() {
        let body: Vec<u8> = tlv(1, &[1, 2, 3]).into_iter().chain(tlv(2, &[4])).collect();
        let read: Vec<(u16, Vec<u8>)> = attrs(&body).map(|(k, v)| (k, v.to_vec())).collect();
        assert_eq!(read, vec![(1, vec![1, 2, 3]), (2, vec![4])]);
    }

    /// Бит вложенности снимается на чтении: тип атрибута называет предмет, не форму.
    #[test]
    fn nested_bit_is_stripped_on_read() {
        let inner = tlv(3, &[9]);
        let body = nested(5, &inner);
        let read: Vec<u16> = attrs(&body).map(|(k, _)| k).collect();
        assert_eq!(read, vec![5], "тип без бита 0x8000");
    }

    /// Обрыв гасит обход целиком: фьюзность держит единственная ветка отказа.
    #[test]
    fn truncated_attribute_stops_the_walk() {
        let mut body = tlv(1, &[1, 2, 3, 4, 5, 6]);
        body.truncate(6);
        assert_eq!(attrs(&body).count(), 0);
    }
}
```

- [ ] **Step 2: Прогнать — тест обязан упасть**

Run: `cargo test -p reflex-linux --features conntrack netlink::tests`
Expected: FAIL — `cannot find function tlv` (модуля ещё нет).

- [ ] **Step 3: Написать модуль**

Перенести из `linux/src/conntrack/wire.rs` без изменения поведения: `aligned`, `Attrs`, `attrs`, `u16_at`, `be16_at`, `be32_at`, `be64_at`, `i32_at`. Добавить сборку:

```rust
//! Обход и сборка TLV netlink — общие для ctnetlink и очереди. Одно место: два обхода одних
//! байтов разошлись бы молча при зелёной сборке.

const ATTR_HDR: usize = 4;
const NESTED: u16 = 0x8000;

/// Атрибут: заголовок и тело, выровненные до четырёх. Длина в заголовке паддинг НЕ считает.
pub(crate) fn tlv(kind: u16, body: &[u8]) -> Vec<u8> {
    let len = (ATTR_HDR + body.len()) as u16;
    len.to_ne_bytes()
        .into_iter()
        .chain(kind.to_ne_bytes())
        .chain(body.iter().copied())
        .chain(std::iter::repeat_n(0u8, aligned(body.len()) - body.len()))
        .collect()
}

/// Вложенный атрибут — тот же TLV с объявленной вложенностью.
pub(crate) fn nested(kind: u16, body: &[u8]) -> Vec<u8> {
    tlv(kind | NESTED, body)
}
```

В `linux/src/lib.rs` добавить `pub(crate) mod netlink;`. В `conntrack/wire.rs` снять перенесённые определения и импортировать: `use crate::netlink::{aligned, attrs, be16_at, be32_at, be64_at, i32_at, u16_at};`.

- [ ] **Step 4: Прогнать — тесты обязаны пройти, старые не покраснеть**

Run: `cargo test -p reflex-linux --features conntrack`
Expected: PASS, включая существующие тесты разбора дампа.

- [ ] **Step 5: Коммит**

```bash
git add linux/src/netlink.rs linux/src/lib.rs linux/src/conntrack/wire.rs
git commit -m "refactor(linux): обход и сборка TLV netlink — одно место"
```

---

### Task 2: `CtView` — вид края, и один чеканщик на два источника

**Files:**
- Modify: `linux/src/conntrack/wire.rs` (добавить `CtView`, `view_of`; переписать `entry_of` через `view_of`)
- Modify: `linux/src/conntrack/mod.rs` (реэкспорт)
- Test: `linux/tests/ct_view.rs`

**Interfaces:**
- Consumes: `netlink::{attrs, be32_at, be64_at}` (Task 1).
- Produces:

```rust
pub struct CtView {
    pub id: u32,
    pub ends: CtEnds,                  // V4 ключуется, V6 разбирается и НЕ ключуется
    pub tuple: Option<Tuple>,          // Some только для V4: то, что умеет ковка ключа
    pub down: Counts,      // от клиента к цели (orig)
    pub up: Counts,        // от цели к клиенту (reply)
    pub started_at: Option<u64>,       // CTA_TIMESTAMP_START как есть: наносекунды реального времени
    pub expires_in: Option<Duration>,    // из CTA_TIMEOUT
    pub tcp: Option<CtTcp>,              // из CTA_PROTOINFO
    pub mark: u32,
}
pub enum CtTcp { SynSent, SynRecv, Established, FinWait, CloseWait, LastAck, TimeWait, Close, Other(u8) }
pub enum CtEnds {
    V4 { src: u32, dst: u32, src_port: u16, dst_port: u16, proto: u8 },
    V6 { src: [u8; 16], dst: [u8; 16], src_port: u16, dst_port: u16, proto: u8 },
    Unknown,                            // семейства нет в кортеже вовсе
}
pub fn view_of(body: &[u8]) -> CtView;   // тело = ТОЛЬКО атрибуты CTA_*, без nfgenmsg
```

- [ ] **Step 1: Написать падающий тест**

```rust
use reflex_linux::conntrack::{view_of, CtTcp};

/// Хелпер: собрать тело NFQA_CT из атрибутов, как их кладёт ядро.
fn ct_body(mark: u32, orig_packets: u64, reply_packets: u64, timeout_secs: u32) -> Vec<u8> {
    // CTA_COUNTERS_PACKETS = 1, CTA_COUNTERS_ORIG = 9, CTA_COUNTERS_REPLY = 10,
    // CTA_MARK = 8, CTA_TIMEOUT = 7. Числа у ctnetlink — big-endian.
    let counters = |packets: u64| tlv_be64(1, packets);
    [
        nested_raw(9, &counters(orig_packets)),
        nested_raw(10, &counters(reply_packets)),
        tlv_be32(8, mark),
        tlv_be32(7, timeout_secs),
    ]
    .concat()
}

/// Вид края читается из тела NFQA_CT тем же разбором, что и запись дампа: один чеканщик.
#[test]
fn view_reads_counters_and_mark() {
    let view = view_of(&ct_body(0xDEAD_BEEF, 5, 0, 118));
    assert_eq!(view.mark, 0xDEAD_BEEF);
    assert_eq!(view.down.packets, 5, "клиент отправил пять");
    assert_eq!(view.up.packets, 0, "цель не ответила ни разу");
    assert_eq!(view.expires_in, Some(std::time::Duration::from_secs(118)));
}

/// Отсутствующий атрибут — не ноль, а «неизвестно»: ядро с выключенным acct счётчиков не шлёт,
/// и ноль пакетов был бы ложью, неотличимой от правды.
#[test]
fn missing_attributes_are_unknown_not_zero() {
    let view = view_of(&[]);
    assert_eq!(view.expires_in, None);
    assert_eq!(view.started_at, None);
    assert!(view.tcp.is_none());
}

/// Начало потока отдаётся АБСОЛЮТНЫМ, как его прислало ядро, а не «сколько назад». Возраст —
/// разность с моментом наблюдения, а момент приносит буква события (§8): разбор, дёрнувший часы
/// сам, сделал бы вид края недетерминированным и непереигрываемым.
#[test]
fn the_start_is_absolute_the_age_is_not_computed_here() {
    let stamp = 1_757_000_000_000_000_000u64;
    // CTA_TIMESTAMP = 20 (вложенный), внутри CTA_TIMESTAMP_START = 1, be64 наносекунд.
    let view = view_of(&nested_raw(20, &tlv_be64(1, stamp)));
    assert_eq!(view.started_at, Some(stamp), "как прислало ядро, без арифметики");
}

/// IPv6 РАЗБИРАЕТСЯ, но ключом не становится. Отдай разбор на IPv6-потоке четвёрку по умолчанию
/// — ВСЕ они схлопнулись бы в один ключ при зелёной сборке. Отказ назван причиной, а не пустотой:
/// незнание обитаемо (§7). Читать шестнадцать байт вместо четырёх стоит нуля и оставляет будущей
/// работе ровно одно место — ковку ключа.
#[test]
fn ipv6_ends_are_read_but_never_keyed() {
    // CTA_TUPLE_IP = 1, внутри CTA_IP_V6_SRC = 3 / CTA_IP_V6_DST = 4.
    let ipv6 = nested_raw(1, &[tlv_bytes(3, &[0x20; 16]), tlv_bytes(4, &[0x21; 16])].concat());
    let view = view_of(&nested_raw(1, &ipv6));
    assert!(
        matches!(view.ends, CtEnds::V6 { src, .. } if src == [0x20; 16]),
        "адреса разобраны, а не потеряны"
    );
    assert!(view.tuple.is_none(), "ключ из них не куётся: пакет уйдёт непонятым");
}

/// Кортежа нет вовсе — тоже названное состояние, не нули.
#[test]
fn absent_ends_are_named_unknown() {
    assert!(matches!(view_of(&[]).ends, CtEnds::Unknown));
}
```

Хелперы `tlv_be32`, `tlv_be64`, `nested_raw` написать в том же файле теста поверх публичной сборки байтов (в тесте — руками, `netlink` крейт-приватен).

- [ ] **Step 2: Прогнать — обязан упасть**

Run: `cargo test -p reflex-linux --features conntrack --test ct_view`
Expected: FAIL — `view_of` не найден.

- [ ] **Step 3: Реализовать**

`addressed` учится читать `CTA_IP_V6_SRC` (3) и `CTA_IP_V6_DST` (4) наравне с `CTA_IP_V4_*` и отдаёт `CtEnds`; `tuple` выводится из `CtEnds::V4` и только из неё. `view_of` собирает `CtView` тем же `fold` по `attrs`, каким сегодня собирается `Entry`; `entry_of` переписывается как `payload.get(NFGEN..).map(view_of)` плюс сборка `Entry` из полей вида. `CTA_COUNTERS_*` читаются существующей `counted`, `CTA_TUPLE_ORIG` — существующей `tupled`. Новое: `CTA_TIMEOUT` = 7 (be32, секунды), `CTA_TIMESTAMP` = 20 (вложенный, `CTA_TIMESTAMP_START` = 1, be64 наносекунд **реального времени от эпохи** — кладётся в вид как есть, без пересчёта в «сколько назад»: часов разбор не дёргает), `CTA_PROTOINFO` = 4 → `CTA_PROTOINFO_TCP` = 1 → `CTA_PROTOINFO_TCP_STATE` = 1 (u8), `CTA_ID` = 12. Все сверены с `nfnetlink_conntrack.h`; `CTA_IP_V6_SRC` = 3, `CTA_IP_V6_DST` = 4.

**Отсутствие — `None`, не ноль.** Ядро без `nf_conntrack_acct` счётчиков не шлёт; ноль пакетов неотличим от «не считали».

- [ ] **Step 4: Прогнать**

Run: `cargo test -p reflex-linux --features conntrack`
Expected: PASS, включая существующие тесты дампа (они идут через переписанный `entry_of`).

- [ ] **Step 5: Коммит**

```bash
git add linux/src/conntrack/ linux/tests/ct_view.rs
git commit -m "feat(linux): CtView — вид края, чеканенный одним разбором CTA_*"
```

---

### Task 3: Сообщения очереди — сборка и разбор без сокета

**Files:**
- Create: `linux/src/queue/wire.rs`
- Create: `linux/src/queue/mod.rs`
- Modify: `linux/src/lib.rs`
- Test: `linux/tests/queue_wire.rs`

**Interfaces:**
- Consumes: `netlink::*` (Task 1), `conntrack::view_of`, `CtView` (Task 2).
- Produces:

```rust
pub struct Packet { pub id: u32, pub payload: Vec<u8>, pub nfmark: u32, pub ct: Option<CtView> }
pub enum Incoming { Packet(Packet), Done, Failed(i32) }

pub fn bind_request(queue: u16, seq: u32) -> Vec<u8>;
pub fn params_request(queue: u16, seq: u32, copy_range: u16) -> Vec<u8>;
pub fn conntrack_flag_request(queue: u16, seq: u32) -> Vec<u8>;   // NFQA_CFG_F_CONNTRACK + маска
pub fn verdict_message(queue: u16, seq: u32, id: u32, accept: bool, ct_mark: Option<u32>) -> Vec<u8>;
pub fn incoming_of(buffer: &[u8]) -> Vec<Incoming>;               // одно сообщение или несколько
```

- [ ] **Step 1: Написать падающие тесты**

```rust
use reflex_linux::queue::{incoming_of, verdict_message, conntrack_flag_request, Incoming};

/// Длины тел — то, что ядро не прощает: две структуры упакованы, и лишний байт выравнивания
/// делает сообщение непонятным молча.
#[test]
fn message_bodies_have_the_sizes_the_kernel_expects() {
    assert_eq!(params_body(0xFFFF).len(), 5, "copy_range be32 + copy_mode u8, БЕЗ выравнивания");
    assert_eq!(cmd_body(1).len(), 4, "command u8 + _pad u8 + pf be16");
    assert_eq!(verdict_body(1, 42).len(), 8, "verdict be32 + id be32");
}

/// Флаг conntrack — то, чем включается NFQA_CT. Без него ядро вида края не приложит, и все
/// приборы на ядерных величинах молча увидят пустоту.
#[test]
fn conntrack_flag_request_sets_flag_and_mask() {
    let built = conntrack_flag_request(200, 1);
    // NFQA_CFG_FLAGS = 5, NFQA_CFG_MASK = 4, NFQA_CFG_F_CONNTRACK = 0x0002, оба be32.
    assert!(contains_be32_attr(&built, 5, 0x0002), "флаг выставлен");
    assert!(contains_be32_attr(&built, 4, 0x0002), "маска называет тот же бит");
}

/// Состояние уезжает вложенным NFQA_CT{CTA_MARK} — именно этого не умеет крейт nfq.
#[test]
fn verdict_carries_conntrack_mark() {
    let built = verdict_message(200, 7, 42, true, Some(0x0000_1234));
    // NFQA_CT = 11 (вложенный), внутри CTA_MARK = 8, be32.
    let ct = nested_attr(&built, 11).expect("NFQA_CT в вердикте");
    assert_eq!(be32_attr(&ct, 8), Some(0x0000_1234));
}

/// Вердикт без смены состояния не несёт NFQA_CT вовсе: не трогать — не то же, что записать своё.
#[test]
fn verdict_without_state_carries_no_conntrack_attribute() {
    let built = verdict_message(200, 7, 42, true, None);
    assert!(nested_attr(&built, 11).is_none());
}

/// Пакет разбирается вместе с видом края: обе половины из одного сообщения.
#[test]
fn packet_carries_payload_and_view() {
    let message = packet_message(/* id */ 9, /* payload */ &[0x45, 0x00], /* ct mark */ 0xABC);
    match incoming_of(&message).as_slice() {
        [Incoming::Packet(packet)] => {
            assert_eq!(packet.id, 9);
            assert_eq!(packet.payload, vec![0x45, 0x00]);
            assert_eq!(packet.ct.as_ref().map(|view| view.mark), Some(0xABC));
        }
        other => panic!("ожидался один пакет, пришло {other:?}"),
    }
}

/// Несколько сообщений в одном буфере — обычный ответ ядра, а не край: считать их по одному
/// значило бы терять пакеты пачками.
#[test]
fn several_messages_in_one_buffer_are_all_read() {
    let buffer = [packet_message(1, &[1], 0), packet_message(2, &[2], 0)].concat();
    assert_eq!(incoming_of(&buffer).len(), 2);
}
```

- [ ] **Step 2: Прогнать — обязан упасть**

Run: `cargo test -p reflex-linux --features nfqueue --test queue_wire`
Expected: FAIL — модуля `queue` нет.

- [ ] **Step 3: Реализовать**

Константы — сверены с `include/uapi/linux/netfilter/nfnetlink_queue.h`, не по памяти:

```
NFNL_SUBSYS_QUEUE      3
NFQNL_MSG_PACKET       0     NFQNL_MSG_VERDICT      1     NFQNL_MSG_CONFIG   2
NFQA_PACKET_HDR        1     NFQA_VERDICT_HDR       2     NFQA_MARK          3
NFQA_PAYLOAD          10     NFQA_CT               11     NFQA_CT_INFO      12
NFQA_CFG_CMD           1     NFQA_CFG_PARAMS        2     NFQA_CFG_QUEUE_MAXLEN 3
NFQA_CFG_MASK          4     NFQA_CFG_FLAGS         5
NFQNL_CFG_CMD_BIND     1     NFQNL_COPY_PACKET      2
NFQA_CFG_F_CONNTRACK   0x0002
NF_DROP                0     NF_ACCEPT              1
```

**Осторожно с двумя:** `NFQA_MARK` — **3**, а не 8 (8 — это `CTA_MARK` из ctnetlink, другое пространство имён); `NFQA_CFG_MASK` — **4**, а не 6. Обе ошибки не ловятся ничем, кроме живого ядра: сообщение уйдёт, ядро молча не поймёт атрибут.

Заголовок сообщения — `nlmsghdr` (16 байт) + `nfgenmsg` (4 байта: `family: u8`, `version: u8` = `NFNETLINK_V0` = 0, `res_id: be16` = номер очереди). Тип сообщения — `(NFNL_SUBSYS_QUEUE << 8) | msg`, где `NFNL_SUBSYS_QUEUE` = 3.

**Тела атрибутов — сверены с uapi, две УПАКОВАННЫЕ.** Писать их как обычные структуры Rust нельзя: выравнивание добавит байт, и ядро молча не поймёт сообщение.

```
nfqnl_msg_packet_hdr    packed, 7 байт:  packet_id be32, hw_protocol be16, hook u8
nfqnl_msg_verdict_hdr           8 байт:  verdict be32, id be32
nfqnl_msg_config_cmd            4 байта: command u8, _pad u8, pf be16
nfqnl_msg_config_params packed, 5 байт:  copy_range be32, copy_mode u8
```

`config_params` в пять байт — самая вероятная ошибка этой задачи: рука пишет восемь. Собирать их байтами (`Vec<u8>` через `extend_from_slice`), а не `repr(C)`-структурами: длина тела тогда видна глазом и проверяется тестом.

Разбор `incoming_of` — рекурсивный обход сообщений буфера по образцу `chunk_of` из `conntrack/wire.rs`: длина из заголовка, `NLMSG_DONE`/`NLMSG_ERROR` как отдельные исходы, иначе — атрибуты через `attrs`, где `NFQA_CT` отдаётся в `view_of` (Task 2), а не разбирается на месте.

- [ ] **Step 4: Прогнать**

Run: `cargo test -p reflex-linux --features nfqueue --test queue_wire`
Expected: PASS.

- [ ] **Step 5: Коммит**

```bash
git add linux/src/queue/ linux/src/lib.rs linux/tests/queue_wire.rs
git commit -m "feat(linux): сообщения очереди — NFQA_CT на приёме и в вердикте"
```

---

### Task 4: Сокет очереди и `Terminal` над ним

**Files:**
- Create: `linux/src/queue/socket.rs`
- Create: `linux/src/queue/terminal.rs`
- Modify: `linux/src/queue/mod.rs`
- Test: `linux/tests/queue_terminal.rs`

**Interfaces:**
- Consumes: `queue::wire::*` (Task 3).
- Produces:

```rust
pub struct QueueSocket { /* fd */ }
impl QueueSocket {
    pub fn open(queue: u16) -> Result<QueueSocket, QueueError>;
    pub fn wait(&self, millis: i32) -> Waited;      // poll на СВОЁМ fd, без /proc/self/fd
    pub fn recv(&self) -> Result<Vec<Incoming>, QueueError>;
    pub fn verdict(&self, id: u32, accept: bool, ct_mark: Option<u32>) -> Result<(), QueueError>;
}
pub enum QueueError { Socket(i32), Send(i32), Recv(i32), Overrun, Kernel(i32) }
impl QueueError { pub fn from_errno(errno: i32) -> QueueError; }   // ENOBUFS → Overrun, прочее → Recv
pub struct Held(pub Packet);            // носитель права ответить
pub enum Answer { Pass, Stop, Remembered { accept: bool, state: u32 } }
impl reflex_core::held::Terminal for QueueSocket { type Carrier = Held; type Answer = Answer; type Refusal = QueueError; }
impl reflex_core::capability::CanRemember for QueueSocket { fn remember(state: u32, accept: bool) -> Answer; }
```

- [ ] **Step 1: Написать падающий тест на способность и на переполнение**

```rust
use reflex_linux::queue::{Answer, QueueError};

/// `ENOBUFS` — величина, а не молчание: ядро сказало, что пакеты потеряны, и это знание нужно
/// прибору (сравнение оттиска через разрыв недоверенно).
#[test]
fn overrun_is_a_value() {
    assert_eq!(QueueError::from_errno(libc::ENOBUFS), QueueError::Overrun);
    assert_eq!(QueueError::from_errno(libc::EPERM), QueueError::Recv(libc::EPERM));
}

/// Способность помнить строится тем же словом, каким отвечает очередь: пятое слово молча не завести.
#[test]
fn remembering_is_one_word_with_the_verdict() {
    let answer = <reflex_linux::queue::QueueSocket as reflex_core::capability::CanRemember>::remember(0x1234, true);
    assert_eq!(answer, Answer::Remembered { accept: true, state: 0x1234 });
}
```

- [ ] **Step 2: Прогнать — обязан упасть**

Run: `cargo test -p reflex-linux --features nfqueue --test queue_terminal`
Expected: FAIL — `QueueSocket` не найден.

- [ ] **Step 3: Реализовать сокет**

Открытие — по образцу `conntrack/dump.rs::open` (`socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER)`, без явного `bind`), затем три сообщения конфигурации из Task 3 подряд.

**`ENOBUFS` НЕ глушить — здесь мы расходимся с крейтом намеренно.** `nfq 0.2.5` в `open()` зовёт `set_recv_enobufs(false)`, то есть выставляет `NETLINK_NO_ENOBUFS` и просит ядро о переполнении не сообщать: очередь переполнилась — пакеты потерялись молча. Нам нужно обратное, и не из аккуратности: провал приёма делает сравнение оттиска через разрыв недоверенным (см. связку рисков в спеке). Не сообщённое переполнение превратится в «цель вдруг перестала отвечать» — то есть в ложную беду, неотличимую от настоящей.

Поэтому: `NETLINK_NO_ENOBUFS` не трогаем (умолчание ядра — сообщать), а `recv`, вернувший `ENOBUFS`, отдаёт `QueueError::Overrun` — букву, а не ошибку. Дескриптор хранится СВОЙ — `/proc/self/fd` не используется. `wait` — `libc::poll` на нём. `recv` — `libc::recv` в буфер 64 КиБ, затем `incoming_of`; `errno == ENOBUFS` → `QueueError::Overrun`. `verdict` — `libc::send` собранного сообщения.

`Terminal::apply` разбирает `Answer` в один вызов `verdict`: `Pass` → accept без `NFQA_CT`, `Stop` → drop, `Remembered { accept, state }` → вердикт с `NFQA_CT{CTA_MARK}`.

Добавить в `core/src/capability.rs`:

```rust
/// Способность помнить на крае: следующее состояние отдаётся ТЕМ ЖЕ словом, что и вердикт.
/// Раздельные слова допускали бы «ответили, но не запомнили» — состояние осталось бы прошлым
/// при отпущенном пакете. Канон §5.
pub trait CanRemember: crate::held::Terminal {
    fn remember(state: u32, accept: bool) -> Self::Answer;
}
```

- [ ] **Step 4: Прогнать**

Run: `cargo test --workspace`
Expected: PASS.

- [ ] **Step 5: Коммит**

```bash
git add linux/src/queue/ core/src/capability.rs linux/tests/queue_terminal.rs
git commit -m "feat(linux): свой сокет очереди, способность помнить на крае"
```

---

### Task 5: Кодек марки

**Files:**
- Create: `instrument/src/edge.rs`
- Modify: `instrument/src/lib.rs`
- Test: `instrument/tests/edge_codec.rs`

**Interfaces:**
- Consumes: ничего из предыдущих задач (чистая арифметика над `u32`).
- Produces:

```rust
pub struct Layout { pub mask: u32, pub tag: u8 }   // маска — ПАРАМЕТР, не константа фреймворка;
                                                   // 15 бит минимум, тег ненулевой
pub enum Phase { Quiet, Suspected, Confirmed, Released }
pub struct Memo { pub phase: Phase, pub imprint: u8 }
pub enum Recall { Ours(Memo), Foreign { theirs: u32 } }   // буква входа, не показание

impl Layout {
    pub fn read(&self, word: u32) -> Recall;
    pub fn write(&self, word: u32, memo: Memo) -> u32;    // read-modify-write под маской
}
```

- [ ] **Step 1: Написать падающие тесты**

```rust
use reflex_instrument::edge::{Layout, Memo, Phase, Recall};

// Пятнадцать бит: тег 4 + фаза 3 + оттиск 8. Маска — ПАРАМЕТР, здесь лишь пример.
const LAYOUT: Layout = Layout { mask: 0x0FFF_E000, tag: 0b101 };

/// Чужие биты переживают наш шаг: сосед по машине нам неизвестен, и стереть его разметку мы не
/// вправе — даже не зная, что она есть.
#[test]
fn foreign_bits_survive_the_write() {
    let foreign = 0x2000_00FF;
    let written = LAYOUT.write(foreign, Memo { phase: Phase::Suspected, imprint: 3 });
    assert_eq!(written & !LAYOUT.mask, foreign, "вне маски — байт в байт");
}

/// Записанное читается обратно.
#[test]
fn what_was_written_is_read_back() {
    let word = LAYOUT.write(0, Memo { phase: Phase::Confirmed, imprint: 200 });
    match LAYOUT.read(word) {
        Recall::Ours(memo) => {
            assert_eq!(memo.phase, Phase::Confirmed);
            assert_eq!(memo.imprint, 200);
        }
        Recall::Foreign { theirs } => panic!("своё прочлось чужим: {theirs:#x}"),
    }
}

/// Писателя называет тег, а не память: сравнение с КОНСТАНТОЙ, иначе юзерспейс снова обзавёлся бы
/// состоянием ради проверки, что состояния не держит.
#[test]
fn another_writer_is_recognised_without_memory() {
    let alien = LAYOUT.write(0, Memo { phase: Phase::Suspected, imprint: 1 }) ^ 0x0000_2000;
    assert!(matches!(LAYOUT.read(alien), Recall::Foreign { .. }));
}

/// Пустое слово — не «наша тишина», а чужое: нулевой тег нашим не бывает.
#[test]
fn empty_word_is_foreign() {
    assert!(matches!(LAYOUT.read(0), Recall::Foreign { theirs: 0 }));
}
```

- [ ] **Step 2: Прогнать — обязан упасть**

Run: `cargo test -p reflex-instrument --test edge_codec`
Expected: FAIL — модуля `edge` нет.

- [ ] **Step 3: Реализовать**

Раскладка внутри маски, от её МЛАДШЕГО бита вверх: **тег 4 бита, фаза 3, оттиск 8** — итого 15. Поля извлекаются сдвигом от `mask.trailing_zeros()`; `write` = `(word & !mask) | ((packed << shift) & mask)`; `read` сверяет тег и при несовпадении отдаёт `Recall::Foreign { theirs: word }`.

**Тег внизу — не произвол.** Он читается первым и решает, доверять ли остальным полям; положенный сверху, он оставил бы младшую границу маски под оттиском, где чужая запись «на бит мимо» тихо испортила бы точку отсчёта вместо того, чтобы объявиться чужой.

**Тег обязан быть ненулевым.** Пустое слово (`mark == 0` — разговор, которого мы не касались) обязано читаться чужим, а не «нашим с фазой `Quiet`»: иначе всякий нетронутый поток выглядел бы уже наблюдаемым.

**Маска обязана вмещать поля.** 15 бит; `Layout` с более узкой маской — ошибка сборки цепочки, а не тихое обрезание старших бит оттиска.

- [ ] **Step 4: Прогнать**

Run: `cargo test --workspace`
Expected: PASS.

- [ ] **Step 5: Коммит**

```bash
git add instrument/src/edge.rs instrument/src/lib.rs instrument/tests/edge_codec.rs
git commit -m "feat(instrument): кодек края — фаза, оттиск, тег писателя под маской"
```

---

### Task 6: Слово края и расслоение носителя

**Files:**
- Create: `instrument/src/edge_word.rs`
- Modify: `engine-nfq/src/talk.rs` или место сборки широкого слова (`Reading`)
- Test: `instrument/tests/edge_word.rs`

**Interfaces:**
- Consumes: `Memo` (Task 5), `Word`/`Descends`/`Conversation`/`Packet` из `reflex-core`.
- Produces:

```rust
// --- в reflex-core: ЗАКОН, носителя не знающий ---
/// Величины, которые ведёт КРАЙ, кто бы им ни был: conntrack, карта eBPF, чужая ОС.
pub trait EdgeView {
    fn down_packets(&self) -> Option<u64>;   // от клиента к цели
    fn up_packets(&self) -> Option<u64>;     // от цели к клиенту
    fn idle(&self) -> Option<Duration>;      // сколько прошло с последнего пакета
    fn mark(&self) -> u32;                   // слово состояния, как его хранит край
}
impl Word for Memo { type Of = Conversation; }        // состояние принадлежит разговору
/// То же состояние, сказанное о пакете: НАШИ биты и маска, под которой они лежат.
/// Не готовое слово ядра — его нельзя произвести из `Memo` в принципе: запись есть
/// read-modify-write, и старое слово знает только край.
pub struct Told { pub under: u32, pub mask: u32 }
impl Word for Told { type Of = Packet; }
impl Descends<Told> for Memo { fn descends(self) -> Told; }   // Memo несёт свой Layout
impl<V> Reads<(Reading, V)> for Seen { ... }           // прибор провода проецирует .0

/// Сужение сквозь пару для приборов, которым нужны обе половины. Локальный тип — иначе
/// орфан-правило (`E0117`): и трейт, и кортеж чужие.
pub struct Edged<N, V> { pub narrow: N, pub edge: V }
impl<N: Reads<Reading>, V: Clone> Reads<(Reading, V)> for Edged<N, V> { ... }

// --- в reflex-linux: НОСИТЕЛЬ ---
/// Вид ядра ПЛЮС то, что вид не несёт: база таймаута для состояния. `CtView` — что приехало с
/// пакетом, база — конфигурация машины, прочитанная при старте. Носитель — их пара, потому что
/// `idle = база − остаток` есть знание conntrack о себе.
pub struct CtEdge { pub view: CtView, pub base: TimeoutBase }
impl EdgeView for CtEdge { ... }
```

**Почему трейт, а не `CtView` напрямую.** `reflex-instrument` знает ровно `reflex-core` и `smallvec` (проверено `cargo tree`); `impl Reads<(Reading, CtView)>` в нём заставил бы алфавит беды зависеть от `reflex-linux`, то есть привязал бы kernel-агностичные приборы к conntrack — против раздела «Закон и его носитель» спеки. Плюс орфан-правило: трейт и `Self` оба чужие, кортеж не fundamental, `E0117`.

Отсюда: закон (`EdgeView`) живёт в `core`, носитель реализует его в `linux`, приборы сужаются generic-ом по `V: EdgeView` и о conntrack не знают. Карта eBPF встанет тем же законом, другим `impl`.

**Спуск `Memo → Told` и почему `Told` — не готовая марка.** Запись состояния есть read-modify-write: новое слово = `(старое & !маска) | наши биты`, а старое слово знает только край, читающий его из `NFQA_CT`. Значит из слова разговора готовую марку произвести НЕЛЬЗЯ — `Descends` и не пытается. `Told` несёт наши биты и маску; край применяет их к прочитанному слову одной операцией.

Чтобы упаковка не разошлась на две (`Layout::write` и `descends` — ровно шов «два закона об одном предмете»), кодек остаётся ОДИН: `Memo` носит свой `Layout` (он `Copy`), `descends` зовёт упаковку `Layout`, а `Layout::write(word, memo)` выражается через тот же `Told`: `(word & !told.mask) | told.under`. Одна упаковка, два входа.

- [ ] **Step 1: Написать падающие тесты**

```rust
/// Пара слов одной области — слово: беда и памятка края обе сказаны о разговоре.
#[test]
fn distress_and_memo_pair_up() {
    fn takes<W: reflex_core::word::Word>() {}
    takes::<(Distress, Memo)>();
}

/// Сужение широкого слова: прибор провода видит провод, прибор края — край, оба слепы к чужому.
#[test]
fn each_instrument_narrows_to_its_own_multiplier() {
    let wide = (Reading::Tcp(some_tcp()), some_view());
    assert!(Seen::read(&wide).is_some(), "провод читается");
    assert!(CtView::read(&wide).is_some(), "край читается");
}
```

Плюс тест-закон, что смешение областей не собирается:

```rust
/// Состояние, сказанное о разговоре, не склеивается с вердиктом о пакете без спуска.
/// ```compile_fail
/// use reflex_core::word::Word;
/// fn takes<W: Word>() {}
/// takes::<(reflex_instrument::edge_word::Memo, reflex_core::word::VerdictWord)>();
/// ```
struct AreasDoNotMix;
```

- [ ] **Step 2: Прогнать — обязан упасть**

Run: `cargo test -p reflex-instrument --test edge_word`
Expected: FAIL — `impl Word for Memo` отсутствует.

- [ ] **Step 3: Реализовать**

Широкое слово транспорта становится парой `(Reading, CtView)`; существующие `Reads` для `Seen`/`SeenTcp` проецируют первый множитель, новый `Reads` для `CtView` — второй. Логика существующих приборов не трогается.

- [ ] **Step 4: Прогнать**

Run: `cargo test --workspace`
Expected: PASS.

- [ ] **Step 5: Коммит**

```bash
git add instrument/src/edge_word.rs engine-nfq/src/talk.rs instrument/tests/edge_word.rs
git commit -m "feat(instrument): слово края в области разговора, расслоение носителя"
```

---

### Task 7: Приборы на величинах края

**Files:**
- Create: `instrument/src/edge_detect.rs`
- Modify: `instrument/src/lib.rs`
- Test: `instrument/tests/edge_detect.rs`

**Interfaces:**
- Consumes: `EdgeView` (Task 6, трейт в `core`), `Layout`/`Memo`/`Phase`/`Recall` (Task 5). `CtView` НЕ упоминается: прибор о носителе не знает.
- Produces:

```rust
pub struct EdgeSilence<V> { after: Duration, layout: Layout, base: TimeoutBase, edge: PhantomData<fn() -> V> }
impl<V: EdgeView> EdgeSilence<V> { pub fn new(after: Duration, layout: Layout, base: TimeoutBase) -> EdgeSilence<V>; }
impl<V: EdgeView> Mealy for EdgeSilence<V> {
    type In = DetectorEvent<Edged<Seen, V>>;   // край абстрактен: conntrack, eBPF-карта, чужая ОС
    type Out = SmallVec<[(Distress, Memo); 2]>;   // слово беды и слово края — обе Of = Conversation
    type Log = ();
}
```

- [ ] **Step 1: Написать падающие тесты**

```rust
/// Цель не ответила вовсе — ядро знает это счётчиком, нам хранить нечего.
#[test]
fn no_reply_at_all_is_read_from_the_edge() {
    let view = view(/* down */ 4, /* up */ 0, /* expires_in */ 110, /* base */ 120);
    let (_next, said, ()) = EdgeSilence::new(secs(5), LAYOUT).step(packet(view));
    assert!(said.iter().any(|(distress, _)| *distress == Distress::NoBytes));
}

/// Тишина меряется ядерной величиной: база минус остаток жизни записи.
#[test]
fn silence_is_measured_by_the_kernel_clock() {
    let view = view(/* down */ 2, /* up */ 3, /* expires_in */ 114, /* base */ 120);
    let (_next, said, ()) = EdgeSilence::new(secs(5), LAYOUT).step(packet(view));
    assert!(
        said.iter().any(|(distress, _)| matches!(distress, Distress::Silence { ms } if *ms >= 6000)),
        "шесть секунд простоя видны без наших часов"
    );
}

/// Сказанное однажды не повторяется: фаза лежит в марке, и второй пакет её оттуда читает.
#[test]
fn a_told_flow_stays_silent_on_the_next_packet() {
    let told = LAYOUT.write(0, Memo { phase: Phase::Confirmed, imprint: 3 });
    let view = with_mark(view(2, 3, 114, 120), told);
    let (_next, said, ()) = EdgeSilence::new(secs(5), LAYOUT).step(packet(view));
    assert!(said.is_empty(), "повторно не жалуемся");
}

/// Прибор состояния не держит: два шага из одного значения дают один и тот же исход.
#[test]
fn the_instrument_is_stateless() {
    let instrument = EdgeSilence::new(secs(5), LAYOUT);
    let view = view(2, 3, 114, 120);
    let (again, first, ()) = instrument.step(packet(view.clone()));
    let (_, second, ()) = again.step(packet(view));
    assert_eq!(first, second, "исход зависит от края, не от прожитого");
}

/// По нашим битам писал другой — это буква, а не тишина: прибор вправе сказать о находке.
#[test]
fn a_foreign_writer_is_observed() {
    let alien = 0x0055_0000;
    let view = with_mark(view(2, 0, 114, 120), alien);
    let (_next, said, ()) = EdgeSilence::new(secs(5), LAYOUT).step(packet(view));
    assert!(said.iter().any(|(distress, _)| matches!(distress, Distress::Diverged { .. })));
}
```

- [ ] **Step 2: Прогнать — обязан упасть**

Run: `cargo test -p reflex-instrument --test edge_detect`
Expected: FAIL — `EdgeSilence` не найден.

- [ ] **Step 3: Реализовать**

Величины берутся через `EdgeView`: «не ответила вовсе» = `up.packets == 0`; «сколько молчит» = `base − expires_in`, где `base` — таймаут ядра для состояния из `view.tcp`, прочитанный при старте (Task 7). Фаза и оттиск читаются `Layout::read`; `Recall::Foreign` даёт `Distress::Diverged`. На выходе — пара слов: беда и памятка края, обе `Of = Conversation`.

Добавить в `instrument/src/distress.rs` вариант `Diverged { theirs: u32 }`.

- [ ] **Step 4: Прогнать**

Run: `cargo test --workspace`
Expected: PASS.

- [ ] **Step 5: Коммит**

```bash
git add instrument/src/edge_detect.rs instrument/src/distress.rs instrument/src/lib.rs instrument/tests/edge_detect.rs
git commit -m "feat(instrument): приборы на величинах края, без собственного состояния"
```

---

### Task 8: Предпосылки машины

**Files:**
- Modify: `linux/src/nfqueue/preflight.rs`
- Test: там же (`#[cfg(test)] mod tests`)

**Interfaces:**
- Consumes: ничего.
- Produces: варианты `PreflightError::{NoConntrack, NoAccounting, NoTimestamps}`.

**Базы таймаута здесь НЕТ, и это не отсрочка.** `preflight` отвечает на вопрос «годится ли машина», а база таймаута — знание носителя о себе (`CtEdge` считает по ней `idle`). Место ей рядом с носителем, а потребитель появляется в Task 10; писать её раньше значило бы оставить мёртвое звено на три задачи вместо одной.

- [ ] **Step 1: Написать падающий тест**

```rust
/// Выключенный acct — факт о машине, и человеку говорят, чем его включить: без счётчиков приборы
/// края видят нули при зелёной сборке.
#[test]
fn accounting_error_names_the_fix() {
    let message = format!("{}", PreflightError::NoAccounting);
    assert!(message.contains("nf_conntrack_acct"));
    assert!(message.contains("sysctl"), "рецепт починки, а не констатация");
}

/// База таймаута читается по состоянию: «сколько молчит» без неё не посчитать.
#[test]
fn timeout_base_is_named_per_state() {
    assert_eq!(sysctl_name(CtTcp::SynSent), "nf_conntrack_tcp_timeout_syn_sent");
    assert_eq!(sysctl_name(CtTcp::Established), "nf_conntrack_tcp_timeout_established");
}
```

- [ ] **Step 2: Прогнать — обязан упасть**

Run: `cargo test -p reflex-linux --features nfqueue preflight`
Expected: FAIL — вариантов нет.

- [ ] **Step 3: Реализовать**

К существующим проверкам добавить чтение `/proc/modules` на `nf_conntrack`, `/proc/sys/net/netfilter/nf_conntrack_acct` и `..._timestamp` (ожидается `1`), с текстами вида `Fix: sudo sysctl -w net.netfilter.nf_conntrack_acct=1`. `tcp_timeout_base` читает соответствующий файл и отдаёт `Duration` в секундах.

- [ ] **Step 4: Прогнать**

Run: `cargo test --workspace`
Expected: PASS.

- [ ] **Step 5: Коммит**

```bash
git add linux/src/nfqueue/preflight.rs
git commit -m "feat(linux): предпосылки края — conntrack, acct, timestamp, база таймаута"
```

---

### Task 9: Девятый закон — `certify::remembering`

**Files:**
- Create: `core/src/certify/remembering.rs`
- Modify: `core/src/certify/mod.rs`
- Modify: `linux/examples/certify.rs`
- Test: `core/tests/certify_remembering.rs`

**Interfaces:**
- Consumes: `CanRemember` (Task 4), `Terminal`, `Held`, `Verdict` (существующие).
- Produces:

```rust
pub trait Recaller { fn recall(&mut self) -> Option<u32>; }   // свидетель: читает марку ДРУГОЙ дверью
pub enum Broken { StateLost { asked: u32, found: u32 }, Clobbered { asked: u32, found: u32 } }
pub enum Invalid { NoConntrack, AnswerNotTaken }
pub fn remembers<T, R>(dut: &mut T, held: Held<T::Carrier>, state: u32, foreign: u32, recaller: &mut R) -> Verdict<Broken, Invalid>
where T: Terminal + CanRemember, R: Recaller + ?Sized;
```

- [ ] **Step 1: Написать падающие тесты**

```rust
/// Закон держится: отданное ядру вернулось.
#[test]
fn kernel_remembers_what_was_told() {
    let mut dut = Bench::taking();
    let mut recaller = Echo::returning(0x2000_1234);
    assert_eq!(
        remembers(&mut dut, held(), 0x0000_1234, 0x2000_0000, &mut recaller),
        Verdict::Held
    );
}

/// Вернулось не то — вина подопытного.
#[test]
fn a_lost_state_is_the_fault_of_the_device() {
    let mut recaller = Echo::returning(0x2000_0000);
    assert!(matches!(
        remembers(&mut Bench::taking(), held(), 0x1234, 0x2000_0000, &mut recaller),
        Verdict::Broken(Broken::StateLost { .. })
    ));
}

/// Наши биты встали, чужие стёрты — это отдельная вина, и она про соседей по машине.
#[test]
fn erasing_foreign_bits_is_its_own_fault() {
    let mut recaller = Echo::returning(0x0000_1234);
    assert!(matches!(
        remembers(&mut Bench::taking(), held(), 0x1234, 0x2000_0000, &mut recaller),
        Verdict::Broken(Broken::Clobbered { .. })
    ));
}

/// Свидетель не увидел записи вовсе — беда стенда, не подопытного.
#[test]
fn a_silent_witness_invalidates_the_run() {
    assert!(matches!(
        remembers(&mut Bench::taking(), held(), 0x1234, 0, &mut Echo::silent()),
        Verdict::Invalid(Invalid::NoConntrack)
    ));
}
```

- [ ] **Step 2: Прогнать — обязан упасть**

Run: `cargo test -p reflex-core --test certify_remembering`
Expected: FAIL — `remembers` не найден.

- [ ] **Step 3: Реализовать**

`remembers` отдаёт `dut.apply(held.answered(T::remember(state, true)))`, затем спрашивает свидетеля. Разбор исхода: свидетель молчит → `Invalid::NoConntrack`; наши биты не совпали → `Broken::StateLost`; наши совпали, чужие пропали → `Broken::Clobbered`; иначе `Held`.

В `linux/examples/certify.rs` добавить прогон закона на живом ядре: свидетелем служит `conntrack::Dump` — **другая дверь** (`NFNL_SUBSYS_CTNETLINK`), берущая те же байты у ядра, но не тем сокетом, каким писали.

- [ ] **Step 4: Прогнать**

Run: `cargo test --workspace && cargo build -p reflex-linux --features certify --example certify`
Expected: PASS + пример собирается.

**Живого прогона здесь нет, и это названо, а не забыто.** Закон требует ядра с включёнными `acct`/`timestamp` и правами; на машине разработки они выключены. Прогон закона на живом ядре — первый шаг стенда Task 10, ДО боевого A/B: если состояние не доезжает до ядра и не возвращается, сравнивать пути бессмысленно. До того момента девятый закон считается написанным, но не подтверждённым.

- [ ] **Step 5: Коммит**

```bash
git add core/src/certify/ core/tests/certify_remembering.rs linux/examples/certify.rs
git commit -m "feat(core): девятый закон — край помнит отданное состояние"
```

---

### Task 10: Боевой регресс-гейт (без сноса)

**Files:**
- Create: `examples/detect-silent-drop/src/edge.rs` (второй путь рядом с существующим)
- Modify: `examples/detect-silent-drop/src/main.rs`
- Test: боевой прогон на вантаже, результат — в описании коммита

**Interfaces:**
- Consumes: всё построенное выше.
- Produces: ничего для последующих задач; выход — доказательство.

- [ ] **Step 1: Собрать пример с обоими путями**

Существующий юзерспейсный путь НЕ трогается. Рядом поднимается второй, на `QueueSocket` + `EdgeSilence`, на своей очереди; оба печатают находки с пометкой пути.

- [ ] **Step 1.5: Поднять стенд и подтвердить девятый закон**

Стенд (docker, `NET_ADMIN`, своя netns): `sysctl -w net.netfilter.nf_conntrack_acct=1 net.netfilter.nf_conntrack_timestamp=1`, правило `queue num N`.

Сначала `certify remember` — девятый закон на живом ядре. Затем ТА ЖЕ проверка с мутацией `apply → verdict(id, accept, None)`: закон обязан покраснеть `Broken::StateLost`. Это закрывает дыру, оставленную сознательно на Task 4 (перевод решения в системный вызов тестами не покрывается).

Здесь же появляется `tcp_timeout_base` рядом с `CtEdge` — у него наконец есть потребитель, и гейт «ноль предупреждений» на обеих фичах проверяется в этой задаче.

- [ ] **Step 2: Прогнать на вантаже**

Run: стенд на реальном ТСПУ, цели `rutracker.org` и `vk.com`, не меньше 20 попыток на цель.
Expected: новый путь называет те же цели, что и старый. Расхождение — стоп, разбирать до совпадения.

- [ ] **Step 3: Замерить границу дропа ответа**

На том же прогоне посчитать цели, у которых `ClientHello` подтверждён (`up.packets > 0`), а данных от цели нет (`Distress::NoBytes` не сработал, соединение закрылось по `FIN` клиента). Это и есть доля дропа ОТВЕТА, помеченная в спеке как неизмеренная.

- [ ] **Step 4: Записать результат**

```bash
git add examples/detect-silent-drop/
git commit -m "test(lab): боевой A/B ядерного пути против юзерспейсного

Прогон на <вантаж>, <N> попыток: совпадение находок <..>.
Доля дропа ответа: <..> — граница из спеки измерена."
```

- [ ] **Step 5: Гейт**

Гейт зелёный, только если новый путь поймал всё, что поймал старый. Красный гейт запрещает Задачу 10 целиком.

---

### Task 11: Снос юзерспейсного состояния

**Files:**
- Modify: `reflex/src/lib.rs` (убрать `FlowTable`, `MIN_IDLE`, фанаут тиков по ключам)
- Modify: `instrument/src/detect.rs` (снять состояние приборов, переведённых на край)
- Test: существующие тесты фасада и приборов

**Interfaces:**
- Consumes: зелёный гейт Задачи 10.
- Produces: ничего.

- [ ] **Step 1: Убедиться, что гейт зелёный**

Run: `git log --oneline -5` — коммит гейта на месте, в его описании совпадение находок.
Expected: если нет — остановиться, Задача 11 не выполняется.

- [ ] **Step 2: Снять таблицу приборов**

`FlowTable::<Probes, FlowKey>` уходит; приборы живут одним экземпляром. `idents` **остаётся** — имя цели не состояние автомата; срок его жизни кроет горизонт клиентской активности.

- [ ] **Step 3: Прогнать**

Run: `cargo test --workspace`
Expected: PASS.

- [ ] **Step 4: Повторить боевой прогон**

Run: тот же стенд, что в Задаче 10.
Expected: находки те же.

- [ ] **Step 5: Коммит**

```bash
git add reflex/src/lib.rs instrument/src/detect.rs
git commit -m "refactor(reflex): юзерспейс zero-state — таблица приборов снесена"
```
