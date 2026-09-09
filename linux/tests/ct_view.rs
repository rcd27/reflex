//! `CtView` — вид края из тела `NFQA_CT`, чеканенный тем же разбором `CTA_*`, что и запись дампа.
//! Байты атрибутов собираются здесь руками: `netlink`-сборка крейт-приватна, а тест обязан кормить
//! разбор тем, что кладёт ядро.

use reflex_linux::conntrack::{view_of, CtEnds, CtTcp};

/// Один атрибут netlink: заголовок (длина без паддинга + тип) и тело, выровненное до четырёх.
fn tlv_bytes(kind: u16, body: &[u8]) -> Vec<u8> {
    let len = (4 + body.len()) as u16;
    let mut out = Vec::new();
    out.extend_from_slice(&len.to_ne_bytes());
    out.extend_from_slice(&kind.to_ne_bytes());
    out.extend_from_slice(body);
    while out.len() % 4 != 0 {
        out.push(0);
    }
    out
}

fn nested_raw(kind: u16, body: &[u8]) -> Vec<u8> {
    tlv_bytes(kind | 0x8000, body)
}

fn tlv_be32(kind: u16, value: u32) -> Vec<u8> {
    tlv_bytes(kind, &value.to_be_bytes())
}

fn tlv_be64(kind: u16, value: u64) -> Vec<u8> {
    tlv_bytes(kind, &value.to_be_bytes())
}

/// Тело NFQA_CT из атрибутов, как их кладёт ядро.
/// CTA_COUNTERS_PACKETS = 1, CTA_COUNTERS_ORIG = 9, CTA_COUNTERS_REPLY = 10,
/// CTA_MARK = 8, CTA_TIMEOUT = 7. Числа у ctnetlink — big-endian.
fn ct_body(mark: u32, orig_packets: u64, reply_packets: u64, timeout_secs: u32) -> Vec<u8> {
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

/// IPv6 РАЗБИРАЕТСЯ, но ключом не становится. Отдай на IPv6-потоке четвёрку по умолчанию — ВСЕ они
/// схлопнулись бы в один ключ при зелёной сборке. Отказ назван причиной, а не пустотой: незнание
/// обитаемо (§7). Шестнадцать байт вместо четырёх стоят нуля и оставляют будущей работе одно место.
#[test]
fn ipv6_ends_are_read_but_never_keyed() {
    // CTA_TUPLE_IP = 1, внутри CTA_IP_V6_SRC = 3 / CTA_IP_V6_DST = 4.
    let ipv6 = nested_raw(
        1,
        &[tlv_bytes(3, &[0x20; 16]), tlv_bytes(4, &[0x21; 16])].concat(),
    );
    let view = view_of(&nested_raw(1, &ipv6));
    assert!(
        matches!(view.ends, CtEnds::V6 { src, .. } if src == [0x20; 16]),
        "адреса разобраны, а не потеряны"
    );
    assert!(
        view.tuple.is_none(),
        "ключ из них не куётся: пакет уйдёт непонятым"
    );
}

/// Кортежа нет вовсе — тоже названное состояние, не нули.
#[test]
fn absent_ends_are_named_unknown() {
    assert!(matches!(view_of(&[]).ends, CtEnds::Unknown));
}

/// TCP-состояние по мнению ядра читается из вложенного `CTA_PROTOINFO`. Без этого теста путь разбора
/// `CTA_PROTOINFO → TCP → STATE` не покрыт ничем и зелен на любой поломке.
/// CTA_PROTOINFO = 4 → CTA_PROTOINFO_TCP = 1 → CTA_PROTOINFO_TCP_STATE = 1 (u8). Состояние 3 = ESTABLISHED.
#[test]
fn tcp_state_is_read_from_protoinfo() {
    let state = tlv_bytes(1, &[3]);
    let tcp = nested_raw(1, &state);
    let body = nested_raw(4, &tcp);
    assert_eq!(view_of(&body).tcp, Some(CtTcp::Established));
}
