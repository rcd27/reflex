//! Терминал очереди: переполнение — величина, а не молчание; способность помнить строится тем же
//! словом, что и вердикт; край спрашивается у носителя, не у бэкенда. Сокет-IO здесь не
//! проверяется (нужно живое ядро — девятый закон), только чистые части: разбор errno, сборка
//! ответа и `Edging`.

use std::time::Duration;

use reflex_core::edge::EdgeView;
use reflex_core::held::Edging;
use reflex_linux::conntrack::CtView;
use reflex_linux::queue::{Answer, Held, Packet, QueueError, TimeoutBase};

/// `ENOBUFS` — величина, а не молчание: ядро сказало, что пакеты потеряны, и это знание нужно
/// прибору (сравнение оттиска через разрыв недоверенно). Прочее errno — обычный отказ приёма.
#[test]
fn overrun_is_a_value() {
    assert_eq!(QueueError::from_errno(libc::ENOBUFS), QueueError::Overrun);
    assert_eq!(
        QueueError::from_errno(libc::EPERM),
        QueueError::Recv(libc::EPERM)
    );
}

/// Способность помнить строится тем же словом, каким отвечает очередь: пятое слово молча не завести.
#[test]
fn remembering_is_one_word_with_the_verdict() {
    let answer = <reflex_linux::queue::QueueSocket as reflex_core::capability::CanRemember>::remember(
        0x1234, true,
    );
    assert_eq!(
        answer,
        Answer::Remembered {
            accept: true,
            state: 0x1234
        }
    );
}

/// Пакет с видом ядра (`NFQA_CT` пришёл) — марка носителя не влияет на конструкцию края, ct есть.
fn packet_with_ct(mark: u32) -> Packet {
    Packet {
        id: 1,
        payload: Vec::new(),
        nfmark: 0,
        ct: Some(CtView {
            mark,
            ..CtView::default()
        }),
    }
}

/// Пакет без вида ядра — поток вне таблицы conntrack (первый `SYN`, счёт ещё не завёлся).
fn packet_without_ct() -> Packet {
    Packet {
        id: 1,
        payload: Vec::new(),
        nfmark: 0,
        ct: None,
    }
}

/// Край спрашивается у носителя сообщения. `None` — поток ещё не в conntrack (первый `SYN` вне
/// таблицы): «не считали», а не «не ответила» (§7). Ноль здесь соврал бы о тишине.
#[test]
fn край_берётся_у_носителя_а_вне_учтённый_поток_даёт_none() {
    let base = TimeoutBase {
        syn_sent: Duration::from_secs(120),
        established: Duration::from_secs(432000),
    };

    let counted = Held::new(packet_with_ct(0xDEAD_BEEF), base);
    assert_eq!(counted.edge().map(|edge| edge.mark()), Some(0xDEAD_BEEF));

    let uncounted = Held::new(packet_without_ct(), base);
    assert!(uncounted.edge().is_none());
}
