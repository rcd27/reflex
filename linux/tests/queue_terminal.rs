//! Терминал очереди: переполнение — величина, а не молчание; способность помнить строится тем же
//! словом, что и вердикт. Сокет-IO здесь не проверяется (нужно живое ядро — девятый закон), только
//! чистые части: разбор errno и сборка ответа.

use reflex_linux::queue::{Answer, QueueError};

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
