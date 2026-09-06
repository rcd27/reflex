//! ПОРТИРУЕМОСТЬ ЦЕПОЧЕК МЕЖДУ БЭКЕНДАМИ (#295, срез 4).
//!
//! Vision §3.2 обещает: смена backend не требует изменения frontend. Проверяется буквально — ОДНА
//! функция-цепочка исполняется над ДВУМЯ разными бэкендами, и её текст при этом не меняется.
//!
//! Настоящие бэкенды здесь не годятся: они требуют root, интерфейса и живой сети. Поэтому берутся
//! два игрушечных — но связь с настоящими проверена компиляцией: `AfPacketBackend` и
//! `TcAfPacketBackend` реализуют те же `Source`/`Sink`.
//!
//! ДВЕ ЗАЯВКИ ЗДЕСЬ БОЛЬШЕ НЕ ПРОВЕРЯЮТСЯ, и это названо, а не забыто.
//!
//! `category::Injection` держал ТИПОМ запрет «оператор после инъектора»: он не реализовывал
//! `Stream`, и операторы до него не дотягивались. Вместе с категорией стадий уходит и он.
//!
//! Тест `the_same_chain_runs_over_two_different_backends` предъявлял ПЕРЕНОСИМОСТЬ — «одна и та
//! же цепочка идёт над двумя разными бэкендами», обещание третьего vision §3.2.
//!
//! Обе возвращаются в плане алфавита, и первая — сильнее: в замыкании движка инъекция перестаёт
//! быть морфизмом цепочки вовсе. Цепочка отдаёт СЛОВО, применяет его драйвер; продолжать нечего,
//! потому что продолжать не за чем. Вторая возвращается тем же планом: цепочка есть значение,
//! бэкенды суть драйверы, и переносимость становится свойством, а не тестом.

use futures::{stream, StreamExt};
use reflex_core::backend::{observing, Sink, Source};
use reflex_core::capability::{CanDrop, CanInject, CanObserve};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

/// Бэкенд, складывающий отправленное в общий счёт: сеть в тесте не нужна, нужен факт отправки.
mod counting {
    use std::sync::atomic::{AtomicU32, Ordering};
    pub static SENT: AtomicU32 = AtomicU32::new(0);

    /// Порт последнего заглушённого потока. Отдельный склад, а не общий счёт: смешивать «сколько
    /// отправлено» с «кого заглушили» значило бы делать два показания неразличимыми.
    pub static SILENCED_PORT: AtomicU32 = AtomicU32::new(0);

    pub fn silence(port: u16) {
        SILENCED_PORT.store(port as u32, Ordering::SeqCst)
    }
    pub fn silenced() -> u32 {
        SILENCED_PORT.load(Ordering::SeqCst)
    }

    pub fn add(n: u32) {
        SENT.fetch_add(n, Ordering::SeqCst);
    }
}

struct Loopback;
impl CanObserve for Loopback {}
impl Source for Loopback {
    type Packet = u8;
    type Packets<'a> = stream::Iter<std::vec::IntoIter<u8>>;
    fn packets(&mut self) -> Self::Packets<'_> {
        stream::iter(vec![1u8, 5])
    }
}
impl Sink for Loopback {
    // КОМАНДА НЕСЁТ КАДР, А НЕ ВЕС. Прежде здесь стоял `u32`, и заявление `CanInject` было
    // выразимо над стоком, которым пакет физически не отправишь. С обязательством `inject`
    // такой сток больше не собирается — игрушка обязана быть честной ровно так же, как живой
    // бэкенд: привилегированной категории «это же тест» не существует.
    type Command = Vec<u8>;
    type Error = ();
    fn emit(&mut self, command: Vec<u8>) -> Result<(), ()> {
        counting::add(command.len() as u32);
        Ok(())
    }
}
impl CanInject for Loopback {
    fn inject(packet: reflex_core::command::InjectablePacket) -> Vec<u8> {
        packet.serialize()
    }
}

/// БЭКЕНД С АЛГЕБРАИЧЕСКОЙ КОМАНДОЙ, как у настоящего `TcAfPacketBackend`.
///
/// # Почему команда не `Vec<u8>`, и почему это важно
///
/// Сток, принимающий байты, о непрозрачности не свидетельствует НИЧЕГО: цепочка над ним написана
/// под тот же `Vec<u8>`, и совпадение бэкендов в единственном месте, где им позволено
/// различаться, выдаётся за переносимость. Принцип непрозрачности (vision §1.3) обещает
/// обратное — пользователю безразлично, каким системным механизмом команда доедет до сети, — и
/// проверить это можно только там, где команда БАЙТАМИ НЕ ЯВЛЯЕТСЯ.
///
/// ЗАВЕДЁН ОН БЫЛ ТРЕТЬИМ, при снесённой стадийной категории и её тесте «одна цепочка над двумя
/// бэкендами» (06.09.2026): двух прежних не хватало, оба несли `Command = Vec<u8>`. Тест ушёл,
/// причина осталась.
#[derive(Debug, Clone)]
enum Verdict {
    Send(Vec<u8>),
    Silence(reflex_core::types::Flow),
}

struct Verdicting;
impl CanObserve for Verdicting {}
impl Source for Verdicting {
    type Packet = u8;
    type Packets<'a> = stream::Iter<std::vec::IntoIter<u8>>;
    fn packets(&mut self) -> Self::Packets<'_> {
        stream::iter(vec![2u8, 8])
    }
}
impl Sink for Verdicting {
    type Command = Verdict;
    type Error = ();
    fn emit(&mut self, command: Verdict) -> Result<(), ()> {
        match command {
            Verdict::Send(bytes) => counting::add(bytes.len() as u32 * 100),
            // ПОТОК ЧИТАЕТСЯ, а не игнорируется: сток, которому дали дроп и который не посмотрел,
            // КОГО ронять, зелен ровно так же, как честный. Отличить их можно только показанием.
            Verdict::Silence(flow) => counting::silence(flow.dst.port()),
        }
        Ok(())
    }
}
impl CanInject for Verdicting {
    fn inject(packet: reflex_core::command::InjectablePacket) -> Verdict {
        Verdict::Send(packet.serialize())
    }
}
impl CanDrop for Verdicting {
    fn drop_flow(flow: reflex_core::types::Flow) -> Verdict {
        Verdict::Silence(flow)
    }

    fn clear_flow(flow: reflex_core::types::Flow) -> Verdict {
        Verdict::Silence(flow)
    }
}
impl Clone for Verdicting {
    fn clone(&self) -> Self {
        Verdicting
    }
}

impl Clone for Loopback {
    fn clone(&self) -> Self {
        Loopback
    }
}

/// СПОСОБНОСТЬ РОНЯТЬ ВЫРАЗИМА И ДОХОДИТ ДО СТОКА.
///
/// До 05.09.2026 `CanDrop` был пустым маркером, и такого теста нельзя было написать вовсе: не
/// существовало значения, которым дроп выражается. Здесь проверяется первая половина — что
/// команда СТРОИТСЯ и сток её ПОЛУЧАЕТ. Вторая половина — что пакет действительно не доехал —
/// типом не выражается и остаётся закону на живом устройстве.
#[tokio::test]
async fn drop_is_expressible_and_reaches_the_sink() {
    let flow = reflex_core::types::Flow {
        src: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 51_000),
        dst: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 443),
        protocol: reflex_core::types::Protocol::Tcp,
    };

    counting::silence(0);
    let sent = Verdicting.emit(Verdicting::drop_flow(flow));

    assert_eq!(sent, Ok(()), "сток не принял команду дропа");
    assert_eq!(
        counting::silenced(),
        443,
        "сток получил дроп, но не посмотрел, КОГО ронять"
    );
}

/// ДВЕРЬ К НАБЛЮДЕНИЯМ ТРЕБУЕТ ЗАЯВЛЕННОЙ СПОСОБНОСТИ, и это проверяет компилятор.
///
/// Прежде проверка стояла в двух местах и делала одно и то же. Две записи одной идеи расходятся
/// молча; здесь она одна.
///
/// БЕРЁТСЯ СУЩЕСТВУЮЩАЯ ФИКСТУРА, а не заводится своя: четвёртый памятный бэкенд рядом с тремя
/// такими же был бы ровно тем дублированием, которое эта задача и снимает — только в тестах.
#[tokio::test]
async fn observing_takes_packets_from_a_declared_observer() {
    let mut backend = Loopback;
    let seen: Vec<u8> = observing(&mut backend).collect().await;

    assert_eq!(seen, vec![1u8, 5], "все пакеты дошли до потребителя");
}
