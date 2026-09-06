//! ПОРТИРУЕМОСТЬ ЦЕПОЧЕК МЕЖДУ БЭКЕНДАМИ (#295, срез 4).
//!
//! Vision §3.2 обещает: смена backend не требует изменения frontend. Проверяется буквально — ОДНА
//! функция-цепочка исполняется над ДВУМЯ разными бэкендами, и её текст при этом не меняется.
//!
//! Настоящие бэкенды здесь не годятся: они требуют root, интерфейса и живой сети. Поэтому берутся
//! два игрушечных — но связь с настоящими проверена компиляцией: `AfPacketBackend` и
//! `TcAfPacketBackend` реализуют те же `Source`/`Sink`.

use futures::{stream, StreamExt};
use reflex_core::backend::{observing, Sink, Source};
use reflex_core::capability::{CanDrop, CanInject, CanObserve};
use reflex_core::category::{from_source, Terminal};
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

    pub fn reset() {
        SENT.store(0, Ordering::SeqCst)
    }
    pub fn add(n: u32) {
        SENT.fetch_add(n, Ordering::SeqCst);
    }
    pub fn total() -> u32 {
        SENT.load(Ordering::SeqCst)
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

/// ДРУГОЙ бэкенд: другой источник, другая ошибка — и та же цепочка поверх.
struct Recorded;
impl CanObserve for Recorded {}
impl Source for Recorded {
    type Packet = u8;
    type Packets<'a> = stream::Iter<std::vec::IntoIter<u8>>;
    fn packets(&mut self) -> Self::Packets<'_> {
        stream::iter(vec![9u8, 9])
    }
}
impl Sink for Recorded {
    type Command = Vec<u8>;
    type Error = String;
    fn emit(&mut self, command: Vec<u8>) -> Result<(), String> {
        counting::add(command.len() as u32 * 10);
        Ok(())
    }
}
impl CanInject for Recorded {
    fn inject(packet: reflex_core::command::InjectablePacket) -> Vec<u8> {
        packet.serialize()
    }
}

/// ТРЕТИЙ БЭКЕНД — С АЛГЕБРАИЧЕСКОЙ КОМАНДОЙ, как у настоящего `TcAfPacketBackend`.
///
/// Заведён потому, что двух первых НЕ ХВАТАЛО для того, что тест обещает названием. Оба несли
/// `Command = Vec<u8>`, и цепочка была написана под этот тип — то есть «одна цепочка над двумя
/// бэкендами» держалось на том, что бэкенды совпадают в единственном месте, где им позволено
/// различаться. Принцип непрозрачности (vision §1.3) обещает обратное: пользователю безразлично,
/// каким системным механизмом команда доедет до сети.
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

/// ОДНА ЦЕПОЧКА, ЛЮБОЙ БЭКЕНД. Текст функции не знает, над чем исполняется.
async fn run_over<B>(backend: &mut B) -> Terminal
where
    B: Source<Packet = u8> + CanObserve + CanInject + Clone,
    for<'a> B::Packets<'a>: Unpin,
{
    let sink = backend.clone();
    from_source(backend)
        .map_signals(|byte| byte > 4)
        .classify(|big| match big {
            true => 2u32,
            false => 1,
        })
        .react(|weight| weight)
        // КОМАНДУ СТРОИТ САМ БЭКЕНД, а цепочка её типа не знает. Прежде здесь стоял литерал
        // `vec![0u8; …]` — то есть текст цепочки утверждал, что команда бэкенда есть байты.
        // Через `B::inject` это утверждение исчезает: домен говорит «отправить вот этот пакет»,
        // а чем оно станет — `Vec<u8>`, вариантом энума или вердиктом очереди — дело функтора.
        .materialize(|weight: u32| {
            B::inject(reflex_core::command::InjectablePacket::Raw(vec![
                0u8;
                weight as usize
            ]))
        })
        .inject_into(sink)
        .drive()
        .await
}

impl Clone for Loopback {
    fn clone(&self) -> Self {
        Loopback
    }
}
impl Clone for Recorded {
    fn clone(&self) -> Self {
        Recorded
    }
}

#[tokio::test]
async fn the_same_chain_runs_over_two_different_backends() {
    counting::reset();
    let end = run_over(&mut Loopback).await;
    assert_eq!(end, Terminal);
    assert_eq!(
        counting::total(),
        1 + 2,
        "цепочка над первым бэкендом не отработала"
    );

    counting::reset();
    run_over(&mut Recorded).await;
    assert_eq!(
        counting::total(),
        20 + 20,
        "та же цепочка над другим бэкендом дала не его результат"
    );

    // ТРЕТИЙ БЭКЕНД НЕ СОВПАДАЕТ С ПЕРВЫМИ ДВУМЯ ТИПОМ КОМАНДЫ, и это ГЛАВНАЯ проверка файла:
    // пока цепочка требовала `Command = Vec<u8>`, она знала о бэкенде ровно то, чего знать не
    // должна. Совпадение двух первых по типу команды делало прежний тест зелёным вакуумно.
    counting::reset();
    run_over(&mut Verdicting).await;
    assert_eq!(
        counting::total(),
        100 + 200,
        "цепочка не перенеслась на бэкенд с алгебраической командой"
    );
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
