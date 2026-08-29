//! ПОРТИРУЕМОСТЬ ЦЕПОЧЕК МЕЖДУ БЭКЕНДАМИ (#295, срез 4).
//!
//! Vision §3.2 обещает: смена backend не требует изменения frontend. Проверяется буквально — ОДНА
//! функция-цепочка исполняется над ДВУМЯ разными бэкендами, и её текст при этом не меняется.
//!
//! Настоящие бэкенды здесь не годятся: они требуют root, интерфейса и живой сети. Поэтому берутся
//! два игрушечных — но связь с настоящими проверена компиляцией: `AfPacketBackend` и
//! `TcAfPacketBackend` реализуют те же `Source`/`Sink`.

use futures::stream;
use reflex_core::backend::{Sink, Source};
use reflex_core::capability::{CanInject, CanObserve};
use reflex_core::category::{from_source, Terminal};

/// Бэкенд, складывающий отправленное в общий счёт: сеть в тесте не нужна, нужен факт отправки.
mod counting {
    use std::sync::atomic::{AtomicU32, Ordering};
    pub static SENT: AtomicU32 = AtomicU32::new(0);

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
impl CanInject for Loopback {}
impl Source for Loopback {
    type Packet = u8;
    type Packets<'a> = stream::Iter<std::vec::IntoIter<u8>>;
    fn packets(&mut self) -> Self::Packets<'_> {
        stream::iter(vec![1u8, 5])
    }
}
impl Sink for Loopback {
    type Command = u32;
    type Error = ();
    fn emit(&mut self, command: u32) -> Result<(), ()> {
        counting::add(command);
        Ok(())
    }
}

/// ДРУГОЙ бэкенд: другой источник, другая ошибка — и та же цепочка поверх.
struct Recorded;
impl CanObserve for Recorded {}
impl CanInject for Recorded {}
impl Source for Recorded {
    type Packet = u8;
    type Packets<'a> = stream::Iter<std::vec::IntoIter<u8>>;
    fn packets(&mut self) -> Self::Packets<'_> {
        stream::iter(vec![9u8, 9])
    }
}
impl Sink for Recorded {
    type Command = u32;
    type Error = String;
    fn emit(&mut self, command: u32) -> Result<(), String> {
        counting::add(command * 10);
        Ok(())
    }
}

/// ОДНА ЦЕПОЧКА, ЛЮБОЙ БЭКЕНД. Текст функции не знает, над чем исполняется.
async fn run_over<B>(backend: &mut B) -> Terminal
where
    B: Source<Packet = u8> + Sink<Command = u32> + CanObserve + CanInject + Clone,
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
        .materialize(|weight| weight)
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
}
