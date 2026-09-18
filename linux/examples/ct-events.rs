//! События conntrack вживую — прибор, не продукт: разговор родился, получил ответ, умер, и сколько
//! байт унёс. Сверяется с `curl` той же минуты.

use std::net::Ipv4Addr;

use reflex_linux::conntrack::{CtEvent, CtKind, DumpError, Events};

fn main() {
    match Events::open() {
        Err(why) => println!("ОТКАЗ {why:?}"),
        Ok(events) => {
            println!("подписан: NEW · UPDATE · DESTROY");
            loop {
                shown(events.next())
            }
        }
    }
}

fn shown(read: Result<Vec<CtEvent>, DumpError>) {
    match read {
        Err(why) => println!("ОТКАЗ ЧТЕНИЯ {why:?}"),
        Ok(happened) => happened.iter().for_each(|event| {
            println!(
                "{:?} {}:{} -> {}:{} proto {} ответ {} путь {:?} вниз {}Б",
                event.kind,
                Ipv4Addr::from(event.entry.orig.src),
                event.entry.orig.src_port,
                Ipv4Addr::from(event.entry.orig.dst),
                event.entry.orig.dst_port,
                event.entry.orig.proto,
                event.replied,
                event.entry.dst,
                match event.kind {
                    CtKind::Died => event.entry.reply_counts.bytes,
                    CtKind::Born | CtKind::Changed => 0,
                },
            )
        }),
    }
}
