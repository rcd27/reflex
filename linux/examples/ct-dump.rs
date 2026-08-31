//! Печать записей conntrack — прибор, не продукт. Нужен, чтобы разбор ctnetlink проверялся ЧУЖИМ
//! оракулом: числа, которые он печатает, сверяются с байтами, посланными заведомо.

use reflex_linux::conntrack::Dump;

fn main() {
    match Dump::open().and_then(|door| door.entries()) {
        Err(why) => println!("ОТКАЗ {:?}", why),
        Ok(found) => {
            println!("записей {}", found.len());
            found.iter().for_each(|entry| {
                println!(
                    "{}.{}.{}.{}:{} -> {}.{}.{}.{}:{} proto {} mark {} orig {}п/{}Б reply {}п/{}Б",
                    entry.orig.src >> 24,
                    (entry.orig.src >> 16) & 0xFF,
                    (entry.orig.src >> 8) & 0xFF,
                    entry.orig.src & 0xFF,
                    entry.orig.src_port,
                    entry.orig.dst >> 24,
                    (entry.orig.dst >> 16) & 0xFF,
                    (entry.orig.dst >> 8) & 0xFF,
                    entry.orig.dst & 0xFF,
                    entry.orig.dst_port,
                    entry.orig.proto,
                    entry.mark,
                    entry.orig_counts.packets,
                    entry.orig_counts.bytes,
                    entry.reply_counts.packets,
                    entry.reply_counts.bytes,
                );
            });
        }
    }
}
