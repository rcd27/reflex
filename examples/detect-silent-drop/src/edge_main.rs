//! # Тихий дроп по ЯДЕРНЫМ величинам — второй путь A/B (Task 10)
//!
//! Тот же тихий дроп, что ловит `detect-silent-drop`, но БЕЗ юзерспейсного состояния: тишина по
//! счётчикам conntrack (`up_packets == 0`) и по `idle` (база − остаток), фаза/оттиск живут в марке
//! ядра. Юзерспейс zero-state. Ставится РЯДОМ с фасадным путём на СВОЕЙ очереди — стенд гоняет оба
//! и сверяет находки (регресс-гейт: ядерный путь обязан поймать всё, что ловит юзерспейсный).
//!
//! ## Запуск
//!
//! ```sh
//! sudo sysctl -w net.netfilter.nf_conntrack_acct=1 net.netfilter.nf_conntrack_timestamp=1
//! sudo nft 'add rule inet reflex_demo out tcp dport 443 queue num 201'
//! sudo ./detect-silent-drop-edge
//! ```

use std::process;
use std::time::Duration;

use reflex_core::mealy::Mealy;
use reflex_core::DetectorEvent;
use reflex_instrument::distress::Distress;
use reflex_instrument::edge::Layout;
use reflex_instrument::edge_detect::EdgeSilence;
use reflex_instrument::edge_word::Edged;
use reflex_instrument::wire::Seen;
use reflex_linux::conntrack::{CtEdge, TimeoutBase};
use reflex_linux::nfqueue::Waited;
use reflex_linux::queue::{Incoming, QueueSocket};

/// Своя очередь — не 200 фасадного пути: стенд гоняет оба одновременно.
const QUEUE: u16 = 201;
/// Маска марки — ПАРАМЕТР цепочки (15 бит: тег 4 + фаза 3 + оттиск 8), тег — наша подпись.
const MARK_MASK: u32 = 0x0FFF_E000;
const MARK_TAG: u8 = 0b101;

fn main() {
    let base = match TimeoutBase::read() {
        Some(base) => base,
        None => {
            eprintln!("[край] нет базы таймаута conntrack — включи nf_conntrack_* и повтори");
            process::exit(2);
        }
    };
    let layout = Layout::new(MARK_MASK, MARK_TAG).expect("15-битная маска, ненулевой тег");
    // Прибор Copy и без состояния: шаг возвращает тот же прибор, исход — только от края и марки.
    let silence: EdgeSilence<CtEdge> = EdgeSilence::new(Duration::from_secs(5), layout);

    let socket = match QueueSocket::open(QUEUE) {
        Ok(socket) => socket,
        Err(why) => {
            eprintln!("[край] сокет очереди {QUEUE}: {why:?}");
            process::exit(2);
        }
    };
    eprintln!("[край] слушаю очередь {QUEUE} на ядерных величинах (zero-state)");

    loop {
        if !matches!(socket.wait(1000), Waited::Ready) {
            continue;
        }
        let batch = match socket.recv() {
            Ok(batch) => batch,
            Err(why) => {
                // ENOBUFS не глотаем: переполнение — величина, не молчание.
                eprintln!("[край] приём: {why:?}");
                continue;
            }
        };
        for incoming in batch {
            let packet = match incoming {
                Incoming::Packet(packet) => packet,
                Incoming::Done | Incoming::Failed(_) => continue,
            };
            // Без ядерного вида судить не о чем — пропускаем пакет как есть.
            let Some(view) = packet.ct else {
                let _ = socket.verdict(packet.id, true, None);
                continue;
            };

            let edge = CtEdge { view, base };
            // Провод EdgeSilence не читает (решает по краю), но пара его требует — выводим номинально
            // из ядерных счётчиков: ответила цель (up) или спрашивал клиент (down).
            let narrow = match view.up.packets {
                0 => Seen::Sent {
                    count: view.down.packets as u32,
                },
                _answered => Seen::Received {
                    count: view.up.packets as u32,
                },
            };
            let (_same, said, ()) = silence.step(DetectorEvent::packet_now(Edged { narrow, edge }));

            let mut answered = false;
            for (distress, memo) in &said {
                if matches!(
                    distress,
                    Distress::NoBytes | Distress::Silence { .. } | Distress::Diverged { .. }
                ) {
                    println!("[край] {distress}");
                }
                if !answered {
                    // Памятка уезжает в марку RMW (чужие биты целы); пакет пропускаем.
                    let _ = socket.verdict(packet.id, true, Some(memo.apply_to(view.mark)));
                    answered = true;
                }
            }
            if !answered {
                let _ = socket.verdict(packet.id, true, None);
            }
        }
    }
}
