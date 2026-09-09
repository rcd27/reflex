//! # Тихий дроп по ЯДЕРНЫМ величинам — второй путь A/B (Task 10)
//!
//! Тот же тихий дроп, что ловит `detect-silent-drop`, но БЕЗ юзерспейсного состояния: тишина по
//! ПАКЕТНЫМ счётчикам conntrack (`up.packets` 0/1/≥2 — байтом нуля цель не даёт, заголовки), фаза и
//! оттиск живут в марке ядра. Юзерспейс zero-state. Ставится РЯДОМ с фасадным путём на СВОЕЙ очереди —
//! стенд гоняет оба и сверяет находки (регресс-гейт: ядерный путь обязан поймать всё, что ловит
//! юзерспейсный).
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
use reflex_instrument::edge::{Layout, Phase, Recall};
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
    // Окно возраста: цель молчит с открытия дольше окна — дроп. Две секунды шире худшего законного
    // ответа под нагрузкой (секунды не хватило: редкий медленный поток vk ложно кричал), но у́же
    // терпения клиента — на вечном дропе повторы идут до ~15 с, возраст порог перешагнёт с запасом.
    let silence: EdgeSilence<CtEdge> = EdgeSilence::new(Duration::from_secs(2), layout);

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

            // Часы дёргаются ЗДЕСЬ, на приходе пакета (§9): `seen` снимает возраст величиной, и прибор
            // часов уже не видит (§2), переигровка сходится (§10). Мир входит в систему одним местом.
            let edge = CtEdge::seen(view, base);
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
            // Трасса РИСКА: пока поток УЖЕ под подозрением, растёт ли счётчик ОТВЕТНЫХ пакетов между
            // нашими наблюдениями? Растёт при `up.bytes == 0` — спуфер `ACK` (ТСПУ так умеет) двигал
            // бы оттиск вечно и глушил подтверждение молча. `ct` вяжет строки одного потока.
            if let Recall::Ours(prior) = layout.read(view.mark) {
                if prior.phase == Phase::Suspected {
                    eprintln!(
                        "[trace] ct={} up_pk={} up_by={} dn_by={} imprint={}",
                        view.id, view.up.packets, view.up.bytes, view.down.bytes, prior.imprint
                    );
                }
            }

            let (_same, (memo, said), ()) =
                silence.step(DetectorEvent::packet_now(Edged { narrow, edge }));

            for distress in &said {
                println!("[край] {distress}");
            }
            // Памятка (если есть) уезжает в марку RMW — чужие биты целы; иначе марку не трогаем.
            let _ = socket.verdict(packet.id, true, memo.map(|memo| memo.apply_to(view.mark)));
        }
    }
}
