//! ПРОПУСКНАЯ СПОСОБНОСТЬ ЦЕПОЧКИ — число, а не вера.
//!
//! Заведён поводом: потребитель замерил 10,4% юзердропов на браузерной нагрузке (7119 пакетов в
//! очереди, 740 потеряно), и первым подозреваемым была цена нашего оборота. Число сняло
//! подозрение — и тем указало на настоящую причину: ведущий цикл отдан потребителю, и пока он
//! думает над показанием, очередь не разбирается.
//!
//! Тест держит порядок величины, а не точное число: он обязан покраснеть, если цена оборота
//! вырастет на ПОРЯДОК (лишний разбор на пакет, копия провода, аллокация на букву), и не обязан
//! реагировать на шум машины. Гоняется в отладочной сборке тоже — там медленнее, потому порог
//! низкий.

#[test]
fn пропускная_способность_цепочки() {
    use reflex::*;
    use reflex_core::builder::TcpBuilder;
    use reflex_core::types::{Flow, Protocol, TcpFlags};
    use std::net::SocketAddr;

    fn recording(frames: &[(u32, Vec<u8>)]) -> Vec<u8> {
        let head: Vec<u8> = [0xd4u8, 0xc3, 0xb2, 0xa1].into_iter()
            .chain([2, 0, 4, 0]).chain([0; 8])
            .chain(65535u32.to_le_bytes()).chain(1u32.to_le_bytes()).collect();
        frames.iter().fold(head, |acc, (micros, body)| {
            acc.into_iter()
                .chain((1_756_000_000 + micros / 1_000_000).to_le_bytes())
                .chain((micros % 1_000_000).to_le_bytes())
                .chain((body.len() as u32).to_le_bytes())
                .chain((body.len() as u32).to_le_bytes())
                .chain(body.iter().copied()).collect()
        })
    }

    // Сто разговоров по двадцать пакетов. Меньше, чем страница браузера (там их вдвадцатеро
    // больше), но довольно: предмет — ЦЕНА ОДНОГО оборота, а она не зависит от длины корпуса.
    // Больше стоило бы сорока секунд на каждом прогоне дерева — налог, которого предмет не стоит.
    let mut frames: Vec<(u32, Vec<u8>)> = Vec::new();
    for talk in 0..100u32 {
        let flow = Flow {
            src: format!("10.0.0.5:{}", 40000 + (talk % 20000) as u16).parse::<SocketAddr>().unwrap(),
            dst: "93.184.216.34:443".parse::<SocketAddr>().unwrap(),
            protocol: Protocol::Tcp,
        };
        let hello = reflex_core::tls::build_client_hello("example.com");
        for step in 0..20u32 {
            let at = talk * 1000 + step * 50;
            let body = TcpBuilder::new().flow(&flow).seq(1 + step * 100).ack(0)
                .flags(TcpFlags::PSH | TcpFlags::ACK).ttl(64)
                .payload(if step == 0 { &hello } else { b"payload-payload-payload" })
                .build().serialize();
            frames.push((at, body));
        }
    }
    let total = frames.len();
    let path = std::env::temp_dir().join(format!("reflex-bench-{}.pcap", std::process::id()));
    std::fs::write(&path, recording(&frames)).unwrap();

    let started = std::time::Instant::now();
    let heard: usize = pcap(&path)
        .from(Tcp).extract(Sni)
        .detect(Retransmit::unanswered())
        .detect(Silence::after(secs(5)))
        .detect(Rst::seen())
        .detect(Unreached::answers())
        .detect(Dismissed::without_a_word())
        .heard().expect("носитель открылся")
        .count();
    let spent = started.elapsed();

    let rate = total as f64 / spent.as_secs_f64();
    eprintln!("кадров {total}, показаний {heard}, время {spent:?} → {rate:.0} пакетов/с");
    std::fs::remove_file(&path).ok();

    // Порог — порядок величины, а не рекорд. Замер на этой машине: 678 тысяч пакетов в секунду в
    // релизе, десятки тысяч в отладке. Двадцать тысяч отделяют «цена оборота не при чём» от
    // «оборот стал причиной»: на браузерной нагрузке в две тысячи пакетов в секунду запас
    // десятикратный.
    assert!(
        rate > 20_000.0,
        "цена оборота выросла на порядок — очередь начнёт ронять пакеты: {rate:.0} пакетов/с"
    );
}
