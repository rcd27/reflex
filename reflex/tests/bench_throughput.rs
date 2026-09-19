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

use reflex::*;

/// Корпус и прогон общие у обоих замеров НАРОЧНО: у замера цены двери закреплено всё, кроме самой
/// двери, — иначе сравнивались бы два разных прогона, а не цена одного отличия.
fn corpus(name: &str) -> (std::path::PathBuf, usize) {
    use reflex_core::builder::TcpBuilder;
    use reflex_core::types::{Flow, Protocol, TcpFlags};
    use std::net::SocketAddr;

    fn recording(frames: &[(u32, Vec<u8>)]) -> Vec<u8> {
        let head: Vec<u8> = [0xd4u8, 0xc3, 0xb2, 0xa1]
            .into_iter()
            .chain([2, 0, 4, 0])
            .chain([0; 8])
            .chain(65535u32.to_le_bytes())
            .chain(1u32.to_le_bytes())
            .collect();
        frames.iter().fold(head, |acc, (micros, body)| {
            acc.into_iter()
                .chain((1_756_000_000 + micros / 1_000_000).to_le_bytes())
                .chain((micros % 1_000_000).to_le_bytes())
                .chain((body.len() as u32).to_le_bytes())
                .chain((body.len() as u32).to_le_bytes())
                .chain(body.iter().copied())
                .collect()
        })
    }

    // Сто разговоров по двадцать пакетов. Меньше, чем страница браузера (там их вдвадцатеро
    // больше), но довольно: предмет — ЦЕНА ОДНОГО оборота, а она не зависит от длины корпуса.
    // Больше стоило бы сорока секунд на каждом прогоне дерева — налог, которого предмет не стоит.
    let mut frames: Vec<(u32, Vec<u8>)> = Vec::new();
    for talk in 0..100u32 {
        let flow = Flow {
            src: format!("10.0.0.5:{}", 40000 + (talk % 20000) as u16)
                .parse::<SocketAddr>()
                .unwrap(),
            dst: "93.184.216.34:443".parse::<SocketAddr>().unwrap(),
            protocol: Protocol::Tcp,
        };
        let hello = reflex_core::tls::build_client_hello("example.com");
        for step in 0..20u32 {
            let at = talk * 1000 + step * 50;
            let body = TcpBuilder::new()
                .flow(&flow)
                .seq(1 + step * 100)
                .ack(0)
                .flags(TcpFlags::PSH | TcpFlags::ACK)
                .ttl(64)
                .payload(if step == 0 {
                    &hello
                } else {
                    b"payload-payload-payload"
                })
                .build()
                .serialize();
            frames.push((at, body));
        }
    }
    let total = frames.len();
    let path = std::env::temp_dir().join(format!("reflex-{name}-{}.pcap", std::process::id()));
    std::fs::write(&path, recording(&frames)).unwrap();
    (path, total)
}

/// Прогон корпуса цепочкой из пяти приборов. `law` — просить ли восьмой закон: ЕДИНСТВЕННОЕ
/// отличие между двумя замерами ниже.
fn ran(path: &std::path::Path, law: Option<Tap<Certified>>) -> std::time::Duration {
    let chain = pcap(path)
        .from(Tcp)
        .extract(Sni)
        .detect(Retransmit::unanswered())
        .detect(Silence::after(secs(5)))
        .detect(Rst::seen())
        .detect(Unreached::answers())
        .detect(Dismissed::without_a_word());
    let chain = match law {
        Some(tap) => chain.certifying(tap),
        None => chain,
    };
    let started = std::time::Instant::now();
    let _heard: usize = chain.heard().expect("носитель открылся").count();
    started.elapsed()
}

#[test]
fn the_throughput_of_a_chain() {
    let (path, total) = corpus("bench");

    let spent = ran(&path, None);

    let rate = total as f64 / spent.as_secs_f64();
    eprintln!("кадров {total}, время {spent:?} → {rate:.0} пакетов/с");
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

/// ЦЕНА ВОСЬМОГО ЗАКОНА — число, а не «дёшево».
///
/// Дверь `certifying` стоит трёх вещей: клона буквы провода в ленту, и — на каждом закрытом окне —
/// ДВУХ пере-подач его свежей семье машин. То есть работа приборов на окне утраивается, и цена эта
/// не разовая: у плотного пайпа окно в 64 буквы закрывается чаще раза в секунду.
///
/// Закон держит ПОРЯДОК, как и соседний замер: он обязан покраснеть, если цена двери вырастет
/// вдесятеро против нынешней, и не обязан отзываться на шум машины. Контроль закреплён — корпус,
/// цепочка и прогон общие, отличается только дверь (иначе сравнивались бы два разных прогона).
///
/// Замер на этой машине (отладка): без двери ~61 тыс. пакетов/с, с дверью ~37 тыс. — цена ×1,7 на
/// тридцати двух закрытых окнах.
///
/// Предсказание было ×3, и расхождение с замером объяснено, а не списано на шум: пере-подача гоняет
/// ТОЛЬКО приборы — буквы в ленте уже разобраны, — тогда как прогон несёт сверх того разбор провода,
/// носителя и слой. Утраивается, стало быть, не весь оборот, а его приборная часть.
///
/// Этим же замером найден дефект окна: прежде сверка стояла за приходом УЗЛА сетки, и на корпусе,
/// уместившемся в десятую долю секунды, свидетельство пришло ОДНО из двух тысяч букв — лента росла
/// до конца источника. Закон (`certifying.rs`) заведён отдельно; цена от починки не изменилась.
#[test]
fn the_price_of_the_eighth_law() {
    let (path, total) = corpus("bench-law");
    let (tx, testimony) = std::sync::mpsc::sync_channel::<Certified>(4096);

    let quiet = ran(&path, None);
    let judged = ran(&path, Some(Tap::new(tx)));
    std::fs::remove_file(&path).ok();

    let verdicts: Vec<Certified> = testimony.try_iter().collect();
    // ОРАКУЛ ОБЯЗАН БЫТЬ ЗРЯЧИМ (Правило 10.8): замер цены двери, которая не сработала ни разу,
    // мерил бы стоимость выключенного признака.
    assert!(
        !verdicts.is_empty(),
        "дверь обязана была сработать, иначе замеряется не она"
    );

    let times = total as f64 / quiet.as_secs_f64() / (total as f64 / judged.as_secs_f64());
    eprintln!(
        "без закона {:.0} пак/с, с законом {:.0} пак/с → цена ×{times:.1}, окон {}",
        total as f64 / quiet.as_secs_f64(),
        total as f64 / judged.as_secs_f64(),
        verdicts.len()
    );

    assert!(
        times < 30.0,
        "цена восьмого закона выросла на порядок против троекратной: ×{times:.1}"
    );
}
