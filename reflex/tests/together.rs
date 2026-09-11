//! НЕСКОЛЬКО ЦЕПОЧЕК РЯДОМ — объявление, которое читается как одно целое.
//!
//! Предмет не в удобстве. У знания ОДИН владелец: две цепочки, отданные двум нитям, дают два
//! порядка событий, и потребитель, сводящий их в одно знание, обязан завести замок — то есть
//! вернуть ровно то, от чего уходили дверью показаний. Набор крутится в ОДНОЙ нити.
//!
//! Замер, которым это заказано: у продукта три транспорта (TCP 443, UDP 53, UDP 443), каждый
//! требует своей цепочки — словарь провода разный, носитель уезжает в цепочку целиком, одну очередь
//! двум не поделить. Каждая забирала нить, и цепочки расползлись по файлу тремя нитяными
//! обвязками: человек, открывший продукт, видел обвязки, а не устройство.

mod paper;

use paper::{request, syn, Paper};
use reflex::*;

/// Прибор, говорящий на каждом пакете. Свой, а не из оснастки: у записи край иного рода, и прибор
/// оснастки, прибитый к бумажному краю, в такую цепочку не собирается.
#[derive(Clone, Copy, Default)]
struct Always;

impl Mealy for Always {
    type In = DetectorEvent<Seen>;
    type Out = SmallVec<[Distress; 2]>;
    type Log = ();

    fn step(self, event: Self::In) -> (Self, Self::Out, ()) {
        match event {
            DetectorEvent::Packet { .. } => (self, smallvec![Distress::NoBytes], ()),
            DetectorEvent::Tick { .. } | DetectorEvent::Opaque { .. } | DetectorEvent::Torn { .. } => {
                (self, SmallVec::new(), ())
            }
        }
    }
}

/// ПРЕДМЕТ: показания ДВУХ цепочек приходят одним потоком, в один цикл.
#[test]
fn показания_двух_цепочек_приходят_одним_потоком() {
    let heard: Vec<Note> = together()
        .chain(
            engine(Paper::new().then_packet(syn(40001)).then_packet(request(40001)).then_stop())
                .from(Tcp)
                .extract(Sni)
                .detect(paper::Crier::always()),
        )
        .chain(
            engine(Paper::new().then_packet(syn(40002)).then_packet(request(40002)).then_stop())
                .from(Tcp)
                .extract(Sni)
                .detect(paper::Crier::always()),
        )
        .heard()
        .collect();

    let ports: std::collections::BTreeSet<u16> =
        heard.iter().map(|note| note.flow.src.port()).collect();
    assert!(
        ports.contains(&40001) && ports.contains(&40002),
        "в одном потоке обязаны быть показания ОБЕИХ цепочек; пришли порты {ports:?}"
    );
}

/// ПРЕДМЕТ: отказ одной цепочки — ЗНАЧЕНИЕ, а не падение набора. Проглотить его значило бы тихо
/// уменьшить продукт; уронить набор — потерять работающие цепочки из-за одной.
#[test]
fn отказ_одной_цепочки_не_отменяет_прочих() {
    let together = together()
        // Запись, которой нет: носитель честно не откроется и скажет причину.
        .chain(
            pcap("нет-такого-файла.pcap")
                .from(Tcp)
                .extract(Sni)
                .detect(own(Always)),
        )
        .chain(
            engine(Paper::new().then_packet(syn(40003)).then_packet(request(40003)).then_stop())
                .from(Tcp)
                .extract(Sni)
                .detect(paper::Crier::always()),
        );

    assert_eq!(
        together.refused().len(),
        1,
        "отказавшая цепочка обязана быть названа, а не проглочена"
    );
    assert!(
        together.refused()[0].why().is_some(),
        "и названа ПРИЧИНОЙ, а не одним фактом отказа"
    );

    let heard: Vec<Note> = together.heard().collect();
    assert!(
        !heard.is_empty(),
        "живая цепочка обязана работать, несмотря на соседку"
    );
}

/// Набор кончается, когда кончились ВСЕ. Иначе цепочка, дочитанная первой, обрывала бы соседку на
/// полуслове — а у неё свой источник и свой срок.
#[test]
fn набор_кончается_когда_кончились_все() {
    let short = Paper::new().then_packet(syn(40004)).then_stop();
    let long = Paper::new()
        .then_packet(syn(40005))
        .then_packet(request(40005))
        .then_packet(request(40005))
        .then_stop();

    let heard: Vec<Note> = together()
        .chain(engine(short).from(Tcp).extract(Sni).detect(paper::Crier::always()))
        .chain(engine(long).from(Tcp).extract(Sni).detect(paper::Crier::always()))
        .heard()
        .collect();

    let from_long = heard
        .iter()
        .filter(|note| note.flow.src.port() == 40005)
        .count();
    assert!(
        from_long >= 2,
        "длинная цепочка обязана договорить: сказано ею {from_long}"
    );
}
