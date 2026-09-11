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

// ─── ЗАКОН НАБОРА: МОЛЧАЩАЯ ЦЕПОЧКА НЕ ДЕРЖИТ ГОВОРЯЩУЮ ─────────────────────────────────────────
//
// Замер, которым закон оплачен: две цепочки рядом клали трафик НАСМЕРТЬ. Пустая цепочка выжигала
// свой срок целиком, пакеты соседки стояли в очереди ядра и вытаймаучивались у клиента —
// `www.google.com` отвечал за 0,35 с в одиночку и не отвечал НИ РАЗУ в наборе.
//
// Бумажный носитель этого поймать не может: его часы двигаются скачком, он не ждёт по-настоящему.
// Потому здесь свой — он ЖДЁТ реально, как ждёт очередь ядра на пустом сокете.

use std::time::{Duration, Instant};

use reflex_core::held::{Answered, Delivered, Held, Refused, Terminal};
use reflex_core::local::Local;
use reflex_core::serves::{Served, Serves};
use reflex_instrument::edge::Layout;

/// НОСИТЕЛЬ, КОТОРЫЙ ЖДЁТ. Работы у него нет никогда: его предмет — молчание, выдержанное честно.
struct Dozing {
    /// Сколько оборотов ещё выдержать, прежде чем сказать «работы не будет никогда». Потолок, а не
    /// вечность: набор обязан кончиться, иначе тест висит вместо того, чтобы падать.
    turns: u32,
}

/// Край, ничего не ведущий: предмет теста — ОЖИДАНИЕ, и настоящий край занял бы в нём место
/// предмета.
#[derive(Debug, Clone, Copy)]
struct Blank;

impl reflex_core::edge::EdgeView for Blank {
    fn down_packets(&self) -> Option<u64> { None }
    fn up_packets(&self) -> Option<u64> { None }
    fn down_bytes(&self) -> Option<u64> { None }
    fn up_bytes(&self) -> Option<u64> { None }
    fn idle(&self) -> Option<Duration> { None }
    fn age(&self) -> Option<Duration> { None }
    fn mark(&self) -> u32 { 0 }
}

#[derive(Debug)]
enum Never {}

impl Terminal for Dozing {
    type Carrier = Vec<u8>;
    type Answer = ();
    type Refusal = Never;

    fn apply(&mut self, answered: Answered<Vec<u8>, ()>) -> Result<Delivered<()>, Refused<(), Never>> {
        Ok(Delivered { at: answered.at, answer: answered.answer })
    }
}

impl reflex_core::capability::CanHold for Dozing {
    fn release() {}
}

impl reflex_core::capability::CanRefuse for Dozing {
    fn refuse() {}
}

impl Serves for Dozing {
    type Edge = Blank;

    fn serve<F>(&mut self, until: Instant, _decide: F) -> Served<Delivered<()>, Refused<(), Never>>
    where
        F: FnOnce(&Held<Vec<u8>>, Option<Blank>) -> (),
    {
        // ЖДЁМ ЧЕСТНО — ровно то, что делает очередь ядра на пустом сокете: спит до срока и
        // возвращается ни с чем. Закон срока соблюдён: раньше `until` не вернулись.
        let now = Instant::now();
        if until > now {
            std::thread::sleep(until - now);
        }
        self.turns = self.turns.saturating_sub(1);
        Served::Idle
    }

    fn exhausted(&self) -> bool {
        self.turns == 0
    }
}

struct Dozes;

impl IntoCarrier for Dozes {
    type Carrier = Local<Dozing>;

    fn open(self) -> Result<Local<Dozing>, Cause> {
        Ok(Local::new(Dozing { turns: 200 }))
    }

    fn layout(&self) -> Layout {
        Layout::preset()
    }

    fn name(&self) -> String {
        "дремлющий носитель".to_string()
    }
}

/// ПРЕДМЕТ: молчащая цепочка не держит говорящую дольше ЛОМТЯ.
///
/// Без потолка ожидания говорящая цепочка ждала бы полного срока молчащей на КАЖДОМ показании — в
/// поле это означало переполнение очереди ядра и убитый трафик, а здесь означало бы секунды вместо
/// миллисекунд.
#[test]
fn молчащая_цепочка_не_держит_говорящую() {
    let говорящая = Paper::new()
        .then_packet(syn(40007))
        .then_packet(request(40007))
        .then_packet(request(40007))
        .then_packet(request(40007))
        .then_stop();

    let started = Instant::now();
    let heard: Vec<Note> = together()
        .chain(engine(Dozes).from(Tcp).extract(Sni).detect(own(Always)))
        .chain(engine(говорящая).from(Tcp).extract(Sni).detect(paper::Crier::always()))
        .heard()
        .take(3)
        .collect();
    let spent = started.elapsed();

    assert_eq!(heard.len(), 3, "говорящая цепочка обязана быть услышана");
    assert!(
        spent < Duration::from_millis(150),
        "три показания не должны стоить трёх сроков молчащей соседки: вышло {spent:?}"
    );
}
