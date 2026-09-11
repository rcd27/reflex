//! ИМЯ ЦЕЛИ ПОДНИМАЕТСЯ, СКОЛЬКИМИ БЫ СЕГМЕНТАМИ НИ ПРИШЛО ПРИВЕТСТВИЕ.
//!
//! Замер, которым это оплачено (живой разговор, снятый и прогнанный обоими путями — боем через
//! очередь и прогоном по записи): приветствие 1561 байт, в первом сегменте 118, имя лежит дальше.
//! Оба пути назвали цель АДРЕСОМ, хотя в проводе есть имя. Дефект общий, не путевой.
//!
//! Цена хуже пропуска беды: продукт, лечащий по цели, метит АДРЕС — а на одном адресе живут чужие
//! имена, и в обход уводятся посторонние разговоры. Не «не увидели», а «навредили непричастному».
//!
//! Почему этого не видел никто: все фикстуры лаборатории сняты `curl`, чьё приветствие короткое
//! (517 байт) и влезает в один сегмент. Корпус, собранный одним клиентом, зелен по построению.

mod paper;

use paper::{log, segment, syn, taken, Paper};
use reflex::*;

/// Прибор, говорящий на каждом пакете: предмет — ИМЯ в реакции, а не пороги паркового прибора.
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

/// Имена, которые цепочка назвала реакции.
fn named(paper: Paper) -> Vec<String> {
    let heard = log::<String>();
    engine(paper)
        .from(Tcp)
        .extract(Sni)
        .detect(own(Always))
        .on(move |target: &str, _distress: Distress| {
            heard.lock().expect("слышно").push(target.to_string())
        })
        .run();
    taken(heard)
}

/// ПРЕДМЕТ: приветствие, разложенное по ТРЁМ сегментам, всё равно даёт имя. Имя лежит во втором —
/// ровно как у живого браузера.
#[test]
fn имя_поднимается_из_приветствия_в_нескольких_сегментах() {
    let hello = reflex_core::tls::build_client_hello("meduza.io");
    let (first, rest) = hello.split_at(40);
    let (second, third) = rest.split_at(rest.len() / 2);

    let said = named(
        Paper::new()
            .then_packet(syn(40001))
            .then_packet(segment(40001, 1, first))
            .then_packet(segment(40001, 1 + first.len() as u32, second))
            .then_packet(segment(
                40001,
                1 + (first.len() + second.len()) as u32,
                third,
            ))
            .then_stop(),
    );

    assert!(
        said.iter().any(|name| name == "meduza.io"),
        "имя обязано подняться из склеенного приветствия; названо: {said:?}"
    );
}

/// Вторая половина: приветствие в ОДНОМ сегменте работает как работало. Без неё первая зелена и на
/// цепочке, которая сломала короткий случай ради длинного.
#[test]
fn короткое_приветствие_в_одном_сегменте_как_прежде() {
    let hello = reflex_core::tls::build_client_hello("example.com");

    let said = named(
        Paper::new()
            .then_packet(syn(40002))
            .then_packet(segment(40002, 1, &hello))
            .then_stop(),
    );

    assert!(
        said.iter().any(|name| name == "example.com"),
        "короткое приветствие обязано работать как работало; названо: {said:?}"
    );
}

/// И третья: ДЫРА в приветствии имени не даёт — но и чужого не выдумывает. Склеенное через дыру
/// назвало бы ДРУГУЮ цель, а это хуже незнания: в обход уехал бы непричастный.
#[test]
fn дыра_в_приветствии_не_рождает_чужого_имени() {
    let hello = reflex_core::tls::build_client_hello("meduza.io");
    let (first, rest) = hello.split_at(40);
    let (_lost, tail) = rest.split_at(rest.len() / 2);

    let said = named(
        Paper::new()
            .then_packet(syn(40003))
            .then_packet(segment(40003, 1, first))
            // Средний сегмент потерян: следующий приходит с разрывом в номерах.
            .then_packet(segment(40003, 1 + (hello.len() - tail.len()) as u32, tail))
            .then_stop(),
    );

    assert!(
        !said.iter().any(|name| name == "meduza.io"),
        "через дыру имя не собирается — и выдумывать его нельзя; названо: {said:?}"
    );
}
