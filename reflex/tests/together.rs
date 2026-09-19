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

use paper::{dns_query, request, syn, Paper};
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
            DetectorEvent::Tick { .. }
            | DetectorEvent::Opaque { .. }
            | DetectorEvent::Torn { .. } => (self, SmallVec::new(), ()),
        }
    }
}

/// ПРЕДМЕТ: показания ДВУХ цепочек приходят одним потоком, в один цикл.
#[test]
fn the_readings_of_two_chains_arrive_as_one_stream() {
    let heard: Vec<Note> = together()
        .chain(
            engine(
                Paper::new()
                    .then_packet(syn(40001))
                    .then_packet(request(40001))
                    .then_stop(),
            )
            .from(Tcp)
            .extract(Sni)
            .detect(paper::Crier::always()),
        )
        .chain(
            engine(
                Paper::new()
                    .then_packet(syn(40002))
                    .then_packet(request(40002))
                    .then_stop(),
            )
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
fn the_refusal_of_one_chain_does_not_cancel_the_rest() {
    let together = together()
        // Запись, которой нет: носитель честно не откроется и скажет причину.
        .chain(
            pcap("нет-такого-файла.pcap")
                .from(Tcp)
                .extract(Sni)
                .detect(own(Always)),
        )
        .chain(
            engine(
                Paper::new()
                    .then_packet(syn(40003))
                    .then_packet(request(40003))
                    .then_stop(),
            )
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
fn the_set_ends_when_every_chain_has_ended() {
    let short = Paper::new().then_packet(syn(40004)).then_stop();
    let long = Paper::new()
        .then_packet(syn(40005))
        .then_packet(request(40005))
        .then_packet(request(40005))
        .then_stop();

    let heard: Vec<Note> = together()
        .chain(
            engine(short)
                .from(Tcp)
                .extract(Sni)
                .detect(paper::Crier::always()),
        )
        .chain(
            engine(long)
                .from(Tcp)
                .extract(Sni)
                .detect(paper::Crier::always()),
        )
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
    fn down_packets(&self) -> Option<u64> {
        None
    }
    fn up_packets(&self) -> Option<u64> {
        None
    }
    fn down_bytes(&self) -> Option<u64> {
        None
    }
    fn up_bytes(&self) -> Option<u64> {
        None
    }
    fn idle(&self) -> Option<Duration> {
        None
    }
    fn age(&self) -> Option<Duration> {
        None
    }
    fn mark(&self) -> u32 {
        0
    }
}

#[derive(Debug)]
enum Never {}

impl Terminal for Dozing {
    type Carrier = Vec<u8>;
    type Answer = ();
    type Refusal = Never;

    fn apply(
        &mut self,
        answered: Answered<Vec<u8>, ()>,
    ) -> Result<Delivered<()>, Refused<(), Never>> {
        Ok(Delivered {
            at: answered.at,
            answer: answered.answer,
        })
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
fn a_silent_chain_does_not_hold_back_a_talking_one() {
    let talking = Paper::new()
        .then_packet(syn(40007))
        .then_packet(request(40007))
        .then_packet(request(40007))
        .then_packet(request(40007))
        .then_stop();

    let started = Instant::now();
    let heard: Vec<Note> = together()
        .chain(engine(Dozes).from(Tcp).extract(Sni).detect(own(Always)))
        .chain(
            engine(talking)
                .from(Tcp)
                .extract(Sni)
                .detect(paper::Crier::always()),
        )
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

/// ПРЕДМЕТ: цепочка СО СВЁРТКОЙ встаёт в набор, и слово о цели у неё звучит.
///
/// Заказано замером потребителя (19.09.2026): у SYN-пайпа копредел требуется ПО СУЩЕСТВУ — блэкхол
/// есть свойство адреса, а не разговора, и один утонувший `SYN` бывает от обычной потери. Пока
/// свёрнутая цепочка в набор не вставала, выбор был из двух, и оба с ценой: своя нить на этот пайп
/// либо порог, переписанный у потребителя заново (`Layer` гасит кратность и забывает по простою —
/// наивный счётчик считал бы повторы ОДНОГО разговора, то есть объявлял бы блэкхолом обычную
/// потерю).
///
/// Структурного запрета здесь нет, и это главное в законе. Слово о цели не едет в поток показаний
/// (там слово РАЗГОВОРА, и спуск между слоями не определён — §5), оно уходит замыканием `on_target`
/// из того же оборота, в той же нити. Набор ему не мешает ничем.
#[test]
fn a_folded_chain_joins_the_set_and_its_target_word_is_spoken() {
    let spoken = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let said = std::sync::Arc::clone(&spoken);

    let heard: Vec<Note> = together()
        .chain(
            engine(
                Paper::new()
                    .then_packet(syn(40101))
                    .then_packet(request(40101))
                    .silent_for(secs(3))
                    .then_stop(),
            )
            .from(Tcp)
            .extract(Sni)
            .detect(paper::Crier::always())
            .about(|words| words.first().map(|word| (*word).clone()))
            .on_target(move |target, _voiced| {
                said.lock()
                    .expect("журнал не отравлен")
                    .push(target.to_string())
            }),
        )
        .chain(
            engine(
                Paper::new()
                    .then_packet(syn(40102))
                    .then_packet(request(40102))
                    .then_stop(),
            )
            .from(Tcp)
            .extract(Sni)
            .detect(paper::Crier::always()),
        )
        .heard()
        .collect();

    assert!(
        !heard.is_empty(),
        "показания разговоров обязаны идти потоком у обеих цепочек"
    );
    assert!(
        !spoken.lock().expect("журнал не отравлен").is_empty(),
        "слово о ЦЕЛИ обязано прозвучать и у цепочки, стоящей в наборе"
    );
}

/// ПРЕДМЕТ: свёрнутая цепочка принимает ТЕ ЖЕ двери, что всякая, и они работают.
///
/// Двери `naming`/`parting`/`severing`/`telling`/`certifying` стояли только у цепочки ДО свёртки, и
/// это была ловушка порядка: выражение со свёрткой собиралось, а дверь у него молча пропадала. Ни
/// одна из них смысла от места не меняет — лента, имена, уход и внеполосное решение живут у всей
/// цепочки, а не у букв, пришедших после `.about`. Там, где порядок смысл НЕСЁТ, его держит тип
/// (§11): прибор чужого алфавита не встаёт в пайп, свёртка без реакции не собирается.
///
/// Заказано тем же замером, что и вход свёрнутой цепочки в набор: у потребителя решение о цели
/// едет дверью `telling`, а пайпу, которому копредел нужен по существу, она была недоступна.
///
/// Разговор здесь DNS не ради разнообразия: имя цели у него есть (`naming` иначе молчал бы по
/// свойству СЦЕНАРИЯ, а не двери — наступлено на TCP, где `request` несёт заголовок без SNI).
#[test]
fn a_folded_chain_takes_the_same_doors() {
    let (tx, named) = std::sync::mpsc::sync_channel(16);
    let (bye, parted) = std::sync::mpsc::sync_channel(16);

    let heard: Vec<Note<_>> = engine(
        Paper::new()
            .then_packet(dns_query(40301, "canary.example"))
            .silent_for(secs(120))
            .then_stop(),
    )
    .from(Udp)
    .extract(Sni)
    .detect(Resolve::names())
    .about(|words| words.first().map(|word| (*word).clone()))
    .on_target(|_target, _voiced| {})
    .naming(reflex_core::Tap::new(tx))
    .parting(reflex_core::Tap::new(bye))
    .severing(|_word| false)
    .heard()
    .expect("носитель открылся")
    .collect();

    let _ = heard;
    assert!(
        !named.try_iter().collect::<Vec<Named>>().is_empty(),
        "имя разговора обязано прозвучать и у свёрнутой цепочки"
    );
    assert!(
        !parted.try_iter().collect::<Vec<Parted>>().is_empty(),
        "уход разговора обязан прозвучать и у свёрнутой цепочки"
    );
}

/// ПРЕДМЕТ: у набора есть ХОД БЕЗ ПОКАЗАНИЯ — окно, по истечении которого управление возвращается
/// потребителю, даже если провод молчал.
///
/// Найдено в поле (19.09.2026): круг крутится ровно столько раз, сколько приходит показаний, и в
/// тишине стоит. Для провода это верно — нет пакетов, нет наблюдений, — но у потребителя на том же
/// круге живёт ВТОРАЯ машина, которой время нужно само по себе: досмотреть срок, снять укрытие,
/// прочесть ответ, пришедший не проводом. Её темп оказывался равен темпу трафика, и ночью, когда
/// человек спит, лечение не доезжало вовсе — выглядя при этом как работа.
///
/// Тик машине даёт потребитель сам (§8: время — буква входа), и заводить таймер внутри наших машин
/// незачем. Не хватало ИСТОЧНИКА хода, и он у цикла уже был: носитель умеет срок (§9.1, «не
/// возвращаться раньше `until`, кроме как с работой»), а наружу этот срок не выходил.
///
/// Три клетки, потому что «показаний не было» и «показаний больше не будет» — разные вести (§7).
#[test]
fn the_set_gives_a_turn_even_when_the_wire_is_silent() {
    let mut chorus = together()
        .chain(
            engine(Paper::new().silent_for(secs(30)).then_stop())
                .from(Tcp)
                .extract(Sni)
                .detect(paper::Crier::always()),
        )
        .heard();

    let first = chorus.within(Duration::from_millis(50));
    assert!(
        matches!(first, Turned::Quiet),
        "провод молчал — набор обязан вернуть ход, а не держать потребителя: {first:?}"
    );
}

/// ПРЕДМЕТ: тот же ход отдаёт ПОКАЗАНИЕ, когда оно есть, и говорит о конце, когда источники
/// кончились. Без второй половины первая ничего не стоит: дверь, всегда отвечающая «тихо», прошла
/// бы первый закон и не сказала бы потребителю ни слова.
#[test]
fn the_same_turn_carries_a_reading_and_then_the_end() {
    let mut chorus = together()
        .chain(
            engine(
                Paper::new()
                    .then_packet(syn(40301))
                    .then_packet(request(40301))
                    .then_stop(),
            )
            .from(Tcp)
            .extract(Sni)
            .detect(paper::Crier::always()),
        )
        .heard();

    let mut said = 0;
    let mut ended = false;
    for _ in 0..64 {
        match chorus.within(Duration::from_millis(50)) {
            Turned::Said(_) => said += 1,
            Turned::Quiet => (),
            Turned::Ended => {
                ended = true;
                break;
            }
        }
    }

    assert!(said > 0, "показания обязаны доходить тем же ходом");
    assert!(
        ended,
        "кончившийся набор обязан сказать о конце, а не молчать"
    );
}
