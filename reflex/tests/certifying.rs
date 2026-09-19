//! ВОСЬМОЙ ЗАКОН НАРУЖУ (§10): свидетельство — слово о ЦЕПОЧКЕ, и оно обязано доходить значением.
//!
//! Предмет не в удобстве двери. До этих законов вердикт `Replayed` выходил единственным путём —
//! через `Report`, а `Report` рождается только по `carrier.exhausted()`, которого у очереди ядра не
//! бывает по построению. То есть на живом носителе §10 предъявлялся строкой в логе, а закон о
//! предъявимости, который можно только прочитать глазами, не предъявлен никому (тот же довод, что
//! и в `recording.rs`: «вердикт берётся ЗНАЧЕНИЕМ из отчёта, а не глазами из лога»).
//!
//! Отсюда форма: кран, как у `naming`/`parting`, — потому что свидетельство не слово машины о
//! разговоре и в `Note` ему места нет по предмету, а автор у него обязателен (§4.1): в наборе
//! цепочек «какая сказала» есть часть утверждения, а не подпись к нему.

mod paper;

use std::sync::mpsc::sync_channel;

use paper::{request, syn, Paper};
use reflex::*;

/// Прибор, говорящий на КАЖДОМ пакете: здоровый разговор беды не рождает, а предмет здесь — не
/// поиск беды, а то, что машине БЫЛО ЧТО СКАЗАТЬ и сказанное воспроизводится.
#[derive(Clone, Copy, Default)]
struct Counter;

impl Mealy for Counter {
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

/// Прибор со СКРЫТЫМ входом: величину берёт из счётчика, живущего вне его состояния. Ровно то, что
/// восьмой закон обязан ловить, — и здесь он доказывает зрячесть КРАНА, а не отчёта (Правило 10.7).
#[derive(Clone, Copy, Default)]
struct Peeking;

static PEEKED: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

impl Mealy for Peeking {
    type In = DetectorEvent<Seen>;
    type Out = SmallVec<[Distress; 2]>;
    type Log = ();

    fn step(self, event: Self::In) -> (Self, Self::Out, ()) {
        match event {
            DetectorEvent::Packet { .. } => {
                let ms = PEEKED.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                (self, smallvec![Distress::Silence { ms }], ())
            }
            DetectorEvent::Tick { .. }
            | DetectorEvent::Opaque { .. }
            | DetectorEvent::Torn { .. } => (self, SmallVec::new(), ()),
        }
    }
}

/// ПРЕДМЕТ: свидетельство приходит КРАНОМ и называет свою цепочку.
///
/// Зелёная половина закона. Красная — ниже, и без неё эта не считается (§10.1).
#[test]
fn the_testimony_arrives_through_a_tap_naming_its_chain() {
    let (tx, heard) = sync_channel(64);

    pcap("tests/fixtures/handshake.pcap")
        .from(Tcp)
        .extract(Sni)
        .detect(own(Counter))
        .certifying(reflex_core::Tap::new(tx))
        .on(|_target: &str, _distress: Distress| {})
        .run();

    let said: Vec<Certified> = heard.try_iter().collect();
    assert!(
        said.iter().any(|it| it.verdict == Replayed::Reproduced),
        "запись обязана дать свидетельство краном: вход детерминирован целиком; пришло {said:?}"
    );
    assert!(
        said.iter().all(|it| it.chain.contains("handshake.pcap")),
        "свидетельство обязано нести АВТОРА — имя своей цепочки; пришло {said:?}"
    );
}

/// ПРЕДМЕТ: тот же кран обязан УМЕТЬ ОТКАЗАТЬ. Свидетель, зелёный на всём, хуже отсутствующего.
#[test]
fn a_hidden_input_is_caught_by_the_same_tap() {
    let (tx, heard) = sync_channel(64);

    pcap("tests/fixtures/handshake.pcap")
        .from(Tcp)
        .extract(Sni)
        .detect(own(Peeking::default()))
        .certifying(reflex_core::Tap::new(tx))
        .on(|_target: &str, _distress: Distress| {})
        .run();

    let said: Vec<Certified> = heard.try_iter().collect();
    assert!(
        said.iter()
            .any(|it| matches!(it.verdict, Replayed::Unstable { .. })),
        "машина со скрытым входом обязана быть уличена ТЕМ ЖЕ краном; пришло {said:?}"
    );
}

/// ПРЕДМЕТ: у НАБОРА свидетельствует каждая цепочка, и каждая — под своим именем.
///
/// Прежде дверь §10 стояла на `Running`, до которого набор не доходит вовсе: `Together::chain`
/// берёт `Detecting` и сразу зовёт `heard()`. Свидетельство набора было непредъявимо ничем — при
/// том, что ленты у цепочек с самого начала раздельны (`Turning` заводится на цепочку).
#[test]
fn each_chain_of_a_set_testifies_under_its_own_name() {
    let (tx, heard) = sync_channel(64);

    let notes: Vec<Note> = together()
        .chain(
            pcap("tests/fixtures/handshake.pcap")
                .from(Tcp)
                .extract(Sni)
                .detect(own(Counter))
                .certifying(reflex_core::Tap::new(tx.clone())),
        )
        .chain(
            pcap("tests/fixtures/chrome-hello.pcap")
                .from(Tcp)
                .extract(Sni)
                .detect(own(Counter))
                .certifying(reflex_core::Tap::new(tx)),
        )
        .heard()
        .collect();

    let _ = notes;
    let said: Vec<Certified> = heard.try_iter().collect();
    // ИМЕНИ МАЛО. Вердикт `NoTape` («судить не о чем») тоже приходит с именем, и проверка одних
    // имён была зелена под мутантом «лента не пишется вовсе» — то есть свидетельствовала бы о
    // работе двери, которой нет. Спрашивается поэтому ВОСПРОИЗВЕДЕНИЕ, по одному на цепочку.
    let reproduced: std::collections::BTreeSet<&str> = said
        .iter()
        .filter(|it| it.verdict == Replayed::Reproduced)
        .map(|it| &*it.chain)
        .collect();
    assert_eq!(
        reproduced.len(),
        2,
        "свидетельствовать обязаны ОБЕ цепочки набора, каждая под своим именем; пришло {said:?}"
    );
}

/// ПРЕДМЕТ: окно судится ПОСРЕДИ прогона, а не в конце.
///
/// У живой очереди конца нет («`exhausted` у неё ложь по построению»), и свидетельство, приходящее
/// «в конце», не приходит никогда. Два вердикта за один прогон — и есть доказательство, что дверь
/// привязана к закрытию ОКНА, а не к концу источника.
#[test]
fn a_window_is_judged_mid_run_not_at_the_end() {
    let (tx, heard) = sync_channel(64);

    engine(
        Paper::new()
            .then_packet(syn(40001))
            .then_packet(request(40001))
            // Тишина набивает ленту узлами сетки: TICK 200 мс, окно 64 буквы — тридцати секунд
            // хватает на несколько окон подряд.
            .silent_for(secs(30))
            .then_packet(request(40001))
            .then_stop(),
    )
    .from(Tcp)
    .extract(Sni)
    .detect(own(Counter))
    .certifying(reflex_core::Tap::new(tx))
    .on(|_target: &str, _distress: Distress| {})
    .run();

    let said: Vec<Certified> = heard.try_iter().collect();
    assert!(
        said.len() >= 2,
        "закрытых окон за прогон было несколько — значит и свидетельств обязано быть несколько, \
         иначе дверь привязана к концу источника, которого у очереди не бывает; пришло {said:?}"
    );
}

/// ПРЕДМЕТ: цепочка, чьи машины замолчали, ГОВОРИТ об этом, а не молчит сама.
///
/// Замер потребителя (19.09.2026): DNS-пайп на канарейке даёт 0,6 пакетной буквы в минуту — 64
/// ПАКЕТНЫХ буквы набираются 107 минут. Вопрос стоял так: неотличим ли такой пайп от исправного всё
/// это время. Ответ — нет, и причина в том, что окно набивают УЗЛЫ СЕТКИ: лента закрывается по ним,
/// и вердикт приходит `Silent` — «лента есть, сказать было нечего». Молчание о собственной
/// предъявимости хуже отказа; отказ назван клеткой (§7, `Silent` против `NoTape`).
///
/// Порядок здесь и есть утверждение: сперва разговор СКАЗАЛ (`Reproduced`), потом провод смолк, и
/// те же машины живы, а свидетельства больше нет. Проверять `Silent` на сценарии без единого
/// сказанного слова нельзя — такой тест зелен и тогда, когда узлы в ленту не идут вовсе (наступлено
/// мутантом «`Tick` мимо ленты»: он покраснил соседний закон, а этот оставил зелёным).
#[test]
fn a_chain_whose_machines_fell_silent_says_so_instead_of_saying_nothing() {
    let (tx, heard) = sync_channel(64);

    engine(
        Paper::new()
            .then_packet(syn(40001))
            // Разговор назвался и получил слово: первому окну есть что воспроизводить.
            .then_packet(request(40001))
            // Дальше провод молчит, как молчит DNS-очередь между запросами.
            .silent_for(secs(30))
            .then_stop(),
    )
    .from(Tcp)
    .extract(Sni)
    // Прибор, который на узлах молчит: машина жива, сказать ей нечего.
    .detect(own(Counter))
    .certifying(reflex_core::Tap::new(tx))
    .on(|_target: &str, _distress: Distress| {})
    .run();

    let said: Vec<Certified> = heard.try_iter().collect();
    assert!(
        said.iter().any(|it| it.verdict == Replayed::Reproduced),
        "пока разговор говорил, свидетельство обязано быть; пришло {said:?}"
    );
    assert!(
        said.iter().any(|it| it.verdict == Replayed::Silent),
        "окно из одних узлов сетки обязано дать `Silent` — «свидетельства нет», а не молчание \
         двери; пришло {said:?}"
    );
}

/// ПРЕДМЕТ: свидетельство §10 приходит и у ЦЕПОЧКИ С ДЕЙСТВИЕМ.
///
/// Прежде дверь жила у `Running`, то есть у наблюдателя, и докблок `Acting::run` честно называл это
/// пределом: «ЛЕНТА §10 не пишется никогда… дверь к ней у действия не открыта». Предел держался не
/// циклом — цикл у обоих терминалов один, — а местом двери. Дверь переехала на цепочку, и предел
/// исчез сам собой: это и проверяется здесь, потому что «исчез сам собой» без прогона есть догадка.
#[test]
fn a_chain_that_acts_testifies_too() {
    let (tx, heard) = sync_channel(64);

    engine(
        Paper::new()
            .then_packet(syn(40001))
            .then_packet(request(40001))
            .silent_for(secs(30))
            .then_stop(),
    )
    .from(Tcp)
    .extract(Sni)
    .detect(own(Counter))
    .certifying(reflex_core::Tap::new(tx))
    .act(|_target, _distress| Act::observe())
    .run();

    let said: Vec<Certified> = heard.try_iter().collect();
    assert!(
        said.iter().any(|it| it.verdict == Replayed::Reproduced),
        "у действия лента обязана писаться тем же циклом, что у наблюдения; пришло {said:?}"
    );
}

/// ПРЕДМЕТ: закон просят у СВЁРНУТОЙ цепочки тем же словом и в любом месте выражения.
///
/// Двери цепочки повторены у `Speaking` (`.detect` уже был) не ради удобства: порядок в выражении
/// несёт смысл (§11), и место, где стоит `.certifying`, смысла НЕ несёт — лента пишется всем
/// буквам цепочки, а не тем, что пришли после слова. Дверь, доступная лишь до `.about`, была бы
/// ловушкой порядка: собралось бы, но у пайпа с копределом закона бы не было, и молча.
#[test]
fn a_folded_chain_is_asked_for_the_law_in_its_own_place() {
    let (tx, heard) = sync_channel(64);

    engine(
        Paper::new()
            .then_packet(syn(40001))
            .then_packet(request(40001))
            .silent_for(secs(3))
            .then_stop(),
    )
    .from(Tcp)
    .extract(Sni)
    .detect(own(Counter))
    .about(|words| words.first().map(|word| (*word).clone()))
    .on_target(|_target, _voiced| {})
    .certifying(reflex_core::Tap::new(tx))
    .on(|_target: &str, _distress: Distress| {})
    .run();

    let said: Vec<Certified> = heard.try_iter().collect();
    assert!(
        said.iter().any(|it| it.verdict == Replayed::Reproduced),
        "свёрнутая цепочка обязана свидетельствовать так же, как всякая другая; пришло {said:?}"
    );
}
