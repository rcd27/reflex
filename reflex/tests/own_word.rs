//! ЧУЖОЙ СЛОВАРЬ: прибор потребителя говорит СВОИМ словом, парк — рядом и на своём.
//!
//! До этой правки `own(машина)` требовал `Out = SmallVec<[Distress; 2]>`: всякий, кто ставил свой
//! прибор, обязан был говорить нашим алфавитом беды. Внешний потребитель (сканилка стратегий, чей
//! предмет — «кто из кандидатов открыл ресурс», а не беда) выдавал пустой вектор и нёс наблюдение
//! мимо алфавита — то есть обходил §2 не по злому умыслу, а потому что двери не было.
//!
//! Здесь дверь есть, и тест держит ОБЕ её половины: своё слово и смешение с парком.

mod paper;

use core::time::Duration;

use paper::{log, request, Paper};
use reflex::*;
use reflex_core::word::{Conversation, Word};

/// Слово потребителя. Предмет — не беда, а исход пробы; выражать его через `Distress` значило бы
/// насилие над обоими словарями.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Probed {
    Opened,
    /// Парк сказал своё — оно вкладывается сюда, не теряясь.
    Park(Distress),
}

/// Слово принадлежит области РАЗГОВОРА: без этого его некуда адресовать (§4).
impl Word for Probed {
    type Of = Conversation;
}

/// ПОДЪЁМ парка в словарь потребителя. Требование стоит на приборе парка, а не на цепочке: кто
/// парк не ставит, тот и не платит.
impl From<Distress> for Probed {
    fn from(distress: Distress) -> Probed {
        Probed::Park(distress)
    }
}

#[derive(Clone, Copy, Default)]
struct Prober;

impl Mealy for Prober {
    type In = DetectorEvent<Seen>;
    type Out = SmallVec<[Probed; 2]>;
    type Log = ();

    fn step(self, event: Self::In) -> (Self, Self::Out, ()) {
        match event {
            // Любой пакет разговора: предмет теста — СЛОВАРЬ, а не то, что именно прибор ловит.
            DetectorEvent::Packet { .. } => (self, smallvec![Probed::Opened], ()),
            _ => (self, SmallVec::new(), ()),
        }
    }
}

/// Прибор, говорящий словом ПАРКА (`Distress`). В цепочке со своим словарём он обязан
/// ВЛОЖИТЬСЯ через `From`, а не потеряться и не подменить чужое слово своим.
#[derive(Clone, Copy, Default)]
struct LikePark;

impl Mealy for LikePark {
    type In = DetectorEvent<Seen>;
    type Out = SmallVec<[Distress; 2]>;
    type Log = ();

    fn step(self, event: Self::In) -> (Self, Self::Out, ()) {
        match event {
            DetectorEvent::Packet { .. } => (self, smallvec![Distress::NoBytes], ()),
            _ => (self, SmallVec::new(), ()),
        }
    }
}

/// ВЛОЖЕНИЕ ПРОВЕРЯЕТСЯ ПРОГОНОМ, а не сборкой. Тесты ниже собирают цепочку и тем доказывают, что
/// ТИПЫ сходятся; этот гоняет её по бумажному носителю и смотрит, ЧТО доехало до реакции.
///
/// Без него правка проверялась бы только на компиляцию: `.on` в собирающихся тестах не зовётся
/// никогда, и всякое утверждение внутри него — украшение.
#[test]
fn слово_парка_доезжает_до_реакции_ВЛОЖЕННЫМ_а_не_подменённым() {
    let heard = log::<Probed>();
    let paper = Paper::new().then_packet(request(40001)).then_stop();

    engine(paper)
        .from(Tcp)
        .extract(Sni)
        .detect(own(Prober))
        .detect(own(LikePark))
        .on(move |_target, probed: Probed| heard.lock().expect("слышно").push(probed))
        .run();

    let said = heard.lock().expect("слышно").clone();
    assert!(
        said.contains(&Probed::Park(Distress::NoBytes)),
        "слово парка обязано доехать ВЛОЖЕННЫМ (`Park(NoBytes)`), а не потеряться и не стать \
         своим словом цепочки; доехало: {said:?}"
    );
    assert!(
        said.contains(&Probed::Opened),
        "своё слово тоже обязано доехать: {said:?}"
    );
}

/// Цепочка со СВОИМ словом собирается, и реакция получает именно его.
#[test]
fn чужой_прибор_говорит_своим_словом() {
    let _chain = engine(Nfqueue::queue(1))
        .from(Tcp)
        .extract(Sni)
        .detect(own(Prober))
        .on(|_target, probed: Probed| {
            // Тип реакции — слово ПОТРЕБИТЕЛЯ, а не `Distress`. Это и есть предмет правки.
            assert!(matches!(probed, Probed::Opened | Probed::Park(_)));
        });
}

/// Парк и чужой прибор в ОДНОЙ цепочке: `Silence` говорит `Distress`, тот вкладывается в `Probed`.
#[test]
fn парк_и_чужой_прибор_уживаются_в_одной_цепочке() {
    let _chain = engine(Nfqueue::queue(1))
        .from(Tcp)
        .extract(Sni)
        .detect(own(Prober))
        .detect(Silence::after(Duration::from_secs(5)))
        .on(|_target, probed: Probed| {
            assert!(matches!(probed, Probed::Opened | Probed::Park(_)));
        });
}

/// Умолчание цело: цепочка из одного парка по-прежнему говорит `Distress`, и подпись реакции
/// прежняя. Ни один пример не изменился ни строкой — этим правка и доказывается.
#[test]
fn парк_без_чужого_прибора_говорит_бедой_как_прежде() {
    let _chain = engine(Nfqueue::queue(1))
        .from(Tcp)
        .extract(Sni)
        .detect(Silence::after(Duration::from_secs(5)))
        .on(|_target, _distress: Distress| {});
}

/// АДРЕС НАРУЖУ: реакция различает РАЗГОВОРЫ одной цели, а не только цель.
///
/// До этой двери наружу выходило только имя цели, и потребитель, которому нужно различать
/// разговоры, восстанавливал адрес в обход конструкции — стоком мимо алфавита (§2). Замер:
/// слушатель канала над сканилкой стратегий, 10.09.
#[test]
fn реакция_получает_ключ_разговора_а_не_только_имя_цели() {
    let seen = log::<u16>();
    let paper = Paper::new()
        .then_packet(request(40001))
        .then_packet(request(40002))
        .then_stop();

    let sink = seen;
    engine(paper)
        .from(Tcp)
        .extract(Sni)
        .detect(own(Prober))
        .on_addressed(move |whom: Whom<'_>, _word: Probed| {
            sink.lock().expect("адреса").push(whom.flow.src.port())
        })
        .run();

    let ports = seen.lock().expect("адреса").clone();
    assert!(
        ports.contains(&40001) && ports.contains(&40002),
        "адрес обязан различать разговоры одной цели; пришло: {ports:?}"
    );
}
