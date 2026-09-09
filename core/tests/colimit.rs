//! Копредел по слою: слово о цели как сведение слов о её разговорах (§4 — `Target ≅ ∐_{k} Conversation`,
//! §5 — сведение слов). Форма наша, свёртка приходит от потребителя значением.

use reflex_core::colimit::Layer;
use reflex_core::types::{Addr, Flow, Protocol};
use reflex_core::word::{Conversation, Target, TargetKey};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

fn target() -> TargetKey<Box<str>> {
    TargetKey::Named("rutracker.org".into())
}

fn flow(n: u32) -> Flow {
    Flow {
        src: SocketAddr::new(IpAddr::V4(Ipv4Addr::from(0x0A00_0000 | n)), 40000 + n as u16),
        dst: SocketAddr::new(IpAddr::V4(Ipv4Addr::from(0x5DB8_D822)), 443),
        protocol: Protocol::Tcp,
    }
}

/// Кратность гасит ХРАНИЛИЩЕ: повтор разговора заменяет его слово, а не множит. Без этого свёртка
/// считала бы один разговор дважды, и «молчит доля» врала бы тем сильнее, чем чаще мы наблюдаем.
#[test]
fn повтор_разговора_заменяет_слово_а_не_множит() {
    let now = Instant::now();
    let mut layer: Layer<Conversation, Target, &str> = Layer::new();
    layer.saw(target(), flow(1), "молчит", now);
    layer.saw(target(), flow(1), "ответил", now);
    assert_eq!(layer.join(&target(), |words| Some(words.len())), Some(1), "один разговор — одно слово");
    assert_eq!(
        layer.join(&target(), |words| Some(*words[0])),
        Some("ответил"),
        "слово ЗАМЕНЕНО, а не оставлено прежним: слой держит текущий снимок, не историю"
    );
}

/// Цель без слов — тоже молчание. Отличается от «цели не знаем»: слой у неё есть, слов в нём нет,
/// и свёртке пустое множество не показываем — иначе «молчат все» ответило бы «да» на пустоте.
#[test]
fn цель_с_пустым_слоем_молчит() {
    let now = Instant::now();
    let mut layer: Layer<Conversation, Target, u8> = Layer::new();
    layer.saw(target(), flow(1), 1, now);
    layer.forget(&target(), &flow(1));

    let all_silent = |words: &[&u8]| words.iter().all(|w| **w == 1).then_some(());
    assert_eq!(layer.join(&target(), all_silent), None, "пустота — не «молчат все»");
}

/// Свёртка видит МНОЖЕСТВО: порядок перечисления на вывод не влияет. Иначе один и тот же набор
/// наблюдений давал бы разные слова о цели по прихоти планировщика.
#[test]
fn порядок_прихода_не_виден_свёртке() {
    let now = Instant::now();
    let sum = |words: &[&u8]| Some(words.iter().copied().sum::<u8>());

    let mut ab: Layer<Conversation, Target, u8> = Layer::new();
    ab.saw(target(), flow(1), 1, now);
    ab.saw(target(), flow(2), 2, now);

    let mut ba: Layer<Conversation, Target, u8> = Layer::new();
    ba.saw(target(), flow(2), 2, now);
    ba.saw(target(), flow(1), 1, now);

    assert_eq!(ab.join(&target(), sum), ba.join(&target(), sum));
}

/// Доля — законная свёртка: как ОПЕРАЦИЯ она не идемпотентна, но она ФУНКЦИЯ МНОЖЕСТВА, а кратность
/// уже снята хранилищем. Свобода свёртки богаче join'а §5, и дедуп есть её цена.
#[test]
fn доля_законная_свёртка() {
    let now = Instant::now();
    let mut layer: Layer<Conversation, Target, bool> = Layer::new();
    layer.saw(target(), flow(1), true, now);
    layer.saw(target(), flow(2), false, now);
    layer.saw(target(), flow(1), true, now); // повтор того же разговора

    let share = |words: &[&bool]| {
        let silent = words.iter().filter(|w| ***w).count();
        Some(silent * 100 / words.len())
    };
    assert_eq!(layer.join(&target(), share), Some(50), "два разговора, один молчит");
}

/// Пустой слой слова не рождает: «сказать нечего» и «свелось в ничто» — разные вещи, и свёртке
/// пустого множества не показываем.
#[test]
fn пустой_слой_молчит() {
    let layer: Layer<Conversation, Target, u8> = Layer::new();
    assert_eq!(layer.join(&target(), |w| Some(w.len())), None);
}

/// Слово о цели живёт, пока живут слова её разговоров. Затихший разговор уходит по простою, и
/// свёртка над оставшимися даёт новое слово сама — отдельного срока у цели нет, он стал бы сроком
/// ГОДНОСТИ, то есть суждением.
#[test]
fn затихший_разговор_уходит_и_меняет_слово_о_цели() {
    let t0 = Instant::now();
    let mut layer: Layer<Conversation, Target, bool> = Layer::new();
    layer.saw(target(), flow(1), true, t0);
    layer.saw(target(), flow(2), false, t0 + Duration::from_secs(30));

    layer.forget_idle(Duration::from_secs(20), t0 + Duration::from_secs(31));
    assert_eq!(
        layer.join(&target(), |w| Some(w.len())),
        Some(1),
        "первый затих — слово о цели теперь о втором"
    );
}

/// Цель, у которой не осталось разговоров, исчезает целиком: пустых слоёв не копим.
#[test]
fn цель_без_разговоров_снимается() {
    let t0 = Instant::now();
    let mut layer: Layer<Conversation, Target, bool> = Layer::new();
    layer.saw(target(), flow(1), true, t0);

    let gone = layer.forget_idle(Duration::from_secs(1), t0 + Duration::from_secs(2));
    assert_eq!(gone, vec![target()], "ушедшая цель названа, а не молча забыта");
    assert_eq!(layer.join(&target(), |w| Some(w.len())), None);
}

/// Разные цели не смешиваются: слой одной не виден свёртке другой.
#[test]
fn слои_разных_целей_не_смешиваются() {
    let now = Instant::now();
    let other = TargetKey::Unnamed(Addr(0x5DB8_D822));
    let mut layer: Layer<Conversation, Target, u8> = Layer::new();
    layer.saw(target(), flow(1), 1, now);
    layer.saw(other.clone(), flow(2), 2, now);

    assert_eq!(layer.join(&target(), |w| Some(w.len())), Some(1));
    assert_eq!(layer.join(&other, |w| Some(w.len())), Some(1));
}

/// Возраст слова о цели считается по САМОМУ СВЕЖЕМУ из сведённых наблюдений, а не по первому и не
/// по случайному. Возьми старейшее — и цель, только что заговорившая одним из двадцати потоков,
/// выглядела бы молчащей минуту; порядок хранения при этом не наш, значит «какое попало» тоже
/// негодно.
#[test]
fn возраст_цели_по_самому_свежему_слову() {
    let t0 = Instant::now();
    let mut layer: Layer<Conversation, Target, u8> = Layer::new();
    layer.saw(target(), flow(1), 1, t0);
    layer.saw(target(), flow(2), 2, t0 + Duration::from_secs(5));
    layer.saw(target(), flow(3), 3, t0 + Duration::from_secs(2));

    assert_eq!(
        layer.freshest(&target()),
        Some(t0 + Duration::from_secs(5)),
        "свежайшее из трёх, а не первое и не последнее положенное"
    );
}

/// Цели без слов возраста нет: «сказать нечего» — не «сказано давно». Верни здесь ноль или `now` —
/// и потребитель принял бы пустоту за свежее наблюдение.
#[test]
fn у_цели_без_слов_возраста_нет() {
    let t0 = Instant::now();
    let mut layer: Layer<Conversation, Target, u8> = Layer::new();
    layer.saw(target(), flow(1), 1, t0);
    layer.forget(&target(), &flow(1));

    assert_eq!(layer.freshest(&target()), None, "пустой слой возраста не имеет");
    assert_eq!(layer.freshest(&TargetKey::Unnamed(Addr(1))), None, "незнакомая цель — тем более");
}
