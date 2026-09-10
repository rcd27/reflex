//! Что движок видел и чего не видел — фундамент слепоты (канон §7/§10). Перехватывающий движок
//! слепнет: NFQUEUE роняет при переполнении, кольцо `AF_PACKET` переполняется, WinDivert теряет
//! по-своему — слепота нормальный режим, обязана быть ВЫРАЗИМА. Движок, не умеющий сказать «я этого
//! не видел», выдаёт своё молчание за молчание сети. Слепота ЗАМЕРЯЕТСЯ ([`sighted`] сравнивает два
//! независимых счёта: ядро и движок, расхождение и есть величина), не объявляется — вывод с одним
//! оракулом не вывод. [`Sight::Full`] не есть свидетельство зрения, если счёта из одного источника:
//! у офлайн-входа «ядро» синтезируется из тех же пакетов, `Full` выходит по построению — второй
//! оракул существует только живьём.

/// Сколько прошло в каждую сторону. Пакеты и байты порознь: заблокированная цель отвечает на `SYN`
/// и молчит после приветствия (пакеты вниз есть, нагрузки нет) — счёт только пакетов её от живой не
/// отличает.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Counted {
    pub up: u64,
    pub up_bytes: u64,
    pub down: u64,
    pub down_bytes: u64,
}

/// Видел ли движок весь разговор.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sight {
    Full,
    Partial { missed_up: u64, missed_down: u64 },
}

/// Что известно о величине, добываемой событием (§7). Третье состояние — весь смысл: пустая клетка
/// значит разное смотря по тому, могли ли мы увидеть событие — у зрячего «ничего не приходило» есть
/// факт о СЕТИ, у ослепшего — о НАС. `Told::Told` читается неловко, имя перенесено как есть (85
/// употреблений в 8 файлах — переименование стоило бы churn'а).
///
/// Сторож: `nothing_seen_while_blind_is_not_the_same_as_nothing_happened` (`core/tests/sight.rs`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Told<T> {
    /// Канал был открыт, событие не приходило — значит его не было.
    Nothing,
    Told(T),
    /// Движок этих пакетов не видел: событие могло произойти и не дойти.
    Blind,
}

/// «Не знаю» адресовано туда же, куда была бы сама величина: третье состояние говорит о ней, не
/// заводит нового адресата.
impl<T: crate::word::Word> crate::word::Word for Told<T> {
    type Of = T::Of;
}

/// Пустой счёт — нейтраль для [`added`].
pub fn no_counts() -> Counted {
    Counted {
        up: 0,
        up_bytes: 0,
        down: 0,
        down_bytes: 0,
    }
}

/// Сложить два отрезка одного разговора. Насыщение, не перенос: счётчик, ушедший по кругу, соврал бы
/// тише застрявшего на потолке.
pub fn added(one: Counted, other: Counted) -> Counted {
    Counted {
        up: one.up.saturating_add(other.up),
        up_bytes: one.up_bytes.saturating_add(other.up_bytes),
        down: one.down.saturating_add(other.down),
        down_bytes: one.down_bytes.saturating_add(other.down_bytes),
    }
}

/// Слепота как расхождение двух независимых счётов. Насыщение в ноль не косметика: движок не может
/// видеть больше ядра, отрицательная слепота была бы утверждением сильнее установленного.
pub fn sighted(kernel: Counted, engine: Counted) -> Sight {
    match (
        kernel.up.saturating_sub(engine.up),
        kernel.down.saturating_sub(engine.down),
    ) {
        (0, 0) => Sight::Full,
        (missed_up, missed_down) => Sight::Partial {
            missed_up,
            missed_down,
        },
    }
}

/// Раннее из двух наблюдений одного предмета. У слепоты здесь старшинство над пустотой (`Blind ⊐
/// Nothing`), в [`later`] наоборот — различие в предмете, не в знаке: здесь величина ОДНОГО
/// разговора (когда отвечающий заговорил), и часть, которую не видели, могла нести ответ.
/// Коммутативна — требование, не свойство: наблюдения приходят из разных источников в произвольном
/// порядке, всякое «пришедшее первым» молча становится выборкой из мультимножества.
pub fn sooner<T: Ord>(one: Told<T>, other: Told<T>) -> Told<T> {
    match (one, other) {
        (Told::Told(mine), Told::Told(theirs)) => Told::Told(mine.min(theirs)),
        (Told::Told(value), Told::Nothing)
        | (Told::Told(value), Told::Blind)
        | (Told::Nothing, Told::Told(value))
        | (Told::Blind, Told::Told(value)) => Told::Told(value),
        (Told::Blind, Told::Nothing)
        | (Told::Nothing, Told::Blind)
        | (Told::Blind, Told::Blind) => Told::Blind,
        (Told::Nothing, Told::Nothing) => Told::Nothing,
    }
}

/// Позднее из двух наблюдений — зеркало [`sooner`], разница в предмете: здесь наблюдение за УЗЛОМ из
/// многих разговоров, слепота одного узел слепым не делает (`Nothing ⊐ Blind`, старшинство обратное).
/// Ветки без `_`: асимметрия видна, только когда обе таблицы выписаны целиком рядом.
pub fn later<T: Ord>(one: Told<T>, other: Told<T>) -> Told<T> {
    match (one, other) {
        (Told::Told(mine), Told::Told(theirs)) => Told::Told(mine.max(theirs)),
        (Told::Told(value), Told::Nothing)
        | (Told::Told(value), Told::Blind)
        | (Told::Nothing, Told::Told(value))
        | (Told::Blind, Told::Told(value)) => Told::Told(value),
        (Told::Nothing, Told::Nothing)
        | (Told::Nothing, Told::Blind)
        | (Told::Blind, Told::Nothing) => Told::Nothing,
        (Told::Blind, Told::Blind) => Told::Blind,
    }
}

/// Наблюдённое слепотой не отменяется: факт, добытый до того, как ослепли, остаётся фактом — иначе
/// действие стирало бы то, что само же добыло.
pub fn told<T>(seen: Told<T>, sight: Sight) -> Told<T> {
    match (seen, sight) {
        (Told::Nothing, Sight::Partial { .. }) => Told::Blind,
        (Told::Nothing, Sight::Full) => Told::Nothing,
        (Told::Told(value), _any) => Told::Told(value),
        (Told::Blind, _any) => Told::Blind,
    }
}
