//! ЗАКОНЫ ФУНКТОРА ПОДЪЁМА (канон §9.2).
//!
//! §9.2 называет `Lift` функтором: «`Lift` поднимает морфизм в поток; функтор идёт только вверх».
//! Слово стояло, законов не было — ни одного. Инвентаризация 20.09.2026: единственный сторож
//! подъёма (`lifting_carries_one_machine_through_the_whole_stream`, `core/tests/step.rs`) утверждает
//! «машина одна на весь поток», а это свойство реализации, не функториальность. Функтор, чьи законы
//! не предъявлены, есть слово на бумаге: подъём, теряющий шаг или пересобирающий машину, назывался
//! бы функтором ровно так же.
//!
//! # Какие два закона и почему они выглядят так
//!
//! **Сохранение тождества:** `Lift(id) = id`. Поднятое тождество отдаёт поток, дословно
//! повторяющий вход. Проверяется по выходам — иначе никак: типы `Lift<S, Id<T>>` и `S` разные.
//!
//! **Сохранение композиции:** `Lift(g ∘ f) = Lift(g) ∘ Lift(f)`. Равенство наблюдательное и с
//! ПЕРЕХОДНИКОМ, и переходник — не поблажка, а сама форма подъёма: `Lift` отдаёт пары `(Out, Log)`,
//! тогда как на вход второму звену нужно слово. То есть буквального `Lift(g) ∘ Lift(f)` не
//! существует в типах, и закон говорит о том, что есть: поток слов, снятый с первого подъёма и
//! поданный второму, даёт ровно то же, что подъём композита. Логи сверяются отдельной парой —
//! §3.4 обещает произведение, и подъём обязан донести обе половины.
//!
//! # Метод
//!
//! Тот же, что у `step_laws.rs`: мир конечен, перебор исчерпывающий, равенство наблюдательное. Своя
//! область у стенда — закон обязан быть выразим тем, кто заводит область снаружи фундамента.
//!
//! # Чем показан красный (Правило 10.7)
//!
//! Мутант «подъём глотает букву» (лишний `poll_next` перед рабочим) валит все четыре закона —
//! проверено прогоном, не выведено. Второй мутант, перестановка половин показания в `Compose`, НЕ
//! СОБИРАЕТСЯ: порядок логов держат типы (`(A::Log, B::Log)`), и закон о показаниях сторожит,
//! стало быть, не порядок, а ДОНЕСЕНИЕ обеих половин подъёмом — что типами не держится.
//!
//! # Чего эти законы НЕ сторожат
//!
//! Они не видят ЛЕНИВОСТИ и не видят `Pending`: источник здесь готов всегда
//! (`futures::stream::iter`), и поведение подъёма на неготовом источнике остаётся за ними. Сказано
//! прямо, чтобы зелёный не читался шире, чем есть.

use futures::StreamExt;
use reflex_core::mealy::{Id, Mealy, MealyExt};
use reflex_core::word::{Base, Word};

/// ОБЛАСТЬ ЗАКОННОГО СТЕНДА — заводится снаружи фундамента, как и в законах категории.
struct Bench;
impl Base for Bench {
    type Fibre = ();
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Beat(u8);

impl Word for Beat {
    type Of = Bench;
}

/// МИР КОНЕЧЕН: все непустые последовательности длины ≤ 3 из трёх значений.
///
/// Длина три — минимум, на котором видна разница между «машина живёт» и «машина пересобирается»: на
/// одном входе подъём с потерянным состоянием неотличим от исправного.
fn world() -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for a in 0..3u8 {
        out.push(vec![a]);
        for b in 0..3u8 {
            out.push(vec![a, b]);
            for c in 0..3u8 {
                out.push(vec![a, b, c]);
            }
        }
    }
    out
}

/// СУММАТОР: помнит всё, что прошло, и копит показание — лог нужен закону о композиции.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Adding(u8);

impl Mealy for Adding {
    type In = Beat;
    type Out = Beat;
    type Log = u8;

    fn step(self, input: Beat) -> (Self, Beat, u8) {
        let sum = self.0.wrapping_add(input.0);
        (Adding(sum), Beat(sum), sum)
    }
}

/// ЗАПАЗДЫВАЮЩИЙ УДВОИТЕЛЬ: память об одном шаге назад — второй вид памяти в том же мире.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Doubling(u8);

impl Mealy for Doubling {
    type In = Beat;
    type Out = Beat;
    type Log = u8;

    fn step(self, input: Beat) -> (Self, Beat, u8) {
        let out = input.0.wrapping_mul(2).wrapping_add(self.0);
        (Doubling(input.0), Beat(out), input.0)
    }
}

/// Прогнать подъём по входам и собрать всё, что он выпустил.
fn lifted<M>(machine: M, input: &[u8]) -> Vec<(Beat, M::Log)>
where
    M: Mealy<In = Beat, Out = Beat>,
{
    let source = futures::stream::iter(input.iter().map(|byte| Beat(*byte)));
    futures::executor::block_on(machine.over(source).collect::<Vec<_>>())
}

/// ЗАКОН 1: `Lift(id) = id` — поднятое тождество дословно повторяет вход.
#[test]
fn lifting_preserves_identity() {
    for input in world() {
        let out: Vec<Beat> = lifted(Id::new(), &input)
            .into_iter()
            .map(|(said, ())| said)
            .collect();
        let bare: Vec<Beat> = input.iter().map(|byte| Beat(*byte)).collect();

        assert_eq!(out, bare, "поднятое тождество исказило вход {input:?}");
    }
}

/// ЗАКОН 2: `Lift(g ∘ f) = Lift(g) ∘ Lift(f)` по словам.
///
/// Слева — подъём композита. Справа — подъём первого звена, с которого сняты слова и поданы
/// подъёму второго. Совпасть они обязаны на каждом шаге, а не в сумме: подъём, съевший шаг или
/// переставивший состояния, дал бы ту же длину при других значениях.
#[test]
fn lifting_preserves_composition() {
    for input in world() {
        let composed: Vec<Beat> = lifted(Adding(0).then(Doubling(0)), &input)
            .into_iter()
            .map(|(said, _log)| said)
            .collect();

        let first: Vec<u8> = lifted(Adding(0), &input)
            .into_iter()
            .map(|(Beat(said), _log)| said)
            .collect();
        let then_second: Vec<Beat> = lifted(Doubling(0), &first)
            .into_iter()
            .map(|(said, _log)| said)
            .collect();

        assert_eq!(
            composed, then_second,
            "подъём композита разошёлся с композицией подъёмов на входе {input:?}"
        );
    }
}

/// ЗАКОН 2а: ПОКАЗАНИЯ ТОЖЕ ДОНЕСЕНЫ, и обе половины произведения (§3.4).
///
/// Отдельным законом, а не вместе со словами: подъём, роняющий лог второго звена, прошёл бы закон 2
/// целиком — слова-то он несёт. Произведение логов проверяется поэлементно против логов, снятых со
/// звеньев порознь.
#[test]
fn lifting_carries_both_halves_of_the_log() {
    for input in world() {
        let composed: Vec<(u8, u8)> = lifted(Adding(0).then(Doubling(0)), &input)
            .into_iter()
            .map(|(_said, log)| log)
            .collect();

        let first: Vec<(Beat, u8)> = lifted(Adding(0), &input);
        let words: Vec<u8> = first.iter().map(|(Beat(said), _log)| *said).collect();
        let left: Vec<u8> = first.into_iter().map(|(_said, log)| log).collect();
        let right: Vec<u8> = lifted(Doubling(0), &words)
            .into_iter()
            .map(|(_said, log)| log)
            .collect();

        let apart: Vec<(u8, u8)> = left.into_iter().zip(right).collect();

        assert_eq!(
            composed, apart,
            "подъём потерял половину показания на входе {input:?}"
        );
    }
}

/// ЧИСЛО ШАГОВ РАВНО ЧИСЛУ БУКВ — закон, который два предыдущих по отдельности не держат.
///
/// Подъём, выпускающий по паре на букву, обязан не проглотить ни одной и не выдумать лишней. Оба
/// закона выше сравнивают ДВА подъёма между собой: сломай оба одинаково — и они сойдутся. Здесь
/// сравнение с входом, который подъёмом не проходил вовсе.
#[test]
fn lifting_yields_exactly_one_word_per_letter() {
    for input in world() {
        let said = lifted(Adding(0), &input);
        assert_eq!(
            said.len(),
            input.len(),
            "подъём выпустил не по слову на букву, вход {input:?}"
        );
    }
}
