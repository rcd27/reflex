//! ШАГ — морфизм категории стадий на носителе ЗНАЧЕНИЯ (#326).
//!
//! Прежде категория стадий (`category.rs`, снесён до этой ветки) была построена над потоком: её
//! морфизмы задавались отображением потока, то есть жили в категории ПОТОКОВ, а стадия оставалась
//! фантомным ярлыком. Второй носитель — «пакет вошёл, вердикт вышел» — в ТУ категорию не влезал:
//! места для носителя в той конструкции не было вовсе.
//!
//! Здесь заводится новая БАЗА, на носителе значения: морфизм как машина Мили. Поток получается из
//! неё функтором, обратно — нет, и это не пробел, а несущая стена (`step::StepExt::over`).

use futures::StreamExt;
use reflex_core::step::{Step, StepExt};
use reflex_core::word::{Region, Word};

/// ОБЛАСТЬ ЗАКОННОГО СТЕНДА.
///
/// Объявляется здесь, а не в фундаменте: закон обязан быть выразим для того, кто заводит свою
/// область снаружи, и стенд — законный заводящий.
struct Bench;
impl Region for Bench {}

/// СЛОВО НУМЕРАТОРА: номер и само слово.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Numbered(u32, &'static str);

impl Word for Numbered {
    type Of = Bench;
}

/// СЛОВО РЕКОРДСМЕНА: номер и рекорд длины.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Record(u32, usize);

impl Word for Record {
    type Of = Bench;
}

/// НУМЕРАТОР: каждому входу даёт его порядковый номер.
///
/// Простейшая машина Мили: ответ зависит не только от входа, но и от того, сколько их было
/// раньше. Чистой функцией такое не выражается — ровно поэтому носитель шага не есть `Fn`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Numbering(u32);

impl Step for Numbering {
    type From = &'static str;
    type To = Numbered;

    fn step(self, word: &'static str) -> (Self, Numbered) {
        (Numbering(self.0 + 1), Numbered(self.0, word))
    }
}

/// РЕКОРДСМЕН: помнит самое длинное слово, что прошло насквозь.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Longest(usize);

impl Step for Longest {
    type From = Numbered;
    type To = Record;

    fn step(self, Numbered(number, word): Numbered) -> (Self, Record) {
        let seen = match word.len() > self.0 {
            true => word.len(),
            false => self.0,
        };
        (Longest(seen), Record(number, seen))
    }
}

/// СОСТОЯНИЕ ЖИВЁТ У ОБОИХ ЗВЕНЬЕВ, а не у первого.
///
/// Это и есть содержание композиции: `Then` обязан вернуть НОВУЮ пару машин, а не пересобрать
/// цепочку из начальных. Забудь он состояние второго звена — рекорд обнулялся бы на каждом слове,
/// и цепочка выглядела бы работающей на одном входе.
#[test]
fn composition_carries_the_state_of_both_links() {
    let chain = Numbering(0).then(Longest(0));

    let (chain, first) = chain.step("aa");
    let (_chain, second) = chain.step("bbbb");

    assert_eq!(first, Record(0, 2), "первое слово: номер 0, рекорд 2");
    assert_eq!(
        second,
        Record(1, 4),
        "второе слово: номер 1 (нумератор помнит), рекорд 4"
    );
}

/// ФУНКТОР ПОДНЯТИЯ ВЕДЁТ ЧЕРЕЗ ПОТОК ОДНУ МАШИНУ, а не по машине на элемент.
///
/// Это и есть содержание функтора: поднятый морфизм остаётся ТЕМ ЖЕ морфизмом. Пересоздавай
/// поднятие машину на каждом элементе — рекорд падал бы на коротком слове, а нумератор всегда
/// отвечал бы нулём. Оба симптома видны только с третьего элемента, поэтому их здесь три.
#[tokio::test]
async fn lifting_carries_one_machine_through_the_whole_stream() {
    let seen: Vec<Record> = Numbering(0)
        .then(Longest(0))
        .over(futures::stream::iter(["aa", "bbbb", "c"]))
        .collect()
        .await;

    assert_eq!(
        seen,
        vec![Record(0, 2), Record(1, 4), Record(2, 4)],
        "рекорд не падает на коротком слове, номера растут — машина в потоке одна"
    );
}
