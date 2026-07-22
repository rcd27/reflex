//! Шаг как морфизм с областью определённости (#152).
//!
//! `Step<A, B, E>` несёт ровно те четыре вещи, ради которых всё затевалось:
//! готовность (`guard`), ошибки (`Result`), наблюдаемость (guard читается БЕЗ
//! выполнения) и перезапускаемость (закон, а не флаг).
//!
//! Главное решение — в ТИПЕ ИСХОДА. `NotReady` и `Failed` разведены, и это прямая
//! проекция молекулы `GuardedRepair`: отсутствие успеха НЕ является уликой поломки.
//! Пока эти два случая живут в одном `Err`, страж обязан их спутать — и сожжёт
//! рабочий кред, приняв «сети не было» за «идентичность сломана». Здесь спутать их
//! нельзя: это разные конструкторы.

use reflex_os::{Level, Step, StepOutcome};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

// ГОТОВНОСТЬ: неготовый шаг не выполняется — и это НЕ ошибка.
#[test]
fn a_step_whose_guard_is_false_does_not_run_and_is_not_an_error() {
    let ran = Arc::new(AtomicUsize::new(0));
    let counted = ran.clone();
    let step: Step<(), u8, String> = Step::new(Level::always(false), move |()| {
        counted.fetch_add(1, Ordering::SeqCst);
        Ok(1)
    });

    let outcome = step.attempt(());

    assert_eq!(outcome, StepOutcome::NotReady);
    assert_eq!(
        ran.load(Ordering::SeqCst),
        0,
        "шаг выполнился вопреки охране"
    );
}

// ОШИБКИ отделены от неготовности: провал выполнения — это улика, а не тишина.
#[test]
fn failure_is_distinguishable_from_not_ready() {
    let step: Step<(), u8, String> =
        Step::new(Level::always(true), |()| Err("бэк отказал".to_string()));

    assert_eq!(
        step.attempt(()),
        StepOutcome::Failed("бэк отказал".to_string())
    );
}

// НАБЛЮДАЕМОСТЬ — главный закон рамки: готовность читается, НЕ выполняя шаг.
// Именно отсюда берётся ответ на вопрос «где мы застряли», которого сегодня нет
// ни у кого: его собирают из логов четырёх сервисов.
#[test]
fn readiness_is_observable_without_running_anything() {
    let ran = Arc::new(AtomicUsize::new(0));
    let counted = ran.clone();
    let step: Step<(), u8, String> = Step::new(Level::always(true), move |()| {
        counted.fetch_add(1, Ordering::SeqCst);
        Ok(1)
    });

    assert!(step.ready());
    assert!(step.ready());
    assert_eq!(
        ran.load(Ordering::SeqCst),
        0,
        "чтение готовности выполнило шаг — значит это не наблюдение, а действие"
    );
}

// ПОСЛЕДОВАТЕЛЬНАЯ КОМПОЗИЦИЯ: второй шаг не трогается, пока первый не продвинулся.
#[test]
fn then_does_not_touch_the_second_step_until_the_first_advances() {
    let ran = Arc::new(AtomicUsize::new(0));
    let counted = ran.clone();

    let first: Step<(), u8, String> = Step::new(Level::always(false), |()| Ok(7));
    let second: Step<u8, u8, String> = Step::new(Level::always(true), move |v| {
        counted.fetch_add(1, Ordering::SeqCst);
        Ok(v + 1)
    });

    let outcome = first.then(second).attempt(());

    assert_eq!(outcome, StepOutcome::NotReady);
    assert_eq!(ran.load(Ordering::SeqCst), 0, "второй шаг тронут зря");
}

// Композиция ПРОПУСКАЕТ значение, когда оба готовы.
#[test]
fn then_pipes_the_value_through_when_both_are_ready() {
    let first: Step<(), u8, String> = Step::new(Level::always(true), |()| Ok(7));
    let second: Step<u8, u8, String> = Step::new(Level::always(true), |v| Ok(v + 1));

    assert_eq!(first.then(second).attempt(()), StepOutcome::Advanced(8));
}

// ГОТОВНОСТЬ КОМПОЗИТА = готовность ПЕРВОГО, и это не упрощение, а честность.
// Готовность второго шага вычислима лишь ПОСЛЕ эффекта первого (в терминах
// restriction-категории — это откат ḡ вдоль f, а откатывать, не выполнив f, нечем).
// Заявлять «готовность композита = встреча готовностей» было бы ложью там, где
// первый шаг сам создаёт предпосылку второго — а у нас именно так: start_dataplane
// делает истинной готовность await_witness.
#[test]
fn readiness_of_a_composite_is_the_readiness_of_its_head() {
    let head_blocked: Step<(), u8, String> = Step::new(Level::always(false), |()| Ok(7));
    let tail_open: Step<u8, u8, String> = Step::new(Level::always(true), Ok);
    assert!(!head_blocked.then(tail_open).ready());

    let head_open: Step<(), u8, String> = Step::new(Level::always(true), |()| Ok(7));
    let tail_blocked: Step<u8, u8, String> = Step::new(Level::always(false), Ok);
    assert!(head_open.then(tail_blocked).ready());
}

// ПЕРЕЗАПУСКАЕМОСТЬ как ЗАКОН, а не флаг: шаг, объявленный перезапускаемым, обязан
// давать тот же исход при повторе. Проверяем на шаге с эффектом — записью в ячейку:
// повтор обязан оставить мир там же, где оставил первый прогон (f ∘ f ≡ f).
#[test]
fn a_restartable_step_is_idempotent() {
    let cell = Arc::new(AtomicUsize::new(0));
    let writes = cell.clone();
    let step: Step<(), (), String> = Step::new(Level::always(true), move |()| {
        writes.store(42, Ordering::SeqCst); // присвоение, а не накопление
        Ok(())
    });

    let once = step.attempt(());
    let after_once = cell.load(Ordering::SeqCst);
    let twice = step.attempt(());
    let after_twice = cell.load(Ordering::SeqCst);

    assert_eq!(once, twice, "повтор дал другой исход");
    assert_eq!(
        after_once, after_twice,
        "повтор оставил мир в другом состоянии"
    );
}

// А ВОТ КОНТРОЛЬ, ради которого предыдущий тест не пустой: шаг с накоплением
// перезапускаемым НЕ является, и закон обязан это увидеть. Это `mesh_bootstrap`
// в миниатюре — сжёг кред, повтор жжёт второй.
#[test]
fn a_consuming_step_is_caught_as_non_idempotent() {
    let burned = Arc::new(AtomicUsize::new(0));
    let counter = burned.clone();
    let step: Step<(), (), String> = Step::new(Level::always(true), move |()| {
        counter.fetch_add(1, Ordering::SeqCst);
        Ok(())
    });

    let _first = step.attempt(());
    let after_once = burned.load(Ordering::SeqCst);
    let _second = step.attempt(());
    let after_twice = burned.load(Ordering::SeqCst);

    assert_ne!(
        after_once, after_twice,
        "накапливающий шаг притворился идемпотентным — закон слеп"
    );
}

// НЕОБЯЗАТЕЛЬНЫЙ шаг вне своей области — ТОЖДЕСТВО, а не преграда. Этот закон я
// узнал провалом: подняв самогасящееся условие `mesh_bootstrap` в обычную охрану,
// я превратил «нечего делать, проходим» в «не готовы, стоп» и уронил 12 тестов
// Смотрителя. Охрана отвечает «действие применимо?», а не «идти ли дальше?».
#[test]
fn an_optional_step_outside_its_domain_is_the_identity() {
    let ran = Arc::new(AtomicUsize::new(0));
    let counted = ran.clone();
    let step: Step<u8, u8, String> = Step::optional(Level::always(false), move |v| {
        counted.fetch_add(1, Ordering::SeqCst);
        Ok(v + 100)
    });

    assert_eq!(step.attempt(7), StepOutcome::Advanced(7), "вход не пропущен");
    assert_eq!(ran.load(Ordering::SeqCst), 0, "неприменимый шаг выполнился");
}

// А внутри области — работает как обычный шаг.
#[test]
fn an_optional_step_inside_its_domain_acts() {
    let step: Step<u8, u8, String> = Step::optional(Level::always(true), |v| Ok(v + 100));
    assert_eq!(step.attempt(7), StepOutcome::Advanced(107));
}
