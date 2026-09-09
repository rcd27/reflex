use core::cell::Cell;

use reflex_engine::row::{Answered, Naming};
use reflex_engine::step::{sever, step, RETELL_HORIZON};
use reflex_engine::Span;
use reflex_engine::{
    Act, Addr, Basis, Cursor, Dir, Epoch, Flow, Interest, Mark, Noticed, Packet, Plan,
    Programme, Sighting, Stepped, Tick,
};

/// ЧТО НАБЛЮДЕНО — без адресата и момента.
///
/// Проекция, а не обеднение: у наблюдения три составляющих, и проверке предмета две другие не
/// нужны. Их стережёт отдельная проверка — иначе они бы не покрывались вовсе, и `Noted` завёлся бы
/// с полями, о которых никто ничего не утверждает.
fn told(stepped: &Stepped) -> Option<Sighting> {
    stepped.sighting.map(|noted| match noted.what {
        Noticed::Talk(sighting) => sighting,
        // ШАГ ВИДИТ ТОЛЬКО РАЗГОВОР: потеря цели случается не на пакете и сюда не приходит.
        Noticed::Loss(lost) => panic!("шаг сказал о цели, а не о разговоре: {lost}"),
    })
}

/// ЧТО ОСТАЛОСЬ ОТ ЗАКРЫВШЕГОСЯ РАЗГОВОРА: цель ответила через `after`, и мы видели три пакета.
fn closed(after: u64) -> reflex_engine::row::Closed {
    reflex_engine::row::Closed {
        answered: Answered::After(Span(after)),
        counted: reflex_engine::row::Counted {
            up: 2,
            up_bytes: 200,
            down: 1,
            down_bytes: 100,
        },
    }
}

fn plan(programme: Programme, epoch: u32) -> Plan {
    Plan {
        programme,
        epoch: Epoch(epoch),
        basis: Basis::Seeded,
        // Наблюдательный интерес шаг закона не читает: он решает, ЧТО сделать с пакетом, а не
        // кто на него смотрит.
        interest: Interest::Idle,
    }
}

fn packet(dir: Dir, payload: &[u8]) -> Packet {
    Packet {
        flow: flow_of(1),
        dst: Addr(7),
        dir,
        opens: false,
        closes: false,
        resets: false,
        payload_len: payload.len(),
        says: Naming::Awaited,
    }
}

/// ПАКЕТ, НА КОТОРОМ ЦЕЛЬ НАЗВАЛАСЬ. На проводе это `ClientHello`; ядру довольно признака.
fn hello(payload: &[u8]) -> Packet {
    Packet {
        says: Naming::Spoken(()),
        ..packet(Dir::Up, payload)
    }
}

/// ПАКЕТ, НА КОТОРОМ ПРИВЕТСТВИЕ ПРОШЛО БЕЗ ИМЕНИ: коннект по IP, MTProto, ECH. Имени НЕ БУДЕТ —
/// и это другой факт, чем «имя впереди».
fn nameless_hello(payload: &[u8]) -> Packet {
    Packet {
        says: Naming::Silent,
        ..packet(Dir::Up, payload)
    }
}

fn syn<'a>() -> Packet {
    Packet {
        opens: true,
        ..packet(Dir::Up, &[])
    }
}

fn run_of(programme: Programme, epoch: u32) -> Cursor {
    step(
        |_| plan(programme, epoch),
        Epoch(epoch),
        Cursor::Fresh,
        &syn(),
        Tick(0),
    )
    .cursor
}

/// ЗАКРЫВШИЙСЯ РАЗГОВОР НЕСЁТ РЕШЕНИЕ ЦЕЛИ, А ПОТЕРЯННЫЙ — НЕТ.
///
/// Пара тестов, и проверяется она РАЗНИЦЕЙ: одно значение ничего бы не установило, потому что
/// прежде обе величины жили под одним именем `Lost` и делили один акт `Pass`. Цена того слияния
/// названа числом: витнес `plane-mark.sh` краснел на 2 прогонах из 10 — последний `ACK` уходил
/// мимо ноги при выученной цели.
#[test]
fn an_ended_conversation_still_carries_the_targets_decision() {
    let stepped: Stepped = step(
        |_| plan(Programme::Mark(Mark(0xbb)), 1),
        Epoch(1),
        Cursor::Ended(closed(40)),
        &packet(Dir::Up, &[]),
        Tick(5),
    );

    assert_eq!(stepped.act, Act::Marked(Mark(0xbb)));
    // ОТВЕТ ЦЕЛИ ПЕРЕЖИВАЕТ ХВОСТ НЕИЗМЕННЫМ, а счёт РАСТЁТ: хвостовой пакет мы видели, и ядро
    // его считает тоже. Перестань считать его мы — счета разошлись бы ровно на хвост, и `sighted`
    // объявил бы это нашей слепотой.
    assert!(
        matches!(
            stepped.cursor,
            Cursor::Ended(reflex_engine::row::Closed {
                answered: Answered::After(Span(40)),
                counted: reflex_engine::row::Counted { up: 3, .. }
            })
        ),
        "хвост разговора забыл ответ цели либо не посчитал себя: {:?}",
        stepped.cursor
    );
    assert_eq!(
        stepped.sighting, None,
        "решение несётся, но разговор не открывается заново"
    );
}

#[test]
fn a_lost_cursor_passes_and_never_takes_a_new_plan() {
    let stepped: Stepped = step(
        |_| plan(Programme::Mark(Mark(0xbb)), 1),
        Epoch(1),
        Cursor::Lost,
        &packet(Dir::Up, &[0u8; 200]),
        Tick(5),
    );

    assert_eq!(stepped.act, Act::Pass);
    assert_eq!(stepped.cursor, Cursor::Lost);
    assert_eq!(stepped.sighting, None);
}

/// Знание спрашивается ДВАЖДЫ за разговор и не чаще: на открытии и на назывании (#317).
/// Не «однажды», как было до переноса момента, — но и не на каждом пакете: спроси мы на каждом,
/// страта менялась бы посреди применения.
#[test]
fn the_table_is_consulted_at_the_opening_and_at_the_naming_and_no_more() {
    let asked = Cell::new(0u32);
    let look_up = |_packet: &Packet| {
        asked.set(asked.get() + 1);
        plan(Programme::Pass, 1)
    };

    let opened = step(&look_up, Epoch(1), Cursor::Fresh, &syn(), Tick(0));
    let named = step(
        &look_up,
        Epoch(1),
        opened.cursor,
        &hello(&[0u8; 300]),
        Tick(1),
    );
    let carried = step(
        &look_up,
        Epoch(1),
        named.cursor,
        &packet(Dir::Up, &[0u8; 300]),
        Tick(2),
    );
    // ВТОРОЕ ИМЯ В ТОМ ЖЕ РАЗГОВОРЕ НИЧЕГО НЕ СПРАШИВАЕТ — контроль к закону «принимается один раз».
    step(
        &look_up,
        Epoch(1),
        carried.cursor,
        &hello(&[0u8; 300]),
        Tick(3),
    );

    assert_eq!(asked.get(), 2);
}

/// ГЛАВНЫЙ ЗАКОН #317: знание, ключёванное ИМЕНЕМ, доезжает до соединения, которое на открытии
/// было безымянным. До переноса момента план брался на SYN — то есть по адресу, единственному,
/// что тогда известно, — и второй адрес той же цели уходил мимо ноги («пакетов ногой 0» при
/// исправной петле, живой прогон 31.08).
#[test]
fn the_plan_is_taken_from_the_identity_not_from_the_address_it_opened_on() {
    let by_address = plan(Programme::Pass, 1);
    let by_identity = plan(Programme::Mark(Mark(0xcc)), 1);
    let look_up = |packet: &Packet| match packet.says {
        Naming::Awaited => by_address,
        Naming::Spoken(()) | Naming::Silent => by_identity,
    };

    let opened = step(&look_up, Epoch(1), Cursor::Fresh, &syn(), Tick(0));
    assert_eq!(opened.act, Act::Pass);

    let named = step(
        &look_up,
        Epoch(1),
        opened.cursor,
        &hello(&[0u8; 300]),
        Tick(1),
    );

    // МЕТКА СТОИТ НА ТОМ ЖЕ ПАКЕТЕ, ГДЕ ЦЕЛЬ НАЗВАЛАСЬ. Это и есть весь предмет: `ClientHello` —
    // единственный пакет, который страте есть что лечить, и решение обязано состояться НА НЁМ, а
    // не тактом позже.
    assert_eq!(named.act, Act::Marked(Mark(0xcc)));

    let after = step(
        &look_up,
        Epoch(1),
        named.cursor,
        &packet(Dir::Up, &[0u8; 100]),
        Tick(2),
    );
    assert_eq!(after.act, Act::Marked(Mark(0xcc)));
}

/// КОНТРОЛЬ К ПРЕДЫДУЩЕМУ: разговор, где цель не назвалась НИКОГДА (коннект по чистому IP,
/// докачка без hello), остаётся на плане, взятом по адресу. Без этого теста закон выше зеленел
/// бы и у реализации, которая просто ждёт второго пакета.
#[test]
fn a_conversation_that_never_names_its_target_keeps_the_plan_it_opened_with() {
    let by_address = plan(Programme::Pass, 1);
    let by_identity = plan(Programme::Mark(Mark(0xcc)), 1);
    let look_up = |packet: &Packet| match packet.says {
        Naming::Awaited => by_address,
        Naming::Spoken(()) | Naming::Silent => by_identity,
    };

    let opened = step(&look_up, Epoch(1), Cursor::Fresh, &syn(), Tick(0));
    let carried = step(
        &look_up,
        Epoch(1),
        opened.cursor,
        &packet(Dir::Up, &[0u8; 300]),
        Tick(1),
    );

    assert_eq!(carried.act, Act::Pass);
}

#[test]
fn the_plan_chosen_at_the_start_is_carried_for_the_whole_conversation() {
    let opened = run_of(Programme::Mark(Mark(0xcc)), 1);

    let asking = step(
        |_| plan(Programme::Pass, 1),
        Epoch(1),
        opened,
        &packet(Dir::Up, &[0u8; 100]),
        Tick(1),
    );

    assert_eq!(asking.act, Act::Marked(Mark(0xcc)));
}

#[test]
fn a_reset_before_the_target_spoke_is_told_apart_from_one_after() {
    let silent = run_of(Programme::Pass, 1);
    let early = step(
        |_| plan(Programme::Pass, 1),
        Epoch(1),
        silent,
        &Packet {
            resets: true,
            ..packet(Dir::Down, &[])
        },
        Tick(1),
    );

    let spoken = step(
        |_| plan(Programme::Pass, 1),
        Epoch(1),
        silent,
        &packet(Dir::Down, &[0u8; 50]),
        Tick(1),
    );
    let late = step(
        |_| plan(Programme::Pass, 1),
        Epoch(1),
        spoken.cursor,
        &Packet {
            resets: true,
            ..packet(Dir::Down, &[])
        },
        Tick(2),
    );

    assert_eq!(
        told(&early),
        Some(Sighting::Reset {
            dst: Addr(7),
            by_client: false,
            target_spoke: false
        })
    );
    assert_eq!(
        told(&late),
        Some(Sighting::Reset {
            dst: Addr(7),
            by_client: false,
            target_spoke: true
        })
    );
}

#[test]
fn a_stale_epoch_is_told_once_and_not_on_every_packet_afterwards() {
    let opened = run_of(Programme::Mark(Mark(0xbb)), 1);

    let first = step(
        |_| plan(Programme::Mark(Mark(0xbb)), 1),
        Epoch(2),
        opened,
        &packet(Dir::Up, &[0u8; 10]),
        Tick(1),
    );
    let second = step(
        |_| plan(Programme::Mark(Mark(0xbb)), 1),
        Epoch(2),
        first.cursor,
        &packet(Dir::Up, &[0u8; 10]),
        Tick(2),
    );

    assert_eq!(
        told(&first),
        Some(Sighting::Stale {
            dst: Addr(7),
            was: Epoch(1)
        })
    );
    assert_eq!(second.sighting, None);
}

/// ПОТЕРЯННЫЙ РАССКАЗ ПОВТОРЯЕТСЯ ЧЕРЕЗ ГОРИЗОНТ — потеря становится ЗАДЕРЖКОЙ, а не потерей.
///
/// Канал наверх лоссовый ПО ПОСТРОЕНИЮ: мы сами так решили и считаем потери. Значит однократный
/// рассказ — это edge-triggered логика в канале, который её не выдерживает: приказ потерялся, а
/// повтора не будет никогда, потому что флоу уже считает, что рассказал.
///
/// Цена в единице человека названа при заведении долга: ролик, начатый по пути, который с тех пор
/// признан мёртвым, доигрывает по нему до конца — вечная загрузка либо обрыв в середине.
///
/// Пара с тестом выше и есть правило целиком: там — «не на каждом пакете», здесь — «и не один
/// раз навсегда». Порознь каждый допускает вырожденную реализацию.
#[test]
fn a_stale_epoch_is_told_again_after_the_horizon_because_the_channel_is_lossy() {
    let opened = run_of(Programme::Mark(Mark(0xbb)), 1);

    let first = step(
        |_| plan(Programme::Mark(Mark(0xbb)), 1),
        Epoch(2),
        opened,
        &packet(Dir::Up, &[0u8; 10]),
        Tick(1),
    );
    // Пакет сразу за первым: рассказывать снова незачем, движок только что услышал.
    let soon = step(
        |_| plan(Programme::Mark(Mark(0xbb)), 1),
        Epoch(2),
        first.cursor,
        &packet(Dir::Up, &[0u8; 10]),
        Tick(2),
    );
    // Пакет за горизонтом: рассказ обязан прозвучать снова — вдруг первый не доехал.
    let later = step(
        |_| plan(Programme::Mark(Mark(0xbb)), 1),
        Epoch(2),
        soon.cursor,
        &packet(Dir::Up, &[0u8; 10]),
        Tick(1 + RETELL_HORIZON.0 + 1),
    );

    assert!(first.sighting.is_some(), "предпосылка: первый рассказ был");
    assert_eq!(soon.sighting, None, "рассказ на каждом пакете вернулся");
    assert_eq!(
        told(&later),
        Some(Sighting::Stale {
            dst: Addr(7),
            was: Epoch(1)
        }),
        "рассказ не повторён за горизонтом — потерянный приказ потерян навсегда"
    );
}

/// ПОМЕЧЕННЫЙ ФЛОУ УХОДИТ НА КАЖДОМ ПАКЕТЕ, а не только на первом.
///
/// Прежде предмет проверялся отводом (`Divert(QuicStep)`); отвод снят вместе с исполнителем
/// (#326), и свойство перенесено на метку — оно принадлежит не отводу, а всякому решению,
/// которое ядро обязано исполнять на всём разговоре.
#[test]
fn a_marked_flow_leaves_on_every_packet_not_only_the_first() {
    let opened = run_of(Programme::Mark(Mark(0xCC)), 1);

    let stepped = step(
        |_| plan(Programme::Mark(Mark(0xCC)), 1),
        Epoch(1),
        opened,
        &packet(Dir::Down, &[0u8; 900]),
        Tick(1),
    );

    assert_eq!(stepped.act, Act::Marked(Mark(0xCC)));
}

#[test]
fn the_first_packet_of_a_flow_reports_what_the_plan_stood_on() {
    let stepped = step(
        |_| Plan {
            programme: Programme::Mark(Mark(1)),
            epoch: Epoch(1),
            basis: Basis::Default,
            interest: Interest::Idle,
        },
        Epoch(1),
        Cursor::Fresh,
        &syn(),
        Tick(0),
    );

    assert_eq!(
        told(&stepped),
        Some(Sighting::Opened {
            dst: Addr(7),
            basis: Basis::Default
        })
    );
}

/// ПРИВЕТСТВИЕ БЕЗ ИМЕНИ ЗАКРЫВАЕТ ВОПРОС О ЛИЧНОСТИ, А НЕ ОТКЛАДЫВАЕТ ЕГО (#300).
///
/// Это правка дефекта, найденного разбором алгебры: прежде принятие плана ждало ИМЕНИ, и разговор,
/// чьё приветствие прошло без имени, оставался «временным» навсегда. Мелькни в нём позже имя —
/// страта сменилась бы на середине применения, то есть применилась бы полторы.
#[test]
fn a_hello_without_a_name_settles_the_plan_and_a_later_name_does_not_move_it() {
    let by_address = plan(Programme::Pass, 1);
    let by_identity = plan(Programme::Mark(Mark(0xcc)), 1);
    let look_up = |packet: &Packet| match packet.says {
        Naming::Awaited => by_address,
        Naming::Silent => by_address,
        Naming::Spoken(()) => by_identity,
    };

    let opened = step(&look_up, Epoch(1), Cursor::Fresh, &syn(), Tick(0));
    let silent = step(
        &look_up,
        Epoch(1),
        opened.cursor,
        &nameless_hello(&[0u8; 300]),
        Tick(1),
    );
    assert_eq!(
        silent.act,
        Act::Pass,
        "безымянное приветствие обслуживается адресом"
    );

    // ПОЗДНЕЕ ИМЯ В ТОМ ЖЕ РАЗГОВОРЕ — ретрансмиссия, чужой split-hello, наш промах разбора.
    let late = step(
        &look_up,
        Epoch(1),
        silent.cursor,
        &hello(&[0u8; 300]),
        Tick(2),
    );

    assert_eq!(
        late.act,
        Act::Pass,
        "план сменился после того, как личность была установлена"
    );
}

// ═══ ЗАКОНЫ JOIN'А ЗНАНИЯ О ЛИЧНОСТИ (#300) ═══
//
// Знание о личности — элемент чума по информации (`Awaited` = ⊥ ⊑ `Silent` ⊑ `Spoken`), событие
// провода — монотонная функция на нём. Три закона ниже и есть то, что делает `joined` join'ом, а
// не «правилом обновления»: правило можно написать любое, join — нет.
//
// Проверяются на ВСЕХ парах, а не на образцах: состояний три, пар девять, перебор дешевле выборки
// и не оставляет клетки непроверенной.

fn all_namings() -> [Naming<()>; 3] {
    [Naming::Awaited, Naming::Silent, Naming::Spoken(())]
}

/// Порядок по информации: ⊥ ниже всех, `Silent` ниже `Spoken`.
fn informs(one: Naming<()>) -> u8 {
    match one {
        Naming::Awaited => 0,
        Naming::Silent => 1,
        Naming::Spoken(()) => 2,
    }
}

/// ЗНАНИЕ НЕ УБЫВАЕТ НИ ОТ КАКОГО СОБЫТИЯ. Нарушь это — и наблюдение могло бы СТИРАТЬ добытое,
/// то есть действие отменяло бы то, что само же установило.
#[test]
fn knowing_never_shrinks() {
    all_namings().into_iter().for_each(|known| {
        all_namings().into_iter().for_each(|said| {
            assert!(
                informs(reflex_engine::joined(known, said)) >= informs(known),
                "знание убыло: {known:?} ⊔ {said:?}"
            );
        })
    });
}

/// ПОВТОР ТОГО ЖЕ СОБЫТИЯ — НЕ СОБЫТИЕ. Ретрансмиссия приветствия обязана оставлять знание там же.
#[test]
fn repeating_the_same_event_changes_nothing() {
    all_namings().into_iter().for_each(|known| {
        all_namings().into_iter().for_each(|said| {
            let once = reflex_engine::joined(known, said);
            assert_eq!(
                reflex_engine::joined(once, said),
                once,
                "повтор сдвинул знание: {known:?} ⊔ {said:?} ⊔ {said:?}"
            );
        })
    });
}

/// ПОРЯДОК ПРИХОДА НЕ РЕШАЕТ. Провод переставляет пакеты, а с выпадением userspace из горячего
/// пути мы вдобавок увидим лишь ПОДМНОЖЕСТВО событий: движок, чей вердикт зависит от очерёдности,
/// на таком проводе недетерминирован.
#[test]
fn the_order_of_arrival_does_not_decide() {
    all_namings().into_iter().for_each(|first| {
        all_namings().into_iter().for_each(|second| {
            assert_eq!(
                reflex_engine::joined(reflex_engine::joined(Naming::Awaited, first), second),
                reflex_engine::joined(reflex_engine::joined(Naming::Awaited, second), first),
                "порядок изменил вердикт: {first:?} против {second:?}"
            );
        })
    });
}

/// КОНТРОЛЬ К ТРЁМ ЗАКОНАМ: снимок решения ИМИ НЕ СВЯЗАН, и это не недосмотр.
///
/// `stood_on` — запись о прошлом решении, а не знание: мы действовали тем, что пришло первым.
/// Если бы и она была коммутативна, тесты выше зеленели бы у обеих функций, и различить величины
/// было бы нечем — то есть законы не свидетельствовали бы ни о чём.
#[test]
fn the_snapshot_of_a_decision_is_deliberately_order_dependent() {
    assert_eq!(
        reflex_engine::stood_on(
            reflex_engine::stood_on(Naming::Awaited, Naming::Silent),
            Naming::Spoken(())
        ),
        Naming::Silent,
        "снимок сдвинулся после того, как решение уже принято"
    );
    assert_eq!(
        reflex_engine::stood_on(
            reflex_engine::stood_on(Naming::Awaited, Naming::Spoken(())),
            Naming::Silent
        ),
        Naming::Spoken(())
    );
}

/// SYN НА ЗАКРЫВШЕМСЯ РАЗГОВОРЕ ОТКРЫВАЕТ НОВЫЙ, А НЕ ПРОДОЛЖАЕТ СТАРЫЙ.
///
/// Четвёрка переиспользуется, и ключ разговора — она. Не открой мы новый run, второй разговор
/// наследовал бы состояние первого: с выпуском по состоянию это значит выпустить его НА SYN, под
/// чужой личностью, и приветствие новой цели до нас не доедет. Замерено: 59 КБ мимо userspace.
#[test]
fn a_syn_on_an_ended_conversation_opens_a_new_one() {
    let stepped: Stepped = step(
        |_| plan(Programme::Mark(Mark(0xbb)), 1),
        Epoch(1),
        Cursor::Ended(closed(40)),
        &syn(),
        Tick(9),
    );

    assert!(
        matches!(stepped.cursor, Cursor::Running(_)),
        "новый разговор обязан завести курсор, вышло {:?}",
        stepped.cursor
    );
    assert!(
        matches!(told(&stepped), Some(Sighting::Opened { .. })),
        "открытие обязано быть наблюдением — иначе строка о нём не узнает"
    );
}

/// ПРИКАЗ ОБОРВАТЬ ЖИВОЙ РАЗГОВОР ИСПОЛНЯЕТСЯ И ПОДТВЕРЖДАЕТСЯ (#318).
///
/// Замысел владельца 31.08: «движок говорит датаплейну — сбрасывай такое-то соединение со стороны
/// клиента, после того как датаплейн отрапортовал троттлинг; датаплейн подтверждает выполнение».
///
/// # Приказ адресован РАЗГОВОРУ, а не цели, и это выяснилось первым же красным
///
/// План замерзает на открытии (`stood_on`) — оттого смена плана ЦЕЛИ живой разговор не трогает,
/// он лишь помечается устаревшим. Ровно поэтому приказ на живое не выражается через план: он
/// обязан прийти в конкретный разговор и лечь в его состояние.
///
/// # Почему отдельная программа, а не `Drop`
///
/// `Drop` роняет ПАКЕТ и молчит: клиент ждёт до своего таймаута, и человек сидит перед крутилкой
/// ровно столько же, сколько сидел бы без нас. Обрыв обязан СКАЗАТЬ, чтобы клиент переподключился
/// немедленно и попал на исправленный план.
///
/// # Свидетельство берётся с ПРОВОДА, а не из журнала
///
/// «Мы послали сброс» — намерение. Что разговор кончился, видно по курсору: он возвращается в
/// `Fresh`, и следующий пакет откроет разговор заново, прочитав текущий план.
#[test]
fn an_order_to_sever_ends_the_conversation_and_says_so() {
    let opened = run_of(Programme::Mark(Mark(0xbb)), 1);

    // ПРИКАЗ ЛОЖИТСЯ В РАЗГОВОР. До него шаг идёт как обычно — это проверяет контроль ниже.
    let ordered = sever(opened);

    let severed = step(
        |_| plan(Programme::Mark(Mark(0xbb)), 1),
        Epoch(1),
        ordered,
        &packet(Dir::Up, &[0u8; 10]),
        Tick(5),
    );

    assert_eq!(severed.act, Act::Sever, "приказ не исполнен");
    // ОБРЫВ ТОЖЕ КОНЧАЕТ РАЗГОВОР, и курсор называет это закрытием, а не возвратом к `Fresh`.
    // Разница с `Fresh` существенна: там разговора НЕ БЫЛО, здесь он БЫЛ и кончился, и о нём
    // известно всё, включая ответ цели. Кто именно оборвал, говорит `Sighting::Severed` — то есть
    // наблюдение, а не состояние.
    assert!(
        matches!(severed.cursor, Cursor::Ended(_)),
        "разговор пережил свой обрыв либо забыл, что был: {:?}",
        severed.cursor
    );
    assert_eq!(
        told(&severed),
        Some(Sighting::Severed { dst: Addr(7) }),
        "обрыв исполнен молча — движок не узнает, что приказ применён"
    );

    // КОНТРОЛЬ: без приказа тот же шаг идёт своим чередом. Без него «всегда рвём» прошло бы тест.
    let untouched = step(
        |_| plan(Programme::Mark(Mark(0xbb)), 1),
        Epoch(1),
        run_of(Programme::Mark(Mark(0xbb)), 1),
        &packet(Dir::Up, &[0u8; 10]),
        Tick(5),
    );
    assert_eq!(
        untouched.act,
        Act::Marked(Mark(0xbb)),
        "оборван неприказанный"
    );
}

/// ПРИВЕТСТВИЕ ВИДНО СНАРУЖИ — и видно, ЧТО оно сказало.
///
/// Прежде `Said` жил только внутри шага: план по нему принимался, наблюдения не выпускалось. Для
/// потребителя двери это значило, что момент, в который цель стала известной, не наступает — а
/// он единственный, где ключ цели доезжает вовремя (#317).
#[test]
fn the_hello_is_seen_from_outside_and_says_what_it_said() {
    let running = step(
        |_asked| plan(Programme::Pass, 1),
        Epoch(1),
        Cursor::Fresh,
        &syn(),
        Tick(1),
    );

    let named = step(
        |_asked| plan(Programme::Pass, 1),
        Epoch(1),
        running.cursor,
        &hello(b"CH"),
        Tick(2),
    );

    assert_eq!(
        told(&named),
        Some(Sighting::Recognised {
            dst: Addr(7),
            said: Naming::Spoken(())
        }),
        "приветствие прошло молча для двери — снаружи не узнать, когда цель стала известной"
    );
}

/// ПРИВЕТСТВИЕ БЕЗ ИМЕНИ — ЭТО ФАКТ, А НЕ ОТСУТСТВИЕ ФАКТА.
///
/// `Silent` значит «имени НЕ БУДЕТ» (коннект по IP, MTProto, ECH), `Awaited` — «его ещё не
/// было». Лечение у них разное, и слить их значило бы ждать имени, которое не придёт никогда.
/// Пара к предыдущему: без неё тест зеленел бы у шага, выпускающего `Recognised` с чем угодно.
#[test]
fn a_hello_without_a_name_is_told_apart_from_no_hello_at_all() {
    let running = step(
        |_asked| plan(Programme::Pass, 1),
        Epoch(1),
        Cursor::Fresh,
        &syn(),
        Tick(1),
    );

    let silent = step(
        |_asked| plan(Programme::Pass, 1),
        Epoch(1),
        running.cursor,
        &nameless_hello(b"nope"),
        Tick(2),
    );
    assert_eq!(
        told(&silent),
        Some(Sighting::Recognised {
            dst: Addr(7),
            said: Naming::Silent
        }),
        "молчание приветствия прочитано как ожидание — разговор остался бы ждать имени навсегда"
    );

    // ОБЫЧНЫЙ ПАКЕТ О ЛИЧНОСТИ НЕ ГОВОРИТ, и наблюдения из него нет: сказать «клиент назвался
    // ничем» значило бы объявить фактом ожидание.
    let plain = step(
        |_asked| plan(Programme::Pass, 1),
        Epoch(1),
        running.cursor,
        &packet(Dir::Up, b"data"),
        Tick(2),
    );
    assert_eq!(
        told(&plain),
        None,
        "пакет, ничего не сказавший о личности, выпустил наблюдение о ней"
    );
}

fn flow_of(n: u32) -> Flow {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    Flow {
        src: SocketAddr::new(IpAddr::V4(Ipv4Addr::from(0x0A00_0000 | n)), 40000 + n as u16),
        dst: SocketAddr::new(IpAddr::V4(Ipv4Addr::from(0x5DB8_D822)), 443),
        protocol: reflex_core::types::Protocol::Tcp,
    }
}
