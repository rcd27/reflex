use crate::row::Answered;
use crate::row::Naming;
use crate::{
    stood_on, About, Act, Cursor, Dir, Epoch, Noted, Ordered, Packet, Plan, Programme, Run,
    Announced, Sighting, Span, Stepped, Tick,
};

// TODO(#298): числа объявлены по слуху — заменить замером на риге
pub fn budget(programme: Programme) -> Span {
    match programme {
        Programme::Pass => Span(0),
        Programme::Mark(_) => Span(20),
    }
}

/// ЧТО ПЛАН ЦЕЛИ ЗНАЧИТ ДЛЯ ПАКЕТА.
///
/// ОБРЫВА ЗДЕСЬ БОЛЬШЕ НЕТ (#326). Прежде стояла строка `Programme::Sever => Act::Pass` с
/// пометкой «ЗАГЛУШКА», и она была не ленью, а следом неверной сигнатуры: обрыв адресуется
/// разговору, а не цели, и честного образа у него в этой точке не существовало. Заглушка при
/// этом молча подменяла наибольшую силу вмешательства наименьшей — единственная такая строка во
/// всей функции. Приказ на живое приходит другим путём: `Ordered::Sever` в состоянии разговора.
pub fn acted(programme: Programme) -> Act {
    match programme {
        Programme::Pass => Act::Pass,
        Programme::Mark(mark) => Act::Marked(mark),
    }
}

/// `look_up` зовётся ДВАЖДЫ за разговор, и это его смысл (#317): на открытии — с тем, что есть
/// на SYN (адрес), и на пакете, где цель назвалась, — с тем, что стало известно (имя). Ключ
/// выбирает вызывающий: ядро не знает ни имён, ни адресных карт, оно знает МОМЕНТ.
pub fn step<'a, L>(
    look_up: L,
    epoch: Epoch,
    cursor: Cursor,
    packet: &Packet<'a>,
    now: Tick,
) -> Stepped
where
    L: Fn(&Packet<'a>) -> Plan,
{
    match cursor {
        // ХВОСТ ЗАКРЫВШЕГОСЯ РАЗГОВОРА НЕСЁТ ТО ЖЕ РЕШЕНИЕ. Прежде здесь стоял `Act::Pass` вместе
        // с `Lost`, и последний `ACK` уходил МИМО ноги при выученной цели: решение переставало
        // применяться к байтам ровно на хвосте. Витнес этого не видел, пока решение исполняло
        // ядро по членству адреса — членство состояния курсора не знает.
        // SYN НА ЗАКРЫВШЕМСЯ РАЗГОВОРЕ ОТКРЫВАЕТ НОВЫЙ. Четвёрка переиспользуется, и без этой
        // ветки второй разговор наследовал бы личность первого: ключ тот же, имя от прошлого
        // соединения, закон выпуска честно видит «личность установлена» и выпускает на SYN —
        // приветствие новой цели до нас не доезжает вовсе. Замерено `lift-leak.sh`: 59 КБ ушли
        // мимо userspace под чужим именем.
        Cursor::Ended(_) if packet.opens => opened(look_up(packet), packet, now),
        Cursor::Ended(closed) => Stepped {
            act: acted(look_up(packet).programme),
            // ХВОСТ РАЗГОВОРА ТОЖЕ СЧИТАЕТСЯ, и это не мелочь. Ядро считает последний `ACK` и
            // ретрансмиссии наравне с прочим; перестань считать их мы — счета разойдутся ровно на
            // хвост, и `sighted` объявит это НАШЕЙ СЛЕПОТОЙ. Мы эти пакеты видели.
            //
            // Ответ цели при этом проносится неизменным: хвост о ней ничего нового не говорит.
            cursor: Cursor::Ended(crate::row::Closed {
                answered: closed.answered,
                counted: crate::row::Counted {
                    up: closed.counted.up + u64::from(matches!(packet.dir, Dir::Up)),
                    up_bytes: closed.counted.up_bytes
                        + match packet.dir {
                            Dir::Up => packet.payload.len() as u64,
                            Dir::Down => 0,
                        },
                    down: closed.counted.down + u64::from(matches!(packet.dir, Dir::Down)),
                    down_bytes: closed.counted.down_bytes
                        + match packet.dir {
                            Dir::Down => packet.payload.len() as u64,
                            Dir::Up => 0,
                        },
                },
            }),
            sighting: None,
        },
        Cursor::Lost => Stepped {
            act: Act::Pass,
            cursor: Cursor::Lost,
            sighting: None,
        },
        Cursor::Fresh => opened(look_up(packet), packet, now),
        Cursor::Running(run) => carried(look_up, run, epoch, packet, now),
    }
}

fn opened(plan: Plan, packet: &Packet<'_>, now: Tick) -> Stepped {
    let carrying = !packet.payload.is_empty();
    let upward = matches!(packet.dir, Dir::Up);
    let run = Run {
        plan,
        // ОТКРЫТИЕ ОБЫЧНО ЗНАЕТ ТОЛЬКО АДРЕС, и тогда разговор ЖДЁТ личности. Но открыться он
        // может и пакетом, который уже всё сказал (коробка увидела флоу не с начала), — потому
        // берётся сказанное, а не константа.
        naming: packet.says,
        up: u16::from(upward),
        down: u16::from(!upward),
        up_bytes: match upward {
            true => packet.payload.len() as u64,
            false => 0,
        },
        down_bytes: match upward {
            true => 0,
            false => packet.payload.len() as u64,
        },
        began: now,
        last_up: now,
        last_down: now,
        answered: match !upward && carrying {
            true => Answered::After(Span(0)),
            false => Answered::NotYet,
        },
        announced: Announced::Never,
        ordered: Ordered::Nothing,
    };
    Stepped {
        // На ОТКРЫТИИ приказа быть не может: разговор только что заведён, и адресовать ему ещё
        // никто ничего не успел.
        act: acted(plan.programme),
        cursor: Cursor::Running(run),
        sighting: Some(noted(
            &run,
            packet,
            now,
            Sighting::Opened {
                dst: packet.dst,
                basis: plan.basis,
            },
        )),
    }
}

/// НАБЛЮДЕНИЕ ОБРЕТАЕТ АДРЕСАТА И МОМЕНТ ЗДЕСЬ, где известны оба.
///
/// Одно место на все ветви, а не поле в каждой: адресат и момент у наблюдения с провода всегда
/// одни и те же — разговор, который его породил, и шаг, на котором это случилось. Разнеси их по
/// ветвям — и появилась бы ветвь, где их забыли проставить.
fn noted(run: &Run, packet: &Packet<'_>, now: Tick, what: Sighting) -> Noted {
    Noted {
        at: now,
        about: About::Talk(packet.flow),
        // РАЗЛИЧИТЕЛЬ, А НЕ ИМЯ: ядро имён не знает. Берётся знание РАЗГОВОРА о личности, а не
        // то, что сказал этот пакет: наблюдение о цели относится к разговору целиком, и пакет,
        // ничего не сказавший, не отменяет уже названного.
        target: stood_on(run.naming, packet.says),
        what,
    }
}

/// ЛИЧНОСТЬ ПРИНИМАЕТСЯ РОВНО ОДИН РАЗ — на первом пакете, который о ней сказал, и только если
/// разговор до сих пор её ЖДАЛ. Второе слово о личности плана не меняет: у соединения одна цель, а
/// повторный `ClientHello` (ретрансмиссия, чужой split hello) сменил бы страту на середине
/// применения — то есть применил бы полторы.
///
/// «СКАЗАЛ» ЗДЕСЬ ВКЛЮЧАЕТ МОЛЧАНИЕ ПРИВЕТСТВИЯ (`Silent`), и это правка дефекта, а не тонкость:
/// прежде принятие ждало ИМЕНИ, поэтому разговор, чьё приветствие прошло без имени, оставался
/// временным навсегда — и мелькни в нём позже имя, план сменился бы на середине применения.
/// Имени не будет — значит решение окончательно, и ждать нечего.
fn adopting(run: &Run, packet: &Packet<'_>) -> bool {
    matches!(run.naming, Naming::Awaited) && !matches!(packet.says, Naming::Awaited)
}

fn carried<'a, L>(look_up: L, run: Run, epoch: Epoch, packet: &Packet<'a>, now: Tick) -> Stepped
where
    L: Fn(&Packet<'a>) -> Plan,
{
    let carrying = !packet.payload.is_empty();
    let upward = matches!(packet.dir, Dir::Up);
    let spoke_now = !upward && carrying && matches!(run.answered, Answered::NotYet);
    // ПЛАН, ПРИНЯТЫЙ ПО ЛИЧНОСТИ, ВЫТЕСНЯЕТ ВРЕМЕННЫЙ. Отсюда же и `act` ниже: он берётся с
    // принятого плана, а не с того, что лежал на открытии, — иначе решение состоялось бы в
    // структуре и не состоялось на проводе.
    let plan = match adopting(&run, packet) {
        false => run.plan,
        true => look_up(packet),
    };
    // УСТАРЕВАНИЕ — ФУНКЦИЯ СОСТОЯНИЯ, А НЕ СЛЕД СОБЫТИЯ (#318). Прежде здесь стояло
    // `&& !run.stale_told`, то есть предикат зависел от истории и потому был неидемпотентен: в
    // лоссовом канале одна потеря отменяла приказ навсегда. Теперь спрашивается только эпоха, а
    // повторы дросселируются горизонтом — потеря становится задержкой.
    let stale = plan.epoch != epoch && due(run.announced, now);
    let over = packet.closes || packet.resets;

    let moved = Run {
        plan,
        naming: stood_on(run.naming, packet.says),
        up: run.up + u16::from(upward),
        down: run.down + u16::from(!upward),
        up_bytes: run.up_bytes + (packet.payload.len() as u64) * u64::from(upward),
        down_bytes: run.down_bytes + (packet.payload.len() as u64) * u64::from(!upward),
        last_up: match upward {
            true => now,
            false => run.last_up,
        },
        last_down: match upward {
            true => run.last_down,
            false => now,
        },
        answered: match (run.answered, spoke_now) {
            (Answered::NotYet, true) => Answered::After(Span(now.0.saturating_sub(run.began.0))),
            (held, _later) => held,
        },
        announced: match stale {
            true => Announced::At(now),
            false => run.announced,
        },
        ..run
    };

    Stepped {
        // ПРИКАЗ СТАРШЕ ПЛАНА: план говорит, КАК вести разговор, приказ — что его больше не
        // ведут. Оттого он проверяется первым.
        act: match run.ordered {
            Ordered::Sever => Act::Sever,
            Ordered::Nothing => acted(plan.programme),
        },
        cursor: match (run.ordered, over) {
            // ОБРЫВ КОНЧАЕТ РАЗГОВОР ТЕМ ЖЕ ШАГОМ, что и исполняется: иначе приказ висел бы
            // применённым и неисполненным, а следующий пакет оборвал бы заново.
            //
            // ЗАКРЫТИЕ НАЗЫВАЕТСЯ ЗАКРЫТИЕМ, а не возвратом к `Fresh` (#320, 03.09). Прежде шаг
            // отдавал сюда `Cursor::Fresh`, а оболочка переводила его в `Ended` по соглашению —
            // то есть у `Fresh` было два смысла («разговора не было» и «разговор кончился»), и
            // держались они комментарием в чужом файле. Вместе с соглашением терялся ОТВЕТ ЦЕЛИ:
            // `Run` выбрасывался, и таблица красила всё завершённое в «не имеем права судить» —
            // 83 слепые цели из 86 на полевом прогоне.
            (Ordered::Sever, _) | (_, true) => Cursor::Ended(crate::row::Closed {
                answered: moved.answered,
                // СЧЁТ БЕРЁТСЯ ПОСЛЕ ЭТОГО ПАКЕТА (`moved`), а не до: закрывающий сегмент —
                // часть разговора, и потерять его значило бы разойтись с ядром ровно на единицу
                // и объявить это слепотой.
                counted: crate::row::Counted {
                    up: moved.up as u64,
                    up_bytes: moved.up_bytes,
                    down: moved.down as u64,
                    down_bytes: moved.down_bytes,
                },
            }),
            (Ordered::Nothing, false) => Cursor::Running(moved),
        },
        sighting: reset_told(&run, packet, upward)
            .or(closed_told(&moved, packet, now))
            .or(spoke_told(&run, packet, now, spoke_now))
            // ПРИВЕТСТВИЕ ВЫШЕ УСТАРЕВАНИЯ В ЦЕПОЧКЕ, и это выбор, а не порядок написания.
            // Приветствие случается на разговоре ОДИН раз, устаревание повторяется по горизонту:
            // проиграй приветствие — и оно потеряно навсегда, проиграй устаревание — оно придёт
            // следующим пакетом.
            .or(named_told(&run, packet))
            .or(severed_told(&run, packet))
            .or(stale_told(plan, packet, stale))
            .map(|what| noted(&run, packet, now, what)),
    }
}

/// КЛИЕНТ НАЗВАЛСЯ — ровно тогда, когда разговор принимает личность.
///
/// Условие то же самое, что у принятия плана ([`adopting`]), и это не совпадение: наблюдение
/// обязано выпускаться в тот же момент, в который знание применяется. Разойдись они — лента
/// показывала бы человеку одно, а решение принималось бы по другому.
///
/// `Awaited` сюда не попадает по построению: `adopting` истинно только когда пакет СКАЗАЛ о
/// личности, а сказать «ничего» нельзя.
fn named_told(run: &Run, packet: &Packet<'_>) -> Option<Sighting> {
    match adopting(run, packet) {
        false => None,
        true => Some(Sighting::Recognised {
            dst: packet.dst,
            said: packet.says,
        }),
    }
}

fn reset_told(run: &Run, packet: &Packet<'_>, upward: bool) -> Option<Sighting> {
    match packet.resets {
        false => None,
        true => Some(Sighting::Reset {
            dst: packet.dst,
            by_client: upward,
            target_spoke: matches!(run.answered, Answered::After(_)),
        }),
    }
}

fn closed_told(moved: &Run, packet: &Packet<'_>, now: Tick) -> Option<Sighting> {
    match packet.closes {
        false => None,
        true => Some(Sighting::Closed {
            dst: packet.dst,
            lasted: Span(now.0.saturating_sub(moved.began.0)),
            up: moved.up,
            down: moved.down,
            down_bytes: moved.down_bytes,
        }),
    }
}

fn spoke_told(run: &Run, packet: &Packet<'_>, now: Tick, spoke_now: bool) -> Option<Sighting> {
    match spoke_now {
        false => None,
        true => Some(Sighting::TargetSpoke {
            dst: packet.dst,
            after: Span(now.0.saturating_sub(run.began.0)),
        }),
    }
}

/// ПОЛОЖИТЬ В РАЗГОВОР ПРИКАЗ ОБОРВАТЬ (#318).
///
/// Приказ адресован РАЗГОВОРУ, а не цели: план замерзает на открытии, и смена плана цели живое
/// соединение не трогает — она лишь метит его устаревшим. Оттого приказ на живое приходит сюда и
/// ложится в состояние разговора, а исполняется следующим же его пакетом.
///
/// ЧИСТАЯ: курсор входит и выходит значением, никакого IO. Кто и почему решил оборвать — не её
/// дело; её дело — чтобы приказ дожил до пакета.
pub fn sever(cursor: Cursor) -> Cursor {
    match cursor {
        // ОБОРВАТЬ НЕЧЕГО, И ЭТО НЕ ОШИБКА: приказ мог опоздать ровно на конец разговора, а
        // потерянному состоянию рвать нечего тем более — мы не знаем, что применяли.
        Cursor::Fresh | Cursor::Ended(_) | Cursor::Lost => cursor,
        Cursor::Running(run) => Cursor::Running(Run {
            ordered: Ordered::Sever,
            ..run
        }),
    }
}

/// ЧЕРЕЗ СКОЛЬКО ПОВТОРИТЬ РАССКАЗ, ЕСЛИ ЕГО НЕ УСЛЫШАЛИ.
///
/// Величина ВЫБРАНА, не замерена: горизонт должен быть заметно больше времени доставки наверх и
/// заметно меньше срока, за который человек успевает пострадать на мёртвом маршруте.
pub const RETELL_HORIZON: Tick = Tick(2_000_000_000);

/// ПОРА ЛИ РАССКАЗЫВАТЬ СНОВА. Чистая и тотальная: оба состояния разобраны.
fn due(announced: Announced, now: Tick) -> bool {
    match announced {
        Announced::Never => true,
        Announced::At(then) => now.0.saturating_sub(then.0) >= RETELL_HORIZON.0,
    }
}

/// СВИДЕТЕЛЬСТВО ИСПОЛНЕНИЯ ПРИКАЗА. Наблюдение, а не отчёт о себе: разговор кончился, и это
/// видно тому, кто смотрит на провод.
fn severed_told(run: &Run, packet: &Packet<'_>) -> Option<Sighting> {
    match run.ordered {
        Ordered::Nothing => None,
        Ordered::Sever => Some(Sighting::Severed { dst: packet.dst }),
    }
}

fn stale_told(plan: Plan, packet: &Packet<'_>, stale: bool) -> Option<Sighting> {
    match stale {
        false => None,
        true => Some(Sighting::Stale {
            dst: packet.dst,
            was: plan.epoch,
        }),
    }
}

/// ДВИЖОК КАК МОРФИЗМ КАТЕГОРИИ ШАГА (шестой vision §3).
///
/// # Что этим лечится
///
/// Свободная функция [`step`] уже была машиной Мили, но в СВОЕЙ подписи: состояние отдельным
/// аргументом, знание — Reader'ом, выход — тройкой в `Stepped`. Цепочка из неё и чужого звена не
/// собиралась, потому что общего носителя не существовало.
///
/// # Знание входит БУКВОЙ, а не Reader'ом, и это несущее
///
/// `look_up: Fn(&Packet) -> Plan` есть НЕЗАПИСАННЫЙ ВХОД: прогнав шаг заново, мы обязаны иметь
/// ту же таблицу целей в том же состоянии — то есть переигровка одного разговора требует
/// восстановить глобальное знание на тот момент. Приняв `Plan` буквой алфавита, мы записываем
/// ОТВЕТ, а не источник, и запись одного разговора становится замкнутой.
///
/// Верности продукту это не нарушает: `Plane::feed` уже зовёт `step` с постоянным замыканием
/// (`|_asked| plan`), разрешив план ДО шага. Буква записывает ровно то, что плоскость разрешила.
///
/// # Курсор переезжает в СОСТОЯНИЕ, а не остаётся в выходе
///
/// `Stepped` несёт `cursor` рядом с `act` и `sighting`. Для морфизма это смешение: состояние
/// принадлежит машине, выход — потребителю. Оттого `To` здесь пара `(Act, Option<Noted>)`, а
/// курсор уезжает в `Self`. Свободная функция при этом остаётся нетронутой: у неё свои
/// потребители, и ломать их ради формы незачем.
///
/// # Лайфтайм в подписи — цена заимствованных байтов, и она названа ЦЕЛИКОМ
///
/// `Packet<'a>` держит `payload: &'a [u8]`, и ассоциированный тип обязан этот лайфтайм назвать.
/// Свободным параметром импла его оставить нельзя (E0207), поэтому он живёт на структуре через
/// `PhantomData`.
///
/// # ОГРАНИЧЕНИЕ, УСТАНОВЛЕННОЕ КОМПИЛЯТОРОМ 06.09.2026
///
/// Одна машина принимает пакеты РОВНО ОДНОГО заимствования. Прогнать её по последовательности, где
/// байты каждого пакета живут свою итерацию, нельзя: `E0597`, «`bytes` does not live long enough».
/// Первая редакция этого докблока утверждала обратное — «лайфтайм ковариантен и сужается до самого
/// короткого заимствования», — и опровергла её сборка, а не рассуждение.
///
/// Причина не в `Advancing`, а в самом `Step`: у него `type From` без собственного лайфтайма, то
/// есть вход не умеет заимствовать ТОЛЬКО НА ВРЕМЯ ВЫЗОВА.
///
/// ЦЕНА ДЛЯ ПРОДУКТА НАЗВАНА, А НЕ СПРЯТАНА: боевой путь устроен именно так — байты принадлежат
/// сообщению ядра и живут до вердикта, значит каждый пакет заимствован своим сроком. Носитель в
/// нынешнем виде горячий путь ещё НЕ ВЫРАЖАЕТ. Лечится это `type From<'i>` (GAT) у самого `Step`
/// — правка фундамента, а не движка, и потому отдельный предмет.
pub struct Advancing<'a> {
    /// СОСТОЯНИЕ РАЗГОВОРА. Публично: живая интроспекция есть обязательство A шестого vision —
    /// спросить у машины, где она, обязано быть можно, не выполняя шага.
    pub cursor: Cursor,
    /// ЭПОХА, С КОТОРОЙ СВЕРЯЕТСЯ УСТАРЕВАНИЕ ПЛАНА.
    pub epoch: Epoch,
    wire: core::marker::PhantomData<&'a ()>,
}

impl<'a> Advancing<'a> {
    pub fn new(cursor: Cursor, epoch: Epoch) -> Advancing<'a> {
        Advancing {
            cursor,
            epoch,
            wire: core::marker::PhantomData,
        }
    }
}

impl<'a> reflex_core::step::Step for Advancing<'a> {
    type From = (Plan, Packet<'a>, Tick);
    type To = (Act, Option<Noted>);

    fn step(self, (plan, packet, now): Self::From) -> (Self, Self::To) {
        let stepped = step(
            |_asked: &Packet<'a>| plan,
            self.epoch,
            self.cursor,
            &packet,
            now,
        );
        (
            Advancing::new(stepped.cursor, self.epoch),
            (stepped.act, stepped.sighting),
        )
    }
}
