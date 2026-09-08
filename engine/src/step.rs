use reflex_core::word::Descends;

use crate::row::Answered;
use crate::row::Naming;
use crate::{
    stood_on, About, Act, Announced, Cursor, Dir, Epoch, Noted, Noticed, Ordered, Packet, Plan,
    Programme, Run, Sighting, Span, Stepped, Tick,
};

// TODO(#298): числа объявлены по слуху — заменить замером на риге
pub fn budget(programme: Programme) -> Span {
    match programme {
        Programme::Pass => Span(0),
        Programme::Mark(_) => Span(20),
    }
}

/// Что план цели значит для пакета — имя спуска. Тело в `impl Descends<Act> for Programme` (спуск
/// один и проверен на направление); имя остаётся ради потребителей, знающих движок этой функцией.
pub fn acted(programme: Programme) -> Act {
    reflex_core::word::Descends::descends(programme)
}

/// `look_up` зовётся дважды за разговор (#317): на открытии — по адресу (SYN), на пакете, где цель
/// назвалась, — по имени. Ключ выбирает вызывающий: ядро знает момент, не имена.
pub fn step<L>(look_up: L, epoch: Epoch, cursor: Cursor, packet: &Packet, now: Tick) -> Stepped
where
    L: Fn(&Packet) -> Plan,
{
    match cursor {
        // SYN на закрывшемся разговоре открывает новый: четвёрка переиспользуется, без этой ветки
        // второй разговор наследовал бы личность первого и выпускался бы на SYN — приветствие
        // новой цели не доехало бы (замер `lift-leak.sh`: 59 КБ мимо userspace под чужим именем).
        Cursor::Ended(_) if packet.opens => opened(look_up(packet), packet, now),
        // Хвост закрывшегося разговора несёт то же решение и ТОЖЕ считается: ядро считает последний
        // `ACK` и ретрансмиссии, перестань считать их мы — счета разойдутся на хвост, и `sighted`
        // объявит это нашей слепотой.
        Cursor::Ended(closed) => Stepped {
            act: look_up(packet).programme.descends(),
            cursor: Cursor::Ended(crate::row::Closed {
                answered: closed.answered,
                counted: crate::row::Counted {
                    up: closed.counted.up + u64::from(matches!(packet.dir, Dir::Up)),
                    up_bytes: closed.counted.up_bytes
                        + match packet.dir {
                            Dir::Up => packet.payload_len as u64,
                            Dir::Down => 0,
                        },
                    down: closed.counted.down + u64::from(matches!(packet.dir, Dir::Down)),
                    down_bytes: closed.counted.down_bytes
                        + match packet.dir {
                            Dir::Down => packet.payload_len as u64,
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

fn opened(plan: Plan, packet: &Packet, now: Tick) -> Stepped {
    let carrying = packet.payload_len > 0;
    let upward = matches!(packet.dir, Dir::Up);
    let run = Run {
        plan,
        // Открытие обычно знает только адрес, и разговор ждёт личности; но открыться можно и
        // пакетом, который уже всё сказал (флоу увиден не с начала) — берётся сказанное.
        naming: packet.says,
        up: u16::from(upward),
        down: u16::from(!upward),
        up_bytes: match upward {
            true => packet.payload_len as u64,
            false => 0,
        },
        down_bytes: match upward {
            true => 0,
            false => packet.payload_len as u64,
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
        // На открытии приказа быть не может: разговор только заведён.
        act: plan.programme.descends(),
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

/// Наблюдение обретает адресата и момент здесь, где известны оба — одно место на все ветви (иначе
/// появилась бы ветвь, где их забыли проставить).
fn noted(run: &Run, packet: &Packet, now: Tick, what: Sighting) -> Noted {
    Noted {
        at: now,
        about: About::Talk(packet.flow),
        // Различитель, не имя (ядро имён не знает): знание РАЗГОВОРА о личности, не то, что сказал
        // этот пакет — пакет, ничего не сказавший, не отменяет названного.
        target: stood_on(run.naming, packet.says),
        // Всё, что видит шаг, видит разговор — потеря цели через эту дверь не проходит.
        what: Noticed::Talk(what),
    }
}

/// Личность принимается ровно один раз — на первом сказавшем пакете, пока разговор её ждал. Второе
/// слово плана не меняет: у соединения одна цель, повторный `ClientHello` сменил бы страту на
/// середине. «Сказал» включает молчание приветствия (`Silent`): иначе разговор без имени оставался
/// бы временным навсегда.
fn adopting(run: &Run, packet: &Packet) -> bool {
    matches!(run.naming, Naming::Awaited) && !matches!(packet.says, Naming::Awaited)
}

fn carried<L>(look_up: L, run: Run, epoch: Epoch, packet: &Packet, now: Tick) -> Stepped
where
    L: Fn(&Packet) -> Plan,
{
    let carrying = packet.payload_len > 0;
    let upward = matches!(packet.dir, Dir::Up);
    let spoke_now = !upward && carrying && matches!(run.answered, Answered::NotYet);
    // План, принятый по личности, вытесняет временный; `act` ниже берётся с принятого.
    let plan = match adopting(&run, packet) {
        false => run.plan,
        true => look_up(packet),
    };
    // Устаревание — функция состояния, не след события (#318): прежний `&& !stale_told` был
    // неидемпотентен (потеря отменяла приказ навсегда). Спрашивается эпоха, повторы дросселирует
    // горизонт — потеря становится задержкой.
    let stale = plan.epoch != epoch && due(run.announced, now);
    let over = packet.closes || packet.resets;

    let moved = Run {
        plan,
        naming: stood_on(run.naming, packet.says),
        up: run.up + u16::from(upward),
        down: run.down + u16::from(!upward),
        up_bytes: run.up_bytes + (packet.payload_len as u64) * u64::from(upward),
        down_bytes: run.down_bytes + (packet.payload_len as u64) * u64::from(!upward),
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
        // Ноль произведения — прекращение, не охват: план говорит КАК вести, приказ — что больше не
        // ведут; второе старше первого, хотя сказано в области уже. Промолчать умеет только приказ
        // — оттого он слева.
        act: run
            .ordered
            .descends()
            .unwrap_or_else(|| plan.programme.descends()),
        cursor: match (run.ordered, over) {
            // Обрыв кончает разговор тем же шагом. Закрытие называется закрытием, не возвратом к
            // `Fresh` (#320): иначе у `Fresh` два смысла и терялся ответ цели (83 слепые цели из 86
            // на полевом прогоне). Счёт берётся после этого пакета (`moved`): закрывающий сегмент —
            // часть разговора.
            (Ordered::Sever, _) | (_, true) => Cursor::Ended(crate::row::Closed {
                answered: moved.answered,
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
            // Приветствие выше устаревания: оно случается раз (проиграй — потеряно), устаревание
            // повторяется по горизонту (проиграй — придёт следующим пакетом).
            .or(named_told(&run, packet))
            .or(severed_told(&run, packet))
            .or(stale_told(plan, packet, stale))
            .map(|what| noted(&run, packet, now, what)),
    }
}

/// Клиент назвался — ровно когда разговор принимает личность (условие то же, что у [`adopting`]:
/// наблюдение выпускается в тот же момент, в который знание применяется).
fn named_told(run: &Run, packet: &Packet) -> Option<Sighting> {
    match adopting(run, packet) {
        false => None,
        true => Some(Sighting::Recognised {
            dst: packet.dst,
            said: packet.says,
        }),
    }
}

fn reset_told(run: &Run, packet: &Packet, upward: bool) -> Option<Sighting> {
    match packet.resets {
        false => None,
        true => Some(Sighting::Reset {
            dst: packet.dst,
            by_client: upward,
            target_spoke: matches!(run.answered, Answered::After(_)),
        }),
    }
}

fn closed_told(moved: &Run, packet: &Packet, now: Tick) -> Option<Sighting> {
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

fn spoke_told(run: &Run, packet: &Packet, now: Tick, spoke_now: bool) -> Option<Sighting> {
    match spoke_now {
        false => None,
        true => Some(Sighting::TargetSpoke {
            dst: packet.dst,
            after: Span(now.0.saturating_sub(run.began.0)),
        }),
    }
}

/// Положить в разговор приказ оборвать (#318). Приказ адресован РАЗГОВОРУ, не цели: план замерзает
/// на открытии, смена плана цели живое соединение не трогает. Чистая: курсор входит и выходит
/// значением.
pub fn sever(cursor: Cursor) -> Cursor {
    match cursor {
        // Оборвать нечего — не ошибка: приказ мог опоздать на конец разговора, а потерянному
        // состоянию рвать нечего тем более.
        Cursor::Fresh | Cursor::Ended(_) | Cursor::Lost => cursor,
        Cursor::Running(run) => Cursor::Running(Run {
            ordered: Ordered::Sever,
            ..run
        }),
    }
}

/// Через сколько повторить рассказ, если не услышали. Выбрана, не замерена: больше времени доставки
/// наверх и меньше срока, за который человек страдает на мёртвом маршруте.
pub const RETELL_HORIZON: Tick = Tick(2_000_000_000);

/// Пора ли рассказывать снова. Чистая и тотальная.
fn due(announced: Announced, now: Tick) -> bool {
    match announced {
        Announced::Never => true,
        Announced::At(then) => now.0.saturating_sub(then.0) >= RETELL_HORIZON.0,
    }
}

/// Свидетельство исполнения приказа. Наблюдение, а не отчёт о себе.
fn severed_told(run: &Run, packet: &Packet) -> Option<Sighting> {
    match run.ordered {
        Ordered::Nothing => None,
        Ordered::Sever => Some(Sighting::Severed { dst: packet.dst }),
    }
}

fn stale_told(plan: Plan, packet: &Packet, stale: bool) -> Option<Sighting> {
    match stale {
        false => None,
        true => Some(Sighting::Stale {
            dst: packet.dst,
            was: plan.epoch,
        }),
    }
}

/// Движок как морфизм категории шага (канон §1). Свободная [`step`] уже машина Мили, но в своей
/// подписи (состояние аргументом, знание Reader'ом, выход тройкой) — цепочка не собиралась.
///
/// Знание входит БУКВОЙ, не Reader'ом: `look_up` есть незаписанный вход (переигровка требовала бы
/// восстановить глобальное знание), а `Plan` буквой записывает ОТВЕТ. `Plane::feed` уже зовёт с
/// постоянным замыканием (`|_| plan`). Цена: свободная функция зовёт `look_up` дважды разными
/// ключами — одна буква двух ответов не выражает; продукт их уже свёл.
///
/// Курсор переезжает в СОСТОЯНИЕ (`Self`), выход — пара `(Act, Option<Noted>)`: состояние машины,
/// выход потребителю. Поднята половина состояния (курсор; счёт снаружи) — из счёта растёт
/// `row::Sight`, а из него клетка «не установлено» восьмого закона; морфизм, поднявший половину,
/// обязан назвать какую.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Advancing {
    /// Состояние разговора. Публично: живая интроспекция — обязательство канона §6 (спросить у
    /// машины, где она, не выполняя шага).
    pub cursor: Cursor,
}

impl Advancing {
    /// Машина из курсора — и больше ни из чего. Эпохи здесь нет: она приходит буквой входа внутри
    /// `Plan` (как в продукте: `Plane::feed` берёт `epoch = plan.epoch`) — полем она сверяла бы
    /// устаревание с числом, замороженным на постройке.
    pub fn new(cursor: Cursor) -> Advancing {
        Advancing { cursor }
    }
}

impl reflex_core::mealy::Mealy for Advancing {
    type In = (Plan, Packet, Tick);

    /// Слово: адресовано пакету — ядро держит его до вердикта, и вердикт уезжает на нём.
    type Out = Act;

    /// Показание: не адресовано никому. Прежде слито с `Act` во временную обёртку `Answer` — голому
    /// кортежу нельзя объявить адрес, не соврав про половину; со вторым выходом обёртка
    /// растворяется.
    type Log = Option<Noted>;

    fn step(self, (plan, packet, now): Self::In) -> (Self, Self::Out, Self::Log) {
        let stepped = step(
            |_asked: &Packet| plan,
            // Эпоха у буквы, не у машины — та же величина, что подаёт продукт.
            plan.epoch,
            self.cursor,
            &packet,
            now,
        );
        (
            Advancing::new(stepped.cursor),
            stepped.act,
            stepped.sighting,
        )
    }
}
