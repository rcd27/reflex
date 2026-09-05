//! НАБЛЮДЕНИЕ ПЛОСКОСТИ → БЕДА СЛОВАРЯ. Распознавание, и только оно (#325, 03.09).
//!
//! # Почему здесь, а не в движке
//!
//! Слой приборов и плоскости — PERFORMANCE FIRST: расчёт, идущий на каждое наблюдение, обязан
//! стоять внизу, у провода, а не подниматься в домен решений. Прежняя редакция жила в
//! `nevod2-runtime::distress` — то есть в КРАЮ движка, хотя ни одного обращения к сети не делала.
//!
//! Лестница у нас сообразна сетевому стеку, снизу вверх с обогащением: провод → приборы →
//! плоскость → политика. Перевод наблюдения в слово словаря есть шаг обогащения, и его этаж —
//! этот.
//!
//! # ЧТО ЗДЕСЬ ЕСТЬ И ЧЕГО ЗДЕСЬ НЕТ: РАЗЛИЧЕНИЕ ОТДЕЛЕНО ОТ АТРИБУЦИИ
//!
//! Здесь отвечают на вопрос **ЧТО СЛУЧИЛОСЬ НА ПРОВОДЕ** — и ни на какой другой. Вопрос **КОМУ
//! ЭТО В СЧЁТ** (какой ноге приписать беду) живёт в `nevod2::finding::trouble`, потому что нога
//! есть понятие политики: наблюдение её не несёт, а знать, что сброс на обходе не должен понижать
//! оценку прямого пути, может только тот, кто ведёт оценки.
//!
//! Прежде обе половины стояли одной функцией, и оттого распознавание было заперто наверху: чтобы
//! спросить «беда ли это», приходилось назвать ногу. Разделение снимает и цикл зависимостей —
//! `instrument` ← `dataplane` ← `nevod2`, ни одной стрелки назад.
//!
//! # Что плоскость знает такого, чего домен не спрашивает
//!
//! ```text
//! Reset.by_client      КТО сбросил. Домен знает только «пришёл RST».
//! Reset.target_spoke   успела ли цель ответить ДО сброса.
//! Closed.down_bytes    сколько БАЙТОВ пришло вниз — молчание видно числом.
//! TargetSpoke.after    через сколько цель заговорила. У домена такого понятия нет вовсе.
//! Peaked.pace          темп как дробь, без деления и потери точности.
//! ```
//!
//! Первое из них — не украшение. Сброс, сделанный САМИМ ЧЕЛОВЕКОМ (закрыл вкладку), выглядит на
//! проводе как сброс от сети, и без `by_client` продукт учился бы на собственном пользователе:
//! понижал бы оценку ноги за то, что человек ушёл. Это тот же класс, что «признак на проводе
//! становится бедой, только если его КТО-ТО ЖДАЛ».
//!
//! # Чего этот перевод НЕ делает, и цена названа
//!
//! * [`reflex_instrument::distress::Distress::Throttled`] — плоскость даёт `Peaked { pace }`, но перевод
//!   требует ПОРОГА, а порог ставится в разрыве замера и доказывается сдвигом. Выдумать его здесь
//!   значило бы завести величину, которой никто не мерил. ЦЕНА: беда, проявляющаяся только
//!   медленностью, этим переводом не видна — цель считается здоровой, пока человек смотрит на
//!   крутилку. Порог — предмет кампании #325.
//! * [`reflex_instrument::distress::Distress::GeoStub`] — требует СОДЕРЖИМОГО ответа, а плоскость смотрит на
//!   заголовки. ЦЕНА: заглушка «недоступно в вашей стране» пройдёт как здоровый ответ.
//! * `Sighting::Peaked`, `Stale`, `Opened`, `TargetSpoke` бедой не являются по построению.
//! * `Sighting::Lost` — НАША слепота (курсор вытеснен из карты), а не беда цели. Перевести её в
//!   беду значило бы записать собственную забывчивость в свойство ноги.

use reflex_instrument::distress::Distress;

use crate::Sighting;

/// ЧТО СЛУЧИЛОСЬ НА ПРОВОДЕ. Чистая функция: перевод проверяется таблицей, без сети.
///
/// Ноги здесь нет намеренно — см. шапку модуля: приписывание беды ноге есть работа политики.
pub fn distress(sighting: &Sighting) -> Option<Distress> {
    match sighting {
        // ОБОРВАЛИ МЫ САМИ — НЕ БЕДА, и это не оттенок. Вменить цели наш собственный приказ
        // значило бы понизить оценку ноги за то, что сделали мы, и следующий разговор ушёл бы
        // хуже — то есть приказ на обрыв лечил бы и калечил одним движением.
        //
        // Признак на проводе становится бедой, только если его КТО-ТО ЖДАЛ; здесь ждали ровно
        // этого.
        Sighting::Severed { .. } => None,
        // ЧЕЛОВЕК ЗАКРЫЛ ВКЛАДКУ — не беда, и это главный случай, ради которого перевод читает
        // `by_client`. На проводе он неотличим от сброса сетью.
        Sighting::Reset {
            by_client: true, ..
        } => None,
        // СБРОС СНАРУЖИ ДО ТОГО, КАК ЦЕЛЬ ЗАГОВОРИЛА — классический признак вмешательства.
        Sighting::Reset {
            by_client: false,
            target_spoke: false,
            ..
        } => Some(Distress::Rst),
        // СБРОС ПОСЛЕ ОТВЕТА ЦЕЛИ бедой НЕ считается: разговор состоялся, а чем он кончился —
        // вопрос протокола и поведения сервера, не проходимости пути. Считать его бедой значило
        // бы чинить обходом то, что обходом не лечится.
        Sighting::Reset {
            by_client: false,
            target_spoke: true,
            ..
        } => None,
        // ЗАКРЫЛОСЬ, НЕ ПОЛУЧИВ НИ БАЙТА ВНИЗ — это и есть тихий дроп: RST не приходил, цель
        // молчала всё время жизни соединения. Длительность идёт в саму беду: «молчало 40 мс» и
        // «молчало 12 секунд» — разные вещи, и решать, много ли это, будет тот, кто знает цену
        // ожидания, а не этот перевод.
        //
        // ПРЕДМЕТ СЧЁТА — БАЙТЫ, А НЕ ПАКЕТЫ, и цена ошибки замерена (31.08, #317). Пока плоскость
        // стояла только на `output`, вниз не приходило НИЧЕГО, и `down: 0` было истинно для любого
        // закрытого флоу: прогон отчитался «беда распознана: 12» — числом о нашей слепоте, а не о
        // цели. Стоило завернуть входящий, и предикат по пакетам умер в другую сторону:
        // заблокированная цель ОТВЕЧАЕТ на SYN и молчит после `ClientHello`, то есть пакеты вниз
        // есть, а разговора нет. Байты различают оба случая, пакеты — ни одного.
        Sighting::Closed {
            lasted,
            down_bytes: 0,
            ..
        } => Some(Distress::Silence {
            ms: (lasted.0 / 1_000_000) as u32,
        }),
        // Байты вниз шли — путь работает. Сколько их и достаточно ли, спрашивает не этот перевод.
        Sighting::Closed { .. } => None,
        // НАША СЛЕПОТА И СЛУЖЕБНЫЕ СОБЫТИЯ. `Lost` — цель замолчала дольше горизонта; `Stale` —
        // план устарел; `Opened`/`TargetSpoke` — начало разговора и ответ цели, то есть скорее
        // отсутствие беды. `Peaked` — темп, для которого нужен недоказанный порог (см. шапку).
        //
        // `Recognised` — ПРИВЕТСТВИЕ ПРОШЛО, и бедой это не является ни в одном варианте. Даже
        // `Naming::Silent` («имени не было») есть знание о цели, а не жалоба на путь: коннект по
        // IP и MTProto — норма, и звать по ним обход значило бы чинить работающее.
        Sighting::Lost { .. }
        | Sighting::Stale { .. }
        | Sighting::Opened { .. }
        | Sighting::Recognised { .. }
        | Sighting::TargetSpoke { .. }
        | Sighting::Peaked { .. } => None,
    }
}

/// КАК ЧЕЛОВЕК УШЁЛ — тип живёт в `reflex_instrument::departure` вместе с прибором.
pub use reflex_instrument::departure::Left;

/// УШЁЛ ЛИ ЧЕЛОВЕК, И КАК — тонкая обёртка над прибором.
///
/// Сам вердикт вынесен в `reflex_instrument::departure`, а здесь остался вызов: плоскость отвечает на два
/// вопроса прибора (см. `impl Departure for Sighting`), прибор из ответов делает вывод. Обёртка
/// оставлена ради читателей, которые зовут `left` по имени.
pub fn left(sighting: &Sighting) -> Option<Left> {
    reflex_instrument::says(reflex_instrument::departure::DepartureInstrument::new(), sighting)
        .first()
        .copied()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Addr, Basis, Epoch, Span};

    const DST: Addr = Addr(0x0A00_0001);

    /// СБРОС ОТ ЧЕЛОВЕКА — НЕ БЕДА. Без этого различия продукт учился бы на собственном
    /// пользователе: закрытая вкладка понижала бы оценку ноги, которая работала исправно.
    #[test]
    fn a_reset_by_the_person_is_not_trouble() {
        let closed_tab = Sighting::Reset {
            dst: DST,
            by_client: true,
            target_spoke: false,
        };
        assert_eq!(distress(&closed_tab), None);
    }

    /// СБРОС СНАРУЖИ ДО ОТВЕТА ЦЕЛИ — беда, и она названа своим словом.
    ///
    /// НОГИ ЗДЕСЬ НЕТ, и это предмет отдельного витнеса выше по лестнице
    /// (`nevod2::finding::trouble`): потеряй мы имя ноги ТАМ, беда на обходе понизила бы оценку
    /// прямого пути. Здесь же нога не участвует вовсе — распознавание от неё не зависит.
    #[test]
    fn a_reset_from_outside_before_the_target_spoke_is_an_rst() {
        let cut = Sighting::Reset {
            dst: DST,
            by_client: false,
            target_spoke: false,
        };
        assert_eq!(distress(&cut), Some(Distress::Rst));
    }

    /// СБРОС ПОСЛЕ ОТВЕТА ЦЕЛИ бедой не считается: путь свою работу сделал.
    #[test]
    fn a_reset_after_the_target_spoke_is_not_a_path_problem() {
        let late = Sighting::Reset {
            dst: DST,
            by_client: false,
            target_spoke: true,
        };
        assert_eq!(distress(&late), None);
    }

    /// ТИХИЙ ДРОП: закрылось без единого пакета вниз. Длительность переезжает в беду, потому что
    /// «молчало 40 мс» и «молчало 12 секунд» — разные вещи для человека.
    #[test]
    fn closing_without_a_single_packet_down_is_silence_and_carries_its_length() {
        let silent = Sighting::Closed {
            dst: DST,
            lasted: Span(12_000_000_000),
            up: 3,
            // ЦЕЛЬ ОТВЕТИЛА НА SYN И ЗАМОЛЧАЛА — пакеты вниз ЕСТЬ, байтов нет. Это самый частый
            // вид блокировки у человека, и предикат по пакетам его не видел бы.
            down: 2,
            down_bytes: 0,
        };
        assert_eq!(
            distress(&silent),
            Some(Distress::Silence { ms: 12_000 }),
            "длительность молчания потеряна или пересчитана"
        );
    }

    /// РАЗГОВОР СОСТОЯЛСЯ — бедой не является, сколько бы пакетов ни было.
    #[test]
    fn a_conversation_with_bytes_down_is_not_trouble() {
        let talked = Sighting::Closed {
            dst: DST,
            lasted: Span(400_000_000),
            up: 5,
            down: 9,
            down_bytes: 4096,
        };
        assert_eq!(distress(&talked), None);
    }

    /// НАША СЛЕПОТА НЕ ЕСТЬ БЕДА ЦЕЛИ. `Lost` означает, что курсор вытеснен из карты — то есть мы
    /// перестали смотреть. Записать это в свойство ноги значило бы учиться на своей забывчивости.
    #[test]
    fn our_own_blindness_is_never_the_legs_fault() {
        assert_eq!(distress(&Sighting::Lost { dst: DST }), None);
        assert_eq!(
            distress(&Sighting::Stale {
                dst: DST,
                was: Epoch(1)
            }),
            None
        );
        assert_eq!(
            distress(&Sighting::Opened {
                dst: DST,
                basis: Basis::Default
            }),
            None
        );
        assert_eq!(
            distress(&Sighting::TargetSpoke {
                dst: DST,
                after: Span(100)
            }),
            None
        );
    }

    /// ДВА УХОДА, И ОНИ РАЗНЫЕ. До этого прибора оба лежали под одним `None` в [`distress`]:
    /// «человек закрыл вкладку — не беда». Для ноги верно, для человека — нет.
    #[test]
    fn leaving_unserved_is_told_apart_from_leaving_served() {
        let unserved = Sighting::Reset {
            dst: DST,
            by_client: true,
            target_spoke: false,
        };
        let served = Sighting::Reset {
            dst: DST,
            by_client: true,
            target_spoke: true,
        };

        assert_eq!(left(&unserved), Some(Left::Unserved));
        assert_eq!(left(&served), Some(Left::Served));
    }

    /// СБРОС СО СТОРОНЫ ЦЕЛИ — НЕ ПРО ЧЕЛОВЕКА. Его предмет — путь, и читает его [`distress`].
    /// Витнес в паре: тот же сброс там БЕДА, здесь молчание.
    #[test]
    fn a_reset_from_the_target_side_is_not_about_the_person() {
        let censored = Sighting::Reset {
            dst: DST,
            by_client: false,
            target_spoke: false,
        };

        assert_eq!(left(&censored), None);
        assert!(distress(&censored).is_some());
    }

    /// ПАСПОРТ ЧИТАЕТ ТО ЖЕ, ЧТО И ФУНКЦИЯ. Без этой сверки паспорт был бы вторым описанием
    /// прибора, расходящимся с ним молча — ровно та болезнь, которую он призван ловить.
    #[test]
    fn the_passport_reads_what_the_bridge_reads() {
        let unserved = Sighting::Reset {
            dst: DST,
            by_client: true,
            target_spoke: false,
        };

        assert_eq!(
            reflex_instrument::says(reflex_instrument::departure::DepartureInstrument::new(), &unserved)
                .first()
                .copied(),
            left(&unserved)
        );
        assert_eq!(
            reflex_instrument::says(reflex_instrument::departure::DepartureInstrument::new(), &unserved)
                .first()
                .copied(),
            Some(Left::Unserved)
        );
    }

    /// КЛЕТКА МОЛЧАНИЯ ЗАПОЛНЕНА, И ЗАПОЛНЕНА ВЕРНО. `Nothing`, а не `Blind`: прибор смотрел и
    /// установил, что наблюдение не о человеке. Пустая клетка означала бы, что прибор выдаёт
    /// собственный отказ за факт о мире.
    #[test]
    fn the_passport_names_its_silence() {
        use reflex_instrument::Instrument;

        assert_eq!(
            reflex_instrument::departure::DepartureInstrument::<Sighting>::SILENCE,
            Some(reflex_instrument::Silence::Nothing),
            "прибор без названного молчания выдаёт свой дефект за факт о мире"
        );
        assert!(
            !reflex_instrument::departure::DepartureInstrument::<Sighting>::LIES.is_empty(),
            "пустой список режимов лжи значит НЕ ПОВЕРЯЛСЯ, а не «не врёт»"
        );
        // ПАРАМЕТРИЗОВАННЫЙ СЦЕНАРИЙ НАЗЫВАЕТСЯ ЦЕЛИКОМ, беспараметрический — просто именем.
        //
        // Прежняя редакция требовала скобок у ВСЕХ и была верна, пока в списке стояли одни
        // параметризованные. `pass` параметров не имеет по природе: это контроль, «беды нет».
        // Требовать у него скобки значило бы либо выкинуть законный оракул, либо приписать ему
        // выдуманные аргументы — и то и другое хуже, чем назвать беспараметрические поимённо.
        const WITHOUT_PARAMETERS: &[&str] = &["pass", "quic_pass", "udp_dns", "steady_slow"];
        assert!(
            reflex_instrument::departure::DepartureInstrument::<Sighting>::ORACLES
                .iter()
                .all(|name| name.contains('(') || WITHOUT_PARAMETERS.contains(name)),
            "параметризованный сценарий называется целиком: `abandon` без терпения — не адрес"
        );
    }
}
