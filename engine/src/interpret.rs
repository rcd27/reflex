//! Наблюдение плоскости → беда словаря. Распознавание, и только оно. Здесь отвечают на вопрос ЧТО
//! случилось на проводе; вопрос КОМУ это в счёт (какой ноге) живёт в политике (нога — понятие
//! политики, наблюдение её не несёт). Разделение снимает цикл зависимостей: `instrument` ← движок ←
//! потребитель. Плоскость знает то, чего домен не спрашивает: кто сбросил (`by_client`), успела ли
//! цель ответить (`target_spoke`), сколько байт вниз (`down_bytes`), темп дробью.

use reflex_instrument::distress::Distress;

use crate::Sighting;

/// Что случилось на проводе. Чистая функция: проверяется таблицей, без сети. Ноги здесь нет —
/// приписывание беды ноге есть работа политики.
pub fn distress(sighting: &Sighting) -> Option<Distress> {
    match sighting {
        // Оборвали мы сами — не беда: вменить цели свой приказ значило бы понизить оценку ноги за
        // то, что сделали мы (приказ на обрыв лечил бы и калечил одним движением).
        Sighting::Severed { .. } => None,
        // Человек закрыл вкладку — не беда (на проводе неотличим от сброса сетью). Главный случай,
        // ради которого перевод читает `by_client`.
        Sighting::Reset {
            by_client: true, ..
        } => None,
        // Сброс снаружи до ответа цели — классический признак вмешательства.
        Sighting::Reset {
            by_client: false,
            target_spoke: false,
            ..
        } => Some(Distress::Rst),
        // Сброс после ответа цели бедой не считается: разговор состоялся, чем кончился — вопрос
        // протокола, не проходимости пути.
        Sighting::Reset {
            by_client: false,
            target_spoke: true,
            ..
        } => None,
        // Закрылось без байта вниз — тихий дроп: RST не приходил, цель молчала. Предмет счёта —
        // БАЙТЫ, не пакеты (замер 31.08): заблокированная цель отвечает на SYN и молчит после
        // `ClientHello` — пакеты вниз есть, байтов нет. Длительность идёт в саму беду.
        Sighting::Closed {
            lasted,
            down_bytes: 0,
            ..
        } => Some(Distress::Silence {
            ms: (lasted.0 / 1_000_000) as u32,
        }),
        // Байты вниз шли — путь работает. Сколько их и достаточно ли, спрашивает не этот перевод.
        Sighting::Closed { .. } => None,
        // Наша слепота и служебные события. `Recognised` (приветствие прошло) бедой не является ни
        // в одном варианте: даже `Naming::Silent` есть знание о цели, коннект по IP/MTProto —
        // норма. `Peaked` — темп, для которого нужен недоказанный порог (см. шапку).
        Sighting::Stale { .. }
        | Sighting::Opened { .. }
        | Sighting::Recognised { .. }
        | Sighting::TargetSpoke { .. }
        | Sighting::Peaked { .. } => None,
    }
}

/// Как человек ушёл — тип живёт в `reflex_instrument::departure` вместе с прибором.
pub use reflex_instrument::departure::Left;

/// Ушёл ли человек, и как — тонкая обёртка над прибором (вердикт в `departure`; здесь вызов ради
/// читателей, зовущих `left` по имени).
pub fn left(sighting: &Sighting) -> Option<Left> {
    reflex_instrument::says(
        reflex_instrument::departure::DepartureInstrument::new(),
        sighting,
    )
    .first()
    .copied()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Addr, Basis, Epoch, Span};

    const DST: Addr = Addr(0x0A00_0001);

    /// Сброс от человека — не беда: иначе продукт учился бы на своём пользователе.
    #[test]
    fn a_reset_by_the_person_is_not_trouble() {
        let closed_tab = Sighting::Reset {
            dst: DST,
            by_client: true,
            target_spoke: false,
        };
        assert_eq!(distress(&closed_tab), None);
    }

    /// Сброс снаружи до ответа цели — беда, названная своим словом. Ноги здесь нет (предмет
    /// отдельного витнеса в политике).
    #[test]
    fn a_reset_from_outside_before_the_target_spoke_is_an_rst() {
        let cut = Sighting::Reset {
            dst: DST,
            by_client: false,
            target_spoke: false,
        };
        assert_eq!(distress(&cut), Some(Distress::Rst));
    }

    /// Сброс после ответа цели бедой не считается: путь свою работу сделал.
    #[test]
    fn a_reset_after_the_target_spoke_is_not_a_path_problem() {
        let late = Sighting::Reset {
            dst: DST,
            by_client: false,
            target_spoke: true,
        };
        assert_eq!(distress(&late), None);
    }

    /// Тихий дроп: закрылось без байта вниз (цель ответила на SYN и замолчала — пакеты есть, байтов
    /// нет). Длительность переезжает в беду.
    #[test]
    fn closing_without_a_single_packet_down_is_silence_and_carries_its_length() {
        let silent = Sighting::Closed {
            dst: DST,
            lasted: Span(12_000_000_000),
            up: 3,
            down: 2,
            down_bytes: 0,
        };
        assert_eq!(
            distress(&silent),
            Some(Distress::Silence { ms: 12_000 }),
            "длительность молчания потеряна или пересчитана"
        );
    }

    /// Разговор состоялся — бедой не является, сколько бы пакетов ни было.
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

    /// Наша слепота не есть беда цели: устаревший план и начало разговора — не жалоба на путь.
    /// Потеря цели сюда не входит — компилятором, а не памятью автора.
    #[test]
    fn our_own_blindness_is_never_the_legs_fault() {
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

    /// Два ухода, и они разные. До прибора оба лежали под одним `None` в [`distress`].
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

    /// Сброс со стороны цели — не про человека. Его предмет — путь, читает [`distress`].
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

    /// Паспорт читает то же, что и функция — иначе был бы вторым описанием, расходящимся молча.
    #[test]
    fn the_passport_reads_what_the_bridge_reads() {
        let unserved = Sighting::Reset {
            dst: DST,
            by_client: true,
            target_spoke: false,
        };

        assert_eq!(
            reflex_instrument::says(
                reflex_instrument::departure::DepartureInstrument::new(),
                &unserved
            )
            .first()
            .copied(),
            left(&unserved)
        );
        assert_eq!(
            reflex_instrument::says(
                reflex_instrument::departure::DepartureInstrument::new(),
                &unserved
            )
            .first()
            .copied(),
            Some(Left::Unserved)
        );
    }

    /// Клетка молчания заполнена верно: `Nothing`, не `Blind` — прибор смотрел и установил, что
    /// наблюдение не о человеке.
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
        // Параметризованный сценарий называется целиком, беспараметрический — просто именем
        // (`pass` — контроль «беды нет», параметров не имеет по природе).
        const WITHOUT_PARAMETERS: &[&str] = &["pass", "quic_pass", "udp_dns", "steady_slow"];
        assert!(
            reflex_instrument::departure::DepartureInstrument::<Sighting>::ORACLES
                .iter()
                .all(|name| name.contains('(') || WITHOUT_PARAMETERS.contains(name)),
            "параметризованный сценарий называется целиком: `abandon` без терпения — не адрес"
        );
    }
}
