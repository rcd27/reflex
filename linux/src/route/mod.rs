//! СВИДЕТЕЛЬ ПУТИ УВОДА: куда маршрутизатор ядра поведёт пакет с меткой увода.
//!
//! Слово «увести» кладёт вердикт очереди (метка пакета, [`crate::queue::Answer::Marked`]), а
//! исполняет его путь, стоящий СНАРУЖИ движка: правило `ip rule fwmark … lookup T` и маршрут в
//! ногу. Слово без пути собирается и исполняется молча — ядро отпустит помеченный пакет туда, куда
//! он шёл, и журнал доложит успех. Оплачено 13.09.2026 дважды за одну ночь:
//!
//! * путь покрывал только TCP — решение стояло на QUIC-разговоре, 72 МБ из 72,5 не уведены;
//! * путь забирал и адресованное самой машине — помеченный mesh уехал в ногу, машина потеряна.
//!
//! Потому путь СВИДЕТЕЛЬСТВУЕТСЯ до первого пакета, и свидетельствует не имя моста и не список
//! правил, а сам маршрутизатор (`RTM_GETROUTE`) — оракул, которым ядро и поведёт пакет. Правила
//! свидетель не ставит: граница мира (§9) не двигается, кто поставил — тот и снимает.
//!
//! ОТКАЗ ПО НЕДОКАЗАННОМУ, а не по доказанно плохому — обратно `preflight`, где неизвестность
//! пропускается. Там отказ отнимал бы работающую машину; здесь пропуск отнимает саму машину.
//!
//! ПРЕДЕЛЫ, названные вслух:
//! * назначение спрашивается одно ([`PROBE`]) — путь, различающий назначения, покрыт им не весь;
//! * вопрос идёт как о пакете самой машины, без входящего устройства: правило с `iif` свидетель
//!   прочтёт непокрытым (отказ, не ложный пропуск);
//! * только IPv4 — ключевание IPv6 ещё не взято.

mod socket;
mod wire;

pub use wire::Went;

use std::fmt;
use std::net::Ipv4Addr;

use reflex_core::types::Protocol;

/// Чем спрашивается покрытие: TEST-NET-2 (RFC 5737) — назначение, которого нет ни в чьей сети, а
/// значит, путь к нему выбирает правило по метке, а не случайный маршрут к соседу.
pub const PROBE: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 1);
const PORT: u16 = 443;
/// Какие L4 обязан покрыть путь. Весь закрытый алфавит, а не «основной»: слово ложится на разговор
/// любого из них.
const COVERED: [Protocol; 2] = [Protocol::Tcp, Protocol::Udp];

/// Путь увода, ПОКАЗАННЫЙ ядром. Построить можно только свидетельством ([`witness`]): поля закрыты,
/// иного конструктора нет.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Path {
    mark: u32,
    device: u32,
}

impl Path {
    /// Метка, которой уводится помеченное.
    pub fn mark(&self) -> u32 {
        self.mark
    }

    /// Индекс устройства ноги.
    pub fn device(&self) -> u32 {
        self.device
    }
}

/// Чем свидетельство не состоялось. Каждая буква несёт своё лечение: беды разные, и слитые, они
/// послали бы человека чинить не то.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unsteerable {
    /// Устройства ноги нет.
    NoLeg(String),
    /// Помеченный пакет этого L4 уходит не в ногу.
    Uncovered { l4: Protocol, went: Went },
    /// Свой адрес машины с меткой не остаётся машине.
    LocalLeaks {
        local: Ipv4Addr,
        l4: Protocol,
        went: Went,
    },
    /// Своих адресов не прочитано ни одного — утечку своего проверить не на чем.
    Blind,
    /// Маршрутизатор не спросить: errno сокета или дампа.
    Socket(i32),
}

impl fmt::Display for Unsteerable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoLeg(device) => write!(
                f,
                "устройства ноги «{device}» нет — уводить некуда. Починка: поднять ногу до движка"
            ),
            Self::Uncovered { l4, went } => write!(
                f,
                "помеченный {l4} уходит не в ногу ({went:?}) — путь увода его не покрывает, слово \
                 «увести» исполнилось бы молча. Починка: правило по метке без ограничения протокола \
                 (ip rule add fwmark <метка> lookup <T>; ip route add default dev <нога> table <T>)"
            ),
            Self::LocalLeaks { local, l4, went } => write!(
                f,
                "свой адрес {local} ({l4}) с меткой уходит не себе ({went:?}) — увод отрежет доступ \
                 к самой машине. Починка: правило `lookup local` обязано стоять ВЫШЕ правила увода"
            ),
            Self::Blind => write!(
                f,
                "не прочитано ни одного своего адреса — проверить, что увод не заберёт адресованное \
                 самой машине, не на чем. Починка: поднять lo"
            ),
            Self::Socket(code) => write!(f, "маршрутизатор ядра не спросить: errno {code}"),
        }
    }
}

impl std::error::Error for Unsteerable {}

/// Свидетельствовать путь увода меткой `mark` в устройство `device`.
pub fn witness(mark: u32, device: &str) -> Result<Path, Unsteerable> {
    let leg = socket::index_of(device).ok_or_else(|| Unsteerable::NoLeg(device.to_string()))?;
    let router = socket::Router::open().map_err(Unsteerable::Socket)?;
    let ask = |dst: Ipv4Addr, l4: Protocol| router.route(dst, mark, l4, PORT);
    let covered = COVERED
        .into_iter()
        .map(|l4| ask(PROBE, l4).map(|went| (l4, went)))
        .collect::<Result<Vec<_>, i32>>()
        .map_err(Unsteerable::Socket)?;
    let kept = router
        .locals()
        .map_err(Unsteerable::Socket)?
        .into_iter()
        .flat_map(|local| COVERED.into_iter().map(move |l4| (local, l4)))
        .map(|(local, l4)| ask(local, l4).map(|went| (local, l4, went)))
        .collect::<Result<Vec<_>, i32>>()
        .map_err(Unsteerable::Socket)?;
    judged(leg, &covered, &kept).map(|()| Path { mark, device: leg })
}

/// Закон свидетеля ОТДЕЛЬНО от чтения мира: так он предъявляется всеми клетками без ядра (§9: выше
/// значения, ниже мир). Покрытие прежде утечки: без пути спрашивать об утечке в него не о чем.
fn judged(
    leg: u32,
    covered: &[(Protocol, Went)],
    kept: &[(Ipv4Addr, Protocol, Went)],
) -> Result<(), Unsteerable> {
    match (
        covered.iter().find(|(_, went)| *went != Went::Device(leg)),
        kept.iter().find(|(_, _, went)| *went != Went::Local),
    ) {
        (Some(&(l4, went)), _) => Err(Unsteerable::Uncovered { l4, went }),
        (None, _) if kept.is_empty() => Err(Unsteerable::Blind),
        (None, Some(&(local, l4, went))) => Err(Unsteerable::LocalLeaks { local, l4, went }),
        (None, None) => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LEG: u32 = 7;
    const HOME: Ipv4Addr = Ipv4Addr::new(192, 168, 77, 1);

    fn both(went: Went) -> Vec<(Protocol, Went)> {
        COVERED.into_iter().map(|l4| (l4, went)).collect()
    }

    fn home(went: Went) -> Vec<(Ipv4Addr, Protocol, Went)> {
        COVERED.into_iter().map(|l4| (HOME, l4, went)).collect()
    }

    #[test]
    fn честный_путь_свидетельствуется() {
        assert_eq!(
            judged(LEG, &both(Went::Device(LEG)), &home(Went::Local)),
            Ok(())
        );
    }

    /// Ночь 13.09: правило `ipproto tcp` — TCP в ноге, UDP идти некуда.
    #[test]
    fn путь_под_один_l4_не_свидетельствуется() {
        let tcp_only = [
            (Protocol::Tcp, Went::Device(LEG)),
            (Protocol::Udp, Went::Refused(101)),
        ];
        assert_eq!(
            judged(LEG, &tcp_only, &home(Went::Local)),
            Err(Unsteerable::Uncovered {
                l4: Protocol::Udp,
                went: Went::Refused(101)
            })
        );
    }

    /// Ушло в устройство, но не в ногу — тоже не путь увода.
    #[test]
    fn чужое_устройство_не_нога() {
        assert!(matches!(
            judged(LEG, &both(Went::Device(LEG + 1)), &home(Went::Local)),
            Err(Unsteerable::Uncovered { .. })
        ));
    }

    /// Ночь 13.09: свой адрес с меткой уехал в ногу — машина отрезана.
    #[test]
    fn утечка_своего_адреса_не_свидетельствуется() {
        assert_eq!(
            judged(LEG, &both(Went::Device(LEG)), &home(Went::Device(LEG))),
            Err(Unsteerable::LocalLeaks {
                local: HOME,
                l4: Protocol::Tcp,
                went: Went::Device(LEG)
            })
        );
    }

    /// Не на чем проверить утечку — отказ, не пропуск: цена ложного пропуска — сама машина.
    #[test]
    fn без_своих_адресов_свидетель_слеп_и_отказывает() {
        assert_eq!(
            judged(LEG, &both(Went::Device(LEG)), &[]),
            Err(Unsteerable::Blind)
        );
    }
}
