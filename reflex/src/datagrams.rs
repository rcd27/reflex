//! ТРАНСПОРТ ДАТАГРАММ, ЧЬЮ СТОРОНУ НАЗВАЛА ОЧЕРЕДЬ.
//!
//! [`crate::Udp`] читает датаграмму как DNS на порту 53, [`crate::Quic`] — как QUIC на 443: оба
//! разводят стороны портом сервера. Звонок Telegram идёт к рефлекторам на ЛЮБОЙ порт (596–599,
//! 1400, …), и порт тогда не называет ничего. Называет правило ядра: оно кладёт в очередь только
//! путь человека к рефлектору, значит всё пришедшее идёт вверх ([`Sides::NamedByQueue`]).
//!
//! Провод — сама датаграмма, владеющая своими байтами: разбирать в ней нечего (голос зашифрован),
//! а потребитель несёт её дальше целиком. Ключ цели — адрес назначения: имени у рефлектора нет.

use reflex_core::types::Flow;
use reflex_core::word::TargetKey;
use reflex_core::Reads;

use crate::{Observation, Observed, Read, Sides, Transport, Unread};

/// Транспорт датаграмм под очередью, чью сторону назвало правило ядра. Пишется в цепочку как
/// `.from(Datagrams)`; очередь обязана нести ТОЛЬКО путь к серверу — ответ, попавший в неё, был
/// бы прочитан как ещё одна датаграмма вверх с перевёрнутыми концами.
pub struct Datagrams;

/// Датаграмма целиком: чей разговор и что в нём. Владеет байтами, потому что кадр очереди живёт
/// до вердикта, а слово провода — в приборах и ленте дольше.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatagramWire {
    /// Четвёрка разговора: клиент — отправитель, сервер — адресат ([`Sides::NamedByQueue`]).
    pub flow: Flow,
    /// Полезная нагрузка UDP, без заголовков.
    pub payload: Box<[u8]>,
}

/// Сужение из ПАРЫ «провод и вид края» (§4): прибор датаграмм читает саму датаграмму, край ему
/// безразличен. Проекция первого множителя, точечная по тому же доводу, что у `DnsMessage`:
/// общий закон «читается из пары, если читается из половины» конфликтует с рефлексивным
/// `Reads<A> for A`. Без неё свой прибор над `Datagrams` обязан был бы читать пару целиком и
/// тащить параметр края, о котором ничего не знает.
impl<V> Reads<(DatagramWire, V)> for DatagramWire {
    fn read(wide: &(DatagramWire, V)) -> Option<DatagramWire> {
        Some(wide.0.clone())
    }
}

impl Transport for Datagrams {
    type Wire = DatagramWire;
    const SIDES: Sides = Sides::NamedByQueue;
    /// Памяти по разговору нет: всё, что знает транспорт, лежит в каждой датаграмме.
    type State = ();

    fn observe(_state: &mut (), read: Read<'_>) -> Observation<DatagramWire> {
        match read {
            Read::Udp(datagram) => Observation::Seen(Observed {
                flow: datagram.flow,
                key: TargetKey::Unnamed(datagram.dst),
                wire: DatagramWire {
                    flow: datagram.flow,
                    payload: datagram.payload.into(),
                },
                reply: None,
            }),
            // Довод тот же, что у `Tcp::observe`: обрезанный кадр мог быть голосом этого звонка.
            Read::Truncated => Observation::Unread(Unread::Truncated),
            // `NotOurPort` под этим правилом не рождается (очередь разводит всё), но вариант назван:
            // проглоти его катч-всё, и новый вариант разбора молча стал бы чужим.
            Read::Tcp(_) | Read::NotIpv4 | Read::NotOurProtocol | Read::NotOurPort => {
                Observation::Foreign
            }
        }
    }

    /// Забывать НЕЧЕГО: состояние пусто по построению (`type State = ()`), вся личность разговора
    /// лежит в самой датаграмме. Тело написано, а не унаследовано, — тот же довод, что у
    /// `Udp::forget`: промолчать здесь можно только по этой причине.
    fn forget(_state: &mut (), _flow: &Flow) {}

    /// Личность датаграммы не собирается из кусков — держать нечего.
    fn holding(_state: &(), _flow: &Flow) -> bool {
        false
    }
}
