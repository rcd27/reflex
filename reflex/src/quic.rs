//! ТРАНСПОРТ QUIC — третий рядом с [`crate::Tcp`] и [`crate::Udp`].
//!
//! ```no_run
//! # #[cfg(feature = "quic")] fn main() -> reflex::Report {
//! use reflex::*;
//!
//! engine(Nfqueue::queue(200))
//!     .from(Quic)                      // 443/UDP, имя цели — из `Initial`
//!     .extract(Sni)
//!     .detect(Retransmit::unanswered())
//!     .detect(Silence::after(secs(5)))
//!     .on(|target, distress| report!("{target}: {distress}"))
//!     .run()
//! # }
//! # #[cfg(not(feature = "quic"))] fn main() {}
//! ```
//!
//! # Зачем он понадобился: молчание, неотличимое от «всё хорошо»
//!
//! Замер потребителя на 21 записи лаборатории с известной землёй: три записи (`quic_drop`,
//! `quic_mute`, `quic_sni_drop`) не поверялись ВОВСЕ — батарея молчала. Молчание здесь не слепота
//! прибора, а НЕ ТОТ ВХОД: `.from(Tcp)` слушает TCP, а беда живёт на 443/UDP. `Udp` не закрывает —
//! он объявлен как DNS (`Wire = DnsMessage`, `PORT = 53`), и QUIC через него не проходит по
//! построению.
//!
//! Цена в единице человека замерена там же: видеосервис грузится с двадцати узлов параллельно и
//! идёт по QUIC. Значит боевой прогон не видел ни одной его блокировки — не «видел хуже», а НЕ
//! ВИДЕЛ, и это молчание неотличимо от «всё хорошо».
//!
//! Разбор при этом лежал в фундаменте готовым (`reflex_core::quic::sni` — имя из зашифрованного
//! `Initial`). Ровно та же порода, что у парка приборов, четвёртой двери шва и `CanMark`: механизм
//! есть, предъявить его нечем. Дыра ФОРМЫ ПРЕДЪЯВЛЕНИЯ, а не механизма.
//!
//! # Словарь провода — ТОТ ЖЕ, что у TCP, и это решение, а не экономия
//!
//! `Wire = Seen`, общий словарь ([`crate::Seen`]). Оттого приборы парка работают на QUIC БЕЗ
//! переделки: повтор клиента, тишина, возраст разговора — понятия транспортно-независимые, и
//! заведи мы свой словарь, пришлось бы заводить и вторые приборы о том же предмете. Краевые
//! приборы работают тем более: они читают `EdgeView`, а провода не видят вовсе.
//!
//! # Чего на QUIC НЕ РОЖДАЕТСЯ, названо прямо
//!
//! * `Seen::Closed` — обрыв в QUIC зашифрован, и наблюдателю невыразим (предел назван в докблоке
//!   `instrument::wire`, здесь он лишь наследуется). Следствие: разговор QUIC не кончается
//!   прощанием никогда, и снимает его только эвикт по простою.
//! * Имя цели — только из КЛИЕНТСКОГО `Initial` версии 1: ни 0-RTT, ни `Retry`, ни ECH (предел
//!   `reflex_core::quic`). Нет имени — цель ключуется адресом, `Unnamed`, и тег не притворяется.
//!
//! # Как узнаётся ПОВТОР, и почему не сравнением байт
//!
//! Клиент, не получивший ответа, шлёт `Initial` заново с ТЕМ ЖЕ `DCID`, но новым номером пакета:
//! байты датаграммы другие, и сравнение «тот же кадр» повтора не увидит. Единственное, что видно
//! наблюдателю и не меняется между попытками, — `DCID` (открытым текстом, RFC 9001 §5.2). У TCP ту
//! же работу делает граница по `seq`; здесь её делает `DCID`.
//!
//! Повтор объявляется ТОЛЬКО пока цель не ответила ни разу. Ответила — и второй `Initial` уже не
//! улика: так бывает при миграции соединения, и обвинять цель за неё значило бы врать.

use std::collections::HashMap;

use reflex_core::types::Flow;
use reflex_core::word::TargetKey;

use crate::{Observation, Observed, Read, Seen, Transport, Unread};

/// Транспорт QUIC: датаграммы на 443, имя цели из `Initial`.
pub struct Quic;

/// Что помнит разбор о разговоре QUIC: чем он открылся и отвечали ли ему.
#[derive(Clone)]
struct Talk {
    /// `DCID` первого клиентского `Initial` — им и различается повтор.
    opened_with: Vec<u8>,
    /// Сколько раз клиент повторил открытие, не получив ответа.
    retries: u32,
    /// Ответила ли цель хоть одной датаграммой. После ответа повтор уликой быть перестаёт.
    answered: bool,
    /// Имя из `Initial`, если оно там было. Копится, потому что в следующих датаграммах его нет.
    named: Option<Box<str>>,
    /// Куски `CRYPTO`, собранные со ВСЕХ клиентских `Initial` этого разговора. Так и надо:
    /// `ClientHello` в QUIC не обязан помещаться в одну датаграмму, и у настоящего клиента он в
    /// неё НЕ ПОМЕЩАЕТСЯ — замер на снятом рукопожатии curl/ngtcp2: имя лежит во ВТОРОЙ датаграмме,
    /// а односоставная `quic::sni` молчит на обеих. Ровно ради этого случая в фундаменте и разведены
    /// `crypto_of` (куски из одной датаграммы) и `sni_of` (имя из склеенных кусков).
    crypto: Vec<(u64, Vec<u8>)>,
}

/// Память разбора QUIC. Своя у транспорта — как `TcpState` у соединений.
#[derive(Default)]
pub struct QuicState {
    talks: HashMap<Flow, Talk>,
}

impl Transport for Quic {
    type Wire = Seen;
    /// 443/UDP. Тот же порт, что у TCP-двойника цели, и это не совпадение: браузер пробует оба.
    const PORT: u16 = 443;
    type State = QuicState;

    fn observe(state: &mut QuicState, read: Read<'_>) -> Observation<Seen> {
        let datagram = match read {
            Read::Udp(datagram) => datagram,
            // Довод тот же, что у `Tcp`/`Udp`: обрезанный кадр МОГ быть нашей датаграммой и МОГ
            // нести ответ цели — ослепнуть на нём честнее, чем счесть его чужим.
            Read::Truncated => return Observation::Unread(Unread::Truncated),
            Read::Tcp(_) | Read::NotIpv4 | Read::NotOurProtocol | Read::NotOurPort => {
                return Observation::Foreign
            }
        };

        // Сторону называет РАЗБОР (`Dir`), а не сравнение портов у нас: правило сторон живёт в
        // одном месте (`parse::upward`), и второе сравнение здесь разошлось бы с ним молча.
        let from_client = matches!(datagram.dir, reflex_core::types::Dir::Up);
        let payload = datagram.payload;
        let talk = state.talks.entry(datagram.flow).or_insert_with(|| Talk {
            opened_with: Vec::new(),
            retries: 0,
            answered: false,
            named: None,
            crypto: Vec::new(),
        });

        let wire = match from_client {
            // ЦЕЛЬ ОТВЕТИЛА. Пакет вниз снимает подозрение с последующих повторов: после ответа
            // второй `Initial` бывает при миграции соединения, и уликой он уже не является.
            false => {
                talk.answered = true;
                Seen::Received {
                    count: payload.len() as u32,
                }
            }
            true => match reflex_core::quic::initial_dcid(payload) {
                // Не `Initial` — обычная датаграмма разговора вверх.
                None => Seen::Sent {
                    count: payload.len() as u32,
                },
                Some(dcid) => {
                    // Имя ищется, пока не найдено: куски копятся по датаграммам, и до последнего
                    // куска склейка честно отдаёт `None`. Найдено — расшифровку больше не зовём:
                    // она не бесплатна, а в повторах имя то же самое.
                    if talk.named.is_none() {
                        talk.crypto
                            .extend(reflex_core::quic::crypto_of(payload));
                        talk.named =
                            reflex_core::quic::sni_of(&talk.crypto).map(String::into_boxed_str);
                        // Имя найдено — куски больше не нужны: держать их значило бы платить
                        // памятью на каждый разговор за то, что уже установлено.
                        if talk.named.is_some() {
                            talk.crypto = Vec::new();
                        }
                    }
                    let repeat = !talk.answered && talk.opened_with == dcid;
                    if talk.opened_with.is_empty() {
                        talk.opened_with = dcid.to_vec();
                    }
                    match repeat {
                        true => {
                            talk.retries = talk.retries.saturating_add(1);
                            Seen::Resent {
                                count: payload.len() as u32,
                            }
                        }
                        // Первое открытие: отдаём ГОЛОВУ, чтобы цепочка узнала цель по имени тем
                        // же путём, что и на TLS.
                        false => Seen::Payload {
                            head: payload.to_vec(),
                            from_client: true,
                        },
                    }
                }
            },
        };

        // Ключ цели: имя из `Initial`, если оно было; иначе адрес, и тег `Unnamed` не притворяется
        // именем (§4 — расслоение по ключу, а не по строке).
        let key = match talk.named.as_ref() {
            Some(name) => TargetKey::Named(name.clone()),
            None => TargetKey::Unnamed(datagram.dst),
        };

        Observation::Seen(Observed {
            flow: datagram.flow,
            key,
            wire,
        })
    }
}
