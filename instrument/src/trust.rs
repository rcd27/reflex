//! Доверие к цели — различает подмену личности от медленного канала. `mirage` (подмена),
//! `big_throttle`, `steady_slow` дают одну картину на транспорте («просил, ответила, ушёл»), но
//! переживаются по-разному. Улика замерена: на записи `mirage` клиент шлёт TLS `Alert` 48
//! (`unknown_ca`) — «я не доверяю этому сертификату», заявление стороны, сильнее улики нет.

use reflex_core::tls::{TlsFragment, TlsRecord};

/// Чем кончилось рукопожатие.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trust {
    /// Клиент отверг сертификат — так выглядит подмена и честная ошибка конфигурации (не различаем,
    /// см. `LIES`).
    RefusedCertificate { alert: u8 },
    /// Клиент оборвал по другой причине: параметры не сошлись, версия не та.
    RefusedOther { alert: u8 },
    /// Рукопожатие дошло до прикладных данных — доверие состоялось.
    Established,
}

/// Сказано разговору: доверие устанавливается раз за рукопожатие.
impl reflex_core::word::Word for Trust {
    type Of = reflex_core::word::Conversation;
}

/// Прибор доверия.
#[derive(Debug, Clone, Copy, Default)]
pub struct TrustInstrument {
    /// Уже высказались: доверие устанавливается один раз.
    settled: bool,
}

/// Коды тревоги о сертификате (RFC 8446 §6.2). Список закрыт: прочее — `RefusedOther`, ибо «чем-то
/// недоволен» и «не верит личности» — разные новости.
const CERTIFICATE_ALERTS: &[u8] = &[
    42, // bad_certificate
    43, // unsupported_certificate
    44, // certificate_revoked
    45, // certificate_expired
    46, // certificate_unknown
    48, // unknown_ca — именно этот приходит на подмену
    51, // decrypt_error: подпись сервера не проверилась
];

impl TrustInstrument {
    pub fn new() -> Self {
        Self::default()
    }

    /// Что даёт очередная запись. Прикладные данные сильнее всего: если пошли — рукопожатие
    /// состоялось; тревога после них про конец разговора, не про доверие.
    fn saw(self, record: TlsRecord) -> (Self, smallvec::SmallVec<[Trust; 2]>) {
        match (self.settled, record.content_type, record.fragment) {
            (true, _content, _fragment) => (self, smallvec::SmallVec::new()),
            (false, reflex_core::tls::TlsContentType::ApplicationData, _fragment) => (
                Self { settled: true },
                smallvec::smallvec![Trust::Established],
            ),
            (false, _content, TlsFragment::Alert { description, .. }) => (
                Self { settled: true },
                smallvec::smallvec![match CERTIFICATE_ALERTS.contains(&description) {
                    true => Trust::RefusedCertificate { alert: description },
                    false => Trust::RefusedOther { alert: description },
                }],
            ),
            (
                false,
                _content,
                TlsFragment::ClientHello { .. } | TlsFragment::ServerHello | TlsFragment::Other,
            ) => (self, smallvec::SmallVec::new()),
        }
    }
}

impl reflex_core::mealy::Mealy for TrustInstrument {
    /// Одна запись TLS, не срез потока: прибор читает по мере поступления записей (иначе годился бы
    /// только записи, не живой очереди).
    type In = reflex_core::DetectorEvent<TlsRecord>;
    /// Слово. Молчание сигналом не является.
    type Out = smallvec::SmallVec<[Trust; 2]>;
    type Log = ();

    fn step(self, event: Self::In) -> (Self, Self::Out, ()) {
        let (state, signals) = match event {
            reflex_core::DetectorEvent::Packet { input, .. } => self.saw(input),
            // Прибор утверждает только по НАЛИЧИЮ записи: `ApplicationData` даёт `Established`,
            // `Alert` — отказ. Прячущая буква способна отнять утверждение, но не создать его:
            // ошибка идёт в сторону пропуска, а не выдумки, и ослеплять тут нечего (§7, Д7).
            reflex_core::DetectorEvent::Tick { .. }
            | reflex_core::DetectorEvent::Opaque { .. }
            | reflex_core::DetectorEvent::Torn { .. } => (self, smallvec::SmallVec::new()),
        };
        (state, signals, ())
    }
}

impl crate::Instrument for TrustInstrument {
    type Signal = Trust;

    const INSTRUMENT: &'static str = "trust";

    const SUBJECT: crate::Subject = crate::Subject::World;

    /// Уровень сеанса: улика в рукопожатии TLS.
    const LAYER: crate::Layer = crate::Layer::Session;
    const PROTOCOLS: &'static [crate::Protocol] = &[crate::Protocol::Tls];

    /// Ступень «то ли пришло»: тот же вопрос, что у содержимого, но про личность отвечающего.
    const RUNG: Option<crate::Rung> = Some(crate::Rung::Authentic);

    const CADENCE: crate::Cadence = crate::Cadence::Foreign;
    const SHAPE: crate::Shape = crate::Shape::Verdict;

    /// Смотрел и не нашёл: поток без записей TLS не даёт вердикта — `Nothing`, улики там нет по
    /// построению.
    const SILENCE: Option<crate::Silence> = Some(crate::Silence::Nothing);

    const LIES: &'static [&'static str] = &[
        "ПОДМЕНА И ЧЕСТНАЯ ОШИБКА ЦЕЛИ НЕРАЗЛИЧИМЫ. Просроченный сертификат у самой цели даёт тот \
         же `certificate_expired`, что и подставной. Прибор говорит «клиент не поверил», и это \
         всё, что он устанавливает; кто виноват — вопрос расследования.",
        "TLS 1.3 ШИФРУЕТ ЧАСТЬ РУКОПОЖАТИЯ. Тревоги ПОСЛЕ `ChangeCipherSpec` едут внутри \
         `ApplicationData` и снаружи неотличимы от данных. Прибор видит только те, что пришли \
         открытым текстом, — на замеренной записи это так, но гарантией не является.",
        "ОТСУТСТВИЕ ТРЕВОГИ НЕ ЕСТЬ ДОВЕРИЕ. Клиент, оборвавший соединение молча (`RST` без \
         `Alert`), даёт `None`, а не `Established`; отличить «поверил» от «ушёл, не сказав» может \
         только наличие прикладных данных, и потому `Established` требует именно их.",
    ];

    const ORACLES: &'static [&'static str] = &["mirage(104.21.32.39)", "pass"];

    const DEATH: &'static str = "тревоги TLS 1.3 читаются; молчание прибора значит отсутствие беды";

    const EVENTS: &'static [&'static str] = &[
        "trust_established",
        "trust_refused_certificate",
        "trust_refused_other",
    ];

    fn name(signal: &Self::Signal) -> &'static str {
        match signal {
            Trust::Established => "trust_established",
            Trust::RefusedCertificate { .. } => "trust_refused_certificate",
            Trust::RefusedOther { .. } => "trust_refused_other",
        }
    }

    fn alarming(signal: &Self::Signal) -> bool {
        match signal {
            Trust::Established => false,
            Trust::RefusedCertificate { .. } | Trust::RefusedOther { .. } => true,
        }
    }

    fn detail(signal: &Self::Signal) -> String {
        match signal {
            Trust::Established => String::new(),
            Trust::RefusedCertificate { alert } => {
                format!("клиент отверг сертификат (тревога {alert})")
            }
            Trust::RefusedOther { alert } => format!("рукопожатие оборвано (тревога {alert})"),
        }
    }
}

#[cfg(test)]
mod stream_tests {
    use super::*;
    use reflex_core::mealy::Mealy;
    use reflex_core::tls::{TlsContentType, TlsRecord};
    use reflex_core::DetectorEvent;

    fn record(fragment: TlsFragment, content_type: TlsContentType) -> TlsRecord {
        TlsRecord {
            content_type,
            version: reflex_core::tls::TlsVersion { major: 3, minor: 3 },
            fragment,
        }
    }

    fn run(records: Vec<TlsRecord>) -> Vec<Trust> {
        records
            .into_iter()
            .fold(
                (TrustInstrument::new(), Vec::new()),
                |(state, said), record| {
                    let (stepped, signals, _) = state.step(DetectorEvent::packet_now(record));
                    (stepped, said.into_iter().chain(signals).collect())
                },
            )
            .1
    }

    /// Прибор судит поток, не срез: тревога приходит третьим-четвёртым пакетом.
    #[test]
    fn a_refusal_arriving_later_is_still_seen() {
        let said = run(vec![
            record(
                TlsFragment::ClientHello { sni: None },
                TlsContentType::Handshake,
            ),
            record(TlsFragment::ServerHello, TlsContentType::Handshake),
            record(
                TlsFragment::Alert {
                    level: 2,
                    description: 48,
                },
                TlsContentType::Alert,
            ),
        ]);

        assert_eq!(said, vec![Trust::RefusedCertificate { alert: 48 }]);
    }

    /// Прикладные данные закрывают вопрос: тревога после них — про конец разговора.
    #[test]
    fn application_data_settles_it_once() {
        let said = run(vec![
            record(TlsFragment::ServerHello, TlsContentType::Handshake),
            record(TlsFragment::Other, TlsContentType::ApplicationData),
            record(
                TlsFragment::Alert {
                    level: 1,
                    description: 0,
                },
                TlsContentType::Alert,
            ),
        ]);

        assert_eq!(said, vec![Trust::Established]);
    }

    /// Пока не случилось ни того ни другого — молчит, а не гадает.
    #[test]
    fn a_handshake_in_progress_says_nothing() {
        let said = run(vec![record(
            TlsFragment::ClientHello { sni: None },
            TlsContentType::Handshake,
        )]);

        assert_eq!(said, Vec::<Trust>::new());
    }
}
