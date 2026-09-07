//! ДОВЕРИЕ К ЦЕЛИ — различает подмену личности от медленного канала.
//!
//! # Дыра, которую он закрывает, названа матрицей покрытия
//!
//! Замер на девятнадцати землях: `mirage` (подмена личности), `big_throttle` (стойло) и
//! `steady_slow` (ровный медленный канал) дают ОДНУ картину на транспорте — «просил, ответила,
//! человек ушёл». Переживаются они по-разному: в первом случае человек не получил НИЧЕГО и не
//! получит, во втором и третьем он получает, только медленно.
//!
//! Прибор просадки их не берёт по построению: у подмены нет момента, до которого было хорошо.
//!
//! # Улика замерена, а не предположена
//!
//! На записи `mirage` (tshark по фикстуре стенда):
//!
//! ```text
//! клиент → ClientHello (тип 1)
//! цель   → ServerHello + ChangeCipherSpec (типы 2, 20)
//! клиент → Alert, description 48
//! ```
//!
//! `48` есть `unknown_ca`: клиент прямо говорит «я не доверяю этому сертификату». Это не догадка
//! по косвенным признакам — это заявление стороны, и сильнее улики на данном уровне не бывает.

use reflex_core::tls::{TlsFragment, TlsRecord};

/// ЧЕМ КОНЧИЛОСЬ РУКОПОЖАТИЕ.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trust {
    /// Клиент отверг СЕРТИФИКАТ. Так выглядит подмена личности — и так же выглядит честная
    /// ошибка конфигурации у цели, которую мы не отличаем и об этом говорим (см. `LIES`).
    RefusedCertificate { alert: u8 },
    /// Клиент оборвал рукопожатие по другой причине: параметры не сошлись, версия не та.
    RefusedOther { alert: u8 },
    /// Рукопожатие дошло до прикладных данных — доверие состоялось.
    Established,
}

/// ПАСПОРТ ПРИБОРА ДОВЕРИЯ.
#[derive(Debug, Clone, Copy, Default)]
pub struct TrustInstrument {
    /// Уже высказались. Второй раз о том же разговоре говорить нечего: доверие устанавливается
    /// один раз.
    settled: bool,
}

/// КОДЫ ТРЕВОГИ, ГОВОРЯЩИЕ ИМЕННО О СЕРТИФИКАТЕ (RFC 8446 §6.2). Список закрытый и короткий:
/// всё прочее попадает в `RefusedOther`, потому что «клиент чем-то недоволен» и «клиент не верит
/// предъявленной личности» — разные новости для человека.
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

    /// ЧТО ДАЁТ ОЧЕРЕДНАЯ ЗАПИСЬ.
    ///
    /// Прикладные данные СИЛЬНЕЕ всего остального: если они пошли, рукопожатие состоялось и клиент
    /// цели поверил. Тревога после них — уже про конец разговора, а не про доверие, и потому
    /// разговор, о котором высказались, больше не судится.
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

impl reflex_core::step::Step for TrustInstrument {
    /// ОДНА ЗАПИСЬ TLS, а не срез потока: прибор читает разговор ПО МЕРЕ поступления записей, а
    /// не ждёт, пока поток кончится, — иначе он годился бы только записи, а не живой очереди.
    type From = reflex_core::DetectorEvent<TlsRecord>;

    /// ПОКАЗАНИЕ. Отсутствие показания сигналом не является: прибор высказывается, когда есть что
    /// сказать.
    type To = smallvec::SmallVec<[Trust; 2]>;

    fn step(self, event: Self::From) -> (Self, Self::To) {
        match event {
            reflex_core::DetectorEvent::Packet { input, .. } => self.saw(input),
            reflex_core::DetectorEvent::Tick { .. } => (self, smallvec::SmallVec::new()),
            // Прибор мерит РАЗОБРАННЫЙ домен; непонятое им не является и молчит так же, как тик.
            reflex_core::DetectorEvent::Opaque { .. } => (self, smallvec::SmallVec::new()),
        }
    }
}

impl crate::Instrument for TrustInstrument {
    type Signal = Trust;

    const INSTRUMENT: &'static str = "trust";

    const SUBJECT: crate::Subject = crate::Subject::World;

    /// УРОВЕНЬ СЕАНСА: улика лежит в рукопожатии TLS. Транспорт видит те же байты и не знает, что
    /// они значат; приложение до них не доходит, потому что разговор кончился раньше.
    const LAYER: crate::Layer = crate::Layer::Session;
    const PROTOCOLS: &'static [crate::Protocol] = &[crate::Protocol::Tls];

    /// СТУПЕНЬ «ТО ЛИ ПРИШЛО»: тот же вопрос, что у содержимого, только про ЛИЧНОСТЬ отвечающего,
    /// а не про тело ответа.
    const RUNG: Option<crate::Rung> = Some(crate::Rung::Authentic);

    const CADENCE: crate::Cadence = crate::Cadence::Foreign;
    const SHAPE: crate::Shape = crate::Shape::Verdict;

    /// СМОТРЕЛ И НЕ НАШЁЛ: поток без записей TLS (обычный HTTP, QUIC, DNS) не даёт вердикта, и
    /// это `Nothing` — улики там нет по построению, а не по слепоте прибора.
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

    /// СМЕРТЬ: прибор научился читать тревоги TLS 1.3 внутри шифрованных записей — тогда его
    /// молчание перестанет означать «может быть, было, но мы не видели».
    const DEATH: &'static str = "тревоги TLS 1.3 читаются; молчание прибора значит отсутствие беды";

    /// ПУБЛИЧНЫЕ ИМЕНА СОБЫТИЙ — реестр, снятый с типа: за границей процесса имя показания не
    /// сторожит компилятор, и `Debug` сменил бы метку молча (#321).
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
    use reflex_core::step::Step;
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
                    let (stepped, signals) = state.step(DetectorEvent::packet_now(record));
                    (stepped, said.into_iter().chain(signals).collect())
                },
            )
            .1
    }

    /// ПРИБОР СУДИТ ПОТОК, А НЕ СРЕЗ.
    ///
    /// Тревога приходит третьим-четвёртым пакетом, и прибор, которому подавали `Vec` целиком,
    /// работал только там, где поток УЖЕ кончился, — то есть на записи. В живую очередь он не
    /// вставал вовсе, и это стоило ему подключённости: на 02.09 доверие было в ленте записи и
    /// отсутствовало в ленте живого трафика.
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

    /// ПРИКЛАДНЫЕ ДАННЫЕ ЗАКРЫВАЮТ ВОПРОС: доверие установлено, и тревога после них — про конец
    /// разговора, а не про личность цели.
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

    /// ПОКА НЕ СЛУЧИЛОСЬ НИ ТОГО НИ ДРУГОГО — прибор молчит, а не гадает.
    #[test]
    fn a_handshake_in_progress_says_nothing() {
        let said = run(vec![record(
            TlsFragment::ClientHello { sni: None },
            TlsContentType::Handshake,
        )]);

        assert_eq!(said, Vec::<Trust>::new());
    }
}
