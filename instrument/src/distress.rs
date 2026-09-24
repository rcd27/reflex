//! Сигнал беды — то, что человек почувствовал бы как поломку. Прибор, а не домен: `Distress`
//! описывает МИР («пришёл сброс», «молчание столько-то»), а лечение живёт в `Finding` и маршруте у
//! потребителя. Пока сигнал жил в домене, четыре прибора провода не могли переехать в общий дом.

// TODO(#325): обогатить парк детекторов по известной таксономии, по одной болезни за раз — захват
// на известном вантаже, контроль здоровой целью того же CDN, прогон записанным проводом, буква.
// Таксономия ТСПУ — Xue et al., «TSPU: Russia's Decentralized Censorship System», IMC '22
// (https://ensa.fi/papers/tspu-imc22.pdf, doi:10.1145/3517745.3561461), рис. 2 «Different
// blocking Behaviors» и текст при нём:
//   SNI-I   — ответ цели усечён и подменён на RST/ACK после ClientHello (ближе всего `Rst`);
//   SNI-II  — после триггерного ClientHello проходит ещё 5–8 пакетов, затем симметричный дроп
//             (в работе: `HelloMuted`, захват узла кэша Google у Билайна на стенде 24.09.2026);
//   SNI-III — троттлинг ~600–700 Б/с (в 2022 заменён на SNI-I);
//   SNI-IV  — дроп всего, включая сам ClientHello (первая берётся в работу: `HelloDropped`,
//             #347, захват rutracker.org на линии стенда 24.09.2026);
//   QUIC    — отпечаток версии в открытых байтах первого пакета;
//   IP      — дроп всего к адресу/от адреса, включая ICMP (ближе всего `Blackhole`).
// Сверх неё — «заморозка» (Хабр, июнь 2026, https://habr.com/ru/articles/1047442/): данные идут, а
// обрезают после 16–20 КБ; и вердикты практиков (RKN Block Checker, https://habr.com/ru/articles/1032572/:
// `TLS_BLOCK` — TCP ok, TLS RST/timeout). Статья 2022 года — не истина о 2026-м: каждая буква
// заводится по захвату на нашем вантаже, таксономия лишь даёт ей имя, чтобы не выдумывать своё.

/// Сигнал беды — что человек почувствовал бы как поломку.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Distress {
    /// Пришёл RST. От кого — вопрос расследования.
    Rst,
    /// Молчание дольше названного окна, в миллисекундах.
    Silence { ms: u32 },
    /// Байты идут, но так медленно, что это неотличимо от поломки.
    Throttled { bps: u32 },
    /// Соединение живо, байтов ноль.
    NoBytes,
    /// Клиент повторил просьбу, а цель не отдала байта. Отдельная буква, не ранний `NoBytes`:
    /// различает их ЧЕЙ ПОРОГ сработал — `NoBytes` по нашему терпению, повтор по RTO клиентского
    /// ядра под фактический RTT. Слей — и замер «360 мс против 1500» станет ненаблюдаем.
    Retransmit { after_ms: u32 },
    /// IP-blackhole: `SYN` ушёл, `SYN+ACK` не пришёл, клиент повторяет `SYN`. Соединение НЕ
    /// состоялось вовсе — отдельная буква, не `NoBytes`/`Silence` (те про УЖЕ открытое соединение).
    /// Блок по адресу, до всякого имени; `after_ms` — от первого `SYN` до повтора (RTO ядра).
    Blackhole { after_ms: u32 },
    /// ЦЕЛЬ ОТВЕЧАЕТ, А ОТВЕТЫ НЕ ДОХОДЯТ: она повторяет один и тот же сегмент с нарастающим RTO,
    /// и прогресса нет. Отдельная буква, не `Silence` и не `Throttled`, и различие проверяемое:
    /// молчание про ОТСУТСТВИЕ байтов (а они идут), троттлинг про СКОРОСТЬ (а тут её не «мало» —
    /// её нет вовсе, повтор не есть прогресс). Слей с любым из них — и фильтр «в обратную сторону»
    /// станет неотличим от медленного канала, каким он и выглядел до этой буквы.
    ///
    /// `retries` — сколько раз цель повторила, не продвинувшись. Величина, а не флаг: одиночный
    /// повтор бывает от обычной потери, ряд повторов — уже заявление стороны.
    Unreached { retries: u32 },
    /// СЕГМЕНТ ПРОГЛОЧЕН В ЖИВОМ РАЗГОВОРЕ: клиент повторяет один и тот же кусок, а цель при этом
    /// ПОДТВЕРЖДАЕТ предыдущие байты — то есть жива и отвечает. Выборочный дроп внутри живого
    /// разговора.
    ///
    /// Отдельно от `Retransmit`, и разница в СИЛЕ утверждения: там подозрение («просили, вниз
    /// ничего»), которое обычная потеря даёт тоже; здесь цель доказанно жива, и потому «не проходит
    /// именно этот сегмент». Обычная потеря так себя не ведёт — она бьёт по любому сегменту, а не
    /// по одному и тому же раз за разом. Слей их — потеряешь либо раннее подозрение, либо точный
    /// диагноз, а лечение у них разное.
    ///
    /// Замер, которым буква оплачена: голова приветствия дошла и подтверждена, хвост с концом имени
    /// не проходит, клиент повторяет его шесть раз. Для человека — глухой таймаут; для батареи до
    /// этой буквы — здоровый разговор, и каждый прибор молчал законно.
    Swallowed { after_ms: u32 },
    /// ЦЕЛЬ ЗАКРЫЛА РАЗГОВОР, НЕ СКАЗАВ НИ БАЙТА ДАННЫХ: приветствие принято, ответа нет, `FIN`.
    ///
    /// Отдельно от `Rst`, и различие не в вежливости: сброс бывает НАШИМ собственным (у него есть
    /// автор), а прощание при нуле сказанного всегда чужое. Отдельно от `Silence` и `NoBytes` —
    /// там цель молчит и разговор жив, здесь она ответила немедленно и ушла. Для человека это
    /// вечная крутилка: браузер переоткрывает и получает то же самое по кругу.
    ///
    /// `after_ms` — от просьбы клиента до прощания. Замер потребителя: три сотых секунды, то есть
    /// не таймаут, а решение.
    Dismissed { after_ms: u32 },
    /// ПРИВЕТСТВИЕ НЕ ПОДТВЕРЖДЕНО НИ РАЗУ: рукопожатие состоялось, клиент отправил первые данные
    /// (у TLS — `ClientHello` с именем), и цель не ответила НИЧЕМ — ни данными, ни подтверждением.
    /// Клиент повторяет их с растущим RTO и сдаётся.
    ///
    /// Имя — из таксономии, а не наше: SNI-IV у Xue et al., «TSPU: Russia's Decentralized
    /// Censorship System», IMC '22 — «drops all packets from both sides, including the initial
    /// ClientHello»; у практиков — `TLS_BLOCK` через тайм-аут (RKN Block Checker), «молчаливый
    /// дроп». Буква называет НАБЛЮДАЕМОЕ, а не причину: что триггер — имя, прибор сам не знает, это
    /// устанавливает контроль той же дорогой с другим именем.
    ///
    /// Отдельно от соседей, и различие проверяемое: `NoBytes` — нет данных (молчащий сервер
    /// приветствие ПОДТВЕРЖДАЕТ); `Retransmit` — подозрение, один повтор даёт и обычная потеря;
    /// `Swallowed` — цель жива и подтверждает голову, здесь не подтверждает ничего; `Blackhole` —
    /// рукопожатия нет вовсе.
    ///
    /// `retries` — сколько раз клиент повторил, `after_ms` — от первой отправки до повтора, на
    /// котором сказано. Замер (линия стенда, 24.09.2026, `rutracker.org`): повторы через 0,30 · 0,59
    /// · 1,22 · 2,43 · 4,80 · 9,67 с; здоровые цели того же пути подтверждают за 36–37 мс.
    HelloDropped { retries: u32, after_ms: u32 },
    /// ПРИВЕТСТВИЕ ПРИНЯТО, ОТВЕТ ЗАГЛУШЁН: рукопожатие состоялось, цель ПОДТВЕРДИЛА первые данные
    /// клиента (`ClientHello` целиком), а своих не прислала — и молчит дольше, чем живой сервер
    /// отвечает после подтверждения.
    ///
    /// Имя — из таксономии: SNI-II у Xue et al., IMC '22, §5.2 — «once a triggering ClientHello
    /// is seen, an additional five to eight packets can be delivered from either side, after which
    /// symmetric packet drops occur»; там же в списке «вне реестра» — сервисы Google.
    ///
    /// Отдельно от соседа [`Distress::HelloDropped`], и различие проверяемое: там цель молчит на
    /// приветствие и клиент его повторяет; здесь приветствие подтверждено, клиенту повторять
    /// нечего — он молча ждёт своего таймаута (20 с у `yt-dlp`), и прибор повторов такой разговор
    /// не видит по построению. Не `NoBytes`: тот судит тишину разговора целиком, этот — только
    /// промежуток между подтверждением приветствия и первым байтом цели.
    ///
    /// `rtt_ms` — рукопожатие этой цели (по нему мерился порог), `after_ms` — от подтверждения до
    /// слова. Замер стенда 24.09.2026: у здоровых разговоров данные идут не позже 0,3 RTT после
    /// подтверждения; у заглушённого узла кэша Google у Билайна — 20 с тишины до ухода клиента.
    HelloMuted { rtt_ms: u32, after_ms: u32 },
    /// Отравление DNS: на запрос пришёл инжект (`NXDOMAIN`/пустой ответ) вместо адреса. Подозрение,
    /// не приговор — легитимный `NXDOMAIN` даёт то же; различает оракул/кросс-резолвер.
    Poisoned,
    /// По НАШИМ битам марки писал другой агент (тег не наш) — не ошибка и не тишина, а находка:
    /// на машине крутится кто-то ещё. `theirs` — чужое слово целиком, для расследования.
    Diverged { theirs: u32 },
}

/// СИЛА УТВЕРЖДЕНИЯ БУКВЫ — судить ли по ней о цели.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Assertion {
    /// Ту же картину даёт и здоровая сеть: обычная потеря, отошедший человек, медленное плечо.
    Suspicion,
    /// Поведение, которого у здоровой сети не бывает: цель не открылась или не донесла.
    Diagnosis,
    /// Находка о мире, а не беда человека: чужой писатель наших битов.
    Finding,
}

impl Distress {
    /// Сила утверждения. Сторож: `the_alphabet_is_weighed_as_its_docblocks_say`.
    pub const fn assertion(&self) -> Assertion {
        match self {
            Distress::Retransmit { .. } | Distress::Silence { .. } | Distress::Throttled { .. } => {
                Assertion::Suspicion
            }
            Distress::Rst
            | Distress::NoBytes
            | Distress::Blackhole { .. }
            | Distress::Unreached { .. }
            | Distress::Swallowed { .. }
            | Distress::Dismissed { .. }
            | Distress::HelloDropped { .. }
            | Distress::HelloMuted { .. }
            | Distress::Poisoned => Assertion::Diagnosis,
            Distress::Diverged { .. } => Assertion::Finding,
        }
    }

    /// Чем снимается симптом — та же величина, которой беду мерила детекция.
    pub const fn relief(&self) -> crate::edge_detect::Relief {
        use crate::edge_detect::Relief;
        match self {
            // На стук не ответила — снятие есть ответ на стук.
            Distress::Blackhole { .. } => Relief::Answered,
            // Приветствие не подтверждено — снятие есть подтверждение, данных не требует.
            Distress::HelloDropped { .. } => Relief::Acknowledged,
            // Цель не донесла (в том числе подтвердив приветствие) — снятие есть данные.
            Distress::NoBytes
            | Distress::Rst
            | Distress::Swallowed { .. }
            | Distress::Unreached { .. }
            | Distress::Dismissed { .. }
            | Distress::HelloMuted { .. } => Relief::Delivered,
            // Беда об имени, а не о разговоре; и подозрения, у которых снимать нечего.
            Distress::Poisoned
            | Distress::Retransmit { .. }
            | Distress::Silence { .. }
            | Distress::Throttled { .. }
            | Distress::Diverged { .. } => Relief::Unknown,
        }
    }

    /// За сколько беда проявилась на этом разговоре — если буква это несёт.
    pub fn after(&self) -> Option<std::time::Duration> {
        let ms = match self {
            Distress::Retransmit { after_ms }
            | Distress::Blackhole { after_ms }
            | Distress::Swallowed { after_ms }
            | Distress::Dismissed { after_ms }
            | Distress::HelloDropped { after_ms, .. }
            | Distress::HelloMuted { after_ms, .. } => Some(*after_ms),
            Distress::Silence { ms } => Some(*ms),
            Distress::Rst
            | Distress::NoBytes
            | Distress::Throttled { .. }
            | Distress::Unreached { .. }
            | Distress::Poisoned
            | Distress::Diverged { .. } => None,
        };
        ms.map(|ms| std::time::Duration::from_millis(u64::from(ms)))
    }

    /// Имя сигнала — публичный контракт (метка в метрику). Тотально и без `Debug` (его формат
    /// нестабилен): переименуй вариант — компилятор промолчит, а метка сменится.
    pub fn name(&self) -> &'static str {
        match self {
            Distress::Rst => "rst",
            Distress::Silence { .. } => "silence",
            Distress::Throttled { .. } => "throttled",
            Distress::NoBytes => "no_bytes",
            Distress::Retransmit { .. } => "retransmit",
            Distress::Blackhole { .. } => "blackhole",
            Distress::Unreached { .. } => "unreached",
            Distress::Swallowed { .. } => "swallowed",
            Distress::Dismissed { .. } => "dismissed",
            Distress::HelloDropped { .. } => "hello_dropped",
            Distress::HelloMuted { .. } => "hello_muted",
            Distress::Poisoned => "poisoned",
            Distress::Diverged { .. } => "diverged",
        }
    }

    /// Требует ли внимания — один ответ на весь алфавит: `Distress` есть «то, что человек ощутил бы
    /// как поломку», небеспокоящей беды в этом типе нет. Метод, а не константа у потребителя:
    /// новая небеспокоящая буква правится здесь одна.
    pub const fn alarming(&self) -> bool {
        true
    }

    /// Величина в единице человека. Пусто — показание есть само событие. От [`core::fmt::Display`] отличается
    /// предметом: тот пишет машинную улику, этот — читаемое человеком; обе в одном файле, чтобы
    /// сверяться глазом.
    pub fn detail(&self) -> String {
        match self {
            Distress::Silence { ms } => format!("{ms} мс без байтов"),
            Distress::Throttled { bps } => format!("{} КБ/с", bps / 1024),
            Distress::Retransmit { after_ms } => format!("повтор через {after_ms} мс"),
            Distress::Blackhole { after_ms } => format!("SYN без ответа через {after_ms} мс"),
            Distress::Unreached { retries } => {
                format!("цель повторила ответ {retries} раза — до клиента не дошло")
            }
            Distress::Swallowed { after_ms } => {
                format!("сегмент не проходит {after_ms} мс, цель при этом отвечает")
            }
            Distress::Dismissed { after_ms } => {
                format!("закрыла разговор через {after_ms} мс, не отдав данных")
            }
            Distress::HelloDropped { retries, after_ms } => {
                format!("приветствие не подтверждено: {retries} повтора за {after_ms} мс")
            }
            Distress::HelloMuted { rtt_ms, after_ms } => {
                format!("приветствие подтверждено, ответа нет {after_ms} мс при RTT {rtt_ms} мс")
            }
            Distress::Diverged { theirs } => format!("чужой писатель марки: {theirs:#010x}"),
            Distress::Rst | Distress::NoBytes | Distress::Poisoned => String::new(),
        }
    }
}

/// Беда сказана о разговоре: наклонение изъявительное (ничего не велит), но адресат есть — потому
/// слово, а не показание.
/// Слово беды с ВОЗРАСТОМ наблюдения, его породившего. Фреймворк отдаёт величину и не судит о
/// годности: возраст — то, что мы видели; годность — вывод из истории цели и независимых проверок,
/// которых у наблюдателя одного разговора нет и быть не должно. Судить будет потребитель, а судить
/// не о чем, если возраст не сказан.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Spoken {
    pub distress: Distress,
    pub since: std::time::Duration,
}

/// Возраст ничего не переадресует: слово о разговоре остаётся словом о разговоре.
impl reflex_core::word::Word for Spoken {
    type Of = reflex_core::word::Conversation;
}

/// Слово о ЦЕЛИ — итог копредела по слою: свёртка слов о её разговорах (§4 `Target ≅ ∐
/// Conversation`, §5 сведение слов). Отдельный тип, а не `Spoken` с флагом: область у него ДРУГАЯ,
/// и §5 держит области раздельно ТИПОМ, а не рантайм-тегом.
///
/// Оттого и дверь у него своя (`on_target`): сложить его с словом о разговоре в одну реакцию
/// нельзя по построению — закон пары разных областей не складывает, а спустить слово о цели к
/// разговору значило бы отменить только что сделанную агрегацию.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Voiced<S = Distress> {
    pub distress: S,
    /// Возраст самого свежего из сведённых наблюдений. Годность судит потребитель — фреймворк
    /// отдаёт величину.
    pub since: std::time::Duration,
}

/// Слово о цели принадлежит области ЦЕЛИ, каким бы ни было слово разговоров под ним: копредел
/// меняет ОБЛАСТЬ, а не словарь (§4).
impl<S> reflex_core::word::Word for Voiced<S> {
    type Of = reflex_core::word::Target;
}

impl Distress {
    /// Одеть беду возрастом. Оба момента — аргументы: своих часов у слова нет (§8), иначе одно и то
    /// же наблюдение звучало бы по-разному при переигровке записи.
    pub fn aged(self, seen_at: std::time::Instant, now: std::time::Instant) -> Spoken {
        Spoken {
            distress: self,
            since: now.saturating_duration_since(seen_at),
        }
    }
}

impl reflex_core::word::Word for Distress {
    type Of = reflex_core::word::Conversation;
}

/// Улика сигнала — имя плюс величина. Имя открывает строку и совпадает с [`Distress::name`]: два
/// имени одного события лечатся уже археологией.
impl core::fmt::Display for Distress {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Distress::Rst => f.write_str("rst"),
            Distress::Silence { ms } => write!(f, "silence ms={ms}"),
            Distress::Throttled { bps } => write!(f, "throttled bps={bps}"),
            Distress::NoBytes => f.write_str("no_bytes"),
            Distress::Retransmit { after_ms } => write!(f, "retransmit after_ms={after_ms}"),
            Distress::Blackhole { after_ms } => write!(f, "blackhole after_ms={after_ms}"),
            Distress::Unreached { retries } => write!(f, "unreached retries={retries}"),
            Distress::Swallowed { after_ms } => write!(f, "swallowed after_ms={after_ms}"),
            Distress::Dismissed { after_ms } => write!(f, "dismissed after_ms={after_ms}"),
            Distress::HelloDropped { retries, after_ms } => {
                write!(f, "hello_dropped retries={retries} after_ms={after_ms}")
            }
            Distress::HelloMuted { rtt_ms, after_ms } => {
                write!(f, "hello_muted rtt_ms={rtt_ms} after_ms={after_ms}")
            }
            Distress::Poisoned => f.write_str("poisoned"),
            Distress::Diverged { theirs } => write!(f, "diverged theirs={theirs:#010x}"),
        }
    }
}

#[cfg(test)]
mod tests {
    /// Алфавит беды перечислен ровно в одном файле (имя, величина, тревожность — свойства БУКВЫ,
    /// копия таблицы разъедется молча). Игла — объявление типа (`concat!`, чтобы тест не
    /// самосчитался); «перечислен в одном файле» и «объявлен в одном файле» суть одно.
    #[test]
    fn the_alphabet_of_trouble_is_spelled_out_in_exactly_one_file() {
        let needle = concat!("enum ", "Distress");
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        // Нечитаемый каталог даёт пустой список, не панику: пустой ≠ ожидаемому, тест покраснеет.
        let spelling: Vec<String> = std::fs::read_dir(&root)
            .into_iter()
            .flatten()
            .filter_map(|entry| entry.ok())
            .filter(|entry| {
                std::fs::read_to_string(entry.path())
                    .map(|text| text.contains(needle))
                    .unwrap_or(false)
            })
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect();

        assert_eq!(
            spelling,
            ["distress.rs"],
            "алфавит беды перечислен в {} файлах",
            spelling.len()
        );
    }
}
