//! Сигнал беды — то, что человек почувствовал бы как поломку. Прибор, а не домен: `Distress`
//! описывает МИР («пришёл сброс», «молчание столько-то»), а лечение живёт в `Finding` и маршруте у
//! потребителя. Пока сигнал жил в домене, четыре прибора провода не могли переехать в общий дом.

/// Сигнал беды — что человек почувствовал бы как поломку.
#[derive(Debug, Clone, PartialEq, Eq)]
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
    /// Отравление DNS: на запрос пришёл инжект (`NXDOMAIN`/пустой ответ) вместо адреса. Подозрение,
    /// не приговор — легитимный `NXDOMAIN` даёт то же; различает оракул/кросс-резолвер.
    Poisoned,
    /// По НАШИМ битам марки писал другой агент (тег не наш) — не ошибка и не тишина, а находка:
    /// на машине крутится кто-то ещё. `theirs` — чужое слово целиком, для расследования.
    Diverged { theirs: u32 },
}

impl Distress {
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
