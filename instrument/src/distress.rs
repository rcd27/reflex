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
            Distress::Diverged { theirs } => format!("чужой писатель марки: {theirs:#010x}"),
            Distress::Rst | Distress::NoBytes | Distress::Poisoned => String::new(),
        }
    }
}

/// Беда сказана о разговоре: наклонение изъявительное (ничего не велит), но адресат есть — потому
/// слово, а не показание.
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
