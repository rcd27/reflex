//! Просадка канала — прибор о том, что «начало качаться хреново», а не «скачалось медленно».

/// Просадка канала: «начало качаться хреново» ≠ «всегда медленный». Различает их только ряд —
/// момент, до которого было хорошо (ср. `ThrottledInstrument` о величине). Три ловушки, каждая
/// замерена: маховик (первое окно неполно — TCP разгоняется), хвост (последнее неполно — файл
/// кончился), пачечность (окно короче пачки даёт нули между ними — окно ≥ секунды). Порог `2`
/// лежит в разрыве замера (sag: отношение 4,4; steady_slow: ~1), не подогнан к краю.
pub struct SagInstrument;

/// Что просело и когда. Не `bool`: без момента и величины беду ни назвать, ни сверить с землёй.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sag {
    /// Номер окна, на котором темп упал.
    pub at_window: usize,
    /// Байт в секунду ДО просадки — доказанная целью планка.
    pub before_bps: u64,
    /// Байт в секунду ПОСЛЕ. Разность с планкой — мера потери человека.
    pub after_bps: u64,
}

/// Сказано разговору: просадка — его свойство, момент внутри него.
impl reflex_core::word::Word for Sag {
    type Of = reflex_core::word::Conversation;
}

impl SagInstrument {
    fn read(&self, observation: &Vec<u64>, _now_ms: u64) -> Option<Sag> {
        // Хвост и маховик отброшены до счёта: оба неполны, участие любого даёт ложную тревогу.
        let windows: &[u64] = match observation.len() {
            0..=3 => return None,
            length => &observation[1..length - 1],
        };

        // Планка — первое окно после маховика, не среднее (среднее уже включает просадку).
        let baseline = match windows.first() {
            None => return None,
            Some(&first) => first,
        };

        // Два окна подряд, не одно: одиночный провал бывает от чего угодно.
        windows
            .windows(2)
            .enumerate()
            .find(|(_, pair)| pair.iter().all(|&bps| bps * 2 < baseline))
            .map(|(index, pair)| Sag {
                // `+1` — номер окна в исходном ряду: маховик отброшен, человек считает от начала.
                at_window: index + 1,
                before_bps: baseline,
                after_bps: pair[0],
            })
    }
}

impl reflex_core::mealy::Mealy for SagInstrument {
    type In = reflex_core::DetectorEvent<Vec<u64>>;
    /// Слово. Молчание сигналом не является — «ничего не случилось» не занимает места в ленте.
    type Out = smallvec::SmallVec<[Sag; 2]>;
    type Log = ();

    fn step(self, event: Self::In) -> (Self, Self::Out, ()) {
        match event {
            reflex_core::DetectorEvent::Packet { input, .. } => {
                let reading = self.read(&input, 0);
                (self, reading.into_iter().collect(), ())
            }
            reflex_core::DetectorEvent::Tick { .. }
            | reflex_core::DetectorEvent::Opaque { .. }
            | reflex_core::DetectorEvent::Torn { .. } => (self, smallvec::SmallVec::new(), ()),
        }
    }
}

impl crate::Instrument for SagInstrument {
    type Signal = Sag;

    const INSTRUMENT: &'static str = "sag";

    const SUBJECT: crate::Subject = crate::Subject::World;

    const LAYER: crate::Layer = crate::Layer::Transport;
    const PROTOCOLS: &'static [crate::Protocol] = &[crate::Protocol::Tcp, crate::Protocol::Udp];
    const RUNG: Option<crate::Rung> = None;

    /// Свои часы: окно закрывается временем, не приходом байта — иначе прибор молчал бы, когда
    /// байты перестали идти совсем.
    const CADENCE: crate::Cadence = crate::Cadence::Own { step_ms: 1_000 };

    /// Ряд: показание осмысленно только относительно предыдущих.
    const SHAPE: crate::Shape = crate::Shape::Series;

    /// Слепота, не пустота: ряд короче четырёх окон ответа не даёт — лечится длинной загрузкой.
    const SILENCE: Option<crate::Silence> = Some(crate::Silence::Blind);

    const LIES: &'static [&'static str] = &[
        "ПРИЧИНЫ НЕ ЗНАЕТ. Просадка от инфраструктурной фильтрации, от переполненного Wi-Fi и от того, что цель отдаёт \
         остаток файла с диска, дают ОДИН ряд. Прибор говорит «стало хуже вот здесь», и это всё, \
         что он устанавливает.",
        "ПЛАНКА ИЗ НАЧАЛА ЗАГРУЗКИ. Если канал был плох С САМОГО НАЧАЛА, планка запомнит плохое, \
         и просадка от неё не отсчитается никогда — ровно как у соседа по парку (`ThrottledInstrument`, \
         огибающая храповиком). Клетка `steady_slow` показывает это прямо: там прибор МОЛЧИТ, и \
         молчание верно, хотя человеку медленно.",
        "ПРОСАДКА В КОНЦЕ ЗАГРУЗКИ НЕ ВИДНА. Последнее окно отброшено намеренно, и цена названа: \
         беда, случившаяся в последнюю секунду, останется незамеченной. Обратное дало бы тревогу \
         на каждой нормальной загрузке.",
    ];

    const ORACLES: &'static [&'static str] = &["sag(10mbit,2mbit,3)", "throttle(2mbit,0)"];

    const DEATH: &'static str =
        "просадка получила причину: прибор различает наведённую просадку и узкий канал";

    const EVENTS: &'static [&'static str] = &["sag"];

    fn name(signal: &Self::Signal) -> &'static str {
        let _ = signal;
        "sag"
    }

    fn alarming(signal: &Self::Signal) -> bool {
        let _ = signal;
        true
    }
}
