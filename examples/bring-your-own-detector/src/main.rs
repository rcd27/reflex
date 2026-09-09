//! # Свой детектор в ту же дверь — расширение фреймворка
//!
//! Вижн: «описать ВСЕ сценарии через пайпы». Все — значит и те, под которые прибора в парке нет.
//! Потребитель приносит СВОЙ автомат Мили и кладёт его в `.detect(own(...))` рядом с парковыми —
//! фиксированное меню приборов перестаёт быть потолком.
//!
//! Здесь `Impatient` — потребительская переделка тишины со СВОИМ порогом (3с против парковых 5с):
//! часы идут от последнего запроса клиента, сбрасываются ответом цели, повтор их не двигает (тот же
//! урок, что и у паркового прибора: повтор — симптом тишины, не её конец). Автомат читает словарь
//! провода `Seen`; сужение из широкого `Reading` и раздачу тиков/эвикт даёт движок — потребитель
//! пишет только логику.
//!
//! ## Что показывает
//!
//! Машина живёт в ЭТОМ крейте, движок про неё ничего не знал — и всё равно гоняет её на каждый
//! поток, кормит буквами провода и тиками, собирает её слова беды в общую реакцию. Тот же
//! `Distress`, та же дверь `.on`, что и у парка.
//!
//! И тот же копредел: `.about` сводит слова СВОЕГО прибора под ключ цели, как сводил бы парковые.
//! Оси перпендикулярны — «чей автомат» и «о чём слово» друг о друге не знают.
//!
//! ## Запуск
//!
//! ```sh
//! sudo nft 'add table inet reflex_demo'
//! sudo nft 'add chain inet reflex_demo out { type filter hook output priority -150; }'
//! sudo nft 'add rule inet reflex_demo out tcp dport 443 queue num 200'
//! cargo run -p bring-your-own-detector
//! # снять правила: sudo nft 'delete table inet reflex_demo'
//! ```

use std::time::{Duration, Instant};

use reflex::*;

/// Свой порог терпения — короче паркового (5с), чтобы вердикт не спутать с прибором парка.
const PATIENCE: Duration = Duration::from_millis(3000);

/// Потребительский прибор: «цель молчит дольше терпения при живом клиенте». Состояние — момент
/// последнего запроса клиента (пусто — ждать нечего). `Copy`, как требует движок: он сеет свежую
/// копию шаблона на каждый поток.
#[derive(Clone, Copy, Default)]
struct Impatient {
    asked_at: Option<Instant>,
}

impl Mealy for Impatient {
    type In = DetectorEvent<Seen>;
    type Out = SmallVec<[Distress; 2]>;
    type Log = ();

    fn step(mut self, event: DetectorEvent<Seen>) -> (Self, Self::Out, ()) {
        match event {
            // Клиент попросил — завести/сдвинуть часы (повтор `Resent` сюда не входит: он их не трогает).
            DetectorEvent::Packet {
                input:
                    Seen::Sent { .. }
                    | Seen::Payload {
                        from_client: true, ..
                    },
                at,
            } => self.asked_at = Some(at),

            // Цель ответила или разговор кончился — тишины нет, часы гасим.
            DetectorEvent::Packet {
                input:
                    Seen::Received { .. }
                    | Seen::Payload {
                        from_client: false, ..
                    }
                    | Seen::Closed { .. },
                ..
            } => self.asked_at = None,

            // Тик: ждём при живом запросе — за порогом высказываемся раз и гасим часы.
            DetectorEvent::Tick { at, .. } => {
                if let Some(since) = self.asked_at {
                    if at.duration_since(since) >= PATIENCE {
                        self.asked_at = None;
                        let ms = at.duration_since(since).as_millis() as u32;
                        return (self, smallvec![Distress::Silence { ms }], ());
                    }
                }
            }

            // Повтор в тишину и непонятое — часы не трогаем.
            _ => {}
        }
        (self, smallvec![], ())
    }
}

fn main() -> Report {
    engine(Nfqueue::queue(200))
        .from(Tcp)
        .extract(Sni)
        .detect(own(Impatient::default())) // СВОЙ автомат, не из парка — в ту же дверь
        // Копредел не спрашивает, чей автомат сказал слово: он сводит слова РАЗГОВОРОВ под ключ
        // цели, а откуда они взялись — из парка или отсюда — его не касается. Оси перпендикулярны:
        // свой прибор × слово о цели собирается так же, как парковый × слово о цели.
        .about(|words| {
            // Величина у слова о цели — МИНИМУМ по разговорам: столько цель молчит НАВЕРНЯКА.
            // Возьми максимум — и число говорило бы о самом невезучем потоке, а не о цели.
            let waited: Vec<u32> = words
                .iter()
                .map(|distress| match distress {
                    Distress::Silence { ms } => Some(*ms),
                    _ => None,
                })
                .collect::<Option<Vec<u32>>>()?; // хоть одно слово не о тишине — цель не молчит
            waited.into_iter().min().map(|ms| Distress::Silence { ms })
        })
        .on_target(|target, voiced| {
            if voiced.since < secs(1) {
                report!(
                    "свой прибор о ЦЕЛИ: {target} — {}",
                    voiced.distress.detail()
                )
            }
        })
        .on(|target, distress| {
            if let Distress::Silence { ms } = distress {
                report!("свой прибор поймал тишину: {target} молчит {ms}мс (порог 3с)")
            }
        })
        .run()
}
