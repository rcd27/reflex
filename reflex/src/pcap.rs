//! ЗАПИСАННЫЙ ПРОВОД КАК НОСИТЕЛЬ. Третий дом движка рядом с очередью ядра и `Local`-краем.
//!
//! ```no_run
//! use reflex::*;
//!
//! fn main() -> Report {
//!     pcap("capture.pcap")
//!         .from(Tcp)
//!         .extract(Sni)
//!         .detect(Retransmit::unanswered())
//!         .detect(Silence::after(secs(5)))
//!         .on(|target, distress| report!("{target}: {distress:?}"))
//!         .run()
//! }
//! ```
//!
//! # Почему файл — носитель, а не «режим тестирования»
//!
//! Носитель по §9 есть функтор из машины в мир, и мир бывает разный: очередь ядра держит пакет и
//! ждёт вердикта, файл не держит ничего. Разница не в том, что файл «понарошку», а в том, каких
//! СПОСОБНОСТЕЙ у него нет — и это говорит ТИП, а не докблок: `CanSever`/`CanInject` здесь не
//! реализованы, поэтому `.act(…)` с записанным проводом **не соберётся**. Записи не разорвать
//! соединение, и компилятор скажет это раньше запуска (§9.1).
//!
//! Это не проза, а проверка: доктест ниже обязан НЕ СОБРАТЬСЯ. Обрыв записанного разговора —
//! бессмыслица, и говорит об этом компилятор, а не человек в комментарии.
//!
//! ```compile_fail,E0277
//! use reflex::*;
//!
//! pcap("capture.pcap")
//!     .from(Tcp)
//!     .extract(Sni)
//!     .detect(Silence::after(secs(5)))
//!     .act(|_target, _distress| Act::sever())
//!     .run();
//! ```
//!
//! # Время
//!
//! Время идёт ИЗ ФАЙЛА (§8: время — буква входа). `core::pcap::read` кладёт моменты записи на
//! основание вызывающего, сохраняя интервалы; шов (`Interleave`) плетёт узлы сетки по ним же.
//! Отсюда два следствия, оба нужные: окно тишины в пять секунд проходит мгновенно (прогон не ждёт
//! реального времени), и один и тот же файл даёт один и тот же ответ — вход детерминирован
//! целиком, чего живой провод не обещает никогда.
//!
//! # Край
//!
//! Conntrack у файла нет, и выдумывать его нельзя. Край строит [`Local`] — тот же декоратор, что
//! заведён для носителей без ядерного дома: счёт кадров по разговору и дом состояния в своей
//! карте вместо `ct_mark`. Приборы края (`Silence`, `SynDrop`) работают, потому что читают закон
//! `EdgeView`, а не conntrack.

use std::path::{Path, PathBuf};

use reflex_core::capability::{CanHold, CanRefuse};
use reflex_core::held::{Answered, Delivered, Held, Refused, Terminal};
use reflex_core::local::Local;
use reflex_core::pcap::Frame;
use reflex_core::serves::{Served, Serves};
use reflex_instrument::edge::Layout;

use crate::{engine, Cause, Engine, IntoCarrier};

/// Рецепт носителя: путь к записи. Открывается в [`IntoCarrier::open`], как и очередь.
pub struct Recording {
    path: PathBuf,
    layout: Layout,
}

impl Recording {
    /// Рецепт по пути. Ровня `Nfqueue::queue(200)`: рецепт, а не открытый носитель, — файла может
    /// не быть, и это обязано стать [`crate::Report`], а не паникой на первой строке цепочки.
    pub fn at(path: impl AsRef<Path>) -> Recording {
        Recording {
            path: path.as_ref().to_path_buf(),
            // Раскладка марки — общая с очередью (`Layout::preset`), а не своя: кодек памятки один,
            // и прибор, поверенный на записи, обязан читать свою фазу тем же способом, что в бою.
            layout: Layout::preset(),
        }
    }

    /// Делить марку с соседом по машине записи незачем — но раскладка задаётся здесь, если запись
    /// снята на машине, где биты уже поделены, и прибор поверяется ПРОТИВ той же раскладки.
    pub fn marking(mut self, layout: Layout) -> Recording {
        self.layout = layout;
        self
    }
}

/// Записанный провод как голова цепочки: `pcap("файл").from(Tcp)…`.
///
/// Дверь отдаёт УЖЕ ОТКРЫТЫЙ движок, а не рецепт, — и это не сахар, а признание частого случая:
/// у записи нет предпосылок, которые стоило бы настраивать между рецептом и движком (очередь
/// выбирает номер, раскладку, местный край — файл не выбирает ничего). Кому раскладка всё же
/// нужна, тот пишет полную форму `engine(Recording::at(путь).marking(…))`; закон у обеих дверей
/// один, вторая — сокращение первой, а не второй способ открыть носитель.
pub fn pcap(path: impl AsRef<Path>) -> Engine<Recording> {
    engine(Recording::at(path))
}

/// Открытая запись: кадры и курсор. Состояния сверх курсора нет — файл не отвечает миру, и
/// хранить ему нечего.
pub struct PcapFile {
    frames: Vec<Frame>,
    next: usize,
}

/// Файлу нечем отказать: вердикт никуда не едет, отказать некому.
#[derive(Debug)]
pub enum Never {}

/// Край, который НИЧЕГО НЕ ЗНАЕТ. Не пустышка ради типа: `Serves` требует, чтобы край был
/// `EdgeView`, а у записи его нет — и честный ответ на всякий вопрос о ней «не считали» (`None`),
/// а не «ноль». Разница ровно та, что §7 держит клеткой незнания: ноль байт вниз значил бы, что
/// цель молчала, тогда как правда — что счётчика нет вовсе.
///
/// Настоящий край поверх строит [`Local`], считая кадры сам; этот отбрасывается декоратором и до
/// приборов не доходит.
#[derive(Debug, Clone, Copy)]
pub struct NoEdge;

impl reflex_core::edge::EdgeView for NoEdge {
    fn down_packets(&self) -> Option<u64> {
        None
    }
    fn down_bytes(&self) -> Option<u64> {
        None
    }
    fn up_packets(&self) -> Option<u64> {
        None
    }
    fn up_bytes(&self) -> Option<u64> {
        None
    }
    fn idle(&self) -> Option<std::time::Duration> {
        None
    }
    fn age(&self) -> Option<std::time::Duration> {
        None
    }
    /// Марки у записи нет. Ноль здесь — не «чистая марка», а единственное представимое «нечего
    /// читать»: дом состояния держит `Local` в своей карте, и эта величина до него не доезжает.
    fn mark(&self) -> u32 {
        0
    }
}

impl Terminal for PcapFile {
    /// Держим голые байты кадра: `Observed for Vec<u8>` уже есть в фундаменте, и заводить свой тип
    /// значило бы завести второй закон о том же (§ «один предмет — один закон»).
    type Carrier = Vec<u8>;
    /// Ответить записи нечем — и это не пустая заглушка, а ПРЕДМЕТ: у носителя без права ответа
    /// слово вердикта пусто по построению, а не по забывчивости.
    type Answer = ();
    type Refusal = Never;

    fn apply(
        &mut self,
        answered: Answered<Vec<u8>, ()>,
    ) -> Result<Delivered<()>, Refused<(), Never>> {
        // Отказать нельзя: некому. Потому `Ok` здесь тотален, и это видно типом `Never`.
        Ok(Delivered {
            at: answered.at,
            answer: answered.answer,
        })
    }
}

impl CanHold for PcapFile {
    fn release() {}
}

impl CanRefuse for PcapFile {
    fn refuse() {}
}

impl Serves for PcapFile {
    /// Своего края у файла нет — его даст `Local` поверх. Не `CtEdge`: conntrack тут неоткуда
    /// взять, а подделывать источник, которого нет, нельзя.
    type Edge = NoEdge;

    /// Срок здесь не при чём, и это не нарушение закона шва, а его вырожденный случай: закон
    /// требует «не возвращаться раньше `until`, КРОМЕ КАК С РАБОТОЙ», а у записи работа есть
    /// всегда, пока файл не кончился. Ждать нечего — время едет из кадров, а не от часов.
    fn serve<F>(&mut self, _until: std::time::Instant, decide: F) -> Served<Delivered<()>, Refused<(), Never>>
    where
        F: FnOnce(&Held<Vec<u8>>, Option<NoEdge>) -> (),
    {
        match self.frames.get(self.next) {
            Some(frame) => {
                // `network`, а не `bytes`: разбор провода ждёт IP-заголовок первым байтом, а в
                // записи перед ним лежит канальный слой. Снимает его `core::pcap` — там известен
                // род слоя, здесь нет.
                let held = Held::new(frame.network().to_vec(), frame.at);
                self.next += 1;
                let answer = decide(&held, None);
                Served::Answered(self.apply(held.answered(answer)))
            }
            // Файл кончился. `Blind`, а не `Idle`: «работы не было» значило бы, что она ещё может
            // появиться, — а из записи не появится никогда (§7, «не смотрели» ≠ «смотрели и пусто»).
            None => Served::Blind,
        }
    }

    fn exhausted(&self) -> bool {
        self.next >= self.frames.len()
    }
}

impl IntoCarrier for Recording {
    type Carrier = Local<PcapFile>;

    fn open(self) -> Result<Local<PcapFile>, Cause> {
        let data = std::fs::read(&self.path)
            .map_err(|why| Cause(format!("запись не прочитана ({}): {why}", self.path.display())))?;
        // Основание — «сейчас»: абсолютного времени записи приборам не нужно, им нужны ИНТЕРВАЛЫ
        // (окно тишины, возраст разговора), а их `read` сохраняет.
        let (frames, broken) = reflex_core::pcap::read(&data, std::time::Instant::now());
        match (frames.is_empty(), broken) {
            // Пустой файл — не ошибка чтения, но и не наблюдение: сказать о нём нечего, и цикл
            // выйдет сразу. Причина названа, чтобы «ничего не найдено» не читалось как «чисто».
            (true, why) => Err(Cause(format!(
                "в записи нет кадров ({}){}",
                self.path.display(),
                match why {
                    Some(broken) => format!(": {broken:?}"),
                    None => String::new(),
                }
            ))),
            // Оборванный хвост — не повод молчать о прочитанном: то, что до обрыва, наблюдение
            // настоящее. Урон назван в отчёте, а не спрятан.
            (false, Some(broken)) => {
                crate::report!("запись оборвана, читаю до обрыва: {broken:?}");
                Ok(Local::new(PcapFile { frames, next: 0 }))
            }
            (false, None) => Ok(Local::new(PcapFile { frames, next: 0 })),
        }
    }

    fn layout(&self) -> Layout {
        self.layout
    }

    fn name(&self) -> String {
        self.path.display().to_string()
    }
}
