//! ЗАМКНУТЬ КОНТУР: то, что решено ВНЕ ПОЛОСЫ, входит буквой и читается на горячем пути.
//!
//! ```no_run
//! # #[cfg(feature = "telling")] fn main() -> reflex::Report {
//! use reflex::*;
//! use reflex::telling::Telling;
//!
//! // Область марки объявлена ЗАРАНЕЕ, а не выбрана на горячем пути (§ `core::mark`).
//! let leg = reflex_core::mark::Region::new(0x0000_0F00).expect("связная область");
//! let telling = Telling::over(leg);
//!
//! // Своя нить — своё расследование. Момент буквы ставит АВТОР, не цикл движка.
//! let posting = telling.clone();
//! std::thread::spawn(move || {
//!     assert!(posting.tell("example.com", 3), "три влезает в четыре бита");
//! });
//!
//! engine(Nfqueue::queue(200))
//!     .from(Tcp)
//!     .extract(Sni)
//!     .detect(Silence::after(secs(5)))
//!     .telling(telling)
//!     .on(|target, distress| report!("{target}: {distress}"))
//!     .run()
//! # }
//! # #[cfg(not(feature = "telling"))] fn main() {}
//! ```
//!
//! # Что здесь ЧЕРНОВОЕ, названо числом и словом
//!
//! Дверь стоит ЗА ФИЧЕЙ (`telling`) и каноном НЕ объявлена. Это третье состояние между «закон
//! утверждён» и «двери нет», и оно в этом дереве законно: так живёт чтение записи, так живёт
//! лестница проб у потребителя. Смысл третьего состояния — получить ЗАМЕР живого потребителя
//! раньше, чем форма станет законом: решать по числам дешевле и честнее, чем по эскизу, а если
//! форма неверна, узнается это на добровольце, а не на канонизированном API.
//!
//! Цена названа: **адресация по ЯРЛЫКУ цели**, а не по ключу (§4). Ярлык теряет тег
//! `Named`/`Unnamed`, и крафт-SNI, равный записи адреса, схлопнётся с безымянной целью того же
//! адреса. Это ровно та беда, ради которой ключ и заведён тегированным; здесь она названа, а не
//! спрятана, и снимается вместе с ответом хранителя на вопрос об адресном словаре.
//!
//! # Место на ленте — СЛЕДУЮЩИЙ СРЕЗ, и это названная дыра, а не забывчивость
//!
//! Значение, попавшее в горячий путь мимо ленты, есть СКРЫТЫЙ ВХОД, и §10 такого не прощает:
//! восьмой закон пере-подаёт ленту и сверяет сказанное, а чего в ленте нет, того он не
//! воспроизведёт. Порода буквы для этого уже есть (`TapeLetter::Answer` с ключом и моментом
//! автора), и дверь шва тоже (`Interleave::answered`) — не хватает ОДНОГО: адресного словаря.
//! Лента адресует РАЗГОВОР (`Whose { flow, target }`), а решение адресовано ЦЕЛИ, у которой
//! разговора может не быть вовсе — тот, по чьим показаниям решали, уже кончился.
//!
//! Пока словарь не расширен, решение живёт в карте цикла и на ленту НЕ ЛОЖИТСЯ. Следствие названо
//! точно: §10 сегодня сверяет сказанное машинами, а вердикт в сравнение не входит вовсе — значит
//! решение не делает закон слабее, чем он есть, но и под закон не попадает. Обе половины чинятся
//! одним заходом: адрес цели в ленте плюс вердикт в сверку.
//!
//! # Почему приборам он не достаётся
//!
//! Тоже не по бедности: цель, которая отвечает нашему контуру, пока провод молчит, — это и есть
//! тихий дроп, и он обязан выглядеть тихим. Отодвинь отклик тишину — дропнутый поток, чей контур
//! сказал «блок», выглядел бы НЕ-тихим, то есть ровно наоборот правде.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// РЕШЁННОЕ ЗНАЧЕНИЕ — реэкспорт рядом с [`Region`]: оно стоит исходом [`Told::decided`] и доводом
/// всякого, кто кладёт решение снаружи. Область фасад отдавал, значение в ней — нет; прочесть
/// положенное было нечем, не взяв `reflex-core`.
pub use reflex_core::mark::Marked;
pub use reflex_core::mark::Region;

/// Положенное снаружи: чья цель, что решено, когда. Момент ставит АВТОР — иначе лента соврала бы о
/// порядке, а расследование отвечает через секунды.
#[derive(Debug, Clone)]
pub struct Told {
    pub target: String,
    pub decided: Marked,
    pub at: Instant,
}

/// ИЗВЕСТНОЕ ЗАРАНЕЕ (#336): решение о семействе имён, которое наблюдение не перебивает.
///
/// Провод несёт не всё. Гео-заглушка лежит внутри TLS и по байтам неотличима от ответа, а банк,
/// увидевший чужую страну, ломается необратимо — ни то, ни другое прибор не различит вовремя.
#[derive(Debug, Clone)]
pub struct Known {
    suffixes: Vec<String>,
    value: u32,
}

/// Семейство имён, ещё не получившее решения.
#[derive(Debug, Clone)]
pub struct Suffixes(Vec<String>);

impl Known {
    /// Имя и все его поддомены: `gosuslugi.ru` покрывает `lk.gosuslugi.ru`, но не `notgosuslugi.ru`.
    pub fn suffixes<N: Into<String>>(names: impl IntoIterator<Item = N>) -> Suffixes {
        Suffixes(names.into_iter().map(Into::into).collect())
    }
}

impl Suffixes {
    pub fn marked(self, value: u32) -> Known {
        Known {
            suffixes: self.0,
            value,
        }
    }
}

/// Почему знание не принято.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unknowable {
    /// Значение не помещается в область ручки.
    Unheld(u32),
    /// Одно имя объявлено двумя знаниями — какое из них правда, решать не нам.
    Twice(String),
}

impl std::fmt::Display for Unknowable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Unknowable::Unheld(value) => write!(f, "знание {value:#x} не помещается в область"),
            Unknowable::Twice(name) => write!(f, "{name} объявлено двумя знаниями"),
        }
    }
}

impl std::error::Error for Unknowable {}

/// Решение со старшинством: знание, объявленное раньше, старше.
#[derive(Debug, Clone, Copy)]
struct Standing {
    rank: usize,
    decided: Marked,
}

type Families = HashMap<Box<str>, Standing>;

/// Самое длинное объявленное семейство, накрывающее имя.
fn standing_in(families: &Families, target: &str) -> Option<Standing> {
    std::iter::once(target)
        .chain(target.match_indices('.').map(|(at, _)| &target[at + 1..]))
        .find_map(|suffix| families.get(suffix).copied())
}

/// Буква в ящике цепочки.
#[derive(Debug, Clone)]
enum Posted {
    Told(Told),
    Bound(String, Standing),
}

/// РУЧКА, КОТОРОЙ КЛАДУТ БУКВУ. Копируется и уезжает в чужую нить: дверь обязана работать из
/// СВОЕГО цикла потребителя (`heard()`), а не только из нашего колбэка. Будь она доступна лишь из
/// реакции — состояние потребителя вернулось бы в замыкание под замок, и весь выигрыш показаний
/// значением пропал бы.
#[derive(Debug)]
pub struct Telling {
    /// Область марки, объявленная ЭТОЙ ручкой. Живёт у ручки, а не у значения, и это существенно:
    /// иначе цепочка узнала бы область только с первым положенным решением, то есть проверить
    /// непересечение с областью приборов было бы уже поздно — движок к тому времени работает.
    region: Region,
    /// ЯЩИК НА КАЖДОГО ЧИТАТЕЛЯ, А НЕ ОДНА ОЧЕРЕДЬ НА ВСЕХ.
    ///
    /// # Чем оплачено (живой стенд)
    ///
    /// Одна `VecDeque` на всех верна про ПИСАТЕЛЕЙ («ручек сколько угодно, дверь одна») и молчит
    /// про читателей: `drain` забирает её целиком, и потребитель, поднявший две цепочки над одним
    /// знанием (TCP и QUIC), получает решение в ту, чей оборот случился раньше. Второй не
    /// достаётся НИКОГДА.
    ///
    /// Видно это не как потеря, а как «лечение через раз»: марка решения доезжала до `SYN` в
    /// 8 случаях из 111 (счётчики ядра), потому что QUIC-нить крутится по тику и без трафика —
    /// и вычерпывала письма у TCP-цепочки, которой они были нужны.
    ///
    /// ЦЕНА НАЗВАНА: письмо, положенное ДО подписки цепочки, ей не достанется — ящика ещё нет.
    /// Для продукта это не потеря (цепочки поднимаются раньше, чем идёт первое расследование), но
    /// для потребителя, кладущего решение до запуска движка, — потеря, и молчаливая.
    boxes: Arc<Mutex<Vec<Arc<Mutex<VecDeque<Posted>>>>>>,
    /// Известное заранее. Объявляется при постройке ручки, до первой копии: копия, снятая раньше
    /// [`Telling::knowing`], объявленного после не увидит.
    families: Arc<Families>,
    /// Адреса, унаследовавшие известное своего имени.
    bound: Arc<Mutex<HashMap<String, Standing>>>,
}

impl Clone for Telling {
    /// Копия — та же очередь и та же область, а не вторая: ручек сколько угодно, дверь одна.
    fn clone(&self) -> Telling {
        Telling {
            region: self.region,
            boxes: Arc::clone(&self.boxes),
            families: Arc::clone(&self.families),
            bound: Arc::clone(&self.bound),
        }
    }
}

impl Telling {
    /// Ручка над ОБЪЯВЛЕННОЙ областью марки. `Default` нет намеренно: области по умолчанию не
    /// бывает — выбрать её за потребителя значило бы выбрать, чьи биты затирать.
    pub fn over(region: Region) -> Telling {
        Telling {
            region,
            boxes: Arc::new(Mutex::new(Vec::new())),
            families: Arc::new(Families::new()),
            bound: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Знать заранее. Порядок объявлений есть старшинство: адрес, общий двум семействам, следует
    /// объявленному первым.
    pub fn knowing(self, known: Known) -> Result<Telling, Unknowable> {
        let decided = self
            .region
            .holding(known.value)
            .ok_or(Unknowable::Unheld(known.value))?;
        let standing = Standing {
            rank: self
                .families
                .values()
                .map(|held| held.rank + 1)
                .max()
                .unwrap_or(0),
            decided,
        };
        match known
            .suffixes
            .iter()
            .find(|suffix| self.families.contains_key(suffix.as_str()))
        {
            Some(twice) => Err(Unknowable::Twice(twice.clone())),
            None => Ok(Telling {
                families: Arc::new(
                    self.families
                        .iter()
                        .map(|(suffix, held)| (suffix.clone(), *held))
                        .chain(
                            known
                                .suffixes
                                .into_iter()
                                .map(|suffix| (suffix.into_boxed_str(), standing)),
                        )
                        .collect(),
                ),
                ..self
            }),
        }
    }

    /// Что известно о цели заранее — по имени или по адресу, унаследовавшему имя.
    pub fn known(&self, target: &str) -> Option<u32> {
        self.standing(target)
            .map(|standing| Marked::read(&self.region, standing.decided.apply_to(0)))
    }

    /// Адрес из ответа на известное имя наследует его знание, и цепочки узнают об этом так же, как
    /// о сказанном. `None` — имя не известно, и адрес остаётся судиться наблюдением.
    pub fn bind(&self, address: impl Into<String>, name: &str) -> Option<u32> {
        let address = address.into();
        let offered = standing_in(&self.families, name)?;
        let kept = self.bound.lock().ok().map(|mut bound| {
            let kept = match bound.get(&address) {
                Some(held) if held.rank <= offered.rank => *held,
                _younger_or_none => offered,
            };
            bound.insert(address.clone(), kept);
            kept
        })?;
        self.post(Posted::Bound(address, kept));
        Some(Marked::read(&self.region, kept.decided.apply_to(0)))
    }

    fn standing(&self, target: &str) -> Option<Standing> {
        standing_in(&self.families, target).or_else(|| {
            self.bound
                .lock()
                .ok()
                .and_then(|bound| bound.get(target).copied())
        })
    }

    /// Чья область — цепочка спрашивает при постройке, чтобы проверить непересечение с приборами.
    pub fn region(&self) -> Region {
        self.region
    }

    /// Сказать движку решение о цели. `false` — решение НЕ положено: значение не влезло в
    /// объявленную область (обрезать молча значило бы превратить «ногу 5» в «ногу 1»), или о цели
    /// известно заранее, и наблюдение этого не перебивает.
    ///
    /// Ждать нечего и возврата ответа нет: машина НЕ ЖДЁТ (§1). Ждущая машина перестаёт быть
    /// машиной Мили — порядок букв стал бы зависеть от задержки, и переигровка сравнивала бы два
    /// разных входа. Ожидание живёт фазой у того, кто спрашивал.
    #[must_use = "`false` значит, что решение НЕ положено: не влезло в область или цель известна"]
    pub fn tell(&self, target: impl Into<String>, value: u32) -> bool {
        match self.region.holding(value) {
            None => false,
            Some(decided) => self.told(Told {
                target: target.into(),
                decided,
                at: Instant::now(),
            }),
        }
    }

    /// То же с ЯВНЫМ моментом — для того, кто знает, КОГДА узнал (проба вернулась в 21:03, а
    /// разобрали её в 21:07).
    #[must_use = "`false` значит, что о цели известно заранее и решение НЕ положено"]
    pub fn told(&self, told: Told) -> bool {
        match self.standing(&told.target) {
            Some(_known) => false,
            None => {
                self.post(Posted::Told(told));
                true
            }
        }
    }

    /// КОПИЯ В КАЖДЫЙ ЯЩИК. Решение адресовано ЦЕЛИ, а не цепочке: оно про то, как вести трафик,
    /// и цепочка, не узнавшая о нём, ведёт по-старому. Отдай его одному читателю — и лечение у
    /// остальных выглядит работающим через раз.
    fn post(&self, posted: Posted) {
        if let Ok(boxes) = self.boxes.lock() {
            boxes.iter().for_each(|mailbox| {
                if let Ok(mut queue) = mailbox.lock() {
                    queue.push_back(posted.clone());
                }
            });
        }
    }

    /// ПОДПИСКА ЧИТАТЕЛЯ — свой дом решений на цепочку, заводится при её постройке.
    ///
    /// Читателей столько, сколько цепочек, и каждая обязана узнать РЕШЕНИЕ ЦЕЛИКОМ: делить его
    /// между ними нечего — оно не работа, а знание.
    pub(crate) fn subscribe(&self) -> Home {
        let queue = Arc::new(Mutex::new(VecDeque::new()));
        if let Ok(mut boxes) = self.boxes.lock() {
            boxes.push(Arc::clone(&queue));
        }
        Home {
            mailbox: Mailbox { queue },
            families: Arc::clone(&self.families),
            bound: HashMap::new(),
            told: HashMap::new(),
        }
    }
}

/// ДОМ РЕШЕНИЙ ОДНОЙ ЦЕПОЧКИ. Читается вердиктом на каждом пакете, потому известное заранее
/// лежит здесь без замка, а привязанное к адресам приезжает буквой, как сказанное.
#[derive(Debug)]
pub(crate) struct Home {
    mailbox: Mailbox,
    families: Arc<Families>,
    bound: HashMap<String, Standing>,
    told: HashMap<String, Marked>,
}

impl Home {
    /// Забрать положенное с прошлого оборота.
    pub(crate) fn collect(&mut self) {
        self.mailbox
            .drain()
            .into_iter()
            .for_each(|posted| match posted {
                Posted::Bound(address, standing) => {
                    self.bound.insert(address, standing);
                }
                Posted::Told(told) => {
                    self.told.insert(told.target, told.decided);
                }
            });
    }

    /// Решение о цели: известное заранее старше сказанного.
    pub(crate) fn decided(&self, label: &str) -> Option<Marked> {
        standing_in(&self.families, label)
            .or_else(|| self.bound.get(label).copied())
            .map(|standing| standing.decided)
            .or_else(|| self.told.get(label).copied())
    }
}

/// ЯЩИК ОДНОЙ ЦЕПОЧКИ. Держит его ведущий цикл и вычерпывает раз в оборот — вычерпывает СВОЙ,
/// и потому сосед по знанию от этого ничего не теряет.
#[derive(Debug)]
struct Mailbox {
    queue: Arc<Mutex<VecDeque<Posted>>>,
}

impl Mailbox {
    /// Забрать положенное. Зовёт ведущий цикл раз в оборот; пусто — обычное дело.
    ///
    /// Отравленный замок не паникует, а отдаёт пустоту: чужая паника в чужой нити не повод ронять
    /// движок, наблюдающий провод. Потеря названа здесь, а не спрятана: положенное в отравленную
    /// очередь до цикла не доедет.
    fn drain(&self) -> Vec<Posted> {
        match self.queue.lock() {
            Err(_poisoned) => Vec::new(),
            Ok(mut queue) => queue.drain(..).collect(),
        }
    }
}
