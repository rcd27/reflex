//! Очередь ядра как терминальный морфизм — единственное место, где решение становится эффектом
//! (канон §9). Прежде вердикт был ВЫЗОВОМ в четырёх местах (`msg.set_verdict(…); let _ =
//! self.queue.verdict(msg);`): вызов нельзя записать, сравнить, развернуть, а `let _ =` выбрасывал
//! единственный факт о доставке (ядро отказывает, например по таймауту очереди). Здесь решение
//! отделено от эффекта: цепочка порождает [`Answered`](reflex_core::held::Answered), мира касается
//! ровно [`Terminal::apply`], отказ становится [`Refused`](reflex_core::held::Refused). `&mut`
//! остаётся (netlink-сокет один, отправка последовательна по природе), но стоит В ОДНОМ месте: выше
//! значения, ниже мир.

use nfq::Verdict;
use reflex_core::capability::Toward;
use reflex_core::command::InjectablePacket;
use reflex_core::held::{Answered, Delivered, Observed, Refused, Terminal};

use super::backend::NfqueueBackend;

/// Сообщение очереди как носитель права ответить. Ньютайп, а не `impl` на `nfq::Message`: правило
/// сирот (`Observed` наш, `Message` чужой) — обёртка и есть место, где мы говорим, ЧЕМ для нас
/// является чужой тип. `#[repr(transparent)]` — изоляция бесплатна (раскладка та же). Байты живут
/// здесь, пока живо сообщение: разбор читает заимствованием, дело помнит улику, полная запись — в
/// сырье независимого прибора.
#[repr(transparent)]
pub struct Queued(pub nfq::Message);

impl Observed for Queued {
    fn payload(&self) -> &[u8] {
        self.0.get_payload()
    }
}

/// Чем можно ответить очереди — её собственный алфавит, не общий на все носители. Ровно четыре
/// слова, сколько умеет очередь; пятый молча не завести — он потребует ветки в [`Terminal::apply`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer {
    /// Пропустить как есть.
    Pass,
    /// Пропустить, поставив метку. Пакет продолжает обход с места, где его забрали: правило,
    /// читающее метку, обязано стоять НИЖЕ правила очереди — поставь выше, метка встанет и не будет
    /// прочитана, а прибор покажет «решение принято».
    Marked(u32),
    /// Не пропускать.
    Stop,
    /// Пропустить с подменёнными байтами.
    Modified(Vec<u8>),
}

/// Почему ядро не приняло ответ. Отдельный тип, не строка: у отказа есть причина от ОС — терять её
/// значило бы возвращаться к `let _ =`.
#[derive(Debug)]
pub struct NotTaken(pub std::io::Error);

impl Terminal for NfqueueBackend {
    type Carrier = Queued;
    type Answer = Answer;
    type Refusal = NotTaken;

    fn apply(
        &mut self,
        answered: Answered<Queued, Answer>,
    ) -> Result<Delivered<Answer>, Refused<Answer, NotTaken>> {
        let Answered {
            carrier: Queued(mut carrier),
            at,
            answer,
        } = answered;

        match &answer {
            Answer::Pass => carrier.set_verdict(Verdict::Accept),
            Answer::Marked(mark) => {
                carrier.set_nfmark(*mark);
                carrier.set_verdict(Verdict::Accept);
            }
            Answer::Stop => carrier.set_verdict(Verdict::Drop),
            // Единственная копия во всём пути, и копирует она не наблюдение, а РЕШЕНИЕ.
            // Наблюдённые байты не копируются (читаются заимствованием, полная запись — в сырье
            // независимого прибора); подменённые байты наши, отдай мы их ядру по владению —
            // `Delivered` перестал бы говорить, ЧЕМ ответили. Платит одна редкая ветвь из четырёх.
            Answer::Modified(bytes) => {
                carrier.set_payload(bytes.clone());
                carrier.set_verdict(Verdict::Accept);
            }
        }

        // Единственное место, где случается мир — и единственное, где его отказ ловится.
        match self.send_verdict(carrier) {
            Ok(()) => Ok(Delivered { at, answer }),
            Err(why) => Err(Refused {
                at,
                answer,
                why: NotTaken(why),
            }),
        }
    }
}

// Заявления очереди — четыре на четыре слова алфавита, покрытие полное (#326). До этого
// `NfqueueBackend` не заявлял ни одной способности, а продукт работает на нём — оба
// сертифицированных закона проверяли неиспользуемые бэкенды. `Marked` было отложено (метка не видна
// на проводе), свидетель нашёлся — правило-счётчик НИЖЕ очереди; закон `certify::marks` ловит им
// читателя выше правила очереди.

impl reflex_core::CanHold for NfqueueBackend {
    fn release() -> Answer {
        Answer::Pass
    }
}

impl reflex_core::CanRefuse for NfqueueBackend {
    fn refuse() -> Answer {
        Answer::Stop
    }
}

impl reflex_core::CanRewrite for NfqueueBackend {
    fn rewrite(bytes: Vec<u8>) -> Answer {
        Answer::Modified(bytes)
    }
}

/// Обрыв — пара, и теперь он один предмет (#326). Сборка `RST` жила в продукте, определение обрыва
/// существовало трижды (полностью в бою, наполовину в примере движка, никак во втором бинаре) —
/// дороже всех дроп без извещения (ровно то, чем бьёт молчаливый дроп на пути). Два случая, не один:
/// прежде `seq` брался из `ack` удержанного пакета всегда — верно для пакета ОТ клиента (серверный
/// `seq` есть подтверждённое клиентом), неверно для пакета ОТ ЦЕЛИ (извещение от её имени несёт `seq
/// + длину`); клиент отбрасывает `RST` не в окно молча, при зелёном вердикте. Различие видно, лишь
/// когда стороны названы типом ([`Toward`]). Номера обязаны быть верны: `RST` вне окна получатель
/// молча отбрасывает (RFC 5961) — оттого извещение предмет ЗАКОНА, изнутри процесса «сказали» и
/// «услышали» неразличимы. Человек: ядро извещённой стороны закрывает сокет немедленно
/// (`ECONNRESET`) вместо таймаута. Законность обрыва решает домен (`pipe::still_carries`), не здесь.
impl reflex_core::CanSever for NfqueueBackend {
    fn notice(seen: &[u8], toward: Toward) -> Option<InjectablePacket> {
        // Таблица живёт в ядре (`core::notice`): предмет её — протокол, а не очередь, и второй
        // носитель взял бы копию, а копии расходятся молча.
        reflex_core::notice::rst_for(seen, toward)
    }
}

/// Четвёртое слово обрело предмет (#326): оставалось без способности (метку не видно на проводе),
/// свидетель нашёлся — правило-счётчик НИЖЕ очереди, тот читатель, ради которого метка ставится.
impl reflex_core::CanMark for NfqueueBackend {
    fn mark(mark: u32) -> Answer {
        Answer::Marked(mark)
    }
}

/// Очередь вошла в категорию — не как `Source`, а как [`Serves`](reflex_core::serves::Serves)
/// (#326). `Source::packets(&mut self)` держит бэкенд заимствованным, пока жив поток, а ответ
/// требует второго `&mut` (`E0499`). Природа: у `AfPacketBackend` два устройства (`split()` их
/// разводит), у очереди netlink-сокет один; `Source` описывает НАБЛЮДЕНИЕ (копий сколько угодно),
/// очередь отдаёт ВЛАДЕНИЕ. `serve` берёт и отвечает неделимо — «взял и забыл ответить» непредставимо.
impl reflex_core::Serves for NfqueueBackend {
    fn serve<F>(
        &mut self,
        decide: F,
    ) -> reflex_core::serves::Served<Delivered<Answer>, Refused<Answer, NotTaken>>
    where
        F: FnOnce(&reflex_core::held::Held<Queued>) -> Answer,
    {
        use reflex_core::serves::Served;
        // Не ждём здесь: ожидание — это часы, а у бэкенда их нет (сколько крутиться на пустой
        // очереди, знает ведущий цикл). `wait` остаётся отдельным и добровольным.
        match self.wait(0) {
            super::Waited::Blind => Served::Blind,
            super::Waited::Idle => Served::Idle,
            super::Waited::Ready => match self.recv() {
                // Пусто при готовом дескрипторе — `EAGAIN`: работы не было, ждать есть на чем.
                Err(_nothing) => Served::Idle,
                Ok(message) => {
                    let held =
                        reflex_core::held::Held::new(Queued(message), std::time::Instant::now());
                    let answer = decide(&held);
                    Served::Answered(self.apply(held.answered(answer)))
                }
            },
        }
    }
}
