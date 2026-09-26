//! НОСИТЕЛЬ ОЧЕРЕДИ ЯДРА — и единственное место фасада, знающее про Linux.
//!
//! Отдельный модуль, а не часть `lib.rs`, потому что это ПРОВЕРЯЕМАЯ граница: `grep reflex_linux
//! src/lib.rs` обязан давать ноль. Пока носитель жил в общем файле, ведущий цикл дотягивался до
//! `QueueSocket`, `Waited`, `CtEdge` и `RawSender` мимо всякого закона — и WinDivert в ту же дверь
//! не встал бы, сколько бы обобщений ни объявили выше.
//!
//! Наружу отсюда торчит ровно рецепт [`Nfqueue`]: что открыть и под какой раскладкой писать
//! состояние. Всё прочее — способности, которыми носитель отвечает удержанному пакету и вводит
//! свои пакеты в сеть.

use std::time::Duration;

use reflex_core::backend::Sink;
use reflex_core::capability::{
    CanHold, CanInject, CanMark, CanRefuse, CanRemember, CanRewrite, CanSever, Toward,
};
use reflex_core::command::InjectablePacket;
use reflex_core::held::{Answered, Delivered, Refused, Terminal};
use reflex_core::local::Local;
use reflex_core::serves::Served;
use reflex_core::Serves;
use reflex_instrument::edge::Layout;
use reflex_linux::conntrack::TimeoutBase;
/// СВЯЗАННЫЕ ТИПЫ НОСИТЕЛЯ НАРУЖУ — через [`crate::carrier`]: `Nfqueue` стоит на фасаде, и то,
/// чем названы его `Carrier` (`Local<QueueSocket>`) и `Answer`, стоит там же. Иначе потребитель,
/// взявшийся назвать тип открытого носителя, берёт `reflex-linux` второй зависимостью — и вместе с
/// ней теряет переносимость, которую фасад обещает всем, что НИЖЕ первой строки цепочки.
pub use reflex_linux::queue::{Answer, QueueSocket};
use reflex_linux::rawsend::RawSender;

use crate::{Cause, IntoCarrier};

/// Носитель — очередь netfilter. `engine(Nfqueue::queue(200))` открывает движок над ней.
pub struct Nfqueue {
    queue: u16,
    layout: Layout,
    /// Путь увода, который обязан быть предъявлен ядром до первого пакета: метка и нога.
    steer: Option<(u32, String)>,
    /// Куда писать провод, каким его видит движок. `None` — не писать.
    record: Option<crate::record::Record>,
}

/// Чем начинается отказ открыть носитель по непредъявленному пути — отличимо от отказа предпосылки
/// машины: лечения у них разные, и человек обязан узнать, какое из двух.
pub const UNSTEERABLE: &str = "путь увода: ";

/// Метка на инъекциях движка: ядро ставит её (SO_MARK) на впрыснутый RST, чтобы он не вернулся в
/// свою же очередь. Правило очереди обязано пропускать помеченное (`meta mark != INJECT_MARK`).
///
/// # ЧЕГО ЭТА МЕТКА НЕ ПОКРЫВАЕТ — И ЭТО НЕ ОГОВОРКА, А ГРАНИЦА
///
/// `meta mark` есть свойство пакета, который отправил ТОТ, КТО МЕТИТ. Наши инъекции её несут, куда
/// бы они ни пошли; пакет, пришедший из сети, не несёт её никогда — метить его было некому.
///
/// Отсюда: условие `meta mark != INJECT_MARK` защищает от возврата НАШЕГО впрыска и ничего не
/// говорит о чужом трафике на обратном пути. Всякий, кто строит на марке КОНТРОЛЬНУЮ пробу — «эти
/// пакеты мои, их наблюдать/лечить не надо», — покрывает ею ровно исходящую половину: на обратном
/// пути миновать нечем, потому что признака там нет.
///
/// Замер, которым это оплачено (поле, 19.09.2026): пока цель уводилась по адресу на исходящем
/// пути, с её адреса за двенадцать секунд пришло 24 пакета, и восемь из них — `RST`, которых цель
/// не посылала. Изменение действовало на одну сторону, беда приходила с другой, и контроль по
/// марке не миновал её ничем.
///
/// Состояние, которое ПЕРЕЖИВАЕТ направление, — это марка разговора (`ct mark`), а не пакета; она
/// и есть дом краевых приборов (§4, Утв. 4.4).
///
/// # МЕТКА ЖИВЁТ В ОБЪЯВЛЕННОЙ ОБЛАСТИ, а не занимает слово целиком
///
/// Было `0xBB` — младший байт, сравниваемый ЦЕЛЫМ СЛОВОМ. Оба свойства оказались дефектом, и
/// оплачен он не нами: на машине потребителя марку пишут трое, младший байт принадлежит чужому
/// решению о цели, и раздача этого самого значения как обычного увела бы чужой трафик из его же
/// цепочки — молча, на одном значении из двухсот пятидесяти трёх.
///
/// Теперь метка — значение в области [`reflex_core::mark::injecting`] (биты 30..31), и правило
/// ядра обязано сравнивать МАСКОЙ, а не словом:
///
/// ```text
/// meta mark and 0xc0000000 != 0x40000000 queue num 200
/// ```
///
/// Так чужие биты в марке перестают ломать признак, а пересечение с нашей же раскладкой приборов
/// проверяется при открытии носителя ([`Nfqueue::open`]) — отказом-значением, не памятью.
///
/// Равенство этой константы своей области держит сторож `inject_mark_lives_in_its_region`
/// (`reflex/tests/carrier.rs`): число здесь — копия, а копии расходятся молча.
pub const INJECT_MARK: u32 = 0x4000_0000;

impl Nfqueue {
    /// СЛУШАЕТ ЛИ КТО-НИБУДЬ ЭТУ ОЧЕРЕДЬ — со слов ЯДРА, а не того, кто запускал слушателя.
    ///
    /// Спрашивается о ЛЮБОЙ очереди, не только о своей: на очередь садится чужой процесс, а знать
    /// о нём нужно нам. Оттого функция, а не метод рецепта, — предмет принадлежит очередям ядра, а
    /// не нашему носителю.
    ///
    /// Три клетки, и средняя обитаема (§7): `Some(true)` — сокет привязан; `Some(false)` —
    /// привязанного нет; `None` — НЕ СМОТРЕЛИ, файла ядра нет (модуль не загружен, машина не та).
    /// Слить `None` с `Some(false)` значило бы объявлять всякого слушателя мёртвым на машине без
    /// модуля, то есть выдавать дефект наблюдателя за свойство мира (Утв. 7.2).
    ///
    /// # Чем оплачено (поле, 15.09.2026)
    ///
    /// Сторонний процесс, которому отдана очередь, умер при старте на всех машинах, а наблюдатель
    /// сутки докладывал об успехе: свидетельством считался успешный `spawn`, то есть ОБЪЯВЛЯЮЩИЙ.
    /// Ядро знало правду всё это время — строка очереди есть ровно тогда, когда к ней привязан
    /// сокет.
    ///
    /// # Чего эта дверь НЕ говорит
    ///
    /// * КТО слушает. Привязан ли ожидаемый процесс или чужой сосед, севший на тот же номер, —
    ///   отсюда не видно (та же беда стоила нам пустого лога стенда: на очереди сидел недобитый
    ///   движок предыдущего прогона). Ответ «слушают» не есть ответ «слушает твой».
    /// * НАДОЛГО ЛИ. Ответ устаревает в тот же миг: между вопросом и делом слушатель успевает уйти.
    ///   Это свидетельство МОМЕНТА, а не состояния.
    ///
    /// Чего дверь, наоборот, НЕ ВРЁТ — проверено прогоном (19.09.2026, пара «до/после» на двух
    /// концах): строка ядра слушателя не переживает. И при штатном закрытии сокета, и при
    /// `SIGKILL` стороннего процесса она уходит синхронно — двухсот миллисекунд хватило. То есть
    /// `Some(true)` не остаётся висеть от мёртвого слушателя, и свидетельство подъёма берётся
    /// РАЗНОСТЬЮ: `Some(false)` до запуска обязателен, `Some(true)` после — и только тогда.
    pub fn listened(queue: u16) -> Option<bool> {
        reflex_linux::queue::listened(queue)
    }

    /// Очередь netfilter с этим номером. Правило (`queue num N`) ставится снаружи — движок правил
    /// не ставит: кто поставил, тот и снимает.
    pub fn queue(num: u16) -> Nfqueue {
        Nfqueue {
            queue: num,
            layout: Layout::preset(),
            steer: None,
            record: None,
        }
    }

    /// Та же очередь, и КАЖДЫЙ её пакет пишется в запись ([`crate::record`]) — ровно таким, каким
    /// его получил движок, до решения. Прогон этой записи (`pcap(путь)`) есть тот же движок на том
    /// же входе, без машины.
    ///
    /// Запись не условие работы: не открылся файл — очередь живёт, отказ печатается по имени.
    pub fn recording(self, record: crate::record::Record) -> Nfqueue {
        Nfqueue {
            record: Some(record),
            ..self
        }
    }

    /// Та же очередь, но движок НЕ ПОДНИМЕТСЯ, пока ядро не покажет путь увода меткой `mark` в ногу
    /// `device` ([`reflex_linux::route::witness`]): помеченный TCP и UDP уходят в ногу, свои адреса
    /// машины остаются машине. Правила ставятся снаружи, как и `queue num N`; здесь они
    /// свидетельствуются.
    ///
    /// Гейт на подъёме, а не на акте: путь — свойство мира, а не входа, и узнать о нём можно лишь
    /// читая мир. Цена молчаливого пропуска оплачена 13.09.2026 — QUIC без увода при докладе об
    /// успехе и машина, отрезанная собственной меткой.
    pub fn steering(self, mark: u32, device: &str) -> Nfqueue {
        Nfqueue {
            steer: Some((mark, device.to_string())),
            ..self
        }
    }

    /// Какие биты марки НАШИ и чем подписан их писатель. Умолчание живёт в общем доме
    /// (`reflex_instrument::edge::Layout::preset`), а не здесь: те же 15 бит и тот же тег берёт
    /// носитель WinDivert, и вторая копия чисел разошлась бы с первой молча — вместе с нею
    /// разошлись бы и два носителя, перестав быть сравнимыми. Нужно тому, кто делит машину с другим
    /// агентом: чужие биты вне маски переживают наш шаг (read-modify-write), а тег отличает нашу
    /// запись от чужой — по нему движок и узнаёт соседа (`Distress::Diverged`) вместо того, чтобы
    /// принять его слово за своё.
    ///
    /// `None` — маска не 15-битная либо тег нулевой: раскладка непредставима, и цепочка её не
    /// получит (предпосылку проверяет [`Layout::new`], а не отладочная проверка, исчезающая в
    /// release).
    pub fn marking(self, mask: u32, tag: u8) -> Option<Nfqueue> {
        Layout::new(mask, tag).map(|layout| Nfqueue { layout, ..self })
    }

    /// Та же очередь, но БЕЗ ядерного дома: край и дом строит [`Local`] сам, в юзерспейсе, а не
    /// `conntrack`/`ct_mark`. Второй свидетель закона `EdgeView` на Linux — не костыль для теста,
    /// а законный носитель для машины без `nf_conntrack_acct`, на которой [`Nfqueue::queue`] не
    /// поднимается вовсе (`TimeoutBase::read()` отдаёт `None`).
    pub fn local(num: u16) -> LocalNfqueue {
        LocalNfqueue {
            queue: num,
            layout: Layout::preset(),
        }
    }
}

/// Рецепт местного носителя: та же очередь netfilter(`queue num N` ставится снаружи, как и у
/// [`Nfqueue::queue`]), но `open` строит [`Local<QueueSocket>`] и НЕ читает базу таймаутов
/// conntrack — местный край и дом не зависят от ядерного учёта, потому и предпосылки у него нет.
pub struct LocalNfqueue {
    queue: u16,
    layout: Layout,
}

impl IntoCarrier for LocalNfqueue {
    type Carrier = Local<QueueSocket>;

    /// `TimeoutBase::read()` здесь НЕ ЗВУЧИТ — это и есть отличие от [`Nfqueue::open`], ради
    /// которого носитель заведён: на машине без `nf_conntrack_acct` он остаётся `None`, и
    /// ядерный носитель не откроется вовсе, а местному эта величина не нужна ни для чего своего.
    ///
    /// `QueueSocket::open` всё равно просит `TimeoutBase` — ТИПОМ, не смыслом: сокет строит из неё
    /// `CtEdge` на пакетах, у которых пришёл вид ядра (`NFQA_CT`), но `Local::serve` этот
    /// `Option<C::Edge>` принимает и ОТБРАСЫВАЕТ (докблок `impl Serves for Local` в `local.rs`) —
    /// отдаёт `decide` СВОЙ `LocalEdge`. Читать sysctl ради величины, которую тут же выбросят, было
    /// бы вторым, никому не нужным замером — потому подставлен ноль, а не итог `::read()`.
    fn open(self) -> Result<Local<QueueSocket>, Cause> {
        // Предпосылка машины — ДО сокета: иначе отсутствующий модуль ядра доедет до потребителя
        // голым `errno`, а он о `nfnetlink_queue` не знает и знать не обязан.
        //
        // СОСТАВ ТРЕБОВАНИЙ — СВОЙ: права и модуль, без conntrack. Прежде здесь стояла общая
        // предпосылка, требовавшая `nf_conntrack_acct`, — то есть носитель, заведённый РОВНО для
        // машины без учёта, на ней и не поднимался, а докблок выше уверял, что «предпосылки у него
        // нет». Нашлось прогоном у потребителя 19.09.2026; законы состава — в `preflight`.
        reflex_linux::nfqueue::preflight::check_for(
            reflex_linux::nfqueue::preflight::Demands::Socket,
        )
        .map_err(|why| Cause(why.to_string()))?;
        let discarded_by_local = TimeoutBase {
            syn_sent: Duration::ZERO,
            established: Duration::ZERO,
        };
        let socket = QueueSocket::open(self.queue, discarded_by_local)
            .map_err(|why| Cause(format!("{why:?}")))?;
        Ok(Local::new(socket))
    }

    fn layout(&self) -> Layout {
        self.layout
    }

    /// Отличимо от [`Nfqueue::queue`] по имени — тот же номер очереди годится и ядерному, и
    /// местному носителю, и отчёт об отказе обязан сказать, КАКОЙ из двух не поднялся.
    fn name(&self) -> String {
        format!("очередь {} (местный край)", self.queue)
    }
}

/// Открытый носитель очереди: сокет очереди И сокет инъекции — оба поднимает [`Nfqueue::open`]
/// (через [`IntoCarrier`]), а не ведущий цикл. Сырой сокет живёт здесь ВСЕГДА, даже у цепочки,
/// которая инжектить не станет (`.on`, не `.act`): ленивое открытие на первом эффекте меняло бы
/// быстрый отказ на старте (`Report::not_started`) на отказ посреди боя — лишний сокет дешевле
/// потерянного отказа.
pub struct NfqueueCarrier {
    socket: QueueSocket,
    sender: RawSender,
    recorder: Option<crate::record::Recorder>,
}

/// Носитель отвечает удержанному тем же терминалом, что и голый `QueueSocket` — делегированием, не
/// второй реализацией: второй закон об одном и том же ответе разошёлся бы с первым молча.
impl Terminal for NfqueueCarrier {
    type Carrier = <QueueSocket as Terminal>::Carrier;
    type Answer = <QueueSocket as Terminal>::Answer;
    type Refusal = <QueueSocket as Terminal>::Refusal;

    fn apply(
        &mut self,
        answered: Answered<Self::Carrier, Self::Answer>,
    ) -> Result<Delivered<Self::Answer>, Refused<Self::Answer, Self::Refusal>> {
        self.socket.apply(answered)
    }
}

/// `Serves`ит тем же швом, что и голый сокет. `exhausted` не переопределяется: ядро конца не
/// обещает, и умолчание трейта — это и есть ответ очереди.
impl Serves for NfqueueCarrier {
    /// Тот же край, что и у голого сокета — тем же словом ОДИН на предмет (см. докблок `impl`).
    type Edge = <QueueSocket as Serves>::Edge;

    fn serve<F>(
        &mut self,
        until: std::time::Instant,
        decide: F,
    ) -> Served<Delivered<Self::Answer>, Refused<Self::Answer, Self::Refusal>>
    where
        F: FnOnce(&reflex_core::held::Held<Self::Carrier>, Option<Self::Edge>) -> Self::Answer,
    {
        // Пишется ДО решения: пакет, на котором цепочка упала бы, в записи обязан остаться.
        let recorder = &self.recorder;
        self.socket.serve(until, move |held, edge| {
            recorder
                .iter()
                .for_each(|recorder| recorder.note(held.seen()));
            decide(held, edge)
        })
    }
}

/// Способности носителя — те же слова, что у сокета очереди, и по той же причине: слово ОДНО на
/// предмет. Пересказать их здесь своими константами значило бы завести вторую таблицу ответов,
/// расходящуюся с первой при зелёной сборке.
impl CanHold for NfqueueCarrier {
    fn release() -> Answer {
        <QueueSocket as CanHold>::release()
    }
}

impl CanRemember for NfqueueCarrier {
    fn remember(state: u32, accept: bool) -> Answer {
        <QueueSocket as CanRemember>::remember(state, accept)
    }
}

/// УДЕРЖАТЬ — тем же сокетом: знак и вердикт по нему живут у очереди (#348).
impl reflex_core::capability::CanDefer for NfqueueCarrier {
    type Token = <QueueSocket as reflex_core::capability::CanDefer>::Token;

    fn deferred(carrier: &Self::Carrier) -> Option<(Self::Token, Answer)> {
        <QueueSocket as reflex_core::capability::CanDefer>::deferred(carrier)
    }

    fn settle(
        &mut self,
        token: Self::Token,
        answer: Answer,
        at: std::time::Instant,
    ) -> Result<Delivered<Answer>, Refused<Answer, Self::Refusal>> {
        self.socket.settle(token, answer, at)
    }
}

/// МЕТИТЬ ПАКЕТ и ПЕРЕПИСАТЬ ПАКЕТ — те же слова, что у сокета, тем же делегированием.
///
/// Способность, которую держит сокет и не предъявляет носитель фасада, недостижима ровно так же,
/// как несуществующая: гейт §9.1 сторожит доступ к тому, чего в цепочке нет. Потому делегирование
/// здесь обязано быть полным — потеряться при нём легче всего именно молча.
///
/// Слова НЕ перепутаны, и это стоит сказать здесь, где они стоят рядом: `mark` кладёт метку на
/// ПАКЕТ (`NFQA_MARK`, читают правила маршрутизации, разговора не переживает), `remember` выше —
/// состояние в conntrack(переживает пакет, читается следующим). Первая приказывает, вторая помнит.
impl CanMark for NfqueueCarrier {
    fn mark(mark: u32) -> Answer {
        <QueueSocket as CanMark>::mark(mark)
    }
}

impl CanRewrite for NfqueueCarrier {
    fn rewrite(bytes: Vec<u8>) -> Answer {
        <QueueSocket as CanRewrite>::rewrite(bytes)
    }
}

/// Отказ — предпосылка обрыва (`CanSever: CanRefuse`): сказать «разговора не будет» вправе тот, кто
/// умеет не пропустить.
impl CanRefuse for NfqueueCarrier {
    fn refuse() -> Answer {
        <QueueSocket as CanRefuse>::refuse()
    }
}

impl CanSever for NfqueueCarrier {
    fn notice(seen: &[u8], toward: Toward) -> Option<InjectablePacket> {
        <QueueSocket as CanSever>::notice(seen, toward)
    }
}

/// Ввод пакета в сеть — СЫРЫМ сокетом носителя, не очередью: очередь отвечает удержанному, а
/// инъекция создаёт новый кадр. Оттого сток и терминал у носителя разные двери, а носитель один.
impl Sink for NfqueueCarrier {
    type Command = InjectablePacket;
    type Error = std::io::Error;

    fn emit(&mut self, command: InjectablePacket) -> Result<(), std::io::Error> {
        self.sender.send(&command.serialize_ip())
    }
}

impl CanInject for NfqueueCarrier {
    fn inject(packet: InjectablePacket) -> InjectablePacket {
        packet
    }
}

impl IntoCarrier for Nfqueue {
    type Carrier = NfqueueCarrier;

    /// База таймаутов conntrack — предпосылка КРАЯ, и её читает РОВНО одно место: здесь.
    /// Обобщённый цикл знать о ней не может — предпосылка носителя есть дело носителя, а в цикле
    /// она была бы абсурдна (WinDivert про conntrack не слышал). Сырой сокет инъекции поднимается
    /// следом, тоже здесь и тоже безусловно (см. докблок [`NfqueueCarrier`]).
    fn open(self) -> Result<NfqueueCarrier, Cause> {
        // ЗАЯВКИ НА МАРКУ ЗДЕСЬ НЕ ПРОВЕРЯЮТСЯ, и это не пропуск: носитель их ОБЪЯВЛЯЕТ
        // (`IntoCarrier::claims`), а сверяет цепочка — там, где рядом лежат ещё раскладка приборов
        // и область внеполосных решений. Проверь мы здесь свою пару, закон разошёлся бы надвое, и
        // каждая половина знала бы только то, что видит: ровно так три пары из шести и оставались
        // незакрытыми до 20.09.2026.
        //
        // Все заявки очереди суть заявки на марку ПАКЕТА — в одном слове, и сравнивать их законно
        // (`core::mark`, «область без слова — половина высказывания»): память прибора едет в
        // вердикте обоими полями, `CtMark` и `SkbMark`, потому что на урезанном netfilter прямой
        // записи `ct mark` нет. Сторож: `remembering_reaches_the_verdict`.
        // Путь — ПРЕЖДЕ предпосылки машины: не поднятая очередь не стоит ничего, а увод по
        // непоказанному пути стоит самой машины.
        self.steer
            .as_ref()
            .map(|(mark, device)| reflex_linux::route::witness(*mark, device))
            .transpose()
            .map_err(|why| Cause(format!("{UNSTEERABLE}{why}")))?;
        reflex_linux::nfqueue::preflight::check().map_err(|why| Cause(why.to_string()))?;
        let base = TimeoutBase::read().ok_or_else(|| {
            Cause(
                "нет базы таймаутов conntrack: включи nf_conntrack_acct и nf_conntrack_timestamp"
                    .to_string(),
            )
        })?;
        let socket =
            QueueSocket::open(self.queue, base).map_err(|why| Cause(format!("{why:?}")))?;
        let sender =
            RawSender::open(INJECT_MARK).map_err(|why| Cause(format!("сокет инъекции: {why}")))?;
        Ok(NfqueueCarrier {
            socket,
            sender,
            recorder: self.record.map(crate::record::Recorder::start),
        })
    }

    fn layout(&self) -> Layout {
        self.layout
    }

    /// ОЧЕРЕДЬ ЗАНИМАЕТ В МАРКЕ ДВОЕ, и оба обязаны быть названы цепочке, а не проверены здесь
    /// вполголоса: область метки своих инъекций (`core::mark::injecting`) и — если увод заказан —
    /// СЛОВО метки увода, которое ядро сверяет целиком.
    ///
    /// Метка увода приходит числом от потребителя и областью не выражается: правило ставит её на
    /// пакет полностью, а какие биты в ней значимы, знает лишь тот, кто это правило писал. Оттого
    /// она и заявляется словом — проверка у слова своя («ни один взведённый бит не лежит в чужой
    /// области»), и без неё запись памятки прибора могла бы САМА поднять биты увода, отправив
    /// разговор в чужую ногу.
    fn claims(&self) -> smallvec::SmallVec<[reflex_core::mark::Claim; 2]> {
        let mut said: smallvec::SmallVec<[reflex_core::mark::Claim; 2]> = smallvec::SmallVec::new();
        said.push(reflex_core::mark::Claim::Region {
            region: reflex_core::mark::injecting(),
            what: "область метки впрыска",
        });
        if let Some((mark, _device)) = self.steer.as_ref() {
            said.push(reflex_core::mark::Claim::Word {
                value: *mark,
                what: "метка увода",
            });
        }
        said
    }

    fn name(&self) -> String {
        format!("очередь {}", self.queue)
    }
}
