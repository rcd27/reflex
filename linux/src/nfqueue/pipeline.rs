use reflex_core::command::InjectablePacket;
use reflex_core::Serves;
use reflex_core::Tap;

use super::backend::NfqueueBackend;
use super::preflight;
use super::terminal::Answer;
use crate::rawsend::RawSender;

/// ПАКЕТ ИЗ ОЧЕРЕДИ, ЖДУЩИЙ ВЕРДИКТА.
///
/// # Байты ЗАИМСТВОВАНЫ, а не скопированы (05.09.2026)
///
/// Прежде здесь стоял `Vec<u8>`, и путь пакета копировал полезную нагрузку ТРИЖДЫ: `to_vec()` при
/// чтении, `clone()` при сборке этой структуры и ещё раз в свидетеле потока. Три аллокации на
/// каждый пакет при цене впуска 3,88 мкс — и ни одна из копий не пережила бы обработчик.
///
/// Байты принадлежат сообщению ядра, пока оно живо, а живо оно до самого вердикта. Обработчику
/// довольно заимствования: разобрать, решить, вернуть решение значением.
pub struct NfqPacket<'a> {
    /// Raw IP packet bytes (no ethernet header).
    pub payload: &'a [u8],
    /// Firewall mark from iptables.
    pub fwmark: u32,
}

/// Типизированный исход шага пайпа (Rule 17): что пайп сделал с одним пакетом.
/// Бизнес-агностик — вердикт + число инжектов, без знания домена. Эмитится в `Tap`;
/// слушатель (rx-конец) — забота потребителя (наблюдаемость в пайпе, не в бизнес-логике).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NfqStep {
    pub fwmark: u32,
    pub verdict: NfqVerdictKind,
    pub injects: usize,
}

/// Лёгкая Copy-метка слова носителя для показаний [`Tap`] — без тяжёлого payload `Modified`.
/// `Marked` не сливается с `Accept`: наблюдение за пайпом обязано различать «пометили» и
/// «пропустили» (канон §6.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NfqVerdictKind {
    Accept,
    Drop,
    Modify,
    Marked,
}

/// Сколько ждать на дескрипторе, прежде чем вернуть управление циклу для проверки его условия.
const POLL_MILLIS: i32 = 100;

/// СЧЁТЧИКИ ЖИВОГО ПАЙПА. Читаются НА ХОДУ, а не после выхода: `recv()` на пустой очереди
/// блокируется, то есть цикл может не завершиться никогда, и посмертный отчёт не приходит.
#[derive(Debug, Default)]
pub struct NfqShared {
    pub received: std::sync::atomic::AtomicU64,
    pub mark_skipped: std::sync::atomic::AtomicU64,
    pub handed: std::sync::atomic::AtomicU64,
    pub again: std::sync::atomic::AtomicU64,
    pub failed: std::sync::atomic::AtomicU64,
    pub blind: std::sync::atomic::AtomicU64,
    /// ОТВЕТОВ, КОТОРЫХ ЯДРО НЕ ПРИНЯЛО.
    ///
    /// Прежде этой величины не существовало, потому что и знания не было: отказ выбрасывался через
    /// `let _ = queue.verdict(msg)` во всех четырёх вердиктах. «Мы ответили» было неотличимо от
    /// «ответ не доехал», и разговор, чьё решение ядро отвергло, выглядел решённым.
    pub not_taken: std::sync::atomic::AtomicU64,
}

impl NfqShared {
    pub fn snapshot(&self) -> NfqCounts {
        use std::sync::atomic::Ordering;
        NfqCounts {
            received: self.received.load(Ordering::Relaxed),
            mark_skipped: self.mark_skipped.load(Ordering::Relaxed),
            handed: self.handed.load(Ordering::Relaxed),
            again: self.again.load(Ordering::Relaxed),
            failed: self.failed.load(Ordering::Relaxed),
            blind: self.blind.load(Ordering::Relaxed),
            not_taken: self.not_taken.load(Ordering::Relaxed),
        }
    }
}

/// ЧТО ПАЙП СДЕЛАЛ С ПОТОКОМ — величина, а не тишина.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NfqCounts {
    /// Сообщений принято от ядра.
    pub received: u64,
    /// Из них замкнуто по собственной метке — обработчик НЕ звали.
    pub mark_skipped: u64,
    /// Из них отдано обработчику.
    pub handed: u64,
    /// Пустых чтений (`EAGAIN`).
    pub again: u64,
    /// Чтений, кончившихся ошибкой.
    pub failed: u64,
    /// Ожиданий вслепую — дескриптор очереди добыть не удалось.
    pub blind: u64,
    /// ОТВЕТОВ, ОТВЕРГНУТЫХ ЯДРОМ. Факт о МИРЕ: мы решили, а решение не доехало.
    pub not_taken: u64,
}

/// Generic handler: receives packet, returns verdict + inject list.
pub trait NfqHandler {
    fn handle(&mut self, packet: &NfqPacket<'_>) -> (Answer, Vec<InjectablePacket>);
}

/// NFQUEUE verdict loop.
///
/// Owns queue + raw sender. Firewall rules managed externally by FirewallGuard.
///
/// - `bind()`: preflight checks -> open queue + raw sender
/// - `run_while()`: verdict loop
pub struct NfqPipeline<H> {
    nfq: NfqueueBackend,
    sender: RawSender,
    handler: H,
    our_fwmark: u32,
    counts: std::sync::Arc<NfqShared>,
    tap: Option<Tap<NfqStep>>,
}

impl<H: NfqHandler> NfqPipeline<H> {
    /// Bind NFQUEUE — no firewall rules.
    /// Use with FirewallGuard which manages rules separately.
    pub fn bind(queue_num: u16, fwmark: u32, handler: H) -> Result<Self, String> {
        preflight::check().map_err(|e| format!("preflight failed: {e}"))?;

        let nfq = NfqueueBackend::open(queue_num)?;
        let sender = RawSender::open(fwmark).map_err(|e| format!("RawSender::open: {e}"))?;

        Ok(Self {
            nfq,
            sender,
            handler,
            our_fwmark: fwmark,
            counts: std::sync::Arc::new(NfqShared::default()),
            tap: None,
        })
    }

    /// Повесить слушатель на пайп: каждый обработанный пакет эмитит `NfqStep`.
    /// Функтор наблюдаемости — non-blocking (drop-on-full), пайп не тормозит.
    pub fn with_tap(mut self, tap: Tap<NfqStep>) -> Self {
        self.tap = Some(tap);
        self
    }

    /// СКОЛЬКО ПАКЕТОВ КУДА ДЕЛОСЬ (#287). Прежде пайп молчал о двух своих законных путях мимо
    /// обработчика — короткое замыкание по метке и `EAGAIN`. «Обработчик не звали» и «пакета не
    /// было» давали один выход, то есть тот самый прибор, чей «ничего не нашёл» неотличим от
    /// «не запускался». Замер стенда: 29 идентификаторов у ядра против 17 вызовов обработчика.
    pub fn counts(&self) -> NfqCounts {
        self.counts.snapshot()
    }

    /// Ручка на счётчики, годная для чтения из СОСЕДНЕГО потока, пока цикл крутится.
    pub fn counts_handle(&self) -> std::sync::Arc<NfqShared> {
        self.counts.clone()
    }

    pub fn step(&mut self) -> Result<bool, String> {
        // ЖДЁМ НА ДЕСКРИПТОРЕ, А НЕ КРУТИМ ЦИКЛ. `Blind` — ждать не на чем, и тогда лучше уснуть
        // на миллисекунду, чем жечь ядро: это не оптимизация, а условие пригодности замера цены.
        match self.nfq.wait(POLL_MILLIS) {
            crate::nfqueue::Waited::Ready => (),
            crate::nfqueue::Waited::Idle => {
                self.counts
                    .again
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                return Ok(false);
            }
            crate::nfqueue::Waited::Blind => {
                self.counts
                    .blind
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                std::thread::sleep(std::time::Duration::from_millis(1));
                return Ok(false);
            }
        }

        // ВЗЯТЬ И ОТВЕТИТЬ — ОДИН ШАГ (`Serves`). Прежде здесь стояли `recv()` и, двадцатью
        // строками ниже, `apply()`: между ними лежал весь разбор, и «взял, но не ответил» было
        // ошибкой, которую ловил только `#[must_use]` на решении — то есть предупреждением.
        // Теперь носитель наружу не выходит вовсе, и держать его негде.
        //
        // Поля разбираются НА ЧАСТИ намеренно: `serve` заимствует очередь, а решению нужны
        // обработчик, отправитель и счётчики. Заимствуй мы `self` целиком, компилятор был бы прав,
        // запретив это.
        let Self {
            nfq,
            handler,
            sender,
            counts,
            tap,
            our_fwmark,
            ..
        } = self;
        let ours = *our_fwmark;

        let outcome = nfq.serve(|held| {
            counts
                .received
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let mark = held.carrier().0.get_nfmark();

            match mark == ours {
                // КОРОТКОЕ ЗАМЫКАНИЕ ПО МЕТКЕ: пакет наш собственный, обработчику его не носим.
                true => {
                    counts
                        .mark_skipped
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    Answer::Pass
                }
                false => {
                    counts
                        .handed
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                    // БАЙТЫ ЗАИМСТВУЮТСЯ У СООБЩЕНИЯ, и живёт заимствование ровно до вердикта —
                    // сообщение всё это время наше.
                    //
                    // TODO(#326): убрать оставшуюся копию в `NfqHandler` — он вправе читать байты
                    // заимствованием, но это правка его потребителей, а не пайпа.
                    let nfq_packet = NfqPacket {
                        payload: held.seen(),
                        fwmark: mark,
                    };

                    let (verdict, injects) = handler.handle(&nfq_packet);

                    for injectable in &injects {
                        let ip_bytes = injectable.serialize_ip();
                        if let Err(e) = sender.send(&ip_bytes) {
                            tracing::warn!("RawSender inject failed: {e}");
                        }
                    }

                    if let Some(tap) = tap {
                        let kind = match &verdict {
                            Answer::Pass => NfqVerdictKind::Accept,
                            Answer::Stop => NfqVerdictKind::Drop,
                            Answer::Modified(_) => NfqVerdictKind::Modify,
                            Answer::Marked(_) => NfqVerdictKind::Marked,
                        };
                        tap.emit(NfqStep {
                            fwmark: mark,
                            verdict: kind,
                            injects: injects.len(),
                        });
                    }

                    verdict
                }
            }
        });

        // ИСХОДЫ РАЗЛИЧАЮТСЯ ВСЕ ЧЕТЫРЕ. `Idle` здесь — это `EAGAIN` при готовом дескрипторе:
        // работы не было. Слить его с отказом ядра значило бы вернуть беду #287, ради которой
        // счётчики и заводились.
        match outcome {
            reflex_core::serves::Served::Idle => {
                self.counts
                    .again
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                Ok(false)
            }
            reflex_core::serves::Served::Blind => {
                self.counts
                    .blind
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                Ok(false)
            }
            reflex_core::serves::Served::Answered(Ok(_delivered)) => Ok(true),
            // ОТКАЗ ЯДРА — ВЕЛИЧИНА, А НЕ ЗАПИСЬ В ЖУРНАЛ. Разговор, чьё решение ядро отвергло,
            // прежде выглядел решённым, и отличить его было нечем.
            reflex_core::serves::Served::Answered(Err(refused)) => {
                self.counts
                    .not_taken
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                tracing::warn!("nfqueue verdict not taken: {:?}", refused.why);
                Ok(true)
            }
        }
    }

    pub fn run_while(&mut self, alive: impl Fn() -> bool) -> Result<(), String> {
        while alive() {
            match self.step() {
                Ok(true) => {}
                Ok(false) => std::thread::sleep(std::time::Duration::from_micros(100)),
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
}
