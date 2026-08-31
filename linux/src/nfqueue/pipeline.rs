use reflex_core::command::InjectablePacket;
use reflex_core::Tap;

use super::backend::NfqueueBackend;
use super::preflight;
use crate::rawsend::RawSender;

/// Packet from NFQUEUE with pending verdict.
pub struct NfqPacket {
    /// Raw IP packet bytes (no ethernet header).
    pub payload: Vec<u8>,
    /// Firewall mark from iptables.
    pub fwmark: u32,
}

/// What to do with the original packet.
pub enum NfqVerdict {
    Accept,
    Drop,
    Modify(Vec<u8>),
    /// ПРОПУСТИТЬ, ПОСТАВИВ МЕТКУ (#317). Решение о пакете принимается ТАМ, ГДЕ ЕСТЬ ЗНАНИЕ —
    /// в обработчике, на том самом пакете, — и уезжает в ядро вместе с вердиктом.
    ///
    /// Прежде такого вердикта не было, и метку приходилось ставить правилом ядра ПО АДРЕСУ, до
    /// очереди: то есть решать раньше, чем узнаешь, кто цель. Живой прогон 31.08 это опроверг
    /// числом — «пакетов ногой 0» при исправной петле, потому что цель ответила с другого адреса.
    AcceptMarked(u32),
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NfqVerdictKind {
    Accept,
    Drop,
    Modify,
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
}

/// Generic handler: receives packet, returns verdict + inject list.
pub trait NfqHandler {
    fn handle(&mut self, packet: &NfqPacket) -> (NfqVerdict, Vec<InjectablePacket>);
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

        let msg = match self.nfq.recv() {
            Ok(msg) => msg,
            Err(e) => {
                if e.contains("EAGAIN") || e.contains("Resource temporarily unavailable") {
                    self.counts
                        .again
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    return Ok(false);
                }
                self.counts
                    .failed
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                return Err(e);
            }
        };
        self.counts
            .received
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let mark = msg.get_nfmark();
        let payload = msg.get_payload().to_vec();

        if mark == self.our_fwmark {
            self.counts
                .mark_skipped
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.nfq.accept(msg);
            return Ok(true);
        }
        self.counts
            .handed
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let nfq_packet = NfqPacket {
            payload: payload.clone(),
            fwmark: mark,
        };

        let (verdict, injects) = self.handler.handle(&nfq_packet);

        for injectable in &injects {
            let ip_bytes = injectable.serialize_ip();
            if let Err(e) = self.sender.send(&ip_bytes) {
                tracing::warn!("RawSender inject failed: {e}");
            }
        }

        if let Some(tap) = &self.tap {
            let kind = match verdict {
                NfqVerdict::Accept | NfqVerdict::AcceptMarked(_) => NfqVerdictKind::Accept,
                NfqVerdict::Drop => NfqVerdictKind::Drop,
                NfqVerdict::Modify(_) => NfqVerdictKind::Modify,
            };
            tap.emit(NfqStep {
                fwmark: mark,
                verdict: kind,
                injects: injects.len(),
            });
        }

        match verdict {
            NfqVerdict::Accept => self.nfq.accept(msg),
            NfqVerdict::Drop => self.nfq.drop_packet(msg),
            NfqVerdict::Modify(new_payload) => self.nfq.modify(msg, &new_payload),
            NfqVerdict::AcceptMarked(mark) => self.nfq.accept_marked(msg, mark),
        }

        Ok(true)
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
