//! conntrack как НОСИТЕЛЬ закона `EdgeView` (core). Вид ядра (`CtView`) — то, что приехало с
//! пакетом; база таймаута — конфигурация машины, прочитанная при старте (не приезжает от ядра на
//! каждом пакете). `idle = база − остаток` есть знание conntrack о себе, потому живёт здесь, где оба
//! слагаемых на руках, а не в приборе: иначе второй край (eBPF) считал бы иначе — два закона об
//! одной величине.

use std::fs;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use reflex_core::edge::EdgeView;

use super::wire::{CtTcp, CtView};

/// Имя sysctl-таймаута по состоянию TCP. `Other` файла не имеет — пусто (базы для него не читаем).
fn sysctl_name(state: CtTcp) -> &'static str {
    match state {
        CtTcp::SynSent => "nf_conntrack_tcp_timeout_syn_sent",
        CtTcp::SynRecv => "nf_conntrack_tcp_timeout_syn_recv",
        CtTcp::Established => "nf_conntrack_tcp_timeout_established",
        CtTcp::FinWait => "nf_conntrack_tcp_timeout_fin_wait",
        CtTcp::CloseWait => "nf_conntrack_tcp_timeout_close_wait",
        CtTcp::LastAck => "nf_conntrack_tcp_timeout_last_ack",
        CtTcp::TimeWait => "nf_conntrack_tcp_timeout_time_wait",
        CtTcp::Close => "nf_conntrack_tcp_timeout_close",
        CtTcp::Other(_) => "",
    }
}

/// База таймаута ядра для состояния — читается из sysctl при старте. Знание носителя о себе, потому
/// живёт здесь, рядом с `CtEdge`, а не в preflight («годится ли машина») и не в приборе.
pub fn tcp_timeout_base(state: CtTcp) -> Option<Duration> {
    let leaf = sysctl_name(state);
    if leaf.is_empty() {
        return None;
    }
    let secs: u64 = fs::read_to_string(format!("/proc/sys/net/netfilter/{leaf}"))
        .ok()?
        .trim()
        .parse()
        .ok()?;
    Some(Duration::from_secs(secs))
}

/// База таймаута ядра по состоянию TCP — sysctl `nf_conntrack_tcp_timeout_*`, снимается при старте.
/// Прочих состояний не держим: idle считаем там, где он осмыслен (ожидание ответа), — рукопожатие и
/// установленное соединение.
#[derive(Debug, Clone, Copy)]
pub struct TimeoutBase {
    pub syn_sent: Duration,
    pub established: Duration,
}

impl TimeoutBase {
    /// Снять базу из sysctl при старте. `None` — файлов нет (не Linux/нет conntrack); тогда idle
    /// не посчитать, и путь края честно об этом скажет, а не соврёт нулём.
    pub fn read() -> Option<TimeoutBase> {
        Some(TimeoutBase {
            syn_sent: tcp_timeout_base(CtTcp::SynSent)?,
            established: tcp_timeout_base(CtTcp::Established)?,
        })
    }

    fn for_state(&self, tcp: Option<CtTcp>) -> Option<Duration> {
        match tcp {
            Some(CtTcp::SynSent) => Some(self.syn_sent),
            Some(CtTcp::Established) => Some(self.established),
            _other => None,
        }
    }
}

/// Носитель `EdgeView`: вид ядра плюс база таймаута, которой виду не хватает для `idle`, плюс СНИМОК
/// возраста, снятый на приходе пакета. Возраст — поле, не запрос: часы дёргает `seen` (край/драйвер,
/// §9), а прибор их уже не видит (§2 — ни скрытых часов в шаге) и переигровка одной записи сходится
/// (§10). Собирается ТОЛЬКО через [`seen`] — литерала нет (поле `age` приватно), оттого второму
/// источнику времени взяться неоткуда.
///
/// [`seen`]: CtEdge::seen
///
/// `Copy` — вид края есть ЗНАЧЕНИЕ: снимок, замерший на приходе пакета. Копия его не «второй край»,
/// а то же наблюдение, поданное второму читателю; удерживать уникальность тут нечего.
#[derive(Debug, Clone, Copy)]
pub struct CtEdge {
    pub view: CtView,
    pub base: TimeoutBase,
    age: Option<Duration>,
}

impl CtEdge {
    /// Собрать вид на приходе пакета. ЕДИНСТВЕННОЕ место, где мир (часы) входит в систему для края:
    /// возраст = `сейчас − начало`, замирает величиной. Начало conntrack кладёт абсолютным
    /// (`ktime_get_real_ns`, наносекунды эпохи), потому свои часы берём из той же эпохи
    /// (`SystemTime`), а не из монотонного `Instant` буквы: его не вычесть из абсолютного начала.
    /// `None` — ядро без `timestamp` начала не дало, тогда возраста нет, и прибор честно не подтвердит
    /// по времени, а не соврёт нулём.
    pub fn seen(view: CtView, base: TimeoutBase) -> CtEdge {
        let age = view.started_at.and_then(|started| {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .ok()?
                .as_nanos() as u64;
            now.checked_sub(started).map(Duration::from_nanos)
        });
        CtEdge { view, base, age }
    }
}

impl EdgeView for CtEdge {
    fn down_packets(&self) -> Option<u64> {
        Some(self.view.down.packets)
    }

    fn up_packets(&self) -> Option<u64> {
        Some(self.view.up.packets)
    }

    fn down_bytes(&self) -> Option<u64> {
        Some(self.view.down.bytes)
    }

    fn up_bytes(&self) -> Option<u64> {
        Some(self.view.up.bytes)
    }

    /// `база(состояние) − остаток`. `None`, если состояние не из тех, чью базу держим, или ядро
    /// остатка не дало. Пересчёт — знание conntrack о себе, приборам его знать незачем.
    fn idle(&self) -> Option<Duration> {
        let base = self.base.for_state(self.view.tcp)?;
        let remaining = self.view.expires_in?;
        base.checked_sub(remaining)
    }

    /// Снимок возраста, снятый `seen` на приходе пакета — ПОЛЕ, не запрос часов: в шаге прибора
    /// часов нет (§2), переигровка сходится (§10).
    fn age(&self) -> Option<Duration> {
        self.age
    }

    fn mark(&self) -> u32 {
        self.view.mark
    }
}
