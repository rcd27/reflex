//! Приборы на величинах КРАЯ, без собственного состояния. Прибор о носителе не знает — читает
//! `EdgeView` (conntrack, карта eBPF, чужая ОС) и марку под своей `Layout`. Собственное `S`
//! вырождено: исход зависит от края и марки, не от прожитого (§ спеки — состояние в ядре).
//!
//! ## Сигнал ПАКЕТНЫЙ, порог — по ВОЗРАСТУ (оба оплачены прогоном)
//!
//! Счётчики БАЙТ conntrack считают полный кадр (L3+L4+нагрузка), не нагрузку: у молчащей цели
//! `up.bytes ≈ 60` — её `SYN+ACK` с заголовками, не ноль. Оттого тишину меряем ПАКЕТАМИ ответной
//! стороны:
//! * `up.packets == 0` → `Blackhole` — `SYN+ACK` не пришёл, соединения не было;
//! * `up.packets == 1` → `NoBytes` — цель прислала ТОЛЬКО `SYN+ACK` и смолкла (тихий дроп ВЫШЕ
//!   сервера: тот `ClientHello` не видел);
//! * `up.packets >= 2` → цель ЖИВА на сетевом уровне (прислала хоть `ACK`) → `Released`.
//!
//! Но КОГДА подтверждать — вопрос времени, не счёта наблюдений. Замер (netns, сервер с ~80 мс RTT
//! отвечает полным `ServerHello`) показал: два наблюдения подряд умещаются в burst рукопожатия —
//! `SYN+ACK` и `ClientHello` уходят встык, ДО ответа, и `up.packets` там ещё `1`. Подтверждать по
//! «второму пакету» — значит кричать дропом на всяком живом сервере, чей ответ отстаёт на RTT. Порог
//! честен только по ВОЗРАСТУ потока (`age`): цель молчит с открытия дольше `after` — вот тогда
//! `NoBytes`/`Blackhole`. Возраст монотонен (не `idle`, что освежается повтором клиента); окно `after`
//! шире обычного RTT, но у́же клиентского терпения — на живом дропе клиент повторяет запрос, и к его
//! повтору возраст перешагивает порог, а живая цель к этому времени давно прислала бы пакет.
//!
//! Байты нужны лишь для «клиент вообще отдал запрос»: `down.bytes > down.packets × HDR + FLOOR` —
//! сверх заголовков не меньше `FLOOR`. Лишние `ACK` добавляют по `HDR` в обе части, порога не двигают.
//!
//! ## Предел назван, а не обойдён втихую
//!
//! Если устройство меж клиентом и целью ПОДТВЕРЖДАЕТ `ClientHello` от имени сервера, а данные глотает
//! (ТСПУ так умеет), `up.packets` уходит за двойку — и по счётчикам conntrack это неотличимо от живого
//! `ACK`. Такой дроп прибор ПРОПУСТИТ (`Released`). Это предел НОСИТЕЛЯ, не закона: глубже счётчиков
//! conntrack не видит; другой край (eBPF с разбором флагов TCP) увидел бы. Ловим дроп ВЫШЕ
//! подтверждающего устройства (`up.packets` замер на 1). Оттиск памятки — снимок `up.packets` на
//! момент записи — существует РАДИ этого предела: даёт трассе увидеть, растёт ли счётчик ответных
//! пакетов (спуфер) или стоит (чистый дроп). В решении он не участвует — порог держит возраст.
//!
//! ## `Released` — ТЕРМИНАЛ, не круг
//!
//! Ожила цель — `Released`, обратно в подозрение поток не возвращается. Круг потребовал бы сторожить
//! рост `down` вторым оттиском, а в 15 битах марки места ему нет. ПРОПУСКАЕМЫЙ случай назван прямо:
//! «ответила на первый запрос, замолчала на втором» (keep-alive) этот прибор не ловит — и не должен.
//! Это не тишина, а ПОВТОР: работа прибора повтора (`Retransmit`). Один случай, размазанный по двум
//! приборам, был бы хуже отданного тому, чья это буква.

use std::marker::PhantomData;
use std::time::Duration;

use reflex_core::edge::EdgeView;
use reflex_core::mealy::Mealy;
use reflex_core::DetectorEvent;
use smallvec::{smallvec, SmallVec};

use crate::distress::Distress;
use crate::edge::{Layout, Memo, Phase, Recall};
use crate::edge_word::Edged;
use crate::wire::Seen;

/// Потолок ОБЫЧНОГО заголовка IPv4+TCP на пакет. С опциями бывает до 80 — если стенд покажет
/// пограничные случаи, поднимать сюда, но именно как потолок заголовка, не как множитель среднего.
const HDR: u64 = 60;
/// Сколько байт СВЕРХ заголовков считаем реальным запросом. `ClientHello`/HTTP-запрос перекрывают.
const FLOOR: u64 = 100;

/// Что прибор оставляет на пакете: памятку в марку (фазу — `None`, если писать нечего: тик без края
/// или чужой писатель, чьи биты не трогаем) и находки (пусто на переходе без беды).
pub type Verdict = (Option<Memo>, SmallVec<[Distress; 2]>);

/// Тишина по ПАКЕТНЫМ величинам края с порогом по ВОЗРАСТУ, через прогрессию фаз
/// (Quiet→Suspected→Confirmed|Released). Фазу и оттиск читает/пишет через марку — состояния в
/// юзерспейсе не держит. Закон, роль возраста, терминальность `Released` и предел — в докблоке модуля.
pub struct EdgeSilence<V> {
    /// Возраст потока, после которого молчание цели считаем дропом. Шире RTT, у́же терпения клиента.
    after: Duration,
    layout: Layout,
    edge: PhantomData<fn() -> V>,
}

// Copy/Clone без `V`-бонда: носитель в фантоме, экземпляр от `V` не зависит.
impl<V> Clone for EdgeSilence<V> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<V> Copy for EdgeSilence<V> {}

/// Оттиск — младшие 8 бит счётчика ответных ПАКЕТОВ на момент записи. РАДИ трассы предела (растёт ли
/// счётчик = спуфер, или стоит = чистый дроп), в решении не участвует. `None` (край не считает) → 0.
fn imprint_of(up: Option<u64>) -> u8 {
    (up.unwrap_or(0) & 0xFF) as u8
}

/// Отдал ли клиент что-то сверх заголовков. Отдельной функцией, а не выражением в ветке: это
/// ЗАКОН о величинах края, и его проверяют таблицей, а не прогоном автомата целиком.
pub(crate) fn asked_for_something<E: EdgeView>(edge: &E) -> bool {
    match (edge.down_bytes(), edge.down_packets()) {
        (Some(bytes), Some(packets)) => bytes > packets.saturating_mul(HDR) + FLOOR,
        _ => false,
    }
}

impl<V: EdgeView> EdgeSilence<V> {
    pub fn new(after: Duration, layout: Layout) -> EdgeSilence<V> {
        EdgeSilence {
            after,
            layout,
            edge: PhantomData,
        }
    }

    /// Памятка: фаза и оттиск ставятся ОДНИМ конструктором — разнести (записать фазу, не обновив
    /// снимок счётчика) нельзя.
    fn memo(&self, phase: Phase, up: Option<u64>) -> Memo {
        Memo::new(self.layout, phase, imprint_of(up))
    }
}

impl<V: EdgeView> Mealy for EdgeSilence<V> {
    /// Край приезжает `Option`: пакет, которого ядро ещё не завело в conntrack (первый `SYN` вне
    /// таблицы), вида не имеет. Это ТРЕТЬЕ значение рядом с «ноль» и «много» (§7): «не считали» —
    /// не «не ответила». Прими прибор непустой `V` — петля роняла бы такие пакеты молча, и разница
    /// между незнанием и наблюдением исчезла бы ещё до прибора.
    type In = DetectorEvent<Edged<Option<Seen>, Option<V>>>;
    type Out = Verdict;
    type Log = ();

    fn step(self, event: Self::In) -> (Self, Self::Out, ()) {
        // Прибор края работает по букве `Packet`: тик марки прочесть не может (ct-вид едет с пакетом).
        let edge = match &event {
            DetectorEvent::Packet { input, .. } => &input.edge,
            // Дыра — потеря НАШЕЙ очереди (ENOBUFS у NFQUEUE), а решение прибор берёт из
            // conntrack — счётчик пакетов и возраст ведёт ЯДРО независимо от того, дошёл ли пакет
            // до нас. Дыра здесь ничего не портит и не прячет: считать нечего, потому что считает
            // не прибор.
            DetectorEvent::Tick { .. }
            | DetectorEvent::Opaque { .. }
            | DetectorEvent::Torn { .. } => {
                return (self, (None, SmallVec::new()), ());
            }
        };
        // Края нет — судить не о чем, и памятки нет: писать в марку по незнанию значило бы
        // выдумать фазу разговора, которого край ещё не видит.
        let Some(edge) = edge else {
            return (self, (None, SmallVec::new()), ());
        };

        // Чужой писатель (тег не наш, слово непустое) — находка, а не тишина. Его биты НЕ трогаем
        // (памятка `None`): у соседа своя маска, затирать её нам нечем.
        let phase = match self.layout.read(edge.mark()) {
            Recall::Foreign { theirs } if theirs != 0 => {
                return (self, (None, smallvec![Distress::Diverged { theirs }]), ());
            }
            Recall::Foreign { .. } => Phase::Quiet, // theirs == 0 — нетронутый поток
            Recall::Ours(memo) => memo.phase,
        };

        let up_pk = edge.up_packets();

        // Жива ли цель (пакетом сверх `SYN+ACK`), состоялось ли рукопожатие, заговорил ли клиент, и
        // перешагнул ли ВОЗРАСТ порог. Возраст — единственные честные часы «сколько молчит с открытия».
        let target_alive = matches!(up_pk, Some(pk) if pk >= 2);
        let only_synack = up_pk == Some(1);
        let no_synack = up_pk == Some(0);
        let client_spoke = asked_for_something(edge);
        let overdue = matches!(edge.age(), Some(age) if age >= self.after);

        let out: Verdict = match phase {
            // Уже сказали — молчим, фазу не трогаем (лежит в марке).
            Phase::Confirmed | Phase::Released => (None, SmallVec::new()),

            // Первое наблюдение. Есть что сторожить — под подозрение, БЕЗ жалобы (порог держит возраст).
            Phase::Quiet => {
                if target_alive || !((client_spoke && only_synack) || no_synack) {
                    (None, SmallVec::new())
                } else {
                    (Some(self.memo(Phase::Suspected, up_pk)), SmallVec::new())
                }
            }

            // Под подозрением: цель ожила — отпускаем; возраст перешагнул порог при молчании — беда;
            // иначе ждём (возраст ещё мал — живой сервер успеет ответить).
            Phase::Suspected => {
                if target_alive {
                    (Some(self.memo(Phase::Released, up_pk)), SmallVec::new())
                } else if overdue && no_synack {
                    let after_ms = edge.age().map_or(0, |age| age.as_millis() as u32);
                    (
                        Some(self.memo(Phase::Confirmed, up_pk)),
                        smallvec![Distress::Blackhole { after_ms }],
                    )
                } else if overdue && only_synack && client_spoke {
                    (
                        Some(self.memo(Phase::Confirmed, up_pk)),
                        smallvec![Distress::NoBytes],
                    )
                } else {
                    (Some(self.memo(Phase::Suspected, up_pk)), SmallVec::new())
                }
            }
        };
        (self, out, ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Край, у которого известны только эти две величины: остальное — «не считали» (§7).
    struct Frames { packets: u64, bytes: u64 }

    impl EdgeView for Frames {
        fn down_packets(&self) -> Option<u64> { Some(self.packets) }
        fn down_bytes(&self) -> Option<u64> { Some(self.bytes) }
        fn up_packets(&self) -> Option<u64> { None }
        fn up_bytes(&self) -> Option<u64> { None }
        fn idle(&self) -> Option<Duration> { None }
        fn age(&self) -> Option<Duration> { None }
        fn mark(&self) -> u32 { 0 }
    }

    /// Порог «клиент отдал запрос» считает КАДРЫ, и это контракт, а не совпадение с conntrack.
    /// Считай край нагрузку — порог завысился бы на заголовок каждого пакета, и запрос перестал
    /// бы наблюдаться. Мера: conntrack нагрузки не знает и знать не может.
    #[test]
    fn порог_запроса_считает_кадры_а_не_нагрузку() {
        // Три пакета вниз, кроме заголовков — ничего: запроса не было.
        assert!(!asked_for_something(&Frames { packets: 3, bytes: 3 * HDR }));
        // Те же три пакета, но сверх заголовков 200 байт: запрос отдан.
        assert!(asked_for_something(&Frames { packets: 3, bytes: 3 * HDR + 200 }));
        // Сверх заголовков есть 50 байт, но это меньше FLOOR (100) — ещё не запрос, а, например,
        // случайный ACK с опцией. Без этого случая мутация «убрать FLOOR» осталась бы незамеченной:
        // оба случая выше не зависят от FLOOR (0 и 200 — по разные стороны и нуля, и сотни).
        assert!(!asked_for_something(&Frames { packets: 3, bytes: 3 * HDR + 50 }));
    }

    /// Учёт выключен — не «ноль запроса», а «не считали». Иначе край без учёта выглядел бы как
    /// клиент, не отправивший ничего, и прибор судил бы о мире по собственной слепоте.
    #[test]
    fn край_без_учёта_не_считается_отсутствием_запроса() {
        struct Blind;
        impl EdgeView for Blind {
            fn down_packets(&self) -> Option<u64> { None }
            fn down_bytes(&self) -> Option<u64> { None }
            fn up_packets(&self) -> Option<u64> { None }
            fn up_bytes(&self) -> Option<u64> { None }
            fn idle(&self) -> Option<Duration> { None }
            fn age(&self) -> Option<Duration> { None }
            fn mark(&self) -> u32 { 0 }
        }
        assert!(!asked_for_something(&Blind));
    }
}
