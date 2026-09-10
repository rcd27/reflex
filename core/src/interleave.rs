//! Шов: пакеты и сетка сходятся в один поток (канон §8). Время перестаёт быть сервисом и становится
//! буквой входного алфавита: потребитель ниже не спрашивает часов, читает буквы [`DetectorEvent`]
//! — этого довольно для `debounce`, `timeout`, окна, простоя. Пока трафик идёт,
//! узлы сетки ВЫЧИСЛЯЮТСЯ ([`Interleave::saw`]/[`Interleave::unread`] чисты, часов не знают);
//! будильник нужен только на тишину ([`Interleave::idle`]). Шов, а не оператор: оператор над потоком
//! (Rx) в тишине бессилен (поток пуст), там время вносят планировщиком, решающим и ГДЕ считать;
//! здесь молчание — законный вход, способ ожидания — свойство того, кто ПОРОЖДАЕТ поток.
//! Монотонность — требование, не свойство: провод переставляет пакеты, очередь отдаёт не по порядку,
//! выпуск ([`crate::watch`]) роняет часть событий; событие с моментом раньше выданного ломает
//! временной оператор МОЛЧА. Цена: опоздавшее выходит с последним выданным моментом — теряем точность
//! на величину опоздания, не порядок.

use core::time::Duration;
use std::time::Instant;

use crate::detector::DetectorEvent;

/// Состояние шва: откуда отмеряется сетка, шаг и до какого момента поток выдан. Шаги чисты
/// (возвращают новое состояние) — это и делает шов проверяемым таблицей без рантайма.
#[derive(Debug, Clone, Copy)]
pub struct Interleave {
    start: Instant,
    every: Duration,
    last: Instant,
}

impl Interleave {
    /// Шов, начатый в момент `at`: сетка отмеряется отсюда.
    pub fn started(at: Instant, every: Duration) -> Self {
        Self {
            start: at,
            every,
            last: at,
        }
    }

    /// Наблюдён пакет — что обязан увидеть потребитель. Сперва узлы, которые пакет перешагнул, потом
    /// он сам: детектор, увидевший пакет раньше закрытия окна, в которое пакет не попал, отнёс бы его
    /// байты не к тому окну.
    pub fn saw<T>(self, input: T, at: Instant) -> (Self, Vec<DetectorEvent<T>>) {
        let at = at.max(self.last);
        let events = self
            .nodes_up_to(at)
            .chain(core::iter::once(DetectorEvent::Packet { input, at }))
            .collect();
        (Self { last: at, ..self }, events)
    }

    /// Наблюдено, но разобрать не смогли — дверь для второй буквы, симметричная [`Interleave::saw`].
    /// Шов про МОМЕНТЫ, не содержимое: непонятое продвигает сетку тем же способом. Не будь двери,
    /// поток из одних неразобранных не двигал бы сетку, и молчание было бы неотличимо от «пакетов нет».
    pub fn unread<T>(
        self,
        why: crate::parse::Unread,
        at: Instant,
    ) -> (Self, Vec<DetectorEvent<T>>) {
        let at = at.max(self.last);
        let events = self
            .nodes_up_to(at)
            .chain(core::iter::once(DetectorEvent::Opaque { why, at }))
            .collect();
        (Self { last: at, ..self }, events)
    }

    /// Нам ОТВЕТИЛИ на спрошенное — третья дверь шва, кладущая букву в алфавит ЛЕНТЫ. Узлы,
    /// которые отклик перешагнул, выходят ПЕРЕД ним: порядок держит та же конструкция, что у
    /// [`Interleave::saw`], а не дисциплина зовущего.
    ///
    /// Отклик двигает СЕТКУ (иначе лента перестала бы быть упорядоченной), но не отменяет тишины
    /// провода: приборы его не видят вовсе — до них он не доходит сужением (§4). Так и надо. Цель,
    /// что отвечает нашему контуру, пока провод молчит, — это тихий дроп, и он обязан выглядеть
    /// тихим; отодвигай отклик тишину, дропнутый поток, чей контур сказал «блок», выглядел бы
    /// НЕ-тихим, то есть ровно наоборот правде.
    pub fn answered<T, K, C>(
        self,
        key: K,
        input: C,
        at: Instant,
    ) -> (Self, Vec<crate::tape::TapeLetter<T, K, C>>) {
        let at = at.max(self.last);
        let events = self
            .nodes_up_to(at)
            // Узел сетки адресован КАЖДОЙ живой машине: у времени ключа нет.
            .map(|event| crate::tape::TapeLetter::Event {
                to: crate::tape::To::Each,
                event,
            })
            .chain(core::iter::once(crate::tape::TapeLetter::Answer(
                crate::tape::Answer { key, input, at },
            )))
            .collect();
        (Self { last: at, ..self }, events)
    }

    /// Прошло время без пакетов — какие узлы наступили. Тишина есть наблюдение: приборы простоя видят
    /// предмет только здесь. Зовётся тем, у кого есть будильник ([`crate::clock::Ticks`] отдаёт
    /// управление рантайму, [`crate::clock::Beats`] занимает поток) — сам шов спать не умеет.
    pub fn idle<T>(self, at: Instant) -> (Self, Vec<DetectorEvent<T>>) {
        let at = at.max(self.last);
        let events = self.nodes_up_to(at).collect();
        (Self { last: at, ..self }, events)
    }

    /// Дыра объявлена. Симметрична [`Interleave::unread`]: узлы, которые дыра перешагнула, выходят
    /// ПЕРЕД ней — порядок держит конструкция, а не дисциплина зовущего.
    pub fn torn<T>(self, at: Instant) -> (Self, Vec<DetectorEvent<T>>) {
        let at = at.max(self.last);
        let events = self
            .nodes_up_to(at)
            .chain(core::iter::once(DetectorEvent::Torn { at }))
            .collect();
        (Self { last: at, ..self }, events)
    }

    /// Узлы сетки с последнего выданного момента по `at` включительно. Номер узла — [`crate::grid::due`]
    /// на его же момент (момент узла попадает на сетку ровно): обратность [`crate::grid::node`] и
    /// [`crate::grid::due`] на ненулевом шаге.
    fn nodes_up_to<T>(&self, at: Instant) -> impl Iterator<Item = DetectorEvent<T>> {
        let start = self.start;
        let every = self.every;
        crate::grid::nodes_between(start, self.last, at, every).map(move |at| DetectorEvent::Tick {
            node: crate::grid::due(start, at, every),
            at,
        })
    }

    /// Момент следующего узла сетки, если он наступит. Чист: часов не спрашивает, считает от последнего
    /// выданного момента — оттого срок не плывёт от того, когда его спросили. Возвращает `None` при
    /// нулевом шаге (отсутствие сетки): прошедший момент был бы гарантией наступления узла, но нулевой
    /// шаг отменяет её, оставляя только значение — узла не будет.
    pub fn next_node(&self) -> Option<Instant> {
        crate::grid::next_due(self.start, self.last, self.every).map(|nth| {
            crate::grid::node(self.start, self.every, nth)
        })
    }
}
