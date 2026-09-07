//! `DetectStream` — У ОПЕРАТОРА ОДНА ЛИНЕЙКА ВРЕМЕНИ, И ЭТО ЧАСЫ РАНТАЙМА (Ruling 20).
//!
//! Будильник оператор берёт у рантайма, а момент узла обязан приходить с ТОЙ ЖЕ линейки. Возьми
//! момент у системных часов — и под управляемым временем линейки разойдутся: будильник
//! отстреливается по виртуальной, сетка считается по системной, между двумя виртуальными
//! пробуждениями системных наносекунд почти не проходит, узлов не наступает ни одного, и тик не
//! рождается НИКОГДА. Беда молчаливая: у потребителя она выглядит зависанием до внешнего
//! таймаута, а не отказом.
//!
//! Проверка идёт под `start_paused`: управляемые часы доказывают «сколько прошло» — узел приходит
//! ровно на своём шаге сетки, а не когда исполнителю дали время. Что оператор просыпается САМ,
//! доказывают настоящие часы, и это отдельная проверка (`detect_stream_grid`, #287); одна другую
//! не заменяет.
use std::time::Duration;

use futures::StreamExt;
use reflex_core::step::Step;
use reflex_core::DetectorEvent;
use reflex_runtime::ReflexRuntimeExt;
use smallvec::SmallVec;

/// Прибор, не читающий пакетов вовсе: единственное, что ему интересно, — номер узла тика.
#[derive(Debug, Clone, Copy, Default)]
struct NodeLog;

impl Step for NodeLog {
    type From = DetectorEvent<u8>;
    type To = SmallVec<[u64; 2]>;

    fn step(self, event: Self::From) -> (Self, Self::To) {
        match event {
            DetectorEvent::Tick { node, .. } => (self, SmallVec::from_slice(&[node])),
            DetectorEvent::Packet { .. } => (self, SmallVec::new()),
            DetectorEvent::Opaque { .. } => (self, SmallVec::new()),
        }
    }
}

/// СЕТКА ИДЁТ ПОД УПРАВЛЯЕМЫМ ВРЕМЕНЕМ, И УЗЛЫ ПРИХОДЯТ РОВНО НА СВОИХ ШАГАХ.
///
/// Шаг взят крупным (10 с), а внешний таймаут — заведомо несоразмерным (час): под управляемыми
/// часами оба виртуальны, и если оператор считает сетку по чужой линейке, тест падает не по
/// значению, а по часовому таймауту — ровно тем зависанием, которым беда видна потребителю.
#[tokio::test(start_paused = true)]
async fn the_grid_advances_on_managed_time() {
    let step = Duration::from_secs(10);
    let source = futures::stream::pending::<u8>();
    let mut stream = Box::pin(source.detect_with_tick(NodeLog, step));

    let began = tokio::time::Instant::now();
    let mut nodes = Vec::new();
    while nodes.len() < 3 {
        match tokio::time::timeout(Duration::from_secs(3600), stream.next()).await {
            Ok(Some(node)) => nodes.push(node),
            other => panic!(
                "под управляемым временем сетка обязана идти, а поток дал {other:?} \
                 (набрано узлов: {nodes:?})"
            ),
        }
    }
    let elapsed = began.elapsed();

    assert_eq!(
        nodes,
        vec![1, 2, 3],
        "узлы обязаны идти подряд от первого, а не повторять номер и не пропадать"
    );
    assert_eq!(
        elapsed,
        step * 3,
        "третий узел сетки с шагом {step:?} обязан прийти ровно через три шага виртуального \
         времени — иначе момент узла снят не с той линейки, что будильник"
    );
}
