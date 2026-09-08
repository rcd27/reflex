//! Закон наблюдения: что породил мир — видно наблюдателю, и притом всё. Роли перевёрнуты против
//! [`injection`](super::injection): подопытный НАБЛЮДАЕТ, свидетельствует [`Origin`] (кто породил
//! трафик), и молчит здесь мир, а не прибор. Закон СЧИТАЕТ, а не проверяет наличие: «не вмешиваясь»
//! типом не выразимо, наблюдатель, роняющий пакеты, синтаксически неотличим от честного.

use std::cmp::Ordering;

use futures::{Stream, StreamExt};

use super::{carries, Verdict};
use crate::held::Observed;

/// Кто породил трафик и сколько его ушло. Число — не у подопытного (спрашивать наблюдателя, сколько
/// было, значит принять его показания за меру его точности): в бою — разность счётчиков ядра,
/// прибор иной природы.
pub trait Origin {
    /// Породить трафик с нонсом и ответить, сколько кадров ушло НА САМОМ ДЕЛЕ.
    fn emit(&mut self, nonce: &[u8]) -> usize;
}

/// Почему закон не держится. Потеря и дубль лечатся в разных местах (приём против разметки).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Broken {
    /// Наблюдатель увидел МЕНЬШЕ, чем ушло: вмешивается в ход, роняя пакеты.
    Lost { sent: usize, seen: usize },
    /// Наблюдатель увидел БОЛЬШЕ, чем ушло: один кадр посчитан несколько раз.
    Duplicated { sent: usize, seen: usize },
}

/// Почему вердикта нет — беда стенда.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Invalid {
    /// Мир не породил ни кадра — наблюдателю нечего было видеть. Зеркало
    /// [`injection::Invalid::WitnessSilent`](super::injection::Invalid::WitnessSilent).
    WorldSilent,
}

/// Дверь к наблюдениям — одна на весь крейт: закон входит той же дверью, что боевой путь, иначе
/// стенд измерял бы сам себя.
pub use crate::backend::observing as watching;

/// Закон наблюдения. Порядок обязателен: поток создаётся ДО вызова (`watching(&mut dut)` в
/// аргументе), мир порождает трафик ВНУТРИ. Чужой трафик не засчитывается (нонс).
pub async fn observes<P, S, O>(
    origin: &mut O,
    nonce: &[u8],
    observed: S,
) -> Verdict<Broken, Invalid>
where
    P: Observed,
    S: Stream<Item = P>,
    O: Origin,
{
    let sent = origin.emit(nonce);
    let seen = observed
        .filter(|packet| std::future::ready(carries(packet.payload(), nonce)))
        .count()
        .await;

    match sent {
        0 => Verdict::Invalid(Invalid::WorldSilent),
        sent => match seen.cmp(&sent) {
            Ordering::Equal => Verdict::Held,
            Ordering::Less => Verdict::Broken(Broken::Lost { sent, seen }),
            Ordering::Greater => Verdict::Broken(Broken::Duplicated { sent, seen }),
        },
    }
}
