//! Закон инъекции: что отдано в сток — наблюдаемо дальним концом. Подопытный отправляет,
//! свидетельствует [`FarEnd`] (тот, до кого должно дойти), и знает это не от подопытного.

use super::{carries, Verdict};
use crate::backend::Sink;
use crate::capability::CanInject;
use crate::command::InjectablePacket;

/// Что видел тот, до кого должно было дойти: чужой процесс (бой) или список (память).
pub trait FarEnd {
    /// Кадры, дошедшие с прошлого вопроса.
    fn arrived(&mut self) -> Vec<Vec<u8>>;
}

/// Список — тоже дальний конец. `take` намеренно: вопрос «что дошло С ПРОШЛОГО РАЗА».
impl FarEnd for Vec<Vec<u8>> {
    fn arrived(&mut self) -> Vec<Vec<u8>> {
        std::mem::take(self)
    }
}

/// Почему закон не держится.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Broken {
    /// Сток сказал, что не смог — отказ, о котором сообщили; починка в мире, не в бэкенде.
    SinkRefused,
    /// Сток ответил `Ok`, а нашего кадра у дальнего конца нет — вот ложное заявление.
    NonceMissing,
}

/// Почему вердикта нет — беда стенда.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Invalid {
    /// Дальний конец не показал ни кадра: пустоту живому устройству разгоняет маяк от ядра, не от
    /// подопытного.
    WitnessSilent,
}

/// Закон инъекции. Нонс, а не число кадров: дальний конец видит и чужой трафик. `emit`, а не
/// `inject`: команда обязана дойти до провода, а не только собраться. Дальний конец ничего не
/// получает от закона — иначе свидетель пересказывал бы вопрос.
pub fn injects<B, F>(
    dut: &mut B,
    nonce: InjectablePacket,
    far_end: &mut F,
) -> Verdict<Broken, Invalid>
where
    B: Sink + CanInject,
    F: FarEnd + ?Sized,
{
    let bytes = nonce.serialize();
    match dut.emit(B::inject(nonce)) {
        Err(_refused) => Verdict::Broken(Broken::SinkRefused),
        Ok(()) => match far_end.arrived().as_slice() {
            [] => Verdict::Invalid(Invalid::WitnessSilent),
            seen => match seen.iter().any(|frame| carries(frame, &bytes)) {
                true => Verdict::Held,
                false => Verdict::Broken(Broken::NonceMissing),
            },
        },
    }
}
