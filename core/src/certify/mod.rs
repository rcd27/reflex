//! Семь законов эталона — что типом невыразимо. Тип убивает пустое заявление способности, закон —
//! ложное (команда построена, а на проводе пусто). Восьмой закон, `replays`, — канон §10.
//!
//! Свидетель — не подопытный: доставку спрашивают у того, кто устроен иначе, и у каждого закона он
//! свой — [`injection`]→[`injection::FarEnd`] (до кого дошло), [`observation`]→[`observation::
//! Origin`] (кто породил трафик), [`holding`]→[`holding::Downstream`] (что ниже по стеку, и
//! спрашивают дважды — закон о порядке). Обрыв [`severing`] спрашивает двоих ([`Downstream`] +
//! [`severing::NearEnd`]): обрыв есть пара, и разница лечения от беды — в адресате второй половины.

pub mod holding;
pub mod injection;
pub mod marking;
pub mod observation;
pub mod refusal;
pub mod rewriting;
pub mod severing;

pub use holding::holds;
pub use injection::injects;
pub use marking::marks;
pub use observation::observes;
pub use refusal::refuses;
pub use rewriting::rewrites;
pub use severing::severs;

/// Держится ли закон. Три состояния: `Held`; `Broken(B)` — вина подопытного; `Invalid(I)` — беда
/// стенда (предпосылка не выполнилась). Разделять обязательно: поломку прибора нельзя предъявлять
/// как нарушение способности. Вердикт обобщён (форма одна), причины у каждого закона свои (сумма,
/// не произведение осей).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict<B, I> {
    Held,
    Broken(B),
    Invalid(I),
}

/// Что прошло ниже по стеку с прошлого вопроса — общий свидетель терминальных законов. «С прошлого
/// вопроса» несуще: законы спрашивают дважды и сравнивают, иначе прошедшее до ответа зачлось бы
/// доставкой.
pub trait Downstream {
    fn passed(&mut self) -> Vec<Vec<u8>>;
}

/// Несёт ли кадр наш нонс — подстрокой, не равенством: наблюдатель видит кадр с чужими
/// заголовками. Публичен намеренно: тем же предикатом живое устройство ждёт нонс в записи — иначе
/// ожидание и суждение разошлись бы.
pub fn carries(frame: &[u8], nonce: &[u8]) -> bool {
    match nonce.len() {
        0 => false,
        len => frame.windows(len).any(|window| window == nonce),
    }
}
