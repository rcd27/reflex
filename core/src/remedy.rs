//! ПОМОГЛО ЛИ ЛЕЧЕНИЕ — вердикт по ИСХОДУ лечимых разговоров, а не по факту «байты пошли» и не по темпу пути.
//!
//! # Чем оплачено (поле, 17.09.2026)
//!
//! Отчёт поля за 200 минут: приборы замечали провал за 0,3 с, решение принималось за 30 мс — а клип по адресу
//! после решения пришёл в 29 петлях из 109. Для узлов кэша провайдера — 0 из 27: ссылка подписана под другой
//! адрес, и уведённые разговоры отдавали по 216 байт отказа, живя по 30 секунд. Пайп ставил тот же увод снова:
//! стадии «помогло ли» у него не было.
//!
//! # Почему по исходу, а не по сравнению путей
//!
//! Первая редакция сравнивала темп уведённого пути с темпом прямой к тем же адресам и на стенде снимала увод
//! с общих фронтов Google: по прямой к тому же адресу шёл чужой трафик. Исход лечимых разговоров о чужих не
//! знает ничего. А «хоть байт» — не исход: отказ тоже байты.
//!
//! ТА РЕДАКЦИЯ ЖИЛА В ДЕРЕВЕ и снесена 20.09.2026 вместе со своей веткой: коммиты `8ed7e71` (вердикт по
//! темпу) и `3f05ec3` (темп путей предикатом потребителя), последний — `remedy-verdict`. Адрес записан
//! затем, что отвергнутое дорого лишь тем, чем оно отвергнуто: ветку из списка видно, а из истории —
//! только по хешу. Её машинерия — `linux/src/conntrack/paths.rs`, 147 строк темпа путей, — в дерево не
//! вошла и потребителя здесь не имеет ни одного.
//!
//! # Три исхода
//!
//! `Cured` — хоть один лечимый разговор донёс объём (порог — аргумент потребителя). `Refused` — есть разговор,
//! в котором клиент ГОВОРИЛ и который прожил терпение, и все такие разговоры — крохи: узел отвечает отказом.
//! `Pending` — всё прочее, включая «отдал больше крохи, но не донёс»: медленно ли, оборвано ли — из счёта байт
//! не различить, и снимать увод по такому было бы гаданием.
//!
//! # Отказ — ещё и ДОЛЯ, и она старше «донесено» (поле .8, 17.09.2026)
//!
//! Кэш провайдера через контур: 237 уведённых разговоров, медиана ответа 216 байт, но редкие отвечают ~6 КБ
//! (отказ после рукопожатия). «Все крохи» такой узел не ловило, а порог «донесено» засчитывал 6 КБ лечением.
//! Поэтому отказ — и когда крох среди говоривших и проживших терпение не меньше `refused_at_least` и их доля не
//! меньше `refused_share_pct`, и в этом случае он решает раньше «донесено»: одиночный ответ не отменяет ряда
//! отказов. Страница через контур этого не заденет — у неё крох нет.
//!
//! # Молчащий клиент — не отказ сервера (стенд, 17.09.2026)
//!
//! Первая редакция судила все лечимые разговоры и сняла увод с `www.youtube.com` и `i.ytimg.com`: браузер
//! заранее открывает соединения «про запас» и ничего в них не шлёт — пять секунд без ответа там молчание
//! КЛИЕНТА. Отказ — когда клиент сказал (приветствие TLS — больше килобайта вверх), а ответа нет.

/// Лечимый разговор глазами наблюдателя: сколько живёт и сколько байт прошло в каждую сторону.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Treated {
    pub age_ms: u64,
    pub reply_bytes: u64,
    pub request_bytes: u64,
}

/// Пороги вердикта — выбираются потребителем по своему замеру.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Patience {
    /// Сколько должен прожить разговор, чтобы его молчание было ответом, а не рукопожатием.
    pub age_ms: u64,
    /// Не больше стольких байт ответа — кроха (рукопожатие, отказ).
    pub crumb_bytes: u64,
    /// Не меньше стольких — донесено.
    pub carried_bytes: u64,
    /// Не меньше стольких байт запроса — клиент говорил.
    pub spoken_bytes: u64,
    /// Ряд отказов: не меньше стольких крох среди говоривших и проживших терпение…
    pub refused_at_least: usize,
    /// …и их доля не меньше стольких процентов.
    pub refused_share_pct: usize,
}

/// Что показали лечимые разговоры.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Remedy {
    Cured,
    Refused,
    Pending,
}

/// Вердикт по лечимым разговорам цели.
pub fn remedy(treated: &[Treated], patience: Patience) -> Remedy {
    let carried = treated
        .iter()
        .any(|one| one.reply_bytes >= patience.carried_bytes);
    let spoken: Vec<&Treated> = treated
        .iter()
        .filter(|one| one.request_bytes >= patience.spoken_bytes)
        .collect();
    let all_crumbs = spoken
        .iter()
        .all(|one| one.reply_bytes <= patience.crumb_bytes);
    let lived: Vec<&&Treated> = spoken
        .iter()
        .filter(|one| one.age_ms >= patience.age_ms)
        .collect();
    let crumbs = lived
        .iter()
        .filter(|one| one.reply_bytes <= patience.crumb_bytes)
        .count();
    let a_row_of_refusals = crumbs >= patience.refused_at_least
        && crumbs * 100 >= patience.refused_share_pct * lived.len();
    match (a_row_of_refusals, carried, all_crumbs && !lived.is_empty()) {
        (true, _, _) => Remedy::Refused,
        (false, true, _) => Remedy::Cured,
        (false, false, true) => Remedy::Refused,
        (false, false, false) => Remedy::Pending,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIELD: Patience = Patience {
        age_ms: 5_000,
        crumb_bytes: 1_024,
        carried_bytes: 512_000,
        spoken_bytes: 512,
        refused_at_least: 3,
        refused_share_pct: 75,
    };

    #[test]
    fn a_row_of_crumbs_refuses_even_beside_a_rare_answer_after_the_handshake() {
        // .8, 90 мин: кэш провайдера через контур — ответы 216 байт подряд и редкий ~6 КБ отказа после рукопожатия.
        let treated = [one(30, 216), one(30, 216), one(30, 216), one(20, 5_980)];
        assert_eq!(remedy(&treated, FIELD), Remedy::Refused);
    }

    #[test]
    fn a_page_through_the_contour_is_never_refused() {
        // Страница: ответы по килобайтам, крох среди говоривших нет — отказом это быть не может.
        let treated = [one(10, 45_000), one(10, 12_000), one(10, 6_000)];
        assert_ne!(remedy(&treated, FIELD), Remedy::Refused);
    }

    #[test]
    fn a_minority_of_crumbs_does_not_refuse_a_working_node() {
        let treated = [
            one(30, 216),
            one(30, 2_000_000),
            one(30, 900_000),
            one(30, 40_000),
        ];
        assert_eq!(remedy(&treated, FIELD), Remedy::Cured);
    }

    /// Разговор, где клиент сказал приветствие TLS (≈ 2,4 КБ вверх, как на .8).
    fn one(age_s: u64, reply_bytes: u64) -> Treated {
        Treated {
            age_ms: age_s * 1_000,
            reply_bytes,
            request_bytes: 2_466,
        }
    }

    #[test]
    fn a_silent_preconnect_is_not_a_refusal() {
        // Стенд, 17.09: соединения «про запас» к www.youtube.com — клиент ничего не сказал, ответа и не было.
        let preconnect = Treated {
            age_ms: 30_000,
            reply_bytes: 0,
            request_bytes: 0,
        };
        assert_eq!(remedy(&[preconnect], FIELD), Remedy::Pending);
    }

    #[test]
    fn a_refusal_is_judged_among_the_spoken_even_beside_a_silent_preconnect() {
        let preconnect = Treated {
            age_ms: 30_000,
            reply_bytes: 0,
            request_bytes: 0,
        };
        assert_eq!(remedy(&[preconnect, one(30, 216)], FIELD), Remedy::Refused);
    }

    #[test]
    fn the_provider_cache_answers_crumbs_through_the_contour_and_is_refused() {
        // .8, 13:42:41: уведённые разговоры к 128.75.236.12/13 — по 216 байт за 30 с.
        assert_eq!(
            remedy(&[one(30, 216), one(30, 216)], FIELD),
            Remedy::Refused
        );
    }

    #[test]
    fn a_handshake_that_has_not_lived_its_patience_is_not_a_refusal() {
        assert_eq!(remedy(&[one(2, 216)], FIELD), Remedy::Pending);
    }

    #[test]
    fn one_carried_clip_cures_whatever_the_rest_do() {
        // .8, 13:42:47: 173.194.163.149 через контур — 2 095 298 байт.
        assert_eq!(
            remedy(&[one(30, 216), one(10, 2_095_298)], FIELD),
            Remedy::Cured
        );
    }

    #[test]
    fn more_than_a_crumb_but_less_than_a_clip_is_not_judged() {
        // .8: `n8v7` через контур 6 864 байт — медленно ли, оборвано ли, не различить.
        assert_eq!(remedy(&[one(120, 6_864)], FIELD), Remedy::Pending);
    }

    #[test]
    fn nothing_treated_is_nothing_to_judge() {
        assert_eq!(remedy(&[], FIELD), Remedy::Pending);
    }
}
