use reflex_engine::row::{
    added, host_of, keyed, net_of, no_counts, sighted, told, Counted, Naming, Sight, TargetKey,
    Told,
};
use reflex_engine::{Addr, Span};

const CDN: Addr = Addr(0xBC_72_60_01);

fn counts(up: u64, up_bytes: u64, down: u64, down_bytes: u64) -> Counted {
    Counted {
        up,
        up_bytes,
        down,
        down_bytes,
    }
}

// ── ИДЕНТИЧНОСТЬ СТРОКИ ────────────────────────────────────────────────────────────────────────

#[test]
fn nazvavshayasya_tsel_klyuchuetsya_imenem() {
    assert_eq!(
        keyed(Naming::Spoken("rutracker.org"), CDN, net_of),
        TargetKey::Named("rutracker.org")
    );
}

#[test]
fn tsel_bez_imeni_klyuchuetsya_setyu_a_ne_adresom() {
    assert_eq!(
        keyed(Naming::<&str>::Silent, CDN, net_of),
        TargetKey::Unnamed(Addr(0xBC_72_60_00))
    );
}

/// ДВА РАЗНЫХ ИМЕНИ НА ОДНОМ АДРЕСЕ РАСХОДЯТСЯ В РАЗНЫЕ СТРОКИ. Это и есть причина, по которой
/// строка собирается по ФЛОУ: на `188.114.96.1` имён ≥69 (замер `dig` 31.08), и группировка по
/// адресу свела бы их в одну строку, а подсказка адрес→имя подставила бы имя последнего.
#[test]
fn dva_imeni_na_odnom_adrese_ne_slivayutsya() {
    assert_ne!(
        keyed(Naming::Spoken("rutracker.org"), CDN, net_of),
        keyed(Naming::Spoken("x.com"), CDN, net_of)
    );
}

/// ОЖИДАНИЕ ИМЕНИ И ЕГО ОТСУТСТВИЕ ключуются одинаково — и это НЕ слияние состояний: они
/// различаются `Standing`, а не ключом. Разделить их ключом значило бы менять строку в момент
/// hello, то есть терять всё, что накоплено до него.
#[test]
fn ozhidanie_imeni_i_ego_otsutstvie_dayut_odnu_stroku() {
    assert_eq!(
        keyed(Naming::<&str>::Awaited, CDN, net_of),
        keyed(Naming::<&str>::Silent, CDN, net_of)
    );
}

#[test]
fn shirina_zapisi_sryvaet_mladshiy_bayt() {
    assert_eq!(net_of(Addr(0x0A_0B_0C_0D)), Addr(0x0A_0B_0C_00));
}

/// ДВЕ ШИРИНЫ РАЗВОДЯТ ОДНУ И ТУ ЖЕ ЦЕЛЬ В РАЗНЫЕ КЛЮЧИ, и это весь смысл параметра: строка копит
/// по сети, действие лечит хозяина. Совпади они — либо строка рассыплется на 256 строк, либо
/// знание применится к 256 чужим.
#[test]
fn shirina_zapisi_i_shirina_deystviya_raznye() {
    assert_ne!(
        keyed(Naming::<&str>::Silent, Addr(0x0A_0B_0C_0D), net_of),
        keyed(Naming::<&str>::Silent, Addr(0x0A_0B_0C_0D), host_of)
    );
}

/// НАЗВАННУЮ ЦЕЛЬ ШИРИНА НЕ КАСАЕТСЯ ВОВСЕ: имя перебивает адрес всегда — иначе вред на 69 доменов
/// вернулся бы через заднюю дверь.
#[test]
fn imya_perebivaet_adres_pri_lyuboy_shirine() {
    assert_eq!(
        keyed(Naming::Spoken("x.com"), Addr(0x0A_0B_0C_0D), net_of),
        keyed(Naming::Spoken("x.com"), Addr(0x0A_0B_0C_0D), host_of)
    );
}

// ── СЧЁТ СКЛАДЫВАЕТСЯ (моноид) ─────────────────────────────────────────────────────────────────

#[test]
fn pustoy_schyot_neytralen() {
    let one = counts(7, 1400, 0, 0);
    assert_eq!(added(one, no_counts()), one);
    assert_eq!(added(no_counts(), one), one);
}

#[test]
fn schyot_ne_zavisit_ot_poryadka() {
    let (one, other) = (counts(7, 1400, 3, 120), counts(2, 90, 11, 4096));
    assert_eq!(added(one, other), added(other, one));
}

#[test]
fn schyot_ne_zavisit_ot_gruppirovki() {
    let (one, other, third) = (
        counts(1, 2, 3, 4),
        counts(5, 6, 7, 8),
        counts(9, 10, 11, 12),
    );
    assert_eq!(
        added(added(one, other), third),
        added(one, added(other, third))
    );
}

// ── ЗРЕНИЕ ЗАМЕРЯЕТСЯ ДВУМЯ ОРАКУЛАМИ ──────────────────────────────────────────────────────────

/// Ядро и плоскость сосчитали одно и то же ⟹ плоскость видела весь разговор.
#[test]
fn sovpavshie_schyotchiki_dayut_polnoe_zrenie() {
    let both = counts(7, 1400, 12, 18000);
    assert_eq!(sighted(both, both), Sight::Full);
}

/// ЯДРО СОСЧИТАЛО БОЛЬШЕ ПЛОСКОСТИ ⟹ мы ослепли, и величина слепоты ИЗВЕСТНА. Это ровно тот
/// случай, что создаёт закрытое утверждение 1 DoD: помеченную цель ядро уводит мимо очереди, и
/// «плоскость таких пакетов не видит».
#[test]
fn yadro_soschitalo_bolshe_znachit_ploskost_oslepla() {
    assert_eq!(
        sighted(
            counts(340, 402_000, 900, 1_400_000),
            counts(7, 1400, 2, 120)
        ),
        Sight::Partial {
            missed_up: 333,
            missed_down: 898,
        }
    );
}

/// ПЛОСКОСТЬ НЕ МОЖЕТ ВИДЕТЬ БОЛЬШЕ ЯДРА, и если счётчики так говорят — это расхождение приборов,
/// а не отрицательная слепота. Насыщаем в ноль: витнес обязан молчать, когда ему нечего сказать.
#[test]
fn ploskost_vperedi_yadra_ne_dayot_otritsatelnoy_slepoty() {
    assert_eq!(
        sighted(counts(2, 100, 0, 0), counts(7, 1400, 3, 120)),
        Sight::Full
    );
}

// ── ОТСУТСТВИЕ НАБЛЮДЕНИЯ ПРИ НЕПОЛНОМ ЗРЕНИИ ЕСТЬ СЛЕПОТА ─────────────────────────────────────

/// Главный закон среза. Пустая клетка «Ответила» значит РАЗНОЕ в зависимости от того, могли ли мы
/// вообще увидеть ответ. Слей их — и человек прочитает «цель молчит» там, где молчим МЫ.
#[test]
fn nichego_ne_nablyudeno_pri_nepolnom_zrenii_chitaetsya_slepotoy() {
    assert_eq!(
        told(
            Told::<Span>::Nothing,
            Sight::Partial {
                missed_up: 333,
                missed_down: 898
            }
        ),
        Told::Blind
    );
}

#[test]
fn nichego_ne_nablyudeno_pri_polnom_zrenii_ostayotsya_otsutstviem() {
    assert_eq!(told(Told::<Span>::Nothing, Sight::Full), Told::Nothing);
}

/// НАБЛЮДЁННОЕ СЛЕПОТОЙ НЕ ОТМЕНЯЕТСЯ: если цель ответила ДО того, как мы ослепли, факт остаётся
/// фактом. Иначе действие стирало бы то, что оно же и добыло.
#[test]
fn nablyudyonnoe_perezhivaet_slepotu() {
    assert_eq!(
        told(
            Told::Told(Span(210)),
            Sight::Partial {
                missed_up: 333,
                missed_down: 898
            }
        ),
        Told::Told(Span(210))
    );
}

#[test]
fn slepota_ne_othodit_nazad_pri_polnom_zrenii() {
    assert_eq!(told(Told::<Span>::Blind, Sight::Full), Told::Blind);
}
