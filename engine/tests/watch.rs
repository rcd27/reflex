use reflex_engine::row::Naming;
use reflex_engine::watch::{released, watched, Watch, SETTLED};
use reflex_engine::{Act, Basis, Epoch, Interest, Mark, Plan, Programme};

const LEG: u32 = 0xCC;

fn plan_of(programme: Programme, interest: Interest) -> Plan {
    Plan {
        programme,
        epoch: Epoch(1),
        basis: Basis::Measured,
        interest,
    }
}

/// Вердикт, применённый по этой программе.
fn act_of(programme: Programme) -> Act {
    match programme {
        Programme::Pass => Act::Pass,
        Programme::Mark(mark) => Act::Marked(mark),
    }
}

/// Решение о выпуске для цели, к которой у приборов интереса нет, — обычный случай.
fn release<N>(naming: Naming<N>, programme: Programme) -> Watch {
    watched(
        naming,
        act_of(programme),
        plan_of(programme, Interest::Idle),
    )
}

/// ОБЯЗАТЕЛЬСТВО ПЕРЕД ЛИФТОМ, названное в #300 до появления предиката: флоу остаётся под
/// наблюдением, пока его личность в ⊥. Проверяется ПО ВСЕМУ пространству планов, а не на одном:
/// выпускать до приветствия нельзя НИ ПРИ КАКОМ решении, иначе снимок начнёт зависеть от того,
/// что видели мы, а не от того, что случилось на проводе.
#[test]
fn poka_lichnost_v_dne_ne_vypuskaem_ni_pri_kakom_plane() {
    [Programme::Pass, Programme::Mark(Mark(LEG))]
        .into_iter()
        .for_each(|programme| {
            assert_eq!(
                release(Naming::<()>::Awaited, programme),
                Watch::Hold,
                "приветствие впереди — выпускать нельзя при {programme:?}"
            );
        });
}

#[test]
fn nazvavshayasya_tsel_vypuskaetsya() {
    assert_eq!(
        release(Naming::Spoken(()), Programme::Mark(Mark(LEG))),
        Watch::Release(Mark(SETTLED | LEG))
    );
}

/// ПРИВЕТСТВИЕ БЕЗ ИМЕНИ ТОЖЕ ЗАКРЫВАЕТ ВОПРОС. Имени не добудется, ждать нечего, и держать такой
/// разговор в горячем пути значило бы платить за наблюдение, которое ничего не принесёт.
#[test]
fn privetstvie_bez_imeni_tozhe_vypuskaet() {
    assert_eq!(
        release(Naming::<()>::Silent, Programme::Mark(Mark(LEG))),
        Watch::Release(Mark(SETTLED | LEG))
    );
}

/// РЕШЕНИЕ «НИЧЕГО НЕ ДЕЛАТЬ» — ТОЖЕ РЕШЕНИЕ, и оно обязано выпускать. Иначе весь трафик, которому
/// мы не нужны, платил бы полную цену дороги в userspace — а это подавляющая его часть.
#[test]
fn reshenie_nichego_ne_delat_vypuskaet_s_nenulevoy_metkoy() {
    match release(Naming::Spoken(()), Programme::Pass) {
        Watch::Release(Mark(mark)) => {
            assert_eq!(mark, SETTLED, "маршрута нет, признак решённости есть");
            assert_ne!(mark, 0, "нулевая метка неотличима от «решения не было»");
        }
        Watch::Hold => panic!("решённый разговор обязан выпускаться"),
    }
}

/// ПРИЗНАК РЕШЁННОСТИ НЕ ПЕРЕСЕКАЕТСЯ С ЖИВЫМИ РАЗРЯДАМИ. `0x1000_0000` носит десинк,
/// `0x2000_0000` — база воркеров; пересечение молча увело бы чужой трафик в чужую очередь.
#[test]
fn priznak_reshyonnosti_ne_zadevaet_zhivye_razryady() {
    assert_eq!(SETTLED & 0x1000_0000, 0, "разряд десинка");
    assert_eq!(SETTLED & 0x2000_0000, 0, "база воркеров");
    assert_eq!(
        SETTLED & 0xFF,
        0,
        "младший байт — маршруты ног (0xCC, 0xBB)"
    );
    assert_ne!(SETTLED, 0);
}

/// ОБРАТНОЕ ЧТЕНИЕ ТОТАЛЬНО ПО ВСЕМУ ПРОСТРАНСТВУ РЕШЕНИЙ.
///
/// Одного случая мало, и это не педантизм: первая редакция проверяла только `Mark`, и
/// обезоруживание разряда отвода НЕ покраснело — отвод без него читался бы обратно как обычный
/// маршрут `Mark(0x01)`, то есть разговор поехал бы не туда, а прибор согласился бы.
///
/// ОТВОД СНЯТ (#326) вместе с исполнителем, и пространство решений стало меньше — но урок
/// остался в силе и стережёт то, что есть: возвращая отвод, вернуть сюда и его случаи.
#[test]
fn vsyakoe_reshenie_chitaetsya_obratno_soboy_zhe() {
    [
        Programme::Pass,
        Programme::Mark(Mark(LEG)),
        Programme::Mark(Mark(0x01)),
    ]
    .into_iter()
    .for_each(|taken| match release(Naming::Spoken(()), taken) {
        Watch::Release(mark) => assert_eq!(
            released(mark),
            Some(taken),
            "решение {taken:?} вернулось из метки {mark:?} другим"
        ),
        Watch::Hold => panic!("решённый разговор обязан выпускаться"),
    });
}

/// РАЗНЫЕ РЕШЕНИЯ ДАЮТ РАЗНЫЕ МЕТКИ. Тотальность обратного чтения этого не влечёт: она держалась
/// бы и при схлопывании двух решений в одну метку, если бы читалось всегда первое.
#[test]
fn raznye_resheniya_ne_delyat_odnu_metku() {
    let marks: Vec<Mark> = [
        Programme::Pass,
        Programme::Mark(Mark(LEG)),
        Programme::Mark(Mark(0x01)),
    ]
    .into_iter()
    .map(|taken| match release(Naming::Spoken(()), taken) {
        Watch::Release(mark) => mark,
        Watch::Hold => panic!("решённый разговор обязан выпускаться"),
    })
    .collect();
    let mut seen = marks.clone();
    seen.sort_by_key(|Mark(bits)| *bits);
    seen.dedup();
    assert_eq!(
        seen.len(),
        marks.len(),
        "две разные ноги делят метку: {marks:?}"
    );
}

/// ОБРАТНОЕ ЧТЕНИЕ. Ядро хранит метку в `ct mark` и возвращает её нам; по ней обязано читаться то
/// же решение, что мы приняли, иначе два конца механизма разъедутся молча.
#[test]
fn metka_chitaetsya_obratno_tem_zhe_resheniem() {
    let taken = Programme::Mark(Mark(LEG));
    match release(Naming::Spoken(()), taken) {
        Watch::Release(mark) => assert_eq!(released(mark), Some(taken)),
        Watch::Hold => panic!("решённый разговор обязан выпускаться"),
    }
}

#[test]
fn metka_bez_priznaka_reshyonnosti_reshenie_ne_neset() {
    assert_eq!(released(Mark(LEG)), None, "маршрут без признака — не наше");
    assert_eq!(released(Mark(0)), None, "решения не было");
}

/// СБРОШЕННЫЙ РАЗГОВОР НЕ ВЫПУСКАЕТСЯ НИКОГДА, даже с установленной личностью: выпустить его
/// значило бы поручить ядру принимать то, что мы решили не пропускать.
#[test]
fn sbroshennyy_razgovor_ne_vypuskaetsya_dazhe_pri_izvestnom_imeni() {
    let plan = plan_of(Programme::Pass, Interest::Idle);
    assert_eq!(watched(Naming::Spoken(()), Act::Drop, plan), Watch::Hold);
    assert_eq!(watched(Naming::<()>::Silent, Act::Drop, plan), Watch::Hold);
}

/// ВТОРАЯ ОСЬ ВЫПУСКА: цель, по которой приборы ждут показаний, не выпускается даже с
/// установленной личностью и принятым решением.
///
/// Без неё беда, наступившая ПОСЛЕ лечения, не видна никому: разговор ушёл в ядро и байтов больше
/// не даёт: наблюдение о незнакомой цели видно только до решения о выпуске.
#[test]
fn tsel_pod_nablyudeniem_ne_vypuskaetsya() {
    let watched_plan = plan_of(Programme::Mark(Mark(LEG)), Interest::Watching);
    [Naming::Spoken(()), Naming::<()>::Silent]
        .into_iter()
        .for_each(|naming| {
            assert_eq!(
                watched(naming, Act::Marked(Mark(LEG)), watched_plan),
                Watch::Hold,
                "приборы ждут показаний — держим"
            );
        });
}

/// ИНТЕРЕС И ПРОГРАММА ПРИЕЗЖАЮТ ОДНИМ ПЛАНОМ, и разъехаться не могут: у `watched` нет способа
/// принять их порознь. Проверяется тем, что ОДНА и та же цель при смене одного лишь интереса
/// меняет решение о выпуске на противоположное.
#[test]
fn interes_reshaet_vypusk_pri_toy_zhe_programme() {
    let programme = Programme::Mark(Mark(LEG));
    let idle = watched(
        Naming::Spoken(()),
        act_of(programme),
        plan_of(programme, Interest::Idle),
    );
    let busy = watched(
        Naming::Spoken(()),
        act_of(programme),
        plan_of(programme, Interest::Watching),
    );
    assert_eq!(idle, Watch::Release(Mark(SETTLED | LEG)));
    assert_eq!(busy, Watch::Hold);
}

/// ПЕРЕХОДНИК НЕ ТЕРЯЕТ РЕШЕНИЯ: что вердикт назначил, то из метки и читается.
#[test]
fn perehodnik_ot_verdikta_ne_teryaet_resheniya() {
    [
        (Act::Pass, Programme::Pass),
        (Act::Marked(Mark(LEG)), Programme::Mark(Mark(LEG))),
        (Act::Marked(Mark(0x01)), Programme::Mark(Mark(0x01))),
    ]
    .into_iter()
    .for_each(|(act, expected)| {
        match watched(
            Naming::Spoken(()),
            act,
            plan_of(Programme::Pass, Interest::Idle),
        ) {
            Watch::Release(mark) => assert_eq!(released(mark), Some(expected), "вердикт {act:?}"),
            Watch::Hold => panic!("решённый разговор обязан выпускаться: {act:?}"),
        }
    });
}
