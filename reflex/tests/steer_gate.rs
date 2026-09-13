//! Гейт пути увода стоит на ДВЕРИ, которой поднимается движок, а не только в свидетеле: закон,
//! не коснувшийся носителя, остаётся бумагой. Тест переисполняет себя в своём сетевом пространстве
//! (`unshare -Ur --net`) и открывает носитель над ногой без правила и с честным правилом.
#![cfg(target_os = "linux")]

use reflex::{Cause, IntoCarrier, Nfqueue, UNSTEERABLE};

const IN_NETNS: &str = "REFLEX_STEER_GATE_IN_NETNS";
const CASE: &str = "носитель_не_поднимается_без_показанного_пути_увода";

#[test]
fn носитель_не_поднимается_без_показанного_пути_увода() {
    match std::env::var(IN_NETNS) {
        Ok(_) => inside_fresh_netns(),
        Err(_) => {
            let exe = std::env::current_exe().unwrap_or_default();
            let child = std::process::Command::new("unshare")
                .args(["-Ur", "--net"])
                .arg(&exe)
                .args([CASE, "--exact", "--nocapture", "--test-threads=1"])
                .env(IN_NETNS, "1")
                .status();
            assert!(
                child.map(|st| st.success()).unwrap_or(false),
                "проход внутри сетевого пространства не запустился или провалился"
            );
        }
    }
}

fn ip(args: &str) {
    let done = std::process::Command::new("ip")
        .args(args.split_whitespace())
        .status()
        .map(|st| st.success())
        .unwrap_or(false);
    assert!(done, "`ip {args}` не прошёл — стенд не собран");
}

/// Отказ носителя ПО ПУТИ, если он был; прочие исходы (подъём, отказ предпосылки) — `None`.
fn refused_by_path(queue: Nfqueue) -> Option<String> {
    match queue.open() {
        Err(Cause(why)) if why.starts_with(UNSTEERABLE) => Some(why),
        Ok(_) | Err(_) => None,
    }
}

fn inside_fresh_netns() {
    [
        "link set lo up",
        "link add leg type dummy",
        "link set leg up",
        "route add default dev leg table 100",
    ]
    .into_iter()
    .for_each(ip);

    let unproven = refused_by_path(Nfqueue::queue(200).steering(0x10000, "leg"));
    assert!(
        unproven
            .as_deref()
            .is_some_and(|why| why.contains("не покрывает")),
        "без правила носитель обязан отказать ПО ПУТИ: {unproven:?}"
    );

    ip("rule add fwmark 0x10000/0x10000 lookup 100 pref 1000");
    let proven = refused_by_path(Nfqueue::queue(200).steering(0x10000, "leg"));
    assert_eq!(proven, None, "показанный путь гейт пропускает");

    assert_eq!(
        refused_by_path(Nfqueue::queue(200)),
        None,
        "без увода гейта нет вовсе"
    );
}
