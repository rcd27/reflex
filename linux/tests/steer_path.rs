//! Свидетель пути увода на ЖИВОМ маршрутизаторе ядра, а не на подделанных байтах.
//!
//! Тест переисполняет себя в свежем сетевом пространстве (`unshare -Ur --net`, приём
//! `os/tests/netlink_link_event.rs`): там он вправе завести ногу и правила, и отвечает ему то же
//! ядро, что поведёт пакеты на машине. Обе беды ночи 13.09.2026 собираются здесь мутантами, и
//! зелёный честного пути засчитывается лишь после того, как тот же свидетель покраснел на каждой
//! (Правило 10.7).

use reflex_core::types::Protocol;
use reflex_linux::route::{witness, Unsteerable, Went};

const IN_NETNS: &str = "REFLEX_LINUX_STEER_IN_NETNS";
const CASE: &str = "путь_увода_свидетельствует_ядро_и_краснеет_на_обеих_бедах";
const MARK: u32 = 0x10000;
const RULE: &str = "fwmark 0x10000/0x10000 lookup 100";

#[test]
fn путь_увода_свидетельствует_ядро_и_краснеет_на_обеих_бедах() {
    match std::env::var(IN_NETNS) {
        Ok(_) => inside_fresh_netns(),
        Err(_) => reexec_inside_netns(),
    }
}

fn reexec_inside_netns() {
    let exe = std::env::current_exe().unwrap_or_default();
    let child = std::process::Command::new("unshare")
        .args(["-Ur", "--net"])
        .arg(&exe)
        .args([CASE, "--exact", "--nocapture", "--test-threads=1"])
        .env(IN_NETNS, "1")
        .status();
    // Провал ЗАПУСКА не глушим: пропуск превратил бы свидетеля в украшение.
    assert!(
        child.is_ok(),
        "не запустился `unshare -Ur --net` — свидетельство не предъявлено"
    );
    assert!(
        child.map(|st| st.success()).unwrap_or(false),
        "проход внутри сетевого пространства провалился"
    );
}

fn ip(args: &str) {
    let done = std::process::Command::new("ip")
        .args(args.split_whitespace())
        .status()
        .map(|st| st.success())
        .unwrap_or(false);
    assert!(
        done,
        "`ip {args}` не прошёл — стенд не собран, свидетельство не предъявлено"
    );
}

fn inside_fresh_netns() {
    // `lan0`, а не `br`: `ip link add br …` читает `br` ключевым словом (broadcast), молча не
    // заводит устройство, и проверка своего адреса шла бы по адресу, которого у машины нет.
    [
        "link set lo up",
        "link add leg type dummy",
        "link set leg up",
        "link add lan0 type dummy",
        "link set lan0 up",
        "addr add 192.168.77.1/24 dev lan0",
        "route add default dev leg table 100",
    ]
    .into_iter()
    .for_each(ip);

    assert_eq!(
        witness(MARK, "нет0"),
        Err(Unsteerable::NoLeg("нет0".to_string())),
        "ноги нет — уводить некуда"
    );

    // Правила нет вовсе: помеченное идти некуда.
    assert!(
        matches!(
            witness(MARK, "leg"),
            Err(Unsteerable::Uncovered {
                l4: Protocol::Tcp,
                went: Went::Refused(_)
            })
        ),
        "без правила путь не свидетельствуется: {:?}",
        witness(MARK, "leg")
    );

    // МУТАНТ 1 — путь под один L4, как в ночь, когда QUIC остался без увода.
    ip(&format!("rule add ipproto tcp {RULE} pref 1000"));
    assert!(
        matches!(
            witness(MARK, "leg"),
            Err(Unsteerable::Uncovered {
                l4: Protocol::Udp,
                ..
            })
        ),
        "путь под один TCP обязан покраснеть на UDP: {:?}",
        witness(MARK, "leg")
    );
    ip("rule del pref 1000");

    // МУТАНТ 2 — свои адреса ниже правила увода, как в ночь, когда машина потеряла mesh.
    ip(&format!("rule add {RULE} pref 10"));
    ip("rule del pref 0");
    ip("rule add lookup local pref 100");
    assert!(
        matches!(
            witness(MARK, "leg"),
            Err(Unsteerable::LocalLeaks {
                went: Went::Device(_),
                ..
            })
        ),
        "свой адрес, уходящий в ногу, обязан покраснеть: {:?}",
        witness(MARK, "leg")
    );
    ip("rule del pref 100");
    ip("rule add lookup local pref 0");
    ip("rule del pref 10");

    // ЧЕСТНЫЙ ПУТЬ — после того, как тот же свидетель показал оба красных.
    ip(&format!("rule add {RULE} pref 1000"));
    let path = witness(MARK, "leg");
    assert!(
        matches!(&path, Ok(shown) if shown.mark() == MARK),
        "честный путь обязан свидетельствоваться: {path:?}"
    );
}
