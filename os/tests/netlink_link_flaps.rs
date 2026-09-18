//! Витнес счётчика смен несущей на НАСТОЯЩЕМ мигании линка (#331), а не на подменённом файле.
//!
//! Как и сосед `netlink_link_event.rs`, тест переисполняет себя внутри свежего сетевого
//! namespace: непривилегированный userns даёт CAP_NET_ADMIN над СВОИМ netns, значит несущую
//! можно подвигать по-настоящему и счётчик двигает ЯДРО.
//!
//! Устройство — `veth`, а не `dummy`. Это не вкусовщина: у `dummy` несущей нет вовсе, и
//! `carrier_changes` стоит нулём через `up`/`down` (замерено). Тест на `dummy` был бы зелен по
//! «файл читается» и слеп к самому предмету. У `veth` несущая поднимается ровно тогда, когда
//! поднят ПАРТНЁР, и каждое его мигание даёт +1 — та же механика, что у сторожевого сброса порта.
//!
//! Оракулов два, и они независимы: ЗНАЧЕНИЕ (счётчик вырос ровно на 2 — мигание не потеряно) и
//! ВРЕМЯ (пол 10с при дедлайне 3с, значит разбудить мог ТОЛЬКО netlink).

use reflex_os::link::{self, Flaps};
use reflex_os::Outcome;
use std::time::Duration;

const IN_NETNS: &str = "REFLEX_OS_IN_NETNS";
const CASE: &str = "netlink_counts_carrier_flaps";

#[test]
fn netlink_counts_carrier_flaps() {
    match std::env::var(IN_NETNS) {
        Ok(_) => inside_fresh_netns(),
        Err(_) => reexec_inside_netns(),
    }
}

/// Внешний проход: перезапустить ЭТОТ ЖЕ бинарь под `unshare`.
fn reexec_inside_netns() {
    let exe = std::env::current_exe();
    assert!(exe.is_ok(), "не узнать собственный путь");
    let path = exe.unwrap_or_default();

    // `--mount --propagation private` обязателен вместе с `--net`: sysfs не следует за сетевым
    // namespace сам, и `/sys/class/net` показывал бы устройства РОДИТЕЛЬСКОГО netns.
    let child = std::process::Command::new("unshare")
        .args(["-Ur", "--net", "--mount", "--propagation", "private"])
        .arg(&path)
        .args([CASE, "--exact", "--nocapture", "--test-threads=1"])
        .env(IN_NETNS, "1")
        .status();

    assert!(
        child.is_ok(),
        "не запустился `unshare -Ur --net` — витнес не предъявлен, а не «пропущен»"
    );
    assert!(
        child.map(|st| st.success()).unwrap_or(false),
        "проход внутри netns провалился"
    );
}

fn ip(args: &[&str]) -> bool {
    std::process::Command::new("ip")
        .args(args)
        .status()
        .map(|st| st.success())
        .unwrap_or(false)
}

/// Внутренний проход: мы в своём netns и вправе двигать несущую.
fn inside_fresh_netns() {
    let remounted = unsafe {
        libc::mount(
            c"none".as_ptr(),
            c"/sys".as_ptr(),
            c"sysfs".as_ptr(),
            0,
            std::ptr::null(),
        )
    };
    assert_eq!(
        remounted, 0,
        "sysfs не перемонтирован — истина была бы чужой"
    );

    assert!(
        ip(&["link", "add", "veth0", "type", "veth", "peer", "name", "veth1"]),
        "пара veth не завелась"
    );
    assert!(ip(&["link", "set", "veth0", "up"]), "veth0 не поднялся");
    assert!(ip(&["link", "set", "veth1", "up"]), "veth1 не поднялся");

    // Пол недостижим намеренно: всё, что быстрее дедлайна, — заслуга подсказки.
    let level = match link::flaps("veth0", Duration::from_secs(10)) {
        Ok(level) => level,
        Err(err) => panic!("уровень счётчика не завёлся: {err}"),
    };

    // База снимается ПОСЛЕ подписки: подъём пары сам по себе дал смены, и вменять их мы не вправе.
    let base = match level.get() {
        Flaps::Counted(seen) => seen,
        Flaps::Gone => panic!("устройство есть, а уровень говорит `Gone`"),
    };

    // Одно мигание партнёра = две смены несущей: вниз и вверх. Ровно так выглядит сторожевой
    // сброс порта: линк уходит и возвращается, а уровень «сейчас лежит» между замерами исчезает.
    let flapped = std::thread::spawn(|| {
        std::thread::sleep(Duration::from_millis(100));
        ip(&["link", "set", "veth1", "down"])
            && {
                std::thread::sleep(Duration::from_millis(100));
                true
            }
            && ip(&["link", "set", "veth1", "up"])
    });

    let started = std::time::Instant::now();
    let outcome = level.wait_until(
        |seen| *seen == Flaps::Counted(base + 2),
        Duration::from_secs(3),
    );
    let elapsed = started.elapsed();

    assert_eq!(flapped.join().ok(), Some(true), "мигание не состоялось");
    assert_eq!(
        outcome,
        Outcome::Witnessed(Flaps::Counted(base + 2)),
        "счётчик не дошёл ровно до +2: мигание потеряно или посчитано лишнее"
    );
    assert!(
        elapsed < Duration::from_secs(1),
        "разбудил не netlink, а пол: ждали {elapsed:?} при поле 10с"
    );
}
