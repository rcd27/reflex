//! Витнес настоящего link-события от ЯДРА (#152), а не сымитированного пайпом.
//!
//! Тест сам переисполняет себя внутри свежего сетевого namespace
//! (`unshare -Ur --net`): непривилегированный userns даёт CAP_NET_ADMIN над СВОИМ
//! netns, значит устройство можно завести по-настоящему, и `RTM_NEWLINK` придёт от
//! ядра, а не от тестовой обвязки. Без этого тест на подсказку был бы фикцией:
//! пайп доказывает, что `poll` работает, но не доказывает, что мы подписаны на
//! link-группу.
//!
//! Оракул — ВРЕМЯ. Пол выставлен заведомо недостижимым (10с) при дедлайне 3с, так
//! что разбудить может ТОЛЬКО подсказка. Уровень без подписи доедет к дедлайну и
//! вернёт ту же `Witnessed(true)` — по значению тест зелен и без netlink, и потому
//! значение здесь ничего не судит.

use reflex_os::{link, Outcome};
use std::time::Duration;

const IN_NETNS: &str = "REFLEX_OS_IN_NETNS";
const CASE: &str = "netlink_wakes_on_kernel_link_event";

#[test]
fn netlink_wakes_on_kernel_link_event() {
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

    // `--mount --propagation private` обязателен вместе с `--net`: sysfs НЕ следует за
    // сетевым namespace сам по себе — `/sys/class/net` продолжал бы показывать
    // устройства РОДИТЕЛЬСКОГО netns, и уровень честно не видел бы созданного dummy0.
    // (На коробке этого расхождения нет: Смотритель живёт в корневом netns.)
    let child = std::process::Command::new("unshare")
        .args(["-Ur", "--net", "--mount", "--propagation", "private"])
        .arg(&path)
        .args([CASE, "--exact", "--nocapture", "--test-threads=1"])
        .env(IN_NETNS, "1")
        .status();

    // Провал ЗАПУСКА не глушим: молчаливый пропуск превратил бы витнес в украшение.
    assert!(
        child.is_ok(),
        "не запустился `unshare -Ur --net` — витнес не предъявлен, а не «пропущен»"
    );
    assert!(
        child.map(|st| st.success()).unwrap_or(false),
        "проход внутри netns провалился"
    );
}

/// Внутренний проход: мы в своём netns и вправе завести устройство.
fn inside_fresh_netns() {
    // Перемонтировать sysfs, чтобы `/sys/class/net` описывал НАШ netns, а не родительский.
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

    // Пол недостижим намеренно: всё, что быстрее дедлайна, — заслуга подсказки.
    let level = link::present("dummy0", Duration::from_secs(10));
    assert!(level.is_ok(), "netlink-уровень не завёлся");

    let born = std::thread::spawn(|| {
        std::thread::sleep(Duration::from_millis(100));
        std::process::Command::new("ip")
            .args(["link", "add", "dummy0", "type", "dummy"])
            .status()
            .map(|st| st.success())
            .unwrap_or(false)
    });

    let started = std::time::Instant::now();
    let outcome = level.map(|l| l.wait_until(|up| *up, Duration::from_secs(3)));
    let elapsed = started.elapsed();

    let created = born.join();
    assert_eq!(created.ok(), Some(true), "устройство не завелось в netns");
    assert_eq!(outcome.ok(), Some(Outcome::Witnessed(true)));
    assert!(
        elapsed < Duration::from_secs(1),
        "разбудил не netlink, а пол: ждали {elapsed:?} при поле 10с"
    );
}
