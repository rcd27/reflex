use reflex_runtime::pid::{PidError, PidGuard};
use std::path::PathBuf;

use std::sync::atomic::{AtomicU32, Ordering};

static COUNTER: AtomicU32 = AtomicU32::new(0);

fn temp_pid_path() -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("geneva-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir.join(format!("test-{n}.pid"))
}

#[test]
fn acquire_clean_start() {
    let path = temp_pid_path();
    let _ = std::fs::remove_file(&path);

    let guard = PidGuard::acquire(path.clone()).unwrap();
    let contents = std::fs::read_to_string(&path).unwrap();
    assert_eq!(contents.trim(), std::process::id().to_string());

    drop(guard);
    assert!(!path.exists());
}

#[test]
fn acquire_stale_pid() {
    let path = temp_pid_path();
    // PID that definitely doesn't exist
    std::fs::write(&path, "4294967295").unwrap();

    let guard = PidGuard::acquire(path.clone()).unwrap();
    let contents = std::fs::read_to_string(&path).unwrap();
    assert_eq!(contents.trim(), std::process::id().to_string());

    drop(guard);
    assert!(!path.exists());
}

#[test]
fn acquire_already_running() {
    let path = temp_pid_path();

    // «Уже запущен» = живой держатель замка, а не просто PID в файле.
    let _held = PidGuard::acquire(path.clone()).unwrap();

    let err = PidGuard::acquire(path.clone()).unwrap_err();
    match err {
        PidError::AlreadyRunning(pid) => assert_eq!(pid, Some(std::process::id())),
        other => panic!("expected AlreadyRunning, got: {other}"),
    }
}

#[test]
fn live_owner_none_when_only_stale_file() {
    let path = temp_pid_path();
    std::fs::write(&path, std::process::id().to_string()).unwrap();

    // Файл есть, но замок никто не держит → демон не запущен.
    assert_eq!(PidGuard::live_owner(&path), None);

    let _ = std::fs::remove_file(&path);
}

#[test]
fn live_owner_reports_pid_while_guard_held() {
    let path = temp_pid_path();
    let _held = PidGuard::acquire(path.clone()).unwrap();

    assert_eq!(PidGuard::live_owner(&path), Some(std::process::id()));
}

#[test]
fn live_owner_none_when_no_file() {
    let path = temp_pid_path();
    let _ = std::fs::remove_file(&path);

    assert_eq!(PidGuard::live_owner(&path), None);
}

// Регрессия контейнерного бага: после рестарта контейнера PID-namespace
// сбрасывается в 1, а pidfile из прошлого прогона остаётся в writable-слое.
// Из-за `exec` демон детерминированно занимает тот же низкий PID, что записан
// в файле — старая проверка `kill(pid, 0)` принимала это за «уже запущен».
// Корректная семантика: нет живого держателя замка → старт разрешён, чей бы
// PID ни лежал в файле.
#[test]
fn acquire_stale_pidfile_with_own_pid_but_no_holder() {
    let path = temp_pid_path();
    std::fs::write(&path, std::process::id().to_string()).unwrap();

    let guard = PidGuard::acquire(path.clone()).expect("stale pidfile must not block startup");

    drop(guard);
    assert!(!path.exists());
}

#[test]
fn acquire_creates_parent_dirs() {
    let dir = std::env::temp_dir()
        .join(format!("geneva-test-{}", std::process::id()))
        .join("nested")
        .join("deep");
    let path = dir.join("daemon.pid");

    let guard = PidGuard::acquire(path.clone()).unwrap();
    assert!(path.exists());

    drop(guard);
    assert!(!path.exists());

    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn acquire_corrupted_pid_file() {
    let path = temp_pid_path();
    std::fs::write(&path, "not-a-number").unwrap();

    let guard = PidGuard::acquire(path.clone()).unwrap();
    let contents = std::fs::read_to_string(&path).unwrap();
    assert_eq!(contents.trim(), std::process::id().to_string());

    drop(guard);
    assert!(!path.exists());
}

/// НОМЕР, КОТОРЫЙ НЕ ПРОЧЁЛСЯ, НЕ ВЫДАЁТСЯ ЗА НУЛЕВОЙ.
///
/// Замок занят живым процессом, а номера в файле нет (демон взял замок и упал до записи; файл
/// обрезан). Прежде отказ нёс `AlreadyRunning(0)` — выдуманный номер, неотличимый от настоящего:
/// читатель шёл искать процесс 0. Клетка (§7) говорит ровно то, что есть: держатель живой, номер
/// неизвестен.
#[test]
fn номер_держателя_который_не_прочёлся_остаётся_неизвестным() {
    let path = temp_pid_path();

    let _held = PidGuard::acquire(path.clone()).unwrap();
    // Держатель жив, но номер в файле стёрт — ровно то состояние, что бывает при падении между
    // взятием замка и записью номера.
    std::fs::write(&path, b"").unwrap();

    match PidGuard::acquire(path.clone()).unwrap_err() {
        PidError::AlreadyRunning(None) => {}
        PidError::AlreadyRunning(Some(pid)) => {
            panic!("номер выдуман там, где его нет: {pid}")
        }
        other => panic!("ожидался занятый замок, вышло: {other}"),
    }
}
