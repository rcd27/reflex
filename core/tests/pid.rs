use reflex_core::pid::{PidError, PidGuard};
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
    std::fs::write(&path, std::process::id().to_string()).unwrap();

    let err = PidGuard::acquire(path.clone()).unwrap_err();
    match err {
        PidError::AlreadyRunning(pid) => assert_eq!(pid, std::process::id()),
        other => panic!("expected AlreadyRunning, got: {other}"),
    }

    let _ = std::fs::remove_file(&path);
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
