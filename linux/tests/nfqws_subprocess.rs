//! Subprocess primitive tests against a fixture script that mimics nfqws2.

use std::path::PathBuf;
use std::time::Duration;

use reflex_linux::nfqws::NfqwsProcess;

fn fixture_path() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir.join("tests/fixtures/fake-nfqws.sh")
}

#[tokio::test]
async fn spawn_help_completes_quickly() {
    let p = NfqwsProcess::spawn(fixture_path(), vec!["--help".to_string()])
        .await
        .expect("spawn --help");
    let timeout = tokio::time::timeout(Duration::from_secs(5), p.wait_for_exit()).await;
    assert!(timeout.is_ok(), "process did not exit within timeout");
}

#[tokio::test]
async fn spawn_with_qnum_keeps_running_until_killed() {
    let p = NfqwsProcess::spawn(
        fixture_path(),
        vec!["--qnum=200".to_string()],
    )
    .await
    .expect("spawn --qnum");
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(p.is_alive());
    p.kill().await.expect("kill");
}
