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
    let p = NfqwsProcess::spawn(fixture_path(), vec!["--qnum=200".to_string()])
        .await
        .expect("spawn --qnum");
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(p.is_alive());
    p.kill().await.expect("kill");
}

/// Real nfqws2 binary smoke test. Ignored by default — to run, set
/// NFQWS2_BIN env var to the nfqws2 binary path and use
/// `cargo test -p reflex-linux --test nfqws_subprocess -- --ignored`.
#[tokio::test]
#[ignore = "requires real nfqws2 binary; set NFQWS2_BIN env"]
async fn real_nfqws2_help_runs_clean() {
    let path = std::env::var("NFQWS2_BIN")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            panic!("NFQWS2_BIN env var must point to nfqws2 binary to run this test");
        });
    let p = NfqwsProcess::spawn(path, vec!["--help".to_string()])
        .await
        .expect("spawn real nfqws2 --help");
    let status = tokio::time::timeout(Duration::from_secs(5), p.wait_for_exit())
        .await
        .expect("wait timeout")
        .expect("wait result");
    assert!(
        status.success() || status.code() == Some(0),
        "nfqws2 --help should exit 0, got {:?}",
        status
    );
}
