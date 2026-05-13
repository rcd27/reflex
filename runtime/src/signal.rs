/// Wait for a shutdown signal (platform-specific).
///
/// - Unix (Linux, macOS): resolves on SIGINT, SIGTERM, or SIGHUP (whichever comes first).
/// - Windows: resolves on Ctrl+C or console close event.
///
/// This replaces `tokio::signal::ctrl_c()` in daemon code to handle
/// all standard termination signals.
pub async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};

        let mut sigint = signal(SignalKind::interrupt()).expect("failed to register SIGINT");
        let mut sigterm = signal(SignalKind::terminate()).expect("failed to register SIGTERM");
        let mut sighup = signal(SignalKind::hangup()).expect("failed to register SIGHUP");

        tokio::select! {
            _ = sigint.recv() => {},
            _ = sigterm.recv() => {},
            _ = sighup.recv() => {},
        }
    }

    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to register Ctrl+C handler");
    }
}
