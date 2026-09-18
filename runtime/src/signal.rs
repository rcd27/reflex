/// ПРОСЬБА ЗАВЕРШИТЬСЯ — ОДНА ДВЕРЬ НА ВСЕ ШТАТНЫЕ СИГНАЛЫ, а не на один. Unix: первый пришедший
/// из SIGINT, SIGTERM, SIGHUP. Прочие платформы: Ctrl+C либо закрытие консоли.
///
/// `tokio::signal::ctrl_c()` на эту роль не годится: systemd и docker просят демона уйти SIGTERM,
/// и слушающий один SIGINT по просьбе НЕ выходит — его добивают по истечении срока, то есть
/// SIGKILL, на котором корректного завершения уже нет. Отдельная дверь на сигнал завела бы вторую
/// точку решения о выходе, и две разошлись бы молча; дверь здесь одна.
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
