//! Experimental CONNECT-UDP transport. No claim of DPI indistinguishability.
pub mod auth;
pub mod capsule;
pub mod client;
pub mod config;
pub mod server;
pub mod tls;

pub(crate) async fn idle_timeout(
    mut activity: tokio::sync::watch::Receiver<tokio::time::Instant>,
    idle: std::time::Duration,
) {
    loop {
        let deadline = *activity.borrow_and_update() + idle;
        tokio::select! {
            _ = tokio::time::sleep_until(deadline) => return,
            changed = activity.changed() => if changed.is_err() { return; },
        }
    }
}

pub async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("install SIGTERM handler");
        tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = terminate.recv() => {} }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
