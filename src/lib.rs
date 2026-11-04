//! mlsbond: hosts that share a VNI agree on keys through MLS and derive the Security
//! Associations that protect the traffic between each pair of them.

// nested ifs read better than let chains here
#![allow(clippy::collapsible_if, clippy::collapsible_match)]

pub mod proto {
    tonic::include_proto!("mlsbond.v1");
}

pub mod client;
pub mod mls;
pub mod prefix;
pub mod server;

/// Logs to stderr without timestamps (the journal adds them), at info unless RUST_LOG says
/// otherwise.
pub fn init_logging() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into());
    tracing_subscriber::fmt().with_env_filter(filter).without_time().with_target(false).init();
}

/// Resolves on SIGINT or SIGTERM.
pub async fn shutdown_signal() {
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).expect("SIGTERM handler");
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = term.recv() => {}
    }
}
