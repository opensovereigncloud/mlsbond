//! mlsbond-server: the Delivery Service every mlsbond client connects to.

use std::net::SocketAddr;
use std::time::Duration;

use clap::Parser;
use mlsbond::server;

#[derive(Parser)]
#[command(about = "mlsbond server: the Delivery Service of every VNI group")]
struct Args {
    /// address of the delivery stream the mlsbond clients connect to
    #[arg(long, default_value = "[::]:4712")]
    listen: SocketAddr,
    /// address of the admin API
    #[arg(long, default_value = "[::1]:4713")]
    admin_listen: SocketAddr,
    /// seconds a member's stream may be gone before it is removed from its VNI groups
    #[arg(long, default_value_t = 10.0)]
    removal_grace: f64,
    /// milliseconds pending changes are collected before a commit is asked for
    #[arg(long, default_value_t = 200)]
    commit_delay_ms: u64,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    mlsbond::init_logging();
    let args = Args::parse();
    let (delivery, admin) = server::start(server::Config {
        removal_grace: Duration::from_secs_f64(args.removal_grace),
        commit_delay: Duration::from_millis(args.commit_delay_ms),
    });
    let delivery = tonic::transport::Server::builder()
        .http2_keepalive_interval(Some(Duration::from_secs(5)))
        .http2_keepalive_timeout(Some(Duration::from_secs(5)))
        .add_service(delivery)
        .serve(args.listen);
    let admin = tonic::transport::Server::builder().add_service(admin).serve(args.admin_listen);
    // the delivery streams never end on their own, so a signal ends the process at once
    tokio::select! {
        r = async { tokio::try_join!(delivery, admin) } => { r?; }
        _ = mlsbond::shutdown_signal() => tracing::info!("stopping"),
    }
    Ok(())
}
