//! mlsbond-client: a host's member in its VNI groups, driven by the host's orchestrator.

use std::net::SocketAddr;
use std::time::Duration;

use clap::Parser;
use mlsbond::client;

#[derive(Parser)]
#[command(about = "mlsbond client: a host's member in its VNI groups")]
struct Args {
    /// address of the client API the orchestrator connects to
    #[arg(long, default_value = "[::1]:4714")]
    listen: SocketAddr,
    /// the mlsbond server, host:port
    #[arg(long)]
    server: String,
    /// key packages kept uploaded at the server
    #[arg(long, default_value_t = 8)]
    key_packages: usize,
    /// seconds pairs from before a rejoin wait for their peer to join too
    #[arg(long, default_value_t = 60.0)]
    stale_pairs_after: f64,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    mlsbond::init_logging();
    let args = Args::parse();
    let api = client::start(client::Config {
        server: args.server,
        key_packages: args.key_packages,
        stale_pairs_after: Duration::from_secs_f64(args.stale_pairs_after),
    });
    // the orchestrator's stream never ends on its own, so a signal ends the process at once
    tokio::select! {
        r = tonic::transport::Server::builder().add_service(api).serve(args.listen) => r?,
        _ = mlsbond::shutdown_signal() => tracing::info!("stopping"),
    }
    Ok(())
}
