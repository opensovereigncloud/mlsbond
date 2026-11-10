//! mlsbond-client: a host's member in its VNI groups, driven by the host's orchestrator.

use std::net::SocketAddr;
use std::time::Duration;

use clap::{Parser, Subcommand};
use mlsbond::client;
use mlsbond::proto;
use mlsbond::proto::client_api_client::ClientApiClient;

#[derive(Parser)]
#[command(about = "mlsbond client: a host's member in its VNI groups", args_conflicts_with_subcommands = true, subcommand_negates_reqs = true)]
struct Args {
    #[command(subcommand)]
    command: Option<Command>,
    /// address of the client API the orchestrator connects to
    #[arg(long, default_value = "[::1]:4752")]
    listen: SocketAddr,
    /// the mlsbond server, host:port
    #[arg(long, required = true)]
    server: Option<String>,
    /// key packages kept uploaded at the server
    #[arg(long, default_value_t = 8)]
    key_packages: usize,
    /// seconds pairs from before a rejoin wait for their peer to join too
    #[arg(long, default_value_t = 60.0)]
    stale_pairs_after: f64,
}

#[derive(Subcommand)]
enum Command {
    /// Show what a running mlsbond client holds: its VNIs and pairs, each with its epoch, SPIs and what it waits on
    Status {
        /// the client API of the mlsbond client
        #[arg(long, default_value = "[::1]:4752")]
        address: SocketAddr,
    },
}

/// One line per pair, as the harness and its users read it. Keys are not part of the status.
fn print_status(st: &proto::StatusResponse) {
    println!("client {}, host prefix {}", st.client_name, st.host_prefix);
    println!(
        "server {}, orchestrator {}",
        if st.server_connected { "connected" } else { "not connected" },
        if st.orchestrator_connected { "connected" } else { "not connected" }
    );
    println!("vnis: {}", st.vnis.iter().map(u32::to_string).collect::<Vec<_>>().join(" "));
}

/// The pairs from one orchestrator's side. With a name, each line ends in it.
fn print_pairs(st: &proto::StatusResponse, orchestrator: &str) {
    for p in &st.pairs {
        let mut line = format!(
            "vni {} pair {}: epoch {}, spi out {} in {}",
            p.vni,
            p.peer_host_prefix,
            p.pair_epoch.map_or("-".to_string(), |e| e.to_string()),
            p.egress_spi,
            p.ingress_spis.iter().map(u32::to_string).collect::<Vec<_>>().join(",")
        );
        if let Some(target) = p.target_epoch {
            line += &format!(", moving to epoch {target}");
        }
        line += &format!(", waiting: {}", waiting_name(p.waiting()));
        if !p.last_error.is_empty() {
            line += &format!(", last error: {}", p.last_error);
        }
        if !orchestrator.is_empty() {
            line += &format!(", orchestrator {orchestrator}");
        }
        println!("{line}");
    }
}

fn waiting_name(waiting: proto::Waiting) -> &'static str {
    match waiting {
        proto::Waiting::Nothing => "nothing",
        proto::Waiting::Ingress => "ingress",
        proto::Waiting::PeerReady => "peer-ready",
        proto::Waiting::Egress => "egress",
        proto::Waiting::PeerSwitched => "peer-switched",
        proto::Waiting::Remove => "remove",
    }
}

async fn status(address: SocketAddr) -> anyhow::Result<()> {
    let mut api = ClientApiClient::connect(format!("http://{address}")).await?;
    let st = api.status(proto::StatusRequest::default()).await?.into_inner();
    print_status(&st);
    if st.orchestrators.iter().all(|o| o.name.is_empty()) {
        print_pairs(&st, "");
    }
    for o in st.orchestrators.iter().filter(|o| !o.name.is_empty()) {
        println!("orchestrator {}: {}", o.name, if o.connected { "connected" } else { "not connected" });
        let request = proto::StatusRequest { orchestrator: o.name.clone() };
        print_pairs(&api.status(request).await?.into_inner(), &o.name);
    }
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    if let Some(Command::Status { address }) = args.command {
        return status(address).await;
    }
    mlsbond::init_logging();
    let api = client::start(client::Config {
        // clap requires it unless there is a subcommand
        server: args.server.expect("--server"),
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
