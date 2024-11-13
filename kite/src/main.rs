use std::time::Duration;

use clap::Parser;
use kite::{
    daemon::start_init_hook_server,
    ebpf::SharedEbpfManager,
    ipc::get_kite_sock,
    utils::{check_kernel_supported, try_remove_rlimit},
};
use tokio::time::interval;
use tracing::{info, Level};

#[derive(Parser, Debug)]
#[command(name = "kite")]
#[command(bin_name = "kite")]
#[command(version, about, long_about = None)]
#[command(propagate_version = true)]
pub struct KiteDaemonArgs {
    /// The namespace to watch for pods.
    #[arg(short, long)]
    namespace: Option<String>,

    /// The label selector to filter pods.
    /// Default is None.
    /// Example: "app=nginx"
    #[arg(long)]
    label_selector: Option<String>,

    /// The field selector to filter pods.
    /// Default is None.
    /// Example: "status.phase=Running"
    #[arg(long)]
    field_selector: Option<String>,
}

async fn print_stats(ebpf_manager: SharedEbpfManager) {
    let mut interval = interval(Duration::from_secs(5));
    loop {
        interval.tick().await;
        for (ident, kite) in ebpf_manager.lock().await.ebpfs.lock().await.iter() {
            for (endpoint, stats) in kite.stats().lock().await.iter() {
                info!(
                    "[{}] Stats for {:?}:{} RPS: {}, Latency (p50/p90/p99): {}/{}/{} ms",
                    ident,
                    endpoint.addr,
                    endpoint.port,
                    stats.request_count() / 5,
                    stats.latencies()[0] / 1_000_000,
                    stats.latencies()[1] / 1_000_000,
                    stats.latencies()[2] / 1_000_000,
                );
            }
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let subscriber = tracing_subscriber::FmtSubscriber::builder()
        // all spans/events with a level higher than TRACE (e.g, debug, info, warn, etc.)
        // will be written to stdout.
        .with_max_level(Level::DEBUG)
        // builds the subscriber.
        .finish();

    tracing::subscriber::set_global_default(subscriber)?;

    // Parse the CLI arguments
    let args = KiteDaemonArgs::try_parse()?;
    info!("Parsed CLI arguments: {:?}", args);

    try_remove_rlimit();

    check_kernel_supported()?;

    let kite_sock = get_kite_sock();

    if kite_sock.exists() {
        std::fs::remove_file(&kite_sock)?;
    }

    // Create the directory for the socket (recursively)
    std::fs::create_dir_all(kite_sock.parent().unwrap())?;

    let ebpf_m = kite::ebpf::EbpfManager::new_shared();
    let ebpf_m_2 = ebpf_m.clone();
    // Spawn the init hook server in the background
    tokio::spawn(async move {
        let r = start_init_hook_server(&kite_sock, ebpf_m.clone()).await;
        if let Err(e) = r {
            tracing::error!("Error starting init hook server: {:?}", e);
        }
    });

    tokio::spawn(print_stats(ebpf_m_2.clone()));

    tracing::info!("Kite Daemon started, press Ctrl+C to stop");

    tokio::signal::ctrl_c().await?;

    tracing::info!("Exiting");

    info!("Exiting");
    Ok(())
}
