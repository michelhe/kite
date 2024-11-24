use std::time::Duration;

use clap::Parser;
use kite::{
    ebpf::SharedEbpfManager,
    ipc::{get_kite_sock, ipc_server_task},
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
    interval.tick().await; // Skip the first tick as it is always 0
    loop {
        let start = tokio::time::Instant::now();
        interval.tick().await;
        for kite in ebpf_manager.lock().await.ebpfs.values() {
            let http_stats = kite.http_stats();
            let mut http_stats = http_stats.lock().await;
            let http_stats = std::mem::take(&mut *http_stats);

            info!("[{}] --- Response stats ---", kite.ident);
            for (endpoint, s) in http_stats.responses.iter() {
                let rps = s.rps(start.elapsed().as_secs());
                let mbps = s.mbps(start.elapsed().as_secs());
                let latency = s.latencies.aggregated();
                info!(
                    "[{}] Stats for {:?}:{} RPS: {}, Latency {} ms, MBps {}",
                    kite.ident, endpoint.addr, endpoint.port, rps, latency, mbps
                );
            }

            info!("[{}] --- Requests stats ---", kite.ident);
            for (endpoint, s) in http_stats.requests.iter() {
                let rps = s.rps(start.elapsed().as_secs());
                let mbps = s.mbps(start.elapsed().as_secs());
                let latency = s.latencies.aggregated();
                info!(
                    "[{}] Stats for {:?}:{} RPS: {}, Latency {} ms, MBps {}",
                    kite.ident, endpoint.addr, endpoint.port, rps, latency, mbps
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
    let ebpf_m_3 = ebpf_m.clone();

    tokio::spawn(async move {
        let r = ipc_server_task(&kite_sock, ebpf_m.clone()).await;
        if let Err(e) = r {
            tracing::error!("Error starting init hook server: {:?}", e);
        }
    });

    tokio::spawn(print_stats(ebpf_m_2.clone()));

    tokio::spawn(async move {
        let mut interval = interval(Duration::from_secs(5));
        interval.tick().await; // Skip the first tick as it is always 0
        loop {
            interval.tick().await;
            let removed = ebpf_m_3.lock().await.cleanup_exited_cgroups().await;
            if !removed.is_empty() {
                tracing::info!("Removed {} ebpfs", removed.len());
            }
        }
    });

    tracing::info!("Kite Daemon started, press Ctrl+C to stop");

    tokio::signal::ctrl_c().await?;

    tracing::info!("Exiting");

    info!("Exiting");
    Ok(())
}
