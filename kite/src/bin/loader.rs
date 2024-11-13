use std::{io::Write, path::PathBuf, time::Duration};

use clap::Parser;
use env_logger::fmt::Formatter;
use kite::{
    cgroup2,
    ebpf::{load_and_attach_kite_ebpf, SharedStats},
    utils::{check_kernel_supported, try_remove_rlimit},
};
use log::{info, Record};
use tokio::time::interval;

#[derive(Parser)]
/// A simple standalone version of kite. The will load the eBPF program and print statistics.
struct Opt {
    /// The identifier of the cgroup. i.e In k8s this will be {pod}-{namespace}
    ident: String,

    /// The path to the cgroup that the eBPF program should attach to.
    /// Defaults to the root cgroup mount. Or you can specify a custom path.
    #[arg(short, long, required = false, default_value = "root")]
    cgroup_path: String,

    #[arg(short, long, default_value = "10")]
    /// The interval at which to collect statistics, in seconds.
    stats_interval: u64,

    #[arg(long, action = clap::ArgAction::SetTrue, required = false)]
    /// Set if you want to see the spammy logs of the eBPF program ELF relocation.
    enable_aya_obj_logs: bool,
}

async fn print_stats(stats: SharedStats, stats_interval: u64) {
    let mut interval = interval(Duration::from_secs(stats_interval));
    loop {
        interval.tick().await;
        let mut stats = stats.lock().await;
        let stats_copy = stats.clone();
        *stats = Default::default();
        drop(stats);
        for (endpoint, stat) in stats_copy.iter() {
            let mut latencies = stat.latencies().to_vec();
            latencies.sort_unstable();
            let p50 = latencies[latencies.len() / 2];
            let p90 = latencies[(latencies.len() * 90) / 100];
            let p99 = latencies[(latencies.len() * 99) / 100];
            info!(
                "{}:{} - RPS: {}, Latency (p50/p90/p99): {}/{}/{} ms",
                endpoint.addr,
                endpoint.port,
                stat.request_count() / interval.period().as_secs(),
                p50 / 1_000_000,
                p90 / 1_000_000,
                p99 / 1_000_000,
            );
        }
    }
}

fn init_logger(opt: &Opt) -> anyhow::Result<()> {
    let mut builder = env_logger::Builder::from_default_env();
    let ident = opt.ident.clone();
    builder
        .format(move |buf: &mut Formatter, record: &Record| {
            writeln!(
                buf,
                "[{}] [{}] [{}] {}",
                record.level(),
                record.target(),
                ident,
                record.args()
            )
        })
        .format_timestamp(Some(env_logger::TimestampPrecision::Millis));

    if !opt.enable_aya_obj_logs {
        // Reduce noise from aya_obj logs
        builder.filter_module("aya_obj", log::LevelFilter::Error);
    }

    builder.init();

    Ok(())
}

#[tokio::main]
pub async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();
    init_logger(&opt)?;

    let cgroup_path = match opt.cgroup_path.as_str() {
        "root" => cgroup2::find_cgroup2_mount(),
        _ => PathBuf::from(&opt.cgroup_path),
    };

    info!(
        "Starting loader on cgroup {:?} with ident: {}",
        &cgroup_path, opt.ident
    );

    check_kernel_supported()?;

    try_remove_rlimit();

    let kite = load_and_attach_kite_ebpf(&cgroup_path).await?;

    // Start the periodic task to print statistics
    tokio::spawn(print_stats(kite.stats(), opt.stats_interval));

    // NOTE: the Ebpf object must be kept in scope for the program to run and stay attached.

    tokio::signal::ctrl_c().await?;

    info!("Received Ctrl-C, unloading program");

    Ok(())
}
