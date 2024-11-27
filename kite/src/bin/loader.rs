use std::{
    io::Write,
    path::{Path, PathBuf},
    time::Duration,
};

use clap::Parser;
use env_logger::fmt::Formatter;
use kite::{
    cgroup2,
    ebpf::KiteEbpf,
    stats::SharedHTTPStats,
    utils::{check_kernel_supported, init_prometheus_server, try_remove_rlimit},
};
use log::{info, Record};
use tokio::time::interval;

#[derive(Parser)]
/// A simple standalone version of kite. The will load the eBPF program and print statistics.
struct Opt {
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

    #[arg(long, action = clap::ArgAction::SetTrue, required = false)]
    print_stats: bool,
}

async fn print_stats(stats: SharedHTTPStats, stats_interval: u64) {
    let mut interval = interval(Duration::from_secs(stats_interval));
    interval.tick().await; // Skip the first tick as it is always 0
    loop {
        let start = tokio::time::Instant::now();
        interval.tick().await;

        let stats_copy = {
            let mut guard = stats.lock().await;
            std::mem::take(&mut *guard)
        };

        println!("--- Response stats ---");
        for (endpoint, s) in stats_copy.responses.iter() {
            let latency_ms = s.latencies.aggregated() / 1_000_000u64;
            let rps = s.rps(start.elapsed().as_secs());
            let mbps: u64 = s.mbps(start.elapsed().as_secs());
            println!(
                "{}:{} - RPS: {}, Latency {} ms, MBps {}",
                endpoint.addr, endpoint.port, rps, latency_ms, mbps
            );
        }

        println!("--- Request stats ---");
        for (endpoint, s) in stats_copy.requests.iter() {
            let latency_ms = s.latencies.aggregated() / 1_000_000u64;
            let rps = s.rps(start.elapsed().as_secs());
            let mbps: u64 = s.mbps(start.elapsed().as_secs());
            println!(
                "{}:{} - RPS: {}, Latency {} ms, MBps {}",
                endpoint.addr, endpoint.port, rps, latency_ms, mbps
            );
        }
    }
}

fn init_logger(opt: &Opt, cgroup_path: &Path) -> anyhow::Result<()> {
    let mut builder = env_logger::Builder::from_default_env();
    let cgroup_path = cgroup_path.to_owned();
    let ident = format!("cgroup={}", cgroup_path.display());
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

    let cgroup_path = match opt.cgroup_path.as_str() {
        "root" => cgroup2::find_cgroup2_mount(),
        _ => PathBuf::from(&opt.cgroup_path),
    };

    init_logger(&opt, &cgroup_path)?;

    info!("Starting loader on cgroup {:?}", &cgroup_path);

    check_kernel_supported()?;

    try_remove_rlimit();

    init_prometheus_server()?;

    let extra_labels = [(
        "hostname",
        std::fs::read_to_string("/proc/sys/kernel/hostname")?,
    )];

    let kite = KiteEbpf::load(&cgroup_path, &extra_labels).await?;

    if opt.print_stats {
        // Start the periodic task to print statistics
        tokio::spawn(print_stats(kite.http_stats(), opt.stats_interval));
    }

    // NOTE: the Ebpf object must be kept in scope for the program to run and stay attached.

    tokio::signal::ctrl_c().await?;

    info!("Received Ctrl-C, unloading program");

    Ok(())
}
