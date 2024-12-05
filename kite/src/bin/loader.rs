use std::{
    io::Write,
    path::{Path, PathBuf},
};

use clap::Parser;
use env_logger::fmt::Formatter;
use kite::{
    cgroup2,
    ebpf::KiteEbpf,
    utils::{check_kernel_supported, init_prometheus_server, try_remove_rlimit},
};
use log::{info, Record};

#[derive(Parser)]
/// A simple standalone version of kite. The will load the eBPF program and print statistics.
struct Opt {
    /// The path to the cgroup that the eBPF program should attach to.
    /// Defaults to the root cgroup mount. Or you can specify a custom path.
    #[arg(short, long, required = false, default_value = "root")]
    cgroup_path: String,

    #[arg(long, action = clap::ArgAction::SetTrue, required = false)]
    /// Set if you want to see the spammy logs of the eBPF program ELF relocation.
    enable_aya_obj_logs: bool,
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

    let _kite = KiteEbpf::load(&cgroup_path, &extra_labels).await?;

    info!("Prometheus exporter started at http://localhost:9000/metrics");

    // NOTE: the Ebpf object must be kept in scope for the program to run and stay attached.

    tokio::signal::ctrl_c().await?;

    info!("Received Ctrl-C, unloading program");

    Ok(())
}
