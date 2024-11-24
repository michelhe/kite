use std::time::Duration;

use anyhow::Context as _;
use aya::util::KernelVersion;
use log::debug;
use metrics_exporter_prometheus::PrometheusBuilder;
use metrics_util::MetricKindMask;

/// We use eBPF features that are only available in newer kernels. Check if the kernel is supported.
pub fn check_kernel_supported() -> anyhow::Result<()> {
    let version = KernelVersion::current()?;
    if version < KernelVersion::new(4, 10, 0) {
        return Err(anyhow::anyhow!(
            "Kernel version {} is not supported. Must be at least 4.10.0",
            version
        ));
    }
    Ok(())
}

pub fn try_remove_rlimit() {
    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }
}

pub fn init_prometheus_server() -> anyhow::Result<()> {
    PrometheusBuilder::new()
        .idle_timeout(
            MetricKindMask::COUNTER | MetricKindMask::HISTOGRAM,
            Some(Duration::from_secs(10)),
        )
        .install()
        .context("Failed to install prometheus server")?;
    Ok(())
}
