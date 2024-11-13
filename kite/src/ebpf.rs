//! This module is responsible to interact with the eBPF programs and collect the stats from them.
//! The eBPF programs are attached to cgroups collect the stats of the HTTP requests made to the pods.
//! See loader.rs for a simple example of how to use this module.
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr},
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::Context as _;
// Re-exports
pub use aya::Ebpf;
use aya::{
    maps::AsyncPerfEventArray,
    programs::{CgroupAttachMode, CgroupSkb, CgroupSkbAttachType, CgroupSock},
};
pub use kite_ebpf_common::{Endpoint as LowLevelEndpoint, HTTPRequestEvent};
use log::{debug, info};
use tokio::{sync::Mutex, task::JoinHandle};
use tokio_util::bytes::BytesMut;

#[derive(Debug, Default, Clone)]
pub struct Stats {
    request_count: u64,
    latencies: Vec<u64>,
}

impl Stats {
    pub fn request_count(&self) -> u64 {
        self.request_count
    }

    pub fn latencies(&self) -> &[u64] {
        &self.latencies
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct Endpoint {
    pub addr: IpAddr,
    pub port: u16,
}

impl From<LowLevelEndpoint> for Endpoint {
    fn from(endpoint: LowLevelEndpoint) -> Self {
        Self {
            addr: IpAddr::V4(Ipv4Addr::from(endpoint.addr)),
            port: endpoint.port,
        }
    }
}

pub type SharedStats = Arc<Mutex<HashMap<Endpoint, Stats>>>;

async fn process_event(event: HTTPRequestEvent, stats: SharedStats) {
    let dst = Endpoint::from(event.conn.dst);
    let mut stats = stats.lock().await;
    let entry = (*stats).entry(dst).or_default();
    entry.request_count += 1;
    entry
        .latencies
        .push(event.end_time_ns - event.start_time_ns);
}

async fn spawn_collectors(
    ebpf: &mut Ebpf,
    stats: SharedStats,
) -> anyhow::Result<Vec<JoinHandle<()>>> {
    let events_map = ebpf
        .take_map("EVENTS")
        .context("Failed to pin EVENTS map")?;

    let mut perf_array = AsyncPerfEventArray::try_from(events_map)?;

    let mut tasks = Vec::new();
    for cpu_id in aya::util::online_cpus().map_err(|(_, error)| error)? {
        let mut buf = perf_array.open(cpu_id, None)?;

        let stats = stats.clone();
        let handle = tokio::task::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(1024))
                .collect::<Vec<_>>();

            loop {
                let events = buf.read_events(&mut buffers).await.unwrap();
                for buf in buffers.iter_mut().take(events.read) {
                    let ptr = buf.as_ptr() as *const HTTPRequestEvent;
                    let data = unsafe { ptr.read_unaligned() };

                    process_event(data, stats.clone()).await;
                }
            }
        });

        tasks.push(handle);
    }
    Ok(tasks)
}

/// Container struct to hold the cgroup eBPF programs and stats.
pub struct KiteEbpf {
    ebpf: Ebpf,
    cgroup_path: PathBuf,
    collector_tasks: Vec<JoinHandle<()>>,
    stats: SharedStats,
}

impl KiteEbpf {
    pub async fn new(mut ebpf: Ebpf, cgroup_path: PathBuf) -> KiteEbpf {
        let stats = Arc::new(Mutex::new(HashMap::new()));
        let collector_tasks = spawn_collectors(&mut ebpf, stats.clone())
            .await
            .expect("Failed to create event collectors");
        KiteEbpf {
            ebpf,
            cgroup_path,
            collector_tasks,
            stats: stats.clone(),
        }
    }

    pub fn cgroup_path(&self) -> &Path {
        &self.cgroup_path
    }

    pub fn ebpf(&self) -> &Ebpf {
        &self.ebpf
    }

    pub fn ebpf_mut(&mut self) -> &mut Ebpf {
        &mut self.ebpf
    }

    pub fn stats(&self) -> SharedStats {
        self.stats.clone()
    }
}

impl Drop for KiteEbpf {
    fn drop(&mut self) {
        debug!("Dropping KiteEbpf for cgroup path: {:?}", self.cgroup_path);
        // Cancel all the collector tasks
        for task in self.collector_tasks.drain(..) {
            task.abort();
        }
    }
}
/// Code for loading the ebpf programs into the kernel.
pub async fn load_and_attach_kite_ebpf(cgroup_path: &Path) -> anyhow::Result<KiteEbpf> {
    info!("Loading program for cgroup path: {:?}", cgroup_path);

    let mut ebpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/kite"
    )))?;

    let cgroup_file = std::fs::File::open(cgroup_path)
        .with_context(|| format!("Failed to open cgroup file: {:?}", cgroup_path))?;

    aya_log::EbpfLogger::init(&mut ebpf).context("Failed to initialize eBPF logger")?;

    let mut loaded_progs = Vec::new();
    // Load and attach the ingress cgroup skb program
    let program_ig: &mut CgroupSkb = ebpf
        .program_mut("kite_ingress")
        .context("Failed to get program")?
        .try_into()?;
    program_ig.load()?;
    program_ig.attach(
        cgroup_file.try_clone()?,
        CgroupSkbAttachType::Ingress,
        CgroupAttachMode::default(),
    )?;
    loaded_progs.push("kite_ingress");

    // Load and attach the egress cgroup skb program
    let program_eg: &mut CgroupSkb = ebpf
        .program_mut("kite_egress")
        .context("Failed to get program")?
        .try_into()?;
    program_eg.load()?;
    program_eg.attach(
        cgroup_file.try_clone()?,
        CgroupSkbAttachType::Egress,
        CgroupAttachMode::default(),
    )?;
    loaded_progs.push("kite_egress");

    // Load and attach the egress cgroup sock program
    let program_sock_release: &mut CgroupSock = ebpf
        .program_mut("kite_sock_release")
        .context("Failed to get program")?
        .try_into()?;
    program_sock_release.load()?;
    program_sock_release.attach(cgroup_file.try_clone()?, CgroupAttachMode::default())?;
    loaded_progs.push("kite_sock_release");

    info!(
        "Successfully loadded ebpf with programs {:?}",
        ebpf.programs().map(|(name, _)| name).collect::<Vec<_>>()
    );

    Ok(KiteEbpf::new(ebpf, cgroup_path.to_owned()).await)
}

/// Convenience struct to manage multiple eBPF programs and their stats.
pub struct EbpfManager {
    /// cgroup_path -> ebpf,
    ebpfs: Arc<Mutex<HashMap<String, KiteEbpf>>>,
}

pub type SharedEbpfManager = Arc<Mutex<EbpfManager>>;

impl EbpfManager {
    pub fn new_shared() -> SharedEbpfManager {
        Arc::new(Mutex::new(EbpfManager {
            ebpfs: Arc::new(Mutex::new(HashMap::new())),
        }))
    }

    pub async fn add(&self, kite: KiteEbpf) {
        self.ebpfs
            .lock()
            .await
            .insert(kite.cgroup_path().to_string_lossy().to_string(), kite);
    }

    pub async fn drop_all(&self) {
        let mut ebpfs = self.ebpfs.lock().await;
        ebpfs.clear();
    }

    pub async fn drop(&self, cgroup_path: &Path) {
        self.ebpfs
            .lock()
            .await
            .remove(cgroup_path.to_string_lossy().as_ref());
    }
}
