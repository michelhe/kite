//! This module is responsible to interact with the eBPF programs and collect the stats from them.
//! The eBPF programs are attached to cgroups collect the stats of the HTTP requests made to the pods.
//! See loader.rs for a simple example of how to use this module.
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::Context as _;
use aya::Ebpf;
use aya::{
    maps::AsyncPerfEventArray,
    programs::{CgroupAttachMode, CgroupSkb, CgroupSkbAttachType, CgroupSock},
};
use log::{debug, info, warn};
use metrics::{counter, histogram, IntoLabels, Label};
use tokio::{sync::Mutex, task::JoinHandle};
use tokio_util::bytes::BytesMut;

use crate::stats::{Endpoint, SharedHTTPStats};
pub use kite_ebpf_types::{Endpoint as LowLevelEndpoint, HTTPEventKind, HTTPRequestEvent};

async fn process_event(
    event: HTTPRequestEvent,
    stats: SharedHTTPStats,
    cgroup_path: PathBuf,
    extra_labels: Arc<Vec<Label>>,
) {
    let dst = Endpoint::from(event.conn.dst);
    let mut stats = stats.lock().await;
    let map = match event.event_kind {
        HTTPEventKind::OutboundRequest => &mut stats.requests,
        HTTPEventKind::InboundRequest => &mut stats.responses,
    };
    let entry = map.entry(dst).or_default();
    entry.request_count += 1;
    entry.total_bytes += event.total_bytes as u64;
    let duration_ns = event.duration_ns;
    entry.latencies.push(duration_ns); // Convert ns to ms

    let base_metric_name = match event.event_kind {
        HTTPEventKind::OutboundRequest => "kite.http.request.outbound",
        HTTPEventKind::InboundRequest => "kite.http.request.inbound",
    };

    let base_labels = [
        ("endpoint", format!("{:?}", dst)),
        ("cgroup_path", cgroup_path.to_string_lossy().to_string()),
    ]
    .into_labels();

    let labels = base_labels
        .into_iter()
        .chain(extra_labels.iter().cloned())
        .map(|label| (label.key().to_string(), label.value().to_string()))
        .collect::<Vec<_>>();

    histogram!(format!("{base_metric_name}.durtaion"), &labels).record(duration_ns as f64);
    counter!(format!("{base_metric_name}.count"), &labels).increment(1);
    histogram!(format!("{base_metric_name}.bytes"), &labels).record(event.total_bytes as f64);
}

/// Container struct to hold the cgroup eBPF programs and stats.
pub struct KiteEbpf {
    /// The path to the cgroup that the eBPF programs are attached to.
    cgroup_path: PathBuf,

    /// The tokio tasks that collect the stats from the eBPF programs.
    collector_tasks: Vec<JoinHandle<()>>,

    /// The shared stats object to store the stats from the eBPF programs.
    http_stats: SharedHTTPStats,

    /// The owned eBPF object to keep the programs loaded and attached as long as this object is alive.
    ebpf: aya::Ebpf,

    /// Opaque labels to identify the eBPF programs. These are used in the metrics.
    labels: Vec<Label>,
}

impl KiteEbpf {
    /// Loads the ebpf programs into the kernel and attaching them to the cgroup_path.
    pub async fn load(cgroup_path: &Path, labels: impl IntoLabels) -> anyhow::Result<KiteEbpf> {
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
        if program_sock_release.load().is_ok() {
            program_sock_release.attach(cgroup_file.try_clone()?, CgroupAttachMode::default())?;
            loaded_progs.push("kite_sock_release");
        } else {
            warn!("Failed to load kite_sock_release program, skipping for now. TODO fix this, without this program we may leak memory");
        }

        info!("Successfully loadded ebpf with programs {:?}", loaded_progs);

        KiteEbpf::new(ebpf, cgroup_path.to_owned(), labels.into_labels()).await
    }

    async fn new(
        ebpf: aya::Ebpf,
        cgroup_path: PathBuf,
        labels: impl IntoLabels,
    ) -> anyhow::Result<Self> {
        let http_stats = Arc::new(Mutex::new(Default::default()));
        let labels = labels.into_labels();
        let mut ebpf = KiteEbpf {
            cgroup_path,
            collector_tasks: Vec::new(),
            http_stats,
            ebpf,
            labels,
        };
        ebpf.spawn_collectors().await?;
        Ok(ebpf)
    }

    async fn spawn_collectors(&mut self) -> anyhow::Result<()> {
        let events_map = self
            .ebpf
            .take_map("EVENTS")
            .context("Failed to pin EVENTS map")?;

        let mut perf_array = AsyncPerfEventArray::try_from(events_map)?;

        for cpu_id in aya::util::online_cpus().map_err(|(_, error)| error)? {
            let mut buf = perf_array.open(cpu_id, None)?;

            let extra_labels = Arc::new(self.copy_lables());
            let cgroup_path = self.cgroup_path.clone();
            let http_stats = self.http_stats();
            let handle = tokio::task::spawn(async move {
                let mut buffers = (0..10)
                    .map(|_| BytesMut::with_capacity(1024))
                    .collect::<Vec<_>>();

                loop {
                    let events = buf.read_events(&mut buffers).await.unwrap();
                    for buf in buffers.iter_mut().take(events.read) {
                        let ptr = buf.as_ptr() as *const HTTPRequestEvent;
                        let data = unsafe { ptr.read_unaligned() };

                        process_event(
                            data,
                            http_stats.clone(),
                            cgroup_path.clone(),
                            extra_labels.clone(),
                        )
                        .await;
                    }
                }
            });

            self.collector_tasks.push(handle);
        }
        Ok(())
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

    pub fn http_stats(&self) -> SharedHTTPStats {
        self.http_stats.clone()
    }

    pub fn copy_lables(&self) -> Vec<Label> {
        self.labels.clone()
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

/// Convenience struct to manage multiple eBPF programs and their stats.
#[derive(Default)]
pub struct EbpfManager {
    /// cgroup -> ebpf,
    pub ebpfs: BTreeMap<PathBuf, KiteEbpf>,
}

pub type SharedEbpfManager = Arc<Mutex<EbpfManager>>;

impl EbpfManager {
    pub fn new_shared() -> SharedEbpfManager {
        Arc::new(Mutex::new(Default::default()))
    }

    /// Attach the eBPF programs to the cgroup_path and store them in the manager.
    /// The ident is an opaque string that can be used to identify the eBPF programs.
    pub async fn attach_to_cgroup(
        &mut self,
        cgroup_path: &Path,
        extra_labels: impl IntoLabels,
    ) -> anyhow::Result<()> {
        if let Some(existing_cgroup) = self
            .ebpfs
            .keys()
            .find(|&existing_cgroup| cgroup_path.starts_with(existing_cgroup))
        {
            let msg = format!(
                "Cgroup path {:?} is already tracked by parent cgroup {:?}",
                cgroup_path, existing_cgroup
            );
            warn!("{}", msg);
            return Err(anyhow::anyhow!(msg));
        }

        let ebpf = KiteEbpf::load(cgroup_path, extra_labels).await?;

        self.ebpfs.insert(cgroup_path.to_owned(), ebpf);

        Ok(())
    }

    pub async fn drop_all(&mut self) {
        let mut ebpfs = std::mem::take(&mut self.ebpfs);
        ebpfs.clear();
    }

    pub async fn drop(&mut self, cgroup_path: &Path) {
        self.ebpfs.remove(cgroup_path);
    }

    /// Cleanup all the eBPF programs that are attached to cgroups that no longer exist.
    /// Return paths of the cgroups that were removed.
    pub async fn cleanup_exited_cgroups(&mut self) -> Vec<PathBuf> {
        let mut removed_paths = Vec::new();

        for cgroup_path in self.ebpfs.keys().cloned().collect::<Vec<_>>() {
            if !cgroup_path.exists() {
                self.ebpfs.remove(&cgroup_path);
                removed_paths.push(cgroup_path);
            }
        }

        removed_paths
    }
}
