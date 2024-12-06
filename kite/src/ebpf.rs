//! This module is responsible to interact with the eBPF programs and collect the stats from them.
//! The eBPF programs are attached to cgroups collect the stats of the HTTP requests made to the pods.
//! See loader.rs for a simple example of how to use this module.
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::Context as _;
use aya::{
    maps::AsyncPerfEventArray,
    programs::{CgroupAttachMode, CgroupSkb, CgroupSkbAttachType, CgroupSock},
    Ebpf,
};
use log::{debug, info, warn};
use metrics::{IntoLabels, Label};
use tokio::{
    sync::{mpsc::channel, Mutex},
    task::JoinHandle,
};

use crate::{
    metrics::process_cgroup_http_event,
    perf_reader::{PerfReadTask, PerfReadTaskMessage},
    stats::{HTTPStats, SharedHTTPStats},
};
pub use kite_ebpf_types::{Endpoint as LowLevelEndpoint, HTTPEventKind, HTTPRequestEvent};

/// Container struct to hold the cgroup eBPF programs and stats.
pub struct KiteEbpf {
    /// The path to the cgroup that the eBPF programs are attached to.
    cgroup_path: PathBuf,

    /// The tokio tasks that collect the stats from the eBPF programs.
    tasks: Vec<JoinHandle<()>>,

    /// The shared stats object to store the stats from the eBPF programs.
    http_stats: SharedHTTPStats,

    /// The owned eBPF object to keep the programs loaded and attached as long as this object is alive.
    #[allow(dead_code)]
    ebpf: aya::Ebpf,
}

impl KiteEbpf {
    /// Loads the ebpf programs into the kernel and attaching them to the cgroup_path.
    /// The returned object must be in scope as long as the eBPF programs are needed.
    /// The eBPF programs will be detached and unloaded when the object is dropped.
    ///
    /// cgroup_path: The path to the cgroup that the eBPF programs will be attached to.
    /// base_labels: The labels to attach to the metrics collected by the eBPF programs.
    pub async fn load(
        cgroup_path: &Path,
        base_labels: impl IntoLabels,
    ) -> anyhow::Result<KiteEbpf> {
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

        KiteEbpf::new(ebpf, cgroup_path.to_owned(), base_labels.into_labels()).await
    }

    async fn new(
        mut ebpf: aya::Ebpf,
        cgroup_path: PathBuf,
        base_labels: impl IntoLabels,
    ) -> anyhow::Result<Self> {
        let http_stats = Arc::new(Mutex::new(Default::default()));
        let base_labels = base_labels.into_labels();

        let mut tasks = Vec::new();

        KiteEbpf::spawn_collectors(
            &mut ebpf,
            &mut tasks,
            http_stats.clone(),
            &cgroup_path,
            base_labels,
        )
        .await?;

        Ok(KiteEbpf {
            ebpf,
            cgroup_path,
            tasks,
            http_stats,
        })
    }

    async fn spawn_collectors(
        ebpf: &mut Ebpf,
        tasks: &mut Vec<JoinHandle<()>>,
        http_stats: Arc<Mutex<HTTPStats>>,
        cgroup_path: &Path,
        base_labels: Vec<Label>,
    ) -> anyhow::Result<()> {
        let events_map = ebpf
            .take_map("EVENTS")
            .context("Failed to pin EVENTS map")?;

        let mut perf_array = AsyncPerfEventArray::try_from(events_map)?;

        let http_status_cloned = http_stats.clone();
        let cgroup_path = cgroup_path.to_owned();

        let (sender, mut receiver) = channel::<PerfReadTaskMessage<HTTPRequestEvent>>(1024);

        let receive_task = tokio::spawn(async move {
            while let Some(message) = receiver.recv().await {
                if message.lost > 0 {
                    tracing::warn!("Lost {} events", message.lost);
                }

                for event in message.events {
                    if let Err(e) = process_cgroup_http_event(
                        event,
                        http_status_cloned.clone(),
                        &cgroup_path,
                        base_labels.clone(),
                    )
                    .await
                    {
                        tracing::error!("Failed to process event {:?}", e);
                    }
                }
            }
        });

        tasks.push(receive_task);

        for cpu_id in aya::util::online_cpus().map_err(|(_, error)| error)? {
            let perf_read_task = PerfReadTask::from_perf_event_ring_buffer(
                perf_array
                    .open(cpu_id, None)
                    .expect("Failed to open perf buffer"),
                10,
                sender.clone(),
            );
            tasks.push(perf_read_task.spawn());
        }

        Ok(())
    }

    pub fn cgroup_path(&self) -> &Path {
        &self.cgroup_path
    }

    pub fn http_stats(&self) -> SharedHTTPStats {
        self.http_stats.clone()
    }
}

impl Drop for KiteEbpf {
    fn drop(&mut self) {
        debug!("Dropping KiteEbpf for cgroup path: {:?}", self.cgroup_path);
        // Cancel all the collector tasks
        for task in self.tasks.drain(..) {
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
