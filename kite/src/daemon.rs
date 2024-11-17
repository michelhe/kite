use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::UnixListener,
};

use crate::{
    cgroup2::find_cgroup2_mount,
    ebpf::{KiteEbpf, SharedEbpfManager},
    ipc::messages::PodHelloMessage,
};

/// Handle PodHelloMessage - Load and attach the Kite eBPF program to the pod's cgroup.
async fn handle_pod_hello_message(
    peer_pid: i32,
    message: &PodHelloMessage,
) -> anyhow::Result<KiteEbpf> {
    tracing::debug!(
        "Received message from pod: {:?} peer_pid={}",
        message,
        peer_pid
    );

    let kube_client = kube::Client::try_default().await.context(
        "Failed to create Kubernetes client. Make sure the kubeconfig is correctly configured.",
    )?;
    let pods: kube::Api<k8s_openapi::api::core::v1::Pod> =
        kube::Api::namespaced(kube_client, &message.namespace);

    let pod = pods.get(&message.pod_name).await.context(
        "Failed to get pod from Kubernetes API. Make sure the pod is running and the kubelet is reachable.",
    )?;

    let proc_cgroup = std::fs::read_to_string(format!("/proc/{}/cgroup", peer_pid))
        .context("Failed reading /proc/pid/cgroup")?;

    // Example 0::/docker/65a1b6ad09655b3f1475ede1aa0061a97c0d1ada9f2b2acac959afbc92094463/kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-besteffort.slice/kubelet-kubepods-besteffort-pod96dd7de3_0783_4613_a707_e0effc077ef5.slice/cri-containerd-13a0f64b909e3ff2d63f196d6947927a8af997ab68f8fa9ebb6d6c7018af4ec9.scope
    let cgroup_relative_path: PathBuf = proc_cgroup
        .lines()
        .find(|line| line.contains("kubepods"))
        .ok_or_else(|| anyhow!("Cgroup path not found"))?
        .split(":")
        .last()
        .ok_or_else(|| anyhow!("Cgroup path not found"))?
        .into();
    // Trim the first /
    let cgroup_relative_path = cgroup_relative_path
        .strip_prefix("/")
        .unwrap_or(&cgroup_relative_path);
    tracing::debug!("Cgroup path: {:?}", cgroup_relative_path);

    let container_cgroup_path = find_cgroup2_mount().join(cgroup_relative_path);
    // We want the cgroup of the pod, not the init container
    let pod_cgroup_path = container_cgroup_path
        .parent()
        .ok_or(anyhow!(format!(
            "Could not find {:?}",
            &cgroup_relative_path
        )))?
        .to_owned();

    tracing::debug!(
        "Loading program for pod: {:?} on cgroup path: {:?}",
        pod.metadata.name,
        pod_cgroup_path
    );

    let ebpf = KiteEbpf::load(&pod_cgroup_path).await?;

    tracing::info!(
        "Successfully loaded program for pod: {pod:?} in namespace {namespace:?} with UID={uid:?}",
        pod = pod.metadata.name,
        namespace = pod.metadata.namespace,
        uid = pod.metadata.uid
    );

    Ok(ebpf)
}

pub async fn start_init_hook_server(
    kite_sock: &Path,
    ebpf_m: SharedEbpfManager,
) -> anyhow::Result<()> {
    // Start the init hook server
    // This server listens for new pods and sends a message to the kite daemon

    // Bind the socket
    let listener = UnixListener::bind(kite_sock)?;

    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();

            tracing::info!(
                "Received connection from pod {peer_cred:?} {peer_addr:?}",
                peer_cred = stream.peer_cred(),
                peer_addr = stream.peer_addr()
            );

            // Clone the ebpf manager to be used in the async block
            let ebpf_m_clone = ebpf_m.clone();

            let peer_pid = stream
                .peer_cred()
                .unwrap() // TODO: Handle error
                .pid()
                .expect("Peer PID is missing on Linux");
            if peer_pid == 0 {
                tracing::error!("Peer PID is 0, bad request");
                continue;
            }
            let (reader, mut writer) = stream.into_split();

            tokio::spawn(async move {
                let mut lines = BufReader::new(reader).lines();

                if let Ok(Some(line)) = lines.next_line().await {
                    let message: Result<PodHelloMessage, _> = serde_json::from_str(&line);

                    match &message {
                        Ok(message) => {
                            let kite_ebpf =
                                handle_pod_hello_message(peer_pid, message).await.unwrap();
                            ebpf_m_clone
                                .lock()
                                .await
                                .add(message.to_ident(), kite_ebpf)
                                .await;
                        }
                        Err(e) => {
                            tracing::error!("Error parsing message: {:?}", e);
                        }
                    }

                    // Send a response back to the pod
                    let response = "{\"message\": \"success\"}";
                    writer
                        .write_all(response.as_bytes())
                        .await
                        .unwrap_or_else(|err| {
                            tracing::error!("Error writing response to pod: {:?}", err);
                        });
                    writer.write_all(b"\n").await.unwrap_or_else(|err| {
                        tracing::error!("Error writing response to pod: {:?}", err);
                    });
                }

                Ok::<(), anyhow::Error>(()) // <- note the explicit type annotation here
            });
        }
    });

    Ok(())
}
