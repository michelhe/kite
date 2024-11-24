use std::path::PathBuf;

use anyhow::{anyhow, Context as _};
use k8s_openapi::api::core::v1::Pod;
use kube::api::{ListParams, ObjectList};

use crate::cgroup2::find_cgroup2_mount;

pub async fn get_pods(
    kube_client: kube::Client,
    namespace: Option<&str>,
) -> anyhow::Result<ObjectList<Pod>> {
    let pods = if let Some(namespace) = namespace {
        kube::Api::namespaced(kube_client, namespace)
    } else {
        kube::Api::all(kube_client)
    };
    let list_params = ListParams::default().timeout(10);
    let pod_list = pods.list(&list_params).await?;

    Ok(pod_list)
}

pub async fn get_pod(
    kube_client: kube::Client,
    name: &str,
    namespace: Option<&str>,
) -> anyhow::Result<Pod> {
    let pods = if let Some(namespace) = namespace {
        kube::Api::namespaced(kube_client, namespace)
    } else {
        kube::Api::all(kube_client)
    };
    Ok(pods.get(name).await?)
}

/// Get the app name of a pod from its labels.
/// We first try to get the "app" label, if it doesn't exist we try to get the "kite.io/app-name" label.
/// If none of the labels exist, we return None.
pub fn get_app_name(pod: &Pod) -> Option<String> {
    let labels = pod.metadata.labels.as_ref()?;
    labels
        .get("app")
        .or_else(|| labels.get("kite.io/app-name"))
        .cloned()
}

/// This function is responsible for getting the current pod.
/// It does so by using the KUBE_POD_NAME and KUBE_NAMESPACE environment variables that are injected by the admission controller or configured by the user.
pub async fn get_current_pod(kube_client: kube::Client) -> anyhow::Result<Pod> {
    let pod_name = std::env::var(super::consts::ENV_KITE_POD_NAME)?;
    let namespace = std::env::var(super::consts::ENV_KITE_POD_NAMESPACE)?;
    let pod = kube::Api::namespaced(kube_client, &namespace)
        .get(&pod_name)
        .await?;
    Ok(pod)
}

/// Get the cgroup path of a pod from its PID.
pub fn get_pod_cgroup_from_pid(pid: i32) -> anyhow::Result<PathBuf> {
    let proc_cgroup = std::fs::read_to_string(format!("/proc/{}/cgroup", pid))
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

    Ok(pod_cgroup_path)
}
