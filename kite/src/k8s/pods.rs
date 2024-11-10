use anyhow::Result;
use k8s_openapi::api::core::v1::Pod;
use kube::api::{ListParams, ObjectList};

pub async fn get_pods(
    kube_client: kube::Client,
    namespace: &Option<String>,
) -> Result<ObjectList<Pod>> {
    let pods = if let Some(namespace) = namespace {
        kube::Api::namespaced(kube_client, namespace)
    } else {
        kube::Api::all(kube_client)
    };
    let list_params = ListParams::default().timeout(10);
    let pod_list = pods.list(&list_params).await?;

    Ok(pod_list)
}

/// This function is responsible for getting the current pod.
/// It does so by using the KUBE_POD_NAME and KUBE_NAMESPACE environment variables that are injected by the admission controller or configured by the user.
pub async fn get_current_pod(kube_client: kube::Client) -> Result<Pod> {
    let pod_name = std::env::var(super::consts::ENV_KITE_POD_NAME)?;
    let namespace = std::env::var(super::consts::ENV_KITE_POD_NAMESPACE)?;
    let pod = kube::Api::namespaced(kube_client, &namespace)
        .get(&pod_name)
        .await?;
    Ok(pod)
}
