/// The admission controller module is responsible for mutating incoming pods
use std::{
    collections::HashSet,
    convert::Infallible,
    future::Future,
    path::{Path, PathBuf},
};

use anyhow::{anyhow, Context};
use clap::Parser;
use config::Config;
use json_patch::{AddOperation, Patch, PatchOperation};
use jsonptr::Pointer;
use k8s_openapi::api::core::v1::Pod;
use kube::core::{
    admission::{AdmissionRequest, AdmissionResponse, AdmissionReview},
    DynamicObject,
};
use serde_json::json;
use tracing::{info, Level};
use warp::{reply, Filter};

mod config;

/// The label that indicates that the pod has been patched by the admission controller already.
pub const LABEL_PATCHED: &str = "kite.io/patched";

/// Perform the label selector logic to determine if the pod should be selected.
/// matchLabels is a map of {key,value} pairs. A single {key,value} in the matchLabels map is equivalent to an element of matchExpressions, whose key field is "key", the operator is "In", and the values array contains only "value". The requirements are ANDed.
pub(self) fn run_match_labels(
    labels: &std::collections::BTreeMap<String, String>,
    match_labels: &std::collections::BTreeMap<String, String>,
) -> bool {
    match_labels
        .iter()
        .all(|(key, value)| labels.get(key).map_or(false, |v| v == value))
}

fn should_apply_patches(pod: &Pod, config: &Config) -> bool {
    match &config.selectors {
        Some(selectors) => {
            let pod_labels = pod.metadata.labels.clone().unwrap_or_default();

            // If include is set, we only apply patches to pods that match the labels.
            if let Some(include) = &selectors.include {
                if !run_match_labels(&pod_labels, &include.match_labels) {
                    return false;
                }
            }

            // If exclude is set, we skip patches for pods that match the labels. Exclude takes precedence over include.
            if let Some(exclude) = &selectors.exclude {
                if run_match_labels(&pod_labels, &exclude.match_labels) {
                    return false;
                }
            }

            true
        }
        None => true,
    }
}

/// Per RFC 6901, If the currently referenced value is a JSON array, the reference token MUST contain either
/// 1. characters comprised of digits (see ABNF below; note that leading zeros are not allowed)
///    that represent an unsigned base-10 integer value,
///    making the new referenced value the array element with the zero-based index identified by the token, OR:
/// 2. exactly the single character "-", making the new referenced value the (nonexistent) member
///    after the last array element.
fn is_referencing_an_array(token: &jsonptr::Token) -> bool {
    token.decoded() == "-"
        || token.decoded().chars().all(char::is_numeric)
            && token.decoded().chars().next() != Some('0')
}

/// Implictly create non-existent documents in the pod JSON and initialize them with an empty value.
fn create_non_existent_values(pod: &Pod, patches: Vec<PatchOperation>) -> Vec<PatchOperation> {
    let mut result = Vec::new();

    let pod_value = serde_json::to_value(pod).unwrap();

    let mut created = HashSet::new();

    for patch in patches {
        let path = patch.path();

        if path.is_root() {
            result.push(patch.clone());
            continue;
        }

        match path.resolve(&pod_value) {
            Err(jsonptr::Error::NotFound(not_found)) => {
                let missing = not_found.pointer;

                // The pod JSON contains up to the parent of the 'missing' document.
                // We will create missing values from that point on using default values.

                // Will walk from missing to the last element in the path, and figure out if it's an array or object.

                let mut current_path = missing.clone();
                for token in path.tokens().skip(missing.tokens().count()) {
                    let new_value = if is_referencing_an_array(&token) {
                        json!([])
                    } else {
                        json!({})
                    };
                    if !created.contains(&current_path) {
                        result.push(PatchOperation::Add(AddOperation {
                            path: current_path.clone(),
                            value: new_value.clone(),
                        }));
                        created.insert(current_path.clone());
                    }
                    current_path.push_back(token.clone());
                }
            }
            _ => {}
        }
        result.push(patch.clone());
    }

    result
}

/// This function is responsible for handling the admission of pods.
/// For now, we only want to add an annotation to the pod. Later, we will attach an initContainer that will be responsible for attaching the eBPF program to the pod.
async fn admission_handler(
    body: AdmissionReview<DynamicObject>,
    config: &Config,
) -> anyhow::Result<reply::Json> {
    tracing::trace!("Admission Handler request {:?}", body);

    // Parse incoming webhook AdmissionRequest first
    let req: AdmissionRequest<DynamicObject> = body.try_into()?;

    // Extract the Pod from the request
    let pod: Pod = req
        .clone()
        .object
        .ok_or(anyhow!("No object in request"))?
        .try_parse()?;
    if pod.spec.is_none() {
        return Err(anyhow!("Pod spec is missing"));
    }

    tracing::debug!(
        "Pod: {:?} namespace={:?}",
        pod.metadata.name,
        pod.metadata.namespace
    );

    // If the pod template is already patched for some reason, skip it
    if let Some(labels) = &pod.metadata.labels {
        if labels.get(LABEL_PATCHED).is_some() {
            tracing::warn!("Skipping pod {:?} because it was already patched", pod,);
            return Ok(warp::reply::json(
                &AdmissionResponse::from(&req).into_review(),
            ));
        }
    }

    if !should_apply_patches(&pod, config) {
        tracing::trace!(
            "Skipping pod {:?} because it does not match the selectors",
            pod.metadata.name
        );
        return Ok(warp::reply::json(
            &AdmissionResponse::from(&req).into_review(),
        ));
    }

    // let mut patches = make_default_patches(&pod);

    let mut patches = vec![PatchOperation::Add(AddOperation {
        path: Pointer::new(["metadata", "labels", LABEL_PATCHED]),
        value: json!("true"),
    })];
    patches.extend_from_slice(&config.patches);

    let patches = create_non_existent_values(&pod, patches);

    let response = AdmissionResponse::from(&req).with_patch(Patch(patches))?;

    tracing::info!(
        "Mutating a Pod: {:?} in namespace={:?} with patches",
        pod.metadata.name,
        pod.metadata.namespace
    );

    tracing::debug!("Admission Handler response {:?}", response);

    // Return the response
    Ok(warp::reply::json(&response.into_review()))
}

#[derive(Parser, Debug, Clone)]
#[command(name = "kite-admission-webhook")]
#[command(version, about, long_about = None)]
#[command(propagate_version = true)]
struct Args {
    #[arg(short, long)]
    /// Path to the configuration file.
    config_file: PathBuf,
    /// The path to the TLS certificate.
    #[arg(long)]
    tls_cert: PathBuf,
    /// The path to the TLS key.
    #[arg(long)]
    tls_key: PathBuf,
    /// The port to listen on.
    /// Default is 3030.
    #[arg(short, long, default_value = "3030")]
    port: u16,
}

fn webhook_task(
    tls_cert: &Path,
    tls_key: &Path,
    port: u16,
    config_file: PathBuf,
) -> impl Future<Output = ()> + 'static {
    let monitor = warp::path("monitor")
        .and(warp::body::json())
        .and_then(move |body: AdmissionReview<DynamicObject>| {
            let config_file = config_file.clone();
            async move {
                // Load the configuration file, we do it for every request to allow for hot-reloading of the configuration.
                let config = Config::from_file(&config_file).unwrap();

                match admission_handler(body, &config).await {
                    Ok(reply) => Ok::<warp::reply::Json, Infallible>(reply),
                    Err(err) => {
                        tracing::error!("Error: {:?}", err);
                        let res = AdmissionResponse::invalid(err.to_string());
                        Ok(warp::reply::json(&res.into_review()))
                    }
                }
            }
        })
        .with(warp::trace::request());

    info!("Starting webhook server on port {}", port);
    let (_addr, fut) = warp::serve(warp::post().and(monitor))
        .tls()
        .cert_path(tls_cert)
        .key_path(tls_key)
        .bind_with_graceful_shutdown(([0, 0, 0, 0], port), async move {
            tokio::signal::ctrl_c()
                .await
                .expect("Failed to install CTRL+C signal handler");
        });
    fut
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let subscriber = tracing_subscriber::FmtSubscriber::builder()
        // all spans/events with a level higher than TRACE (e.g, debug, info, warn, etc.)
        // will be written to stdout.
        .with_max_level(Level::DEBUG)
        // builds the subscriber.
        .finish();

    tracing::subscriber::set_global_default(subscriber)?;

    // Parse the CLI arguments
    let args = Args::try_parse()?;

    info!("Parsed CLI arguments: {:?}", args);

    // Load the configuration file to validate it.
    let _ = Config::from_file(&args.config_file).context("Failed to load configuration file")?;

    // Run the server on an async task

    tokio::spawn(async move {
        webhook_task(&args.tls_cert, &args.tls_key, args.port, args.config_file).await
    });

    let ctrl_c = tokio::signal::ctrl_c();
    ctrl_c.await?;

    info!("Exiting admission server");

    Ok(())
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_match_labels() {
        let mut labels = vec![("app".to_string(), "nginx".to_string())]
            .into_iter()
            .collect();
        let match_labels = vec![("app".to_string(), "nginx".to_string())]
            .into_iter()
            .collect();

        assert_eq!(run_match_labels(&labels, &match_labels), true);

        labels.remove("app");

        assert_eq!(run_match_labels(&labels, &match_labels), false);
    }

    #[test]
    fn test_should_apply_patches_no_selectors() {
        let config = Config {
            selectors: None,
            patches: vec![],
        };

        let pod = Pod::default();

        assert_eq!(should_apply_patches(&pod, &config), true);
    }

    #[test]
    fn test_should_apply_patches_include() {
        let config = Config {
            selectors: Some(config::Selectors {
                include: Some(config::LabelSelector {
                    match_labels: vec![("app".to_string(), "nginx".to_string())]
                        .into_iter()
                        .collect(),
                }),
                exclude: None,
            }),
            patches: vec![],
        };

        let mut pod = Pod::default();

        assert_eq!(should_apply_patches(&pod, &config), false);

        pod.metadata.labels = Some(
            vec![("app".to_string(), "nginx".to_string())]
                .into_iter()
                .collect(),
        );

        assert_eq!(should_apply_patches(&pod, &config), true);
    }

    #[test]
    fn test_should_apply_patches_exclude() {
        let config = Config {
            selectors: Some(config::Selectors {
                include: None,
                exclude: Some(config::LabelSelector {
                    match_labels: vec![("app".to_string(), "nginx".to_string())]
                        .into_iter()
                        .collect(),
                }),
            }),
            patches: vec![],
        };

        let mut pod = Pod::default();

        assert_eq!(should_apply_patches(&pod, &config), true);

        pod.metadata.labels = Some(
            vec![("app".to_string(), "nginx".to_string())]
                .into_iter()
                .collect(),
        );

        assert_eq!(should_apply_patches(&pod, &config), false);
    }

    #[test]
    fn test_create_non_existent_values() {
        let pod: Pod = serde_json::from_value(json!({
            "spec": {
                "containers": [
                    {
                        "name": "nginx",
                        "image": "nginx:latest"
                    }
                ]
            }
        }))
        .unwrap();

        assert!(pod.metadata.labels.is_none());
        assert!(pod.metadata.annotations.is_none());
        assert!(pod.spec.clone().unwrap().containers.len() == 1);
        assert!(pod.spec.clone().unwrap().init_containers.is_none());

        let patches = json!([
            // This operation is missing the labels object.
            {
                "op": "add",
                "path": "/metadata/labels/kite.io~1patched",
                "value": "true"
            },
            // This operation is missing both initContainers array and an element within it.
            {
                "op": "add",
                "path": "/spec/initContainers/-/name",
                "value": "my-init-container"
            },
            // This should create the env var array
            {
                "op": "add",
                "path": "/spec/containers/0/env/-",
                "value": {
                    "name": "MY_ENV",
                    "value": "value"
                }
            },
            // This should re-create the env var array as it was already seen above.
            {
                "op": "add",
                "path": "/spec/containers/0/env/-",
                "value": {
                    "name": "MY_ENV_2",
                    "value": "value"
                }
            }
        ]);
        let patches: Vec<PatchOperation> = serde_json::from_value(patches).unwrap();

        let patches = create_non_existent_values(&pod, patches);

        eprintln!("{:?}", patches);

        assert!(patches.len() == 8);

        assert_eq!(
            patches[0],
            serde_json::from_value(json!({
                "op": "add",
                "path": "/metadata/labels",
                "value": {}
            }))
            .unwrap()
        );

        assert_eq!(
            patches[2],
            serde_json::from_value(json!({
                "op": "add",
                "path": "/spec/initContainers",
                "value": []
            }))
            .unwrap()
        );

        assert_eq!(
            patches[3],
            serde_json::from_value(json!({
                "op": "add",
                "path": "/spec/initContainers/-",
                "value": {}
            }))
            .unwrap()
        );

        assert_eq!(
            patches[3],
            serde_json::from_value(json!({
                "op": "add",
                "path": "/spec/initContainers/-",
                "value": {}
            }))
            .unwrap()
        );

        assert_eq!(
            patches[5],
            serde_json::from_value(json!({
                "op": "add",
                "path": "/spec/containers/0/env",
                "value": []
            }))
            .unwrap()
        );

        assert_eq!(
            patches[6],
            serde_json::from_value(json!({
                "op": "add",
                "path": "/spec/containers/0/env/-",
                "value": {
                    "name": "MY_ENV",
                    "value": "value"
                }
            }))
            .unwrap()
        );

        // Check that a second patch to create env vars is not created.
        assert_eq!(
            patches[7],
            serde_json::from_value(json!({
                "op": "add",
                "path": "/spec/containers/0/env/-",
                "value": {
                    "name": "MY_ENV_2",
                    "value": "value"
                }
            }))
            .unwrap()
        );
    }
}
