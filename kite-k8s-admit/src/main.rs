/// The admission controller module is responsible for mutating incoming pods
use std::{convert::Infallible, path::PathBuf};

use anyhow::{anyhow, Context};
use clap::Parser;
use config::{Config, PatchRule};
use json_patch::{AddOperation, Patch, PatchOperation};
use jsonptr::Pointer;
use k8s_openapi::api::core::v1::Pod;
use kube::{
    core::{
        admission::{AdmissionRequest, AdmissionResponse, AdmissionReview},
        DynamicObject,
    },
    ResourceExt,
};
use serde_json::json;
use tracing::{info, Level};
use warp::{reply, Filter};

mod config;

/// The label that indicates that the pod has been patched by the admission controller already.
pub const LABEL_PATCHED: &str = "kite.io/patched";

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
/// This function creates the missing documents as PatchOperation::Add operations.
/// The pod object is consumed and returned in the patched form along with the PatchOperations that were created.
fn patch_and_fill_default_values(
    pod: Pod,
    patches: &[PatchOperation],
) -> anyhow::Result<(Pod, Vec<PatchOperation>)> {
    let mut result = Vec::new();

    let mut pod_value = serde_json::to_value(pod)?;

    for patch in patches {
        let mut ops = vec![];
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
                    let add = PatchOperation::Add(AddOperation {
                        path: current_path.clone(),
                        value: new_value.clone(),
                    });
                    ops.push(add);
                    current_path.push_back(token.clone());
                }
            }
            Err(e) => {
                return Err(e.into());
            }
            Ok(_) => {}
        }
        ops.push(patch.clone());

        json_patch::patch(&mut pod_value, &ops)?;
        result.extend(ops.into_iter());
    }

    Ok((serde_json::from_value(pod_value)?, result))
}

/// Evaluate patch rules against the pod and return all that patches that should be applied.
pub(self) fn execute_rules(
    rules: &[PatchRule],
    mut pod: Pod,
    patches: &mut Vec<PatchOperation>,
) -> anyhow::Result<Pod> {
    let labels = pod.labels().clone();

    for rule in rules.iter().filter(|rule| rule.is_matching(&labels)) {
        let (new_pod, todo_patches) = patch_and_fill_default_values(pod, &rule.patches)?;
        patches.extend(todo_patches.into_iter());
        pod = new_pod;
    }

    Ok(pod)
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

    let mut patches = Vec::new();
    let pod = execute_rules(&config.rules, pod, &mut patches)?;

    if patches.is_empty() {
        tracing::trace!(
            "Skipping pod {:?} because no patches are required",
            pod.metadata.name
        );
        return Ok(warp::reply::json(
            &AdmissionResponse::from(&req).into_review(),
        ));
    }

    // Add a label to the pod to indicate that it has been patched
    let pod = execute_rules(
        &[PatchRule::new(
            None,
            vec![PatchOperation::Add(AddOperation {
                path: Pointer::new(["metadata", "labels", LABEL_PATCHED]),
                value: json!("true"),
            })],
        )],
        pod,
        &mut patches,
    )?;

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

#[derive(clap::Args, Debug, Clone)]
struct TlsArgs {
    /// The path to the TLS certificate.
    #[arg(long, requires = "tls_key")]
    tls_cert: Option<PathBuf>,
    /// The path to the TLS key.
    #[arg(long, requires = "tls_cert")]
    tls_key: Option<PathBuf>,
}

#[derive(Parser, Debug, Clone)]
#[command(name = "kite-admission-webhook")]
#[command(version, about, long_about = None)]
#[command(propagate_version = true)]
struct Args {
    /// The port to listen on.
    #[arg(short, long, default_value = "3030")]
    port: u16,
    #[arg(short, long)]
    /// Path to the configuration file.
    config_file: PathBuf,

    #[command(flatten)]
    tls_args: Option<TlsArgs>,
}

async fn webhook_task(port: u16, config_file: PathBuf, tls: Option<TlsArgs>) {
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

    if let Some(tls) = tls {
        // Unwrap the TLS arguments, safe to unwrap as the CLI parser ensures that both are present.
        let tls_cert = tls.tls_cert.unwrap();
        let tls_key = tls.tls_key.unwrap();
        warp::serve(warp::post().and(monitor))
            .tls()
            .key_path(tls_key)
            .cert_path(tls_cert)
            .bind_with_graceful_shutdown(([0, 0, 0, 0], port), async move {
                tokio::signal::ctrl_c()
                    .await
                    .expect("Failed to install CTRL+C signal handler");
            })
            .1
            .await;
    } else {
        tracing::warn!("TLS is not enabled. Webhooks in Kubernetes require HTTPS.");
        warp::serve(warp::post().and(monitor))
            .bind_with_graceful_shutdown(([0, 0, 0, 0], port), async move {
                tokio::signal::ctrl_c()
                    .await
                    .expect("Failed to install CTRL+C signal handler");
            })
            .1
            .await;
    }
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

    tokio::spawn(async move { webhook_task(args.port, args.config_file, args.tls_args).await });

    let ctrl_c = tokio::signal::ctrl_c();
    ctrl_c.await?;

    info!("Exiting admission server");

    Ok(())
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_example_1_inject_label() {
        let config = Config::from_str(
            r#"
            rules: 
            - selectors: {}
              patches:
              - op: add
                path: /spec/containers/0/env/-
                value:
                  name: KUBE_POD_NAME
                  valueFrom:
                    fieldRef:
                      fieldPath: metadata.name
                      "#,
        )
        .unwrap();

        let pod: Pod = serde_json::from_value(json!({
            "metadata": {
                "name": "my-pod",
                "namespace": "default"
            },
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

        let mut patches = Vec::new();
        let pod = execute_rules(&config.rules, pod, &mut patches).unwrap();

        assert_eq!(patches.len(), 2);

        assert_eq!(
            patches[0],
            serde_json::from_value(json!({
                "op": "add",
                "path": "/spec/containers/0/env",
                "value": []
            }))
            .unwrap()
        );

        assert_eq!(
            patches[1],
            serde_json::from_value(json!({
                "op": "add",
                "path": "/spec/containers/0/env/-",
                "value": {
                    "name": "KUBE_POD_NAME",
                    "valueFrom": {
                        "fieldRef": {
                            "fieldPath": "metadata.name"
                        }
                    }
                }
            }))
            .unwrap()
        );

        assert_eq!(
            pod.spec.as_ref().unwrap().containers[0]
                .env
                .as_ref()
                .unwrap()
                .len(),
            1
        );

        assert_eq!(
            pod.spec.as_ref().unwrap().containers[0]
                .env
                .as_ref()
                .unwrap()[0]
                .name,
            "KUBE_POD_NAME"
        );
    }

    #[test]
    fn test_example_2_inject_volume_mount() {
        let config = Config::from_str(
            r#"
            rules:
            - selectors:
                include:
                  matchLabels:
                    app: my-app
              patches:
                - op: add
                  path: /spec/containers/0/volumeMounts/-
                  value:
                    name: my-volume
                    mountPath: /path/to/mount
                - op: add
                  path: /spec/volumes/-
                  value:
                    name: my-volume
                    emptyDir: {}
            "#,
        )
        .unwrap();

        let pod: Pod = serde_json::from_value(json!({
            "metadata": {
                "name": "my-pod",
                "namespace": "default",
                "labels": {
                    "app": "my-app"
                }
            },
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

        let mut patches = Vec::new();
        let pod = execute_rules(&config.rules, pod, &mut patches).unwrap();

        assert_eq!(
            pod.spec.as_ref().unwrap().volumes.as_ref().unwrap()[0].name,
            "my-volume"
        );
        assert_eq!(
            pod.spec.as_ref().unwrap().containers[0]
                .volume_mounts
                .as_ref()
                .unwrap()[0]
                .name,
            "my-volume"
        );
    }

    #[test]
    fn test_patch_and_fill_default_values() {
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
                "path": "/spec/initContainers/-",
                "value": {
                    "name": "my-init-container"
                }
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

        let (pod, patches) = patch_and_fill_default_values(pod, &patches).unwrap();

        eprintln!("{}", serde_json::to_value(&pod).unwrap());

        // Check that the labels object was created and populated with the patched label.
        assert_eq!(
            pod.metadata.labels.unwrap().get("kite.io/patched"),
            Some(&"true".to_string())
        );
        // Check that the initContainers array was created and populated with the init container.
        assert!(
            pod.spec
                .as_ref()
                .unwrap()
                .init_containers
                .as_ref()
                .unwrap()
                .len()
                == 1
        );
        assert_eq!(
            pod.spec.as_ref().unwrap().init_containers.as_ref().unwrap()[0].name,
            "my-init-container"
        );
        // Check that the env var array was created and populated with the env var.
        assert!(
            pod.spec.as_ref().unwrap().containers[0]
                .env
                .as_ref()
                .unwrap()
                .len()
                == 2
        );
        assert_eq!(
            pod.spec.as_ref().unwrap().containers[0]
                .env
                .as_ref()
                .unwrap()[0]
                .name,
            "MY_ENV"
        );
        assert_eq!(
            pod.spec.as_ref().unwrap().containers[0]
                .env
                .as_ref()
                .unwrap()[1]
                .name,
            "MY_ENV_2"
        );

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
                "value": {
                    "name": "my-init-container"
                }
            }))
            .unwrap()
        );

        assert_eq!(
            patches[4],
            serde_json::from_value(json!({
                "op": "add",
                "path": "/spec/containers/0/env",
                "value": []
            }))
            .unwrap()
        );

        assert_eq!(
            patches[5],
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
            patches[6],
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
