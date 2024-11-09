/// The admission controller module is responsible for mutating incoming pods
use std::convert::Infallible;
use std::env;

use anyhow::anyhow;
use clap::Parser;
use jsonptr::Pointer;
use k8s_openapi::api::core::v1::Pod;
use kube::core::{
    admission::{AdmissionRequest, AdmissionResponse, AdmissionReview, Operation},
    DynamicObject,
};
use serde_json::json;
use tracing::{info, Level};
use warp::{reply, Filter};

use kite::k8s;
use kite::socket::get_kite_sock;

/// Add PatchOperations that add the kite.io/patched label to the object
fn patch_labels(patches: &mut Vec<json_patch::PatchOperation>, pod: &Pod) {
    // Ensures that annotations exists before adding to it
    if pod.metadata.labels.is_none() {
        patches.push(json_patch::PatchOperation::Add(json_patch::AddOperation {
            path: Pointer::new(&["metadata", "labels"]),
            value: json!({}),
        }));
    }

    patches.push(json_patch::PatchOperation::Add(json_patch::AddOperation {
        path: Pointer::new(&["metadata", "labels", k8s::consts::LABEL_PATCHED]),
        value: json!("true"),
    }));
}

/// Add PatchOperations that add the kite.io/monitored annotation to the object
fn patch_annotations(patches: &mut Vec<json_patch::PatchOperation>, pod: &Pod) {
    // Ensures that annotations exists before adding to it
    if pod.metadata.annotations.is_none() {
        patches.push(json_patch::PatchOperation::Add(json_patch::AddOperation {
            path: Pointer::new(&["metadata", "annotations"]),
            value: json!({}),
        }));
    }

    patches.push(json_patch::PatchOperation::Add(json_patch::AddOperation {
        path: Pointer::new(&["metadata", "annotations", k8s::consts::ANNOTATION_MONITORED]),
        value: json!("true"),
    }));
}

/// Add PatchOperations that add the kite volume to the pod spec
fn patch_kite_volume(patches: &mut Vec<json_patch::PatchOperation>, pod: &Pod) {
    // It's OK to unwrap spec here because we checked it in the admission_handler
    let pod_spec = pod.spec.as_ref().unwrap();

    // Ensures that volumes exists before adding to it
    if pod_spec.volumes.is_none() {
        patches.push(json_patch::PatchOperation::Add(json_patch::AddOperation {
            path: Pointer::new(&["spec", "volumes"]),
            value: json!([]),
        }));
    }

    // Add the kite volume entry to the volumes array
    patches.push(json_patch::PatchOperation::Add(json_patch::AddOperation {
        path: Pointer::new(&["spec", "volumes", "-"]),
        value: json!({
            "name": "kite-socket",
            "hostPath": {
                "type": "Socket",
                "path": get_kite_sock()
            }
        }),
    }));
}

/// Add PatchOperations that add the initContainer to the pod spec
fn patch_init_container(patches: &mut Vec<json_patch::PatchOperation>, pod: &Pod) {
    // It's OK to unwrap spec here because we checked it in the admission_handler
    let pod_spec = pod.spec.as_ref().unwrap();

    // Ensures that initContainers exists before adding to it
    if pod_spec.init_containers.is_none() {
        patches.push(json_patch::PatchOperation::Add(json_patch::AddOperation {
            path: Pointer::new(&["spec", "initContainers"]),
            value: json!([]),
        }));
    }

    // Prepare the initContainer spec
    let init_container_spec = json!({
        "name": "kite",
        "image": env::var("IMAGE_NAME").unwrap_or("kite:latest".to_string()),
        "command": ["kite-init-container"],
        "volumeMounts": [
            {
                "name": "kite-socket",
                "mountPath": get_kite_sock(),
            }
        ],
        "env": [
            {
                "name": k8s::consts::ENV_KITE_POD_NAME,
                "valueFrom": {
                    "fieldRef": {
                        "fieldPath": "metadata.name"
                    }
                }
            },
            {
                "name": k8s::consts::ENV_KITE_POD_NAMESPACE,
                "valueFrom": {
                    "fieldRef": {
                        "fieldPath": "metadata.namespace"
                    }
                }
            },
            {
                "name": "KITE_SOCK",
                "value": get_kite_sock()
            }
        ]
    });

    // Add the initContainer to the pod spec
    patches.push(json_patch::PatchOperation::Add(json_patch::AddOperation {
        path: Pointer::new(&["spec", "initContainers", "-"]),
        value: init_container_spec,
    }));
}

/// Mutate the incoming object by adding the necessary annotations and initContainer
fn mutate_object(
    req: AdmissionRequest<DynamicObject>,
    pod: &Pod,
) -> anyhow::Result<AdmissionResponse> {
    // The patches to be applied to the object
    let mut patches = Vec::new();

    patch_labels(&mut patches, &pod);
    patch_annotations(&mut patches, &pod);
    patch_kite_volume(&mut patches, &pod);
    patch_init_container(&mut patches, &pod);

    Ok(AdmissionResponse::from(&req).with_patch(json_patch::Patch(patches))?)
}

/// This function is responsible for handling the admission of pods.
/// For now, we only want to add an annotation to the pod. Later, we will attach an initContainer that will be responsible for attaching the eBPF program to the pod.
async fn admission_handler(body: AdmissionReview<DynamicObject>) -> anyhow::Result<reply::Json> {
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
        if labels.get(k8s::consts::LABEL_PATCHED).is_some() {
            tracing::debug!("Skipping pod {:?} because it was already patched", pod,);
            return Ok(warp::reply::json(
                &AdmissionResponse::from(&req).into_review(),
            ));
        }
    }

    let response = match req.operation {
        Operation::Create => mutate_object(req, &pod)?,
        _ => Err(anyhow!("Operation {:?} not supported", req.operation))?,
    };

    tracing::info!(
        "Succesfully mutated Pod: {:?} in namespace={:?}",
        pod.metadata.name,
        pod.metadata.namespace
    );
    tracing::trace!("Admission response: {:?}", response);
    // Return the response
    Ok(warp::reply::json(&response.into_review()))
}

#[derive(Parser, Debug)]
#[command(name = "kite-admission-webhook")]
#[command(version, about, long_about = None)]
#[command(propagate_version = true)]
struct AdmissionControllerArgs {
    /// The path to the TLS certificate.
    #[arg(long)]
    tls_cert: String,
    /// The path to the TLS key.
    #[arg(long)]
    tls_key: String,
    /// The port to listen on.
    /// Default is 3030.
    #[arg(short, long, default_value = "3030")]
    port: u16,
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
    let args = AdmissionControllerArgs::try_parse()?;

    info!("Parsed CLI arguments: {:?}", args);

    // Start the appropriate command
    let monitor = warp::path("monitor")
        .and(warp::body::json())
        .and_then(|body: AdmissionReview<DynamicObject>| async move {
            match admission_handler(body).await {
                Ok(reply) => Ok::<warp::reply::Json, Infallible>(reply),
                Err(err) => {
                    tracing::error!("Error: {:?}", err);
                    let res = AdmissionResponse::invalid(err.to_string());
                    Ok(warp::reply::json(&res.into_review()))
                }
            }
        })
        .with(warp::trace::request());

    // Run the server on an async task
    info!("Starting admission server on port {}", args.port);
    warp::serve(warp::post().and(monitor))
        .tls()
        .cert_path(args.tls_cert)
        .key_path(args.tls_key)
        .run(([0, 0, 0, 0], args.port))
        .await;

    info!("Exiting admission server");

    Ok(())
}
