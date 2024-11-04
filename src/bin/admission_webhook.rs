/// The admission controller module is responsible for mutating incoming pods
use std::convert::Infallible;
use std::env;

use anyhow::{anyhow, Result};
use clap::Parser;
use jsonptr::Pointer;
use k8s_openapi::api::core::v1::{Pod, PodSpec, PodTemplateSpec};
use kube::api::ObjectMeta;
use kube::core::{
    admission::{AdmissionRequest, AdmissionResponse, AdmissionReview, Operation},
    DynamicObject,
};
use serde_json::json;
use tracing::{info, Level};
use warp::{reply, Filter};

use kite::k8s;
use kite::socket::get_kite_sock;

/// Container for an object to be mutated and has PodSpec and ObjectMeta fields.
struct PodLikeObject {
    pod_spec: PodSpec,
    metadata: ObjectMeta,
    json_root: Pointer,
}

/// This function is responsible for parsing the incoming object and returning a PodLikeObject.
/// This is necessary because the incoming object can be a Pod, Deployment, DaemonSet, etc.
fn get_pod_like_object(kind: &str, obj: DynamicObject) -> Result<PodLikeObject> {
    match kind {
        "Pod" => {
            let pod: Pod = obj.try_parse()?;
            // If the object is a plain Pod, it can also be parsed as a PodTemplateSpec.
            Ok(PodLikeObject {
                pod_spec: pod.spec.ok_or(anyhow!("No spec field in pod"))?,
                metadata: pod.metadata,
                json_root: Pointer::root(),
            })
        }
        _ => {
            // If the objects is not a Pod, we assume it has a PodTemplateSpec field.
            let template = obj
                .data
                .get("spec")
                .ok_or(anyhow!("No spec field in object"))?
                .get("template")
                .ok_or(anyhow!("No template field in spec"))?;

            let pod_template_spec: PodTemplateSpec = serde_json::from_value(template.clone())?;

            Ok(PodLikeObject {
                pod_spec: pod_template_spec
                    .spec
                    .ok_or(anyhow!("No spec field in pod template"))?,
                metadata: pod_template_spec
                    .metadata
                    .ok_or(anyhow!("No metadata field in pod template"))?,
                json_root: Pointer::new(["spec", "template"]),
            })
        }
    }
}

/// Join a root pointer with a list of tokens
fn join_jsonptr(root: &Pointer, tokens: &[&str]) -> Pointer {
    let mut p = Pointer::root();
    p.append(root);
    p.append(&Pointer::new(tokens));
    p
}

/// Add PatchOperations that add the kite.io/patched label to the object
fn patch_labels(
    patches: &mut Vec<json_patch::PatchOperation>,
    obj_metadata: &ObjectMeta,
    obj_root: &Pointer,
) {
    // Ensures that annotations exists before adding to it
    if obj_metadata.labels.is_none() {
        patches.push(json_patch::PatchOperation::Add(json_patch::AddOperation {
            path: join_jsonptr(obj_root, &["metadata", "labels"]),
            value: json!({}),
        }));
    }

    patches.push(json_patch::PatchOperation::Add(json_patch::AddOperation {
        path: join_jsonptr(
            obj_root,
            &["metadata", "labels", k8s::consts::LABEL_PATCHED],
        ),
        value: json!("true"),
    }));
}

/// Add PatchOperations that add the kite.io/monitored annotation to the object
fn patch_annotations(
    patches: &mut Vec<json_patch::PatchOperation>,
    obj_metadata: &ObjectMeta,
    obj_root: &Pointer,
) {
    // Ensures that annotations exists before adding to it
    if obj_metadata.annotations.is_none() {
        patches.push(json_patch::PatchOperation::Add(json_patch::AddOperation {
            path: join_jsonptr(obj_root, &["metadata", "annotations"]),
            value: json!({}),
        }));
    }

    patches.push(json_patch::PatchOperation::Add(json_patch::AddOperation {
        path: join_jsonptr(
            obj_root,
            &["metadata", "annotations", k8s::consts::ANNOTATION_MONITORED],
        ),
        value: json!("true"),
    }));
}

/// Add PatchOperations that add the kite volume to the pod spec
fn patch_kite_volume(
    patches: &mut Vec<json_patch::PatchOperation>,
    pod_spec: &PodSpec,
    obj_root: &Pointer,
) {
    // Ensures that volumes exists before adding to it
    if pod_spec.volumes.is_none() {
        patches.push(json_patch::PatchOperation::Add(json_patch::AddOperation {
            path: join_jsonptr(obj_root, &["spec", "volumes"]),
            value: json!([]),
        }));
    }

    // Add the kite volume entry to the volumes array
    patches.push(json_patch::PatchOperation::Add(json_patch::AddOperation {
        path: join_jsonptr(obj_root, &["spec", "volumes", "-"]),
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
fn patch_init_container(
    patches: &mut Vec<json_patch::PatchOperation>,
    pod_spec: &PodSpec,
    obj_root: &Pointer,
) {
    // Ensures that initContainers exists before adding to it
    if pod_spec.init_containers.is_none() {
        patches.push(json_patch::PatchOperation::Add(json_patch::AddOperation {
            path: join_jsonptr(obj_root, &["spec", "initContainers"]),
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
        path: join_jsonptr(obj_root, &["spec", "initContainers", "-"]),
        value: init_container_spec,
    }));
}

/// Mutate the incoming object by adding the necessary annotations and initContainer
fn mutate_object(
    req: AdmissionRequest<DynamicObject>,
    pod_like: PodLikeObject,
) -> Result<AdmissionResponse> {
    // The patches to be applied to the object
    let mut patches = Vec::new();

    patch_labels(&mut patches, &pod_like.metadata, &pod_like.json_root);
    patch_annotations(&mut patches, &pod_like.metadata, &pod_like.json_root);
    patch_kite_volume(&mut patches, &pod_like.pod_spec, &pod_like.json_root);
    patch_init_container(&mut patches, &pod_like.pod_spec, &pod_like.json_root);

    Ok(AdmissionResponse::from(&req).with_patch(json_patch::Patch(patches))?)
}

/// This function is responsible for handling the admission of pods.
/// For now, we only want to add an annotation to the pod. Later, we will attach an initContainer that will be responsible for attaching the eBPF program to the pod.
async fn admission_handler(body: AdmissionReview<DynamicObject>) -> Result<reply::Json> {
    tracing::trace!("Admission Handler request {:?}", body);

    // Parse incoming webhook AdmissionRequest first
    let req: AdmissionRequest<_> = body.try_into()?;

    tracing::info!("Got admission request for a {:?}", req.kind.kind);

    let pod_like = get_pod_like_object(
        &req.kind.kind,
        req.clone().object.ok_or(anyhow!("No object in request"))?,
    )?;

    // If the pod template is already patched (i.e Deployment was patched but we also listen for the ReplicaSet)
    if let Some(labels) = &pod_like.metadata.labels {
        if labels.get(k8s::consts::LABEL_PATCHED).is_some() {
            tracing::debug!(
                "Skipping {:?}({:?}) because it was already patched",
                req.kind.kind,
                pod_like.metadata.name
            );
            return Ok(warp::reply::json(
                &AdmissionResponse::from(&req).into_review(),
            ));
        }
    }

    let response = match req.operation {
        Operation::Create => mutate_object(req, pod_like)?,
        _ => Err(anyhow!("Operation {:?} not supported", req.operation))?,
    };

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
async fn main() -> Result<()> {
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
