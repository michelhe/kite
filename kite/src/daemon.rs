use std::path::Path;

use super::k8s::pods::get_pods;
use super::socket::get_kite_sock;
use anyhow::Result;
use clap::Parser;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;

use crate::socket::api::KitePodHelloMessage;

#[derive(Parser, Debug)]
#[command(name = "kite")]
#[command(bin_name = "kite")]
#[command(version, about, long_about = None)]
#[command(propagate_version = true)]
pub struct KiteDaemonArgs {
    /// The namespace to watch for pods.
    #[arg(short, long)]
    namespace: Option<String>,

    /// The label selector to filter pods.
    /// Default is None.
    /// Example: "app=nginx"
    #[arg(long)]
    label_selector: Option<String>,

    /// The field selector to filter pods.
    /// Default is None.
    /// Example: "status.phase=Running"
    #[arg(long)]
    field_selector: Option<String>,
}

async fn handle_hello_message(message: &KitePodHelloMessage) {
    tracing::debug!("Received message from pod: {:?}", message);
    // TODO: Use the message details to attach the eBPF program to the pod.
}

async fn start_init_hook_server(kite_sock: &Path) -> Result<()> {
    // Start the init hook server
    // This server listens for new pods and sends a message to the kite daemon

    if kite_sock.exists() {
        std::fs::remove_file(kite_sock)?;
    }

    // Create the directory for the socket (recursively)
    std::fs::create_dir_all(kite_sock.parent().unwrap())?;

    // Bind the socket
    let listener = UnixListener::bind(kite_sock)?;

    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let (reader, mut writer) = stream.into_split();

            tokio::spawn(async move {
                let mut lines = BufReader::new(reader).lines();

                if let Ok(Some(line)) = lines.next_line().await {
                    let message: Result<KitePodHelloMessage, _> = serde_json::from_str(&line);

                    match &message {
                        Ok(message) => {
                            handle_hello_message(message).await;
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
            });
        }
    });

    Ok(())
}

pub async fn kite_daemon_main(args: KiteDaemonArgs) -> Result<()> {
    let kite_sock = get_kite_sock();

    // Spawn the init hook server in the background
    tokio::spawn(async move {
        let r = start_init_hook_server(&kite_sock).await;
        if let Err(e) = r {
            tracing::error!("Error starting init hook server: {:?}", e);
        }
    });

    let kube_client = kube::Client::try_default().await?;
    let pods = get_pods(kube_client.clone(), &args.namespace).await?;

    for pod in pods.items {
        println!("Pod: {}", pod.metadata.name.as_ref().unwrap());
    }

    tracing::info!("Kite Daemon started, press Ctrl+C to stop");

    tokio::signal::ctrl_c().await?;

    tracing::info!("Exiting");

    Ok(())
}
