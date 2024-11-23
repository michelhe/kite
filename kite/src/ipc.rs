//! This module defines the unix socket communication between the system's components.
//! i.e between the initContainer and the kite daemon.
use std::{
    env,
    path::{Path, PathBuf},
    sync::{Mutex, Once},
};

use anyhow::{anyhow, Context as _};
use tokio::{
    io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader},
    net::UnixListener,
};

use crate::{ebpf::SharedEbpfManager, k8s::pods::get_pod_cgroup_from_pid};

pub const ENV_KITE_SOCK: &str = "KITE_SOCK";

static KITE_SOCK_DEFAULT: &str = "/var/run/kite/kite.sock";

static INIT: Once = Once::new();
static mut CACHED_PATH: Option<Mutex<PathBuf>> = None;

/// Get the path to the kite socket
/// The path is read from the KITE_SOCK environment variable, or defaults to "/var/run/kite/kite.sock"
pub fn get_kite_sock() -> PathBuf {
    unsafe {
        INIT.call_once(|| {
            let path = env::var(ENV_KITE_SOCK)
                .unwrap_or_else(|_| KITE_SOCK_DEFAULT.to_string())
                .into();
            CACHED_PATH = Some(Mutex::new(path));
        });

        CACHED_PATH.as_ref().unwrap().lock().unwrap().clone()
    }
}

pub async fn send_message<M: serde::Serialize>(message: M) -> anyhow::Result<serde_json::Value> {
    let stream = tokio::net::UnixStream::connect(get_kite_sock()).await?;
    let (reader, mut writer) = stream.into_split();

    let message_json = serde_json::to_string(&message)?;
    writer.write_all(message_json.as_bytes()).await?;
    writer.write_all(b"\n").await?; // Add a newline to the end of the message

    let mut lines = BufReader::new(reader).lines();

    // Wait for the server to respond
    let response = lines
        .next_line()
        .await?
        .ok_or(anyhow!("No response from server"));
    Ok(serde_json::from_str(&response?)?)
}

pub mod messages {

    /// Api message sent from initContainer to the kite daemon
    #[derive(Debug, serde::Serialize, serde::Deserialize)]
    pub struct PodHelloMessage {
        pub pod_name: String,
        pub namespace: String,
    }

    impl PodHelloMessage {
        pub fn new(pod_name: String, namespace: String) -> Self {
            Self {
                pod_name,
                namespace,
            }
        }

        pub fn to_ident(&self) -> String {
            format!("{}-{}", self.pod_name, self.namespace)
        }
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind")]
pub enum Message {
    PodHelloMessage(messages::PodHelloMessage),
}

pub async fn ipc_server_task(kite_sock: &Path, ebpf_m: SharedEbpfManager) -> anyhow::Result<()> {
    // Bind the socket
    let listener = UnixListener::bind(kite_sock)?;

    tokio::task::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();

            tracing::info!(
                "Received connection from client {peer_cred:?} {peer_addr:?}",
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
                tracing::info!("Reading message from client");
                let mut lines = BufReader::new(reader).lines();
                let line = lines
                    .next_line()
                    .await
                    .context("Failed to read line from the client")?
                    .ok_or(anyhow!("No message from client"))?;
                tracing::debug!("Received message: {:?}", line);

                let message: Message =
                    serde_json::from_str(&line).context("Failed to parse message")?;

                tracing::debug!("Parsed message: {:?}", message);

                match message {
                    Message::PodHelloMessage(message) => {
                        tracing::debug!(
                            "Received message from pod: {:?} peer_pid={}",
                            message,
                            peer_pid
                        );

                        let ident = message.to_ident();
                        let cgroup_path = get_pod_cgroup_from_pid(peer_pid)
                            .context("Failed to get pod cgroup")?;

                        tracing::debug!(
                            "Loading program for pod: {:?} on cgroup path: {:?}",
                            message.pod_name,
                            cgroup_path
                        );
                        ebpf_m_clone
                            .lock()
                            .await
                            .attach_to_cgroup(&cgroup_path, ident)
                            .await
                            .context("Failed to attach ebpf to cgroup")?;

                        tracing::info!(
                            "Successfully loaded program for pod: {pod:?} in namespace {namespace:?}",
                            pod = message.pod_name,
                            namespace = message.namespace,
                        );
                    }
                }

                // Send a response back to the client
                let response = "{\"message\": \"success\"}";
                writer.write_all(response.as_bytes()).await?;
                writer.write_all(b"\n").await?;
                Ok::<(), anyhow::Error>(()) // <- note the explicit type annotation here
            });
        }
    });

    Ok(())
}
