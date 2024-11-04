/// This module defines the unix socket communication between the system's components.
use std::env;
use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::Once;

use anyhow::anyhow;
use tokio::io::AsyncBufReadExt as _;
use tokio::io::AsyncWriteExt as _;
use tokio::io::BufReader;

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

pub mod api {

    /// Api message sent from initContainer to the kite daemon
    #[derive(Debug, serde::Serialize, serde::Deserialize)]
    pub struct KitePodHelloMessage {
        pod_name: String,
        namespace: String,
    }

    impl KitePodHelloMessage {
        pub fn new(pod_name: String, namespace: String) -> Self {
            Self {
                pod_name,
                namespace,
            }
        }
    }
}
