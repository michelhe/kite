use tokio::time::timeout;
use tracing::{info, Level};

use std::env;
use std::time::Duration;

use kite::socket as kite_socket;

async fn inner_main() -> anyhow::Result<()> {
    let subscriber = tracing_subscriber::FmtSubscriber::builder()
        // all spans/events with a level higher than TRACE (e.g, debug, info, warn, etc.)
        // will be written to stdout.
        .with_max_level(Level::DEBUG)
        // builds the subscriber.
        .finish();

    tracing::subscriber::set_global_default(subscriber)?;

    let pod_name = env::var(kite::k8s::consts::ENV_KITE_POD_NAME)?;
    let namespace = env::var(kite::k8s::consts::ENV_KITE_POD_NAMESPACE)?;

    let message = kite_socket::api::KitePodHelloMessage::new(pod_name, namespace);

    info!("Sending message to daemon: {:?}", message);

    let response = timeout(Duration::from_secs(5), kite_socket::send_message(message)).await??;

    info!("Received response from daemon: {}", response);

    Ok(())
}

#[tokio::main]
pub async fn main() {
    // Note: The init container always returns 0, even if it fails it's task.
    // This is because we don't want to fail pods if the init container fails.
    match inner_main().await {
        Ok(_) => {
            tracing::info!("Init container completed successfully");
        }
        Err(e) => {
            tracing::error!("Error running init container: {:?}", e);
        }
    }
}
