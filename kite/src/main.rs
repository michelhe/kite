use anyhow::Result;
use clap::Parser;
use tracing::{info, Level};

use kite::daemon::{kite_daemon_main, KiteDaemonArgs};

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
    let args = KiteDaemonArgs::try_parse()?;

    info!("Parsed CLI arguments: {:?}", args);
    kite_daemon_main(args).await?;

    info!("Exiting");
    Ok(())
}
