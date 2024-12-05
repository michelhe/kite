use aya::maps::{perf::AsyncPerfEventArrayBuffer, MapData};
use tokio::{sync::mpsc::Sender, task::JoinHandle};
use tokio_util::bytes::BytesMut;
use tracing::warn;

pub(crate) struct PerfReadTaskMessage<T: Sized + Send + Sync + 'static> {
    pub(crate) events: Vec<T>,
    pub(crate) lost: usize,
}

/// Helper struct to spawn a task that reads perf events from a ring buffer.
pub(crate) struct PerfReadTask<T: Sized + Send + Sync + 'static> {
    /// The ring buffer to read events from
    ring_buffer: AsyncPerfEventArrayBuffer<MapData>,

    /// Buffers to read the events into
    event_buffers: Vec<BytesMut>,

    /// Where to send the read events
    sender: Sender<PerfReadTaskMessage<T>>,
}

impl<T: Sized + Send + Sync + 'static> PerfReadTask<T> {
    /// Create a new PerfReadTask
    /// # Arguments
    /// * `ring_buffer` - The ring buffer to read events from
    /// * `num_event_buffers` - The number of event buffers to allocate
    /// * `sender` - Where to send the read events
    pub(crate) fn from_perf_event_ring_buffer(
        ring_buffer: AsyncPerfEventArrayBuffer<MapData>,
        num_event_buffers: usize,
        sender: Sender<PerfReadTaskMessage<T>>,
    ) -> Self {
        let event_buffers = (0..num_event_buffers)
            .map(|_| BytesMut::with_capacity(1024))
            .collect::<Vec<_>>();

        PerfReadTask {
            ring_buffer,
            event_buffers,
            sender,
        }
    }

    async fn read_events(&mut self) -> anyhow::Result<PerfReadTaskMessage<T>> {
        let events = self
            .ring_buffer
            .read_events(&mut self.event_buffers)
            .await?;
        if events.lost > 0 {
            tracing::warn!("PerfReadTask: Lost {} events", events.lost);
        }

        let perf_events = self
            .event_buffers
            .iter_mut()
            .take(events.read)
            .map(|buf| {
                let raw_ptr = buf.as_ptr() as *const T;
                unsafe { raw_ptr.read_unaligned() }
            })
            .collect();

        Ok(PerfReadTaskMessage {
            events: perf_events,
            lost: events.lost,
        })
    }

    async fn run(mut self) -> anyhow::Result<()> {
        loop {
            let result = self.read_events().await?;
            self.sender.send(result).await?;
        }
    }

    pub fn spawn(self) -> JoinHandle<()> {
        tokio::spawn(async move {
            if let Err(e) = self.run().await {
                warn!("PerfReadTask failed: {:?}", e);
            }
        })
    }
}
