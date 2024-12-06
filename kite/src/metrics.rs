//! Handle recording of metrics for HTTP events sent from the eBPF programs.

use core::str;
use std::{
    net::IpAddr,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::Context as _;
use httparse::EMPTY_HEADER;
use kite_ebpf_types::{Endpoint, HTTPEventKind, HTTPRequestEvent, PacketData};
use metrics::{counter, histogram, IntoLabels as _, Label};
use metrics_exporter_prometheus::PrometheusBuilder;
use metrics_util::MetricKindMask;

use crate::{http, stats::SharedHTTPStats, utils::is_global_ip};

async fn record_internal(key: Endpoint, event: &HTTPRequestEvent, stats: SharedHTTPStats) {
    let mut stats = stats.lock().await;
    let map = match event.event_kind {
        HTTPEventKind::OutboundRequest => &mut stats.requests,
        HTTPEventKind::InboundRequest => &mut stats.responses,
    };
    let entry = map.entry(key).or_default();
    entry.request_count += 1;
    entry.total_bytes += event.total_bytes as u64;
    entry.latencies.push(event.duration_ns); // Convert ns to ms
}

async fn add_address_labels(addr: IpAddr, labels: &mut Vec<(String, String)>) {
    let is_global = is_global_ip(addr);
    labels.push((
        "kite_ip_is_global".to_string(),
        if is_global {
            "true".to_string()
        } else {
            "false".to_string()
        },
    ));
}

async fn record_prometheus_metrics(
    key: Endpoint,
    event: &HTTPRequestEvent,
    cgroup_path: PathBuf,
    extra_labels: &[Label],
    base_metric_name: &str,
) {
    let base_labels = [
        // ("endpoint", format!("{:?}", key)),  TODO: This causes numerous time series to be created, which is not ideal. Fix later.
        ("cgroup_path", cgroup_path.to_string_lossy().to_string()),
    ]
    .into_labels();

    let mut labels = base_labels
        .into_iter()
        .chain(extra_labels.iter().cloned())
        .map(|label| (label.key().to_string(), label.value().to_string()))
        .collect::<Vec<_>>();

    add_address_labels(key.addr, &mut labels).await;

    histogram!(format!("{base_metric_name}.duration"), &labels).record(event.duration_ns as f64);
    counter!(format!("{base_metric_name}.count"), &labels).increment(1);
    histogram!(format!("{base_metric_name}.bytes"), &labels).record(event.total_bytes as f64);
}

/// Parsed data from the HTTP packets and adds labels to the metrics.
fn add_labels_from_http(
    request_packet: &PacketData,
    response_packet: &PacketData,
    labels: &mut Vec<Label>,
) -> anyhow::Result<()> {
    let mut request_headers = [EMPTY_HEADER; 100];
    let mut response_headers = [EMPTY_HEADER; 100];
    let mut request = httparse::Request::new(&mut request_headers);
    let mut response: httparse::Response<'_, '_> = httparse::Response::new(&mut response_headers);

    tracing::trace!(
        "request_packet: {:?}",
        str::from_utf8(request_packet.as_slice())
    );
    if let httparse::Status::Complete(_) = request.parse(request_packet.as_slice())? {
        let request_host: &str = http::get_host(&request)
            .unwrap_or(Ok("<MISSING>"))
            .unwrap_or("<UNPARSEABLE>");
        labels.push(Label::new(
            "request_host".to_string(),
            request_host.to_string(),
        ));

        let request_path = http::get_path(&request).unwrap_or("<UNPARSEABLE>");
        labels.push(Label::new(
            "request_path".to_string(),
            request_path.to_string(),
        ));

        let request_method = request.method.unwrap_or("<UNPARSEABLE>");
        labels.push(Label::new(
            "request_method".to_string(),
            request_method.to_string(),
        ));
    }

    tracing::trace!(
        "response_packet: {:?}",
        str::from_utf8(response_packet.as_slice())
    );
    if let httparse::Status::Complete(_) = response.parse(response_packet.as_slice())? {
        let status = http::get_status(&response);
        labels.push(Label::new(
            "response_status".to_string(),
            status.to_string(),
        ));
    }

    Ok(())
}

/// Process an HTTP event and record metrics.
pub(crate) async fn process_cgroup_http_event(
    event: HTTPRequestEvent,
    http_stats: SharedHTTPStats,
    cgroup_path: &Path,
    mut labels: Vec<Label>,
) -> anyhow::Result<()> {
    let (key, base_metric_name) = match event.event_kind {
        HTTPEventKind::OutboundRequest => (event.conn.src, "kite.http.request.outbound"),
        HTTPEventKind::InboundRequest => (event.conn.dst, "kite.http.request.inbound"),
    };

    add_labels_from_http(&event.request, &event.response, &mut labels)?;

    tokio::join!(
        record_internal(key, &event, http_stats),
        record_prometheus_metrics(
            key,
            &event,
            cgroup_path.to_owned(),
            &labels,
            base_metric_name
        )
    );

    Ok(())
}

pub fn init_prometheus_server() -> anyhow::Result<()> {
    PrometheusBuilder::new()
        .idle_timeout(
            MetricKindMask::COUNTER | MetricKindMask::HISTOGRAM,
            Some(Duration::from_secs(10)),
        )
        .install()
        .context("Failed to install prometheus server")?;
    Ok(())
}
