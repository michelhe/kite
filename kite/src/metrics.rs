//! Handle recording of metrics for HTTP events sent from the eBPF programs.

use core::str;
use std::{path::Path, time::Duration};

use anyhow::Context as _;
use httparse::EMPTY_HEADER;
use kite_ebpf_types::{Endpoint, HTTPEventKind, HTTPRequestEvent};
use metrics::{counter, histogram, IntoLabels as _, Label};
use metrics_exporter_prometheus::PrometheusBuilder;
use metrics_util::MetricKindMask;

use crate::{http, stats::SharedHTTPStats, utils::is_global_ip};

async fn record_internal(
    key: Endpoint,
    event_kind: HTTPEventKind,
    total_bytes: usize,
    duration_ns: u64,
    stats: SharedHTTPStats,
) {
    let mut stats = stats.lock().await;
    let map = match event_kind {
        HTTPEventKind::OutboundRequest => &mut stats.requests,
        HTTPEventKind::InboundRequest => &mut stats.responses,
    };
    let entry = map.entry(key).or_default();
    entry.request_count += 1;
    entry.total_bytes += total_bytes as u64;
    entry.latencies.push(duration_ns); // Convert ns to ms
}

async fn record_prometheus_metrics(
    base_metric_name: &str,
    key: Endpoint,
    duration_ns: u64,
    total_bytes: usize,
    cgroup_path: &Path,
    extra_labels: &[Label],
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

    let is_global = is_global_ip(key.addr);
    labels.push((
        "kite_ip_is_global".to_string(),
        if is_global {
            "true".to_string()
        } else {
            "false".to_string()
        },
    ));

    histogram!(format!("{base_metric_name}.duration"), &labels).record(duration_ns as f64);
    counter!(format!("{base_metric_name}.count"), &labels).increment(1);
    histogram!(format!("{base_metric_name}.bytes"), &labels).record(total_bytes as f64);
}

/// Parsed data from the HTTP packets and adds labels to the metrics.
fn add_labels_from_http(
    request: &httparse::Request,
    response: &httparse::Response,
    labels: &mut Vec<Label>,
) -> anyhow::Result<()> {
    let request_host: &str = http::get_host(request)
        .unwrap_or(Ok("<MISSING>"))
        .unwrap_or("<UNPARSEABLE>");
    labels.push(Label::new(
        "request_host".to_string(),
        request_host.to_string(),
    ));

    let request_path = http::get_path(request).unwrap_or("<UNPARSEABLE>");
    labels.push(Label::new(
        "request_path".to_string(),
        request_path.to_string(),
    ));

    let request_method = request.method.unwrap_or("<UNPARSEABLE>");
    labels.push(Label::new(
        "request_method".to_string(),
        request_method.to_string(),
    ));

    let status = http::get_status(response);
    labels.push(Label::new(
        "response_status".to_string(),
        status.to_string(),
    ));

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

    let mut total_bytes = event.header_bytes;

    let mut request_headers = [EMPTY_HEADER; 100];
    let mut response_headers = [EMPTY_HEADER; 100];
    let mut request = httparse::Request::new(&mut request_headers);
    let mut response: httparse::Response<'_, '_> = httparse::Response::new(&mut response_headers);

    match (
        request.parse(event.request.as_slice())?,
        response.parse(event.response.as_slice())?,
    ) {
        (httparse::Status::Complete(_), httparse::Status::Complete(_)) => {
            add_labels_from_http(&request, &response, &mut labels)?;
            // Add the content-length header to the total bytes
            // This is not ideal because its merely a hint to what size the body is going to be, but the connection can be cut short before the body is sent.
            // We record this anyway as in 99% of the cases, we prefer to have a rough estimate of the total bytes sent in the happy path.
            total_bytes += http::get_content_length(&response).unwrap_or(0);
        }
        _ => {
            tracing::warn!("Failed to parse HTTP request or response");
            return Ok(());
        }
    }
    tokio::join!(
        record_internal(
            key,
            event.event_kind,
            total_bytes,
            event.duration_ns,
            http_stats
        ),
        record_prometheus_metrics(
            base_metric_name,
            key,
            event.duration_ns,
            total_bytes,
            cgroup_path,
            &labels
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
