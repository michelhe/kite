use aya_ebpf::{
    bindings::{sk_action::SK_PASS, BPF_F_NO_PREALLOC},
    helpers::bpf_ktime_get_ns,
    programs::SkBuffContext,
};
use aya_log_ebpf::{debug, warn};
use kite_ebpf_types::{Connection, HTTPEventKind};

use crate::{maps, tcp::ParsedTcp, utils};

/// Internal state for tracking HTTP connections.
#[repr(C, packed)]
pub struct HTTPConnectionState {
    pub conn: Connection,
    pub kind: HTTPEventKind,
    pub request_count: usize,
    pub total_time_ns: u64,
    pub header_bytes: usize,
    pub last_request_time_ns: u64,
}

/// This function is called whenever a new request is detected on a tracked connection.
/// It will update the connection state and store the request packet.
#[inline]
pub fn on_request(
    ctx: &SkBuffContext,
    tcp: &ParsedTcp,
    conn: Connection,
    cookie: u64,
    kind: HTTPEventKind,
) -> Result<i32, i64> {
    let data = HTTPConnectionState {
        conn,
        kind,
        request_count: 1,
        total_time_ns: 0,
        header_bytes: tcp.data_size,
        last_request_time_ns: unsafe { bpf_ktime_get_ns() },
    };
    maps::KITE_CONTRACK.insert(&cookie, &data, BPF_F_NO_PREALLOC as u64)?;

    let pd = utils::read_packet_to_map(ctx, tcp.data_offset as u32)?;
    maps::REQUEST_PACKETS.insert(&cookie, &pd, BPF_F_NO_PREALLOC as u64)?;
    Ok(0)
}

/// Called whenever a response is received for a tracked connection.
/// This function will submit the event to userspace.
#[inline(always)]
pub fn on_response(
    ctx: &SkBuffContext,
    tcp: &ParsedTcp,
    cookie: u64,
    state: &mut HTTPConnectionState,
    conn: Connection,
) -> Result<i32, i64> {
    let start_time_ns = state.last_request_time_ns;
    let end_time_ns = unsafe { bpf_ktime_get_ns() };
    let duration_ns = if end_time_ns < start_time_ns {
        warn!(
            ctx,
            "Negative duration for {:i}:{} -> {:i}:{}",
            conn.src.addr,
            conn.src.port,
            conn.dst.addr,
            conn.dst.port,
        );
        0
    } else {
        end_time_ns - start_time_ns
    };

    let event_kind = state.kind;
    let prefix = match event_kind {
        HTTPEventKind::InboundRequest => "Inbound",
        HTTPEventKind::OutboundRequest => "Outbound",
    };

    debug!(
        ctx,
        "{} - {:i}:{} -> {:i}:{} took {}ms ({} bytes)",
        prefix,
        conn.src.addr,
        conn.src.port,
        conn.dst.addr,
        conn.dst.port,
        duration_ns / 1_000_000,
        state.header_bytes,
    );

    // Submit the event to userspace
    // Populate the event
    let event = maps::get_scratch_event()?;
    event.cookie = cookie;
    event.event_kind = event_kind;
    event.header_bytes = state.header_bytes;
    event.conn = conn;
    event.duration_ns = duration_ns;

    // Copy state.request into event.request
    event.request = unsafe { *maps::REQUEST_PACKETS.get(&cookie).ok_or(SK_PASS)? };
    // And free memory
    maps::REQUEST_PACKETS.remove(&cookie)?;

    let pd = utils::read_packet_to_map(ctx, tcp.data_offset as u32)?;
    event.response = *pd;

    maps::EVENTS.output(ctx, &event, 0);
    // KITE_CONTRACK.remove(&cookie)?; // Remove to avoid memory leak.
    Ok(0)
}
