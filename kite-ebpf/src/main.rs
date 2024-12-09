#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::{sk_action::SK_PASS, BPF_F_NO_PREALLOC},
    cty::c_long,
    helpers::{bpf_get_socket_cookie, bpf_ktime_get_ns},
    macros::{cgroup_skb, cgroup_sock, map},
    maps::{HashMap, PerCpuArray, PerfEventArray},
    programs::{SkBuffContext, SockContext},
    EbpfContext,
};
use aya_log_ebpf::{debug, error, trace, warn};
use kite_ebpf_types::{Connection, HTTPEventKind, HTTPRequestEvent, PacketData};

mod tcp;
use tcp::{parse_tcp, ParsedTcp};
mod http;
use http::{detect_http, HTTPDetection};

#[repr(C, packed)]
struct HTTPConnectionState {
    conn: Connection,
    kind: HTTPEventKind,
    request_count: usize,
    total_time_ns: u64,
    total_bytes: usize,
    last_request_time_ns: u64,
}

const MAX_CONNECTIONS: u32 = 10000;

#[map]
static KITE_CONTRACK: HashMap<u64, HTTPConnectionState> =
    HashMap::with_max_entries(MAX_CONNECTIONS, BPF_F_NO_PREALLOC);

#[map]
static EVENTS: PerfEventArray<HTTPRequestEvent> = PerfEventArray::new(0);

#[map]
static REQUEST_PACKETS: HashMap<u64, PacketData> = HashMap::with_max_entries(MAX_CONNECTIONS, 0);

/// A buffer to store temp TCP data.
#[map]
static mut SCRATCH_PACKET: PerCpuArray<PacketData> = PerCpuArray::with_max_entries(1, 0);

#[inline]
#[allow(static_mut_refs)]
fn get_scratch_packet() -> Result<&'static mut PacketData, c_long> {
    let event = unsafe {
        let ptr = SCRATCH_PACKET.get_ptr_mut(0).ok_or(SK_PASS)?;
        &mut *ptr
    };
    Ok(event)
}
/// A helper function to track the connection of an HTTP request in the ebpf map.
#[inline]
fn begin_tracking_http_request(
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
        total_bytes: tcp.data_size,
        last_request_time_ns: unsafe { bpf_ktime_get_ns() },
    };
    KITE_CONTRACK.insert(&cookie, &data, BPF_F_NO_PREALLOC as u64)?;

    let pd = get_scratch_packet()?;
    read_packet(ctx, pd, tcp.data_offset as u32)?;

    REQUEST_PACKETS.insert(&cookie, &pd, BPF_F_NO_PREALLOC as u64)?;
    Ok(0)
}

#[map]
static mut SCRATCH_EVENT: PerCpuArray<HTTPRequestEvent> = PerCpuArray::with_max_entries(1, 0);

#[inline]
#[allow(static_mut_refs)]
fn get_scratch_event() -> Result<&'static mut HTTPRequestEvent, c_long> {
    let event = unsafe {
        let ptr = SCRATCH_EVENT.get_ptr_mut(0).ok_or(SK_PASS)?;
        &mut *ptr
    };
    Ok(event)
}

/// Read the response packet from the context. A helper function with necessary bound checks to make the verifier happy.
#[inline(always)]
fn read_packet(ctx: &SkBuffContext, pd: &mut PacketData, offset: u32) -> Result<(), c_long> {
    let packet_len = ctx.len() as usize;
    let buf_len = pd.buf.len();

    if offset as usize >= packet_len {
        return Err(-1);
    }

    let read_len = core::cmp::min(buf_len, packet_len - offset as usize);

    if read_len == 0 || read_len > buf_len {
        return Err(-1);
    }

    ctx.load_bytes(offset as usize, &mut pd.buf[0..read_len])?;
    pd.len = read_len as usize;
    Ok(())
}

/// Called from within HTTP response packet context to finish tracking the HTTP request.
#[inline(always)]
fn finish_tracking_http_request(
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
        state.total_bytes,
    );

    // Submit the event to userspace
    // Populate the event
    let event = get_scratch_event()?;
    event.cookie = cookie;
    event.event_kind = event_kind;
    event.total_bytes = state.total_bytes;
    event.conn = conn;
    event.duration_ns = duration_ns;
    // Copy state.request into event.request
    event.request = unsafe { *REQUEST_PACKETS.get(&cookie).ok_or(SK_PASS)? };

    let pd = get_scratch_packet()?;
    read_packet(ctx, pd, tcp.data_offset as u32)?;
    event.response = *pd;

    EVENTS.output(ctx, &event, 0);
    // KITE_CONTRACK.remove(&cookie)?; // Remove to avoid memory leak.
    Ok(0)
}

#[cgroup_skb]
pub fn kite_ingress(ctx: SkBuffContext) -> i32 {
    match ingress_main(&ctx) {
        Ok(res) => res as i32,
        Err(err) => {
            error!(&ctx, "kite_ingress - Error: {}", err);
            SK_PASS as i32
        }
    }
}

#[inline(always)]
fn ingress_main(ctx: &SkBuffContext) -> Result<u32, c_long> {
    let maybe_tcp = parse_tcp(&ctx)?;
    if maybe_tcp.is_none() {
        return Ok(SK_PASS);
    }
    let tcp = maybe_tcp.unwrap(); // Safe to unwrap because we checked for None
    let http_detection = detect_http(&ctx, &tcp)?;

    let conn = Connection::from_egress(tcp.src, tcp.dst);

    let cookie = unsafe { bpf_get_socket_cookie(ctx.as_ptr()) };

    match KITE_CONTRACK.get_ptr_mut(&cookie) {
        None => {
            // We haven't seen this connection before.

            if http_detection.is_none() {
                return Ok(SK_PASS);
            }
            let http_detection = http_detection.unwrap();

            let kind = match http_detection {
                HTTPDetection::Request => HTTPEventKind::InboundRequest,
                HTTPDetection::Response => {
                    // We are seeing an HTTP response in the ingress program, which is unexpected.
                    // This is likely a response to a request that was sent before the connection was tracked.
                    warn!(
                        ctx,
                        "Unexpected response in ingress program from {:i}:{} -> {:i}:{}",
                        conn.src.addr,
                        conn.src.port,
                        conn.dst.addr,
                        conn.dst.port,
                    );
                    return Ok(SK_PASS);
                }
            };

            // Begin tracking this connection.
            begin_tracking_http_request(ctx, &tcp, conn, cookie, kind)?;
        }
        Some(state) => {
            // We have seen this connection before.

            let state = unsafe { &mut *state };
            state.total_bytes += tcp.data_size;

            match http_detection {
                None => {
                    // Probably a continuation of a previous request or response, account for its size.
                }
                Some(HTTPDetection::Request) => {
                    // This skb is a new request on a connection we've seen before.
                    warn!(
                        ctx,
                        "New request on the same socket {:i}:{} -> {:i}:{}",
                        conn.src.addr,
                        conn.src.port,
                        conn.dst.addr,
                        conn.dst.port,
                    );
                    return Ok(SK_PASS);
                }
                Some(HTTPDetection::Response) => {
                    finish_tracking_http_request(ctx, &tcp, cookie, state, conn)?;
                }
            }
        }
    }

    Ok(SK_PASS)
}

#[cgroup_skb]
pub fn kite_egress(ctx: SkBuffContext) -> i32 {
    match egress_main(&ctx) {
        Ok(res) => res as i32,
        Err(err) => {
            error!(&ctx, "kite_egress - Error: {}", err);
            SK_PASS as i32
        }
    }
}

fn egress_main(ctx: &SkBuffContext) -> Result<u32, i64> {
    let maybe_tcp = parse_tcp(&ctx)?;
    if maybe_tcp.is_none() {
        return Ok(SK_PASS);
    }
    let tcp = maybe_tcp.unwrap(); // Safe to unwrap because we checked for None
    let http_detection = detect_http(&ctx, &tcp)?;

    // In the egress program, the source and destination are reversed because the packet is going out.
    let conn = Connection::from_egress(tcp.src, tcp.dst);

    let cookie = unsafe { bpf_get_socket_cookie(ctx.as_ptr()) };

    match KITE_CONTRACK.get_ptr_mut(&cookie) {
        None => {
            // We haven't seen this connection before.
            if http_detection.is_none() {
                return Ok(SK_PASS);
            }
            let http_detection = http_detection.unwrap();

            let kind = match http_detection {
                HTTPDetection::Request => HTTPEventKind::OutboundRequest,
                HTTPDetection::Response => {
                    // This is likely a response to a request that was sent before the connection was tracked.
                    warn!(
                        ctx,
                        "Unexpected response in egress program from {:i}:{} -> {:i}:{}",
                        conn.src.addr,
                        conn.src.port,
                        conn.dst.addr,
                        conn.dst.port,
                    );
                    return Ok(SK_PASS);
                }
            };

            // Begin tracking this connection.
            begin_tracking_http_request(ctx, &tcp, conn, cookie, kind)?;
        }
        Some(state) => {
            // We have seen this connection before.
            let state = unsafe { &mut *state };

            // Account for the size of the packet.
            state.total_bytes += tcp.data_size;

            match http_detection {
                None => {
                    // Probably a continuation of a previous request or response, account for its size.
                }
                Some(HTTPDetection::Request) => {
                    // This skb is a new request on a connection we've seen before.
                    warn!(
                        ctx,
                        "New request on the same socket {:i}:{} -> {:i}:{}",
                        conn.src.addr,
                        conn.src.port,
                        conn.dst.addr,
                        conn.dst.port,
                    );
                    return Ok(SK_PASS);
                }
                Some(HTTPDetection::Response) => {
                    // This skb is a response to a request we've seen before.
                    trace!(
                        ctx,
                        "Response on {:i}:{} -> {:i}:{}",
                        conn.src.addr,
                        conn.src.port,
                        conn.dst.addr,
                        conn.dst.port,
                    );
                    finish_tracking_http_request(ctx, &tcp, cookie, state, conn)?;
                }
            }
        }
    }

    Ok(SK_PASS)
}

#[cgroup_sock(sock_release)]
/// This program is called when a socket is released. We use it to clean up the connection tracking.
pub fn kite_sock_release(ctx: SockContext) -> i32 {
    match try_sock_release(&ctx) {
        Ok(res) => res,
        Err(err) => {
            error!(&ctx, "kite_sock_release - Error: {}", err);
            1
        }
    }
}

fn try_sock_release(ctx: &SockContext) -> Result<i32, i64> {
    let cookie = unsafe { bpf_get_socket_cookie(ctx.as_ptr()) };
    let maybe_data = unsafe { KITE_CONTRACK.get(&cookie) };
    if maybe_data.is_none() {
        return Ok(1);
    } else {
        let data = maybe_data.unwrap();
        trace!(
            ctx,
            "Connection {:i}:{}->{:i}{} closed",
            data.conn.src.addr,
            data.conn.src.port,
            data.conn.dst.addr,
            data.conn.dst.port
        );
        KITE_CONTRACK.remove(&cookie)?;
    }
    Ok(1)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
