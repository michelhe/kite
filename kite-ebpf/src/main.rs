#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::BPF_F_NO_PREALLOC,
    helpers::{bpf_get_socket_cookie, bpf_ktime_get_ns},
    macros::{cgroup_skb, cgroup_sock, map},
    maps::{HashMap, PerfEventArray},
    programs::{SkBuffContext, SockContext},
    EbpfContext,
};
use aya_log_ebpf::{debug, error, warn};
use kite_ebpf_types::{Connection, Endpoint, HTTPEventKind, HTTPRequestEvent};

mod bindings;
use bindings::{iphdr, tcphdr};

const ETH_P_IP: u32 = 8;
#[allow(unused)]
const ETH_P_IPV6: u32 = 0x86DD; // TODO: Support IPv6
const IPPROTO_TCP: u8 = 6;

const SK_PASS: i32 = 1;

struct ParsedTcp {
    ip: iphdr,
    tcp: tcphdr,
    data_offset: usize,
    data_size: usize,
}

#[repr(C, packed)]
struct HTTPConnectionData {
    conn: Connection,
    kind: HTTPEventKind,
    request_count: usize,
    total_time_ns: u64,
    bytes_out: usize,
    bytes_in: usize,
    last_request_time_ns: u64,
}

const MAX_CONNECTIONS: u32 = 10000;

#[map]
static KITE_CONTRACK: HashMap<u64, HTTPConnectionData> =
    HashMap::with_max_entries(MAX_CONNECTIONS, BPF_F_NO_PREALLOC);

#[map]
static EVENTS: PerfEventArray<HTTPRequestEvent> = PerfEventArray::new(0);

fn parse_tcp(ctx: &SkBuffContext) -> Result<Option<ParsedTcp>, i64> {
    let protocol = unsafe { (*ctx.skb.skb).protocol };

    // TODO: Support IPv6
    if protocol != ETH_P_IP {
        return Ok(None);
    }

    let ip = ctx.load::<iphdr>(0)?;

    if ip.protocol != IPPROTO_TCP {
        return Ok(None);
    }

    let ip_hlen: usize = u8::from_be(ip.ihl()) as usize * 4;
    let tcp = ctx.load::<tcphdr>(ip_hlen)?;

    let tcp_hlen = tcp.doff() as usize * 4;

    Ok(Some(ParsedTcp {
        ip,
        tcp,
        data_offset: ip_hlen + tcp_hlen,
        data_size: ctx.len() as usize - ip_hlen - tcp_hlen,
    }))
}

#[derive(Clone, Copy)]
enum HTTPDetection {
    Request,
    Response,
}

fn detect_http(ctx: &SkBuffContext, tcp: &ParsedTcp) -> Result<Option<HTTPDetection>, i64> {
    if tcp.data_size < 8 {
        return Ok(None);
    }

    let data = ctx.load::<[u8; 8]>(tcp.data_offset)?;

    match (
        data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
    ) {
        (b'G', b'E', b'T', b' ', _, _, _, _) => Ok(Some(HTTPDetection::Request)),
        (b'P', b'O', b'S', b'T', _, _, _, _) => Ok(Some(HTTPDetection::Request)),
        (b'P', b'U', b'T', b' ', _, _, _, _) => Ok(Some(HTTPDetection::Request)),
        (b'D', b'E', b'L', b'E', b'T', b'E', _, _) => Ok(Some(HTTPDetection::Request)),
        (b'H', b'E', b'A', b'D', _, _, _, _) => Ok(Some(HTTPDetection::Request)),
        (b'O', b'P', b'T', b'I', b'O', b'N', b'S', _) => Ok(Some(HTTPDetection::Request)),
        (b'C', b'O', b'N', b'N', b'E', b'C', b'T', _) => Ok(Some(HTTPDetection::Request)),
        (b'T', b'R', b'A', b'C', b'E', _, _, _) => Ok(Some(HTTPDetection::Request)),
        (b'P', b'A', b'T', b'C', b'H', _, _, _) => Ok(Some(HTTPDetection::Request)),
        (b'H', b'T', b'T', b'P', b'/', _, _, _) => Ok(Some(HTTPDetection::Response)),
        _ => Ok(None),
    }
}

/// A helper function to track the connection of an HTTP request in the ebpf map.
#[inline]
fn begin_tracking_http_request(
    conn: Connection,
    cookie: u64,
    bytes_out: usize,
    bytes_in: usize,
    kind: HTTPEventKind,
) -> Result<i32, i64> {
    let data = HTTPConnectionData {
        conn,
        kind,
        request_count: 1,
        total_time_ns: 0,
        bytes_out,
        bytes_in,
        last_request_time_ns: unsafe { bpf_ktime_get_ns() },
    };
    KITE_CONTRACK.insert(&cookie, &data, BPF_F_NO_PREALLOC as u64)?;
    Ok(0)
}

#[inline]
fn finish_tracking_http_request(
    ctx: &SkBuffContext,
    cookie: u64,
    data: &HTTPConnectionData,
    conn: Connection,
) -> Result<i32, i64> {
    let start_time_ns = data.last_request_time_ns;
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

    let event_kind = data.kind;
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
        data.bytes_out + data.bytes_in,
    );

    // TODO we need to account for the response size as well, for that we need to track the socket till the response is sent.
    let event = HTTPRequestEvent {
        event_kind: data.kind,
        total_bytes: data.bytes_out + data.bytes_in, // TODO: Split to bytes_out and bytes_in
        conn,
        duration_ns,
    };
    EVENTS.output(ctx, &event, 0);
    KITE_CONTRACK.remove(&cookie)?; // Remove to avoid memory leak.
    Ok(0)
}

#[cgroup_skb]
pub fn kite_ingress(ctx: SkBuffContext) -> i32 {
    match ingress_main(&ctx) {
        Ok(res) => res,
        Err(err) => {
            error!(&ctx, "Error: {}", err);
            SK_PASS
        }
    }
}

fn ingress_main(ctx: &SkBuffContext) -> Result<i32, i64> {
    let maybe_tcp = parse_tcp(&ctx)?;
    if maybe_tcp.is_none() {
        return Ok(SK_PASS);
    }
    let tcp = maybe_tcp.unwrap(); // Safe to unwrap because we checked for None
    let http_detection = detect_http(&ctx, &tcp)?;

    let conn = Connection::new(
        Endpoint::new(u32::from_be(tcp.ip.saddr), u16::from_be(tcp.tcp.source)),
        Endpoint::new(u32::from_be(tcp.ip.daddr), u16::from_be(tcp.tcp.dest)),
    );

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
            begin_tracking_http_request(conn, cookie, 0, tcp.data_size, kind)?;
        }
        Some(data) => {
            // We have seen this connection before.

            // Account for the size of the packet.
            unsafe {
                (*data).bytes_in += tcp.data_size;
            }

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
                    finish_tracking_http_request(ctx, cookie, unsafe { &*data }, conn)?;
                }
            }
        }
    }

    Ok(SK_PASS)
}

#[cgroup_skb]
pub fn kite_egress(ctx: SkBuffContext) -> i32 {
    match egress_main(&ctx) {
        Ok(res) => res,
        Err(err) => {
            error!(&ctx, "Error: {}", err);
            SK_PASS
        }
    }
}

fn egress_main(ctx: &SkBuffContext) -> Result<i32, i64> {
    let maybe_tcp = parse_tcp(&ctx)?;
    if maybe_tcp.is_none() {
        return Ok(SK_PASS);
    }
    let tcp = maybe_tcp.unwrap(); // Safe to unwrap because we checked for None
    let http_detection = detect_http(&ctx, &tcp)?;

    // In the egress program, the source and destination are reversed because the packet is going out.
    let conn = Connection::new(
        Endpoint::new(u32::from_be(tcp.ip.daddr), u16::from_be(tcp.tcp.dest)),
        Endpoint::new(u32::from_be(tcp.ip.saddr), u16::from_be(tcp.tcp.source)),
    );

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
            begin_tracking_http_request(conn, cookie, tcp.data_size, 0, kind)?;
        }
        Some(data) => {
            // We have seen this connection before.

            // Account for the size of the packet.
            unsafe {
                (*data).bytes_out += tcp.data_size;
            }

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
                    finish_tracking_http_request(ctx, cookie, unsafe { &*data }, conn)?;
                }
            }
        }
    }

    Ok(SK_PASS)
}

const SOCK_PASS: i32 = 1;

#[cgroup_sock(sock_release)]
/// This program is called when a socket is released. We use it to clean up the connection tracking.
pub fn kite_sock_release(ctx: SockContext) -> i32 {
    match try_sock_release(&ctx) {
        Ok(res) => res,
        Err(err) => {
            error!(&ctx, "Error: {}", err);
            SOCK_PASS
        }
    }
}

fn try_sock_release(ctx: &SockContext) -> Result<i32, i64> {
    let cookie = unsafe { bpf_get_socket_cookie(ctx.as_ptr()) };
    let maybe_data = unsafe { KITE_CONTRACK.get(&cookie) };
    if maybe_data.is_none() {
        return Ok(SOCK_PASS);
    } else {
        let data = maybe_data.unwrap();
        debug!(
            ctx,
            "Connection {:i}:{}->{:i}{} closed",
            data.conn.src.addr,
            data.conn.src.port,
            data.conn.dst.addr,
            data.conn.dst.port
        );
        KITE_CONTRACK.remove(&cookie)?;
    }
    Ok(SOCK_PASS)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
