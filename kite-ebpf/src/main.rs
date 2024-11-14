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
use aya_log_ebpf::{debug, error, info, warn};
use kite_ebpf_common::{Connection, Endpoint, HTTPRequestEvent};

mod bindings;
use bindings::{iphdr, tcphdr};

const ETH_P_IP: u32 = 8;
#[allow(unused)]
const ETH_P_IPV6: u32 = 0x86DD; // TODO: Support IPv6
const IPPROTO_TCP: u8 = 6;

const SK_PASS: i32 = 1;

struct ParsedHeaders {
    ip: iphdr,
    tcp: tcphdr,
    ip_hlen: usize,
    tcp_hlen: usize,
}

#[repr(C)]
pub struct ConnectionData {
    pub conn: Connection,
    pub request_count: usize,
    pub total_time_ns: u64,
    pub last_request_time_ns: u64,
}

const MAX_CONNECTIONS: u32 = 10000;

#[map]
static KITE_CONTRACK: HashMap<u64, ConnectionData> =
    HashMap::with_max_entries(MAX_CONNECTIONS, BPF_F_NO_PREALLOC);

#[map]
static EVENTS: PerfEventArray<HTTPRequestEvent> = PerfEventArray::new(0);

fn is_tcp(ctx: &SkBuffContext) -> Result<Option<ParsedHeaders>, i64> {
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

    Ok(Some(ParsedHeaders {
        ip,
        tcp,
        ip_hlen,
        tcp_hlen,
    }))
}

fn check_http<const INGRESS: bool>(
    ctx: &SkBuffContext,
    headers: &ParsedHeaders,
) -> Result<bool, i64> {
    let data_offset = headers.ip_hlen + headers.tcp_hlen;
    let data_size = ctx.len() as usize - data_offset;

    if data_size < 8 {
        return Ok(false);
    }

    let data = ctx.load::<[u8; 8]>(data_offset)?;

    if INGRESS {
        match (
            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
        ) {
            (b'G', b'E', b'T', b' ', _, _, _, _) => Ok(true),
            (b'P', b'O', b'S', b'T', _, _, _, _) => Ok(true),
            (b'P', b'U', b'T', b' ', _, _, _, _) => Ok(true),
            (b'D', b'E', b'L', b'E', b'T', b'E', _, _) => Ok(true),
            (b'H', b'E', b'A', b'D', _, _, _, _) => Ok(true),
            (b'O', b'P', b'T', b'I', b'O', b'N', b'S', _) => Ok(true),
            (b'C', b'O', b'N', b'N', b'E', b'C', b'T', _) => Ok(true),
            (b'T', b'R', b'A', b'C', b'E', _, _, _) => Ok(true),
            (b'P', b'A', b'T', b'C', b'H', _, _, _) => Ok(true),
            _ => Ok(false),
        }
    } else {
        if (data[0], data[1], data[2], data[3], data[4]) == (b'H', b'T', b'T', b'P', b'/') {
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

fn try_kite<const INGRESS: bool>(ctx: &SkBuffContext) -> Result<i32, i64> {
    let maybe_headers = is_tcp(&ctx)?;
    if maybe_headers.is_none() {
        return Ok(SK_PASS);
    }
    let headers = maybe_headers.unwrap(); // Safe to unwrap because we checked for None

    if !check_http::<INGRESS>(&ctx, &headers)? {
        // Not an HTTP request or response, or not relevant for the current program attachment mode.
        return Ok(SK_PASS);
    }

    let cookie = unsafe { bpf_get_socket_cookie(ctx.as_ptr()) };

    let conn = if INGRESS {
        Connection {
            src: Endpoint::new(
                u32::from_be(headers.ip.saddr),
                u16::from_be(headers.tcp.source),
            ),
            dst: Endpoint::new(
                u32::from_be(headers.ip.daddr),
                u16::from_be(headers.tcp.dest),
            ),
        }
    } else {
        // In the egress program, the source and destination are reversed because the packet is going out.
        Connection {
            src: Endpoint::new(
                u32::from_be(headers.ip.daddr),
                u16::from_be(headers.tcp.dest),
            ),
            dst: Endpoint::new(
                u32::from_be(headers.ip.saddr),
                u16::from_be(headers.tcp.source),
            ),
        }
    };

    unsafe {
        match KITE_CONTRACK.get_ptr_mut(&cookie) {
            Some(data) => match INGRESS {
                true => {
                    debug!(
                        ctx,
                        "New request on the same socket {:i}:{} -> {:i}:{}",
                        conn.src.addr,
                        conn.src.port,
                        conn.dst.addr,
                        conn.dst.port,
                    );
                    (*data).request_count += 1;
                    (*data).last_request_time_ns = bpf_ktime_get_ns();
                }
                false => {
                    let start_time_ns = (*data).last_request_time_ns;
                    let end_time_ns = bpf_ktime_get_ns();
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
                    debug!(
                        ctx,
                        "Response from {:i}:{} -> {:i}:{} took {}ms",
                        conn.src.addr,
                        conn.src.port,
                        conn.dst.addr,
                        conn.dst.port,
                        duration_ns / 1_000_000,
                    );

                    let event = HTTPRequestEvent { conn, duration_ns };
                    EVENTS.output(ctx, &event, 0);
                    (*data).total_time_ns += duration_ns;
                }
            },
            None => {
                if INGRESS {
                    debug!(
                        ctx,
                        "New request from {:i}:{} -> {:i}:{}",
                        conn.src.addr,
                        conn.src.port,
                        conn.dst.addr,
                        conn.dst.port,
                    );
                    let data = ConnectionData {
                        conn,
                        request_count: 1,
                        total_time_ns: 0,
                        last_request_time_ns: bpf_ktime_get_ns(),
                    };
                    KITE_CONTRACK.insert(&cookie, &data, BPF_F_NO_PREALLOC as u64)?;
                } else {
                    debug!(
                        ctx,
                        "Response without request from {}:{} to {}:{}",
                        conn.src.addr,
                        conn.src.port,
                        conn.dst.addr,
                        conn.dst.port,
                    );
                }
            }
        }
    };

    Ok(SK_PASS)
}

#[cgroup_skb]
pub fn kite_ingress(ctx: SkBuffContext) -> i32 {
    match try_kite::<true>(&ctx) {
        Ok(res) => res,
        Err(err) => {
            error!(&ctx, "Error: {}", err);
            SK_PASS
        }
    }
}

#[cgroup_skb]
pub fn kite_egress(ctx: SkBuffContext) -> i32 {
    match try_kite::<false>(&ctx) {
        Ok(res) => res,
        Err(err) => {
            error!(&ctx, "Error: {}", err);
            SK_PASS
        }
    }
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
