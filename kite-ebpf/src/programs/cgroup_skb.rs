use aya_ebpf::bindings::sk_action::SK_PASS;
use aya_ebpf::cty::c_long;
use aya_ebpf::helpers::bpf_get_socket_cookie;
use aya_ebpf::programs::SkBuffContext;
use aya_ebpf::EbpfContext;
use aya_log_ebpf::{trace, warn};
use kite_ebpf_types::{Connection, HTTPEventKind};

use crate::contrack;
use crate::http::{detect_http, HTTPDetection};
use crate::maps;
use crate::tcp::parse_tcp;

pub enum ProgramType {
    Ingress,
    Egress,
}

#[inline(always)]
pub fn cgroup_skb_program(ctx: &SkBuffContext, prog_type: ProgramType) -> Result<u32, c_long> {
    let maybe_tcp: Option<crate::tcp::ParsedTcp> = parse_tcp(&ctx)?;
    if maybe_tcp.is_none() {
        return Ok(SK_PASS);
    }
    let tcp = maybe_tcp.unwrap(); // Safe to unwrap because we checked for None
    let http_detection = detect_http(&ctx, &tcp)?;

    // In the egress program, the source and destination are reversed because the packet is going out.
    let conn = match prog_type {
        ProgramType::Ingress => Connection::from_ingress(tcp.dst, tcp.src),
        ProgramType::Egress => Connection::from_egress(tcp.src, tcp.dst),
    };
    let cookie = unsafe { bpf_get_socket_cookie(ctx.as_ptr()) };

    match maps::KITE_CONTRACK.get_ptr_mut(&cookie) {
        None => {
            // We haven't seen this connection before.
            if http_detection.is_none() {
                return Ok(SK_PASS);
            }
            let http_detection = http_detection.unwrap();

            let kind = match http_detection {
                HTTPDetection::Request => match prog_type {
                    ProgramType::Ingress => HTTPEventKind::InboundRequest,
                    ProgramType::Egress => HTTPEventKind::OutboundRequest,
                },
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
            contrack::on_request(ctx, &tcp, conn, cookie, kind)?;
        }
        Some(state) => {
            // We have seen this connection before.
            let state = unsafe { &mut *state };

            // Account for the size of the packet.
            state.header_bytes += tcp.data_size;

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
                    contrack::on_response(ctx, &tcp, cookie, state, conn)?;
                }
            }
        }
    }

    Ok(SK_PASS)
}
