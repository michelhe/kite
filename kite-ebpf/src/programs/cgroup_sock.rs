use aya_ebpf::{cty::c_long, helpers::bpf_get_socket_cookie, programs::SockContext, EbpfContext};
use aya_log_ebpf::trace;

use crate::maps::KITE_CONTRACK;

#[inline(always)]
pub fn cgroup_sock_release(ctx: &SockContext) -> Result<i32, c_long> {
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
