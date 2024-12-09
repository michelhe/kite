use aya_ebpf::{cty::c_long, programs::SkBuffContext};
use kite_ebpf_types::PacketData;

use crate::maps;

/// Read the response packet from the context. A helper function with necessary bound checks to make the verifier happy.
#[inline(always)]
pub fn read_packet(ctx: &SkBuffContext, pd: &mut PacketData, offset: u32) -> Result<(), c_long> {
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

pub fn read_packet_to_map(ctx: &SkBuffContext, offset: u32) -> Result<&'static PacketData, c_long> {
    let pd: &mut PacketData = maps::get_scratch_packet()?;
    read_packet(ctx, pd, offset)?;
    Ok(pd)
}
