use aya_ebpf::{cty::c_long, programs::SkBuffContext};

///! TCP Packet parsing utilities
use crate::bindings::{iphdr, tcphdr};

const ETH_P_IP: u32 = 8;
#[allow(unused)]
const ETH_P_IPV6: u32 = 0x86DD; // TODO: Support IPv6
const IPPROTO_TCP: u8 = 6;

pub struct ParsedTcp {
    pub ip: iphdr,
    pub tcp: tcphdr,
    pub data_offset: usize,
    pub data_size: usize,
}

#[inline(always)]
pub fn parse_tcp(ctx: &SkBuffContext) -> Result<Option<ParsedTcp>, c_long> {
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
