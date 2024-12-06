//! TCP Packet parsing utilities

use aya_ebpf::{cty::c_long, programs::SkBuffContext};
use aya_log_ebpf::error;
use kite_ebpf_types::Endpoint;
use network_types::eth::EtherType;
use network_types::ip::{IpProto, Ipv4Hdr, Ipv6Hdr};
use network_types::tcp::TcpHdr;

pub struct ParsedTcp {
    pub src: Endpoint,
    pub dst: Endpoint,
    pub data_offset: usize,
    pub data_size: usize,
}

fn parse_ipv4(ctx: &SkBuffContext) -> Result<Option<ParsedTcp>, c_long> {
    let ip = ctx.load::<Ipv4Hdr>(0)?;

    if ip.proto != IpProto::Tcp {
        return Ok(None);
    }

    let ip_hlen: usize = u8::from_be(ip.ihl()) as usize * 4;
    let tot_len = u16::from_be(ip.tot_len) as usize;

    if tot_len < ip_hlen {
        error!(ctx, "Invalid IP header length");
        return Err(1);
    }
    let tcp_len = tot_len as usize - ip_hlen;
    let tcp_offset = ip_hlen;

    let tcp = ctx.load::<TcpHdr>(tcp_offset)?;

    let tcp_doff = tcp.doff() as usize * 4;

    Ok(Some(ParsedTcp {
        src: Endpoint::new_v4(ip.src_addr(), u16::from_be(tcp.source)),
        dst: Endpoint::new_v4(ip.dst_addr(), u16::from_be(tcp.dest)),
        data_offset: tcp_offset + tcp_doff,
        data_size: tcp_len - tcp_doff,
    }))
}

// /// Check if the given protocol is an extension header.
// /// See https://en.wikipedia.org/wiki/IPv6_packet#Extension_headers
// #[inline(always)]
// fn is_extension_header(proto: IpProto) -> Result<bool, c_long> {
//     match proto {
//         IpProto::HopOpt => Ok(true),
//         IpProto::Ipv6Route => Ok(true),
//         IpProto::Ipv6Frag => Ok(true),
//         IpProto::Esp => Ok(true),
//         IpProto::Ah => Ok(true),
//         IpProto::Ipv6Opts => Ok(true),
//         IpProto::MobilityHeader => Ok(true),
//         IpProto::Hip => Ok(true),
//         IpProto::Shim6 => Ok(true),
//         IpProto::Test1 | IpProto::Test2 => Ok(true),
//         _ => Ok(false),
//     }
// }

// /// Parses an extension header and returns its next header value and length. Extension headers have a common format:
// /// The first byte specifies the next_header field.
// /// The second byte specifies the header_length (in 8-byte units, excluding the first 8 bytes).
// fn get_extension_header(data: &[u8]) -> Result<(IpProto, usize), c_long> {
//     if data.len() < 2 {
//         return Err(1); // Not enough data to parse the extension header
//     }

//     let next_header = unsafe { core::mem::transmute::<u8, IpProto>(data[0]) };
//     let header_len_units = data[1] as usize;

//     // The total header length is (header_len_units + 1) * 8 bytes
//     let header_len = (header_len_units + 1) * 8;

//     if data.len() < header_len {
//         return Err(1); // Malformed header
//     }

//     Ok((next_header, header_len))
// }

/// Parse an IPv6 packet and extracts TCP payload information.
/// Assumes that the packet is an IPv6 packet (i.e., the caller should check the protocol field).
/// Returns None if the packet does not contain a TCP header.
/// NOTE: For now, we don't support extension headers due to eBPF limitations.
fn parse_ipv6(ctx: &SkBuffContext) -> Result<Option<ParsedTcp>, c_long> {
    let ip = ctx.load::<Ipv6Hdr>(0)?;
    let ipv6_hlen = Ipv6Hdr::LEN;
    let payload_len = u16::from_be(ip.payload_len) as usize;

    // const EXT_HDR_SIZE: usize = 8;

    // // Traverse the header chain until we find the TCP header
    // let mut next_hdr = ip.next_hdr;
    // let mut offset = ipv6_hlen;
    // while is_extension_header(next_hdr).unwrap() {
    //     let hdr: [u8; EXT_HDR_SIZE] = ctx.load(offset)?;
    //     let (next, len) = get_extension_header(&hdr)?;
    //     next_hdr = next;
    //     offset += len;
    // }

    let next_hdr = ip.next_hdr;
    let offset = ipv6_hlen;

    if next_hdr != IpProto::Tcp {
        return Ok(None);
    }

    let tcp = ctx.load::<TcpHdr>(offset)?;
    let tcp_doff = tcp.doff() as usize * 4;

    Ok(Some(ParsedTcp {
        src: Endpoint::new_v6(ip.src_addr(), u16::from_be(tcp.source)),
        dst: Endpoint::new_v6(ip.dst_addr(), u16::from_be(tcp.dest)),
        data_offset: offset + tcp_doff,
        data_size: payload_len - tcp_doff,
    }))
}

#[inline(always)]
pub fn parse_tcp(ctx: &SkBuffContext) -> Result<Option<ParsedTcp>, c_long> {
    let protocol = unsafe { (*ctx.skb.skb).protocol };

    if protocol == EtherType::Ipv4 as u32 {
        parse_ipv4(ctx)
    } else if protocol == EtherType::Ipv6 as u32 {
        parse_ipv6(ctx)
    } else {
        Ok(None)
    }
}
