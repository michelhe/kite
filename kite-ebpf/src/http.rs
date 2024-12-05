use aya_ebpf::{cty::c_long, programs::SkBuffContext};

use crate::tcp::ParsedTcp;

#[derive(Clone, Copy)]
pub enum HTTPDetection {
    Request,
    Response,
}

#[inline(always)]
/// Detects HTTP traffic by looking at the first 8 bytes of the TCP payload.
pub fn detect_http(ctx: &SkBuffContext, tcp: &ParsedTcp) -> Result<Option<HTTPDetection>, c_long> {
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
