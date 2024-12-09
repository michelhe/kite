#![no_std]

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
/// A convenience type for representing an Address:Port pair.
pub struct Endpoint {
    pub addr: core::net::IpAddr,
    pub port: u16,
}

impl Endpoint {
    pub fn new(addr: IpAddr, port: u16) -> Self {
        Self { addr, port }
    }
    pub fn new_v4(addr: Ipv4Addr, port: u16) -> Self {
        Self::new(IpAddr::V4(addr), port)
    }

    pub fn new_v6(addr: Ipv6Addr, port: u16) -> Self {
        Self::new(IpAddr::V6(addr), port)
    }
}

#[cfg(feature = "user")]
impl core::fmt::Display for Endpoint {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}:{}", self.addr, self.port)
    }
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
/// A convenience type for representing a connection between two endpoints.
pub struct Connection {
    pub src: Endpoint,
    pub dst: Endpoint,
}

impl Connection {
    /// Create a new connection from ingress path.
    /// The argument are the source and destination endpoints as present in the packet.
    pub fn from_ingress(tcp_src: Endpoint, tcp_dst: Endpoint) -> Self {
        Self {
            src: tcp_src,
            dst: tcp_dst,
        }
    }

    /// Create a new connection from egress path.
    /// The argument are the source and destination endpoints as present in the packet.
    pub fn from_egress(tcp_src: Endpoint, tcp_dst: Endpoint) -> Self {
        Self {
            src: tcp_dst,
            dst: tcp_src,
        }
    }

    pub fn filter_port(&self, port: u16) -> bool {
        self.src.port == port || self.dst.port == port
    }
}

#[repr(C)]
#[derive(Debug, Clone, PartialEq, Eq, Copy)]
pub enum HTTPEventKind {
    OutboundRequest,
    InboundRequest,
}

const MTU: usize = 1500;

/// Wrapper around a packet data buffer.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PacketData {
    pub buf: [u8; MTU],
    pub len: usize,
}

impl Default for PacketData {
    fn default() -> Self {
        Self {
            buf: [0; MTU],
            len: 0,
        }
    }
}

#[cfg(feature = "user")]
impl PacketData {
    #[inline(always)]
    pub fn as_slice(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}

/// An event representing a measurment of a single HTTP request.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct HTTPRequestEvent {
    /// Unique identifier for the socket connection.
    pub cookie: u64,
    /// The kind of event.
    pub event_kind: HTTPEventKind,
    /// The connection that the request was sent on.
    pub conn: Connection,
    /// Duration (in nanoseconds) of the time it took to receive the response headers.
    /// The duration does not include the time it takes to read the response body.
    pub duration_ns: u64,
    /// TODO: This a slight lie for now, as we we are not actually measuring the data sent in the response body.
    pub total_bytes: usize,

    // /// The request data.
    pub request: PacketData,
    /// The response data.
    pub response: PacketData,
}

unsafe impl Send for HTTPRequestEvent {}
unsafe impl Sync for HTTPRequestEvent {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Endpoint {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Connection {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for HTTPRequestEvent {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PacketData {}
