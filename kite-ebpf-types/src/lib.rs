#![no_std]

#[repr(C, packed)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
/// A convenience type for representing an Address:Port pair.
pub struct Endpoint {
    pub addr: u32,
    pub port: u16,
}

impl Endpoint {
    pub fn new(addr: u32, port: u16) -> Self {
        Self { addr, port }
    }
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// A convenience type for representing a connection between two endpoints.
pub struct Connection {
    pub src: Endpoint,
    pub dst: Endpoint,
}

impl Connection {
    pub fn new(src: Endpoint, dst: Endpoint) -> Self {
        Self { src, dst }
    }

    /// Returns a hash of the connection key. Note that we assume that the dest address is unique per port and always either 127.0.0.1 or 0.0.0.0.
    // pub fn hash(&self) -> u64 {
    //     let mut hash: u64 = 0;
    //     hash |= (self.src.addr as u64) << 32;
    //     hash |= (self.src.port as u64) << 16;
    //     hash |= self.dst.port as u64;
    //     hash
    // }

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

/// An event representing a measurment of a single HTTP request.
#[repr(C, packed)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HTTPRequestEvent {
    pub event_kind: HTTPEventKind,
    pub conn: Connection,
    pub duration_ns: u64,
    /// TODO: This a slight lie for now, as we we are not actually measuring the data sent in the response body.
    pub total_bytes: usize,
    // TODO: bytes sent/received, CPU time, etc.
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Endpoint {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Connection {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for RequestEvent {}
