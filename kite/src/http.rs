//! Utils for parsing HTTP data from TCP packets
use core::str;
use std::str::Utf8Error;

pub use httparse::{Request, Response};

pub fn get_host<'buf>(request: &'buf Request) -> Option<Result<&'buf str, Utf8Error>> {
    request
        .headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case("host"))
        .map(|header| str::from_utf8(header.value))
}

pub fn get_path<'buf>(request: &'buf Request) -> Option<&'buf str> {
    request.path
}

pub fn get_status(response: &Response) -> u16 {
    response.code.unwrap_or(0)
}

pub fn get_content_length(response: &Response) -> Option<usize> {
    response
        .headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case("content-length"))
        .and_then(|header| str::from_utf8(header.value).ok())
        .and_then(|value| value.parse().ok())
}
