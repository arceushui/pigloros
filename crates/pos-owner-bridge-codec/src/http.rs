use crate::OwnerBridgeCodecError;

const MAX_REQUEST_LINE_BYTES: usize = 256;
const MAX_HEADER_BLOCK_BYTES: usize = 8_192;
const MAX_HEADERS: usize = 24;
const MAX_HEADER_NAME_BYTES: usize = 32;
const MAX_HEADER_VALUE_BYTES: usize = 512;

const OWNER_DOCUMENT_PATH: &str = "/owner.html";
const OWNER_HOST: &[u8] = b"localhost:49291";
const FETCH_DESTINATION: &[u8] = b"document";
const FETCH_MODE: &[u8] = b"navigate";

/// The closed response class selected after loopback HTTP admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LoopbackRequestDisposition {
    /// The request may receive the one immutable packaged owner document.
    OwnerDocument,
    /// The request was admissible but addresses no packaged asset.
    NotFound,
}

/// Strictly admit one complete loopback request under ADR-110 §4.
///
/// The caller supplies exactly the bytes read before its header deadline. This
/// function allocates nothing, accepts only one complete HTTP/1.1 request, and
/// rejects request bodies, pipelining, and every malformed or duplicate
/// required header.
///
/// # Errors
///
/// Returns [`OwnerBridgeCodecError::InvalidHttpRequest`] for malformed input,
/// an unsupported method or HTTP version, a missing/duplicate required header,
/// a request body, or surplus request bytes. Returns
/// [`OwnerBridgeCodecError::BoundsExceeded`] for input that exceeds an ADR-110
/// parser bound.
pub fn admit_loopback_http_request(
    input: &[u8],
) -> Result<LoopbackRequestDisposition, OwnerBridgeCodecError> {
    if input.len() > MAX_HEADER_BLOCK_BYTES {
        return Err(OwnerBridgeCodecError::BoundsExceeded);
    }
    let request_line_end = input
        .windows(2)
        .position(|pair| pair == b"\r\n")
        .ok_or(OwnerBridgeCodecError::InvalidHttpRequest)?;
    if request_line_end + 2 > MAX_REQUEST_LINE_BYTES {
        return Err(OwnerBridgeCodecError::BoundsExceeded);
    }

    let mut header_slots = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut request = httparse::Request::new(&mut header_slots);
    let consumed = match request
        .parse(input)
        .map_err(|_| OwnerBridgeCodecError::InvalidHttpRequest)?
    {
        httparse::Status::Complete(consumed) => consumed,
        httparse::Status::Partial => return Err(OwnerBridgeCodecError::InvalidHttpRequest),
    };
    if consumed != input.len() || request.method != Some("GET") || request.version != Some(1) {
        return Err(OwnerBridgeCodecError::InvalidHttpRequest);
    }

    let mut host_seen = false;
    let mut destination_seen = false;
    let mut mode_seen = false;
    for header in request.headers {
        if header.name.len() > MAX_HEADER_NAME_BYTES || header.value.len() > MAX_HEADER_VALUE_BYTES
        {
            return Err(OwnerBridgeCodecError::BoundsExceeded);
        }
        match header.name {
            "Host" => {
                if host_seen || header.value != OWNER_HOST {
                    return Err(OwnerBridgeCodecError::InvalidHttpRequest);
                }
                host_seen = true;
            }
            "Sec-Fetch-Dest" => {
                if destination_seen || header.value != FETCH_DESTINATION {
                    return Err(OwnerBridgeCodecError::InvalidHttpRequest);
                }
                destination_seen = true;
            }
            "Sec-Fetch-Mode" => {
                if mode_seen || header.value != FETCH_MODE {
                    return Err(OwnerBridgeCodecError::InvalidHttpRequest);
                }
                mode_seen = true;
            }
            name if name.eq_ignore_ascii_case("content-length")
                || name.eq_ignore_ascii_case("transfer-encoding") =>
            {
                return Err(OwnerBridgeCodecError::InvalidHttpRequest);
            }
            _ => {}
        }
    }
    if !(host_seen && destination_seen && mode_seen) {
        return Err(OwnerBridgeCodecError::InvalidHttpRequest);
    }

    match request.path {
        Some(OWNER_DOCUMENT_PATH) => Ok(LoopbackRequestDisposition::OwnerDocument),
        Some(_) => Ok(LoopbackRequestDisposition::NotFound),
        None => Err(OwnerBridgeCodecError::InvalidHttpRequest),
    }
}
