//! The loopback listener over real sockets, through its public seam only.

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant};

use pos_owner_bridge::listener::bind::StdBinder;
use pos_owner_bridge::listener::{
    ListenerConfig, ListenerTimeouts, LoopbackListener, MAX_CONCURRENT_CONNECTIONS,
};
use pos_owner_bridge::LoopbackPort;
use sha2::{Digest, Sha256};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const OWNER_REQUEST: &[u8] = b"GET /owner.html HTTP/1.1\r\nHost: localhost:49291\r\n\
Sec-Fetch-Dest: document\r\nSec-Fetch-Mode: navigate\r\n\r\n";

/// The packaged page, read from the crate's assets rather than from the listener's internals.
const OWNER_PAGE: &[u8] = include_bytes!("../assets/owner.html");

fn start(config: ListenerConfig) -> Result<LoopbackListener, pos_owner_bridge::BridgeError> {
    LoopbackListener::start(Box::new(StdBinder::new(0)), config)
}

fn exchange(address: SocketAddr, request: &[u8]) -> io::Result<Vec<u8>> {
    let mut stream = TcpStream::connect(address)?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.write_all(request)?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response)?;
    Ok(response)
}

/// Whether `response` is the pinned owner response: the pinned digest of head and body, and the
/// packaged page as its body.
fn is_the_pinned_owner_response(response: &[u8]) -> bool {
    let digest: [u8; 32] = Sha256::digest(response).into();
    digest == *ListenerConfig::adr().expected_digest() && response.ends_with(OWNER_PAGE)
}

#[test]
fn serves_the_exact_pinned_owner_response_once() -> TestResult {
    let listener = start(ListenerConfig::adr())?;
    let response = exchange(listener.v4_addr(), OWNER_REQUEST)?;
    assert!(is_the_pinned_owner_response(&response));
    let served = listener.served();
    assert_eq!(served.count, 1);
    assert!(served.integrity_ok);
    Ok(())
}

#[test]
fn serves_over_ipv6_when_the_ipv6_loopback_is_held() -> TestResult {
    let listener = start(ListenerConfig::adr())?;
    // This only exercises the IPv6 serve path on a host that has an IPv6 loopback; the held-v6
    // path is also covered in `listener/tests.rs`.
    if let Some(v6) = listener.v6_addr() {
        assert!(is_the_pinned_owner_response(&exchange(v6, OWNER_REQUEST)?));
        assert_eq!(listener.served().count, 1);
    }
    Ok(())
}

#[test]
fn a_second_completion_raises_the_served_count_and_navigation_resets_it() -> TestResult {
    let mut listener = start(ListenerConfig::adr())?;
    exchange(listener.v4_addr(), OWNER_REQUEST)?;
    exchange(listener.v4_addr(), OWNER_REQUEST)?;
    assert_eq!(listener.served().count, 2);
    listener.begin_navigation();
    assert_eq!(listener.served().count, 0);
    assert!(listener.served().integrity_ok);
    Ok(())
}

#[test]
fn another_admitted_path_gets_the_fixed_404_and_is_not_counted() -> TestResult {
    let listener = start(ListenerConfig::adr())?;
    let request = b"GET /favicon.ico HTTP/1.1\r\nHost: localhost:49291\r\n\
Sec-Fetch-Dest: document\r\nSec-Fetch-Mode: navigate\r\n\r\n";
    let response = exchange(listener.v4_addr(), request)?;
    assert!(response.starts_with(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n"));
    assert_eq!(listener.served().count, 0);
    Ok(())
}

#[test]
fn a_malformed_request_gets_the_fixed_400() -> TestResult {
    let listener = start(ListenerConfig::adr())?;
    let response = exchange(listener.v4_addr(), b"POST /owner.html HTTP/1.1\r\n\r\n")?;
    assert!(response.starts_with(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n"));
    assert_eq!(listener.served().count, 0);
    Ok(())
}

#[test]
fn a_header_block_that_fills_the_buffer_gets_the_fixed_400() -> TestResult {
    let listener = start(ListenerConfig::adr())?;
    let response = exchange(listener.v4_addr(), &[b'a'; 8_192])?;
    assert!(response.starts_with(b"HTTP/1.1 400 Bad Request\r\n"));
    Ok(())
}

#[test]
fn a_silent_connection_is_closed_after_the_first_byte_timeout_without_a_response() -> TestResult {
    let listener = start(ListenerConfig::adr())?;
    let started = Instant::now();
    let response = exchange(listener.v4_addr(), b"")?;
    assert!(response.is_empty());
    // Only the lower bound is deterministic. A loaded runner may take longer, and the client's
    // own ten-second read timeout turns a hung listener into a failure.
    assert!(started.elapsed() >= Duration::from_millis(900));
    Ok(())
}

#[test]
fn an_incomplete_header_block_is_closed_at_the_header_deadline_without_a_response() -> TestResult {
    let timeouts = ListenerTimeouts {
        first_byte: Duration::from_millis(300),
        header: Duration::from_millis(300),
        idle: Duration::from_secs(30),
    };
    let config = ListenerConfig::new(timeouts, *ListenerConfig::adr().expected_digest());
    let listener = start(config)?;
    let started = Instant::now();
    let response = exchange(listener.v4_addr(), b"GET /owner.html HTTP/1.1\r\nHost")?;
    assert!(response.is_empty());
    assert!(started.elapsed() >= Duration::from_millis(250));
    Ok(())
}

#[test]
fn silent_preconnect_sockets_cannot_starve_a_real_navigation() -> TestResult {
    let listener = start(ListenerConfig::adr())?;
    let address = listener.v4_addr();
    let silent: Vec<TcpStream> = (0..MAX_CONCURRENT_CONNECTIONS)
        .map(|_| TcpStream::connect(address))
        .collect::<io::Result<_>>()?;
    let started = Instant::now();
    let response = exchange(address, OWNER_REQUEST)?;
    assert!(is_the_pinned_owner_response(&response));
    // The three silent sockets hold every slot until their first-byte deadline, so the real
    // request cannot have been answered earlier. There is no upper bound: see above.
    assert!(started.elapsed() >= Duration::from_millis(900));
    assert_eq!(listener.served().count, 1);
    drop(silent);
    Ok(())
}

#[test]
fn a_digest_mismatch_fails_the_integrity_verdict() -> TestResult {
    let config = ListenerConfig::new(ListenerConfig::adr().timeouts(), [0; 32]);
    let listener = start(config)?;
    exchange(listener.v4_addr(), OWNER_REQUEST)?;
    let served = listener.served();
    assert_eq!(served.count, 1);
    assert!(!served.integrity_ok);
    Ok(())
}

#[test]
fn shutdown_is_idempotent_and_stops_accepting() -> TestResult {
    let mut listener = start(ListenerConfig::adr())?;
    assert!(listener.is_running());
    listener.shutdown();
    assert!(!listener.is_running());
    listener.shutdown();
    assert!(!listener.is_running());
    Ok(())
}

#[test]
fn a_request_written_in_two_segments_is_served() -> TestResult {
    let listener = start(ListenerConfig::adr())?;
    let mut stream = TcpStream::connect(listener.v4_addr())?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_nodelay(true)?;
    let (first, second) = OWNER_REQUEST.split_at(20);
    stream.write_all(first)?;
    stream.flush()?;
    // Whether the listener reads the segments apart or together, the request must be served.
    // Reading them apart is tested deterministically against a scripted reader in the crate.
    stream.write_all(second)?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response)?;
    assert!(is_the_pinned_owner_response(&response));
    Ok(())
}
