use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

use pos_owner_bridge::listener::assets::{
    BAD_REQUEST_RESPONSE, NOT_FOUND_RESPONSE, OWNER_HTML, OWNER_RESPONSE_HEAD,
    OWNER_RESPONSE_SHA256,
};
use pos_owner_bridge::listener::bind::StdBinder;
use pos_owner_bridge::listener::ledger::ServedLedger;
use pos_owner_bridge::listener::serve::{
    respond, write_hashed, write_owner_response, ListenerTimeouts, OwnerWrite, ServeContext,
    ADR_TIMEOUTS,
};
use pos_owner_bridge::listener::{ListenerConfig, LoopbackListener, MAX_CONCURRENT_CONNECTIONS};
use pos_owner_bridge::LoopbackPort;
use pos_owner_bridge_codec::LoopbackRequestDisposition;
use sha2::Digest;
use sha2::Sha256;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const OWNER_REQUEST: &[u8] = b"GET /owner.html HTTP/1.1\r\nHost: localhost:49291\r\n\
Sec-Fetch-Dest: document\r\nSec-Fetch-Mode: navigate\r\n\r\n";

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

fn expected_owner_response() -> Vec<u8> {
    let mut expected = OWNER_RESPONSE_HEAD.as_bytes().to_vec();
    expected.extend_from_slice(OWNER_HTML);
    expected
}

#[test]
fn serves_the_exact_pinned_owner_response_once() -> TestResult {
    let listener = start(ListenerConfig::adr())?;
    let response = exchange(listener.v4_addr(), OWNER_REQUEST)?;
    assert_eq!(response, expected_owner_response());
    let served = listener.served();
    assert_eq!(served.count, 1);
    assert!(served.integrity_ok);
    assert_eq!(ListenerConfig::adr().expected_digest, OWNER_RESPONSE_SHA256);
    Ok(())
}

#[test]
fn serves_over_ipv6_when_the_ipv6_loopback_is_held() -> TestResult {
    let listener = start(ListenerConfig::adr())?;
    if let Some(v6) = listener.v6_addr() {
        assert_eq!(exchange(v6, OWNER_REQUEST)?, expected_owner_response());
        assert_eq!(listener.served().count, 1);
    } else {
        assert!(listener.v6_addr().is_none());
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
    assert_eq!(response, NOT_FOUND_RESPONSE.as_bytes());
    assert_eq!(listener.served().count, 0);
    Ok(())
}

#[test]
fn a_malformed_request_gets_the_fixed_400() -> TestResult {
    let listener = start(ListenerConfig::adr())?;
    let response = exchange(listener.v4_addr(), b"POST /owner.html HTTP/1.1\r\n\r\n")?;
    assert_eq!(response, BAD_REQUEST_RESPONSE.as_bytes());
    assert_eq!(listener.served().count, 0);
    Ok(())
}

#[test]
fn a_header_block_that_fills_the_buffer_gets_the_fixed_400() -> TestResult {
    let listener = start(ListenerConfig::adr())?;
    let response = exchange(listener.v4_addr(), &[b'a'; 8_192])?;
    assert_eq!(response, BAD_REQUEST_RESPONSE.as_bytes());
    Ok(())
}

#[test]
fn a_silent_connection_is_closed_after_the_first_byte_timeout_without_a_response() -> TestResult {
    let listener = start(ListenerConfig::adr())?;
    let started = Instant::now();
    let response = exchange(listener.v4_addr(), b"")?;
    assert!(response.is_empty());
    assert!(started.elapsed() >= Duration::from_millis(900));
    assert!(started.elapsed() < Duration::from_secs(5));
    Ok(())
}

#[test]
fn an_incomplete_header_block_is_closed_at_the_header_deadline_without_a_response() -> TestResult {
    let config = ListenerConfig {
        timeouts: ListenerTimeouts {
            first_byte: Duration::from_millis(300),
            header: Duration::from_millis(300),
            idle: Duration::from_secs(30),
        },
        expected_digest: OWNER_RESPONSE_SHA256,
    };
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
    assert_eq!(response, expected_owner_response());
    assert!(started.elapsed() >= Duration::from_millis(900));
    assert!(started.elapsed() < ADR_TIMEOUTS.first_byte + Duration::from_secs(3));
    assert_eq!(listener.served().count, 1);
    drop(silent);
    Ok(())
}

#[test]
fn a_digest_mismatch_fails_the_integrity_verdict() -> TestResult {
    let config = ListenerConfig {
        timeouts: ADR_TIMEOUTS,
        expected_digest: [0; 32],
    };
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
    let address = listener.v4_addr();
    listener.shutdown();
    listener.shutdown();
    assert!(TcpStream::connect_timeout(&address, Duration::from_millis(500)).is_err());
    Ok(())
}

#[test]
fn a_request_that_arrives_in_two_segments_is_served() -> TestResult {
    let listener = start(ListenerConfig::adr())?;
    let mut stream = TcpStream::connect(listener.v4_addr())?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    let (first, second) = OWNER_REQUEST.split_at(20);
    stream.write_all(first)?;
    std::thread::sleep(Duration::from_millis(100));
    stream.write_all(second)?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response)?;
    assert_eq!(response, expected_owner_response());
    Ok(())
}

/// A writer that accepts a few bytes at a time, then fails the way a closed peer does.
struct Flaky {
    accepted: Vec<u8>,
    chunk: usize,
    budget: usize,
    fail_with_error: bool,
}

impl Write for Flaky {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.accepted.len() >= self.budget {
            return if self.fail_with_error {
                Err(io::Error::from(io::ErrorKind::BrokenPipe))
            } else {
                Ok(0)
            };
        }
        let take = bytes
            .len()
            .min(self.chunk)
            .min(self.budget - self.accepted.len());
        self.accepted
            .extend_from_slice(bytes.get(..take).unwrap_or_default());
        Ok(take)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

const fn flaky(chunk: usize, budget: usize, fail_with_error: bool) -> Flaky {
    Flaky {
        accepted: Vec::new(),
        chunk,
        budget,
        fail_with_error,
    }
}

#[test]
fn only_the_bytes_the_writer_accepted_are_hashed() {
    let mut hasher = Sha256::new();
    let mut partial = flaky(7, usize::MAX, false);
    assert!(write_hashed(&mut partial, b"hello world", &mut hasher));
    assert_eq!(partial.accepted, b"hello world");
    let digest: [u8; 32] = hasher.finalize().into();
    let expected: [u8; 32] = Sha256::digest(b"hello world").into();
    assert_eq!(digest, expected);
    for fail_with_error in [false, true] {
        let mut broken = flaky(4, 5, fail_with_error);
        assert!(!write_hashed(
            &mut broken,
            b"hello world",
            &mut Sha256::new()
        ));
        assert_eq!(broken.accepted, b"hello");
    }
}

#[test]
fn a_failed_or_mismatched_owner_response_never_counts_as_served() {
    let mut whole = flaky(64, usize::MAX, false);
    let complete = write_owner_response(&mut whole, &ADR_DIGEST);
    assert_eq!(complete, OwnerWrite::Complete { digest_ok: true });
    assert_eq!(whole.accepted, expected_owner_response());
    let mut mismatched = flaky(4_096, usize::MAX, false);
    assert_eq!(
        write_owner_response(&mut mismatched, &[0; 32]),
        OwnerWrite::Complete { digest_ok: false }
    );
    for budget in [10, OWNER_RESPONSE_HEAD.len() + 10] {
        let mut cut = flaky(100, budget, true);
        assert_eq!(
            write_owner_response(&mut cut, &ADR_DIGEST),
            OwnerWrite::Incomplete
        );
    }
}

const ADR_DIGEST: [u8; 32] = OWNER_RESPONSE_SHA256;

#[test]
fn responses_to_a_broken_peer_leave_the_ledger_untouched() {
    let ledger = Arc::new(ServedLedger::default());
    let context = ServeContext {
        ledger: Arc::clone(&ledger),
        timeouts: ADR_TIMEOUTS,
        expected_digest: ADR_DIGEST,
    };
    for disposition in [
        Some(LoopbackRequestDisposition::OwnerDocument),
        Some(LoopbackRequestDisposition::NotFound),
        None,
    ] {
        respond(&mut flaky(8, 20, true), disposition, &context);
    }
    assert_eq!(ledger.snapshot().count, 0);
    respond(
        &mut flaky(4_096, usize::MAX, false),
        Some(LoopbackRequestDisposition::OwnerDocument),
        &context,
    );
    assert_eq!(ledger.snapshot().count, 1);
}
