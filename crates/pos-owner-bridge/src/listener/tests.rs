//! The loopback binder, the listener's serving internals and the pinned assets, in isolation.

use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use pos_owner_bridge_codec::LoopbackRequestDisposition;
use sha2::{Digest, Sha256};

use super::assets::{
    ASSET_MANIFEST, BAD_REQUEST_RESPONSE, CSP_SCRIPT_SHA256, CSP_STYLE_SHA256, NOT_FOUND_RESPONSE,
    OWNER_HTML, OWNER_HTML_SHA256, OWNER_RESPONSE_HEAD, OWNER_RESPONSE_SHA256,
};
use super::bind::{
    bind_loopback, check_ipv6_absent, classify_bind_error, BindError, Ipv6Mode, LoopbackBinder,
    StdBinder,
};
use super::ledger::ServedLedger;
use super::serve::{
    read_request, respond, write_hashed, write_owner_response, OwnerWrite, ReadOutcome,
    ServeContext, TimedRead, MIN_TIMEOUT, REQUEST_BUFFER_BYTES,
};
use super::{
    dispatch, spawn_thread_handle, start_accept_threads, ListenerConfig, ListenerTimeouts,
    LoopbackListener, Shared, SlotGuard, ADR_TIMEOUTS, MAX_CONCURRENT_CONNECTIONS,
};
use crate::{BridgeError, LoopbackPort, UnavailableCode};

fn expected_owner_response() -> Vec<u8> {
    let mut expected = OWNER_RESPONSE_HEAD.as_bytes().to_vec();
    expected.extend_from_slice(OWNER_HTML);
    expected
}

type TestResult = Result<(), Box<dyn std::error::Error>>;

const NO_PROBE_ERROR: i32 = 0;

/// A scripted binder: IPv4 and IPv6 results are fixed, and the probe error is shared and mutable.
struct ScriptedBinder {
    v4: Result<(), BindError>,
    v6: Result<(), BindError>,
    probe: Arc<AtomicI32>,
}

fn ephemeral() -> Result<TcpListener, BindError> {
    TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).map_err(|_| BindError::Other)
}

impl LoopbackBinder for ScriptedBinder {
    fn bind_v4(&mut self) -> Result<TcpListener, BindError> {
        self.v4.and_then(|()| ephemeral())
    }

    fn bind_v6(&mut self) -> Result<TcpListener, BindError> {
        self.v6.and_then(|()| ephemeral())
    }

    fn probe_v6(&mut self) -> Result<(), BindError> {
        match self.probe.load(Ordering::SeqCst) {
            NO_PROBE_ERROR => Ok(()),
            code => Err(BindError::Unavailable(code)),
        }
    }
}

fn binder(
    v4: Result<(), BindError>,
    v6: Result<(), BindError>,
    probe_error: i32,
) -> (ScriptedBinder, Arc<AtomicI32>) {
    let probe = Arc::new(AtomicI32::new(probe_error));
    let scripted = ScriptedBinder {
        v4,
        v6,
        probe: Arc::clone(&probe),
    };
    (scripted, probe)
}

const PORT_UNAVAILABLE: BridgeError = BridgeError::Unavailable(UnavailableCode::PortUnavailable);
const LOOPBACK_CHANGED: BridgeError = BridgeError::Unavailable(UnavailableCode::LoopbackChanged);

#[test]
fn both_sockets_bind_in_dual_mode() -> TestResult {
    let (mut scripted, _) = binder(Ok(()), Ok(()), NO_PROBE_ERROR);
    let sockets = bind_loopback(&mut scripted)?;
    assert_eq!(sockets.mode, Ipv6Mode::Dual);
    assert!(sockets.v6.is_some());
    Ok(())
}

#[test]
fn identical_absence_runs_ipv4_only() -> TestResult {
    let (mut scripted, _) = binder(Ok(()), Err(BindError::Unavailable(10_047)), 10_047);
    let sockets = bind_loopback(&mut scripted)?;
    assert_eq!(
        sockets.mode,
        Ipv6Mode::Absent {
            startup_error: 10_047
        }
    );
    assert!(sockets.v6.is_none());
    Ok(())
}

#[test]
fn a_succeeding_startup_probe_is_a_loopback_change() {
    let (mut scripted, _) = binder(Ok(()), Err(BindError::Unavailable(10_047)), NO_PROBE_ERROR);
    assert_eq!(bind_loopback(&mut scripted).err(), Some(LOOPBACK_CHANGED));
}

#[test]
fn a_different_startup_probe_error_is_a_loopback_change() {
    let (mut scripted, _) = binder(Ok(()), Err(BindError::Unavailable(10_047)), 10_049);
    assert_eq!(bind_loopback(&mut scripted).err(), Some(LOOPBACK_CHANGED));
}

#[test]
fn ipv6_in_use_or_other_failures_fail_closed() {
    for failure in [BindError::InUse, BindError::Other] {
        let (mut scripted, _) = binder(Ok(()), Err(failure), NO_PROBE_ERROR);
        assert_eq!(bind_loopback(&mut scripted).err(), Some(PORT_UNAVAILABLE));
    }
}

#[test]
fn an_ipv4_failure_fails_closed_in_every_mode() {
    for v6 in [Ok(()), Err(BindError::Unavailable(97))] {
        let (mut scripted, _) = binder(Err(BindError::InUse), v6, 97);
        assert_eq!(bind_loopback(&mut scripted).err(), Some(PORT_UNAVAILABLE));
    }
}

#[test]
fn the_probe_check_accepts_only_the_identical_error_value() {
    let (mut scripted, probe) = binder(Ok(()), Ok(()), 97);
    assert_eq!(check_ipv6_absent(&mut scripted, 97), Ok(()));
    probe.store(99, Ordering::SeqCst);
    assert_eq!(check_ipv6_absent(&mut scripted, 97), Err(LOOPBACK_CHANGED));
    probe.store(NO_PROBE_ERROR, Ordering::SeqCst);
    assert_eq!(check_ipv6_absent(&mut scripted, 97), Err(LOOPBACK_CHANGED));
}

#[test]
fn the_listener_reports_loopback_changed_when_ipv6_appears_after_startup() -> TestResult {
    let (scripted, probe) = binder(Ok(()), Err(BindError::Unavailable(97)), 97);
    let mut listener = LoopbackListener::start(Box::new(scripted), ListenerConfig::adr())?;
    assert_eq!(listener.mode(), Ipv6Mode::Absent { startup_error: 97 });
    assert!(listener.v6_addr().is_none());
    assert_eq!(listener.probe_ipv6(), Ok(()));
    probe.store(NO_PROBE_ERROR, Ordering::SeqCst);
    assert_eq!(listener.probe_ipv6(), Err(LOOPBACK_CHANGED));
    Ok(())
}

#[test]
fn a_dual_listener_probe_is_a_no_op() -> TestResult {
    let (scripted, _) = binder(Ok(()), Ok(()), NO_PROBE_ERROR);
    let mut listener = LoopbackListener::start(Box::new(scripted), ListenerConfig::adr())?;
    assert_eq!(listener.mode(), Ipv6Mode::Dual);
    assert!(listener.v6_addr().is_some());
    assert_eq!(listener.probe_ipv6(), Ok(()));
    Ok(())
}

#[test]
fn the_listener_refuses_to_start_when_binding_fails() {
    let (scripted, _) = binder(Err(BindError::InUse), Ok(()), NO_PROBE_ERROR);
    let started = LoopbackListener::start(Box::new(scripted), ListenerConfig::adr());
    assert_eq!(started.err(), Some(PORT_UNAVAILABLE));
}

/// The error values that mean "no IPv6 loopback" on this platform, and values that mean it only
/// on another platform and so must not be taken for absence here.
#[cfg(target_os = "linux")]
const ABSENT: [i32; 2] = [97, 99];
#[cfg(target_os = "linux")]
const FOREIGN: [i32; 2] = [10_047, 10_049];
#[cfg(target_os = "macos")]
const ABSENT: [i32; 2] = [47, 49];
#[cfg(target_os = "macos")]
const FOREIGN: [i32; 2] = [10_047, 10_049];
#[cfg(windows)]
const ABSENT: [i32; 2] = [10_047, 10_049];
#[cfg(windows)]
const FOREIGN: [i32; 2] = [97, 99];
#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
const ABSENT: [i32; 0] = [];
#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
const FOREIGN: [i32; 0] = [];

#[test]
fn bind_failures_are_classified_by_kind_and_platform_value() {
    let in_use = io::Error::from(io::ErrorKind::AddrInUse);
    assert_eq!(classify_bind_error(&in_use), BindError::InUse);
    for code in ABSENT {
        let absent = io::Error::from_raw_os_error(code);
        assert_eq!(classify_bind_error(&absent), BindError::Unavailable(code));
    }
    for code in FOREIGN {
        let elsewhere = io::Error::from_raw_os_error(code);
        assert_eq!(classify_bind_error(&elsewhere), BindError::Other);
    }
    let other = io::Error::from_raw_os_error(1);
    assert_eq!(classify_bind_error(&other), BindError::Other);
    assert_eq!(
        classify_bind_error(&io::Error::other("no code")),
        BindError::Other
    );
}

#[test]
fn the_std_binder_binds_ephemeral_ports_and_reports_a_conflict() -> TestResult {
    let first = StdBinder::new(0).bind_v4()?;
    let port = first.local_addr()?.port();
    assert_eq!(StdBinder::new(port).bind_v4().err(), Some(BindError::InUse));
    let held = StdBinder::new(0).bind_v6();
    assert!(held.is_ok() || matches!(held, Err(BindError::Unavailable(_))));
    let probe = StdBinder::new(0).probe_v6();
    assert!(probe.is_ok() || matches!(probe, Err(BindError::Unavailable(_))));
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

#[test]
fn the_embedded_document_matches_its_manifest_and_pinned_digests() {
    let html: [u8; 32] = Sha256::digest(OWNER_HTML).into();
    assert_eq!(html, OWNER_HTML_SHA256);
    let hex = html
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .concat();
    assert_eq!(
        ASSET_MANIFEST,
        format!("{hex}  /owner.html  text/html; charset=utf-8\n")
    );
    let mut response = Sha256::new();
    response.update(OWNER_RESPONSE_HEAD.as_bytes());
    response.update(OWNER_HTML);
    let digest: [u8; 32] = response.finalize().into();
    assert_eq!(digest, OWNER_RESPONSE_SHA256);
    assert!(OWNER_RESPONSE_HEAD.contains(&format!("Content-Length: {}\r\n", OWNER_HTML.len())));
    let text = String::from_utf8_lossy(OWNER_HTML);
    let hashed = |tag: &str| {
        let start = text.find(&format!("<{tag}>")).map(|at| at + tag.len() + 2);
        let end = text.find(&format!("</{tag}>"));
        start
            .zip(end)
            .and_then(|(from, to)| text.get(from..to))
            .map(|inner| {
                let digest: [u8; 32] = Sha256::digest(inner.as_bytes()).into();
                digest
            })
    };
    for (tag, pinned) in [("script", CSP_SCRIPT_SHA256), ("style", CSP_STYLE_SHA256)] {
        let digest = hashed(tag).map(|bytes| base64_standard(&bytes));
        assert_eq!(digest.as_deref(), Some(pinned));
        for head in [
            OWNER_RESPONSE_HEAD,
            NOT_FOUND_RESPONSE,
            BAD_REQUEST_RESPONSE,
        ] {
            assert!(head.contains(&format!("'sha256-{pinned}'")));
        }
    }
    assert!(NOT_FOUND_RESPONSE.contains("Content-Length: 0\r\n"));
    assert!(BAD_REQUEST_RESPONSE.starts_with("HTTP/1.1 400"));
}

fn base64_standard(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let mut group = [0_u8; 3];
        group[..chunk.len()].copy_from_slice(chunk);
        let word = (u32::from(group[0]) << 16) | (u32::from(group[1]) << 8) | u32::from(group[2]);
        for position in 0..4 {
            if position <= chunk.len() {
                let index = usize::try_from((word >> (18 - 6 * position)) & 63).unwrap_or(0);
                out.push(char::from(ALPHABET.get(index).copied().unwrap_or(b'A')));
            } else {
                out.push('=');
            }
        }
    }
    out
}

const OWNER_REQUEST: &[u8] = b"GET /owner.html HTTP/1.1\r\nHost: localhost:49291\r\n\
Sec-Fetch-Dest: document\r\nSec-Fetch-Mode: navigate\r\n\r\n";

/// A reader that delivers scripted chunks and records the limit given before each read.
struct Scripted {
    chunks: VecDeque<io::Result<Vec<u8>>>,
    limits: Vec<Duration>,
}

impl Scripted {
    fn new(chunks: Vec<io::Result<Vec<u8>>>) -> Self {
        Self {
            chunks: chunks.into(),
            limits: Vec::new(),
        }
    }
}

impl Read for Scripted {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        match self.chunks.pop_front() {
            Some(Ok(chunk)) => {
                let count = chunk.len().min(buffer.len());
                buffer
                    .get_mut(..count)
                    .unwrap_or_default()
                    .copy_from_slice(chunk.get(..count).unwrap_or_default());
                Ok(count)
            }
            Some(Err(error)) => Err(error),
            None => Ok(0),
        }
    }
}

impl TimedRead for Scripted {
    fn limit_next_read(&mut self, limit: Duration) -> io::Result<()> {
        self.limits.push(limit);
        Ok(())
    }
}

fn read_scripted(
    chunks: Vec<io::Result<Vec<u8>>>,
    timeouts: ListenerTimeouts,
) -> (ReadOutcome, Vec<Duration>) {
    let mut reader = Scripted::new(chunks);
    let mut buffer = [0_u8; REQUEST_BUFFER_BYTES];
    let outcome = read_request(&mut reader, &mut buffer, timeouts);
    (outcome, reader.limits)
}

#[test]
fn a_request_head_that_arrives_in_pieces_is_assembled_under_each_deadline() {
    let timeouts = ListenerTimeouts {
        first_byte: Duration::from_secs(10),
        header: Duration::from_secs(20),
        idle: Duration::from_secs(30),
    };
    let (first, second) = OWNER_REQUEST.split_at(20);
    let chunks = vec![Ok(first.to_vec()), Ok(second.to_vec())];
    let (outcome, limits) = read_scripted(chunks, timeouts);
    assert_eq!(outcome, ReadOutcome::Complete(OWNER_REQUEST.len()));
    assert_eq!(limits.len(), 2, "{limits:?}");
    let before_first_byte = limits.first().copied().unwrap_or_default();
    let before_header_end = limits.get(1).copied().unwrap_or_default();
    assert!(before_first_byte <= timeouts.first_byte);
    assert!(before_header_end > timeouts.first_byte);
    assert!(before_header_end <= timeouts.header);
}

#[test]
fn a_silent_closed_or_failed_read_is_answered_with_nothing() {
    let timeouts = ListenerConfig::adr().timeouts();
    for chunks in [
        vec![Ok(Vec::new())],
        vec![Err(io::Error::from(io::ErrorKind::TimedOut))],
        vec![Ok(b"GET /owner".to_vec()), Ok(Vec::new())],
    ] {
        assert_eq!(read_scripted(chunks, timeouts).0, ReadOutcome::Silent);
    }
}

#[test]
fn a_full_buffer_without_the_end_of_the_head_is_too_large() {
    let chunks = vec![Ok(vec![b'a'; REQUEST_BUFFER_BYTES])];
    let outcome = read_scripted(chunks, ListenerConfig::adr().timeouts()).0;
    assert_eq!(outcome, ReadOutcome::TooLarge);
    let chunks = vec![Ok(vec![b'a'; REQUEST_BUFFER_BYTES - 1]), Ok(b"a".to_vec())];
    let outcome = read_scripted(chunks, ListenerConfig::adr().timeouts()).0;
    assert_eq!(outcome, ReadOutcome::TooLarge);
}

#[test]
fn a_passed_deadline_still_reads_for_the_shortest_limit_a_socket_accepts() {
    let timeouts = ListenerTimeouts {
        first_byte: Duration::ZERO,
        ..ListenerConfig::adr().timeouts()
    };
    let (outcome, limits) = read_scripted(vec![Ok(OWNER_REQUEST.to_vec())], timeouts);
    assert_eq!(outcome, ReadOutcome::Complete(OWNER_REQUEST.len()));
    assert_eq!(limits, [MIN_TIMEOUT]);
}

#[test]
fn the_fixed_error_responses_are_written_exactly() {
    let context = ServeContext {
        ledger: Arc::new(ServedLedger::default()),
        timeouts: ADR_TIMEOUTS,
        expected_digest: ADR_DIGEST,
    };
    let cases = [
        (None, BAD_REQUEST_RESPONSE),
        (
            Some(LoopbackRequestDisposition::NotFound),
            NOT_FOUND_RESPONSE,
        ),
    ];
    for (disposition, expected) in cases {
        let mut writer = flaky(64, usize::MAX, false);
        respond(&mut writer, disposition, &context);
        assert_eq!(writer.accepted, expected.as_bytes());
    }
    assert_eq!(context.ledger.snapshot().count, 0);
}

#[test]
fn production_listener_values_are_the_adr_values() {
    let config = ListenerConfig::adr();
    assert_eq!(
        config.timeouts(),
        ListenerTimeouts {
            first_byte: Duration::from_secs(1),
            header: Duration::from_secs(2),
            idle: Duration::from_secs(30),
        }
    );
    assert_eq!(config.timeouts(), ADR_TIMEOUTS);
    assert_eq!(*config.expected_digest(), OWNER_RESPONSE_SHA256);
    assert_eq!(super::MAX_CONCURRENT_CONNECTIONS, 3);
}

fn held(shared: &Arc<Shared>) -> usize {
    shared.active.load(Ordering::SeqCst)
}

fn serve_context() -> Arc<ServeContext> {
    Arc::new(ServeContext {
        ledger: Arc::new(ServedLedger::default()),
        timeouts: ADR_TIMEOUTS,
        expected_digest: ADR_DIGEST,
    })
}

fn connected() -> Result<(TcpStream, TcpStream), io::Error> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let client = TcpStream::connect(listener.local_addr()?)?;
    let (server, _) = listener.accept()?;
    Ok((client, server))
}

#[test]
fn a_slot_guard_frees_its_slot_when_it_is_dropped() {
    let shared = Arc::new(Shared::default());
    let guards: Vec<Option<SlotGuard>> = (0..MAX_CONCURRENT_CONNECTIONS)
        .map(|_| SlotGuard::acquire(&shared))
        .collect();
    assert!(guards.iter().all(Option::is_some));
    assert_eq!(held(&shared), MAX_CONCURRENT_CONNECTIONS);
    assert!(SlotGuard::acquire(&shared).is_none());
    drop(guards);
    assert_eq!(held(&shared), 0);
    assert!(SlotGuard::acquire(&shared).is_some());
}

#[test]
fn a_worker_that_cannot_be_spawned_gives_back_its_slot_and_closes_the_stream() -> TestResult {
    let shared = Arc::new(Shared::default());
    let (mut client, server) = connected()?;
    let slot = SlotGuard::acquire(&shared).ok_or("no slot")?;
    assert_eq!(held(&shared), 1);
    dispatch(server, slot, &serve_context(), |_work| {
        Err(io::Error::other("no threads left"))
    });
    assert_eq!(held(&shared), 0);
    let mut closed = Vec::new();
    assert_eq!(io::Read::read_to_end(&mut client, &mut closed)?, 0);
    Ok(())
}

#[test]
fn a_worker_that_runs_gives_back_its_slot_when_it_finishes() -> TestResult {
    let shared = Arc::new(Shared::default());
    let (client, server) = connected()?;
    drop(client);
    let slot = SlotGuard::acquire(&shared).ok_or("no slot")?;
    dispatch(server, slot, &serve_context(), |work| {
        work();
        Ok(())
    });
    assert_eq!(held(&shared), 0);
    Ok(())
}

fn bound() -> Result<TcpListener, io::Error> {
    TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
}

#[test]
fn accept_threads_start_for_every_socket_and_stop_on_request() -> TestResult {
    let shared = Arc::new(Shared::default());
    let sockets = [bound()?, bound()?];
    let workers = start_accept_threads(
        sockets,
        &serve_context(),
        &shared,
        |socket| socket.set_nonblocking(true),
        spawn_thread_handle,
    )?;
    assert_eq!(workers.len(), 2);
    shared.stop.store(true, Ordering::SeqCst);
    for worker in workers {
        assert!(worker.join().is_ok());
    }
    Ok(())
}

#[test]
fn a_socket_that_cannot_be_configured_stops_the_threads_already_started() -> TestResult {
    let shared = Arc::new(Shared::default());
    let calls = std::cell::Cell::new(0);
    let outcome = start_accept_threads(
        [bound()?, bound()?],
        &serve_context(),
        &shared,
        |socket| {
            calls.set(calls.get() + 1);
            if calls.get() == 2 {
                Err(io::Error::other("cannot configure"))
            } else {
                socket.set_nonblocking(true)
            }
        },
        spawn_thread_handle,
    );
    assert!(outcome.is_err());
    assert!(shared.stop.load(Ordering::SeqCst));
    Ok(())
}

#[test]
fn a_thread_that_cannot_be_spawned_fails_the_start_and_stops_the_others() -> TestResult {
    let shared = Arc::new(Shared::default());
    let spawned = std::cell::Cell::new(0);
    let outcome = start_accept_threads(
        [bound()?, bound()?],
        &serve_context(),
        &shared,
        |socket| socket.set_nonblocking(true),
        |work| {
            spawned.set(spawned.get() + 1);
            if spawned.get() == 2 {
                Err(io::Error::other("no threads left"))
            } else {
                spawn_thread_handle(work)
            }
        },
    );
    assert!(outcome.is_err());
    assert!(shared.stop.load(Ordering::SeqCst));
    Ok(())
}
