//! ADR-069 R11 §5.1 steps 7 and 8 and §7 in the states `Starting`, `Open`
//! and `ReconcileFailed`, against the signed test installation staged as
//! root in the isolated container (invariants 9 to 13, 15 to 17).

use std::ffi::OsStr;
use std::fs;
use std::io::{Read, Write};
use std::os::linux::net::SocketAddrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{SocketAddr, UnixDatagram, UnixListener, UnixStream};
use std::path::Path;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{mpsc, Arc, OnceLock};
use std::time::{Duration, Instant};

use ciborium::value::Value;
use ed25519_dalek::VerifyingKey;
use pos_reference::provider_admission::test_support::StagedInstallation;
use pos_reference::sandbox_provider_protocol::{
    AdmissionGrant, RevocationUpdateRequest, SandboxCancelRequest, SandboxDescribeRequest,
    SandboxDescribeResponse, SandboxExecuteRequest, SandboxProviderError, SandboxProviderErrorCode,
    SandboxProviderResult, SandboxReconcileRequest, SandboxTerminalOutcome,
};
use pos_reference::selector::installation::authority::AdmittedSelectorProvider;
use rustix::event::PollFlags;

use super::{
    accepting, exchange_deadline, missed, readiness, trusted_peer, Admission, ControlState,
    Deadlined, Responder, EXECUTE_CLOSED, FENCED, LIVE, REVOKED,
};
use crate::provider_runtime::endpoint::bind_endpoints;
use crate::provider_runtime::port::ExecutePort;
use crate::provider_runtime::reconcile::ReconcileError;
use crate::provider_runtime::tests::PortFixture;
use crate::provider_runtime::tests::{
    bind_as_provider, cancellation_context, encode, in_isolated_root, install_spi1,
    key_and_provider_revocation_update, revocation_update, spi1, test_port, Scripted, TestResult,
    RUNTIME_SEED,
};
use crate::provider_runtime::ExchangeObserver;
use crate::provider_runtime::{
    serve_with, AdmissionState, ProviderRuntimeError, ProviderStartupError, RuntimeAuthority,
};
use crate::StagingLimits;

const RUNTIME: &str = "/run/pigloros";
const EXECUTE: &str = "/run/pigloros/provider-execute.sock";
const CONTROL: &str = "/run/pigloros/provider-control.sock";
const NOTIFY: &str = "@pigloros-provider-runtime-notify";
const CLIENT_TIMEOUT: Duration = Duration::from_secs(10);

/// The retained authority a request names.
#[derive(Clone, Copy)]
pub(super) struct Authority {
    pub(super) apt1: [u8; 32],
    pub(super) epoch: u64,
}

/// Stage SIC1 with an execution source, SPI1, its key and `/run/pigloros`.
fn stage() -> TestResult<StagedInstallation> {
    let staged = StagedInstallation::stage_execution()?;
    install_spi1(&spi1(22)?, &RUNTIME_SEED)?;
    fs::create_dir(RUNTIME)?;
    fs::set_permissions(RUNTIME, fs::Permissions::from_mode(0o755))?;
    Ok(staged)
}

/// `records`, each with its four-byte big-endian length.
fn framed(records: &[&[u8]]) -> TestResult<Vec<u8>> {
    let mut bytes = Vec::new();
    for record in records {
        bytes.extend(u32::try_from(record.len())?.to_be_bytes());
        bytes.extend(*record);
    }
    Ok(bytes)
}

/// Send `bytes` to `endpoint`, end the write side, and read to EOF.
fn exchange_at(endpoint: &str, bytes: &[u8]) -> TestResult<Vec<u8>> {
    let mut stream = UnixStream::connect(endpoint)?;
    stream.set_read_timeout(Some(CLIENT_TIMEOUT))?;
    stream.write_all(bytes)?;
    stream.shutdown(std::net::Shutdown::Write)?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response)?;
    Ok(response)
}

fn exchange(records: &[&[u8]]) -> TestResult<Vec<u8>> {
    exchange_at(EXECUTE, &framed(records)?)
}

/// The one record of a complete response.
fn unframe(response: &[u8]) -> TestResult<&[u8]> {
    let (prefix, record) = response.split_at_checked(4).ok_or("short response")?;
    assert_eq!(
        usize::try_from(u32::from_be_bytes(prefix.try_into()?))?,
        record.len()
    );
    Ok(record)
}

/// A self-digested request record: `[[magic, version, fields..], digest]`,
/// whose digest is flipped when `corrupt`.
pub(super) fn request(
    magic: &str,
    version: u64,
    fields: Vec<Value>,
    corrupt: bool,
) -> TestResult<Vec<u8>> {
    let mut prefix = vec![
        Value::Text(magic.to_owned()),
        Value::Integer(version.into()),
    ];
    prefix.extend(fields);
    let unsigned = Value::Array(prefix);
    let mut preimage = format!("PiglorOS.{magic}.v1\0").into_bytes();
    preimage.extend(encode(&unsigned)?);
    let mut digest = *blake3::hash(&preimage).as_bytes();
    if corrupt {
        digest[0] ^= 1;
    }
    encode(&Value::Array(vec![unsigned, Value::Bytes(digest.to_vec())]))
}

pub(super) fn request_authority(request_id: [u8; 16], authority: Authority) -> Value {
    Value::Array(vec![
        Value::Bytes(request_id.to_vec()),
        Value::Bytes(authority.apt1.to_vec()),
        Value::Integer(authority.epoch.into()),
        Value::Bytes(vec![7; 16]),
    ])
}

pub(super) fn describe(request_id: [u8; 16], authority: Authority) -> TestResult<Vec<u8>> {
    request(
        "SDQ1",
        1,
        vec![request_authority(request_id, authority)],
        false,
    )
}

/// An SCQ1 or SRQ1 for attempt `[9; 16]`.
fn attempt_request(magic: &str, authority: Authority) -> TestResult<Vec<u8>> {
    request(
        magic,
        1,
        vec![
            request_authority([8; 16], authority),
            Value::Bytes(vec![9; 16]),
            Value::Bytes(vec![10; 32]),
        ],
        false,
    )
}

/// The SPE1 of `response`, verified under the runtime key with no detail.
fn refusal(response: &[u8], key: &VerifyingKey) -> TestResult<SandboxProviderError> {
    let error = SandboxProviderError::from_canonical_cbor(unframe(response)?)?;
    error.verify_signature(key)?;
    assert_eq!(error.safe_detail, None);
    assert_eq!(error.runtime_attestation_key_id, "runtime");
    Ok(error)
}

/// Assert an SPE1 of `code` that names only `operation`.
fn assert_invalid(
    response: &[u8],
    key: &VerifyingKey,
    operation: Option<u8>,
    code: SandboxProviderErrorCode,
) -> TestResult {
    let error = refusal(response, key)?;
    assert_eq!(
        (
            error.operation,
            error.request_id,
            error.request_digest,
            error.attempt_id,
            error.code
        ),
        (operation, None, None, None, code)
    );
    Ok(())
}

/// Assert an SPE1 of `code` that binds every identity of the request.
fn assert_refused(
    response: &[u8],
    key: &VerifyingKey,
    expected: (u8, [u8; 16], [u8; 32], Option<[u8; 16]>),
    code: SandboxProviderErrorCode,
) -> TestResult {
    let error = refusal(response, key)?;
    assert_eq!(
        (
            error.operation,
            error.request_id,
            error.request_digest,
            error.attempt_id,
            error.code
        ),
        (
            Some(expected.0),
            Some(expected.1),
            Some(expected.2),
            expected.3,
            code
        )
    );
    Ok(())
}

/// Replace the execute leaf with a foreign socket, then wake the acceptor
/// through the control socket: the acceptor finds the replaced leaf before
/// it accepts, and both listeners close (invariant 10). The replacement and
/// the waking connection, which [`assert_unanswered`] checks once the
/// listeners are gone. The acceptor is woken even when the replacement
/// fails: a removed leaf without a replacement ends serving too.
fn replace_execute_leaf() -> TestResult<(UnixListener, UnixStream)> {
    let replacement = fs::remove_file(EXECUTE).and_then(|()| UnixListener::bind(EXECUTE));
    let woken = UnixStream::connect(CONTROL);
    Ok((replacement?, woken?))
}

/// Assert that `stream` ends with zero bytes: it is closed or reset, and
/// does not merely wait.
fn assert_unanswered(mut stream: UnixStream) -> TestResult {
    stream.set_read_timeout(Some(CLIENT_TIMEOUT))?;
    let mut byte = [0; 1];
    match stream.read(&mut byte) {
        Ok(read) => assert_eq!(read, 0),
        Err(error) => assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset),
    }
    Ok(())
}

/// Assert that `endpoint` answers `bytes` with nothing: a connection closed
/// with input still unread is reset rather than ended, and one closed before
/// the write completes refuses it with a broken pipe.
fn assert_silent(endpoint: &str, bytes: &[u8]) -> TestResult {
    let mut stream = UnixStream::connect(endpoint)?;
    match stream.write_all(bytes) {
        Ok(()) => stream.shutdown(std::net::Shutdown::Write)?,
        Err(error) => assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe),
    }
    assert_unanswered(stream)
}

/// Ends serving on every path. Dropped before [`ServingGuard::end`], as
/// when a check fails or panics, it replaces the execute leaf and wakes the
/// acceptor, so the thread scope never waits on a runtime that is still
/// serving. Dropped either way, it then removes the execute leaf, so no
/// socket file is left to collide with the next bind.
struct ServingGuard {
    armed: bool,
}

impl ServingGuard {
    /// End serving now: the replacement and the waking connection.
    fn end(&mut self) -> TestResult<(UnixListener, UnixStream)> {
        self.armed = false;
        replace_execute_leaf()
    }
}

impl Drop for ServingGuard {
    fn drop(&mut self) {
        if self.armed {
            // The queued connection has already woken the acceptor, and a
            // leaf that is replaced or removed ends serving either way.
            drop(replace_execute_leaf());
        }
        drop(fs::remove_file(EXECUTE));
    }
}

/// Bind both endpoints, serve them through `responder` while
/// `check` runs, then end serving through a replaced execute leaf.
fn while_serving(responder: &Responder<'_>, check: impl FnOnce() -> TestResult) -> TestResult {
    let (execute, control) = bind_endpoints(Path::new(EXECUTE), Path::new(CONTROL))?;
    let woken = std::thread::scope(|scope| -> TestResult<UnixStream> {
        let serving = scope.spawn(|| responder.serve(&execute, &control));
        let mut guard = ServingGuard { armed: true };
        check()?;
        let (replacement, woken) = guard.end()?;
        assert_eq!(
            serving.join().map_err(|_| "the runtime panicked")?,
            ProviderRuntimeError::UnsafeEndpoint
        );
        drop(replacement);
        Ok(woken)
    })?;
    drop((execute, control));
    assert_unanswered(woken)
}

/// Steps 1 to 6 for describe, cancel and reconcile.
fn refuses_by_precedence(key: &VerifyingKey, authority: Authority) -> TestResult {
    use SandboxProviderErrorCode as Code;
    // Step 1: no frame, an empty frame and bytes that are no record.
    assert_invalid(
        &exchange_at(EXECUTE, b"")?,
        key,
        None,
        Code::InvalidEncoding,
    )?;
    assert_invalid(
        &exchange_at(EXECUTE, &[0; 4])?,
        key,
        None,
        Code::InvalidEncoding,
    )?;
    assert_invalid(&exchange(&[b"\xff"])?, key, None, Code::InvalidEncoding)?;
    // A record whose magic names no operation of this socket.
    let foreign = request("SPX1", 1, Vec::new(), false)?;
    assert_invalid(&exchange(&[&foreign])?, key, None, Code::InvalidEncoding)?;
    // A describe record with a trailing byte names its operation in its
    // magic but is no canonical record: step 1.
    let trailing = [describe([1; 16], authority)?, vec![0]].concat();
    assert_invalid(&exchange(&[&trailing])?, key, None, Code::InvalidEncoding)?;
    // Steps 2, 3 and 5.
    let version = request(
        "SDQ1",
        2,
        vec![request_authority([1; 16], authority)],
        false,
    )?;
    assert_invalid(
        &exchange(&[&version])?,
        key,
        Some(0),
        Code::UnsupportedVersion,
    )?;
    let bounds = describe([0; 16], authority)?;
    assert_invalid(&exchange(&[&bounds])?, key, Some(0), Code::FieldOutOfBounds)?;
    let digest = request("SDQ1", 1, vec![request_authority([1; 16], authority)], true)?;
    assert_invalid(&exchange(&[&digest])?, key, Some(0), Code::DigestMismatch)?;
    let cancel_bounds = request(
        "SCQ1",
        1,
        vec![
            request_authority([8; 16], authority),
            Value::Bytes(vec![0; 16]),
            Value::Bytes(vec![10; 32]),
        ],
        false,
    )?;
    assert_invalid(
        &exchange(&[&cancel_bounds])?,
        key,
        Some(2),
        Code::FieldOutOfBounds,
    )?;
    let reconcile_version = request(
        "SRQ1",
        2,
        vec![
            request_authority([8; 16], authority),
            Value::Bytes(vec![9; 16]),
            Value::Bytes(vec![10; 32]),
        ],
        false,
    )?;
    assert_invalid(
        &exchange(&[&reconcile_version])?,
        key,
        Some(3),
        Code::UnsupportedVersion,
    )?;
    // Step 6: another APT1 or policy epoch.
    for stale in [
        Authority {
            apt1: [0x55; 32],
            ..authority
        },
        Authority {
            epoch: authority.epoch + 1,
            ..authority
        },
    ] {
        let bytes = describe([1; 16], stale)?;
        let decoded = SandboxDescribeRequest::from_canonical_cbor(&bytes)?;
        assert_refused(
            &exchange(&[&bytes])?,
            key,
            (0, [1; 16], decoded.request_digest, None),
            Code::AuthorityMismatch,
        )?;
    }
    let stale_cancel = attempt_request(
        "SCQ1",
        Authority {
            apt1: [0x55; 32],
            ..authority
        },
    )?;
    let decoded = SandboxCancelRequest::from_canonical_cbor(&stale_cancel)?;
    assert_refused(
        &exchange(&[&stale_cancel])?,
        key,
        (2, [8; 16], decoded.request_digest, Some([9; 16])),
        Code::AuthorityMismatch,
    )?;
    Ok(())
}

/// A 2 MiB record is within the 16 MiB frame bound (ADR-069 §4), so it is
/// read whole and refused at step 2, not at step 1 as an oversized frame.
fn reads_a_record_above_one_mebibyte(key: &VerifyingKey) -> TestResult {
    let large = request("SDQ1", 2, vec![Value::Bytes(vec![0; 2 << 20])], false)?;
    assert_invalid(
        &exchange(&[&large])?,
        key,
        Some(0),
        SandboxProviderErrorCode::UnsupportedVersion,
    )
}

/// Cancel and reconcile pass step 6 and get SPE1 `code`: 11 while the
/// runtime is `Starting` or `ReconcileFailed` (invariants 12 and 13), 15 for
/// an attempt the `Open` runtime's lifecycle does not hold (invariant 15).
fn answers_attempt_operations(
    key: &VerifyingKey,
    authority: Authority,
    (cancelled, code): (SandboxProviderErrorCode, SandboxProviderErrorCode),
) -> TestResult {
    let cancel = attempt_request("SCQ1", authority)?;
    let decoded = SandboxCancelRequest::from_canonical_cbor(&cancel)?;
    assert_refused(
        &exchange(&[&cancel])?,
        key,
        (2, [8; 16], decoded.request_digest, Some([9; 16])),
        cancelled,
    )?;
    let reconcile = attempt_request("SRQ1", authority)?;
    let decoded = SandboxReconcileRequest::from_canonical_cbor(&reconcile)?;
    assert_refused(
        &exchange(&[&reconcile])?,
        key,
        (3, [8; 16], decoded.request_digest, Some([9; 16])),
        code,
    )
}

/// Wait until the execute endpoint accepts connections.
fn await_bound() -> TestResult {
    let deadline = Instant::now() + CLIENT_TIMEOUT;
    while UnixStream::connect(EXECUTE).is_err() {
        if Instant::now() > deadline {
            return Err("the execute endpoint was never bound".into());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    Ok(())
}

/// Send reconcile requests until one gets SPE1 `15`: restart
/// reconciliation opened admission.
fn await_open(key: &VerifyingKey, authority: Authority) -> TestResult {
    let deadline = Instant::now() + CLIENT_TIMEOUT;
    let reconcile = attempt_request("SRQ1", authority)?;
    while refusal(&exchange(&[&reconcile])?, key)?.code != SandboxProviderErrorCode::UnknownAttempt
    {
        if Instant::now() > deadline {
            return Err("admission never opened".into());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    Ok(())
}

/// Step 7 with a restart reconciliation that fails as soon as it runs.
fn never_reconciled() -> impl FnOnce(&RuntimeAuthority) -> Result<Scripted, ProviderRuntimeError> {
    |_| Ok(Scripted(mpsc::channel().1))
}

/// Assert that `manager` received no datagram: nothing sent `READY=1`.
fn assert_not_notified(manager: &UnixDatagram) -> TestResult {
    manager.set_read_timeout(Some(Duration::from_millis(200)))?;
    let mut datagram = [0; 16];
    assert!(manager.recv(&mut datagram).is_err(), "READY=1 was sent");
    manager.set_read_timeout(Some(CLIENT_TIMEOUT))?;
    Ok(())
}

/// Assert that neither endpoint has a node.
fn assert_unbound() {
    assert!(!Path::new(EXECUTE).exists() && !Path::new(CONTROL).exists());
}

/// A startup refusal, a step 7 refusal and a pre-existing node at an
/// endpoint each bind nothing and send no READY=1.
fn binds_nothing_on_a_refusal(manager: &UnixDatagram) -> TestResult {
    assert_eq!(
        serve_with(
            || Err(ProviderStartupError::SlotCount),
            // Were step 7 to run first, its refusal would be returned.
            |_| Err::<Scripted, _>(ProviderRuntimeError::HostUnavailable),
            Some(OsStr::new(NOTIFY))
        ),
        ProviderRuntimeError::Startup(ProviderStartupError::SlotCount)
    );
    assert_unbound();
    assert_not_notified(manager)?;
    // Step 7 runs before any socket exists.
    let authority = bind_as_provider()??;
    assert_eq!(
        serve_with(
            move || Ok(authority),
            |_| {
                assert_unbound();
                Err::<Scripted, _>(ProviderRuntimeError::HostUnavailable)
            },
            Some(OsStr::new(NOTIFY))
        ),
        ProviderRuntimeError::HostUnavailable
    );
    assert_unbound();
    assert_not_notified(manager)?;
    fs::write(EXECUTE, b"")?;
    let authority = bind_as_provider()??;
    assert_eq!(
        serve_with(
            move || Ok(authority),
            |authority| {
                assert!(!Path::new(CONTROL).exists());
                never_reconciled()(authority)
            },
            Some(OsStr::new(NOTIFY))
        ),
        ProviderRuntimeError::UnsafeEndpoint
    );
    assert!(fs::symlink_metadata(EXECUTE)?.is_file());
    assert!(!Path::new(CONTROL).exists());
    assert_not_notified(manager)?;
    fs::remove_file(EXECUTE)?;
    Ok(())
}

/// Reconciliation opens admission, but a control exchange began earlier:
/// execute admission stays closed for the life of the process (R11 D9), so
/// execute is refused with 11 though the port is composed, while cancel and
/// reconcile are still answered from its lifecycle (ADR-069 R15 §3.3) and
/// name an unknown attempt (invariant 15), and describe still answers. The returned fixture must outlive the port.
fn serves_open_after_a_control_exchange(
    key: &VerifyingKey,
    retained: Authority,
    staged: &StagedInstallation,
    reconciled: &mpsc::Sender<Result<ExecutePort, ReconcileError>>,
) -> TestResult<PortFixture> {
    let (fixture, port) = test_port(StagingLimits {
        aggregate_bytes: 512 * 1024 * 1024,
    })?;
    reconciled.send(Ok(port))?;
    await_open(key, retained)?;
    answers_attempt_operations(
        key,
        retained,
        (
            SandboxProviderErrorCode::UnknownAttempt,
            SandboxProviderErrorCode::UnknownAttempt,
        ),
    )?;
    let execute = SandboxExecuteRequest::from_canonical_cbor(staged.request())?;
    assert_refused(
        &exchange(&[staged.evaluation(), staged.request()])?,
        key,
        (
            1,
            execute.request.request_id,
            execute.request_digest,
            Some(execute.attempt_id),
        ),
        SandboxProviderErrorCode::SandboxUnavailable,
    )?;
    let bytes = describe([4; 16], retained)?;
    SandboxDescribeResponse::from_canonical_cbor(unframe(&exchange(&[&bytes])?)?)?
        .verify_signature(key)?;
    Ok(fixture)
}

/// The records of a response, in order.
fn records(mut response: &[u8]) -> TestResult<Vec<Vec<u8>>> {
    let mut records = Vec::new();
    while !response.is_empty() {
        let (prefix, rest) = response.split_at_checked(4).ok_or("short frame")?;
        let length = usize::try_from(u32::from_be_bytes(prefix.try_into()?))?;
        let (record, rest) = rest.split_at_checked(length).ok_or("short record")?;
        records.push(record.to_vec());
        response = rest;
    }
    Ok(records)
}

/// Send `source` without ending the write side, read AGR1 when `granted`,
/// then end the write side and read the rest to EOF: every record the
/// connection received.
fn execute_exchange(source: &[&[u8]], granted: bool) -> TestResult<Vec<Vec<u8>>> {
    let mut stream = UnixStream::connect(EXECUTE)?;
    stream.set_read_timeout(Some(CLIENT_TIMEOUT))?;
    stream.write_all(&framed(source)?)?;
    let mut received = Vec::new();
    if granted {
        let mut prefix = [0; 4];
        stream.read_exact(&mut prefix)?;
        let mut grant = vec![0; usize::try_from(u32::from_be_bytes(prefix))?];
        stream.read_exact(&mut grant)?;
        received.push(grant);
        // No input follows: the admitted attempt's input fails.
        stream.shutdown(std::net::Shutdown::Write)?;
    }
    let mut rest = Vec::new();
    stream.read_to_end(&mut rest)?;
    received.extend(records(&rest)?);
    Ok(received)
}

/// An execute is admitted through the port: AGR1, then, its input never
/// arriving, the stored `UnavailableAfterAdmission` response (code 10, R9
/// Amendment 1 change A). An exact repeat joins the attempt and replays the
/// stored full response byte for byte, with no second AGR1 (invariant 31);
/// other bytes for the same attempt get `16`. A source that half-closes
/// right after SPX1 fails step 1 with `0`.
fn admits_joins_and_refuses_through_the_port(
    key: &VerifyingKey,
    staged: &StagedInstallation,
) -> TestResult {
    let execute = SandboxExecuteRequest::from_canonical_cbor(staged.request())?;
    let first = execute_exchange(&[staged.evaluation(), staged.request()], true)?;
    let grant = AdmissionGrant::from_canonical_cbor(&first[0])?;
    assert_eq!(grant.attempt_id, execute.attempt_id);
    let result =
        SandboxProviderResult::from_canonical_cbor(first.last().ok_or("no terminal result")?)?;
    result.verify_signature(key)?;
    assert_eq!(
        result.outcome,
        SandboxTerminalOutcome::UnavailableAfterAdmission
    );
    assert_eq!(result.agr1_digest, Some(grant.grant_digest()));
    let repeat = execute_exchange(&[staged.evaluation(), staged.request()], false)?;
    assert_eq!(repeat, first);
    let conflicting = staged.changed_request(|request| request.request.nonce[0] ^= 1)?;
    let decoded = SandboxExecuteRequest::from_canonical_cbor(&conflicting)?;
    let refused = execute_exchange(&[staged.evaluation(), &conflicting], false)?;
    assert_refused(
        &framed(&[&refused[0]])?,
        key,
        (
            1,
            decoded.request.request_id,
            decoded.request_digest,
            Some(decoded.attempt_id),
        ),
        SandboxProviderErrorCode::RequestIdentityConflict,
    )?;
    assert_invalid(
        &exchange(&[staged.evaluation(), staged.request()])?,
        key,
        None,
        SandboxProviderErrorCode::InvalidEncoding,
    )
}

#[test]
fn the_open_port_admits_joins_and_refuses_by_code() -> TestResult {
    if !in_isolated_root(
        "provider_runtime::serving::tests::the_open_port_admits_joins_and_refuses_by_code",
    )? {
        return Ok(());
    }
    let staged = stage()?;
    let authority = bind_as_provider()??;
    let (admitted, _, _) = &authority;
    let key = *admitted.provider().runtime_attestation_key();
    let retained = Authority {
        apt1: admitted.bootstrap().policy().policy_digest(),
        epoch: admitted.bootstrap().policy().policy_epoch(),
    };
    let (fixture, port) = test_port(StagingLimits {
        aggregate_bytes: 512 * 1024 * 1024,
    })?;
    let (reconciled, reconciling) = mpsc::channel();
    reconciled.send(Ok(port))?;
    let served = std::thread::spawn(move || {
        serve_with(
            move || Ok(authority),
            move |_| Ok(Scripted(reconciling)),
            None,
        )
    });
    let checked = await_bound()
        .and_then(|()| await_open(&key, retained))
        .and_then(|()| admits_joins_and_refuses_through_the_port(&key, &staged));
    let (replacement, woken) = replace_execute_leaf()?;
    assert_eq!(
        served.join().map_err(|_| "the runtime panicked")?,
        ProviderRuntimeError::UnsafeEndpoint
    );
    assert_unanswered(woken)?;
    drop(replacement);
    fs::remove_file(EXECUTE).ok();
    drop(fixture);
    drop(staged);
    checked
}

/// EVR1 then SPX1: the precedence of each, step 6, then SPE1 11.
fn refuses_execute_while_starting(key: &VerifyingKey, staged: &StagedInstallation) -> TestResult {
    use SandboxProviderErrorCode as Code;
    let evaluation = staged.evaluation();
    let execute = SandboxExecuteRequest::from_canonical_cbor(staged.request())?;
    assert_refused(
        &exchange(&[evaluation, staged.request()])?,
        key,
        (
            1,
            execute.request.request_id,
            execute.request_digest,
            Some(execute.attempt_id),
        ),
        Code::SandboxUnavailable,
    )?;
    // Bytes after SPX1 are read after the answer, so the peer gets the
    // SPE1 and a clean EOF.
    let trailing = exchange(&[evaluation, staged.request(), b"trailing"])?;
    assert_eq!(refusal(&trailing, key)?.code, Code::SandboxUnavailable);
    // Another TRS1 is another authority (step 6).
    let foreign_trust =
        staged.changed_request(|request| request.authority.trs1_digest = [0x66; 32])?;
    let decoded = SandboxExecuteRequest::from_canonical_cbor(&foreign_trust)?;
    assert_refused(
        &exchange(&[evaluation, &foreign_trust])?,
        key,
        (
            1,
            decoded.request.request_id,
            decoded.request_digest,
            Some(decoded.attempt_id),
        ),
        Code::AuthorityMismatch,
    )?;
    // EVR1 with a trailing byte, EVR1 of another version, an SPX1 of
    // another version, and EVR1 without its SPX1.
    let trailing = [evaluation, &[0]].concat();
    assert_invalid(&exchange(&[&trailing])?, key, None, Code::InvalidEncoding)?;
    // EVR1 of another version, with a zero request ID, and with another
    // self-digest.
    for (field, value, code) in [
        (1, Value::Integer(2.into()), Code::UnsupportedVersion),
        (2, Value::Bytes(vec![0; 16]), Code::FieldOutOfBounds),
        (14, Value::Bytes(vec![0x77; 32]), Code::DigestMismatch),
    ] {
        let mut fields: Value = ciborium::from_reader(evaluation)?;
        if let Value::Array(values) = &mut fields {
            values[field] = value;
        }
        let changed = encode(&fields)?;
        assert_invalid(
            &exchange(&[&changed, staged.request()])?,
            key,
            Some(1),
            code,
        )?;
    }
    let mut record: Value = ciborium::from_reader(staged.request())?;
    if let Value::Array(values) = &mut record {
        if let Value::Array(unsigned) = &mut values[0] {
            unsigned[1] = Value::Integer(2.into());
        }
    }
    let old_request = encode(&record)?;
    assert_invalid(
        &exchange(&[evaluation, &old_request])?,
        key,
        Some(1),
        Code::UnsupportedVersion,
    )?;
    assert_invalid(&exchange(&[evaluation])?, key, None, Code::InvalidEncoding)?;
    // Step 4: a repeated capability ID.
    let mut record: Value = ciborium::from_reader(staged.request())?;
    if let Value::Array(values) = &mut record {
        if let Value::Array(unsigned) = &mut values[0] {
            unsigned[19] = Value::Array(vec![Value::Text("a".to_owned()); 2]);
        }
    }
    let unordered = encode(&record)?;
    assert_invalid(
        &exchange(&[evaluation, &unordered])?,
        key,
        Some(1),
        Code::NonCanonicalOrder,
    )?;
    Ok(())
}

#[test]
fn the_runtime_binds_notifies_and_serves_while_starting() -> TestResult {
    if !in_isolated_root(
        "provider_runtime::serving::tests::the_runtime_binds_notifies_and_serves_while_starting",
    )? {
        return Ok(());
    }
    let staged = stage()?;
    let manager = UnixDatagram::bind_addr(&SocketAddr::from_abstract_name(&NOTIFY[1..])?)?;
    manager.set_read_timeout(Some(CLIENT_TIMEOUT))?;
    binds_nothing_on_a_refusal(&manager)?;
    let authority = bind_as_provider()??;
    let (admitted, _, _) = &authority;
    let key = *admitted.provider().runtime_attestation_key();
    let manifest = admitted.provider().manifest().clone();
    let hcp1 = admitted.provider().host_profile().profile_digest;
    let retained = Authority {
        apt1: admitted.bootstrap().policy().policy_digest(),
        epoch: admitted.bootstrap().policy().policy_epoch(),
    };
    // Restart reconciliation runs until the test sends its outcome.
    let (reconciled, reconciling) = mpsc::channel();
    let served = std::thread::spawn(move || {
        serve_with(
            move || Ok(authority),
            move |_| Ok(Scripted(reconciling)),
            Some(OsStr::new(NOTIFY)),
        )
    });
    // The first datagram is READY=1, sent after both leaves are owner-only
    // (invariant 9).
    let mut ready = [0; 16];
    let length = manager.recv(&mut ready)?;
    assert_eq!(&ready[..length], b"READY=1");
    for leaf in [EXECUTE, CONTROL] {
        let metadata = fs::symlink_metadata(leaf)?;
        assert!(metadata.file_type().is_socket());
        assert_eq!((metadata.uid(), metadata.mode() & 0o7777), (0, 0o600));
    }
    // Describe answers from the startup authority (invariant 12).
    let bytes = describe([1; 16], retained)?;
    let response = SandboxDescribeResponse::from_canonical_cbor(unframe(&exchange(&[&bytes])?)?)?;
    response.validate_for_request(&SandboxDescribeRequest::from_canonical_cbor(&bytes)?)?;
    response.verify_signature(&key)?;
    assert_eq!(
        (
            response.spm1_digest,
            response.provider_binary_digest,
            response.hcp1_digest,
            response.active_apt1_digest,
            response.runtime_attestation_key_id.as_str(),
        ),
        (
            manifest.manifest_digest,
            manifest.binary_digest,
            hcp1,
            retained.apt1,
            manifest.runtime_attestation_key_id.as_str(),
        )
    );
    refuses_by_precedence(&key, retained)?;
    reads_a_record_above_one_mebibyte(&key)?;
    answers_attempt_operations(
        &key,
        retained,
        (
            SandboxProviderErrorCode::SandboxUnavailable,
            SandboxProviderErrorCode::SandboxUnavailable,
        ),
    )?;
    refuses_execute_while_starting(&key, &staged)?;
    // A root control connection is closed with zero bytes.
    assert_silent(CONTROL, b"\0\0\0\x01x")?;
    // An unfinished frame is cut at the initial control deadline (BHC1
    // limit 16, 2 s in the fixture) and still answered: SPE1 0 with no
    // identities, then EOF (journal 22582).
    let mut stalled = UnixStream::connect(EXECUTE)?;
    stalled.set_read_timeout(Some(CLIENT_TIMEOUT))?;
    stalled.write_all(&[0, 0, 0, 10, 1, 2])?;
    let mut answer = Vec::new();
    stalled.read_to_end(&mut answer)?;
    assert_invalid(
        &answer,
        &key,
        None,
        SandboxProviderErrorCode::InvalidEncoding,
    )?;
    // Frames after a describe are read before the answer, so the peer
    // gets the SDY1 and a clean EOF.
    let trailing = exchange(&[&describe([3; 16], retained)?, b"trailing"])?;
    SandboxDescribeResponse::from_canonical_cbor(unframe(&trailing)?)?.verify_signature(&key)?;
    let runtime = serves_open_after_a_control_exchange(&key, retained, &staged, &reconciled)?;
    let (replacement, woken) = replace_execute_leaf()?;
    let replaced = fs::symlink_metadata(EXECUTE)?.ino();
    assert_eq!(
        served.join().map_err(|_| "the runtime panicked")?,
        ProviderRuntimeError::UnsafeEndpoint
    );
    assert_unanswered(woken)?;
    // Only the leaf that kept its own identity is removed.
    assert_eq!(fs::symlink_metadata(EXECUTE)?.ino(), replaced);
    assert!(!Path::new(CONTROL).exists());
    drop(replacement);
    drop(runtime);
    drop(staged);
    Ok(())
}

/// Read one SPE1 `12` for the describe request `[id; 16]` from `stream`.
fn assert_busy(
    stream: &mut UnixStream,
    key: &VerifyingKey,
    id: u8,
    retained: Authority,
) -> TestResult {
    let bytes = describe([id; 16], retained)?;
    let decoded = SandboxDescribeRequest::from_canonical_cbor(&bytes)?;
    stream.write_all(&framed(&[&bytes])?)?;
    stream.shutdown(std::net::Shutdown::Write)?;
    stream.set_read_timeout(Some(CLIENT_TIMEOUT))?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response)?;
    assert_refused(
        &response,
        key,
        (0, [id; 16], decoded.request_digest, None),
        SandboxProviderErrorCode::AdmissionBusy,
    )
}

/// Read the SPE1 0 that a connection which sent nothing gets at its
/// deadline.
fn assert_expired(stream: &mut UnixStream, key: &VerifyingKey) -> TestResult {
    stream.set_read_timeout(Some(CLIENT_TIMEOUT))?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response)?;
    assert_invalid(
        &response,
        key,
        None,
        SandboxProviderErrorCode::InvalidEncoding,
    )
}

#[test]
fn full_pools_and_a_failed_reconcile_refuse() -> TestResult {
    if !in_isolated_root(
        "provider_runtime::serving::tests::full_pools_and_a_failed_reconcile_refuse",
    )? {
        return Ok(());
    }
    let staged = stage()?;
    let (admitted, _, signer) = bind_as_provider()??;
    let (admitted, signer) = (Arc::new(admitted), Arc::new(signer));
    let key = *admitted.provider().runtime_attestation_key();
    let retained = Authority {
        apt1: admitted.bootstrap().policy().policy_digest(),
        epoch: admitted.bootstrap().policy().policy_epoch(),
    };
    // A failed reconciliation keeps cancel and reconcile refused with 11
    // for the life of the process (invariant 13).
    let failed = OnceLock::from(AdmissionState::ReconcileFailed);
    let responder = Responder::new(&admitted, &signer, &failed, 4);
    while_serving(&responder, || {
        answers_attempt_operations(
            &key,
            retained,
            (
                SandboxProviderErrorCode::SandboxUnavailable,
                SandboxProviderErrorCode::SandboxUnavailable,
            ),
        )?;
        let bytes = describe([6; 16], retained)?;
        SandboxDescribeResponse::from_canonical_cbor(unframe(&exchange(&[&bytes])?)?)?
            .verify_signature(&key)?;
        let execute = SandboxExecuteRequest::from_canonical_cbor(staged.request())?;
        assert_refused(
            &exchange(&[staged.evaluation(), staged.request()])?,
            &key,
            (
                1,
                execute.request.request_id,
                execute.request_digest,
                Some(execute.attempt_id),
            ),
            SandboxProviderErrorCode::SandboxUnavailable,
        )
    })?;
    // A full pool of one: the next connection is accepted and refused with
    // SPE1 12 at once (journal 22582).
    // Every uncharged read shares one reader place here (item P7): the
    // refusal waits until the holder's read ended at its deadline.
    while_serving(&Responder::new(&admitted, &signer, &failed, 1), || {
        let mut holder = UnixStream::connect(EXECUTE)?;
        assert_busy(&mut UnixStream::connect(EXECUTE)?, &key, 2, retained)?;
        assert_expired(&mut holder, &key)
    })?;
    // Pool 0 (ELM1 exact deny-all) refuses every connection with 12. One
    // refusal runs at a time: while it waits, the next connection stays
    // unanswered, and is refused once the first ends.
    while_serving(&Responder::new(&admitted, &signer, &failed, 0), || {
        assert_busy(&mut UnixStream::connect(EXECUTE)?, &key, 4, retained)?;
        let mut holder = UnixStream::connect(EXECUTE)?;
        let mut waiting = UnixStream::connect(EXECUTE)?;
        waiting.set_read_timeout(Some(Duration::from_millis(300)))?;
        let mut early = [0; 1];
        assert!(waiting.read(&mut early).is_err());
        assert_expired(&mut holder, &key)?;
        assert_busy(&mut waiting, &key, 5, retained)
    })?;
    drop(staged);
    Ok(())
}

#[test]
fn a_deadlined_stream_has_nothing_to_flush() -> TestResult {
    // A Unix stream has no buffered output: flushing writes nothing.
    let (local, mut peer) = UnixStream::pair()?;
    Deadlined::new(&local, Duration::from_secs(1)).flush()?;
    peer.set_nonblocking(true)?;
    let mut byte = [0; 1];
    assert_eq!(
        peer.read(&mut byte).map_err(|error| error.kind()),
        Err(std::io::ErrorKind::WouldBlock)
    );
    Ok(())
}

#[test]
fn only_the_trusted_peer_uid_is_answered() -> TestResult {
    // The peer of a socket pair runs as this process's UID.
    let (local, _) = UnixStream::pair()?;
    let uid = rustix::process::geteuid().as_raw();
    assert!(trusted_peer(&local, uid));
    assert!(!trusted_peer(&local, uid + 1));
    Ok(())
}

/// Assert that `peer` reads nothing, not even server write EOF, and that
/// all of `sent` is still unread at `server`: the connection was dropped
/// before anything was read or written.
fn assert_dropped_unread(server: &UnixStream, peer: &mut UnixStream, sent: &[u8]) -> TestResult {
    peer.set_nonblocking(true)?;
    let mut byte = [0; 1];
    assert_eq!(
        peer.read(&mut byte).map_err(|error| error.kind()),
        Err(std::io::ErrorKind::WouldBlock)
    );
    let mut unread = vec![0; sent.len() + 1];
    let mut reader = server;
    assert_eq!(reader.read(&mut unread)?, sent.len());
    assert_eq!(&unread[..sent.len()], sent);
    Ok(())
}

/// A peer of another UID gets zero bytes on either socket: neither the
/// revocation responder nor the execute answer reads its request, and the
/// control state stays `Live` (R11 §6 step 6).
fn drops_an_untrusted_peer(
    admitted: &Arc<AdmittedSelectorProvider>,
    signer: &Arc<crate::KeyFileRuntimeSigner>,
    retained: Authority,
) -> TestResult {
    let starting = OnceLock::new();
    let untrusted = Responder {
        peer_uid: rustix::process::geteuid().as_raw() + 1,
        ..Responder::new(admitted, signer, &starting, 4)
    };
    let (update, _) = revocation_update(admitted, &[], 4)?;
    let context = cancellation_context(admitted, &update, Vec::new(), Vec::new())?;
    let sent = framed(&[&context.to_canonical_cbor()?, &update])?;
    let (server, mut peer) = UnixStream::pair()?;
    peer.write_all(&sent)?;
    untrusted.exchange(&server, Instant::now());
    assert_dropped_unread(&server, &mut peer, &sent)?;
    assert_eq!(
        untrusted.revocation.observer().state.load(Ordering::SeqCst),
        LIVE
    );
    let sent = framed(&[&describe([4; 16], retained)?])?;
    let (server, mut peer) = UnixStream::pair()?;
    peer.write_all(&sent)?;
    untrusted.answer(server.try_clone()?, Admission::Answered, None);
    assert_dropped_unread(&server, &mut peer, &sent)?;
    assert_eq!(
        untrusted.revocation.observer().state.load(Ordering::SeqCst),
        LIVE
    );
    Ok(())
}

#[test]
fn the_control_socket_acknowledges_and_a_self_revocation_closes_execute() -> TestResult {
    if !in_isolated_root(
        "provider_runtime::serving::tests::the_control_socket_acknowledges_and_a_self_revocation_closes_execute",
    )? {
        return Ok(());
    }
    let staged = stage()?;
    let (admitted, _, signer) = bind_as_provider()??;
    let (admitted, signer) = (Arc::new(admitted), Arc::new(signer));
    let key = *admitted.provider().runtime_attestation_key();
    let retained = Authority {
        apt1: admitted.bootstrap().policy().policy_digest(),
        epoch: admitted.bootstrap().policy().policy_epoch(),
    };
    the_control_state_only_advances(&admitted)?;
    drops_an_untrusted_peer(&admitted, &signer, retained)?;
    let starting = OnceLock::new();
    // An acknowledged update fences the runtime for good; describe still
    // answers and execute is refused with 11 (invariant 24).
    let fenced = Responder::new(&admitted, &signer, &starting, 4);
    while_serving(&fenced, || {
        let (update, _) = revocation_update(&admitted, &[], 1)?;
        let context_bytes = cancellation_context(&admitted, &update, Vec::new(), Vec::new())?
            .to_canonical_cbor()?;
        assert!(!exchange_at(CONTROL, &framed(&[&context_bytes, &update])?)?.is_empty());
        let bytes = describe([1; 16], retained)?;
        SandboxDescribeResponse::from_canonical_cbor(unframe(&exchange(&[&bytes])?)?)?
            .verify_signature(&key)?;
        let refused = exchange(&[staged.evaluation(), staged.request()])?;
        assert_eq!(
            refusal(&refused, &key)?.code,
            SandboxProviderErrorCode::SandboxUnavailable
        );
        Ok(())
    })?;
    // A self-revoking update is acknowledged. Afterwards every execute
    // connection gets zero bytes, and only the retained RCA1 is resent
    // (invariant 25).
    let revoked = Responder::new(&admitted, &signer, &starting, 4);
    while_serving(&revoked, || {
        let manifest = admitted.provider().manifest().manifest_digest;
        let (update, _) = revocation_update(&admitted, &[manifest], 2)?;
        let context_bytes = cancellation_context(&admitted, &update, Vec::new(), Vec::new())?
            .to_canonical_cbor()?;
        let exchange_bytes = framed(&[&context_bytes, &update])?;
        let rca1 = exchange_at(CONTROL, &exchange_bytes)?;
        assert!(!rca1.is_empty());
        assert_silent(EXECUTE, &framed(&[&describe([2; 16], retained)?])?)?;
        assert_eq!(exchange_at(CONTROL, &exchange_bytes)?, rca1);
        let (other, _) = revocation_update(&admitted, &[], 3)?;
        let context =
            cancellation_context(&admitted, &other, Vec::new(), Vec::new())?.to_canonical_cbor()?;
        assert!(exchange_at(CONTROL, &framed(&[&context, &other])?)?.is_empty());
        Ok(())
    })?;
    drop(staged);
    Ok(())
}

#[test]
fn a_control_exchange_ends_100_ms_after_its_accept() {
    let accepted = Instant::now();
    assert_eq!(
        exchange_deadline(accepted),
        accepted + Duration::from_millis(100)
    );
}

/// The live control state only advances: the fence and an acknowledgement
/// that does not revoke this runtime leave it `Fenced`; one that revokes
/// its SPM1, its binary or its runtime-attestation key, each alone, makes it
/// `Revoked` (R11 §7.1).
fn the_control_state_only_advances(admitted: &AdmittedSelectorProvider) -> TestResult {
    let bootstrap = admitted.bootstrap();
    let next_revoking = |keys: &[&str], providers: &[[u8; 32]], nonce| -> TestResult<_> {
        let (update, _) = key_and_provider_revocation_update(admitted, keys, providers, nonce)?;
        Ok(RevocationUpdateRequest::authenticate(
            &update,
            bootstrap.trust(),
            bootstrap.revocation(),
        )?
        .next_revocation)
    };
    let next = |providers: &[[u8; 32]], nonce| next_revoking(&[], providers, nonce);
    let manifest = admitted.provider().manifest();
    for (keys, providers, nonce) in [
        (Vec::new(), vec![manifest.binary_digest], 10),
        (
            vec![manifest.runtime_attestation_key_id.as_str()],
            Vec::new(),
            11,
        ),
    ] {
        let control = ControlState {
            state: AtomicU8::new(FENCED),
            admitted,
        };
        control.acknowledging(bootstrap.trust(), &next_revoking(&keys, &providers, nonce)?);
        assert!(control.revoked());
    }
    let control = ControlState {
        state: AtomicU8::new(LIVE),
        admitted,
    };
    let state = || control.state.load(Ordering::SeqCst);
    control.advance(EXECUTE_CLOSED);
    assert_eq!(state(), EXECUTE_CLOSED);
    control.fencing();
    assert_eq!(state(), FENCED);
    control.advance(EXECUTE_CLOSED);
    assert_eq!(state(), FENCED);
    control.acknowledging(bootstrap.trust(), &next(&[], 7)?);
    assert!(!control.revoked());
    control.acknowledging(bootstrap.trust(), &next(&[manifest.manifest_digest], 8)?);
    assert!(control.revoked());
    assert_eq!(state(), REVOKED);
    // A later acknowledgement that revokes nothing cannot undo it.
    control.acknowledging(bootstrap.trust(), &next(&[], 9)?);
    assert_eq!(state(), REVOKED);
    Ok(())
}

#[test]
fn the_control_interval_is_bhc1_limit_16_in_milliseconds() {
    use pos_reference::sandbox_provider_protocol::SandboxLimit;
    let caps: Vec<SandboxLimit> = (0..17)
        .map(|limit_id| SandboxLimit {
            limit_id,
            value: u64::from(limit_id) * 100 + 7,
        })
        .collect();
    assert_eq!(super::control_interval(&caps), Duration::from_millis(1607));
}

#[test]
fn a_control_request_is_routed_revoked_first_then_by_state_then_by_pool() {
    use super::{control_route, ControlRoute};
    use SandboxProviderErrorCode as Code;
    for (opened, taken) in [(None, false), (Some(()), false), (Some(()), true)] {
        assert_eq!(control_route(true, opened, taken), ControlRoute::Silent);
    }
    assert_eq!(
        control_route::<()>(false, None, true),
        ControlRoute::Refused(Code::SandboxUnavailable)
    );
    assert_eq!(
        control_route(false, Some(()), false),
        ControlRoute::Refused(Code::AdmissionBusy)
    );
    assert_eq!(control_route(false, Some(7), true), ControlRoute::Answer(7));
}

#[test]
fn the_execute_listener_is_polled_while_either_pool_has_room() {
    // A free answered slot alone, room for an uncharged reader alone, and
    // neither.
    assert!(accepting(true, false));
    assert!(accepting(false, true));
    assert!(!accepting(false, false));
}

#[test]
fn execute_readiness_counts_only_while_accepting() {
    let none = PollFlags::empty();
    assert_eq!(readiness(true, none, none), (false, false));
    assert_eq!(readiness(true, PollFlags::IN, none), (true, false));
    assert_eq!(readiness(true, none, PollFlags::IN), (false, true));
    // While not accepting, whatever the execute listener reports is ignored.
    assert_eq!(readiness(false, none, PollFlags::IN), (false, false));
    assert_eq!(
        readiness(false, PollFlags::IN, PollFlags::HUP),
        (true, false)
    );
}

#[test]
fn only_an_accept_that_produced_nothing_backs_off() {
    // A control accept that missed, alone.
    assert!(missed(true, false, false));
    assert!(missed(true, true, true));
    // An execute accept that was ready and produced nothing, alone.
    assert!(missed(false, true, false));
    // A ready execute accept that produced a connection, and no accept.
    assert!(!missed(false, true, true));
    assert!(!missed(false, false, false));
}

mod selector_client;
