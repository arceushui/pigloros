use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::thread::JoinHandle;

use ciborium::value::Value;

use super::*;
use crate::sandbox_provider_protocol::SandboxAdmissionError;
use crate::sandbox_provider_protocol::{ReconciliationEvidence, TerminalEvidenceCheck};
use crate::selector::SelectorBoundaryError;
use crate::selector_transport_test_fixture::{
    authenticated_transport_fixture, TransportAdmissionFixture,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const REQUEST_ID: [u8; 16] = [5; 16];
const NONCE: [u8; 16] = [6; 16];
const ATTEMPT: [u8; 16] = [7; 16];
const AGR1: [u8; 32] = [8; 32];
const SPY1: [u8; 32] = [9; 32];
const SAU1: [u8; 32] = [10; 32];
const TIMEOUT: Duration = Duration::from_secs(2);

fn accepted() -> ReconciliationEvidenceFields {
    ReconciliationEvidenceFields {
        attempt_id: ATTEMPT,
        agr1_digest: AGR1,
        terminal_spy1_digest: SPY1,
        final_sau1_digest: SAU1,
    }
}

fn uint(value: u64) -> Value {
    Value::Integer(value.into())
}

fn key(fixture: &TransportAdmissionFixture) -> Value {
    Value::Text(
        fixture
            .provider
            .manifest()
            .runtime_attestation_key_id
            .clone(),
    )
}

fn sry1(fixture: &TransportAdmissionFixture, digest: [u8; 32]) -> TestResult<Vec<u8>> {
    fixture.sign_runtime_record(
        "SRY1",
        Value::Array(vec![
            Value::Text("SRY1".to_owned()),
            uint(1),
            Value::Bytes(REQUEST_ID.to_vec()),
            Value::Bytes(ATTEMPT.to_vec()),
            Value::Bool(true),
            Value::Bytes(digest.to_vec()),
            key(fixture),
        ]),
    )
}

fn scy1(fixture: &TransportAdmissionFixture) -> TestResult<Vec<u8>> {
    fixture.sign_runtime_record(
        "SCY1",
        Value::Array(vec![
            Value::Text("SCY1".to_owned()),
            uint(1),
            Value::Bytes(REQUEST_ID.to_vec()),
            Value::Bytes(ATTEMPT.to_vec()),
            uint(0),
            Value::Bytes(SPY1.to_vec()),
            key(fixture),
        ]),
    )
}

/// An SPE1 for `operation` bound to the request, with `code`.
fn spe1(
    fixture: &TransportAdmissionFixture,
    operation: u64,
    request_id: [u8; 16],
    request_digest: [u8; 32],
    code: u64,
) -> TestResult<Vec<u8>> {
    fixture.sign_runtime_record(
        "SPE1",
        Value::Array(vec![
            Value::Text("SPE1".to_owned()),
            uint(1),
            uint(operation),
            Value::Bytes(request_id.to_vec()),
            Value::Bytes(request_digest.to_vec()),
            Value::Bytes(ATTEMPT.to_vec()),
            uint(code),
            Value::Null,
            key(fixture),
        ]),
    )
}

struct Provider {
    transport: ProviderTransport,
    thread: JoinHandle<std::io::Result<Vec<u8>>>,
    _directory: tempfile::TempDir,
}

/// A provider that reads one request frame, then answers `answer` (if any).
fn provider(answer: Option<Vec<u8>>) -> TestResult<Provider> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("execute.sock");
    let listener = UnixListener::bind(&path)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    let thread = std::thread::spawn(move || -> std::io::Result<Vec<u8>> {
        let (mut stream, _) = listener.accept()?;
        let mut prefix = [0; 4];
        stream.read_exact(&mut prefix)?;
        let length = usize::try_from(u32::from_be_bytes(prefix)).map_err(std::io::Error::other)?;
        let mut request = vec![0; length];
        stream.read_exact(&mut request)?;
        let mut trailing = Vec::new();
        stream.read_to_end(&mut trailing)?;
        if let Some(answer) = answer {
            let length = u32::try_from(answer.len()).map_err(std::io::Error::other)?;
            stream.write_all(&length.to_be_bytes())?;
            stream.write_all(&answer)?;
        }
        stream.shutdown(std::net::Shutdown::Write)?;
        Ok(request)
    });
    Ok(Provider {
        transport: ProviderTransport::from_path_for_test(&path)?,
        thread,
        _directory: directory,
    })
}

fn join(provider: Provider) -> TestResult<Vec<u8>> {
    Ok(provider.thread.join().map_err(|_| "provider panicked")??)
}

#[test]
fn reconcile_sends_the_exact_srq1_and_recomputes_the_tuple() -> TestResult {
    let fixture = authenticated_transport_fixture()?;
    let (request, bytes) = fixture
        .provider
        .reconcile_request(REQUEST_ID, NONCE, ATTEMPT, AGR1)?;
    let digest = ReconciliationEvidence::new(&accepted())?.digest();
    let server = provider(Some(sry1(&fixture, digest)?))?;
    let verified = server.transport.reconcile(
        &fixture.provider,
        &request,
        &bytes,
        Some(&accepted()),
        TIMEOUT,
    )?;
    assert_eq!(verified.check(), TerminalEvidenceCheck::Recomputed);
    assert_eq!(join(server)?, bytes);
    Ok(())
}

#[test]
fn reconcile_refuses_a_signed_digest_that_is_not_the_recomputed_one() -> TestResult {
    let fixture = authenticated_transport_fixture()?;
    let (request, bytes) = fixture
        .provider
        .reconcile_request(REQUEST_ID, NONCE, ATTEMPT, AGR1)?;
    let server = provider(Some(sry1(&fixture, [77; 32])?))?;
    let result = server.transport.reconcile(
        &fixture.provider,
        &request,
        &bytes,
        Some(&accepted()),
        TIMEOUT,
    );
    assert_eq!(
        result,
        Err(ProviderControlError::Evidence(
            SandboxAdmissionError::Protocol(
                crate::sandbox_provider_protocol::SandboxProviderProtocolError::InconsistentFields
            )
        ))
    );
    join(server)?;
    Ok(())
}

#[test]
fn cancel_sends_the_exact_scq1_and_authenticates_the_scy1() -> TestResult {
    let fixture = authenticated_transport_fixture()?;
    let (request, bytes) = fixture
        .provider
        .cancel_request(REQUEST_ID, NONCE, ATTEMPT, AGR1)?;
    let server = provider(Some(scy1(&fixture)?))?;
    let verified =
        server
            .transport
            .cancel(&fixture.provider, &request, &bytes, Some(SPY1), TIMEOUT)?;
    assert_eq!(verified.check(), TerminalEvidenceCheck::Recomputed);
    assert_eq!(join(server)?, bytes);
    Ok(())
}

#[test]
fn each_authenticated_spe1_code_maps_to_its_refusal() -> TestResult {
    let fixture = authenticated_transport_fixture()?;
    let (request, bytes) = fixture
        .provider
        .reconcile_request(REQUEST_ID, NONCE, ATTEMPT, AGR1)?;
    let expected = [
        (11, ProviderControlRefusal::Pending11, true),
        (12, ProviderControlRefusal::Busy12, true),
        (13, ProviderControlRefusal::Other, false),
        (14, ProviderControlRefusal::CleanupFailed14, true),
        (15, ProviderControlRefusal::UnknownAttempt15, false),
        (16, ProviderControlRefusal::RequestIdReuse16, false),
    ];
    for (code, refusal, retryable) in expected {
        let answer = spe1(&fixture, 3, REQUEST_ID, request.request_digest, code)?;
        let server = provider(Some(answer))?;
        let result = server
            .transport
            .reconcile(&fixture.provider, &request, &bytes, None, TIMEOUT);
        assert_eq!(result, Err(ProviderControlError::Refused(refusal)));
        assert_eq!(refusal.is_retryable(), retryable);
        join(server)?;
    }
    Ok(())
}

#[test]
fn an_spe1_bound_to_another_request_or_operation_is_evidence_failure() -> TestResult {
    let fixture = authenticated_transport_fixture()?;
    let (request, bytes) = fixture
        .provider
        .reconcile_request(REQUEST_ID, NONCE, ATTEMPT, AGR1)?;
    let mismatched = [
        spe1(&fixture, 3, [99; 16], request.request_digest, 15)?,
        spe1(&fixture, 3, REQUEST_ID, [99; 32], 15)?,
        spe1(&fixture, 2, REQUEST_ID, request.request_digest, 15)?,
    ];
    for answer in mismatched {
        let server = provider(Some(answer))?;
        let result = server
            .transport
            .reconcile(&fixture.provider, &request, &bytes, None, TIMEOUT);
        assert_eq!(
            result,
            Err(ProviderControlError::Evidence(
                SandboxAdmissionError::ConformanceMismatch
            ))
        );
        join(server)?;
    }
    Ok(())
}

#[test]
fn unauthenticated_and_missing_answers_are_distinguished() -> TestResult {
    let fixture = authenticated_transport_fixture()?;
    let (request, bytes) = fixture
        .provider
        .reconcile_request(REQUEST_ID, NONCE, ATTEMPT, AGR1)?;
    let server = provider(Some(b"not cbor".to_vec()))?;
    let garbage = server
        .transport
        .reconcile(&fixture.provider, &request, &bytes, None, TIMEOUT);
    assert!(matches!(garbage, Err(ProviderControlError::Evidence(_))));
    join(server)?;
    let silent = provider(None)?;
    let closed = silent
        .transport
        .reconcile(&fixture.provider, &request, &bytes, None, TIMEOUT);
    assert_eq!(
        closed,
        Err(ProviderControlError::Boundary(
            SelectorBoundaryError::SelectorUnavailable
        ))
    );
    join(silent)?;
    Ok(())
}

#[test]
fn a_foreign_provider_process_receives_no_request() -> TestResult {
    let fixture = authenticated_transport_fixture()?;
    let (request, bytes) = fixture
        .provider
        .cancel_request(REQUEST_ID, NONCE, ATTEMPT, AGR1)?;
    let server = provider(None)?;
    let transport = server.transport.expecting(1, 1);
    let result = transport.cancel(&fixture.provider, &request, &bytes, None, TIMEOUT);
    assert_eq!(
        result,
        Err(ProviderControlError::Boundary(
            SelectorBoundaryError::ArtifactInvalid
        ))
    );
    // The provider saw a connection with no request frame.
    assert!(server
        .thread
        .join()
        .map_err(|_| "provider panicked")?
        .is_err());
    Ok(())
}
