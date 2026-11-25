use std::io::{Read, Write as _};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use ciborium::value::Value;

use super::*;
use crate::provider_transport::ProviderTransport;
use crate::sandbox_provider_protocol::ReconciliationEvidence;
use crate::selector_transport_test_fixture::{
    authenticated_transport_fixture, TransportAdmissionFixture,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const ATTEMPT: [u8; 16] = [7; 16];
const AGR1: [u8; 32] = [8; 32];
const SPY1: [u8; 32] = [9; 32];
const SAU1: [u8; 32] = [10; 32];

#[derive(Clone, Default)]
struct Sink(Arc<Mutex<Vec<u8>>>);

impl Sink {
    fn text(&self) -> String {
        String::from_utf8_lossy(
            &self
                .0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        )
        .into_owned()
    }
}

impl Write for Sink {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

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

fn sry1(fixture: &TransportAdmissionFixture, index: u8, digest: [u8; 32]) -> TestResult<Vec<u8>> {
    fixture.sign_runtime_record(
        "SRY1",
        Value::Array(vec![
            Value::Text("SRY1".to_owned()),
            uint(1),
            Value::Bytes(
                derive(
                    REQUEST_ID_DOMAIN,
                    ATTEMPT,
                    ControlOperation::Reconcile,
                    index,
                )
                .to_vec(),
            ),
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
            Value::Bytes(derive(REQUEST_ID_DOMAIN, ATTEMPT, ControlOperation::Cancel, 0).to_vec()),
            Value::Bytes(ATTEMPT.to_vec()),
            uint(0),
            Value::Bytes(SPY1.to_vec()),
            key(fixture),
        ]),
    )
}

/// An SPE1 `code` answering the reconcile request of retry `index`.
fn spe1(fixture: &TransportAdmissionFixture, index: u8, code: u64) -> TestResult<Vec<u8>> {
    let (request, _) = fixture.provider.reconcile_request(
        derive(
            REQUEST_ID_DOMAIN,
            ATTEMPT,
            ControlOperation::Reconcile,
            index,
        ),
        derive(NONCE_DOMAIN, ATTEMPT, ControlOperation::Reconcile, index),
        ATTEMPT,
        AGR1,
    )?;
    fixture.sign_runtime_record(
        "SPE1",
        Value::Array(vec![
            Value::Text("SPE1".to_owned()),
            uint(1),
            uint(3),
            Value::Bytes(request.request.request_id.to_vec()),
            Value::Bytes(request.request_digest.to_vec()),
            Value::Bytes(ATTEMPT.to_vec()),
            uint(code),
            Value::Null,
            key(fixture),
        ]),
    )
}

struct Provider {
    transport: ProviderTransport,
    thread: JoinHandle<std::io::Result<Vec<Vec<u8>>>>,
    _directory: tempfile::TempDir,
}

/// A provider that serves one connection per scripted answer; `None` closes
/// the connection without answering. It returns every request it read.
fn provider(answers: Vec<Option<Vec<u8>>>) -> TestResult<Provider> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("execute.sock");
    let listener = UnixListener::bind(&path)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    let thread = std::thread::spawn(move || -> std::io::Result<Vec<Vec<u8>>> {
        let mut requests = Vec::new();
        for answer in answers {
            let (mut stream, _) = listener.accept()?;
            let mut prefix = [0; 4];
            stream.read_exact(&mut prefix)?;
            let length =
                usize::try_from(u32::from_be_bytes(prefix)).map_err(std::io::Error::other)?;
            let mut request = vec![0; length];
            stream.read_exact(&mut request)?;
            requests.push(request);
            let mut trailing = Vec::new();
            stream.read_to_end(&mut trailing)?;
            if let Some(answer) = answer {
                let length = u32::try_from(answer.len()).map_err(std::io::Error::other)?;
                stream.write_all(&length.to_be_bytes())?;
                stream.write_all(&answer)?;
            }
            stream.shutdown(std::net::Shutdown::Write)?;
        }
        Ok(requests)
    });
    Ok(Provider {
        transport: ProviderTransport::from_path_for_test(&path)?,
        thread,
        _directory: directory,
    })
}

fn requests(provider: Provider) -> TestResult<Vec<Vec<u8>>> {
    Ok(provider.thread.join().map_err(|_| "provider panicked")??)
}

fn reconcile_with(
    fixture: &TransportAdmissionFixture,
    provider: &Provider,
    accepted: Option<&ReconciliationEvidenceFields>,
) -> String {
    let sink = Sink::default();
    let diagnostics: DiagnosticSink = Mutex::new(Box::new(sink.clone()));
    AttemptControl {
        transport: &provider.transport,
        admitted: &fixture.provider,
        attempt_id: ATTEMPT,
        agr1_digest: AGR1,
        timeout: Duration::from_secs(2),
        diagnostics: &diagnostics,
    }
    .reconcile(accepted);
    sink.text()
}

fn recomputed() -> TestResult<[u8; 32]> {
    Ok(ReconciliationEvidence::new(&accepted())?.digest())
}

#[test]
fn a_recomputed_reconcile_sends_the_derived_request_and_reports_nothing() -> TestResult {
    let fixture = authenticated_transport_fixture()?;
    let server = provider(vec![Some(sry1(&fixture, 0, recomputed()?)?)])?;
    assert_eq!(
        reconcile_with(&fixture, &server, Some(&accepted())),
        String::new()
    );
    let (_, expected) = fixture.provider.reconcile_request(
        derive(REQUEST_ID_DOMAIN, ATTEMPT, ControlOperation::Reconcile, 0),
        derive(NONCE_DOMAIN, ATTEMPT, ControlOperation::Reconcile, 0),
        ATTEMPT,
        AGR1,
    )?;
    assert_eq!(requests(server)?, vec![expected]);
    Ok(())
}

#[test]
fn a_reconcile_without_an_accepted_terminal_reports_the_unverified_digest() -> TestResult {
    let fixture = authenticated_transport_fixture()?;
    let server = provider(vec![Some(sry1(&fixture, 0, [77; 32])?)])?;
    let report = reconcile_with(&fixture, &server, None);
    assert!(report.contains("provider reconcile digest is unverified"));
    requests(server)?;
    Ok(())
}

#[test]
fn a_contradicting_digest_is_reported_and_not_retried() -> TestResult {
    let fixture = authenticated_transport_fixture()?;
    let server = provider(vec![Some(sry1(&fixture, 0, [77; 32])?)])?;
    let report = reconcile_with(&fixture, &server, Some(&accepted()));
    assert!(report.contains("provider reconcile failed"));
    assert_eq!(requests(server)?.len(), 1);
    Ok(())
}

#[test]
fn a_busy_provider_gets_the_next_distinct_request_and_then_succeeds() -> TestResult {
    let fixture = authenticated_transport_fixture()?;
    let server = provider(vec![
        Some(spe1(&fixture, 0, 12)?),
        Some(spe1(&fixture, 1, 11)?),
        Some(sry1(&fixture, 2, recomputed()?)?),
    ])?;
    assert_eq!(
        reconcile_with(&fixture, &server, Some(&accepted())),
        String::new()
    );
    let sent = requests(server)?;
    assert_eq!(sent.len(), 3);
    assert!(sent[0] != sent[1] && sent[1] != sent[2] && sent[0] != sent[2]);
    Ok(())
}

#[test]
fn retryable_refusals_stop_at_four_distinct_requests() -> TestResult {
    let fixture = authenticated_transport_fixture()?;
    let answers = (0..MAX_DISTINCT_REQUESTS)
        .map(|index| spe1(&fixture, index, 14).map(Some))
        .collect::<TestResult<Vec<_>>>()?;
    let server = provider(answers)?;
    let report = reconcile_with(&fixture, &server, Some(&accepted()));
    assert!(report.contains("provider reconcile failed"));
    assert_eq!(requests(server)?.len(), usize::from(MAX_DISTINCT_REQUESTS));
    Ok(())
}

#[test]
fn a_permanent_refusal_is_not_retried() -> TestResult {
    let fixture = authenticated_transport_fixture()?;
    let server = provider(vec![Some(spe1(&fixture, 0, 15)?)])?;
    let report = reconcile_with(&fixture, &server, Some(&accepted()));
    assert!(report.contains("provider reconcile failed"));
    assert_eq!(requests(server)?.len(), 1);
    Ok(())
}

#[test]
fn an_unreachable_provider_gets_one_byte_identical_repeat() -> TestResult {
    let fixture = authenticated_transport_fixture()?;
    let server = provider(vec![None, Some(sry1(&fixture, 0, recomputed()?)?)])?;
    assert_eq!(
        reconcile_with(&fixture, &server, Some(&accepted())),
        String::new()
    );
    let sent = requests(server)?;
    assert_eq!(sent.len(), 2);
    assert_eq!(sent[0], sent[1]);
    Ok(())
}

#[test]
fn a_provider_that_stays_unreachable_is_reported_after_one_repeat() -> TestResult {
    let fixture = authenticated_transport_fixture()?;
    let server = provider(vec![None, None])?;
    let report = reconcile_with(&fixture, &server, Some(&accepted()));
    assert!(report.contains("provider reconcile failed"));
    assert_eq!(requests(server)?.len(), 2);
    Ok(())
}

#[test]
fn cancel_sends_the_derived_scq1_and_reports_only_failures() -> TestResult {
    let fixture = authenticated_transport_fixture()?;
    let sink = Sink::default();
    let diagnostics: DiagnosticSink = Mutex::new(Box::new(sink.clone()));
    let server = provider(vec![Some(scy1(&fixture)?)])?;
    AttemptControl {
        transport: &server.transport,
        admitted: &fixture.provider,
        attempt_id: ATTEMPT,
        agr1_digest: AGR1,
        timeout: Duration::from_secs(2),
        diagnostics: &diagnostics,
    }
    .cancel(Some(SPY1));
    assert_eq!(sink.text(), String::new());
    let (_, expected) = fixture.provider.cancel_request(
        derive(REQUEST_ID_DOMAIN, ATTEMPT, ControlOperation::Cancel, 0),
        derive(NONCE_DOMAIN, ATTEMPT, ControlOperation::Cancel, 0),
        ATTEMPT,
        AGR1,
    )?;
    assert_eq!(requests(server)?, vec![expected]);

    let silent = provider(vec![None, None])?;
    AttemptControl {
        transport: &silent.transport,
        admitted: &fixture.provider,
        attempt_id: ATTEMPT,
        agr1_digest: AGR1,
        timeout: Duration::from_secs(2),
        diagnostics: &diagnostics,
    }
    .cancel(None);
    assert!(sink.text().contains("provider cancel failed"));
    requests(silent)?;
    Ok(())
}

#[test]
fn derived_identities_differ_by_domain_operation_and_index_and_are_nonzero() {
    let id = |operation, index| derive(REQUEST_ID_DOMAIN, ATTEMPT, operation, index);
    let all = [
        id(ControlOperation::Cancel, 0),
        id(ControlOperation::Cancel, 1),
        id(ControlOperation::Reconcile, 0),
        id(ControlOperation::Reconcile, 1),
        derive(NONCE_DOMAIN, ATTEMPT, ControlOperation::Cancel, 0),
        derive(NONCE_DOMAIN, [8; 16], ControlOperation::Cancel, 0),
    ];
    for (position, identity) in all.iter().enumerate() {
        assert_ne!(*identity, [0; 16]);
        assert!(!all[position + 1..].contains(identity));
    }
}
