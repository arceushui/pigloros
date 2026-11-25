use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::thread::JoinHandle;

use super::super::{read_frame, write_frame, Deadline};
use super::*;
use crate::selector_transport_test_fixture::authenticated_transport_fixture;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct Served {
    client: GuestProviderClient,
    thread: JoinHandle<Result<(), String>>,
    _directory: tempfile::TempDir,
}

/// A guest client bound to this process, and a provider thread running `script`.
fn serve(
    script: impl FnOnce(UnixListener) -> Result<(), String> + Send + 'static,
) -> TestResult<Served> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("provider.sock");
    let listener = UnixListener::bind(&path)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    let owner = std::fs::metadata(&path)?.uid();
    let pid = NonZeroU64::new(u64::from(std::process::id())).ok_or("pid zero")?;
    let client = GuestProviderClient::bound_to_process(&path, owner, Ok, pid)?;
    Ok(Served {
        client,
        thread: std::thread::spawn(move || script(listener)),
        _directory: directory,
    })
}

fn join(served: Served) -> TestResult {
    served.thread.join().map_err(|_| "provider panicked")??;
    Ok(())
}

fn deadline() -> Result<Deadline, String> {
    Deadline::new(Duration::from_secs(5)).map_err(|error| error.to_string())
}

fn accept(listener: &UnixListener) -> Result<UnixStream, String> {
    listener
        .accept()
        .map(|(stream, _)| stream)
        .map_err(|error| error.to_string())
}

/// The EVR1 and SPX1 frames of one execute connection.
fn read_attempt(stream: &mut UnixStream, deadline: &Deadline) -> Result<(), String> {
    for _ in 0..2 {
        read_frame(stream, deadline)
            .map_err(|error| format!("{error:?}"))?
            .ok_or("attempt frame missing")?;
    }
    Ok(())
}

/// Every frame up to the client's write EOF.
fn drain(stream: &mut UnixStream, deadline: &Deadline) -> Result<(), String> {
    while read_frame(stream, deadline)
        .map_err(|error| format!("{error:?}"))?
        .is_some()
    {}
    Ok(())
}

fn send(stream: &mut UnixStream, frame: &[u8], deadline: &Deadline) -> Result<(), String> {
    write_frame(stream, frame, deadline).map_err(|error| format!("{error:?}"))
}

fn finish(stream: &UnixStream) -> Result<(), String> {
    stream
        .shutdown(std::net::Shutdown::Write)
        .map_err(|error| error.to_string())
}

#[test]
fn execute_returns_the_authenticated_execution_and_its_verified_output() -> TestResult {
    let fixture = authenticated_transport_fixture()?;
    let grant = fixture.agr1.clone();
    let rest = fixture
        .sau1
        .iter()
        .cloned()
        .chain([
            fixture.spr1.clone(),
            fixture.output_chunk.clone(),
            fixture.spy1.clone(),
        ])
        .collect::<Vec<_>>();
    let served = serve(move |listener| {
        let mut stream = accept(&listener)?;
        let deadline = deadline()?;
        read_attempt(&mut stream, &deadline)?;
        send(&mut stream, &grant, &deadline)?;
        drain(&mut stream, &deadline)?;
        for frame in rest {
            send(&mut stream, &frame, &deadline)?;
        }
        finish(&stream)
    })?;
    let mut input = std::io::Cursor::new(b"input".to_vec());
    let terminal = served.client.execute(
        &fixture.provider,
        &fixture.commitment,
        &fixture.evaluation,
        &fixture.spx1,
        &mut input,
        Duration::from_secs(5),
    )?;
    let GuestTerminal::Execution(mut execution) = terminal else {
        return Err("expected an execution".into());
    };
    assert_eq!(execution.agr1_bytes(), fixture.agr1);
    assert_eq!(execution.spr1_bytes(), fixture.spr1);
    assert_eq!(execution.spy1_bytes(), fixture.spy1);
    assert_eq!(execution.sau1_frames(), fixture.sau1.as_slice());
    let grant = fixture.provider.authenticate_selector_grant(
        &fixture.agr1,
        &fixture.request,
        &fixture.commitment,
    )?;
    assert_eq!(execution.agr1_digest(), grant.grant_digest());
    let accepted = execution.accepted_evidence([7; 16]);
    assert_eq!(accepted.agr1_digest, grant.grant_digest());
    assert_eq!(accepted.attempt_id, [7; 16]);
    assert_eq!(
        accepted.terminal_spy1_digest,
        crate::sandbox_provider_protocol::SandboxProviderResult::from_canonical_cbor(
            &fixture.spy1
        )?
        .result_digest()
    );
    let last_sau1 = fixture.sau1.last().ok_or("no SAU1")?;
    let wrapper: ciborium::value::Value = ciborium::from_reader(last_sau1.as_slice())?;
    let ciborium::value::Value::Array(wrapper) = wrapper else {
        return Err("SAU1 wrapper is not an array".into());
    };
    let Some(ciborium::value::Value::Bytes(digest)) = wrapper.get(1) else {
        return Err("SAU1 digest missing".into());
    };
    assert_eq!(accepted.final_sau1_digest.as_slice(), digest.as_slice());
    assert_ne!(accepted.final_sau1_digest, [0; 32]);
    let output = execution
        .with_verified_output(|_, reader| {
            let mut bytes = Vec::new();
            reader
                .read_to_end(&mut bytes)
                .map_err(|_| SelectorBoundaryError::Io)?;
            Ok(bytes)
        })?
        .ok_or("output missing")?;
    assert_eq!(output, b"output");
    let (spy1, agr1) = execution
        .with_verified_reply_output(|spy1, agr1, _, _, _, _| Ok((spy1.to_vec(), agr1.to_vec())))?
        .ok_or("output missing")?;
    assert_eq!((spy1, agr1), (fixture.spy1.clone(), fixture.agr1.clone()));
    join(served)
}

#[test]
fn execute_returns_an_authenticated_pre_admission_error() -> TestResult {
    let fixture = authenticated_transport_fixture()?;
    let error = fixture.spe1.clone();
    let served = serve(move |listener| {
        let mut stream = accept(&listener)?;
        let deadline = deadline()?;
        read_attempt(&mut stream, &deadline)?;
        send(&mut stream, &error, &deadline)?;
        finish(&stream)
    })?;
    let mut input = std::io::Cursor::new(b"input".to_vec());
    let terminal = served.client.execute(
        &fixture.provider,
        &fixture.commitment,
        &fixture.evaluation,
        &fixture.spx1,
        &mut input,
        Duration::from_secs(5),
    )?;
    let GuestTerminal::Error(bytes) = terminal else {
        return Err("expected an authenticated error".into());
    };
    assert_eq!(bytes, fixture.spe1);
    join(served)
}

#[test]
fn a_provider_that_ends_after_agr1_twice_leaves_the_terminal_unavailable() -> TestResult {
    let fixture = authenticated_transport_fixture()?;
    let grant = fixture.agr1.clone();
    let served = serve(move |listener| {
        let deadline = deadline()?;
        for _ in 0..2 {
            let mut stream = accept(&listener)?;
            read_attempt(&mut stream, &deadline)?;
            send(&mut stream, &grant, &deadline)?;
            drain(&mut stream, &deadline)?;
            finish(&stream)?;
        }
        Ok(())
    })?;
    let grant = fixture.provider.authenticate_selector_grant(
        &fixture.agr1,
        &fixture.request,
        &fixture.commitment,
    )?;
    let mut input = std::io::Cursor::new(b"input".to_vec());
    let result = served.client.execute(
        &fixture.provider,
        &fixture.commitment,
        &fixture.evaluation,
        &fixture.spx1,
        &mut input,
        Duration::from_secs(5),
    );
    assert_eq!(
        result.err(),
        Some(GuestExecuteError::TerminalUnavailable {
            agr1_digest: grant.grant_digest()
        })
    );
    join(served)
}

#[test]
fn a_request_that_is_not_an_spx1_never_reaches_the_provider() -> TestResult {
    let fixture = authenticated_transport_fixture()?;
    let served = serve(|_listener| Ok(()))?;
    let mut input = std::io::Cursor::new(b"input".to_vec());
    let result = served.client.execute(
        &fixture.provider,
        &fixture.commitment,
        &fixture.evaluation,
        b"not an spx1",
        &mut input,
        Duration::from_secs(5),
    );
    assert_eq!(result.err(), Some(GuestExecuteError::BeforeAdmission));
    join(served)
}

#[test]
fn an_unreachable_provider_fails_cancel_and_reconcile_through_the_one_transport() -> TestResult {
    let fixture = authenticated_transport_fixture()?;
    let served = serve(|listener| {
        let deadline = deadline()?;
        for _ in 0..2 {
            let mut stream = accept(&listener)?;
            read_frame(&mut stream, &deadline)
                .map_err(|error| format!("{error:?}"))?
                .ok_or("request frame missing")?;
            drain(&mut stream, &deadline)?;
            finish(&stream)?;
        }
        Ok(())
    })?;
    let unreachable = Some(GuestControlError::Unreachable(
        SelectorBoundaryError::SelectorUnavailable,
    ));
    let (cancel, cancel_bytes) = fixture
        .provider
        .cancel_request([5; 16], [6; 16], [7; 16], [8; 32])?;
    let cancelled = served.client.cancel(
        &fixture.provider,
        &cancel,
        &cancel_bytes,
        None,
        Duration::from_secs(2),
    );
    assert_eq!(cancelled.err(), unreachable);
    let (reconcile, reconcile_bytes) = fixture
        .provider
        .reconcile_request([5; 16], [6; 16], [7; 16], [8; 32])?;
    let reconciled = served.client.reconcile(
        &fixture.provider,
        &reconcile,
        &reconcile_bytes,
        None,
        Duration::from_secs(2),
    );
    assert_eq!(reconciled.err(), unreachable);
    join(served)
}

#[test]
fn a_client_needs_a_present_socket_and_a_running_provider_process() -> TestResult {
    let pid = NonZeroU64::new(u64::from(std::process::id())).ok_or("pid zero")?;
    assert!(GuestProviderClient::for_provider_process(
        Path::new("/nonexistent/provider.sock"),
        pid
    )
    .is_err());
    let gone = NonZeroU64::new(u64::from(u32::MAX)).ok_or("pid zero")?;
    assert!(GuestProviderClient::bound_to_process(Path::new("/"), 0, Ok, gone).is_err());
    Ok(())
}

#[test]
fn every_transport_failure_has_its_guest_class() {
    let digest = [9; 32];
    assert_eq!(
        GuestExecuteError::from(ProviderTransportError::BeforeAdmission),
        GuestExecuteError::BeforeAdmission
    );
    assert_eq!(
        GuestExecuteError::from(ProviderTransportError::AfterAdmission {
            agr1_digest: digest,
            failure: PostAdmissionProviderFailure::TerminalUnavailable,
        }),
        GuestExecuteError::TerminalUnavailable {
            agr1_digest: digest
        }
    );
    assert_eq!(
        GuestExecuteError::from(ProviderTransportError::AfterAdmission {
            agr1_digest: digest,
            failure: PostAdmissionProviderFailure::EvidenceInvalid,
        }),
        GuestExecuteError::EvidenceInvalid {
            agr1_digest: digest
        }
    );
}

#[test]
fn every_control_failure_has_its_guest_class() {
    let refusals = [
        (ProviderControlRefusal::Pending11, GuestRefusal::Pending),
        (ProviderControlRefusal::Busy12, GuestRefusal::Busy),
        (
            ProviderControlRefusal::CleanupFailed14,
            GuestRefusal::CleanupFailed,
        ),
        (
            ProviderControlRefusal::UnknownAttempt15,
            GuestRefusal::UnknownAttempt,
        ),
        (
            ProviderControlRefusal::RequestIdReuse16,
            GuestRefusal::RequestIdReuse,
        ),
        (ProviderControlRefusal::Other, GuestRefusal::Other),
    ];
    for (refusal, expected) in refusals {
        assert_eq!(
            GuestControlError::from(ProviderControlError::Refused(refusal)),
            GuestControlError::Refused(expected)
        );
    }
    assert_eq!(
        GuestControlError::from(ProviderControlError::Boundary(SelectorBoundaryError::Io)),
        GuestControlError::Unreachable(SelectorBoundaryError::Io)
    );
    assert_eq!(
        GuestControlError::from(ProviderControlError::Evidence(
            SandboxAdmissionError::Revoked
        )),
        GuestControlError::Rejected(SandboxAdmissionError::Revoked)
    );
}
