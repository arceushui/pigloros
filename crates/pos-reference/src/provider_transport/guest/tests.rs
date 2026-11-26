use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::thread::JoinHandle;

use super::super::{read_frame, write_frame, Deadline};
use super::*;
use crate::selector_transport_test_fixture::{
    authenticated_transport_fixture, derived_nonce, TransportAdmissionFixture,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct Served {
    client: GuestProviderClient,
    thread: JoinHandle<Result<(), String>>,
    _directory: tempfile::TempDir,
}

/// A socket path in a fresh directory, bound and private to its owner.
fn bind_socket() -> TestResult<(tempfile::TempDir, std::path::PathBuf, UnixListener)> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("provider.sock");
    let listener = UnixListener::bind(&path)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    Ok((directory, path, listener))
}

/// A guest client for the socket at `path`, bound to this process.
fn client_for(path: &Path) -> TestResult<GuestProviderClient> {
    let owner = std::fs::metadata(path)?.uid();
    let pid = NonZeroU64::new(u64::from(std::process::id())).ok_or("pid zero")?;
    Ok(GuestProviderClient::bound_to_process(path, owner, Ok, pid)?)
}

/// A guest client bound to this process, and a provider thread running `script`.
fn serve(
    script: impl FnOnce(UnixListener) -> Result<(), String> + Send + 'static,
) -> TestResult<Served> {
    let (directory, path, listener) = bind_socket()?;
    Ok(Served {
        client: client_for(&path)?,
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
    let (cancel, cancel_bytes) =
        fixture
            .provider
            .cancel_request([5; 16], derived_nonce("guest tests"), [7; 16], [8; 32])?;
    let cancelled = served.client.cancel(
        &fixture.provider,
        &cancel,
        &cancel_bytes,
        None,
        Duration::from_secs(2),
    );
    assert_eq!(cancelled.err(), unreachable);
    let (reconcile, reconcile_bytes) = fixture.provider.reconcile_request(
        [5; 16],
        derived_nonce("guest tests"),
        [7; 16],
        [8; 32],
    )?;
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

// --- The commitment, the wait and the evidence report of the guest execute (#444 3b). ---

const FIXTURE_ADMISSION_TIME: u64 = 1_800_000_000;

fn lower_hex_of(bytes: &[u8; 32]) -> String {
    blake3::Hash::from(*bytes).to_hex().to_string()
}

fn digest_hex(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

#[test]
fn the_commitment_is_the_selectors_own_and_carries_the_attempts_watchdog() -> TestResult {
    let (evaluation, admitted, resolved) =
        crate::selector::installation::tests::root_selector_fixture()?;
    let requirement = evaluation
        .sandbox_requirement
        .as_ref()
        .ok_or("the fixture names no sandbox requirement")?;
    let (image, launch) =
        selected_image_and_launch(&admitted, requirement, FIXTURE_ADMISSION_TIME)?;
    let expected = admitted.provider().derive_selector_grant_commitment(
        &image.image,
        &launch,
        &evaluation,
        resolved.attempt(),
        &[],
    )?;

    let derived =
        GuestProviderClient::commitment(&admitted, &evaluation, 0, FIXTURE_ADMISSION_TIME)?;
    assert_eq!(derived.commitment, expected);
    assert_eq!(
        derived.watchdog,
        Duration::from_millis(resolved.attempt().watchdog_ms)
    );
    assert_ne!(derived.watchdog, Duration::ZERO);
    Ok(())
}

/// A copy of `evaluation` whose requirement `change` edits, bound again to its digests.
fn rebound_requirement(
    evaluation: &EvaluationRequest,
    change: impl FnOnce(&mut crate::evaluator_protocol::SandboxRequirement),
) -> TestResult<EvaluationRequest> {
    let mut changed = evaluation.clone();
    changed
        .sandbox_requirement
        .as_mut()
        .map(change)
        .ok_or("the fixture names no sandbox requirement")?;
    changed.output_capability.capability_digest = changed.expected_output_capability_digest()?;
    changed.request_digest = changed.digest()?;
    Ok(changed)
}

#[test]
fn each_step_of_the_commitment_refuses_on_its_own() -> TestResult {
    let (evaluation, admitted, _) = crate::selector::installation::tests::root_selector_fixture()?;
    let refused = |evaluation: &EvaluationRequest, ordinal: u16| {
        GuestProviderClient::commitment(&admitted, evaluation, ordinal, FIXTURE_ADMISSION_TIME)
            .err()
    };

    let mut bare = evaluation.clone();
    bare.sandbox_requirement = None;
    assert_eq!(refused(&bare, 0), Some(GuestCommitmentError));

    // The case is not installed: the selector's own step fails, whatever the image.
    assert!(admitted
        .bootstrap()
        .resolve_installed_case(&evaluation, u16::MAX)
        .is_err());
    assert_eq!(refused(&evaluation, u16::MAX), Some(GuestCommitmentError));

    // The image or the launch policy is not held: the case still resolves.
    let no_image =
        rebound_requirement(&evaluation, |requirement| requirement.sim1_digest = [0; 32])?;
    let no_policy =
        rebound_requirement(&evaluation, |requirement| requirement.lps1_digest = [0; 32])?;
    for changed in [&no_image, &no_policy] {
        assert!(admitted
            .bootstrap()
            .resolve_installed_case(changed, 0)
            .is_ok());
        assert_eq!(refused(changed, 0), Some(GuestCommitmentError));
    }

    // Image and launch policy admit, but the requirement names another policy epoch: only the
    // derivation of the commitment refuses.
    let other_epoch =
        rebound_requirement(&evaluation, |requirement| requirement.policy_epoch += 1)?;
    let requirement = other_epoch
        .sandbox_requirement
        .as_ref()
        .ok_or("the requirement is missing")?;
    assert!(admitted
        .bootstrap()
        .resolve_installed_case(&other_epoch, 0)
        .is_ok());
    assert!(selected_image_and_launch(&admitted, requirement, FIXTURE_ADMISSION_TIME).is_ok());
    assert_eq!(refused(&other_epoch, 0), Some(GuestCommitmentError));
    Ok(())
}

#[derive(Default)]
struct FakeClock {
    now: std::cell::Cell<Duration>,
    pauses: std::cell::RefCell<Vec<Duration>>,
}

impl GuestClock for FakeClock {
    fn elapsed(&self) -> Duration {
        self.now.get()
    }

    fn pause(&self, interval: Duration) {
        self.now.set(self.now.get() + interval);
        self.pauses.borrow_mut().push(interval);
    }
}

fn starting() -> Exchange<u8> {
    Exchange::Refused(Some(SandboxProviderErrorCode::SandboxUnavailable))
}

#[test]
fn the_wait_asks_again_while_the_provider_is_starting() {
    let clock = FakeClock::default();
    let mut answers = vec![Exchange::Done(7), starting(), starting()];
    let outcome = until_open(
        || answers.pop().ok_or(GuestExecuteError::BeforeAdmission),
        &clock,
        Duration::from_mins(2),
    );
    assert_eq!(outcome, Ok(7));
    assert_eq!(*clock.pauses.borrow(), vec![OPEN_RETRY_INTERVAL; 2]);
}

#[test]
fn the_wait_ends_with_the_last_refusal_when_its_window_is_over() {
    let clock = FakeClock::default();
    let mut exchanges = 0_u32;
    let outcome: Result<u8, _> = until_open(
        || {
            exchanges += 1;
            Ok(starting())
        },
        &clock,
        3 * OPEN_RETRY_INTERVAL,
    );
    assert_eq!(
        outcome,
        Err(GuestWaitError::Refused(Some(
            SandboxProviderErrorCode::SandboxUnavailable
        )))
    );
    // Asks at 0 s, 1 s and 2 s inside the window, and once more at 3 s, which is outside it.
    assert_eq!((exchanges, clock.pauses.borrow().len()), (4, 3));
}

#[test]
fn any_other_answer_ends_the_wait_at_once() {
    let refusals = [
        Exchange::Refused(Some(SandboxProviderErrorCode::PayloadTransferTimeout)),
        Exchange::Refused(Some(SandboxProviderErrorCode::AdmissionBusy)),
        Exchange::Refused(None),
    ];
    for refusal in refusals {
        let clock = FakeClock::default();
        let expected = GuestWaitError::Refused(match &refusal {
            Exchange::Refused(code) => *code,
            Exchange::Done(_) => None,
        });
        let mut once = Some(refusal);
        let outcome: Result<u8, _> = until_open(
            || once.take().ok_or(GuestExecuteError::BeforeAdmission),
            &clock,
            Duration::from_mins(2),
        );
        assert_eq!(outcome, Err(expected));
        assert!(clock.pauses.borrow().is_empty());
    }
    let clock = FakeClock::default();
    let failed: Result<u8, _> = until_open(
        || Err(GuestExecuteError::BeforeAdmission),
        &clock,
        Duration::from_mins(2),
    );
    assert_eq!(
        failed,
        Err(GuestWaitError::Execute(GuestExecuteError::BeforeAdmission))
    );
    assert!(clock.pauses.borrow().is_empty());
}

#[test]
fn the_instant_clock_counts_up_and_pauses() {
    let clock = GuestInstantClock::start();
    clock.pause(Duration::from_millis(5));
    assert!(clock.elapsed() >= Duration::from_millis(5));
}

#[test]
fn a_refusal_has_its_code_and_an_execution_has_none() -> TestResult {
    let fixture = authenticated_transport_fixture()?;
    assert_eq!(
        GuestTerminal::Error(fixture.spe1.clone()).refusal_code(),
        Some(SandboxProviderErrorCode::PayloadTransferTimeout)
    );
    assert_eq!(GuestTerminal::Error(vec![0xff]).refusal_code(), None);
    assert!(matches!(
        classify(GuestTerminal::Error(fixture.spe1)),
        Exchange::Refused(Some(SandboxProviderErrorCode::PayloadTransferTimeout))
    ));
    Ok(())
}

/// A provider thread that runs one complete execution.
fn serve_execution(fixture: &TransportAdmissionFixture) -> TestResult<Served> {
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
    serve(move |listener| {
        let mut stream = accept(&listener)?;
        let deadline = deadline()?;
        read_attempt(&mut stream, &deadline)?;
        send(&mut stream, &grant, &deadline)?;
        drain(&mut stream, &deadline)?;
        for frame in rest {
            send(&mut stream, &frame, &deadline)?;
        }
        finish(&stream)
    })
}

#[test]
fn an_execution_is_reported_as_the_selector_observed_it() -> TestResult {
    let fixture = authenticated_transport_fixture()?;
    let served = serve_execution(&fixture)?;
    let mut input = std::io::Cursor::new(b"input".to_vec());
    let grant = GuestCommitment {
        commitment: fixture.commitment.clone(),
        watchdog: Duration::from_secs(5),
    };
    let job = GuestExecuteJob {
        evaluation: &fixture.evaluation,
        spx1: &fixture.spx1,
    };
    let clock = FakeClock::default();
    let mut execution = served.client.execute_when_open(
        &fixture.provider,
        &grant,
        &job,
        &mut input,
        &clock,
        Duration::from_mins(2),
    )?;
    assert_eq!(execution.agr1_bytes(), fixture.agr1);
    assert!(clock.pauses.borrow().is_empty());

    let result = SandboxProviderResult::from_canonical_cbor(&fixture.spy1)?;
    let receipt = SandboxProviderReceipt::from_canonical_cbor(&fixture.spr1)?;
    let presence = |digest: Option<[u8; 32]>| {
        if digest.is_some() {
            "present"
        } else {
            "absent"
        }
    };
    let mut expected = vec![
        format!("outcome\t{:?}", result.outcome),
        format!(
            "events\t{}",
            result
                .operational_events
                .iter()
                .map(u8::to_string)
                .collect::<Vec<_>>()
                .join(",")
        ),
        format!("ready1\t{}", presence(receipt.ready1_digest)),
        format!("release1\t{}", presence(receipt.release1_digest)),
        format!(
            "rqe1\t{}",
            lower_hex_of(&receipt.requested_configuration_evidence)
        ),
        format!(
            "koe1\t{}",
            lower_hex_of(&receipt.kernel_observation_evidence)
        ),
        format!("tme1\t{}", lower_hex_of(&receipt.termination_evidence)),
        format!("agr1\t{}", lower_hex_of(&execution.agr1_digest())),
        format!("raw\tagr1\t{}", digest_hex(&fixture.agr1)),
        format!("raw\tspr1\t{}", digest_hex(&fixture.spr1)),
        format!("raw\tspy1\t{}", digest_hex(&fixture.spy1)),
    ];
    for (index, frame) in fixture.sau1.iter().enumerate() {
        expected.push(format!("raw\tsau1\t{index}\t{}", digest_hex(frame)));
    }
    expected.push(format!(
        "output\t{}\t{}",
        b"output".len(),
        digest_hex(b"output")
    ));
    assert_eq!(execution.report()?, expected);
    join(served)
}

#[test]
fn a_refused_execute_ends_the_wait_with_its_code() -> TestResult {
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
    let grant = GuestCommitment {
        commitment: fixture.commitment.clone(),
        watchdog: Duration::from_secs(5),
    };
    let job = GuestExecuteJob {
        evaluation: &fixture.evaluation,
        spx1: &fixture.spx1,
    };
    let clock = FakeClock::default();
    let outcome = served.client.execute_when_open(
        &fixture.provider,
        &grant,
        &job,
        &mut input,
        &clock,
        Duration::from_mins(2),
    );
    assert_eq!(
        outcome.err(),
        Some(GuestWaitError::Refused(Some(
            SandboxProviderErrorCode::PayloadTransferTimeout
        )))
    );
    assert!(clock.pauses.borrow().is_empty());
    join(served)
}

fn test_execution(receipt: &[u8], result: &[u8]) -> GuestExecution {
    GuestExecution(AuthenticatedProviderExecution::from_test_frames(
        vec![1],
        receipt.to_vec(),
        result.to_vec(),
        vec![vec![2]],
        None,
    ))
}

#[test]
fn a_report_needs_both_signed_records_to_decode() -> TestResult {
    let fixture = authenticated_transport_fixture()?;
    assert_eq!(
        test_execution(&fixture.spr1, &[0xff]).report().err(),
        Some(GuestReportError)
    );
    assert_eq!(
        test_execution(&[0xff], &fixture.spy1).report().err(),
        Some(GuestReportError)
    );
    Ok(())
}

#[test]
fn a_report_has_no_output_line_without_a_staged_output() -> TestResult {
    let fixture = authenticated_transport_fixture()?;
    let lines = test_execution(&fixture.spr1, &fixture.spy1).report()?;
    assert!(lines.iter().all(|line| !line.starts_with("output\t")));
    assert!(lines.contains(&format!("raw\tsau1\t0\t{}", digest_hex(&[2]))));
    Ok(())
}

#[test]
fn a_client_for_the_admitted_provider_needs_the_socket_sic1_names() -> TestResult {
    let (_, admitted, _) = crate::selector::installation::tests::root_selector_fixture()?;
    let own = NonZeroU64::new(u64::from(std::process::id())).ok_or("no process id")?;
    assert!(GuestProviderClient::for_admitted_provider(&admitted, own).is_err());
    Ok(())
}
