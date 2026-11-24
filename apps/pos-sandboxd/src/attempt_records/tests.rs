//! The terminal records of ended attempts, one case per ELM1 limit ID, the
//! watchdog deadline `D ± G`, each D5 contradiction and the provider faults
//! (ADR-069 R9 §4.6, R10 §4.8; Redmine #443 journal 22723).

use std::error::Error;

use pos_reference::sandbox_provider_protocol::{
    AdmissionAuthority, AdmissionGrant, AdmissionGrantFields, AttemptProgressCode, BarrierFailure,
    CancelSource, CleanupResult, Contradiction, ExecutionRelease, ExecutionReleaseFields,
    KernelObservationStatus, LaunchFailure, LocalNetworkSession, LocalNetworkTermination,
    RequestedConfigurationStatus, SandboxExecutionMode, SandboxLimit, SandboxTerminalOutcome,
    StartJobResult, TerminalCode, TransferRecord, WATCHDOG_GRACE_NS,
};

use super::{AttemptAdmission, AttemptRecords, EvidenceFault};
use crate::{
    AdapterIo, AttemptCgroupEmptyBasis, AttemptEnding, AttemptLifecycleError,
    AttemptLimitEventSnapshot, AttemptProgress, CompletedAttemptCleanup, EffectiveCgroupLimits,
    EndedAttempt, ExecuteError, ImageActivationError, IssuedGrant, KernelObservation,
    NetworkEvidence, ObservedUnit, OutputReservationRefused, PlannedAttemptIntent, ReleaseOutcome,
    ReleaseResources, ResourceEvidence, ServedProxy, SystemdUnitResultObservation,
    SystemdVerifiedStart, TerminalResources, TerminalServiceError, TransientServiceUnitName,
    UnitState, WorkUsage,
};

type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

const ATTEMPT: [u8; 16] = [0x5a; 16];
const AGR1: [u8; 32] = [0x6b; 32];
const READY1: [u8; 32] = [0x7c; 32];
/// The invocation and cgroup `(st_dev, inode)` of `KernelObservation::fixture`.
const INVOCATION: [u8; 16] = [0x11; 16];
const CGROUP: (u64, u64) = (26, 5678);
/// The unit's `ActiveEnterTimestampMonotonic` and ELM1 limit 4.
const ACTIVATED: u64 = 1_000_000_000_000;
const WATCHDOG_MS: u64 = 10_000;
const D: u64 = ACTIVATED + WATCHDOG_MS * 1_000_000;
/// ELM1 limit 8.
const OUTPUT_LIMIT: u64 = 100;
const CLEANED_AT: u64 = 2_000_000_000_000;

/// R10 §8.1 `S`: a framed 70-byte EAO1 stream.
const FRAMED: &str = "00000007826445414f3101000000378964454f45310103f6f6f6f6880000000000\
                      00000058209cd8b956c8795d49680acf9b4a3e44ead3889f3e1f2caf8edbcb156e0d\
                      6dc02d";

fn framed() -> TestResult<Vec<u8>> {
    let hex = FRAMED.replace(' ', "");
    (0..hex.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&hex[at..at + 2], 16).map_err(Into::into))
        .collect()
}

/// The ELM1 limits: the watchdog and the output ceiling, every other 1.
fn limits() -> Vec<SandboxLimit> {
    (0..17)
        .map(|limit_id| SandboxLimit {
            limit_id,
            value: match limit_id {
                4 => WATCHDOG_MS,
                8 => OUTPUT_LIMIT,
                _ => 1,
            },
        })
        .collect()
}

/// A five-byte input transfer, complete or not.
const fn input(complete: bool) -> TransferRecord {
    TransferRecord {
        start: 100,
        deadline: 1_000,
        finish: 500,
        expected_bytes: 5,
        accepted_bytes: if complete { 5 } else { 3 },
        complete,
    }
}

fn admission(mode: SandboxExecutionMode, input: Option<TransferRecord>) -> AttemptAdmission {
    admission_of(None, mode, input)
}

/// The admission under `grant`'s AGR1, or under filler AGR1 bytes of
/// digest [`AGR1`] that no verifier accepts.
fn admission_of(
    grant: Option<&SignedGrant>,
    mode: SandboxExecutionMode,
    input: Option<TransferRecord>,
) -> AttemptAdmission {
    let issued = grant.map_or_else(
        || IssuedGrant::fixture(AGR1, limits(), mode),
        |signed| {
            IssuedGrant::fixture(signed.grant.grant_digest(), limits(), mode)
                .with_bytes(&signed.bytes)
        },
    );
    AttemptAdmission::new(issued, input)
}

/// The runtime-attestation key ID the test signer holds.
const KEY_ID: &str = "runtime";

fn signing_key() -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[42; 32])
}

fn signer() -> crate::KeyFileRuntimeSigner {
    crate::KeyFileRuntimeSigner::from_signing_key(signing_key(), KEY_ID.to_owned())
}

/// A signed AGR1 of the test attempt and its exact bytes.
struct SignedGrant {
    grant: AdmissionGrant,
    bytes: Vec<u8>,
}

/// The AGR1 of the test attempt under ELM1 `[0xe1; 32]`, the digest
/// `IssuedGrant::fixture` names, signed by the test key.
fn signed_grant() -> TestResult<SignedGrant> {
    let digest = |byte| [byte; 32];
    let fields = AdmissionGrantFields {
        request_id: [0x31; 16],
        attempt_id: ATTEMPT,
        authority: AdmissionAuthority {
            evr1_digest: digest(0x41),
            fixture_contract_digest: digest(0x42),
            fixture_digest: digest(0x43),
            execution_profile_digest: digest(0x44),
            lps1_digest: digest(0x45),
            sim1_digest: digest(0x46),
            apt1_digest: digest(0x47),
            trs1_digest: digest(0x48),
            rvs1_digest: digest(0x49),
            spm1_digest: digest(0x4a),
            pcf1_digest: digest(0x4b),
            pcr1_digest: digest(0x4c),
            hcp1_digest: digest(0x4d),
        },
        trust_epoch: 1,
        revocation_epoch: 2,
        policy_epoch: 3,
        elm1_digest: digest(0xe1),
        input_digest: digest(0x51),
        exchange_plan_digests: Vec::new(),
        expected_launch_policy_digest: digest(0x45),
        expected_readback_set_digest: digest(0x52),
        runtime_attestation_key_id: KEY_ID.to_owned(),
    };
    let public = signing_key().verifying_key();
    let admitted = crate::AdmittedRuntimeKey::new(KEY_ID, &public);
    let verified =
        crate::sign_verified(&signer(), admitted, AdmissionGrant::self_digested(fields)?)?;
    let grant = AdmissionGrant::new(verified, &public)?;
    let bytes = grant.to_canonical_cbor()?;
    Ok(SignedGrant { grant, bytes })
}

/// The `ReleaseV1` the test key signs for `grant`, bound to `koe1`.
fn signed_release(grant: &AdmissionGrant, koe1: [u8; 32]) -> TestResult<ExecutionRelease> {
    let public = signing_key().verifying_key();
    let admitted = crate::AdmittedRuntimeKey::new(KEY_ID, &public);
    Ok(crate::issue_release(
        &signer(),
        admitted,
        ExecutionReleaseFields {
            attempt_id: ATTEMPT,
            nonce: [0x61; 32],
            ready1_digest: READY1,
            trs1_digest: grant.authority.trs1_digest,
            rvs1_digest: grant.authority.rvs1_digest,
            apt1_digest: grant.authority.apt1_digest,
            trust_epoch: grant.trust_epoch,
            revocation_epoch: grant.revocation_epoch,
            policy_epoch: grant.policy_epoch,
            expected_readback_digest: [0x62; 32],
            observed_readback_digest: koe1,
            deadline_monotonic_ns: D,
            runtime_attestation_key_id: KEY_ID.to_owned(),
        },
    )?)
}

/// The four limit-event sources with these counters.
fn sources(oom_kill: u64, memory: u64, swap: u64, pids: u64, throttled: u64) -> [Vec<u8>; 4] {
    [
        format!("low 0\nhigh 0\nmax {memory}\noom 0\noom_kill {oom_kill}\n").into_bytes(),
        format!("high 0\nmax {swap}\nfail 0\n").into_bytes(),
        format!("max {pids}\n").into_bytes(),
        format!("usage_usec 10\nnr_throttled {throttled}\nthrottled_usec {throttled}\n")
            .into_bytes(),
    ]
}

fn quiet() -> [Vec<u8>; 4] {
    sources(0, 0, 0, 0, 0)
}

fn verified_start() -> TestResult<SystemdVerifiedStart> {
    Ok(SystemdVerifiedStart::for_test(
        TransientServiceUnitName::from_attempt_id(ATTEMPT)?,
        "/org/freedesktop/systemd1/unit/attempt",
    )?)
}

/// The fake start whose RQE1 the tests use (`String`, as in the execute
/// tests).
fn start() -> String {
    "attempt".to_owned()
}

/// The admission of [`ATTEMPT`] under the signed test grant, with a
/// complete input, its AGR1 digest, and the signer and key of that grant.
pub(super) fn signed_admission() -> TestResult<(
    crate::AttemptAdmission,
    [u8; 32],
    crate::KeyFileRuntimeSigner,
    ed25519_dalek::VerifyingKey,
)> {
    let grant = signed_grant()?;
    let digest = grant.grant.grant_digest();
    let input = TransferRecord {
        start: 1,
        deadline: 4,
        finish: 3,
        expected_bytes: 1,
        accepted_bytes: 1,
        complete: true,
    };
    Ok((
        admission_of(Some(&grant), SandboxExecutionMode::AirGapped, Some(input)),
        digest,
        signer(),
        signing_key().verifying_key(),
    ))
}

/// A Completed response with output, signed by the test key and retained
/// in `lifecycle` for [`ATTEMPT`].
pub(super) fn completed_retained(
    lifecycle: &crate::AttemptLifecycle,
) -> TestResult<std::sync::Arc<crate::RetainedResponse>> {
    completed_pending(lifecycle).and_then(|pending| retain_pending(pending, lifecycle))
}

/// A Completed attempt of [`ATTEMPT`] that ended in `lifecycle` and whose
/// response is not retained yet.
pub(super) fn completed_pending(
    lifecycle: &crate::AttemptLifecycle,
) -> TestResult<crate::test_fixtures::PendingCompleted> {
    let grant = signed_grant()?;
    let digest = grant.grant.grant_digest();
    lifecycle.failed_granted(
        &pos_reference::provider_admission::execution::FailedInput::fixture(ATTEMPT, digest),
    )?;
    let output = crate::StagingLedger::new(crate::StagingLimits {
        aggregate_bytes: 1024,
    });
    let ended = Released {
        grant: Some(grant),
        output_ledger: Some(output),
        ..Released::default()
    }
    .ended()?;
    Ok(crate::test_fixtures::PendingCompleted {
        ended,
        attempt_id: ATTEMPT,
        agr1_digest: digest,
    })
}

/// Retain `pending`'s response in `lifecycle`, signed by the test key.
pub(super) fn retain_pending(
    pending: crate::test_fixtures::PendingCompleted,
    lifecycle: &crate::AttemptLifecycle,
) -> TestResult<std::sync::Arc<crate::RetainedResponse>> {
    let public = signing_key().verifying_key();
    Ok(lifecycle.retain_response(
        pending.ended,
        &signer(),
        crate::AdmittedRuntimeKey::new(KEY_ID, &public),
    )?)
}

/// What one released attempt observed; the default is a Completed run.
struct Released {
    baseline: [Vec<u8>; 4],
    terminal: [Vec<u8>; 4],
    terminal_at: (i64, i64),
    terminal_cgroup: (u64, u64),
    service: Option<(&'static str, i32, i32)>,
    ending: AttemptEnding,
    output: Option<Vec<u8>>,
    ceiling: bool,
    /// Whether the stdin feed completed; `None` when the clock could not
    /// report one of its times.
    feed_complete: Option<bool>,
    network: NetworkEvidence,
    /// KOE1 `/work` and TME1 `work-after`: mount ID and capacity.
    work: Option<(u64, u64)>,
    work_after: Option<(u64, u64)>,
    input: Option<TransferRecord>,
    cancel: Option<CancelSource>,
    proved: bool,
    cleaned_at: Option<u64>,
    /// The signed AGR1, under which `ReleaseV1` is signed too; `None` for
    /// filler AGR1 bytes and no `ReleaseV1`.
    grant: Option<SignedGrant>,
    /// The ledger the output is charged to, one byte per captured byte;
    /// `None` for an uncharged output.
    output_ledger: Option<crate::StagingLedger>,
}

impl Default for Released {
    fn default() -> Self {
        Self {
            baseline: quiet(),
            terminal: quiet(),
            terminal_at: (1_005, 0),
            terminal_cgroup: CGROUP,
            service: Some(("success", 1, 0)),
            ending: AttemptEnding::CgroupEmpty,
            output: None,
            ceiling: false,
            feed_complete: Some(true),
            network: NetworkEvidence::None,
            work: None,
            work_after: None,
            input: Some(input(true)),
            cancel: None,
            proved: true,
            cleaned_at: Some(CLEANED_AT),
            grant: None,
            output_ledger: None,
        }
    }
}

/// The stdin feed after the release, within the run.
const fn feed(complete: bool) -> TransferRecord {
    TransferRecord {
        start: 1_001_000_000_000,
        deadline: 1_003_000_000_000,
        finish: 1_001_500_000_000,
        expected_bytes: 5,
        accepted_bytes: if complete { 5 } else { 2 },
        complete,
    }
}

fn observation(work: Option<(u64, u64)>) -> KernelObservation {
    let observation = KernelObservation::fixture(INVOCATION);
    match work {
        Some((mount_id, capacity)) => observation.with_work_for_test(mount_id, capacity),
        None => observation,
    }
}

/// The release phase: a frozen status-0 KOE1 bound to the fake start's
/// RQE1, and no `ReleaseV1`.
fn release(work: Option<(u64, u64)>) -> TestResult<ReleaseOutcome> {
    release_of(None, work, false)
}

/// The release phase under `grant`: KOE1 binds its AGR1, and the
/// `ReleaseV1` it signs was sent if `send`.
fn release_of(
    grant: Option<&SignedGrant>,
    work: Option<(u64, u64)>,
    send: bool,
) -> TestResult<ReleaseOutcome> {
    let agr1 = grant.map_or(AGR1, |signed| signed.grant.grant_digest());
    let requested =
        crate::RequestedConfiguration::requested_configuration_evidence(&start(), ATTEMPT, agr1)?;
    let observation = observation(work);
    let koe1 =
        crate::observation_evidence(ATTEMPT, agr1, READY1, requested.digest(), &observation)?;
    let release = grant
        .filter(|_| send)
        .map(|signed| signed_release(&signed.grant, koe1.digest()))
        .transpose()?;
    Ok(ReleaseOutcome::new(
        Some(READY1),
        Some((ObservedUnit::new(&observation), koe1)),
        release,
    ))
}

/// Resource evidence with a baseline at 1000 s and the terminal reading.
fn evidence(
    release: ReleaseOutcome,
    baseline: [Vec<u8>; 4],
    terminal: TerminalResources,
) -> TestResult<ResourceEvidence> {
    evidence_of(release, (CGROUP, CGROUP), baseline, terminal)
}

/// [`evidence`] with the baseline snapshot's and the bound unit's cgroup
/// identities (`(st_dev, inode)`) given.
fn evidence_of(
    release: ReleaseOutcome,
    (baseline_cgroup, unit_cgroup): ((u64, u64), (u64, u64)),
    baseline: [Vec<u8>; 4],
    terminal: TerminalResources,
) -> TestResult<ResourceEvidence> {
    let resources = ReleaseResources::new(
        ACTIVATED,
        AttemptLimitEventSnapshot::for_test(baseline_cgroup, baseline, (1_000, 1))?,
        EffectiveCgroupLimits::for_test(CGROUP)?,
    );
    let mut evidence = ResourceEvidence::new(Some(resources), release);
    evidence.conclude(Some((INVOCATION, unit_cgroup)), terminal);
    Ok(evidence)
}

fn terminal(run: &Released) -> TestResult<TerminalResources> {
    let started = verified_start()?;
    let service = match run.service {
        Some((result, code, status)) => Ok(SystemdUnitResultObservation::for_test(
            &started, result, code, status,
        )?),
        None => Err(TerminalServiceError::Unstarted),
    };
    Ok(TerminalResources::new(
        Ok(AttemptLimitEventSnapshot::for_test(
            run.terminal_cgroup,
            run.terminal.clone(),
            run.terminal_at,
        )?),
        run.work_after
            .map(|(mount_id, capacity)| Ok(WorkUsage::for_test(mount_id, capacity, 7))),
        service,
        Ok(()),
    ))
}

fn cleanup(proved: bool) -> TestResult<crate::AttemptCleanup> {
    Ok(if proved {
        Ok(Some(CompletedAttemptCleanup::for_test(
            PlannedAttemptIntent::new(ATTEMPT, AGR1)?,
            Some(AttemptCgroupEmptyBasis::Events),
        )))
    } else {
        Err(AttemptLifecycleError::CleanupFailed)
    })
}

fn adapter(run: &Released) -> TestResult<AdapterIo> {
    let output = match &run.output {
        Some(output) => output.clone(),
        None => framed()?,
    };
    let charge = match &run.output_ledger {
        Some(ledger) => ledger.reserve_storage(output.len() as u64)?,
        None => crate::StagingLedger::new(crate::StagingLimits { aggregate_bytes: 0 })
            .reserve_storage(0)?,
    };
    Ok(AdapterIo::for_test_capture(
        run.feed_complete.map(feed),
        output,
        run.ceiling,
        charge,
    ))
}

impl Released {
    fn ended(self) -> TestResult<EndedAttempt<String>> {
        let terminal = terminal(&self)?;
        let adapter = adapter(&self)?;
        let progress = AttemptProgress::Executed {
            started: start(),
            ending: self.ending,
            network: self.network,
            evidence: evidence(
                release_of(self.grant.as_ref(), self.work, true)?,
                self.baseline,
                terminal,
            )?,
            adapter,
        };
        Ok(EndedAttempt::for_test(
            ATTEMPT,
            admission_of(
                self.grant.as_ref(),
                SandboxExecutionMode::AirGapped,
                self.input,
            ),
            self.cancel,
            progress,
            (cleanup(self.proved)?, self.cleaned_at),
        ))
    }

    fn records(self) -> TestResult<AttemptRecords> {
        Ok(self.ended()?.records()?)
    }

    fn code(self) -> TestResult<Option<TerminalCode>> {
        let records = self.records()?;
        assert_recomputed(&records);
        Ok(records.classification().code())
    }
}

/// TME1 records exactly the classification a verifier recomputes from it
/// and the RQE1 and KOE1 it binds (R9 §6 rule 7).
fn assert_recomputed(records: &AttemptRecords) {
    let termination = records.termination();
    let recomputed = termination
        .facts(records.requested(), records.observed())
        .classify();
    assert_eq!(&recomputed, records.classification());
    assert_eq!(termination.fields().terminal_code, recomputed.code());
    assert_eq!(
        termination.fields().contradiction,
        recomputed.contradiction()
    );
    assert_eq!(
        termination.fields().koe1_digest,
        records.observed().digest()
    );
}

#[test]
fn a_clean_released_run_is_completed() -> TestResult {
    let records = Released::default().records()?;
    assert_recomputed(&records);
    let classification = records.classification();
    assert_eq!(classification.code(), None);
    assert_eq!(classification.outcome(), SandboxTerminalOutcome::Completed);
    assert!(!classification.quarantined());
    assert_eq!(
        records.requested().fields().status,
        RequestedConfigurationStatus::Verified
    );
    assert!(matches!(
        records.observed().fields().status,
        KernelObservationStatus::Observed { .. }
    ));
    let fields = records.termination().fields();
    assert_eq!(fields.attempt_id, ATTEMPT);
    assert_eq!(fields.agr1_digest, AGR1);
    assert_eq!(fields.elm1_digest, [0xe1; 32]);
    assert_eq!(fields.progress, AttemptProgressCode::Released);
    assert_eq!(fields.start_job, Some(StartJobResult::Done));
    assert_eq!(fields.watchdog_deadline, D);
    assert_eq!(fields.input, input(true));
    assert_eq!(fields.adapter_input, Some(feed(true)));
    assert_eq!(fields.cleanup.result, CleanupResult::Proved);
    assert_eq!(fields.cleanup.finished_at, CLEANED_AT);
    assert!(fields.cleanup.empty_basis.is_some());
    assert!(fields.local_network.is_none() && fields.work_after.is_none());
    assert_eq!(
        fields
            .terminal
            .as_ref()
            .map(|terminal| terminal.observed_at),
        Some(1_005_000_000_000)
    );
    Ok(())
}

/// One case per ELM1 limit ID with a TME1 field (R9 §4.6.5 and D6; owner
/// reading, Redmine #443 journal 22723): IDs 3, 5 and 9 select no code, IDs
/// 13 and 14 are enforced before AGR1 and ID 15 has no field (O8).
#[test]
fn each_cgroup_limit_id_selects_its_code() -> TestResult {
    let cases: [(&str, Released, Option<TerminalCode>); 6] = [
        (
            "0 oom_kill",
            Released {
                terminal: sources(1, 0, 0, 0, 0),
                ..Released::default()
            },
            Some(TerminalCode::OomKilled),
        ),
        (
            "0 systemd oom-kill",
            Released {
                service: Some(("oom-kill", 2, 9)),
                ..Released::default()
            },
            Some(TerminalCode::OomKilled),
        ),
        (
            "0 memory max",
            Released {
                terminal: sources(0, 1, 0, 0, 0),
                ..Released::default()
            },
            Some(TerminalCode::MemoryLimit),
        ),
        (
            "1 swap max",
            Released {
                terminal: sources(0, 0, 1, 0, 0),
                ..Released::default()
            },
            Some(TerminalCode::MemoryLimit),
        ),
        (
            "2 tasks",
            Released {
                terminal: sources(0, 0, 0, 1, 0),
                ..Released::default()
            },
            Some(TerminalCode::TaskLimit),
        ),
        (
            "3 throttling",
            Released {
                terminal: sources(0, 0, 0, 0, 9),
                ..Released::default()
            },
            None,
        ),
    ];
    for (case, run, expected) in cases {
        assert_eq!(run.code()?, expected, "{case}");
    }
    Ok(())
}

/// The limit IDs that act through the main exit, the transfers, the
/// capture and `/work`.
#[test]
fn each_process_and_transfer_limit_id_selects_its_code() -> TestResult {
    let cases: [(&str, Released, Option<TerminalCode>); 7] = [
        (
            "6 SIGXFSZ",
            Released {
                service: Some(("signal", 2, 25)),
                ..Released::default()
            },
            Some(TerminalCode::FileOrOutputLimit),
        ),
        (
            "6 SIGXFSZ core",
            Released {
                service: Some(("core-dump", 3, 25)),
                ..Released::default()
            },
            Some(TerminalCode::FileOrOutputLimit),
        ),
        (
            "7 input",
            Released {
                input: Some(input(false)),
                ..Released::default()
            },
            Some(TerminalCode::ProtocolFailure),
        ),
        (
            "8 output ceiling",
            Released {
                output: Some(vec![0; 100]),
                ceiling: true,
                ..Released::default()
            },
            Some(TerminalCode::FileOrOutputLimit),
        ),
        (
            "9 /work",
            Released {
                work: Some((44, 1 << 30)),
                work_after: Some((44, 1 << 30)),
                ..Released::default()
            },
            None,
        ),
        (
            "16 stdin feed",
            Released {
                feed_complete: Some(false),
                ..Released::default()
            },
            Some(TerminalCode::ProtocolFailure),
        ),
        (
            "crash",
            Released {
                service: Some(("signal", 2, 11)),
                ..Released::default()
            },
            Some(TerminalCode::ProcessCrash),
        ),
    ];
    for (case, run, expected) in cases {
        assert_eq!(run.code()?, expected, "{case}");
    }
    Ok(())
}

/// IDs 13 and 14 are recorded at AGR1 and select nothing.
#[test]
fn the_admission_ledger_is_recorded_from_agr1() -> TestResult {
    let records = Released::default().records()?;
    let fields = records.termination().fields();
    assert_eq!(fields.admission.active_attempts, 1);
    assert_eq!(fields.admission.incomplete_inputs, 1);
    assert_eq!(records.classification().code(), None);
    Ok(())
}

/// IDs 10 to 12 act through the Local session's termination.
#[test]
fn the_local_session_termination_selects_its_code() -> TestResult {
    let cases = [
        (None, false, None),
        (
            Some(LocalNetworkTermination::RemoteUnavailable),
            false,
            Some(TerminalCode::IpcFailure),
        ),
        (
            Some(LocalNetworkTermination::DigestMismatch),
            true,
            Some(TerminalCode::ProtocolFailure),
        ),
    ];
    for (termination, watchdog_expired, expected) in cases {
        let run = Released {
            network: NetworkEvidence::Local(ServedProxy {
                session: LocalNetworkSession::fixture(termination),
                watchdog_expired,
            }),
            ..Released::default()
        };
        let records = run.records()?;
        let network = records
            .termination()
            .fields()
            .local_network
            .ok_or("no local network record")?;
        assert_eq!(network.termination, termination.map(Into::into));
        assert_eq!(network.watchdog_closed, watchdog_expired);
        assert_eq!(records.classification().code(), expected);
    }
    Ok(())
}

/// ID 4: systemd's timeout is the watchdog only at or after `D - G`; the
/// broker's kill without it is an enforcement failure (R9 §4.6.5).
#[test]
fn the_watchdog_needs_the_deadline_minus_grace() -> TestResult {
    let at = |ns: u64| -> TestResult<(i64, i64)> {
        Ok((
            i64::try_from(ns / 1_000_000_000)?,
            i64::try_from(ns % 1_000_000_000)?,
        ))
    };
    let timeout = |terminal_at, ending| Released {
        terminal_at,
        service: Some(("timeout", 2, 9)),
        ending,
        cleaned_at: Some(D + 2 * WATCHDOG_GRACE_NS),
        ..Released::default()
    };
    let cases = [
        (
            timeout(at(D - WATCHDOG_GRACE_NS)?, AttemptEnding::CgroupEmpty),
            Some(TerminalCode::Watchdog),
        ),
        (
            timeout(at(D + WATCHDOG_GRACE_NS)?, AttemptEnding::WatchdogKilled),
            Some(TerminalCode::Watchdog),
        ),
        (
            timeout(at(D - WATCHDOG_GRACE_NS - 1)?, AttemptEnding::CgroupEmpty),
            Some(TerminalCode::CleanupFailed),
        ),
        (
            Released {
                ending: AttemptEnding::WatchdogKilled,
                ..Released::default()
            },
            Some(TerminalCode::CleanupFailed),
        ),
    ];
    for (run, expected) in cases {
        assert_eq!(run.code()?, expected);
    }
    Ok(())
}

/// D5: a contradiction is code 2 even when the attempt was cancelled (O3),
/// and a counter decrease is never read as a limit event.
#[test]
fn each_contradiction_is_code_2() -> TestResult {
    let cases = [
        Released {
            terminal_cgroup: (26, 9999),
            cancel: Some(CancelSource::CancelRequest),
            ending: AttemptEnding::Cancelled { watchdog: None },
            ..Released::default()
        },
        // KOE1 recorded one `/work` capacity, `work-after` another.
        Released {
            work: Some((44, 1 << 30)),
            work_after: Some((44, 1 << 29)),
            ..Released::default()
        },
        Released {
            baseline: sources(1, 0, 0, 0, 0),
            ..Released::default()
        },
    ];
    let expected = [
        Contradiction::IdentityChanged,
        Contradiction::IdentityChanged,
        Contradiction::CounterDecreased,
    ];
    for (run, expected) in cases.into_iter().zip(expected) {
        let records = run.records()?;
        assert_recomputed(&records);
        assert_eq!(records.classification().contradiction(), Some(expected));
        assert_eq!(
            records.classification().code(),
            Some(TerminalCode::CleanupFailed)
        );
        assert!(records.classification().quarantined());
    }
    // `work-after` that could not be read beside a KOE1 `/work` is missing
    // evidence, not a contradiction.
    let unread = Released {
        work: Some((44, 1 << 30)),
        ..Released::default()
    }
    .records()?;
    assert!(unread.termination().fields().work_after.is_none());
    assert!(unread.classification().contradiction().is_none());
    assert_eq!(
        unread.classification().code(),
        Some(TerminalCode::CleanupFailed)
    );
    Ok(())
}

/// A terminal snapshot older than the baseline is reversed time (D5), here
/// on a release that never came.
#[test]
fn a_reversed_snapshot_is_code_2() -> TestResult {
    let run = Released {
        terminal_at: (999, 0),
        cleaned_at: Some(CLEANED_AT),
        ..Released::default()
    };
    let terminal = terminal(&run)?;
    let progress = AttemptProgress::Failed {
        error: ExecuteError::ReleaseTimeout,
        unit: UnitState::Killed,
        started: Some(start()),
        evidence: Some(evidence(release(None)?, quiet(), terminal)?),
    };
    let records = EndedAttempt::for_test(
        ATTEMPT,
        admission(SandboxExecutionMode::AirGapped, Some(input(true))),
        None,
        progress,
        (cleanup(true)?, Some(CLEANED_AT)),
    )
    .records()?;
    assert_recomputed(&records);
    let fields = records.termination().fields();
    assert_eq!(fields.progress, AttemptProgressCode::StartedNotReleased);
    assert!(fields.adapter_input.is_none() && fields.output_capture.is_none());
    assert_eq!(
        records.classification().contradiction(),
        Some(Contradiction::TimeReversed)
    );
    assert_eq!(
        records.classification().code(),
        Some(TerminalCode::CleanupFailed)
    );
    Ok(())
}

/// A missing service result or an unproved cleanup is code 2; a cancelled
/// run with an unproved cleanup reports Cancelled and is quarantined.
#[test]
fn missing_evidence_and_failed_cleanup_are_code_2() -> TestResult {
    let missing = Released {
        service: None,
        ..Released::default()
    };
    assert_eq!(missing.code()?, Some(TerminalCode::CleanupFailed));
    let unproved = Released {
        proved: false,
        ..Released::default()
    }
    .records()?;
    let fields = unproved.termination().fields();
    assert_eq!(fields.cleanup.result, CleanupResult::NotProved);
    assert!(fields.cleanup.empty_basis.is_none());
    assert_eq!(
        unproved.classification().code(),
        Some(TerminalCode::CleanupFailed)
    );
    let cancelled = Released {
        proved: false,
        cancel: Some(CancelSource::Revocation),
        ending: AttemptEnding::Cancelled { watchdog: None },
        ..Released::default()
    }
    .records()?;
    assert_eq!(
        cancelled.classification().code(),
        Some(TerminalCode::Cancelled)
    );
    assert_eq!(
        cancelled.classification().outcome(),
        SandboxTerminalOutcome::Cancelled
    );
    assert!(cancelled.classification().quarantined());
    Ok(())
}

/// An attempt that ended before its unit start: RQE1 status 1, KOE1 status
/// 1, progress 0, and the AGR1-time watchdog deadline.
#[test]
fn an_unstarted_attempt_has_progress_0() -> TestResult {
    let unstarted = |progress, cancel, input| {
        EndedAttempt::<String>::for_test(
            ATTEMPT,
            admission(SandboxExecutionMode::Local, input),
            cancel,
            progress,
            (Ok(None), Some(CLEANED_AT)),
        )
        .records()
    };
    let reservation = |refused| AttemptProgress::Failed {
        error: ExecuteError::OutputReservation(refused),
        unit: UnitState::NotStarted,
        started: None,
        evidence: None,
    };
    let cases = [
        (
            unstarted(
                AttemptProgress::Withdrawn,
                Some(CancelSource::CancelRequest),
                Some(input(true)),
            )?,
            None,
            Some(TerminalCode::Cancelled),
        ),
        (
            unstarted(AttemptProgress::InputFailed, None, Some(input(false)))?,
            None,
            Some(TerminalCode::ProtocolFailure),
        ),
        (
            unstarted(
                AttemptProgress::NotActivated(ImageActivationError::Transport),
                None,
                Some(input(true)),
            )?,
            Some(LaunchFailure::RootNotActivated),
            Some(TerminalCode::ProtocolFailure),
        ),
        (
            unstarted(
                reservation(OutputReservationRefused::AggregateExceeded),
                None,
                Some(input(true)),
            )?,
            Some(LaunchFailure::OutputReservationRefused),
            Some(TerminalCode::ProtocolFailure),
        ),
        (
            unstarted(
                reservation(OutputReservationRefused::AdmissionClosed),
                None,
                Some(input(true)),
            )?,
            Some(LaunchFailure::AdmissionClosed),
            Some(TerminalCode::CleanupFailed),
        ),
    ];
    for (records, launch_failure, expected) in cases {
        assert_recomputed(&records);
        let fields = records.termination().fields();
        assert_eq!(fields.progress, AttemptProgressCode::NotStarted);
        assert_eq!(fields.launch_failure, launch_failure);
        assert!(fields.start_job.is_none() && fields.local_network.is_none());
        // `D` at AGR1: the fixture grant was issued at 2 ns.
        assert_eq!(fields.watchdog_deadline, 2 + D - ACTIVATED);
        assert_eq!(fields.cleanup.result, CleanupResult::NothingCommitted);
        assert_eq!(
            records.requested().fields().status,
            RequestedConfigurationStatus::NotRequested
        );
        assert!(matches!(
            records.observed().fields().status,
            KernelObservationStatus::NotReached
        ));
        assert_eq!(records.classification().code(), expected);
    }
    Ok(())
}

/// A Local attempt whose release never came records its bound proxy as a
/// clean close, and the barrier's expiry after `ReadyV1` (R9 §4.6.1).
#[test]
fn an_unreleased_local_attempt_records_its_proxy_and_barrier() -> TestResult {
    let run = Released::default();
    let terminal = terminal(&run)?;
    let progress = AttemptProgress::Failed {
        error: ExecuteError::ReleaseTimeout,
        unit: UnitState::Killed,
        started: Some(start()),
        evidence: Some(evidence(release(None)?, quiet(), terminal)?),
    };
    let records = EndedAttempt::for_test(
        ATTEMPT,
        admission(SandboxExecutionMode::Local, Some(input(true))),
        None,
        progress,
        (cleanup(true)?, Some(CLEANED_AT)),
    )
    .records()?;
    assert_recomputed(&records);
    let fields = records.termination().fields();
    assert_eq!(fields.progress, AttemptProgressCode::StartedNotReleased);
    assert_eq!(fields.barrier_failure, Some(BarrierFailure::RecheckExpired));
    assert!(fields
        .local_network
        .is_some_and(|network| network.termination.is_none() && !network.watchdog_closed));
    assert_eq!(fields.watchdog_deadline, D);
    assert_eq!(
        records.classification().code(),
        Some(TerminalCode::ProtocolFailure)
    );
    Ok(())
}

/// An unreleased Local attempt whose resource evidence is `evidence`.
fn unreleased(evidence: ResourceEvidence) -> TestResult<Result<AttemptRecords, EvidenceFault>> {
    unreleased_in(SandboxExecutionMode::Local, evidence)
}

/// An unreleased attempt in `mode` whose resource evidence is `evidence`.
fn unreleased_in(
    mode: SandboxExecutionMode,
    evidence: ResourceEvidence,
) -> TestResult<Result<AttemptRecords, EvidenceFault>> {
    let progress = AttemptProgress::Failed {
        error: ExecuteError::ReleaseTimeout,
        unit: UnitState::Killed,
        started: Some(start()),
        evidence: Some(evidence),
    };
    Ok(EndedAttempt::for_test(
        ATTEMPT,
        admission(mode, Some(input(true))),
        None,
        progress,
        (cleanup(true)?, Some(CLEANED_AT)),
    )
    .records())
}

/// The barrier's own refusal is recorded over the expiry the release
/// timeout would otherwise imply (R9 §4.6.1).
#[test]
fn the_barrier_refusal_is_recorded_as_given() -> TestResult {
    let terminal = terminal(&Released::default())?;
    let refused = release(None)?.refused(Some(BarrierFailure::ReadyMismatch));
    let records = unreleased(evidence(refused, quiet(), terminal)?)??;
    assert_recomputed(&records);
    assert_eq!(
        records.termination().fields().barrier_failure,
        Some(BarrierFailure::ReadyMismatch)
    );
    Ok(())
}

/// Before a release, a baseline without its terminal snapshot records
/// neither (R9 §4.6.3): the pair is missing evidence.
#[test]
fn an_unreleased_baseline_without_its_terminal_records_neither() -> TestResult {
    let started = verified_start()?;
    let terminal = TerminalResources::new(
        Err(crate::AttemptCgroupError::InvalidPath),
        None,
        Ok(SystemdUnitResultObservation::for_test(
            &started, "success", 1, 0,
        )?),
        Ok(()),
    );
    let records = unreleased(evidence(release(None)?, quiet(), terminal)?)??;
    assert_recomputed(&records);
    let fields = records.termination().fields();
    assert_eq!(fields.progress, AttemptProgressCode::StartedNotReleased);
    assert!(fields.unit.is_some());
    assert!(fields.baseline.is_none() && fields.terminal.is_none());
    Ok(())
}

/// Only a Local attempt has a proxy to close: an unreleased air-gapped
/// attempt records no local network (R9 §4.6.3).
#[test]
fn an_unreleased_air_gapped_attempt_records_no_proxy() -> TestResult {
    let terminal = terminal(&Released::default())?;
    let evidence = evidence(release(None)?, quiet(), terminal)?;
    let records = unreleased_in(SandboxExecutionMode::AirGapped, evidence)??;
    assert_recomputed(&records);
    let fields = records.termination().fields();
    assert_eq!(fields.progress, AttemptProgressCode::StartedNotReleased);
    assert!(fields.local_network.is_none());
    Ok(())
}

/// A `ReadyV1` whose observation never froze is a status-2 KOE1 that binds
/// that `ReadyV1` (R9 §4.4).
#[test]
fn a_ready_without_a_frozen_observation_is_koe1_status_2() -> TestResult {
    let terminal = terminal(&Released::default())?;
    let release = ReleaseOutcome::new(Some(READY1), None, None);
    let records = unreleased(evidence(release, quiet(), terminal)?)??;
    assert_recomputed(&records);
    assert!(matches!(
        records.observed().fields().status,
        KernelObservationStatus::ObservationFailed {
            ready1_digest: READY1
        }
    ));
    Ok(())
}

/// A bound unit or a baseline whose cgroup device is outside the kernel's
/// bounds has no R9 identity: no records.
#[test]
fn an_unrepresentable_unit_or_baseline_cgroup_is_a_fault() -> TestResult {
    let out_of_bounds = (u64::MAX, 1);
    for cgroups in [(CGROUP, out_of_bounds), (out_of_bounds, CGROUP)] {
        let terminal = terminal(&Released::default())?;
        let evidence = evidence_of(release(None)?, cgroups, quiet(), terminal)?;
        assert!(matches!(
            unreleased(evidence)?,
            Err(EvidenceFault::Unrepresentable)
        ));
    }
    Ok(())
}

/// A start requested and failed before any unit was bound: no snapshot, no
/// empty basis, and missing evidence when the failure was not observed.
#[test]
fn a_failure_before_binding_records_no_unit() -> TestResult {
    let failed = |error, started| AttemptProgress::Failed {
        error,
        unit: UnitState::Killed,
        started,
        evidence: None,
    };
    let records = EndedAttempt::for_test(
        ATTEMPT,
        admission(SandboxExecutionMode::AirGapped, Some(input(true))),
        None,
        failed(ExecuteError::HostTimeout, Some(start())),
        (cleanup(true)?, Some(CLEANED_AT)),
    )
    .records()?;
    assert_recomputed(&records);
    let fields = records.termination().fields();
    assert_eq!(fields.progress, AttemptProgressCode::StartedNotReleased);
    assert!(fields.unit.is_none() && fields.baseline.is_none());
    assert!(fields.cleanup.empty_basis.is_none());
    assert_eq!(fields.watchdog_deadline, 0);
    // A start without its failure has no RQE1 (R9 §4.3).
    let unverified = EndedAttempt::for_test(
        ATTEMPT,
        admission(SandboxExecutionMode::AirGapped, Some(input(true))),
        None,
        failed(ExecuteError::HostTimeout, None),
        (cleanup(true)?, Some(CLEANED_AT)),
    );
    assert!(matches!(
        unverified.records(),
        Err(EvidenceFault::Unrepresentable)
    ));
    Ok(())
}

/// A time TME1 requires that the clock could not report, or a record that
/// breaks R9 rule 9, is a provider fault: no records (owner reading G2).
#[test]
fn unreadable_times_and_unordered_records_are_faults() -> TestResult {
    let no_input = Released {
        input: None,
        ..Released::default()
    };
    assert!(matches!(
        no_input.ended()?.records(),
        Err(EvidenceFault::Clock)
    ));
    let no_cleanup = Released {
        cleaned_at: None,
        ..Released::default()
    };
    assert!(matches!(
        no_cleanup.ended()?.records(),
        Err(EvidenceFault::Clock)
    ));
    let negative = Released {
        terminal_at: (-1, 0),
        ..Released::default()
    };
    assert!(matches!(
        negative.ended()?.records(),
        Err(EvidenceFault::Clock)
    ));
    // An unreadable `adapter-input` time is a provider fault too, never R10's
    // null `adapter-input` (R9 Amendment 1 change F).
    let no_feed_time = Released {
        feed_complete: None,
        ..Released::default()
    };
    assert!(matches!(
        no_feed_time.ended()?.records(),
        Err(EvidenceFault::Clock)
    ));
    let early_cleanup = Released {
        cleaned_at: Some(1),
        ..Released::default()
    };
    assert!(matches!(
        early_cleanup.ended()?.records(),
        Err(EvidenceFault::Record(_))
    ));
    let out_of_bounds = Released {
        terminal_cgroup: (u64::MAX, 1),
        ..Released::default()
    };
    assert!(matches!(
        out_of_bounds.ended()?.records(),
        Err(EvidenceFault::Unrepresentable)
    ));
    Ok(())
}

/// The pre-release resource evidence with a baseline snapshot taken at
/// `baseline_at`.
fn evidence_at(baseline_at: (i64, i64)) -> TestResult<ReleaseResources> {
    Ok(ReleaseResources::new(
        ACTIVATED,
        AttemptLimitEventSnapshot::for_test(CGROUP, quiet(), baseline_at)?,
        EffectiveCgroupLimits::for_test(CGROUP)?,
    ))
}

/// R9 Amendment 1 change F: the production host refuses the release when
/// the baseline snapshot's `observed-at` is no readable time.
#[cfg(target_os = "linux")]
#[test]
fn the_production_host_times_the_baseline_snapshot() -> TestResult {
    use crate::{SystemdTransientUnitTransport, UnitHost};
    for (at, timed) in [
        ((1_000, 1), true),
        ((-1, 0), false),
        ((0, -1), false),
        ((i64::MAX, 0), false),
        ((18_446_744_073, 709_551_615), true),
        ((18_446_744_073, 709_551_616), false),
    ] {
        assert_eq!(
            <SystemdTransientUnitTransport as UnitHost>::evidence_timed(&evidence_at(at)?),
            timed,
            "{at:?}"
        );
    }
    Ok(())
}

/// R9 Amendment 1 change F: an attempt whose execute path sent no
/// `ReleaseV1` because a pre-release time was unreadable has no records and
/// no response, whichever of the two times failed.
#[test]
fn an_unreadable_pre_release_time_is_a_provider_fault() -> TestResult {
    for (baseline_at, recorded) in [((-1, 0), true), ((1_000, 1), false)] {
        let mut evidence = ResourceEvidence::new(Some(evidence_at(baseline_at)?), release(None)?);
        evidence.conclude(Some((INVOCATION, CGROUP)), terminal(&Released::default())?);
        let ended = EndedAttempt::for_test(
            ATTEMPT,
            admission(
                SandboxExecutionMode::AirGapped,
                recorded.then(|| input(true)),
            ),
            None,
            AttemptProgress::Failed {
                error: ExecuteError::UnreadableClock,
                unit: UnitState::Killed,
                started: Some(start()),
                evidence: Some(evidence),
            },
            (cleanup(true)?, Some(CLEANED_AT)),
        );
        assert!(matches!(ended.records(), Err(EvidenceFault::Clock)));
        let public = signing_key().verifying_key();
        assert!(matches!(
            ended.signed_response(&signer(), crate::AdmittedRuntimeKey::new(KEY_ID, &public)),
            Err(super::ResponseFault::Evidence(EvidenceFault::Clock))
        ));
    }
    Ok(())
}

/// A failure after `ReleaseV1` leaves no ending, which a progress-2 TME1
/// requires: no records, by the owner's decision (2026-11-19, Q2).
#[test]
fn a_failure_after_the_release_is_a_provider_fault() -> TestResult {
    let ended = failed_after_release()?;
    assert!(matches!(ended.records(), Err(EvidenceFault::Record(_))));
    // No response is emitted either.
    let public = signing_key().verifying_key();
    assert!(matches!(
        ended.signed_response(&signer(), crate::AdmittedRuntimeKey::new(KEY_ID, &public)),
        Err(super::ResponseFault::Evidence(EvidenceFault::Record(_)))
    ));
    Ok(())
}

/// An attempt that failed after its `ReleaseV1` was sent.
fn failed_after_release() -> TestResult<EndedAttempt<String>> {
    let requested =
        crate::RequestedConfiguration::requested_configuration_evidence(&start(), ATTEMPT, AGR1)?;
    let observation = observation(None);
    let koe1 =
        crate::observation_evidence(ATTEMPT, AGR1, READY1, requested.digest(), &observation)?;
    let public = signing_key().verifying_key();
    let sent = crate::issue_release(
        &signer(),
        crate::AdmittedRuntimeKey::new(KEY_ID, &public),
        pos_reference::sandbox_provider_protocol::ExecutionReleaseFields {
            attempt_id: ATTEMPT,
            nonce: [0x61; 32],
            ready1_digest: READY1,
            trs1_digest: [0x48; 32],
            rvs1_digest: [0x49; 32],
            apt1_digest: [0x47; 32],
            trust_epoch: 1,
            revocation_epoch: 2,
            policy_epoch: 3,
            expected_readback_digest: [0x62; 32],
            observed_readback_digest: koe1.digest(),
            deadline_monotonic_ns: D,
            runtime_attestation_key_id: "runtime".to_owned(),
        },
    )?;
    let release = ReleaseOutcome::new(
        Some(READY1),
        Some((ObservedUnit::new(&observation), koe1)),
        Some(sent),
    );
    let run = Released::default();
    let progress = AttemptProgress::Failed {
        error: ExecuteError::Cgroup(Box::new(std::io::Error::other("cgroup read failed"))),
        unit: UnitState::Killed,
        started: Some(start()),
        evidence: Some(evidence(release, quiet(), terminal(&run)?)?),
    };
    Ok(EndedAttempt::for_test(
        ATTEMPT,
        admission(SandboxExecutionMode::AirGapped, Some(input(true))),
        None,
        progress,
        (cleanup(true)?, Some(CLEANED_AT)),
    ))
}

mod response;

// The lifecycle tests' fixtures, kept here so coverage scores them as test
// code.
impl AttemptAdmission {
    /// The admission of the attempt records' test attempt under their
    /// signed test grant, with that grant's signer and key, for the
    /// lifecycle tests that sign a real response.
    pub(crate) fn signed_for_test(
    ) -> Result<crate::test_fixtures::SignedAdmission, Box<dyn std::error::Error + Send + Sync>>
    {
        signed_admission().map(|(admission, digest, signer, key)| {
            crate::test_fixtures::SignedAdmission {
                admission,
                digest,
                signer,
                key,
            }
        })
    }
}

impl crate::RetainedResponse {
    /// A Completed response, signed by the test runtime key, retained by a
    /// throwaway lifecycle: what the lifecycle tests retain for their fake
    /// attempts.
    pub(crate) fn signed_for_test(
    ) -> Result<std::sync::Arc<Self>, Box<dyn std::error::Error + Send + Sync>> {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        let directory = tempfile::tempdir()?;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
        for child in ["registry", "attempts"] {
            let path = directory.path().join(child);
            std::fs::create_dir(&path)?;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))?;
        }
        let parent = std::fs::File::open(directory.path())?;
        let registry = crate::SystemdAttemptRegistry::from_runtime_directory(
            &parent,
            parent.metadata()?.uid(),
        )?;
        let ledger = crate::StagingLedger::new(crate::StagingLimits {
            aggregate_bytes: 1024,
        });
        let lifecycle: crate::AttemptLifecycle =
            crate::AttemptLifecycle::new(registry, ledger, &crate::ReconciledRestart::for_test());
        lifecycle.completed_for_test()
    }
}
