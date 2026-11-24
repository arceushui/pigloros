//! TME1: the R10 §8.3 vectors as R14 §4.5 replaces them, the R14 §4.6
//! vectors, the R9 §4.6.2 parser, the R9 §4.6.3 and R10 §4.8 shape tables,
//! and R9 §6 rules 1, 2, 7 and 9 within the record, as R10 §7 and R14 §3.5
//! extend them.

use std::num::NonZeroU64;

use ciborium::value::Value;
use pos_reference::sandbox_provider_protocol::{
    AdmissionLedger, AttemptProgressCode, CancelSource, CgroupCounters, CgroupEmptyBasis,
    CgroupIdentity, CgroupSnapshot, CgroupSources, CleanupRecord, CleanupResult, Contradiction,
    EndingCode, KernelObservationEvidence, KernelObservationFacts, LaunchFailure, MainExitCode,
    OutputCaptureFacts, OutputCaptureRecord, RequestedConfigurationEvidence,
    RequestedConfigurationStatus, SandboxProviderProtocolError as ProtocolError, ServiceFacts,
    ServiceResultCode, StartJobResult, TerminalCode, TerminationEvidence,
    TerminationEvidenceFields, TerminationFacts, TransferRecord, UnitIdentity, WorkMountFacts,
    WorkStatfsFacts,
};

use super::oracle::{
    bounds_raw_size, checks_envelope, edit, encode, filled, integer, rejects_every_retyped_node,
    rejects_malformed_encodings, set, unhex, unsigned, with, TestResult,
};
use super::vectors::{
    KOE1_A, KOE1_A_DIGEST, KOE1_B_DIGEST, RQE1_A, SAU1_EVENT_1_AUTHORITY, SAU1_EVENT_2_AUTHORITY,
    TME1_A, TME1_A_DIGEST, TME1_B, TME1_B_DIGEST, TME1_C, TME1_C_DIGEST, TME1_D, TME1_D_DIGEST,
    TME1_E, TME1_E_DIGEST, TME1_F, TME1_F_DIGEST, TME1_G, TME1_G_DIGEST, TME1_H, TME1_H_DIGEST,
};

pub(super) fn decode(bytes: &[u8]) -> Result<(), ProtocolError> {
    TerminationEvidence::from_canonical_cbor(bytes).map(|_| ())
}

const CGROUP: CgroupIdentity = CgroupIdentity {
    major: 0,
    minor: 26,
    inode: 5678,
};
const MEMORY: &[u8] = b"low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\noom_group_kill 0\n";
const SWAP: &[u8] = b"high 0\nmax 0\nfail 0\n";
const CPU_BASELINE: &[u8] = b"usage_usec 1200\nuser_usec 800\nsystem_usec 400\nnr_periods 3\nnr_throttled 0\nthrottled_usec 0\nnr_bursts 0\nburst_usec 0\n";
const CPU_TERMINAL: &[u8] = b"usage_usec 9800\nuser_usec 7100\nsystem_usec 2700\nnr_periods 9\nnr_throttled 0\nthrottled_usec 0\nnr_bursts 0\nburst_usec 0\n";
const BASELINE_AT: u64 = 1_000_000_000_000;
const TERMINAL_AT: u64 = 1_000_250_000_000;
/// The R10 §8.3 stdin feed: it starts 10 s after the baseline, has an
/// ELM1\[16\] window of 2000 ms, and accepts the 5 input bytes.
const FEED_START: u64 = 1_000_010_000_000;
const FEED_DEADLINE: u64 = 1_000_012_000_000;
const FEED_FINISH: u64 = 1_000_010_500_000;
/// The R9 §7.5 input transfer's finish.
const INPUT_FINISH: u64 = 999_500_000_000;
/// `S`, the 70-byte framed Unavailable observation of R10 §8.1.
const STREAM_BYTES: u64 = 70;
const ZERO: CgroupCounters = CgroupCounters {
    oom_kill: 0,
    memory_max: 0,
    swap_max: 0,
    pids_max: 0,
    nr_throttled: 0,
    throttled_usec: 0,
};

fn sources(observed_at: u64, pids: &[u8], cpu: &[u8]) -> CgroupSources {
    CgroupSources {
        cgroup: CGROUP,
        observed_at,
        sources: [MEMORY.to_vec(), SWAP.to_vec(), pids.to_vec(), cpu.to_vec()],
    }
}

/// The R10 §8.3 stdin feed of every vector but TME1-E and -F.
const fn feed(accepted_bytes: u64, finish: u64) -> TransferRecord {
    TransferRecord {
        start: FEED_START,
        deadline: FEED_DEADLINE,
        finish,
        expected_bytes: 5,
        accepted_bytes,
        complete: accepted_bytes == 5 && finish <= FEED_DEADLINE,
    }
}

/// The R10 §8.3 TME1-A fields: R9 §7.5 with `S` captured and the feed.
pub(super) fn vector_a_fields() -> TestResult<TerminationEvidenceFields> {
    Ok(TerminationEvidenceFields {
        attempt_id: [0x11; 16],
        agr1_digest: [0x22; 32],
        elm1_digest: [0x33; 32],
        koe1_digest: unhex(KOE1_A_DIGEST)?.as_slice().try_into()?,
        progress: AttemptProgressCode::Released,
        launch_failure: None,
        start_job: Some(StartJobResult::Done),
        unit: Some(UnitIdentity {
            invocation_id: [0x77; 16],
            cgroup: CGROUP,
        }),
        baseline: Some(sources(BASELINE_AT, b"max 0\n", CPU_BASELINE)),
        terminal: Some(sources(TERMINAL_AT, b"max 0\n", CPU_TERMINAL)),
        contradiction: None,
        service: Some(ServiceFacts::CLEAN),
        ending: Some(EndingCode::CgroupEmpty),
        barrier_failure: None,
        input: TransferRecord {
            start: 999_000_000_000,
            deadline: 1_001_000_000_000,
            finish: INPUT_FINISH,
            expected_bytes: 5,
            accepted_bytes: 5,
            complete: true,
        },
        output_capture: Some(OutputCaptureRecord {
            accepted_bytes: STREAM_BYTES,
            ceiling_reached: false,
            complete_frame: true,
        }),
        output_transfer: None,
        local_network: None,
        admission: AdmissionLedger {
            active_attempts: 1,
            incomplete_inputs: 0,
        },
        work_after: Some(WorkStatfsFacts {
            mount: WorkMountFacts {
                mount_id: 302,
                capacity_bytes: 1_048_576,
            },
            available_bytes: 1_044_480,
        }),
        watchdog_deadline: 1_005_000_000_000,
        cancel_source: None,
        cleanup: CleanupRecord {
            result: CleanupResult::Proved,
            empty_basis: Some(CgroupEmptyBasis::Events),
            finished_at: 1_000_400_000_000,
        },
        previous_tme1_digest: None,
        terminal_code: None,
        adapter_input: Some(feed(5, FEED_FINISH)),
    })
}

/// The R9 §7.6 and §7.6a fields: TME1-A, cancelled.
fn cancelled_fields(status: u8) -> TestResult<TerminationEvidenceFields> {
    Ok(TerminationEvidenceFields {
        service: Some(ServiceFacts {
            result: ServiceResultCode::Signal,
            exec_main_code: MainExitCode::Killed,
            exec_main_status: status,
        }),
        ending: Some(EndingCode::Cancelled),
        cancel_source: Some(CancelSource::CancelRequest),
        output_capture: Some(OutputCaptureRecord {
            accepted_bytes: 0,
            ceiling_reached: false,
            complete_frame: false,
        }),
        ..vector_a_fields()?
    })
}

fn vector_b_fields() -> TestResult<TerminationEvidenceFields> {
    let mut fields = cancelled_fields(9)?;
    fields.baseline = Some(sources(BASELINE_AT, b"max 3\n", CPU_BASELINE));
    fields.terminal = Some(sources(TERMINAL_AT, b"max 2\n", CPU_TERMINAL));
    fields.contradiction = Some(Contradiction::CounterDecreased);
    fields.terminal_code = Some(TerminalCode::CleanupFailed);
    Ok(fields)
}

fn vector_c_fields() -> TestResult<TerminationEvidenceFields> {
    let mut fields = cancelled_fields(15)?;
    fields.cleanup = CleanupRecord {
        result: CleanupResult::NotProved,
        empty_basis: None,
        finished_at: 1_000_400_000_000,
    };
    fields.terminal_code = Some(TerminalCode::Cancelled);
    Ok(fields)
}

/// TME1-D: ELM1\[8\] is 69, so `S` stops at the ceiling; the adapter exited 1.
fn vector_d_fields() -> TestResult<TerminationEvidenceFields> {
    Ok(TerminationEvidenceFields {
        output_capture: Some(OutputCaptureRecord {
            accepted_bytes: STREAM_BYTES - 1,
            ceiling_reached: true,
            complete_frame: false,
        }),
        service: Some(ServiceFacts {
            result: ServiceResultCode::ExitCode,
            exec_main_code: MainExitCode::Exited,
            exec_main_status: 1,
        }),
        terminal_code: Some(TerminalCode::FileOrOutputLimit),
        ..vector_a_fields()?
    })
}

/// TME1-E: the stdin feed stopped at `EPIPE` after 3 bytes.
fn vector_e_fields() -> TestResult<TerminationEvidenceFields> {
    Ok(TerminationEvidenceFields {
        adapter_input: Some(feed(3, 1_000_010_200_000)),
        terminal_code: Some(TerminalCode::ProtocolFailure),
        ..vector_a_fields()?
    })
}

/// TME1-F: the aggregate ledger refused the output reservation, so no unit
/// was started.
fn vector_f_fields() -> TestResult<TerminationEvidenceFields> {
    Ok(TerminationEvidenceFields {
        koe1_digest: unhex(KOE1_B_DIGEST)?.as_slice().try_into()?,
        progress: AttemptProgressCode::NotStarted,
        launch_failure: Some(LaunchFailure::OutputReservationRefused),
        start_job: None,
        unit: None,
        baseline: None,
        terminal: None,
        service: None,
        ending: None,
        output_capture: None,
        work_after: None,
        cleanup: CleanupRecord {
            result: CleanupResult::Proved,
            empty_basis: None,
            finished_at: 999_600_000_000,
        },
        terminal_code: Some(TerminalCode::ProtocolFailure),
        adapter_input: None,
        ..vector_a_fields()?
    })
}

/// TME1-G: a Local attempt's network could not be set up (R14 §4.6).
fn vector_g_fields() -> TestResult<TerminationEvidenceFields> {
    Ok(TerminationEvidenceFields {
        launch_failure: Some(LaunchFailure::NetworkSetupFailed),
        terminal_code: Some(TerminalCode::IpcFailure),
        ..vector_f_fields()?
    })
}

/// TME1-H: a Replay attempt's capture was unavailable (R14 §4.6).
fn vector_h_fields() -> TestResult<TerminationEvidenceFields> {
    Ok(TerminationEvidenceFields {
        launch_failure: Some(LaunchFailure::ReplayUnavailable),
        ..vector_f_fields()?
    })
}

fn transfer(values: [u64; 5], complete: bool) -> Value {
    let mut entries = values.map(integer).to_vec();
    entries.push(Value::Bool(complete));
    Value::Array(entries)
}

/// A unit identity, snapshot, service, capture and `/work` reading copied
/// from TME1-A.
fn vector_field(index: usize) -> TestResult<Value> {
    Ok(unsigned(&unhex(TME1_A)?)?[index].clone())
}

/// A decodable TME1 at each progress, derived from TME1-A.
pub(super) fn at_progress(progress: u64) -> TestResult<Vec<u8>> {
    let vector = unhex(TME1_A)?;
    match progress {
        0 => edit(&vector, |fields| {
            fields[6] = integer(0);
            for index in [8, 9, 10, 11, 13, 14, 17, 21, 27] {
                fields[index] = Value::Null;
            }
            set(fields, &[24, 1], Value::Null)?;
            fields[26] = integer(2);
            Ok(())
        }),
        1 => edit(&vector, |fields| {
            fields[6] = integer(1);
            fields[14] = Value::Null;
            fields[17] = Value::Null;
            fields[27] = Value::Null;
            fields[15] = integer(10);
            fields[26] = integer(10);
            Ok(())
        }),
        _ => Ok(vector),
    }
}

/// Every optional field present at once.
fn every_field_present() -> TestResult<Vec<u8>> {
    edit(&unhex(TME1_A)?, |fields| {
        fields[12] = integer(0);
        fields[18] = transfer([1, 3, 2, 4, 4], true);
        fields[19] = Value::Array(vec![integer(2), Value::Bool(true)]);
        fields[23] = integer(1);
        fields[25] = filled(0x99, 32);
        fields[26] = integer(2);
        Ok(())
    })
}

#[test]
fn tme1_vectors_decode_and_encode_byte_for_byte() -> TestResult {
    for (vector, digest, fields) in [
        (TME1_A, TME1_A_DIGEST, vector_a_fields()?),
        (TME1_B, TME1_B_DIGEST, vector_b_fields()?),
        (TME1_C, TME1_C_DIGEST, vector_c_fields()?),
        (TME1_D, TME1_D_DIGEST, vector_d_fields()?),
        (TME1_E, TME1_E_DIGEST, vector_e_fields()?),
        (TME1_F, TME1_F_DIGEST, vector_f_fields()?),
        (TME1_G, TME1_G_DIGEST, vector_g_fields()?),
        (TME1_H, TME1_H_DIGEST, vector_h_fields()?),
    ] {
        let bytes = unhex(vector)?;
        let decoded = TerminationEvidence::from_canonical_cbor(&bytes)?;
        assert_eq!(decoded.fields(), &fields);
        assert_eq!(decoded.digest().to_vec(), unhex(digest)?);
        assert_eq!(decoded.canonical_bytes(), bytes.as_slice());
        assert_eq!(TerminationEvidence::new(&fields)?, decoded);
    }
    let every = TerminationEvidence::from_canonical_cbor(&every_field_present()?)?;
    assert_eq!(TerminationEvidence::new(every.fields())?, every);
    Ok(())
}

#[test]
fn tme1_digests_are_the_sau1_terminal_authority_digests() -> TestResult {
    for (vector, authority) in [
        (TME1_B, SAU1_EVENT_2_AUTHORITY),
        (TME1_C, SAU1_EVENT_1_AUTHORITY),
    ] {
        let termination = TerminationEvidence::from_canonical_cbor(&unhex(vector)?)?;
        let digests = Value::Array(vec![
            filled(0x22, 32),
            filled(0x33, 32),
            Value::Bytes(termination.digest().to_vec()),
        ]);
        assert_eq!(encode(&digests)?, unhex(authority)?);
    }
    Ok(())
}

#[test]
fn tme1_facts_are_the_classification_view() -> TestResult {
    let requested = RequestedConfigurationEvidence::from_canonical_cbor(&unhex(RQE1_A)?)?;
    let observed = KernelObservationEvidence::from_canonical_cbor(&unhex(KOE1_A)?)?;
    let termination = TerminationEvidence::from_canonical_cbor(&every_field_present()?)?;
    let snapshot = |observed_at| CgroupSnapshot {
        cgroup: CGROUP,
        observed_at,
        counters: ZERO,
    };
    let expected = TerminationFacts {
        progress: AttemptProgressCode::Released,
        launch_failure: None,
        start_job: Some(StartJobResult::Done),
        unit: Some(UnitIdentity {
            invocation_id: [0x77; 16],
            cgroup: CGROUP,
        }),
        baseline: Some(snapshot(BASELINE_AT)),
        terminal: Some(snapshot(TERMINAL_AT)),
        service: Some(ServiceFacts::CLEAN),
        ending: Some(EndingCode::CgroupEmpty),
        barrier_failure: None,
        input_complete: true,
        adapter_input_complete: Some(true),
        output_capture: Some(OutputCaptureFacts {
            ceiling_reached: false,
            complete_frame: true,
        }),
        output_transfer_complete: Some(true),
        local_network_termination: Some(
            pos_reference::sandbox_provider_protocol::LocalNetworkTerminationCode::ProtocolFailure,
        ),
        work_after: Some(WorkStatfsFacts {
            mount: WorkMountFacts {
                mount_id: 302,
                capacity_bytes: 1_048_576,
            },
            available_bytes: 1_044_480,
        }),
        watchdog_deadline: NonZeroU64::new(1_005_000_000_000),
        cancel_source: Some(CancelSource::Revocation),
        cleanup: CleanupResult::Proved,
        requested: RequestedConfigurationStatus::Verified,
        observed: KernelObservationFacts::Observed {
            invocation_id: [0x77; 16],
            cgroup: CGROUP,
            work: Some(WorkMountFacts {
                mount_id: 302,
                capacity_bytes: 1_048_576,
            }),
        },
    };
    assert_eq!(termination.facts(&requested, &observed), expected);

    let unreadable =
        TerminationEvidence::from_canonical_cbor(&with(&unhex(TME1_A)?, &[22], integer(0))?)?;
    assert_eq!(
        unreadable.facts(&requested, &observed).watchdog_deadline,
        None
    );
    let counted = TerminationEvidence::from_canonical_cbor(&with(
        &unhex(TME1_A)?,
        &[10, 2, 0],
        Value::Bytes(b"oom_kill 007\nmax 18446744073709551615\n".to_vec()),
    )?)?;
    let counters = counted
        .facts(&requested, &observed)
        .baseline
        .ok_or("baseline")?
        .counters;
    assert_eq!((counters.oom_kill, counters.memory_max), (7, u64::MAX));
    Ok(())
}

#[test]
fn tme1_rule_1_envelope_size_and_types() -> TestResult {
    checks_envelope(&unhex(TME1_A)?, decode)?;
    rejects_malformed_encodings(&unhex(TME1_A)?, decode);
    bounds_raw_size(64 * 1024, decode);
    for record in [
        unhex(TME1_A)?,
        unhex(TME1_B)?,
        unhex(TME1_C)?,
        unhex(TME1_D)?,
        unhex(TME1_E)?,
        unhex(TME1_F)?,
        unhex(TME1_G)?,
        unhex(TME1_H)?,
        every_field_present()?,
        at_progress(0)?,
        with(&at_progress(1)?, &[7], integer(2))?,
    ] {
        assert_eq!(decode(&record), Ok(()));
        rejects_every_retyped_node(&record, decode)?;
    }
    Ok(())
}

#[test]
fn tme1_rule_2_zero_identities_and_closed_codes() -> TestResult {
    let every = every_field_present()?;
    for (path, value) in [
        (vec![2], filled(0, 16)),
        (vec![3], filled(0, 32)),
        (vec![4], filled(0, 32)),
        (vec![5], filled(0, 32)),
        (vec![25], filled(0, 32)),
        (vec![9, 0], filled(0, 16)),
        (vec![9, 1, 1], integer(0)),
        (vec![21, 1], integer(0)),
        (vec![6], integer(3)),
        (vec![6], integer(256)),
        (vec![7], integer(8)),
        (vec![8], integer(6)),
        (vec![12], integer(3)),
        (vec![13, 0], integer(11)),
        (vec![13, 1], integer(4)),
        (vec![13, 2], integer(256)),
        (vec![14], integer(8)),
        (vec![15], integer(13)),
        (vec![19, 0], integer(5)),
        (vec![23], integer(2)),
        (vec![24, 0], integer(3)),
        (vec![24, 1], integer(2)),
        (vec![26], integer(0)),
        (vec![26], integer(11)),
        (vec![16, 3], integer(134_217_729)),
        (vec![16, 4], integer(134_217_729)),
        (vec![17, 0], integer(134_217_729)),
        (vec![27, 3], integer(134_217_729)),
        (vec![27, 4], integer(134_217_729)),
        (vec![20, 0], integer(0)),
        (vec![20, 0], integer(257)),
        (vec![20, 1], integer(257)),
    ] {
        assert_eq!(
            decode(&with(&every, &path, value)?),
            Err(ProtocolError::FieldOutOfBounds),
            "{path:?}"
        );
    }
    let largest = edit(&every, |fields| {
        fields[16] = transfer([1, 2, 1, 134_217_728, 134_217_728], true);
        set(fields, &[17, 0], integer(134_217_728))?;
        set(fields, &[27, 3], integer(134_217_728))?;
        set(fields, &[27, 4], integer(134_217_728))?;
        fields[20] = Value::Array(vec![integer(256), integer(256)]);
        Ok(())
    })?;
    assert_eq!(decode(&largest), Ok(()));
    Ok(())
}

/// One shape case: the changes to the base record at a progress, and
/// whether R9 §4.6.3 accepts the result.
type ShapeCase = (Vec<(Vec<usize>, Value)>, bool);

fn change(path: &[usize], value: Value) -> (Vec<usize>, Value) {
    (path.to_vec(), value)
}

/// Each case breaks at most one shape rule; `[24, 1]` keeps the empty
/// basis consistent with the unit.
fn check_shapes(progress: u64, cases: Vec<ShapeCase>) -> TestResult {
    for (changes, accepted) in cases {
        let description = format!("progress {progress}: {changes:?}");
        let record = edit(&at_progress(progress)?, |fields| {
            for (path, value) in changes {
                set(fields, &path, value)?;
            }
            Ok(())
        })?;
        let expected = if accepted {
            Ok(())
        } else {
            Err(ProtocolError::InconsistentFields)
        };
        assert_eq!(decode(&record), expected, "{description}");
    }
    Ok(())
}

fn ordered_transfer() -> Value {
    transfer([1, 3, 2, 4, 4], true)
}

#[test]
fn tme1_rule_2_shape_at_progress_0() -> TestResult {
    let baseline = vector_field(10)?;
    check_shapes(
        0,
        vec![
            (vec![], true),
            (vec![change(&[7], integer(0))], true),
            (vec![change(&[7], integer(1))], true),
            (vec![change(&[7], integer(2))], false),
            (vec![change(&[7], integer(3))], true),
            (vec![change(&[7], integer(4))], true),
            (vec![change(&[7], integer(5))], true),
            (vec![change(&[7], integer(6))], true),
            (vec![change(&[7], integer(7))], true),
            (vec![change(&[27], vector_field(27)?)], false),
            (vec![change(&[8], integer(0))], false),
            (
                vec![change(&[9], vector_field(9)?), change(&[24, 1], integer(0))],
                false,
            ),
            (vec![change(&[10], baseline.clone())], false),
            (vec![change(&[11], baseline)], false),
            (vec![change(&[13], vector_field(13)?)], false),
            (vec![change(&[14], integer(0))], false),
            (vec![change(&[15], integer(0))], false),
            (vec![change(&[17], vector_field(17)?)], false),
            (vec![change(&[18], ordered_transfer())], false),
            (
                vec![change(
                    &[19],
                    Value::Array(vec![Value::Null, Value::Bool(false)]),
                )],
                false,
            ),
            (vec![change(&[21], vector_field(21)?)], false),
        ],
    )
}

#[test]
fn tme1_rule_2_shape_at_progress_1() -> TestResult {
    let null = || Value::Null;
    check_shapes(
        1,
        vec![
            (vec![], true),
            (vec![change(&[7], integer(2))], true),
            (vec![change(&[15], null()), change(&[13], null())], true),
            (
                vec![
                    change(&[9], null()),
                    change(&[10], null()),
                    change(&[11], null()),
                    change(&[21], null()),
                    change(&[24, 1], null()),
                ],
                true,
            ),
            (vec![change(&[7], integer(0))], false),
            (vec![change(&[7], integer(1))], false),
            (vec![change(&[7], integer(3))], false),
            (vec![change(&[7], integer(4))], false),
            (vec![change(&[7], integer(5))], false),
            (vec![change(&[7], integer(6))], false),
            (vec![change(&[7], integer(7))], false),
            (vec![change(&[27], vector_field(27)?)], false),
            // A null start job is missing evidence (code 2), not a shape
            // error (owner reading G1, Redmine #443 journal 22723).
            (vec![change(&[8], null())], true),
            (vec![change(&[11], null())], false),
            (vec![change(&[10], null())], false),
            (
                vec![
                    change(&[9], null()),
                    change(&[21], null()),
                    change(&[24, 1], null()),
                ],
                false,
            ),
            (
                vec![
                    change(&[9], null()),
                    change(&[10], null()),
                    change(&[11], null()),
                    change(&[24, 1], null()),
                ],
                false,
            ),
            (vec![change(&[14], integer(0))], false),
            (vec![change(&[17], vector_field(17)?)], false),
            (vec![change(&[18], ordered_transfer())], false),
        ],
    )
}

#[test]
fn tme1_rule_2_shape_at_progress_2() -> TestResult {
    let null = || Value::Null;
    check_shapes(
        2,
        vec![
            (vec![change(&[13], null())], true),
            // A null feed is missing evidence (code 2), not a shape error.
            (vec![change(&[27], null())], true),
            (vec![change(&[7], integer(0))], false),
            (vec![change(&[7], integer(3))], false),
            (vec![change(&[7], integer(5))], false),
            (vec![change(&[8], null())], true),
            (vec![change(&[8], integer(1))], false),
            (vec![change(&[9], null()), change(&[24, 1], null())], false),
            (vec![change(&[10], null())], false),
            (vec![change(&[11], null())], false),
            (vec![change(&[14], null())], false),
            (vec![change(&[15], integer(0))], false),
            (vec![change(&[17], null())], false),
        ],
    )
}

#[test]
fn tme1_main_exit_status_and_empty_basis_rules() -> TestResult {
    let vector = unhex(TME1_A)?;
    for (result, exit, status, accepted) in [
        (0, 0, 0, true),
        (0, 0, 1, false),
        (5, 2, 0, false),
        (5, 2, 64, true),
        (5, 2, 65, false),
        (6, 3, 1, true),
        (6, 3, 65, false),
        (4, 1, 255, true),
    ] {
        let service = Value::Array(vec![integer(result), integer(exit), integer(status)]);
        let expected = if accepted {
            Ok(())
        } else {
            Err(ProtocolError::InconsistentFields)
        };
        assert_eq!(
            decode(&with(&vector, &[13], service)?),
            expected,
            "service {result} {exit} {status}"
        );
    }
    for (result, basis, accepted) in [
        (0, Value::Null, false),
        (0, integer(1), true),
        (1, integer(0), false),
        (1, Value::Null, true),
        (2, integer(0), false),
        (2, Value::Null, true),
    ] {
        let changed = edit(&vector, |fields| {
            set(fields, &[24, 0], integer(result))?;
            set(fields, &[24, 1], basis)
        })?;
        let expected = if accepted {
            Ok(())
        } else {
            Err(ProtocolError::InconsistentFields)
        };
        assert_eq!(decode(&changed), expected, "cleanup {result}");
    }
    assert_eq!(
        decode(&with(&at_progress(0)?, &[24, 1], integer(0))?),
        Err(ProtocolError::InconsistentFields)
    );
    Ok(())
}

#[test]
fn tme1_rule_9_transfers_and_cleanup_are_ordered() -> TestResult {
    // Without the stdin feed, whose own ordering against `input` is tested
    // separately, so each input transfer is checked alone.
    let vector = with(&unhex(TME1_A)?, &[27], Value::Null)?;
    let (start, deadline, finish) = (999_000_000_000, 1_001_000_000_000, 999_500_000_000);
    for (input, accepted) in [
        (transfer([deadline, deadline, deadline, 5, 5], true), true),
        (
            transfer([deadline + 1, deadline, deadline + 2, 5, 5], false),
            false,
        ),
        (transfer([finish + 1, deadline, finish, 5, 5], true), false),
        (transfer([start, deadline, finish, 5, 4], true), false),
        (transfer([start, deadline, finish, 5, 4], false), true),
        (transfer([start, deadline, deadline + 1, 5, 5], true), false),
        (transfer([start, deadline, deadline + 1, 5, 5], false), true),
        (transfer([start, deadline, finish, 5, 5], false), false),
    ] {
        let expected = if accepted {
            Ok(())
        } else {
            Err(ProtocolError::InconsistentFields)
        };
        assert_eq!(
            decode(&with(&vector, &[16], input.clone())?),
            expected,
            "{input:?}"
        );
    }
    assert_eq!(
        decode(&with(&vector, &[18], transfer([2, 1, 3, 4, 4], false))?),
        Err(ProtocolError::InconsistentFields)
    );
    assert_eq!(
        decode(&with(&vector, &[24, 2], integer(TERMINAL_AT))?),
        Ok(())
    );
    assert_eq!(
        decode(&with(&vector, &[24, 2], integer(TERMINAL_AT - 1))?),
        Err(ProtocolError::InconsistentFields)
    );
    Ok(())
}

/// One source case: the baseline source index, its bytes and the result.
type SourceCase = (usize, Vec<u8>, Result<(), ProtocolError>);

fn check_sources(cases: Vec<SourceCase>) -> TestResult {
    let vector = unhex(TME1_A)?;
    for (source, bytes, expected) in cases {
        let description = format!("source {source}: {:?}", String::from_utf8_lossy(&bytes));
        assert_eq!(
            decode(&with(&vector, &[10, 2, source], Value::Bytes(bytes))?),
            expected,
            "{description}"
        );
    }
    Ok(())
}

#[test]
fn tme1_rule_7_parser_accepts_the_normative_forms() -> TestResult {
    // 17 + 400 * 10 + 76 + 3 = 4096 bytes.
    let mut largest = b"oom_kill 0\nmax 0\n".to_vec();
    for index in 0..400 {
        largest.extend(format!("k{index:06} 0\n").into_bytes());
    }
    largest.extend(b"z".repeat(76));
    largest.extend(b" 0\n");
    assert_eq!(largest.len(), 4096);
    let mut over = largest.clone();
    over.insert(0, b' ');
    check_sources(vec![
        (0, Vec::new(), Err(ProtocolError::FieldOutOfBounds)),
        (0, largest, Ok(())),
        (0, over, Err(ProtocolError::FieldOutOfBounds)),
        (0, b"oom_kill 0\r\nmax 0\r\n".to_vec(), Ok(())),
        (
            0,
            b"\toom_kill\t0 \nmax\x0c0\nk\xc3\xa4y 5\n".to_vec(),
            Ok(()),
        ),
        (0, b"oom_kill\r0\nmax 0\n".to_vec(), Ok(())),
    ])?;
    let vector = unhex(TME1_A)?;
    assert_eq!(
        decode(&with(
            &vector,
            &[11, 2, 3],
            Value::Bytes(b"x 0\n".to_vec())
        )?),
        Err(ProtocolError::InvalidEncoding)
    );
    assert_eq!(
        decode(&with(
            &vector,
            &[10, 2],
            Value::Array(vec![Value::Bytes(MEMORY.to_vec()); 3])
        )?),
        Err(ProtocolError::InvalidEncoding)
    );
    Ok(())
}

#[test]
fn tme1_rule_7_parser_rejects_every_other_form() -> TestResult {
    let invalid = |source: usize, bytes: &[u8]| -> SourceCase {
        (source, bytes.to_vec(), Err(ProtocolError::InvalidEncoding))
    };
    check_sources(vec![
        invalid(0, b"\xff\n"),
        invalid(0, b"oom_kill 0\nmax 0"),
        invalid(0, b"oom_kill 0\n\nmax 0\n"),
        invalid(0, b"oom_kill 0\n \nmax 0\n"),
        invalid(0, b"oom_kill\nmax 0\n"),
        invalid(0, b"oom_kill 0 1\nmax 0\n"),
        invalid(0, b"oom_kill +1\nmax 0\n"),
        invalid(0, b"oom_kill 1a\nmax 0\n"),
        invalid(0, b"oom_kill 18446744073709551616\nmax 0\n"),
        invalid(0, b"oom_kill 0\nmax 0\nmax 1\n"),
        invalid(0, b"max 0\n"),
        invalid(0, b"oom_kill 0\n"),
        invalid(1, b"high 0\n"),
        invalid(1, b"\xff\n"),
        invalid(2, b"other 0\n"),
        invalid(2, b"\xff\n"),
        invalid(3, b"throttled_usec 0\n"),
        invalid(3, b"nr_throttled 0\n"),
        invalid(3, b"\xff\n"),
    ])
}

#[test]
fn tme1_encoder_applies_the_decoder_rules() -> TestResult {
    let mut fields = vector_a_fields()?;
    fields.ending = None;
    assert_eq!(
        TerminationEvidence::new(&fields),
        Err(ProtocolError::InconsistentFields)
    );
    let mut fields = vector_a_fields()?;
    fields.baseline = Some(sources(BASELINE_AT, b"max\n", CPU_BASELINE));
    assert_eq!(
        TerminationEvidence::new(&fields),
        Err(ProtocolError::InvalidEncoding)
    );
    Ok(())
}

const fn expect(accepted: bool) -> Result<(), ProtocolError> {
    if accepted {
        Ok(())
    } else {
        Err(ProtocolError::InconsistentFields)
    }
}

#[test]
fn tme1_r10_rule_9_a_complete_frame_is_framed_and_below_the_ceiling() -> TestResult {
    let capture = |accepted: u64, ceiling: bool, frame: bool| {
        Value::Array(vec![
            integer(accepted),
            Value::Bool(ceiling),
            Value::Bool(frame),
        ])
    };
    let vector = unhex(TME1_A)?;
    for (value, accepted) in [
        // R10 §8.3: `[5, false, true]` is too short to be framed.
        (capture(5, false, true), false),
        (capture(20, false, true), false),
        (capture(21, false, true), true),
        (capture(STREAM_BYTES, true, true), false),
        (capture(STREAM_BYTES, true, false), true),
        (capture(0, false, false), true),
    ] {
        assert_eq!(
            decode(&with(&vector, &[17], value.clone())?),
            expect(accepted),
            "{value:?}"
        );
    }
    // TME1-D with `complete-frame` true.
    assert_eq!(
        decode(&with(&unhex(TME1_D)?, &[17, 2], Value::Bool(true))?),
        Err(ProtocolError::InconsistentFields)
    );
    Ok(())
}

#[test]
fn tme1_r10_rule_9_the_feed_lies_within_the_released_run() -> TestResult {
    let vector = unhex(TME1_A)?;
    let window = |start: u64, finish: u64, expected: u64, complete: bool| {
        transfer([start, FEED_DEADLINE, finish, expected, expected], complete)
    };
    for (value, accepted) in [
        (window(FEED_START, FEED_FINISH, 5, true), true),
        // After the terminal snapshot (R10 §8.3), and at it.
        (window(FEED_START, 1_000_260_000_000, 5, false), false),
        (window(FEED_START, TERMINAL_AT, 5, false), true),
        (window(FEED_START, TERMINAL_AT + 1, 5, false), false),
        // Not the verified input's length.
        (window(FEED_START, FEED_FINISH, 6, true), false),
        (window(FEED_START, FEED_FINISH, 4, true), false),
        // Before the input transfer finished and before the baseline.
        (window(999_400_000_000, FEED_FINISH, 5, true), false),
        (window(BASELINE_AT, FEED_FINISH, 5, true), true),
        (window(BASELINE_AT - 1, FEED_FINISH, 5, true), false),
        // The R9 transfer ordering applies.
        (window(FEED_START, FEED_START - 1, 5, true), false),
        (window(FEED_START, FEED_FINISH, 5, false), false),
        (
            window(FEED_DEADLINE + 1, FEED_DEADLINE + 2, 5, false),
            false,
        ),
    ] {
        assert_eq!(
            decode(&with(&vector, &[27], value.clone())?),
            expect(accepted),
            "{value:?}"
        );
    }
    // The input transfer's finish bounds the feed's start on its own.
    for (finish, accepted) in [(FEED_START, true), (FEED_START + 1, false)] {
        let changed = with(&vector, &[16, 2], integer(finish))?;
        assert_eq!(decode(&changed), expect(accepted), "input finish {finish}");
    }
    // A feed recorded before `ReleaseV1` or without a start is rejected.
    assert_eq!(
        decode(&with(&unhex(TME1_F)?, &[27], vector_field(27)?)?),
        Err(ProtocolError::InconsistentFields)
    );
    Ok(())
}

/// R14 §4.6: launch failures 6 and 7 require progress 0, so TME1-G at
/// progress 1 (a start job, no unit) is refused.
#[test]
fn tme1_r14_launch_failures_6_and_7_require_progress_0() -> TestResult {
    for vector in [TME1_G, TME1_H] {
        let started = edit(&unhex(vector)?, |fields| {
            fields[6] = integer(1);
            fields[8] = integer(0);
            Ok(())
        })?;
        assert_eq!(decode(&started), Err(ProtocolError::InconsistentFields));
    }
    Ok(())
}
