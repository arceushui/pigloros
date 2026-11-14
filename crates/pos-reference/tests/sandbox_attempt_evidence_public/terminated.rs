//! TME1: the R9 §7.5, §7.6 and §7.6a vectors, the §4.6.2 parser, the
//! §4.6.3 shape table, and R9 §6 rules 1, 2, 7 and 9 within the record.

use std::num::NonZeroU64;

use ciborium::value::Value;
use pos_reference::sandbox_provider_protocol::{
    AdmissionLedger, AttemptProgressCode, CancelSource, CgroupCounters, CgroupEmptyBasis,
    CgroupIdentity, CgroupSnapshot, CgroupSources, CleanupRecord, CleanupResult, Contradiction,
    EndingCode, KernelObservationEvidence, KernelObservationFacts, MainExitCode,
    OutputCaptureFacts, OutputCaptureRecord, RequestedConfigurationEvidence,
    RequestedConfigurationStatus, SandboxProviderProtocolError as ProtocolError, ServiceFacts,
    ServiceResultCode, StartJobResult, TerminalCode, TerminationEvidence,
    TerminationEvidenceFields, TerminationFacts, TransferRecord, UnitIdentity, WorkMountFacts,
    WorkStatfsFacts,
};

use super::oracle::{
    bounds_raw_size, checks_envelope, edit, encode, filled, integer, rejects_every_retyped_node,
    set, unhex, unsigned, with, TestResult,
};
use super::vectors::{
    KOE1_A, KOE1_A_DIGEST, RQE1_A, SAU1_EVENT_1_AUTHORITY, SAU1_EVENT_2_AUTHORITY, TME1_A,
    TME1_A_DIGEST, TME1_B, TME1_B_DIGEST, TME1_C, TME1_C_DIGEST,
};

pub fn decode(bytes: &[u8]) -> Result<(), ProtocolError> {
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

/// The R9 §7.5 fields, written out from the R9 text.
pub fn vector_a_fields() -> TestResult<TerminationEvidenceFields> {
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
            finish: 999_500_000_000,
            expected_bytes: 5,
            accepted_bytes: 5,
            complete: true,
        },
        output_capture: Some(OutputCaptureRecord {
            accepted_bytes: 5,
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
pub fn at_progress(progress: u64) -> TestResult<Vec<u8>> {
    let vector = unhex(TME1_A)?;
    match progress {
        0 => edit(&vector, |fields| {
            fields[6] = integer(0);
            for index in [8, 9, 10, 11, 13, 14, 17, 21] {
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
    bounds_raw_size(64 * 1024, decode);
    for record in [
        unhex(TME1_A)?,
        unhex(TME1_B)?,
        unhex(TME1_C)?,
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
        (vec![7], integer(3)),
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
        fields[20] = Value::Array(vec![integer(256), integer(256)]);
        Ok(())
    })?;
    assert_eq!(decode(&largest), Ok(()));
    Ok(())
}

#[test]
fn tme1_rule_2_shape_follows_progress() -> TestResult {
    let unit = vector_field(9)?;
    let baseline = vector_field(10)?;
    let service = vector_field(13)?;
    let capture = vector_field(17)?;
    let work = vector_field(21)?;
    let ordered = transfer([1, 3, 2, 4, 4], true);
    let network = Value::Array(vec![Value::Null, Value::Bool(false)]);
    let null = Value::Null;
    // Each case breaks exactly one shape rule; `[24, 1]` keeps the empty
    // basis consistent with the unit.
    let cases: Vec<(u64, Vec<(Vec<usize>, Value)>, bool)> = vec![
        (0, vec![], true),
        (0, vec![(vec![7], integer(0))], true),
        (0, vec![(vec![7], integer(1))], true),
        (0, vec![(vec![7], integer(2))], false),
        (0, vec![(vec![8], integer(0))], false),
        (
            0,
            vec![(vec![9], unit.clone()), (vec![24, 1], integer(0))],
            false,
        ),
        (0, vec![(vec![10], baseline.clone())], false),
        (0, vec![(vec![11], baseline.clone())], false),
        (0, vec![(vec![13], service.clone())], false),
        (0, vec![(vec![14], integer(0))], false),
        (0, vec![(vec![15], integer(0))], false),
        (0, vec![(vec![17], capture.clone())], false),
        (0, vec![(vec![18], ordered.clone())], false),
        (0, vec![(vec![19], network.clone())], false),
        (0, vec![(vec![21], work.clone())], false),
        (1, vec![], true),
        (1, vec![(vec![7], integer(2))], true),
        (
            1,
            vec![(vec![15], null.clone()), (vec![13], null.clone())],
            true,
        ),
        (
            1,
            vec![
                (vec![9], null.clone()),
                (vec![10], null.clone()),
                (vec![11], null.clone()),
                (vec![21], null.clone()),
                (vec![24, 1], null.clone()),
            ],
            true,
        ),
        (1, vec![(vec![7], integer(0))], false),
        (1, vec![(vec![7], integer(1))], false),
        (1, vec![(vec![8], null.clone())], false),
        (1, vec![(vec![11], null.clone())], false),
        (1, vec![(vec![10], null.clone())], false),
        (
            1,
            vec![
                (vec![9], null.clone()),
                (vec![21], null.clone()),
                (vec![24, 1], null.clone()),
            ],
            false,
        ),
        (
            1,
            vec![
                (vec![9], null.clone()),
                (vec![10], null.clone()),
                (vec![11], null.clone()),
                (vec![24, 1], null.clone()),
            ],
            false,
        ),
        (1, vec![(vec![14], integer(0))], false),
        (1, vec![(vec![17], capture)], false),
        (1, vec![(vec![18], ordered)], false),
        (2, vec![(vec![13], null.clone())], true),
        (2, vec![(vec![7], integer(0))], false),
        (2, vec![(vec![8], null.clone())], false),
        (2, vec![(vec![8], integer(1))], false),
        (
            2,
            vec![(vec![9], null.clone()), (vec![24, 1], null.clone())],
            false,
        ),
        (2, vec![(vec![10], null.clone())], false),
        (2, vec![(vec![11], null.clone())], false),
        (2, vec![(vec![14], null.clone())], false),
        (2, vec![(vec![15], integer(0))], false),
        (2, vec![(vec![17], null)], false),
    ];
    for (progress, changes, accepted) in cases {
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
    let vector = unhex(TME1_A)?;
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

#[test]
fn tme1_rule_7_sources_follow_the_normative_parser() -> TestResult {
    let vector = unhex(TME1_A)?;
    // 17 + 400 * 10 + 76 + 3 = 4096 bytes.
    let filler = {
        let mut source = b"oom_kill 0\nmax 0\n".to_vec();
        for index in 0..400 {
            source.extend(format!("k{index:06} 0\n").into_bytes());
        }
        source.extend(b"z".repeat(76));
        source.extend(b" 0\n");
        assert_eq!(source.len(), 4096);
        source
    };
    let mut over = filler.clone();
    over.insert(0, b' ');
    let cases: Vec<(usize, Vec<u8>, Result<(), ProtocolError>)> = vec![
        (0, Vec::new(), Err(ProtocolError::FieldOutOfBounds)),
        (0, filler, Ok(())),
        (0, over, Err(ProtocolError::FieldOutOfBounds)),
        (0, b"oom_kill 0\r\nmax 0\r\n".to_vec(), Ok(())),
        (
            0,
            b"\toom_kill\t0 \nmax\x0c0\nk\xc3\xa4y 5\n".to_vec(),
            Ok(()),
        ),
        (0, b"oom_kill\r0\nmax 0\n".to_vec(), Ok(())),
        (0, b"\xff\n".to_vec(), Err(ProtocolError::InvalidEncoding)),
        (
            0,
            b"oom_kill 0\nmax 0".to_vec(),
            Err(ProtocolError::InvalidEncoding),
        ),
        (
            0,
            b"oom_kill 0\n\nmax 0\n".to_vec(),
            Err(ProtocolError::InvalidEncoding),
        ),
        (
            0,
            b"oom_kill 0\n \nmax 0\n".to_vec(),
            Err(ProtocolError::InvalidEncoding),
        ),
        (
            0,
            b"oom_kill\nmax 0\n".to_vec(),
            Err(ProtocolError::InvalidEncoding),
        ),
        (
            0,
            b"oom_kill 0 1\nmax 0\n".to_vec(),
            Err(ProtocolError::InvalidEncoding),
        ),
        (
            0,
            b"oom_kill +1\nmax 0\n".to_vec(),
            Err(ProtocolError::InvalidEncoding),
        ),
        (
            0,
            b"oom_kill 1a\nmax 0\n".to_vec(),
            Err(ProtocolError::InvalidEncoding),
        ),
        (
            0,
            b"oom_kill 18446744073709551616\nmax 0\n".to_vec(),
            Err(ProtocolError::InvalidEncoding),
        ),
        (
            0,
            b"oom_kill 0\nmax 0\nmax 1\n".to_vec(),
            Err(ProtocolError::InvalidEncoding),
        ),
        (0, b"max 0\n".to_vec(), Err(ProtocolError::InvalidEncoding)),
        (
            0,
            b"oom_kill 0\n".to_vec(),
            Err(ProtocolError::InvalidEncoding),
        ),
        (1, b"high 0\n".to_vec(), Err(ProtocolError::InvalidEncoding)),
        (1, b"\xff\n".to_vec(), Err(ProtocolError::InvalidEncoding)),
        (
            2,
            b"other 0\n".to_vec(),
            Err(ProtocolError::InvalidEncoding),
        ),
        (2, b"\xff\n".to_vec(), Err(ProtocolError::InvalidEncoding)),
        (
            3,
            b"throttled_usec 0\n".to_vec(),
            Err(ProtocolError::InvalidEncoding),
        ),
        (
            3,
            b"nr_throttled 0\n".to_vec(),
            Err(ProtocolError::InvalidEncoding),
        ),
        (3, b"\xff\n".to_vec(), Err(ProtocolError::InvalidEncoding)),
    ];
    for (source, bytes, expected) in cases {
        let description = format!("source {source}: {:?}", String::from_utf8_lossy(&bytes));
        assert_eq!(
            decode(&with(&vector, &[10, 2, source], Value::Bytes(bytes))?),
            expected,
            "{description}"
        );
    }
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
