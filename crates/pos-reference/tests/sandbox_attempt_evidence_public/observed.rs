//! KOE1: the R9 §7.3 and §7.4 vectors as R14 §4.1 replaces KOE1-A,
//! `observed_state_digest`, and the R9 §6 rules 1, 2 and 4 that the record
//! alone decides. The R14 `network-readback` is in `network_readback`.

use ciborium::value::Value;
use pos_reference::sandbox_provider_protocol::{
    BlockIdentity, CgroupIdentity, DeviceNumber, FdIdentity, KernelObservationEvidence,
    KernelObservationEvidenceFields, KernelObservationStatus, NamespaceIdentity,
    ObservedKernelState, RootMount, SandboxProviderProtocolError as ProtocolError, WorkMountFacts,
};

use super::oracle::{
    bounds_raw_size, checks_envelope, encode, filled, integer, rejects_every_retyped_node,
    rejects_malformed_encodings, unhex, unsigned, with, TestResult,
};
use super::vectors::{
    KOE1_A, KOE1_A_DIGEST, KOE1_B, KOE1_B_DIGEST, RQE1_A_DIGEST, RQE1_B_DIGEST,
    SAU1_EVENT_11_AUTHORITY,
};

pub(super) fn decode(bytes: &[u8]) -> Result<(), ProtocolError> {
    KernelObservationEvidence::from_canonical_cbor(bytes).map(|_| ())
}

pub(super) fn digest(hex: &str) -> TestResult<[u8; 32]> {
    Ok(unhex(hex)?.as_slice().try_into()?)
}

pub(super) const fn namespace(inode: u64) -> NamespaceIdentity {
    NamespaceIdentity {
        major: 0,
        minor: 4,
        inode,
    }
}

/// The R9 §7.3 observation, written out from the R9 text.
pub(super) fn vector_observation() -> ObservedKernelState {
    ObservedKernelState {
        invocation_id: [0x77; 16],
        main_pid: 4242,
        launcher: FdIdentity {
            mount_id: 303,
            inode: 12,
        },
        adapter: FdIdentity {
            mount_id: 301,
            inode: 57,
        },
        root_mount: RootMount {
            mount_id: 301,
            device: DeviceNumber {
                major: 253,
                minor: 3,
            },
        },
        root_mapper: BlockIdentity {
            device: DeviceNumber {
                major: 253,
                minor: 3,
            },
            diskseq: 7,
        },
        root_loop: BlockIdentity {
            device: DeviceNumber { major: 7, minor: 0 },
            diskseq: 6,
        },
        cgroup: CgroupIdentity {
            major: 0,
            minor: 26,
            inode: 5678,
        },
        namespaces: std::array::from_fn(|index| namespace(4_026_532_001 + index as u64)),
        provider_namespaces: provider_namespaces(),
        observed_fdl1_digest: [0x88; 32],
        work: Some(WorkMountFacts {
            mount_id: 302,
            capacity_bytes: 1_048_576,
        }),
        network_readback: None,
    }
}

/// The R9 §7.3 provider namespaces.
pub(super) fn provider_namespaces() -> [NamespaceIdentity; 6] {
    std::array::from_fn(|index| namespace(4_026_531_835 + index as u64))
}

pub(super) fn vector_a_fields() -> TestResult<KernelObservationEvidenceFields> {
    Ok(KernelObservationEvidenceFields {
        attempt_id: [0x11; 16],
        agr1_digest: [0x22; 32],
        status: KernelObservationStatus::Observed {
            ready1_digest: [0x44; 32],
            observation: Box::new(vector_observation()),
        },
        requested_configuration_evidence: digest(RQE1_A_DIGEST)?,
    })
}

#[test]
fn koe1_vectors_decode_and_encode_byte_for_byte() -> TestResult {
    let bytes = unhex(KOE1_A)?;
    let decoded = KernelObservationEvidence::from_canonical_cbor(&bytes)?;
    assert_eq!(decoded.fields(), &vector_a_fields()?);
    assert_eq!(decoded.digest(), digest(KOE1_A_DIGEST)?);
    assert_eq!(decoded.canonical_bytes(), bytes.as_slice());
    assert_eq!(
        KernelObservationEvidence::new(&vector_a_fields()?)?,
        decoded
    );
    assert_eq!(decoded.fields().status.code(), 0);
    assert_eq!(decoded.fields().status.ready1_digest(), Some([0x44; 32]));

    let bytes = unhex(KOE1_B)?;
    let fields = KernelObservationEvidenceFields {
        status: KernelObservationStatus::NotReached,
        requested_configuration_evidence: digest(RQE1_B_DIGEST)?,
        ..vector_a_fields()?
    };
    let decoded = KernelObservationEvidence::from_canonical_cbor(&bytes)?;
    assert_eq!(decoded.fields(), &fields);
    assert_eq!(decoded.digest(), digest(KOE1_B_DIGEST)?);
    assert_eq!(
        KernelObservationEvidence::new(&fields)?.canonical_bytes(),
        bytes.as_slice()
    );
    assert_eq!(decoded.fields().status.code(), 1);
    assert_eq!(decoded.fields().status.ready1_digest(), None);

    let failed = KernelObservationEvidenceFields {
        status: KernelObservationStatus::ObservationFailed {
            ready1_digest: [0x44; 32],
        },
        ..vector_a_fields()?
    };
    let encoded = KernelObservationEvidence::new(&failed)?;
    assert_eq!(encoded.fields(), &failed);
    assert_eq!(encoded.fields().status.code(), 2);
    assert_eq!(encoded.fields().status.ready1_digest(), Some([0x44; 32]));
    let fields = unsigned(encoded.canonical_bytes())?;
    assert_eq!((&fields[4], &fields[7]), (&integer(2), &Value::Null));
    Ok(())
}

#[test]
fn koe1_digest_is_the_sau1_event_11_observed_state_digest() -> TestResult {
    let observed = KernelObservationEvidence::from_canonical_cbor(&unhex(KOE1_A)?)?;
    let authority = Value::Array(vec![
        filled(0x22, 32),
        filled(0x44, 32),
        Value::Bytes(observed.digest().to_vec()),
    ]);
    assert_eq!(encode(&authority)?, unhex(SAU1_EVENT_11_AUTHORITY)?);
    Ok(())
}

#[test]
fn koe1_rule_1_envelope_size_types_and_devices() -> TestResult {
    let vector = unhex(KOE1_A)?;
    checks_envelope(&vector, decode)?;
    rejects_malformed_encodings(&vector, decode);
    bounds_raw_size(64 * 1024, decode);
    rejects_every_retyped_node(&vector, decode)?;
    rejects_every_retyped_node(&unhex(KOE1_B)?, decode)?;
    for (path, value, accepted) in [
        (vec![7, 4, 1, 0], 4095, true),
        (vec![7, 4, 1, 0], 4096, false),
        (vec![7, 7, 0, 1], 1_048_575, true),
        (vec![7, 7, 0, 1], 1_048_576, false),
        (vec![7, 7, 0, 0], u64::from(u32::MAX) + 1, false),
    ] {
        let mut changed = with(&vector, &path, integer(value))?;
        if path[..3] == [7, 4, 1] {
            // The mounted device stays the mapper's.
            changed = with(&changed, &[7, 5, 0, 0], integer(value))?;
        }
        let expected = if accepted {
            Ok(())
        } else {
            Err(ProtocolError::FieldOutOfBounds)
        };
        assert_eq!(decode(&changed), expected, "{path:?} = {value}");
    }
    Ok(())
}

#[test]
fn koe1_rule_2_zero_and_out_of_range_fields() -> TestResult {
    let vector = unhex(KOE1_A)?;
    for (path, value) in [
        (vec![2], filled(0, 16)),
        (vec![3], filled(0, 32)),
        (vec![4], integer(3)),
        (vec![5], filled(0, 32)),
        (vec![6], filled(0, 32)),
        (vec![7, 0], filled(0, 16)),
        (vec![7, 1], integer(0)),
        (vec![7, 1], integer(4_194_305)),
        (vec![7, 2, 1], integer(0)),
        (vec![7, 3, 1], integer(0)),
        (vec![7, 5, 1], integer(0)),
        (vec![7, 6, 1], integer(0)),
        (vec![7, 7, 1], integer(0)),
        (vec![7, 8, 2, 1], integer(0)),
        (vec![7, 10], filled(0, 32)),
        (vec![7, 11, 1], integer(0)),
    ] {
        assert_eq!(
            decode(&with(&vector, &path, value)?),
            Err(ProtocolError::FieldOutOfBounds),
            "{path:?}"
        );
    }
    assert_eq!(decode(&with(&vector, &[7, 1], integer(4_194_304))?), Ok(()));
    assert_eq!(decode(&with(&vector, &[7, 11], Value::Null)?), Ok(()));
    Ok(())
}

#[test]
fn koe1_rule_2_status_decides_the_ready_digest_and_observation() -> TestResult {
    let observed = unhex(KOE1_A)?;
    let observation = unsigned(&observed)?[7].clone();
    let ready = filled(0x44, 32);
    for (status, ready, observation, accepted) in [
        (0, ready.clone(), observation.clone(), true),
        (0, Value::Null, observation.clone(), false),
        (0, ready.clone(), Value::Null, false),
        (1, Value::Null, Value::Null, true),
        (1, ready.clone(), Value::Null, false),
        (1, Value::Null, observation.clone(), false),
        (2, ready.clone(), Value::Null, true),
        (2, Value::Null, Value::Null, false),
        (2, ready, observation, false),
    ] {
        let changed = super::oracle::edit(&observed, |fields| {
            fields[4] = integer(status);
            fields[5] = ready;
            fields[7] = observation;
            Ok(())
        })?;
        let expected = if accepted {
            Ok(())
        } else {
            Err(ProtocolError::InconsistentFields)
        };
        assert_eq!(decode(&changed), expected, "status {status}");
    }
    Ok(())
}

#[test]
fn koe1_rule_4_mount_device_is_the_mapper_and_namespaces_are_isolated() -> TestResult {
    let vector = unhex(KOE1_A)?;
    assert_eq!(
        decode(&with(&vector, &[7, 4, 1, 1], integer(4))?),
        Err(ProtocolError::InconsistentFields)
    );
    let fields = unsigned(&vector)?;
    for index in 0..6 {
        let shared = super::oracle::at(&mut fields.clone(), &[7, 9, index])?.clone();
        let changed = with(&vector, &[7, 8, index], shared)?;
        assert_eq!(
            decode(&changed),
            Err(ProtocolError::InconsistentFields),
            "namespace {index}"
        );
    }
    let mut observation = vector_observation();
    observation.provider_namespaces[3] = observation.namespaces[3];
    let fields = KernelObservationEvidenceFields {
        status: KernelObservationStatus::Observed {
            ready1_digest: [0x44; 32],
            observation: Box::new(observation),
        },
        ..vector_a_fields()?
    };
    assert_eq!(
        KernelObservationEvidence::new(&fields),
        Err(ProtocolError::InconsistentFields)
    );
    Ok(())
}
