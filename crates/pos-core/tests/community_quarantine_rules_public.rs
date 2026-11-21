//! The quarantine rules `SetReason` needs (ADR-129 annex "Failure-to-quarantine
//! mapping" and "Exact control transition"; revision 8 R8.5), checked against
//! independently encoded preimages.

use ciborium::value::Value;
use pos_core::community_lifecycle::{
    community_decision_provenance_digest_v1, community_quarantine_delta_digest_v1,
    community_quarantine_reason_v1, AtomicCommitFailureV1 as Atomic,
    BundleContentReasonV1 as Content, CommunityDecisionProvenanceInputV1 as Provenance,
    CommunityLifecycleErrorV1 as Error, CommunityPassKeyV1 as Pass,
    CommunityPluginHostErrorV1 as Host, CommunityQuarantineDeltaRowV1 as Row,
    CommunityQuarantineReasonV1 as Reason, ComponentTrapClassV1 as Trap,
    RevocationBasisV1 as Revocation, TrapReproductionV1 as Reproduction,
    TrustDenialBasisV1 as Denial,
};
use pos_core::{Hash, TimelineId};

type Fallible<T> = Result<T, Box<dyn std::error::Error>>;
type TestResult = Fallible<()>;

const fn hash(byte: u8) -> Hash {
    Hash::from_bytes([byte; 32])
}
fn uint(value: u64) -> Value {
    Value::Integer(value.into())
}
fn bytes(value: &[u8]) -> Value {
    Value::Bytes(value.to_vec())
}
fn encode(value: &Value) -> Fallible<Vec<u8>> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out)?;
    Ok(out)
}
fn domain_hash(name: &str, preimage: &[u8]) -> Hash {
    let mut input = format!("PiglorOS.Community.{name}.v1").into_bytes();
    input.push(0);
    input.extend_from_slice(preimage);
    Hash::from_bytes(*blake3::hash(&input).as_bytes())
}
fn pass() -> Result<Pass, Error> {
    Pass::new(
        TimelineId::from_ulid(ulid::Ulid::from_bytes([1; 16])),
        [2; 16],
        3,
    )
}
fn pass_bytes() -> Fallible<Vec<u8>> {
    encode(&Value::Array(vec![
        bytes(b"CPK1"),
        uint(1),
        bytes(&[1; 16]),
        bytes(&[2; 16]),
        uint(3),
    ]))
}

/// Every host failure, its annex quarantine reason and its independent code.
fn host_cases() -> Vec<(Host, Option<Reason>)> {
    vec![
        (Host::InvalidManifest, None),
        (
            Host::InvalidBundleContent {
                reason: Content::Malformed,
            },
            None,
        ),
        (
            Host::ArtifactTrustDenied {
                basis: Denial::Expired,
            },
            None,
        ),
        (
            Host::ArtifactRevoked {
                basis: Revocation::PublisherKey,
            },
            Some(Reason::Revoked),
        ),
        (
            Host::ArtifactRevoked {
                basis: Revocation::OperatorDenial,
            },
            Some(Reason::Revoked),
        ),
        (Host::IncompatibleAbi, None),
        (Host::MissingFeature { index: 1 }, None),
        (Host::CapabilityDenied { index: 1 }, None),
        (Host::InvalidInvocation, None),
        (Host::InvalidGuestOutput, None),
        (Host::UnsupportedSchema, None),
        (Host::StateMigrationFailed, None),
        (Host::GuestDeclaredFailure, None),
        (
            Host::ComponentTrap {
                class: Trap::Unreachable,
                reproduction: Reproduction::Unverified,
            },
            Some(Reason::Trapped),
        ),
        (Host::WorkerCrashed, Some(Reason::Unavailable)),
        (Host::FuelExhausted, Some(Reason::ResourceExhausted)),
        (Host::MemoryLimitExceeded, Some(Reason::ResourceExhausted)),
        (Host::HostCallLimitExceeded, Some(Reason::ResourceExhausted)),
        (Host::OutputLimitExceeded, Some(Reason::ResourceExhausted)),
        (Host::DeterministicDeadlineExceeded, None),
        (Host::OperationalWatchdogStop, None),
        (
            Host::AtomicCommitFailed {
                failure: Atomic::Operational,
            },
            None,
        ),
    ]
}

/// The annex mapping: 11 Trapped, 13–16 `ResourceExhausted`, 2 Revoked and
/// 12 Unavailable; nothing else quarantines, a watchdog stop included.
#[test]
fn the_annex_mapping_quarantines_exactly_codes_2_11_and_12_to_16() {
    for (host, expected) in host_cases() {
        assert!(
            community_quarantine_reason_v1(host) == expected,
            "{} maps to the wrong reason",
            host.name()
        );
    }
    let codes: Vec<u8> = [
        Reason::Trapped,
        Reason::ResourceExhausted,
        Reason::Revoked,
        Reason::Unavailable,
    ]
    .iter()
    .map(|reason| reason.code())
    .collect();
    assert_eq!(codes, [0, 1, 2, 3]);
}

/// I50: a vector for each R8.5 form, recomputed from an independent
/// preimage: a CFI1 with a pass and CIN1, the pre-execution CFO1 with nulls,
/// and the reset form with a null host failure.
#[test]
fn decision_provenance_reproduces_each_form_independently() -> TestResult {
    let revoked = Host::ArtifactRevoked {
        basis: Revocation::Artifact,
    };
    let trap = Host::ComponentTrap {
        class: Trap::StackExhausted,
        reproduction: Reproduction::ReproducedByConformance,
    };
    let forms = [
        (
            Provenance {
                pass_key: Some(pass()?),
                member_binding_digest: hash(4),
                prepared_invocation_digest: Some(hash(6)),
                host_failure: Some(trap),
                trust_snapshot_digest: hash(9),
            },
            Value::Array(vec![
                bytes(&pass_bytes()?),
                bytes(&[4; 32]),
                bytes(&[6; 32]),
                Value::Array(vec![uint(11), uint(5), uint(0)]),
                bytes(&[9; 32]),
            ]),
        ),
        (
            Provenance {
                pass_key: None,
                member_binding_digest: hash(4),
                prepared_invocation_digest: None,
                host_failure: Some(revoked),
                trust_snapshot_digest: hash(9),
            },
            Value::Array(vec![
                Value::Null,
                bytes(&[4; 32]),
                Value::Null,
                Value::Array(vec![uint(2), uint(1)]),
                bytes(&[9; 32]),
            ]),
        ),
        (
            Provenance {
                pass_key: None,
                member_binding_digest: hash(4),
                prepared_invocation_digest: None,
                host_failure: None,
                trust_snapshot_digest: hash(9),
            },
            Value::Array(vec![
                Value::Null,
                bytes(&[4; 32]),
                Value::Null,
                Value::Null,
                bytes(&[9; 32]),
            ]),
        ),
        (
            Provenance {
                pass_key: None,
                member_binding_digest: hash(4),
                prepared_invocation_digest: None,
                host_failure: Some(Host::WorkerCrashed),
                trust_snapshot_digest: hash(9),
            },
            Value::Array(vec![
                Value::Null,
                bytes(&[4; 32]),
                Value::Null,
                Value::Array(vec![uint(12)]),
                bytes(&[9; 32]),
            ]),
        ),
    ];
    let mut digests = Vec::new();
    for (input, preimage) in forms {
        let digest = community_decision_provenance_digest_v1(input);
        assert_eq!(
            digest,
            domain_hash("DecisionProvenance", &encode(&preimage)?)
        );
        digests.push(digest);
    }
    digests.sort_unstable();
    digests.dedup();
    assert_eq!(digests.len(), 4);
    Ok(())
}

/// Each component is bound: changing the member or the trust snapshot
/// changes the digest.
#[test]
fn decision_provenance_binds_the_member_and_the_trust_snapshot() {
    let base = Provenance {
        pass_key: None,
        member_binding_digest: hash(4),
        prepared_invocation_digest: None,
        host_failure: Some(Host::WorkerCrashed),
        trust_snapshot_digest: hash(9),
    };
    let digest = community_decision_provenance_digest_v1(base);
    for changed in [
        Provenance {
            member_binding_digest: hash(5),
            ..base
        },
        Provenance {
            trust_snapshot_digest: hash(8),
            ..base
        },
    ] {
        assert_ne!(community_decision_provenance_digest_v1(changed), digest);
    }
}

const fn row(key: u8) -> Row {
    Row {
        quarantine_key_digest: hash(key),
        ledger_digest: hash(key + 1),
        outcome_digest: hash(key + 2),
    }
}

/// The CAB1 quarantine delta recomputes from an independent preimage.
#[test]
fn the_quarantine_delta_reproduces_its_preimage() -> TestResult {
    let rows = [row(1), row(10)];
    let preimage = Value::Array(
        rows.iter()
            .map(|row| {
                Value::Array(vec![
                    bytes(row.quarantine_key_digest.as_bytes()),
                    bytes(row.ledger_digest.as_bytes()),
                    bytes(row.outcome_digest.as_bytes()),
                ])
            })
            .collect(),
    );
    assert_eq!(
        community_quarantine_delta_digest_v1(&rows)?,
        domain_hash("QuarantineDelta", &encode(&preimage)?)
    );
    let full: Vec<Row> = (1..=64).map(|key| row(key * 3)).collect();
    assert!(community_quarantine_delta_digest_v1(&full).is_ok());
    Ok(())
}

/// No row, 65 rows, a zero digest, unordered rows and a repeated key are
/// refused.
#[test]
fn the_quarantine_delta_refuses_bad_rows() {
    let over: Vec<Row> = (1..=65).map(|key| row(key * 3)).collect();
    assert_eq!(
        community_quarantine_delta_digest_v1(&[]).err(),
        Some(Error::BoundsExceeded)
    );
    assert_eq!(
        community_quarantine_delta_digest_v1(&over).err(),
        Some(Error::BoundsExceeded)
    );
    let zero = |field: usize| {
        let mut bad = row(1);
        match field {
            0 => bad.quarantine_key_digest = Hash::zero(),
            1 => bad.ledger_digest = Hash::zero(),
            _ => bad.outcome_digest = Hash::zero(),
        }
        bad
    };
    for rows in [
        vec![zero(0)],
        vec![zero(1)],
        vec![zero(2)],
        vec![row(10), row(1)],
        vec![
            row(1),
            Row {
                ledger_digest: hash(7),
                ..row(1)
            },
        ],
    ] {
        assert_eq!(
            community_quarantine_delta_digest_v1(&rows).err(),
            Some(Error::InvalidBinding)
        );
    }
}
