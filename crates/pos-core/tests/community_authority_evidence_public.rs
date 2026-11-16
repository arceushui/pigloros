//! ADR-129 revision 6 CAU1 current authority evidence (R6.6, I27) and CAV1
//! current view (R6.7, I28) at their public seam.
//!
//! Every expected wire is built independently with `ciborium` from the ADR
//! field lists, and every digest with `blake3` from the ADR-128
//! `CurrentAuthority` domain (CAU1) or the `H(record)` rule (CAV1).

use ciborium::value::Value;
use pos_core::community_lifecycle::{
    CommunityArtifactOperationV1 as Operation, CommunityAuthorityEvidenceInputV1 as EvidenceInput,
    CommunityAuthorityEvidenceV1 as Evidence, CommunityAuthorityViewRowV1 as AuthorityRow,
    CommunityClockBoundV1 as ClockBound, CommunityClockLatchV1 as ClockLatch,
    CommunityCurrentViewInputV1 as ViewInput, CommunityCurrentViewV1 as View,
    CommunityDecisionRowV1 as Decision, CommunityKeyStateV1 as KeyState,
    CommunityKeyViewRowV1 as KeyRow, CommunityLifecycleErrorV1 as Error,
    CommunityMaterializationReferenceV1 as Materialized, CommunityObjectBindingV1 as Object,
    CommunityPassFrontierV1 as Frontier, CommunityPassKeyV1 as PassKey,
    CommunityScopeStateV1 as ScopeState, CommunityScopeViewRowV1 as ScopeRow,
    CommunityTrustViewRowV1 as TrustRow, MAX_COMMUNITY_DECISION_ROWS_V1,
    MAX_COMMUNITY_OBJECT_BINDINGS_V1, MAX_COMMUNITY_VIEW_AUTHORITY_ROWS_V1,
    MAX_COMMUNITY_VIEW_KEY_ROWS_V1, MAX_COMMUNITY_VIEW_SCOPE_ROWS_V1,
    MAX_COMMUNITY_VIEW_TRUST_ROWS_V1,
};
use pos_core::{ErasureArtifactClassV1 as Class, Hash, KeyRoleV1, TimelineId};

type Fallible<T> = Result<T, Box<dyn std::error::Error>>;
type TestResult = Fallible<()>;

const INCARNATION: [u8; 16] = [7; 16];
const GENERATION: [u8; 16] = [2; 16];
const OPERATION_ID: [u8; 16] = [5; 16];
const HORIZON: u64 = 1_000;
const MAX_HORIZON: u64 = u64::MAX / 2;

const fn hash(byte: u8) -> Hash {
    Hash::from_bytes([byte; 32])
}
const fn timeline(byte: u8) -> TimelineId {
    TimelineId::from_ulid(ulid::Ulid::from_bytes([byte; 16]))
}
fn counted(index: u64) -> Hash {
    let mut bytes = [1; 32];
    bytes[24..].copy_from_slice(&index.to_be_bytes());
    Hash::from_bytes(bytes)
}
fn uint(value: u64) -> Value {
    Value::Integer(value.into())
}
fn bytes(value: &[u8]) -> Value {
    Value::Bytes(value.to_vec())
}
fn text(value: &str) -> Value {
    Value::Text(value.to_owned())
}
fn hash_value(value: Hash) -> Value {
    bytes(value.as_bytes())
}
fn encode(value: &Value) -> Fallible<Vec<u8>> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out)?;
    Ok(out)
}
fn fields(value: &mut Value) -> Fallible<&mut Vec<Value>> {
    Ok(value.as_array_mut().ok_or("fixture array expected")?)
}
fn domain_digest(domain: &str, encoded: &[u8]) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(format!("PiglorOS.Community.{domain}.v1").as_bytes());
    hasher.update(&[0]);
    hasher.update(encoded);
    Hash::from_bytes(*hasher.finalize().as_bytes())
}

/// Non-canonical variants of one valid record: a widened version, an
/// indefinite outer array, a short outer array, a trailing byte and a
/// truncation.
fn noncanonical(valid: &[u8]) -> [Vec<u8>; 5] {
    let mut wide_version = valid.to_vec();
    wide_version.splice(6..7, [0x18, 0x01]);
    let mut indefinite = valid.to_vec();
    indefinite[0] = 0x9f;
    let mut short = valid.to_vec();
    short[0] -= 1;
    let mut trailing = valid.to_vec();
    trailing.push(0);
    let truncated = valid[..valid.len() - 1].to_vec();
    [wide_version, indefinite, short, trailing, truncated]
}

fn operation_value(operation: Operation) -> Fallible<[Value; 2]> {
    Ok(match operation {
        Operation::Pass(key) => [
            uint(0),
            bytes(&encode(&Value::Array(vec![
                bytes(b"CPK1"),
                uint(1),
                bytes(&key.timeline().inner().to_bytes()),
                bytes(&key.generation()),
                uint(key.ordinal()),
            ]))?),
        ],
        Operation::Initialization(id) => [uint(1), bytes(&id)],
        Operation::Control(id) => [uint(2), bytes(&id)],
    })
}

// ---------------------------------------------------------------- CAU1

const fn object(byte: u8) -> Object {
    Object {
        object_address: hash(byte),
        artifact_digest: hash(byte + 1),
        registration_address: hash(byte + 2),
    }
}

const fn decision(byte: u8, head_seq: u64) -> Decision {
    Decision {
        decision_digest: hash(byte),
        request_digest: hash(byte + 1),
        leaf_grant_id: hash(byte + 2),
        authority_timeline: timeline(9),
        head_seq,
        revocation_epoch: 3,
        policy_revision: hash(byte + 3),
    }
}

fn evidence_input() -> EvidenceInput {
    EvidenceInput {
        store_incarnation: INCARNATION,
        timeline: timeline(4),
        generation: GENERATION,
        operation: Operation::Initialization(OPERATION_ID),
        input_identity: hash(10),
        object_bindings: vec![object(20), object(30)],
        inventory_generation: 77,
        current_premise_digest: hash(11),
        // Equal leading fields: the order falls through to the head.
        decision_rows: vec![decision(40, 5), decision(40, 300)],
        recipient_identity_digest: hash(12),
        clock_bound: ClockBound {
            reservation_id: 9,
            reservation_sample_micros: 400,
            decision_bound_micros: 32_000_400,
        },
        evidence_not_after_micros: HORIZON,
    }
}

fn object_value(row: &Object) -> Value {
    Value::Array(vec![
        hash_value(row.object_address),
        hash_value(row.artifact_digest),
        hash_value(row.registration_address),
    ])
}

fn decision_value(row: &Decision) -> Value {
    Value::Array(vec![
        hash_value(row.decision_digest),
        hash_value(row.request_digest),
        hash_value(row.leaf_grant_id),
        bytes(&row.authority_timeline.inner().to_bytes()),
        uint(row.head_seq),
        uint(row.revocation_epoch),
        hash_value(row.policy_revision),
    ])
}

/// The ADR-129 R6.6 field list, in order.
fn evidence_value(input: &EvidenceInput) -> Fallible<Value> {
    let [kind, identity] = operation_value(input.operation)?;
    Ok(Value::Array(vec![
        bytes(b"CAU1"),
        uint(1),
        bytes(&input.store_incarnation),
        bytes(&input.timeline.inner().to_bytes()),
        bytes(&input.generation),
        kind,
        identity,
        hash_value(input.input_identity),
        Value::Array(input.object_bindings.iter().map(object_value).collect()),
        uint(input.inventory_generation),
        hash_value(input.current_premise_digest),
        Value::Array(input.decision_rows.iter().map(decision_value).collect()),
        hash_value(input.recipient_identity_digest),
        Value::Array(vec![
            uint(input.clock_bound.reservation_id),
            uint(input.clock_bound.reservation_sample_micros),
            uint(input.clock_bound.decision_bound_micros),
        ]),
        uint(input.evidence_not_after_micros),
    ]))
}

fn assert_evidence_round_trip(input: EvidenceInput) -> TestResult {
    let expected = encode(&evidence_value(&input)?)?;
    let record = Evidence::new(input)?;
    let encoded = record.to_canonical_cbor();
    assert_eq!(encoded.as_slice(), expected.as_slice());
    assert_eq!(encoded.capacity(), encoded.len());
    assert_eq!(
        record.digest(),
        domain_digest("CurrentAuthority", &expected)
    );
    let decoded = Evidence::from_canonical_cbor(&expected)?;
    assert!(decoded == record);
    assert!(decoded.as_input() == record.as_input());
    Ok(())
}

fn evidence_error(input: EvidenceInput) -> Option<Error> {
    Evidence::new(input).err()
}

/// I27: the exact fifteen fields, `input_identity` at index 7, and the
/// ADR-128 `CurrentAuthority` commitment.
#[test]
fn cau1_has_fifteen_fields_with_input_identity_at_index_7() -> TestResult {
    let input = evidence_input();
    let mut value = evidence_value(&input)?;
    let items = fields(&mut value)?;
    assert_eq!(items.len(), 15);
    assert_eq!(items[7], hash_value(input.input_identity));
    assert_evidence_round_trip(input)?;
    for operation in [
        Operation::Control(OPERATION_ID),
        Operation::Pass(PassKey::new(timeline(4), GENERATION, 1)?),
        Operation::Pass(PassKey::new(timeline(4), GENERATION, u64::MAX)?),
    ] {
        assert_evidence_round_trip(EvidenceInput {
            operation,
            ..evidence_input()
        })?;
    }
    // No object rows; wide unsigned heads everywhere.
    assert_evidence_round_trip(EvidenceInput {
        object_bindings: vec![],
        inventory_generation: u64::MAX,
        decision_rows: vec![Decision {
            revocation_epoch: u64::MAX,
            ..decision(40, u64::MAX)
        }],
        clock_bound: ClockBound {
            reservation_id: u64::MAX,
            reservation_sample_micros: MAX_HORIZON - 1,
            decision_bound_micros: MAX_HORIZON,
        },
        evidence_not_after_micros: MAX_HORIZON,
        ..evidence_input()
    })
}

/// I27: a 14-field CAU1 (the revision 5 layout without `input_identity`)
/// and a 16-field CAU1 are rejected.
#[test]
fn cau1_rejects_other_field_counts_and_noncanonical_framing() -> TestResult {
    let input = evidence_input();
    let mut fourteen = evidence_value(&input)?;
    fields(&mut fourteen)?.remove(7);
    assert_eq!(
        Evidence::from_canonical_cbor(&encode(&fourteen)?).err(),
        Some(Error::InvalidEncoding)
    );
    let mut sixteen = evidence_value(&input)?;
    fields(&mut sixteen)?.push(uint(0));
    assert_eq!(
        Evidence::from_canonical_cbor(&encode(&sixteen)?).err(),
        Some(Error::InvalidEncoding)
    );
    let valid = encode(&evidence_value(&input)?)?;
    for variant in noncanonical(&valid) {
        assert!(Evidence::from_canonical_cbor(&variant).is_err());
    }
    let mut version = evidence_value(&input)?;
    fields(&mut version)?[1] = uint(2);
    assert_eq!(
        Evidence::from_canonical_cbor(&encode(&version)?).err(),
        Some(Error::UnsupportedVersion)
    );
    assert_eq!(
        Evidence::from_canonical_cbor(&vec![0; 1_048_577]).err(),
        Some(Error::BoundsExceeded)
    );
    // Row and clock arities are exact.
    for (index, replacement) in [
        (
            8,
            Value::Array(vec![Value::Array(vec![hash_value(hash(1))])]),
        ),
        (
            11,
            Value::Array(vec![Value::Array(vec![hash_value(hash(1))])]),
        ),
        (13, Value::Array(vec![uint(1), uint(2)])),
    ] {
        let mut value = evidence_value(&input)?;
        fields(&mut value)?[index] = replacement;
        assert_eq!(
            Evidence::from_canonical_cbor(&encode(&value)?).err(),
            Some(Error::InvalidEncoding)
        );
    }
    Ok(())
}

#[test]
fn cau1_row_bounds_hold_at_the_limit_and_refuse_one_over() -> TestResult {
    let objects = (0..MAX_COMMUNITY_OBJECT_BINDINGS_V1 as u64)
        .map(|index| Object {
            object_address: counted(index),
            artifact_digest: hash(1),
            registration_address: hash(1),
        })
        .collect::<Vec<_>>();
    let decisions = (0..MAX_COMMUNITY_DECISION_ROWS_V1 as u64)
        .map(|index| Decision {
            decision_digest: counted(index),
            revocation_epoch: u64::MAX,
            ..decision(1, u64::MAX)
        })
        .collect::<Vec<_>>();
    let full = EvidenceInput {
        object_bindings: objects.clone(),
        decision_rows: decisions.clone(),
        ..evidence_input()
    };
    let encoded = Evidence::new(full.clone())?.to_canonical_cbor();
    assert!(encoded.len() <= 1_048_576);
    assert_evidence_round_trip(full)?;

    let mut more_objects = objects;
    more_objects.push(Object {
        object_address: counted(u64::MAX),
        ..object(1)
    });
    let mut more_decisions = decisions;
    more_decisions.push(Decision {
        decision_digest: counted(u64::MAX),
        ..decision(1, 1)
    });
    for input in [
        EvidenceInput {
            object_bindings: more_objects.clone(),
            ..evidence_input()
        },
        EvidenceInput {
            decision_rows: more_decisions.clone(),
            ..evidence_input()
        },
        EvidenceInput {
            decision_rows: vec![],
            ..evidence_input()
        },
    ] {
        assert_eq!(evidence_error(input.clone()), Some(Error::BoundsExceeded));
        assert_eq!(
            Evidence::from_canonical_cbor(&encode(&evidence_value(&input)?)?).err(),
            Some(Error::BoundsExceeded)
        );
    }
    Ok(())
}

fn evidence_field_cases() -> Fallible<Vec<EvidenceInput>> {
    let base = evidence_input;
    let clock = base().clock_bound;
    Ok(vec![
        EvidenceInput {
            store_incarnation: [0; 16],
            ..base()
        },
        EvidenceInput {
            timeline: timeline(0),
            ..base()
        },
        EvidenceInput {
            generation: [0; 16],
            ..base()
        },
        EvidenceInput {
            operation: Operation::Initialization([0; 16]),
            ..base()
        },
        EvidenceInput {
            operation: Operation::Pass(PassKey::new(timeline(5), GENERATION, 1)?),
            ..base()
        },
        EvidenceInput {
            operation: Operation::Pass(PassKey::new(timeline(4), [3; 16], 1)?),
            ..base()
        },
        EvidenceInput {
            input_identity: Hash::zero(),
            ..base()
        },
        EvidenceInput {
            current_premise_digest: Hash::zero(),
            ..base()
        },
        EvidenceInput {
            recipient_identity_digest: Hash::zero(),
            ..base()
        },
        EvidenceInput {
            clock_bound: ClockBound {
                reservation_id: 0,
                ..clock
            },
            ..base()
        },
        EvidenceInput {
            clock_bound: ClockBound {
                reservation_sample_micros: clock.decision_bound_micros,
                ..clock
            },
            ..base()
        },
        EvidenceInput {
            clock_bound: ClockBound {
                reservation_sample_micros: clock.decision_bound_micros + 1,
                ..clock
            },
            ..base()
        },
        EvidenceInput {
            object_bindings: vec![object(30), object(20)],
            ..base()
        },
        EvidenceInput {
            object_bindings: vec![object(20), object(20)],
            ..base()
        },
        EvidenceInput {
            decision_rows: vec![decision(40, 300), decision(40, 5)],
            ..base()
        },
        EvidenceInput {
            decision_rows: vec![decision(40, 5), decision(40, 5)],
            ..base()
        },
    ])
}

fn evidence_row_cases() -> Vec<EvidenceInput> {
    let base = evidence_input;
    let mut cases = vec![];
    for zeroed in 0..3 {
        let mut row = object(20);
        match zeroed {
            0 => row.object_address = Hash::zero(),
            1 => row.artifact_digest = Hash::zero(),
            _ => row.registration_address = Hash::zero(),
        }
        cases.push(EvidenceInput {
            object_bindings: vec![row],
            ..base()
        });
    }
    for zeroed in 0..5 {
        let mut row = decision(40, 5);
        match zeroed {
            0 => row.decision_digest = Hash::zero(),
            1 => row.request_digest = Hash::zero(),
            2 => row.leaf_grant_id = Hash::zero(),
            3 => row.policy_revision = Hash::zero(),
            _ => row.authority_timeline = timeline(0),
        }
        cases.push(EvidenceInput {
            decision_rows: vec![row],
            ..base()
        });
    }
    cases
}

#[test]
fn cau1_refuses_zero_unordered_and_inconsistent_fields() -> TestResult {
    let base = evidence_input;
    let clock = base().clock_bound;
    let mut cases = evidence_field_cases()?;
    cases.extend(evidence_row_cases());
    for input in cases {
        assert_eq!(evidence_error(input.clone()), Some(Error::InvalidBinding));
        assert_eq!(
            Evidence::from_canonical_cbor(&encode(&evidence_value(&input)?)?).err(),
            Some(Error::InvalidBinding)
        );
    }
    // A sample one microsecond before the bound is valid.
    assert_evidence_round_trip(EvidenceInput {
        clock_bound: ClockBound {
            reservation_sample_micros: clock.decision_bound_micros - 1,
            ..clock
        },
        ..base()
    })?;
    for horizon in [0, MAX_HORIZON + 1] {
        assert_eq!(
            evidence_error(EvidenceInput {
                evidence_not_after_micros: horizon,
                ..base()
            }),
            Some(Error::BoundsExceeded)
        );
    }
    Ok(())
}

// ---------------------------------------------------------------- CAV1

const SCOPE_STATES: [(ScopeState, u64); 4] = [
    (ScopeState::Open, 0),
    (ScopeState::Frozen, 1),
    (ScopeState::Closed, 2),
    (ScopeState::Unavailable, 3),
];
const KEY_STATES: [(KeyState, u64); 4] = [
    (KeyState::Available, 0),
    (KeyState::DestructionPending, 1),
    (KeyState::Tombstoned, 2),
    (KeyState::Unavailable, 3),
];

const fn head_ref() -> Materialized {
    Materialized {
        owner_reference: hash(60),
        artifact_class: Class::TimelineReplay,
        object_address: hash(61),
        artifact_digest: hash(62),
        registration_address: hash(63),
        attestation_address: hash(64),
    }
}

const fn scope_row(scope: u8, owner: u8) -> ScopeRow {
    ScopeRow {
        scope_reference: hash(scope),
        owner_reference: hash(owner),
        topology_generation: 4,
        state: ScopeState::Open,
        lease_digest: hash(70),
        not_after_micros: 900,
    }
}

const fn authority_row(byte: u8, head_seq: u64, revocation_epoch: u64) -> AuthorityRow {
    AuthorityRow {
        authority_timeline: timeline(byte),
        head_seq,
        revocation_epoch,
        registry_digest: hash(80),
        capability_policy_revision: hash(81),
        consent_policy_revision: hash(82),
        binding_digest: hash(83),
    }
}

fn trust_row(scope: &str, plugin_id: &str) -> TrustRow {
    TrustRow {
        scope: scope.to_owned(),
        plugin_id: plugin_id.to_owned(),
        policy_digest: hash(90),
        policy_floor: 3,
        release_floor: 4,
        highest_trusted_utc_second: 1_700_000_000,
        active_manifest_digest: hash(91),
        active_release_digest: hash(92),
    }
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    bytes
        .iter()
        .flat_map(|byte| {
            [
                DIGITS[usize::from(byte >> 4)],
                DIGITS[usize::from(byte & 15)],
            ]
        })
        .map(char::from)
        .collect()
}

/// An ADR-128 owner text: `community:<T32>:<G32>:<purpose>:<kind>:<op>`.
fn owner(purpose: u8, operation: &str) -> String {
    format!(
        "community:{}:{}:{purpose}:{operation}",
        hex(&timeline(4).inner().to_bytes()),
        hex(&GENERATION)
    )
}

const fn key_row(owner: String, epoch: u64) -> KeyRow {
    KeyRow {
        owner,
        role: KeyRoleV1::CommunityArtifactEncryption,
        epoch,
        material_fingerprint: hash(100),
        state: KeyState::Available,
        key_intent_digest: hash(101),
    }
}

fn pass_owner() -> String {
    owner(0, "p:0000000000000001")
}
fn initialization_owner() -> String {
    owner(3, &format!("i:{}", hex(&OPERATION_ID)))
}

fn view_input() -> Fallible<ViewInput> {
    Ok(ViewInput {
        store_incarnation: INCARNATION,
        timeline: timeline(4),
        generation: GENERATION,
        inventory_generation: 77,
        frontier: Frontier::Committed(PassKey::new(timeline(4), GENERATION, 2)?),
        selected_head: Some(head_ref()),
        // Equal scope reference: the order falls through to the owner.
        scope_rows: vec![scope_row(50, 51), scope_row(50, 52)],
        // Equal T and head: the order falls through to the epoch.
        authority_rows: vec![authority_row(9, 7, 1), authority_row(9, 7, 2)],
        // Equal scope: the order falls through to the Plugin ID.
        trust_rows: vec![
            trust_row("community.trust", "plugin.a"),
            trust_row("community.trust", "plugin.b"),
        ],
        // Equal owner and role: the order falls through to the epoch.
        key_rows: vec![
            key_row(pass_owner(), 1),
            key_row(pass_owner(), 2),
            key_row(initialization_owner(), 1),
        ],
        clock_latch: ClockLatch {
            overrun_count: 3,
            latched: false,
        },
    })
}

fn frontier_value(frontier: Frontier) -> Fallible<Value> {
    Ok(match frontier {
        Frontier::Initial => Value::Array(vec![uint(0)]),
        Frontier::Committed(key) => Value::Array(vec![
            uint(1),
            bytes(&encode(&Value::Array(vec![
                bytes(b"CPK1"),
                uint(1),
                bytes(&key.timeline().inner().to_bytes()),
                bytes(&key.generation()),
                uint(key.ordinal()),
            ]))?),
        ]),
    })
}

/// The CMI1 codec owns the full class table; these tests use only the
/// `TimelineReplay` (0) and `ReproManifest` (1) classes.
fn class_code(class: Class) -> u64 {
    u64::from(class == Class::ReproManifest)
}

fn head_value(head: Option<Materialized>) -> Value {
    head.map_or(Value::Null, |head| {
        Value::Array(vec![
            hash_value(head.owner_reference),
            uint(class_code(head.artifact_class)),
            hash_value(head.object_address),
            hash_value(head.artifact_digest),
            hash_value(head.registration_address),
            hash_value(head.attestation_address),
        ])
    })
}

fn state_code<T: PartialEq + Copy>(codes: &[(T, u64)], state: T) -> u64 {
    codes
        .iter()
        .find(|(candidate, _)| *candidate == state)
        .map_or(u64::MAX, |(_, code)| *code)
}

/// The ADR-129 §3 and R6.7 CAV1 field list, in order.
fn view_value(input: &ViewInput) -> Fallible<Value> {
    Ok(Value::Array(vec![
        bytes(b"CAV1"),
        uint(1),
        bytes(&input.store_incarnation),
        bytes(&input.timeline.inner().to_bytes()),
        bytes(&input.generation),
        uint(input.inventory_generation),
        frontier_value(input.frontier)?,
        head_value(input.selected_head),
        Value::Array(
            input
                .scope_rows
                .iter()
                .map(|row| {
                    Value::Array(vec![
                        hash_value(row.scope_reference),
                        hash_value(row.owner_reference),
                        uint(row.topology_generation),
                        uint(state_code(&SCOPE_STATES, row.state)),
                        hash_value(row.lease_digest),
                        uint(row.not_after_micros),
                    ])
                })
                .collect(),
        ),
        Value::Array(
            input
                .authority_rows
                .iter()
                .map(|row| {
                    Value::Array(vec![
                        bytes(&row.authority_timeline.inner().to_bytes()),
                        uint(row.head_seq),
                        uint(row.revocation_epoch),
                        hash_value(row.registry_digest),
                        hash_value(row.capability_policy_revision),
                        hash_value(row.consent_policy_revision),
                        hash_value(row.binding_digest),
                    ])
                })
                .collect(),
        ),
        Value::Array(
            input
                .trust_rows
                .iter()
                .map(|row| {
                    Value::Array(vec![
                        text(&row.scope),
                        text(&row.plugin_id),
                        hash_value(row.policy_digest),
                        uint(row.policy_floor),
                        uint(row.release_floor),
                        uint(row.highest_trusted_utc_second),
                        hash_value(row.active_manifest_digest),
                        hash_value(row.active_release_digest),
                    ])
                })
                .collect(),
        ),
        Value::Array(
            input
                .key_rows
                .iter()
                .map(|row| {
                    Value::Array(vec![
                        text(&row.owner),
                        uint(u64::from(row.role.code())),
                        uint(row.epoch),
                        hash_value(row.material_fingerprint),
                        uint(state_code(&KEY_STATES, row.state)),
                        hash_value(row.key_intent_digest),
                    ])
                })
                .collect(),
        ),
        Value::Array(vec![
            uint(input.clock_latch.overrun_count),
            Value::Bool(input.clock_latch.latched),
        ]),
    ]))
}

fn assert_view_round_trip(input: ViewInput) -> TestResult {
    let expected = encode(&view_value(&input)?)?;
    let record = View::new(input)?;
    let encoded = record.to_canonical_cbor();
    assert_eq!(encoded.as_slice(), expected.as_slice());
    assert_eq!(encoded.capacity(), encoded.len());
    assert_eq!(record.digest(), domain_digest("CAV1", &expected));
    let decoded = View::from_canonical_cbor(&expected)?;
    assert!(decoded == record);
    assert!(decoded.as_input() == record.as_input());
    Ok(())
}

fn view_error(input: ViewInput) -> Option<Error> {
    View::new(input).err()
}

fn wire_error(input: &ViewInput) -> Fallible<Option<Error>> {
    Ok(View::from_canonical_cbor(&encode(&view_value(input)?)?).err())
}

/// I28: thirteen fields, H(CAV1), both frontier forms and every state code.
#[test]
fn cav1_round_trips_both_frontiers_and_every_state() -> TestResult {
    let mut value = view_value(&view_input()?)?;
    assert_eq!(fields(&mut value)?.len(), 13);
    assert_view_round_trip(view_input()?)?;
    // Code-0 initialize with no selected head: a null head and `[0]`.
    assert_view_round_trip(ViewInput {
        frontier: Frontier::Initial,
        selected_head: None,
        ..view_input()?
    })?;
    // An initial head that is selected.
    assert_view_round_trip(ViewInput {
        frontier: Frontier::Initial,
        ..view_input()?
    })?;
    // Fork reads the parent's head and frontier: another T's pass key.
    assert_view_round_trip(ViewInput {
        frontier: Frontier::Committed(PassKey::new(timeline(8), [9; 16], u64::MAX)?),
        ..view_input()?
    })?;
    for (state, _) in SCOPE_STATES {
        assert_view_round_trip(ViewInput {
            scope_rows: vec![ScopeRow {
                state,
                ..scope_row(50, 51)
            }],
            ..view_input()?
        })?;
    }
    for (state, _) in KEY_STATES {
        assert_view_round_trip(ViewInput {
            key_rows: vec![KeyRow {
                state,
                ..key_row(pass_owner(), 1)
            }],
            ..view_input()?
        })?;
    }
    // Every closed key role; empty optional row sets; wide heads; latched.
    for code in 0..8 {
        assert_view_round_trip(ViewInput {
            key_rows: vec![KeyRow {
                role: KeyRoleV1::from_code(code)?,
                ..key_row(pass_owner(), u64::MAX)
            }],
            ..view_input()?
        })?;
    }
    assert_view_round_trip(ViewInput {
        inventory_generation: u64::MAX,
        scope_rows: vec![],
        authority_rows: vec![authority_row(9, u64::MAX, u64::MAX)],
        trust_rows: vec![TrustRow {
            policy_floor: u64::MAX,
            release_floor: u64::MAX,
            highest_trusted_utc_second: u64::MAX,
            ..trust_row("community.trust", "plugin.a")
        }],
        key_rows: vec![],
        clock_latch: ClockLatch {
            overrun_count: u64::MAX,
            latched: true,
        },
        ..view_input()?
    })?;
    assert_view_round_trip(ViewInput {
        scope_rows: vec![ScopeRow {
            topology_generation: u64::MAX,
            not_after_micros: MAX_HORIZON,
            ..scope_row(50, 51)
        }],
        selected_head: Some(Materialized {
            artifact_class: Class::ReproManifest,
            ..head_ref()
        }),
        ..view_input()?
    })
}

/// I28: the head is null only with an initial frontier, and a head ref with
/// a zero digest is rejected.
#[test]
fn cav1_binds_the_null_head_to_the_initial_frontier() -> TestResult {
    let null_committed = ViewInput {
        selected_head: None,
        ..view_input()?
    };
    assert_eq!(
        view_error(null_committed.clone()),
        Some(Error::InvalidBinding)
    );
    assert_eq!(wire_error(&null_committed)?, Some(Error::InvalidBinding));
    for zeroed in 0..5 {
        let mut head = head_ref();
        match zeroed {
            0 => head.owner_reference = Hash::zero(),
            1 => head.object_address = Hash::zero(),
            2 => head.artifact_digest = Hash::zero(),
            3 => head.registration_address = Hash::zero(),
            _ => head.attestation_address = Hash::zero(),
        }
        let input = ViewInput {
            selected_head: Some(head),
            ..view_input()?
        };
        assert_eq!(view_error(input.clone()), Some(Error::InvalidBinding));
        assert_eq!(wire_error(&input)?, Some(Error::InvalidBinding));
    }
    Ok(())
}

/// I28: scope and Plugin texts of 128 bytes are accepted; 0 or 129 bytes
/// are `BoundsExceeded`, and a text outside the grammar is `InvalidBinding`.
#[test]
fn cav1_trust_texts_hold_their_bounds_and_grammar() -> TestResult {
    let longest = format!("a{}", "b".repeat(127));
    assert_view_round_trip(ViewInput {
        trust_rows: vec![trust_row(&longest, &longest)],
        ..view_input()?
    })?;
    let over = format!("a{}", "b".repeat(128));
    for (scope, plugin_id, error) in [
        ("", "plugin.a", Error::BoundsExceeded),
        ("community.trust", "", Error::BoundsExceeded),
        (over.as_str(), "plugin.a", Error::BoundsExceeded),
        ("community.trust", over.as_str(), Error::BoundsExceeded),
        ("Community.trust", "plugin.a", Error::InvalidBinding),
        ("community.trust", "-plugin", Error::InvalidBinding),
    ] {
        let input = ViewInput {
            trust_rows: vec![trust_row(scope, plugin_id)],
            ..view_input()?
        };
        assert_eq!(view_error(input.clone()), Some(error));
        assert_eq!(wire_error(&input)?, Some(error));
    }
    Ok(())
}

/// The key owner follows the ADR-128 grammar exactly.
#[test]
fn cav1_key_owners_follow_the_adr_128_grammar() -> TestResult {
    let t = hex(&timeline(4).inner().to_bytes());
    let g = hex(&GENERATION);
    let operation = hex(&OPERATION_ID);
    for valid in [
        format!("community:{t}:{g}:0:p:ffffffffffffffff"),
        format!("community:{t}:{g}:1:c:{operation}"),
        format!("community:{t}:{g}:2:i:{operation}"),
        format!("community:{t}:{g}:3:i:{operation}"),
    ] {
        assert_view_round_trip(ViewInput {
            key_rows: vec![key_row(valid, 1)],
            ..view_input()?
        })?;
    }
    let zero16 = "0".repeat(16);
    let zero32 = "0".repeat(32);
    for invalid in [
        format!("communitx:{t}:{g}:0:p:0000000000000001"),
        format!("community:{zero32}:{g}:0:p:0000000000000001"),
        format!("community:{t}:{zero32}:0:p:0000000000000001"),
        format!("community:{}:{g}:0:p:0000000000000001", t.to_uppercase()),
        format!("community:{t}:{g}:0:p:000000000000000g"),
        format!("community:{t}:{g}0:0:p:0000000000000001"),
        format!("community:{t}:{g}:4:p:0000000000000001"),
        format!("community:{t}:{g}:0:x:0000000000000001"),
        format!("community:{t}:{g}:0:p:{zero16}"),
        format!("community:{t}:{g}:0:p:{operation}"),
        format!("community:{t}:{g}:0:i:0000000000000001"),
        format!("community:{t}:{g}:0:c:{zero32}"),
        format!("community:{t}:{g}:0:p:0000000000000001:extra"),
        format!("community:{t}:{g}:0:p"),
        format!("community:{t}:{g}:0"),
        format!("community:{t}:{g}"),
        format!("community:{t}"),
        "community".to_owned(),
    ] {
        let input = ViewInput {
            key_rows: vec![key_row(invalid, 1)],
            ..view_input()?
        };
        assert_eq!(view_error(input.clone()), Some(Error::InvalidBinding));
        assert_eq!(wire_error(&input)?, Some(Error::InvalidBinding));
    }
    for (owner, error) in [
        (String::new(), Error::BoundsExceeded),
        ("a".repeat(129), Error::BoundsExceeded),
    ] {
        let input = ViewInput {
            key_rows: vec![key_row(owner, 1)],
            ..view_input()?
        };
        assert_eq!(view_error(input.clone()), Some(error));
        assert_eq!(wire_error(&input)?, Some(error));
    }
    Ok(())
}

#[test]
fn cav1_row_bounds_hold_at_the_limit_and_refuse_one_over() -> TestResult {
    let t = hex(&timeline(4).inner().to_bytes());
    let g = hex(&GENERATION);
    let scopes = (0..MAX_COMMUNITY_VIEW_SCOPE_ROWS_V1 as u64)
        .map(|index| ScopeRow {
            scope_reference: counted(index),
            topology_generation: u64::MAX,
            not_after_micros: MAX_HORIZON,
            ..scope_row(1, 1)
        })
        .collect::<Vec<_>>();
    let authorities = (0..MAX_COMMUNITY_VIEW_AUTHORITY_ROWS_V1 as u64)
        .map(|index| authority_row(9, index, u64::MAX))
        .collect::<Vec<_>>();
    let longest = |index: usize| format!("{index:03}{}", "a".repeat(125));
    let trust = (0..MAX_COMMUNITY_VIEW_TRUST_ROWS_V1)
        .map(|index| TrustRow {
            policy_floor: u64::MAX,
            release_floor: u64::MAX,
            highest_trusted_utc_second: u64::MAX,
            ..trust_row(&longest(index), &longest(index))
        })
        .collect::<Vec<_>>();
    let keys = (0..MAX_COMMUNITY_VIEW_KEY_ROWS_V1 as u64)
        .map(|index| {
            key_row(
                format!("community:{t}:{g}:0:p:{:016x}", index + 1),
                u64::MAX,
            )
        })
        .collect::<Vec<_>>();
    let full = ViewInput {
        inventory_generation: u64::MAX,
        scope_rows: scopes.clone(),
        authority_rows: authorities.clone(),
        trust_rows: trust.clone(),
        key_rows: keys.clone(),
        ..view_input()?
    };
    assert!(View::new(full.clone())?.to_canonical_cbor().len() <= 2_097_152);
    assert_view_round_trip(full)?;

    let mut more_scopes = scopes;
    more_scopes.push(ScopeRow {
        scope_reference: counted(u64::MAX),
        ..scope_row(1, 1)
    });
    let mut more_authorities = authorities;
    more_authorities.push(authority_row(10, 0, 0));
    let mut more_trust = trust;
    more_trust.push(trust_row("zzz", "zzz"));
    let mut more_keys = keys;
    more_keys.push(key_row(
        format!("community:{t}:{g}:1:p:0000000000000001"),
        1,
    ));
    for input in [
        ViewInput {
            scope_rows: more_scopes,
            ..view_input()?
        },
        ViewInput {
            authority_rows: more_authorities,
            ..view_input()?
        },
        ViewInput {
            trust_rows: more_trust,
            ..view_input()?
        },
        ViewInput {
            trust_rows: vec![],
            ..view_input()?
        },
        ViewInput {
            key_rows: more_keys,
            ..view_input()?
        },
    ] {
        assert_eq!(view_error(input.clone()), Some(Error::BoundsExceeded));
        assert_eq!(wire_error(&input)?, Some(Error::BoundsExceeded));
    }
    Ok(())
}

fn view_field_cases() -> Fallible<Vec<ViewInput>> {
    let base = view_input;
    Ok(vec![
        ViewInput {
            store_incarnation: [0; 16],
            ..base()?
        },
        ViewInput {
            timeline: timeline(0),
            ..base()?
        },
        ViewInput {
            generation: [0; 16],
            ..base()?
        },
        ViewInput {
            scope_rows: vec![scope_row(50, 52), scope_row(50, 51)],
            ..base()?
        },
        ViewInput {
            scope_rows: vec![scope_row(50, 51), scope_row(50, 51)],
            ..base()?
        },
        ViewInput {
            authority_rows: vec![authority_row(9, 7, 2), authority_row(9, 7, 1)],
            ..base()?
        },
        ViewInput {
            authority_rows: vec![authority_row(9, 7, 1), authority_row(9, 7, 1)],
            ..base()?
        },
        ViewInput {
            authority_rows: vec![authority_row(0, 7, 1)],
            ..base()?
        },
        ViewInput {
            trust_rows: vec![
                trust_row("community.trust", "plugin.b"),
                trust_row("community.trust", "plugin.a"),
            ],
            ..base()?
        },
        ViewInput {
            trust_rows: vec![
                trust_row("community.trust", "plugin.a"),
                trust_row("community.trust", "plugin.a"),
            ],
            ..base()?
        },
        ViewInput {
            key_rows: vec![key_row(pass_owner(), 2), key_row(pass_owner(), 1)],
            ..base()?
        },
        ViewInput {
            key_rows: vec![key_row(pass_owner(), 1), key_row(pass_owner(), 1)],
            ..base()?
        },
        ViewInput {
            key_rows: vec![key_row(pass_owner(), 0)],
            ..base()?
        },
        ViewInput {
            key_rows: vec![
                KeyRow {
                    role: KeyRoleV1::SubjectDataEncryption,
                    ..key_row(pass_owner(), 1)
                },
                KeyRow {
                    role: KeyRoleV1::SubjectDataEncryption,
                    ..key_row(pass_owner(), 1)
                },
            ],
            ..base()?
        },
    ])
}

fn view_row_cases() -> Fallible<Vec<ViewInput>> {
    let base = view_input;
    let mut cases = vec![
        // Unordered by the leading key, ordered by the trailing one.
        ViewInput {
            scope_rows: vec![scope_row(51, 50), scope_row(50, 51)],
            ..base()?
        },
        ViewInput {
            authority_rows: vec![authority_row(9, 8, 1), authority_row(9, 7, 5)],
            ..base()?
        },
        ViewInput {
            authority_rows: vec![authority_row(9, 7, 1), authority_row(8, 7, 2)],
            ..base()?
        },
        ViewInput {
            trust_rows: vec![
                trust_row("community.trust", "plugin.a"),
                trust_row("community.other", "plugin.z"),
            ],
            ..base()?
        },
    ];
    for zeroed in 0..3 {
        let mut row = scope_row(50, 51);
        match zeroed {
            0 => row.scope_reference = Hash::zero(),
            1 => row.owner_reference = Hash::zero(),
            _ => row.lease_digest = Hash::zero(),
        }
        cases.push(ViewInput {
            scope_rows: vec![row],
            ..base()?
        });
    }
    for zeroed in 0..4 {
        let mut row = authority_row(9, 7, 1);
        match zeroed {
            0 => row.registry_digest = Hash::zero(),
            1 => row.capability_policy_revision = Hash::zero(),
            2 => row.consent_policy_revision = Hash::zero(),
            _ => row.binding_digest = Hash::zero(),
        }
        cases.push(ViewInput {
            authority_rows: vec![row],
            ..base()?
        });
    }
    for zeroed in 0..3 {
        let mut row = trust_row("community.trust", "plugin.a");
        match zeroed {
            0 => row.policy_digest = Hash::zero(),
            1 => row.active_manifest_digest = Hash::zero(),
            _ => row.active_release_digest = Hash::zero(),
        }
        cases.push(ViewInput {
            trust_rows: vec![row],
            ..base()?
        });
    }
    for zeroed in 0..2 {
        let mut row = key_row(pass_owner(), 1);
        if zeroed == 0 {
            row.material_fingerprint = Hash::zero();
        } else {
            row.key_intent_digest = Hash::zero();
        }
        cases.push(ViewInput {
            key_rows: vec![row],
            ..base()?
        });
    }
    Ok(cases)
}

#[test]
fn cav1_refuses_zero_unordered_and_repeated_rows() -> TestResult {
    let base = view_input;
    let mut cases = view_field_cases()?;
    cases.extend(view_row_cases()?);
    for input in cases {
        assert_eq!(view_error(input.clone()), Some(Error::InvalidBinding));
        assert_eq!(wire_error(&input)?, Some(Error::InvalidBinding));
    }
    // Role orders after the owner, before the epoch.
    assert_view_round_trip(ViewInput {
        key_rows: vec![
            KeyRow {
                role: KeyRoleV1::SubjectDataEncryption,
                ..key_row(pass_owner(), 9)
            },
            key_row(pass_owner(), 1),
        ],
        ..base()?
    })?;
    for horizon in [0, MAX_HORIZON + 1] {
        let input = ViewInput {
            scope_rows: vec![ScopeRow {
                not_after_micros: horizon,
                ..scope_row(50, 51)
            }],
            ..base()?
        };
        assert_eq!(view_error(input.clone()), Some(Error::BoundsExceeded));
        assert_eq!(wire_error(&input)?, Some(Error::BoundsExceeded));
    }
    Ok(())
}

#[test]
fn cav1_rejects_unknown_codes_and_noncanonical_framing() -> TestResult {
    let input = view_input()?;
    let valid = encode(&view_value(&input)?)?;
    for variant in noncanonical(&valid) {
        assert!(View::from_canonical_cbor(&variant).is_err());
    }
    let mut version = view_value(&input)?;
    fields(&mut version)?[1] = uint(2);
    assert_eq!(
        View::from_canonical_cbor(&encode(&version)?).err(),
        Some(Error::UnsupportedVersion)
    );
    assert_eq!(
        View::from_canonical_cbor(&vec![0; 2_097_153]).err(),
        Some(Error::BoundsExceeded)
    );
    let mut twelve = view_value(&input)?;
    fields(&mut twelve)?.pop();
    assert_eq!(
        View::from_canonical_cbor(&encode(&twelve)?).err(),
        Some(Error::InvalidEncoding)
    );
    // (field, row, column, replacement): unknown codes and a non-bool latch.
    for (field, row, column, replacement) in [
        (8, Some(0), 3, uint(4)),
        (11, Some(0), 1, uint(8)),
        (11, Some(0), 1, uint(256)),
        (11, Some(0), 4, uint(4)),
        (12, None, 1, uint(1)),
        (6, None, 0, uint(2)),
    ] {
        let mut value = view_value(&input)?;
        let target = &mut fields(&mut value)?[field];
        let target = match row {
            Some(row) => &mut fields(target)?[row],
            None => target,
        };
        fields(target)?[column] = replacement;
        assert_eq!(
            View::from_canonical_cbor(&encode(&value)?).err(),
            Some(Error::InvalidEncoding),
            "field {field} column {column}"
        );
    }
    // Every row array has its exact arity.
    for field in 8..12 {
        let mut value = view_value(&input)?;
        fields(&mut fields(&mut value)?[field])?[0] = Value::Array(vec![uint(0)]);
        assert_eq!(
            View::from_canonical_cbor(&encode(&value)?).err(),
            Some(Error::InvalidEncoding),
            "field {field}"
        );
    }
    // A head ref that is neither null nor a six-field array.
    let mut head = view_value(&input)?;
    fields(&mut head)?[7] = Value::Array(vec![uint(0)]);
    assert_eq!(
        View::from_canonical_cbor(&encode(&head)?).err(),
        Some(Error::InvalidEncoding)
    );
    // A latch that is not a two-field array.
    let mut latch = view_value(&input)?;
    fields(&mut latch)?[12] = Value::Array(vec![uint(0)]);
    assert_eq!(
        View::from_canonical_cbor(&encode(&latch)?).err(),
        Some(Error::InvalidEncoding)
    );
    Ok(())
}
