//! ADR-129 §3/§4 native evidence records at their public seam: CSB1 scope
//! bindings, CPV1 original provenance and CMI1 materialization bindings.
//!
//! Every expected wire is built independently with `ciborium` from the ADR
//! field lists, and every digest with `blake3` from the ADR-128 domain the
//! record uses (`ScopeCover`, `OwnerProvenance`) or the `H(record)` rule.

use ciborium::value::Value;
use pos_core::community_lifecycle::{
    CommunityArtifactOperationV1 as Operation, CommunityFactualNodeReferenceV1 as FactualNode,
    CommunityLifecycleErrorV1 as Error, CommunityMaterializationInputV1 as MaterializationInput,
    CommunityMaterializationReferenceV1 as Materialized,
    CommunityMaterializationV1 as Materialization, CommunityNativeNodeReferenceV1 as NativeRef,
    CommunityOriginalProvenanceInputV1 as ProvenanceInput,
    CommunityOriginalProvenanceV1 as Provenance, CommunityPassKeyV1 as PassKey,
    CommunityProducerBindingV1 as Producer, CommunityScopeBindingInputV1 as BindingInput,
    CommunityScopeBindingV1 as Binding, CommunityScopeCoverageRowV1 as Coverage,
    CommunityScopeCoverageRowsV1 as CoverageRows, CommunityScopeMemberV1 as Member,
    CommunityScopeMembersV1 as Members, CommunityTypedInputRefV1 as TypedRef,
    CommunityTypedInputRefsV1 as TypedRefs, MAX_COMMUNITY_COVERAGE_ROWS_V1,
    MAX_COMMUNITY_EXPANDED_INPUTS_V1, MAX_COMMUNITY_LOGICAL_RECORD_BYTES_V1,
    MAX_COMMUNITY_SCOPE_MEMBERS_V1,
};
use pos_core::{ErasureArtifactClassV1 as Class, Hash, TimelineId};

type Fallible<T> = Result<T, Box<dyn std::error::Error>>;
type TestResult = Fallible<()>;

const INCARNATION: [u8; 16] = [7; 16];
const GENERATION: [u8; 16] = [2; 16];
const OPERATION_ID: [u8; 16] = [5; 16];
const HORIZON: u64 = 1_000;
const MAX_HORIZON: u64 = u64::MAX / 2;
const ONE_MIB: usize = 1_048_576;

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
fn encode(value: &Value) -> Fallible<Vec<u8>> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out)?;
    Ok(out)
}
fn fields(value: &mut Value) -> Fallible<&mut Vec<Value>> {
    match value {
        Value::Array(values) => Ok(values),
        _ => Err("fixture array expected".into()),
    }
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

fn operation_value(operation: Operation) -> [Value; 2] {
    match operation {
        Operation::Pass(key) => [uint(0), bytes(&key.to_canonical_cbor())],
        Operation::Initialization(id) => [uint(1), bytes(&id)],
        Operation::Control(id) => [uint(2), bytes(&id)],
    }
}

// ---------------------------------------------------------------- CSB1

fn members() -> [Member; 2] {
    [1, 2].map(|scope| Member {
        scope_reference: hash(scope),
        source_timeline: timeline(4),
        owner_reference: hash(30),
        retention_lease_reference: hash(31),
        not_after_micros: 900,
    })
}
fn member_value(member: &Member) -> Value {
    Value::Array(vec![
        bytes(member.scope_reference.as_bytes()),
        bytes(&member.source_timeline.inner().to_bytes()),
        bytes(member.owner_reference.as_bytes()),
        bytes(member.retention_lease_reference.as_bytes()),
        uint(member.not_after_micros),
    ])
}
const fn coverage() -> [Coverage; 2] {
    [
        Coverage {
            typed_input_ref_digest: hash(40),
            scope_set_digest: hash(41),
        },
        Coverage {
            typed_input_ref_digest: hash(42),
            scope_set_digest: hash(43),
        },
    ]
}
fn coverage_value(row: &Coverage) -> Value {
    Value::Array(vec![
        bytes(row.typed_input_ref_digest.as_bytes()),
        bytes(row.scope_set_digest.as_bytes()),
    ])
}
const fn binding_input<'a>(rows: &'a [Coverage], scope: &'a [Member]) -> BindingInput<'a> {
    BindingInput {
        store_incarnation: INCARNATION,
        timeline: timeline(1),
        generation: GENERATION,
        operation: Operation::Initialization(OPERATION_ID),
        input_identity: hash(20),
        coverage_rows: CoverageRows::from_rows(rows),
        scope_members: Members::from_members(scope),
        policy_revision: hash(21),
        evidence_not_after_micros: HORIZON,
    }
}
fn binding_value(input: &BindingInput<'_>, rows: &[Coverage], scope: &[Member]) -> Value {
    let [kind, identity] = operation_value(input.operation);
    Value::Array(vec![
        bytes(b"CSB1"),
        uint(1),
        bytes(&input.store_incarnation),
        bytes(&input.timeline.inner().to_bytes()),
        bytes(&input.generation),
        kind,
        identity,
        bytes(input.input_identity.as_bytes()),
        Value::Array(rows.iter().map(coverage_value).collect()),
        Value::Array(scope.iter().map(member_value).collect()),
        Value::Array(vec![text("pos.community.actual-input-scope"), uint(1)]),
        bytes(input.policy_revision.as_bytes()),
        uint(input.evidence_not_after_micros),
    ])
}

#[test]
fn scope_binding_matches_independent_wire_and_scope_cover_digest() -> TestResult {
    let rows = coverage();
    let scope = members();
    let pass = PassKey::new(timeline(1), GENERATION, 9)?;
    for operation in [
        Operation::Initialization(OPERATION_ID),
        Operation::Control([6; 16]),
        Operation::Pass(pass),
    ] {
        let input = BindingInput {
            operation,
            ..binding_input(&rows, &scope)
        };
        let record = Binding::new(input)?;
        let encoded = record.to_canonical_cbor();
        let expected = encode(&binding_value(&input, &rows, &scope))?;
        assert_eq!(encoded.as_slice(), expected.as_slice());
        assert_eq!(record.digest(), domain_digest("ScopeCover", &expected));
        let decoded = Binding::from_canonical_cbor(&encoded)?;
        assert!(decoded.as_input() == record.as_input());
        assert_eq!(decoded.as_input().coverage_rows.len(), 2);
        assert!(!decoded.as_input().coverage_rows.is_empty());
        let decoded_rows: Vec<_> = decoded
            .as_input()
            .coverage_rows
            .iter()
            .collect::<Result<_, _>>()?;
        assert!(decoded_rows == rows);
    }
    Ok(())
}

#[test]
fn scope_binding_admits_empty_rows_and_compares_rows_by_value() -> TestResult {
    let record = Binding::new(binding_input(&[], &[]))?;
    let decoded = Binding::from_canonical_cbor(&record.to_canonical_cbor())?;
    assert!(decoded.as_input().coverage_rows.is_empty());
    assert!(decoded.as_input().scope_members.is_empty());
    let rows = coverage();
    assert!(CoverageRows::from_rows(&rows) == CoverageRows::from_rows(&rows));
    assert!(CoverageRows::from_rows(&rows) != CoverageRows::from_rows(&rows[..1]));
    assert!(CoverageRows::from_rows(&rows[..1]) != CoverageRows::from_rows(&rows[1..]));
    Ok(())
}

#[test]
fn scope_binding_refuses_every_zero_or_foreign_identity() -> TestResult {
    let rows = coverage();
    let scope = members();
    let base = binding_input(&rows, &scope);
    let foreign = PassKey::new(timeline(9), GENERATION, 1)?;
    let cases = [
        BindingInput {
            store_incarnation: [0; 16],
            ..base
        },
        BindingInput {
            timeline: timeline(0),
            ..base
        },
        BindingInput {
            generation: [0; 16],
            ..base
        },
        BindingInput {
            operation: Operation::Initialization([0; 16]),
            ..base
        },
        BindingInput {
            operation: Operation::Control([0; 16]),
            ..base
        },
        BindingInput {
            operation: Operation::Pass(foreign),
            ..base
        },
        BindingInput {
            input_identity: Hash::zero(),
            ..base
        },
        BindingInput {
            policy_revision: Hash::zero(),
            ..base
        },
    ];
    for input in cases {
        assert_eq!(Binding::new(input).map(drop), Err(Error::InvalidBinding));
    }
    let zero_member = [Member {
        owner_reference: Hash::zero(),
        ..scope[0]
    }];
    assert_eq!(
        Binding::new(binding_input(&rows, &zero_member)).map(drop),
        Err(Error::InvalidBinding)
    );
    Ok(())
}

#[test]
fn scope_binding_refuses_zero_duplicate_and_unordered_coverage() {
    let scope = members();
    let [first, second] = coverage();
    let cases: [&[Coverage]; 5] = [
        &[Coverage {
            typed_input_ref_digest: Hash::zero(),
            ..first
        }],
        &[Coverage {
            scope_set_digest: Hash::zero(),
            ..first
        }],
        &[first, first],
        &[
            first,
            Coverage {
                scope_set_digest: hash(50),
                ..first
            },
        ],
        &[second, first],
    ];
    for rows in cases {
        assert_eq!(
            Binding::new(binding_input(rows, &scope)).map(drop),
            Err(Error::InvalidBinding)
        );
    }
    let [one, two] = scope;
    for order in [[two, one], [one, one]] {
        assert_eq!(
            Binding::new(binding_input(&[first], &order)).map(drop),
            Err(Error::InvalidBinding)
        );
    }
}

/// An over-maximum count head is refused before any row is read, so a
/// declared count with no rows behind it is `BoundsExceeded`, not a row error.
#[test]
fn decoders_refuse_an_over_maximum_count_before_reading_rows() -> TestResult {
    let empty = Binding::new(binding_input(&[], &[]))?.to_canonical_cbor();
    let position = empty
        .windows(3)
        .position(|window| window == [0x80, 0x80, 0x82])
        .ok_or("empty row arrays")?;
    let mut rows = empty.to_vec();
    rows.splice(position..=position, [0x19, 0x10, 0x01]);
    let mut members = empty.to_vec();
    members.splice(position + 1..=position + 1, [0x19, 0x08, 0x01]);
    for patched in [rows, members] {
        assert_eq!(
            Binding::from_canonical_cbor(&patched).map(drop),
            Err(Error::BoundsExceeded)
        );
    }
    Ok(())
}

#[test]
fn scope_binding_bounds_its_horizon() -> TestResult {
    let rows = coverage();
    let scope = members();
    for horizon in [0, MAX_HORIZON + 1] {
        let input = BindingInput {
            evidence_not_after_micros: horizon,
            ..binding_input(&rows, &scope)
        };
        assert_eq!(Binding::new(input).map(drop), Err(Error::BoundsExceeded));
    }
    Binding::new(BindingInput {
        evidence_not_after_micros: MAX_HORIZON,
        ..binding_input(&rows, &scope)
    })?;
    Ok(())
}

fn many_coverage(count: u64) -> Vec<Coverage> {
    (1..=count)
        .map(|index| Coverage {
            typed_input_ref_digest: counted(index),
            scope_set_digest: hash(41),
        })
        .collect()
}
fn many_members(count: u64) -> Vec<Member> {
    (1..=count)
        .map(|index| Member {
            scope_reference: counted(index),
            source_timeline: timeline(4),
            owner_reference: hash(30),
            retention_lease_reference: hash(31),
            not_after_micros: MAX_HORIZON,
        })
        .collect()
}

#[test]
fn scope_binding_at_both_maxima_fits_and_one_more_is_refused() -> TestResult {
    let max_rows = MAX_COMMUNITY_COVERAGE_ROWS_V1 as u64;
    let max_members = MAX_COMMUNITY_SCOPE_MEMBERS_V1 as u64;
    let rows = many_coverage(max_rows);
    let scope = many_members(max_members);
    let record = Binding::new(binding_input(&rows, &scope))?;
    let encoded = record.to_canonical_cbor();
    assert!(encoded.len() <= ONE_MIB);
    let decoded = Binding::from_canonical_cbor(&encoded)?;
    assert!(decoded.as_input() == record.as_input());

    let over_rows = many_coverage(max_rows + 1);
    assert_eq!(
        Binding::new(binding_input(&over_rows, &scope)).map(drop),
        Err(Error::BoundsExceeded)
    );
    let over_members = many_members(max_members + 1);
    assert_eq!(
        Binding::new(binding_input(&rows, &over_members)).map(drop),
        Err(Error::BoundsExceeded)
    );

    let mut value = binding_value(&binding_input(&over_rows, &[]), &over_rows, &[]);
    let encoded = encode(&value)?;
    assert_eq!(
        Binding::from_canonical_cbor(&encoded).map(drop),
        Err(Error::BoundsExceeded)
    );
    fields(&mut value)?[8] = Value::Array(Vec::new());
    fields(&mut value)?[9] = Value::Array(over_members.iter().map(member_value).collect());
    assert_eq!(
        Binding::from_canonical_cbor(&encode(&value)?).map(drop),
        Err(Error::BoundsExceeded)
    );
    Ok(())
}

#[test]
fn scope_binding_decoder_refuses_another_rule_and_malformed_fields() -> TestResult {
    let rows = coverage();
    let scope = members();
    let input = binding_input(&rows, &scope);
    let valid = binding_value(&input, &rows, &scope);
    let rules = [
        Value::Array(vec![text("pos.community.actual-input-scopf"), uint(1)]),
        Value::Array(vec![text("pos.community.actual-input-scope"), uint(2)]),
        Value::Array(vec![text("pos.community.actual-input-scope")]),
    ];
    for rule in rules {
        let mut value = valid.clone();
        fields(&mut value)?[10] = rule;
        assert_eq!(
            Binding::from_canonical_cbor(&encode(&value)?).map(drop),
            Err(Error::InvalidBinding)
        );
    }
    let mut bad_row = valid.clone();
    fields(&mut bad_row)?[8] = Value::Array(vec![Value::Array(vec![bytes(&[40; 32])])]);
    let mut bad_operation = valid.clone();
    fields(&mut bad_operation)?[5] = uint(3);
    let mut wide_horizon = valid.clone();
    fields(&mut wide_horizon)?[12] = uint(u64::MAX);
    for value in [bad_row, bad_operation] {
        assert_eq!(
            Binding::from_canonical_cbor(&encode(&value)?).map(drop),
            Err(Error::InvalidEncoding)
        );
    }
    assert_eq!(
        Binding::from_canonical_cbor(&encode(&wide_horizon)?).map(drop),
        Err(Error::BoundsExceeded)
    );
    let mut unordered = valid;
    fields(&mut unordered)?[8] =
        Value::Array(vec![coverage_value(&rows[1]), coverage_value(&rows[0])]);
    assert_eq!(
        Binding::from_canonical_cbor(&encode(&unordered)?).map(drop),
        Err(Error::InvalidBinding)
    );
    assert_eq!(
        Binding::from_canonical_cbor(&vec![0; ONE_MIB + 1]).map(drop),
        Err(Error::BoundsExceeded)
    );
    Ok(())
}

// ---------------------------------------------------------------- CPV1

const fn native(producer: u64, node: u32) -> NativeRef {
    NativeRef {
        store_incarnation: INCARNATION,
        producer_ordinal: producer,
        node_ordinal: node,
        node_digest: hash(11),
    }
}
fn native_value(reference: &NativeRef) -> Value {
    Value::Array(vec![
        uint(0),
        Value::Array(vec![
            bytes(&reference.store_incarnation),
            uint(reference.producer_ordinal),
            uint(u64::from(reference.node_ordinal)),
            bytes(reference.node_digest.as_bytes()),
        ]),
    ])
}
const fn sources() -> [TypedRef<'static>; 2] {
    [
        TypedRef::Native(native(9, 0)),
        TypedRef::Artifact {
            owner_reference: hash(13),
            artifact_class: Class::ReproManifest,
            artifact_digest: hash(14),
            registration_address: hash(15),
            source_scope_binding_digest: hash(16),
        },
    ]
}
fn sources_values() -> Vec<Value> {
    vec![
        native_value(&native(9, 0)),
        Value::Array(vec![
            uint(2),
            bytes(&[13; 32]),
            uint(1),
            bytes(&[14; 32]),
            bytes(&[15; 32]),
            bytes(&[16; 32]),
        ]),
    ]
}
const fn provenance_input<'a>(refs: &'a [TypedRef<'a>]) -> ProvenanceInput<'a> {
    ProvenanceInput {
        store_incarnation: INCARNATION,
        timeline: timeline(1),
        generation: GENERATION,
        operation: Operation::Initialization(OPERATION_ID),
        input_identity: hash(20),
        scope_binding_digest: hash(21),
        source_root_refs: TypedRefs::from_references(refs),
        rule_bundle_digest: hash(22),
        budget_identity: hash(23),
        evidence_not_after_micros: HORIZON,
    }
}
fn provenance_value(input: &ProvenanceInput<'_>, refs: Vec<Value>) -> Value {
    let [kind, identity] = operation_value(input.operation);
    Value::Array(vec![
        bytes(b"CPV1"),
        uint(1),
        bytes(&input.store_incarnation),
        bytes(&input.timeline.inner().to_bytes()),
        bytes(&input.generation),
        kind,
        identity,
        bytes(input.input_identity.as_bytes()),
        bytes(input.scope_binding_digest.as_bytes()),
        Value::Array(refs),
        bytes(input.rule_bundle_digest.as_bytes()),
        bytes(input.budget_identity.as_bytes()),
        uint(input.evidence_not_after_micros),
    ])
}

#[test]
fn provenance_matches_independent_wire_and_owner_provenance_digest() -> TestResult {
    let refs = sources();
    let pass = PassKey::new(timeline(1), GENERATION, 9)?;
    for operation in [
        Operation::Initialization(OPERATION_ID),
        Operation::Control([6; 16]),
        Operation::Pass(pass),
    ] {
        let input = ProvenanceInput {
            operation,
            ..provenance_input(&refs)
        };
        let record = Provenance::new(input)?;
        let encoded = record.to_canonical_cbor();
        let expected = encode(&provenance_value(&input, sources_values()))?;
        assert_eq!(encoded.as_slice(), expected.as_slice());
        assert_eq!(record.digest(), domain_digest("OwnerProvenance", &expected));
        let decoded = Provenance::from_canonical_cbor(&encoded)?;
        assert!(decoded.as_input() == record.as_input());
    }
    let empty = Provenance::new(provenance_input(&[]))?;
    let decoded = Provenance::from_canonical_cbor(&empty.to_canonical_cbor())?;
    assert!(decoded.as_input().source_root_refs.is_empty());
    Ok(())
}

#[test]
fn provenance_refuses_every_zero_foreign_or_unordered_identity() -> TestResult {
    let refs = sources();
    let base = provenance_input(&refs);
    let foreign = PassKey::new(timeline(1), [9; 16], 1)?;
    let cases = [
        ProvenanceInput {
            store_incarnation: [0; 16],
            ..base
        },
        ProvenanceInput {
            timeline: timeline(0),
            ..base
        },
        ProvenanceInput {
            generation: [0; 16],
            ..base
        },
        ProvenanceInput {
            operation: Operation::Control([0; 16]),
            ..base
        },
        ProvenanceInput {
            operation: Operation::Pass(foreign),
            ..base
        },
        ProvenanceInput {
            input_identity: Hash::zero(),
            ..base
        },
        ProvenanceInput {
            scope_binding_digest: Hash::zero(),
            ..base
        },
        ProvenanceInput {
            rule_bundle_digest: Hash::zero(),
            ..base
        },
        ProvenanceInput {
            budget_identity: Hash::zero(),
            ..base
        },
    ];
    for input in cases {
        assert_eq!(Provenance::new(input).map(drop), Err(Error::InvalidBinding));
    }
    let foreign_native = [TypedRef::Native(NativeRef {
        store_incarnation: [8; 16],
        ..native(9, 0)
    })];
    let unordered = [refs[1], refs[0]];
    let duplicate = [refs[0], refs[0]];
    for list in [&foreign_native[..], &unordered, &duplicate] {
        assert_eq!(
            Provenance::new(provenance_input(list)).map(drop),
            Err(Error::InvalidBinding)
        );
    }
    for horizon in [0, MAX_HORIZON + 1] {
        let input = ProvenanceInput {
            evidence_not_after_micros: horizon,
            ..base
        };
        assert_eq!(Provenance::new(input).map(drop), Err(Error::BoundsExceeded));
    }
    Provenance::new(ProvenanceInput {
        evidence_not_after_micros: MAX_HORIZON,
        ..base
    })?;
    Ok(())
}

fn widest_factual_refs(owner: &str, count: u64) -> Vec<TypedRef<'_>> {
    (0..count)
        .map(|index| TypedRef::Factual {
            timeline: timeline(4),
            node: FactualNode {
                tick: u64::MAX - count + index + 1,
                scheduler_position: u32::MAX,
                owner_id: owner,
                output_ordinal: u32::MAX,
                schema_id: u32::MAX,
                artifact_digest: hash(10),
            },
            record_digest: hash(12),
        })
        .collect()
}

#[test]
fn provenance_at_the_source_maximum_fits_and_one_more_is_refused() -> TestResult {
    let max = MAX_COMMUNITY_EXPANDED_INPUTS_V1 as u64;
    let owner = "o".repeat(128);
    let widest = widest_factual_refs(&owner, max);
    let record = Provenance::new(provenance_input(&widest))?;
    let encoded = record.to_canonical_cbor();
    assert!(encoded.len() <= ONE_MIB);
    let decoded = Provenance::from_canonical_cbor(&encoded)?;
    assert!(decoded.as_input() == record.as_input());

    let over: Vec<_> = (1..=max + 1)
        .map(|producer| TypedRef::Native(native(producer, 0)))
        .collect();
    assert_eq!(
        Provenance::new(provenance_input(&over)).map(drop),
        Err(Error::BoundsExceeded)
    );
    let values = (1..=max + 1)
        .map(|producer| native_value(&native(producer, 0)))
        .collect();
    let value = provenance_value(&provenance_input(&[]), values);
    assert_eq!(
        Provenance::from_canonical_cbor(&encode(&value)?).map(drop),
        Err(Error::BoundsExceeded)
    );
    Ok(())
}

#[test]
fn provenance_decoder_refuses_malformed_fields() -> TestResult {
    let refs = sources();
    let valid = provenance_value(&provenance_input(&refs), sources_values());
    let mut bad_ref = valid.clone();
    fields(&mut bad_ref)?[9] = Value::Array(vec![Value::Array(vec![uint(9)])]);
    let mut short_identity = valid.clone();
    fields(&mut short_identity)?[6] = bytes(&[5; 15]);
    for value in [bad_ref, short_identity] {
        assert_eq!(
            Provenance::from_canonical_cbor(&encode(&value)?).map(drop),
            Err(Error::InvalidEncoding)
        );
    }
    let mut foreign = valid;
    fields(&mut foreign)?[2] = bytes(&[8; 16]);
    assert_eq!(
        Provenance::from_canonical_cbor(&encode(&foreign)?).map(drop),
        Err(Error::InvalidBinding)
    );
    assert_eq!(
        Provenance::from_canonical_cbor(&vec![0; ONE_MIB + 1]).map(drop),
        Err(Error::BoundsExceeded)
    );
    Ok(())
}

// ---------------------------------------------------------------- CMI1

const fn materialized(class: Class) -> Materialized {
    Materialized {
        owner_reference: hash(60),
        artifact_class: class,
        object_address: hash(61),
        artifact_digest: hash(62),
        registration_address: hash(63),
        attestation_address: hash(64),
    }
}
const fn materialization_input(magic: [u8; 4], class: Class) -> MaterializationInput {
    MaterializationInput {
        store_incarnation: INCARNATION,
        timeline: timeline(1),
        generation: GENERATION,
        record_magic: magic,
        logical_record_digest: hash(65),
        plaintext_length: 4096,
        materialization: materialized(class),
        producer: Producer::Native(native(9, 1)),
        scope_binding_digest: hash(66),
        evidence_not_after_micros: HORIZON,
    }
}
const fn class_code(class: Class) -> u64 {
    match class {
        Class::TimelineReplay => 0,
        Class::ReproManifest => 1,
        Class::CausalTrace => 2,
        Class::CalibrationReport => 3,
        Class::Export => 4,
        Class::ForkOrSnapshot => 5,
        Class::ConformanceReport => 6,
    }
}
fn materialization_value(input: &MaterializationInput) -> Value {
    let reference = input.materialization;
    let producer = match input.producer {
        Producer::Native(node) => native_value(&node),
        Producer::Control(request) => Value::Array(vec![uint(1), bytes(request.as_bytes())]),
    };
    Value::Array(vec![
        bytes(b"CMI1"),
        uint(1),
        bytes(&input.store_incarnation),
        bytes(&input.timeline.inner().to_bytes()),
        bytes(&input.generation),
        bytes(&input.record_magic),
        bytes(input.logical_record_digest.as_bytes()),
        uint(input.plaintext_length),
        Value::Array(vec![
            bytes(reference.owner_reference.as_bytes()),
            uint(class_code(reference.artifact_class)),
            bytes(reference.object_address.as_bytes()),
            bytes(reference.artifact_digest.as_bytes()),
            bytes(reference.registration_address.as_bytes()),
            bytes(reference.attestation_address.as_bytes()),
        ]),
        producer,
        bytes(input.scope_binding_digest.as_bytes()),
        uint(input.evidence_not_after_micros),
    ])
}

/// The ADR-129 construction annex COW1 families and their ARD1 classes.
const FAMILIES: [(&[u8; 4], Class); 19] = [
    (b"CSC1", Class::TimelineReplay),
    (b"CSR1", Class::TimelineReplay),
    (b"CIN1", Class::TimelineReplay),
    (b"COV1", Class::TimelineReplay),
    (b"CPN1", Class::TimelineReplay),
    (b"CPI1", Class::TimelineReplay),
    (b"CIS1", Class::TimelineReplay),
    (b"CIR1", Class::TimelineReplay),
    (b"CPE1", Class::TimelineReplay),
    (b"CES1", Class::TimelineReplay),
    (b"CIB1", Class::TimelineReplay),
    (b"CED1", Class::TimelineReplay),
    (b"CEB1", Class::TimelineReplay),
    (b"CAT1", Class::CausalTrace),
    (b"GCA1", Class::CausalTrace),
    (b"CIV1", Class::ReproManifest),
    (b"CRR1", Class::ReproManifest),
    (b"CFI1", Class::TimelineReplay),
    (b"CFO1", Class::TimelineReplay),
];
const CLASSES: [Class; 7] = [
    Class::TimelineReplay,
    Class::ReproManifest,
    Class::CausalTrace,
    Class::CalibrationReport,
    Class::Export,
    Class::ForkOrSnapshot,
    Class::ConformanceReport,
];

#[test]
fn materialization_matches_independent_wire_and_record_digest() -> TestResult {
    for producer in [Producer::Native(native(9, 1)), Producer::Control(hash(67))] {
        let input = MaterializationInput {
            producer,
            ..materialization_input(*b"CSC1", Class::TimelineReplay)
        };
        let record = Materialization::new(input)?;
        let encoded = record.to_canonical_cbor();
        let expected = encode(&materialization_value(&input))?;
        assert_eq!(encoded.as_slice(), expected.as_slice());
        assert_eq!(record.digest(), domain_digest("CMI1", &expected));
        let decoded = Materialization::from_canonical_cbor(&encoded)?;
        assert!(decoded.as_input() == record.as_input());
    }
    Ok(())
}

#[test]
fn materialization_admits_exactly_each_family_with_its_class() -> TestResult {
    for (magic, family_class) in FAMILIES {
        for class in CLASSES {
            let result = Materialization::new(materialization_input(*magic, class)).map(drop);
            if class == family_class {
                assert_eq!(result, Ok(()));
                let record = Materialization::new(materialization_input(*magic, class))?;
                Materialization::from_canonical_cbor(&record.to_canonical_cbor())?;
            } else {
                assert_eq!(result, Err(Error::InvalidBinding));
            }
        }
    }
    for magic in [b"CMO1", b"CMF1", b"CNE1", b"CSB1", b"XXXX"] {
        assert_eq!(
            Materialization::new(materialization_input(*magic, Class::TimelineReplay)).map(drop),
            Err(Error::InvalidBinding)
        );
    }
    Ok(())
}

#[test]
fn materialization_bounds_its_length_and_horizon() -> TestResult {
    let base = materialization_input(*b"CSC1", Class::TimelineReplay);
    for length in [1, MAX_COMMUNITY_LOGICAL_RECORD_BYTES_V1] {
        let input = MaterializationInput {
            plaintext_length: length,
            ..base
        };
        let record = Materialization::new(input)?;
        let decoded = Materialization::from_canonical_cbor(&record.to_canonical_cbor())?;
        assert_eq!(decoded.as_input().plaintext_length, length);
    }
    for length in [0, MAX_COMMUNITY_LOGICAL_RECORD_BYTES_V1 + 1] {
        let input = MaterializationInput {
            plaintext_length: length,
            ..base
        };
        assert_eq!(
            Materialization::new(input).map(drop),
            Err(Error::BoundsExceeded)
        );
    }
    assert_eq!(MAX_COMMUNITY_LOGICAL_RECORD_BYTES_V1, 64 * 1024 * 1024);
    for horizon in [0, MAX_HORIZON + 1] {
        let input = MaterializationInput {
            evidence_not_after_micros: horizon,
            ..base
        };
        assert_eq!(
            Materialization::new(input).map(drop),
            Err(Error::BoundsExceeded)
        );
    }
    Materialization::new(MaterializationInput {
        evidence_not_after_micros: MAX_HORIZON,
        ..base
    })?;
    Ok(())
}

#[test]
fn materialization_refuses_every_zero_or_foreign_identity() {
    let base = materialization_input(*b"CSC1", Class::TimelineReplay);
    let reference = base.materialization;
    let references = [
        Materialized {
            owner_reference: Hash::zero(),
            ..reference
        },
        Materialized {
            object_address: Hash::zero(),
            ..reference
        },
        Materialized {
            artifact_digest: Hash::zero(),
            ..reference
        },
        Materialized {
            registration_address: Hash::zero(),
            ..reference
        },
        Materialized {
            attestation_address: Hash::zero(),
            ..reference
        },
    ];
    let producers = [
        Producer::Control(Hash::zero()),
        Producer::Native(NativeRef {
            producer_ordinal: 0,
            ..native(9, 1)
        }),
        Producer::Native(NativeRef {
            node_digest: Hash::zero(),
            ..native(9, 1)
        }),
        Producer::Native(NativeRef {
            store_incarnation: [8; 16],
            ..native(9, 1)
        }),
    ];
    let mut cases = vec![
        MaterializationInput {
            store_incarnation: [0; 16],
            ..base
        },
        MaterializationInput {
            timeline: timeline(0),
            ..base
        },
        MaterializationInput {
            generation: [0; 16],
            ..base
        },
        MaterializationInput {
            logical_record_digest: Hash::zero(),
            ..base
        },
        MaterializationInput {
            scope_binding_digest: Hash::zero(),
            ..base
        },
    ];
    cases.extend(references.map(|materialization| MaterializationInput {
        materialization,
        ..base
    }));
    cases.extend(producers.map(|producer| MaterializationInput { producer, ..base }));
    for input in cases {
        assert_eq!(
            Materialization::new(input).map(drop),
            Err(Error::InvalidBinding)
        );
    }
}

#[test]
fn materialization_decoder_refuses_malformed_fields() -> TestResult {
    let valid = materialization_value(&materialization_input(*b"CSC1", Class::TimelineReplay));
    let mut producer = valid.clone();
    fields(&mut producer)?[9] = Value::Array(vec![uint(2), bytes(&[67; 32])]);
    let mut class = valid.clone();
    if let Value::Array(reference) = &mut fields(&mut class)?[8] {
        reference[1] = uint(7);
    }
    let mut short_reference = valid.clone();
    if let Value::Array(reference) = &mut fields(&mut short_reference)?[8] {
        reference.pop();
    }
    let mut magic = valid.clone();
    fields(&mut magic)?[5] = bytes(b"CSC");
    let mut short_producer = valid.clone();
    fields(&mut short_producer)?[9] = Value::Array(vec![uint(1)]);
    for value in [producer, class, short_reference, magic, short_producer] {
        assert_eq!(
            Materialization::from_canonical_cbor(&encode(&value)?).map(drop),
            Err(Error::InvalidEncoding)
        );
    }
    let mut foreign = valid;
    fields(&mut foreign)?[5] = bytes(b"CMO1");
    assert_eq!(
        Materialization::from_canonical_cbor(&encode(&foreign)?).map(drop),
        Err(Error::InvalidBinding)
    );
    assert_eq!(
        Materialization::from_canonical_cbor(&[0; 1025]).map(drop),
        Err(Error::BoundsExceeded)
    );
    Ok(())
}

// ---------------------------------------------------------------- framing

#[test]
fn every_decoder_refuses_noncanonical_framing() -> TestResult {
    let rows = coverage();
    let scope = members();
    let binding = Binding::new(binding_input(&rows, &scope))?
        .to_canonical_cbor()
        .to_vec();
    let refs = sources();
    let provenance = Provenance::new(provenance_input(&refs))?
        .to_canonical_cbor()
        .to_vec();
    let materialization =
        Materialization::new(materialization_input(*b"CSC1", Class::TimelineReplay))?
            .to_canonical_cbor()
            .to_vec();
    for variant in noncanonical(&binding) {
        assert!(Binding::from_canonical_cbor(&variant).is_err());
    }
    for variant in noncanonical(&provenance) {
        assert!(Provenance::from_canonical_cbor(&variant).is_err());
    }
    for variant in noncanonical(&materialization) {
        assert!(Materialization::from_canonical_cbor(&variant).is_err());
    }
    let mut version = materialization;
    version[6] = 2;
    assert_eq!(
        Materialization::from_canonical_cbor(&version).map(drop),
        Err(Error::UnsupportedVersion)
    );
    Ok(())
}

#[test]
fn every_decoder_refuses_a_widened_inner_integer() -> TestResult {
    let materialization = materialization_input(*b"CSC1", Class::TimelineReplay);
    let encoded = Materialization::new(materialization)?.to_canonical_cbor();
    // plaintext_length 4096 is `19 10 00`; widen it to a four-byte head.
    let needle = [0x19, 0x10, 0x00];
    let position = encoded
        .windows(3)
        .position(|window| window == needle)
        .ok_or("length head")?;
    let mut widened = encoded.to_vec();
    widened.splice(position..position + 3, [0x1a, 0, 0, 0x10, 0x00]);
    assert_eq!(
        Materialization::from_canonical_cbor(&widened).map(drop),
        Err(Error::InvalidEncoding)
    );
    // Both records end with the horizon 1000, `19 03 e8`; widen it.
    let binding = Binding::new(binding_input(&coverage(), &members()))?.to_canonical_cbor();
    assert_eq!(
        Binding::from_canonical_cbor(&widen_final_horizon(&binding)?).map(drop),
        Err(Error::InvalidEncoding)
    );
    let provenance = Provenance::new(provenance_input(&sources()))?.to_canonical_cbor();
    assert_eq!(
        Provenance::from_canonical_cbor(&widen_final_horizon(&provenance)?).map(drop),
        Err(Error::InvalidEncoding)
    );
    Ok(())
}

fn widen_final_horizon(encoded: &[u8]) -> Fallible<Vec<u8>> {
    let split = encoded.len().checked_sub(3).ok_or("short record")?;
    if encoded[split..] != [0x19, 0x03, 0xe8] {
        return Err("horizon head".into());
    }
    let mut widened = encoded[..split].to_vec();
    widened.extend_from_slice(&[0x1a, 0, 0, 0x03, 0xe8]);
    Ok(widened)
}
