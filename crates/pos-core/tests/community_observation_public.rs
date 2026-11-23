//! ADR-129 §4 COV1 and CPE1 (revision 9, R9.2–R9.5 and R9.7) with their
//! digest helpers, at their public seam.
//!
//! Every expected wire is built independently with `ciborium` from the ADR
//! field lists and every digest from the `H(M, bytes)` rule with `blake3`.

use ciborium::value::Value;
use pos_core::community_lifecycle::{
    community_event_source_authority_digest_v1 as authority_digest,
    community_observation_materialization_id_v1 as materialization_id,
    community_recorded_consumer_digest_v1 as consumer_digest,
    community_recorded_consumer_set_digest_v1 as consumer_set_digest,
    community_reducer_configuration_digest_v1 as configuration_digest, ArtifactRefV1,
    CommunityEventSourceRefV1 as SourceRef, CommunityLifecycleErrorV1 as Error,
    CommunityObservationEventRowV1 as Row, CommunityObservationSourceInputV1 as ProofInput,
    CommunityObservationSourceV1 as Proof, CommunityObservationValueInputV1 as ValueInput,
    CommunityObservationValueV1 as ObservationValue, CommunityReducerBindingV1 as Reducer,
    MAX_COMMUNITY_OBSERVATION_BYTES_V1, MAX_COMMUNITY_OBSERVATION_EVENTS_V1,
    MAX_COMMUNITY_OBSERVATION_SOURCE_BYTES_V1, MAX_COMMUNITY_OBSERVATION_VALUE_BYTES_V1,
    MAX_COMMUNITY_RECORDED_CONSUMERS_V1,
};
use pos_core::{Hash, TimelineId};

type Fallible<T> = Result<T, Box<dyn std::error::Error>>;
type TestResult = Fallible<()>;

const fn hash(byte: u8) -> Hash {
    Hash::from_bytes([byte; 32])
}

const fn timeline(byte: u8) -> TimelineId {
    TimelineId::from_ulid(ulid::Ulid::from_bytes([byte; 16]))
}

fn uint(value: u64) -> Value {
    Value::Integer(value.into())
}

fn bytes(value: &[u8]) -> Value {
    Value::Bytes(value.to_vec())
}

fn encode(value: &Value) -> Fallible<Vec<u8>> {
    let mut out = Vec::new();
    ciborium::ser::into_writer(value, &mut out)?;
    Ok(out)
}

fn adr_h(magic: &str, bytes: &[u8]) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(format!("PiglorOS.Community.{magic}.v1\0").as_bytes());
    hasher.update(bytes);
    Hash::from_bytes(*hasher.finalize().as_bytes())
}

fn fields(value: &mut Value) -> Fallible<&mut Vec<Value>> {
    value.as_array_mut().ok_or_else(|| "array".into())
}

const OPERATION: [u8; 16] = [3; 16];
const GENERATION: [u8; 16] = [2; 16];

const fn artifact_ref(length: usize) -> ArtifactRefV1 {
    ArtifactRefV1 {
        schema_id: 0x4f42_0001,
        byte_length: length as u64,
        digest: [9; 32],
    }
}

const fn value_input(payload: &[u8]) -> ValueInput<'_> {
    ValueInput {
        timeline: timeline(1),
        generation: GENERATION,
        operation_id: OPERATION,
        observation_artifact_ref: artifact_ref(payload.len()),
        observation_bytes: payload,
    }
}

fn value_wire(payload: &[u8]) -> Value {
    Value::Array(vec![
        bytes(b"COV1"),
        uint(1),
        bytes(&[1; 16]),
        bytes(&GENERATION),
        bytes(&OPERATION),
        Value::Array(vec![
            uint(0x4f42_0001),
            uint(payload.len() as u64),
            bytes(&[9; 32]),
        ]),
        bytes(payload),
    ])
}

#[test]
fn cov1_has_the_exact_wire_digest_and_payload_bound() -> TestResult {
    let value = ObservationValue::new(value_input(b"observed"))?;
    let wire = encode(&value_wire(b"observed"))?;
    assert_eq!(value.to_canonical_cbor().as_slice(), wire.as_slice());
    assert_eq!(value.digest(), adr_h("COV1", &wire));
    let decoded = ObservationValue::from_canonical_cbor(&wire)?;
    assert!(decoded.as_input() == value.as_input());
    assert_eq!(MAX_COMMUNITY_OBSERVATION_BYTES_V1, 1_048_576);
    assert_eq!(MAX_COMMUNITY_OBSERVATION_VALUE_BYTES_V1, 1_048_704);
    let full = vec![7; MAX_COMMUNITY_OBSERVATION_BYTES_V1];
    let full_wire = ObservationValue::new(value_input(&full))?.to_canonical_cbor();
    assert!(full_wire.len() <= MAX_COMMUNITY_OBSERVATION_VALUE_BYTES_V1);
    assert!(ObservationValue::from_canonical_cbor(&full_wire).is_ok());
    let over = vec![7; MAX_COMMUNITY_OBSERVATION_BYTES_V1 + 1];
    assert_eq!(
        ObservationValue::new(value_input(&over)).err(),
        Some(Error::BoundsExceeded)
    );
    assert_eq!(
        ObservationValue::from_canonical_cbor(&encode(&value_wire(&over))?).err(),
        Some(Error::BoundsExceeded)
    );
    assert_eq!(
        ObservationValue::from_canonical_cbor(&vec![
            0;
            MAX_COMMUNITY_OBSERVATION_VALUE_BYTES_V1 + 1
        ])
        .err(),
        Some(Error::BoundsExceeded)
    );
    let empty = ObservationValue::new(value_input(&[]))?;
    assert_eq!(
        empty.to_canonical_cbor().as_slice(),
        encode(&value_wire(&[]))?.as_slice()
    );
    Ok(())
}

#[test]
fn cov1_requires_its_identities_and_the_exact_reference_length() -> TestResult {
    type Edit = fn(&mut ValueInput<'static>);
    let edits: [Edit; 5] = [
        |input| input.timeline = timeline(0),
        |input| input.generation = [0; 16],
        |input| input.operation_id = [0; 16],
        |input| input.observation_artifact_ref.digest = [0; 32],
        |input| input.observation_artifact_ref.byte_length += 1,
    ];
    for edit in edits {
        let mut input = value_input(b"observed");
        edit(&mut input);
        assert_eq!(
            ObservationValue::new(input).err(),
            Some(Error::InvalidBinding)
        );
    }
    let wire = encode(&value_wire(b"observed"))?;
    let mut trailing = wire;
    trailing.push(0);
    assert_eq!(
        ObservationValue::from_canonical_cbor(&trailing).err(),
        Some(Error::InvalidEncoding)
    );
    let mut versioned = value_wire(b"observed");
    fields(&mut versioned)?[1] = uint(2);
    assert_eq!(
        ObservationValue::from_canonical_cbor(&encode(&versioned)?).err(),
        Some(Error::UnsupportedVersion)
    );
    let mut long = value_wire(b"observed");
    fields(&mut long)?[5] = Value::Array(vec![uint(0x4f42_0001), uint(9), bytes(&[9; 32])]);
    assert_eq!(
        ObservationValue::from_canonical_cbor(&encode(&long)?).err(),
        Some(Error::InvalidBinding)
    );
    Ok(())
}

fn row(seq: u64) -> Row {
    let byte = u8::try_from(seq % 200 + 1).unwrap_or(1);
    Row {
        logical_seq: seq,
        event_id: [byte; 16],
        payload_hash: hash(byte),
        source: SourceRef {
            owner_reference: hash(0xa0),
            artifact_digest: hash(byte),
            registration_address: hash(0xa1),
            source_scope_binding_digest: hash(0xa2),
        },
    }
}

const fn reducer(byte: u8) -> Reducer {
    Reducer {
        consumer_identity_digest: hash(byte),
        schema_digest: hash(0xb1),
        reducer_digest: hash(0xb2),
        configuration_digest: hash(0xb3),
        admission_evidence_digest: hash(0xb4),
        minimization_policy_digest: hash(0xb5),
    }
}

fn proof_input(events: u64, reducers: u8) -> ProofInput {
    ProofInput {
        operation_id: OPERATION,
        timeline: timeline(1),
        generation: GENERATION,
        through_seq: events,
        event_rows: (1..=events).map(row).collect(),
        reducer_policy_bindings: (1..=reducers).map(reducer).collect(),
        observation_value_digest: hash(0xc1),
        scope_union_digest: hash(0xc2),
        authority_request_digest: hash(0xc3),
        evidence_not_after_micros: 1_000,
    }
}

fn row_wire(row: &Row) -> Value {
    Value::Array(vec![
        uint(row.logical_seq),
        bytes(&row.event_id),
        bytes(row.payload_hash.as_bytes()),
        Value::Array(vec![
            uint(2),
            bytes(row.source.owner_reference.as_bytes()),
            uint(0),
            bytes(row.source.artifact_digest.as_bytes()),
            bytes(row.source.registration_address.as_bytes()),
            bytes(row.source.source_scope_binding_digest.as_bytes()),
        ]),
    ])
}

fn proof_wire(input: &ProofInput) -> Fallible<Value> {
    let consumers = encode(&Value::Array(
        input
            .reducer_policy_bindings
            .iter()
            .map(|row| bytes(row.consumer_identity_digest.as_bytes()))
            .collect(),
    ))?;
    Ok(Value::Array(vec![
        bytes(b"CPE1"),
        uint(1),
        bytes(&input.operation_id),
        bytes(&id(input.timeline)),
        bytes(&input.generation),
        bytes(adr_h("RecordedConsumerSet", &consumers).as_bytes()),
        uint(u64::from(input.through_seq != 0)),
        uint(input.through_seq),
        Value::Array(input.event_rows.iter().map(row_wire).collect()),
        Value::Array(
            input
                .reducer_policy_bindings
                .iter()
                .map(|row| {
                    Value::Array(
                        [
                            row.consumer_identity_digest,
                            row.schema_digest,
                            row.reducer_digest,
                            row.configuration_digest,
                            row.admission_evidence_digest,
                            row.minimization_policy_digest,
                        ]
                        .iter()
                        .map(|hash| bytes(hash.as_bytes()))
                        .collect(),
                    )
                })
                .collect(),
        ),
        bytes(input.observation_value_digest.as_bytes()),
        bytes(input.scope_union_digest.as_bytes()),
        bytes(input.authority_request_digest.as_bytes()),
        uint(input.evidence_not_after_micros),
    ]))
}

const fn id(timeline: TimelineId) -> [u8; 16] {
    timeline.inner().to_bytes()
}

fn decode(value: &Value) -> Fallible<Result<Proof, Error>> {
    Ok(Proof::from_canonical_cbor(&encode(value)?))
}

#[test]
fn cpe1_has_the_exact_wire_for_a_prefix_and_for_genesis() -> TestResult {
    for (events, from) in [(3, 1), (0, 0)] {
        let input = proof_input(events, 2);
        let proof = Proof::new(input.clone())?;
        let wire = encode(&proof_wire(&input)?)?;
        assert_eq!(proof.to_canonical_cbor().as_slice(), wire.as_slice());
        assert_eq!(proof.digest(), adr_h("CPE1", &wire));
        assert_eq!(proof.from_seq(), from);
        let decoded = Proof::from_canonical_cbor(&wire)?;
        assert!(decoded.as_input() == proof.as_input());
    }
    Ok(())
}

#[test]
fn cpe1_rows_are_exactly_the_complete_prefix_within_4096() -> TestResult {
    type Edit = fn(&mut ProofInput);
    assert_eq!(MAX_COMMUNITY_OBSERVATION_EVENTS_V1, 4096);
    let full = Proof::new(proof_input(4096, 64))?;
    let wire = full.to_canonical_cbor();
    assert!(wire.len() <= MAX_COMMUNITY_OBSERVATION_SOURCE_BYTES_V1);
    assert!(Proof::from_canonical_cbor(&wire).is_ok());
    assert_eq!(
        Proof::new(proof_input(4097, 1)).err(),
        Some(Error::BoundsExceeded)
    );
    assert_eq!(
        decode(&proof_wire(&proof_input(4097, 1))?)?.err(),
        Some(Error::BoundsExceeded)
    );
    let edits: [Edit; 5] = [
        |input| input.through_seq = 4,
        |input| input.through_seq = 2,
        |input| input.event_rows.swap(0, 1),
        |input| input.event_rows[0].logical_seq = 0,
        |input| input.event_rows.remove(1).logical_seq = 0,
    ];
    for edit in edits {
        let mut input = proof_input(3, 1);
        edit(&mut input);
        assert_eq!(Proof::new(input).err(), Some(Error::InvalidBinding));
    }
    Ok(())
}

#[test]
fn cpe1_reducer_rows_are_one_to_64_strictly_by_consumer() -> TestResult {
    type Zero = fn(&mut Reducer);
    assert_eq!(MAX_COMMUNITY_RECORDED_CONSUMERS_V1, 64);
    assert_eq!(
        Proof::new(proof_input(1, 0)).err(),
        Some(Error::BoundsExceeded)
    );
    assert_eq!(
        Proof::new(proof_input(1, 65)).err(),
        Some(Error::BoundsExceeded)
    );
    assert_eq!(
        decode(&proof_wire(&proof_input(1, 65))?)?.err(),
        Some(Error::BoundsExceeded)
    );
    let mut unsorted = proof_input(1, 2);
    unsorted.reducer_policy_bindings.swap(0, 1);
    let mut repeated = proof_input(1, 2);
    repeated.reducer_policy_bindings[1] = repeated.reducer_policy_bindings[0];
    for input in [unsorted, repeated] {
        assert_eq!(Proof::new(input).err(), Some(Error::InvalidBinding));
    }
    let zeros: [Zero; 6] = [
        |row| row.consumer_identity_digest = Hash::zero(),
        |row| row.schema_digest = Hash::zero(),
        |row| row.reducer_digest = Hash::zero(),
        |row| row.configuration_digest = Hash::zero(),
        |row| row.admission_evidence_digest = Hash::zero(),
        |row| row.minimization_policy_digest = Hash::zero(),
    ];
    for zero in zeros {
        let mut input = proof_input(1, 1);
        zero(&mut input.reducer_policy_bindings[0]);
        assert_eq!(Proof::new(input).err(), Some(Error::InvalidBinding));
    }
    Ok(())
}

#[test]
fn cpe1_identities_are_required_and_derived_fields_are_checked_on_decode() -> TestResult {
    type Edit = fn(&mut ProofInput);
    let edits: [Edit; 11] = [
        |input| input.operation_id = [0; 16],
        |input| input.timeline = timeline(0),
        |input| input.observation_value_digest = Hash::zero(),
        |input| input.scope_union_digest = Hash::zero(),
        |input| input.authority_request_digest = Hash::zero(),
        |input| input.event_rows[0].event_id = [0; 16],
        |input| input.event_rows[0].payload_hash = Hash::zero(),
        |input| input.event_rows[0].source.owner_reference = Hash::zero(),
        |input| input.event_rows[0].source.artifact_digest = Hash::zero(),
        |input| input.event_rows[0].source.registration_address = Hash::zero(),
        |input| input.event_rows[0].source.source_scope_binding_digest = Hash::zero(),
    ];
    for edit in edits {
        let mut input = proof_input(1, 1);
        edit(&mut input);
        assert_eq!(Proof::new(input).err(), Some(Error::InvalidBinding));
    }
    let mut horizon = proof_input(1, 1);
    horizon.evidence_not_after_micros = 0;
    assert_eq!(Proof::new(horizon).err(), Some(Error::BoundsExceeded));
    let input = proof_input(2, 1);
    let edits: [(usize, Value); 4] = [
        (5, bytes(&[0xee; 32])),
        (6, uint(0)),
        (6, uint(2)),
        (
            8,
            Value::Array(vec![
                row_wire(&row(1)),
                Value::Array(vec![uint(1), bytes(&[2; 16]), bytes(&[2; 32]), {
                    let mut genesis = row_wire(&row(2));
                    fields(&mut genesis)?[3] =
                        Value::Array(vec![uint(4), bytes(&[1; 16]), bytes(&[0; 32])]);
                    fields(&mut genesis)?[3].clone()
                }]),
            ]),
        ),
    ];
    for (field, value) in edits {
        let mut changed = proof_wire(&input)?;
        fields(&mut changed)?[field] = value;
        assert_eq!(decode(&changed)?.err(), Some(Error::InvalidBinding));
    }
    // A mode-2 row reference of another class.
    let mut other_class = proof_wire(&input)?;
    let rows = &mut fields(&mut other_class)?[8];
    let first = &mut rows.as_array_mut().ok_or("rows")?[0];
    fields(fields(first)?.get_mut(3).ok_or("ref")?)?[2] = uint(1);
    assert_eq!(decode(&other_class)?.err(), Some(Error::InvalidBinding));
    let wire = encode(&proof_wire(&input)?)?;
    let mut trailing = wire.clone();
    trailing.push(0);
    assert_eq!(
        Proof::from_canonical_cbor(&trailing).err(),
        Some(Error::InvalidEncoding)
    );
    assert_eq!(
        Proof::from_canonical_cbor(&vec![0; MAX_COMMUNITY_OBSERVATION_SOURCE_BYTES_V1 + 1]).err(),
        Some(Error::BoundsExceeded)
    );
    for end in 0..wire.len() {
        assert!(Proof::from_canonical_cbor(&wire[..end]).is_err());
    }
    Ok(())
}

#[test]
fn digest_helpers_follow_the_revision_9_formulas() -> TestResult {
    let preimage = encode(&Value::Array(vec![
        Value::Text("plugin.a".into()),
        bytes(&[1; 32]),
    ]))?;
    assert_eq!(
        consumer_digest("plugin.a", hash(1))?,
        adr_h("RecordedConsumer", &preimage)
    );
    assert!(consumer_digest(&"p".repeat(128), hash(1)).is_ok());
    assert_eq!(
        consumer_digest(&"p".repeat(129), hash(1)).err(),
        Some(Error::BoundsExceeded)
    );
    assert_eq!(
        consumer_digest("", hash(1)).err(),
        Some(Error::InvalidBinding)
    );
    assert_eq!(
        consumer_digest("plugin.a", Hash::zero()).err(),
        Some(Error::InvalidBinding)
    );
    let set = encode(&Value::Array(vec![bytes(&[1; 32]), bytes(&[2; 32])]))?;
    assert_eq!(
        consumer_set_digest(&[hash(1), hash(2)]),
        adr_h("RecordedConsumerSet", &set)
    );
    assert_eq!(
        configuration_digest(b"config"),
        adr_h("ReducerConfiguration", &encode(&bytes(b"config"))?)
    );
    let rows = [(timeline(1), hash(5)), (timeline(2), hash(6))];
    let authority = encode(&Value::Array(vec![
        Value::Array(vec![bytes(&[1; 16]), bytes(&[5; 32])]),
        Value::Array(vec![bytes(&[2; 16]), bytes(&[6; 32])]),
    ]))?;
    assert_eq!(
        authority_digest(&rows)?,
        adr_h("EventSourceAuthority", &authority)
    );
    for invalid in [
        vec![],
        vec![(timeline(0), hash(5))],
        vec![(timeline(1), Hash::zero())],
        vec![rows[1], rows[0]],
        vec![rows[0], rows[0]],
    ] {
        assert_eq!(
            authority_digest(&invalid).err(),
            Some(Error::InvalidBinding)
        );
    }
    let preimage = encode(&Value::Array(vec![bytes(&[1; 16]), bytes(&[7; 16])]))?;
    let full = adr_h("ObservationMaterialization", &preimage);
    let mut expected = [0; 16];
    expected.copy_from_slice(&full.as_bytes()[..16]);
    assert_eq!(materialization_id(timeline(1), [7; 16])?, expected);
    assert_eq!(
        materialization_id(timeline(0), [7; 16]).err(),
        Some(Error::InvalidBinding)
    );
    assert_eq!(
        materialization_id(timeline(1), [0; 16]).err(),
        Some(Error::InvalidBinding)
    );
    Ok(())
}
