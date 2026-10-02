//! Public-seam tests for ADR-105 revision 6 `FAE1`.
//!
//! They cover canonical round trips, closure leaves and root, the primitive
//! code-2 origin digest, every conjunctive bound, the structural rules, and
//! the `IFA1` admission record.

use ciborium::Value;
use pos_core::{
    fork_attribution_authority_origin_digest_v1, fork_attribution_closure_leaf_v1, CanonicalBytes,
    EntityId, EventId, ForkAttributionAuthorityEnvelopeInputV1, ForkAttributionAuthorityEnvelopeV1,
    ForkAttributionAuthorityRecordsV1, ForkAttributionAuthorityUnsignedEnvelopeV1,
    ForkAttributionClassifierRecordsV1, ForkAttributionClosureLeafTypeV1 as Leaf,
    ForkAttributionCodecErrorV1 as CodecError, ForkAttributionIssuerV1, ForkEventEvidenceV1,
    ForkTimelineImportInputV1, ForkTimelineImportV1, Hash, ImportedForkAttributionAdmissionInputV1,
    ImportedForkAttributionAdmissionV1, ImportedKeyRecordV1, ImportedKeyTombstoneV1, KeyIdentityV1,
    KeyRoleV1, Kind, PublicKey, Seq, Signature, TimelineEventEnvelopeInputV1,
    TimelineEventEnvelopeV1, TimelineId, WallTime, MAX_FORK_ADMISSION_RECORD_BYTES_V1,
    MAX_FORK_ATTRIBUTION_AUTHORITY_ENVELOPE_BYTES_V1, MAX_FORK_ATTRIBUTION_AUTHORITY_EVENTS_V1,
    MAX_FORK_ATTRIBUTION_AUTHORITY_INTERVENTIONS_V1,
    MAX_FORK_ATTRIBUTION_AUTHORITY_PAYLOAD_BYTES_V1, MAX_FORK_ATTRIBUTION_ISSUER_BYTES_V1,
    MAX_FORK_PUBLICATION_ARTIFACT_BYTES_V1, MAX_FORK_PUBLICATION_BINDING_BYTES_V1,
    MAX_FORK_PUBLICATION_OPERATION_BYTES_V1, MAX_FORK_TIMELINE_IMPORT_BYTES_V1,
    MAX_IMPORTED_FORK_ATTRIBUTION_ADMISSION_BYTES_V1, MAX_IMPORTED_KEY_RECORD_BYTES_V1,
    MAX_IMPORTED_KEY_TOMBSTONE_BYTES_V1, MAX_IMPORTED_PRINCIPAL_OWNER_BINDING_BYTES_V1,
    MAX_TIMELINE_EVENT_PAYLOAD_BYTES_V1,
};
use ulid::Ulid;

type TestResult = Result<(), Box<dyn std::error::Error>>;
type Fallible<T> = Result<T, Box<dyn std::error::Error>>;

/// Independently computed vectors for [`minimal_input`] signed with
/// `[0x77; 64]` (see the PR description).
const MINIMAL_CLOSURE_ROOT_HEX: &str =
    "b18b387904c86d2c9fdbf1896d81d7508af63d18bf897b02d035dc11a52c95a5";
const MINIMAL_ORIGIN_HEX: &str = "9295d29c42cde209b7cfa35cc7f9370388df6c3dc4e0622b9f9c6cb6f24cc8b2";
const MINIMAL_FULL_DIGEST_HEX: &str =
    "2e435c896df9434b44bee96fe7011b01f6b31367200aae9e982426b242d21a62";
const LEAF_POB1_ABC_HEX: &str = "228dbb3ed905013085bb6c199eeeeb26b51cb1cf31e4726ade5cfb26d417f434";
const LEAF_ABSENT_IKT1_HEX: &str =
    "00407c3cea10c3ac368741563730e55ed6c0f8d58cb3d1815f44cb803ef7670f";
const LEAF_FOP1_ABC_HEX: &str = "6e751a25abc7f3f073a3a61847730690eb61d30bbc349065c8f89b4646af1e57";
const SIGNATURE_DOMAIN: &[u8] = b"pigloros/fork-attribution-authority-envelope/signature/v1";
/// The signature adds its 2-byte `bstr` head to the unsigned array.
const SIGNATURE_ITEM_BYTES: usize = 2 + 64;

const fn hash(value: u8) -> Hash {
    Hash::from_bytes([value; 32])
}

const fn timeline_id(value: u8) -> TimelineId {
    TimelineId::from_ulid(Ulid::from_bytes([value; 16]))
}

fn unhex(text: &str) -> Fallible<Vec<u8>> {
    (0..text.len())
        .step_by(2)
        .map(|at| -> Fallible<u8> {
            let pair = text.get(at..at + 2).ok_or("odd hex length")?;
            Ok(u8::from_str_radix(pair, 16)?)
        })
        .collect()
}

fn items(bytes: &[u8]) -> Fallible<Vec<Value>> {
    ciborium::from_reader::<Value, _>(bytes)?
        .into_array()
        .map_err(|_| "not a CBOR array".into())
}

fn encode(items: Vec<Value>) -> Fallible<Vec<u8>> {
    let mut out = Vec::new();
    ciborium::into_writer(&Value::Array(items), &mut out)?;
    Ok(out)
}

fn decode(bytes: &[u8]) -> Result<ForkAttributionAuthorityEnvelopeV1, CodecError> {
    ForkAttributionAuthorityEnvelopeV1::from_canonical_cbor(bytes)
}

/// Apply `edit` to the top-level `FAE1` fields and return the decoder error.
fn decode_edited(
    canonical: &[u8],
    edit: impl FnOnce(&mut Vec<Value>) -> Fallible<()>,
) -> Fallible<Option<CodecError>> {
    let mut fields = items(canonical)?;
    edit(&mut fields)?;
    Ok(decode(&encode(fields)?).err())
}

fn set(fields: &mut [Value], at: usize, value: Value) -> Fallible<()> {
    *fields.get_mut(at).ok_or("field index")? = value;
    Ok(())
}

fn list(fields: &mut [Value], at: usize) -> Fallible<&mut Vec<Value>> {
    match fields.get_mut(at) {
        Some(Value::Array(values)) => Ok(values),
        _ => Err("not a list field".into()),
    }
}

fn issuer() -> Result<ForkAttributionIssuerV1, CodecError> {
    ForkAttributionIssuerV1::new("issuer-a", 1, PublicKey::from_bytes([0x22; 32]))
}

fn attribution_identity() -> KeyIdentityV1 {
    KeyIdentityV1::new("creator-a", KeyRoleV1::SubjectAttributionSigning, 1)
}

fn live_key() -> Result<ImportedKeyRecordV1, CodecError> {
    ImportedKeyRecordV1::new(
        attribution_identity(),
        Some(hash(0x44)),
        PublicKey::from_bytes([0x55; 32]),
    )
}

fn fork(local_head: u64) -> Result<ForkTimelineImportV1, CodecError> {
    ForkTimelineImportV1::new(ForkTimelineImportInputV1 {
        child_timeline_id: timeline_id(2),
        name: Some("fork".to_owned()),
        owner: None,
        parent_timeline_id: timeline_id(1),
        parent_cut: 4,
        local_head,
        parent_chain_hash: hash(0x66),
    })
}

fn records() -> ForkAttributionAuthorityRecordsV1 {
    ForkAttributionAuthorityRecordsV1 {
        principal_owner_binding: b"POB1-bytes".to_vec(),
        fork_admission: b"FAR1-bytes".to_vec(),
        event_origins: Vec::new(),
        intervention_admissions: Vec::new(),
        publication_operation: b"FPO1-bytes".to_vec(),
        publication_binding: b"FPB1-bytes".to_vec(),
        publication_artifact: b"FPA1-bytes".to_vec(),
    }
}

fn classifier() -> ForkAttributionClassifierRecordsV1 {
    ForkAttributionClassifierRecordsV1 {
        source: b"FCS1-bytes".to_vec(),
        table: b"FCT1-bytes".to_vec(),
        registration: b"FCR1-bytes".to_vec(),
    }
}

/// An empty child segment whose source never registered a classifier.
fn minimal_input() -> Result<ForkAttributionAuthorityEnvelopeInputV1, CodecError> {
    Ok(ForkAttributionAuthorityEnvelopeInputV1 {
        import_operation_id: hash(0x11),
        issuer: issuer()?,
        issuer_policy_digest: hash(0x33),
        records: records(),
        key_record: live_key()?,
        key_tombstone: None,
        event_evidence: Vec::new(),
        timeline_import: fork(0)?,
        classifier: None,
        append_operations: Vec::new(),
    })
}

fn evidence(seq: u64, payload: Vec<u8>) -> Fallible<ForkEventEvidenceV1> {
    let payload = CanonicalBytes::from_vec(payload);
    let envelope = TimelineEventEnvelopeV1::new(
        TimelineEventEnvelopeInputV1 {
            identity: KeyIdentityV1::new("timeline-owner", KeyRoleV1::TimelineIntegritySigning, 1),
            origin_timeline_id: timeline_id(2),
            event_id: EventId::from_ulid(Ulid::from_parts(seq, 7)),
            origin_logical_seq: Seq::from_u64(seq),
            entity_id: EntityId::from_ulid(Ulid::from_parts(1, 2)),
            event_type: Kind::new("fork.test"),
            schema_version: 1,
            wall_time: WallTime::from_micros(1_000 + seq),
            causation_id: None,
            correlation_id: None,
        },
        &payload,
    )?;
    Ok(ForkEventEvidenceV1::new(
        envelope,
        payload,
        Signature::from_bytes([0x77; 64]),
    )?)
}

/// Replace the segment with `events`, one `EOR1`/`FOP1` each, and a classifier.
fn with_events(
    events: Vec<ForkEventEvidenceV1>,
    base: ForkAttributionAuthorityEnvelopeInputV1,
) -> Fallible<ForkAttributionAuthorityEnvelopeInputV1> {
    let count = events.len();
    Ok(ForkAttributionAuthorityEnvelopeInputV1 {
        records: ForkAttributionAuthorityRecordsV1 {
            event_origins: vec![b"EOR1-bytes".to_vec(); count],
            ..base.records
        },
        event_evidence: events,
        timeline_import: fork(u64::try_from(count)?)?,
        classifier: Some(classifier()),
        append_operations: vec![b"FOP1-bytes".to_vec(); count],
        ..base
    })
}

/// Three Events, one intervention, a classifier, and a destroyed source key.
fn populated_input() -> Fallible<ForkAttributionAuthorityEnvelopeInputV1> {
    let events = vec![
        evidence(5, b"first".to_vec())?,
        evidence(6, Vec::new())?,
        evidence(7, b"third".to_vec())?,
    ];
    let mut input = with_events(events, minimal_input()?)?;
    input.records.intervention_admissions = vec![b"FIA1-bytes".to_vec()];
    input.key_record = ImportedKeyRecordV1::new(
        attribution_identity(),
        None,
        PublicKey::from_bytes([0x55; 32]),
    )?;
    input.key_tombstone = Some(ImportedKeyTombstoneV1::new(
        attribution_identity(),
        hash(0x44),
        hash(0x45),
        hash(0x46),
    )?);
    Ok(input)
}

fn sign(
    input: ForkAttributionAuthorityEnvelopeInputV1,
) -> Fallible<ForkAttributionAuthorityEnvelopeV1> {
    Ok(ForkAttributionAuthorityEnvelopeV1::new(
        ForkAttributionAuthorityUnsignedEnvelopeV1::new(input)?,
        Signature::from_bytes([0x77; 64]),
    ))
}

fn unsigned_error(input: ForkAttributionAuthorityEnvelopeInputV1) -> Option<CodecError> {
    ForkAttributionAuthorityUnsignedEnvelopeV1::new(input).err()
}

#[test]
fn minimal_envelope_matches_independent_root_origin_and_digest_vectors() -> TestResult {
    let envelope = sign(minimal_input()?)?;
    let unsigned = envelope.unsigned();
    assert_eq!(
        unsigned.closure_root().as_bytes().to_vec(),
        unhex(MINIMAL_CLOSURE_ROOT_HEX)?
    );
    assert_eq!(
        unsigned.authority_origin_digest().as_bytes().to_vec(),
        unhex(MINIMAL_ORIGIN_HEX)?
    );
    assert_eq!(
        fork_attribution_authority_origin_digest_v1(
            hash(0x11),
            &issuer()?,
            hash(0x33),
            timeline_id(1),
            timeline_id(2)
        ),
        unsigned.authority_origin_digest()
    );
    assert_eq!(
        envelope.full_envelope_digest().as_bytes().to_vec(),
        unhex(MINIMAL_FULL_DIGEST_HEX)?
    );
    let unsigned_bytes = unsigned.canonical_bytes();
    let signed = envelope.to_canonical_cbor();
    assert_eq!((unsigned_bytes.len(), signed.len()), (434, 500));
    assert_eq!((unsigned_bytes[0], signed[0]), (0x96, 0x97));
    assert_eq!(&signed[1..unsigned_bytes.len()], &unsigned_bytes[1..]);
    assert_eq!(
        &signed[unsigned_bytes.len()..],
        [&[0x58_u8, 64][..], &[0x77_u8; 64][..]].concat()
    );
    let mut message = SIGNATURE_DOMAIN.to_vec();
    message.extend_from_slice(&434_u64.to_be_bytes());
    message.extend_from_slice(unsigned_bytes);
    assert_eq!(unsigned.signature_message(), message);
    assert_eq!(decode(&signed)?, envelope);
    assert_eq!(envelope.signature(), Signature::from_bytes([0x77; 64]));
    assert_eq!(unsigned.input(), &minimal_input()?);
    for end in 0..signed.len() {
        assert_eq!(
            decode(&signed[..end]).err(),
            Some(CodecError::InvalidEncoding)
        );
    }
    Ok(())
}

#[test]
fn closure_leaves_match_independent_vectors_and_codes_are_closed() -> TestResult {
    assert_eq!(
        fork_attribution_closure_leaf_v1(Leaf::PrincipalOwnerBinding, b"abc")?
            .as_bytes()
            .to_vec(),
        unhex(LEAF_POB1_ABC_HEX)?
    );
    assert_eq!(
        fork_attribution_closure_leaf_v1(Leaf::ImportedKeyTombstone, b"")?
            .as_bytes()
            .to_vec(),
        unhex(LEAF_ABSENT_IKT1_HEX)?
    );
    assert_eq!(
        fork_attribution_closure_leaf_v1(Leaf::AppendOperation, b"abc")?
            .as_bytes()
            .to_vec(),
        unhex(LEAF_FOP1_ABC_HEX)?
    );
    let mut known = Vec::new();
    for code in 0..=u8::MAX {
        match Leaf::from_code(code) {
            Ok(leaf) => {
                assert_eq!(leaf.code(), code);
                known.push(leaf);
            }
            Err(error) => assert_eq!(error, CodecError::InvalidEncoding),
        }
    }
    assert_eq!(known.len(), 15);
    let absent = [
        Leaf::ImportedKeyTombstone,
        Leaf::ClassifierSource,
        Leaf::ClassifierTable,
        Leaf::ClassifierRegistration,
    ];
    let largest = known
        .iter()
        .copied()
        .map(Leaf::maximum_bytes)
        .max()
        .unwrap_or(0);
    let buffer = vec![0x5a; largest + 1];
    for leaf in known {
        assert_eq!(leaf.may_be_absent(), absent.contains(&leaf));
        let maximum = leaf.maximum_bytes();
        assert!(fork_attribution_closure_leaf_v1(leaf, &buffer[..maximum]).is_ok());
        assert_eq!(
            fork_attribution_closure_leaf_v1(leaf, &buffer[..=maximum]),
            Err(CodecError::FieldOutOfBounds)
        );
        assert_eq!(
            fork_attribution_closure_leaf_v1(leaf, b"").is_ok(),
            leaf.may_be_absent()
        );
    }
    Ok(())
}

#[test]
fn populated_envelope_round_trips_and_commits_every_closure_member() -> TestResult {
    let envelope = sign(populated_input()?)?;
    let signed = envelope.to_canonical_cbor();
    assert_eq!(decode(&signed)?, envelope);
    for end in 0..signed.len() {
        assert_eq!(
            decode(&signed[..end]).err(),
            Some(CodecError::InvalidEncoding)
        );
    }
    let root = envelope.unsigned().closure_root();
    let base = populated_input()?;
    let mut variants = Vec::new();
    for edit in 0..10 {
        let mut input = base.clone();
        match edit {
            0 => input.records.principal_owner_binding.push(0),
            1 => input.records.fork_admission.push(0),
            2 => input.records.event_origins[0].push(0),
            3 => input.records.intervention_admissions[0].push(0),
            4 => input.records.publication_operation.push(0),
            5 => input.records.publication_binding.push(0),
            6 => input.records.publication_artifact.push(0),
            7 => input.append_operations[2].push(0),
            8 => input.event_evidence[1] = evidence(6, b"x".to_vec())?,
            _ => input.timeline_import = fork(4)?,
        }
        variants.push(input);
    }
    let mut classifier_variants = Vec::new();
    for edit in 0..3 {
        let mut records = classifier();
        match edit {
            0 => records.source.push(0),
            1 => records.table.push(0),
            _ => records.registration.push(0),
        }
        classifier_variants.push(ForkAttributionAuthorityEnvelopeInputV1 {
            classifier: Some(records),
            ..base.clone()
        });
    }
    variants.extend(classifier_variants);
    variants.push(ForkAttributionAuthorityEnvelopeInputV1 {
        key_tombstone: Some(ImportedKeyTombstoneV1::new(
            attribution_identity(),
            hash(0x47),
            hash(0x45),
            hash(0x46),
        )?),
        ..base.clone()
    });
    for variant in variants {
        let changed = ForkAttributionAuthorityUnsignedEnvelopeV1::new(variant)?;
        assert_ne!(changed.closure_root(), root);
        assert_eq!(
            changed.authority_origin_digest(),
            envelope.unsigned().authority_origin_digest()
        );
    }
    let reissued =
        ForkAttributionAuthorityUnsignedEnvelopeV1::new(ForkAttributionAuthorityEnvelopeInputV1 {
            import_operation_id: hash(0x12),
            ..base
        })?;
    assert_eq!(reissued.closure_root(), root);
    assert_ne!(
        reissued.authority_origin_digest(),
        envelope.unsigned().authority_origin_digest()
    );
    let resigned = ForkAttributionAuthorityEnvelopeV1::new(
        envelope.unsigned().clone(),
        Signature::from_bytes([0x78; 64]),
    );
    assert_ne!(
        resigned.full_envelope_digest(),
        envelope.full_envelope_digest()
    );
    Ok(())
}

#[test]
fn decoder_rejects_revision_5_arity_versions_and_alternate_encodings() -> TestResult {
    let signed = sign(minimal_input()?)?.to_canonical_cbor();
    for arity in [19, 22, 24] {
        let edited = decode_edited(&signed, |fields| {
            fields.resize(arity, Value::Null);
            Ok(())
        })?;
        assert_eq!(edited, Some(CodecError::InvalidEncoding), "{arity} fields");
    }
    let version = decode_edited(&signed, |fields| set(fields, 1, Value::Integer(2.into())))?;
    assert_eq!(version, Some(CodecError::UnsupportedVersion));
    let marker = decode_edited(&signed, |fields| set(fields, 0, Value::Text("FAE2".into())))?;
    assert_eq!(marker, Some(CodecError::InvalidEncoding));
    let mut trailing = signed.clone();
    trailing.push(0);
    assert_eq!(decode(&trailing).err(), Some(CodecError::InvalidEncoding));
    let version_at = 1 + 5;
    assert_eq!(signed[version_at], 0x01);
    let widened = [&signed[..version_at], &[0x18_u8][..], &signed[version_at..]].concat();
    assert_eq!(decode(&widened).err(), Some(CodecError::NonCanonical));
    assert_eq!(
        decode(&vec![
            0;
            MAX_FORK_ATTRIBUTION_AUTHORITY_ENVELOPE_BYTES_V1 + 1
        ])
        .err(),
        Some(CodecError::FieldOutOfBounds)
    );
    for at in [5, 6] {
        let edited = decode_edited(&signed, |fields| set(fields, at, Value::Bytes(vec![9; 32])))?;
        assert_eq!(
            edited,
            Some(CodecError::FieldMismatch),
            "derived field {at}"
        );
    }
    for at in [2, 4] {
        let edited = decode_edited(&signed, |fields| set(fields, at, Value::Bytes(vec![0; 32])))?;
        assert_eq!(
            edited,
            Some(CodecError::FieldOutOfBounds),
            "zero field {at}"
        );
    }
    for input in [
        ForkAttributionAuthorityEnvelopeInputV1 {
            import_operation_id: Hash::zero(),
            ..minimal_input()?
        },
        ForkAttributionAuthorityEnvelopeInputV1 {
            issuer_policy_digest: Hash::zero(),
            ..minimal_input()?
        },
    ] {
        assert_eq!(unsigned_error(input), Some(CodecError::FieldOutOfBounds));
    }
    Ok(())
}

#[test]
fn classifier_fields_are_all_or_none_and_required_for_any_event_record() -> TestResult {
    let present = sign(ForkAttributionAuthorityEnvelopeInputV1 {
        classifier: Some(classifier()),
        ..minimal_input()?
    })?;
    let signed = present.to_canonical_cbor();
    assert_eq!(decode(&signed)?, present);
    for nulls in [&[18][..], &[19], &[20], &[18, 19], &[18, 20], &[19, 20]] {
        let edited = decode_edited(&signed, |fields| {
            nulls
                .iter()
                .try_for_each(|at| set(fields, *at, Value::Null))
        })?;
        assert_eq!(
            edited,
            Some(CodecError::FieldMismatch),
            "null fields {nulls:?}"
        );
    }
    let populated = sign(populated_input()?)?.to_canonical_cbor();
    let unclassified = decode_edited(&populated, |fields| {
        [18, 19, 20]
            .iter()
            .try_for_each(|at| set(fields, *at, Value::Null))
    })?;
    assert_eq!(unclassified, Some(CodecError::FieldMismatch));
    let interventions_only = ForkAttributionAuthorityEnvelopeInputV1 {
        records: ForkAttributionAuthorityRecordsV1 {
            intervention_admissions: vec![b"FIA1-bytes".to_vec()],
            ..records()
        },
        ..minimal_input()?
    };
    assert_eq!(
        unsigned_error(interventions_only.clone()),
        Some(CodecError::FieldMismatch)
    );
    assert!(ForkAttributionAuthorityUnsignedEnvelopeV1::new(
        ForkAttributionAuthorityEnvelopeInputV1 {
            classifier: Some(classifier()),
            ..interventions_only
        }
    )
    .is_ok());
    let events_only = ForkAttributionAuthorityEnvelopeInputV1 {
        classifier: None,
        ..populated_input()?
    };
    assert_eq!(unsigned_error(events_only), Some(CodecError::FieldMismatch));
    Ok(())
}

#[test]
fn event_record_counts_and_key_lifecycle_must_agree() -> TestResult {
    let signed = sign(populated_input()?)?.to_canonical_cbor();
    for at in [9, 21] {
        let edited = decode_edited(&signed, |fields| {
            list(fields, at)?.pop();
            Ok(())
        })?;
        assert_eq!(edited, Some(CodecError::FieldMismatch), "list field {at}");
    }
    let without_tombstone = decode_edited(&signed, |fields| set(fields, 15, Value::Null))?;
    assert_eq!(without_tombstone, Some(CodecError::FieldMismatch));
    let mut missing_append = populated_input()?;
    missing_append.append_operations.pop();
    let mut extra_origin = populated_input()?;
    extra_origin
        .records
        .event_origins
        .push(b"EOR1-bytes".to_vec());
    let live_with_tombstone = ForkAttributionAuthorityEnvelopeInputV1 {
        key_record: live_key()?,
        ..populated_input()?
    };
    for input in [missing_append, extra_origin, live_with_tombstone] {
        assert_eq!(unsigned_error(input), Some(CodecError::FieldMismatch));
    }
    Ok(())
}

/// Carried record fields as `(FAE1 field, list item?, bound)`.
const RECORD_BOUNDS: [(usize, bool, usize); 11] = [
    (7, false, MAX_IMPORTED_PRINCIPAL_OWNER_BINDING_BYTES_V1),
    (8, false, MAX_FORK_ADMISSION_RECORD_BYTES_V1),
    (9, true, 384),
    (10, true, 512),
    (11, false, MAX_FORK_PUBLICATION_OPERATION_BYTES_V1),
    (12, false, MAX_FORK_PUBLICATION_BINDING_BYTES_V1),
    (13, false, MAX_FORK_PUBLICATION_ARTIFACT_BYTES_V1),
    (18, false, 196_608),
    (19, false, 196_608),
    (20, false, 192),
    (21, true, 768),
];

/// Replace the record at `field` (its first item for a list) with `record`.
fn input_with_record(
    field: usize,
    record: Vec<u8>,
) -> Fallible<ForkAttributionAuthorityEnvelopeInputV1> {
    let mut input = populated_input()?;
    let records = &mut input.records;
    let classifier = input.classifier.as_mut().ok_or("classifier")?;
    let slot = match field {
        7 => &mut records.principal_owner_binding,
        8 => &mut records.fork_admission,
        9 => records.event_origins.first_mut().ok_or("EOR1")?,
        10 => records.intervention_admissions.first_mut().ok_or("FIA1")?,
        11 => &mut records.publication_operation,
        12 => &mut records.publication_binding,
        13 => &mut records.publication_artifact,
        18 => &mut classifier.source,
        19 => &mut classifier.table,
        20 => &mut classifier.registration,
        _ => input.append_operations.first_mut().ok_or("FOP1")?,
    };
    *slot = record;
    Ok(input)
}

#[test]
fn every_carried_record_bound_accepts_its_maximum_and_rejects_beyond_it() -> TestResult {
    let signed = sign(populated_input()?)?.to_canonical_cbor();
    for (field, is_list, maximum) in RECORD_BOUNDS {
        let largest = sign(input_with_record(field, vec![0x5a; maximum])?)?;
        assert_eq!(
            decode(&largest.to_canonical_cbor())?,
            largest,
            "field {field}"
        );
        for record in [Vec::new(), vec![0x5a; maximum + 1]] {
            assert_eq!(
                unsigned_error(input_with_record(field, record.clone())?),
                Some(CodecError::FieldOutOfBounds),
                "field {field} with {} bytes",
                record.len()
            );
            let edited = decode_edited(&signed, |fields| {
                if is_list {
                    *list(fields, field)?.first_mut().ok_or("item")? = Value::Bytes(record);
                    Ok(())
                } else {
                    set(fields, field, Value::Bytes(record))
                }
            })?;
            assert_eq!(
                edited,
                Some(CodecError::FieldOutOfBounds),
                "decoded field {field}"
            );
        }
    }
    for (field, maximum) in [
        (3, MAX_FORK_ATTRIBUTION_ISSUER_BYTES_V1),
        (14, MAX_IMPORTED_KEY_RECORD_BYTES_V1),
        (15, MAX_IMPORTED_KEY_TOMBSTONE_BYTES_V1),
        (17, MAX_FORK_TIMELINE_IMPORT_BYTES_V1),
    ] {
        for (length, expected) in [
            (0, CodecError::FieldOutOfBounds),
            (maximum, CodecError::InvalidEncoding),
            (maximum + 1, CodecError::FieldOutOfBounds),
        ] {
            let edited = decode_edited(&signed, |fields| {
                set(fields, field, Value::Bytes(vec![0; length]))
            })?;
            assert_eq!(
                edited,
                Some(expected),
                "typed field {field} with {length} bytes"
            );
        }
    }
    Ok(())
}

#[test]
fn event_and_intervention_counts_accept_their_maximum_and_reject_one_more() -> TestResult {
    let tiny = evidence(5, Vec::new())?;
    let events = vec![tiny.clone(); MAX_FORK_ATTRIBUTION_AUTHORITY_EVENTS_V1];
    let mut input = with_events(events, minimal_input()?)?;
    input.records.intervention_admissions =
        vec![b"FIA1".to_vec(); MAX_FORK_ATTRIBUTION_AUTHORITY_INTERVENTIONS_V1];
    let largest = sign(input.clone())?;
    let signed = largest.to_canonical_cbor();
    assert_eq!(decode(&signed)?, largest);

    let mut origins = input.clone();
    origins.records.event_origins.push(b"EOR1".to_vec());
    let mut interventions = input.clone();
    interventions
        .records
        .intervention_admissions
        .push(b"FIA1".to_vec());
    let mut appends = input.clone();
    appends.append_operations.push(b"FOP1".to_vec());
    let mut evidence_items = input;
    evidence_items.event_evidence.push(tiny.clone());
    for input in [origins, interventions, appends, evidence_items] {
        assert_eq!(unsigned_error(input), Some(CodecError::FieldOutOfBounds));
    }
    let fee1 = items(&tiny.to_canonical_cbor())?;
    for (at, extra) in [
        (9, Value::Bytes(b"EOR1".to_vec())),
        (10, Value::Bytes(b"FIA1".to_vec())),
        (16, Value::Array(fee1)),
        (21, Value::Bytes(b"FOP1".to_vec())),
    ] {
        let edited = decode_edited(&signed, |fields| {
            list(fields, at)?.push(extra);
            Ok(())
        })?;
        assert_eq!(
            edited,
            Some(CodecError::FieldOutOfBounds),
            "list field {at}"
        );
    }
    Ok(())
}

/// Four Events whose payloads sum to `60 MiB + extra`.
fn sixty_mebibytes(extra: usize) -> Fallible<Vec<ForkEventEvidenceV1>> {
    let full = MAX_TIMELINE_EVENT_PAYLOAD_BYTES_V1;
    let last = MAX_FORK_ATTRIBUTION_AUTHORITY_PAYLOAD_BYTES_V1 - 3 * full + extra;
    [full, full, full, last]
        .into_iter()
        .zip(5..)
        .map(|(length, seq)| evidence(seq, vec![0xab; length]))
        .collect()
}

#[test]
fn aggregate_and_per_event_payload_bounds_are_conjunctive() -> TestResult {
    let largest = sign(with_events(sixty_mebibytes(0)?, minimal_input()?)?)?;
    let signed = largest.to_canonical_cbor();
    assert_eq!(decode(&signed)?, largest);
    let over = sixty_mebibytes(1)?;
    let last = items(&over[3].to_canonical_cbor())?;
    assert_eq!(
        unsigned_error(with_events(over, minimal_input()?)?),
        Some(CodecError::FieldOutOfBounds)
    );
    let edited = decode_edited(&signed, |fields| {
        *list(fields, 16)?.get_mut(3).ok_or("FEE1")? = Value::Array(last);
        Ok(())
    })?;
    assert_eq!(edited, Some(CodecError::FieldOutOfBounds));
    let oversized_payload = decode_edited(&signed, |fields| match list(fields, 16)?.get_mut(0) {
        Some(Value::Array(fee1)) => set(
            fee1,
            3,
            Value::Bytes(vec![0; MAX_TIMELINE_EVENT_PAYLOAD_BYTES_V1 + 1]),
        ),
        _ => Err("FEE1".into()),
    })?;
    assert_eq!(oversized_payload, Some(CodecError::FieldOutOfBounds));
    Ok(())
}

/// Sixty MiB of payload plus `tiny` empty-payload Events with maximum-size
/// `EOR1` and `FOP1`, maximum `FIA1`, and an `FCS1` of `source` bytes.
fn sized_input(
    big: &[ForkEventEvidenceV1],
    tiny: usize,
    source: usize,
) -> Fallible<ForkAttributionAuthorityEnvelopeInputV1> {
    let mut events = big.to_vec();
    events.extend(std::iter::repeat_n(evidence(5, Vec::new())?, tiny));
    let count = events.len();
    let mut input = with_events(events, minimal_input()?)?;
    input.records.event_origins = vec![vec![0x31; 384]; count];
    input.records.intervention_admissions =
        vec![vec![0x32; 512]; MAX_FORK_ATTRIBUTION_AUTHORITY_INTERVENTIONS_V1];
    input.append_operations = vec![vec![0x33; 768]; count];
    input.classifier = Some(ForkAttributionClassifierRecordsV1 {
        source: vec![0x41; source],
        table: vec![0x42; 196_608],
        registration: vec![0x43; 192],
    });
    Ok(input)
}

fn signed_length(input: ForkAttributionAuthorityEnvelopeInputV1) -> Fallible<usize> {
    Ok(ForkAttributionAuthorityUnsignedEnvelopeV1::new(input)?
        .canonical_bytes()
        .len()
        + SIGNATURE_ITEM_BYTES)
}

#[test]
fn complete_envelope_accepts_exactly_64_mebibytes_and_rejects_one_more_byte() -> TestResult {
    let maximum = MAX_FORK_ATTRIBUTION_AUTHORITY_ENVELOPE_BYTES_V1;
    let per_event =
        signed_length(sized_input(&[], 1, 1_024)?)? - signed_length(sized_input(&[], 0, 1_024)?)?;
    let big = sixty_mebibytes(0)?;
    let base = signed_length(sized_input(&big, 0, 1_024)?)?;
    let tiny = (maximum - base - 8_192) / per_event;
    let probe = signed_length(sized_input(&big, tiny, 1_024)?)?;
    let source = 1_024 + maximum - probe;
    assert!(source < 65_536, "the FCS1 head width must not change");
    let exact = sign(sized_input(&big, tiny, source)?)?;
    let signed = exact.to_canonical_cbor();
    assert_eq!(signed.len(), maximum);
    assert_eq!(decode(&signed)?, exact);
    assert_eq!(
        unsigned_error(sized_input(&big, tiny, source + 1)?),
        Some(CodecError::FieldOutOfBounds)
    );
    Ok(())
}

#[test]
fn import_admission_record_derives_from_the_exact_envelope() -> TestResult {
    let envelope = sign(minimal_input()?)?;
    let admission = ImportedForkAttributionAdmissionV1::from_envelope(&envelope, 3)?;
    let value = admission.input();
    let mut far1 = b"pigloros/fork-admission/v1".to_vec();
    far1.extend_from_slice(b"FAR1-bytes");
    assert_eq!(
        value.fork_admission_digest.as_bytes(),
        blake3::hash(&far1).as_bytes()
    );
    assert_eq!(value.import_operation_id, hash(0x11));
    assert_eq!(
        value.authority_origin_digest,
        envelope.unsigned().authority_origin_digest()
    );
    assert_eq!(value.full_envelope_digest, envelope.full_envelope_digest());
    assert_eq!(value.issuer, issuer()?);
    assert_eq!(value.issuer_policy_digest, hash(0x33));
    assert_eq!(value.issuer_policy_generation, 3);
    assert_eq!(value.child_timeline_id, timeline_id(2));
    assert_eq!(value.final_logical_head, 4);
    assert_eq!(value.closure_root, envelope.unsigned().closure_root());
    let bytes = admission.to_canonical_cbor();
    assert_eq!(&bytes[..6], &[0x8c, 0x64, b'I', b'F', b'A', b'1']);
    assert_eq!(
        ImportedForkAttributionAdmissionV1::from_canonical_cbor(&bytes)?,
        admission
    );
    for end in 0..bytes.len() {
        assert_eq!(
            ImportedForkAttributionAdmissionV1::from_canonical_cbor(&bytes[..end]).err(),
            Some(CodecError::InvalidEncoding)
        );
    }
    assert_eq!(
        ImportedForkAttributionAdmissionV1::from_envelope(&envelope, 0),
        Err(CodecError::FieldOutOfBounds)
    );
    Ok(())
}

fn admission_input() -> Result<ImportedForkAttributionAdmissionInputV1, CodecError> {
    Ok(ImportedForkAttributionAdmissionInputV1 {
        import_operation_id: hash(1),
        authority_origin_digest: hash(2),
        full_envelope_digest: hash(3),
        issuer: ForkAttributionIssuerV1::new(
            "i".repeat(128),
            u64::MAX,
            PublicKey::from_bytes([4; 32]),
        )?,
        issuer_policy_digest: hash(5),
        issuer_policy_generation: u64::MAX,
        child_timeline_id: timeline_id(2),
        final_logical_head: u64::MAX,
        closure_root: hash(6),
        fork_admission_digest: hash(7),
    })
}

#[test]
fn import_admission_record_enforces_bounds_and_canonical_bytes() -> TestResult {
    let widest = ImportedForkAttributionAdmissionV1::new(admission_input()?)?;
    let bytes = widest.to_canonical_cbor();
    assert_eq!(bytes.len(), 428);
    assert!(bytes.len() <= MAX_IMPORTED_FORK_ATTRIBUTION_ADMISSION_BYTES_V1);
    let decode_admission = ImportedForkAttributionAdmissionV1::from_canonical_cbor;
    assert_eq!(decode_admission(&bytes)?, widest);
    let base = admission_input()?;
    for zero in 0..7 {
        let mut input = base.clone();
        match zero {
            0 => input.import_operation_id = Hash::zero(),
            1 => input.authority_origin_digest = Hash::zero(),
            2 => input.full_envelope_digest = Hash::zero(),
            3 => input.issuer_policy_digest = Hash::zero(),
            4 => input.closure_root = Hash::zero(),
            5 => input.fork_admission_digest = Hash::zero(),
            _ => input.issuer_policy_generation = 0,
        }
        assert_eq!(
            ImportedForkAttributionAdmissionV1::new(input),
            Err(CodecError::FieldOutOfBounds)
        );
    }
    let mut fields = items(&bytes)?;
    set(&mut fields, 1, Value::Integer(2.into()))?;
    assert_eq!(
        decode_admission(&encode(fields)?).err(),
        Some(CodecError::UnsupportedVersion)
    );
    let mut fields = items(&bytes)?;
    set(&mut fields, 5, Value::Bytes(Vec::new()))?;
    assert_eq!(
        decode_admission(&encode(fields)?).err(),
        Some(CodecError::FieldOutOfBounds)
    );
    let mut fields = items(&bytes)?;
    set(&mut fields, 5, Value::Bytes(b"x".to_vec()))?;
    assert_eq!(
        decode_admission(&encode(fields)?).err(),
        Some(CodecError::InvalidEncoding)
    );
    let mut fields = items(&bytes)?;
    set(&mut fields, 2, Value::Bytes(vec![0; 32]))?;
    assert_eq!(
        decode_admission(&encode(fields)?).err(),
        Some(CodecError::FieldOutOfBounds)
    );
    let version_at = 1 + 5;
    assert_eq!(bytes[version_at], 0x01);
    let widened = [&bytes[..version_at], &[0x18_u8][..], &bytes[version_at..]].concat();
    assert_eq!(
        decode_admission(&widened).err(),
        Some(CodecError::NonCanonical)
    );
    let mut trailing = bytes;
    trailing.push(0);
    assert_eq!(
        decode_admission(&trailing).err(),
        Some(CodecError::InvalidEncoding)
    );
    assert_eq!(
        decode_admission(&vec![
            0;
            MAX_IMPORTED_FORK_ATTRIBUTION_ADMISSION_BYTES_V1 + 1
        ])
        .err(),
        Some(CodecError::FieldOutOfBounds)
    );
    Ok(())
}
