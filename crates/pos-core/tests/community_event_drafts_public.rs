//! Independent CED1/CEB1 and draft-vector wire oracles, not Seal evidence.

use ciborium::value::Value;
use pos_core::community_lifecycle::{
    community_event_draft_vector_bytes_v1 as vector_bytes,
    CommunityEventDraftFragmentInputV1 as FragmentInput,
    CommunityEventDraftFragmentReferenceV1 as Reference, CommunityEventDraftFragmentV1 as Fragment,
    CommunityEventDraftManifestInputV1 as ManifestInput, CommunityEventDraftManifestV1 as Manifest,
    CommunityLifecycleErrorV1 as Error, CommunityMaterializationReferenceV1 as Materialization,
    CommunityPassKeyV1 as Pass, MAX_COMMUNITY_EVENT_DRAFTS_V1,
    MAX_COMMUNITY_EVENT_DRAFT_FRAGMENTS_V1, MAX_COMMUNITY_EVENT_DRAFT_FRAGMENT_BYTES_V1,
    MAX_COMMUNITY_EVENT_DRAFT_FRAGMENT_RECORD_BYTES_V1,
    MAX_COMMUNITY_EVENT_DRAFT_MANIFEST_BYTES_V1, MAX_COMMUNITY_EVENT_DRAFT_VECTOR_BYTES_V1,
};
use pos_core::{
    pipeline_draft_vector_digest_v1, CanonicalBytes, CorrelationId, EntityId,
    ErasureArtifactClassV1, EventDraft, EventId, Hash, Kind, TimelineId, WallTime,
};
use ulid::Ulid;

type Fallible<T> = Result<T, Box<dyn std::error::Error>>;
type TestResult = Fallible<()>;

const MAX_VECTOR: usize = 67_108_864;
const MAX_FRAGMENT: usize = 262_144;

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
fn fields(value: &mut Value) -> Fallible<&mut Vec<Value>> {
    match value {
        Value::Array(values) => Ok(values),
        _ => Err("fixture is not an array".into()),
    }
}
fn pass(ordinal: u64) -> Fallible<Pass> {
    Ok(Pass::new(
        TimelineId::from_ulid(Ulid::from_bytes([1; 16])),
        [2; 16],
        ordinal,
    )?)
}
fn pass_value(ordinal: u64) -> Value {
    Value::Array(vec![
        bytes(b"CPK1"),
        uint(1),
        bytes(&[1; 16]),
        bytes(&[2; 16]),
        uint(ordinal),
    ])
}
fn digest(domain: &[u8], encoded: &[u8]) -> Hash {
    let mut preimage = domain.to_vec();
    preimage.extend_from_slice(encoded);
    Hash::from_bytes(*blake3::hash(&preimage).as_bytes())
}
const fn materialization() -> Materialization {
    Materialization {
        owner_reference: hash(20),
        artifact_class: ErasureArtifactClassV1::TimelineReplay,
        object_address: hash(21),
        artifact_digest: hash(22),
        registration_address: hash(23),
        attestation_address: hash(24),
    }
}
fn materialization_value() -> Value {
    Value::Array(vec![
        bytes(&[20; 32]),
        uint(0),
        bytes(&[21; 32]),
        bytes(&[22; 32]),
        bytes(&[23; 32]),
        bytes(&[24; 32]),
    ])
}
fn fragment_input(offset: u64, total: u64, data: &[u8]) -> Fallible<FragmentInput<'_>> {
    Ok(FragmentInput {
        pass_key: pass(3)?,
        byte_offset: offset,
        total_plaintext_bytes: total,
        fragment_bytes: data,
    })
}
fn fragment_value(offset: u64, total: u64, data: &[u8]) -> Fallible<Value> {
    Ok(Value::Array(vec![
        bytes(b"CEB1"),
        uint(1),
        bytes(&encode(&pass_value(3))?),
        uint(offset),
        uint(total),
        bytes(data),
    ]))
}
const fn reference(offset: u64, length: u32, digest: Hash) -> Reference {
    Reference {
        byte_offset: offset,
        fragment_length: length,
        fragment_digest: digest,
        materialization: materialization(),
    }
}
fn manifest_input(fragments: Vec<Reference>, total: u64, count: u64) -> Fallible<ManifestInput> {
    Ok(ManifestInput {
        pass_key: pass(3)?,
        fragments,
        total_plaintext_bytes: total,
        draft_count: count,
        draft_vector_digest: hash(9),
    })
}
fn manifest_value(rows: &[(u64, u64, u8)], total: u64, count: u64) -> Fallible<Value> {
    Ok(Value::Array(vec![
        bytes(b"CED1"),
        uint(1),
        bytes(&encode(&pass_value(3))?),
        Value::Array(
            rows.iter()
                .map(|(offset, length, digest)| {
                    Value::Array(vec![
                        uint(*offset),
                        uint(*length),
                        bytes(&[*digest; 32]),
                        materialization_value(),
                    ])
                })
                .collect(),
        ),
        uint(total),
        uint(count),
        bytes(&[9; 32]),
    ]))
}
const fn id(byte: u8) -> Ulid {
    Ulid::from_bytes([byte; 16])
}
fn plain_draft(payload: Vec<u8>) -> EventDraft {
    EventDraft::new(
        EntityId::from_ulid(id(5)),
        Kind::new("a"),
        CanonicalBytes::from_vec(payload),
    )
}
fn full_draft(payload: Vec<u8>, micros: u64) -> EventDraft {
    let mut draft = plain_draft(payload);
    draft.event_type = Kind::new("kind.text");
    draft.causation_id = Some(EventId::from_ulid(id(6)));
    draft.correlation_id = Some(CorrelationId::from_ulid(id(7)));
    draft.wall_time = Some(WallTime::from_micros(micros));
    draft
}
fn draft_value(draft: &EventDraft) -> Value {
    Value::Array(vec![
        bytes(&draft.entity.inner().to_bytes()),
        Value::Text(draft.event_type.as_str().to_owned()),
        bytes(draft.payload.as_slice()),
        draft
            .causation_id
            .map_or(Value::Null, |id| bytes(&id.inner().to_bytes())),
        draft
            .correlation_id
            .map_or(Value::Null, |id| bytes(&id.inner().to_bytes())),
        uint(1),
        draft
            .wall_time
            .map_or(Value::Null, |time| uint(time.as_micros())),
    ])
}

/// Split `vector` into CEB1 fragments of at most `chunk` bytes, with the
/// manifest that names their real digests.
fn sealed<'a>(
    vector: &'a [u8],
    chunk: usize,
    drafts: &[EventDraft],
) -> Fallible<(Manifest, Vec<Fragment<'a>>)> {
    sealed_as(
        vector,
        chunk,
        drafts.len() as u64,
        pipeline_draft_vector_digest_v1(drafts),
    )
}

/// [`sealed`] with an explicit recorded draft count and vector digest.
fn sealed_as(
    vector: &[u8],
    chunk: usize,
    count: u64,
    vector_digest: Hash,
) -> Fallible<(Manifest, Vec<Fragment<'_>>)> {
    let total = vector.len() as u64;
    let mut fragments = Vec::new();
    let mut references = Vec::new();
    for (index, data) in vector.chunks(chunk).enumerate() {
        let offset = (index * chunk) as u64;
        let fragment = Fragment::new(fragment_input(offset, total, data)?)?;
        references.push(reference(
            offset,
            u32::try_from(data.len())?,
            fragment.digest(),
        ));
        fragments.push(fragment);
    }
    let manifest = Manifest::new(ManifestInput {
        draft_vector_digest: vector_digest,
        ..manifest_input(references, total, count)?
    })?;
    Ok((manifest, fragments))
}

/// The record as an indefinite-length array, and with its CPK1 byte string
/// as an indefinite-length byte string.
fn indefinite_forms(encoded: &[u8]) -> Fallible<[Vec<u8>; 2]> {
    if encoded[7] != 0x58 {
        return Err("fixture CPK1 is not at offset 7".into());
    }
    let end = 9 + usize::from(encoded[8]);
    let mut array = vec![0x9f];
    array.extend_from_slice(&encoded[1..]);
    array.push(0xff);
    let mut string = encoded[..7].to_vec();
    string.push(0x5f);
    string.extend_from_slice(&encoded[7..end]);
    string.push(0xff);
    string.extend_from_slice(&encoded[end..]);
    Ok([array, string])
}

#[test]
fn fragment_has_exact_six_fields_digest_and_borrowed_bytes() -> TestResult {
    let data = [7_u8; 5];
    let fragment = Fragment::new(fragment_input(2, 9, &data)?)?;
    let expected = encode(&fragment_value(2, 9, &data)?)?;
    assert_eq!(&*fragment.to_canonical_cbor(), &expected);
    assert_eq!(
        fragment.digest(),
        digest(b"PiglorOS.Community.CEB1.v1\0", &expected)
    );
    let decoded = Fragment::from_canonical_cbor(&expected)?;
    assert!(*decoded.as_input() == fragment_input(2, 9, &data)?);
    let rows = decoded.as_input().fragment_bytes;
    assert_eq!(
        rows.as_ptr() as usize - expected.as_ptr() as usize,
        expected.len() - 5
    );
    Ok(())
}

#[test]
fn fragment_length_and_vector_range_bounds_are_exact() -> TestResult {
    let full = vec![1; MAX_FRAGMENT];
    let over = vec![1; MAX_FRAGMENT + 1];
    assert_eq!(MAX_COMMUNITY_EVENT_DRAFT_FRAGMENT_BYTES_V1, MAX_FRAGMENT);
    assert_eq!(MAX_COMMUNITY_EVENT_DRAFT_VECTOR_BYTES_V1, MAX_VECTOR as u64);
    let max = MAX_VECTOR as u64;
    for (offset, total, data, expected) in [
        (0, 1, &full[..1], None),
        (0, max, &full[..], None),
        (max - 1, max, &full[..1], None),
        (3, 4, &full[..1], None),
        (0, 1, &full[..0], Some(Error::BoundsExceeded)),
        (0, max, &over[..], Some(Error::BoundsExceeded)),
        (0, 0, &full[..1], Some(Error::BoundsExceeded)),
        (0, max + 1, &full[..1], Some(Error::BoundsExceeded)),
        (4, 4, &full[..1], Some(Error::InvalidBinding)),
        (3, 4, &full[..2], Some(Error::InvalidBinding)),
        (u64::MAX, 4, &full[..1], Some(Error::InvalidBinding)),
    ] {
        let built = Fragment::new(fragment_input(offset, total, data)?);
        assert_eq!(built.as_ref().err(), expected.as_ref());
        let encoded = encode(&fragment_value(offset, total, data)?)?;
        let decoded = Fragment::from_canonical_cbor(&encoded);
        assert_eq!(decoded.err(), expected);
        if let Ok(fragment) = built {
            assert_eq!(&*fragment.to_canonical_cbor(), &encoded);
        }
    }
    Ok(())
}

#[test]
fn fragment_rejects_truncation_trailer_version_size_and_nonpreferred() -> TestResult {
    let encoded = encode(&fragment_value(1, 3, &[4, 5])?)?;
    for end in 0..encoded.len() {
        assert!(Fragment::from_canonical_cbor(&encoded[..end]).is_err());
    }
    let mut trailing = encoded.clone();
    trailing.push(0);
    assert_eq!(
        Fragment::from_canonical_cbor(&trailing).err(),
        Some(Error::InvalidEncoding)
    );
    let mut version = fragment_value(1, 3, &[4, 5])?;
    fields(&mut version)?[1] = uint(2);
    assert_eq!(
        Fragment::from_canonical_cbor(&encode(&version)?).err(),
        Some(Error::UnsupportedVersion)
    );
    let mut nonpreferred = encoded.clone();
    let offset = encoded.len() - 5;
    nonpreferred.splice(offset..=offset, [0x18, 1]);
    assert_eq!(
        Fragment::from_canonical_cbor(&nonpreferred).err(),
        Some(Error::InvalidEncoding)
    );
    let mut bad_pass = fragment_value(1, 3, &[4, 5])?;
    fields(&mut bad_pass)?[2] = bytes(&encode(&pass_value(0))?);
    assert_eq!(
        Fragment::from_canonical_cbor(&encode(&bad_pass)?).err(),
        Some(Error::InvalidBinding)
    );
    for form in indefinite_forms(&encoded)? {
        assert_eq!(
            Fragment::from_canonical_cbor(&form).err(),
            Some(Error::InvalidEncoding)
        );
    }
    let limit = MAX_COMMUNITY_EVENT_DRAFT_FRAGMENT_RECORD_BYTES_V1;
    assert_eq!(limit, 262_218);
    // The largest valid CEB1: a u64::MAX ordinal (the 50-byte CPK1), a
    // five-byte offset and total, and a full fragment.
    let full = vec![3; MAX_FRAGMENT];
    let max = MAX_VECTOR as u64;
    let largest = Fragment::new(FragmentInput {
        pass_key: pass(u64::MAX)?,
        ..fragment_input(max - MAX_FRAGMENT as u64, max, &full)?
    })?;
    let largest = largest.to_canonical_cbor();
    assert_eq!(largest.len(), limit);
    assert!(Fragment::from_canonical_cbor(&largest).is_ok());
    assert_eq!(
        Fragment::from_canonical_cbor(&vec![0; limit]).err(),
        Some(Error::InvalidEncoding)
    );
    assert_eq!(
        Fragment::from_canonical_cbor(&vec![0; limit + 1]).err(),
        Some(Error::BoundsExceeded)
    );
    Ok(())
}

#[test]
fn manifest_has_exact_seven_fields_and_digest() -> TestResult {
    let input = manifest_input(
        vec![reference(0, 30, hash(4)), reference(30, 2, hash(5))],
        32,
        1,
    )?;
    let manifest = Manifest::new(input.clone())?;
    let expected = encode(&manifest_value(&[(0, 30, 4), (30, 2, 5)], 32, 1)?)?;
    assert_eq!(&*manifest.to_canonical_cbor(), &expected);
    assert_eq!(
        manifest.digest(),
        digest(b"PiglorOS.Community.CED1.v1\0", &expected)
    );
    assert!(*Manifest::from_canonical_cbor(&expected)?.as_input() == input);
    Ok(())
}

#[test]
fn manifest_partition_must_be_contiguous_from_zero_and_complete() -> TestResult {
    for (rows, total, expected) in [
        (&[(0, 50)][..], 50, None),
        (&[(0, 20), (20, 30)][..], 50, None),
        (&[][..], 50, Some(Error::InvalidBinding)),
        (&[(10, 40)][..], 50, Some(Error::InvalidBinding)),
        (&[(0, 20), (30, 20)][..], 50, Some(Error::InvalidBinding)),
        (&[(0, 30), (20, 30)][..], 50, Some(Error::InvalidBinding)),
        (&[(0, 40)][..], 50, Some(Error::InvalidBinding)),
        (&[(0, 60)][..], 50, Some(Error::InvalidBinding)),
        (&[(0, 1)][..], 0, Some(Error::BoundsExceeded)),
        (&[(0, 0)][..], 50, Some(Error::BoundsExceeded)),
        (&[(0, 262_145)][..], 262_145, Some(Error::BoundsExceeded)),
        (&[(0, 262_144), (262_144, 1)][..], 262_145, None),
    ] {
        let references = rows
            .iter()
            .map(|(offset, length)| reference(*offset, *length, hash(4)))
            .collect();
        assert_eq!(
            Manifest::new(manifest_input(references, total, 1)?).err(),
            expected
        );
        let wire: Vec<_> = rows
            .iter()
            .map(|(offset, length)| (*offset, u64::from(*length), 4))
            .collect();
        assert_eq!(
            Manifest::from_canonical_cbor(&encode(&manifest_value(&wire, total, 1)?)?).err(),
            expected
        );
    }
    assert_eq!(
        Manifest::from_canonical_cbor(&encode(&manifest_value(
            &[(0, u64::from(u32::MAX) + 1, 4)],
            5,
            0
        )?)?)
        .err(),
        Some(Error::BoundsExceeded)
    );
    Ok(())
}

#[test]
fn manifest_counts_and_vector_length_bounds_are_exact() -> TestResult {
    let limit = MAX_COMMUNITY_EVENT_DRAFT_FRAGMENTS_V1;
    assert_eq!(limit, 256);
    let max = MAX_VECTOR as u64;
    let rows = |count: u64, length: u64| -> Vec<(u64, u64, u8)> {
        (0..count)
            .map(|index| (index * length, length, 4))
            .collect()
    };
    for (rows, total, count, expected) in [
        (rows(256, 262_144), max, 1024, None),
        (rows(257, 1), 257, 0, Some(Error::BoundsExceeded)),
        (rows(1, 1), 1, 1025, Some(Error::BoundsExceeded)),
        (rows(1, 1), max + 1, 0, Some(Error::BoundsExceeded)),
    ] {
        let references = rows
            .iter()
            .map(|(offset, length, _)| {
                reference(*offset, u32::try_from(*length).unwrap_or(0), hash(4))
            })
            .collect();
        assert_eq!(
            Manifest::new(manifest_input(references, total, count)?).err(),
            expected
        );
        let encoded = encode(&manifest_value(&rows, total, count)?)?;
        assert!(encoded.len() <= MAX_COMMUNITY_EVENT_DRAFT_MANIFEST_BYTES_V1);
        assert_eq!(Manifest::from_canonical_cbor(&encoded).err(), expected);
    }
    assert_eq!(MAX_COMMUNITY_EVENT_DRAFTS_V1, 1024);
    Ok(())
}

#[test]
fn manifest_length_must_hold_the_draft_count() -> TestResult {
    // The empty vector is exactly one byte; otherwise at least the array head
    // plus 25 bytes (the smallest valid draft) per draft.
    for (total, count, valid) in [
        (1, 0, true),
        (2, 0, false),
        (26, 1, true),
        (25, 1, false),
        (1, 1, false),
        (25_603, 1024, true),
        (25_602, 1024, false),
    ] {
        let input = manifest_input(
            vec![reference(0, u32::try_from(total)?, hash(4))],
            total,
            count,
        )?;
        let expected = (!valid).then_some(Error::InvalidBinding);
        assert_eq!(Manifest::new(input).err(), expected);
        let wire = encode(&manifest_value(&[(0, total, 4)], total, count)?)?;
        assert_eq!(Manifest::from_canonical_cbor(&wire).err(), expected);
    }
    let smallest = [plain_draft(Vec::new())];
    let vector = vector_bytes(&smallest)?;
    assert_eq!(vector.len(), 26);
    let (manifest, fragments) = sealed(&vector, MAX_FRAGMENT, &smallest)?;
    assert_eq!(manifest.reconstruct(&fragments)?, smallest);
    Ok(())
}

#[test]
fn manifest_rejects_zero_digests_and_foreign_materialization() -> TestResult {
    let mut zero_vector = manifest_input(vec![reference(0, 1, hash(4))], 1, 0)?;
    zero_vector.draft_vector_digest = Hash::zero();
    let zero_fragment = manifest_input(vec![reference(0, 1, Hash::zero())], 1, 0)?;
    let mut foreign = reference(0, 1, hash(4));
    foreign.materialization.artifact_class = ErasureArtifactClassV1::CausalTrace;
    let mut unbound = reference(0, 1, hash(4));
    unbound.materialization.attestation_address = Hash::zero();
    for input in [
        zero_vector,
        zero_fragment,
        manifest_input(vec![foreign], 1, 0)?,
        manifest_input(vec![unbound], 1, 0)?,
    ] {
        assert_eq!(Manifest::new(input).err(), Some(Error::InvalidBinding));
    }
    let mut wire = manifest_value(&[(0, 1, 4)], 1, 0)?;
    fields(&mut wire)?[6] = bytes(&[0; 32]);
    assert_eq!(
        Manifest::from_canonical_cbor(&encode(&wire)?).err(),
        Some(Error::InvalidBinding)
    );
    Ok(())
}

#[test]
fn manifest_rejects_truncation_trailer_version_size_and_malformed_rows() -> TestResult {
    let encoded = encode(&manifest_value(&[(0, 1, 4)], 1, 0)?)?;
    for end in 0..encoded.len() {
        assert!(Manifest::from_canonical_cbor(&encoded[..end]).is_err());
    }
    let mut trailing = encoded;
    trailing.push(0);
    assert_eq!(
        Manifest::from_canonical_cbor(&trailing).err(),
        Some(Error::InvalidEncoding)
    );
    let mut version = manifest_value(&[(0, 1, 4)], 1, 0)?;
    fields(&mut version)?[1] = uint(2);
    assert_eq!(
        Manifest::from_canonical_cbor(&encode(&version)?).err(),
        Some(Error::UnsupportedVersion)
    );
    for row in [
        Value::Null,
        Value::Array(vec![uint(0), uint(1), bytes(&[4; 32])]),
        Value::Array(vec![
            uint(0),
            uint(1),
            bytes(&[4; 31]),
            materialization_value(),
        ]),
    ] {
        let mut malformed = manifest_value(&[], 1, 0)?;
        fields(&mut malformed)?[3] = Value::Array(vec![row]);
        assert_eq!(
            Manifest::from_canonical_cbor(&encode(&malformed)?).err(),
            Some(Error::InvalidEncoding)
        );
    }
    let encoded = encode(&manifest_value(&[(0, 1, 4)], 1, 0)?)?;
    let mut nonshortest = encoded.clone();
    let total_at = encoded.len() - 36;
    if nonshortest[total_at..total_at + 2] != [0x01, 0x00] {
        return Err("fixture total is not where expected".into());
    }
    nonshortest.splice(total_at..=total_at, [0x18, 0x01]);
    for form in indefinite_forms(&encoded)?.into_iter().chain([nonshortest]) {
        assert_eq!(
            Manifest::from_canonical_cbor(&form).err(),
            Some(Error::InvalidEncoding)
        );
    }
    let limit = MAX_COMMUNITY_EVENT_DRAFT_MANIFEST_BYTES_V1;
    assert_eq!(limit, 65_536);
    assert_eq!(
        Manifest::from_canonical_cbor(&vec![0; limit]).err(),
        Some(Error::InvalidEncoding)
    );
    assert_eq!(
        Manifest::from_canonical_cbor(&vec![0; limit + 1]).err(),
        Some(Error::BoundsExceeded)
    );
    Ok(())
}

#[test]
fn empty_vector_is_one_byte_array_in_one_fragment() -> TestResult {
    let vector = vector_bytes(&[])?;
    assert_eq!(&*vector, &[0x80]);
    let (manifest, fragments) = sealed(&vector, MAX_FRAGMENT, &[])?;
    assert_eq!(manifest.as_input().fragments.len(), 1);
    assert_eq!(manifest.as_input().total_plaintext_bytes, 1);
    assert!(manifest.reconstruct(&fragments)?.is_empty());
    Ok(())
}

#[test]
fn draft_vector_matches_independent_oracle_and_reconstructs_exactly() -> TestResult {
    let drafts = vec![
        plain_draft(vec![1, 2, 3]),
        full_draft(vec![4; 30], 23),
        full_draft(Vec::new(), u64::MAX),
    ];
    let vector = vector_bytes(&drafts)?;
    let oracle = encode(&Value::Array(drafts.iter().map(draft_value).collect()))?;
    assert_eq!(&*vector, &oracle);
    for chunk in [1, 7, MAX_FRAGMENT] {
        let (manifest, fragments) = sealed(&vector, chunk, &drafts)?;
        assert_eq!(manifest.reconstruct(&fragments)?, drafts);
        let encoded = manifest.to_canonical_cbor();
        assert_eq!(
            Manifest::from_canonical_cbor(&encoded)?.reconstruct(&fragments)?,
            drafts
        );
    }
    Ok(())
}

#[test]
fn draft_vector_count_and_byte_bounds_are_exact() -> TestResult {
    let many = vec![plain_draft(Vec::new()); 1024];
    let vector = vector_bytes(&many)?;
    let (manifest, fragments) = sealed(&vector, MAX_FRAGMENT, &many)?;
    assert_eq!(manifest.reconstruct(&fragments)?.len(), 1024);
    assert_eq!(
        vector_bytes(&vec![plain_draft(Vec::new()); 1025]).err(),
        Some(Error::BoundsExceeded)
    );
    // One-draft vectors at exactly 64 MiB and one byte over, for null
    // optionals, full-width optionals, and a 24-byte type (two-byte text
    // head) with a mid-width (five-byte) wall time and one null identifier.
    // The overhead is measured with the independent oracle at a payload
    // length of the same five-byte head width.
    let forms: [fn(usize) -> EventDraft; 3] = [
        |length| plain_draft(vec![0; length]),
        |length| full_draft(vec![0; length], u64::MAX),
        |length| {
            let mut draft = full_draft(vec![0; length], 70_000);
            draft.event_type = Kind::new("x".repeat(24));
            draft.correlation_id = None;
            draft
        },
    ];
    for (index, make) in forms.into_iter().enumerate() {
        let probe = 70_000;
        let overhead = encode(&Value::Array(vec![draft_value(&make(probe))]))?.len() - probe;
        let exact = [make(MAX_VECTOR - overhead)];
        let vector = vector_bytes(&exact)?;
        assert_eq!(vector.len(), MAX_VECTOR);
        assert_eq!(
            vector_bytes(&[make(MAX_VECTOR - overhead + 1)]).err(),
            Some(Error::BoundsExceeded)
        );
        if index == 0 {
            let (manifest, fragments) = sealed(&vector, MAX_FRAGMENT, &exact)?;
            assert_eq!(fragments.len(), 256);
            assert_eq!(manifest.reconstruct(&fragments)?, exact);
        }
    }
    Ok(())
}

#[test]
fn draft_vector_keeps_the_existing_draft_rule() -> TestResult {
    let mut nil_entity = plain_draft(vec![0; 4]);
    nil_entity.entity = EntityId::from_ulid(Ulid::nil());
    let mut empty_type = plain_draft(vec![0; 4]);
    empty_type.event_type = Kind::new("");
    for draft in [nil_entity, empty_type] {
        assert_eq!(
            vector_bytes(std::slice::from_ref(&draft)).err(),
            Some(Error::InvalidBinding)
        );
        let vector = encode(&Value::Array(vec![draft_value(&draft)]))?;
        let (manifest, fragments) = sealed_as(&vector, MAX_FRAGMENT, 1, hash(9))?;
        assert_eq!(
            manifest.reconstruct(&fragments).err(),
            Some(Error::InvalidBinding)
        );
    }
    // Nil causation and correlation identifiers are existing valid fields.
    let mut nil_links = full_draft(vec![1], 1);
    nil_links.causation_id = Some(EventId::from_ulid(Ulid::nil()));
    nil_links.correlation_id = Some(CorrelationId::from_ulid(Ulid::nil()));
    let drafts = [nil_links];
    let vector = vector_bytes(&drafts)?;
    let (manifest, fragments) = sealed(&vector, MAX_FRAGMENT, &drafts)?;
    assert_eq!(manifest.reconstruct(&fragments)?, drafts);
    Ok(())
}

#[test]
fn reconstruction_rejects_malformed_vectors() -> TestResult {
    let valid = draft_value(&full_draft(vec![1], 2));
    let with = |index: usize, value: Value| -> Fallible<Vec<u8>> {
        let mut draft = valid.clone();
        fields(&mut draft)?[index] = value;
        encode(&Value::Array(vec![draft]))
    };
    let one = encode(&Value::Array(vec![valid.clone()]))?;
    let mut trailing = one.clone();
    trailing.push(0);
    let mut too_many = vec![0x99, 0x04, 0x01];
    too_many.extend(std::iter::repeat_n(0, 30));
    let mut wide = vec![0x98, 0x01];
    wide.extend_from_slice(&one[1..]);
    let mut short_entity = valid.clone();
    fields(&mut short_entity)?[0] = bytes(&[5; 15]);
    let mut six_fields = valid.clone();
    fields(&mut six_fields)?.pop();
    for (vector, error) in [
        (with(5, uint(2))?, Error::InvalidEncoding),
        (with(6, Value::Text("t".into()))?, Error::InvalidEncoding),
        (with(3, bytes(&[6; 15]))?, Error::InvalidEncoding),
        (with(1, bytes(b"a"))?, Error::InvalidEncoding),
        (with(1, Value::Text(String::new()))?, Error::InvalidBinding),
        (
            encode(&Value::Array(vec![six_fields]))?,
            Error::InvalidEncoding,
        ),
        (
            encode(&Value::Array(vec![short_entity]))?,
            Error::InvalidEncoding,
        ),
        (
            {
                let mut bad = with(1, Value::Text("ab".into()))?;
                let at = bad
                    .windows(3)
                    .position(|w| w == [0x62, b'a', b'b'])
                    .ok_or("text")?;
                bad[at + 1] = 0xff;
                bad
            },
            Error::InvalidEncoding,
        ),
        (trailing, Error::InvalidEncoding),
        (too_many, Error::BoundsExceeded),
        (wide, Error::InvalidEncoding),
    ] {
        let (manifest, fragments) = sealed_as(&vector, MAX_FRAGMENT, 1, hash(9))?;
        assert_eq!(manifest.reconstruct(&fragments).err(), Some(error));
    }
    Ok(())
}

#[test]
fn reconstruction_binds_count_digest_and_every_fragment_field() -> TestResult {
    let drafts = [plain_draft(vec![1; 40])];
    let vector = vector_bytes(&drafts)?;
    let total = vector.len() as u64;
    let (manifest, fragments) = sealed(&vector, 4, &drafts)?;
    assert!(manifest.reconstruct(&fragments[..1]).is_err());
    let mut count = manifest.as_input().clone();
    count.draft_count = 2;
    let mut vector_digest = manifest.as_input().clone();
    vector_digest.draft_vector_digest = hash(9);
    for input in [count, vector_digest] {
        assert_eq!(
            Manifest::new(input)?.reconstruct(&fragments).err(),
            Some(Error::InvalidBinding)
        );
    }
    // Substitute the second fragment with one whose own digest is referenced,
    // so that only the named field disagrees with the manifest.
    let mut other_pass = fragment_input(4, total, &vector[4..8])?;
    other_pass.pass_key = pass(4)?;
    for substitute in [
        other_pass,
        fragment_input(3, total, &vector[3..7])?,
        fragment_input(4, total + 1, &vector[4..8])?,
        fragment_input(4, total, &vector[4..7])?,
    ] {
        let substitute = Fragment::new(substitute)?;
        let mut input = manifest.as_input().clone();
        input.fragments[1].fragment_digest = substitute.digest();
        let manifest = Manifest::new(input)?;
        let mut set = Vec::new();
        for (index, fragment) in fragments.iter().enumerate() {
            set.push(if index == 1 {
                Fragment::new(*substitute.as_input())?
            } else {
                Fragment::new(*fragment.as_input())?
            });
        }
        assert_eq!(
            manifest.reconstruct(&set).err(),
            Some(Error::InvalidBinding)
        );
        set[1] = Fragment::new(*fragments[1].as_input())?;
        assert_eq!(
            manifest.reconstruct(&set).err(),
            Some(Error::InvalidBinding)
        );
    }
    let mut stale = manifest.as_input().clone();
    stale.fragments[1].fragment_digest = hash(8);
    assert_eq!(
        Manifest::new(stale)?.reconstruct(&fragments).err(),
        Some(Error::InvalidBinding)
    );
    Ok(())
}
