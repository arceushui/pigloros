//! Independent CAT1 wire oracles, not presentation retention evidence.

use ciborium::value::Value;
use pos_core::community_lifecycle::{
    CommunityAnnotationItemV1 as Item, CommunityAnnotationManifestInputV1 as Input,
    CommunityAnnotationManifestV1 as Manifest, CommunityClaimArtifactV1 as Artifact,
    CommunityDigestListV1 as Digests, CommunityGuestClaimContextV1 as Context,
    CommunityLifecycleErrorV1 as Error, CommunityPassKeyV1 as Pass,
    COMMUNITY_CLAIM_STATE_SCHEMA_V1 as STATE_SCHEMA, MAX_COMMUNITY_ANNOTATION_CLAIM_BYTES_V1,
    MAX_COMMUNITY_ANNOTATION_GUEST_INDEX_V1, MAX_COMMUNITY_ANNOTATION_INPUT_REFS_V1,
    MAX_COMMUNITY_ANNOTATION_ITEMS_V1, MAX_COMMUNITY_ANNOTATION_MANIFEST_BYTES_V1,
};
use pos_core::{Hash, TimelineId};

type Fallible<T> = Result<T, Box<dyn std::error::Error>>;
type TestResult = Fallible<()>;

const MAX_BYTES: usize = 2_097_152;
const MAX_CLAIMS: usize = 1_048_576;

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
fn pass_value() -> Value {
    Value::Array(vec![
        bytes(b"CPK1"),
        uint(1),
        bytes(&[1; 16]),
        bytes(&[2; 16]),
        uint(3),
    ])
}
/// `count` distinct strictly ascending digests.
fn ascending(count: u32) -> Vec<Hash> {
    (0..count)
        .map(|index| {
            let mut digest = [0xaa; 32];
            digest[..4].copy_from_slice(&index.to_be_bytes());
            Hash::from_bytes(digest)
        })
        .collect()
}
struct Row<'a> {
    index: u64,
    claim: &'a [u8],
    digests: &'a [Hash],
}
fn input<'a>(rows: &[Row<'a>]) -> Fallible<Input<'a>> {
    Ok(Input {
        pass_key: Pass::new(
            TimelineId::from_ulid(ulid::Ulid::from_bytes([1; 16])),
            [2; 16],
            3,
        )?,
        member_binding_digest: hash(4),
        invocation_step_digest: hash(5),
        items: rows
            .iter()
            .map(|row| Item {
                guest_index: row.index,
                claim_bytes: row.claim,
                resolved_input_digests: Digests::from_digests(row.digests),
            })
            .collect(),
        evidence_not_after_micros: 6,
    })
}
fn fixture(rows: &[Row<'_>]) -> Fallible<Value> {
    Ok(Value::Array(vec![
        bytes(b"CAT1"),
        uint(1),
        bytes(&encode(&pass_value())?),
        bytes(&[4; 32]),
        bytes(&[5; 32]),
        Value::Array(
            rows.iter()
                .map(|row| {
                    Value::Array(vec![
                        uint(row.index),
                        bytes(row.claim),
                        Value::Array(
                            row.digests
                                .iter()
                                .map(|digest| bytes(digest.as_bytes()))
                                .collect(),
                        ),
                    ])
                })
                .collect(),
        ),
        uint(6),
    ]))
}
/// Construction and decoding both give `expected`; a valid record also
/// encodes exactly as the oracle does.
fn check(rows: &[Row<'_>], expected: Option<Error>) -> TestResult {
    let built = Manifest::new(input(rows)?);
    let encoded = encode(&fixture(rows)?)?;
    assert_eq!(built.as_ref().err(), expected.as_ref());
    assert_eq!(Manifest::from_canonical_cbor(&encoded).err(), expected);
    if let Ok(manifest) = built {
        assert_eq!(&*manifest.to_canonical_cbor(), &encoded);
    }
    Ok(())
}
const fn row<'a>(index: u64, claim: &'a [u8], digests: &'a [Hash]) -> Row<'a> {
    Row {
        index,
        claim,
        digests,
    }
}

#[test]
fn manifest_has_exact_seven_fields_digest_and_borrowed_items() -> TestResult {
    let digests = ascending(2);
    let rows = [row(0, b"claim", &digests), row(7, b"x", &[])];
    let manifest = Manifest::new(input(&rows)?)?;
    let expected = encode(&fixture(&rows)?)?;
    assert_eq!(&*manifest.to_canonical_cbor(), &expected);
    let mut preimage = b"PiglorOS.Community.CAT1.v1\0".to_vec();
    preimage.extend_from_slice(&expected);
    assert_eq!(
        manifest.digest(),
        Hash::from_bytes(*blake3::hash(&preimage).as_bytes())
    );
    let decoded = Manifest::from_canonical_cbor(&expected)?;
    assert!(*decoded.as_input() == input(&rows)?);
    let claim = decoded.as_input().items[0].claim_bytes;
    let offset = claim.as_ptr() as usize - expected.as_ptr() as usize;
    assert_eq!(&expected[offset..offset + claim.len()], b"claim");
    let listed: Vec<Hash> = decoded.as_input().items[0]
        .resolved_input_digests
        .iter()
        .collect();
    assert_eq!(listed, digests);
    Ok(())
}

#[test]
fn item_count_bound_is_exact_and_never_empty() -> TestResult {
    assert_eq!(MAX_COMMUNITY_ANNOTATION_ITEMS_V1, 1024);
    let many: Vec<Row<'_>> = (0..1025).map(|_| row(0, b"c", &[])).collect();
    check(&[], Some(Error::BoundsExceeded))?;
    check(&many[..1], None)?;
    check(&many[..1024], None)?;
    check(&many, Some(Error::BoundsExceeded))
}

#[test]
fn guest_index_is_at_most_63_and_nondecreasing() -> TestResult {
    assert_eq!(MAX_COMMUNITY_ANNOTATION_GUEST_INDEX_V1, 63);
    check(&[row(63, b"c", &[])], None)?;
    check(&[row(64, b"c", &[])], Some(Error::BoundsExceeded))?;
    check(&[row(3, b"c", &[]), row(3, b"d", &[])], None)?;
    check(&[row(3, b"c", &[]), row(4, b"d", &[])], None)?;
    check(
        &[row(4, b"c", &[]), row(3, b"d", &[])],
        Some(Error::InvalidBinding),
    )
}

#[test]
fn resolved_digests_are_bounded_nonzero_and_strictly_ascending() -> TestResult {
    assert_eq!(MAX_COMMUNITY_ANNOTATION_INPUT_REFS_V1, 4096);
    let digests = ascending(4097);
    check(&[row(0, b"c", &digests[..4096])], None)?;
    check(&[row(0, b"c", &digests)], Some(Error::BoundsExceeded))?;
    for invalid in [
        vec![Hash::zero()],
        vec![hash(7), hash(7)],
        vec![hash(8), hash(7)],
    ] {
        check(&[row(0, b"c", &invalid)], Some(Error::InvalidBinding))?;
    }
    Ok(())
}

#[test]
fn summed_claim_bytes_bound_is_exact() -> TestResult {
    assert_eq!(MAX_COMMUNITY_ANNOTATION_CLAIM_BYTES_V1, MAX_CLAIMS);
    let claims = vec![1; MAX_CLAIMS + 1];
    let half = MAX_CLAIMS / 2;
    check(&[row(0, &claims[..MAX_CLAIMS], &[])], None)?;
    check(
        &[row(0, &claims[..half], &[]), row(1, &claims[..half], &[])],
        None,
    )?;
    check(&[row(0, &claims, &[])], Some(Error::BoundsExceeded))?;
    check(
        &[row(0, &claims[..half], &[]), row(1, &claims[..=half], &[])],
        Some(Error::BoundsExceeded),
    )
}

#[test]
fn whole_encoding_bound_is_exact() -> TestResult {
    assert_eq!(MAX_COMMUNITY_ANNOTATION_MANIFEST_BYTES_V1, MAX_BYTES);
    let digests = ascending(4096);
    let claim = vec![2; 20_000];
    let probe = 1000;
    let rows = |first: usize| -> Vec<Row<'_>> {
        (0..15)
            .map(|index| {
                row(
                    0,
                    if index == 0 {
                        &claim[..first]
                    } else {
                        &claim[..1]
                    },
                    &digests,
                )
            })
            .collect()
    };
    let measured = encode(&fixture(&rows(probe))?)?.len();
    let first = probe + (MAX_BYTES - measured);
    let exact = rows(first);
    assert_eq!(encode(&fixture(&exact)?)?.len(), MAX_BYTES);
    check(&exact, None)?;
    let over = rows(first + 1);
    assert_eq!(
        Manifest::new(input(&over)?).err(),
        Some(Error::BoundsExceeded)
    );
    assert_eq!(
        Manifest::from_canonical_cbor(&encode(&fixture(&over)?)?).err(),
        Some(Error::BoundsExceeded)
    );
    Ok(())
}

#[test]
fn manifest_rejects_zero_links_and_invalid_horizon() -> TestResult {
    let rows = [row(0, b"c", &[])];
    for index in 0..2 {
        let mut input = input(&rows)?;
        if index == 0 {
            input.member_binding_digest = Hash::zero();
        } else {
            input.invocation_step_digest = Hash::zero();
        }
        assert_eq!(Manifest::new(input).err(), Some(Error::InvalidBinding));
    }
    for (horizon, valid) in [
        (1, true),
        (u64::MAX / 2, true),
        (0, false),
        (u64::MAX / 2 + 1, false),
    ] {
        let mut input = input(&rows)?;
        input.evidence_not_after_micros = horizon;
        assert_eq!(Manifest::new(input).is_ok(), valid);
    }
    Ok(())
}

#[test]
fn manifest_rejects_truncation_trailer_version_and_noncanonical_forms() -> TestResult {
    let rows = [row(5, b"c", &[])];
    let encoded = encode(&fixture(&rows)?)?;
    for end in 0..encoded.len() {
        assert!(Manifest::from_canonical_cbor(&encoded[..end]).is_err());
    }
    let mut trailing = encoded.clone();
    trailing.push(0);
    let mut version = fixture(&rows)?;
    fields(&mut version)?[1] = uint(2);
    assert_eq!(
        Manifest::from_canonical_cbor(&encode(&version)?).err(),
        Some(Error::UnsupportedVersion)
    );
    let end = 9 + usize::from(encoded[8]);
    let index_at = end + 68 + 2;
    if encoded[7] != 0x58 || encoded[index_at - 1..=index_at] != [0x83, 0x05] {
        return Err("fixture layout changed".into());
    }
    let mut nonshortest = encoded.clone();
    nonshortest.splice(index_at..=index_at, [0x18, 0x05]);
    let mut array = vec![0x9f];
    array.extend_from_slice(&encoded[1..]);
    array.push(0xff);
    let mut string = encoded[..7].to_vec();
    string.push(0x5f);
    string.extend_from_slice(&encoded[7..end]);
    string.push(0xff);
    string.extend_from_slice(&encoded[end..]);
    for form in [trailing, nonshortest, array, string] {
        assert_eq!(
            Manifest::from_canonical_cbor(&form).err(),
            Some(Error::InvalidEncoding)
        );
    }
    for item in [
        Value::Null,
        Value::Array(vec![uint(0), bytes(b"c")]),
        Value::Array(vec![uint(0), Value::Text("c".into()), Value::Array(vec![])]),
        Value::Array(vec![
            uint(0),
            bytes(b"c"),
            Value::Array(vec![bytes(&[1; 31])]),
        ]),
    ] {
        let mut malformed = fixture(&rows)?;
        fields(&mut malformed)?[5] = Value::Array(vec![item]);
        assert_eq!(
            Manifest::from_canonical_cbor(&encode(&malformed)?).err(),
            Some(Error::InvalidEncoding)
        );
    }
    assert_eq!(
        Manifest::from_canonical_cbor(&vec![0; MAX_BYTES]).err(),
        Some(Error::InvalidEncoding)
    );
    assert_eq!(
        Manifest::from_canonical_cbor(&vec![0; MAX_BYTES + 1]).err(),
        Some(Error::BoundsExceeded)
    );
    Ok(())
}

#[test]
fn every_retained_claim_is_compared_with_the_actual_invocation() -> TestResult {
    let artifact = |schema: u32, byte: u8| Artifact {
        schema,
        digest: hash(byte),
    };
    let context = Context {
        inputs: [
            artifact(10, 1),
            artifact(STATE_SCHEMA, 2),
            artifact(12, 3),
            artifact(13, 4),
        ],
        next_state: artifact(STATE_SCHEMA, 5),
        event_drafts: &[],
        execution_profile_digest: hash(6),
    };
    let claim = |policy: u8| {
        encode(&Value::Array(vec![
            bytes(b"GCA1"),
            uint(1),
            uint(0),
            Value::Array(vec![Value::Array(vec![uint(0), uint(10), bytes(&[1; 32])])]),
            Value::Array(vec![]),
            bytes(&[policy; 32]),
        ]))
    };
    let valid = claim(6)?;
    let substituted = claim(7)?;
    let manifest = Manifest::new(input(&[row(0, &valid, &[]), row(1, &valid, &[])])?)?;
    assert!(manifest.validate_claims(&context).is_ok());
    let manifest = Manifest::new(input(&[row(0, &valid, &[]), row(1, &substituted, &[])])?)?;
    assert_eq!(
        manifest.validate_claims(&context).err(),
        Some(Error::InvalidBinding)
    );
    Ok(())
}
