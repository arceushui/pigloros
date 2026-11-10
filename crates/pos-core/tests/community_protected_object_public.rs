//! Independent COW1/CAR1/COA1 oracles; parsed records never authorize use.

#[path = "support/community_nonce_properties.rs"]
pub mod nonce_properties;

use ciborium::value::Value;
use pos_core::community_lifecycle::{
    CommunityArtifactAdmissionInputV1 as AdmissionInput, CommunityArtifactAdmissionV1 as Admission,
    CommunityArtifactChildrenV1 as Children, CommunityArtifactHeaderInputV1 as HeaderInput,
    CommunityArtifactHeaderV1 as Header, CommunityArtifactKindV1 as Kind,
    CommunityArtifactOperationV1 as Operation, CommunityArtifactPurposeV1 as Purpose,
    CommunityClassificationProofInputV1 as ProofInput, CommunityClassificationProofV1 as Proof,
    CommunityEncryptedEnvelopeV1 as Envelope, CommunityLifecycleErrorV1 as Error,
    CommunityProtectedObjectV1 as Object,
    MAX_COMMUNITY_ENVELOPE_PLAINTEXT_BYTES_V1 as MAX_PLAINTEXT,
};
use pos_core::{
    ArtifactChildEdgeV1, ArtifactRegistrationV1, ErasureArtifactClassV1 as Class, Hash, TimelineId,
};
use proptest::arbitrary::any;

type Fallible<T> = Result<T, Box<dyn std::error::Error>>;
type TestResult = Fallible<()>;

const fn hash(byte: u8) -> Hash {
    Hash::from_bytes([byte; 32])
}
const fn header_input() -> HeaderInput {
    HeaderInput {
        timeline: TimelineId::from_ulid(ulid::Ulid::from_bytes([1; 16])),
        generation: [2; 16],
        purpose: Purpose::ExecutionState,
        operation: Operation::Control([3; 16]),
        record_kind: Kind::StateContent,
        scope_cover_digest: hash(4),
        evidence_not_after_micros: 5,
    }
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
fn envelope(input: HeaderInput, length: usize, nonce: [u8; 12]) -> Result<Vec<u8>, Error> {
    let ciphertext = vec![6; length];
    let envelope = Envelope::new(Header::new(input)?, nonce, &ciphertext)?;
    Ok(envelope.to_canonical_cbor().to_vec())
}
const fn proof_header() -> HeaderInput {
    HeaderInput {
        record_kind: Kind::ClassificationProof,
        ..header_input()
    }
}
fn object_value(content: &[u8], proof: &[u8]) -> Value {
    Value::Array(vec![bytes(b"COW1"), uint(1), bytes(content), bytes(proof)])
}
fn domain_hash(domain: &[u8], bytes: &[u8]) -> Hash {
    let mut preimage = domain.to_vec();
    preimage.push(0);
    preimage.extend_from_slice(bytes);
    Hash::from_bytes(*blake3::hash(&preimage).as_bytes())
}
const fn admission_input(generation: u64) -> AdmissionInput {
    AdmissionInput {
        protected_object_address: hash(1),
        artifact_digest: hash(2),
        registration_address: hash(3),
        owner_binding_digest: hash(4),
        scope_cover_digest: hash(5),
        evidence_not_after_micros: 6,
        admission_inventory_generation: generation,
        authority_evidence_digest: hash(7),
    }
}
fn admission_value(generation: u64) -> Value {
    Value::Array(vec![
        bytes(b"COA1"),
        uint(1),
        bytes(&[1; 32]),
        bytes(&[2; 32]),
        bytes(&[3; 32]),
        bytes(&[4; 32]),
        bytes(&[5; 32]),
        uint(6),
        uint(generation),
        bytes(&[7; 32]),
    ])
}
const fn proof_input<'a>(
    header: &'a Header,
    children: &'a [ArtifactChildEdgeV1],
) -> ProofInput<'a> {
    ProofInput {
        header,
        owner_binding_digest: hash(8),
        plaintext_commitment: hash(9),
        envelope_address: hash(10),
        children: Children::from_children(children),
        host_provenance_digest: hash(11),
    }
}
const fn child(class: Class, byte: u8, required: bool) -> ArtifactChildEdgeV1 {
    ArtifactChildEdgeV1 {
        artifact_class: class,
        artifact_digest: hash(byte),
        registration_address: hash(12),
        required,
    }
}
fn proof_value() -> Fallible<Value> {
    let key = Value::Array(vec![
        Value::Text(format!(
            "community:{}:{}:0:c:{}",
            "01".repeat(16),
            "02".repeat(16),
            "03".repeat(16)
        )),
        uint(7),
        uint(1),
    ]);
    Ok(Value::Array(vec![
        bytes(b"CAR1"),
        uint(1),
        bytes(&[8; 32]),
        bytes(&[1; 16]),
        bytes(&[2; 16]),
        uint(0),
        uint(0),
        bytes(&[9; 32]),
        bytes(&[10; 32]),
        bytes(&[4; 32]),
        uint(0),
        Value::Array(vec![]),
        bytes(&encode(&key)?),
        uint(5),
        bytes(&[11; 32]),
    ]))
}
fn fields(value: &mut Value) -> Fallible<&mut Vec<Value>> {
    match value {
        Value::Array(values) => Ok(values),
        _ => Err("fixture is not an array".into()),
    }
}

#[test]
fn object_exact_wire_domains_and_borrowed_ranges() -> TestResult {
    nonce_properties::check(any::<[u8; 12]>(), |nonce| {
        let content = envelope(header_input(), 16, nonce)?;
        let companion = envelope(proof_header(), 16, nonce)?;
        let expected = encode(&object_value(&content, &companion))?;
        let object = Object::new(&content, &companion)?;
        assert_eq!(&*object.to_canonical_cbor(), &expected);
        assert_eq!(
            object.address(),
            domain_hash(b"PiglorOS.Community.ProtectedObject.v1", &expected)
        );
        assert_ne!(
            object.address(),
            ArtifactRegistrationV1::artifact_digest(Class::TimelineReplay, &expected)
        );
        let decoded = Object::from_canonical_cbor(&expected)?;
        assert_eq!(decoded.content_envelope(), &content);
        assert_eq!(decoded.proof_envelope(), &companion);
        let start = expected.as_ptr() as usize;
        for borrowed in [decoded.content_envelope(), decoded.proof_envelope()] {
            let offset = borrowed.as_ptr() as usize - start;
            assert!(offset + borrowed.len() <= expected.len());
            assert_eq!(&expected[offset..offset + borrowed.len()], borrowed);
        }
        Ok(())
    })
}

#[test]
fn object_rejects_every_companion_context_substitution() -> TestResult {
    nonce_properties::check(any::<[u8; 12]>(), |nonce| {
        let content = envelope(header_input(), 16, nonce)?;
        let mut substitutions = [proof_header(); 7];
        substitutions[0].timeline = TimelineId::from_ulid(ulid::Ulid::from_bytes([9; 16]));
        substitutions[1].generation = [9; 16];
        substitutions[2].purpose = Purpose::ReplayEvidence;
        substitutions[3].operation = Operation::Initialization([3; 16]);
        substitutions[4].record_kind = Kind::StateContent;
        substitutions[5].scope_cover_digest = hash(9);
        substitutions[6].evidence_not_after_micros = 9;
        for input in substitutions {
            let companion = envelope(input, 16, nonce)?;
            assert_eq!(
                Object::new(&content, &companion).err(),
                Some(Error::InvalidBinding)
            );
        }
        Ok(())
    })
}

#[test]
fn object_accepts_payload_limits_and_refuses_larger_proof() -> TestResult {
    nonce_properties::check(any::<[u8; 12]>(), |nonce| {
        let content = envelope(header_input(), MAX_PLAINTEXT + 16, nonce)?;
        let companion = envelope(proof_header(), 512 * 1024 + 16, nonce)?;
        let encoded = Object::new(&content, &companion)?.to_canonical_cbor();
        assert!(encoded.len() < 4 * 1024 * 1024);
        assert_eq!(
            Object::from_canonical_cbor(&encoded)?.content_envelope(),
            &content
        );
        let too_large = envelope(proof_header(), 512 * 1024 + 17, nonce)?;
        assert_eq!(
            Object::new(&content, &too_large).err(),
            Some(Error::BoundsExceeded)
        );
        assert_eq!(
            Object::from_canonical_cbor(&vec![0; 4 * 1024 * 1024 + 1]).err(),
            Some(Error::BoundsExceeded)
        );
        Ok(())
    })
}

#[test]
fn object_rejects_framing_and_invalid_nested_records() -> TestResult {
    nonce_properties::check(any::<[u8; 12]>(), |nonce| {
        let content = envelope(header_input(), 16, nonce)?;
        let companion = envelope(proof_header(), 16, nonce)?;
        let encoded = encode(&object_value(&content, &companion))?;
        for end in 0..encoded.len() {
            assert!(Object::from_canonical_cbor(&encoded[..end]).is_err());
        }
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert_eq!(
            Object::from_canonical_cbor(&trailing).err(),
            Some(Error::InvalidEncoding)
        );
        let mut unsupported = object_value(&content, &companion);
        fields(&mut unsupported)?[1] = uint(2);
        assert_eq!(
            Object::from_canonical_cbor(&encode(&unsupported)?).err(),
            Some(Error::UnsupportedVersion)
        );
        let mut nonpreferred = encoded;
        nonpreferred.splice(6..7, [0x18, 1]);
        assert_eq!(
            Object::from_canonical_cbor(&nonpreferred).err(),
            Some(Error::InvalidEncoding)
        );
        for value in [object_value(&[], &companion), object_value(&content, &[])] {
            assert!(Object::from_canonical_cbor(&encode(&value)?).is_err());
        }
        Ok(())
    })
}

#[test]
fn admission_has_exact_wire_and_distinct_current_authority_binding() -> TestResult {
    for generation in [0, 23, 24, 255, 256, u64::MAX] {
        let input = admission_input(generation);
        let record = Admission::new(input)?;
        let expected = encode(&admission_value(generation))?;
        assert_eq!(&*record.to_canonical_cbor(), &expected);
        assert!(*Admission::from_canonical_cbor(&expected)?.as_input() == input);
        assert_eq!(
            record.digest(),
            domain_hash(b"PiglorOS.Community.ArtifactAdmission.v1", &expected)
        );
    }
    Ok(())
}

#[test]
fn admission_rejects_zero_links_and_invalid_horizons() {
    for field in 0..6 {
        let mut input = admission_input(0);
        match field {
            0 => input.protected_object_address = Hash::zero(),
            1 => input.artifact_digest = Hash::zero(),
            2 => input.registration_address = Hash::zero(),
            3 => input.owner_binding_digest = Hash::zero(),
            4 => input.scope_cover_digest = Hash::zero(),
            _ => input.authority_evidence_digest = Hash::zero(),
        }
        assert_eq!(Admission::new(input).err(), Some(Error::InvalidBinding));
    }
    for horizon in [0, u64::MAX / 2 + 1, u64::MAX] {
        let input = AdmissionInput {
            evidence_not_after_micros: horizon,
            ..admission_input(0)
        };
        assert_eq!(Admission::new(input).err(), Some(Error::BoundsExceeded));
    }
    assert!(Admission::new(AdmissionInput {
        evidence_not_after_micros: u64::MAX / 2,
        ..admission_input(0)
    })
    .is_ok());
}

#[test]
fn admission_rejects_all_truncations_trailing_versions_and_nonpreferred() -> TestResult {
    let encoded = encode(&admission_value(0))?;
    for end in 0..encoded.len() {
        assert!(Admission::from_canonical_cbor(&encoded[..end]).is_err());
    }
    let mut trailing = encoded.clone();
    trailing.push(0);
    assert_eq!(
        Admission::from_canonical_cbor(&trailing).err(),
        Some(Error::InvalidEncoding)
    );
    let mut unsupported = admission_value(0);
    fields(&mut unsupported)?[1] = uint(2);
    assert_eq!(
        Admission::from_canonical_cbor(&encode(&unsupported)?).err(),
        Some(Error::UnsupportedVersion)
    );
    let mut nonpreferred = encoded;
    nonpreferred.splice(6..7, [0x18, 1]);
    assert_eq!(
        Admission::from_canonical_cbor(&nonpreferred).err(),
        Some(Error::InvalidEncoding)
    );
    assert_eq!(
        Admission::from_canonical_cbor(&vec![0; 1025]).err(),
        Some(Error::BoundsExceeded)
    );
    Ok(())
}

#[test]
fn classification_exact_wire_and_protected_identity() -> TestResult {
    let header = Header::new(header_input())?;
    let proof = Proof::new(proof_input(&header, &[]))?;
    let expected = encode(&proof_value()?)?;
    assert_eq!(&*proof.to_canonical_cbor(), &expected);
    assert_eq!(
        proof.digest(),
        domain_hash(b"PiglorOS.Community.ClassificationProof.v1", &expected)
    );
    let decoded = Proof::from_canonical_cbor(&expected, &header)?;
    assert_eq!(&*decoded.to_canonical_cbor(), &expected);
    assert!(decoded.as_input().children.is_empty());
    assert!(proof.as_input().children.as_canonical_rows().is_none());
    Ok(())
}

#[test]
fn classification_rejects_context_class_key_and_horizon_substitutions() -> TestResult {
    let header = Header::new(header_input())?;
    let changes = [
        (3, bytes(&[9; 16])),
        (4, bytes(&[9; 16])),
        (5, uint(2)),
        (6, uint(1)),
        (9, bytes(&[9; 32])),
        (10, uint(1)),
        (13, uint(6)),
    ];
    for (index, value) in changes {
        let mut fixture = proof_value()?;
        fields(&mut fixture)?[index] = value;
        assert_eq!(
            Proof::from_canonical_cbor(&encode(&fixture)?, &header).err(),
            Some(Error::InvalidBinding)
        );
    }
    for key in [
        Value::Array(vec![Value::Text("other".into()), uint(7), uint(1)]),
        Value::Array(vec![
            Value::Text(format!(
                "community:{}:{}:0:c:{}",
                "01".repeat(16),
                "02".repeat(16),
                "03".repeat(16)
            )),
            uint(0),
            uint(1),
        ]),
        Value::Array(vec![Value::Text("other".into()), uint(7), uint(2)]),
    ] {
        let mut fixture = proof_value()?;
        fields(&mut fixture)?[12] = bytes(&encode(&key)?);
        assert_eq!(
            Proof::from_canonical_cbor(&encode(&fixture)?, &header).err(),
            Some(Error::InvalidBinding)
        );
    }
    Ok(())
}

#[test]
fn classification_children_use_existing_class_order_and_borrow_original_bytes() -> TestResult {
    let header = Header::new(header_input())?;
    let classes = [
        Class::TimelineReplay,
        Class::ReproManifest,
        Class::CausalTrace,
        Class::CalibrationReport,
        Class::Export,
        Class::ForkOrSnapshot,
        Class::ConformanceReport,
    ];
    let children: Vec<_> = classes
        .into_iter()
        .enumerate()
        .map(|(index, class)| child(class, 1, index % 2 == 0))
        .collect();
    let proof = Proof::new(proof_input(&header, &children))?;
    let encoded = proof.to_canonical_cbor();
    let decoded = Proof::from_canonical_cbor(&encoded, &header)?;
    assert!(!proof.as_input().children.is_empty());
    assert!(!decoded.as_input().children.is_empty());
    assert_eq!(
        decoded.as_input().children.iter().collect::<Vec<_>>(),
        children
    );
    let rows = decoded
        .as_input()
        .children
        .as_canonical_rows()
        .ok_or("missing borrowed rows")?;
    assert_eq!(rows.len(), 7 * 71);
    let offset = rows.as_ptr() as usize - encoded.as_ptr() as usize;
    assert!(offset + rows.len() <= encoded.len());
    assert_eq!(&encoded[offset..offset + rows.len()], rows);
    let mut expected = proof_value()?;
    fields(&mut expected)?[11] = Value::Array(
        (0..7)
            .map(|index| {
                Value::Array(vec![
                    uint(index),
                    bytes(&[1; 32]),
                    bytes(&[12; 32]),
                    Value::Bool(index % 2 == 0),
                ])
            })
            .collect(),
    );
    assert_eq!(&*encoded, &encode(&expected)?);
    Ok(())
}

#[test]
fn classification_rejects_zero_links_and_unsorted_or_duplicate_children() -> TestResult {
    let header = Header::new(header_input())?;
    for index in 0..4 {
        let mut input = proof_input(&header, &[]);
        match index {
            0 => input.owner_binding_digest = Hash::zero(),
            1 => input.plaintext_commitment = Hash::zero(),
            2 => input.envelope_address = Hash::zero(),
            _ => input.host_provenance_digest = Hash::zero(),
        }
        assert_eq!(Proof::new(input).err(), Some(Error::InvalidBinding));
    }
    let first = child(Class::TimelineReplay, 1, true);
    let second = child(Class::TimelineReplay, 2, false);
    for children in [
        vec![second, first],
        vec![first, first],
        vec![
            first,
            ArtifactChildEdgeV1 {
                required: false,
                ..first
            },
        ],
        vec![ArtifactChildEdgeV1 {
            artifact_digest: Hash::zero(),
            ..first
        }],
        vec![ArtifactChildEdgeV1 {
            registration_address: Hash::zero(),
            ..first
        }],
    ] {
        assert_eq!(
            Proof::new(proof_input(&header, &children)).err(),
            Some(Error::InvalidBinding)
        );
    }
    Ok(())
}

#[test]
fn classification_accepts_2048_edges_and_rejects_one_more() -> TestResult {
    let header = Header::new(header_input())?;
    let children: Vec<_> = (0_u32..2049)
        .map(|index| {
            let mut digest = [1; 32];
            digest[..4].copy_from_slice(&index.to_be_bytes());
            ArtifactChildEdgeV1 {
                artifact_digest: Hash::from_bytes(digest),
                ..child(Class::TimelineReplay, 1, true)
            }
        })
        .collect();
    let proof = Proof::new(proof_input(&header, &children[..2048]))?;
    let encoded = proof.to_canonical_cbor();
    assert!(encoded.len() <= 512 * 1024);
    assert_eq!(
        Proof::from_canonical_cbor(&encoded, &header)?
            .as_input()
            .children
            .len(),
        2048
    );
    assert_eq!(
        Proof::new(proof_input(&header, &children)).err(),
        Some(Error::BoundsExceeded)
    );
    let mut fixture = proof_value()?;
    fields(&mut fixture)?[11] = Value::Array(vec![uint(0); 2049]);
    assert_eq!(
        Proof::from_canonical_cbor(&encode(&fixture)?, &header).err(),
        Some(Error::BoundsExceeded)
    );
    Ok(())
}

#[test]
fn classification_rejects_malformed_child_codes_bools_and_shapes() -> TestResult {
    let header = Header::new(header_input())?;
    let valid = Value::Array(vec![
        uint(0),
        bytes(&[1; 32]),
        bytes(&[12; 32]),
        Value::Bool(true),
    ]);
    let mut changes = Vec::new();
    for (index, value) in [
        (0, uint(7)),
        (1, bytes(&[1; 31])),
        (2, bytes(&[12; 33])),
        (3, uint(1)),
    ] {
        let mut row = valid.clone();
        fields(&mut row)?[index] = value;
        changes.push(row);
    }
    changes.push(Value::Array(vec![]));
    for row in changes {
        let mut fixture = proof_value()?;
        fields(&mut fixture)?[11] = Value::Array(vec![row]);
        assert!(Proof::from_canonical_cbor(&encode(&fixture)?, &header).is_err());
    }
    for (index, value) in [(5, uint(4)), (6, uint(9)), (12, bytes(&[]))] {
        let mut fixture = proof_value()?;
        fields(&mut fixture)?[index] = value;
        assert_eq!(
            Proof::from_canonical_cbor(&encode(&fixture)?, &header).err(),
            Some(Error::InvalidEncoding)
        );
    }
    Ok(())
}

#[test]
fn classification_rejects_truncations_trailers_nonpreferred_and_oversize() -> TestResult {
    let header = Header::new(header_input())?;
    let encoded = encode(&proof_value()?)?;
    for end in 0..encoded.len() {
        assert!(Proof::from_canonical_cbor(&encoded[..end], &header).is_err());
    }
    let mut trailing = encoded.clone();
    trailing.push(0);
    assert_eq!(
        Proof::from_canonical_cbor(&trailing, &header).err(),
        Some(Error::InvalidEncoding)
    );
    let mut unsupported = proof_value()?;
    fields(&mut unsupported)?[1] = uint(2);
    assert_eq!(
        Proof::from_canonical_cbor(&encode(&unsupported)?, &header).err(),
        Some(Error::UnsupportedVersion)
    );
    let mut nonpreferred = encoded;
    nonpreferred.splice(6..7, [0x18, 1]);
    assert_eq!(
        Proof::from_canonical_cbor(&nonpreferred, &header).err(),
        Some(Error::InvalidEncoding)
    );
    assert_eq!(
        Proof::from_canonical_cbor(&vec![0; 512 * 1024 + 1], &header).err(),
        Some(Error::BoundsExceeded)
    );
    Ok(())
}
