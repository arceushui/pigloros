//! Exact closed metadata framing is separate from authenticated/current use.

#[path = "support/community_nonce_properties.rs"]
pub mod nonce_properties;

use ciborium::value::Value;
use pos_core::community_lifecycle::{
    CommunityArtifactHeaderInputV1 as HeaderInput, CommunityArtifactHeaderV1 as Header,
    CommunityArtifactKindV1 as Kind, CommunityArtifactOperationV1 as Operation,
    CommunityArtifactPurposeV1 as Purpose, CommunityEncryptedEnvelopeV1 as Envelope,
    CommunityLifecycleErrorV1 as Error, CommunityMetadataEnvelopeV1 as Metadata,
    CommunityMetadataSchemaV1 as Schema, CommunityMetadataScopeInputV1 as ScopeInput,
    CommunityMetadataScopeV1 as Scope, CommunityScopeMembersV1 as Members,
};
use pos_core::{Hash, TimelineId};
use proptest::arbitrary::any;

type Fallible<T> = Result<T, Box<dyn std::error::Error>>;
type TestResult = Fallible<()>;
const fn timeline(byte: u8) -> TimelineId {
    TimelineId::from_ulid(ulid::Ulid::from_bytes([byte; 16]))
}
fn scope_bytes() -> Fallible<Vec<u8>> {
    Ok(Scope::new(ScopeInput {
        store_incarnation: [1; 16],
        metadata_anchor_timeline: timeline(2),
        metadata_anchor_generation: [3; 16],
        protection_operation_id: [4; 16],
        scope_members: Members::from_members(&[]),
        metadata_not_after_micros: 100,
    })?
    .to_canonical_cbor()
    .to_vec())
}
fn header(scope: &[u8]) -> Fallible<HeaderInput> {
    Ok(HeaderInput {
        timeline: timeline(2),
        generation: [3; 16],
        purpose: Purpose::LifecycleControl,
        operation: Operation::Control([4; 16]),
        record_kind: Kind::LifecycleControl,
        scope_cover_digest: Scope::from_canonical_cbor(scope)?.digest(),
        evidence_not_after_micros: 100,
    })
}
fn envelope(input: HeaderInput, nonce: [u8; 12]) -> Fallible<Vec<u8>> {
    Ok(Envelope::new(Header::new(input)?, nonce, &[6; 16])?
        .to_canonical_cbor()
        .to_vec())
}
fn bytes(value: &[u8]) -> Value {
    Value::Bytes(value.to_vec())
}
fn value(scope: &[u8], envelope: &[u8]) -> Value {
    Value::Array(vec![
        bytes(b"CNE1"),
        Value::Integer(1.into()),
        bytes(b"NMP1"),
        bytes(scope),
        bytes(envelope),
    ])
}
fn encode(value: &Value) -> Fallible<Vec<u8>> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out)?;
    Ok(out)
}
fn fields(value: &mut Value) -> Fallible<&mut Vec<Value>> {
    match value {
        Value::Array(values) => Ok(values),
        _ => Err("array expected".into()),
    }
}

#[test]
fn exact_native_envelope_domain_and_borrowed_original_nested_ranges() -> TestResult {
    nonce_properties::check(any::<[u8; 12]>(), |nonce| {
        let scope = scope_bytes()?;
        let envelope = envelope(header(&scope)?, nonce)?;
        let metadata = Metadata::new(Schema::Nmp1, &scope, &envelope)?;
        assert!(metadata.schema() == Schema::Nmp1);
        assert_eq!(metadata.scope_cover().as_input().store_incarnation, [1; 16]);
        let expected = encode(&value(&scope, &envelope))?;
        assert_eq!(metadata.to_canonical_cbor().as_slice(), expected.as_slice());
        let mut preimage = b"PiglorOS.Community.NativeEvidenceEnvelope.v1\0".to_vec();
        preimage.extend_from_slice(&expected);
        assert_eq!(
            metadata.address(),
            Hash::from_bytes(*blake3::hash(&preimage).as_bytes())
        );
        let decoded = Metadata::from_canonical_cbor(&expected)?;
        assert_eq!(decoded.address(), metadata.address());
        assert_eq!(decoded.scope_cover_bytes(), scope);
        assert_eq!(decoded.envelope_bytes(), envelope);
        assert!(expected
            .as_ptr_range()
            .contains(&decoded.scope_cover_bytes().as_ptr()));
        assert!(expected
            .as_ptr_range()
            .contains(&decoded.envelope_bytes().as_ptr()));
        assert!(expected
            .as_ptr_range()
            .contains(&decoded.envelope().ciphertext_and_tag().as_ptr()));
        Ok(())
    })
}

#[test]
fn whitelist_is_exactly_the_31_accepted_native_metadata_schemas() -> TestResult {
    nonce_properties::check(any::<[u8; 12]>(), |nonce| {
        let scope = scope_bytes()?;
        let envelope = envelope(header(&scope)?, nonce)?;
        for (expected_schema, magic) in [
            (Schema::Cob1, *b"COB1"),
            (Schema::Csb1, *b"CSB1"),
            (Schema::Cpv1, *b"CPV1"),
            (Schema::Cau1, *b"CAU1"),
            (Schema::Cav1, *b"CAV1"),
            (Schema::Csi1, *b"CSI1"),
            (Schema::Cci1, *b"CCI1"),
            (Schema::Cmi1, *b"CMI1"),
            (Schema::Cpd1, *b"CPD1"),
            (Schema::Cbq1, *b"CBQ1"),
            (Schema::Cdp1, *b"CDP1"),
            (Schema::Cmb1, *b"CMB1"),
            (Schema::Cnt1, *b"CNT1"),
            (Schema::Cms1, *b"CMS1"),
            (Schema::Csh1, *b"CSH1"),
            (Schema::Cst1, *b"CST1"),
            (Schema::Cgi1, *b"CGI1"),
            (Schema::Cga1, *b"CGA1"),
            (Schema::Cgc1, *b"CGC1"),
            (Schema::Cri1, *b"CRI1"),
            (Schema::Cpr1, *b"CPR1"),
            (Schema::Cps1, *b"CPS1"),
            (Schema::Cpc1, *b"CPC1"),
            (Schema::Cab1, *b"CAB1"),
            (Schema::Cqk1, *b"CQK1"),
            (Schema::Cqc1, *b"CQC1"),
            (Schema::Cqr1, *b"CQR1"),
            (Schema::Cqo1, *b"CQO1"),
            (Schema::Cgr1, *b"CGR1"),
            (Schema::Ctb1, *b"CTB1"),
            (Schema::Nmp1, *b"NMP1"),
        ] {
            let schema = Schema::from_magic(magic).ok_or("accepted schema missing")?;
            assert_eq!(
                std::mem::discriminant(&schema),
                std::mem::discriminant(&expected_schema)
            );
            assert_eq!(expected_schema.magic(), magic);
            assert_eq!(schema.magic(), magic);
            let metadata = Metadata::new(schema, &scope, &envelope)?;
            assert_eq!(
                Metadata::from_canonical_cbor(&metadata.to_canonical_cbor())?
                    .schema()
                    .magic(),
                magic
            );
        }
        for magic in [
            *b"CSC1", *b"CIN1", *b"CSR1", *b"CAT1", *b"GCA1", *b"CIV1", *b"CFI1", *b"CFO1",
            *b"CMA1", *b"CSM1", *b"CKP1", *b"CKU1", *b"COE1", *b"NEW1",
        ] {
            assert!(Schema::from_magic(magic).is_none());
            let mut candidate = value(&scope, &envelope);
            fields(&mut candidate)?[2] = bytes(&magic);
            assert_eq!(
                Metadata::from_canonical_cbor(&encode(&candidate)?).err(),
                Some(Error::InvalidBinding)
            );
        }
        Ok(())
    })
}

#[test]
fn header_requires_exact_control_anchor_and_scope_with_no_deadline_extension() -> TestResult {
    nonce_properties::check(any::<[u8; 12]>(), |nonce| {
        let scope = scope_bytes()?;
        let original = header(&scope)?;
        for substitute in [
            HeaderInput {
                purpose: Purpose::ExecutionState,
                record_kind: Kind::StateContent,
                ..original
            },
            HeaderInput {
                record_kind: Kind::ClassificationProof,
                ..original
            },
            HeaderInput {
                operation: Operation::Initialization([7; 16]),
                ..original
            },
            HeaderInput {
                operation: Operation::Control([7; 16]),
                ..original
            },
            HeaderInput {
                timeline: timeline(8),
                ..original
            },
            HeaderInput {
                generation: [9; 16],
                ..original
            },
            HeaderInput {
                scope_cover_digest: Hash::from_bytes([10; 32]),
                ..original
            },
            HeaderInput {
                evidence_not_after_micros: 101,
                ..original
            },
        ] {
            let altered = envelope(substitute, nonce)?;
            assert_eq!(
                Metadata::new(Schema::Nmp1, &scope, &altered).err(),
                Some(Error::InvalidBinding)
            );
        }
        let shorter = envelope(
            HeaderInput {
                evidence_not_after_micros: 99,
                ..original
            },
            nonce,
        )?;
        assert_eq!(
            Metadata::new(Schema::Nmp1, &scope, &shorter)?
                .envelope()
                .header()
                .as_input()
                .evidence_not_after_micros,
            99
        );
        Ok(())
    })
}

#[test]
fn full_ciphertext_and_scope_limits_fit_the_native_wrapper() -> TestResult {
    nonce_properties::check(any::<[u8; 12]>(), |nonce| {
        use pos_core::community_lifecycle::{
            CommunityScopeMemberV1, MAX_COMMUNITY_SCOPE_MEMBERS_V1,
        };
        let rows: Vec<_> = (1..=MAX_COMMUNITY_SCOPE_MEMBERS_V1)
            .map(|n| {
                let mut digest = [0; 32];
                digest[24..].copy_from_slice(&(n as u64).to_be_bytes());
                CommunityScopeMemberV1 {
                    scope_reference: Hash::from_bytes(digest),
                    source_timeline: timeline(6),
                    owner_reference: Hash::from_bytes([7; 32]),
                    retention_lease_reference: Hash::from_bytes([8; 32]),
                    not_after_micros: i64::MAX as u64,
                }
            })
            .collect();
        let scope = Scope::new(ScopeInput {
            scope_members: Members::from_members(&rows),
            ..*Scope::from_canonical_cbor(&scope_bytes()?)?.as_input()
        })?
        .to_canonical_cbor();
        let ciphertext = vec![6; 3 * 1024 * 1024 + 16];
        let envelope =
            Envelope::new(Header::new(header(&scope)?)?, nonce, &ciphertext)?.to_canonical_cbor();
        let metadata = Metadata::new(Schema::Cdp1, &scope, &envelope)?;
        let encoded = metadata.to_canonical_cbor();
        assert!(encoded.len() < 4_194_304);
        assert_eq!(
            Metadata::from_canonical_cbor(&encoded)?
                .envelope()
                .ciphertext_and_tag()
                .len(),
            ciphertext.len()
        );
        Ok(())
    })
}

#[test]
fn complete_wrapper_rejects_malformed_nested_or_outer_framing() -> TestResult {
    nonce_properties::check(any::<[u8; 12]>(), |nonce| {
        let scope = scope_bytes()?;
        let envelope = envelope(header(&scope)?, nonce)?;
        assert!(Metadata::new(Schema::Nmp1, b"invalid", &envelope).is_err());
        assert!(Metadata::new(Schema::Nmp1, &scope, b"invalid").is_err());
        let canonical = encode(&value(&scope, &envelope))?;
        for length in 0..canonical.len() {
            assert!(Metadata::from_canonical_cbor(&canonical[..length]).is_err());
        }
        let mut trailing = canonical.clone();
        trailing.push(0);
        assert!(Metadata::from_canonical_cbor(&trailing).is_err());
        let mut nonpreferred = canonical;
        nonpreferred.splice(6..7, [0x18, 1]);
        assert!(Metadata::from_canonical_cbor(&nonpreferred).is_err());
        for field in 0..5 {
            let mut candidate = value(&scope, &envelope);
            fields(&mut candidate)?[field] = Value::Null;
            assert!(Metadata::from_canonical_cbor(&encode(&candidate)?).is_err());
        }
        let mut candidate = value(&scope, &envelope);
        fields(&mut candidate)?[1] = Value::Integer(2.into());
        assert!(Metadata::from_canonical_cbor(&encode(&candidate)?).is_err());
        for (field, length) in [(3, 1_048_577), (4, 3_147_841)] {
            let mut candidate = value(&scope, &envelope);
            fields(&mut candidate)?[field] = bytes(&vec![0; length]);
            assert_eq!(
                Metadata::from_canonical_cbor(&encode(&candidate)?).err(),
                Some(Error::BoundsExceeded)
            );
        }
        assert_eq!(
            Metadata::from_canonical_cbor(&vec![0; 4_194_305]).err(),
            Some(Error::BoundsExceeded)
        );
        Ok(())
    })
}
