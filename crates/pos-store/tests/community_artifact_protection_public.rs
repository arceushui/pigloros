//! ADR-128 artifact protection for one scope cohort (ADR-129 §3) through its
//! public seam: the `ProtectArtifacts` CKP1 and CCI1, the COE1/CAR1/COW1
//! framing, the exact unpublished ARD1 and the COA1 builder.
//!
//! Every expected digest is computed independently with `blake3` from the
//! ADR-128 formulas: the `ArtifactBytes` artifact digest, the
//! `ArtifactOwner` owner reference and the `ProtectedObject` address.

use std::error::Error as StdError;

use pos_core::community_lifecycle::{
    CommunityArtifactKindV1 as Kind, CommunityArtifactOperationV1 as Operation,
    CommunityArtifactPurposeV1 as Purpose, CommunityCopyHolderV1, CommunityCopyStateV1,
    CommunityEncryptedEnvelopeV1, CommunityLifecycleErrorV1 as Error, CommunityMemberSlotsV1,
    CommunityProtectedObjectV1, CommunityRecordKindsV1,
};
use pos_core::{
    ArtifactChildEdgeV1, ArtifactDataClassV1, ArtifactOptionalityV1, ArtifactTransitionRuleV1,
    AuthorityTrustRootSealV1, ErasureArtifactClassV1 as Class, Hash, KeyRoleV1, TimelineId,
};
use pos_store::community::{
    CommunityArtifactProtectorV1, CommunityProtectedRecordV1, CommunityProtectionCohortV1,
    CommunityRecordEvidenceV1,
};
use ulid::Ulid;

type Fallible<T> = Result<T, Box<dyn StdError>>;
type TestResult = Fallible<()>;

const SEAL: AuthorityTrustRootSealV1 = AuthorityTrustRootSealV1::for_composition_root();
const GENERATION: [u8; 16] = [5; 16];
const HORIZON: u64 = 1_000;

const fn hash(byte: u8) -> Hash {
    Hash::from_bytes([byte; 32])
}

const fn timeline() -> TimelineId {
    TimelineId::from_ulid(Ulid::from_bytes([4; 16]))
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

fn domain(prefix: &[u8], parts: &[&[u8]]) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(prefix);
    for part in parts {
        hasher.update(part);
    }
    Hash::from_bytes(*hasher.finalize().as_bytes())
}

const fn kinds(kind: Kind) -> CommunityRecordKindsV1 {
    CommunityRecordKindsV1::empty()
        .with(kind)
        .with(Kind::ClassificationProof)
}

fn cohort(purpose: Purpose, kind: Kind) -> Fallible<CommunityProtectionCohortV1> {
    Ok(CommunityProtectionCohortV1 {
        parent_operation: Operation::Initialization([3; 16]),
        timeline: timeline(),
        generation: GENERATION,
        purpose,
        scope_set_digest: hash(6),
        scope_cover_digest: hash(7),
        evidence_not_after_micros: HORIZON,
        allowed_record_kinds: kinds(kind),
        member_slots: CommunityMemberSlotsV1::new(&[0])?,
        authority_request_digest: hash(8),
    })
}

const fn child(byte: u8, address: u8) -> ArtifactChildEdgeV1 {
    ArtifactChildEdgeV1 {
        artifact_class: Class::TimelineReplay,
        artifact_digest: hash(byte),
        registration_address: hash(address),
        required: true,
    }
}

const fn evidence(children: &[ArtifactChildEdgeV1]) -> CommunityRecordEvidenceV1<'_> {
    CommunityRecordEvidenceV1 {
        owner_binding_digest: hash(9),
        host_provenance_digest: hash(10),
        children,
    }
}

/// The suboperation's CKP1 names a fresh protection ID under its parent and
/// the role-7 control owner; its CCI1 is the revision-1 key-vault copy.
#[test]
fn provisioning_writes_the_key_intent_and_vault_copy() -> TestResult {
    let protector = CommunityArtifactProtectorV1::provision(
        &SEAL,
        cohort(Purpose::ExecutionState, Kind::StateContent)?,
    )?;
    let intent = protector.key_intent();
    let fields = intent.as_input();
    assert_ne!(fields.protection_operation_id, [0; 16]);
    assert!(fields.parent_operation == Operation::Initialization([3; 16]));
    assert!(fields.purpose == Purpose::ExecutionState);
    assert_eq!(fields.scope_set_digest, hash(6));
    assert_eq!(fields.evidence_not_after_micros, HORIZON);
    assert!(fields.allowed_record_kinds == kinds(Kind::StateContent));
    assert_eq!(fields.authority_request_digest, hash(8));
    assert_ne!(fields.material_fingerprint, Hash::zero());
    assert_eq!(
        intent.key_owner_text(),
        format!(
            "community:{}:{}:0:c:{}",
            hex(&timeline().inner().to_bytes()),
            hex(&GENERATION),
            hex(&fields.protection_operation_id)
        )
    );
    let copy = protector.copy_descriptor().as_input();
    assert_ne!(copy.copy_id, [0; 16]);
    assert_eq!(copy.revision, 1);
    assert!(copy.predecessor.is_none());
    assert!(copy.parent_operation == Operation::Initialization([3; 16]));
    assert_eq!(copy.holder, CommunityCopyHolderV1::KeyVault);
    assert_eq!(copy.holder_digest, intent.digest());
    assert!(copy.purpose == Purpose::ExecutionState);
    assert_eq!(copy.scope_set_digest, hash(6));
    assert!(copy.object_commitment.is_none());
    assert_eq!(copy.state, CommunityCopyStateV1::Owned);
    assert_eq!(copy.deadline_micros, HORIZON);

    // A second suboperation gets its own identities and material.
    let other = CommunityArtifactProtectorV1::provision(
        &SEAL,
        cohort(Purpose::ExecutionState, Kind::StateContent)?,
    )?;
    let other_fields = other.key_intent().as_input();
    assert_ne!(
        other_fields.protection_operation_id,
        fields.protection_operation_id
    );
    assert_ne!(
        other_fields.material_fingerprint,
        fields.material_fingerprint
    );
    assert_ne!(other.copy_descriptor().as_input().copy_id, copy.copy_id);
    Ok(())
}

/// Both envelopes share one COH1 context except the proof's kind 8, and the
/// COW1 address is `H("ProtectedObject", COW1)`.
fn assert_framing(
    record: &CommunityProtectedRecordV1,
    purpose: Purpose,
    kind: Kind,
    protection: [u8; 16],
) -> TestResult {
    let object = CommunityProtectedObjectV1::from_canonical_cbor(record.object())?;
    let content = CommunityEncryptedEnvelopeV1::from_canonical_cbor(object.content_envelope())?;
    let header = content.header().as_input();
    assert_eq!(header.timeline, timeline());
    assert_eq!(header.generation, GENERATION);
    assert!(header.purpose == purpose);
    assert!(header.operation == Operation::Control(protection));
    assert!(header.record_kind == kind);
    assert_eq!(header.scope_cover_digest, hash(7));
    assert_eq!(header.evidence_not_after_micros, HORIZON);
    // The AAD is BLAKE3("EnvelopeContext" || 0 || COH1), per ADR-128 §2.
    assert_eq!(
        content.header().associated_data_digest(),
        domain(
            b"PiglorOS.Community.EnvelopeContext.v1\0",
            &[&content.header().to_canonical_cbor()]
        )
    );
    let proof = CommunityEncryptedEnvelopeV1::from_canonical_cbor(object.proof_envelope())?;
    assert!(proof.header().as_input().record_kind == Kind::ClassificationProof);
    assert_ne!(proof.nonce(), content.nonce());
    assert_eq!(
        record.object_address(),
        domain(
            b"PiglorOS.Community.ProtectedObject.v1\0",
            &[record.object()]
        )
    );
    Ok(())
}

/// COA1 takes its object, ARD1, COB1, scope-cover and horizon fields from
/// the record, and the CAU1 digest and inventory generation from its caller.
fn assert_admission(record: &CommunityProtectedRecordV1) -> TestResult {
    let admission = record.admission(&SEAL, 42, hash(30))?;
    let bound = admission.as_input();
    assert_eq!(bound.protected_object_address, record.object_address());
    assert_eq!(
        bound.artifact_digest,
        record.registration().fields().artifact_digest
    );
    assert_eq!(bound.registration_address, record.registration().address());
    assert_eq!(bound.owner_binding_digest, hash(9));
    assert_eq!(bound.scope_cover_digest, hash(7));
    assert_eq!(bound.evidence_not_after_micros, HORIZON);
    assert_eq!(bound.admission_inventory_generation, 42);
    assert_eq!(bound.authority_evidence_digest, hash(30));
    assert_eq!(
        record.admission(&SEAL, 42, Hash::zero()).err(),
        Some(Error::InvalidBinding)
    );
    Ok(())
}

/// COE1 and its kind-8 proof share one COH1 context; the COW1 address and
/// the ARD1 fields follow ADR-128 exactly, with optionality and transition
/// rule from the purpose (owner decision on #560).
#[test]
fn protection_frames_the_object_and_derives_its_registration() -> TestResult {
    let children = [child(20, 21), child(22, 23)];
    // (purpose, kind, ARD1 class and its ERC1 byte, optionality, purpose digit)
    for (purpose, kind, (class, class_byte), optionality, digit) in [
        (
            Purpose::ExecutionState,
            Kind::StateContent,
            (Class::TimelineReplay, 0_u8),
            ArtifactOptionalityV1::Required,
            0,
        ),
        (
            Purpose::PresentationTrace,
            Kind::TraceAnnotation,
            (Class::CausalTrace, 2),
            ArtifactOptionalityV1::Optional,
            1,
        ),
        (
            Purpose::ReplayEvidence,
            Kind::ReplayReceiptOrRoot,
            (Class::ReproManifest, 1),
            ArtifactOptionalityV1::Optional,
            2,
        ),
        (
            Purpose::LifecycleControl,
            Kind::LifecycleControl,
            (Class::TimelineReplay, 0),
            ArtifactOptionalityV1::Required,
            3,
        ),
    ] {
        let mut protector = CommunityArtifactProtectorV1::provision(&SEAL, cohort(purpose, kind)?)?;
        let protection = protector.key_intent().as_input().protection_operation_id;
        let fingerprint = protector.key_intent().as_input().material_fingerprint;
        let owner_text = protector.key_intent().key_owner_text().to_owned();
        assert!(owner_text.contains(&format!(":{digit}:c:")));
        let record = protector.protect(kind, b"record bytes", evidence(&children))?;

        assert_framing(&record, purpose, kind, protection)?;

        let fields = record.registration().fields();
        let length = (record.object().len() as u64).to_be_bytes();
        assert_eq!(fields.artifact_class, class);
        assert_eq!(
            fields.artifact_digest,
            domain(
                b"PiglorOS.ArtifactBytes.v1\0",
                &[&[class_byte], &length, record.object()]
            )
        );
        let catalogue = format!(
            "community-artifact:{}:{}",
            hex(&timeline().inner().to_bytes()),
            hex(&GENERATION)
        );
        assert_eq!(catalogue.len(), 84);
        let catalogue_length = u32::try_from(catalogue.len())?.to_be_bytes();
        assert_eq!(
            fields.owner_reference,
            domain(
                b"PiglorOS.ArtifactOwner.v1\0",
                &[&catalogue_length, catalogue.as_bytes()]
            )
        );
        assert_eq!(fields.data_class, ArtifactDataClassV1::PrivateSubjectData);
        assert_eq!(fields.optionality, optionality);
        assert_eq!(fields.transition_rule, ArtifactTransitionRuleV1::Remove);
        assert_eq!(
            fields.required_key_roles,
            vec![KeyRoleV1::CommunityArtifactEncryption]
        );
        assert_eq!(fields.key_dependencies.len(), 1);
        let dependency = &fields.key_dependencies[0];
        assert_eq!(dependency.identity.owner_id.as_str(), owner_text);
        assert_eq!(
            dependency.identity.role,
            KeyRoleV1::CommunityArtifactEncryption
        );
        assert_eq!(dependency.identity.epoch, 1);
        assert_eq!(dependency.material_digest, fingerprint);
        assert!(dependency.private_material_required);
        assert_eq!(fields.child_artifacts, children.to_vec());

        assert_admission(&record)?;
    }
    Ok(())
}

/// Every refusal of `protect` for a record or its evidence.
#[test]
fn protection_refuses_records_it_cannot_protect() -> TestResult {
    let mut protector = CommunityArtifactProtectorV1::provision(
        &SEAL,
        cohort(Purpose::ExecutionState, Kind::StateContent)?,
    )?;
    let none: [ArtifactChildEdgeV1; 0] = [];
    for (kind, evidence, error) in [
        (
            Kind::ClassificationProof,
            evidence(&none),
            Error::InvalidBinding,
        ),
        (
            Kind::StateRevisionOrHead,
            evidence(&none),
            Error::InvalidBinding,
        ),
        (
            Kind::StateContent,
            CommunityRecordEvidenceV1 {
                owner_binding_digest: Hash::zero(),
                ..evidence(&none)
            },
            Error::InvalidBinding,
        ),
        (
            Kind::StateContent,
            CommunityRecordEvidenceV1 {
                host_provenance_digest: Hash::zero(),
                ..evidence(&none)
            },
            Error::InvalidBinding,
        ),
        (
            Kind::StateContent,
            evidence(&[child(22, 23), child(20, 21)]),
            Error::InvalidBinding,
        ),
        // CAR1 admits two digests under one address; ARD1 does not.
        (
            Kind::StateContent,
            evidence(&[child(20, 21), child(22, 21)]),
            Error::InvalidBinding,
        ),
        // A zero child digest or registration address.
        (
            Kind::StateContent,
            evidence(&[child(0, 21)]),
            Error::InvalidBinding,
        ),
        (
            Kind::StateContent,
            evidence(&[child(20, 0)]),
            Error::InvalidBinding,
        ),
    ] {
        assert_eq!(
            protector.protect(kind, b"record", evidence).err(),
            Some(error)
        );
    }
    assert_eq!(
        protector
            .protect(
                Kind::StateContent,
                &vec![0; 3 * 1024 * 1024 + 1],
                evidence(&none)
            )
            .err(),
        Some(Error::BoundsExceeded)
    );
    assert!(protector
        .protect(
            Kind::StateContent,
            &vec![0; 3 * 1024 * 1024],
            evidence(&none)
        )
        .is_ok());

    Ok(())
}

/// ADR-128 §3 child bound: 2048 direct children are protected, 2049 are
/// refused.
#[test]
fn protection_holds_the_child_bound() -> TestResult {
    let mut protector = CommunityArtifactProtectorV1::provision(
        &SEAL,
        cohort(Purpose::ExecutionState, Kind::StateContent)?,
    )?;
    // 2049 children, strictly ordered, exceed the ARD1/CAR1 child bound.
    let many = (0..2049_u64)
        .map(|index| {
            let mut digest = [1; 32];
            digest[24..].copy_from_slice(&index.to_be_bytes());
            ArtifactChildEdgeV1 {
                artifact_class: Class::TimelineReplay,
                artifact_digest: Hash::from_bytes(digest),
                registration_address: Hash::from_bytes(digest),
                required: false,
            }
        })
        .collect::<Vec<_>>();
    assert_eq!(
        protector
            .protect(Kind::StateContent, b"record", evidence(&many))
            .err(),
        Some(Error::BoundsExceeded)
    );
    assert!(protector
        .protect(Kind::StateContent, b"record", evidence(&many[..2048]))
        .is_ok());
    Ok(())
}

/// A cohort a protector cannot serve: no proof kind, no scope cover, or a
/// CKP1 refusal.
#[test]
fn protection_refuses_cohorts_it_cannot_serve() -> TestResult {
    let none: [ArtifactChildEdgeV1; 0] = [];
    // A key whose intent does not allow proofs cannot protect anything.
    let mut no_proof = CommunityArtifactProtectorV1::provision(
        &SEAL,
        CommunityProtectionCohortV1 {
            allowed_record_kinds: CommunityRecordKindsV1::empty().with(Kind::StateContent),
            ..cohort(Purpose::ExecutionState, Kind::StateContent)?
        },
    )?;
    assert_eq!(
        no_proof
            .protect(Kind::StateContent, b"record", evidence(&none))
            .err(),
        Some(Error::InvalidBinding)
    );
    // A zero scope cover cannot head an envelope.
    let mut no_cover = CommunityArtifactProtectorV1::provision(
        &SEAL,
        CommunityProtectionCohortV1 {
            scope_cover_digest: Hash::zero(),
            ..cohort(Purpose::ExecutionState, Kind::StateContent)?
        },
    )?;
    assert_eq!(
        no_cover
            .protect(Kind::StateContent, b"record", evidence(&none))
            .err(),
        Some(Error::InvalidBinding)
    );
    // CKP1 refuses a zero scope set or a kind the purpose does not admit.
    for invalid in [
        CommunityProtectionCohortV1 {
            scope_set_digest: Hash::zero(),
            ..cohort(Purpose::ExecutionState, Kind::StateContent)?
        },
        cohort(Purpose::ExecutionState, Kind::TraceAnnotation)?,
    ] {
        assert_eq!(
            CommunityArtifactProtectorV1::provision(&SEAL, invalid).err(),
            Some(Error::InvalidBinding)
        );
    }
    Ok(())
}
