use pos_core::{
    ArtifactChildEdgeV1, ArtifactDataClassV1, ArtifactKeyDependencyV1, ArtifactOptionalityV1,
    ArtifactRegistrationErrorV1, ArtifactRegistrationFieldsV1, ArtifactRegistrationV1,
    ArtifactTransitionRuleV1, ErasureArtifactClassV1, Hash, KeyIdentityV1, KeyRoleV1, OwnerIdV1,
    MAX_ARTIFACT_REGISTRATION_BYTES_V1, MAX_ARTIFACT_REGISTRATION_CHILDREN_V1,
    MAX_ARTIFACT_REGISTRATION_KEYS_V1,
};
use std::fmt::Write as _;

fn sample_fields() -> Result<ArtifactRegistrationFieldsV1, Box<dyn std::error::Error>> {
    Ok(ArtifactRegistrationFieldsV1 {
        artifact_class: ErasureArtifactClassV1::TimelineReplay,
        artifact_digest: ArtifactRegistrationV1::artifact_digest(
            ErasureArtifactClassV1::TimelineReplay,
            b"abc",
        )?,
        owner_reference: ArtifactRegistrationV1::owner_reference(&OwnerIdV1::new("alice")?),
        data_class: ArtifactDataClassV1::StructuralAuditMetadata,
        optionality: ArtifactOptionalityV1::Required,
        transition_rule: ArtifactTransitionRuleV1::RetainStructure,
        required_key_roles: Vec::new(),
        key_dependencies: Vec::new(),
        child_artifacts: Vec::new(),
    })
}

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut output, "{byte:02x}").expect("writing to a String cannot fail");
    }
    output
}

#[test]
fn adr_093_golden_vector_is_exact_and_structural_only() -> Result<(), Box<dyn std::error::Error>> {
    let registration = ArtifactRegistrationV1::new(sample_fields()?)?;
    assert_eq!(
        hex(registration.fields().artifact_digest.as_bytes()),
        "353d3a42d9776fdbad857bd923f31270ba2899439132a8a258ce4302553ac041"
    );
    assert_eq!(
        hex(registration.fields().owner_reference.as_bytes()),
        "365678ef2286c7e68ab7ada3f90f20feca822efbc88abc5a7bf60e950a65176c"
    );
    assert_eq!(registration.canonical_cbor().len(), 82);
    assert_eq!(
        hex(registration.canonical_cbor()),
        "8b444152443101005820353d3a42d9776fdbad857bd923f31270ba2899439132a8a258ce4302553ac0415820365678ef2286c7e68ab7ada3f90f20feca822efbc88abc5a7bf60e950a65176c040002808080"
    );
    assert_eq!(
        hex(registration.address().as_bytes()),
        "cf582ad1bf9273ac6fa17e9335b359dec8d7ffccfbf6720c336db987e3aefd9c"
    );
    assert_eq!(
        ArtifactRegistrationV1::from_canonical_cbor(registration.canonical_cbor())?,
        registration
    );
    Ok(())
}

#[test]
fn decoder_rejects_noncanonical_and_wrong_shape() -> Result<(), Box<dyn std::error::Error>> {
    let canonical = ArtifactRegistrationV1::new(sample_fields()?)?
        .canonical_cbor()
        .to_vec();
    let mut noncanonical = canonical.clone();
    noncanonical.insert(6, 0x18);
    assert_eq!(
        ArtifactRegistrationV1::from_canonical_cbor(&noncanonical),
        Err(ArtifactRegistrationErrorV1::NonCanonical)
    );
    let mut wrong_array = canonical.clone();
    wrong_array[0] = 0x8a;
    assert!(ArtifactRegistrationV1::from_canonical_cbor(&wrong_array).is_err());
    let mut wrong_magic = canonical.clone();
    wrong_magic[2] = b'X';
    assert!(ArtifactRegistrationV1::from_canonical_cbor(&wrong_magic).is_err());
    let mut wrong_class = canonical.clone();
    wrong_class[7] = 7;
    assert_eq!(
        ArtifactRegistrationV1::from_canonical_cbor(&wrong_class),
        Err(ArtifactRegistrationErrorV1::UnsupportedValue)
    );
    let mut wrong_version = canonical.clone();
    wrong_version[6] = 2;
    assert_eq!(
        ArtifactRegistrationV1::from_canonical_cbor(&wrong_version),
        Err(ArtifactRegistrationErrorV1::UnsupportedValue)
    );
    for (index, invalid_code) in [(76, 5), (77, 2), (78, 4)] {
        let mut unknown = canonical.clone();
        unknown[index] = invalid_code;
        assert_eq!(
            ArtifactRegistrationV1::from_canonical_cbor(&unknown),
            Err(ArtifactRegistrationErrorV1::UnsupportedValue)
        );
    }
    let mut negative_class = canonical.clone();
    negative_class[7] = 0x20;
    assert_eq!(
        ArtifactRegistrationV1::from_canonical_cbor(&negative_class),
        Err(ArtifactRegistrationErrorV1::InvalidEncoding)
    );
    let mut tagged = canonical.clone();
    tagged[0] = 0xc0;
    assert_eq!(
        ArtifactRegistrationV1::from_canonical_cbor(&tagged),
        Err(ArtifactRegistrationErrorV1::InvalidEncoding)
    );
    let mut indefinite = canonical.clone();
    indefinite[0] = 0x9f;
    assert_eq!(
        ArtifactRegistrationV1::from_canonical_cbor(&indefinite),
        Err(ArtifactRegistrationErrorV1::InvalidEncoding)
    );
    for prefix in 0..canonical.len() {
        assert!(ArtifactRegistrationV1::from_canonical_cbor(&canonical[..prefix]).is_err());
    }
    let mut trailing = canonical;
    trailing.push(0);
    assert!(ArtifactRegistrationV1::from_canonical_cbor(&trailing).is_err());
    let oversized = vec![0; MAX_ARTIFACT_REGISTRATION_BYTES_V1 + 1];
    assert_eq!(
        ArtifactRegistrationV1::from_canonical_cbor(&oversized),
        Err(ArtifactRegistrationErrorV1::FieldOutOfBounds)
    );
    Ok(())
}

#[test]
fn every_closed_field_code_and_unsigned_width_round_trips() -> Result<(), Box<dyn std::error::Error>>
{
    let classes = [
        ErasureArtifactClassV1::TimelineReplay,
        ErasureArtifactClassV1::ReproManifest,
        ErasureArtifactClassV1::CausalTrace,
        ErasureArtifactClassV1::CalibrationReport,
        ErasureArtifactClassV1::Export,
        ErasureArtifactClassV1::ForkOrSnapshot,
        ErasureArtifactClassV1::ConformanceReport,
    ];
    let data_classes = [
        ArtifactDataClassV1::PrivateSubjectData,
        ArtifactDataClassV1::ConsentedSharedData,
        ArtifactDataClassV1::PublicRecord,
        ArtifactDataClassV1::AggregateData,
        ArtifactDataClassV1::StructuralAuditMetadata,
    ];
    let optionalities = [
        ArtifactOptionalityV1::Required,
        ArtifactOptionalityV1::Optional,
    ];
    let transitions = [
        ArtifactTransitionRuleV1::PreserveExact,
        ArtifactTransitionRuleV1::RedactViews,
        ArtifactTransitionRuleV1::RetainStructure,
        ArtifactTransitionRuleV1::Remove,
    ];
    let class_count = classes.len();
    let mut class_digests = std::collections::BTreeSet::new();
    for artifact_class in classes {
        assert!(
            class_digests.insert(ArtifactRegistrationV1::artifact_digest(
                artifact_class,
                b"abc"
            )?)
        );
        for data_class in data_classes {
            for optionality in optionalities {
                for transition_rule in transitions {
                    let mut fields = sample_fields()?;
                    fields.artifact_class = artifact_class;
                    fields.data_class = data_class;
                    fields.optionality = optionality;
                    fields.transition_rule = transition_rule;
                    let record = ArtifactRegistrationV1::new(fields)?;
                    assert_eq!(
                        ArtifactRegistrationV1::from_canonical_cbor(record.canonical_cbor())?,
                        record
                    );
                }
            }
        }
    }
    assert_eq!(class_digests.len(), class_count);
    let owner = OwnerIdV1::new("a".repeat(128))?;
    for epoch in [
        23,
        24,
        255,
        256,
        65_535,
        65_536,
        4_294_967_295,
        4_294_967_296,
    ] {
        let mut fields = sample_fields()?;
        fields.required_key_roles = vec![KeyRoleV1::TimelineIntegritySigning];
        fields.key_dependencies.push(ArtifactKeyDependencyV1 {
            identity: KeyIdentityV1::from_parts(owner, KeyRoleV1::TimelineIntegritySigning, epoch),
            material_digest: Hash::from_bytes([9; 32]),
            private_material_required: false,
        });
        let record = ArtifactRegistrationV1::new(fields)?;
        assert_eq!(
            ArtifactRegistrationV1::from_canonical_cbor(record.canonical_cbor())?,
            record
        );
    }
    Ok(())
}

#[test]
fn parser_rejects_invalid_direct_field_and_array_heads() -> Result<(), Box<dyn std::error::Error>> {
    let canonical = ArtifactRegistrationV1::new(sample_fields()?)?
        .canonical_cbor()
        .to_vec();
    for index in [79, 80, 81] {
        let mut oversized = canonical.clone();
        oversized[index] = if index == 79 { 0x86 } else { 0x99 };
        if index != 79 {
            oversized.insert(index + 1, 0x08);
            oversized.insert(index + 2, 0x01);
        }
        assert_eq!(
            ArtifactRegistrationV1::from_canonical_cbor(&oversized),
            Err(ArtifactRegistrationErrorV1::FieldOutOfBounds)
        );
    }
    let mut wrong_blob = canonical.clone();
    wrong_blob[8] = 0x81;
    assert_eq!(
        ArtifactRegistrationV1::from_canonical_cbor(&wrong_blob),
        Err(ArtifactRegistrationErrorV1::InvalidEncoding)
    );
    let mut wrong_blob_length = canonical.clone();
    wrong_blob_length[9] = 31;
    assert_eq!(
        ArtifactRegistrationV1::from_canonical_cbor(&wrong_blob_length),
        Err(ArtifactRegistrationErrorV1::InvalidEncoding)
    );
    let mut nonpreferred = canonical;
    nonpreferred[7] = 0x18;
    nonpreferred.insert(8, 0);
    assert_eq!(
        ArtifactRegistrationV1::from_canonical_cbor(&nonpreferred),
        Err(ArtifactRegistrationErrorV1::NonCanonical)
    );
    Ok(())
}

#[test]
fn parser_rejects_invalid_nested_owner_role_and_boolean() -> Result<(), Box<dyn std::error::Error>>
{
    let mut fields = sample_fields()?;
    fields.required_key_roles = vec![KeyRoleV1::TimelineIntegritySigning];
    fields.key_dependencies.push(ArtifactKeyDependencyV1 {
        identity: KeyIdentityV1::from_parts(
            OwnerIdV1::new("alice")?,
            KeyRoleV1::TimelineIntegritySigning,
            1,
        ),
        material_digest: Hash::from_bytes([3; 32]),
        private_material_required: false,
    });
    let canonical = ArtifactRegistrationV1::new(fields)?
        .canonical_cbor()
        .to_vec();
    let owner_at = canonical
        .windows(5)
        .position(|window| window == b"alice")
        .ok_or_else(|| std::io::Error::other("missing test owner"))?;
    let mut invalid_utf8 = canonical.clone();
    invalid_utf8[owner_at] = 0xff;
    assert_eq!(
        ArtifactRegistrationV1::from_canonical_cbor(&invalid_utf8),
        Err(ArtifactRegistrationErrorV1::InvalidEncoding)
    );
    let mut empty_owner = canonical.clone();
    empty_owner[owner_at - 1] = 0x60;
    assert_eq!(
        ArtifactRegistrationV1::from_canonical_cbor(&empty_owner),
        Err(ArtifactRegistrationErrorV1::FieldOutOfBounds)
    );
    let mut unknown_role = canonical.clone();
    unknown_role[80] = 7;
    assert_eq!(
        ArtifactRegistrationV1::from_canonical_cbor(&unknown_role),
        Err(ArtifactRegistrationErrorV1::UnsupportedValue)
    );
    let mut mismatched_role = canonical.clone();
    mismatched_role[80] = 1;
    assert_eq!(
        ArtifactRegistrationV1::from_canonical_cbor(&mismatched_role),
        Err(ArtifactRegistrationErrorV1::InvalidOrder)
    );
    let mut oversized_role_code = canonical.clone();
    oversized_role_code[80] = 0x19;
    oversized_role_code.insert(81, 1);
    oversized_role_code.insert(82, 0);
    assert_eq!(
        ArtifactRegistrationV1::from_canonical_cbor(&oversized_role_code),
        Err(ArtifactRegistrationErrorV1::UnsupportedValue)
    );
    let mut invalid_boolean = canonical;
    let last_dependency_field = invalid_boolean.len() - 2;
    invalid_boolean[last_dependency_field] = 0xf6;
    assert_eq!(
        ArtifactRegistrationV1::from_canonical_cbor(&invalid_boolean),
        Err(ArtifactRegistrationErrorV1::InvalidEncoding)
    );
    Ok(())
}

#[test]
fn every_prefix_of_nested_widths_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
    for epoch in [1, 256, 65_536, 4_294_967_296] {
        let mut fields = sample_fields()?;
        fields.required_key_roles = vec![KeyRoleV1::TimelineIntegritySigning];
        fields.key_dependencies.push(ArtifactKeyDependencyV1 {
            identity: KeyIdentityV1::from_parts(
                OwnerIdV1::new("alice")?,
                KeyRoleV1::TimelineIntegritySigning,
                epoch,
            ),
            material_digest: Hash::from_bytes([4; 32]),
            private_material_required: false,
        });
        fields.child_artifacts.push(ArtifactChildEdgeV1 {
            artifact_class: ErasureArtifactClassV1::Export,
            artifact_digest: Hash::from_bytes([5; 32]),
            registration_address: Hash::from_bytes([6; 32]),
            required: true,
        });
        let canonical = ArtifactRegistrationV1::new(fields)?
            .canonical_cbor()
            .to_vec();
        for prefix in 0..canonical.len() {
            assert!(ArtifactRegistrationV1::from_canonical_cbor(&canonical[..prefix]).is_err());
        }
    }
    Ok(())
}

#[test]
fn direct_keys_require_exact_roles_unique_identities_and_nonzero_epochs(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut fields = sample_fields()?;
    let owner = OwnerIdV1::new("alice")?;
    let first = ArtifactKeyDependencyV1 {
        identity: KeyIdentityV1::from_parts(owner, KeyRoleV1::SubjectDataEncryption, 1),
        material_digest: Hash::from_bytes([7; 32]),
        private_material_required: true,
    };
    fields.key_dependencies.push(first);
    assert_eq!(
        ArtifactRegistrationV1::new(fields.clone()),
        Err(ArtifactRegistrationErrorV1::InvalidOrder)
    );
    fields
        .required_key_roles
        .push(KeyRoleV1::SubjectDataEncryption);
    let registration = ArtifactRegistrationV1::new(fields.clone())?;
    assert_eq!(
        ArtifactRegistrationV1::from_canonical_cbor(registration.canonical_cbor())?,
        registration
    );
    fields.key_dependencies.push(first);
    assert_eq!(
        ArtifactRegistrationV1::new(fields.clone()),
        Err(ArtifactRegistrationErrorV1::InvalidOrder)
    );
    fields.key_dependencies.pop();
    fields.key_dependencies[0].identity.epoch = 0;
    assert_eq!(
        ArtifactRegistrationV1::new(fields.clone()),
        Err(ArtifactRegistrationErrorV1::InvalidOrder)
    );
    fields.key_dependencies[0] = first;
    fields
        .required_key_roles
        .push(KeyRoleV1::SubjectDataEncryption);
    assert_eq!(
        ArtifactRegistrationV1::new(fields),
        Err(ArtifactRegistrationErrorV1::InvalidOrder)
    );
    Ok(())
}

#[test]
fn child_edges_reject_duplicate_address_and_wrong_order() -> Result<(), Box<dyn std::error::Error>>
{
    let mut fields = sample_fields()?;
    let first = ArtifactChildEdgeV1 {
        artifact_class: ErasureArtifactClassV1::Export,
        artifact_digest: Hash::from_bytes([1; 32]),
        registration_address: Hash::from_bytes([2; 32]),
        required: true,
    };
    let second = ArtifactChildEdgeV1 {
        artifact_digest: Hash::from_bytes([3; 32]),
        registration_address: Hash::from_bytes([4; 32]),
        required: false,
        ..first
    };
    fields.child_artifacts = vec![first, second];
    let registration = ArtifactRegistrationV1::new(fields.clone())?;
    assert_eq!(
        ArtifactRegistrationV1::from_canonical_cbor(registration.canonical_cbor())?,
        registration
    );
    fields.child_artifacts.swap(0, 1);
    assert_eq!(
        ArtifactRegistrationV1::new(fields.clone()),
        Err(ArtifactRegistrationErrorV1::InvalidOrder)
    );
    fields.child_artifacts = vec![
        first,
        ArtifactChildEdgeV1 {
            registration_address: first.registration_address,
            ..second
        },
    ];
    assert_eq!(
        ArtifactRegistrationV1::new(fields),
        Err(ArtifactRegistrationErrorV1::InvalidOrder)
    );
    Ok(())
}

#[test]
fn maximal_direct_lists_fit_the_enclosing_one_mib_record() -> Result<(), Box<dyn std::error::Error>>
{
    let mut fields = sample_fields()?;
    let owner = OwnerIdV1::new("a".repeat(128))?;
    fields.required_key_roles = vec![KeyRoleV1::SubjectDataEncryption];
    for epoch in 1..=MAX_ARTIFACT_REGISTRATION_KEYS_V1 {
        fields.key_dependencies.push(ArtifactKeyDependencyV1 {
            identity: KeyIdentityV1::from_parts(
                owner,
                KeyRoleV1::SubjectDataEncryption,
                u64::try_from(epoch)?,
            ),
            material_digest: Hash::from_bytes([7; 32]),
            private_material_required: true,
        });
    }
    for index in 0..MAX_ARTIFACT_REGISTRATION_CHILDREN_V1 {
        let mut digest = [0; 32];
        digest[24..].copy_from_slice(&u64::try_from(index)?.to_be_bytes());
        fields.child_artifacts.push(ArtifactChildEdgeV1 {
            artifact_class: ErasureArtifactClassV1::Export,
            artifact_digest: Hash::from_bytes(digest),
            registration_address: Hash::from_bytes(digest),
            required: true,
        });
    }
    let registration = ArtifactRegistrationV1::new(fields.clone())?;
    assert!(registration.canonical_cbor().len() < MAX_ARTIFACT_REGISTRATION_BYTES_V1);
    assert_eq!(
        ArtifactRegistrationV1::from_canonical_cbor(registration.canonical_cbor())?.fields(),
        &fields
    );
    fields.key_dependencies.push(fields.key_dependencies[0]);
    assert_eq!(
        ArtifactRegistrationV1::new(fields),
        Err(ArtifactRegistrationErrorV1::FieldOutOfBounds)
    );
    let mut excess_roles = sample_fields()?;
    excess_roles.required_key_roles = vec![KeyRoleV1::SubjectDataEncryption; 6];
    assert_eq!(
        ArtifactRegistrationV1::new(excess_roles),
        Err(ArtifactRegistrationErrorV1::FieldOutOfBounds)
    );
    let mut excess_children = sample_fields()?;
    excess_children.child_artifacts = vec![
        ArtifactChildEdgeV1 {
            artifact_class: ErasureArtifactClassV1::Export,
            artifact_digest: Hash::from_bytes([5; 32]),
            registration_address: Hash::from_bytes([6; 32]),
            required: true,
        };
        MAX_ARTIFACT_REGISTRATION_CHILDREN_V1 + 1
    ];
    assert_eq!(
        ArtifactRegistrationV1::new(excess_children),
        Err(ArtifactRegistrationErrorV1::FieldOutOfBounds)
    );
    Ok(())
}
