//! Catalogue rows for the community erasure-budget tests (ADR-129
//! revision 13): the Memory counter tests and the planner's capacity tests
//! bind them through `MemoryStore::bind_erasure_rows_for_test`.

use pos_core::{
    ArtifactDataClassV1, ArtifactKeyDependencyV1, ArtifactOptionalityV1,
    ArtifactRegistrationCatalogRowV1, ArtifactRegistrationFieldsV1, ArtifactRegistrationV1,
    ArtifactTransitionRuleV1, ErasureArtifactClassV1, Hash, KeyIdentityV1, KeyRoleV1, OwnerIdV1,
};

/// A test result with a boxed error.
pub type Fallible<T> = Result<T, Box<dyn std::error::Error>>;

/// A `TimelineReplay` catalogue row of `owner` and `data_class` with
/// `role_7` community key dependencies and a digest unique to `seed`.
///
/// # Errors
/// The ARD1 or catalogue-row codec's refusal.
pub fn erasure_row(
    owner: &'static str,
    data_class: ArtifactDataClassV1,
    role_7: u64,
    seed: u64,
) -> Fallible<ArtifactRegistrationCatalogRowV1> {
    let owner = OwnerIdV1::from_static(owner);
    let class = ErasureArtifactClassV1::TimelineReplay;
    let bytes = seed.to_le_bytes().to_vec();
    let digest = ArtifactRegistrationV1::artifact_digest(class, &bytes);
    let key_dependencies: Vec<_> = (1..=role_7)
        .map(|epoch| ArtifactKeyDependencyV1 {
            identity: KeyIdentityV1::new(
                "community:budget",
                KeyRoleV1::CommunityArtifactEncryption,
                epoch,
            ),
            material_digest: Hash::from_bytes([0x5c; 32]),
            private_material_required: true,
        })
        .collect();
    let registration = ArtifactRegistrationV1::new(ArtifactRegistrationFieldsV1 {
        artifact_class: class,
        artifact_digest: digest,
        owner_reference: ArtifactRegistrationV1::owner_reference(&owner),
        data_class,
        optionality: ArtifactOptionalityV1::Required,
        transition_rule: ArtifactTransitionRuleV1::PreserveExact,
        required_key_roles: if role_7 == 0 {
            Vec::new()
        } else {
            vec![KeyRoleV1::CommunityArtifactEncryption]
        },
        key_dependencies,
        child_artifacts: Vec::new(),
    })
    .map_err(|error| format!("{error:?}"))?;
    Ok(ArtifactRegistrationCatalogRowV1::from_persisted(
        owner,
        class,
        digest,
        registration.address(),
        bytes,
        registration.canonical_cbor(),
    )
    .map_err(|error| format!("{error:?}"))?)
}

/// `count` community rows (private, one role-7 key) from `seed` on.
///
/// # Errors
/// As [`erasure_row`].
pub fn community_rows(seed: u64, count: u64) -> Fallible<Vec<ArtifactRegistrationCatalogRowV1>> {
    (seed..seed + count)
        .map(|index| {
            erasure_row(
                "community-artifact:budget",
                ArtifactDataClassV1::PrivateSubjectData,
                1,
                index,
            )
        })
        .collect()
}
