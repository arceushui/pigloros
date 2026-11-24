//! ADR-129 revision 13, R13.1(2), I130 and I132: the Memory community
//! erasure-budget counters count exactly the closure the Local erasure
//! authority builds at submission.
//!
//! Memory only: the `SQLite` store has no community domain until Stack B
//! (#399), so its counters and I147 come with R13-2. The parity holds at
//! the bound: with `targets(A)` counted at 4,096 the closure fits, and at
//! 4,097 the submission is `ScopeTooLarge`, so the closure is exactly the
//! counted size.

use super::*;

use pos_core::{
    ArtifactDataClassV1, ArtifactKeyDependencyV1, ArtifactOptionalityV1,
    ArtifactRegistrationCatalogRowV1, ArtifactRegistrationFieldsV1, ArtifactRegistrationV1,
    ArtifactTransitionRuleV1,
};

/// A `TimelineReplay` catalogue row of `owner` and `data_class` with
/// `role_7` community key dependencies, unique to `seed`.
fn budget_row(
    owner: &'static str,
    data_class: ArtifactDataClassV1,
    role_7: u64,
    seed: u64,
) -> TestResult<ArtifactRegistrationCatalogRowV1> {
    let owner = OwnerIdV1::from_static(owner);
    let class = ErasureArtifactClassV1::TimelineReplay;
    let bytes = seed.to_le_bytes().to_vec();
    let digest = ArtifactRegistrationV1::artifact_digest(class, &bytes);
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
        key_dependencies: (1..=role_7)
            .map(|epoch| ArtifactKeyDependencyV1 {
                identity: KeyIdentityV1::new(
                    "community:budget",
                    KeyRoleV1::CommunityArtifactEncryption,
                    epoch,
                ),
                material_digest: Hash::from_bytes([0x5c; 32]),
                private_material_required: true,
            })
            .collect(),
        child_artifacts: Vec::new(),
    })
    .map_err(fail)?;
    ArtifactRegistrationCatalogRowV1::from_persisted(
        owner,
        class,
        digest,
        registration.address(),
        bytes,
        registration.canonical_cbor(),
    )
    .map_err(fail)
}

/// A community row: private, one role-7 key.
fn community(seed: u64) -> TestResult<ArtifactRegistrationCatalogRowV1> {
    budget_row(
        "community-artifact:budget",
        ArtifactDataClassV1::PrivateSubjectData,
        1,
        seed,
    )
}

/// The Memory driver store with a Fork of the actor's root, the other
/// actor's Fork of that Fork and its own root, rows of every kind on them,
/// rows bound to two Timelines, a second role-0 key of the actor, the other
/// actor's role-0 key and a role-7 key under the actor's subject owner;
/// then owned roots until the counters give `targets`.
fn budget_store(targets: u64) -> TestResult<MemoryStore> {
    let (mut store, _) = memory_store(&[])?;
    let fork = TimelineId::from_ulid(Ulid::from_bytes([0x91; 16]));
    let nested = TimelineId::from_ulid(Ulid::from_bytes([0x92; 16]));
    for (id, owner, parent) in [
        (fork, actor(), memory_owned_timeline()),
        (nested, other_actor(), fork),
    ] {
        store.create_timeline_with_meta(TimelineMeta {
            id,
            owner: Some(owner),
            fork_point: Some((parent, Seq::ZERO)),
            ..TimelineMeta::root("budget-fork")
        })?;
    }
    let other = owned_roots_on(&mut store, other_actor(), 1)?[0];
    let mut registry = store.load_key_registry()?.ok_or("no key registry")?;
    let own_role_7 = KeyIdentityV1::from_parts(
        subject_key(1)?.owner_id,
        KeyRoleV1::CommunityArtifactEncryption,
        1,
    );
    for (identity, material) in [
        (subject_key(2)?, 0x84),
        (subject_key_of(other_actor(), 1)?, 0x85),
        (own_role_7, 0x86),
    ] {
        registry
            .register_key(KeyRegistrationV1::new(
                identity,
                Hash::from_bytes([material; 32]),
                None,
            ))
            .map_err(fail)?;
    }
    store.save_key_registry(&registry)?;
    let shared = community(10)?;
    let crossing = community(11)?;
    store.bind_erasure_rows_for_test(
        memory_owned_timeline(),
        vec![
            community(1)?,
            community(2)?,
            community(3)?,
            budget_row("other-owner", ArtifactDataClassV1::PrivateSubjectData, 2, 4)?,
            budget_row("other-owner", ArtifactDataClassV1::PrivateSubjectData, 0, 5)?,
            budget_row(
                "other-owner",
                ArtifactDataClassV1::ConsentedSharedData,
                0,
                6,
            )?,
            shared.clone(),
            crossing.clone(),
        ],
    );
    store.bind_erasure_rows_for_test(fork, vec![shared]);
    store.bind_erasure_rows_for_test(nested, vec![community(12)?]);
    store.bind_erasure_rows_for_test(other, vec![crossing, community(13)?]);
    // Store target; the root, its Fork and the nested Fork; two role-0
    // keys; on the root three community rows, the two-key and keyless
    // private rows, the shared row and the crossing row; the nested Fork's
    // row. The consented row, the role-7 key and the other root are not
    // the actor's.
    let counted = store.erasure_targets_for_test(actor());
    assert_eq!(counted, 1 + 3 + 2 + (6 + 3 + 1 + 2 + 2) + 2);
    let padding = usize::try_from(targets - counted)?;
    owned_roots_on(&mut store, actor(), padding)?;
    assert_eq!(store.erasure_targets_for_test(actor()), targets);
    Ok(store)
}

#[test]
fn the_counted_targets_are_the_closure_the_authority_admits() -> TestResult {
    for (targets, expected) in [
        (4_096, Ok(ErasureLifecycleV1::Submitted)),
        (4_097, Err(LocalErasureSubmitErrorV1::ScopeTooLarge)),
    ] {
        let mut host = memory_host(budget_store(targets)?, &driver_case()?)?;
        assert_eq!(
            host.command_sender()?
                .submit_local_erasure(&submission(1, ErasureScopeV1::PrivateSubjectData)?)
                .map(|admitted| admitted.state.lifecycle()),
            expected
        );
    }
    Ok(())
}
