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

use pos_core::community_lifecycle::COMMUNITY_ERASURE_TARGET_LINE_V1;
use pos_core::{
    ArtifactDataClassV1, ArtifactKeyDependencyV1, ArtifactOptionalityV1,
    ArtifactRegistrationCatalogRowV1, ArtifactRegistrationFieldsV1, ArtifactRegistrationV1,
    ArtifactTransitionRuleV1,
};

/// The artifact class of every catalogue row of this file.
const ROW_CLASS: ErasureArtifactClassV1 = ErasureArtifactClassV1::TimelineReplay;

/// The artifact digest of the catalogue row `budget_row` builds for `seed`.
fn row_digest(seed: u64) -> Hash {
    ArtifactRegistrationV1::artifact_digest(ROW_CLASS, &seed.to_le_bytes())
}

/// A `TimelineReplay` catalogue row of `owner` and `data_class` with
/// `role_7` community key dependencies, unique to `seed`.
fn budget_row(
    owner: &'static str,
    data_class: ArtifactDataClassV1,
    role_7: u64,
    seed: u64,
) -> TestResult<ArtifactRegistrationCatalogRowV1> {
    let owner = OwnerIdV1::from_static(owner);
    let class = ROW_CLASS;
    let bytes = seed.to_le_bytes().to_vec();
    let digest = row_digest(seed);
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

/// The no-component reference of an Artifact target, as `freeze.rs` builds it.
const NO_COMPONENT: ErasureReferenceV1 = ErasureReferenceV1::from_digest([0; 32]);

/// R13, I138, **bound-rows form**: with the community line reached
/// (`targets(A)` at `COMMUNITY_ERASURE_TARGET_LINE_V1`, 4,096 less the 128
/// targets `R_other` that R13.1(6) keeps for other writers, which is where the
/// community planner stops with every reserve held), an ADR-136 request of
/// the actor still freezes and finalizes, and every private row of its
/// affected scope is an Artifact obligation of the receipt.
///
/// Only the requesting actor's closure is exercised at the line: the other
/// actor's `targets(A)` is far below it here, and the parity of every
/// actor's counted closure with `closure_fits` is I130 and I132 above. The
/// rows are bound through `bind_erasure_rows_for_test`, not by passes: no
/// pass can commit before A5, so the full form of I138 (a request of every
/// actor in scope after passes up to the first refusal, 14 or 19) remains an
/// obligation of the A5 Commit slice.
///
/// This is the slowest test of the file: the drive signs one
/// acknowledgement step per obligation, about 4,000 of them.
#[test]
fn a_request_freezes_at_the_community_line_and_lists_every_private_row() -> TestResult {
    let mut host = memory_host(
        budget_store(COMMUNITY_ERASURE_TARGET_LINE_V1)?,
        &driver_case()?,
    )?;
    submitted(&mut host, 1, ErasureScopeV1::PrivateSubjectData)?;
    let receipt = finalized(driver().drive(&mut host, request_of(1)?)?)?;
    // The Artifact targets only: a role-7 key target carries its row's
    // digest too, with the key's digest in `key_digest`.
    let listed = receipt
        .acknowledgements()
        .iter()
        .filter(|acknowledgement| acknowledgement.target.key_digest == NO_COMPONENT)
        .map(|acknowledgement| acknowledgement.target.artifact_digest)
        .collect::<Vec<_>>();
    let target = |seed: u64| ErasureReferenceV1::from_digest(*row_digest(seed).as_bytes());
    // Every private row bound to the actor's root, its Fork or the nested
    // Fork: the community rows 1 to 3, the shared row 10, the crossing row
    // 11 and the nested Fork's row 12, and the other owner's private rows 4
    // and 5. Not the consented row 6, nor row 13 of the other actor's root.
    for seed in [1, 2, 3, 4, 5, 10, 11, 12] {
        assert!(listed.contains(&target(seed)), "row {seed}");
    }
    for seed in [6, 13] {
        assert!(!listed.contains(&target(seed)), "row {seed}");
    }
    Ok(())
}
