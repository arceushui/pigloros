//! One original epoch survives complete A/B/A/B imported validations.

use super::super::fixture::{pin_policy, Fallible, Shape, Spec, World};
use super::ImportedRuntimeVerifier;
use pos_core::{
    store::{EventStore, SeqRange},
    trusted_clock::{GuardMonotonicSourceV1, ScriptedGuardMonotonicSourceV1},
    ErasureHostErrorV1, ErasureProtectedOperationV1, ErasureRecoveryLimitsV1, ErasureReferenceV1,
    Hash, Seq, WorldReplayClosureV1,
};
use pos_runtime::{
    ErasureCoordinatorCompositionV1, ErasureExecutionHostV1, VerifiedWorldReplayV1,
    WorldReplayForkSourceV1, WorldReplayUseV1, WorldReplayVerificationErrorV1,
    WorldReplayVerifierV1,
};
use pos_store::{
    memory::MemoryStore, ForkAttributionAuthorityImportPortV1,
    ForkAttributionAuthorityImportRequestV1, ForkManifestPublicationPortV1, ForkReplayReadBudgetV1,
    ForkReplayReadLimitsV1, ForkReplayRequirementV1,
};
use std::{sync::Arc, time::Duration};

struct PairVerifier([ImportedRuntimeVerifier; 2]);

impl WorldReplayVerifierV1 for PairVerifier {
    fn read_profile(
        &self,
        closure: &WorldReplayClosureV1,
        intent: &pos_runtime::WorldReplayReadIntentV1,
        generation: ErasureReferenceV1,
    ) -> Result<(pos_core::EventReadBounds, ForkReplayReadLimitsV1), WorldReplayVerificationErrorV1>
    {
        self.0
            .iter()
            .find(|arm| arm.leaf == intent.timeline_id())
            .ok_or(WorldReplayVerificationErrorV1::RequestMismatch)?
            .read_profile(closure, intent, generation)
    }

    fn verify(
        &self,
        closure: &WorldReplayClosureV1,
        requested: &WorldReplayUseV1,
        generation: ErasureReferenceV1,
    ) -> Result<VerifiedWorldReplayV1, WorldReplayVerificationErrorV1> {
        self.0
            .iter()
            .find(|arm| arm.leaf == requested.timeline_id())
            .ok_or(WorldReplayVerificationErrorV1::RequestMismatch)?
            .verify(closure, requested, generation)
    }
}

struct ImportedPair {
    host: ErasureExecutionHostV1,
    capabilities: [VerifiedWorldReplayV1; 2],
    requirements: [[ForkReplayRequirementV1; 2]; 2],
}

fn imported_pair(limits: ForkReplayReadLimitsV1) -> Fallible<ImportedPair> {
    let mut world = World::new(Shape::EmptyUnclassified, false)?;
    let parent = world.child_at(0)?.id;
    for _ in 0..2 {
        world.add_child_at(parent, Seq::from_u64(4), Shape::EmptyUnclassified)?;
    }
    assert_eq!(world.source.read(world.root, SeqRange::all())?.len(), 4);
    let mut store = MemoryStore::new();
    world.seed_destination(&mut store)?;
    let mut imported = Vec::new();
    for (index, child) in world.children.iter().enumerate() {
        let lane = u8::try_from(index)?;
        let spec = Spec {
            child: index,
            import_seed: 0x11 + lane,
            binding_seed: 0x21 + lane,
            principal_seed: 0x41 + lane,
            admission_seed: 0x31 + lane,
            registration_seed: 0x61 + lane,
            publication_seed: 0x91 + lane,
            operations_seed: 0xa0 + 4 * lane,
            ..Spec::default()
        };
        let built = world.build(&spec)?;
        assert_eq!(child.parent_cut, 4);
        assert!(world.source.read_own(child.id, SeqRange::all())?.is_empty());
        pin_policy(&mut store, &built.policy)?;
        store.import_verified(&ForkAttributionAuthorityImportRequestV1 {
            envelope_bytes: &built.bytes,
            expected_issuer_policy_digest: built.policy.digest(),
            parent_timeline_id: child.parent,
            trust_anchors: &world.anchors,
        })?;
        let committed = store.read_committed(child.id, 4)?;
        assert!(committed.authority_origin_digest.is_some());
        imported.push(ForkReplayRequirementV1::new(
            child.id,
            Seq::from_u64(4),
            committed.record_id,
            committed.authority_origin_digest,
        )?);
    }
    let requirements = [[imported[1], imported[0]], [imported[2], imported[0]]];
    let arm = |required: [ForkReplayRequirementV1; 2]| -> Fallible<ImportedRuntimeVerifier> {
        let mut sources = required
            .iter()
            .map(|required| {
                WorldReplayForkSourceV1::new(required.child_timeline_id(), Some(*required))
            })
            .collect::<Result<Vec<_>, _>>()?;
        sources.push(WorldReplayForkSourceV1::new(world.root, None)?);
        Ok(ImportedRuntimeVerifier {
            leaf: required[0].child_timeline_id(),
            sources,
            required: required.to_vec(),
            limits,
            arm_depth: 2,
        })
    };
    let owner = Arc::new(PairVerifier([arm(requirements[0])?, arm(requirements[1])?]));
    let composition = ErasureCoordinatorCompositionV1::closed().with_world_replay_verifier(owner);
    let mut host = ErasureExecutionHostV1::recover_memory_fixture_with_authority(
        store,
        &composition,
        ErasureRecoveryLimitsV1::compiled_maximum(),
    )?;
    let generation = Hash::from_bytes(host.containment_gate().inventory_generation()?.digest());
    let capabilities = {
        let mut sender = host.read_sender()?;
        let mut admit =
            |required: &[ForkReplayRequirementV1; 2]| -> Fallible<VerifiedWorldReplayV1> {
                let leaf = required[0].child_timeline_id();
                let closure =
                    WorldReplayClosureV1::test_fixture_for_timeline_with_inventory_generation(
                        leaf, generation,
                    )?;
                let requested = WorldReplayUseV1::new(
                    leaf,
                    ErasureProtectedOperationV1::Export,
                    SeqRange::all(),
                    Seq::from_u64(4),
                    vec!["count".to_owned()],
                    Vec::new(),
                )?;
                Ok(sender.admit_world_replay(&closure, &requested)?)
            };
        [admit(&requirements[0])?, admit(&requirements[1])?]
    };
    Ok(ImportedPair {
        host,
        capabilities,
        requirements,
    })
}

fn probe(
    pair: &mut ImportedPair,
    limits: ForkReplayReadLimitsV1,
    good_marks: usize,
    bad_mark: Duration,
) -> Fallible<(usize, usize)> {
    // g0 and budget construction see zero. Accepted marks then advance to
    // 500ms, so expiry at 1200ms distinguishes original g0 from a phase reset.
    let mut clock = ScriptedGuardMonotonicSourceV1::new(
        [Duration::ZERO; 2]
            .into_iter()
            .chain(std::iter::repeat_n(Duration::from_millis(500), good_marks))
            .chain([bad_mark, Duration::from_millis(500)]),
    );
    let g0 = clock.mark();
    let mut budget = ForkReplayReadBudgetV1::new(limits, g0, &mut clock)?;
    let ImportedPair {
        host,
        capabilities,
        requirements,
    } = pair;
    let mut sender = host.read_sender()?;
    let mut inner_fence = Err(ErasureHostErrorV1::Conflict);
    let mut outcome = (0, 0);
    sender.with_protected_ancestry_fence(
        capabilities[0].timeline_id(),
        ErasureProtectedOperationV1::Export,
        &mut |sender| {
            inner_fence = sender.with_protected_ancestry_fence(
                capabilities[1].timeline_id(),
                ErasureProtectedOperationV1::Export,
                &mut |sender| {
                    for arm in [0, 1, 0, 1] {
                        let before = budget.remaining_native_bytes();
                        let result =
                            sender.validate_world_replay_forks(&capabilities[arm], &mut budget);
                        outcome.1 = before - budget.remaining_native_bytes();
                        match result {
                            Ok(evidence) => {
                                assert_eq!(evidence.len(), 2);
                                for (actual, required) in evidence.iter().zip(&requirements[arm]) {
                                    assert_eq!(actual.requirement(), *required);
                                }
                                outcome.0 += 1;
                            }
                            Err(error) => {
                                assert_eq!(error, ErasureHostErrorV1::AdapterFailure);
                                let remaining = budget.remaining_native_bytes();
                                assert_eq!(
                                    sender
                                        .validate_world_replay_forks(
                                            &capabilities[arm],
                                            &mut budget
                                        )
                                        .map(|_| ()),
                                    Err(ErasureHostErrorV1::AdapterFailure)
                                );
                                assert!(budget.check_time().is_err());
                                assert_eq!(budget.remaining_native_bytes(), remaining);
                                break;
                            }
                        }
                    }
                },
            );
        },
    )?;
    inner_fence?;
    Ok(outcome)
}

fn deadline_case(bad_mark: Duration) -> Fallible<()> {
    let limits = ForkReplayReadLimitsV1::new(2, 1_024, 65_536, 1_048_576, 1_000_000)?;
    let mut pair = imported_pair(limits)?;
    let (mut lower, mut upper) = (1, 65_536);
    assert_eq!(probe(&mut pair, limits, lower, bad_mark)?, (0, 0));
    // This positive control proves all four real validations and enough
    // non-time resources; an early empty/ordinary bypass cannot count.
    assert_eq!(probe(&mut pair, limits, upper, bad_mark)?.0, 4);
    for _ in 0..16 {
        if upper - lower == 1 {
            break;
        }
        let middle = lower + (upper - lower) / 2;
        if probe(&mut pair, limits, middle, bad_mark)? >= (3, 211) {
            upper = middle;
        } else {
            lower = middle;
        }
    }
    assert_eq!(upper - lower, 1);
    let (complete, fourth_call_bytes) = probe(&mut pair, limits, upper, bad_mark)?;
    assert_eq!(complete, 3);
    // Two Fork metadata/visited/parent carriers cost 2*(49+16+16).
    // Root metadata/visited adds 25+16: 203 before its four 8-byte cursors.
    // Only 211/219/227 is strictly inside actual ancestor Event visibility.
    assert!(fourth_call_bytes > 203 && fourth_call_bytes < 235);
    Ok(())
}

#[test]
fn imported_memory_runtime_keeps_original_deadline_inside_later_arm_ancestor() -> Fallible<()> {
    deadline_case(Duration::from_millis(1_200))
}

#[test]
fn imported_memory_runtime_latches_regression_inside_later_arm_ancestor() -> Fallible<()> {
    deadline_case(Duration::ZERO)
}
