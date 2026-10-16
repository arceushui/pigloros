//! Real imported ancestry through Runtime's public protected validation seam.
//!
//! The outer fence may inspect ordinary ancestry metadata. Depth assertions
//! concern the bounded native validation walk, not all reads by that fence.

mod deadline;
mod repeat;

use super::fixture::{pin_policy, Fallible, Shape, Spec, World};
use pos_core::{
    store::{EventStore, SeqRange},
    trusted_clock::{GuardMonotonicSourceV1, ScriptedGuardMonotonicSourceV1},
    ErasureHostErrorV1, ErasureProtectedOperationV1, ErasureRecoveryLimitsV1, ErasureReferenceV1,
    ErasureReplayClaimV1, EventReadBounds, Hash, Seq, TimelineId, WorldReplayClosureV1,
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

struct ImportedRuntimeVerifier {
    leaf: TimelineId,
    sources: Vec<WorldReplayForkSourceV1>,
    required: Vec<ForkReplayRequirementV1>,
    limits: ForkReplayReadLimitsV1,
    arm_depth: usize,
}

impl WorldReplayVerifierV1 for ImportedRuntimeVerifier {
    fn read_profile(
        &self,
        _closure: &WorldReplayClosureV1,
        intent: &pos_runtime::WorldReplayReadIntentV1,
        _generation: ErasureReferenceV1,
    ) -> Result<(EventReadBounds, ForkReplayReadLimitsV1), WorldReplayVerificationErrorV1> {
        if intent.timeline_id() != self.leaf {
            return Err(WorldReplayVerificationErrorV1::RequestMismatch);
        }
        Ok((
            EventReadBounds::new_with_total_bytes_and_elapsed(
                1_024,
                128,
                self.arm_depth,
                64,
                1_048_576,
                1_000_000,
            ),
            self.limits,
        ))
    }

    fn verify(
        &self,
        closure: &WorldReplayClosureV1,
        requested: &WorldReplayUseV1,
        generation: ErasureReferenceV1,
    ) -> Result<VerifiedWorldReplayV1, WorldReplayVerificationErrorV1> {
        if requested.timeline_id() != self.leaf
            || requested.source_logical_head() != Seq::from_u64(4)
        {
            return Err(WorldReplayVerificationErrorV1::RequestMismatch);
        }
        let bounds = EventReadBounds::new_with_total_bytes_and_elapsed(
            1_024,
            128,
            self.arm_depth,
            64,
            1_048_576,
            1_000_000,
        );
        let verified = pos_runtime::world_replay::test_verified_world_replay_with_fields_and_bounds(
            closure.digest(),
            closure.timeline_id(),
            closure.source_head(),
            requested.clone(),
            generation,
            ErasureReplayClaimV1::Exact,
            (bounds, self.limits),
        );
        Ok(
            pos_runtime::world_replay::test_verified_world_replay_with_fork_attribution(
                verified,
                Some(Hash::from_bytes([0xd7; 32])),
                self.sources.clone(),
                self.required.clone(),
                self.limits,
            ),
        )
    }
}

fn imported_host(
    world: &World,
    limits: ForkReplayReadLimitsV1,
    arm_depth: usize,
) -> Fallible<ErasureExecutionHostV1> {
    assert_eq!(world.children.len(), 2);
    let mut store = MemoryStore::new();
    world.seed_destination(&mut store)?;
    let mut required = Vec::new();
    for (index, child) in world.children.iter().enumerate() {
        let spec = if index == 0 {
            Spec::default()
        } else {
            Spec::distinct(index)
        };
        let built = world.build(&spec)?;
        assert_eq!(child.parent_cut, 4);
        assert_eq!(child.shape, Shape::EmptyUnclassified);
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
        required.push(ForkReplayRequirementV1::new(
            child.id,
            Seq::from_u64(4),
            committed.record_id,
            committed.authority_origin_digest,
        )?);
    }
    required.reverse();
    let leaf = world.child_at(1)?.id;
    let mut sources = required
        .iter()
        .map(|required| WorldReplayForkSourceV1::new(required.child_timeline_id(), Some(*required)))
        .collect::<Result<Vec<_>, _>>()?;
    sources.push(WorldReplayForkSourceV1::new(world.root, None)?);
    let verifier = Arc::new(ImportedRuntimeVerifier {
        leaf,
        sources,
        required,
        limits,
        arm_depth,
    });
    let composition =
        ErasureCoordinatorCompositionV1::closed().with_world_replay_verifier(verifier);
    Ok(
        ErasureExecutionHostV1::recover_memory_fixture_with_authority(
            store,
            &composition,
            ErasureRecoveryLimitsV1::compiled_maximum(),
        )?,
    )
}

#[test]
fn imported_memory_runtime_checks_effective_depth_before_deep_ancestor() -> Fallible<()> {
    let mut world = World::new(Shape::EmptyUnclassified, false)?;
    let parent = world.child_at(0)?.id;
    world.add_child_at(parent, Seq::from_u64(4), Shape::EmptyUnclassified)?;
    let leaf = world.child_at(1)?.id;
    assert_eq!(world.source.read(world.root, SeqRange::all())?.len(), 4);
    for (ledger_depth, arm_depth, succeeds) in [(2, 2, true), (2, 1, false), (1, 2, false)] {
        let limits =
            ForkReplayReadLimitsV1::new(ledger_depth, 1_024, 65_536, 1_048_576, 1_000_000)?;
        let mut host = imported_host(&world, limits, arm_depth)?;
        let generation = Hash::from_bytes(host.containment_gate().inventory_generation()?.digest());
        let closure = WorldReplayClosureV1::test_fixture_for_timeline_with_inventory_generation(
            leaf, generation,
        )?;
        let requested = WorldReplayUseV1::new(
            leaf,
            ErasureProtectedOperationV1::Read,
            SeqRange::all(),
            Seq::from_u64(4),
            vec!["count".to_owned()],
            Vec::new(),
        )?;
        let mut reads = host.read_sender()?;
        // The installed owner, not a caller-forged Runtime value, mints the
        // complete [leaf,parent,root] classification and both real imports.
        let capability = reads.admit_world_replay(&closure, &requested)?;
        let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::from_millis(1)]);
        let g0 = clock.mark();
        let mut budget = ForkReplayReadBudgetV1::new(limits, g0, &mut clock)?;
        let mut result = Err(ErasureHostErrorV1::Conflict);
        reads.with_protected_ancestry_fence(
            leaf,
            ErasureProtectedOperationV1::Read,
            &mut |sender| {
                result = sender.validate_world_replay_forks(&capability, &mut budget);
                if !succeeds {
                    assert_eq!(
                        result.as_ref().map(|_| ()),
                        Err(&ErasureHostErrorV1::AdapterFailure)
                    );
                    // Two empty Fork carriers each cost metadata49 + visitedID16
                    // + parentID16. Refusal precedes the root carrier/cursors.
                    assert_eq!(
                        limits.max_native_bytes() - budget.remaining_native_bytes(),
                        2 * (49 + 16 + 16)
                    );
                    let remaining = budget.remaining_native_bytes();
                    assert_eq!(
                        sender
                            .validate_world_replay_forks(&capability, &mut budget)
                            .map(|_| ()),
                        Err(ErasureHostErrorV1::AdapterFailure)
                    );
                    assert!(budget.check_time().is_err());
                    assert_eq!(budget.remaining_native_bytes(), remaining);
                }
            },
        )?;
        if succeeds {
            assert_eq!(result?.len(), 2);
            assert!(budget.remaining_native_bytes() < limits.max_native_bytes());
            budget.check_time()?;
        }
    }
    Ok(())
}
