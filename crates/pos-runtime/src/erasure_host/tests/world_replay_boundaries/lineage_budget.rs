//! Whole-operation refusals over a real, empty two-level Memory lineage.

use super::*;

// Reading child visibility visits child and root; reading root visits root.
// Each native visit remembers a 16-byte ID, copies 49/25 metadata bytes,
// and a child also copies its 16-byte parent ID. No Events are present.
const CHILD_READ_BYTES: usize = 16 + 49 + 16 + 16 + 25;
const ROOT_READ_BYTES: usize = 16 + 25;
const VALIDATION_BYTES: usize = CHILD_READ_BYTES + 24 + ROOT_READ_BYTES;
const FENCE_BYTES: usize = CHILD_READ_BYTES + 16 + 16 + ROOT_READ_BYTES + 16;
const GOOD_MARK: Duration = Duration::from_millis(1);

struct LineageFixture {
    host: ErasureExecutionHostV1,
    prepared: PreparedWorldReplayReadV1,
    classified: VerifiedWorldReplayV1,
}

impl LineageFixture {
    fn new() -> Self {
        let (mut host, _) = world_replay_host(WorldReplayVerifierModeV1::Exact);
        let (root, child) = {
            let mut commands = test_ok(host.command_sender());
            let root = test_ok(commands.create_timeline("budget root")).id();
            let child = test_ok(commands.fork_timeline(root, Seq::ZERO, "budget child")).id();
            (root, child)
        };
        let generation = test_ok(host.gate.inventory_generation());
        let closure = test_ok(
            WorldReplayClosureV1::test_fixture_for_timeline_with_inventory_generation(
                child,
                Hash::from_bytes(generation.digest()),
            ),
        );
        let requested = replay_use(&closure);
        let mut sender = test_ok(host.read_sender());
        let prepared = test_ok(sender.prepare_world_replay_read(&closure, intent_for(&requested)));
        let verified = test_ok(sender.admit_world_replay(&closure, &requested));
        let sources = [child, root]
            .map(|timeline| test_ok(crate::WorldReplayForkSourceV1::new(timeline, None)));
        // Classify the ordinary Fork explicitly to exercise complete native
        // traversal, without inventing imported authority or adapter failures.
        let classified = crate::world_replay::test_verified_world_replay_with_fork_attribution(
            verified,
            Some(Hash::from_bytes([0xda; 32])),
            sources.to_vec(),
            Vec::new(),
            prepared.fork_read_limits(),
        );
        Self {
            host,
            prepared,
            classified,
        }
    }

    fn validate(
        &mut self,
        budget: &mut ForkReplayReadBudgetV1<'_>,
    ) -> Result<(), ErasureHostErrorV1> {
        let mut result = Err(ErasureHostErrorV1::Conflict);
        let mut sender = test_ok(self.host.read_sender());
        sender.with_protected_ancestry_fence(
            self.classified.timeline_id(),
            ErasureProtectedOperationV1::Read,
            &mut |sender| {
                result = sender
                    .validate_world_replay_forks(&self.classified, budget)
                    .map(|evidence| assert!(evidence.is_empty()));
            },
        )?;
        result
    }

    fn fence(
        &mut self,
        budget: &mut ForkReplayReadBudgetV1<'_>,
        callbacks: &Cell<usize>,
        installed: &Cell<bool>,
    ) -> Result<(), ErasureHostErrorV1> {
        test_ok(self.host.read_sender()).with_world_replay_read_fence(
            &[&self.prepared],
            budget,
            |_, _| {
                callbacks.set(callbacks.get() + 1);
                Ok(())
            },
            |(), verdict| {
                callbacks.set(callbacks.get() + 1);
                verdict?;
                installed.set(true);
                Ok(())
            },
        )
    }
}

fn clock_for(good_marks: Option<usize>, bad_mark: Duration) -> ScriptedGuardMonotonicSourceV1 {
    let script = good_marks.map_or_else(
        || vec![GOOD_MARK],
        |marks| {
            // g0 and ledger construction remain healthy. The good mark after
            // the refusal proves that failure is latched, not transient.
            std::iter::repeat_n(GOOD_MARK, marks + 2)
                .chain([bad_mark, GOOD_MARK])
                .collect()
        },
    );
    ScriptedGuardMonotonicSourceV1::new(script)
}

#[test]
fn classified_lineage_latches_expiry_and_regression_at_every_checkpoint() {
    let mut fixture = LineageFixture::new();
    let limits = fixture.prepared.fork_read_limits();
    let expired = GOOD_MARK + Duration::from_micros(limits.max_elapsed_micros() + 1);
    for bad_mark in [expired, Duration::ZERO] {
        let mut probe = |good_marks: Option<usize>| {
            let mut clock = clock_for(good_marks, bad_mark);
            let g0 = clock.mark();
            let mut budget = test_ok(ForkReplayReadBudgetV1::new(limits, g0, &mut clock));
            let expected = good_marks.map_or(Ok(()), |_| Err(ErasureHostErrorV1::AdapterFailure));
            assert_eq!(fixture.validate(&mut budget), expected);
            if good_marks.is_none() {
                assert_eq!(
                    limits.max_native_bytes() - budget.remaining_native_bytes(),
                    VALIDATION_BYTES
                );
            } else {
                let remaining = budget.remaining_native_bytes();
                assert_eq!(fixture.validate(&mut budget), expected);
                assert_eq!(budget.remaining_native_bytes(), remaining);
            }
            assert_eq!(budget.check_time().is_ok(), good_marks.is_none());
            assert_eq!(fixture.host.status(), ErasureHostStatusV1::Ready);
            clock.samples_taken()
        };
        // Only discover checkpoint positions. The independent debit formula,
        // exact refusal, permanent latch and healthy control define correctness.
        let checkpoints = probe(None) - 3;
        assert!((2..1_024).contains(&checkpoints));
        for good_marks in 0..checkpoints {
            assert_eq!(probe(Some(good_marks)), good_marks + 3);
        }
        probe(None);
    }
}

#[test]
fn owning_fence_latches_each_clock_refusal_before_installation_and_releases_gates() {
    let mut fixture = LineageFixture::new();
    let limits = fixture.prepared.fork_read_limits();
    let expired = GOOD_MARK + Duration::from_micros(limits.max_elapsed_micros() + 1);
    for bad_mark in [expired, Duration::ZERO] {
        let mut probe = |good_marks: Option<usize>| {
            let mut clock = clock_for(good_marks, bad_mark);
            let g0 = clock.mark();
            let mut budget = test_ok(ForkReplayReadBudgetV1::new(limits, g0, &mut clock));
            let callbacks = Cell::new(0);
            let installed = Cell::new(false);
            let expected = good_marks.map_or(Ok(()), |_| Err(ErasureHostErrorV1::AdapterFailure));
            assert_eq!(fixture.fence(&mut budget, &callbacks, &installed), expected);
            assert_eq!(installed.get(), good_marks.is_none());
            let called = callbacks.get();
            if good_marks.is_none() {
                assert_eq!(called, 2);
                assert_eq!(
                    limits.max_native_bytes() - budget.remaining_native_bytes(),
                    FENCE_BYTES
                );
            } else {
                let remaining = budget.remaining_native_bytes();
                assert_eq!(fixture.fence(&mut budget, &callbacks, &installed), expected);
                assert_eq!(callbacks.get(), called);
                assert_eq!(budget.remaining_native_bytes(), remaining);
            }
            assert_eq!(budget.check_time().is_ok(), good_marks.is_none());
            assert_eq!(fixture.host.status(), ErasureHostStatusV1::Ready);
            (clock.samples_taken(), called)
        };
        let checkpoints = probe(None).0 - 3;
        assert!((2..1_024).contains(&checkpoints));
        for good_marks in 0..checkpoints {
            let (samples, callbacks) = probe(Some(good_marks));
            assert_eq!(samples, good_marks + 3);
            // Only the final post-staging check can call either callback;
            // complete receives its refusal and cannot install detached State.
            assert_eq!(callbacks, if good_marks + 1 == checkpoints { 2 } else { 0 });
            // Same host and preparations: reacquisition proves gate release.
            probe(None);
        }
    }
}

#[test]
fn classified_parent_copy_uses_the_original_remaining_byte_budget() {
    let mut fixture = LineageFixture::new();
    let limits = fixture.prepared.fork_read_limits();
    for (available, remaining, succeeds) in [
        (CHILD_READ_BYTES + 23, 23, false),
        (VALIDATION_BYTES, 0, true),
        (CHILD_READ_BYTES + 24, 0, false),
        (VALIDATION_BYTES + 1, 1, true),
    ] {
        let mut clock = clock_for(None, Duration::ZERO);
        let g0 = clock.mark();
        let mut budget = test_ok(ForkReplayReadBudgetV1::new(limits, g0, &mut clock));
        // Earlier whole-operation work consumes the prefix; Runtime must not
        // replace this original ledger with the capability's full ceiling.
        test_ok(budget.charge_bytes(limits.max_native_bytes() - available));
        let expected = if succeeds {
            Ok(())
        } else {
            Err(ErasureHostErrorV1::AdapterFailure)
        };
        assert_eq!(fixture.validate(&mut budget), expected);
        assert_eq!(budget.remaining_native_bytes(), remaining);
        assert_eq!(budget.check_time().is_ok(), succeeds);
        assert_eq!(fixture.host.status(), ErasureHostStatusV1::Ready);
    }
}

#[test]
fn owning_fence_funds_visited_and_parent_copies_before_callbacks() {
    let mut fixture = LineageFixture::new();
    let limits = fixture.prepared.fork_read_limits();
    for (available, remaining, succeeds) in [
        (CHILD_READ_BYTES + 15, 15, false),
        (FENCE_BYTES, 0, true),
        (CHILD_READ_BYTES + 16 + 15, 15, false),
        (FENCE_BYTES + 1, 1, true),
    ] {
        let mut clock = clock_for(None, Duration::ZERO);
        let g0 = clock.mark();
        let mut budget = test_ok(ForkReplayReadBudgetV1::new(limits, g0, &mut clock));
        test_ok(budget.charge_bytes(limits.max_native_bytes() - available));
        let callbacks = Cell::new(0);
        let installed = Cell::new(false);
        assert_eq!(
            fixture.fence(&mut budget, &callbacks, &installed),
            if succeeds {
                Ok(())
            } else {
                Err(ErasureHostErrorV1::AdapterFailure)
            }
        );
        assert_eq!(callbacks.get(), if succeeds { 2 } else { 0 });
        assert_eq!(installed.get(), succeeds);
        assert_eq!(budget.remaining_native_bytes(), remaining);
        assert_eq!(budget.check_time().is_ok(), succeeds);
        assert_eq!(fixture.host.status(), ErasureHostStatusV1::Ready);
    }
}
