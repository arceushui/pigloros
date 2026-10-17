//! Reject stale or substituted preparations before touching native history.

use super::*;
use pos_core::trusted_clock::{GuardMonotonicSourceV1, ScriptedGuardMonotonicSourceV1};
use std::{cell::Cell, time::Duration};

mod lineage_budget;

fn intent_for(requested: &WorldReplayUseV1) -> WorldReplayReadIntentV1 {
    test_ok(WorldReplayReadIntentV1::new(
        requested.timeline_id(),
        requested.operation(),
        requested.range(),
        requested.consumer_ids().to_vec(),
        requested.requested_optional_view_roots().to_vec(),
    ))
}

#[test]
fn every_prepared_event_bound_must_be_independently_finite() {
    let (mut host, closure) = world_replay_host(WorldReplayVerifierModeV1::Exact);
    let requested = replay_use(&closure);
    let intent = intent_for(&requested);
    let prepared =
        test_ok(test_ok(host.read_sender()).prepare_world_replay_read(&closure, intent.clone()));
    for dimension in 0..6 {
        for unbounded in [false, true] {
            let mut sizes = [1; 5];
            let mut elapsed = 1;
            if dimension < sizes.len() {
                sizes[dimension] = if unbounded { usize::MAX } else { 0 };
            } else {
                elapsed = if unbounded { u64::MAX } else { 0 };
            }
            let bounds = EventReadBounds::new_with_total_bytes_and_elapsed(
                sizes[0], sizes[1], sizes[2], sizes[3], sizes[4], elapsed,
            );
            assert_eq!(
                PreparedWorldReplayReadV1::new(
                    &closure,
                    intent.clone(),
                    prepared.generation(),
                    Arc::clone(prepared.owner()),
                    bounds,
                    prepared.fork_read_limits(),
                )
                .err(),
                Some(WorldReplayVerificationErrorV1::RequestMismatch),
                "dimension {dimension}, unbounded {unbounded}"
            );
        }
    }
    assert!(PreparedWorldReplayReadV1::new(
        &closure,
        intent,
        prepared.generation(),
        Arc::clone(prepared.owner()),
        EventReadBounds::new_with_total_bytes_and_elapsed(1, 1, 1, 1, 1, 1),
        prepared.fork_read_limits(),
    )
    .is_ok());
}

#[test]
fn preparations_reject_stale_generation_and_substituted_closure_or_use() {
    let (mut host, closure) = world_replay_host(WorldReplayVerifierModeV1::Exact);
    let requested = replay_use(&closure);
    let intent = intent_for(&requested);
    let stale_closure = test_ok(
        WorldReplayClosureV1::test_fixture_with_inventory_generation(Hash::from_bytes(
            reference(1).digest(),
        )),
    );
    let mut sender = test_ok(host.read_sender());
    assert_eq!(
        sender
            .prepare_world_replay_read(&stale_closure, intent.clone())
            .err(),
        Some(ErasureHostErrorV1::StaleGeneration),
    );
    let prepared = test_ok(sender.prepare_world_replay_read(&closure, intent.clone()));
    let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
    let start = clock.mark();
    let mut budget = test_ok(ForkReplayReadBudgetV1::new(
        prepared.fork_read_limits(),
        start,
        &mut clock,
    ));
    // Model a previously issued opaque preparation, not a stale sender. The
    // constructor is Runtime-private and grants no authority to external code.
    let stale = test_ok(PreparedWorldReplayReadV1::new(
        &stale_closure,
        intent.clone(),
        reference(1),
        Arc::clone(prepared.owner()),
        prepared.read_bounds(),
        prepared.fork_read_limits(),
    ));
    let foreign = test_ok(PreparedWorldReplayReadV1::new(
        &closure,
        intent,
        prepared.generation(),
        Arc::new(WorldReplayVerifierModeV1::Exact),
        prepared.read_bounds(),
        prepared.fork_read_limits(),
    ));
    for (refused, expected) in [
        (&stale, ErasureHostErrorV1::StaleGeneration),
        (&foreign, ErasureHostErrorV1::Conflict),
    ] {
        let callbacks = Cell::new(0);
        let before = budget.remaining_native_bytes();
        assert_eq!(
            sender.with_world_replay_read_fence(
                &[&prepared, refused],
                &mut budget,
                |_, _| {
                    callbacks.set(callbacks.get() + 1);
                    Ok(())
                },
                |(), verdict| {
                    callbacks.set(callbacks.get() + 1);
                    verdict
                },
            ),
            Err(expected)
        );
        assert_eq!(callbacks.get(), 0);
        assert_eq!(budget.remaining_native_bytes(), before);
    }
    assert_eq!(
        sender.observe_world_replay_use(&stale, &mut budget),
        Err(ErasureHostErrorV1::StaleGeneration),
    );
    assert_eq!(
        sender.admit_prepared_world_replay(&prepared, &stale_closure, &requested, &mut budget),
        Err(ErasureHostErrorV1::Conflict),
    );
    let different_use = test_ok(WorldReplayUseV1::new(
        requested.timeline_id(),
        ErasureProtectedOperationV1::Snapshot,
        requested.range(),
        requested.source_logical_head(),
        requested.consumer_ids().to_vec(),
        Vec::new(),
    ));
    assert_eq!(
        sender.admit_prepared_world_replay(&prepared, &closure, &different_use, &mut budget),
        Err(ErasureHostErrorV1::Conflict),
    );
    // Identity refusals do not consume or poison otherwise valid authority.
    assert!(sender
        .admit_prepared_world_replay(&prepared, &closure, &requested, &mut budget,)
        .is_ok());
}

#[test]
fn event_reads_reject_stale_capabilities_and_substituted_operation_budgets() {
    let (mut host, closure) = world_replay_host(WorldReplayVerifierModeV1::Exact);
    let requested = replay_use(&closure);
    let mut sender = test_ok(host.read_sender());
    let verified = test_ok(sender.admit_world_replay(&closure, &requested));
    let non_authoritative = crate::world_replay::test_verified_world_replay(
        &closure,
        &requested,
        verified.inventory_generation(),
        pos_core::ErasureReplayClaimV1::StructuralOnly,
        verified.fork_read_limits(),
    );
    let stale = crate::world_replay::test_verified_world_replay(
        &closure,
        &requested,
        reference(1),
        pos_core::ErasureReplayClaimV1::Exact,
        verified.fork_read_limits(),
    );
    let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
    let start = clock.mark();
    let mut budget = test_ok(ForkReplayReadBudgetV1::new(
        verified.fork_read_limits(),
        start,
        &mut clock,
    ));
    assert_eq!(verified.require_authoritative_use(), Ok(()));
    let before = budget.remaining_native_bytes();
    assert_eq!(
        sender.read_world_replay_events(&non_authoritative, &mut budget),
        Err(ErasureHostErrorV1::AuthorizationDenied),
    );
    assert_eq!(budget.remaining_native_bytes(), before);
    assert_eq!(
        sender.read_world_replay_events(&stale, &mut budget),
        Err(ErasureHostErrorV1::StaleGeneration),
    );
    let mut other_clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
    let start = other_clock.mark();
    let limits = test_ok(pos_store::ForkReplayReadLimitsV1::new(
        1, 1, 1, 1, 1_000_000,
    ));
    let mut other_budget = test_ok(ForkReplayReadBudgetV1::new(limits, start, &mut other_clock));
    assert_eq!(
        sender.read_world_replay_events(&verified, &mut other_budget),
        Err(ErasureHostErrorV1::Conflict),
    );
    assert_eq!(host.status(), ErasureHostStatusV1::Ready);
}

#[test]
fn prepared_admission_rechecks_original_deadline_after_verification() {
    let (mut host, closure) = world_replay_host(WorldReplayVerifierModeV1::Exact);
    let requested = replay_use(&closure);
    let mut sender = test_ok(host.read_sender());
    let prepared = test_ok(sender.prepare_world_replay_read(&closure, intent_for(&requested)));
    let good_mark = Duration::from_millis(1);
    let expired_mark = Duration::from_micros(prepared.fork_read_limits().max_elapsed_micros())
        + good_mark
        + Duration::from_micros(1);
    for post_verifier_mark in [good_mark, expired_mark, Duration::ZERO] {
        // g0, budget construction and preparation validation are healthy.
        // The fourth sample is the post-verifier check: expiry or regression
        // must override the otherwise valid capability and remain latched.
        let mut clock = ScriptedGuardMonotonicSourceV1::new(
            [good_mark; 3]
                .into_iter()
                .chain([post_verifier_mark, good_mark]),
        );
        let start = clock.mark();
        let mut budget = test_ok(ForkReplayReadBudgetV1::new(
            prepared.fork_read_limits(),
            start,
            &mut clock,
        ));
        let result = sender
            .admit_prepared_world_replay(&prepared, &closure, &requested, &mut budget)
            .map(|_| ());
        let healthy = post_verifier_mark == good_mark;
        assert_eq!(
            result,
            if healthy {
                Ok(())
            } else {
                Err(ErasureHostErrorV1::AdapterFailure)
            }
        );
        assert_eq!(budget.check_time().is_ok(), healthy);
        assert_eq!(
            budget.remaining_native_bytes(),
            prepared.fork_read_limits().max_native_bytes()
        );
        assert_eq!(clock.samples_taken(), if healthy { 5 } else { 4 });
    }
    assert_eq!(host.status(), ErasureHostStatusV1::Ready);
}

#[test]
fn prepared_admission_requires_each_original_policy_dimension() {
    let (mut host, closure) = world_replay_host(WorldReplayVerifierModeV1::Exact);
    let requested = replay_use(&closure);
    let mut sender = test_ok(host.read_sender());
    let original = test_ok(sender.prepare_world_replay_read(&closure, intent_for(&requested)));
    for (different_bounds, different_limits) in [(false, false), (true, false), (false, true)] {
        let bounds = if different_bounds {
            EventReadBounds::new_with_total_bytes_and_elapsed(
                65_535, 128, 8, 65_536, 67_108_864, 30_000_000,
            )
        } else {
            original.read_bounds()
        };
        let limits = if different_limits {
            test_ok(pos_store::ForkReplayReadLimitsV1::new(
                8,
                1_023,
                262_144,
                256 * 1024 * 1024,
                30_000_000,
            ))
        } else {
            original.fork_read_limits()
        };
        // Model a retained preparation whose owner later returns one changed
        // policy dimension. Its identity, use and original ledger still agree.
        let prepared = test_ok(PreparedWorldReplayReadV1::new(
            &closure,
            intent_for(&requested),
            original.generation(),
            Arc::clone(original.owner()),
            bounds,
            limits,
        ));
        let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
        let start = clock.mark();
        let mut budget = test_ok(ForkReplayReadBudgetV1::new(limits, start, &mut clock));
        assert_eq!(
            sender
                .admit_prepared_world_replay(&prepared, &closure, &requested, &mut budget)
                .map(|_| ()),
            if different_bounds || different_limits {
                Err(ErasureHostErrorV1::Conflict)
            } else {
                Ok(())
            }
        );
        assert_eq!(budget.remaining_native_bytes(), limits.max_native_bytes());
        test_ok(budget.check_time());
    }
    assert_eq!(host.status(), ErasureHostStatusV1::Ready);
}

#[test]
fn ordinary_history_refuses_an_unclassified_fork_requirement() {
    let (mut host, closure) = replay_fault_host(FaultModeV1::Passthrough);
    let requested = replay_use(&closure);
    let mut sender = test_ok(host.read_sender());
    let ordinary = test_ok(sender.admit_world_replay(&closure, &requested));
    let requirement = test_ok(pos_store::ForkReplayRequirementV1::new(
        closure.timeline_id(),
        requested.source_logical_head(),
        Hash::from_bytes([0x91; 32]),
        None,
    ));
    let inconsistent =
        crate::world_replay::test_with_unclassified_fork_requirement(ordinary.clone(), requirement);
    let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
    let start = clock.mark();
    let mut budget = test_ok(ForkReplayReadBudgetV1::new(
        ordinary.fork_read_limits(),
        start,
        &mut clock,
    ));
    assert!(test_ok(sender.validate_world_replay_forks(&ordinary, &mut budget)).is_empty());
    let remaining_bytes = budget.remaining_native_bytes();
    assert_eq!(
        sender.validate_world_replay_forks(&inconsistent, &mut budget),
        Err(ErasureHostErrorV1::Conflict)
    );
    assert_eq!(budget.remaining_native_bytes(), remaining_bytes);
    test_ok(budget.check_time());
    assert!(test_ok(sender.validate_world_replay_forks(&ordinary, &mut budget)).is_empty());
    assert_eq!(host.status(), ErasureHostStatusV1::Ready);
}

#[test]
fn read_fence_rejects_zero_or_three_arms_without_invoking_callbacks() {
    let (mut host, closure) = world_replay_host(WorldReplayVerifierModeV1::Exact);
    let requested = replay_use(&closure);
    let mut sender = test_ok(host.read_sender());
    let prepared = test_ok(sender.prepare_world_replay_read(&closure, intent_for(&requested)));
    let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
    let start = clock.mark();
    let mut budget = test_ok(ForkReplayReadBudgetV1::new(
        prepared.fork_read_limits(),
        start,
        &mut clock,
    ));
    for arms in [Vec::new(), vec![&prepared, &prepared, &prepared]] {
        let callbacks = Cell::new(0);
        let result = sender.with_world_replay_read_fence(
            &arms,
            &mut budget,
            |_, _| {
                callbacks.set(callbacks.get() + 1);
                Ok(())
            },
            |(), verdict| {
                callbacks.set(callbacks.get() + 1);
                verdict
            },
        );
        assert_eq!(result, Err(ErasureHostErrorV1::Conflict));
        assert_eq!(callbacks.get(), 0);
    }
}

#[test]
fn fork_source_rejects_attribution_for_a_different_timeline() {
    let timeline = TimelineId::new();
    let required = test_ok(pos_store::ForkReplayRequirementV1::new(
        timeline,
        pos_core::Seq::ZERO,
        Hash::from_bytes([7; 32]),
        None,
    ));
    assert_eq!(
        crate::world_replay::WorldReplayForkSourceV1::new(TimelineId::new(), Some(required)),
        Err(WorldReplayVerificationErrorV1::RequestMismatch),
    );
    let source = test_ok(crate::world_replay::WorldReplayForkSourceV1::new(
        timeline,
        Some(required),
    ));
    assert_eq!(source.timeline_id(), timeline);
    assert_eq!(source.required_attribution(), Some(required));
}

fn replay_fault_host(fault: FaultModeV1) -> (ErasureExecutionHostV1, WorldReplayClosureV1) {
    let composition = ErasureCoordinatorCompositionV1::closed()
        .with_world_replay_verifier(Arc::new(WorldReplayVerifierModeV1::Exact));
    let mut host = test_ok(ErasureExecutionHostV1::recover_with_composition(
        Box::new(fault_store(fault)),
        &composition,
        ErasureRecoveryLimitsV1::compiled_maximum(),
    ));
    let root = {
        let mut sender = test_ok(host.command_sender());
        let root = test_ok(sender.create_timeline("replay boundary")).id();
        test_ok(sender.append(
            root,
            &[EventDraft::new(
                EntityId::new(),
                Kind::new("host.fixture"),
                CanonicalBytes::from_vec(Vec::new()),
            )],
        ));
        root
    };
    let generation = test_ok(host.gate.inventory_generation());
    let closure = test_ok(
        WorldReplayClosureV1::test_fixture_for_timeline_with_inventory_generation(
            root,
            Hash::from_bytes(generation.digest()),
        ),
    );
    (host, closure)
}

#[test]
fn event_reads_reject_malformed_successful_batches_and_stale_heads() {
    for (fault, head, succeeds) in [
        (FaultModeV1::Passthrough, 1, true),
        (FaultModeV1::ForkReplayEventCount, 1, false),
        (FaultModeV1::ForkReplayEventSequence, 1, false),
        (FaultModeV1::Passthrough, 0, false),
    ] {
        let (mut host, closure) = replay_fault_host(fault);
        let requested = test_ok(WorldReplayUseV1::new(
            closure.timeline_id(),
            ErasureProtectedOperationV1::Read,
            SeqRange::all(),
            Seq::from_u64(head),
            vec!["count".to_owned()],
            Vec::new(),
        ));
        let generation = test_ok(host.gate.inventory_generation());
        let verified = crate::world_replay::test_verified_world_replay(
            &closure,
            &requested,
            generation,
            pos_core::ErasureReplayClaimV1::Exact,
            test_ok(pos_store::ForkReplayReadLimitsV1::new(
                8,
                1_024,
                262_144,
                256 * 1024 * 1024,
                30_000_000,
            )),
        );
        let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
        let start = clock.mark();
        let mut budget = test_ok(ForkReplayReadBudgetV1::new(
            verified.fork_read_limits(),
            start,
            &mut clock,
        ));
        let result = test_ok(host.read_sender()).read_world_replay_events(&verified, &mut budget);
        if succeeds {
            let events = test_ok(result);
            assert_eq!(events.len(), 1);
            assert_eq!(events[0].seq, Seq::from_u64(1));
        } else {
            assert_eq!(result, Err(ErasureHostErrorV1::AdapterFailure));
        }
        assert_eq!(host.status(), ErasureHostStatusV1::Ready);
    }
}

#[test]
fn bounded_reads_keep_partial_ranges_and_accept_the_exact_event_ceiling() {
    let (mut host, closure) = replay_fault_host(FaultModeV1::Passthrough);
    test_ok(test_ok(host.command_sender()).append(
        closure.timeline_id(),
        &[EventDraft::new(
            EntityId::new(),
            Kind::new("host.fixture"),
            CanonicalBytes::from_vec(Vec::new()),
        )],
    ));
    let generation = test_ok(host.gate.inventory_generation());
    let limits = test_ok(pos_store::ForkReplayReadLimitsV1::new(
        8,
        1_024,
        262_144,
        256 * 1024 * 1024,
        30_000_000,
    ));
    for (last, maximum, expected_count) in [(1, 1, Some(1)), (2, 2, Some(2)), (2, 1, None)] {
        let requested = test_ok(WorldReplayUseV1::new(
            closure.timeline_id(),
            ErasureProtectedOperationV1::Read,
            SeqRange::bounded(Seq::from_u64(1), Seq::from_u64(last)),
            Seq::from_u64(2),
            vec!["count".to_owned()],
            Vec::new(),
        ));
        let verified = crate::world_replay::test_verified_world_replay_with_fields_and_bounds(
            closure.digest(),
            closure.timeline_id(),
            closure.source_head(),
            requested,
            generation,
            pos_core::ErasureReplayClaimV1::Exact,
            (
                EventReadBounds::new_with_total_bytes_and_elapsed(
                    65_536, 128, 8, maximum, 67_108_864, 30_000_000,
                ),
                limits,
            ),
        );
        let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
        let start = clock.mark();
        let mut budget = test_ok(ForkReplayReadBudgetV1::new(limits, start, &mut clock));
        let result = test_ok(host.read_sender()).read_world_replay_events(&verified, &mut budget);
        if let Some(count) = expected_count {
            let events = test_ok(result);
            assert_eq!(events.len(), count);
            assert_eq!(events[0].seq, Seq::from_u64(1));
            assert_eq!(events[count - 1].seq, Seq::from_u64(last));
        } else {
            assert_eq!(result, Err(ErasureHostErrorV1::AdapterFailure));
        }
        assert_eq!(host.status(), ErasureHostStatusV1::Ready);
    }
}

#[test]
fn two_sqlite_read_arms_keep_independent_depths_and_settle_the_owned_interval() {
    use crate::world_replay::test_support::{with_replay_observer, ReplayPhaseV1};
    use std::{cell::RefCell, rc::Rc};
    let composition = ErasureCoordinatorCompositionV1::closed()
        .with_world_replay_verifier(Arc::new(WorldReplayVerifierModeV1::Exact));
    let mut host = test_ok(ErasureExecutionHostV1::open_with_authority(
        StoreConfig::SqliteInMemory,
        &composition,
        ErasureRecoveryLimitsV1::compiled_maximum(),
    ));
    let mut leaves = Vec::new();
    for _ in 0..2 {
        let mut sender = test_ok(host.command_sender());
        let mut leaf = test_ok(sender.create_timeline("read arm root")).id();
        for _ in 0..4 {
            leaf = test_ok(sender.fork_timeline(leaf, Seq::ZERO, "read arm child")).id();
        }
        leaves.push(leaf);
    }
    let generation = test_ok(host.gate.inventory_generation());
    let preparations: Vec<_> = leaves
        .into_iter()
        .map(|timeline| {
            let closure = test_ok(
                WorldReplayClosureV1::test_fixture_for_timeline_with_inventory_generation(
                    timeline,
                    Hash::from_bytes(generation.digest()),
                ),
            );
            let requested = replay_use(&closure);
            test_ok(
                test_ok(host.read_sender())
                    .prepare_world_replay_read(&closure, intent_for(&requested)),
            )
        })
        .collect();
    // Run twice: leaking the first owned SQLite transaction would make the
    // second acquisition borrowed and would omit its required settlement.
    for _ in 0..2 {
        let phases = Rc::new(RefCell::new(Vec::new()));
        let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
        let start = clock.mark();
        let mut budget = test_ok(ForkReplayReadBudgetV1::new(
            preparations[0].fork_read_limits(),
            start,
            &mut clock,
        ));
        let result = with_replay_observer(
            Rc::new({
                let phases = Rc::clone(&phases);
                move |phase| phases.borrow_mut().push(phase)
            }),
            || {
                test_ok(host.read_sender()).with_world_replay_read_fence(
                    &[&preparations[0], &preparations[1]],
                    &mut budget,
                    |_, _| Ok(()),
                    |(), verdict| verdict,
                )
            },
        );
        assert_eq!(result, Ok(()));
        let phases = phases.borrow();
        assert_eq!(
            phases
                .iter()
                .filter(|phase| **phase == ReplayPhaseV1::BeforeRollback)
                .count(),
            1
        );
        assert_eq!(
            phases
                .iter()
                .filter(|phase| **phase == ReplayPhaseV1::AfterRollback)
                .count(),
            1
        );
        assert_eq!(host.status(), ErasureHostStatusV1::Ready);
    }
}

#[test]
fn native_head_and_event_errors_preserve_the_public_refusal_mapping() {
    use pos_store::{
        ForkReplayAuthorityReadErrorV1 as ReadError, ForkReplayLineageReadErrorV1 as LineageError,
    };

    for (native, expected) in [
        (
            LineageError::Read(ReadError::CorruptAuthority),
            ErasureHostErrorV1::AdapterFailure,
        ),
        (LineageError::AccessFrozen, ErasureHostErrorV1::AccessFrozen),
        (
            LineageError::ContainmentUnavailable,
            ErasureHostErrorV1::RecoveryUnavailable,
        ),
    ] {
        for fault in [
            FaultModeV1::ForkReplayHeadError(native),
            FaultModeV1::ForkReplayEventsError(native),
        ] {
            let (mut host, closure) = replay_fault_host(fault);
            let requested = test_ok(WorldReplayUseV1::new(
                closure.timeline_id(),
                ErasureProtectedOperationV1::Read,
                SeqRange::all(),
                Seq::from_u64(1),
                vec!["count".to_owned()],
                Vec::new(),
            ));
            let mut reads = test_ok(host.read_sender());
            let prepared =
                test_ok(reads.prepare_world_replay_read(&closure, intent_for(&requested)));
            let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
            let start = clock.mark();
            let mut budget = test_ok(ForkReplayReadBudgetV1::new(
                prepared.fork_read_limits(),
                start,
                &mut clock,
            ));
            let verified = test_ok(reads.admit_prepared_world_replay(
                &prepared,
                &closure,
                &requested,
                &mut budget,
            ));
            let observed = reads.observe_world_replay_use(&prepared, &mut budget);
            if fault == FaultModeV1::ForkReplayHeadError(native) {
                assert_eq!(observed, Err(expected));
            } else {
                // The Event fault cannot bypass the successful native head
                // read or the independently known one-Event range.
                assert_eq!(test_ok(observed), requested);
            }
            assert_eq!(
                reads.read_world_replay_events(&verified, &mut budget),
                Err(expected)
            );
            test_ok(budget.check_time());
            assert_eq!(host.status(), ErasureHostStatusV1::Ready);
        }
    }
}

#[test]
fn oversized_native_event_counts_refuse_before_materialization() {
    let (mut host, closure) = replay_fault_host(FaultModeV1::ForkReplayOversizedHead);
    let head = Seq::from_u64(u64::from(u32::MAX) + 1);
    for (range, expected) in [
        (SeqRange::all(), ErasureHostErrorV1::AdapterFailure),
        (SeqRange::from_seq(head), ErasureHostErrorV1::AccessFrozen),
    ] {
        let requested = test_ok(WorldReplayUseV1::new(
            closure.timeline_id(),
            ErasureProtectedOperationV1::Read,
            range,
            head,
            vec!["count".to_owned()],
            Vec::new(),
        ));
        let generation = test_ok(host.gate.inventory_generation());
        // Deliberately inconsistent adapter/verifier seam output, not a claim
        // that this one-Event fixture contains billions of admitted Events.
        let verified = crate::world_replay::test_verified_world_replay(
            &closure,
            &requested,
            generation,
            pos_core::ErasureReplayClaimV1::Exact,
            test_ok(pos_store::ForkReplayReadLimitsV1::new(
                8,
                1_024,
                262_144,
                256 * 1024 * 1024,
                30_000_000,
            )),
        );
        let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
        let start = clock.mark();
        let mut budget = test_ok(ForkReplayReadBudgetV1::new(
            verified.fork_read_limits(),
            start,
            &mut clock,
        ));
        // The all-Event range cannot fit usize on 32-bit and exceeds the
        // finite Event bound on 64-bit. A one-Event range at the same head
        // reaches the adapter's distinct materialization refusal on both.
        assert_eq!(
            test_ok(host.read_sender()).read_world_replay_events(&verified, &mut budget),
            Err(expected),
        );
        test_ok(budget.check_time());
        assert_eq!(host.status(), ErasureHostStatusV1::Ready);
    }
}

#[test]
fn native_head_and_event_reads_latch_expiry_at_every_clock_boundary() {
    let (mut host, closure) = replay_fault_host(FaultModeV1::Passthrough);
    let requested = test_ok(WorldReplayUseV1::new(
        closure.timeline_id(),
        ErasureProtectedOperationV1::Read,
        SeqRange::all(),
        Seq::from_u64(1),
        vec!["count".to_owned()],
        Vec::new(),
    ));
    let mut reads = test_ok(host.read_sender());
    let prepared = test_ok(reads.prepare_world_replay_read(&closure, intent_for(&requested)));
    let verified = test_ok(reads.admit_world_replay(&closure, &requested));
    let good_mark = Duration::from_millis(1);
    let expired_mark = Duration::from_micros(prepared.fork_read_limits().max_elapsed_micros())
        + good_mark
        + Duration::from_micros(1);
    for materialize in [false, true] {
        let mut probe = |good_marks: Option<usize>| {
            // A successful trace enumerates clock positions only. Independent
            // head/Event assertions below define success; every expired prefix
            // must refuse and stay latched, including Runtime post-read checks.
            let script = good_marks.map_or_else(
                || vec![good_mark],
                |marks| {
                    std::iter::repeat_n(good_mark, marks + 2)
                        .chain([expired_mark, good_mark])
                        .collect()
                },
            );
            let mut clock = ScriptedGuardMonotonicSourceV1::new(script);
            let start = clock.mark();
            let mut budget = test_ok(ForkReplayReadBudgetV1::new(
                prepared.fork_read_limits(),
                start,
                &mut clock,
            ));
            let result = if materialize {
                reads
                    .read_world_replay_events(&verified, &mut budget)
                    .map(|events| {
                        assert_eq!(events.len(), 1);
                        assert_eq!(events[0].seq, Seq::from_u64(1));
                    })
            } else {
                reads
                    .observe_world_replay_use(&prepared, &mut budget)
                    .map(|observed| assert_eq!(observed, requested))
            };
            assert_eq!(
                result,
                good_marks.map_or(Ok(()), |_| Err(ErasureHostErrorV1::AdapterFailure))
            );
            assert_eq!(budget.check_time().is_ok(), good_marks.is_none());
            clock.samples_taken()
        };
        // Exclude g0, budget construction, and the healthy final assertion.
        // Reuse immutable native history with a fresh ledger per position.
        let checkpoints = probe(None) - 3;
        assert!((2..1_024).contains(&checkpoints));
        for good_marks in 0..checkpoints {
            assert_eq!(probe(Some(good_marks)), good_marks + 3);
        }
        probe(None);
    }
    assert_eq!(host.status(), ErasureHostStatusV1::Ready);
}

#[test]
fn protected_event_reads_preserve_empty_and_past_head_range_boundaries() {
    for (first, succeeds) in [(2, true), (3, false)] {
        let (mut host, closure) = replay_fault_host(FaultModeV1::Passthrough);
        let requested = test_ok(WorldReplayUseV1::new(
            closure.timeline_id(),
            ErasureProtectedOperationV1::Read,
            SeqRange::from_seq(Seq::from_u64(first)),
            Seq::from_u64(1),
            vec!["count".to_owned()],
            Vec::new(),
        ));
        let generation = test_ok(host.gate.inventory_generation());
        let verified = crate::world_replay::test_verified_world_replay(
            &closure,
            &requested,
            generation,
            pos_core::ErasureReplayClaimV1::Exact,
            test_ok(pos_store::ForkReplayReadLimitsV1::new(
                8,
                1_024,
                262_144,
                256 * 1024 * 1024,
                30_000_000,
            )),
        );
        let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
        let start = clock.mark();
        let mut budget = test_ok(ForkReplayReadBudgetV1::new(
            verified.fork_read_limits(),
            start,
            &mut clock,
        ));
        let result = test_ok(host.read_sender()).read_world_replay_events(&verified, &mut budget);
        if succeeds {
            assert!(test_ok(result).is_empty());
        } else {
            assert_eq!(result, Err(ErasureHostErrorV1::AdapterFailure));
        }
        test_ok(budget.check_time());
        assert_eq!(host.status(), ErasureHostStatusV1::Ready);
    }
}

#[test]
fn read_fence_setup_panic_preserves_payload_and_poisons_before_callbacks() {
    let (mut host, closure) = replay_fault_host(FaultModeV1::BeginForkReplayPanic);
    let requested = replay_use(&closure);
    let callbacks = Cell::new(0);
    let mut sender = test_ok(host.read_sender());
    let prepared = test_ok(sender.prepare_world_replay_read(&closure, intent_for(&requested)));
    let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
    let start = clock.mark();
    let mut budget = test_ok(ForkReplayReadBudgetV1::new(
        prepared.fork_read_limits(),
        start,
        &mut clock,
    ));
    let observed = test_ok(sender.observe_world_replay_use(&prepared, &mut budget));
    let verified =
        test_ok(sender.admit_prepared_world_replay(&prepared, &closure, &observed, &mut budget));
    assert_eq!(
        test_ok(sender.read_world_replay_events(&verified, &mut budget)).len(),
        1,
    );
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        sender.with_world_replay_read_fence(
            &[&prepared],
            &mut budget,
            |_, _| {
                callbacks.set(callbacks.get() + 1);
                Ok(())
            },
            |(), verdict| {
                callbacks.set(callbacks.get() + 1);
                verdict
            },
        )
    }));
    let payload = outcome
        .err()
        .unwrap_or_else(|| std::panic::resume_unwind(Box::new("native setup did not unwind")));
    assert_eq!(
        payload.downcast_ref::<&str>(),
        Some(&"fork replay setup panic")
    );
    assert_eq!(callbacks.get(), 0);
    // The caller may catch the native unwind while retaining its old sender.
    // Poisoning must revoke that sender too, even with a healthy clock/budget.
    test_ok(budget.check_time());
    let before = budget.remaining_native_bytes();
    assert_eq!(
        sender
            .prepare_world_replay_read(&closure, intent_for(&requested))
            .err(),
        Some(ErasureHostErrorV1::RecoveryUnavailable),
    );
    assert_eq!(
        sender.observe_world_replay_use(&prepared, &mut budget),
        Err(ErasureHostErrorV1::RecoveryUnavailable),
    );
    assert_eq!(
        sender
            .admit_prepared_world_replay(&prepared, &closure, &observed, &mut budget)
            .err(),
        Some(ErasureHostErrorV1::RecoveryUnavailable),
    );
    assert_eq!(
        sender.read_world_replay_events(&verified, &mut budget),
        Err(ErasureHostErrorV1::RecoveryUnavailable),
    );
    assert_eq!(
        sender.validate_world_replay_forks(&verified, &mut budget),
        Err(ErasureHostErrorV1::RecoveryUnavailable),
    );
    assert_eq!(budget.remaining_native_bytes(), before);
    test_ok(budget.check_time());
    assert_eq!(host.status(), ErasureHostStatusV1::Poisoned);
    assert!(host.read_sender().is_err());
}

#[test]
fn admitted_timeline_with_missing_native_lineage_refuses_before_callbacks() {
    // Unlike an unknown Timeline, this identity is admitted by the real host
    // gate. Only the adapter's lineage result is faulted after admission.
    for (fault, succeeds) in [
        (FaultModeV1::Passthrough, true),
        (FaultModeV1::ForkReplayLineageMissing, false),
    ] {
        let (mut host, closure) = replay_fault_host(fault);
        let requested = replay_use(&closure);
        test_ok(
            host.gate
                .authorize(closure.timeline_id(), ErasureProtectedOperationV1::Read),
        );
        let mut sender = test_ok(host.read_sender());
        let prepared = test_ok(sender.prepare_world_replay_read(&closure, intent_for(&requested)));
        let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
        let start = clock.mark();
        let mut budget = test_ok(ForkReplayReadBudgetV1::new(
            prepared.fork_read_limits(),
            start,
            &mut clock,
        ));
        let classified = root_lineage_capability(
            sender.host,
            closure.timeline_id(),
            prepared.fork_read_limits(),
        );
        // Classification and owning-fence traversal have different contracts:
        // a missing classified source is Conflict, whereas an unavailable
        // fence member is AdapterFailure. Both use the same admitted root.
        assert_eq!(
            sender.validate_world_replay_forks(&classified, &mut budget),
            if succeeds {
                Ok(Vec::new())
            } else {
                Err(ErasureHostErrorV1::Conflict)
            }
        );
        let callbacks = Cell::new(0);
        let result = sender.with_world_replay_read_fence(
            &[&prepared],
            &mut budget,
            |_, _| {
                callbacks.set(callbacks.get() + 1);
                Ok(())
            },
            |(), verdict| {
                callbacks.set(callbacks.get() + 1);
                verdict
            },
        );
        assert_eq!(
            result,
            if succeeds {
                Ok(())
            } else {
                Err(ErasureHostErrorV1::AdapterFailure)
            }
        );
        assert_eq!(callbacks.get(), if succeeds { 2 } else { 0 });
        test_ok(budget.check_time());
        assert_eq!(host.status(), ErasureHostStatusV1::Ready);
    }
}

#[test]
fn faulty_lineage_refuses_classification_and_fence_before_preparation() {
    for fault in [
        FaultModeV1::ForkReplayLineageCycle,
        FaultModeV1::ForkReplayLineageSubstitute,
    ] {
        let (mut host, closure) = replay_fault_host(fault);
        let requested = replay_use(&closure);
        let generation = test_ok(host.gate.inventory_generation());
        let verified = crate::world_replay::test_verified_world_replay(
            &closure,
            &requested,
            generation,
            pos_core::ErasureReplayClaimV1::Exact,
            test_ok(pos_store::ForkReplayReadLimitsV1::new(
                8,
                1_024,
                262_144,
                256 * 1024 * 1024,
                30_000_000,
            )),
        );
        let limits = verified.fork_read_limits();
        let source = test_ok(crate::WorldReplayForkSourceV1::new(
            closure.timeline_id(),
            None,
        ));
        // Repeated classification follows the faulty native self-parent, so
        // Runtime must detect the cycle rather than an unrelated order mismatch.
        let sources = if fault == FaultModeV1::ForkReplayLineageCycle {
            vec![source.clone(), source]
        } else {
            vec![source]
        };
        let verified = crate::world_replay::test_verified_world_replay_with_fork_attribution(
            verified,
            Some(Hash::from_bytes([0xda; 32])),
            sources,
            Vec::new(),
            limits,
        );
        let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
        let start = clock.mark();
        let mut budget = test_ok(ForkReplayReadBudgetV1::new(limits, start, &mut clock));
        let mut sender = test_ok(host.read_sender());
        assert_eq!(
            sender.validate_world_replay_forks(&verified, &mut budget),
            Err(ErasureHostErrorV1::Conflict)
        );
        let prepared = test_ok(sender.prepare_world_replay_read(&closure, intent_for(&requested)));
        let callbacks = Cell::new(0);
        assert_eq!(
            sender.with_world_replay_read_fence(
                &[&prepared],
                &mut budget,
                |_, _| {
                    callbacks.set(callbacks.get() + 1);
                    Ok(())
                },
                |(), verdict| {
                    callbacks.set(callbacks.get() + 1);
                    verdict
                },
            ),
            Err(ErasureHostErrorV1::AdapterFailure)
        );
        assert_eq!(callbacks.get(), 0);
        assert_eq!(host.status(), ErasureHostStatusV1::Ready);
    }
}
