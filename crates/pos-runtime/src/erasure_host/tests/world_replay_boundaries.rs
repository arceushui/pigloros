//! Reject stale or substituted preparations before touching native history.

use super::*;
use pos_core::trusted_clock::{GuardMonotonicSourceV1, ScriptedGuardMonotonicSourceV1};
use std::{cell::Cell, time::Duration};

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
