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
        intent,
        reference(1),
        Arc::clone(prepared.owner()),
        prepared.read_bounds(),
        prepared.fork_read_limits(),
    ));
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
    let stale = crate::world_replay::test_verified_world_replay(
        &closure,
        &requested,
        reference(1),
        pos_core::ErasureReplayClaimV1::Exact,
    );
    let mut clock = ScriptedGuardMonotonicSourceV1::new([Duration::ZERO]);
    let start = clock.mark();
    let mut budget = test_ok(ForkReplayReadBudgetV1::new(
        verified.fork_read_limits(),
        start,
        &mut clock,
    ));
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
