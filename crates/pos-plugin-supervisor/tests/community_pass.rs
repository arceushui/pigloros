//! Pass-level tests of the community Plugin Driver adapter (ADR-061 r4, #543).
//!
//! Every test drives real scheduled passes through the registry, the local
//! admission host and an in-memory store, with the `test-support` probe worker
//! standing in for the Component worker. The probe's Component bytes name the
//! behaviour: `draft:<type>` returns one Event, `chain:<type>` echoes the
//! prior state into the Event and appends `+` to it, and the other names are
//! the probe's faults (see `tests/support/worker_probe.rs`).

use std::time::Duration;

use pos_core::{
    CanonicalBytes, CoreError, EntityId, Event, EventDraft, EventStore, Kind, PipelineOutcomeV1,
};
use pos_plugin_supervisor::pass_harness::{initial, LostPort, World};
use pos_plugin_supervisor::test_support::{self, err, ok};
use pos_plugin_supervisor::{CommunityPluginHandleV1, ReceiptDispositionV1};
use pos_runtime::community_plugin_host::{
    classify_pass_failure, AtomicCommitFailureV1, CommunityPluginHostErrorV1, ComponentTrapClassV1,
    HostFailureClassV1, PassFailureV1, TrapReproductionV1,
};
use pos_runtime::{
    PluginAvailabilityV1, PluginCompositionErrorV1, RuntimeError, ScheduledDriverBindingV1,
};

type Error = CommunityPluginHostErrorV1;

const PROBE: &str = env!("CARGO_BIN_EXE_pos-plugin-worker-probe");
/// A generous watchdog for invocations that should finish promptly.
const PROMPT: Duration = Duration::from_mins(1);
/// A short watchdog for an invocation that must be stopped.
const SHORT: Duration = Duration::from_secs(1);
/// The classification of a typed non-committed pipeline outcome.
const NOT_ADMITTED: Error = Error::AtomicCommitFailed {
    failure: AtomicCommitFailureV1::DeterministicTypedResult,
};

/// A pass world whose Drivers launch the probe worker.
fn new_world() -> World {
    World::new(PROBE)
}

fn payloads(events: &[Event]) -> Vec<Vec<u8>> {
    events
        .iter()
        .map(|event| event.payload.as_slice().to_vec())
        .collect()
}

fn dispositions(handle: &CommunityPluginHandleV1) -> Vec<ReceiptDispositionV1> {
    handle
        .receipts()
        .iter()
        .map(|receipt| receipt.disposition)
        .collect()
}

#[test]
fn a_pass_commits_every_draft_atomically_and_only_then_the_state() {
    let mut world = new_world();
    let alpha = world.add("alpha", "community.alpha", b"chain:community.alpha", PROMPT);
    let beta = world.add("beta", "community.beta", b"draft:community.beta", PROMPT);
    for handle in [&alpha, &beta] {
        let binding = world.registry.scheduled_binding(handle.plugin_id());
        assert_eq!(binding, Some(ScheduledDriverBindingV1::NonParticipant));
    }

    let staged = ok(world.stage());
    // Staged output commits nothing and adopts no state before the batch.
    assert!(world.events().is_empty());
    assert_eq!(alpha.committed_state(), initial());
    assert_eq!(beta.committed_state(), initial());
    assert_eq!(dispositions(&alpha), [ReceiptDispositionV1::Staged]);
    assert_eq!(dispositions(&beta), [ReceiptDispositionV1::Staged]);

    let receipt = ok(world.admit(&staged));
    assert_eq!(receipt.map(|r| r.committed_events().len()), Some(2));
    let events = world.events();
    assert_eq!(
        payloads(&events),
        [b"initial".to_vec(), b"community.beta".to_vec()]
    );
    let types: Vec<_> = events.iter().map(|e| e.event_type.as_str()).collect();
    assert_eq!(types, ["community.alpha", "community.beta"]);
    assert_eq!(alpha.committed_state().bytes, b"initial+");
    assert_eq!(beta.committed_state().bytes, b"next");
    assert_eq!(dispositions(&alpha), [ReceiptDispositionV1::Committed]);
    assert_eq!(dispositions(&beta), [ReceiptDispositionV1::Committed]);

    let receipts = alpha.receipts();
    assert_eq!(receipts[0].negotiated.plugin_id(), "alpha");
    assert_eq!(receipts[0].limits(), receipts[0].negotiated.limits());
    assert_eq!(receipts[0].metering, Some(test_support::METERING));
    assert!(receipts[0].output_digest.is_some());

    // The committed state is the prior state of the next invocation.
    let _receipt = ok(world.pass());
    assert_eq!(payloads(&world.events())[2], b"initial+");
    assert_eq!(alpha.committed_state().bytes, b"initial++");
}

/// One failing member in a pass beside one that succeeds.
struct Failure {
    component: &'static [u8],
    watchdog: Duration,
    error: Error,
    quarantine: Option<PluginAvailabilityV1>,
}

const fn failure(
    component: &'static [u8],
    error: Error,
    quarantine: Option<PluginAvailabilityV1>,
) -> Failure {
    Failure {
        component,
        watchdog: PROMPT,
        error,
        quarantine,
    }
}

/// Run one pass whose second member fails as `failure` says, and check that
/// the whole pass is discarded and only that member is marked.
///
/// Returns the pass error, so a caller can inspect what the real pass raised.
fn check_failure(failure: &Failure) -> RuntimeError {
    let mut world = new_world();
    let alpha = world.add("alpha", "community.alpha", b"draft:community.alpha", PROMPT);
    let beta = world.add(
        "beta",
        "community.beta",
        failure.component,
        failure.watchdog,
    );

    let error = err(world.pass());
    let expected = PassFailureV1::Host(failure.error);
    assert_eq!(classify_pass_failure(&error), expected, "{}", failure.error);

    // Nothing committed: not the unaffected Plugin's Event, nor its state.
    assert!(world.events().is_empty(), "{}", failure.error);
    assert_eq!(alpha.committed_state(), initial());
    assert_eq!(dispositions(&alpha), [ReceiptDispositionV1::Discarded]);
    // The unaffected Plugin is never marked or quarantined.
    assert_eq!(alpha.last_failure(), None);
    assert_eq!(alpha.availability(), PluginAvailabilityV1::Available);

    assert_eq!(beta.last_failure(), Some(failure.error));
    let quarantine = failure
        .quarantine
        .unwrap_or(PluginAvailabilityV1::Available);
    assert_eq!(beta.availability(), quarantine, "{}", failure.error);
    // The failed invocation keeps its receipt, with the closed failure.
    let receipts = beta.receipts();
    assert_eq!(receipts.len(), 1, "{}", failure.error);
    assert_eq!(receipts[0].failure, Some(failure.error));
    assert_eq!(
        receipts[0].guest_error.is_some(),
        failure.error == Error::GuestDeclaredFailure
    );
    assert_eq!(receipts[0].disposition, ReceiptDispositionV1::Discarded);

    world.sync(&[&alpha, &beta]);
    let (a, b) = (alpha.plugin_id(), beta.plugin_id());
    assert_eq!(
        world.registry.availability(a),
        Some(PluginAvailabilityV1::Available)
    );
    assert_eq!(world.registry.availability(b), Some(quarantine));
    error
}

#[test]
fn a_resource_limit_discards_the_pass_and_exhausts_only_that_plugin() {
    let exhausted = Some(PluginAvailabilityV1::ResourceExhausted);
    for (component, error) in [
        (&b"fuel"[..], Error::FuelExhausted),
        (&b"memory"[..], Error::MemoryLimitExceeded),
        (&b"host-calls"[..], Error::HostCallLimitExceeded),
        (&b"output-limit"[..], Error::OutputLimitExceeded),
    ] {
        check_failure(&failure(component, error, exhausted));
    }
}

#[test]
fn a_trap_or_a_crash_discards_the_pass_and_quarantines_only_that_plugin() {
    let trap = Error::ComponentTrap {
        class: ComponentTrapClassV1::StackExhausted,
        reproduction: TrapReproductionV1::Unverified,
    };
    check_failure(&failure(b"trap", trap, Some(PluginAvailabilityV1::Trapped)));
    for component in [&b"exit"[..], b"abort"] {
        let unavailable = Some(PluginAvailabilityV1::Unavailable);
        check_failure(&failure(component, Error::WorkerCrashed, unavailable));
    }
}

#[test]
fn an_invalid_output_discards_the_pass_and_only_marks_that_plugin() {
    for (component, error) in [
        (&b"bad-digest"[..], Error::InvalidGuestOutput),
        (&b"guest-error"[..], Error::GuestDeclaredFailure),
        (&b"draft:Not.An.Id"[..], Error::InvalidGuestOutput),
    ] {
        check_failure(&failure(component, error, None));
    }
}

/// R7-F4: a valid guest output the host cannot commit is authoritative.
#[test]
fn a_draft_with_dependency_digests_is_unsupported_schema_and_authoritative() {
    // `check_failure` asserts the whole pass is discarded: no Event, no state,
    // no quarantine, and the receipt disposition is `Discarded`.
    let unsupported = Error::UnsupportedSchema;
    let raised = check_failure(&failure(b"deps:community.beta", unsupported, None));
    let PassFailureV1::Host(host) = classify_pass_failure(&raised) else {
        std::panic::resume_unwind(Box::new("the pass raised no host error"))
    };
    assert_eq!(host, unsupported);
    assert_eq!(host.class(), HostFailureClassV1::Authoritative);
}

#[test]
fn a_watchdog_stop_discards_the_pass_without_quarantine() {
    check_failure(&Failure {
        watchdog: SHORT,
        ..failure(b"hang", Error::OperationalWatchdogStop, None)
    });
}

#[test]
fn a_quarantined_plugin_blocks_passes_in_memory_until_the_host_clears_it() {
    let mut world = new_world();
    let alpha = world.add("alpha", "community.alpha", b"draft:community.alpha", PROMPT);
    let beta = world.add("beta", "community.beta", b"fuel", PROMPT);
    let error = err(world.pass());
    assert_eq!(
        classify_pass_failure(&error),
        PassFailureV1::Host(Error::FuelExhausted)
    );
    world.sync(&[&alpha, &beta]);
    assert_eq!(alpha.receipts().len(), 1);

    // The registry refuses the pass before any Driver runs: no worker, no
    // state, no Event, and no new failure.
    let refused = err(world.pass());
    assert!(matches!(
        refused,
        RuntimeError::Composition(PluginCompositionErrorV1::ImplementationUnavailable {
            plugin_id,
            availability: PluginAvailabilityV1::ResourceExhausted,
        }) if plugin_id == beta.plugin_id()
    ));
    assert_eq!(classify_pass_failure(&refused), PassFailureV1::Unrelated);
    assert_eq!(alpha.receipts().len(), 1);
    assert!(world.events().is_empty());

    let () = ok(beta.clear_quarantine(&mut world.registry));
    assert_eq!(beta.availability(), PluginAvailabilityV1::Available);
    assert_eq!(beta.last_failure(), None);
    // Cleared, the Plugin runs again, and fails again.
    let again = err(world.pass());
    assert_eq!(
        classify_pass_failure(&again),
        PassFailureV1::Host(Error::FuelExhausted)
    );
    assert_eq!(alpha.receipts().len(), 2);
}

#[test]
fn a_typed_non_commit_and_a_store_error_discard_the_pass_and_classify() {
    let mut world = new_world();
    let alpha = world.add("alpha", "community.alpha", b"chain:community.alpha", PROMPT);
    let beta = world.add("beta", "community.beta", b"draft:community.beta", PROMPT);

    // A typed non-committed outcome: an Event committed after staging moves
    // the Logical Head, so the store reports an admission conflict.
    let staged = ok(world.stage());
    let _events = ok(world.store.append(
        world.timeline,
        &[EventDraft::new(
            EntityId::new(),
            Kind::new("human.action"),
            CanonicalBytes::from_static(b"human"),
        )],
    ));
    let conflict = err(world.admit(&staged));
    assert!(matches!(
        conflict,
        RuntimeError::ScheduledPassNotAdmitted(ref outcome)
            if matches!(**outcome, PipelineOutcomeV1::AdmissionConflict)
    ));
    assert_eq!(
        classify_pass_failure(&conflict),
        PassFailureV1::Host(NOT_ADMITTED)
    );
    assert_eq!(world.events().len(), 1);

    // A store error: the erasure fence froze the Timeline after staging. A
    // frozen Timeline cannot be read, so its Events were counted above.
    let staged = ok(world.stage());
    world.gate.freeze_timeline_for_test(world.timeline);
    let frozen = err(world.admit(&staged));
    assert!(matches!(
        frozen,
        RuntimeError::Store(CoreError::ErasureAccessFrozen)
    ));
    let operational = Error::AtomicCommitFailed {
        failure: AtomicCommitFailureV1::Operational,
    };
    assert_eq!(
        classify_pass_failure(&frozen),
        PassFailureV1::Host(operational)
    );

    // Both discarded every staged Driver output and quarantined nobody.
    for handle in [&alpha, &beta] {
        assert_eq!(handle.committed_state(), initial());
        assert_eq!(
            dispositions(handle),
            [
                ReceiptDispositionV1::Discarded,
                ReceiptDispositionV1::Discarded
            ]
        );
        assert_eq!(handle.availability(), PluginAvailabilityV1::Available);
        assert_eq!(handle.last_failure(), None);
    }
}

#[test]
fn a_lost_commit_outcome_keeps_the_staged_state_for_recovery() {
    let mut world = new_world();
    let alpha = world.add("alpha", "community.alpha", b"chain:community.alpha", PROMPT);
    let beta = world.add("beta", "community.beta", b"draft:community.beta", PROMPT);
    let staged = ok(world.stage());
    let admission = world.admission(&staged);
    let lost = err(world
        .registry
        .admit_scheduled_pass(&mut LostPort(&mut world.store), &admission));
    assert_eq!(classify_pass_failure(&lost), PassFailureV1::InDoubt);

    // Nothing was discarded and nothing adopted: the exact basis is retained.
    for handle in [&alpha, &beta] {
        assert_eq!(handle.committed_state(), initial());
        assert_eq!(dispositions(handle), [ReceiptDispositionV1::Staged]);
        assert_eq!(handle.availability(), PluginAvailabilityV1::Available);
        assert_eq!(handle.last_failure(), None);
    }
    let blocked = err(world.stage());
    assert!(matches!(blocked, RuntimeError::PendingDriverStep));
    assert_eq!(alpha.receipts().len(), 1);

    // Recovery resubmits the retained basis: the state commits, no Driver
    // runs again.
    let recovered = ok(world.registry.recover_scheduled_pass(&mut world.store));
    assert_eq!(recovered.map(|r| r.committed_events().len()), Some(2));
    assert_eq!(world.events().len(), 2);
    assert_eq!(alpha.committed_state().bytes, b"initial+");
    assert_eq!(beta.committed_state().bytes, b"next");
    assert_eq!(dispositions(&alpha), [ReceiptDispositionV1::Committed]);
    assert_eq!(alpha.receipts().len(), 1);
}

#[test]
fn abandoning_an_in_doubt_pass_discards_the_staged_state() {
    let mut world = new_world();
    let alpha = world.add("alpha", "community.alpha", b"chain:community.alpha", PROMPT);
    let staged = ok(world.stage());
    let admission = world.admission(&staged);
    let lost = err(world
        .registry
        .admit_scheduled_pass(&mut LostPort(&mut world.store), &admission));
    assert_eq!(classify_pass_failure(&lost), PassFailureV1::InDoubt);
    world.registry.abort_step();
    assert_eq!(alpha.committed_state(), initial());
    assert_eq!(dispositions(&alpha), [ReceiptDispositionV1::Discarded]);
}
