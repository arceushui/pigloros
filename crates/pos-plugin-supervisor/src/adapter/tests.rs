//! Unit tests of the adapter's mapping, staging, receipts, quarantine table
//! and registration. The pass-level tests are in `tests/community_pass.rs`.

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use pos_core::{CoreError, EntityId, Kind, PipelineOutcomeV1};
use pos_runtime::community_plugin_host::{
    plugin_output_digest_v1, MeteringV1, AtomicCommitFailureV1, ComponentTrapClassV1, EventDraftV1,
    FieldRefV1, GuestPluginErrorV1, PluginErrorCodeV1, TraceAnnotationV1, TrapReproductionV1,
};
use ulid::Ulid;

use super::failure::commit_failed;
use super::output::{map_draft, mapped_drafts};
use super::*;
use crate::launch::WorkerProgramV1;
use crate::test_support::{
    self, community_pin, err, ok, pin_of, DriverPlugin, METERING, SMALL_BUDGET,
};

const DENIED: Error = commit_failed(AtomicCommitFailureV1::DeterministicTypedResult);

fn plugin(id: PluginId, has_driver: bool) -> DriverPlugin {
    DriverPlugin {
        id,
        name: "community-fixture",
        event_type: "community.event",
        has_driver,
    }
}

/// A context source that counts its calls and answers with a fixed result.
struct FixedSource {
    calls: Arc<AtomicUsize>,
    refusal: Option<Error>,
}

impl InvocationContextSourceV1 for FixedSource {
    fn context(
        &mut self,
        _: TimelineId,
        _: &ObservationView<'_>,
    ) -> Result<InvocationContextV1, Error> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.refusal.map_or_else(
            || {
                Ok(InvocationContextV1 {
                    invocation: test_support::invocation(b"observation"),
                    host_inputs: HostInputs { simulation_time: 1 },
                })
            },
            Err,
        )
    }
}

fn draft(event_type: &str, payload: &[u8]) -> EventDraftV1 {
    EventDraftV1 {
        event_schema_id: 1,
        entity_id: [7; 16],
        event_type: event_type.to_owned(),
        canonical_payload: payload.to_vec(),
        dependency_digests: Vec::new(),
    }
}

/// A valid output echoing the fixture invocation, with one annotation.
fn output(drafts: Vec<EventDraftV1>) -> PluginOutputV1 {
    let mut output = PluginOutputV1 {
        invocation_id: test_support::invocation(b"observation").invocation_id,
        event_drafts: drafts,
        next_state_schema: [5; 32],
        next_state_bytes: b"next".to_vec(),
        trace_annotations: vec![TraceAnnotationV1 {
            annotation_schema_id: 9,
            canonical_bytes: b"trace".to_vec(),
            dependency_digests: Vec::new(),
        }],
        consumed_dependencies: Vec::new(),
        output_digest: [0; 32],
    };
    output.output_digest = plugin_output_digest_v1(&output);
    output
}

fn report(output: PluginOutputV1) -> InvocationReportV1<PluginOutputV1> {
    InvocationReportV1 {
        result: Ok(output),
        metering: METERING,
        operational_log: Vec::new(),
    }
}

fn initial() -> CommunityStateV1 {
    CommunityStateV1 {
        schema: [9; 32],
        bytes: b"initial".to_vec(),
    }
}

fn fixture(
    refusal: Option<Error>,
) -> (CommunityDriverV1, CommunityPluginHandleV1, Arc<AtomicUsize>) {
    let calls = Arc::new(AtomicUsize::new(0));
    let supervisor = WorkerProgramV1::new(PathBuf::from("/worker"))
        .and_then(|program| CommunityPluginSupervisorV1::new(program, Duration::from_secs(1)));
    let (driver, handle) = CommunityDriverV1::new(CommunityDriverConfigV1 {
        plugin_id: PluginId::new(),
        name: "community-fixture",
        tick_interval: Duration::from_millis(250),
        subscriptions: vec![ProjectionKey::new(EntityId::new())],
        supervisor: supervisor
            .unwrap_or_else(|| std::panic::resume_unwind(Box::new("invalid supervisor"))),
        negotiated: test_support::negotiated_with("plugin-a", SMALL_BUDGET, Vec::new()),
        component: b"component".to_vec(),
        source: Box::new(FixedSource {
            calls: Arc::clone(&calls),
            refusal,
        }),
        initial_state: initial(),
    });
    (driver, handle, calls)
}

fn every_error() -> Vec<(Error, Option<PluginAvailabilityV1>)> {
    use PluginAvailabilityV1 as Availability;
    let trap = Error::ComponentTrap {
        class: ComponentTrapClassV1::Other,
        reproduction: TrapReproductionV1::Unverified,
    };
    let exhausted = Some(Availability::ResourceExhausted);
    vec![
        (Error::InvalidManifest, None),
        (Error::ArtifactTrustDenied, None),
        (Error::ArtifactRevoked, Some(Availability::Revoked)),
        (Error::IncompatibleAbi, None),
        (Error::MissingFeature { index: 0 }, None),
        (Error::CapabilityDenied { index: 0 }, None),
        (Error::InvalidInvocation, None),
        (Error::InvalidGuestOutput, None),
        (Error::UnsupportedSchema, None),
        (Error::StateMigrationFailed, None),
        (Error::GuestDeclaredFailure, None),
        (trap, Some(Availability::Trapped)),
        (Error::WorkerCrashed, Some(Availability::Unavailable)),
        (Error::FuelExhausted, exhausted),
        (Error::MemoryLimitExceeded, exhausted),
        (Error::HostCallLimitExceeded, exhausted),
        (Error::OutputLimitExceeded, exhausted),
        (Error::DeterministicDeadlineExceeded, None),
        (Error::OperationalWatchdogStop, None),
        (DENIED, None),
    ]
}

#[test]
fn only_traps_resource_limits_revocation_and_crashes_quarantine() {
    for (error, expected) in every_error() {
        assert_eq!(quarantine_for(error), expected, "{error:?}");
    }
}

#[test]
fn a_failed_pass_is_classified_by_its_commit_contract() {
    let host = PassFailureV1::Host;
    let operational = commit_failed(AtomicCommitFailureV1::Operational);
    let rejected = Box::new(PipelineOutcomeV1::Rejected);
    let not_admitted = RuntimeError::ScheduledPassNotAdmitted(rejected);
    let unknown = RuntimeError::Store(CoreError::StorageOutcomeUnknown("lost".to_owned()));
    let frozen = RuntimeError::Store(CoreError::ErasureAccessFrozen);
    let crashed = RuntimeError::from(Error::WorkerCrashed);
    assert_eq!(classify_pass_failure(&not_admitted), host(DENIED));
    assert_eq!(classify_pass_failure(&unknown), PassFailureV1::InDoubt);
    assert_eq!(classify_pass_failure(&frozen), host(operational));
    assert_eq!(classify_pass_failure(&crashed), host(Error::WorkerCrashed));
    for unrelated in [
        RuntimeError::PendingDriverStep,
        RuntimeError::NoScheduledAdmissionInDoubt,
    ] {
        assert_eq!(classify_pass_failure(&unrelated), PassFailureV1::Unrelated);
    }
}

#[test]
fn a_draft_maps_to_an_event_draft_or_is_rejected() {
    let mapped = ok(map_draft(&EventDraftV1 {
        entity_id: *b"0123456789abcdef",
        ..draft("community.event", b"payload")
    }));
    let entity = EntityId::from_ulid(Ulid::from(u128::from_be_bytes(*b"0123456789abcdef")));
    assert_eq!(mapped.entity, entity);
    assert_eq!(mapped.event_type, Kind::new("community.event"));
    assert_eq!(mapped.payload.as_slice(), b"payload");
    assert_eq!(mapped.causation_id, None);

    let with_dependency = EventDraftV1 {
        dependency_digests: vec![[1; 32]],
        ..draft("community.event", b"p")
    };
    for malformed in [draft("Community.Event", b"p"), draft("", b"p")] {
        assert_eq!(map_draft(&malformed), Err(Error::InvalidGuestOutput));
    }
    // Dependency digests have nowhere to go: a distinct, closed refusal.
    assert_eq!(map_draft(&with_dependency), Err(Error::UnsupportedSchema));
}

#[test]
fn drafts_are_mapped_in_the_guests_order_within_the_event_bytes_limit() {
    let two = output(vec![draft("a.b", b"one"), draft("c.d", b"two")]);
    let drafts = ok(mapped_drafts(&two, 6));
    let payloads: Vec<&[u8]> = drafts.iter().map(|d| d.payload.as_slice()).collect();
    assert_eq!(payloads, [&b"one"[..], &b"two"[..]]);
    assert_eq!(mapped_drafts(&two, 5), Err(Error::OutputLimitExceeded));
    // Nothing above the limit is mapped partly; a bad draft stops the vector.
    let unmappable = output(vec![draft("a.b", b"one"), draft("BAD", b"two")]);
    assert_eq!(
        mapped_drafts(&unmappable, 100),
        Err(Error::InvalidGuestOutput)
    );
    assert!(ok(mapped_drafts(&output(Vec::new()), 0)).is_empty());
}

#[test]
fn a_valid_output_is_staged_with_a_receipt_until_the_batch_commits() {
    let (mut driver, handle, _) = fixture(None);
    let valid = output(vec![draft("community.event", b"payload")]);
    let digest = valid.output_digest;
    let staged = ok(driver.accept([3; 16], report(valid)));
    assert_eq!(staged.drafts.len(), 1);
    assert_eq!(
        driver.staged,
        Some(CommunityStateV1 {
            schema: [5; 32],
            bytes: b"next".to_vec()
        })
    );
    // The next state is not adopted before the batch commits.
    assert_eq!(handle.committed_state(), initial());
    let receipts = handle.receipts();
    assert_eq!(receipts.len(), 1);
    let receipt = &receipts[0];
    assert_eq!(receipt.invocation_id, [3; 16]);
    assert_eq!(receipt.negotiated, driver.negotiated);
    assert_eq!(receipt.output_digest, Some(digest));
    assert_eq!(receipt.limits, driver.negotiated.limits());
    assert_eq!(receipt.metering, Some(METERING));
    assert_eq!(receipt.failure, None);
    assert_eq!(receipt.guest_error, None);
    assert_eq!(receipt.dropped_trace_annotations, 1);
    assert_eq!(receipt.disposition, ReceiptDispositionV1::Staged);

    driver.commit_step();
    assert_eq!(driver.staged, None);
    assert_eq!(handle.committed_state().bytes, b"next");
    assert_eq!(handle.committed_state().schema, [5; 32]);
    assert_eq!(
        handle.receipts()[0].disposition,
        ReceiptDispositionV1::Committed
    );
    // A second commit has nothing staged and changes nothing.
    driver.commit_step();
    assert_eq!(handle.committed_state().bytes, b"next");
}

#[test]
fn an_abort_discards_the_staged_state_and_receipt() {
    let (mut driver, handle, _) = fixture(None);
    let _staged = ok(driver.accept([3; 16], report(output(vec![draft("a.b", b"p")]))));
    driver.abort_step();
    assert_eq!(driver.staged, None);
    assert_eq!(handle.committed_state(), initial());
    assert_eq!(
        handle.receipts()[0].disposition,
        ReceiptDispositionV1::Discarded
    );
    // A discarded receipt is never committed afterwards.
    driver.commit_step();
    assert_eq!(
        handle.receipts()[0].disposition,
        ReceiptDispositionV1::Discarded
    );
}

#[test]
fn an_unmappable_or_declared_failure_stages_nothing_and_keeps_its_receipt() {
    let (mut driver, handle, _) = fixture(None);
    let unmappable = output(vec![draft("BAD", b"p")]);
    let digest = unmappable.output_digest;
    assert_eq!(
        driver.accept([1; 16], report(unmappable)).err(),
        Some(Error::InvalidGuestOutput)
    );
    let guest = GuestPluginErrorV1 {
        code: PluginErrorCodeV1::InvalidState(FieldRefV1 {
            schema_id: 4,
            field_ordinal: 7,
        }),
        canonical_coordinate: Some(b"at".to_vec()),
        related_digest: Some([8; 32]),
    };
    let declared = InvocationReportV1 {
        result: Err(guest.clone()),
        metering: METERING,
        operational_log: Vec::new(),
    };
    assert_eq!(
        driver.accept([3; 16], declared).err(),
        Some(Error::GuestDeclaredFailure)
    );
    assert_eq!(driver.staged, None);
    let receipts = handle.receipts();
    assert_eq!(receipts[0].output_digest, Some(digest));
    assert_eq!(receipts[0].failure, Some(Error::InvalidGuestOutput));
    assert_eq!(receipts[0].dropped_trace_annotations, 1);
    // The guest's exact plugin-error, with its field ordinal, is kept.
    assert_eq!(receipts[1].output_digest, None);
    assert_eq!(receipts[1].failure, Some(Error::GuestDeclaredFailure));
    assert_eq!(receipts[1].guest_error, Some(guest));
    assert_eq!(receipts[1].metering, Some(METERING));
    assert_eq!(receipts[1].dropped_trace_annotations, 0);
    assert!(receipts
        .iter()
        .all(|r| r.disposition == ReceiptDispositionV1::Discarded));
}

#[test]
fn the_prior_state_is_always_the_one_the_adapter_holds() {
    let mut invocation = test_support::invocation(b"observation");
    invocation.prior_state_schema = [0xee; 32];
    invocation.prior_state_bytes = b"host supplied".to_vec();
    let replaced = with_prior_state(invocation, initial());
    assert_eq!(replaced.prior_state_schema, [9; 32]);
    assert_eq!(replaced.prior_state_bytes, b"initial");
}

#[test]
fn receipts_are_bounded_and_the_oldest_is_dropped() {
    let (driver, handle, _) = fixture(None);
    let limit = u64::try_from(MAX_RETAINED_RECEIPTS_V1).unwrap_or(u64::MAX);
    for index in 0..=limit {
        let mut receipt = driver_receipt(&driver);
        receipt.metering = Some(MeteringV1 {
            host_calls: index,
            ..METERING
        });
        driver.shared.push_receipt(receipt);
    }
    let receipts = handle.receipts();
    assert_eq!(receipts.len(), MAX_RETAINED_RECEIPTS_V1);
    let host_calls = |at: usize| receipts[at].metering.map(|metering| metering.host_calls);
    assert_eq!(host_calls(0), Some(1));
    assert_eq!(host_calls(MAX_RETAINED_RECEIPTS_V1 - 1), Some(limit));
}

fn driver_receipt(driver: &CommunityDriverV1) -> CommunityInvocationReceiptV1 {
    CommunityInvocationReceiptV1 {
        invocation_id: [0; 16],
        negotiated: driver.negotiated.clone(),
        output_digest: None,
        limits: driver.negotiated.limits(),
        metering: Some(METERING),
        dropped_trace_annotations: 0,
        failure: None,
        guest_error: None,
        disposition: ReceiptDispositionV1::Discarded,
    }
}

#[test]
fn a_refused_invocation_marks_or_quarantines_only_by_its_class() {
    for (error, quarantine) in every_error() {
        let (mut driver, handle, calls) = fixture(Some(error));
        let failed = err(driver.step(TimelineId::new(), ObservationView::empty()));
        assert!(
            matches!(failed, RuntimeError::CommunityPlugin(refused) if refused == error),
            "{error:?}"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(handle.last_failure(), Some(error));
        assert_eq!(
            handle.availability(),
            quarantine.unwrap_or(PluginAvailabilityV1::Available),
            "{error:?}"
        );
    }
}

#[test]
fn a_quarantined_adapter_refuses_to_run_until_it_is_cleared() {
    let (mut driver, handle, calls) = fixture(Some(Error::FuelExhausted));
    assert!(driver
        .step(TimelineId::new(), ObservationView::empty())
        .is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let refused = err(driver.step(TimelineId::new(), ObservationView::empty()));
    assert!(matches!(
        refused,
        RuntimeError::Composition(PluginCompositionErrorV1::ImplementationUnavailable {
            plugin_id,
            availability: PluginAvailabilityV1::ResourceExhausted,
        }) if plugin_id == handle.plugin_id()
    ));
    // The refusal never reached the context source and is not a new failure.
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    let mut registry = PluginRegistry::new();
    let plugin = plugin(handle.plugin_id(), false);
    let () = ok(registry.register_pinned_generated(
        &plugin,
        PluginRegistrationV1::new(community_pin(1, "community"), PluginAvailabilityV1::Available),
        None,
        None,
    ));
    let () = ok(handle.sync_registry(&mut registry));
    assert_eq!(
        registry.availability(plugin.id),
        Some(PluginAvailabilityV1::ResourceExhausted)
    );
    let () = ok(handle.clear_quarantine(&mut registry));
    assert_eq!(
        registry.availability(plugin.id),
        Some(PluginAvailabilityV1::Available)
    );
    assert_eq!(handle.availability(), PluginAvailabilityV1::Available);
    assert_eq!(handle.last_failure(), None);
    // Cleared, the adapter runs again and reaches its source.
    assert!(driver
        .step(TimelineId::new(), ObservationView::empty())
        .is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[test]
fn syncing_an_unregistered_plugin_leaves_the_handle_quarantined() {
    let (mut driver, handle, _) = fixture(Some(Error::WorkerCrashed));
    assert!(driver
        .step(TimelineId::new(), ObservationView::empty())
        .is_err());
    let mut registry = PluginRegistry::new();
    for result in [
        handle.sync_registry(&mut registry),
        handle.clear_quarantine(&mut registry),
    ] {
        assert!(matches!(
            err(result),
            RuntimeError::Composition(PluginCompositionErrorV1::MissingImplementation { .. })
        ));
    }
    assert_eq!(handle.availability(), PluginAvailabilityV1::Unavailable);
    assert_eq!(handle.last_failure(), Some(Error::WorkerCrashed));
}

#[test]
fn a_step_drops_a_stale_staged_state_first() {
    let (mut driver, handle, _) = fixture(Some(Error::InvalidInvocation));
    let _staged = ok(driver.accept([1; 16], report(output(vec![draft("a.b", b"p")]))));
    assert!(driver.staged.is_some());
    assert!(driver
        .step(TimelineId::new(), ObservationView::empty())
        .is_err());
    assert_eq!(driver.staged, None);
    assert_eq!(
        handle.receipts()[0].disposition,
        ReceiptDispositionV1::Discarded
    );
}

#[test]
fn the_driver_reports_its_configuration() {
    let (driver, _, _) = fixture(None);
    assert_eq!(driver.name(), "community-fixture");
    assert_eq!(driver.tick_interval(), Duration::from_millis(250));
    assert_eq!(driver.subscriptions().len(), 1);
    assert!(!driver.requires_snapshot_anchor());
}

#[test]
fn registration_is_pinned_community_and_non_participant() {
    let (driver, handle, _) = fixture(None);
    let plugin = plugin(handle.plugin_id(), true);
    let mut registry = PluginRegistry::new();
    let () = ok(register_community_driver(
        &mut registry,
        &plugin,
        community_pin(1, "community"),
        driver,
    ));
    assert_eq!(
        registry.scheduled_binding(plugin.id),
        Some(ScheduledDriverBindingV1::NonParticipant)
    );
    assert_eq!(
        registry.availability(plugin.id),
        Some(PluginAvailabilityV1::Available)
    );
    assert_eq!(registry.driver_count(), 1);
}

#[test]
fn registration_rejects_a_non_community_pin() {
    use DomainImplementationKindV1 as Impl;
    use PluginIsolationV1 as Isolation;
    for (kind, isolation, expected) in [
        (
            Impl::Plugin,
            Isolation::OperatorTrustedNative,
            PluginPinFieldV1::Isolation,
        ),
        (
            Impl::PublicAdapter,
            Isolation::GovernedCommunity,
            PluginPinFieldV1::ImplementationKind,
        ),
        (
            Impl::PublicAdapter,
            Isolation::OperatorTrustedNative,
            PluginPinFieldV1::ImplementationKind,
        ),
    ] {
        let (driver, handle, _) = fixture(None);
        let plugin = plugin(handle.plugin_id(), true);
        let mut registry = PluginRegistry::new();
        let pin = pin_of(kind, isolation, 1, "community");
        let rejected = err(register_community_driver(
            &mut registry,
            &plugin,
            pin,
            driver,
        ));
        assert!(matches!(
            rejected,
            RuntimeError::Composition(PluginCompositionErrorV1::IncompatibleImplementation {
                field,
                ..
            }) if field == expected
        ));
        assert_eq!(registry.driver_count(), 0);
    }
}
