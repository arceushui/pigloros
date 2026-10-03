#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]

//! `pos-time` — timeline replay, snapshots, and fork-comparison utilities.
//!
//! Builds on top of `pos-core` (traits/types), `pos-store` (backend factory),
//! `pos-state` (projection registry) and `pos-runtime` (staged executor).
//!
//! | Module | Purpose |
//! |--------|---------|
//! | [`mod@replay`] | Install protected Replay State through a staged fold |
//! | [`mod@snapshot`] | Protected snapshots, `Unavailable` until #502 |
//! | [`compare()`] | Install both Fork arms and report diverged entities |
//! | [`merge()`] | Conflict-free / strategy-guided timeline merge |
//!
//! Protected Replay and Compare never fold through a visible
//! `ProjectionRegistry` (ADR-113 §8). Inside ADR-112's release guard they read
//! and verify the Event range, fold it on the process-global
//! [`pos_runtime::StagedFoldExecutorV1`] with the host-installed
//! [`pos_runtime::HostProjectionProviderV1`], prepare the install, and move it
//! in only through [`pos_runtime::handoff`]. They return State only, never
//! Events. On a failure after the range was read and verified, the visible
//! registry forgets only the revoked subjects of that range, after release
//! (ADR-093 Revision 4). Each release reports its payload-free health
//! signals into the caller's [`ReleaseHealthV1`].
#![cfg_attr(all(coverage_nightly, test), feature(coverage_attribute))]

use std::{cell::Cell, sync::Arc};

use pos_core::trusted_clock::{
    ApplicableExpiriesV1, GuardMonotonicSourceV1, MonotonicMarkV1, ProtectedHandoffTargetV1,
    ReleaseGuardV1, StagedProtectedOutputV1, SystemGuardMonotonicSourceV1,
    TrustedClockOverrunKindV1,
};
use pos_core::{staged_install::ProjectionSourceV1, ErasureReferenceV1, Event};
use pos_runtime::{
    GuardedFoldWindowV1, HostProjectionProviderV1, StagedFoldExecutorV1, StagedFoldPlanV1,
};
use pos_state::{
    ProjectionRegistry, ProtectedProjectionProviderV1, RecordedConsumerV1, RevokedSubjectsV1,
    StagedProjectionV1,
};

pub mod compare;
pub mod merge;
pub mod replay;
pub mod snapshot;

pub use compare::{compare, ForkDiff};
pub use merge::{
    can_merge_conflict_free, merge, merge_with_strategy, MergeConflict, MergeResult, MergeSpec,
    MergeStrategy,
};
pub use replay::{replay, replay_at};
pub use snapshot::{snapshot, verify_snapshot_consistency, Snapshot, SnapshotError};

/// The ADR-112 capability of one protected release: the held release guard
/// and the expiries checked under it, plus the caller's health record. The
/// release consumes it.
pub struct ProtectedReleaseV1<'g> {
    /// The held authority guard.
    pub guard: ReleaseGuardV1<'g>,
    /// The applicable expiries checked under `guard`.
    pub expiries: ApplicableExpiriesV1,
    /// Where the release reports its payload-free health signals.
    pub health: &'g ReleaseHealthV1,
}

/// Payload-free health signals of protected releases, which the release host
/// forwards to its health sink. Signals only accumulate; none carries State,
/// Events or a cause.
#[derive(Debug, Default)]
pub struct ReleaseHealthV1 {
    overrun: Cell<Option<TrustedClockOverrunKindV1>>,
    guard_release_late: Cell<Option<&'static str>>,
}

impl ReleaseHealthV1 {
    /// An empty record.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            overrun: Cell::new(None),
            guard_release_late: Cell::new(None),
        }
    }

    /// ADR-112's `trusted_clock_fence_overrun{kind}` signal, when a
    /// handoff's post-handoff check detected an overrun.
    #[must_use]
    pub const fn overrun_signal(&self) -> Option<TrustedClockOverrunKindV1> {
        self.overrun.get()
    }

    /// ADR-113 P2's [`pos_runtime::GUARD_RELEASE_LATE_SIGNAL`], when a
    /// failure-path teardown was predicted to end after `g0 + 30 s`.
    #[must_use]
    pub const fn guard_release_late(&self) -> Option<&'static str> {
        self.guard_release_late.get()
    }

    fn record_overrun(&self, signal: Option<TrustedClockOverrunKindV1>) {
        self.overrun.set(self.overrun.get().or(signal));
    }

    fn record_guard_release_late(&self, signal: Option<&'static str>) {
        self.guard_release_late
            .set(self.guard_release_late.get().or(signal));
    }
}

/// The staged fold of one protected arm: the executor, the host-installed
/// provider and the recorded consumer set.
#[derive(Clone, Copy)]
pub struct ProtectedFoldV1<'a> {
    /// The process-global staged-fold executor.
    pub executor: &'a StagedFoldExecutorV1,
    /// The host catalogue provider of the installed composition.
    pub provider: &'a Arc<HostProjectionProviderV1>,
    /// The recorded consumers, in the visible registry's slot order.
    pub consumers: &'a [RecordedConsumerV1],
}

/// Every protected failure is ADR-093 `Unavailable`; the closed cause is
/// dropped, never exposed.
fn unavailable<E>(error: E) -> pos_core::CoreError {
    drop(error);
    pos_core::CoreError::ArtifactUnavailable
}

/// The source of a verified read: the requested Timeline at the inventory
/// generation the closure was verified against.
const fn verified_source(
    timeline: pos_core::TimelineId,
    closure: &pos_core::WorldReplayClosureV1,
) -> ProjectionSourceV1 {
    let generation = ErasureReferenceV1::from_digest(*closure.inventory_generation().as_bytes());
    ProjectionSourceV1::bound(timeline, Some(generation))
}

/// Fold a verified range on the staged executor inside `guard`'s window.
/// The plan takes the Events without copying their payloads.
fn fold_staged(
    fold: &ProtectedFoldV1<'_>,
    guard: &ReleaseGuardV1<'_>,
    events: Vec<Event>,
    source: ProjectionSourceV1,
) -> Result<StagedProjectionV1, pos_core::CoreError> {
    let window = GuardedFoldWindowV1::new(guard);
    let plan = StagedFoldPlanV1::new(fold.consumers.to_vec(), events, source);
    let provider: Arc<dyn ProtectedProjectionProviderV1 + Send + Sync> =
        Arc::<HostProjectionProviderV1>::clone(fold.provider);
    fold.executor
        .fold(&window, &mut SystemGuardMonotonicSourceV1, provider, plan)
        .map_err(unavailable)
}

/// P1: the handoff work must be planned to end by `g0 + 29 s`.
fn handoff_reserve(guard: &ReleaseGuardV1<'_>) -> Result<(), pos_core::CoreError> {
    pos_runtime::check_handoff_reserve(&mut SystemGuardMonotonicSourceV1, guard.guard_started_at())
        .map_err(unavailable)
}

/// P2: record the payload-free late signal when teardown, measured on
/// `clock`, is predicted to end after `g0 + 30 s`.
fn record_p2(
    health: &ReleaseHealthV1,
    clock: &mut dyn GuardMonotonicSourceV1,
    g0: MonotonicMarkV1,
) {
    health.record_guard_release_late(pos_runtime::teardown_signal(clock, g0));
}

/// The ADR-112 handoff of one staged install, then the health signals, with
/// P2 measured on the production monotonic source.
fn handoff_with_p2<T: ProtectedHandoffTargetV1>(
    guard: ReleaseGuardV1<'_>,
    expiries: &ApplicableExpiriesV1,
    staged: StagedProtectedOutputV1<T>,
    health: &ReleaseHealthV1,
) -> Result<(), pos_core::CoreError> {
    handoff_with_p2_on(
        guard,
        expiries,
        staged,
        health,
        &mut SystemGuardMonotonicSourceV1,
    )
}

/// [`handoff_with_p2`] with P2 measured on `p2_clock`.
///
/// On success the overrun signal is recorded and the committed value (the
/// displaced maps) is dropped after the handoff returns. On failure,
/// `handoff_checked` has already rolled back and released the guard; P2 is
/// then evaluated against the guard's `g0` and the payload-free late signal
/// is recorded before the failure is reported.
fn handoff_with_p2_on<T: ProtectedHandoffTargetV1>(
    guard: ReleaseGuardV1<'_>,
    expiries: &ApplicableExpiriesV1,
    staged: StagedProtectedOutputV1<T>,
    health: &ReleaseHealthV1,
    p2_clock: &mut dyn GuardMonotonicSourceV1,
) -> Result<(), pos_core::CoreError> {
    let g0 = guard.guard_started_at();
    match pos_runtime::handoff(guard, expiries, staged) {
        Ok(used) => {
            health.record_overrun(used.overrun_signal());
            Ok(())
        }
        Err(error) => {
            // ADR-113 §4/§9 order this as "P2, then teardown", but
            // `handoff_checked` (#503) rolls back and drops the guard
            // internally on `Err`, so P2 is evaluated after that teardown.
            // That is conservative (it can only over-signal); see #515.
            record_p2(health, p2_clock, g0);
            Err(unavailable(error))
        }
    }
}

/// P2, then teardown: a guard that did not reach the handoff is rolled back
/// and released, after recording the payload-free late signal when the
/// teardown is predicted to end after `g0 + 30 s`. Teardown runs either way.
/// A guard the handoff consumed has nothing left to tear down.
fn teardown(guard: Option<ReleaseGuardV1<'_>>, health: &ReleaseHealthV1) {
    if let Some(guard) = guard {
        record_p2(
            health,
            &mut SystemGuardMonotonicSourceV1,
            guard.guard_started_at(),
        );
        drop(guard);
    }
}

/// Apply the ADR-093 Revision 4 failure-path forget after release: only the
/// revoked subjects of a range that was read and verified, and only on failure.
fn forget_on_failure<T>(
    result: Result<T, pos_core::CoreError>,
    registry: &mut ProjectionRegistry,
    revoked: Option<&RevokedSubjectsV1>,
) -> Result<T, pos_core::CoreError> {
    if let (Err(_), Some(subjects)) = (&result, revoked) {
        registry.forget_revoked_subjects(subjects);
    }
    result
}

const fn host_error_to_core(error: pos_core::ErasureHostErrorV1) -> pos_core::CoreError {
    match error {
        pos_core::ErasureHostErrorV1::AccessFrozen => pos_core::CoreError::ErasureAccessFrozen,
        pos_core::ErasureHostErrorV1::RecoveryUnavailable
        | pos_core::ErasureHostErrorV1::StaleGeneration => {
            pos_core::CoreError::ErasureContainmentUnavailable
        }
        pos_core::ErasureHostErrorV1::AuthorizationDenied
        | pos_core::ErasureHostErrorV1::Conflict
        | pos_core::ErasureHostErrorV1::AdapterFailure => pos_core::CoreError::ArtifactUnavailable,
    }
}

fn require_world_replay(
    sender: &mut pos_runtime::ErasureReadSenderV1<'_>,
    closure: &pos_core::WorldReplayClosureV1,
    requested_use: &pos_runtime::WorldReplayUseV1,
) -> Result<pos_core::EventReadBounds, pos_core::CoreError> {
    let verified = sender
        .admit_world_replay(closure, requested_use)
        .map_err(host_error_to_core)?;
    verified
        .require_authoritative_use()
        .map_err(|_| pos_core::CoreError::ArtifactUnavailable)?;
    Ok(verified.read_bounds())
}

/// Return `registry`'s canonical consumer selection before any host read.
fn consumer_selection(
    registry: &pos_state::ProjectionRegistry,
) -> Result<Vec<String>, pos_core::CoreError> {
    let mut consumer_ids: Vec<String> = registry
        .reducer_names()
        .into_iter()
        .map(str::to_owned)
        .collect();
    consumer_ids.sort_unstable();
    pos_core::world_consumer_set::validate_consumer_id_selection(&consumer_ids)
        .map(|()| consumer_ids)
        .map_err(|_| pos_core::CoreError::ArtifactUnavailable)
}

/// Bind one protected use to the Timeline's currently observed logical head.
///
/// The installed verifier must accept the closure only for this exact head,
/// and [`read_complete_world_replay`] rejects any read that observes another.
fn observed_world_replay_use(
    sender: &mut pos_runtime::ErasureReadSenderV1<'_>,
    timeline: pos_core::TimelineId,
    operation: pos_core::ErasureProtectedOperationV1,
    range: pos_core::SeqRange,
    consumer_ids: &[String],
) -> Result<pos_runtime::WorldReplayUseV1, pos_core::CoreError> {
    sender
        .logical_head(timeline)
        .map_err(host_error_to_core)
        .and_then(|head| {
            pos_runtime::WorldReplayUseV1::new(
                timeline,
                operation,
                range,
                head,
                consumer_ids.to_vec(),
                Vec::new(),
            )
            .map_err(|_| pos_core::CoreError::ArtifactUnavailable)
        })
}

/// Read the complete range of a verified use at its bound logical head.
///
/// The read fails closed unless the Timeline's logical head still equals the
/// head bound into the verified use. An Event appended after the head was
/// observed makes an open-ended read return more Events than expected, which
/// is rejected by the exact count and sequence check after the read.
fn read_complete_world_replay(
    sender: &mut pos_runtime::ErasureReadSenderV1<'_>,
    requested_use: &pos_runtime::WorldReplayUseV1,
    bounds: pos_core::EventReadBounds,
) -> Result<Vec<pos_core::Event>, pos_core::CoreError> {
    use pos_core::CoreError;

    let timeline = requested_use.timeline_id();
    let range = requested_use.range();
    let head = sender
        .logical_head(timeline)
        .map_err(host_error_to_core)?
        .as_u64();
    if head != requested_use.source_logical_head().as_u64() {
        return Err(CoreError::ArtifactUnavailable);
    }
    let first = range.from.as_u64().max(1);
    let last = range.to.map_or(head, pos_core::Seq::as_u64);
    if first > head.saturating_add(1) {
        return Err(CoreError::ArtifactUnavailable);
    }
    let expected = if first > last { 0 } else { last - first + 1 };
    // An unrepresentable count cannot fit a verifier's finite max_events.
    let expected = usize::try_from(expected).unwrap_or(usize::MAX);
    if expected > bounds.max_events() {
        return Err(CoreError::ArtifactUnavailable);
    }

    let events = sender
        .read_bounded(timeline, range, bounds)
        .map_err(host_error_to_core)?;
    if events.len() != expected
        || events.iter().enumerate().any(|(index, event)| {
            event.seq.as_u64() != first + u64::try_from(index).unwrap_or(u64::MAX)
        })
    {
        return Err(CoreError::ArtifactUnavailable);
    }
    Ok(events)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub mod test_support {
    use std::{
        fmt::Debug,
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        },
    };

    use pos_core::retention::{
        WorldRetentionLeaseInputV1, WorldRetentionLeaseV1, WorldRetentionPolicyInputV1,
        WorldRetentionPolicyV1,
    };
    use pos_core::trusted_clock::{
        open_release_guard, reserve_trusted_clock, ApplicableExpiriesV1, ExpiryPremisesV1,
        ReleaseGuardV1, SystemGuardMonotonicSourceV1, SystemTrustedWallSourceV1,
        TrustedWallSourceV1, WaitBudgetV1,
    };
    use pos_core::trusted_clock_fixture::TrustedClockFixtureV1;
    use pos_core::{
        AssuranceLevelV1, AuthenticatedPrincipalDraftV1, AuthenticatedPrincipalResultV1,
        Capability, ErasureGate, ErasureRecoveryLimitsV1, ErasureReferenceV1, ErasureReplayClaimV1,
        Hash, Plugin, PluginId, PrincipalRefV1, Reducer, TimelineId, WallTime,
        WorldReplayClosureV1,
    };
    use pos_runtime::{
        ErasureCoordinatorCompositionV1, ErasureExecutionHostV1, HostProjectionProviderV1,
        InstalledPluginFactoryV1, InstalledPluginProductV1, NoActionApproverV1,
        StagedFoldExecutorV1, VerifiedWorldReplayV1, WorldReplayUseV1,
        WorldReplayVerificationErrorV1, WorldReplayVerifierV1,
    };
    use pos_state::{ProjectionObservationPolicyV1, ProjectionRegistry, RecordedConsumerV1};
    use pos_store::StoreConfig;

    use crate::{ProtectedFoldV1, ProtectedReleaseV1, ReleaseHealthV1};

    const DAY_MICROS: u64 = 86_400_000_000;

    /// Serializes folds on the process-global staged executor.
    static EXECUTOR_SERIAL: AtomicBool = AtomicBool::new(false);

    /// Holds [`EXECUTOR_SERIAL`] until dropped.
    ///
    /// A plain flag guard rather than a `MutexGuard`, so a fixture that holds it
    /// for a whole test is not reported as a lock held longer than needed.
    pub(crate) struct SerialGuard;

    impl Drop for SerialGuard {
        fn drop(&mut self) {
            EXECUTOR_SERIAL.store(false, Ordering::Release);
        }
    }

    pub(crate) struct FixturePlugin {
        id: PluginId,
        name: &'static str,
    }

    impl Plugin for FixturePlugin {
        fn id(&self) -> PluginId {
            self.id
        }

        fn name(&self) -> &'static str {
            self.name
        }

        fn capability(&self) -> Capability {
            Capability {
                owned_event_types: Vec::new(),
                owned_entity_kinds: Vec::new(),
                has_driver: false,
                has_reducer: true,
            }
        }
    }

    pub(crate) struct FixtureConfiguration {
        name: &'static str,
        reducer: fn() -> Box<dyn Reducer>,
    }

    impl InstalledPluginFactoryV1 for FixturePlugin {
        type Configuration = FixtureConfiguration;
        type Plugin = Self;
        type Approver = NoActionApproverV1;

        fn configuration_details(configuration: &FixtureConfiguration) -> Vec<u8> {
            configuration.name.as_bytes().to_vec()
        }

        fn build(
            configuration: &FixtureConfiguration,
        ) -> InstalledPluginProductV1<Self, NoActionApproverV1> {
            InstalledPluginProductV1 {
                plugin: Self {
                    id: PluginId::new(),
                    name: configuration.name,
                },
                reducer: Some((configuration.reducer)()),
                approver: NoActionApproverV1,
            }
        }
    }

    /// One admitted staged consumer and the executor, held under the lock
    /// that serializes folds in this test process.
    pub(crate) struct ProtectedFixture {
        _serial: Option<SerialGuard>,
        executor: StagedFoldExecutorV1,
        provider: Arc<HostProjectionProviderV1>,
        consumers: Vec<RecordedConsumerV1>,
        name: &'static str,
        reducer: fn() -> Box<dyn Reducer>,
        policy: Option<ProjectionObservationPolicyV1>,
    }

    impl ProtectedFixture {
        pub(crate) fn new(name: &'static str, reducer: fn() -> Box<dyn Reducer>) -> Self {
            Self::admitted(Some(serial()), name, reducer, None)
        }

        /// A fixture whose admitted entry and installed slot both carry
        /// `policy`.
        pub(crate) fn observable(
            name: &'static str,
            reducer: fn() -> Box<dyn Reducer>,
            policy: ProjectionObservationPolicyV1,
        ) -> Self {
            Self::admitted(Some(serial()), name, reducer, Some(policy))
        }

        /// Another admission of the same reducer under its own provider and
        /// Plugin identity, serialized by this fixture's lock.
        pub(crate) fn rival(&self) -> Self {
            Self::admitted(None, self.name, self.reducer, self.policy.clone())
        }

        fn admitted(
            serial: Option<SerialGuard>,
            name: &'static str,
            reducer: fn() -> Box<dyn Reducer>,
            policy: Option<ProjectionObservationPolicyV1>,
        ) -> Self {
            let mut provider = HostProjectionProviderV1::default();
            let configuration = Arc::new(FixtureConfiguration { name, reducer });
            let consumer = test_ok(
                provider.admit_fixture_with_policy::<FixturePlugin>(configuration, policy.clone()),
            );
            Self {
                _serial: serial,
                executor: test_ok(StagedFoldExecutorV1::acquire()),
                provider: Arc::new(provider),
                consumers: vec![consumer],
                name,
                reducer,
                policy,
            }
        }

        /// A visible registry whose one installed slot is the recorded
        /// consumer, with the fixture's observation policy.
        pub(crate) fn registry(&self, gate: Arc<dyn ErasureGate>) -> ProjectionRegistry {
            self.registry_with_policy(gate, self.policy.clone())
        }

        /// A visible registry whose one installed slot is the recorded
        /// consumer, with `policy` in place of the fixture's.
        pub(crate) fn registry_with_policy(
            &self,
            gate: Arc<dyn ErasureGate>,
            policy: Option<ProjectionObservationPolicyV1>,
        ) -> ProjectionRegistry {
            let mut registry = ProjectionRegistry::new().with_erasure_gate(gate);
            test_ok(registry.register_installed_reducer_with_policy(
                self.consumers[0].plugin_id(),
                self.name,
                (self.reducer)(),
                policy,
            ));
            registry
        }

        pub(crate) fn fold(&self) -> ProtectedFoldV1<'_> {
            ProtectedFoldV1 {
                executor: &self.executor,
                provider: &self.provider,
                consumers: &self.consumers,
            }
        }
    }

    fn lease(deadline: u64) -> WorldRetentionLeaseV1 {
        let policy = test_ok(WorldRetentionPolicyV1::new(WorldRetentionPolicyInputV1 {
            policy_revision: 1,
            purpose: "world".to_owned(),
            audience_policy_hash: Hash::from_bytes([7; 32]),
            minimum_post_admission_days: 90,
            maximum_active_days: 30,
            maximum_total_days: 120,
        }));
        let input = WorldRetentionLeaseInputV1 {
            timeline_id: TimelineId::new(),
            policy_hash: policy.digest(),
            started_at_micros: deadline - 120 * DAY_MICROS,
            admission_closes_at_micros: deadline - 90 * DAY_MICROS,
            retention_deadline_micros: deadline,
        };
        test_ok(WorldRetentionLeaseV1::new(&policy, input))
    }

    fn authenticated(expires_at: u64) -> AuthenticatedPrincipalResultV1 {
        let draft = AuthenticatedPrincipalDraftV1 {
            principal: test_ok(PrincipalRefV1::try_new([1; 16], "operators")),
            adapter_id: "test-passkey".to_owned(),
            assurance: test_ok(AssuranceLevelV1::try_new(2)),
            issued_at: WallTime::from_micros(1),
            expires_at: WallTime::from_micros(expires_at),
            binding_digest: Hash::from_bytes([7; 32]),
        };
        test_ok(AuthenticatedPrincipalResultV1::try_from_draft(draft))
    }

    /// Spin-acquire [`EXECUTOR_SERIAL`], yielding between attempts, and return
    /// a guard that releases it on drop.
    fn serial() -> SerialGuard {
        while EXECUTOR_SERIAL
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            std::thread::yield_now();
        }
        SerialGuard
    }

    /// An observation policy permitting the `n` field.
    pub(crate) fn count_policy() -> ProjectionObservationPolicyV1 {
        test_ok(ProjectionObservationPolicyV1::try_new(
            vec!["n".to_owned()],
            "count.v1".to_owned(),
            Hash::from_bytes([7; 32]),
            Hash::from_bytes([8; 32]),
            Hash::from_bytes([9; 32]),
        ))
    }

    /// Run `body` with one fresh ADR-112 release on its own authority.
    pub(crate) fn with_release<T>(body: impl FnOnce(ProtectedReleaseV1<'_>) -> T) -> T {
        with_release_health(&ReleaseHealthV1::new(), body)
    }

    /// Run `body` with one fresh ADR-112 release reporting into `health`.
    pub(crate) fn with_release_health<T>(
        health: &ReleaseHealthV1,
        body: impl FnOnce(ProtectedReleaseV1<'_>) -> T,
    ) -> T {
        let mut port = TrustedClockFixtureV1::new();
        let guard = guard_on(&mut port);
        let expiries = far_expiries(&guard);
        body(ProtectedReleaseV1 {
            guard,
            expiries,
            health,
        })
    }

    /// Run `body` with a release whose expiries were checked under another
    /// authority's guard: every check before the handoff passes, and the
    /// ADR-112 handoff then refuses it as `AuthorityRegressed`.
    pub(crate) fn with_mismatched_release_health<T>(
        health: &ReleaseHealthV1,
        body: impl FnOnce(ProtectedReleaseV1<'_>) -> T,
    ) -> T {
        let mut other_port = TrustedClockFixtureV1::new();
        let other_guard = guard_on(&mut other_port);
        let expiries = far_expiries(&other_guard);
        drop(other_guard);
        let mut port = TrustedClockFixtureV1::new();
        let guard = guard_on(&mut port);
        body(ProtectedReleaseV1 {
            guard,
            expiries,
            health,
        })
    }

    /// Reserve on `port`'s identity and open its release guard.
    fn guard_on(port: &mut TrustedClockFixtureV1) -> ReleaseGuardV1<'_> {
        let mut store = port.clone();
        let mut wait = WaitBudgetV1::new();
        let reservation = test_ok(reserve_trusted_clock(
            &mut store,
            &mut SystemTrustedWallSourceV1,
            &mut SystemGuardMonotonicSourceV1,
            &mut wait,
            None,
        ));
        test_ok(open_release_guard(
            port,
            reservation,
            &mut wait,
            &mut SystemGuardMonotonicSourceV1,
        ))
    }

    /// Expiries far in the future, checked under `guard`.
    fn far_expiries(guard: &ReleaseGuardV1<'_>) -> ApplicableExpiriesV1 {
        let far = test_ok(SystemTrustedWallSourceV1.sample()).as_micros() + 1_000 * DAY_MICROS;
        let leases = [lease(far)];
        let access = authenticated(far);
        let premises = ExpiryPremisesV1 {
            retention_leases: &leases,
            consent_grants: &[],
            consent_references: &[],
            access: Some(&access),
        };
        test_ok(guard.applicable_expiries(&premises))
    }

    struct ExactWorldReplayVerifier;

    impl WorldReplayVerifierV1 for ExactWorldReplayVerifier {
        fn verify(
            &self,
            closure: &WorldReplayClosureV1,
            requested_use: &WorldReplayUseV1,
            inventory_generation: ErasureReferenceV1,
        ) -> Result<VerifiedWorldReplayV1, WorldReplayVerificationErrorV1> {
            Ok(pos_runtime::world_replay::test_verified_world_replay(
                closure,
                requested_use,
                inventory_generation,
                ErasureReplayClaimV1::Exact,
            ))
        }
    }

    pub(crate) fn open_exact_host() -> ErasureExecutionHostV1 {
        let composition = ErasureCoordinatorCompositionV1::closed()
            .with_world_replay_verifier(Arc::new(ExactWorldReplayVerifier));
        test_ok(ErasureExecutionHostV1::open_with_authority(
            StoreConfig::Memory,
            &composition,
            ErasureRecoveryLimitsV1::compiled_maximum(),
        ))
    }

    pub(crate) fn closure_for_host(
        host: &mut ErasureExecutionHostV1,
        timeline: pos_core::TimelineId,
    ) -> WorldReplayClosureV1 {
        closure_for_host_consumer(host, timeline, "count")
    }

    pub(crate) fn closure_for_host_consumer(
        host: &mut ErasureExecutionHostV1,
        timeline: pos_core::TimelineId,
        consumer_id: &str,
    ) -> WorldReplayClosureV1 {
        let (_, generation) = test_ok(test_ok(host.read_sender()).read_bounded_at_generation(
            timeline,
            pos_core::store::SeqRange::all(),
            pos_core::store::EventReadBounds::new(usize::MAX, usize::MAX, usize::MAX, usize::MAX),
            None,
        ));
        test_ok(WorldReplayClosureV1::test_fixture_for_timeline_consumer(
            timeline,
            Hash::from_bytes(generation.digest()),
            consumer_id,
        ))
    }

    pub(crate) fn test_ok<T, E: Debug>(value: Result<T, E>) -> T {
        value.unwrap_or_else(|error| {
            std::panic::resume_unwind(Box::new(format!(
                "unexpected test fixture error: {error:?}"
            )))
        })
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::{
        handoff_with_p2_on, host_error_to_core, observed_world_replay_use,
        read_complete_world_replay, ReleaseHealthV1,
    };
    use pos_core::trusted_clock::{
        ScriptedGuardMonotonicSourceV1, StagedArtifactBytesV1, StagedProtectedOutputV1,
    };
    use pos_core::{
        event::{CanonicalBytes, EventDraft, Kind},
        store::{EventReadBounds, SeqRange},
        CoreError, EntityId, ErasureHostErrorV1, ErasureProtectedOperationV1, Seq, TimelineId,
    };
    use pos_runtime::{WorldReplayUseV1, GUARD_RELEASE_LATE_SIGNAL};
    use std::time::Duration;

    /// A refused handoff whose P2 measurement lands past `g0 + 30 s` records
    /// the late signal; nothing is handed over and no overrun is recorded.
    #[test]
    fn a_late_refused_handoff_records_the_guard_release_late_signal() {
        let health = ReleaseHealthV1::new();
        let refused = crate::test_support::with_mismatched_release_health(&health, |release| {
            let mut late = ScriptedGuardMonotonicSourceV1::new([Duration::from_hours(1)]);
            let staged = StagedProtectedOutputV1::stage(StagedArtifactBytesV1::new(vec![7]));
            handoff_with_p2_on(
                release.guard,
                &release.expiries,
                staged,
                release.health,
                &mut late,
            )
        });
        assert!(matches!(refused, Err(CoreError::ArtifactUnavailable)));
        assert_eq!(health.overrun_signal(), None);
        assert_eq!(health.guard_release_late(), Some(GUARD_RELEASE_LATE_SIGNAL));
    }

    fn use_at(timeline: TimelineId, range: SeqRange, head: u64) -> WorldReplayUseV1 {
        crate::test_support::test_ok(WorldReplayUseV1::new(
            timeline,
            ErasureProtectedOperationV1::Read,
            range,
            Seq::from_u64(head),
            vec!["count".to_owned()],
            Vec::new(),
        ))
    }

    #[test]
    fn complete_replay_rejects_moved_heads_and_insufficient_bounds() {
        let mut host = crate::test_support::open_exact_host();
        let timeline = {
            let mut commands = crate::test_support::test_ok(host.command_sender());
            let timeline = crate::test_support::test_ok(commands.create_timeline("bounded-replay"));
            let draft = EventDraft::new(
                EntityId::new(),
                Kind::new("test.tick"),
                CanonicalBytes::from_vec(Vec::new()),
            );
            crate::test_support::test_ok(commands.append(timeline.id(), &[draft.clone(), draft]));
            timeline.id()
        };
        let mut sender = crate::test_support::test_ok(host.read_sender());
        let sufficient = EventReadBounds::new(65_536, 128, 8, 2);
        for stale_head in [1, 3] {
            assert!(matches!(
                read_complete_world_replay(
                    &mut sender,
                    &use_at(timeline, SeqRange::all(), stale_head),
                    sufficient,
                ),
                Err(CoreError::ArtifactUnavailable)
            ));
        }
        assert!(matches!(
            read_complete_world_replay(
                &mut sender,
                &use_at(timeline, SeqRange::from_seq(Seq::from_u64(4)), 2),
                sufficient,
            ),
            Err(CoreError::ArtifactUnavailable)
        ));
        assert!(matches!(
            read_complete_world_replay(
                &mut sender,
                &use_at(timeline, SeqRange::all(), 2),
                EventReadBounds::new(65_536, 128, 8, 1),
            ),
            Err(CoreError::ArtifactUnavailable)
        ));
        assert!(crate::test_support::test_ok(read_complete_world_replay(
            &mut sender,
            &use_at(timeline, SeqRange::from_seq(Seq::from_u64(3)), 2),
            sufficient,
        ))
        .is_empty());
        assert_eq!(
            crate::test_support::test_ok(read_complete_world_replay(
                &mut sender,
                &use_at(timeline, SeqRange::bounded(Seq::ZERO, Seq::from_u64(1)), 2),
                sufficient,
            ))
            .len(),
            1
        );
        assert_eq!(
            crate::test_support::test_ok(read_complete_world_replay(
                &mut sender,
                &use_at(timeline, SeqRange::all(), 2),
                sufficient,
            ))
            .len(),
            2
        );
        assert!(read_complete_world_replay(
            &mut sender,
            &use_at(TimelineId::new(), SeqRange::all(), 2),
            sufficient,
        )
        .is_err());
        assert!(read_complete_world_replay(
            &mut sender,
            &use_at(timeline, SeqRange::all(), 2),
            EventReadBounds::new(65_536, 0, 8, 2),
        )
        .is_err());
    }

    #[test]
    fn observed_use_binds_the_current_logical_head() {
        let mut host = crate::test_support::open_exact_host();
        let timeline = {
            let mut commands = crate::test_support::test_ok(host.command_sender());
            let timeline = crate::test_support::test_ok(commands.create_timeline("observed-head"));
            let draft = EventDraft::new(
                EntityId::new(),
                Kind::new("test.tick"),
                CanonicalBytes::from_vec(Vec::new()),
            );
            crate::test_support::test_ok(commands.append(timeline.id(), &[draft]));
            timeline.id()
        };
        let mut sender = crate::test_support::test_ok(host.read_sender());
        let consumers = ["count".to_owned()];
        let observed = crate::test_support::test_ok(observed_world_replay_use(
            &mut sender,
            timeline,
            ErasureProtectedOperationV1::Read,
            SeqRange::all(),
            &consumers,
        ));
        assert_eq!(observed.source_logical_head(), Seq::from_u64(1));
        assert!(matches!(
            observed_world_replay_use(
                &mut sender,
                timeline,
                ErasureProtectedOperationV1::Read,
                SeqRange::bounded(Seq::ZERO, Seq::from_u64(2)),
                &consumers,
            ),
            Err(CoreError::ArtifactUnavailable)
        ));
        assert!(observed_world_replay_use(
            &mut sender,
            TimelineId::new(),
            ErasureProtectedOperationV1::Read,
            SeqRange::all(),
            &consumers,
        )
        .is_err());
    }

    #[test]
    fn host_errors_map_to_stable_public_time_errors() {
        assert!(matches!(
            host_error_to_core(ErasureHostErrorV1::AccessFrozen),
            CoreError::ErasureAccessFrozen
        ));
        for host in [
            ErasureHostErrorV1::RecoveryUnavailable,
            ErasureHostErrorV1::StaleGeneration,
        ] {
            assert!(matches!(
                host_error_to_core(host),
                CoreError::ErasureContainmentUnavailable
            ));
        }
        for host in [
            ErasureHostErrorV1::AuthorizationDenied,
            ErasureHostErrorV1::Conflict,
            ErasureHostErrorV1::AdapterFailure,
        ] {
            assert!(matches!(
                host_error_to_core(host),
                CoreError::ArtifactUnavailable
            ));
        }
    }

    /// Case 13 (registry part): the ADR-093 Revision 4 forget applies only on
    /// failure, only for a range that was read and verified, and only to its
    /// revoked subjects.
    #[test]
    fn the_failure_path_forget_applies_only_to_verified_failed_ranges() {
        use pos_core::{Event, EventId, Hash, SchemaVersion, WallTime};
        use std::sync::Arc;

        let event = |entity, event_type: &str, payload| Event {
            id: EventId::new(),
            entity,
            event_type: Kind::new(event_type),
            payload,
            wall_time: WallTime::from_micros(1),
            seq: Seq::from_u64(1),
            causation_id: None,
            correlation_id: None,
            schema_version: SchemaVersion::V1,
            signature: None,
            signature_identity: None,
            origin: None,
            payload_hash: Hash::from_bytes([0; 32]),
        };
        let (revoked, kept, timeline) = (EntityId::new(), EntityId::new(), TimelineId::new());
        let mut registry = pos_state::ProjectionRegistry::new()
            .with_erasure_gate(Arc::new(pos_core::ErasureContainmentGateV1::new_test_open()));
        registry.register("events", Box::new(pos_state::EntityStateProjection));
        for entity in [revoked, kept] {
            registry.apply_event(
                timeline,
                &event(entity, "test.tick", CanonicalBytes::from_vec(Vec::new())),
            );
        }
        let payload = crate::test_support::test_ok(
            pos_core::ConsentRevokedV1 {
                subject_id: revoked,
                grantee_id: EntityId::new(),
                grant_seq: 1,
                fence_seq: 2,
            }
            .encode(),
        );
        let range = [event(
            revoked,
            pos_core::EVENT_TYPE_CONSENT_REVOKED_V1,
            payload,
        )];
        let subjects = pos_state::RevokedSubjectsV1::from_verified_events(&range);
        let present = |registry: &pos_state::ProjectionRegistry, entity| {
            crate::test_support::test_ok(registry.state_for(timeline, &entity)).is_some()
        };

        assert!(super::forget_on_failure(Ok(()), &mut registry, Some(&subjects)).is_ok());
        assert!(present(&registry, revoked));
        let unverified = Err::<(), _>(CoreError::ArtifactUnavailable);
        assert!(super::forget_on_failure(unverified, &mut registry, None).is_err());
        assert!(present(&registry, revoked));
        let failed = Err::<(), _>(CoreError::ArtifactUnavailable);
        assert!(super::forget_on_failure(failed, &mut registry, Some(&subjects)).is_err());
        assert!(!present(&registry, revoked));
        assert!(present(&registry, kept));
    }
}
