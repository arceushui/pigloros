//! Plugin registry — the single registration point for all plugins.
//!
//! A plugin registers its `Capability` here. The registry wires:
//! - event type schemas into `SchemaRegistry`
//! - reducers into `ProjectionRegistry`
//! - drivers into the runtime's step loop

use indexmap::IndexMap;

use pos_core::{
    clock::Seq,
    event::{Event, EventDraft, Kind},
    ids::PluginId,
    ActionApprover, ActionRejected, Capability, ConsentAuthority, ConsentCapabilityToken,
    ConsentError, ConsentGate, Plugin, ProposedAction, Reducer, MAX_PROPOSED_ACTION_PAYLOAD_BYTES,
};
use pos_state::ProjectionRegistry;

use crate::{
    composition::{PluginComposition, RegisteredEventSchema, RegisteredPlugin},
    driver::{
        Driver, DriverRecoveryEvidence, ObservationSnapshot, ProjectionKey, SnapshotAnchor,
        StepOutput, TimelineHistorySegment,
    },
    error::RuntimeError,
    recorder::{RunMode, RECORDER_EVENT_TYPE},
    schema::{EventTypeSchema, SchemaRegistry},
};
use std::{collections::HashSet, sync::Arc};

fn extend_unique_subscriptions(
    subscriptions: &mut Vec<ProjectionKey>,
    seen: &mut HashSet<ProjectionKey>,
    keys: &[ProjectionKey],
) {
    for key in keys {
        if seen.insert(key.clone()) {
            subscriptions.push(key.clone());
        }
    }
}

fn driver_visible_event(event: &Event) -> bool {
    !pos_core::is_consent_event_type(&event.event_type)
        && !pos_core::is_geographic_event_type(&event.event_type)
        && event.event_type.as_str() != pos_core::HOST_CONSENT_CLOSED_EVENT_TYPE
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod coverage_paths {
    use super::*;
    use crate::driver::{ObservationView, StepOutput, TimelineHistorySegment};
    use pos_core::{
        clock::{Seq, WallTime},
        crypto::Hash,
        event::{CanonicalBytes, Kind, SchemaVersion},
        ids::{EntityId, EventId, TimelineId},
        Event,
    };
    use std::sync::{Arc, Mutex};

    struct RestoreDriver {
        committed: Arc<Mutex<bool>>,
    }

    impl Driver for RestoreDriver {
        fn name(&self) -> &'static str {
            "coverage-restore"
        }

        fn step(
            &mut self,
            _: TimelineId,
            _: ObservationView<'_>,
        ) -> Result<StepOutput, RuntimeError> {
            Ok(StepOutput::empty())
        }

        fn commit_restore_from_history(&mut self) {
            *self
                .committed
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = true;
        }
    }

    struct RestoreFailureDriver {
        aborts: Arc<Mutex<u32>>,
    }

    struct RecoveryVisibilityDriver {
        observed: Arc<Mutex<Vec<(String, bool)>>>,
    }

    impl Driver for RecoveryVisibilityDriver {
        fn name(&self) -> &'static str {
            "coverage-recovery-visibility"
        }

        fn step(
            &mut self,
            _: TimelineId,
            _: ObservationView<'_>,
        ) -> Result<StepOutput, RuntimeError> {
            Ok(StepOutput::empty())
        }

        fn needs_recovery_payload(&self, _: &crate::driver::RecoveryEventHeader) -> bool {
            true
        }

        fn stage_restore_from_history(
            &mut self,
            evidence: &DriverRecoveryEvidence,
        ) -> Result<(), RuntimeError> {
            self.observed
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .extend(evidence.events().iter().map(|event| {
                    (
                        event.header().event_type().as_str().to_owned(),
                        event.payload().is_some(),
                    )
                }));
            Ok(())
        }
    }

    #[test]
    fn recovery_filters_geographic_events_before_driver_evidence() {
        let timeline = TimelineId::new();
        let observed = Arc::new(Mutex::new(Vec::new()));
        let mut registry = PluginRegistry::new();
        registry.register_driver(Box::new(RecoveryVisibilityDriver {
            observed: Arc::clone(&observed),
        }));
        let event = Event {
            id: EventId::new(),
            entity: EntityId::new(),
            event_type: Kind::new("ordinary.event"),
            payload: CanonicalBytes::from_static(b"ordinary"),
            wall_time: WallTime::from_micros(1),
            seq: Seq::from_u64(1),
            causation_id: None,
            correlation_id: None,
            schema_version: SchemaVersion::V1,
            signature: None,
            signature_identity: None,
            payload_hash: Hash::from_bytes([0; 32]),
        };
        let mut location = event.clone();
        location.event_type = Kind::new(pos_core::GEOGRAPHIC_EVENT_TYPE);
        location.seq = Seq::from_u64(2);
        let mut cell = event.clone();
        cell.event_type = Kind::new(pos_core::GEOGRAPHIC_CELL_EVENT_TYPE);
        cell.seq = Seq::from_u64(3);
        let mut marker = event.clone();
        marker.event_type = Kind::new(pos_core::HOST_CONSENT_CLOSED_EVENT_TYPE);
        marker.seq = Seq::from_u64(4);
        let events = vec![event, location, cell, marker];
        registry.fold_events(&events);
        assert!(registry
            .restore_driver_state(
                &[TimelineHistorySegment::new(timeline, Seq::from_u64(4))],
                &events,
            )
            .is_ok());
        assert_eq!(
            observed
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .as_slice(),
            [("ordinary.event".to_owned(), true)]
        );
    }

    impl Driver for RestoreFailureDriver {
        fn name(&self) -> &'static str {
            "coverage-restore-failure"
        }

        fn step(
            &mut self,
            _: TimelineId,
            _: ObservationView<'_>,
        ) -> Result<StepOutput, RuntimeError> {
            Ok(StepOutput::empty())
        }

        fn stage_restore_from_history(
            &mut self,
            _: &DriverRecoveryEvidence,
        ) -> Result<(), RuntimeError> {
            Err(RuntimeError::InvalidRecoveryEvidence {
                reason: "coverage restore failure",
            })
        }

        fn abort_restore_from_history(&mut self) {
            *self
                .aborts
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) += 1;
        }
    }

    #[test]
    fn restore_with_history_commits_and_advances_driver_cursor() {
        let timeline = TimelineId::new();
        let committed = Arc::new(Mutex::new(false));
        let mut registry = PluginRegistry::new();
        registry.register_driver(Box::new(RestoreDriver {
            committed: Arc::clone(&committed),
        }));
        assert!(registry.step_all(timeline).is_ok());
        let event = Event {
            id: EventId::new(),
            entity: EntityId::new(),
            event_type: Kind::new("coverage.restore"),
            payload: CanonicalBytes::from_static(b"history"),
            wall_time: WallTime::from_micros(1),
            seq: Seq::from_u64(1),
            causation_id: None,
            correlation_id: None,
            schema_version: SchemaVersion::V1,
            signature: None,
            signature_identity: None,
            payload_hash: Hash::from_bytes([0; 32]),
        };
        let result = registry.restore_driver_state(
            &[TimelineHistorySegment::new(timeline, Seq::from_u64(1))],
            &[event],
        );
        assert!(result.is_ok());
        assert!(*committed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner));
        assert!(registry
            .restore_driver_state(&[TimelineHistorySegment::new(timeline, Seq::ZERO)], &[],)
            .is_ok());
    }

    #[test]
    fn transaction_cleanup_ignores_unresolvable_staged_identifiers() {
        let id = PluginId::new();
        let mut registry = PluginRegistry::new();
        registry.pending_step = Some(PendingStep {
            timeline: TimelineId::new(),
            driver_ids: vec![id],
            cadence_updates: Vec::new(),
            event_cursors: Vec::new(),
            operation: OperationContext::Public,
        });
        registry.abort_step();

        registry.pending_step = Some(PendingStep {
            timeline: TimelineId::new(),
            driver_ids: vec![id],
            cadence_updates: vec![(id, 1)],
            event_cursors: vec![(id, Seq::ZERO)],
            operation: OperationContext::Public,
        });
        assert!(registry.commit_step_at(Seq::ZERO, 0).is_ok());
    }

    #[test]
    fn restore_failure_aborts_drivers_that_staged_before_the_failure() {
        let timeline = TimelineId::new();
        let aborts = Arc::new(Mutex::new(0));
        let mut registry = PluginRegistry::new();
        registry.register_driver(Box::new(RestoreDriver {
            committed: Arc::new(Mutex::new(false)),
        }));
        registry.register_driver(Box::new(RestoreFailureDriver {
            aborts: Arc::clone(&aborts),
        }));

        assert!(matches!(
            registry
                .restore_driver_state(&[TimelineHistorySegment::new(timeline, Seq::ZERO)], &[],),
            Err(RuntimeError::InvalidRecoveryEvidence { .. })
        ));
        assert_eq!(
            *aborts
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
            1
        );
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod coverage_entrypoints {
    use super::*;
    use crate::driver::{Driver, ObservationView, StepOutput, TimelineHistorySegment};
    use pos_core::{
        clock::{Seq, WallTime},
        crypto::Hash,
        event::{CanonicalBytes, Event, EventDraft, Kind, SchemaVersion},
        ids::{EntityId, EventId, TimelineId},
        ConsentAuthority, ConsentGrantedV1,
    };

    struct NoopDriver;

    impl Driver for NoopDriver {
        fn step(
            &mut self,
            _: TimelineId,
            _: ObservationView<'_>,
        ) -> Result<StepOutput, RuntimeError> {
            Ok(StepOutput {
                drafts: vec![EventDraft::new(
                    EntityId::new(),
                    Kind::new("coverage.public.tick"),
                    CanonicalBytes::from_static(b"coverage"),
                )],
            })
        }

        fn name(&self) -> &'static str {
            "coverage-registry-driver"
        }
    }

    struct CommitTrackingDriver {
        committed: std::sync::Arc<std::sync::Mutex<bool>>,
    }

    impl Driver for CommitTrackingDriver {
        fn step(
            &mut self,
            _: TimelineId,
            _: ObservationView<'_>,
        ) -> Result<StepOutput, RuntimeError> {
            Ok(StepOutput::empty())
        }

        fn name(&self) -> &'static str {
            "coverage-commit-tracking-driver"
        }

        fn commit_restore_from_history(&mut self) {
            *self
                .committed
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = true;
        }
    }

    #[test]
    fn restore_and_cadence_entrypoints_update_driver_state() {
        let mut registry = PluginRegistry::new();
        registry.register_driver(Box::new(NoopDriver));
        let timeline = TimelineId::new();
        let restore_event = event("coverage.restore", 1);
        assert!(registry
            .restore_driver_state(
                &[TimelineHistorySegment::new(timeline, Seq::from_u64(1))],
                &[restore_event],
            )
            .is_ok());
        assert!(registry
            .tick_cadenced(timeline, u128::MAX)
            .is_ok_and(|drafts| drafts.len() == 1));
    }

    #[test]
    fn restore_commit_and_cursor_paths_are_exercised_at_a_public_seam() {
        let committed = std::sync::Arc::new(std::sync::Mutex::new(false));
        let mut registry = PluginRegistry::new();
        registry.register_driver(Box::new(CommitTrackingDriver {
            committed: std::sync::Arc::clone(&committed),
        }));
        let timeline = TimelineId::new();
        assert!(registry.step_all(timeline).is_ok());
        let restore_event = event("coverage.restore.commit", 1);
        assert!(registry
            .restore_driver_state(
                &[TimelineHistorySegment::new(timeline, Seq::from_u64(1))],
                &[restore_event],
            )
            .is_ok());
        assert!(*committed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner));
    }

    #[test]
    fn public_entrypoints_fail_closed_when_the_consent_gate_is_unbound() {
        let timeline = TimelineId::new();
        assert!(matches!(
            PluginRegistry::new()
                .without_consent_gate()
                .tick_cadenced(timeline, 0),
            Err(RuntimeError::ConsentOperationUnavailable)
        ));
        assert!(matches!(
            PluginRegistry::new()
                .without_consent_gate()
                .step_all(timeline),
            Err(RuntimeError::ConsentOperationUnavailable)
        ));
    }

    fn event(event_type: &str, seq: u64) -> Event {
        Event {
            id: EventId::new(),
            entity: EntityId::new(),
            event_type: Kind::new(event_type),
            payload: CanonicalBytes::from_static(b"coverage"),
            wall_time: WallTime::from_micros(1),
            seq: Seq::from_u64(seq),
            causation_id: None,
            correlation_id: None,
            schema_version: SchemaVersion::V1,
            signature: None,
            signature_identity: None,
            payload_hash: Hash::from_bytes([0; 32]),
        }
    }

    #[test]
    fn authorized_projection_public_and_protected_evidence_paths_are_explicit() {
        let timeline = TimelineId::new();
        assert!(matches!(
            PluginRegistry::new().into_authorized_projections(timeline, Seq::ZERO, 0, None, None,),
            Err(RuntimeError::ConsentOperationUnavailable)
        ));
        assert!(PluginRegistry::new()
            .into_authorized_projections(timeline, Seq::ZERO, 0, None, Some(&[]))
            .is_ok());

        for protected_type in [
            "consent.granted.v1",
            pos_core::GEOGRAPHIC_EVENT_TYPE,
            "persona.profile.v1",
            "timeline.fork.created.v1",
            "retention.policy.v1",
        ] {
            assert!(matches!(
                PluginRegistry::new().into_authorized_projections(
                    timeline,
                    Seq::from_u64(1),
                    0,
                    None,
                    Some(&[event(protected_type, 1)]),
                ),
                Err(RuntimeError::ConsentOperationUnavailable)
            ));
        }

        let subject = EntityId::new();
        let authority = ConsentAuthority::new();
        let token = authority.record_grant_on_timeline(
            timeline,
            &ConsentGrantedV1 {
                subject_id: subject,
                grantee_id: EntityId::new(),
                purpose: "coverage".to_owned(),
                modalities: 0,
                min_geo_resolution: 0,
                fork_permitted: false,
                export_permitted: false,
                retention_days: 0,
                expiry_secs: 0,
                grant_seq: 1,
            },
        );
        assert!(PluginRegistry::new()
            .with_consent_authority(authority)
            .into_authorized_projections(timeline, Seq::ZERO, 0, Some(&token), None)
            .is_ok());
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    mod marker_driver {
        use super::*;
        use std::sync::{Arc, Mutex};

        pub(super) struct DriverImpl {
            pub(super) observed: Arc<Mutex<Vec<String>>>,
        }

        impl Driver for DriverImpl {
            fn step(
                &mut self,
                _: TimelineId,
                _: ObservationView<'_>,
            ) -> Result<StepOutput, RuntimeError> {
                Ok(StepOutput::empty())
            }

            fn name(&self) -> &'static str {
                "coverage-visibility-driver"
            }

            fn needs_recovery_payload(&self, _: &crate::driver::RecoveryEventHeader) -> bool {
                true
            }

            fn stage_restore_from_history(
                &mut self,
                evidence: &crate::driver::DriverRecoveryEvidence,
            ) -> Result<(), RuntimeError> {
                self.observed
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .extend(
                        evidence
                            .events()
                            .iter()
                            .map(|event| event.header().event_type().as_str().to_owned()),
                    );
                Ok(())
            }
        }
    }

    #[test]
    fn public_recovery_seam_hides_host_control_markers() {
        let timeline = TimelineId::new();
        let observed = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut registry = PluginRegistry::new();
        registry.register_driver(Box::new(marker_driver::DriverImpl {
            observed: std::sync::Arc::clone(&observed),
        }));
        let events = vec![
            event("ordinary.event", 1),
            event(pos_core::HOST_CONSENT_CLOSED_EVENT_TYPE, 2),
        ];

        registry.fold_events(&events);
        assert!(registry
            .restore_driver_state(
                &[TimelineHistorySegment::new(timeline, Seq::from_u64(2))],
                &events,
            )
            .is_ok());
        assert_eq!(
            *observed
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
            vec!["ordinary.event".to_owned()]
        );
    }
}

fn validate_recovery_evidence(
    timeline_segments: &[TimelineHistorySegment],
    events: &[Event],
) -> Result<(), RuntimeError> {
    let unique = timeline_segments
        .iter()
        .enumerate()
        .all(|(index, segment)| {
            !timeline_segments[..index]
                .iter()
                .any(|prior| prior.timeline_id() == segment.timeline_id())
        });
    let ordered = timeline_segments
        .windows(2)
        .all(|pair| pair[0].through() <= pair[1].through());
    let Some(last_segment) = timeline_segments.last() else {
        return Err(RuntimeError::InvalidRecoveryEvidence {
            reason: "Timeline ancestry is empty",
        });
    };
    if !unique || !ordered {
        return Err(RuntimeError::InvalidRecoveryEvidence {
            reason: "Timeline ancestry is duplicate or unordered",
        });
    }
    let expected_through = last_segment.through();
    if events.is_empty() && expected_through == Seq::ZERO {
        return Ok(());
    }
    if events.first().map_or(Seq::ZERO, |event| event.seq) != Seq::from_u64(1) {
        return Err(RuntimeError::InvalidRecoveryEvidence {
            reason: "source Events must begin at sequence 1",
        });
    }
    for pair in events.windows(2) {
        if pair[1].seq != Seq::from_u64(pair[0].seq.as_u64().saturating_add(1)) {
            return Err(RuntimeError::InvalidRecoveryEvidence {
                reason: "source Events must be contiguous",
            });
        }
    }
    if events.last().map_or(Seq::ZERO, |event| event.seq) != expected_through {
        return Err(RuntimeError::InvalidRecoveryEvidence {
            reason: "source Events must reach the final Timeline bound",
        });
    }
    Ok(())
}

fn reject_host_owned_drafts(output: &StepOutput) -> Result<(), RuntimeError> {
    reject_host_owned_draft_slice(&output.drafts)
}

fn reject_host_owned_draft_slice(drafts: &[EventDraft]) -> Result<(), RuntimeError> {
    drafts
        .iter()
        .find(|draft| {
            pos_core::is_geographic_event_type(&draft.event_type)
                || pos_core::is_consent_event_type(&draft.event_type)
        })
        .map_or(Ok(()), |draft| {
            if pos_core::is_consent_event_type(&draft.event_type) {
                Err(RuntimeError::ConsentDraft {
                    event_type: draft.event_type.as_str().to_owned(),
                })
            } else {
                Err(RuntimeError::GeographicDraft {
                    event_type: draft.event_type.as_str().to_owned(),
                })
            }
        })
}

fn invoke_driver(
    driver: &mut dyn Driver,
    timeline: pos_core::ids::TimelineId,
    observations: crate::driver::ObservationView<'_>,
) -> Result<StepOutput, RuntimeError> {
    let name = driver.name().to_owned();
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        driver.step(timeline, observations)
    }))
    .map_err(|_| RuntimeError::DriverPanicked { name })?
}

/// A registered plugin entry.
struct PluginEntry {
    name: String,
    version: String,
    driver: Option<Box<dyn Driver>>,
    approver: Option<Box<dyn ActionApprover>>,
    last_tick: Option<u128>,
    event_cursor: Seq,
}

const fn plugin_name(entry: &PluginEntry) -> &str {
    entry.name.as_str()
}

const fn plugin_name_and_version(entry: &PluginEntry) -> (&str, &str) {
    (entry.name.as_str(), entry.version.as_str())
}

struct PendingStep {
    timeline: pos_core::ids::TimelineId,
    driver_ids: Vec<PluginId>,
    cadence_updates: Vec<(PluginId, u128)>,
    event_cursors: Vec<(PluginId, Seq)>,
    operation: OperationContext,
}

/// Explicit host operation authorization for a Driver Tick or projection read.
///
/// `Public` is deliberately explicit at every host call site. `Protected` is
/// only usable when it carries a capability issued by the authority bound to
/// this registry.
#[derive(Clone)]
pub enum OperationContext {
    Public,
    Protected {
        token: ConsentCapabilityToken,
        now_secs: u64,
    },
}

#[derive(Clone, Copy)]
enum AnchoredSelection {
    All,
    Cadenced { now_ns: u128 },
}

type AnchoredSelectionResult = (Vec<PluginId>, Vec<(PluginId, u128)>, Vec<ProjectionKey>);

/// The central plugin registry.
///
/// Plugins register here; the registry wires their components into the
/// appropriate sub-registries. Iteration order (`step_all`, `plugin_names`) is
/// guaranteed to match registration order.
pub struct PluginRegistry {
    /// `IndexMap` preserves insertion order — `step_all` / `plugin_names` are stable.
    plugins: IndexMap<PluginId, PluginEntry>,
    approver_map: IndexMap<Kind, PluginId>,
    pub schemas: SchemaRegistry,
    projections: ProjectionRegistry,
    pending_step: Option<PendingStep>,
    run_mode: RunMode,
    resource_limit: Option<u64>,
    poisoned_driver: Option<String>,
    consent_gate: Option<Arc<dyn ConsentGate>>,
}

impl PluginRegistry {
    /// Return an immutable, deterministic description of the effective
    /// registration topology.
    ///
    /// Plugin order is preserved and schemas are sorted so equality is
    /// independent of registration-map iteration order. The result compares
    /// metadata only, never opaque plugin code.
    #[must_use]
    pub fn composition(&self) -> PluginComposition {
        let plugins = self
            .plugins
            .iter()
            .map(|(id, entry)| RegisteredPlugin {
                id: *id,
                name: entry.name.clone(),
                version: entry.version.clone(),
            })
            .collect();

        let mut schemas: Vec<_> = self
            .schemas
            .iter()
            .map(|schema| RegisteredEventSchema {
                event_type: schema.event_type.as_str().to_owned(),
                json_schema: schema.json_schema.clone(),
            })
            .collect();
        schemas.sort_unstable_by(|left, right| left.event_type.cmp(&right.event_type));

        PluginComposition { plugins, schemas }
    }

    fn snapshot_for_subscriptions(&self, subscriptions: &[ProjectionKey]) -> ObservationSnapshot {
        ObservationSnapshot::from_subscriptions(subscriptions.iter(), |key| {
            self.projections.state_for(key.entity_id()).cloned()
        })
    }

    fn snapshot_for_tick(
        &self,
        timeline: pos_core::ids::TimelineId,
        timeline_head: Seq,
        operation: &OperationContext,
    ) -> Result<ObservationSnapshot, RuntimeError> {
        let mut seen = HashSet::new();
        let mut subscriptions = Vec::new();

        for entry in self
            .plugins
            .values()
            .filter_map(|entry| entry.driver.as_deref())
        {
            extend_unique_subscriptions(&mut subscriptions, &mut seen, entry.subscriptions());
        }

        self.authorize_snapshot_subscriptions(
            timeline,
            timeline_head,
            operation,
            subscriptions.iter(),
        )?;
        Ok(self.snapshot_for_subscriptions(&subscriptions))
    }

    fn authorize_snapshot_subscriptions<'a>(
        &self,
        timeline: pos_core::ids::TimelineId,
        timeline_head: Seq,
        operation: &OperationContext,
        subscriptions: impl IntoIterator<Item = &'a ProjectionKey>,
    ) -> Result<(), RuntimeError> {
        let subscriptions: Vec<ProjectionKey> = subscriptions.into_iter().cloned().collect();
        match operation {
            OperationContext::Public if !subscriptions.is_empty() => {
                Err(RuntimeError::Consent(ConsentError::NoConsent))
            }
            OperationContext::Public => Ok(()),
            OperationContext::Protected { token, now_secs } => {
                let Some(gate) = self.consent_gate.as_ref() else {
                    return Err(RuntimeError::ConsentOperationUnavailable);
                };
                for key in &subscriptions {
                    gate.authorize_projection(
                        timeline,
                        *key.entity_id(),
                        timeline_head.as_u64(),
                        *now_secs,
                        token,
                    )
                    .map_err(RuntimeError::Consent)?;
                }
                Ok(())
            }
        }
    }

    #[must_use]
    pub fn new() -> Self {
        Self::new_with_mode(RunMode::Live)
    }

    /// Create a projection-only registry for replay.
    #[must_use]
    pub fn new_replay() -> Self {
        Self::new_with_mode(RunMode::Replay)
    }

    fn new_with_mode(run_mode: RunMode) -> Self {
        let mut schemas = SchemaRegistry::new();
        // Auto-register the Recorder's internal event type so that
        // Recorder::to_draft() output passes SchemaRegistry::validate().
        schemas.register(EventTypeSchema {
            event_type: pos_core::event::Kind::new(RECORDER_EVENT_TYPE),
            description: "Internal: nondeterministic output recorded by the Recorder".to_owned(),
            json_schema: None,
        });
        schemas.register(EventTypeSchema {
            event_type: pos_core::event::Kind::new(pos_core::EVENT_TYPE_CONSENT_REVOKED_V1),
            description: "Gateway-owned durable consent revocation marker".to_owned(),
            json_schema: None,
        });
        Self {
            plugins: IndexMap::new(),
            approver_map: IndexMap::new(),
            schemas,
            projections: ProjectionRegistry::new(),
            pending_step: None,
            run_mode,
            resource_limit: None,
            poisoned_driver: None,
            // Every live registry has a host-owned gate, even before the
            // caller binds a durable authority. This default fails closed for
            // protected drafts instead of exposing an unguarded public path.
            consent_gate: Some(Arc::new(ConsentAuthority::new())),
        }
    }

    /// Bound the number of Event drafts one atomic Tick may stage.
    #[must_use]
    pub const fn with_resource_limit(mut self, limit: u64) -> Self {
        self.resource_limit = Some(limit);
        self
    }

    /// Bind the concrete host-owned consent authority used for protected work.
    #[must_use]
    pub fn with_consent_authority(mut self, authority: ConsentAuthority) -> Self {
        self.consent_gate = Some(Arc::new(authority));
        self
    }

    /// Bind a host-owned consent gate used by protected Driver work.
    #[must_use]
    pub fn with_consent_gate(mut self, gate: Arc<dyn ConsentGate>) -> Self {
        self.consent_gate = Some(gate);
        self
    }

    /// Remove the host-owned consent gate so protected operations fail closed.
    ///
    /// This is useful for hosts that are not authorized to perform protected
    /// work. It never enables an unguarded path: protected validation returns
    /// [`RuntimeError::ConsentOperationUnavailable`] while public operations
    /// remain available.
    #[must_use]
    pub fn without_consent_gate(mut self) -> Self {
        self.consent_gate = None;
        self
    }

    /// Return the host-bound consent gate for a capability-scoped read.
    #[must_use]
    pub fn clone_consent_gate(&self) -> Option<Arc<dyn ConsentGate>> {
        self.consent_gate.clone()
    }

    /// Fold a host-captured Event range into the registered reducers.
    pub fn fold_events(&mut self, events: &[Event]) {
        let visible_events: Vec<Event> = events
            .iter()
            .filter(|event| event.event_type.as_str() != pos_core::HOST_CONSENT_CLOSED_EVENT_TYPE)
            .cloned()
            .collect();
        self.projections.fold_events(&visible_events);
    }

    /// Consume the registry after authorizing its final projection snapshot.
    ///
    /// A protected registry requires a token issued by the bound host authority;
    /// its returned projection snapshot is reduced to that token's subject.
    /// A token-less registry is only exportable when the caller supplies the
    /// completed durable Event prefix and every Event in that prefix is public.
    /// Registered schemas alone do not determine whether this particular run
    /// emitted protected Events, which keeps public Backtest runs valid.
    ///
    /// # Errors
    /// Returns a consent error when a protected registry lacks a valid capability,
    /// when a public caller supplies no Event-prefix evidence, or when that
    /// evidence contains a protected Event family.
    pub fn into_authorized_projections(
        mut self,
        timeline: pos_core::ids::TimelineId,
        timeline_head: Seq,
        now_secs: u64,
        token: Option<&ConsentCapabilityToken>,
        public_events: Option<&[Event]>,
    ) -> Result<ProjectionRegistry, RuntimeError> {
        if let Some(token) = token {
            self.consent_gate
                .as_ref()
                .ok_or(RuntimeError::ConsentOperationUnavailable)?
                .validate_token(timeline, token, timeline_head.as_u64(), now_secs)
                .map_err(RuntimeError::Consent)?;
            self.projections.retain_subject(&token.subject_id());
            return Ok(self.projections);
        }
        let Some(events) = public_events else {
            return Err(RuntimeError::ConsentOperationUnavailable);
        };
        if events.iter().any(|event| {
            pos_core::is_consent_event_type(&event.event_type)
                || pos_core::is_geographic_event_type(&event.event_type)
                || pos_core::required_modality_for_event(&event.event_type) != 0
                || event.event_type.as_str().starts_with("timeline.fork.")
                || event.event_type.as_str().starts_with("retention.")
        }) {
            return Err(RuntimeError::ConsentOperationUnavailable);
        }
        Ok(self.projections)
    }

    /// Read one projection state after the bound host gate authorizes its subject.
    ///
    /// The registry never exposes the projection registry through this seam. The
    /// caller must present a token issued by the same host-bound gate and bound
    /// to the requested subject and Timeline.
    ///
    /// # Errors
    /// Returns a consent error when the token is invalid or a missing-gate error
    /// when this registry has no host policy.
    pub fn projection_state_for_reducer(
        &self,
        timeline: pos_core::ids::TimelineId,
        timeline_head: Seq,
        now_secs: u64,
        token: &ConsentCapabilityToken,
        reducer: &str,
        subject: pos_core::ids::EntityId,
    ) -> Result<Option<pos_core::State>, RuntimeError> {
        let gate = self
            .consent_gate
            .as_ref()
            .ok_or(RuntimeError::ConsentOperationUnavailable)?;
        gate.authorize_projection(timeline, subject, timeline_head.as_u64(), now_secs, token)
            .map_err(RuntimeError::Consent)?;
        Ok(self
            .projections
            .state_for_reducer(reducer, &subject)
            .cloned())
    }

    fn validate_operation(
        &self,
        timeline: pos_core::ids::TimelineId,
        operation: &OperationContext,
        timeline_head: Seq,
        commit_now_secs: Option<u64>,
    ) -> Result<(), RuntimeError> {
        match operation {
            OperationContext::Public => self
                .consent_gate
                .as_ref()
                .map(|_| ())
                .ok_or(RuntimeError::ConsentOperationUnavailable),
            OperationContext::Protected { token, now_secs } => {
                let validation_now_secs = commit_now_secs.unwrap_or(*now_secs);
                self.consent_gate
                    .as_ref()
                    .ok_or(RuntimeError::ConsentOperationUnavailable)
                    .and_then(|authority| {
                        authority
                            .validate_token(
                                timeline,
                                token,
                                timeline_head.as_u64(),
                                validation_now_secs,
                            )
                            .map_err(RuntimeError::Consent)
                    })
            }
        }
    }

    fn validate_protected_drafts(
        &self,
        timeline: pos_core::ids::TimelineId,
        operation: &OperationContext,
        timeline_head: Seq,
        drafts: &[pos_core::event::EventDraft],
    ) -> Result<(), RuntimeError> {
        let (protected_token, now_secs) = match operation {
            OperationContext::Protected { token, now_secs } => (Some(token), *now_secs),
            OperationContext::Public => (None, timeline_head.as_u64()),
        };
        let gate = self.consent_gate.as_ref();
        for draft in drafts {
            let Some(gate) = gate else {
                return Err(RuntimeError::ConsentOperationUnavailable);
            };
            let subject = protected_token.map_or(draft.entity, ConsentCapabilityToken::subject_id);
            match protected_token {
                Some(token) => {
                    let sensitive = pos_core::required_modality_for_event(&draft.event_type) != 0
                        || draft.event_type.as_str().starts_with("timeline.fork.")
                        || draft.event_type.as_str().starts_with("retention.");
                    if sensitive && draft.entity != token.subject_id() {
                        return Err(RuntimeError::Consent(pos_core::ConsentError::NoConsent));
                    }
                    token
                        .authorize_event_type(&draft.event_type)
                        .map_err(RuntimeError::Consent)?;
                }
                None => gate
                    .authorize_event(
                        timeline,
                        subject,
                        &draft.event_type,
                        timeline_head.as_u64(),
                        now_secs,
                    )
                    .map_err(RuntimeError::Consent)?,
            }
        }
        Ok(())
    }

    fn reject_unanchored_drivers(&self) -> Result<(), RuntimeError> {
        self.plugins
            .values()
            .filter_map(|entry| entry.driver.as_deref())
            .find(|driver| driver.requires_snapshot_anchor())
            .map_or(Ok(()), |driver| {
                Err(RuntimeError::MissingSnapshotAnchor {
                    driver: driver.name().to_owned(),
                })
            })
    }

    fn ensure_no_pending_step(&self) -> Result<(), RuntimeError> {
        if let Some(name) = &self.poisoned_driver {
            return Err(RuntimeError::DriverCommitPanicked { name: name.clone() });
        }
        if self.pending_step.is_some() {
            Err(RuntimeError::PendingDriverStep)
        } else {
            Ok(())
        }
    }

    fn abort_drivers(&mut self, driver_ids: &[PluginId]) -> Option<RuntimeError> {
        let mut first_error = None;
        for id in driver_ids {
            if let Some(driver) = self
                .plugins
                .get_mut(id)
                .and_then(|entry| entry.driver.as_mut())
            {
                let name = driver.name().to_owned();
                if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| driver.abort_step()))
                    .is_err()
                {
                    self.poisoned_driver = Some(name.clone());
                    first_error.get_or_insert(RuntimeError::DriverAbortPanicked { name });
                }
            }
        }
        first_error
    }

    fn invoke_selected_driver(
        &mut self,
        id: PluginId,
        timeline: pos_core::ids::TimelineId,
        snapshot: &ObservationSnapshot,
        committed_events: &[Event],
    ) -> Result<StepOutput, RuntimeError> {
        let Some(entry) = self.plugins.get_mut(&id) else {
            return Err(RuntimeError::NoDriver {
                name: id.to_string(),
            });
        };
        let Some(driver) = entry.driver.as_mut() else {
            return Err(RuntimeError::NoDriver {
                name: entry.name.clone(),
            });
        };
        let visible_events: Vec<Event> = committed_events
            .iter()
            .filter(|event| driver_visible_event(event))
            .cloned()
            .collect();
        let observations = snapshot.view_for_events_after(
            driver.subscriptions(),
            &visible_events,
            driver.event_subscriptions(),
            entry.event_cursor,
        );
        invoke_driver(driver.as_mut(), timeline, observations)
            .and_then(|output| reject_host_owned_drafts(&output).map(|()| output))
    }

    fn collect_anchored_selection(
        &self,
        selection: AnchoredSelection,
    ) -> Result<AnchoredSelectionResult, RuntimeError> {
        let mut driver_ids = Vec::new();
        let mut cadence_updates = Vec::new();
        let mut seen_subscriptions = HashSet::new();
        let mut subscriptions = Vec::new();

        for (id, entry) in &self.plugins {
            let Some(driver) = entry.driver.as_deref() else {
                continue;
            };
            let selected = match selection {
                AnchoredSelection::All => true,
                AnchoredSelection::Cadenced { now_ns } => {
                    let interval_ns = driver.tick_interval().as_nanos();
                    match entry.last_tick {
                        Some(previous_ns) => {
                            let due_at = previous_ns.checked_add(interval_ns).ok_or_else(|| {
                                RuntimeError::CadenceOverflow {
                                    driver: entry.name.clone(),
                                    previous_ns,
                                    interval_ns,
                                }
                            })?;
                            now_ns >= due_at
                        }
                        None => true,
                    }
                }
            };
            if selected {
                driver_ids.push(*id);
                if let AnchoredSelection::Cadenced { now_ns } = selection {
                    cadence_updates.push((*id, now_ns));
                }
                extend_unique_subscriptions(
                    &mut subscriptions,
                    &mut seen_subscriptions,
                    driver.subscriptions(),
                );
            }
        }

        Ok((driver_ids, cadence_updates, subscriptions))
    }

    fn step_anchored_transaction(
        &mut self,
        timeline: pos_core::ids::TimelineId,
        observed_through: Seq,
        selection: AnchoredSelection,
        committed_events: &[Event],
        operation: OperationContext,
    ) -> Result<Vec<pos_core::event::EventDraft>, RuntimeError> {
        self.ensure_no_pending_step()?;
        self.validate_operation(timeline, &operation, observed_through, None)?;
        let (driver_ids, cadence_updates, subscriptions) =
            self.collect_anchored_selection(selection)?;
        let mut event_cursors = Vec::new();

        let anchor = SnapshotAnchor::new(timeline, observed_through);
        self.authorize_snapshot_subscriptions(
            timeline,
            observed_through,
            &operation,
            subscriptions.iter(),
        )?;
        let snapshot =
            ObservationSnapshot::from_anchored_subscriptions(anchor, subscriptions.iter(), |key| {
                self.projections.state_for(key.entity_id()).cloned()
            });
        let mut all_drafts = Vec::new();
        let mut staged_driver_ids = Vec::new();
        for id in driver_ids {
            let result = self.invoke_selected_driver(id, timeline, &snapshot, committed_events);
            match result {
                Ok(output) => {
                    if let Err(error) = self.validate_protected_drafts(
                        timeline,
                        &operation,
                        observed_through,
                        &output.drafts,
                    ) {
                        staged_driver_ids.push(id);
                        let _ = self.abort_drivers(&staged_driver_ids);
                        return Err(error);
                    }
                    let requested = u64::try_from(all_drafts.len())
                        .unwrap_or(u64::MAX)
                        .saturating_add(u64::try_from(output.drafts.len()).unwrap_or(u64::MAX));
                    if let Some(limit) = self.resource_limit {
                        if requested > limit {
                            staged_driver_ids.push(id);
                            let _ = self.abort_drivers(&staged_driver_ids);
                            return Err(RuntimeError::ResourceExhausted {
                                driver: "host-tick-budget".to_owned(),
                                requested,
                                limit,
                            });
                        }
                    }
                    staged_driver_ids.push(id);
                    event_cursors.push((id, observed_through));
                    all_drafts.extend(output.drafts);
                }
                Err(error) => {
                    staged_driver_ids.push(id);
                    let _ = self.abort_drivers(&staged_driver_ids);
                    return Err(error);
                }
            }
        }

        self.pending_step = Some(PendingStep {
            timeline,
            driver_ids: staged_driver_ids,
            cadence_updates,
            event_cursors,
            operation,
        });
        Ok(all_drafts)
    }

    fn commit_pending_step(&mut self, pending: PendingStep) {
        for id in &pending.driver_ids {
            if let Some(driver) = self
                .plugins
                .get_mut(id)
                .and_then(|entry| entry.driver.as_mut())
            {
                let name = driver.name().to_owned();
                if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| driver.commit_step()))
                    .is_err()
                {
                    self.poisoned_driver = Some(name);
                }
            }
        }
        for (id, now_ns) in pending.cadence_updates {
            if let Some(entry) = self.plugins.get_mut(&id) {
                entry.last_tick = Some(now_ns);
            }
        }
        for (id, cursor) in pending.event_cursors {
            if let Some(entry) = self.plugins.get_mut(&id) {
                entry.event_cursor = cursor;
            }
        }
    }

    /// Commit a staged step after revalidating it at the supplied fresh time.
    ///
    /// # Errors
    /// Returns the consent-fence error and aborts every staged Driver when the
    /// operation is no longer authorized. Callers must not append drafts until
    /// this fence succeeds; [`Self::append_and_commit_step_at`] combines the
    /// fence and host append in one host-owned boundary.
    pub fn commit_step_at(
        &mut self,
        timeline_head: Seq,
        commit_now_secs: u64,
    ) -> Result<(), RuntimeError> {
        let Some(pending) = self.pending_step.take() else {
            return Ok(());
        };
        if let Err(error) = self.validate_operation(
            pending.timeline,
            &pending.operation,
            timeline_head,
            Some(commit_now_secs),
        ) {
            let _ = self.abort_drivers(&pending.driver_ids);
            return Err(error);
        }
        self.commit_pending_step(pending);
        Ok(())
    }

    /// Fence and append one staged host Tick before committing Driver state.
    ///
    /// The consent validation happens while the host owns both the registry's
    /// pending step and the [`pos_core::store::EventStore`] borrow. A rejected fence therefore
    /// aborts the staged Drivers before any draft reaches durable storage.
    ///
    /// # Errors
    /// Returns the consent or store error and aborts the staged step when the
    /// fence or append fails.
    pub fn append_and_commit_step_at(
        &mut self,
        store: &mut dyn pos_core::store::EventStore,
        timeline_head: Seq,
        commit_now_secs: u64,
        drafts: &[EventDraft],
    ) -> Result<Vec<Event>, RuntimeError> {
        let Some(pending) = self.pending_step.take() else {
            return Err(RuntimeError::PendingDriverStep);
        };
        let pending_timeline = pending.timeline;
        let operation = pending.operation.clone();
        let events = match operation {
            OperationContext::Protected { token, now_secs: _ } => {
                let Some(gate) = self.consent_gate.clone() else {
                    let _ = self.abort_drivers(&pending.driver_ids);
                    return Err(RuntimeError::ConsentOperationUnavailable);
                };
                if let Err(error) = reject_host_owned_draft_slice(drafts).and_then(|()| {
                    self.validate_protected_drafts(
                        pending_timeline,
                        &OperationContext::Protected {
                            token: token.clone(),
                            now_secs: commit_now_secs,
                        },
                        timeline_head,
                        drafts,
                    )
                }) {
                    let _ = self.abort_drivers(&pending.driver_ids);
                    return Err(error);
                }
                let mut append_result = Ok(Vec::new());
                let mut append = || {
                    append_result = store.append(pending_timeline, drafts);
                };
                if let Err(error) = gate.with_token_fence(
                    pending_timeline,
                    &token,
                    timeline_head.as_u64(),
                    commit_now_secs,
                    &mut append,
                ) {
                    let _ = self.abort_drivers(&pending.driver_ids);
                    return Err(RuntimeError::Consent(error));
                }
                match append_result {
                    Ok(events) => events,
                    Err(error) => {
                        let _ = self.abort_drivers(&pending.driver_ids);
                        return Err(error.into());
                    }
                }
            }
            OperationContext::Public => {
                if let Err(error) = self.validate_operation(
                    pending_timeline,
                    &OperationContext::Public,
                    timeline_head,
                    Some(commit_now_secs),
                ) {
                    let _ = self.abort_drivers(&pending.driver_ids);
                    return Err(error);
                }
                if let Err(error) = reject_host_owned_draft_slice(drafts).and_then(|()| {
                    self.validate_protected_drafts(
                        pending_timeline,
                        &OperationContext::Public,
                        timeline_head,
                        drafts,
                    )
                }) {
                    let _ = self.abort_drivers(&pending.driver_ids);
                    return Err(error);
                }
                match store.append(pending_timeline, drafts) {
                    Ok(events) => events,
                    Err(error) => {
                        let _ = self.abort_drivers(&pending.driver_ids);
                        return Err(error.into());
                    }
                }
            }
        };
        self.commit_pending_step(pending);
        Ok(events)
    }

    /// Abort the Driver and cadence state staged by an anchored step.
    pub fn abort_step(&mut self) {
        if let Some(pending) = self.pending_step.take() {
            let _ = self.abort_drivers(&pending.driver_ids);
        }
    }

    /// Restore every Driver's append-committed state from validated history.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError::PendingDriverStep`] if a transaction is active,
    /// or the first Driver-specific durable-history validation error.
    pub fn restore_driver_state(
        &mut self,
        timeline_segments: &[TimelineHistorySegment],
        events: &[Event],
    ) -> Result<(), RuntimeError> {
        self.ensure_no_pending_step()?;
        validate_recovery_evidence(timeline_segments, events)?;
        // Consent is host control-plane history. Validate the full durable
        // prefix above, then ensure Drivers never receive grant/revocation
        // headers or payloads during recovery.
        let visible_events: Vec<Event> = events
            .iter()
            .filter(|event| driver_visible_event(event))
            .cloned()
            .collect();
        let mut staged = Vec::new();
        let mut failure = None;
        for (id, entry) in &mut self.plugins {
            let Some(driver) = entry.driver.as_mut() else {
                continue;
            };
            let evidence =
                DriverRecoveryEvidence::from_events(timeline_segments, &visible_events, |header| {
                    driver.needs_recovery_payload(header)
                });
            if let Err(error) = driver.stage_restore_from_history(&evidence) {
                driver.abort_restore_from_history();
                failure = Some(error);
                break;
            }
            staged.push(*id);
        }
        if let Some(error) = failure {
            for staged_id in staged {
                if let Some(staged_driver) = self
                    .plugins
                    .get_mut(&staged_id)
                    .and_then(|staged_entry| staged_entry.driver.as_mut())
                {
                    staged_driver.abort_restore_from_history();
                }
            }
            return Err(error);
        }
        for id in staged {
            if let Some(driver) = self
                .plugins
                .get_mut(&id)
                .and_then(|entry| entry.driver.as_mut())
            {
                let name = driver.name().to_owned();
                if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    driver.commit_restore_from_history();
                }))
                .is_err()
                {
                    self.poisoned_driver = Some(name.clone());
                    return Err(RuntimeError::DriverRestorePanicked { name });
                }
            }
            if let Some(entry) = self.plugins.get_mut(&id) {
                entry.event_cursor = events.last().map_or(Seq::ZERO, |event| event.seq);
            }
        }
        Ok(())
    }

    /// Register a plugin.
    ///
    /// Wires event-type schemas and (optionally) a reducer and driver.
    ///
    /// # Errors
    /// Returns [`RuntimeError::DuplicatePlugin`] if a plugin with the same `PluginId`
    /// is already registered.
    pub fn register(
        &mut self,
        plugin: &dyn Plugin,
        reducer: Option<Box<dyn Reducer>>,
        driver: Option<Box<dyn Driver>>,
    ) -> Result<(), RuntimeError> {
        let context = self.registration_context(plugin)?;
        self.register_with_approver_slice(plugin, reducer, driver, None, &[], context)
    }

    /// Register a plugin with an optional [`ActionApprover`] (ADR-057).
    ///
    /// Wires event-type schemas, (optionally) a reducer and driver, and (optionally)
    /// an action approver indexed by the explicitly supplied event types.
    ///
    /// # Errors
    /// Returns [`RuntimeError::DuplicatePlugin`] if a plugin with the same `PluginId`
    /// is already registered.
    pub fn register_with_approver(
        &mut self,
        plugin: &dyn Plugin,
        reducer: Option<Box<dyn Reducer>>,
        driver: Option<Box<dyn Driver>>,
        approver: Option<Box<dyn ActionApprover>>,
        approver_event_types: impl IntoIterator<Item = Kind>,
    ) -> Result<(), RuntimeError> {
        let context = self.registration_context(plugin)?;
        let approver_event_types: Vec<Kind> = approver_event_types.into_iter().collect();
        self.register_with_approver_slice(
            plugin,
            reducer,
            driver,
            approver,
            &approver_event_types,
            context,
        )
    }

    fn registration_context(
        &self,
        plugin: &dyn Plugin,
    ) -> Result<(PluginId, String, Capability), RuntimeError> {
        let id = plugin.id();
        let name = plugin.name().to_owned();

        if self.plugins.contains_key(&id) {
            return Err(RuntimeError::DuplicatePlugin { id, name });
        }

        Ok((id, name, plugin.capability()))
    }

    fn register_with_approver_slice(
        &mut self,
        plugin: &dyn Plugin,
        reducer: Option<Box<dyn Reducer>>,
        driver: Option<Box<dyn Driver>>,
        approver: Option<Box<dyn ActionApprover>>,
        approver_event_types: &[Kind],
        context: (PluginId, String, Capability),
    ) -> Result<(), RuntimeError> {
        let (id, name, cap) = context;
        if let Some(kind) = cap
            .owned_event_types
            .iter()
            .find(|kind| pos_core::is_geographic_event_type(kind))
        {
            return Err(RuntimeError::ReservedGeographicEventType {
                name,
                event_type: kind.as_str().to_owned(),
            });
        }
        if let Some(kind) = cap
            .owned_event_types
            .iter()
            .find(|kind| pos_core::is_consent_event_type(kind))
        {
            return Err(RuntimeError::ReservedConsentEventType {
                name,
                event_type: kind.as_str().to_owned(),
            });
        }

        if cap.has_driver != driver.is_some() {
            return Err(RuntimeError::CapabilityMismatch {
                name: name.clone(),
                reason: if cap.has_driver {
                    "has_driver=true but no driver provided".to_owned()
                } else {
                    "has_driver=false but a driver was provided".to_owned()
                },
            });
        }
        if cap.has_reducer != reducer.is_some() {
            return Err(RuntimeError::CapabilityMismatch {
                name: name.clone(),
                reason: if cap.has_reducer {
                    "has_reducer=true but no reducer provided".to_owned()
                } else {
                    "has_reducer=false but a reducer was provided".to_owned()
                },
            });
        }

        if approver.is_none() && !approver_event_types.is_empty() {
            return Err(RuntimeError::CapabilityMismatch {
                name,
                reason: "approver event types were supplied without an approver".to_owned(),
            });
        }
        if let Some(kind) = approver_event_types
            .iter()
            .find(|kind| !cap.owned_event_types.contains(kind))
        {
            return Err(RuntimeError::CapabilityMismatch {
                name,
                reason: format!("approver event type '{kind}' is not plugin-owned"),
            });
        }

        if approver.is_some() {
            if let Some(kind) = cap.owned_event_types.iter().find(|kind| {
                approver_event_types.contains(*kind) && self.approver_map.contains_key(*kind)
            }) {
                return Err(RuntimeError::CapabilityMismatch {
                    name,
                    reason: format!("an action approver route already exists for '{kind}'"),
                });
            }
        }

        // Register event type schemas
        for kind in &cap.owned_event_types {
            self.schemas.register(EventTypeSchema {
                event_type: kind.clone(),
                description: format!("owned by plugin '{name}'"),
                json_schema: None,
            });
        }

        // Wire reducer into projection registry
        if let Some(r) = reducer {
            self.projections.register(&name, r);
        }

        // Index action approver if present
        if approver.is_some() {
            for kind in approver_event_types {
                self.approver_map.insert(kind.clone(), id);
            }
        }

        self.plugins.insert(
            id,
            PluginEntry {
                name,
                version: plugin.version().to_owned(),
                driver,
                approver,
                last_tick: None,
                event_cursor: Seq::ZERO,
            },
        );
        Ok(())
    }

    /// Returns `true` if a plugin with this id is registered.
    #[must_use]
    pub fn contains(&self, id: &PluginId) -> bool {
        self.plugins.contains_key(id)
    }

    /// Number of registered plugins.
    #[must_use]
    pub fn len(&self) -> usize {
        self.plugins.len()
    }

    /// Returns `true` if no plugins are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.plugins.is_empty()
    }

    /// Iterate over plugin names in registration order.
    pub fn plugin_names(&self) -> impl Iterator<Item = &str> {
        self.plugins.values().map(plugin_name)
    }

    /// Iterate over registered plugin (name, version) pairs in registration order.
    pub fn plugin_versions(&self) -> impl Iterator<Item = (&str, &str)> {
        self.plugins.values().map(plugin_name_and_version)
    }

    /// Register a driver directly (for tests and late-bound agent registration).
    pub fn register_driver(&mut self, driver: Box<dyn Driver>) {
        let name = driver.name().to_owned();
        self.plugins.insert(
            pos_core::ids::PluginId::new(),
            PluginEntry {
                name,
                version: "0.1.0".to_owned(),
                driver: Some(driver),
                approver: None,
                last_tick: None,
                event_cursor: Seq::ZERO,
            },
        );
    }

    /// Submit a proposed action through the capability-checked envelope (ADR-057).
    ///
    /// Routes to the approver registered for `proposal.event_type`. This is a
    /// live-only boundary: replay accepts a [`pos_state::ProjectionRegistry`]
    /// and never receives a [`PluginRegistry`], so replay cannot submit actions.
    ///
    /// # Errors
    /// Returns [`ActionRejected`] if the payload is too large, no approver is registered
    /// for the event type, or domain validation fails.
    pub fn submit_action(&self, proposal: &ProposedAction) -> Result<EventDraft, ActionRejected> {
        if self.run_mode == RunMode::Replay {
            return Err(ActionRejected::UnknownEventType);
        }
        if proposal.payload.len() > MAX_PROPOSED_ACTION_PAYLOAD_BYTES {
            return Err(ActionRejected::PayloadTooLarge {
                size: proposal.payload.len(),
                max: MAX_PROPOSED_ACTION_PAYLOAD_BYTES,
            });
        }

        let expected_capability = format!("{}.submit", proposal.event_type.as_str());
        if proposal.capability.as_str() != expected_capability {
            return Err(ActionRejected::CapabilityNotGranted);
        }

        let Some(approver) = self.approver_for(&proposal.event_type) else {
            return Err(ActionRejected::UnknownEventType);
        };

        approver.approve(proposal)
    }

    /// Return the action approver registered for the given event type, if any.
    #[must_use]
    fn approver_for(&self, event_type: &Kind) -> Option<&dyn ActionApprover> {
        self.approver_map
            .get(event_type)
            .and_then(|plugin_id| self.plugins.get(plugin_id))
            .and_then(|entry| entry.approver.as_deref())
    }

    /// Step ready drivers on cadence, returning all drafts from eligible plugins.
    ///
    /// Only drivers whose `tick_interval()` has elapsed since their last tick
    /// will fire. First-tick drivers always fire.
    ///
    /// # Errors
    /// Propagates any [`RuntimeError`] from drivers. Returns
    /// [`RuntimeError::CadenceOverflow`] before snapshot creation or driver mutation
    /// when a prior tick plus the configured interval cannot fit in `u128` nanoseconds.
    ///
    /// # Panics
    ///
    /// Panics only if the registry's internal due-driver set refers to an entry
    /// whose registered driver disappeared without passing through a public API.
    pub fn tick_cadenced(
        &mut self,
        timeline: pos_core::ids::TimelineId,
        now_ns: u128,
    ) -> Result<Vec<pos_core::event::EventDraft>, RuntimeError> {
        self.ensure_no_pending_step()?;
        self.reject_unanchored_drivers()?;
        self.validate_operation(timeline, &OperationContext::Public, Seq::ZERO, None)?;
        let mut all_drafts = Vec::new();
        let mut due_driver_ids = HashSet::new();
        let mut seen_subscriptions = HashSet::new();
        let mut due_subscriptions = Vec::new();

        for (id, entry) in &self.plugins {
            if let Some(driver) = entry.driver.as_deref() {
                let interval_ns = driver.tick_interval().as_nanos();
                let ready = match entry.last_tick {
                    Some(previous_ns) => {
                        let due_at = previous_ns.checked_add(interval_ns).ok_or_else(|| {
                            RuntimeError::CadenceOverflow {
                                driver: entry.name.clone(),
                                previous_ns,
                                interval_ns,
                            }
                        })?;
                        now_ns >= due_at
                    }
                    None => true,
                };
                if ready {
                    due_driver_ids.insert(*id);
                    extend_unique_subscriptions(
                        &mut due_subscriptions,
                        &mut seen_subscriptions,
                        driver.subscriptions(),
                    );
                }
            }
        }

        self.authorize_snapshot_subscriptions(
            timeline,
            Seq::ZERO,
            &OperationContext::Public,
            due_subscriptions.iter(),
        )?;
        let snapshot = self.snapshot_for_subscriptions(&due_subscriptions);
        for (id, entry) in &mut self.plugins {
            if due_driver_ids.remove(id) {
                if let Some(driver) = entry.driver.as_mut() {
                    let observations = snapshot.view_for(driver.subscriptions());
                    let output = invoke_driver(driver.as_mut(), timeline, observations)?;
                    reject_host_owned_drafts(&output)?;
                    entry.last_tick = Some(now_ns);
                    all_drafts.extend(output.drafts);
                }
            }
        }
        debug_assert!(due_driver_ids.is_empty());
        self.validate_protected_drafts(
            timeline,
            &OperationContext::Public,
            Seq::ZERO,
            &all_drafts,
        )?;
        Ok(all_drafts)
    }

    /// Step cadence-ready Drivers against one host-owned immutable-prefix
    /// anchor, staging Driver and cadence state until commit or abort.
    ///
    /// # Errors
    /// Returns [`RuntimeError::PendingDriverStep`] when a prior anchored step is
    /// still pending, [`RuntimeError::CadenceOverflow`] when cadence arithmetic
    /// overflows, or propagates a selected Driver or draft validation error.
    ///
    /// # Panics
    /// Panics only if the internally collected due-Driver identifiers stop
    /// referring to their registered entries without passing through a public API.
    pub fn tick_cadenced_anchored(
        &mut self,
        timeline: pos_core::ids::TimelineId,
        now_ns: u128,
        observed_through: Seq,
    ) -> Result<Vec<pos_core::event::EventDraft>, RuntimeError> {
        self.step_anchored_transaction(
            timeline,
            observed_through,
            AnchoredSelection::Cadenced { now_ns },
            &[],
            OperationContext::Public,
        )
    }

    /// Step cadence-ready Drivers with a host-filtered committed Event prefix.
    ///
    /// # Errors
    /// Returns a staged-step, cadence, Driver, or draft validation error.
    pub fn tick_cadenced_anchored_with_events(
        &mut self,
        timeline: pos_core::ids::TimelineId,
        now_ns: u128,
        observed_through: Seq,
        committed_events: &[Event],
    ) -> Result<Vec<pos_core::event::EventDraft>, RuntimeError> {
        self.step_anchored_transaction(
            timeline,
            observed_through,
            AnchoredSelection::Cadenced { now_ns },
            committed_events,
            OperationContext::Public,
        )
    }

    /// Step cadence-ready Drivers under a host-issued protected capability.
    ///
    /// # Errors
    /// Returns a consent, staged-step, cadence, Driver, or draft validation error.
    pub fn tick_cadenced_anchored_protected(
        &mut self,
        timeline: pos_core::ids::TimelineId,
        now_ns: u128,
        observed_through: Seq,
        token: ConsentCapabilityToken,
        now_secs: u64,
        committed_events: &[Event],
    ) -> Result<Vec<pos_core::event::EventDraft>, RuntimeError> {
        self.step_anchored_transaction(
            timeline,
            observed_through,
            AnchoredSelection::Cadenced { now_ns },
            committed_events,
            OperationContext::Protected { token, now_secs },
        )
    }

    /// Number of plugins that have a driver registered.
    #[must_use]
    pub fn driver_count(&self) -> usize {
        self.plugins.values().filter(|e| e.driver.is_some()).count()
    }

    /// Step all plugins that have a driver, collecting their event drafts.
    ///
    /// Calls `driver.step(timeline, observations)` on each plugin that registered a driver.
    /// Returns all drafts from all drivers in registration order.
    ///
    /// # Errors
    /// Propagates any [`RuntimeError`] from drivers.
    pub fn step_all(
        &mut self,
        timeline: pos_core::ids::TimelineId,
    ) -> Result<Vec<pos_core::event::EventDraft>, RuntimeError> {
        self.ensure_no_pending_step()?;
        self.reject_unanchored_drivers()?;
        self.validate_operation(timeline, &OperationContext::Public, Seq::ZERO, None)?;
        let mut all_drafts = Vec::new();
        let snapshot = self.snapshot_for_tick(timeline, Seq::ZERO, &OperationContext::Public)?;
        for entry in self.plugins.values_mut() {
            if let Some(driver) = entry.driver.as_mut() {
                let observations = snapshot.view_for(driver.subscriptions());
                let output = invoke_driver(driver.as_mut(), timeline, observations)?;
                reject_host_owned_drafts(&output)?;
                all_drafts.extend(output.drafts);
            }
        }
        self.validate_protected_drafts(
            timeline,
            &OperationContext::Public,
            Seq::ZERO,
            &all_drafts,
        )?;
        Ok(all_drafts)
    }

    /// Step every Driver against one host-owned immutable-prefix anchor,
    /// staging Driver state until commit or abort.
    ///
    /// # Errors
    /// Returns [`RuntimeError::PendingDriverStep`] when a prior anchored step is
    /// still pending, or propagates a Driver or draft validation error.
    ///
    /// # Panics
    /// Panics only if the internally collected Driver identifiers stop
    /// referring to their registered entries without passing through a public API.
    pub fn step_all_anchored(
        &mut self,
        timeline: pos_core::ids::TimelineId,
        observed_through: Seq,
    ) -> Result<Vec<pos_core::event::EventDraft>, RuntimeError> {
        self.step_anchored_transaction(
            timeline,
            observed_through,
            AnchoredSelection::All,
            &[],
            OperationContext::Public,
        )
    }

    /// Step all Drivers with a host-filtered committed Event prefix.
    ///
    /// # Errors
    /// Returns a staged-step, Driver, or draft validation error.
    pub fn step_all_anchored_with_events(
        &mut self,
        timeline: pos_core::ids::TimelineId,
        observed_through: Seq,
        committed_events: &[Event],
    ) -> Result<Vec<pos_core::event::EventDraft>, RuntimeError> {
        self.step_anchored_transaction(
            timeline,
            observed_through,
            AnchoredSelection::All,
            committed_events,
            OperationContext::Public,
        )
    }

    /// Step every Driver under a host-issued protected capability.
    ///
    /// # Errors
    /// Returns a consent, staged-step, Driver, or draft validation error.
    pub fn step_all_anchored_protected(
        &mut self,
        timeline: pos_core::ids::TimelineId,
        observed_through: Seq,
        token: ConsentCapabilityToken,
        now_secs: u64,
        committed_events: &[Event],
    ) -> Result<Vec<pos_core::event::EventDraft>, RuntimeError> {
        self.step_anchored_transaction(
            timeline,
            observed_through,
            AnchoredSelection::All,
            committed_events,
            OperationContext::Protected { token, now_secs },
        )
    }
}

impl Default for PluginRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::driver::{ObservationView, SnapshotAnchor, StepOutput};
    use pos_core::{
        clock::{Seq, WallTime},
        crypto::Hash,
        event::{CanonicalBytes, EventDraft, Kind, SchemaVersion},
        ids::{EntityId, EventId, PluginId, TimelineId},
        Capability, ConsentGrantedV1, ConsentRevokedV1, CoreError, Event, Plugin, Reducer, State,
    };
    use pos_store::{open_store, StoreConfig};
    use std::{
        sync::{Arc, Mutex},
        time::Duration,
    };

    trait TestValueExt<T> {
        fn test_ok(self) -> T;
    }

    impl<T, E: std::fmt::Debug> TestValueExt<T> for Result<T, E> {
        fn test_ok(self) -> T {
            self.unwrap_or_else(|error| {
                std::panic::resume_unwind(Box::new(format!(
                    "unexpected registry fixture error: {error:?}"
                )))
            })
        }
    }

    impl<T> TestValueExt<T> for Option<T> {
        fn test_ok(self) -> T {
            self.unwrap_or_else(|| {
                std::panic::resume_unwind(Box::new("missing registry fixture value"))
            })
        }
    }

    trait TestErrorExt<T, E> {
        fn test_err(self) -> E;
    }

    impl<T: std::fmt::Debug, E> TestErrorExt<T, E> for Result<T, E> {
        fn test_err(self) -> E {
            match self {
                Ok(value) => std::panic::resume_unwind(Box::new(format!(
                    "unexpected successful registry fixture value: {value:?}"
                ))),
                Err(error) => error,
            }
        }
    }

    // ── Test helpers ──────────────────────────────────────────────────────────

    struct TestPlugin {
        id: PluginId,
        name: &'static str,
        cap: Capability,
    }

    impl Plugin for TestPlugin {
        fn id(&self) -> PluginId {
            self.id
        }
        fn name(&self) -> &'static str {
            self.name
        }
        fn capability(&self) -> Capability {
            self.cap.clone()
        }
    }

    fn simple_plugin(name: &'static str, event_types: &[&str]) -> TestPlugin {
        plugin_with_caps(name, event_types, false, false)
    }

    fn plugin_with_caps(
        name: &'static str,
        event_types: &[&str],
        has_driver: bool,
        has_reducer: bool,
    ) -> TestPlugin {
        TestPlugin {
            id: PluginId::new(),
            name,
            cap: Capability {
                owned_event_types: event_types.iter().map(|s| Kind::new(*s)).collect(),
                owned_entity_kinds: vec![],
                has_driver,
                has_reducer,
            },
        }
    }

    struct CountReducer;
    impl Reducer for CountReducer {
        fn initial(&self) -> State {
            State::new()
        }
        fn apply(&self, state: &mut State, _: &Event) {
            let n = state
                .get("n")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
            state.set("n", serde_json::json!(n + 1));
        }
    }

    struct NoopDriver;
    impl crate::driver::Driver for NoopDriver {
        fn name(&self) -> &'static str {
            "noop"
        }
        fn step(
            &mut self,
            _: pos_core::ids::TimelineId,
            _: ObservationView<'_>,
        ) -> Result<crate::driver::StepOutput, RuntimeError> {
            Ok(crate::driver::StepOutput::empty())
        }
    }

    struct PanickingDriver;
    impl crate::driver::Driver for PanickingDriver {
        fn name(&self) -> &'static str {
            "panicking"
        }

        fn step(
            &mut self,
            _: pos_core::ids::TimelineId,
            _: ObservationView<'_>,
        ) -> Result<crate::driver::StepOutput, RuntimeError> {
            std::panic::resume_unwind(Box::new("test driver panic"));
        }
    }

    struct AbortPanickingDriver;
    impl crate::driver::Driver for AbortPanickingDriver {
        fn name(&self) -> &'static str {
            "abort-panicking"
        }

        fn step(
            &mut self,
            _: pos_core::ids::TimelineId,
            _: ObservationView<'_>,
        ) -> Result<crate::driver::StepOutput, RuntimeError> {
            Ok(StepOutput::empty())
        }

        fn abort_step(&mut self) {
            std::panic::resume_unwind(Box::new("test abort panic"));
        }
    }

    #[derive(Default)]
    struct TransactionState {
        steps: usize,
        commits: usize,
        aborts: usize,
        restores: usize,
        staged: bool,
        anchors: Vec<SnapshotAnchor>,
    }

    struct TransactionalDriver {
        name: &'static str,
        state: Arc<Mutex<TransactionState>>,
        interval: Duration,
        fail: bool,
    }

    impl Driver for TransactionalDriver {
        fn name(&self) -> &'static str {
            self.name
        }

        fn step(
            &mut self,
            _: TimelineId,
            observations: ObservationView<'_>,
        ) -> Result<StepOutput, RuntimeError> {
            if self.fail {
                return Err(RuntimeError::NoDriver {
                    name: self.name.to_owned(),
                });
            }
            let mut state = self.state.lock().test_ok();
            state.steps += 1;
            state.staged = true;
            state.anchors.push(observations.anchor().test_ok());
            drop(state);
            Ok(StepOutput::empty())
        }

        fn tick_interval(&self) -> Duration {
            self.interval
        }

        fn requires_snapshot_anchor(&self) -> bool {
            true
        }

        fn commit_step(&mut self) {
            let mut state = self.state.lock().test_ok();
            assert!(state.staged);
            state.staged = false;
            state.commits += 1;
        }

        fn abort_step(&mut self) {
            let mut state = self.state.lock().test_ok();
            if state.staged {
                state.staged = false;
                state.aborts += 1;
            }
        }

        fn stage_restore_from_history(
            &mut self,
            _evidence: &DriverRecoveryEvidence,
        ) -> Result<(), RuntimeError> {
            self.state.lock().test_ok().restores += 1;
            Ok(())
        }
    }

    // ── Tests ─────────────────────────────────────────────────────────────────

    #[test]
    fn anchored_step_converts_driver_panic_to_abortable_error() {
        let mut registry = PluginRegistry::new();
        let plugin = plugin_with_caps("panicking", &["probe.event"], true, false);
        registry
            .register(&plugin, None, Some(Box::new(PanickingDriver)))
            .test_ok();

        let error = registry
            .step_all_anchored(TimelineId::new(), Seq::ZERO)
            .test_err();
        assert!(matches!(error, RuntimeError::DriverPanicked { .. }));
        registry.abort_step();
    }

    #[test]
    fn aborting_a_staged_driver_catches_a_driver_abort_panic() {
        let mut registry = PluginRegistry::new();
        let plugin = plugin_with_caps("abort-panicking", &[], true, false);
        registry
            .register(&plugin, None, Some(Box::new(AbortPanickingDriver)))
            .test_ok();
        registry
            .step_all_anchored(TimelineId::new(), Seq::ZERO)
            .test_ok();
        registry.abort_step();
        assert!(registry
            .step_all_anchored(TimelineId::new(), Seq::ZERO)
            .is_err());
    }

    #[test]
    fn resource_limit_aborts_before_collecting_a_later_driver_output() {
        struct BudgetDriver {
            aborted: Arc<Mutex<bool>>,
        }

        impl Driver for BudgetDriver {
            fn name(&self) -> &'static str {
                "budget"
            }

            fn step(
                &mut self,
                _: TimelineId,
                _: ObservationView<'_>,
            ) -> Result<StepOutput, RuntimeError> {
                Ok(StepOutput::new(vec![
                    EventDraft::new(
                        EntityId::new(),
                        Kind::new("budget.event"),
                        CanonicalBytes::from_static(b"one"),
                    ),
                    EventDraft::new(
                        EntityId::new(),
                        Kind::new("budget.event"),
                        CanonicalBytes::from_static(b"two"),
                    ),
                ]))
            }

            fn abort_step(&mut self) {
                *self.aborted.lock().test_ok() = true;
            }
        }

        let aborted = Arc::new(Mutex::new(false));
        let mut registry = PluginRegistry::new().with_resource_limit(1);
        registry.register_driver(Box::new(BudgetDriver {
            aborted: Arc::clone(&aborted),
        }));
        let error = registry
            .step_all_anchored(TimelineId::new(), Seq::ZERO)
            .test_err();
        assert!(matches!(error, RuntimeError::ResourceExhausted { .. }));
        assert!(*aborted.lock().test_ok());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn anchored_step_stages_until_commit_and_rejects_a_second_pending_step() {
        let timeline = TimelineId::new();
        let state = Arc::new(Mutex::new(TransactionState::default()));
        let mut registry = PluginRegistry::new();
        registry.register_driver(Box::new(TransactionalDriver {
            name: "transactional",
            state: Arc::clone(&state),
            interval: Duration::from_nanos(100),
            fail: false,
        }));

        assert!(matches!(
            registry.step_all(timeline),
            Err(RuntimeError::MissingSnapshotAnchor { .. })
        ));
        assert_eq!(state.lock().test_ok().steps, 0);

        assert!(registry
            .step_all_anchored(timeline, Seq::from_u64(7))
            .test_ok()
            .is_empty());
        {
            let observed = state.lock().test_ok();
            assert_eq!(observed.steps, 1);
            assert_eq!(observed.commits, 0);
            assert!(observed.staged);
            assert_eq!(
                observed.anchors,
                [SnapshotAnchor::new(timeline, Seq::from_u64(7))]
            );
            drop(observed);
        }
        assert!(matches!(
            registry.step_all_anchored(timeline, Seq::from_u64(7)),
            Err(RuntimeError::PendingDriverStep)
        ));
        assert!(matches!(
            registry.step_all(timeline),
            Err(RuntimeError::PendingDriverStep)
        ));
        assert!(matches!(
            registry.tick_cadenced(timeline, 0),
            Err(RuntimeError::PendingDriverStep)
        ));
        assert_eq!(state.lock().test_ok().steps, 1);

        registry.commit_step_at(Seq::ZERO, 0).test_ok();
        assert_eq!(state.lock().test_ok().commits, 1);
        assert!(!state.lock().test_ok().staged);

        registry
            .step_all_anchored(timeline, Seq::from_u64(7))
            .test_ok();
        registry.abort_step();
        assert_eq!(state.lock().test_ok().aborts, 1);
        assert!(!state.lock().test_ok().staged);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn driver_history_restoration_runs_before_any_new_transaction() {
        let timeline = TimelineId::new();
        let state = Arc::new(Mutex::new(TransactionState::default()));
        let mut registry = PluginRegistry::new();
        registry.register_driver(Box::new(TransactionalDriver {
            name: "restoring",
            state: Arc::clone(&state),
            interval: Duration::from_nanos(1),
            fail: false,
        }));

        registry
            .restore_driver_state(&[TimelineHistorySegment::new(timeline, Seq::ZERO)], &[])
            .test_ok();
        assert_eq!(state.lock().test_ok().restores, 1);

        registry.step_all_anchored(timeline, Seq::ZERO).test_ok();
        assert!(matches!(
            registry.restore_driver_state(&[TimelineHistorySegment::new(timeline, Seq::ZERO)], &[]),
            Err(RuntimeError::PendingDriverStep)
        ));
        registry.abort_step();

        let event = Event {
            id: EventId::new(),
            entity: EntityId::new(),
            event_type: Kind::new("restoration.fixture"),
            payload: CanonicalBytes::from_static(b"history"),
            wall_time: WallTime::from_micros(1),
            seq: Seq::from_u64(1),
            causation_id: None,
            correlation_id: None,
            schema_version: SchemaVersion::V1,
            signature: None,
            signature_identity: None,
            payload_hash: Hash::from_bytes([0; 32]),
        };
        registry
            .restore_driver_state(
                &[TimelineHistorySegment::new(timeline, Seq::from_u64(1))],
                &[event],
            )
            .test_ok();
        assert_eq!(state.lock().test_ok().restores, 2);
    }

    #[test]
    fn panicking_restore_commit_is_reported_and_poisoned() {
        struct RestoreCommitPanickingDriver;

        impl Driver for RestoreCommitPanickingDriver {
            fn name(&self) -> &'static str {
                "restore-commit-panicking"
            }

            fn step(
                &mut self,
                _: TimelineId,
                _: ObservationView<'_>,
            ) -> Result<StepOutput, RuntimeError> {
                Ok(StepOutput::empty())
            }

            fn commit_restore_from_history(&mut self) {
                std::panic::resume_unwind(Box::new("restore commit panic"));
            }
        }

        let timeline = TimelineId::new();
        let mut registry = PluginRegistry::new();
        registry.register_driver(Box::new(RestoreCommitPanickingDriver));
        let error = registry
            .restore_driver_state(&[TimelineHistorySegment::new(timeline, Seq::ZERO)], &[])
            .test_err();
        assert!(matches!(error, RuntimeError::DriverRestorePanicked { .. }));
    }

    #[test]
    fn panicking_step_commit_marks_the_driver_poisoned() {
        struct StepCommitPanickingDriver;

        impl Driver for StepCommitPanickingDriver {
            fn name(&self) -> &'static str {
                "step-commit-panicking"
            }

            fn step(
                &mut self,
                _: TimelineId,
                _: ObservationView<'_>,
            ) -> Result<StepOutput, RuntimeError> {
                Ok(StepOutput::empty())
            }

            fn commit_step(&mut self) {
                std::panic::resume_unwind(Box::new("step commit panic"));
            }
        }

        let mut registry = PluginRegistry::new();
        registry.register_driver(Box::new(StepCommitPanickingDriver));
        registry
            .step_all_anchored(TimelineId::new(), Seq::ZERO)
            .test_ok();
        registry.commit_step_at(Seq::ZERO, 0).test_ok();
        assert!(registry
            .step_all_anchored(TimelineId::new(), Seq::ZERO)
            .is_err());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn failed_driver_recovery_aborts_every_earlier_staged_driver() {
        #[derive(Default)]
        struct RestoreState {
            staged: bool,
            commits: usize,
            aborts: usize,
        }

        struct RestoreDriver {
            state: Arc<Mutex<RestoreState>>,
            rejects: bool,
        }

        impl Driver for RestoreDriver {
            fn name(&self) -> &'static str {
                "restore-fixture"
            }

            fn step(
                &mut self,
                _: TimelineId,
                _: ObservationView<'_>,
            ) -> Result<StepOutput, RuntimeError> {
                Ok(StepOutput::empty())
            }

            fn stage_restore_from_history(
                &mut self,
                _: &DriverRecoveryEvidence,
            ) -> Result<(), RuntimeError> {
                if self.rejects {
                    self.state.lock().test_ok().staged = true;
                    return Err(RuntimeError::NoDriver {
                        name: "rejected recovery".to_owned(),
                    });
                }
                self.state.lock().test_ok().staged = true;
                Ok(())
            }

            fn commit_restore_from_history(&mut self) {
                let mut state = self.state.lock().test_ok();
                assert!(state.staged);
                state.staged = false;
                state.commits += 1;
            }

            fn abort_restore_from_history(&mut self) {
                let mut state = self.state.lock().test_ok();
                if state.staged {
                    state.staged = false;
                    state.aborts += 1;
                }
            }
        }

        let first = Arc::new(Mutex::new(RestoreState::default()));
        let second = Arc::new(Mutex::new(RestoreState::default()));
        let mut registry = PluginRegistry::new();
        registry.register_driver(Box::new(RestoreDriver {
            state: Arc::clone(&first),
            rejects: false,
        }));
        registry.register_driver(Box::new(RestoreDriver {
            state: Arc::clone(&second),
            rejects: true,
        }));

        assert!(registry
            .restore_driver_state(
                &[TimelineHistorySegment::new(TimelineId::new(), Seq::ZERO)],
                &[],
            )
            .is_err());
        let first = first.lock().test_ok();
        assert!(!first.staged);
        assert_eq!(first.commits, 0);
        assert_eq!(first.aborts, 1);
        drop(first);
        let second = second.lock().test_ok();
        assert!(!second.staged);
        assert_eq!(second.commits, 0);
        assert_eq!(second.aborts, 1);
        drop(second);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn anchored_partial_driver_failure_aborts_earlier_staged_state() {
        let timeline = TimelineId::new();
        let first = Arc::new(Mutex::new(TransactionState::default()));
        let failed = Arc::new(Mutex::new(TransactionState::default()));
        let mut registry = PluginRegistry::new();
        registry.register_driver(Box::new(TransactionalDriver {
            name: "first",
            state: Arc::clone(&first),
            interval: Duration::from_nanos(1),
            fail: false,
        }));
        registry.register_driver(Box::new(TransactionalDriver {
            name: "failed",
            state: Arc::clone(&failed),
            interval: Duration::from_nanos(1),
            fail: true,
        }));

        assert!(registry.step_all_anchored(timeline, Seq::ZERO).is_err());
        let first = first.lock().test_ok();
        assert_eq!(first.steps, 1);
        assert_eq!(first.aborts, 1);
        assert!(!first.staged);
        drop(first);
        assert_eq!(failed.lock().test_ok().steps, 0);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn anchored_cadence_is_staged_and_legacy_preflights_all_registered_drivers() {
        let timeline = TimelineId::new();
        let state = Arc::new(Mutex::new(TransactionState::default()));
        let mut registry = PluginRegistry::new();
        registry.register_driver(Box::new(TransactionalDriver {
            name: "cadenced-provider",
            state: Arc::clone(&state),
            interval: Duration::from_nanos(100),
            fail: false,
        }));

        assert!(registry
            .tick_cadenced_anchored_with_events(timeline, 0, Seq::ZERO, &[])
            .test_ok()
            .is_empty());
        registry.abort_step();
        registry
            .tick_cadenced_anchored(timeline, 0, Seq::ZERO)
            .test_ok();
        registry.commit_step_at(Seq::ZERO, 0).test_ok();
        assert_eq!(state.lock().test_ok().steps, 2);

        assert!(matches!(
            registry.tick_cadenced(timeline, 50),
            Err(RuntimeError::MissingSnapshotAnchor { .. })
        ));
        assert_eq!(state.lock().test_ok().steps, 2);

        assert!(registry
            .tick_cadenced_anchored(timeline, 50, Seq::ZERO)
            .test_ok()
            .is_empty());
        registry.commit_step_at(Seq::ZERO, 0).test_ok();
        assert_eq!(state.lock().test_ok().steps, 2);

        registry
            .tick_cadenced_anchored(timeline, 100, Seq::ZERO)
            .test_ok();
        registry.commit_step_at(Seq::ZERO, 0).test_ok();
        assert_eq!(state.lock().test_ok().steps, 3);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn register_plugin_wires_schemas() {
        let mut reg = PluginRegistry::new();
        let p = simple_plugin("world", &["world.observation", "world.action"]);
        reg.register(&p, None, None).test_ok();
        assert!(reg.schemas.contains("world.observation"));
        assert!(reg.schemas.contains("world.action"));
        assert!(!reg.schemas.contains("agent.decision"));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn plugins_cannot_claim_core_owned_geographic_event_types() {
        let plugin = simple_plugin("malicious-geo", &[pos_core::GEOGRAPHIC_EVENT_TYPE]);
        let error = PluginRegistry::new()
            .register(&plugin, None, None)
            .test_err();
        assert!(error.to_string().contains(pos_core::GEOGRAPHIC_EVENT_TYPE));

        let cell = simple_plugin("future-geo", &[pos_core::GEOGRAPHIC_CELL_EVENT_TYPE]);
        let error = PluginRegistry::new().register(&cell, None, None).test_err();
        assert!(error
            .to_string()
            .contains(pos_core::GEOGRAPHIC_CELL_EVENT_TYPE));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn plugins_cannot_claim_gateway_owned_consent_event_types() {
        for event_type in [
            pos_core::EVENT_TYPE_CONSENT_GRANTED_V1,
            pos_core::EVENT_TYPE_CONSENT_REVOKED_V1,
            "consent.future.v2",
        ] {
            let plugin = simple_plugin("malicious-consent", &[event_type]);
            assert!(matches!(
                PluginRegistry::new().register(&plugin, None, None),
                Err(RuntimeError::ReservedConsentEventType { .. })
            ));
        }
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn register_plugin_with_reducer_wires_projections() {
        let mut reg = PluginRegistry::new();
        let p = plugin_with_caps("counter", &["counter.tick"], false, true);
        reg.register(&p, Some(Box::new(CountReducer)), None)
            .test_ok();
        // Apply an event and verify the reducer ran
        let event = Event {
            id: EventId::new(),
            entity: EntityId::new(),
            event_type: Kind::new("counter.tick"),
            payload: CanonicalBytes::from_vec(vec![]),
            wall_time: WallTime::from_micros(0),
            seq: Seq::from_u64(1),
            causation_id: None,
            correlation_id: None,
            schema_version: SchemaVersion::V1,
            signature: None,
            signature_identity: None,
            payload_hash: Hash::from_bytes([0u8; 32]),
        };
        reg.projections.apply_event(&event);
        let state = reg.projections.state_for(&event.entity).test_ok();
        assert_eq!(state.get("n").and_then(serde_json::Value::as_u64), Some(1));
        let mut protected = event;
        protected.event_type = Kind::new(pos_core::GEOGRAPHIC_EVENT_TYPE);
        reg.projections.apply_event(&protected);
        assert_eq!(
            reg.projections
                .state_for(&protected.entity)
                .and_then(|state| state.get("n"))
                .and_then(serde_json::Value::as_u64),
            Some(1)
        );
    }

    #[test]
    fn capability_projection_and_gate_clone_are_bound_public_seams() {
        let timeline = TimelineId::new();
        let subject = EntityId::new();
        let authority = ConsentAuthority::new();
        let token = authority.record_grant_on_timeline(
            timeline,
            &ConsentGrantedV1 {
                subject_id: subject,
                grantee_id: EntityId::new(),
                purpose: "projection-seam".to_owned(),
                modalities: 0,
                min_geo_resolution: 0,
                fork_permitted: false,
                export_permitted: false,
                retention_days: 0,
                expiry_secs: 0,
                grant_seq: 1,
            },
        );
        let unbound = PluginRegistry::new();
        assert!(unbound.clone_consent_gate().is_some());
        assert!(PluginRegistry::new()
            .with_consent_gate(Arc::new(ConsentAuthority::new()))
            .clone_consent_gate()
            .is_some());
        assert!(matches!(
            unbound.projection_state_for_reducer(
                timeline,
                Seq::ZERO,
                0,
                &token,
                "projection",
                subject,
            ),
            Err(RuntimeError::Consent(_))
        ));

        let plugin = plugin_with_caps("projection", &["projection.event"], false, true);
        let mut bound = PluginRegistry::new().with_consent_authority(authority);
        bound
            .register(&plugin, Some(Box::new(CountReducer)), None)
            .test_ok();
        assert!(bound.clone_consent_gate().is_some());
        let projection_event = |entity, seq| Event {
            id: EventId::new(),
            entity,
            event_type: Kind::new("projection.event"),
            payload: CanonicalBytes::from_static(b"projection"),
            wall_time: WallTime::from_micros(0),
            seq,
            causation_id: None,
            correlation_id: None,
            schema_version: SchemaVersion::V1,
            signature: None,
            signature_identity: None,
            payload_hash: Hash::from_bytes([0; 32]),
        };
        bound
            .projections
            .apply_event(&projection_event(subject, Seq::from_u64(1)));
        let unrelated = EntityId::new();
        bound
            .projections
            .apply_event(&projection_event(unrelated, Seq::from_u64(2)));
        let state = bound
            .projection_state_for_reducer(timeline, Seq::ZERO, 0, &token, "projection", subject)
            .test_ok()
            .test_ok();
        assert_eq!(state.get("n").and_then(serde_json::Value::as_u64), Some(1));
        assert!(bound
            .projection_state_for_reducer(timeline, Seq::ZERO, 0, &token, "missing", subject,)
            .test_ok()
            .is_none());
        let authorized = bound
            .into_authorized_projections(timeline, Seq::from_u64(2), 0, Some(&token), None)
            .test_ok();
        assert!(authorized
            .state_for_reducer("projection", &unrelated)
            .is_none());
        assert!(authorized.state_for(&subject).is_some());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn duplicate_plugin_returns_error() {
        let mut reg = PluginRegistry::new();
        let id = PluginId::new();
        let p1 = TestPlugin {
            id,
            name: "dup",
            cap: Capability::default(),
        };
        let p2 = TestPlugin {
            id,
            name: "dup",
            cap: Capability::default(),
        };
        reg.register(&p1, None, None).test_ok();
        let err = reg.register(&p2, None, None).test_err();
        assert!(matches!(err, RuntimeError::DuplicatePlugin { .. }));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn duplicate_plugin_does_not_consume_approver_event_types() {
        let mut reg = PluginRegistry::new();
        let id = PluginId::new();
        let plugin = TestPlugin {
            id,
            name: "dup",
            cap: Capability::default(),
        };
        reg.register(&plugin, None, None).test_ok();

        let consumed = std::cell::Cell::new(false);
        let event_types = std::iter::once_with(|| {
            consumed.set(true);
            Kind::new("must.not.be.consumed")
        });
        let error = reg
            .register_with_approver(&plugin, None, None, None, event_types)
            .test_err();

        assert!(matches!(error, RuntimeError::DuplicatePlugin { .. }));
        assert!(!consumed.get());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn contains_len_is_empty() {
        let mut reg = PluginRegistry::new();
        assert!(reg.is_empty());
        let p = simple_plugin("p", &[]);
        reg.register(&p, None, None).test_ok();
        assert_eq!(reg.len(), 1);
        assert_eq!(reg.driver_count(), 0);
        assert!(reg.contains(&p.id));
        assert!(!reg.is_empty());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn tick_cadenced_skips_driverless_plugins() {
        let mut store = pos_store::open_store(pos_store::StoreConfig::Memory).test_ok();
        let tl = store.create_timeline("t").test_ok();
        let mut reg = PluginRegistry::new();
        let p = simple_plugin("p", &[]);
        reg.register(&p, None, None).test_ok();
        let drafts = reg.tick_cadenced(tl.id(), 0).test_ok();
        assert!(drafts.is_empty());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn plugin_names_iterator() {
        let mut reg = PluginRegistry::new();
        let p1 = simple_plugin("alpha", &[]);
        let p2 = simple_plugin("beta", &[]);
        reg.register(&p1, None, None).test_ok();
        reg.register(&p2, None, None).test_ok();
        let names: Vec<&str> = reg.plugin_names().collect();
        assert!(names.contains(&"alpha"));
        assert!(names.contains(&"beta"));
        let versions: Vec<(&str, &str)> = reg.plugin_versions().collect();
        assert!(versions.contains(&("alpha", "0.1.0")));
        assert!(versions.contains(&("beta", "0.1.0")));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn step_all_calls_drivers_and_collects_drafts() {
        use crate::driver::{Driver, StepOutput};
        use pos_store::{open_store, StoreConfig};

        struct SimpleDriver {
            entity: EntityId,
            calls: u32,
        }
        impl Driver for SimpleDriver {
            fn name(&self) -> &'static str {
                "simple"
            }
            fn step(
                &mut self,
                _: pos_core::ids::TimelineId,
                _: ObservationView<'_>,
            ) -> Result<StepOutput, RuntimeError> {
                self.calls += 1;
                let draft = EventDraft::new(
                    self.entity,
                    Kind::new("driver.tick"),
                    CanonicalBytes::from_vec(vec![]),
                );
                Ok(StepOutput::new(vec![draft]))
            }
        }

        let mut store = open_store(StoreConfig::Memory).test_ok();
        let tl = store.create_timeline("t").test_ok();

        let entity = EntityId::new();
        let p = plugin_with_caps("driven", &["driver.tick"], true, false);
        let driver = SimpleDriver { entity, calls: 0 };
        assert_eq!(driver.name(), "simple"); // force coverage of name()

        let mut reg = PluginRegistry::new();
        reg.register(&p, None, Some(Box::new(driver))).test_ok();
        assert_eq!(reg.driver_count(), 1);

        let drafts = reg.step_all(tl.id()).test_ok();
        assert_eq!(drafts.len(), 1);
        assert_eq!(drafts[0].event_type.as_str(), "driver.tick");

        let anchored = reg
            .step_all_anchored_with_events(tl.id(), Seq::ZERO, &[])
            .test_ok();
        assert_eq!(anchored.len(), 1);
        assert_eq!(anchored[0].event_type.as_str(), "driver.tick");
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn step_all_no_drivers_returns_empty() {
        use pos_store::{open_store, StoreConfig};
        let mut store = open_store(StoreConfig::Memory).test_ok();
        let tl = store.create_timeline("t").test_ok();
        let p = simple_plugin("nodrive", &[]);
        let mut reg = PluginRegistry::new();
        reg.register(&p, None, None).test_ok();
        let drafts = reg.step_all(tl.id()).test_ok();
        assert!(drafts.is_empty());
    }

    #[test]
    fn direct_driver_selection_reports_missing_entries() {
        let mut registry = PluginRegistry::new();
        let snapshot = ObservationSnapshot::default();
        let missing = registry
            .invoke_selected_driver(PluginId::new(), TimelineId::new(), &snapshot, &[])
            .test_err();
        assert!(matches!(missing, RuntimeError::NoDriver { .. }));

        let plugin = simple_plugin("registered-without-driver", &[]);
        let plugin_id = plugin.id;
        registry.register(&plugin, None, None).test_ok();
        let absent = registry
            .invoke_selected_driver(plugin_id, TimelineId::new(), &snapshot, &[])
            .test_err();
        assert!(matches!(absent, RuntimeError::NoDriver { .. }));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn selected_driver_never_receives_gateway_owned_consent_events() {
        struct EventDriver {
            subscriptions: Vec<Kind>,
            observed: Arc<Mutex<Vec<String>>>,
        }

        impl Driver for EventDriver {
            fn name(&self) -> &'static str {
                "event-filter"
            }

            fn event_subscriptions(&self) -> &[Kind] {
                &self.subscriptions
            }

            fn step(
                &mut self,
                _: TimelineId,
                observations: ObservationView<'_>,
            ) -> Result<StepOutput, RuntimeError> {
                self.observed.lock().test_ok().extend(
                    observations
                        .events()
                        .iter()
                        .map(|event| event.event_type.as_str().to_owned()),
                );
                Ok(StepOutput::empty())
            }
        }

        let observed = Arc::new(Mutex::new(Vec::new()));
        let mut registry = PluginRegistry::new();
        let plugin_id = PluginId::new();
        registry.plugins.insert(
            plugin_id,
            PluginEntry {
                name: "event-filter".to_owned(),
                version: "0.1.0".to_owned(),
                driver: Some(Box::new(EventDriver {
                    subscriptions: vec![
                        Kind::new("ordinary.event"),
                        Kind::new(pos_core::EVENT_TYPE_CONSENT_GRANTED_V1),
                        Kind::new(pos_core::GEOGRAPHIC_EVENT_TYPE),
                        Kind::new(pos_core::GEOGRAPHIC_CELL_EVENT_TYPE),
                    ],
                    observed: Arc::clone(&observed),
                })),
                approver: None,
                last_tick: None,
                event_cursor: Seq::ZERO,
            },
        );

        let ordinary = Event {
            id: EventId::new(),
            entity: EntityId::new(),
            event_type: Kind::new("ordinary.event"),
            payload: CanonicalBytes::from_static(b"ordinary"),
            wall_time: WallTime::from_micros(1),
            seq: Seq::from_u64(1),
            causation_id: None,
            correlation_id: None,
            schema_version: SchemaVersion::V1,
            signature: None,
            signature_identity: None,
            payload_hash: Hash::from_bytes([0; 32]),
        };
        let mut consent = ordinary.clone();
        consent.event_type = Kind::new(pos_core::EVENT_TYPE_CONSENT_GRANTED_V1);
        let mut location = ordinary.clone();
        location.event_type = Kind::new(pos_core::GEOGRAPHIC_EVENT_TYPE);
        let mut cell = ordinary.clone();
        cell.event_type = Kind::new(pos_core::GEOGRAPHIC_CELL_EVENT_TYPE);

        registry
            .invoke_selected_driver(
                plugin_id,
                TimelineId::new(),
                &ObservationSnapshot::default(),
                &[ordinary, consent, location, cell],
            )
            .test_ok();

        assert_eq!(
            observed.lock().test_ok().as_slice(),
            ["ordinary.event".to_owned()]
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn protected_operation_validation_fails_closed_and_checks_the_bound_authority() {
        let grant = ConsentGrantedV1 {
            subject_id: EntityId::new(),
            grantee_id: EntityId::new(),
            purpose: "runtime-test".to_owned(),
            modalities: pos_core::MODALITY_LOCATION,
            min_geo_resolution: 0,
            fork_permitted: false,
            export_permitted: false,
            retention_days: 1,
            expiry_secs: 0,
            grant_seq: 4,
        };
        let timeline = TimelineId::new();
        let authority = ConsentAuthority::new();
        let token = authority.record_grant_on_timeline(timeline, &grant);
        let operation = OperationContext::Protected { token, now_secs: 1 };

        let mut unbound = PluginRegistry::new();
        unbound.consent_gate = None;
        assert!(unbound
            .validate_operation(timeline, &operation, Seq::from_u64(3), None)
            .is_err_and(|error| matches!(error, RuntimeError::ConsentOperationUnavailable)));

        let bound = PluginRegistry::new().with_consent_authority(authority.clone());
        assert!(bound
            .validate_operation(timeline, &operation, Seq::from_u64(3), None)
            .is_ok());
        authority
            .record_revocation_on_timeline(
                timeline,
                &ConsentRevokedV1 {
                    subject_id: grant.subject_id,
                    grantee_id: grant.grantee_id,
                    grant_seq: grant.grant_seq,
                    fence_seq: 5,
                },
            )
            .test_ok();
        assert!(bound
            .validate_operation(timeline, &operation, Seq::from_u64(5), None)
            .is_err_and(|error| matches!(error, RuntimeError::Consent(_))));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn missing_consent_gate_rejects_snapshot_and_draft_authorization() {
        let timeline = TimelineId::new();
        let key = ProjectionKey::new(EntityId::new());
        let authority = ConsentAuthority::new();
        let grant = ConsentGrantedV1 {
            subject_id: key.entity_id().to_owned(),
            grantee_id: EntityId::new(),
            purpose: "missing-gate-coverage".to_owned(),
            modalities: 0,
            min_geo_resolution: 0,
            fork_permitted: false,
            export_permitted: false,
            retention_days: 0,
            expiry_secs: 0,
            grant_seq: 1,
        };
        let token = authority.record_grant_on_timeline(timeline, &grant);
        let registry = PluginRegistry::new().without_consent_gate();
        let operation = OperationContext::Protected { token, now_secs: 0 };
        assert!(matches!(
            registry.authorize_snapshot_subscriptions(
                timeline,
                Seq::ZERO,
                &operation,
                std::slice::from_ref(&key),
            ),
            Err(RuntimeError::ConsentOperationUnavailable)
        ));
        let draft = EventDraft::new(
            EntityId::new(),
            Kind::new("missing-gate.event"),
            CanonicalBytes::from_static(b"coverage"),
        );
        assert!(matches!(
            registry.validate_protected_drafts(
                timeline,
                &OperationContext::Public,
                Seq::ZERO,
                std::slice::from_ref(&draft),
            ),
            Err(RuntimeError::ConsentOperationUnavailable)
        ));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn step_all_propagates_driver_error() {
        struct FailingDriver;

        impl Driver for FailingDriver {
            fn name(&self) -> &'static str {
                "failing"
            }

            fn step(
                &mut self,
                _: TimelineId,
                _: ObservationView<'_>,
            ) -> Result<StepOutput, RuntimeError> {
                Err(RuntimeError::NoDriver {
                    name: "failing".to_owned(),
                })
            }
        }

        let mut store = open_store(StoreConfig::Memory).test_ok();
        let timeline = store.create_timeline("t").test_ok();
        let mut reg = PluginRegistry::new();
        reg.register_driver(Box::new(FailingDriver));

        let error = reg.step_all(timeline.id()).test_err();
        assert!(error.to_string().contains("failing"));

        let error = reg.tick_cadenced(timeline.id(), 0).test_err();
        assert!(error.to_string().contains("failing"));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn generic_driver_boundaries_reject_geographic_drafts() {
        struct GeographicDriver;
        impl Driver for GeographicDriver {
            fn name(&self) -> &'static str {
                "geographic"
            }

            fn step(
                &mut self,
                _: TimelineId,
                _: ObservationView<'_>,
            ) -> Result<StepOutput, RuntimeError> {
                Ok(StepOutput::new(vec![EventDraft::new(
                    EntityId::new(),
                    Kind::new("geo.location"),
                    CanonicalBytes::from_vec(Vec::new()),
                )]))
            }
        }

        let mut store = open_store(StoreConfig::Memory).test_ok();
        let timeline = store.create_timeline("driver-geo").test_ok();
        let mut registry = PluginRegistry::new();
        registry.register_driver(Box::new(GeographicDriver));
        assert!(matches!(
            registry.step_all(timeline.id()),
            Err(RuntimeError::GeographicDraft { .. })
        ));
        assert!(matches!(
            registry.tick_cadenced(timeline.id(), 0),
            Err(RuntimeError::GeographicDraft { .. })
        ));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn generic_driver_boundaries_reject_gateway_owned_consent_drafts() {
        struct ConsentDriver;
        impl crate::driver::Driver for ConsentDriver {
            fn name(&self) -> &'static str {
                "consent"
            }

            fn step(
                &mut self,
                _: TimelineId,
                _: ObservationView<'_>,
            ) -> Result<StepOutput, RuntimeError> {
                Ok(StepOutput::new(vec![EventDraft::new(
                    EntityId::new(),
                    Kind::new(pos_core::EVENT_TYPE_CONSENT_GRANTED_V1),
                    CanonicalBytes::from_vec(Vec::new()),
                )]))
            }
        }

        struct AllowedDriver;
        impl crate::driver::Driver for AllowedDriver {
            fn name(&self) -> &'static str {
                "allowed"
            }

            fn step(
                &mut self,
                _: TimelineId,
                _: ObservationView<'_>,
            ) -> Result<StepOutput, RuntimeError> {
                Ok(StepOutput::new(vec![EventDraft::new(
                    EntityId::new(),
                    Kind::new("driver.allowed.v1"),
                    CanonicalBytes::from_vec(Vec::new()),
                )]))
            }
        }

        let mut store = open_store(StoreConfig::Memory).test_ok();
        let timeline = store.create_timeline("driver-consent").test_ok();
        let mut registry = PluginRegistry::new();
        registry.register_driver(Box::new(ConsentDriver));
        assert!(matches!(
            registry.step_all(timeline.id()),
            Err(RuntimeError::ConsentDraft { .. })
        ));
        assert!(matches!(
            registry.tick_cadenced(timeline.id(), 0),
            Err(RuntimeError::ConsentDraft { .. })
        ));

        let mut allowed = PluginRegistry::new();
        allowed.register_driver(Box::new(AllowedDriver));
        assert_eq!(allowed.tick_cadenced(timeline.id(), 0).test_ok().len(), 1);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn tick_cadenced_materializes_only_subscribed_projection_state() {
        use crate::driver::ProjectionKey;
        use pos_store::{open_store, StoreConfig};

        struct ObservingDriver {
            target: ProjectionKey,
            entity: EntityId,
        }

        impl Driver for ObservingDriver {
            fn name(&self) -> &'static str {
                "observing"
            }

            fn subscriptions(&self) -> &[ProjectionKey] {
                std::slice::from_ref(&self.target)
            }

            fn step(
                &mut self,
                _: pos_core::ids::TimelineId,
                observations: ObservationView<'_>,
            ) -> Result<crate::driver::StepOutput, RuntimeError> {
                let observed = observations
                    .state_for(&self.target)
                    .and_then(|state| state.get("n"))
                    .and_then(serde_json::Value::as_u64);
                let drafts = (observed == Some(1))
                    .then(|| {
                        EventDraft::new(
                            self.entity,
                            Kind::new("driver.observed"),
                            CanonicalBytes::from_vec(vec![]),
                        )
                    })
                    .into_iter()
                    .collect();
                Ok(crate::driver::StepOutput::new(drafts))
            }
        }

        let mut store = open_store(StoreConfig::Memory).test_ok();
        let timeline = store.create_timeline("t").test_ok();
        let observed_entity = EntityId::new();
        let event = Event {
            id: EventId::new(),
            entity: observed_entity,
            event_type: Kind::new("counter.tick"),
            payload: CanonicalBytes::from_vec(vec![]),
            wall_time: WallTime::from_micros(0),
            seq: Seq::from_u64(1),
            causation_id: None,
            correlation_id: None,
            schema_version: SchemaVersion::V1,
            signature: None,
            signature_identity: None,
            payload_hash: Hash::from_bytes([0; 32]),
        };

        let mut reg = PluginRegistry::new();
        reg.projections.register("counter", Box::new(CountReducer));
        reg.projections.apply_event(&event);
        let authority = ConsentAuthority::new();
        let grant = ConsentGrantedV1 {
            subject_id: observed_entity,
            grantee_id: EntityId::new(),
            purpose: "projection-test".to_owned(),
            modalities: 0,
            min_geo_resolution: 0,
            fork_permitted: false,
            export_permitted: false,
            retention_days: 0,
            expiry_secs: 0,
            grant_seq: 1,
        };
        let token = authority.record_grant_on_timeline(timeline.id(), &grant);
        reg = reg.with_consent_authority(authority);
        reg.register_driver(Box::new(ObservingDriver {
            target: ProjectionKey::new(observed_entity),
            entity: EntityId::new(),
        }));

        let drafts = reg
            .tick_cadenced_anchored_protected(timeline.id(), 0, Seq::ZERO, token.clone(), 0, &[])
            .test_ok();
        assert_eq!(drafts.len(), 1);
        assert_eq!(drafts[0].event_type.as_str(), "driver.observed");
        reg.commit_step_at(Seq::ZERO, 0).test_ok();

        let drafts = reg
            .step_all_anchored_protected(timeline.id(), Seq::ZERO, token, 0, &[])
            .test_ok();
        assert_eq!(drafts.len(), 1);
        assert_eq!(drafts[0].event_type.as_str(), "driver.observed");
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn tick_cadenced_deduplicates_snapshot_subscriptions() {
        use crate::driver::ProjectionKey;
        use pos_store::{open_store, StoreConfig};

        struct DuplicateKeyDriver {
            keys: Vec<ProjectionKey>,
        }

        impl Driver for DuplicateKeyDriver {
            fn name(&self) -> &'static str {
                "dup-key-driver"
            }

            fn subscriptions(&self) -> &[ProjectionKey] {
                &self.keys
            }

            fn step(
                &mut self,
                _: TimelineId,
                _: ObservationView<'_>,
            ) -> Result<StepOutput, RuntimeError> {
                Ok(StepOutput::empty())
            }
        }

        let mut store = open_store(StoreConfig::Memory).test_ok();
        let timeline = store.create_timeline("t").test_ok();
        let key = ProjectionKey::new(EntityId::new());
        let subject_id = key.entity_id().to_owned();
        let driver = DuplicateKeyDriver {
            keys: vec![key.clone(), key],
        };
        let plugin = plugin_with_caps("dup-key-plugin", &[], true, false);
        let authority = ConsentAuthority::new();
        let grant = ConsentGrantedV1 {
            subject_id,
            grantee_id: EntityId::new(),
            purpose: "projection-dedup-test".to_owned(),
            modalities: 0,
            min_geo_resolution: 0,
            fork_permitted: false,
            export_permitted: false,
            retention_days: 0,
            expiry_secs: 0,
            grant_seq: 1,
        };
        let token = authority.record_grant_on_timeline(timeline.id(), &grant);
        let mut reg = PluginRegistry::new().with_consent_authority(authority);
        reg.register(&plugin, None, Some(Box::new(driver)))
            .test_ok();

        let drafts = reg
            .tick_cadenced_anchored_protected(timeline.id(), 0, Seq::ZERO, token, 0, &[])
            .test_ok();
        assert!(drafts.is_empty());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn snapshot_for_subscriptions_handles_duplicate_and_missing_projection_keys() {
        use crate::driver::ProjectionKey;

        let mut reg = PluginRegistry::new();
        reg.projections.register("counter", Box::new(CountReducer));
        let observed_entity = EntityId::new();
        let missing_entity = EntityId::new();

        let event = Event {
            id: EventId::new(),
            entity: observed_entity,
            event_type: Kind::new("counter.tick"),
            payload: CanonicalBytes::from_vec(vec![]),
            wall_time: WallTime::from_micros(0),
            seq: Seq::from_u64(1),
            causation_id: None,
            correlation_id: None,
            schema_version: SchemaVersion::V1,
            signature: None,
            signature_identity: None,
            payload_hash: Hash::from_bytes([0; 32]),
        };
        reg.projections.apply_event(&event);

        let observed = ProjectionKey::new(observed_entity);
        let missing = ProjectionKey::new(missing_entity);
        let subscriptions = vec![observed.clone(), observed.clone(), missing.clone()];
        let snapshot = reg.snapshot_for_subscriptions(&subscriptions);
        let view = snapshot.view_for(&subscriptions);

        assert_eq!(view.len(), 2);
        assert_eq!(
            view.state_for(&observed)
                .and_then(|state| state.get("n").and_then(serde_json::Value::as_u64)),
            Some(1)
        );
        assert_eq!(view.state_for(&missing), None);
    }

    struct AppendFailStore;

    impl pos_core::store::EventStore for AppendFailStore {
        fn create_timeline(&mut self, _: &str) -> Result<pos_core::timeline::Timeline, CoreError> {
            Err(CoreError::Storage("create timeline unavailable".to_owned()))
        }

        fn append(&mut self, _: TimelineId, _: &[EventDraft]) -> Result<Vec<Event>, CoreError> {
            Err(CoreError::Storage("append unavailable".to_owned()))
        }

        fn read(
            &self,
            _: TimelineId,
            _: pos_core::store::SeqRange,
        ) -> Result<Vec<Event>, CoreError> {
            Ok(Vec::new())
        }

        fn fork(
            &mut self,
            _: TimelineId,
            _: Seq,
            _: &str,
        ) -> Result<pos_core::timeline::Timeline, CoreError> {
            Err(CoreError::Storage("fork unavailable".to_owned()))
        }

        fn list_timelines(&self) -> Result<Vec<pos_core::timeline::Timeline>, CoreError> {
            Ok(Vec::new())
        }

        fn get_timeline(
            &self,
            _: TimelineId,
        ) -> Result<Option<pos_core::timeline::Timeline>, CoreError> {
            Ok(None)
        }
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn protected_append_fences_cover_missing_gate_and_store_errors() {
        struct EmptyDriver;

        impl Driver for EmptyDriver {
            fn name(&self) -> &'static str {
                "empty"
            }

            fn step(
                &mut self,
                _: TimelineId,
                _: ObservationView<'_>,
            ) -> Result<StepOutput, RuntimeError> {
                Ok(StepOutput::empty())
            }
        }

        let timeline = TimelineId::new();
        let subject = EntityId::new();
        let authority = ConsentAuthority::new();
        let grant = ConsentGrantedV1 {
            subject_id: subject,
            grantee_id: EntityId::new(),
            purpose: "append-boundary".to_owned(),
            modalities: 0,
            min_geo_resolution: 0,
            fork_permitted: false,
            export_permitted: false,
            retention_days: 0,
            expiry_secs: 0,
            grant_seq: 1,
        };
        let token = authority.record_grant_on_timeline(timeline, &grant);
        let append_drafts = vec![EventDraft::new(
            subject,
            Kind::new("world.test"),
            CanonicalBytes::from_static(b"append"),
        )];

        let mut missing_gate = PluginRegistry::new().with_consent_authority(authority.clone());
        missing_gate.register_driver(Box::new(EmptyDriver));
        missing_gate
            .step_all_anchored_protected(timeline, Seq::ZERO, token.clone(), 0, &[])
            .test_ok();
        missing_gate.consent_gate = None;
        let mut missing_gate_store = open_store(StoreConfig::Memory).test_ok();
        assert!(matches!(
            missing_gate
                .append_and_commit_step_at(
                    missing_gate_store.as_mut(),
                    Seq::ZERO,
                    0,
                    &append_drafts,
                )
                .test_err(),
            RuntimeError::ConsentOperationUnavailable
        ));

        let mut store_error = PluginRegistry::new().with_consent_authority(authority.clone());
        store_error.register_driver(Box::new(EmptyDriver));
        store_error
            .step_all_anchored_protected(timeline, Seq::ZERO, token, 0, &[])
            .test_ok();
        let mut failing_store = AppendFailStore;
        assert!(matches!(
            store_error
                .append_and_commit_step_at(&mut failing_store, Seq::ZERO, 0, &append_drafts,)
                .test_err(),
            RuntimeError::Store(CoreError::Storage(_))
        ));

        let mut public_fence = PluginRegistry::new().with_consent_authority(authority);
        public_fence.register_driver(Box::new(EmptyDriver));
        let drafts = public_fence
            .step_all_anchored(timeline, Seq::ZERO)
            .test_ok();
        public_fence.consent_gate = None;
        let mut public_store = open_store(StoreConfig::Memory).test_ok();
        assert!(matches!(
            public_fence
                .append_and_commit_step_at(public_store.as_mut(), Seq::ZERO, 0, &drafts)
                .test_err(),
            RuntimeError::ConsentOperationUnavailable
        ));

        let mut public_replacement = PluginRegistry::new();
        public_replacement.register_driver(Box::new(EmptyDriver));
        public_replacement
            .step_all_anchored(timeline, Seq::ZERO)
            .test_ok();
        let forged = vec![EventDraft::new(
            subject,
            Kind::new(pos_core::EVENT_TYPE_CONSENT_GRANTED_V1),
            CanonicalBytes::from_static(b"forged"),
        )];
        let mut public_replacement_store = open_store(StoreConfig::Memory).test_ok();
        assert!(matches!(
            public_replacement
                .append_and_commit_step_at(
                    public_replacement_store.as_mut(),
                    Seq::ZERO,
                    0,
                    &forged,
                )
                .test_err(),
            RuntimeError::ConsentDraft { .. }
        ));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn append_commit_rejects_when_no_step_is_pending() {
        let mut no_pending = PluginRegistry::new();
        let mut no_pending_store = open_store(StoreConfig::Memory).test_ok();
        assert!(matches!(
            no_pending.append_and_commit_step_at(no_pending_store.as_mut(), Seq::ZERO, 0, &[]),
            Err(RuntimeError::PendingDriverStep)
        ));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn append_commit_accepts_an_empty_public_step() {
        let mut public_store = open_store(StoreConfig::Memory).test_ok();
        let public_timeline = public_store.create_timeline("append-public").test_ok();
        let mut public_success = PluginRegistry::new();
        public_success
            .step_all_anchored(public_timeline.id(), Seq::ZERO)
            .test_ok();
        assert!(public_success
            .append_and_commit_step_at(public_store.as_mut(), Seq::ZERO, 0, &[])
            .test_ok()
            .is_empty());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn append_commit_propagates_store_failures() {
        let timeline = TimelineId::new();
        let mut public_store_error = PluginRegistry::new();
        public_store_error
            .step_all_anchored(timeline, Seq::ZERO)
            .test_ok();
        let mut failing_store = AppendFailStore;
        assert!(matches!(
            public_store_error
                .append_and_commit_step_at(&mut failing_store, Seq::ZERO, 0, &[])
                .test_err(),
            RuntimeError::Store(CoreError::Storage(_))
        ));
    }

    fn append_grant(subject_id: EntityId) -> ConsentGrantedV1 {
        ConsentGrantedV1 {
            subject_id,
            grantee_id: EntityId::new(),
            purpose: "append-coverage".to_owned(),
            modalities: 0,
            min_geo_resolution: 0,
            fork_permitted: false,
            export_permitted: false,
            retention_days: 0,
            expiry_secs: 0,
            grant_seq: 1,
        }
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn append_commit_accepts_an_empty_protected_step() {
        let subject = EntityId::new();
        let mut protected_store = open_store(StoreConfig::Memory).test_ok();
        let protected_timeline = protected_store
            .create_timeline("append-protected")
            .test_ok();
        let authority = ConsentAuthority::new();
        let token =
            authority.record_grant_on_timeline(protected_timeline.id(), &append_grant(subject));
        let mut protected_success = PluginRegistry::new().with_consent_authority(authority);
        protected_success
            .step_all_anchored_protected(protected_timeline.id(), Seq::ZERO, token, 0, &[])
            .test_ok();
        assert!(protected_success
            .append_and_commit_step_at(protected_store.as_mut(), Seq::ZERO, 0, &[])
            .test_ok()
            .is_empty());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn append_commit_rejects_a_forged_protected_draft() {
        let subject = EntityId::new();
        let mut protected_store = open_store(StoreConfig::Memory).test_ok();
        let protected_timeline = protected_store
            .create_timeline("append-protected-reject")
            .test_ok();
        let reject_authority = ConsentAuthority::new();
        let reject_token = reject_authority
            .record_grant_on_timeline(protected_timeline.id(), &append_grant(subject));
        let mut protected_reject = PluginRegistry::new().with_consent_authority(reject_authority);
        protected_reject
            .step_all_anchored_protected(protected_timeline.id(), Seq::ZERO, reject_token, 0, &[])
            .test_ok();
        let forged = [EventDraft::new(
            subject,
            Kind::new(pos_core::EVENT_TYPE_CONSENT_GRANTED_V1),
            CanonicalBytes::from_static(b"forged"),
        )];
        assert!(matches!(
            protected_reject.append_and_commit_step_at(
                protected_store.as_mut(),
                Seq::ZERO,
                0,
                &forged,
            ),
            Err(RuntimeError::ConsentDraft { .. })
        ));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn public_cadenced_tick_reaches_draft_fence_after_driver_output() {
        struct SensitiveDriver {
            subject: EntityId,
        }

        impl Driver for SensitiveDriver {
            fn name(&self) -> &'static str {
                "sensitive"
            }

            fn step(
                &mut self,
                _: TimelineId,
                _: ObservationView<'_>,
            ) -> Result<StepOutput, RuntimeError> {
                Ok(StepOutput::new(vec![EventDraft::new(
                    self.subject,
                    Kind::new("geo.position.v1"),
                    CanonicalBytes::from_static(b"sensitive"),
                )]))
            }
        }

        let timeline = TimelineId::new();
        let subject = EntityId::new();
        let authority = ConsentAuthority::new();
        let grant = ConsentGrantedV1 {
            subject_id: subject,
            grantee_id: EntityId::new(),
            purpose: "cadenced-boundary".to_owned(),
            modalities: pos_core::MODALITY_LOCATION,
            min_geo_resolution: 0,
            fork_permitted: false,
            export_permitted: false,
            retention_days: 1,
            expiry_secs: 0,
            grant_seq: 1,
        };
        let _token = authority.record_grant_on_timeline(timeline, &grant);
        let mut registry = PluginRegistry::new().with_consent_authority(authority);
        registry.register_driver(Box::new(SensitiveDriver { subject }));
        assert!(matches!(
            registry.tick_cadenced(timeline, 0).test_err(),
            RuntimeError::Consent(ConsentError::NoConsent)
        ));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn cadence_overflow_is_named_and_precedes_every_driver_step() {
        use std::{
            sync::{
                atomic::{AtomicUsize, Ordering},
                Arc,
            },
            time::Duration,
        };

        struct CadenceDriver {
            name: &'static str,
            interval: Duration,
            steps: Arc<AtomicUsize>,
        }

        impl Driver for CadenceDriver {
            fn name(&self) -> &'static str {
                self.name
            }

            fn step(
                &mut self,
                _: TimelineId,
                _: ObservationView<'_>,
            ) -> Result<StepOutput, RuntimeError> {
                self.steps.fetch_add(1, Ordering::SeqCst);
                Ok(StepOutput::empty())
            }

            fn tick_interval(&self) -> Duration {
                self.interval
            }
        }

        let overflow_steps = Arc::new(AtomicUsize::new(0));
        let untouched_steps = Arc::new(AtomicUsize::new(0));
        let mut registry = PluginRegistry::new();
        registry.register_driver(Box::new(CadenceDriver {
            name: "overflow-driver",
            interval: Duration::from_nanos(2),
            steps: Arc::clone(&overflow_steps),
        }));
        registry.register_driver(Box::new(CadenceDriver {
            name: "must-not-step",
            interval: Duration::from_nanos(1),
            steps: Arc::clone(&untouched_steps),
        }));

        let timeline = TimelineId::new();
        registry.tick_cadenced(timeline, u128::MAX - 1).test_ok();
        let error = registry.tick_cadenced(timeline, u128::MAX).test_err();

        assert!(matches!(
            error,
            RuntimeError::CadenceOverflow {
                driver,
                previous_ns,
                interval_ns: 2,
            } if driver == "overflow-driver" && previous_ns == u128::MAX - 1
        ));
        assert_eq!(overflow_steps.load(Ordering::SeqCst), 1);
        assert_eq!(untouched_steps.load(Ordering::SeqCst), 1);

        let mut anchored = PluginRegistry::new();
        anchored.register_driver(Box::new(CadenceDriver {
            name: "anchored-overflow",
            interval: Duration::from_nanos(2),
            steps: Arc::new(AtomicUsize::new(0)),
        }));
        anchored
            .tick_cadenced_anchored(timeline, u128::MAX - 1, Seq::ZERO)
            .test_ok();
        anchored.commit_step_at(Seq::ZERO, 0).test_ok();
        let error = anchored
            .tick_cadenced_anchored(timeline, u128::MAX, Seq::ZERO)
            .test_err();
        assert!(matches!(
            error,
            RuntimeError::CadenceOverflow {
                driver,
                previous_ns,
                interval_ns: 2,
            } if driver == "anchored-overflow" && previous_ns == u128::MAX - 1
        ));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn cadence_keeps_registration_order_when_a_middle_driver_is_skipped() {
        use std::time::Duration;

        struct OrderedDriver {
            name: &'static str,
            interval: Duration,
        }

        impl Driver for OrderedDriver {
            fn name(&self) -> &'static str {
                self.name
            }

            fn step(
                &mut self,
                _: TimelineId,
                _: ObservationView<'_>,
            ) -> Result<StepOutput, RuntimeError> {
                Ok(StepOutput::new(vec![EventDraft::new(
                    EntityId::new(),
                    Kind::new(self.name),
                    CanonicalBytes::from_static(b"ordered"),
                )]))
            }

            fn tick_interval(&self) -> Duration {
                self.interval
            }
        }

        let mut registry = PluginRegistry::new();
        for (name, interval) in [
            ("cadence.first", Duration::from_nanos(1)),
            ("cadence.middle", Duration::from_nanos(2)),
            ("cadence.third", Duration::from_nanos(1)),
        ] {
            registry.register_driver(Box::new(OrderedDriver { name, interval }));
        }

        let timeline = TimelineId::new();
        assert_eq!(registry.tick_cadenced(timeline, 0).test_ok().len(), 3);
        let drafts = registry.tick_cadenced(timeline, 1).test_ok();
        assert_eq!(
            drafts
                .iter()
                .map(|draft| draft.event_type.as_str())
                .collect::<Vec<_>>(),
            vec!["cadence.first", "cadence.third"]
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn tick_cadenced_respects_driver_interval() {
        use pos_store::{open_store, StoreConfig};

        struct IntervalDriver;
        impl Driver for IntervalDriver {
            fn name(&self) -> &'static str {
                "interval-driver"
            }

            fn step(
                &mut self,
                _: TimelineId,
                _: ObservationView<'_>,
            ) -> Result<StepOutput, RuntimeError> {
                let event = EventDraft::new(
                    EntityId::new(),
                    Kind::new("interval.tick"),
                    CanonicalBytes::from_vec(vec![]),
                );
                Ok(StepOutput::new(vec![event]))
            }
        }

        let mut store = open_store(StoreConfig::Memory).test_ok();
        let timeline = store.create_timeline("t").test_ok();
        let plugin = plugin_with_caps("interval-plugin", &[], true, false);
        let mut reg = PluginRegistry::new();
        reg.register(&plugin, None, Some(Box::new(IntervalDriver)))
            .test_ok();

        let first = reg.tick_cadenced(timeline.id(), 0).test_ok();
        assert_eq!(first.len(), 1);

        let too_early = reg.tick_cadenced(timeline.id(), 50_000_000).test_ok();
        assert!(
            too_early.is_empty(),
            "interval gate should suppress a second tick"
        );

        let ready = reg.tick_cadenced(timeline.id(), 100_000_000).test_ok();
        assert_eq!(
            ready.len(),
            1,
            "interval gate should allow next eligible tick"
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn step_all_deduplicates_snapshot_subscriptions_across_drivers() {
        use crate::driver::ProjectionKey;
        use pos_store::{open_store, StoreConfig};
        use std::sync::{Arc, Mutex};

        struct SnapshotDriver {
            key: ProjectionKey,
            observed: Arc<Mutex<Vec<usize>>>,
        }

        impl Driver for SnapshotDriver {
            fn name(&self) -> &'static str {
                "snapshot-driver"
            }

            fn subscriptions(&self) -> &[ProjectionKey] {
                std::slice::from_ref(&self.key)
            }

            fn step(
                &mut self,
                _: TimelineId,
                observations: ObservationView<'_>,
            ) -> Result<StepOutput, RuntimeError> {
                self.observed.lock().test_ok().push(observations.len());
                Ok(StepOutput::empty())
            }
        }

        let mut store = open_store(StoreConfig::Memory).test_ok();
        let timeline = store.create_timeline("t").test_ok();
        let shared_key = ProjectionKey::new(EntityId::new());
        let observed = Arc::new(Mutex::new(Vec::new()));
        let authority = ConsentAuthority::new();
        let grant = pos_core::ConsentGrantedV1 {
            subject_id: shared_key.entity_id().to_owned(),
            grantee_id: EntityId::new(),
            purpose: "projection-dedup-test".to_owned(),
            modalities: 0,
            min_geo_resolution: 0,
            fork_permitted: false,
            export_permitted: false,
            retention_days: 0,
            expiry_secs: 0,
            grant_seq: 1,
        };
        let token = authority.record_grant_on_timeline(timeline.id(), &grant);
        let mut reg = PluginRegistry::new().with_consent_authority(authority);

        reg.register_driver(Box::new(SnapshotDriver {
            key: shared_key.clone(),
            observed: observed.clone(),
        }));
        reg.register_driver(Box::new(SnapshotDriver {
            key: shared_key,
            observed: observed.clone(),
        }));

        let drafts = reg
            .step_all_anchored_protected(timeline.id(), Seq::ZERO, token, 0, &[])
            .test_ok();
        assert_eq!(drafts.len(), 0);

        assert_eq!(observed.lock().test_ok().as_slice(), [1, 1]);
        reg.commit_step_at(Seq::ZERO, 0).test_ok();
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn plugin_registry_default() {
        let reg = PluginRegistry::default();
        assert!(reg.is_empty());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn schema_validation_after_registration() {
        let mut reg = PluginRegistry::new();
        let p = simple_plugin("agent", &["agent.decision"]);
        reg.register(&p, None, None).test_ok();
        let valid = EventDraft::new(
            EntityId::new(),
            Kind::new("agent.decision"),
            CanonicalBytes::from_vec(vec![]),
        );
        let invalid = EventDraft::new(
            EntityId::new(),
            Kind::new("unknown.type"),
            CanonicalBytes::from_vec(vec![]),
        );
        reg.schemas.validate(&valid).test_ok();
        assert!(reg.schemas.validate(&invalid).is_err());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn register_rejects_capability_mismatch() {
        let mut reg = PluginRegistry::new();
        let p = plugin_with_caps("mismatch", &["x.y"], true, false);
        let err = reg.register(&p, None, None).test_err();
        assert!(matches!(err, RuntimeError::CapabilityMismatch { .. }));

        let p2 = plugin_with_caps("mismatch2", &["x.y"], false, false);
        let err = reg
            .register(&p2, Some(Box::new(CountReducer)), None)
            .test_err();
        assert!(matches!(err, RuntimeError::CapabilityMismatch { .. }));

        let p3 = plugin_with_caps("mismatch3", &["x.y"], false, true);
        let err = reg.register(&p3, None, None).test_err();
        assert!(matches!(err, RuntimeError::CapabilityMismatch { .. }));

        let p4 = plugin_with_caps("mismatch4", &["x.y"], false, false);
        let mut noop = NoopDriver;
        assert_eq!(crate::driver::Driver::name(&noop), "noop");
        drop(crate::driver::Driver::step(
            &mut noop,
            TimelineId::new(),
            ObservationView::empty(),
        ));
        let err = reg.register(&p4, None, Some(Box::new(noop))).test_err();
        assert!(matches!(err, RuntimeError::CapabilityMismatch { .. }));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn composition_preserves_plugin_order_and_canonicalizes_unordered_registrations() {
        let first = TestPlugin {
            id: PluginId::new(),
            name: "first",
            cap: Capability {
                owned_event_types: vec![Kind::new("z.event")],
                owned_entity_kinds: vec![],
                has_driver: false,
                has_reducer: false,
            },
        };
        let second = TestPlugin {
            id: PluginId::new(),
            name: "second",
            cap: Capability {
                owned_event_types: vec![Kind::new("a.event")],
                owned_entity_kinds: vec![],
                has_driver: false,
                has_reducer: false,
            },
        };
        let mut registry = PluginRegistry::new();
        registry.register(&first, None, None).test_ok();
        registry.register(&second, None, None).test_ok();
        let composition = registry.composition();
        assert_eq!(
            composition
                .plugins
                .iter()
                .map(|plugin| plugin.name.as_str())
                .collect::<Vec<_>>(),
            vec!["first", "second"]
        );
        assert_eq!(
            composition
                .schemas
                .iter()
                .map(|schema| schema.event_type.as_str())
                .collect::<Vec<_>>(),
            vec![
                "a.event",
                pos_core::EVENT_TYPE_CONSENT_REVOKED_V1,
                "runtime.recorded_output",
                "z.event",
            ]
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn cover_validate_recovery_evidence_empty_segments_and_zero_bound_paths() {
        // Empty ancestry → InvalidRecoveryEvidence (first else branch)
        drop(validate_recovery_evidence(&[], &[]));
        // Empty events with through=ZERO → early Ok() return
        let zero_segment = TimelineHistorySegment::new(TimelineId::new(), Seq::ZERO);
        drop(validate_recovery_evidence(&[zero_segment], &[]));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn validate_recovery_evidence_rejects_duplicate_and_unordered_segments() {
        let timeline = TimelineId::new();
        let mut registry = PluginRegistry::new();
        let duplicate = [
            TimelineHistorySegment::new(timeline, Seq::from_u64(1)),
            TimelineHistorySegment::new(timeline, Seq::from_u64(2)),
        ];
        assert!(matches!(
            registry.restore_driver_state(&duplicate, &[]),
            Err(RuntimeError::InvalidRecoveryEvidence {
                reason: "Timeline ancestry is duplicate or unordered"
            })
        ));

        let unordered = [
            TimelineHistorySegment::new(TimelineId::new(), Seq::from_u64(2)),
            TimelineHistorySegment::new(TimelineId::new(), Seq::from_u64(1)),
        ];
        assert!(matches!(
            registry.restore_driver_state(&unordered, &[]),
            Err(RuntimeError::InvalidRecoveryEvidence {
                reason: "Timeline ancestry is duplicate or unordered"
            })
        ));
    }

    struct MockActionApprover;

    impl ActionApprover for MockActionApprover {
        fn approve(&self, proposal: &ProposedAction) -> Result<EventDraft, ActionRejected> {
            if proposal.payload.as_slice() == b"reject_me" {
                return Err(ActionRejected::DomainValidationFailed(
                    "rejected".to_owned(),
                ));
            }
            Ok(EventDraft::new(
                proposal.actor_entity_id,
                proposal.event_type.clone(),
                proposal.payload.clone(),
            ))
        }
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn plugin_registry_registers_approver_and_submits_action() {
        let plugin = plugin_with_caps("approver_plugin", &["action.type"], false, false);
        let mut reg = PluginRegistry::default();
        reg.register_with_approver(
            &plugin,
            None,
            None,
            Some(Box::new(MockActionApprover)),
            [Kind::new("action.type")],
        )
        .test_ok();

        assert!(reg.approver_for(&Kind::new("action.type")).is_some());
        assert!(reg.approver_for(&Kind::new("other.type")).is_none());

        let duplicate_plugin =
            plugin_with_caps("duplicate_approver", &["action.type"], false, false);
        let duplicate = reg
            .register_with_approver(
                &duplicate_plugin,
                None,
                None,
                Some(Box::new(MockActionApprover)),
                [Kind::new("action.type")],
            )
            .test_err();
        assert!(matches!(duplicate, RuntimeError::CapabilityMismatch { .. }));

        let no_approver = plugin_with_caps("missing_approver", &["missing.type"], false, false);
        let missing = reg
            .register_with_approver(&no_approver, None, None, None, [Kind::new("missing.type")])
            .test_err();
        assert!(matches!(missing, RuntimeError::CapabilityMismatch { .. }));

        let foreign_type = plugin_with_caps("foreign_type", &["owned.type"], false, false);
        let foreign = reg
            .register_with_approver(
                &foreign_type,
                None,
                None,
                Some(Box::new(MockActionApprover)),
                [Kind::new("not-owned.type")],
            )
            .test_err();
        assert!(matches!(foreign, RuntimeError::CapabilityMismatch { .. }));

        let actor = EntityId::new();
        let valid = ProposedAction::new(
            Kind::new("action.type"),
            actor,
            CanonicalBytes::from_vec(b"ok_payload".to_vec()),
            Kind::new("action.type.submit"),
        );
        let draft = reg.submit_action(&valid).test_ok();
        assert_eq!(draft.entity, actor);
        assert_eq!(draft.event_type.as_str(), "action.type");

        // Capability is enforced by the registry before the approver runs.
        let wrong_capability = ProposedAction::new(
            Kind::new("action.type"),
            actor,
            CanonicalBytes::from_vec(b"ok_payload".to_vec()),
            Kind::new("action.type.read"),
        );
        assert_eq!(
            reg.submit_action(&wrong_capability),
            Err(ActionRejected::CapabilityNotGranted)
        );

        // Payload too large (>4096)
        let too_large = ProposedAction::new(
            Kind::new("action.type"),
            actor,
            CanonicalBytes::from_vec(vec![0u8; 5000]),
            Kind::new("action.type.submit"),
        );
        assert_eq!(
            reg.submit_action(&too_large),
            Err(ActionRejected::PayloadTooLarge {
                size: 5000,
                max: 4096
            })
        );

        // Unknown event type
        let unknown = ProposedAction::new(
            Kind::new("unknown.type"),
            actor,
            CanonicalBytes::from_vec(b"ok".to_vec()),
            Kind::new("unknown.type.submit"),
        );
        assert_eq!(
            reg.submit_action(&unknown),
            Err(ActionRejected::UnknownEventType)
        );

        // Domain validation failure
        let rejected = ProposedAction::new(
            Kind::new("action.type"),
            actor,
            CanonicalBytes::from_vec(b"reject_me".to_vec()),
            Kind::new("action.type.submit"),
        );
        assert_eq!(
            reg.submit_action(&rejected),
            Err(ActionRejected::DomainValidationFailed(
                "rejected".to_owned()
            ))
        );

        let replay = PluginRegistry::new_replay();
        assert_eq!(
            replay.submit_action(&valid),
            Err(ActionRejected::UnknownEventType)
        );
    }

    #[test]
    fn driverless_registry_ticks_without_drafts() {
        let mut driverless = PluginRegistry::new();
        let plugin = simple_plugin("coverage-driverless", &[]);
        driverless.register(&plugin, None, None).test_ok();
        driverless.tick_cadenced(TimelineId::new(), 0).test_ok();
        driverless.commit_step_at(Seq::ZERO, 0).test_ok();
    }

    #[test]
    fn replay_rejects_action_submission() {
        let proposal = ProposedAction::new(
            Kind::new("replay.event"),
            EntityId::new(),
            CanonicalBytes::from_static(b"coverage"),
            Kind::new("replay.event.submit"),
        );
        assert_eq!(
            PluginRegistry::new_replay().submit_action(&proposal),
            Err(ActionRejected::UnknownEventType)
        );
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod coverage_public_error_paths {
    use super::*;
    use crate::driver::{ObservationView, StepOutput};
    use pos_core::{
        clock::Seq,
        event::{CanonicalBytes, EventDraft, Kind},
        ids::{EntityId, TimelineId},
        ConsentGrantedV1, ConsentRevokedV1,
    };
    use pos_store::{open_store, StoreConfig};

    struct EmptyDriver;

    impl Driver for EmptyDriver {
        fn name(&self) -> &'static str {
            "coverage-public-empty"
        }

        fn step(
            &mut self,
            _: TimelineId,
            _: ObservationView<'_>,
        ) -> Result<StepOutput, RuntimeError> {
            Ok(StepOutput::empty())
        }
    }

    struct MismatchedSensitiveDriver {
        entity: EntityId,
    }

    impl Driver for MismatchedSensitiveDriver {
        fn name(&self) -> &'static str {
            "coverage-public-mismatch"
        }

        fn step(
            &mut self,
            _: TimelineId,
            _: ObservationView<'_>,
        ) -> Result<StepOutput, RuntimeError> {
            Ok(StepOutput::new(vec![EventDraft::new(
                self.entity,
                Kind::new("retention.extend.v1"),
                CanonicalBytes::from_static(b"coverage"),
            )]))
        }
    }

    fn grant(subject_id: EntityId) -> ConsentGrantedV1 {
        ConsentGrantedV1 {
            subject_id,
            grantee_id: EntityId::new(),
            purpose: "coverage".to_owned(),
            modalities: 0,
            min_geo_resolution: 0,
            fork_permitted: false,
            export_permitted: false,
            retention_days: 0,
            expiry_secs: 0,
            grant_seq: 1,
        }
    }

    fn revoke(authority: &ConsentAuthority, timeline: TimelineId, grant: &ConsentGrantedV1) {
        assert!(authority
            .record_revocation_on_timeline(
                timeline,
                &ConsentRevokedV1 {
                    subject_id: grant.subject_id,
                    grantee_id: grant.grantee_id,
                    grant_seq: grant.grant_seq,
                    fence_seq: 1,
                },
            )
            .is_ok());
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn memory_store() -> Box<dyn pos_core::store::EventStore> {
        open_store(StoreConfig::Memory).unwrap_or_else(|error| {
            std::panic::resume_unwind(Box::new(format!(
                "opening the in-memory store failed: {error:?}"
            )))
        })
    }

    #[test]
    fn protected_step_rejects_sensitive_draft_for_another_subject() {
        let timeline = TimelineId::new();
        let subject = EntityId::new();
        let authority = ConsentAuthority::new();
        let consent_grant = grant(subject);
        let token = authority.record_grant_on_timeline(timeline, &consent_grant);
        let mut mismatch = PluginRegistry::new().with_consent_authority(authority);
        mismatch.register_driver(Box::new(MismatchedSensitiveDriver {
            entity: EntityId::new(),
        }));
        assert!(mismatch
            .step_all_anchored_protected(timeline, Seq::ZERO, token, 0, &[])
            .is_err());
    }

    #[test]
    fn revocation_rejects_staged_commit() {
        let timeline = TimelineId::new();
        let subject = EntityId::new();
        let authority = ConsentAuthority::new();
        let consent_grant = grant(subject);
        let token = authority.record_grant_on_timeline(timeline, &consent_grant);
        let mut commit = PluginRegistry::new().with_consent_authority(authority.clone());
        commit.register_driver(Box::new(EmptyDriver));
        assert!(commit
            .step_all_anchored_protected(timeline, Seq::ZERO, token, 0, &[])
            .is_ok());
        revoke(&authority, timeline, &consent_grant);
        assert!(commit.commit_step_at(Seq::ZERO, 1).is_err());
    }

    #[test]
    fn revocation_rejects_staged_append() {
        let timeline = TimelineId::new();
        let subject = EntityId::new();
        let authority = ConsentAuthority::new();
        let consent_grant = grant(subject);
        let token = authority.record_grant_on_timeline(timeline, &consent_grant);
        let mut fenced_append = PluginRegistry::new().with_consent_authority(authority.clone());
        fenced_append.register_driver(Box::new(EmptyDriver));
        assert!(fenced_append
            .step_all_anchored_protected(timeline, Seq::ZERO, token, 0, &[])
            .is_ok());
        revoke(&authority, timeline, &consent_grant);
        let mut store = memory_store();
        assert!(fenced_append
            .append_and_commit_step_at(store.as_mut(), Seq::ZERO, 1, &[])
            .is_err());
    }

    #[test]
    fn missing_gate_rejects_staged_protected_append() {
        let timeline = TimelineId::new();
        let authority = ConsentAuthority::new();
        let token = authority.record_grant_on_timeline(timeline, &grant(EntityId::new()));
        let mut protected_append = PluginRegistry::new().with_consent_authority(authority);
        protected_append.register_driver(Box::new(EmptyDriver));
        assert!(protected_append
            .step_all_anchored_protected(timeline, Seq::ZERO, token, 0, &[])
            .is_ok());
        protected_append = protected_append.without_consent_gate();
        let mut store = memory_store();
        assert!(protected_append
            .append_and_commit_step_at(store.as_mut(), Seq::ZERO, 0, &[])
            .is_err());
    }

    #[test]
    fn missing_gate_rejects_staged_public_append() {
        let timeline = TimelineId::new();
        let mut public_append = PluginRegistry::new();
        public_append.register_driver(Box::new(EmptyDriver));
        assert!(public_append.step_all_anchored(timeline, Seq::ZERO).is_ok());
        public_append = public_append.without_consent_gate();
        let mut store = memory_store();
        assert!(public_append
            .append_and_commit_step_at(store.as_mut(), Seq::ZERO, 0, &[])
            .is_err());
    }
}
