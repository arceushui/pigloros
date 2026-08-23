use pos_core::{
    clock::{Seq, WallTime},
    crypto::Hash,
    event::{CanonicalBytes, Event, Kind, SchemaVersion},
    ids::{EntityId, EventId, PluginId, TimelineId},
    Capability, Plugin,
};
use pos_runtime::{
    Driver, DriverRecoveryEvidence, ObservationView, PluginRegistry, ProjectionKey, RuntimeError,
    StepOutput, TimelineHistorySegment,
};
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
                "unexpected runtime fixture error: {error:?}"
            )))
        })
    }
}

impl<T> TestValueExt<T> for Option<T> {
    fn test_ok(self) -> T {
        self.unwrap_or_else(|| std::panic::resume_unwind(Box::new("missing runtime fixture value")))
    }
}

trait TestErrorExt<T, E> {
    fn test_err(self) -> E;
}

impl<T: std::fmt::Debug, E> TestErrorExt<T, E> for Result<T, E> {
    fn test_err(self) -> E {
        match self {
            Ok(value) => std::panic::resume_unwind(Box::new(format!(
                "unexpected successful runtime fixture value: {value:?}"
            ))),
            Err(error) => error,
        }
    }
}

fn event(seq: u64, entity: EntityId, event_type: &str, payload: Vec<u8>) -> Event {
    Event {
        id: EventId::new(),
        entity,
        event_type: Kind::new(event_type),
        payload: CanonicalBytes::from_vec(payload),
        wall_time: WallTime::from_micros(seq),
        seq: Seq::from_u64(seq),
        causation_id: None,
        correlation_id: None,
        schema_version: SchemaVersion::V1,
        signature: None,
        payload_hash: Hash::from_bytes([u8::try_from(seq).test_ok(); 32]),
    }
}

struct DefaultRecoveryDriver;

type ObservedEvidence = (Vec<TimelineHistorySegment>, Vec<Option<Vec<u8>>>);

impl Driver for DefaultRecoveryDriver {
    fn name(&self) -> &'static str {
        "default-recovery"
    }

    fn step(&mut self, _: TimelineId, _: ObservationView<'_>) -> Result<StepOutput, RuntimeError> {
        Ok(StepOutput::empty())
    }
}

struct MetadataOnlyPlugin {
    id: PluginId,
}

impl Plugin for MetadataOnlyPlugin {
    fn id(&self) -> PluginId {
        self.id
    }

    fn name(&self) -> &'static str {
        "metadata-only"
    }

    fn capability(&self) -> Capability {
        Capability::default()
    }
}

struct InspectingRecoveryDriver {
    selected_entity: EntityId,
    observed: Arc<Mutex<Option<ObservedEvidence>>>,
}

impl Driver for InspectingRecoveryDriver {
    fn name(&self) -> &'static str {
        "inspecting-recovery"
    }

    fn step(&mut self, _: TimelineId, _: ObservationView<'_>) -> Result<StepOutput, RuntimeError> {
        Ok(StepOutput::empty())
    }

    fn needs_recovery_payload(&self, header: &pos_runtime::RecoveryEventHeader) -> bool {
        header.entity() == self.selected_entity && header.event_type().as_str() == "selected"
    }

    fn stage_restore_from_history(
        &mut self,
        evidence: &DriverRecoveryEvidence,
    ) -> Result<(), RuntimeError> {
        let payloads = evidence
            .events()
            .iter()
            .map(|event| {
                let sequence = event.header().seq();
                assert_eq!(sequence, event.header().seq());
                event.payload().map(|payload| payload.as_slice().to_vec())
            })
            .collect();
        *self.observed.lock().test_ok() = Some((evidence.timeline_segments().to_vec(), payloads));
        Ok(())
    }
}

struct RejectingRecoveryDriver;

impl Driver for RejectingRecoveryDriver {
    fn name(&self) -> &'static str {
        "rejecting-recovery"
    }

    fn step(&mut self, _: TimelineId, _: ObservationView<'_>) -> Result<StepOutput, RuntimeError> {
        Ok(StepOutput::empty())
    }

    fn stage_restore_from_history(
        &mut self,
        _: &DriverRecoveryEvidence,
    ) -> Result<(), RuntimeError> {
        Err(RuntimeError::NoDriver {
            name: "rejected recovery".to_owned(),
        })
    }
}

#[test]
fn recovery_evidence_exposes_all_headers_only_selected_payloads_and_is_atomic() {
    let timeline = TimelineId::new();
    let selected = EntityId::new();
    let other = EntityId::new();
    let segments = [TimelineHistorySegment::new(timeline, Seq::from_u64(2))];
    let events = [
        event(1, selected, "selected", vec![1]),
        event(2, other, "unselected", vec![2]),
    ];
    let observed = Arc::new(Mutex::new(None));

    let mut registry = PluginRegistry::new();
    registry.register_driver(Box::new(DefaultRecoveryDriver));
    registry.register_driver(Box::new(InspectingRecoveryDriver {
        selected_entity: selected,
        observed: Arc::clone(&observed),
    }));
    registry.restore_driver_state(&segments, &events).test_ok();

    let (actual_segments, payloads) = observed.lock().test_ok().take().test_ok();
    assert_eq!(actual_segments, segments);
    assert_eq!(actual_segments[0].timeline_id(), timeline);
    assert_eq!(actual_segments[0].through(), Seq::from_u64(2));
    assert_eq!(payloads, vec![Some(vec![1]), None]);

    let mut rejected = PluginRegistry::new();
    rejected.register_driver(Box::new(DefaultRecoveryDriver));
    rejected.register_driver(Box::new(RejectingRecoveryDriver));
    assert!(rejected.restore_driver_state(&segments, &events).is_err());
}

#[test]
fn registry_rejects_incomplete_recovery_before_any_driver_is_staged() {
    let timeline = TimelineId::new();
    let observed = Arc::new(Mutex::new(None));
    let mut registry = PluginRegistry::new();
    registry.register_driver(Box::new(InspectingRecoveryDriver {
        selected_entity: EntityId::new(),
        observed: Arc::clone(&observed),
    }));

    let segments = [TimelineHistorySegment::new(timeline, Seq::from_u64(3))];
    let events = [
        event(1, EntityId::new(), "selected", vec![1]),
        event(3, EntityId::new(), "selected", vec![3]),
    ];
    let error = registry.restore_driver_state(&segments, &events).test_err();

    assert!(matches!(
        error,
        RuntimeError::InvalidRecoveryEvidence { .. }
    ));
    assert!(observed.lock().test_ok().is_none());
}

#[test]
fn registry_recovery_boundary_rejects_each_invalid_source_shape() {
    let first = TimelineId::new();
    let second = TimelineId::new();
    let selected = EntityId::new();
    let cases = [
        (Vec::new(), Vec::new()),
        (
            vec![
                TimelineHistorySegment::new(first, Seq::from_u64(1)),
                TimelineHistorySegment::new(first, Seq::from_u64(2)),
            ],
            vec![event(1, selected, "selected", vec![1])],
        ),
        (
            vec![
                TimelineHistorySegment::new(first, Seq::from_u64(2)),
                TimelineHistorySegment::new(second, Seq::from_u64(1)),
            ],
            vec![
                event(1, selected, "selected", vec![1]),
                event(2, selected, "selected", vec![2]),
            ],
        ),
        (
            vec![TimelineHistorySegment::new(first, Seq::from_u64(1))],
            Vec::new(),
        ),
        (
            vec![TimelineHistorySegment::new(first, Seq::from_u64(1))],
            vec![event(2, selected, "selected", vec![2])],
        ),
        (
            vec![TimelineHistorySegment::new(first, Seq::from_u64(2))],
            vec![event(1, selected, "selected", vec![1])],
        ),
    ];

    for (segments, events) in cases {
        let mut registry = PluginRegistry::new();
        registry.register_driver(Box::new(DefaultRecoveryDriver));
        assert!(matches!(
            registry.restore_driver_state(&segments, &events),
            Err(RuntimeError::InvalidRecoveryEvidence { .. })
        ));
    }
}

#[test]
fn recovery_ignores_driverless_plugins_and_rejects_pending_transactions() {
    let timeline = TimelineId::new();
    let segments = [TimelineHistorySegment::new(timeline, Seq::ZERO)];
    let mut driverless = PluginRegistry::new();
    let plugin = MetadataOnlyPlugin {
        id: PluginId::new(),
    };
    driverless.register(&plugin, None, None).test_ok();
    driverless.restore_driver_state(&segments, &[]).test_ok();

    let mut pending = PluginRegistry::new();
    pending.register_driver(Box::new(DefaultRecoveryDriver));
    pending.step_all_anchored(timeline, Seq::ZERO).test_ok();
    assert!(matches!(
        pending.restore_driver_state(&segments, &[]),
        Err(RuntimeError::PendingDriverStep)
    ));
    pending.abort_step();
}

#[test]
fn scheduler_skips_metadata_only_plugins_and_rejects_cadence_overflow() {
    let timeline = TimelineId::new();
    let mut registry = PluginRegistry::new();
    let plugin = MetadataOnlyPlugin {
        id: PluginId::new(),
    };
    registry.register(&plugin, None, None).test_ok();
    registry.register_driver(Box::new(DefaultRecoveryDriver));
    registry.step_all_anchored(timeline, Seq::ZERO).test_ok();
    registry.commit_step_at(Seq::ZERO, 0).test_ok();
    registry.commit_step_at(Seq::ZERO, 0).test_ok();

    let mut cadenced = PluginRegistry::new();
    cadenced.register_driver(Box::new(CadencedDriver {
        subscriptions: vec![ProjectionKey::new(EntityId::new())],
    }));
    cadenced
        .tick_cadenced_anchored(timeline, u128::MAX, Seq::ZERO)
        .test_ok();
    cadenced.commit_step_at(Seq::ZERO, 0).test_ok();
    assert!(matches!(
        cadenced.tick_cadenced_anchored(timeline, u128::MAX, Seq::ZERO),
        Err(RuntimeError::CadenceOverflow { .. })
    ));
}

struct CadencedDriver {
    subscriptions: Vec<ProjectionKey>,
}

impl Driver for CadencedDriver {
    fn name(&self) -> &'static str {
        "cadenced"
    }

    fn tick_interval(&self) -> Duration {
        Duration::from_nanos(1)
    }

    fn subscriptions(&self) -> &[ProjectionKey] {
        &self.subscriptions
    }

    fn step(&mut self, _: TimelineId, _: ObservationView<'_>) -> Result<StepOutput, RuntimeError> {
        Ok(StepOutput::empty())
    }
}
