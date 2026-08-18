use pos_core::{
    clock::{Seq, WallTime},
    crypto::Hash,
    event::{CanonicalBytes, Event, Kind, SchemaVersion},
    ids::{EntityId, EventId, TimelineId},
};
use pos_runtime::{
    Driver, DriverRecoveryEvidence, ObservationView, PluginRegistry, RuntimeError, StepOutput,
    TimelineHistorySegment,
};
use std::sync::{Arc, Mutex};

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
        payload_hash: Hash::from_bytes([u8::try_from(seq).expect("fixture sequence fits u8"); 32]),
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
                let _ = event.header().seq();
                event.payload().map(|payload| payload.as_slice().to_vec())
            })
            .collect();
        *self.observed.lock().expect("fixture lock") =
            Some((evidence.timeline_segments().to_vec(), payloads));
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
    registry.restore_driver_state(&segments, &events).unwrap();

    let (actual_segments, payloads) = observed.lock().expect("fixture lock").take().unwrap();
    assert_eq!(actual_segments, segments);
    assert_eq!(actual_segments[0].timeline_id(), timeline);
    assert_eq!(actual_segments[0].through(), Seq::from_u64(2));
    assert_eq!(payloads, vec![Some(vec![1]), None]);

    let mut rejected = PluginRegistry::new();
    rejected.register_driver(Box::new(DefaultRecoveryDriver));
    rejected.register_driver(Box::new(RejectingRecoveryDriver));
    assert!(rejected.restore_driver_state(&segments, &events).is_err());
}
