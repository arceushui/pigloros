//! The first-party twin of the community fixture.
//!
//! The twin is an operator-trusted native Plugin whose Driver commits one fixed Event per pass
//! through the same registry and admission path.
//!
//! The twin implements the same domain contract as the community guest (one owned Event type,
//! one Event per step, for the same entity). It differs only in isolation class, which is the
//! point of the parity cases: ADR-021 decision 7 requires shared semantic and authority
//! contracts, not identical runtime trust.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use pos_core::{
    CanonicalBytes, Capability, EntityId, EventDraft, Hash, Kind, Plugin, PluginId, TimelineId,
};
use pos_plugin_publisher::test_support::BoxResult;
use pos_runtime::{
    DomainImplementationKindV1, Driver, ObservationView, PluginAvailabilityV1, PluginIsolationV1,
    PluginPinV1, PluginRegistrationV1, PluginRegistry, RuntimeError, ScheduledDriverBindingV1,
    StepOutput,
};

/// The Plugin name of the twin.
pub const NAME: &str = "first-party-twin";
/// The payload of every Event the twin emits. Parity is semantic, so the community guest's
/// payload bytes are not compared with it.
const PAYLOAD: &[u8] = b"first-party";

/// A native Plugin that owns one Event type and has a Driver.
pub struct TwinPlugin {
    /// The Plugin ID.
    pub id: PluginId,
    /// The one Event type the Plugin owns.
    pub event_type: &'static str,
}

impl Plugin for TwinPlugin {
    fn id(&self) -> PluginId {
        self.id
    }

    fn name(&self) -> &'static str {
        NAME
    }

    fn capability(&self) -> Capability {
        Capability {
            owned_event_types: vec![Kind::new(self.event_type)],
            has_driver: true,
            ..Capability::default()
        }
    }
}

/// The twin's Driver: one draft per step, counting its steps.
pub struct TwinDriver {
    draft: EventDraft,
    steps: Arc<AtomicUsize>,
}

impl Driver for TwinDriver {
    fn name(&self) -> &'static str {
        NAME
    }

    fn step(&mut self, _: TimelineId, _: ObservationView<'_>) -> Result<StepOutput, RuntimeError> {
        self.steps.fetch_add(1, Ordering::SeqCst);
        Ok(StepOutput::new(vec![self.draft.clone()]))
    }
}

/// The entity `text` names, parsed from its ULID text.
///
/// # Errors
/// Returns the parse error of an invalid ULID text.
pub fn entity_of(text: &str) -> BoxResult<EntityId> {
    Ok(serde_json::from_value(serde_json::Value::from(text))?)
}

/// The operator-trusted native pin of the twin.
fn native_pin() -> BoxResult<PluginPinV1> {
    Ok(PluginPinV1::try_new(
        DomainImplementationKindV1::Plugin,
        PluginIsolationV1::OperatorTrustedNative,
        Hash::from_bytes([0x46; 32]),
        vec!["first-party-parity".to_owned()],
    )?)
}

/// Register the twin on the pinned local path and return its step counter.
///
/// The twin owns `event_type` and emits for `entity`. It is assigned the non-participant
/// scheduled profile, as `register_community_driver` does for a community Driver.
///
/// # Errors
/// Returns the registry's registration or profile-composition error.
pub fn register_twin(
    registry: &mut PluginRegistry,
    event_type: &'static str,
    entity: EntityId,
) -> BoxResult<Arc<AtomicUsize>> {
    let plugin = TwinPlugin {
        id: PluginId::new(),
        event_type,
    };
    let steps = Arc::new(AtomicUsize::new(0));
    let payload = CanonicalBytes::from_static(PAYLOAD);
    let driver = TwinDriver {
        draft: EventDraft::new(entity, Kind::new(event_type), payload),
        steps: Arc::clone(&steps),
    };
    let available = PluginAvailabilityV1::Available;
    let registration = PluginRegistrationV1::new(native_pin()?, available);
    let driver: Box<dyn Driver> = Box::new(driver);
    registry.register_pinned_generated(&plugin, registration, None, Some(driver))?;
    let binding = (plugin.id, ScheduledDriverBindingV1::NonParticipant);
    registry.compose_scheduled_profiles(&[binding])?;
    Ok(steps)
}
