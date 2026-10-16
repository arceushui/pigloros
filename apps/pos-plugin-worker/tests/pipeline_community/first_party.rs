//! The first-party twin of the community fixture.
//!
//! The twin is an operator-trusted native Plugin whose Driver commits one fixed Event per pass
//! through the same registry and admission path.
//!
//! The twin implements the same domain contract as the community guest (one owned Event type,
//! one Event per step, for the same entity). It differs only in isolation class, which is the
//! point of the parity cases: ADR-021 decision 7 requires shared semantic and authority
//! contracts, not identical runtime trust.
//!
//! The authority cases (#632) register further first-party Plugins of the same shape, which may
//! own one Event type and emit another. The failure cases (#633) switch a first-party Driver to
//! fail while it stages, and the over-budget case (#634) switches it to stage one more draft.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
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
/// The pin role of the twin.
const ROLE: &str = "first-party-parity";
/// The payload of every Event the twin emits. Parity is semantic, so the community guest's
/// payload bytes are not compared with it.
const PAYLOAD: &[u8] = b"first-party";

/// What one first-party native Plugin owns and its Driver emits.
#[derive(Clone, Copy)]
pub struct Native {
    /// The Plugin and Driver name.
    pub name: &'static str,
    /// The one Event type the Plugin owns.
    pub owned: &'static str,
    /// The Event type of the one draft the Driver emits on every step.
    pub emitted: &'static str,
    /// The role of the Plugin's pin; a registry holds each role once.
    pub role: &'static str,
}

impl Native {
    /// The twin of the community fixture, which emits the one Event type it owns.
    #[must_use]
    pub const fn twin(event_type: &'static str) -> Self {
        Self {
            name: NAME,
            owned: event_type,
            emitted: event_type,
            role: ROLE,
        }
    }
}

/// A native Plugin that owns one Event type and has a Driver.
pub struct TwinPlugin {
    /// The Plugin ID.
    pub id: PluginId,
    /// What the Plugin owns and its Driver emits.
    pub native: Native,
}

impl Plugin for TwinPlugin {
    fn id(&self) -> PluginId {
        self.id
    }

    fn name(&self) -> &'static str {
        self.native.name
    }

    fn capability(&self) -> Capability {
        Capability {
            owned_event_types: vec![Kind::new(self.native.owned)],
            has_driver: true,
            ..Capability::default()
        }
    }
}

/// The twin's Driver: one draft per step, counting its steps.
///
/// It stages two drafts while `burst` is set, and fails while `fail` is set.
pub struct TwinDriver {
    name: &'static str,
    draft: EventDraft,
    steps: Arc<AtomicUsize>,
    fail: Arc<AtomicBool>,
    burst: Arc<AtomicBool>,
}

impl Driver for TwinDriver {
    fn name(&self) -> &'static str {
        self.name
    }

    fn step(&mut self, _: TimelineId, _: ObservationView<'_>) -> Result<StepOutput, RuntimeError> {
        self.steps.fetch_add(1, Ordering::SeqCst);
        if self.fail.load(Ordering::SeqCst) {
            // The native counterpart of a guest trap: the registry turns the unwind into
            // `DriverPanicked`. `resume_unwind` skips the panic hook; `panic!` is denied.
            std::panic::resume_unwind(Box::new("the first-party Driver failed"));
        }
        let drafts = 1 + usize::from(self.burst.load(Ordering::SeqCst));
        Ok(StepOutput::new(vec![self.draft.clone(); drafts]))
    }
}

/// What the test keeps of a registered first-party Driver.
pub struct Switched {
    /// The Driver's step counter.
    pub steps: Arc<AtomicUsize>,
    /// Set to make every later step of the Driver fail.
    pub fail: Arc<AtomicBool>,
    /// Set to make every later step of the Driver stage two drafts instead of one.
    pub burst: Arc<AtomicBool>,
}

/// The entity `text` names, parsed from its ULID text.
///
/// # Errors
/// Returns the parse error of an invalid ULID text.
pub fn entity_of(text: &str) -> BoxResult<EntityId> {
    Ok(serde_json::from_value(serde_json::Value::from(text))?)
}

/// The operator-trusted native pin of a first-party Plugin in `role`.
///
/// # Errors
/// Returns the pin's metadata error for an empty role.
pub fn native_pin(role: &str) -> BoxResult<PluginPinV1> {
    Ok(PluginPinV1::try_new(
        DomainImplementationKindV1::Plugin,
        PluginIsolationV1::OperatorTrustedNative,
        Hash::from_bytes([0x46; 32]),
        vec![role.to_owned()],
    )?)
}

/// Register the twin on the pinned local path and return its step counter.
///
/// The twin owns `event_type` and emits it for `entity`.
///
/// # Errors
/// Returns the registry's registration or profile-composition error.
pub fn register_twin(
    registry: &mut PluginRegistry,
    event_type: &'static str,
    entity: EntityId,
) -> BoxResult<Arc<AtomicUsize>> {
    register_native(registry, Native::twin(event_type), entity)
}

/// Register the first-party Plugin `native` on the pinned local path and return its step counter.
///
/// Its Driver emits for `entity`. It is assigned the non-participant scheduled profile, as
/// `register_community_driver` does for a community Driver.
///
/// # Errors
/// Returns the registry's registration or profile-composition error.
pub fn register_native(
    registry: &mut PluginRegistry,
    native: Native,
    entity: EntityId,
) -> BoxResult<Arc<AtomicUsize>> {
    Ok(register_switched(registry, native, entity)?.steps)
}

/// As [`register_native`], returning the switches that make the Driver fail or burst as well.
///
/// # Errors
/// Returns the registry's registration or profile-composition error.
pub fn register_switched(
    registry: &mut PluginRegistry,
    native: Native,
    entity: EntityId,
) -> BoxResult<Switched> {
    let plugin = TwinPlugin {
        id: PluginId::new(),
        native,
    };
    let switched = Switched {
        steps: Arc::new(AtomicUsize::new(0)),
        fail: Arc::new(AtomicBool::new(false)),
        burst: Arc::new(AtomicBool::new(false)),
    };
    let payload = CanonicalBytes::from_static(PAYLOAD);
    let driver = TwinDriver {
        name: native.name,
        draft: EventDraft::new(entity, Kind::new(native.emitted), payload),
        steps: Arc::clone(&switched.steps),
        fail: Arc::clone(&switched.fail),
        burst: Arc::clone(&switched.burst),
    };
    let available = PluginAvailabilityV1::Available;
    let registration = PluginRegistrationV1::new(native_pin(native.role)?, available);
    let driver: Box<dyn Driver> = Box::new(driver);
    registry.register_pinned_generated(&plugin, registration, None, Some(driver))?;
    let binding = (plugin.id, ScheduledDriverBindingV1::NonParticipant);
    registry.compose_scheduled_profiles(&[binding])?;
    Ok(switched)
}
