//! ADR-119 registry swap seams (section 4.4): prepare with the primary
//! excluded, install, the registry-side dry run, the swap, the single-entry
//! restore and the prefix check.

use std::sync::{Arc, Mutex, PoisonError};

use pos_core::clock::WallTime;
use pos_core::event::{CanonicalBytes, SchemaVersion};
use pos_core::ids::{EntityId, EventId};

use super::test_ext::TestValueExt;
use super::*;
use crate::community_pin_v1;
use crate::driver::ObservationView;

type Log = Arc<Mutex<Vec<(&'static str, &'static str)>>>;
type Refusal = FallbackSwapRefusalV1;

const WEATHER: &[&str] = &["swap.weather.v1"];
const HEAD: &[&str] = &["swap.head.v1"];
const TAIL: &[&str] = &["swap.tail.v1"];
const OTHER: &[&str] = &["swap.other.v1"];
const SPARE: &[&str] = &["swap.spare.v1"];

struct SwapPlugin {
    id: PluginId,
    name: &'static str,
    owned: &'static [&'static str],
    has_driver: bool,
}

impl SwapPlugin {
    fn new(name: &'static str, owned: &'static [&'static str]) -> Self {
        Self {
            id: PluginId::new(),
            name,
            owned,
            has_driver: true,
        }
    }
}

impl Plugin for SwapPlugin {
    fn id(&self) -> PluginId {
        self.id
    }

    fn name(&self) -> &'static str {
        self.name
    }

    fn capability(&self) -> Capability {
        Capability {
            owned_event_types: self.owned.iter().copied().map(Kind::new).collect(),
            has_driver: self.has_driver,
            ..Capability::default()
        }
    }
}

/// A Driver that logs its restore calls, and can refuse a stage or panic in
/// a commit.
struct SwapDriver {
    name: &'static str,
    log: Log,
    refuse_stage: bool,
    panic_commit: bool,
}

impl SwapDriver {
    fn boxed(name: &'static str, log: &Log) -> Box<dyn Driver> {
        Self::faulty(name, log, false, false)
    }

    fn faulty(name: &'static str, log: &Log, refuse: bool, panic: bool) -> Box<dyn Driver> {
        Box::new(Self {
            name,
            log: Arc::clone(log),
            refuse_stage: refuse,
            panic_commit: panic,
        })
    }

    fn note(&self, call: &'static str) {
        let mut calls = self.log.lock().unwrap_or_else(PoisonError::into_inner);
        calls.push((self.name, call));
    }
}

impl Driver for SwapDriver {
    fn name(&self) -> &'static str {
        self.name
    }

    fn step(&mut self, _: TimelineId, _: ObservationView<'_>) -> Result<StepOutput, RuntimeError> {
        Ok(StepOutput::empty())
    }

    fn stage_restore_from_history(
        &mut self,
        _evidence: &DriverRecoveryEvidence,
    ) -> Result<(), RuntimeError> {
        self.note("stage");
        if self.refuse_stage {
            return Err(RuntimeError::InvalidRecoveryEvidence {
                reason: "the test Driver refuses",
            });
        }
        Ok(())
    }

    fn commit_restore_from_history(&mut self) {
        self.note("commit");
        if self.panic_commit {
            std::panic::resume_unwind(Box::new("the test Driver panics"));
        }
    }

    fn abort_restore_from_history(&mut self) {
        self.note("abort");
    }
}

fn registration(role: &str) -> Result<PluginRegistrationV1, PluginCompositionErrorV1> {
    community_pin_v1(Hash::from_bytes([7; 32]), vec![role.to_owned()])
        .map(|pin| PluginRegistrationV1::new(pin, PluginAvailabilityV1::Available))
}

/// A registry of `head`, `primary` and `tail`, in that registration order.
struct Rig {
    registry: PluginRegistry,
    head: PluginId,
    primary: PluginId,
    tail: PluginId,
    log: Log,
}

impl Rig {
    /// The rig, its Drivers composed non-participant when `compose`.
    fn new(compose: bool) -> Self {
        let head = SwapPlugin::new("head", HEAD);
        let primary = SwapPlugin::new("primary", WEATHER);
        let tail = SwapPlugin::new("tail", TAIL);
        let mut rig = Self {
            registry: PluginRegistry::new(),
            head: head.id,
            primary: primary.id,
            tail: tail.id,
            log: Log::default(),
        };
        rig.register(&head, "role.head").test_ok();
        rig.register(&primary, "role.weather").test_ok();
        rig.register(&tail, "role.tail").test_ok();
        if compose {
            rig.registry.compose_non_participant_drivers().test_ok();
        }
        rig
    }

    fn register(&mut self, plugin: &SwapPlugin, role: &str) -> Result<(), RuntimeError> {
        let driver = SwapDriver::boxed(plugin.name, &self.log);
        self.register_with(plugin, role, driver)
    }

    fn register_with(
        &mut self,
        plugin: &SwapPlugin,
        role: &str,
        driver: Box<dyn Driver>,
    ) -> Result<(), RuntimeError> {
        let driver = plugin.has_driver.then_some(driver);
        self.registry
            .register_pinned_generated(plugin, registration(role)?, None, driver)
    }

    fn prepare(
        &self,
        plugin: &SwapPlugin,
        role: &str,
        replacing: Option<PluginId>,
    ) -> Result<PreparedRegistrationV1, RuntimeError> {
        let driver = SwapDriver::boxed(plugin.name, &self.log);
        let registration = registration(role)?;
        self.registry
            .prepare_pinned_generated_v1(plugin, registration, Some(driver), replacing)
    }

    /// A candidate for the primary's entry, and its prepared registration.
    fn candidate(&self) -> (SwapPlugin, PreparedRegistrationV1) {
        let candidate = SwapPlugin::new("candidate", WEATHER);
        let prepared = self.prepare(&candidate, "role.weather", Some(self.primary));
        (candidate, prepared.test_ok())
    }

    fn calls(&self) -> Vec<(&'static str, &'static str)> {
        let calls = self.log.lock().unwrap_or_else(PoisonError::into_inner);
        calls.clone()
    }

    fn clear_calls(&self) {
        self.log
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();
    }

    fn cursor(&self, plugin: PluginId) -> Option<Seq> {
        self.registry
            .plugins
            .get(&plugin)
            .map(|entry| entry.event_cursor)
    }
}

fn event(seq: u64) -> Event {
    Event {
        id: EventId::new(),
        entity: EntityId::new(),
        event_type: Kind::new("swap.history.v1"),
        payload: CanonicalBytes::from_static(b"history"),
        wall_time: WallTime::from_micros(1),
        seq: Seq::from_u64(seq),
        causation_id: None,
        correlation_id: None,
        schema_version: SchemaVersion::V1,
        signature: None,
        signature_identity: None,
        origin: None,
        payload_hash: Hash::from_bytes([1; 32]),
    }
}

fn history(timeline: TimelineId, through: u64) -> (Vec<TimelineHistorySegment>, Vec<Event>) {
    let segments = vec![TimelineHistorySegment::new(
        timeline,
        Seq::from_u64(through),
    )];
    (segments, (1..=through).map(event).collect())
}

/// The swap refusal of `result`, if it is one.
const fn refusal_of<T>(result: &Result<T, RuntimeError>) -> Option<Refusal> {
    match result {
        Err(RuntimeError::FallbackSwap(refusal)) => Some(*refusal),
        _ => None,
    }
}

fn names(registry: &PluginRegistry) -> Vec<&str> {
    registry.plugin_names().collect()
}

#[test]
fn prepare_excludes_only_the_replaced_primary_from_the_type_and_role_checks() {
    let rig = Rig::new(true);
    let revision = rig.registry.registration_revision;
    let schemas = rig.registry.schemas.len();
    let candidate = SwapPlugin::new("candidate", WEATHER);

    // The primary owns the candidate's types: only its own exclusion helps.
    let unexcluded = rig.prepare(&candidate, "role.candidate", None);
    assert!(matches!(
        unexcluded,
        Err(RuntimeError::Composition(
            PluginCompositionErrorV1::DuplicateEventTypeOwner { .. }
        ))
    ));
    let wrong_primary = rig.prepare(&candidate, "role.candidate", Some(rig.head));
    assert!(matches!(
        wrong_primary,
        Err(RuntimeError::Composition(
            PluginCompositionErrorV1::DuplicateEventTypeOwner { .. }
        ))
    ));

    // The primary holds the candidate's role: only its own exclusion helps.
    let other = SwapPlugin::new("other", OTHER);
    let role_held = rig.prepare(&other, "role.weather", None);
    assert!(matches!(
        role_held,
        Err(RuntimeError::Composition(
            PluginCompositionErrorV1::DuplicateRole { .. }
        ))
    ));
    let sibling_role = rig.prepare(&candidate, "role.head", Some(rig.primary));
    assert!(matches!(
        sibling_role,
        Err(RuntimeError::Composition(
            PluginCompositionErrorV1::DuplicateRole { .. }
        ))
    ));
    let excluded = rig
        .prepare(&other, "role.weather", Some(rig.primary))
        .test_ok();
    assert_eq!(excluded.replacing(), Some(rig.primary));

    let prepared = rig
        .prepare(&candidate, "role.weather", Some(rig.primary))
        .test_ok();
    assert_eq!(prepared.plugin_id(), candidate.id);
    assert_eq!(prepared.replacing(), Some(rig.primary));
    assert_eq!(prepared.version(), "0.1.0");
    let roles = prepared.pin().map(|pin| pin.roles().to_vec());
    assert_eq!(roles, Some(vec!["role.weather".to_owned()]));

    // Preparing never changes the registry.
    assert_eq!(names(&rig.registry), ["head", "primary", "tail"]);
    assert_eq!(rig.registry.registration_revision, revision);
    assert_eq!(rig.registry.schemas.len(), schemas);
}

#[test]
fn prepare_keeps_the_plugin_id_check_and_refuses_the_primary_itself() {
    let rig = Rig::new(true);
    let mut itself = SwapPlugin::new("candidate", WEATHER);
    itself.id = rig.primary;
    let same = rig.prepare(&itself, "role.weather", Some(rig.primary));
    assert_eq!(refusal_of(&same), Some(Refusal::SameAsPrimary));

    let mut twin = SwapPlugin::new("candidate", WEATHER);
    twin.id = rig.tail;
    let duplicate = rig.prepare(&twin, "role.weather", Some(rig.primary));
    assert!(matches!(
        duplicate,
        Err(RuntimeError::DuplicatePlugin { .. })
    ));
}

#[test]
fn install_prepared_installs_fresh_and_refuses_replacing_or_stale() {
    let mut rig = Rig::new(true);
    let extra = SwapPlugin::new("extra", OTHER);
    let spare = SwapPlugin::new("spare", SPARE);
    let first = rig.prepare(&extra, "role.extra", None).test_ok();
    let second = rig.prepare(&spare, "role.spare", None).test_ok();
    rig.registry.install_prepared_v1(first).test_ok();
    assert_eq!(names(&rig.registry), ["head", "primary", "tail", "extra"]);

    // The install of `first` made `second` stale.
    let stale = rig.registry.install_prepared_v1(second);
    assert_eq!(refusal_of(&stale), Some(Refusal::StalePreparation));

    let (_, replacing) = rig.candidate();
    let refused = rig.registry.install_prepared_v1(replacing);
    assert_eq!(refusal_of(&refused), Some(Refusal::NotInstallable));
    assert_eq!(rig.registry.len(), 4);
}

#[test]
fn swap_takes_the_primary_index_and_keeps_every_sibling() {
    let mut rig = Rig::new(true);
    let (segments, events) = history(TimelineId::new(), 2);
    rig.registry
        .restore_driver_state(&segments, &events)
        .test_ok();
    assert!(rig.registry.restored_binding.is_some());
    rig.registry.plugins[&rig.primary].last_tick = Some(41);
    let revision = rig.registry.registration_revision;
    let schemas = rig.registry.schemas.len();

    let (candidate, prepared) = rig.candidate();
    rig.registry.validate_swap_v1(&prepared).test_ok();
    rig.registry.swap_entry_v1(prepared).test_ok();

    assert_eq!(names(&rig.registry), ["head", "candidate", "tail"]);
    assert!(!rig.registry.contains(&rig.primary));
    assert_eq!(rig.registry.plugins.get_index_of(&candidate.id), Some(1));
    let entry = &rig.registry.plugins[&candidate.id];
    assert_eq!(entry.last_tick, Some(41));
    assert_eq!(entry.event_cursor, Seq::ZERO);
    let binding = Some(ScheduledDriverBindingV1::NonParticipant);
    assert_eq!(rig.registry.scheduled_binding(candidate.id), binding);
    assert_eq!(rig.registry.scheduled_binding(rig.primary), None);
    assert_eq!(rig.registry.registration_revision, revision + 1);
    assert_eq!(rig.registry.restored_binding, None);
    assert_eq!(rig.registry.schemas.len(), schemas);
    let facts = rig
        .registry
        .fallback_registry_facts_v1(candidate.id)
        .test_ok();
    assert_eq!(facts.owned_event_types, ["swap.weather.v1"]);

    // The siblings keep their restored cursor and their binding.
    for sibling in [rig.head, rig.tail] {
        assert_eq!(rig.cursor(sibling), Some(Seq::from_u64(2)));
        assert_eq!(rig.registry.scheduled_binding(sibling), binding);
    }
}

#[test]
fn swap_without_a_scheduled_binding_moves_none() {
    let mut rig = Rig::new(false);
    let (candidate, prepared) = rig.candidate();
    rig.registry.swap_entry_v1(prepared).test_ok();
    assert_eq!(names(&rig.registry), ["head", "candidate", "tail"]);
    assert_eq!(rig.registry.scheduled_binding(candidate.id), None);
}

#[test]
fn validate_swap_refuses_every_failed_check_and_changes_nothing() {
    let mut rig = Rig::new(true);
    let other = SwapPlugin::new("other", OTHER);
    let revision = rig.registry.registration_revision;

    let fresh = rig.prepare(&other, "role.other", None).test_ok();
    let refused = rig.registry.validate_swap_v1(&fresh);
    assert_eq!(refusal_of(&refused), Some(Refusal::NotReplacing));

    let unknown = rig
        .prepare(&other, "role.other", Some(PluginId::new()))
        .test_ok();
    let refused = rig.registry.validate_swap_v1(&unknown);
    assert_eq!(refusal_of(&refused), Some(Refusal::UnknownPrimary));

    let differ = rig
        .prepare(&other, "role.other", Some(rig.primary))
        .test_ok();
    let refused = rig.registry.validate_swap_v1(&differ);
    assert_eq!(refusal_of(&refused), Some(Refusal::OwnedTypesDiffer));
    let refused = rig.registry.swap_entry_v1(differ);
    assert_eq!(refusal_of(&refused), Some(Refusal::OwnedTypesDiffer));
    assert_eq!(names(&rig.registry), ["head", "primary", "tail"]);
    assert_eq!(rig.registry.registration_revision, revision);

    let (_, prepared) = rig.candidate();
    rig.registry.run_mode = RunMode::Replay;
    let replay = rig.registry.validate_swap_v1(&prepared);
    assert!(matches!(replay, Err(RuntimeError::ModeMismatch { .. })));
    rig.registry.run_mode = RunMode::Live;

    rig.registry.poisoned_driver = Some(String::from("poisoned"));
    let poisoned = rig.registry.validate_swap_v1(&prepared);
    assert!(matches!(
        poisoned,
        Err(RuntimeError::DriverCommitPanicked { .. })
    ));
    rig.registry.poisoned_driver = None;
    rig.registry.validate_swap_v1(&prepared).test_ok();

    // Any registration after the preparation makes it stale.
    let spare = SwapPlugin::new("spare", SPARE);
    rig.register(&spare, "role.spare").test_ok();
    let stale = rig.registry.swap_entry_v1(prepared);
    assert_eq!(refusal_of(&stale), Some(Refusal::StalePreparation));
    assert!(rig.registry.contains(&rig.primary));
}

#[test]
fn restore_entry_restores_only_the_named_entry() {
    let mut rig = Rig::new(true);
    let (candidate, prepared) = rig.candidate();
    rig.registry.swap_entry_v1(prepared).test_ok();
    rig.clear_calls();

    let (segments, events) = history(TimelineId::new(), 3);
    rig.registry
        .restore_entry_from_history_v1(candidate.id, &segments, &events)
        .test_ok();
    assert_eq!(
        rig.calls(),
        [("candidate", "stage"), ("candidate", "commit")]
    );
    let entry = &rig.registry.plugins[&candidate.id];
    assert_eq!(entry.event_cursor, Seq::from_u64(3));
    assert!(entry.pass_state.carried.is_empty());
    assert_ne!(entry.pass_state.history, HistoryInputV1::None);
    assert_eq!(entry.chain, StepChainV1::Lookup);
    assert_eq!(rig.registry.restored_binding, None);
    for sibling in [rig.head, rig.tail] {
        assert_eq!(rig.cursor(sibling), Some(Seq::ZERO));
    }
}

#[test]
fn restore_entry_refuses_before_any_driver_call() {
    let mut rig = Rig::new(true);
    let (segments, events) = history(TimelineId::new(), 2);

    rig.registry.run_mode = RunMode::Replay;
    let replay = rig
        .registry
        .restore_entry_from_history_v1(rig.primary, &segments, &events);
    assert!(matches!(replay, Err(RuntimeError::ModeMismatch { .. })));
    rig.registry.run_mode = RunMode::Live;

    rig.registry.poisoned_driver = Some(String::from("poisoned"));
    let poisoned = rig
        .registry
        .restore_entry_from_history_v1(rig.primary, &segments, &events);
    assert!(matches!(
        poisoned,
        Err(RuntimeError::DriverCommitPanicked { .. })
    ));
    rig.registry.poisoned_driver = None;

    let invalid = rig
        .registry
        .restore_entry_from_history_v1(rig.primary, &[], &events);
    assert!(matches!(
        invalid,
        Err(RuntimeError::InvalidRecoveryEvidence { .. })
    ));
    let unknown = rig
        .registry
        .restore_entry_from_history_v1(PluginId::new(), &segments, &events);
    assert!(matches!(unknown, Err(RuntimeError::NoDriver { .. })));
    assert!(rig.calls().is_empty());
    assert_eq!(rig.cursor(rig.primary), Some(Seq::ZERO));
}

#[test]
fn restore_entry_aborts_a_refused_stage_and_poisons_on_a_commit_panic() {
    let mut rig = Rig::new(true);
    let (segments, events) = history(TimelineId::new(), 2);
    let staller = SwapPlugin::new("staller", OTHER);
    let crasher = SwapPlugin::new("crasher", SPARE);
    let stage_fault = SwapDriver::faulty(staller.name, &rig.log, true, false);
    let commit_fault = SwapDriver::faulty(crasher.name, &rig.log, false, true);
    let registered = [
        rig.register_with(&staller, "role.staller", stage_fault),
        rig.register_with(&crasher, "role.crasher", commit_fault),
    ];
    assert!(registered.iter().all(Result::is_ok));

    let refused = rig
        .registry
        .restore_entry_from_history_v1(staller.id, &segments, &events);
    assert!(matches!(
        refused,
        Err(RuntimeError::InvalidRecoveryEvidence {
            reason: "the test Driver refuses"
        })
    ));
    assert_eq!(rig.calls(), [("staller", "stage"), ("staller", "abort")]);
    assert_eq!(rig.cursor(staller.id), Some(Seq::ZERO));
    assert_eq!(rig.registry.poisoned_driver, None);

    let panicked = rig
        .registry
        .restore_entry_from_history_v1(crasher.id, &segments, &events);
    assert!(matches!(
        panicked,
        Err(RuntimeError::DriverRestorePanicked { ref name }) if name == "crasher"
    ));
    let poisoned = rig.registry.poisoned_driver.as_deref();
    assert_eq!(poisoned, Some("crasher"));
}

#[test]
fn restore_entry_of_a_driverless_entry_resets_its_pass_state() {
    let mut rig = Rig::new(true);
    let mut quiet = SwapPlugin::new("quiet", OTHER);
    quiet.has_driver = false;
    rig.register(&quiet, "role.quiet").test_ok();
    let (segments, events) = history(TimelineId::new(), 2);
    rig.registry
        .restore_entry_from_history_v1(quiet.id, &segments, &events)
        .test_ok();
    assert_eq!(rig.cursor(quiet.id), Some(Seq::from_u64(2)));
    assert!(rig.calls().is_empty());
}

#[test]
fn the_prefix_check_is_the_restore_check() {
    let timeline = TimelineId::new();
    let (segments, events) = history(timeline, 3);
    let whole = PluginRegistry::validate_recovery_prefix_v1(&segments, &events);
    assert!(whole.is_ok());
    let nothing = PluginRegistry::validate_recovery_prefix_v1(&history(timeline, 0).0, &[]);
    assert!(nothing.is_ok());
    let empty = PluginRegistry::validate_recovery_prefix_v1(&[], &events);
    assert!(matches!(
        empty,
        Err(RuntimeError::InvalidRecoveryEvidence { .. })
    ));
    let gap = [event(1), event(3)];
    let short = PluginRegistry::validate_recovery_prefix_v1(&segments, &gap);
    assert!(matches!(
        short,
        Err(RuntimeError::InvalidRecoveryEvidence { .. })
    ));
}

fn copied<T: Clone>(value: &T) -> T {
    value.clone()
}

#[test]
fn every_refusal_renders_distinctly_and_converts_transparently() {
    let refusals = [
        Refusal::SameAsPrimary,
        Refusal::NotReplacing,
        Refusal::NotInstallable,
        Refusal::StalePreparation,
        Refusal::UnknownPrimary,
        Refusal::OwnedTypesDiffer,
        Refusal::CapacityUnavailable,
        Refusal::CandidateRegistered,
    ];
    let mut rendered: Vec<String> = Vec::new();
    for refusal in refusals {
        let message = refusal.to_string();
        assert!(!message.is_empty());
        assert!(!rendered.contains(&message), "{message}");
        assert_eq!(RuntimeError::from(refusal).to_string(), message);
        assert_eq!(copied(&refusal), refusal);
        assert!(!format!("{refusal:?}").is_empty());
        rendered.push(message);
    }
}
