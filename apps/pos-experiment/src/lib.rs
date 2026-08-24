#![forbid(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]

//! `pos-experiment` — Wave 4 closed experiment host loop.
//!
//! An [`Experiment`] composes plugins and runs them through a closed tick loop,
//! driving drivers, validating event types, appending to the store, and folding
//! projections on each tick until a [`StopCondition`] is met.
#![cfg_attr(all(coverage_nightly, test), feature(coverage_attribute))]

use pos_core::{
    clock::WallTime,
    crypto::Hash,
    event::{EventDraft, Kind},
    ids::EntityId,
    ConsentAuthority, ConsentCapabilityToken, ConsentGate, ReproManifest, Timeline,
};
use pos_runtime::PluginRegistry;
use pos_store::{open_store, StoreConfig};
use std::collections::HashSet;
use std::fmt::{self, Debug, Formatter};
use std::sync::{Arc, Mutex, MutexGuard};

// Experiment hosts may close their own session, but they are not a Gateway
// consent issuer.  Keep this durable lifecycle marker outside the canonical
// `consent.*` namespace so only Gateway APIs can create consent events.
const EXPERIMENT_CONSENT_CLOSED_EVENT_TYPE: &str = pos_core::HOST_CONSENT_CLOSED_EVENT_TYPE;
const EXPERIMENT_CONSENT_TIMELINE_MARKER: &[u8] = b"timeline";
const EXPERIMENT_CONSENT_SUBJECT_MARKER_PREFIX: &[u8] = b"subject:";

fn current_now_secs() -> u64 {
    WallTime::now().as_micros() / 1_000_000
}

fn is_public_event_type(event_type: &Kind) -> bool {
    !pos_core::is_consent_event_type(event_type)
        && event_type.as_str() != EXPERIMENT_CONSENT_CLOSED_EVENT_TYPE
        && !pos_core::is_geographic_event_type(event_type)
        && pos_core::required_modality_for_event(event_type) == 0
        && !event_type.as_str().starts_with("timeline.fork.")
        && !event_type.as_str().starts_with("retention.")
}

fn reject_protected_events(events: &[pos_core::Event]) -> Result<(), ExperimentError> {
    if events
        .iter()
        .any(|event| !is_public_event_type(&event.event_type))
    {
        Err(pos_runtime::RuntimeError::ConsentOperationUnavailable.into())
    } else {
        Ok(())
    }
}

fn reject_protected_history(
    store: &dyn pos_core::store::EventStore,
    timeline: pos_core::ids::TimelineId,
    head: pos_core::clock::Seq,
) -> Result<(), ExperimentError> {
    if head == pos_core::clock::Seq::ZERO {
        return reject_protected_events(&[]);
    }
    store
        .read(
            timeline,
            pos_store::SeqRange::bounded(pos_core::clock::Seq::from_u64(1), head),
        )
        .map_err(ExperimentError::from)
        .and_then(|events| reject_protected_events(&events))
}

pub mod moat_proof;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Stop condition for an experiment run.
#[derive(Clone, Debug)]
pub enum StopCondition {
    /// Run exactly N ticks.
    MaxTicks(u64),
    /// Run until the store reaches N total events.
    MaxEvents(u64),
}

impl StopCondition {
    const fn reached(&self, ticks: u64, total_events: u64) -> bool {
        match self {
            Self::MaxTicks(max) => ticks >= *max,
            Self::MaxEvents(max) => total_events >= *max,
        }
    }
}

/// Configuration for an experiment.
pub struct ExperimentConfig {
    pub name: String,
    pub stop: StopCondition,
    /// Store backend to use.
    pub store_config: StoreConfig,
}

/// Result of a completed experiment run.
pub struct RunResult {
    pub timeline_id: pos_core::ids::TimelineId,
    pub ticks: u64,
    pub total_events: u64,
    timeline_head: u64,
    /// Exported manifest for reproducibility.
    pub manifest: ReproManifest,
    /// Final projection state after all ticks.
    projections: pos_state::ProjectionRegistry,
    consent_gate: Option<Arc<dyn ConsentGate>>,
    protected_token: Option<ConsentCapabilityToken>,
    /// Accurate recipe for re-opening the run's store, when one is known.
    pub store_config: Option<StoreConfig>,
}

impl Debug for RunResult {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RunResult")
            .field("timeline_id", &self.timeline_id)
            .field("ticks", &self.ticks)
            .field("total_events", &self.total_events)
            .field("timeline_head", &self.timeline_head)
            .field("manifest", &self.manifest)
            .field("store_config", &self.store_config)
            .finish_non_exhaustive()
    }
}

/// Host-owned configuration required to execute a reproduction.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReproductionRecipe {
    pub host_id: String,
    pub format_version: u32,
    pub configuration: serde_json::Value,
}

impl ReproductionRecipe {
    #[must_use]
    pub fn new(
        host_id: impl Into<String>,
        format_version: u32,
        configuration: serde_json::Value,
    ) -> Self {
        Self {
            host_id: host_id.into(),
            format_version,
            configuration,
        }
    }
}

/// A host envelope containing kernel provenance and a host-executable recipe.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReproductionManifest {
    pub manifest: ReproManifest,
    pub recipe: ReproductionRecipe,
}

impl RunResult {
    /// Read one subject's projection state using a host-issued consent token.
    ///
    /// The token must be bound to this result's Timeline and requested subject;
    /// the host gate captured at run completion revalidates its current fence.
    ///
    /// # Errors
    /// Returns [`ExperimentError::Runtime`] when the token is absent, stale, or
    /// issued by another host authority.
    pub fn projection_state_for_reducer(
        &self,
        reducer: &str,
        subject: EntityId,
        token: &ConsentCapabilityToken,
        now_secs: u64,
    ) -> Result<Option<pos_core::State>, ExperimentError> {
        let gate = self
            .consent_gate
            .as_ref()
            .ok_or(pos_runtime::RuntimeError::ConsentOperationUnavailable)?;
        self.store_config
            .clone()
            .ok_or(ExperimentError::MissingStoreRecoveryRecipe)
            .and_then(|config| open_store(config).map_err(ExperimentError::from))
            .and_then(|store| {
                store
                    .logical_head(self.timeline_id)
                    .map_err(ExperimentError::from)
            })
            .and_then(|timeline_head| {
                gate.authorize_projection(
                    self.timeline_id,
                    subject,
                    timeline_head.as_u64(),
                    now_secs,
                    token,
                )
                .map_err(|error| map_runtime_error(pos_runtime::RuntimeError::Consent(error)))
            })
            .map(|()| {
                self.projections
                    .state_for_reducer(reducer, &subject)
                    .cloned()
            })
    }

    /// Reopen the store and branch from this result's Timeline at its head.
    ///
    /// A result produced with [`ExperimentSession::with_protected_token`] is
    /// capability-scoped: its token is revalidated at the durable Timeline
    /// head and must carry `fork_permitted`. Results from an explicitly public
    /// run carry no consent capability and are public artifacts; they do not
    /// expose a protected projection through this API.
    ///
    /// # Errors
    /// Returns [`ExperimentError`] if no accurate recovery recipe is available,
    /// the store cannot be opened, or the fork fails.
    pub fn branch(&self, name: &str) -> Result<Timeline, ExperimentError> {
        let store_config = self
            .store_config
            .clone()
            .ok_or(ExperimentError::MissingStoreRecoveryRecipe)?;
        let mut store = open_store(store_config)?;
        let timelines = store.list_timelines()?;
        let timeline = timelines
            .iter()
            .find(|t| t.id() == self.timeline_id)
            .ok_or_else(|| {
                pos_core::CoreError::Storage(format!(
                    "timeline {} not found for branching",
                    self.timeline_id
                ))
            })?;
        let current_head = store.logical_head(timeline.id())?;
        let mut fork_result: Result<Timeline, ExperimentError> =
            Err(pos_runtime::RuntimeError::ConsentOperationUnavailable.into());
        match (self.consent_gate.as_ref(), self.protected_token.as_ref()) {
            (Some(gate), Some(token)) => {
                if !token.fork_permitted() {
                    return Err(pos_runtime::RuntimeError::Consent(
                        pos_core::ConsentError::ForkNotPermitted,
                    )
                    .into());
                }
                let mut append = || {
                    fork_result = store
                        .fork(timeline.id(), current_head, name)
                        .map_err(ExperimentError::from);
                };
                if let Err(error) = gate.with_token_fence(
                    self.timeline_id,
                    token,
                    current_head.as_u64(),
                    current_now_secs(),
                    &mut append,
                ) {
                    return Err(map_runtime_error(pos_runtime::RuntimeError::Consent(error)));
                }
            }
            (Some(_), None) | (None, Some(_)) => {
                return Err(pos_runtime::RuntimeError::ConsentOperationUnavailable.into());
            }
            (None, None) => {
                reject_protected_history(store.as_ref(), timeline.id(), current_head)?;
                fork_result = store
                    .fork(timeline.id(), current_head, name)
                    .map_err(ExperimentError::from);
            }
        }
        fork_result
    }

    /// Consume this result to form a host-executable reproduction manifest.
    ///
    /// Capability-scoped results require a live token with `export_permitted`.
    /// An explicitly public result has no protected capability to export.
    ///
    /// # Errors
    /// Returns [`ExperimentError::Runtime`] when a protected result has no
    /// live export-capable token or its host authority rejects the token.
    pub fn into_reproduction_manifest(
        self,
        recipe: ReproductionRecipe,
    ) -> Result<ReproductionManifest, ExperimentError> {
        let timeline_head = if self.protected_token.is_some() {
            let config = self
                .store_config
                .clone()
                .ok_or(ExperimentError::MissingStoreRecoveryRecipe)?;
            let store = open_store(config)?;
            Some(store.logical_head(self.timeline_id)?.as_u64())
        } else {
            None
        };
        match (self.consent_gate.as_ref(), self.protected_token.as_ref()) {
            (Some(gate), Some(token)) => {
                gate.validate_token(
                    self.timeline_id,
                    token,
                    timeline_head.ok_or(pos_runtime::RuntimeError::ConsentOperationUnavailable)?,
                    current_now_secs(),
                )
                .map_err(pos_runtime::RuntimeError::Consent)?;
                if !token.export_permitted() {
                    return Err(pos_runtime::RuntimeError::Consent(
                        pos_core::ConsentError::ExportNotPermitted,
                    )
                    .into());
                }
            }
            (Some(_), None) | (None, Some(_)) => {
                return Err(pos_runtime::RuntimeError::ConsentOperationUnavailable.into());
            }
            (None, None) => {}
        }
        Ok(ReproductionManifest {
            manifest: self.manifest,
            recipe,
        })
    }
}

/// The closed experiment host loop.
///
/// tick loop: pre-fold → `step_all()` → `validate_batch()` → `append()` → post-fold
pub struct Experiment {
    config: ExperimentConfig,
    registry: PluginRegistry,
    fork_registry_factory: Option<ForkRegistryFactory>,
}

/// A started experiment that owns its live `EventStore` and Timeline.
///
/// A session advances only at completed tick boundaries. Its [`Self::fork`]
/// operation therefore never exposes a partially-applied driver batch.
pub struct ExperimentSession {
    config: ExperimentConfig,
    registry: PluginRegistry,
    parent_composition: pos_runtime::PluginComposition,
    store: SharedEventStore,
    recovery_store_config: Option<StoreConfig>,
    fork_registry_factory: Option<ForkRegistryFactory>,
    timeline: Timeline,
    ticks: u64,
    total_events: u64,
    complete: bool,
    health: SessionHealth,
    boundary: TickBoundaryCoordinator,
    step_mode: Option<StepMode>,
    last_simulation_time_ns: Option<u128>,
    consent_revoked: bool,
    revoked_subjects: HashSet<EntityId>,
    consent_revocation_pending: Option<PendingConsentRevocation>,
    operation_token: Option<ConsentCapabilityToken>,
}

/// Result of one interactive tick-boundary attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TickOutcome {
    /// Persisted Events were folded or driver Events were emitted.
    Advanced {
        /// Events newly folded into projections, regardless of origin.
        folded_events: u64,
        /// Driver Events appended during this boundary.
        emitted_events: u64,
    },
    /// The boundary completed without folding or emitting an Event.
    Quiescent,
    /// The configured stop condition had already been reached.
    Stopped,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SessionHealth {
    Healthy,
    Faulted,
}

#[derive(Clone, Copy, Debug)]
enum PendingConsentRevocation {
    /// Close every capability on the session Timeline.
    Timeline { marker_entity: EntityId },
    /// Fence one capability subject, then persist the session closure marker.
    Subject {
        subject_id: EntityId,
        marker_entity: EntityId,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StepMode {
    AllDrivers,
    Cadenced,
}

impl StepMode {
    const fn name(self) -> &'static str {
        match self {
            Self::AllDrivers => "AllDrivers",
            Self::Cadenced => "Cadenced",
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum StepRequest {
    AllDrivers,
    Cadenced(u128),
}

impl StepRequest {
    const fn mode(self) -> StepMode {
        match self {
            Self::AllDrivers => StepMode::AllDrivers,
            Self::Cadenced(_) => StepMode::Cadenced,
        }
    }

    const fn simulation_time_ns(self) -> Option<u128> {
        match self {
            Self::AllDrivers => None,
            Self::Cadenced(now_ns) => Some(now_ns),
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct TickBoundaryCoordinator {
    folded_through: pos_core::clock::Seq,
}

enum TickAdvance {
    Advanced { folded_events: u64 },
    Quiescent,
}

struct CapturedRange {
    through: pos_core::clock::Seq,
    events: Vec<pos_core::Event>,
    timeline: Timeline,
}

type ForkRegistryFactory =
    Arc<dyn Fn() -> Result<PluginRegistry, pos_runtime::RuntimeError> + Send + Sync>;
type SharedEventStore = Arc<Mutex<Box<dyn pos_core::store::EventStore>>>;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum ExperimentError {
    #[error("runtime error: {0}")]
    Runtime(#[from] pos_runtime::RuntimeError),
    #[error("action rejected: {0}")]
    ActionRejected(#[from] pos_core::ActionRejected),
    #[error("store error: {0}")]
    Store(#[from] pos_core::CoreError),
    #[error("a fresh PluginRegistry factory is required to run a forked experiment session")]
    MissingForkRegistryFactory,
    #[error("the experiment store has no accurate recovery recipe")]
    MissingStoreRecoveryRecipe,
    #[error("the shared experiment EventStore lock is poisoned")]
    SharedStoreLockPoisoned,
    #[error("the fresh PluginRegistry is incompatible with the parent plugin composition")]
    IncompatibleForkRegistry,
    #[error("the experiment session is faulted; rebuild it from persisted Timeline history")]
    SessionFaulted,
    #[error("consent has been revoked at the completed Tick Boundary")]
    ConsentRevokedV1,
    #[error("cadence time regressed from {previous_ns}ns to {requested_ns}ns")]
    CadenceTimeRegressed {
        previous_ns: u128,
        requested_ns: u128,
    },
    #[error("cannot use {requested} stepping after session selected {active} stepping")]
    StepModeMismatch {
        active: &'static str,
        requested: &'static str,
    },
}

fn map_runtime_error(error: pos_runtime::RuntimeError) -> ExperimentError {
    match error {
        pos_runtime::RuntimeError::Store(error) => ExperimentError::Store(error),
        error => ExperimentError::Runtime(error),
    }
}

// ---------------------------------------------------------------------------
// Private helpers: shared tick and completion pipeline
// ---------------------------------------------------------------------------

fn capture_pending_range(
    store: &dyn pos_core::store::EventStore,
    timeline_id: pos_core::ids::TimelineId,
    folded_through: pos_core::clock::Seq,
) -> Result<CapturedRange, ExperimentError> {
    let through = store.logical_head(timeline_id)?;
    if through < folded_through {
        return Err(pos_core::CoreError::Storage(format!(
            "logical Timeline head {} precedes fold cursor {}",
            through.as_u64(),
            folded_through.as_u64()
        ))
        .into());
    }
    let timeline = store
        .get_timeline(timeline_id)?
        .ok_or(pos_core::CoreError::TimelineNotFound(timeline_id))?;
    let events = if through == folded_through {
        Vec::new()
    } else {
        let from = pos_core::clock::Seq::from_u64(folded_through.as_u64() + 1);
        store.read(timeline_id, pos_store::SeqRange::bounded(from, through))?
    };
    validate_captured_range(folded_through, through, &events)?;
    Ok(CapturedRange {
        through,
        events,
        timeline,
    })
}

fn validate_captured_range(
    folded_through: pos_core::clock::Seq,
    through: pos_core::clock::Seq,
    events: &[pos_core::Event],
) -> Result<(), ExperimentError> {
    let expected_len = through.as_u64() - folded_through.as_u64();
    if u64::try_from(events.len()).unwrap_or(u64::MAX) != expected_len {
        return Err(pos_core::CoreError::Storage(
            "captured Timeline range does not contain every expected Event".to_owned(),
        )
        .into());
    }
    let mut expected = folded_through.as_u64();
    for event in events {
        expected += 1;
        if event.seq.as_u64() != expected {
            return Err(pos_core::CoreError::Storage(
                "captured Timeline range is not contiguous in logical sequence order".to_owned(),
            )
            .into());
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FoldedEventCount(u64);

impl FoldedEventCount {
    const fn is_zero(self) -> bool {
        self.0 == 0
    }

    const fn saturating_add(self, other: Self) -> Self {
        Self(self.0.saturating_add(other.0))
    }
}

fn fold_captured_range(
    boundary: &mut TickBoundaryCoordinator,
    registry: &mut PluginRegistry,
    captured: &CapturedRange,
) -> FoldedEventCount {
    registry.fold_events(&captured.events);
    boundary.folded_through = captured.through;
    FoldedEventCount(u64::try_from(captured.events.len()).unwrap_or(u64::MAX))
}

fn append_driver_drafts(
    store: &mut dyn pos_core::store::EventStore,
    timeline_id: pos_core::ids::TimelineId,
    registry: &mut PluginRegistry,
    observed_through: pos_core::clock::Seq,
) -> Result<u64, ExperimentError> {
    let drafts = match registry.step_all_anchored(timeline_id, observed_through) {
        Ok(drafts) => drafts,
        Err(error) => {
            registry.abort_step();
            return Err(error.into());
        }
    };
    if let Err(error) = registry.schemas.validate_batch(&drafts) {
        registry.abort_step();
        return Err(error.into());
    }
    if drafts.is_empty() {
        registry
            .commit_step_at(observed_through, 0)
            .map(|()| 0)
            .map_err(ExperimentError::from)
    } else {
        store
            .logical_head(timeline_id)
            .map_err(ExperimentError::from)
            .and_then(|head| {
                registry
                    .append_and_commit_step_at(store, head, 0, &drafts)
                    .map(|events| u64::try_from(events.len()).unwrap_or(u64::MAX))
                    .map_err(map_runtime_error)
            })
    }
}

/// Advance exactly one complete tick through the experiment pipeline.
fn advance_tick(
    store: &mut dyn pos_core::store::EventStore,
    timeline_id: pos_core::ids::TimelineId,
    registry: &mut PluginRegistry,
    boundary: &mut TickBoundaryCoordinator,
) -> Result<(TickAdvance, Timeline), ExperimentError> {
    let before = capture_pending_range(store, timeline_id, boundary.folded_through)?;
    let mut folded_events = fold_captured_range(boundary, registry, &before);
    let emitted_events =
        append_driver_drafts(store, timeline_id, registry, boundary.folded_through)?;
    let after = capture_pending_range(store, timeline_id, boundary.folded_through)?;
    folded_events = folded_events.saturating_add(fold_captured_range(boundary, registry, &after));
    let outcome = if folded_events.is_zero() && emitted_events == 0 {
        TickAdvance::Quiescent
    } else {
        TickAdvance::Advanced {
            folded_events: folded_events.0,
        }
    };
    Ok((outcome, after.timeline))
}

fn chain_head(
    store: &dyn pos_core::store::EventStore,
    timeline_id: pos_core::ids::TimelineId,
) -> Result<Hash, ExperimentError> {
    store
        .read(timeline_id, pos_store::SeqRange::all())
        .map(|events| {
            if events.is_empty() {
                Hash::zero()
            } else {
                let mut hasher = blake3::Hasher::new();
                for event in &events {
                    hasher.update(event.payload_hash.as_bytes());
                }
                Hash::from_bytes(*hasher.finalize().as_bytes())
            }
        })
        .map_err(ExperimentError::from)
}

fn lock_store(
    store: &Mutex<Box<dyn pos_core::store::EventStore>>,
) -> Result<MutexGuard<'_, Box<dyn pos_core::store::EventStore>>, ExperimentError> {
    store
        .lock()
        .map_err(|_| ExperimentError::SharedStoreLockPoisoned)
}

fn read_completed_prefix(
    store: &dyn pos_core::store::EventStore,
    timeline_id: pos_core::ids::TimelineId,
    through: pos_core::clock::Seq,
) -> Result<Vec<pos_core::Event>, ExperimentError> {
    let head = store.logical_head(timeline_id)?;
    if head < through {
        return Err(pos_core::CoreError::Storage(
            "logical Timeline head precedes completed fold cursor".to_owned(),
        )
        .into());
    }
    read_completed_prefix_at(store, timeline_id, through)
}

fn read_completed_prefix_at(
    store: &dyn pos_core::store::EventStore,
    timeline_id: pos_core::ids::TimelineId,
    through: pos_core::clock::Seq,
) -> Result<Vec<pos_core::Event>, ExperimentError> {
    let timeline = store
        .get_timeline(timeline_id)?
        .ok_or(pos_core::CoreError::TimelineNotFound(timeline_id))?;
    if timeline.id() != timeline_id {
        return Err(pos_core::CoreError::Storage(
            "EventStore returned mismatched Timeline metadata".to_owned(),
        )
        .into());
    }
    let events = if through == pos_core::clock::Seq::ZERO {
        Vec::new()
    } else {
        store.read(
            timeline_id,
            pos_store::SeqRange::bounded(pos_core::clock::Seq::from_u64(1), through),
        )?
    };
    validate_captured_range(pos_core::clock::Seq::ZERO, through, &events)?;
    Ok(events)
}

fn timeline_ancestry(
    store: &dyn pos_core::store::EventStore,
    active_timeline: pos_core::ids::TimelineId,
    active_through: pos_core::clock::Seq,
) -> Result<Vec<pos_runtime::TimelineHistorySegment>, ExperimentError> {
    let mut reversed = Vec::new();
    let mut seen = Vec::new();
    let mut current = active_timeline;
    let mut through = active_through;
    loop {
        if seen.contains(&current) {
            return Err(pos_core::CoreError::Storage(
                "Timeline ancestry contains a cycle".to_owned(),
            )
            .into());
        }
        let timeline = store
            .get_timeline(current)?
            .ok_or(pos_core::CoreError::TimelineNotFound(current))?;
        if timeline.id() != current {
            return Err(pos_core::CoreError::Storage(
                "EventStore returned mismatched Timeline ancestry metadata".to_owned(),
            )
            .into());
        }
        seen.push(current);
        reversed.push(pos_runtime::TimelineHistorySegment::new(current, through));
        match timeline.meta.fork_point {
            Some((parent, fork_at)) => {
                current = parent;
                through = fork_at;
            }
            None => break,
        }
    }
    reversed.reverse();
    Ok(reversed)
}

fn hydrate_projections(registry: &mut PluginRegistry, events: &[pos_core::Event]) {
    registry.fold_events(events);
}

fn restore_inherited_eval_events(
    store: &dyn pos_core::store::EventStore,
    eval_timeline: pos_core::ids::TimelineId,
    train_head: pos_core::clock::Seq,
    registry: &mut PluginRegistry,
) -> Result<Vec<pos_core::Event>, ExperimentError> {
    let inherited = if train_head == pos_core::clock::Seq::ZERO {
        Ok(Vec::new())
    } else {
        store
            .read(
                eval_timeline,
                pos_store::SeqRange::bounded(pos_core::clock::Seq::from_u64(1), train_head),
            )
            .map_err(ExperimentError::from)
    };
    inherited
        .and_then(|events| {
            validate_captured_range(pos_core::clock::Seq::ZERO, train_head, &events)
                .map(|()| events)
        })
        .and_then(|events| {
            timeline_ancestry(store, eval_timeline, train_head).map(|ancestry| (events, ancestry))
        })
        .and_then(|(events, ancestry)| {
            registry
                .restore_driver_state(&ancestry, &events)
                .map_err(ExperimentError::from)
                .map(|()| events)
        })
}

/// Run the tick loop on the given store and timeline.
///
/// Returns `(ticks, total_events, chain_head_hash)`.
///
/// # Errors
/// Returns [`ExperimentError`] on runtime or store failures.
fn run_experiment_on_store(
    store: &mut dyn pos_core::store::EventStore,
    timeline_id: pos_core::ids::TimelineId,
    stop: &StopCondition,
    registry: &mut PluginRegistry,
    folded_through: pos_core::clock::Seq,
) -> Result<(u64, u64, Hash), ExperimentError> {
    let mut ticks: u64 = 0;
    let mut total_events: u64 = 0;
    let mut boundary = TickBoundaryCoordinator { folded_through };

    loop {
        if stop.reached(ticks, total_events) {
            break;
        }

        match advance_tick(store, timeline_id, registry, &mut boundary) {
            Ok((TickAdvance::Advanced { folded_events }, _)) => {
                total_events = total_events.saturating_add(folded_events);
                ticks += 1;
            }
            Ok((TickAdvance::Quiescent, _)) => {
                ticks += 1;
                break;
            }
            Err(error) => return Err(error),
        }
    }

    chain_head(store, timeline_id).map(|head| (ticks, total_events, head))
}

/// Fork the train timeline for eval. Error path covered via fault-injection tests.
fn fork_eval_timeline(
    store: &mut dyn pos_core::store::EventStore,
    train_tl_id: pos_core::ids::TimelineId,
    train_head_seq: pos_core::clock::Seq,
    eval_name: &str,
) -> Result<Timeline, ExperimentError> {
    store
        .fork(train_tl_id, train_head_seq, eval_name)
        .map_err(ExperimentError::from)
}

// ---------------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------------

impl Experiment {
    #[must_use]
    pub fn new(config: ExperimentConfig) -> Self {
        Self {
            config,
            registry: PluginRegistry::new(),
            fork_registry_factory: None,
        }
    }

    /// Configure how each runnable Fork receives fresh plugin runtime state.
    ///
    /// The factory must register the same deterministic plugin composition as
    /// the parent. Fork creation hydrates fresh projections from inherited
    /// Timeline history and stages durable Driver state from host-filtered,
    /// sequence-bounded recovery evidence before the child can step.
    #[must_use]
    pub fn with_fork_registry_factory(
        mut self,
        factory: impl Fn() -> Result<PluginRegistry, pos_runtime::RuntimeError> + Send + Sync + 'static,
    ) -> Self {
        self.fork_registry_factory = Some(Arc::new(factory));
        self
    }

    /// Apply a deterministic per-Tick Event budget to the runtime.
    #[must_use]
    pub fn with_resource_limit(mut self, limit: u64) -> Self {
        self.registry = self.registry.with_resource_limit(limit);
        self
    }

    /// Bind the host-owned consent authority used for protected Tick Boundaries.
    #[must_use]
    pub fn with_consent_authority(mut self, authority: ConsentAuthority) -> Self {
        self.registry = self.registry.with_consent_authority(authority);
        self
    }

    /// Run without a host-owned consent gate; protected operations fail closed.
    #[must_use]
    pub fn without_consent_gate(mut self) -> Self {
        self.registry = self.registry.without_consent_gate();
        self
    }

    /// Register a plugin (wires schemas + reducer + driver).
    ///
    /// # Errors
    /// Returns [`pos_runtime::RuntimeError::DuplicatePlugin`] if a plugin with the same id
    /// is already registered.
    pub fn register(
        &mut self,
        plugin: &dyn pos_core::Plugin,
        reducer: Option<Box<dyn pos_core::Reducer>>,
        driver: Option<Box<dyn pos_runtime::Driver>>,
    ) -> Result<(), pos_runtime::RuntimeError> {
        self.registry.register(plugin, reducer, driver)
    }

    /// Register a plugin with an optional action approver.
    ///
    /// # Errors
    /// Returns [`pos_runtime::RuntimeError::DuplicatePlugin`] if a plugin with the same id
    /// is already registered.
    pub fn register_with_approver(
        &mut self,
        plugin: &dyn pos_core::Plugin,
        reducer: Option<Box<dyn pos_core::Reducer>>,
        driver: Option<Box<dyn pos_runtime::Driver>>,
        approver: Option<Box<dyn pos_core::ActionApprover>>,
        approver_event_types: impl IntoIterator<Item = pos_core::Kind>,
    ) -> Result<(), pos_runtime::RuntimeError> {
        self.registry.register_with_approver(
            plugin,
            reducer,
            driver,
            approver,
            approver_event_types,
        )
    }

    /// Create the experiment Timeline and retain the live runtime resources.
    ///
    /// # Errors
    /// Returns [`ExperimentError::Store`] if the configured `EventStore` cannot be
    /// opened or cannot create the Timeline.
    pub fn start(self) -> Result<ExperimentSession, ExperimentError> {
        let store_config = self.config.store_config.clone();
        let store = open_store(store_config.clone())?;
        self.start_with_store_and_recipe(store, Some(store_config))
    }

    /// Create the experiment Timeline in a host-supplied `EventStore` adapter.
    ///
    /// This is the production composition seam for decorators such as bounded,
    /// fault-reporting, or observability adapters. Because the supplied adapter
    /// cannot be reconstructed from [`ExperimentConfig::store_config`], results
    /// from this session do not advertise a recovery recipe.
    ///
    /// # Errors
    /// Returns [`ExperimentError::Store`] if the supplied store cannot create
    /// the Timeline.
    pub fn start_with_store(
        self,
        store: Box<dyn pos_core::store::EventStore>,
    ) -> Result<ExperimentSession, ExperimentError> {
        self.start_with_store_and_recipe(store, None)
    }

    fn start_with_store_and_recipe(
        self,
        mut store: Box<dyn pos_core::store::EventStore>,
        recovery_store_config: Option<StoreConfig>,
    ) -> Result<ExperimentSession, ExperimentError> {
        let parent_composition = self.registry.composition();
        let timeline = store.create_timeline(&self.config.name)?;
        Ok(ExperimentSession {
            config: self.config,
            registry: self.registry,
            parent_composition,
            store: Arc::new(Mutex::new(store)),
            recovery_store_config,
            fork_registry_factory: self.fork_registry_factory,
            timeline,
            ticks: 0,
            total_events: 0,
            complete: false,
            health: SessionHealth::Healthy,
            boundary: TickBoundaryCoordinator {
                folded_through: pos_core::clock::Seq::ZERO,
            },
            step_mode: None,
            last_simulation_time_ns: None,
            consent_revoked: false,
            revoked_subjects: HashSet::new(),
            consent_revocation_pending: None,
            operation_token: None,
        })
    }

    /// Resume an existing durable Timeline with a fresh Driver registry.
    ///
    /// Persisted Events are validated and folded in logical sequence order.
    /// Stateful Drivers reconstruct only their append-committed state from
    /// host-filtered immutable evidence, making this the recovery path after a
    /// faulted live session whose final append outcome may be ambiguous.
    ///
    /// # Errors
    /// Returns a store error when the Timeline cannot be opened or its logical
    /// history is invalid. Returns [`ExperimentError::Runtime`] with
    /// [`pos_runtime::RuntimeError::ConsentOperationUnavailable`] when the
    /// history contains a host-owned consent-closure marker but this
    /// experiment has no bound consent authority.
    pub fn resume(
        self,
        timeline_id: pos_core::ids::TimelineId,
    ) -> Result<ExperimentSession, ExperimentError> {
        let store_config = self.config.store_config.clone();
        let store = open_store(store_config.clone())?;
        self.resume_with_store_and_recipe(timeline_id, store, Some(store_config))
    }

    /// Resume a durable Timeline through a host-supplied `EventStore` adapter.
    ///
    /// Persisted Events are validated and folded exactly as in [`Self::resume`].
    /// This variant keeps host decorators in the recovery path instead of
    /// reconstructing an adapter from [`ExperimentConfig::store_config`].
    ///
    /// # Errors
    /// Returns a store error when the Timeline cannot be opened or its logical
    /// history is invalid. Returns [`ExperimentError::Runtime`] with
    /// [`pos_runtime::RuntimeError::ConsentOperationUnavailable`] when the
    /// history contains a host-owned consent-closure marker but this
    /// experiment has no bound consent authority.
    pub fn resume_with_store(
        self,
        timeline_id: pos_core::ids::TimelineId,
        store: Box<dyn pos_core::store::EventStore>,
    ) -> Result<ExperimentSession, ExperimentError> {
        self.resume_with_store_and_recipe(timeline_id, store, None)
    }

    fn resume_with_store_and_recipe(
        mut self,
        timeline_id: pos_core::ids::TimelineId,
        store: Box<dyn pos_core::store::EventStore>,
        recovery_store_config: Option<StoreConfig>,
    ) -> Result<ExperimentSession, ExperimentError> {
        let parent_composition = self.registry.composition();
        let timeline = store
            .get_timeline(timeline_id)?
            .ok_or(pos_core::CoreError::TimelineNotFound(timeline_id))?;
        if timeline.id() != timeline_id {
            return Err(pos_core::CoreError::Storage(
                "EventStore returned mismatched resume Timeline metadata".to_owned(),
            )
            .into());
        }
        let folded_through = store.logical_head(timeline_id)?;
        let events = if folded_through == pos_core::clock::Seq::ZERO {
            Vec::new()
        } else {
            store.read(
                timeline_id,
                pos_store::SeqRange::bounded(pos_core::clock::Seq::from_u64(1), folded_through),
            )?
        };
        validate_captured_range(pos_core::clock::Seq::ZERO, folded_through, &events)?;
        let ancestry = timeline_ancestry(store.as_ref(), timeline_id, folded_through)?;
        self.registry.restore_driver_state(&ancestry, &events)?;
        hydrate_projections(&mut self.registry, &events);
        let revoked_subjects = recovered_revoked_subjects(&events);
        let consent_revoked = events.iter().any(|event| {
            event.event_type.as_str() == EXPERIMENT_CONSENT_CLOSED_EVENT_TYPE
                && marker_subject(event).is_none()
        });
        if events
            .iter()
            .any(|event| event.event_type.as_str() == EXPERIMENT_CONSENT_CLOSED_EVENT_TYPE)
        {
            let gate = self
                .registry
                .clone_consent_gate()
                .ok_or(pos_runtime::RuntimeError::ConsentOperationUnavailable)?;
            // Subject-scoped markers retain their actual subject in the
            // payload. Legacy or malformed markers conservatively close
            // the whole Timeline so no capability survives a restart.
            for marker in events
                .iter()
                .filter(|event| event.event_type.as_str() == EXPERIMENT_CONSENT_CLOSED_EVENT_TYPE)
            {
                let result = marker_subject(marker).map_or_else(
                    || gate.fence_timeline_at(timeline_id, marker.seq.as_u64()),
                    |subject| gate.fence_subject_at(timeline_id, subject, marker.seq.as_u64()),
                );
                if let Err(error) = result {
                    return Err(map_runtime_error(pos_runtime::RuntimeError::Consent(error)));
                }
            }
        }
        Ok(ExperimentSession {
            config: self.config,
            registry: self.registry,
            parent_composition,
            store: Arc::new(Mutex::new(store)),
            recovery_store_config,
            fork_registry_factory: self.fork_registry_factory,
            timeline,
            ticks: 0,
            total_events: folded_through.as_u64(),
            complete: false,
            health: SessionHealth::Healthy,
            boundary: TickBoundaryCoordinator { folded_through },
            step_mode: None,
            last_simulation_time_ns: None,
            consent_revoked,
            revoked_subjects,
            consent_revocation_pending: None,
            operation_token: None,
        })
    }

    /// Run the experiment to completion and return a [`RunResult`].
    ///
    /// The closed tick loop:
    /// 1. capture, validate, and fold every persisted Event through the boundary
    /// 2. `step_all()` — call all registered drivers against one immutable snapshot
    /// 3. `validate_batch()` and `append()` — atomically persist the driver batch
    /// 4. capture, validate, and fold every Event through the post-step boundary
    ///
    /// # Errors
    /// Returns [`ExperimentError::Runtime`] on driver or schema errors,
    /// or [`ExperimentError::Store`] on persistence errors.
    pub fn run(self) -> Result<RunResult, ExperimentError> {
        self.start()?.run_to_completion()
    }

    /// Fork the experiment's timeline at the current head, returning a new child [`Timeline`].
    ///
    /// Delegates to `store.fork()`.
    ///
    /// # Errors
    /// Returns [`ExperimentError::Store`] if the fork fails.
    pub fn branch(
        &self,
        name: &str,
        store: &mut dyn pos_core::store::EventStore,
    ) -> Result<Timeline, ExperimentError> {
        // Find the timeline by listing and matching on name.
        let timelines = store.list_timelines()?;
        let timeline = timelines
            .iter()
            .find(|t| t.meta.name.as_deref() == Some(&self.config.name))
            .ok_or_else(|| {
                pos_core::CoreError::Storage(format!(
                    "timeline '{}' not found for branching",
                    self.config.name
                ))
            })?;

        let current_head = store.logical_head(timeline.id())?;
        reject_protected_history(store, timeline.id(), current_head)?;
        Ok(store.fork(timeline.id(), current_head, name)?)
    }

    /// Fork a Timeline containing protected Events with an explicit capability.
    ///
    /// The current durable head is read before validation and the store fork is
    /// performed under the authority's token fence, so revocation cannot race
    /// the protected branch admission.
    ///
    /// # Errors
    /// Returns a consent error when `token` is stale or does not permit forks,
    /// or a store error when the Timeline cannot be read or forked.
    pub fn branch_with_token(
        &self,
        name: &str,
        store: &mut dyn pos_core::store::EventStore,
        token: &ConsentCapabilityToken,
        now_secs: u64,
    ) -> Result<Timeline, ExperimentError> {
        let timelines = store.list_timelines()?;
        let timeline = timelines
            .iter()
            .find(|t| t.meta.name.as_deref() == Some(&self.config.name))
            .ok_or_else(|| {
                pos_core::CoreError::Storage(format!(
                    "timeline '{}' not found for branching",
                    self.config.name
                ))
            })?;
        let current_head = store.logical_head(timeline.id())?;
        if !token.fork_permitted() {
            return Err(pos_runtime::RuntimeError::Consent(
                pos_core::ConsentError::ForkNotPermitted,
            )
            .into());
        }
        let Some(gate) = self.registry.clone_consent_gate() else {
            return Err(pos_runtime::RuntimeError::ConsentOperationUnavailable.into());
        };
        let mut fork_result: Result<Timeline, ExperimentError> =
            Err(pos_runtime::RuntimeError::ConsentOperationUnavailable.into());
        let mut append = || {
            fork_result = store
                .fork(timeline.id(), current_head, name)
                .map_err(ExperimentError::from);
        };
        if let Err(error) = gate.with_token_fence(
            timeline.id(),
            token,
            current_head.as_u64(),
            now_secs,
            &mut append,
        ) {
            return Err(map_runtime_error(pos_runtime::RuntimeError::Consent(error)));
        }
        fork_result
    }
}

impl ExperimentSession {
    const fn reached_stop_condition(&self) -> bool {
        self.config.stop.reached(self.ticks, self.total_events)
    }

    /// Return the active Timeline handle.
    #[must_use]
    pub const fn timeline(&self) -> &Timeline {
        &self.timeline
    }

    /// Bind a timeline-issued capability for protected Tick Boundaries.
    ///
    /// The legacy time argument is retained for source compatibility but is
    /// not cached: every protected boundary samples the host clock afresh.
    #[must_use]
    pub const fn with_protected_token(mut self, token: ConsentCapabilityToken, _: u64) -> Self {
        self.operation_token = Some(token);
        self
    }

    /// Bind the host-owned consent authority used by a protected operation.
    #[must_use]
    pub fn with_consent_authority(mut self, authority: ConsentAuthority) -> Self {
        self.registry = self.registry.with_consent_authority(authority);
        self
    }

    /// Advance one complete tick.
    ///
    /// Compatibility wrapper around [`Self::step_tick`]. Returns `true` when
    /// the boundary advanced persisted state and `false` for quiescence or a
    /// reached stop condition. Quiescence does not disable a later call.
    ///
    /// # Errors
    /// Returns [`ExperimentError::StepModeMismatch`] if this session already
    /// selected cadenced stepping, or runtime/store/fault errors from the atomic
    /// tick pipeline.
    pub fn step(&mut self) -> Result<bool, ExperimentError> {
        self.step_tick()
            .map(|outcome| matches!(outcome, TickOutcome::Advanced { .. }))
    }

    /// Advance one complete interactive Tick Boundary.
    ///
    /// The host folds a captured contiguous range, steps every driver against
    /// one immutable snapshot, appends the driver batch, then folds the complete
    /// post-step range. A [`TickOutcome::Quiescent`] session remains resumable.
    ///
    /// # Errors
    /// Returns [`ExperimentError::StepModeMismatch`] if this session already
    /// selected cadenced stepping.
    /// Pre-boundary read errors are retryable. Any error after projection or
    /// driver mutation faults the session and subsequent calls return
    /// [`ExperimentError::SessionFaulted`].
    pub fn step_tick(&mut self) -> Result<TickOutcome, ExperimentError> {
        self.step_with_mode(StepRequest::AllDrivers)
    }

    /// Advance one complete Tick Boundary at caller-supplied simulation time.
    ///
    /// Due drivers run in registration order against the same immutable snapshot.
    /// Equal timestamps are accepted; a lower timestamp or mixing this API with
    /// [`Self::step_tick`] is rejected before capture or mutation.
    ///
    /// # Errors
    /// Returns [`ExperimentError::CadenceTimeRegressed`] for decreasing time,
    /// [`ExperimentError::StepModeMismatch`] after all-driver stepping, or the
    /// same runtime/store/fault errors as [`Self::step_tick`].
    pub fn step_cadenced(&mut self, now_ns: u128) -> Result<TickOutcome, ExperimentError> {
        self.step_with_mode(StepRequest::Cadenced(now_ns))
    }

    /// Read one subject's projection state under a host-issued consent token.
    ///
    /// # Errors
    /// Returns [`ExperimentError::SessionFaulted`] after any stateful boundary
    /// failure; rebuild the session through [`Experiment::resume`] before reading.
    pub fn projection_state_for_reducer(
        &self,
        reducer: &str,
        subject: EntityId,
        token: &ConsentCapabilityToken,
        now_secs: u64,
    ) -> Result<Option<pos_core::State>, ExperimentError> {
        if self.health == SessionHealth::Faulted {
            return Err(ExperimentError::SessionFaulted);
        }
        if self.consent_revoked
            || self.consent_revocation_pending.is_some()
            || self.revoked_subjects.contains(&subject)
        {
            return Err(ExperimentError::ConsentRevokedV1);
        }
        let timeline_head = lock_store(&self.store)
            .and_then(|store| Ok(store.logical_head(self.timeline.id())?))?;
        self.registry
            .projection_state_for_reducer(
                self.timeline.id(),
                timeline_head,
                now_secs,
                token,
                reducer,
                subject,
            )
            .map_err(map_runtime_error)
    }

    /// Read the immutable source prefix folded through the last completed Tick Boundary.
    ///
    /// The returned Events begin at sequence one and are contiguous through the
    /// session's completed fold cursor, making them suitable for pure replay
    /// verification. A failed boundary cannot expose a partial append here.
    ///
    /// # Errors
    /// Returns a store or shared-store locking error if the completed prefix
    /// cannot be read.
    pub fn source_events(&self) -> Result<Vec<pos_core::Event>, ExperimentError> {
        self.source_events_with_control().map(|events| {
            events
                .into_iter()
                .filter(|event| is_public_event_type(&event.event_type))
                .collect()
        })
    }

    pub(crate) fn source_events_with_control(
        &self,
    ) -> Result<Vec<pos_core::Event>, ExperimentError> {
        lock_store(&self.store).and_then(|store| {
            read_completed_prefix(
                store.as_ref(),
                self.timeline.id(),
                self.boundary.folded_through,
            )
        })
    }

    /// Append host-approved Events at the current completed Tick Boundary.
    ///
    /// This is the external-input seam used by counterfactual interventions.
    /// The batch is schema-validated and atomically appended before the new
    /// range is folded, so a failed append cannot expose a partial Tick.
    ///
    /// # Errors
    /// Returns a runtime validation, store, or post-append capture error.
    fn append_events(
        &mut self,
        drafts: &[pos_core::event::EventDraft],
    ) -> Result<u64, ExperimentError> {
        if self.health == SessionHealth::Faulted {
            return Err(ExperimentError::SessionFaulted);
        }
        if self.consent_revoked
            || self.consent_revocation_pending.is_some()
            || drafts
                .iter()
                .any(|draft| self.revoked_subjects.contains(&draft.entity))
        {
            return Err(ExperimentError::ConsentRevokedV1);
        }
        if drafts
            .iter()
            .any(|draft| pos_core::is_consent_event_type(&draft.event_type))
        {
            return Err(ExperimentError::ConsentRevokedV1);
        }
        self.registry.schemas.validate_batch(drafts)?;
        if drafts.is_empty() {
            return Ok(0);
        }
        let emitted = lock_store(&self.store).and_then(|mut store| {
            store
                .append(self.timeline.id(), drafts)
                .map_err(ExperimentError::from)
        })?;
        let after = match lock_store(&self.store).and_then(|store| {
            capture_pending_range(
                store.as_ref(),
                self.timeline.id(),
                self.boundary.folded_through,
            )
        }) {
            Ok(captured) => captured,
            Err(error) => {
                self.health = SessionHealth::Faulted;
                return Err(error);
            }
        };
        fold_captured_range(&mut self.boundary, &mut self.registry, &after);
        self.total_events = self.boundary.folded_through.as_u64();
        Ok(u64::try_from(emitted.len()).unwrap_or(u64::MAX))
    }

    /// Submit one external action through the owning Plugin's authority seam.
    ///
    /// The approved Event is appended only at the current completed Tick
    /// Boundary. Callers cannot bypass the Plugin's actor, capability, schema,
    /// and domain validation by supplying an arbitrary `EventDraft`.
    ///
    /// # Errors
    /// Returns the owning Plugin's action rejection or a store/runtime error
    /// when the approved Event cannot be appended and folded.
    pub fn submit_action(
        &mut self,
        proposal: &pos_core::ProposedAction,
    ) -> Result<u64, ExperimentError> {
        let draft = self.registry.submit_action(proposal)?;
        self.append_events(std::slice::from_ref(&draft))
    }

    /// Revoke the default session subject's consent at the next Tick Boundary.
    ///
    /// The current completed boundary remains readable. With a bound consent
    /// authority, the next step commits only the experiment-owned lifecycle
    /// marker; a following step returns [`TickOutcome::Stopped`] without
    /// invoking or committing any Driver. Without an authority, that next
    /// step fails closed before appending the marker.
    pub fn revoke_consent_at_boundary(&mut self) {
        if !self.consent_revoked {
            self.consent_revocation_pending = Some(PendingConsentRevocation::Timeline {
                marker_entity: consent_marker_entity("session"),
            });
        }
    }

    /// Schedule a durable, subject-scoped consent revocation.
    ///
    /// The request immediately closes external append authority. With a bound
    /// consent authority, the host persists an experiment-owned lifecycle
    /// marker as the next atomic boundary; Drivers are not invoked for that
    /// boundary. Recovery derives the closed state from that marker rather
    /// than from process memory. Without an authority, the next step fails
    /// closed before appending the marker.
    pub fn revoke_consent_for_subject_at_boundary(&mut self, subject: EntityId) {
        if !self.consent_revoked {
            self.consent_revocation_pending = Some(PendingConsentRevocation::Subject {
                subject_id: subject,
                marker_entity: consent_marker_entity(&subject.to_string()),
            });
        }
    }

    fn step_with_mode(&mut self, request: StepRequest) -> Result<TickOutcome, ExperimentError> {
        if self.health == SessionHealth::Faulted {
            return Err(ExperimentError::SessionFaulted);
        }
        let requested = request.mode();
        if let Some(active) = self.step_mode {
            if active != requested {
                return Err(ExperimentError::StepModeMismatch {
                    active: active.name(),
                    requested: requested.name(),
                });
            }
        }
        if let (Some(previous_ns), Some(requested_ns)) =
            (self.last_simulation_time_ns, request.simulation_time_ns())
        {
            if requested_ns < previous_ns {
                return Err(ExperimentError::CadenceTimeRegressed {
                    previous_ns,
                    requested_ns,
                });
            }
        }

        let outcome = self.step_boundary(request)?;
        if outcome != TickOutcome::Stopped {
            self.step_mode = Some(requested);
            if let Some(now_ns) = request.simulation_time_ns() {
                self.last_simulation_time_ns = Some(now_ns);
            }
        }
        Ok(outcome)
    }

    fn select_step_drafts(
        &mut self,
        request: StepRequest,
        committed_events: &[pos_core::Event],
    ) -> Result<Vec<EventDraft>, pos_runtime::RuntimeError> {
        match (request, self.operation_token.clone()) {
            (StepRequest::AllDrivers, Some(token)) => self.registry.step_all_anchored_protected(
                self.timeline.id(),
                self.boundary.folded_through,
                token,
                current_now_secs(),
                committed_events,
            ),
            (StepRequest::Cadenced(now_ns), Some(token)) => {
                self.registry.tick_cadenced_anchored_protected(
                    self.timeline.id(),
                    now_ns,
                    self.boundary.folded_through,
                    token,
                    current_now_secs(),
                    committed_events,
                )
            }
            (StepRequest::AllDrivers, None) => self.registry.step_all_anchored_with_events(
                self.timeline.id(),
                self.boundary.folded_through,
                committed_events,
            ),
            (StepRequest::Cadenced(now_ns), None) => {
                self.registry.tick_cadenced_anchored_with_events(
                    self.timeline.id(),
                    now_ns,
                    self.boundary.folded_through,
                    committed_events,
                )
            }
        }
    }

    fn step_boundary(&mut self, request: StepRequest) -> Result<TickOutcome, ExperimentError> {
        if let Some(revocation) = self.consent_revocation_pending.take() {
            return self.commit_consent_revocation(revocation);
        }
        if self.consent_revoked || self.complete || self.reached_stop_condition() {
            self.complete = true;
            return Ok(TickOutcome::Stopped);
        }

        let (mut folded_events, committed_events) = self.prepare_tick()?;

        let drafts = match self.select_step_drafts(request, &committed_events) {
            Ok(drafts) => drafts,
            Err(error) => {
                self.registry.abort_step();
                self.health = SessionHealth::Faulted;
                return Err(error.into());
            }
        };
        if drafts
            .iter()
            .any(|draft| self.revoked_subjects.contains(&draft.entity))
        {
            self.registry.abort_step();
            return Err(ExperimentError::ConsentRevokedV1);
        }
        if let Err(error) = self.registry.schemas.validate_batch(&drafts) {
            self.registry.abort_step();
            self.health = SessionHealth::Faulted;
            return Err(error.into());
        }
        let emitted_events = if drafts.is_empty() {
            self.registry
                .commit_step_at(self.boundary.folded_through, current_now_secs())?;
            0
        } else {
            match lock_store(&self.store)
                .and_then(|mut store| {
                    let head = store
                        .logical_head(self.timeline.id())
                        .map_err(ExperimentError::from)?;
                    self.registry
                        .append_and_commit_step_at(
                            store.as_mut(),
                            head,
                            current_now_secs(),
                            &drafts,
                        )
                        .map_err(map_runtime_error)
                })
                .map(|events| u64::try_from(events.len()).unwrap_or(u64::MAX))
            {
                Ok(count) => count,
                Err(error) => {
                    self.health = SessionHealth::Faulted;
                    return Err(error);
                }
            }
        };

        let after = match lock_store(&self.store).and_then(|store| {
            capture_pending_range(
                store.as_ref(),
                self.timeline.id(),
                self.boundary.folded_through,
            )
        }) {
            Ok(captured) => captured,
            Err(error) => {
                self.health = SessionHealth::Faulted;
                return Err(error);
            }
        };
        folded_events = folded_events
            .saturating_add(fold_captured_range(&mut self.boundary, &mut self.registry, &after).0);
        self.timeline = after.timeline;
        self.total_events = self.total_events.saturating_add(folded_events);
        self.ticks = self.ticks.saturating_add(1);

        if folded_events == 0 && emitted_events == 0 {
            Ok(TickOutcome::Quiescent)
        } else {
            Ok(TickOutcome::Advanced {
                folded_events,
                emitted_events,
            })
        }
    }

    fn commit_consent_revocation(
        &mut self,
        revocation: PendingConsentRevocation,
    ) -> Result<TickOutcome, ExperimentError> {
        let (marker_entity, subject) = match revocation {
            PendingConsentRevocation::Timeline { marker_entity } => (marker_entity, None),
            PendingConsentRevocation::Subject {
                subject_id,
                marker_entity,
            } => (marker_entity, Some(subject_id)),
        };
        let marker_payload = subject.map_or_else(
            || pos_core::event::CanonicalBytes::from_static(EXPERIMENT_CONSENT_TIMELINE_MARKER),
            |subject_id| {
                let mut bytes = EXPERIMENT_CONSENT_SUBJECT_MARKER_PREFIX.to_vec();
                bytes.extend_from_slice(subject_id.to_string().as_bytes());
                pos_core::event::CanonicalBytes::from_vec(bytes)
            },
        );
        let emitted_events = lock_store(&self.store)
            .and_then(|mut store| {
                let head = store.logical_head(self.timeline.id())?;
                let draft = EventDraft::new(
                    marker_entity,
                    Kind::new(EXPERIMENT_CONSENT_CLOSED_EVENT_TYPE),
                    marker_payload,
                );
                let mut append_result = Ok(Vec::new());
                let mut append = || {
                    append_result = store.append(self.timeline.id(), std::slice::from_ref(&draft));
                };
                let gate = self
                    .registry
                    .clone_consent_gate()
                    .ok_or(ExperimentError::Runtime(
                        pos_runtime::RuntimeError::ConsentOperationUnavailable,
                    ))?;
                gate.with_revocation_fence(
                    self.timeline.id(),
                    subject,
                    head.as_u64().saturating_add(1),
                    &mut append,
                )
                .map_err(pos_runtime::RuntimeError::Consent)
                .map_err(ExperimentError::Runtime)?;
                let events = append_result?;
                Ok(u64::try_from(events.len()).unwrap_or(u64::MAX))
            })
            .inspect_err(|_| {
                self.health = SessionHealth::Faulted;
            })?;
        let after = lock_store(&self.store)
            .and_then(|store| {
                capture_pending_range(
                    store.as_ref(),
                    self.timeline.id(),
                    self.boundary.folded_through,
                )
            })
            .inspect_err(|_| {
                self.health = SessionHealth::Faulted;
            })?;
        let folded_events = fold_captured_range(&mut self.boundary, &mut self.registry, &after);
        self.timeline = after.timeline;
        self.total_events = self.total_events.saturating_add(folded_events.0);
        self.ticks = self.ticks.saturating_add(1);
        if let Some(subject) = subject {
            self.revoked_subjects.insert(subject);
        } else {
            self.consent_revoked = true;
            self.complete = true;
        }
        Ok(TickOutcome::Advanced {
            folded_events: folded_events.0,
            emitted_events,
        })
    }

    fn prepare_tick(&mut self) -> Result<(u64, Vec<pos_core::Event>), ExperimentError> {
        let before = lock_store(&self.store).and_then(|store| {
            capture_pending_range(
                store.as_ref(),
                self.timeline.id(),
                self.boundary.folded_through,
            )
        })?;
        let mut committed_events = lock_store(&self.store).and_then(|store| {
            read_completed_prefix_at(
                store.as_ref(),
                self.timeline.id(),
                self.boundary.folded_through,
            )
        })?;
        committed_events.extend(before.events.iter().cloned());
        let folded_events = fold_captured_range(&mut self.boundary, &mut self.registry, &before);
        Ok((folded_events.0, committed_events))
    }

    fn hydrate_fork_registry(
        &self,
        registry: &mut PluginRegistry,
        ancestry: &[pos_runtime::TimelineHistorySegment],
        events: &[pos_core::Event],
        durable_head: pos_core::clock::Seq,
    ) -> Result<(), ExperimentError> {
        let Some(token) = self.operation_token.as_ref() else {
            reject_protected_events(events)?;
            registry.restore_driver_state(ancestry, events)?;
            hydrate_projections(registry, events);
            return Ok(());
        };
        let gate = self
            .registry
            .clone_consent_gate()
            .ok_or(pos_runtime::RuntimeError::ConsentOperationUnavailable)?;
        let mut hydration_error = None;
        let mut hydrate = || {
            if let Err(error) = registry.restore_driver_state(ancestry, events) {
                hydration_error = Some(error);
            } else {
                hydrate_projections(registry, events);
            }
        };
        gate.with_token_fence(
            self.timeline.id(),
            token,
            durable_head.as_u64(),
            current_now_secs(),
            &mut hydrate,
        )
        .map_err(pos_runtime::RuntimeError::Consent)?;
        hydration_error.map_or(Ok(()), |error| Err(error.into()))
    }

    fn fork_timeline_at(
        &self,
        name: &str,
        fork_head: pos_core::clock::Seq,
    ) -> Result<Timeline, ExperimentError> {
        lock_store(&self.store).and_then(|mut store| {
            let durable_head = store.logical_head(self.timeline.id())?;
            let mut fork_result = None;
            let mut append = || {
                fork_result = Some(store.fork(self.timeline.id(), fork_head, name));
            };
            if let Some(token) = self.operation_token.as_ref() {
                let gate = self
                    .registry
                    .clone_consent_gate()
                    .ok_or(pos_runtime::RuntimeError::ConsentOperationUnavailable)?;
                gate.with_token_fence(
                    self.timeline.id(),
                    token,
                    durable_head.as_u64(),
                    current_now_secs(),
                    &mut append,
                )
                .map_err(pos_runtime::RuntimeError::Consent)?;
            } else {
                append();
            }
            Ok(fork_result.ok_or(pos_runtime::RuntimeError::ConsentOperationUnavailable)??)
        })
    }

    /// Fork the active Timeline at its most recently completed tick boundary.
    ///
    /// The child shares the live store, owns a fresh runtime registry, hydrates
    /// projections from inherited Timeline history, restores only durable
    /// Driver state from host-filtered bounded evidence, and can be stepped
    /// immediately without reopening persistence.
    ///
    /// A session bound with [`Self::with_protected_token`] must still hold a
    /// live token whose `fork_permitted` flag is set at this exact Timeline
    /// head. An explicitly public session has no consent capability to carry
    /// into the child.
    ///
    /// # Errors
    /// Returns [`ExperimentError::Runtime`] if fresh runtime construction fails,
    /// [`ExperimentError::Store`] if history hydration or forking fails, or
    /// [`ExperimentError::SharedStoreLockPoisoned`] if the shared store is poisoned.
    pub fn fork(&mut self, name: &str) -> Result<Self, ExperimentError> {
        if self.health == SessionHealth::Faulted {
            return Err(ExperimentError::SessionFaulted);
        }
        let fork_head = self.boundary.folded_through;
        let durable_head = lock_store(&self.store)
            .and_then(|store| Ok(store.logical_head(self.timeline.id())?))?;
        if let Some(token) = self.operation_token.as_ref() {
            let gate = self
                .registry
                .clone_consent_gate()
                .ok_or(pos_runtime::RuntimeError::ConsentOperationUnavailable)?;
            gate.validate_token(
                self.timeline.id(),
                token,
                durable_head.as_u64(),
                current_now_secs(),
            )
            .map_err(pos_runtime::RuntimeError::Consent)?;
            if !token.fork_permitted() {
                return Err(pos_runtime::RuntimeError::Consent(
                    pos_core::ConsentError::ForkNotPermitted,
                )
                .into());
            }
        }
        let factory = self
            .fork_registry_factory
            .as_ref()
            .ok_or(ExperimentError::MissingForkRegistryFactory)?;
        let mut registry = factory()?;
        if let Some(gate) = self.registry.clone_consent_gate() {
            registry = registry.with_consent_gate(gate);
        }
        if registry.composition() != self.parent_composition {
            return Err(ExperimentError::IncompatibleForkRegistry);
        }
        let (events, ancestry) = lock_store(&self.store).and_then(|store| {
            let events = read_completed_prefix(store.as_ref(), self.timeline.id(), fork_head)?;
            let ancestry = timeline_ancestry(
                store.as_ref(),
                self.timeline.id(),
                self.boundary.folded_through,
            )?;
            Ok((events, ancestry))
        })?;
        self.hydrate_fork_registry(&mut registry, &ancestry, &events, durable_head)?;
        let config = ExperimentConfig {
            name: name.to_owned(),
            stop: self.config.stop.clone(),
            store_config: self.config.store_config.clone(),
        };

        let timeline = self.fork_timeline_at(name, fork_head)?;
        Ok(Self {
            config,
            registry,
            parent_composition: self.parent_composition.clone(),
            store: Arc::clone(&self.store),
            recovery_store_config: self.recovery_store_config.clone(),
            fork_registry_factory: Some(Arc::clone(factory)),
            timeline,
            ticks: self.ticks,
            total_events: self.boundary.folded_through.as_u64(),
            complete: false,
            health: SessionHealth::Healthy,
            boundary: TickBoundaryCoordinator {
                folded_through: self.boundary.folded_through,
            },
            step_mode: None,
            last_simulation_time_ns: None,
            consent_revoked: self.consent_revoked,
            revoked_subjects: self.revoked_subjects.clone(),
            consent_revocation_pending: self.consent_revocation_pending,
            operation_token: self.operation_token.clone(),
        })
    }

    /// Advance until the stop condition or an empty driver batch, then return
    /// the completed result.
    ///
    /// # Errors
    /// Returns runtime or store errors from a tick or final chain-head read.
    pub fn run_to_completion(mut self) -> Result<RunResult, ExperimentError> {
        loop {
            match self.step() {
                Ok(true) => {}
                Ok(false) => break,
                Err(error) => return Err(error),
            }
        }

        let timeline_id = self.timeline.id();
        let timeline_head = self.boundary.folded_through;
        let plugin_versions: Vec<(String, String)> = self
            .registry
            .plugin_versions()
            .map(|(name, version)| (name.to_owned(), version.to_owned()))
            .collect();
        let consent_gate = self
            .operation_token
            .as_ref()
            .and_then(|_| self.registry.clone_consent_gate());
        let protected_token = self.operation_token;
        let public_events = lock_store(&self.store)
            .and_then(|store| read_completed_prefix(store.as_ref(), timeline_id, timeline_head))?;
        let projections = self
            .registry
            .into_authorized_projections(
                timeline_id,
                timeline_head,
                current_now_secs(),
                protected_token.as_ref(),
                Some(&public_events),
            )
            .map_err(ExperimentError::Runtime)?;
        let ticks = self.ticks;
        let total_events = self.total_events;
        let store_config = self.recovery_store_config;
        lock_store(&self.store)
            .and_then(|store| chain_head(store.as_ref(), timeline_id))
            .map(|chain_head| {
                let mut manifest = ReproManifest::new(timeline_id, chain_head, WallTime::now());
                for (name, version) in &plugin_versions {
                    manifest = manifest.with_plugin_version(name, version.clone());
                }
                manifest
                    .adapter_records
                    .push(pos_core::manifest::AdapterRecord {
                        plugin_id: pos_core::ids::PluginId::new(),
                        call_index: 0,
                        input_hash: Hash::zero(),
                        output_hash: Hash::from_bytes(
                            *blake3::hash(timeline_id.to_string().as_bytes()).as_bytes(),
                        ),
                        wall_time: WallTime::now(),
                    });

                RunResult {
                    timeline_id,
                    ticks,
                    total_events,
                    timeline_head: timeline_head.as_u64(),
                    manifest,
                    projections,
                    consent_gate,
                    protected_token,
                    store_config,
                }
            })
    }
}

fn consent_marker_entity(subject: &str) -> EntityId {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"PiglorOS.ConsentRevocationMarker.v1\0");
    hasher.update(subject.as_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0; 16];
    bytes.copy_from_slice(&digest.as_bytes()[..16]);
    EntityId::from_ulid(ulid::Ulid::from(u128::from_be_bytes(bytes)))
}

fn marker_subject(event: &pos_core::Event) -> Option<EntityId> {
    event
        .payload
        .as_slice()
        .strip_prefix(EXPERIMENT_CONSENT_SUBJECT_MARKER_PREFIX)
        .and_then(|bytes| std::str::from_utf8(bytes).ok())
        .and_then(|text| ulid::Ulid::from_string(text).ok())
        .map(EntityId::from_ulid)
}

fn recovered_revoked_subjects(events: &[pos_core::Event]) -> HashSet<EntityId> {
    events
        .iter()
        .filter(|event| event.event_type.as_str() == EXPERIMENT_CONSENT_CLOSED_EVENT_TYPE)
        .filter_map(marker_subject)
        .collect()
}

// ---------------------------------------------------------------------------
// BacktestRunner
// ---------------------------------------------------------------------------

/// Configuration for a backtest run: a temporal split into train and eval phases.
pub struct BacktestConfig {
    /// Base name used for both timelines (suffixed with `-train` / `-eval`).
    pub experiment_name: String,
    /// Number of ticks in the training phase.
    pub train_ticks: u64,
    /// Number of ticks in the evaluation phase.
    pub eval_ticks: u64,
    /// Store backend for both phases.
    pub store_config: pos_store::StoreConfig,
}

/// Result of a completed backtest run.
pub struct BacktestResult {
    /// Result from the training phase.
    pub train_result: RunResult,
    /// Result from the evaluation phase (runs on a fork of the train timeline).
    pub eval_result: RunResult,
    /// Total events committed in the training phase.
    pub train_events: u64,
    /// Total events committed in the evaluation phase.
    pub eval_events: u64,
    /// Event count ratio: `eval_events` / `train_events` (naive persistence baseline).
    pub persistence_lift: f64,
    /// Average events per tick in train phase (population avg baseline).
    pub train_avg_events_per_tick: f64,
    /// Average events per tick in eval phase.
    pub eval_avg_events_per_tick: f64,
    /// Lift of eval vs persistence baseline: `eval_avg` / `train_avg` - 1.0 (0.0 if `train_avg` == 0).
    pub lift_vs_persistence: f64,
    /// Calibration report computed from the eval timeline.
    pub eval_report: pos_plugin_eval::CalibrationReport,
}

/// Temporal-split backtest runner.
///
/// Runs a train phase, forks the timeline at the train head, then runs an eval
/// phase on the fork. Reports per-phase event counts and lift metrics vs a
/// persistence baseline (events-per-tick ratio).
pub struct BacktestRunner {
    config: BacktestConfig,
    /// Factory callable that produces a fresh, pre-registered `PluginRegistry`
    /// (or just an empty one — callers may register plugins after calling
    /// [`BacktestRunner::run`] if they prefer to use the returned `Experiment`).
    ///
    /// Called **twice**: once for the train phase and once for the eval phase.
    registry_factory: Box<dyn Fn() -> pos_runtime::PluginRegistry + Send>,
}

fn build_backtest_run_result(
    store: &dyn pos_core::store::EventStore,
    registry: PluginRegistry,
    timeline_id: pos_core::ids::TimelineId,
    ticks: u64,
    total_events: u64,
    timeline_head: pos_core::clock::Seq,
    manifest: ReproManifest,
    store_config: StoreConfig,
) -> Result<RunResult, ExperimentError> {
    let history = read_completed_prefix(store, timeline_id, timeline_head)?;
    let projections = registry
        .into_authorized_projections(
            timeline_id,
            timeline_head,
            current_now_secs(),
            None,
            Some(&history),
        )
        .map_err(ExperimentError::Runtime)?;
    Ok(RunResult {
        timeline_id,
        ticks,
        total_events,
        timeline_head: timeline_head.as_u64(),
        manifest,
        projections,
        consent_gate: None,
        protected_token: None,
        store_config: Some(store_config),
    })
}

fn backtest_metrics(
    train_ticks: u64,
    train_events: u64,
    eval_ticks: u64,
    eval_events: u64,
) -> (f64, f64, f64, f64) {
    let train_events_f = f64::from(u32::try_from(train_events).unwrap_or(u32::MAX));
    let eval_events_f = f64::from(u32::try_from(eval_events).unwrap_or(u32::MAX));
    let train_ticks_f = f64::from(u32::try_from(train_ticks).unwrap_or(u32::MAX));
    let eval_ticks_f = f64::from(u32::try_from(eval_ticks).unwrap_or(u32::MAX));
    let train_avg = if train_ticks == 0 {
        0.0
    } else {
        train_events_f / train_ticks_f
    };
    let eval_avg = if eval_ticks == 0 {
        0.0
    } else {
        eval_events_f / eval_ticks_f
    };
    let persistence_lift = if train_events == 0 {
        0.0
    } else {
        eval_events_f / train_events_f
    };
    let lift_vs_persistence = if train_ticks == 0 {
        0.0
    } else {
        eval_avg / train_avg - 1.0
    };
    (train_avg, eval_avg, persistence_lift, lift_vs_persistence)
}

impl BacktestRunner {
    /// Create a new backtest runner.
    ///
    /// `registry_factory` is called twice — once per phase — to produce independent
    /// plugin registries so that each phase starts with fresh driver state.
    pub fn new(
        config: BacktestConfig,
        registry_factory: impl Fn() -> pos_runtime::PluginRegistry + Send + 'static,
    ) -> Self {
        Self {
            config,
            registry_factory: Box::new(registry_factory),
        }
    }

    /// Run the backtest: train phase then eval phase.
    ///
    /// Opens the store once, runs train, forks at the train head, then runs eval
    /// on the same store using the forked timeline.
    ///
    /// # Errors
    /// Returns [`ExperimentError::Runtime`] or [`ExperimentError::Store`] on failure.
    pub fn run(self) -> Result<BacktestResult, ExperimentError> {
        let mut store = open_store(self.config.store_config.clone())?;
        self.run_on_store(store.as_mut())
    }

    /// Run backtest phases on an already-opened store (test seam for fault injection).
    fn run_on_store(
        self,
        store: &mut dyn pos_core::store::EventStore,
    ) -> Result<BacktestResult, ExperimentError> {
        let store_config = self.config.store_config.clone();

        // --- Train phase ---
        let train_name = format!("{}-train", self.config.experiment_name);
        let train_tl = store.create_timeline(&train_name)?;
        let train_tl_id = train_tl.id();

        let mut train_registry = (self.registry_factory)();
        let train_stop = StopCondition::MaxTicks(self.config.train_ticks);
        let (train_ticks, train_events, train_chain_head) = run_experiment_on_store(
            store,
            train_tl_id,
            &train_stop,
            &mut train_registry,
            pos_core::clock::Seq::ZERO,
        )?;

        let train_head_seq = store.logical_head(train_tl_id)?;

        // --- Fork train timeline to eval ---
        let eval_name = format!("{}-eval", self.config.experiment_name);
        let eval_tl = fork_eval_timeline(store, train_tl_id, train_head_seq, &eval_name)?;
        let eval_tl_id = eval_tl.id();

        // --- Eval phase (same store, forked timeline) ---
        let mut eval_registry = (self.registry_factory)();
        let inherited =
            restore_inherited_eval_events(store, eval_tl_id, train_head_seq, &mut eval_registry)?;
        hydrate_projections(&mut eval_registry, &inherited);
        let eval_stop = StopCondition::MaxTicks(self.config.eval_ticks);
        let (eval_ticks, eval_events, eval_chain_head) = run_experiment_on_store(
            store,
            eval_tl_id,
            &eval_stop,
            &mut eval_registry,
            train_head_seq,
        )?;

        let (
            train_avg_events_per_tick,
            eval_avg_events_per_tick,
            persistence_lift,
            lift_vs_persistence,
        ) = backtest_metrics(train_ticks, train_events, eval_ticks, eval_events);

        let train_manifest = ReproManifest::new(train_tl_id, train_chain_head, WallTime::now());
        let eval_manifest = ReproManifest::new(eval_tl_id, eval_chain_head, WallTime::now());
        let eval_head_seq = store.logical_head(eval_tl_id)?;
        let train_result = build_backtest_run_result(
            store,
            train_registry,
            train_tl_id,
            train_ticks,
            train_events,
            train_head_seq,
            train_manifest,
            store_config.clone(),
        )?;
        let eval_result = build_backtest_run_result(
            store,
            eval_registry,
            eval_tl_id,
            eval_ticks,
            eval_events,
            eval_head_seq,
            eval_manifest,
            store_config,
        )?;

        let eval_report = pos_plugin_eval::compute_report(store, eval_tl_id)
            .map_err(|e| ExperimentError::Store(pos_core::CoreError::Storage(e.to_string())))?;

        Ok(BacktestResult {
            train_result,
            eval_result,
            train_events,
            eval_events,
            persistence_lift,
            train_avg_events_per_tick,
            eval_avg_events_per_tick,
            lift_vs_persistence,
            eval_report,
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    trait TestValueExt<T> {
        fn test_ok(self) -> T;
    }

    impl<T, E: std::fmt::Debug> TestValueExt<T> for Result<T, E> {
        fn test_ok(self) -> T {
            self.unwrap_or_else(|error| {
                std::panic::resume_unwind(Box::new(format!("unexpected test error: {error:?}")))
            })
        }
    }

    impl<T> TestValueExt<T> for Option<T> {
        fn test_ok(self) -> T {
            self.unwrap_or_else(|| std::panic::resume_unwind(Box::new("expected test value")))
        }
    }

    fn protect_session(session: ExperimentSession, subject_id: EntityId) -> ExperimentSession {
        let authority = ConsentAuthority::new();
        let grant = ConsentGrantedV1 {
            subject_id,
            grantee_id: EntityId::new(),
            purpose: "protected-projection-test".to_owned(),
            modalities: 0,
            min_geo_resolution: 0,
            fork_permitted: false,
            export_permitted: false,
            retention_days: 0,
            expiry_secs: 0,
            grant_seq: 1,
        };
        let token = authority.record_grant_on_timeline(session.timeline().id(), &grant);
        session
            .with_consent_authority(authority)
            .with_protected_token(token, 0)
    }

    trait TestErrorExt<E> {
        fn test_err(self) -> E;
    }

    impl<T, E> TestErrorExt<E> for Result<T, E> {
        fn test_err(self) -> E {
            self.err()
                .unwrap_or_else(|| std::panic::resume_unwind(Box::new("expected test error")))
        }
    }

    use super::*;
    use pos_core::{
        event::{CanonicalBytes, EventDraft, Kind},
        ids::{EntityId, PluginId, TimelineId},
        ActionApprover, ActionRejected, Capability, ConsentGrantedV1, CoreError, Event, EventStore,
        Plugin, ProposedAction, Reducer, State,
    };
    use pos_runtime::{Driver, ObservationView, ProjectionKey, RuntimeError, StepOutput};
    use pos_store::StoreConfig;

    // ── Inline test helpers ───────────────────────────────────────────────

    struct TestPlugin {
        id: PluginId,
        name: &'static str,
        event_types: Vec<Kind>,
        has_driver: bool,
        has_reducer: bool,
    }

    impl Plugin for TestPlugin {
        fn id(&self) -> PluginId {
            self.id
        }
        fn name(&self) -> &'static str {
            self.name
        }
        fn capability(&self) -> Capability {
            Capability {
                owned_event_types: self.event_types.clone(),
                owned_entity_kinds: vec![],
                has_driver: self.has_driver,
                has_reducer: self.has_reducer,
            }
        }
    }

    fn make_plugin(name: &'static str, event_types: &[&str]) -> TestPlugin {
        TestPlugin {
            id: PluginId::new(),
            name,
            event_types: event_types.iter().map(|s| Kind::new(*s)).collect(),
            has_driver: true,
            has_reducer: false,
        }
    }

    #[test]
    fn reproduction_manifest_wraps_a_host_owned_recipe() {
        let timeline_id = pos_core::ids::TimelineId::new();
        let result = RunResult {
            timeline_id,
            ticks: 0,
            total_events: 0,
            timeline_head: 0,
            manifest: ReproManifest::new(
                timeline_id,
                pos_core::crypto::Hash::zero(),
                pos_core::clock::WallTime::from_micros(0),
            ),
            projections: pos_state::ProjectionRegistry::new(),
            consent_gate: None,
            protected_token: None,
            store_config: None,
        };
        let manifest = result
            .into_reproduction_manifest(ReproductionRecipe::new(
                "test-host",
                1,
                serde_json::json!({"provider": "fixture-local"}),
            ))
            .test_ok();

        assert_eq!(manifest.manifest.timeline_id, timeline_id);
        assert_eq!(manifest.recipe.host_id, "test-host");
        assert_eq!(manifest.recipe.format_version, 1);
        assert_eq!(
            manifest.recipe.configuration,
            serde_json::json!({"provider": "fixture-local"})
        );
    }

    #[test]
    fn protected_run_result_enforces_fork_and_export_capabilities() {
        let database = tempfile::NamedTempFile::new().test_ok();
        let store_config = StoreConfig::Sqlite {
            path: database.path().to_str().test_ok().to_owned(),
        };
        let mut store = pos_store::open_store(store_config.clone()).test_ok();
        let timeline_id = store.create_timeline("run-result-policy").test_ok().id();
        let subject_id = EntityId::new();
        let authority = ConsentAuthority::new();
        let token = authority.record_grant_on_timeline(
            timeline_id,
            &ConsentGrantedV1 {
                subject_id,
                grantee_id: EntityId::new(),
                purpose: "run-result-policy".to_owned(),
                modalities: 0,
                min_geo_resolution: 0,
                fork_permitted: false,
                export_permitted: false,
                retention_days: 0,
                expiry_secs: 0,
                grant_seq: 1,
            },
        );
        let gate: Arc<dyn ConsentGate> = Arc::new(authority);
        let mut result = RunResult {
            timeline_id,
            ticks: 0,
            total_events: 0,
            timeline_head: 0,
            manifest: ReproManifest::new(
                timeline_id,
                pos_core::crypto::Hash::zero(),
                pos_core::clock::WallTime::from_micros(0),
            ),
            projections: pos_state::ProjectionRegistry::new(),
            consent_gate: Some(Arc::clone(&gate)),
            protected_token: Some(token.clone()),
            store_config: Some(store_config),
        };
        result
            .projections
            .register("projection", Box::new(CountReducer));
        result.projections.apply_event(&Event {
            id: pos_core::EventId::new(),
            entity: subject_id,
            event_type: Kind::new("projection.event"),
            payload: pos_core::CanonicalBytes::from_static(b"projection"),
            wall_time: pos_core::clock::WallTime::from_micros(0),
            seq: pos_core::clock::Seq::from_u64(1),
            causation_id: None,
            correlation_id: None,
            schema_version: pos_core::event::SchemaVersion::V1,
            signature: None,
            payload_hash: pos_core::crypto::Hash::zero(),
        });
        let projected = result
            .projection_state_for_reducer("projection", subject_id, &token, 0)
            .test_ok()
            .test_ok();
        assert_eq!(
            projected.get("n").and_then(serde_json::Value::as_u64),
            Some(1)
        );
        assert!(result
            .projection_state_for_reducer("missing", subject_id, &token, 0)
            .test_ok()
            .is_none());
        assert!(matches!(
            result.branch("forbidden"),
            Err(ExperimentError::Runtime(
                pos_runtime::RuntimeError::Consent(pos_core::ConsentError::ForkNotPermitted)
            ))
        ));
        assert!(matches!(
            result.into_reproduction_manifest(ReproductionRecipe::new(
                "test-host",
                1,
                serde_json::json!({}),
            )),
            Err(ExperimentError::Runtime(
                pos_runtime::RuntimeError::Consent(pos_core::ConsentError::ExportNotPermitted)
            ))
        ));
    }

    #[test]
    fn session_projection_reads_use_the_caller_time_and_reject_expiry() {
        let experiment = Experiment::new(ExperimentConfig {
            name: "fresh-projection-time".to_owned(),
            stop: StopCondition::MaxTicks(1),
            store_config: StoreConfig::Memory,
        });
        let session = experiment.start().test_ok();
        let timeline_id = session.timeline().id();
        let subject_id = EntityId::new();
        let authority = ConsentAuthority::new();
        let token = authority.record_grant_on_timeline(
            timeline_id,
            &ConsentGrantedV1 {
                subject_id,
                grantee_id: EntityId::new(),
                purpose: "fresh-projection-time".to_owned(),
                modalities: 0,
                min_geo_resolution: 0,
                fork_permitted: false,
                export_permitted: false,
                retention_days: 0,
                expiry_secs: 10,
                grant_seq: 1,
            },
        );
        let session = session
            .with_consent_authority(authority)
            .with_protected_token(token.clone(), 0);
        assert!(matches!(
            session.projection_state_for_reducer("missing", subject_id, &token, 11),
            Err(ExperimentError::Runtime(
                pos_runtime::RuntimeError::Consent(pos_core::ConsentError::Expired)
            ))
        ));
    }

    #[test]
    fn subject_revocation_fences_capability_before_the_closure_marker() {
        let experiment = Experiment::new(ExperimentConfig {
            name: "subject-revocation-fence".to_owned(),
            stop: StopCondition::MaxTicks(1),
            store_config: StoreConfig::Memory,
        });
        let session = experiment.start().test_ok();
        let timeline_id = session.timeline().id();
        let subject_id = EntityId::new();
        let authority = ConsentAuthority::new();
        let token = authority.record_grant_on_timeline(
            timeline_id,
            &ConsentGrantedV1 {
                subject_id,
                grantee_id: EntityId::new(),
                purpose: "subject-revocation-fence".to_owned(),
                modalities: 0,
                min_geo_resolution: 0,
                fork_permitted: true,
                export_permitted: true,
                retention_days: 0,
                expiry_secs: 0,
                grant_seq: 1,
            },
        );
        let mut session = session
            .with_consent_authority(authority.clone())
            .with_protected_token(token.clone(), 0);
        session.revoke_consent_for_subject_at_boundary(subject_id);
        assert!(matches!(
            session.projection_state_for_reducer("missing", subject_id, &token, 0),
            Err(ExperimentError::ConsentRevokedV1)
        ));
        assert!(matches!(
            session.step_tick(),
            Ok(TickOutcome::Advanced {
                emitted_events: 1,
                ..
            })
        ));
        assert!(authority
            .validate_on_timeline(timeline_id, &token, 0, 0)
            .is_err());
    }

    #[test]
    fn subject_revocation_recovery_fences_only_the_revoked_subject() {
        let database = tempfile::NamedTempFile::new().test_ok();
        let store_config = StoreConfig::Sqlite {
            path: database.path().to_str().test_ok().to_owned(),
        };
        let authority = ConsentAuthority::new();
        let subject = EntityId::new();
        let unrelated = EntityId::new();
        let mut session = Experiment::new(ExperimentConfig {
            name: "subject-recovery".to_owned(),
            stop: StopCondition::MaxTicks(2),
            store_config: store_config.clone(),
        })
        .with_consent_authority(authority.clone())
        .start()
        .test_ok();
        let timeline_id = session.timeline().id();
        let grant = |subject_id| ConsentGrantedV1 {
            subject_id,
            grantee_id: EntityId::new(),
            purpose: "subject-recovery".to_owned(),
            modalities: 0,
            min_geo_resolution: 0,
            fork_permitted: false,
            export_permitted: false,
            retention_days: 0,
            expiry_secs: 0,
            grant_seq: 1,
        };
        let subject_token = authority.record_grant_on_timeline(timeline_id, &grant(subject));
        let unrelated_token = authority.record_grant_on_timeline(timeline_id, &grant(unrelated));
        session.revoke_consent_for_subject_at_boundary(subject);
        session.step_tick().test_ok();
        drop(session);

        let resumed = Experiment::new(ExperimentConfig {
            name: "subject-recovery".to_owned(),
            stop: StopCondition::MaxTicks(2),
            store_config,
        })
        .with_consent_authority(authority.clone())
        .resume(timeline_id)
        .test_ok();
        assert!(authority
            .validate_on_timeline(timeline_id, &subject_token, 1, 0)
            .is_err());
        assert!(authority
            .validate_on_timeline(timeline_id, &unrelated_token, 1, 0)
            .is_ok());
        assert!(resumed
            .projection_state_for_reducer("missing", unrelated, &unrelated_token, 0)
            .is_ok());
    }

    fn make_plugin_with_reducer(name: &'static str, event_types: &[&str]) -> TestPlugin {
        let mut p = make_plugin(name, event_types);
        p.has_reducer = true;
        p
    }

    #[derive(Clone, Copy)]
    struct CompositionPluginSpec {
        id: PluginId,
        name: &'static str,
        version: &'static str,
        event_type: &'static str,
    }

    struct CompositionPlugin(CompositionPluginSpec);

    impl Plugin for CompositionPlugin {
        fn id(&self) -> PluginId {
            self.0.id
        }

        fn name(&self) -> &'static str {
            self.0.name
        }

        fn version(&self) -> &'static str {
            self.0.version
        }

        fn capability(&self) -> Capability {
            Capability {
                owned_event_types: vec![Kind::new(self.0.event_type)],
                owned_entity_kinds: vec![],
                has_driver: false,
                has_reducer: false,
            }
        }
    }

    fn composition_registry(plugins: &[CompositionPluginSpec]) -> PluginRegistry {
        let mut registry = PluginRegistry::new();
        for spec in plugins {
            registry
                .register(&CompositionPlugin(*spec), None, None)
                .test_ok();
        }
        registry
    }

    struct AcceptingApprover;

    impl ActionApprover for AcceptingApprover {
        fn approve(&self, proposal: &ProposedAction) -> Result<EventDraft, ActionRejected> {
            Ok(EventDraft::new(
                proposal.actor_entity_id,
                proposal.event_type.clone(),
                proposal.payload.clone(),
            ))
        }
    }

    struct UnknownEventApprover;

    impl ActionApprover for UnknownEventApprover {
        fn approve(&self, proposal: &ProposedAction) -> Result<EventDraft, ActionRejected> {
            Ok(EventDraft::new(
                proposal.actor_entity_id,
                Kind::new("unregistered.approved.event"),
                proposal.payload.clone(),
            ))
        }
    }

    #[test]
    fn experiment_register_with_approver_forwards_the_full_registration() {
        let plugin = CompositionPlugin(CompositionPluginSpec {
            id: PluginId::new(),
            name: "approver-plugin",
            version: "1",
            event_type: "approver.event",
        });
        let mut experiment = Experiment::new(ExperimentConfig {
            name: "approver-registration".to_owned(),
            stop: StopCondition::MaxTicks(0),
            store_config: StoreConfig::Memory,
        });
        experiment
            .register_with_approver(
                &plugin,
                None,
                None,
                Some(Box::new(AcceptingApprover)),
                [Kind::new("approver.event")],
            )
            .test_ok();
        let proposal = ProposedAction::new(
            Kind::new("approver.event"),
            EntityId::new(),
            CanonicalBytes::from_static(b"action"),
            Kind::new("approver.submit"),
        );
        assert_eq!(
            AcceptingApprover.approve(&proposal).test_ok().event_type,
            Kind::new("approver.event")
        );
    }

    #[test]
    fn session_submit_action_appends_the_approved_event() {
        let plugin = CompositionPlugin(CompositionPluginSpec {
            id: PluginId::new(),
            name: "submit-plugin",
            version: "1",
            event_type: "submit.event",
        });
        let mut experiment = Experiment::new(ExperimentConfig {
            name: "submit-action".to_owned(),
            stop: StopCondition::MaxTicks(1),
            store_config: StoreConfig::Memory,
        });
        experiment
            .register_with_approver(
                &plugin,
                None,
                None,
                Some(Box::new(AcceptingApprover)),
                [Kind::new("submit.event")],
            )
            .test_ok();
        let mut session = experiment.start().test_ok();
        let proposal = ProposedAction::new(
            Kind::new("submit.event"),
            EntityId::new(),
            CanonicalBytes::from_static(b"approved"),
            Kind::new("submit.event.submit"),
        );
        let denied = ProposedAction::new(
            Kind::new("submit.event"),
            EntityId::new(),
            CanonicalBytes::from_static(b"denied"),
            Kind::new("submit.event.invalid"),
        );

        assert!(session.submit_action(&denied).is_err());
        assert_eq!(session.submit_action(&proposal).test_ok(), 1);
        assert_eq!(session.source_events().test_ok().len(), 1);
    }

    #[test]
    fn session_without_drivers_commits_a_quiescent_tick() {
        let mut session = Experiment::new(ExperimentConfig {
            name: "empty-tick".to_owned(),
            stop: StopCondition::MaxTicks(1),
            store_config: StoreConfig::Memory,
        })
        .start()
        .test_ok();

        assert!(matches!(session.step_tick(), Ok(TickOutcome::Quiescent)));
        assert!(matches!(session.step_tick(), Ok(TickOutcome::Stopped)));
    }

    #[test]
    fn current_now_secs_uses_epoch_seconds() {
        assert!(current_now_secs() > 1_000_000);
    }

    #[test]
    fn fold_captured_range_advances_the_boundary() {
        let mut store = pos_store::memory::MemoryStore::new();
        let timeline = store.create_timeline("fold-boundary").test_ok();
        let mut boundary = TickBoundaryCoordinator {
            folded_through: pos_core::clock::Seq::ZERO,
        };
        let mut registry = PluginRegistry::new();
        let captured = CapturedRange {
            through: pos_core::clock::Seq::from_u64(3),
            events: Vec::new(),
            timeline,
        };

        assert_eq!(
            fold_captured_range(&mut boundary, &mut registry, &captured).0,
            0
        );
        assert_eq!(boundary.folded_through, pos_core::clock::Seq::from_u64(3));
    }

    #[test]
    fn advance_tick_distinguishes_empty_and_folded_ranges() {
        let mut empty_store = pos_store::memory::MemoryStore::new();
        let empty_timeline = empty_store.create_timeline("empty-range").test_ok();
        let empty = advance_tick(
            &mut empty_store,
            empty_timeline.id(),
            &mut PluginRegistry::new(),
            &mut TickBoundaryCoordinator {
                folded_through: pos_core::clock::Seq::ZERO,
            },
        )
        .test_ok();
        assert!(matches!(empty.0, TickAdvance::Quiescent));

        let mut folded_store = pos_store::memory::MemoryStore::new();
        let folded_timeline = folded_store.create_timeline("folded-range").test_ok();
        folded_store
            .append(
                folded_timeline.id(),
                &[EventDraft::new(
                    EntityId::new(),
                    Kind::new("folded.event"),
                    CanonicalBytes::from_static(b"folded"),
                )],
            )
            .test_ok();
        let folded = advance_tick(
            &mut folded_store,
            folded_timeline.id(),
            &mut PluginRegistry::new(),
            &mut TickBoundaryCoordinator {
                folded_through: pos_core::clock::Seq::ZERO,
            },
        )
        .test_ok();
        assert!(matches!(
            folded.0,
            TickAdvance::Advanced { folded_events: 1 }
        ));
    }

    #[test]
    fn session_submit_action_rejects_an_approver_output_with_an_unknown_schema() {
        let plugin = CompositionPlugin(CompositionPluginSpec {
            id: PluginId::new(),
            name: "unknown-output-plugin",
            version: "1",
            event_type: "submit.event",
        });
        let mut experiment = Experiment::new(ExperimentConfig {
            name: "unknown-output".to_owned(),
            stop: StopCondition::MaxTicks(1),
            store_config: StoreConfig::Memory,
        });
        experiment
            .register_with_approver(
                &plugin,
                None,
                None,
                Some(Box::new(UnknownEventApprover)),
                [Kind::new("submit.event")],
            )
            .test_ok();
        let mut session = experiment.start().test_ok();
        let proposal = ProposedAction::new(
            Kind::new("submit.event"),
            EntityId::new(),
            CanonicalBytes::from_static(b"unknown-output"),
            Kind::new("submit.event.submit"),
        );

        assert!(session.submit_action(&proposal).is_err());
    }

    #[test]
    fn session_submit_action_propagates_store_append_failure() {
        let plugin = CompositionPlugin(CompositionPluginSpec {
            id: PluginId::new(),
            name: "append-failure-plugin",
            version: "1",
            event_type: "submit.event",
        });
        let mut experiment = Experiment::new(ExperimentConfig {
            name: "append-failure".to_owned(),
            stop: StopCondition::MaxTicks(1),
            store_config: StoreConfig::Memory,
        });
        experiment
            .register_with_approver(
                &plugin,
                None,
                None,
                Some(Box::new(AcceptingApprover)),
                [Kind::new("submit.event")],
            )
            .test_ok();
        let mut session = experiment
            .start_with_store(Box::new(CaptureAwareStore {
                base: Box::new(pos_store::memory::MemoryStore::new()),
                state: Arc::new(Mutex::new(HostTransactionState::default())),
                fail_append: true,
                fail_post_step_capture: false,
            }))
            .test_ok();
        let proposal = ProposedAction::new(
            Kind::new("submit.event"),
            EntityId::new(),
            CanonicalBytes::from_static(b"append-failure"),
            Kind::new("submit.event.submit"),
        );

        assert!(session.submit_action(&proposal).is_err());
    }

    fn assert_incompatible_fork(mut session: ExperimentSession) {
        let error = session.fork("incompatible-child").err().test_ok();
        assert_eq!(
            error.to_string(),
            "the fresh PluginRegistry is incompatible with the parent plugin composition"
        );
        assert_eq!(
            lock_store(&session.store)
                .test_ok()
                .list_timelines()
                .test_ok()
                .len(),
            1
        );
    }

    /// A driver that emits `n` events of `event_type` per tick, for at most `max_ticks` ticks.
    struct FixedDriver {
        entity: EntityId,
        event_type: Kind,
        events_per_tick: usize,
        ticks_remaining: Option<u64>,
    }

    #[derive(Default)]
    struct HostTransactionState {
        steps: usize,
        commits: usize,
        aborts: usize,
        committed_tick: u64,
        staged: bool,
        anchors: Vec<pos_runtime::SnapshotAnchor>,
        append_calls: Vec<(usize, usize)>,
        capture_commits: Vec<usize>,
    }

    struct HostTransactionalDriver {
        entity: EntityId,
        event_type: Option<Kind>,
        state: Arc<Mutex<HostTransactionState>>,
        fail_step: bool,
    }

    impl Driver for HostTransactionalDriver {
        fn name(&self) -> &'static str {
            "host-transactional"
        }

        fn step(
            &mut self,
            _: pos_core::ids::TimelineId,
            observations: ObservationView<'_>,
        ) -> Result<StepOutput, RuntimeError> {
            let mut state = self.state.lock().test_ok();
            state.steps += 1;
            state.staged = true;
            state.anchors.push(observations.anchor().test_ok());
            drop(state);
            if self.fail_step {
                return Err(RuntimeError::UnknownEventType(
                    "injected partial Driver failure".to_owned(),
                ));
            }
            let drafts = self
                .event_type
                .clone()
                .map(|event_type| {
                    EventDraft::new(
                        self.entity,
                        event_type,
                        CanonicalBytes::from_static(b"host-transaction"),
                    )
                })
                .into_iter()
                .collect();
            Ok(StepOutput::new(drafts))
        }

        fn requires_snapshot_anchor(&self) -> bool {
            true
        }

        fn commit_step(&mut self) {
            let mut state = self.state.lock().test_ok();
            assert!(state.staged);
            state.staged = false;
            state.commits += 1;
            state.committed_tick += 1;
        }

        fn abort_step(&mut self) {
            let mut state = self.state.lock().test_ok();
            if state.staged {
                state.staged = false;
                state.aborts += 1;
            }
        }
    }

    struct CaptureAwareStore {
        base: Box<dyn EventStore>,
        state: Arc<Mutex<HostTransactionState>>,
        fail_append: bool,
        fail_post_step_capture: bool,
    }

    impl EventStore for CaptureAwareStore {
        fn create_timeline(&mut self, name: &str) -> Result<Timeline, CoreError> {
            self.base.create_timeline(name)
        }

        fn append(
            &mut self,
            timeline: pos_core::ids::TimelineId,
            drafts: &[EventDraft],
        ) -> Result<Vec<Event>, CoreError> {
            let mut state = self.state.lock().test_ok();
            let commits = state.commits;
            state.append_calls.push((drafts.len(), commits));
            drop(state);
            if self.fail_append {
                Err(CoreError::Storage("injected append failure".to_owned()))
            } else {
                self.base.append(timeline, drafts)
            }
        }

        fn read(
            &self,
            timeline: pos_core::ids::TimelineId,
            range: pos_core::store::SeqRange,
        ) -> Result<Vec<Event>, CoreError> {
            self.base.read(timeline, range)
        }

        fn fork(
            &mut self,
            parent: pos_core::ids::TimelineId,
            at_seq: pos_core::clock::Seq,
            name: &str,
        ) -> Result<Timeline, CoreError> {
            self.base.fork(parent, at_seq, name)
        }

        fn list_timelines(&self) -> Result<Vec<Timeline>, CoreError> {
            self.base.list_timelines()
        }

        fn get_timeline(
            &self,
            id: pos_core::ids::TimelineId,
        ) -> Result<Option<Timeline>, CoreError> {
            self.base.get_timeline(id)
        }

        fn logical_head(
            &self,
            id: pos_core::ids::TimelineId,
        ) -> Result<pos_core::clock::Seq, CoreError> {
            let state = self.state.lock().test_ok();
            if state.steps > 0 {
                let post_step_capture = !state.append_calls.is_empty();
                let commits = state.commits;
                drop(state);
                self.state.lock().test_ok().capture_commits.push(commits);
                if self.fail_post_step_capture && post_step_capture {
                    return Err(CoreError::Storage(
                        "injected post-step capture failure".to_owned(),
                    ));
                }
            }
            self.base.logical_head(id)
        }
    }

    #[test]
    fn host_transaction_adapters_cover_driver_and_store_seams() {
        let driver_state = Arc::new(Mutex::new(HostTransactionState::default()));
        let entity = EntityId::new();
        let timeline = pos_core::ids::TimelineId::new();
        let mut driver = HostTransactionalDriver {
            entity,
            event_type: Some(Kind::new("host.transaction")),
            state: Arc::clone(&driver_state),
            fail_step: false,
        };
        assert_eq!(driver.name(), "host-transactional");
        assert!(driver.requires_snapshot_anchor());
        let view = ObservationView::anchored_empty(pos_runtime::SnapshotAnchor::new(
            timeline,
            pos_core::clock::Seq::ZERO,
        ));
        assert_eq!(driver.step(timeline, view).test_ok().drafts.len(), 1);
        driver.commit_step();
        let view = ObservationView::anchored_empty(pos_runtime::SnapshotAnchor::new(
            timeline,
            pos_core::clock::Seq::ZERO,
        ));
        assert_eq!(driver.step(timeline, view).test_ok().drafts.len(), 1);
        driver.abort_step();

        let store_state = Arc::new(Mutex::new(HostTransactionState::default()));
        let mut store = CaptureAwareStore {
            base: Box::new(pos_store::memory::MemoryStore::new()),
            state: Arc::clone(&store_state),
            fail_append: false,
            fail_post_step_capture: false,
        };
        let created = store.create_timeline("capture-aware-seam").test_ok();
        let draft = EventDraft::new(
            entity,
            Kind::new("capture.event"),
            CanonicalBytes::from_static(b"capture"),
        );
        assert_eq!(store.append(created.id(), &[draft]).test_ok().len(), 1);
        assert!(!store
            .read(created.id(), pos_store::SeqRange::all())
            .test_ok()
            .is_empty());
        let _fork = store
            .fork(created.id(), pos_core::clock::Seq::ZERO, "capture-fork")
            .test_ok();
        assert!(!store.list_timelines().test_ok().is_empty());
        assert!(store.get_timeline(created.id()).test_ok().is_some());
        assert_eq!(store.logical_head(created.id()).test_ok().as_u64(), 1);
    }

    impl FixedDriver {
        fn new(entity: EntityId, event_type: &str, events_per_tick: usize) -> Self {
            Self {
                entity,
                event_type: Kind::new(event_type),
                events_per_tick,
                ticks_remaining: None,
            }
        }

        fn with_max_ticks(mut self, n: u64) -> Self {
            self.ticks_remaining = Some(n);
            self
        }
    }

    impl Driver for FixedDriver {
        fn name(&self) -> &'static str {
            "fixed"
        }
        fn step(
            &mut self,
            _: pos_core::ids::TimelineId,
            _: ObservationView<'_>,
        ) -> Result<StepOutput, RuntimeError> {
            if let Some(remaining) = self.ticks_remaining.as_mut() {
                if *remaining == 0 {
                    return Ok(StepOutput::empty());
                }
                *remaining -= 1;
            }
            let drafts: Vec<EventDraft> = (0..self.events_per_tick)
                .map(|_| {
                    EventDraft::new(
                        self.entity,
                        self.event_type.clone(),
                        CanonicalBytes::from_vec(vec![]),
                    )
                })
                .collect();
            Ok(StepOutput::new(drafts))
        }
    }

    struct CadencedCountingDriver {
        name: &'static str,
        entity: EntityId,
        event_type: Kind,
        interval: std::time::Duration,
        steps: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl Driver for CadencedCountingDriver {
        #[cfg_attr(coverage_nightly, coverage(off))]
        fn name(&self) -> &'static str {
            self.name
        }

        #[cfg_attr(coverage_nightly, coverage(off))]
        fn tick_interval(&self) -> std::time::Duration {
            self.interval
        }

        #[cfg_attr(coverage_nightly, coverage(off))]
        fn step(
            &mut self,
            _: pos_core::ids::TimelineId,
            _: ObservationView<'_>,
        ) -> Result<StepOutput, RuntimeError> {
            self.steps.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(StepOutput::new(vec![EventDraft::new(
                self.entity,
                self.event_type.clone(),
                CanonicalBytes::from_vec(self.name.as_bytes().to_vec()),
            )]))
        }
    }

    struct FailLogicalHeadStore {
        inner: Box<dyn EventStore>,
        calls: std::cell::Cell<u8>,
        fail_on_call: u8,
    }

    impl EventStore for FailLogicalHeadStore {
        #[cfg_attr(coverage_nightly, coverage(off))]
        fn create_timeline(&mut self, name: &str) -> Result<Timeline, CoreError> {
            self.inner.create_timeline(name)
        }

        #[cfg_attr(coverage_nightly, coverage(off))]
        fn append(
            &mut self,
            timeline: pos_core::ids::TimelineId,
            drafts: &[EventDraft],
        ) -> Result<Vec<Event>, CoreError> {
            self.inner.append(timeline, drafts)
        }

        #[cfg_attr(coverage_nightly, coverage(off))]
        fn read(
            &self,
            timeline: pos_core::ids::TimelineId,
            range: pos_core::store::SeqRange,
        ) -> Result<Vec<Event>, CoreError> {
            self.inner.read(timeline, range)
        }

        #[cfg_attr(coverage_nightly, coverage(off))]
        fn fork(
            &mut self,
            parent: pos_core::ids::TimelineId,
            at_seq: pos_core::clock::Seq,
            name: &str,
        ) -> Result<Timeline, CoreError> {
            self.inner.fork(parent, at_seq, name)
        }

        #[cfg_attr(coverage_nightly, coverage(off))]
        fn list_timelines(&self) -> Result<Vec<Timeline>, CoreError> {
            self.inner.list_timelines()
        }

        #[cfg_attr(coverage_nightly, coverage(off))]
        fn get_timeline(
            &self,
            id: pos_core::ids::TimelineId,
        ) -> Result<Option<Timeline>, CoreError> {
            self.inner.get_timeline(id)
        }

        #[cfg_attr(coverage_nightly, coverage(off))]
        fn logical_head(
            &self,
            id: pos_core::ids::TimelineId,
        ) -> Result<pos_core::clock::Seq, CoreError> {
            let call = self.calls.get().saturating_add(1);
            self.calls.set(call);
            if call == self.fail_on_call {
                Err(CoreError::Storage(
                    "injected boundary head failure".to_owned(),
                ))
            } else {
                self.inner.logical_head(id)
            }
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

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn projection_count(session: &ExperimentSession, entity: EntityId) -> u64 {
        let _ = entity;
        session.total_events
    }

    fn new_cadence_session(
        name: &str,
    ) -> (
        ExperimentSession,
        Arc<std::sync::atomic::AtomicUsize>,
        EntityId,
    ) {
        let entity = EntityId::new();
        let steps = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let plugin = make_plugin_with_reducer("cadence", &["cadence.event"]);
        let mut experiment = Experiment::new(ExperimentConfig {
            name: name.to_owned(),
            stop: StopCondition::MaxTicks(20),
            store_config: StoreConfig::Memory,
        });
        experiment
            .register(
                &plugin,
                Some(Box::new(CountReducer)),
                Some(Box::new(CadencedCountingDriver {
                    name: "cadence-driver",
                    entity,
                    event_type: Kind::new("cadence.event"),
                    interval: std::time::Duration::from_millis(100),
                    steps: Arc::clone(&steps),
                })),
            )
            .test_ok();
        (experiment.start().test_ok(), steps, entity)
    }

    fn cadence_session_state(
        session: &ExperimentSession,
        entity: EntityId,
        expected_steps: usize,
    ) -> (u64, u64, u64) {
        assert_eq!(
            projection_count(session, entity),
            u64::try_from(expected_steps).test_ok()
        );
        (
            session.timeline.head.as_u64(),
            session.ticks,
            session.total_events,
        )
    }

    struct RecordingDriver {
        subscriptions: Vec<ProjectionKey>,
        seen_counts: Arc<Mutex<Vec<u64>>>,
    }

    impl RecordingDriver {
        fn new(entity: EntityId, seen_counts: Arc<Mutex<Vec<u64>>>) -> Self {
            Self {
                subscriptions: vec![ProjectionKey::new(entity)],
                seen_counts,
            }
        }
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    impl Driver for RecordingDriver {
        fn name(&self) -> &'static str {
            "recording"
        }

        fn subscriptions(&self) -> &[ProjectionKey] {
            &self.subscriptions
        }

        fn step(
            &mut self,
            _: pos_core::ids::TimelineId,
            observations: ObservationView<'_>,
        ) -> Result<StepOutput, RuntimeError> {
            let count = observations
                .state_for(&self.subscriptions[0])
                .and_then(|state| state.get("n"))
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
            self.seen_counts.lock().test_ok().push(count);
            Ok(StepOutput::empty())
        }
    }

    struct InterleavingDriver {
        path: String,
        entity: EntityId,
        subscriptions: Vec<ProjectionKey>,
        seen_counts: Arc<Mutex<Vec<u64>>>,
        injected: bool,
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    impl Driver for InterleavingDriver {
        fn name(&self) -> &'static str {
            "interleaving"
        }

        fn subscriptions(&self) -> &[ProjectionKey] {
            &self.subscriptions
        }

        fn step(
            &mut self,
            timeline: pos_core::ids::TimelineId,
            observations: ObservationView<'_>,
        ) -> Result<StepOutput, RuntimeError> {
            let count = observations
                .state_for(&self.subscriptions[0])
                .and_then(|state| state.get("n"))
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
            self.seen_counts.lock().test_ok().push(count);
            if self.injected {
                return Ok(StepOutput::empty());
            }
            self.injected = true;
            let mut gateway_store =
                pos_store::sqlite::SqliteStore::open(&self.path).map_err(RuntimeError::Store)?;
            let mut human = EventDraft::new(
                self.entity,
                Kind::new("world.action"),
                CanonicalBytes::from_vec(b"human".to_vec()),
            );
            human.wall_time = Some(WallTime::from_micros(200));
            gateway_store
                .append(timeline, &[human])
                .map_err(RuntimeError::Store)?;
            let mut ai = EventDraft::new(
                self.entity,
                Kind::new("agent.decision"),
                CanonicalBytes::from_vec(b"ai".to_vec()),
            );
            ai.wall_time = Some(WallTime::from_micros(100));
            Ok(StepOutput::new(vec![ai]))
        }
    }

    struct LockInspectingReducer {
        store: Arc<Mutex<Option<SharedEventStore>>>,
        saw_unlocked_store: Arc<std::sync::atomic::AtomicBool>,
    }

    impl Reducer for LockInspectingReducer {
        fn initial(&self) -> State {
            State::new()
        }

        fn apply(&self, _: &mut State, _: &Event) {
            let store = self.store.lock().test_ok().clone();
            let is_unlocked = store.is_some_and(|store| store.try_lock().is_ok());
            self.saw_unlocked_store
                .store(is_unlocked, std::sync::atomic::Ordering::SeqCst);
        }
    }

    // ── Tests ─────────────────────────────────────────────────────────────

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn experiment_runs_to_max_ticks() {
        let entity = EntityId::new();
        let plugin = make_plugin("ticker", &["tick.event"]);
        let driver = FixedDriver::new(entity, "tick.event", 1);

        let mut exp = Experiment::new(ExperimentConfig {
            name: "max-ticks-test".to_owned(),
            stop: StopCondition::MaxTicks(5),
            store_config: StoreConfig::Memory,
        });
        exp.register(&plugin, None, Some(Box::new(driver)))
            .test_ok();

        let result = exp.run().test_ok();
        assert_eq!(result.ticks, 5);
        assert_eq!(result.total_events, 5);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn experiment_stops_on_max_events() {
        let entity = EntityId::new();
        let plugin = make_plugin("producer", &["prod.event"]);
        // 2 events per tick; stop after 6 events → 3 ticks
        let driver = FixedDriver::new(entity, "prod.event", 2);

        let mut exp = Experiment::new(ExperimentConfig {
            name: "max-events-test".to_owned(),
            stop: StopCondition::MaxEvents(6),
            store_config: StoreConfig::Memory,
        });
        exp.register(&plugin, None, Some(Box::new(driver)))
            .test_ok();

        let result = exp.run().test_ok();
        assert_eq!(result.total_events, 6);
        assert_eq!(result.ticks, 3);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn experiment_empty_driver_terminates() {
        struct IdleDriver;
        impl Driver for IdleDriver {
            fn name(&self) -> &'static str {
                "idle"
            }
            fn step(
                &mut self,
                _: pos_core::ids::TimelineId,
                _: ObservationView<'_>,
            ) -> Result<StepOutput, RuntimeError> {
                Ok(StepOutput::empty())
            }
        }

        assert_eq!(IdleDriver.name(), "idle");
        let plugin = make_plugin("idle-plugin", &[]);
        let mut exp = Experiment::new(ExperimentConfig {
            name: "idle-test".to_owned(),
            stop: StopCondition::MaxTicks(1_000_000),
            store_config: StoreConfig::Memory,
        });
        exp.register(&plugin, None, Some(Box::new(IdleDriver)))
            .test_ok();

        // Should terminate quickly, not loop forever
        let result = exp.run().test_ok();
        assert_eq!(result.ticks, 1);
        assert_eq!(result.total_events, 0);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn step_cadenced_runs_real_intervals_and_preserves_registration_order() {
        let entity = EntityId::new();
        let fast_steps = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let slow_steps = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let fast = make_plugin("fast", &["cadence.fast"]);
        let slow = make_plugin("slow", &["cadence.slow"]);
        let mut experiment = Experiment::new(ExperimentConfig {
            name: "cadenced-order".to_owned(),
            stop: StopCondition::MaxTicks(10),
            store_config: StoreConfig::Memory,
        });
        experiment
            .register(
                &fast,
                None,
                Some(Box::new(CadencedCountingDriver {
                    name: "fast-driver",
                    entity,
                    event_type: Kind::new("cadence.fast"),
                    interval: std::time::Duration::from_millis(100),
                    steps: Arc::clone(&fast_steps),
                })),
            )
            .test_ok();
        experiment
            .register(
                &slow,
                None,
                Some(Box::new(CadencedCountingDriver {
                    name: "slow-driver",
                    entity,
                    event_type: Kind::new("cadence.slow"),
                    interval: std::time::Duration::from_millis(200),
                    steps: Arc::clone(&slow_steps),
                })),
            )
            .test_ok();
        let mut session = experiment.start().test_ok();

        assert_eq!(
            session.step_cadenced(0).test_ok(),
            TickOutcome::Advanced {
                folded_events: 2,
                emitted_events: 2,
            }
        );
        assert_eq!(
            session.step_cadenced(100_000_000).test_ok(),
            TickOutcome::Advanced {
                folded_events: 1,
                emitted_events: 1,
            }
        );
        assert_eq!(
            session.step_cadenced(200_000_000).test_ok(),
            TickOutcome::Advanced {
                folded_events: 2,
                emitted_events: 2,
            }
        );
        assert_eq!(fast_steps.load(std::sync::atomic::Ordering::SeqCst), 3);
        assert_eq!(slow_steps.load(std::sync::atomic::Ordering::SeqCst), 2);
        let events = lock_store(&session.store)
            .test_ok()
            .read(session.timeline.id(), pos_store::SeqRange::all())
            .test_ok();
        assert_eq!(
            events
                .iter()
                .map(|event| event.event_type.as_str())
                .collect::<Vec<_>>(),
            vec![
                "cadence.fast",
                "cadence.slow",
                "cadence.fast",
                "cadence.fast",
                "cadence.slow",
            ]
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn step_cadenced_rejects_time_regression_before_mutation_and_remains_usable() {
        let (mut cadenced, cadenced_steps, entity) = new_cadence_session("cadence-validation");
        cadenced.step_cadenced(0).test_ok();
        cadenced.step_cadenced(100_000_000).test_ok();
        let before_steps = cadenced_steps.load(std::sync::atomic::Ordering::SeqCst);
        let before = cadence_session_state(&cadenced, entity, before_steps);
        assert!(matches!(
            cadenced.step_cadenced(99_999_999),
            Err(ExperimentError::CadenceTimeRegressed {
                previous_ns: 100_000_000,
                requested_ns: 99_999_999,
            })
        ));
        assert_eq!(
            cadenced_steps.load(std::sync::atomic::Ordering::SeqCst),
            before_steps
        );
        assert_eq!(
            cadence_session_state(&cadenced, entity, before_steps),
            before
        );
        cadenced.step_cadenced(200_000_000).test_ok();
        let equal_steps = cadenced_steps.load(std::sync::atomic::Ordering::SeqCst);
        let ticks_before_equal = cadenced.ticks;
        assert_eq!(
            cadenced.step_cadenced(200_000_000).test_ok(),
            TickOutcome::Quiescent
        );
        assert_eq!(cadenced.ticks, ticks_before_equal + 1);
        assert_eq!(
            cadenced_steps.load(std::sync::atomic::Ordering::SeqCst),
            equal_steps
        );
        assert!(matches!(
            cadenced.step_cadenced(300_000_000).test_ok(),
            TickOutcome::Advanced {
                folded_events: 1,
                emitted_events: 1,
            }
        ));
        assert_eq!(
            cadenced_steps.load(std::sync::atomic::Ordering::SeqCst),
            equal_steps + 1
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn step_cadenced_and_all_driver_modes_reject_mixing_before_mutation() {
        let (mut all_first, all_steps, all_entity) = new_cadence_session("all-first");
        all_first.step_tick().test_ok();
        let all_before_steps = all_steps.load(std::sync::atomic::Ordering::SeqCst);
        let all_before = cadence_session_state(&all_first, all_entity, all_before_steps);
        assert!(matches!(
            all_first.step_cadenced(0),
            Err(ExperimentError::StepModeMismatch {
                active: "AllDrivers",
                requested: "Cadenced",
            })
        ));
        assert_eq!(
            all_steps.load(std::sync::atomic::Ordering::SeqCst),
            all_before_steps
        );
        assert_eq!(
            cadence_session_state(&all_first, all_entity, all_before_steps),
            all_before
        );

        let (mut cadence_first, later_steps, later_entity) = new_cadence_session("cadence-first");
        cadence_first.step_cadenced(0).test_ok();
        let later_before_steps = later_steps.load(std::sync::atomic::Ordering::SeqCst);
        let later_before = cadence_session_state(&cadence_first, later_entity, later_before_steps);
        assert!(matches!(
            cadence_first.step_tick(),
            Err(ExperimentError::StepModeMismatch {
                active: "Cadenced",
                requested: "AllDrivers",
            })
        ));
        assert_eq!(
            later_steps.load(std::sync::atomic::Ordering::SeqCst),
            later_before_steps
        );
        assert_eq!(
            cadence_session_state(&cadence_first, later_entity, later_before_steps),
            later_before
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn step_cadenced_fork_and_resume_choose_fresh_modes() {
        let database = tempfile::NamedTempFile::new().test_ok();
        let path = database.path().to_str().test_ok().to_owned();
        let plugin = CompositionPluginSpec {
            id: PluginId::new(),
            name: "mode",
            version: "1.0.0",
            event_type: "mode.event",
        };
        let mut experiment = Experiment::new(ExperimentConfig {
            name: "mode-parent".to_owned(),
            stop: StopCondition::MaxTicks(10),
            store_config: StoreConfig::Sqlite { path: path.clone() },
        })
        .with_fork_registry_factory(move || Ok(composition_registry(&[plugin])));
        experiment
            .register(&CompositionPlugin(plugin), None, None)
            .test_ok();
        let mut parent = experiment.start().test_ok();
        let parent_id = parent.timeline().id();
        assert_eq!(
            parent.step_cadenced(100_000_000).test_ok(),
            TickOutcome::Quiescent
        );
        let mut child = parent.fork("mode-child").test_ok();
        assert_eq!(child.step_cadenced(0).test_ok(), TickOutcome::Quiescent);
        assert!(matches!(
            parent.step_cadenced(99_999_999),
            Err(ExperimentError::CadenceTimeRegressed {
                previous_ns: 100_000_000,
                requested_ns: 99_999_999,
            })
        ));
        assert!(matches!(
            child.step_tick(),
            Err(ExperimentError::StepModeMismatch { .. })
        ));
        drop(parent);
        drop(child);

        let mut recovery = Experiment::new(ExperimentConfig {
            name: "mode-resume".to_owned(),
            stop: StopCondition::MaxTicks(10),
            store_config: StoreConfig::Sqlite { path },
        });
        recovery
            .register(&CompositionPlugin(plugin), None, None)
            .test_ok();
        let mut resumed = recovery.resume(parent_id).test_ok();
        assert_eq!(resumed.step_cadenced(0).test_ok(), TickOutcome::Quiescent);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn step_cadenced_failed_first_boundary_does_not_latch_mode() {
        let mut session = Experiment::new(ExperimentConfig {
            name: "first-boundary-failure".to_owned(),
            stop: StopCondition::MaxTicks(10),
            store_config: StoreConfig::Memory,
        })
        .start()
        .test_ok();
        {
            let mut store = lock_store(&session.store).test_ok();
            let inner =
                std::mem::replace(&mut *store, Box::new(pos_store::memory::MemoryStore::new()));
            *store = Box::new(FailLogicalHeadStore {
                inner,
                calls: std::cell::Cell::new(0),
                fail_on_call: 1,
            });
        }

        assert!(matches!(
            session.step_cadenced(0),
            Err(ExperimentError::Store(CoreError::Storage(message)))
                if message == "injected boundary head failure"
        ));
        assert_eq!(session.ticks, 0);
        assert_eq!(session.step_tick().test_ok(), TickOutcome::Quiescent);
        assert_eq!(session.ticks, 1);
        assert!(matches!(
            session.step_cadenced(0),
            Err(ExperimentError::StepModeMismatch {
                active: "AllDrivers",
                requested: "Cadenced",
            })
        ));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn interactive_session_folds_actions_before_one_shared_snapshot_and_resumes_after_quiescence() {
        let entity = EntityId::new();
        let seen_counts = Arc::new(Mutex::new(Vec::new()));
        let plugin = make_plugin_with_reducer("actions", &["world.action"]);
        let mut experiment = Experiment::new(ExperimentConfig {
            name: "next-tick-action".to_owned(),
            stop: StopCondition::MaxTicks(10),
            store_config: StoreConfig::Memory,
        });
        experiment
            .register(
                &plugin,
                Some(Box::new(CountReducer)),
                Some(Box::new(RecordingDriver::new(
                    entity,
                    Arc::clone(&seen_counts),
                ))),
            )
            .test_ok();
        let mut session = protect_session(experiment.start().test_ok(), entity);
        let timeline = session.timeline().id();
        lock_store(&session.store)
            .test_ok()
            .append(
                timeline,
                &[EventDraft::new(
                    entity,
                    Kind::new("world.action"),
                    CanonicalBytes::from_vec(b"first".to_vec()),
                )],
            )
            .test_ok();

        assert_eq!(
            session.step_tick().test_ok(),
            TickOutcome::Advanced {
                folded_events: 1,
                emitted_events: 0,
            }
        );
        assert_eq!(session.step_tick().test_ok(), TickOutcome::Quiescent);
        lock_store(&session.store)
            .test_ok()
            .append(
                timeline,
                &[EventDraft::new(
                    entity,
                    Kind::new("world.action"),
                    CanonicalBytes::from_vec(b"second".to_vec()),
                )],
            )
            .test_ok();
        assert!(matches!(
            session.step_tick().test_ok(),
            TickOutcome::Advanced {
                folded_events: 1,
                emitted_events: 0
            }
        ));
        assert_eq!(*seen_counts.lock().test_ok(), vec![1, 1, 2]);
        assert_eq!(session.total_events, 2);
        assert_eq!(session.ticks, 3);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn action_appended_during_step_waits_for_the_post_step_logical_fold() {
        let database = tempfile::NamedTempFile::new().test_ok();
        let path = database.path().to_str().test_ok().to_owned();
        let entity = EntityId::new();
        let seen_counts = Arc::new(Mutex::new(Vec::new()));
        let plugin = make_plugin_with_reducer("interleaving", &["world.action", "agent.decision"]);
        let mut experiment = Experiment::new(ExperimentConfig {
            name: "interleaved-action".to_owned(),
            stop: StopCondition::MaxTicks(10),
            store_config: StoreConfig::Sqlite { path: path.clone() },
        });
        experiment
            .register(
                &plugin,
                Some(Box::new(CountReducer)),
                Some(Box::new(InterleavingDriver {
                    path,
                    entity,
                    subscriptions: vec![ProjectionKey::new(entity)],
                    seen_counts: Arc::clone(&seen_counts),
                    injected: false,
                })),
            )
            .test_ok();
        let mut session = protect_session(experiment.start().test_ok(), entity);
        assert_eq!(
            session.step_tick().test_ok(),
            TickOutcome::Advanced {
                folded_events: 2,
                emitted_events: 1,
            }
        );
        assert_eq!(session.step_tick().test_ok(), TickOutcome::Quiescent);
        assert_eq!(*seen_counts.lock().test_ok(), vec![0, 2]);

        let timeline = session.timeline().id();
        let store = lock_store(&session.store).test_ok();
        let events = store.read(timeline, pos_store::SeqRange::all()).test_ok();
        assert_eq!(
            events
                .iter()
                .map(|event| (event.seq.as_u64(), event.wall_time.as_micros()))
                .collect::<Vec<_>>(),
            vec![(1, 200), (2, 100)]
        );
        let mut replayed = pos_state::ProjectionRegistry::new();
        replayed.register("interleaving", Box::new(CountReducer));
        pos_time::replay(store.as_ref(), timeline, &mut replayed).test_ok();
        drop(store);
        assert!(replayed.state_for(&entity).is_some());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn projection_access_is_healthy_fault_safe_and_replay_hydrated() {
        struct UnknownDraftDriver {
            entity: EntityId,
        }

        #[cfg_attr(coverage_nightly, coverage(off))]
        impl Driver for UnknownDraftDriver {
            fn name(&self) -> &'static str {
                "unknown-draft"
            }

            fn step(
                &mut self,
                _: pos_core::ids::TimelineId,
                _: ObservationView<'_>,
            ) -> Result<StepOutput, RuntimeError> {
                Ok(StepOutput::new(vec![EventDraft::new(
                    self.entity,
                    Kind::new("unknown.event"),
                    CanonicalBytes::from_vec(Vec::new()),
                )]))
            }
        }

        let database = tempfile::NamedTempFile::new().test_ok();
        let path = database.path().to_str().test_ok().to_owned();
        let entity = EntityId::new();
        let plugin = make_plugin_with_reducer("faulting", &["world.action"]);
        let mut experiment = Experiment::new(ExperimentConfig {
            name: "fault-and-resume".to_owned(),
            stop: StopCondition::MaxTicks(10),
            store_config: StoreConfig::Sqlite { path: path.clone() },
        });
        experiment
            .register(
                &plugin,
                Some(Box::new(CountReducer)),
                Some(Box::new(UnknownDraftDriver { entity })),
            )
            .test_ok();
        let mut session = experiment.start().test_ok();
        let timeline = session.timeline().id();
        lock_store(&session.store)
            .test_ok()
            .append(
                timeline,
                &[EventDraft::new(
                    entity,
                    Kind::new("world.action"),
                    CanonicalBytes::from_vec(b"persisted".to_vec()),
                )],
            )
            .test_ok();
        assert!(matches!(
            session.step_tick(),
            Err(ExperimentError::Runtime(RuntimeError::UnknownEventType(_)))
        ));
        assert!(matches!(
            session.step_tick(),
            Err(ExperimentError::SessionFaulted)
        ));
        assert!(matches!(
            session.step_tick(),
            Err(ExperimentError::SessionFaulted)
        ));
        assert!(matches!(
            session.fork("faulted-child"),
            Err(ExperimentError::SessionFaulted)
        ));
        drop(session);

        let seen_counts = Arc::new(Mutex::new(Vec::new()));
        let recovery_plugin = make_plugin_with_reducer("recovery", &["world.action"]);
        let mut recovery = Experiment::new(ExperimentConfig {
            name: "recovered".to_owned(),
            stop: StopCondition::MaxTicks(10),
            store_config: StoreConfig::Sqlite { path },
        });
        recovery
            .register(
                &recovery_plugin,
                Some(Box::new(CountReducer)),
                Some(Box::new(RecordingDriver::new(
                    entity,
                    Arc::clone(&seen_counts),
                ))),
            )
            .test_ok();
        let mut resumed = protect_session(recovery.resume(timeline).test_ok(), entity);
        assert_eq!(resumed.total_events, 1);
        assert_eq!(projection_count(&resumed, entity), 1);
        assert_eq!(resumed.step_tick().test_ok(), TickOutcome::Quiescent);
        assert_eq!(*seen_counts.lock().test_ok(), vec![1]);
        assert_eq!(projection_count(&resumed, entity), 1);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn empty_durable_timeline_resumes_and_stops_after_one_quiescent_tick() {
        let database = tempfile::NamedTempFile::new().test_ok();
        let path = database.path().to_str().test_ok().to_owned();
        let config = StoreConfig::Sqlite { path };
        let timeline = {
            let mut store = open_store(config.clone()).test_ok();
            store.create_timeline("empty-resume").test_ok().id()
        };
        let mut session = Experiment::new(ExperimentConfig {
            name: "resumed-empty".to_owned(),
            stop: StopCondition::MaxTicks(1),
            store_config: config,
        })
        .resume(timeline)
        .test_ok();

        assert_eq!(session.step_tick().test_ok(), TickOutcome::Quiescent);
        assert_eq!(session.step_tick().test_ok(), TickOutcome::Stopped);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn durable_resume_propagates_open_and_missing_timeline_failures() {
        let directory = tempfile::tempdir().test_ok();
        let directory_config = ExperimentConfig {
            name: "resume-open-failure".to_owned(),
            stop: StopCondition::MaxTicks(1),
            store_config: StoreConfig::Sqlite {
                path: directory.path().to_str().test_ok().to_owned(),
            },
        };
        assert!(Experiment::new(directory_config)
            .resume(pos_core::ids::TimelineId::new())
            .is_err());

        let missing_database = tempfile::NamedTempFile::new().test_ok();
        let missing_path = missing_database.path().to_str().test_ok().to_owned();
        drop(
            open_store(StoreConfig::Sqlite {
                path: missing_path.clone(),
            })
            .test_ok(),
        );
        assert!(Experiment::new(ExperimentConfig {
            name: "resume-missing".to_owned(),
            stop: StopCondition::MaxTicks(1),
            store_config: StoreConfig::Sqlite { path: missing_path },
        })
        .resume(pos_core::ids::TimelineId::new())
        .is_err());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn durable_resume_propagates_metadata_and_event_read_failures() {
        let metadata_database = tempfile::NamedTempFile::new().test_ok();
        let metadata_path = metadata_database.path().to_str().test_ok().to_owned();
        let metadata_timeline = {
            let mut store = open_store(StoreConfig::Sqlite {
                path: metadata_path.clone(),
            })
            .test_ok();
            store.create_timeline("resume-metadata").test_ok().id()
        };
        rusqlite::Connection::open(&metadata_path)
            .test_ok()
            .execute(
                "UPDATE timelines SET name = X'FF' WHERE id = ?1",
                rusqlite::params![metadata_timeline.to_string()],
            )
            .test_ok();
        assert!(Experiment::new(ExperimentConfig {
            name: "resume-metadata".to_owned(),
            stop: StopCondition::MaxTicks(1),
            store_config: StoreConfig::Sqlite {
                path: metadata_path,
            },
        })
        .resume(metadata_timeline)
        .is_err());

        let read_database = tempfile::NamedTempFile::new().test_ok();
        let read_path = read_database.path().to_str().test_ok().to_owned();
        let read_timeline = {
            let mut store = open_store(StoreConfig::Sqlite {
                path: read_path.clone(),
            })
            .test_ok();
            let timeline = store.create_timeline("resume-read").test_ok();
            store
                .append(
                    timeline.id(),
                    &[EventDraft::new(
                        EntityId::new(),
                        Kind::new("resume.event"),
                        CanonicalBytes::from_vec(Vec::new()),
                    )],
                )
                .test_ok();
            timeline.id()
        };
        rusqlite::Connection::open(&read_path)
            .test_ok()
            .execute("DROP TABLE events", [])
            .test_ok();
        assert!(Experiment::new(ExperimentConfig {
            name: "resume-read".to_owned(),
            stop: StopCondition::MaxTicks(1),
            store_config: StoreConfig::Sqlite { path: read_path },
        })
        .resume(read_timeline)
        .is_err());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn durable_resume_propagates_malformed_ancestry_failure() {
        let head_database = tempfile::NamedTempFile::new().test_ok();
        let head_path = head_database.path().to_str().test_ok().to_owned();
        let malformed_head_timeline = {
            let mut store = pos_store::sqlite::SqliteStore::open(&head_path).test_ok();
            let root = store.create_timeline("resume-head-root").test_ok();
            store
                .append(
                    root.id(),
                    &[EventDraft::new(
                        EntityId::new(),
                        Kind::new("resume.event"),
                        CanonicalBytes::from_vec(Vec::new()),
                    )],
                )
                .test_ok();
            let child = store
                .fork(
                    root.id(),
                    pos_core::clock::Seq::from_u64(1),
                    "resume-head-child",
                )
                .test_ok();
            store
                .append(
                    child.id(),
                    &[EventDraft::new(
                        EntityId::new(),
                        Kind::new("resume.event"),
                        CanonicalBytes::from_vec(Vec::new()),
                    )],
                )
                .test_ok();
            store
                .fork(
                    child.id(),
                    pos_core::clock::Seq::from_u64(2),
                    "resume-head-grandchild",
                )
                .test_ok()
                .id()
        };
        let missing_parent = pos_core::ids::TimelineId::new();
        rusqlite::Connection::open(&head_path)
            .test_ok()
            .execute(
                "UPDATE timelines SET parent_id = ?2 WHERE id = ?1",
                rusqlite::params![
                    malformed_head_timeline.to_string(),
                    missing_parent.to_string()
                ],
            )
            .test_ok();
        assert!(Experiment::new(ExperimentConfig {
            name: "resume-head".to_owned(),
            stop: StopCondition::MaxTicks(1),
            store_config: StoreConfig::Sqlite { path: head_path },
        })
        .resume(malformed_head_timeline)
        .is_err());
    }

    #[derive(Clone, Copy)]
    enum CaptureFault {
        LogicalHead,
        SecondLogicalHead,
        GetTimeline,
        MissingTimeline,
        Read,
        EmptyRead,
    }

    struct CaptureFaultStore {
        base: pos_store::memory::MemoryStore,
        fault: CaptureFault,
        head_calls: std::cell::Cell<u8>,
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    impl EventStore for CaptureFaultStore {
        fn create_timeline(&mut self, name: &str) -> Result<Timeline, CoreError> {
            self.base.create_timeline(name)
        }

        fn append(
            &mut self,
            timeline: pos_core::ids::TimelineId,
            drafts: &[EventDraft],
        ) -> Result<Vec<Event>, CoreError> {
            self.base.append(timeline, drafts)
        }

        fn read(
            &self,
            timeline: pos_core::ids::TimelineId,
            range: pos_core::store::SeqRange,
        ) -> Result<Vec<Event>, CoreError> {
            match self.fault {
                CaptureFault::Read => Err(CoreError::Storage("injected read failure".to_owned())),
                CaptureFault::EmptyRead => Ok(Vec::new()),
                _ => self.base.read(timeline, range),
            }
        }

        fn fork(
            &mut self,
            parent: pos_core::ids::TimelineId,
            at_seq: pos_core::clock::Seq,
            name: &str,
        ) -> Result<Timeline, CoreError> {
            self.base.fork(parent, at_seq, name)
        }

        fn list_timelines(&self) -> Result<Vec<Timeline>, CoreError> {
            self.base.list_timelines()
        }

        fn get_timeline(
            &self,
            id: pos_core::ids::TimelineId,
        ) -> Result<Option<Timeline>, CoreError> {
            match self.fault {
                CaptureFault::GetTimeline => {
                    Err(CoreError::Storage("injected metadata failure".to_owned()))
                }
                CaptureFault::MissingTimeline => Ok(None),
                _ => self.base.get_timeline(id),
            }
        }

        fn logical_head(
            &self,
            id: pos_core::ids::TimelineId,
        ) -> Result<pos_core::clock::Seq, CoreError> {
            match self.fault {
                CaptureFault::LogicalHead => {
                    Err(CoreError::Storage("injected head failure".to_owned()))
                }
                CaptureFault::SecondLogicalHead => {
                    let calls = self.head_calls.get();
                    self.head_calls.set(calls.saturating_add(1));
                    if calls == 0 {
                        self.base.logical_head(id)
                    } else {
                        Err(CoreError::Storage(
                            "injected second head failure".to_owned(),
                        ))
                    }
                }
                _ => self.base.logical_head(id),
            }
        }
    }

    struct CaptureFailDriver;

    #[cfg_attr(coverage_nightly, coverage(off))]
    impl Driver for CaptureFailDriver {
        fn name(&self) -> &'static str {
            "capture-fail"
        }

        fn step(
            &mut self,
            _: pos_core::ids::TimelineId,
            _: ObservationView<'_>,
        ) -> Result<StepOutput, RuntimeError> {
            Err(RuntimeError::UnknownEventType(
                "capture.driver.failure".to_owned(),
            ))
        }
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn captured_ranges_propagate_each_store_and_integrity_failure() {
        for fault in [
            CaptureFault::LogicalHead,
            CaptureFault::GetTimeline,
            CaptureFault::MissingTimeline,
            CaptureFault::Read,
            CaptureFault::EmptyRead,
        ] {
            let mut store = CaptureFaultStore {
                base: pos_store::memory::MemoryStore::new(),
                fault,
                head_calls: std::cell::Cell::new(0),
            };
            let timeline = store.create_timeline("capture-fault").test_ok();
            store
                .append(
                    timeline.id(),
                    &[EventDraft::new(
                        EntityId::new(),
                        Kind::new("capture.event"),
                        CanonicalBytes::from_vec(Vec::new()),
                    )],
                )
                .test_ok();

            assert!(
                capture_pending_range(&store, timeline.id(), pos_core::clock::Seq::ZERO,).is_err()
            );
        }
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn tick_pipeline_and_branch_propagate_each_boundary_failure() {
        let mut first_capture_store = CaptureFaultStore {
            base: pos_store::memory::MemoryStore::new(),
            fault: CaptureFault::LogicalHead,
            head_calls: std::cell::Cell::new(0),
        };
        let first_timeline = first_capture_store
            .create_timeline("first-capture")
            .test_ok();
        assert!(advance_tick(
            &mut first_capture_store,
            first_timeline.id(),
            &mut PluginRegistry::new(),
            &mut TickBoundaryCoordinator {
                folded_through: pos_core::clock::Seq::ZERO,
            },
        )
        .is_err());

        let mut second_capture_store = CaptureFaultStore {
            base: pos_store::memory::MemoryStore::new(),
            fault: CaptureFault::SecondLogicalHead,
            head_calls: std::cell::Cell::new(0),
        };
        let second_timeline = second_capture_store
            .create_timeline("second-capture")
            .test_ok();
        assert!(advance_tick(
            &mut second_capture_store,
            second_timeline.id(),
            &mut PluginRegistry::new(),
            &mut TickBoundaryCoordinator {
                folded_through: pos_core::clock::Seq::ZERO,
            },
        )
        .is_err());

        let mut driver_store = pos_store::memory::MemoryStore::new();
        let driver_timeline = driver_store.create_timeline("driver-failure").test_ok();
        let mut registry = PluginRegistry::new();
        registry
            .register(
                &make_plugin("capture-fail", &[]),
                None,
                Some(Box::new(CaptureFailDriver)),
            )
            .test_ok();
        assert!(append_driver_drafts(
            &mut driver_store,
            driver_timeline.id(),
            &mut registry,
            pos_core::clock::Seq::ZERO,
        )
        .is_err());

        let mut branch_store = CaptureFaultStore {
            base: pos_store::memory::MemoryStore::new(),
            fault: CaptureFault::LogicalHead,
            head_calls: std::cell::Cell::new(0),
        };
        branch_store.create_timeline("branch-head").test_ok();
        assert!(Experiment::new(ExperimentConfig {
            name: "branch-head".to_owned(),
            stop: StopCondition::MaxTicks(1),
            store_config: StoreConfig::Memory,
        })
        .branch("child", &mut branch_store)
        .is_err());
    }

    #[derive(Clone, Copy, Debug)]
    enum TransactionHostPath {
        AdvanceTick,
        Session,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum TransactionCase {
        NonEmpty,
        ZeroDraft,
        SchemaFailure,
        AppendFailure,
        PartialDriverFailure,
        PostCaptureFailure,
    }

    fn transaction_registry(
        case: TransactionCase,
        state: &Arc<Mutex<HostTransactionState>>,
        failing_state: &Arc<Mutex<HostTransactionState>>,
    ) -> PluginRegistry {
        let (owned_event_types, emitted_event_type): (&[&str], Option<&str>) = match case {
            TransactionCase::ZeroDraft | TransactionCase::PartialDriverFailure => (&[], None),
            TransactionCase::SchemaFailure => (
                &["host.transaction.known"],
                Some("host.transaction.unknown"),
            ),
            TransactionCase::NonEmpty
            | TransactionCase::AppendFailure
            | TransactionCase::PostCaptureFailure => {
                (&["host.transaction"], Some("host.transaction"))
            }
        };
        let mut registry = PluginRegistry::new();
        registry
            .register(
                &make_plugin("host-transaction", owned_event_types),
                None,
                Some(Box::new(HostTransactionalDriver {
                    entity: EntityId::new(),
                    event_type: emitted_event_type.map(Kind::new),
                    state: Arc::clone(state),
                    fail_step: false,
                })),
            )
            .test_ok();
        if case == TransactionCase::PartialDriverFailure {
            registry
                .register(
                    &make_plugin("host-failing", &[]),
                    None,
                    Some(Box::new(HostTransactionalDriver {
                        entity: EntityId::new(),
                        event_type: None,
                        state: Arc::clone(failing_state),
                        fail_step: true,
                    })),
                )
                .test_ok();
        }
        registry
    }

    fn seed_external_event(store: &mut dyn EventStore, timeline: pos_core::ids::TimelineId) {
        store
            .append(
                timeline,
                &[EventDraft::new(
                    EntityId::new(),
                    Kind::new("external.before"),
                    CanonicalBytes::from_static(b"before"),
                )],
            )
            .test_ok();
    }

    fn capture_aware_store(
        base: Box<dyn EventStore>,
        case: TransactionCase,
        state: &Arc<Mutex<HostTransactionState>>,
    ) -> CaptureAwareStore {
        CaptureAwareStore {
            base,
            state: Arc::clone(state),
            fail_append: case == TransactionCase::AppendFailure,
            fail_post_step_capture: case == TransactionCase::PostCaptureFailure,
        }
    }

    struct HostCaseResult {
        timeline: pos_core::ids::TimelineId,
        result: Result<(), ExperimentError>,
        state: Arc<Mutex<HostTransactionState>>,
        failing_state: Arc<Mutex<HostTransactionState>>,
    }

    fn run_host_transaction_case(
        path: TransactionHostPath,
        case: TransactionCase,
    ) -> HostCaseResult {
        let state = Arc::new(Mutex::new(HostTransactionState::default()));
        let failing_state = Arc::new(Mutex::new(HostTransactionState::default()));
        let registry = transaction_registry(case, &state, &failing_state);

        let (timeline, result) = match path {
            TransactionHostPath::AdvanceTick => {
                let mut base: Box<dyn EventStore> = Box::new(pos_store::memory::MemoryStore::new());
                let timeline = base.create_timeline("transaction-advance").test_ok().id();
                seed_external_event(base.as_mut(), timeline);
                let mut store = capture_aware_store(base, case, &state);
                let mut registry = registry;
                let mut boundary = TickBoundaryCoordinator {
                    folded_through: pos_core::clock::Seq::ZERO,
                };
                let result =
                    advance_tick(&mut store, timeline, &mut registry, &mut boundary).map(|_| ());
                (timeline, result)
            }
            TransactionHostPath::Session => {
                let mut session = Experiment {
                    config: ExperimentConfig {
                        name: "transaction-session".to_owned(),
                        stop: StopCondition::MaxTicks(1),
                        store_config: StoreConfig::Memory,
                    },
                    registry,
                    fork_registry_factory: None,
                }
                .start()
                .test_ok();
                let timeline = session.timeline().id();
                {
                    let mut store = session.store.lock().test_ok();
                    seed_external_event(store.as_mut(), timeline);
                    let base = std::mem::replace(
                        &mut *store,
                        Box::new(pos_store::memory::MemoryStore::new()),
                    );
                    *store = Box::new(capture_aware_store(base, case, &state));
                }
                (timeline, session.step_tick().map(|_| ()))
            }
        };
        HostCaseResult {
            timeline,
            result,
            state,
            failing_state,
        }
    }

    fn assert_host_transaction_case(path: TransactionHostPath, case: TransactionCase) {
        let HostCaseResult {
            timeline,
            result,
            state,
            failing_state,
        } = run_host_transaction_case(path, case);
        let state = state.lock().test_ok();
        match case {
            TransactionCase::NonEmpty
            | TransactionCase::AppendFailure
            | TransactionCase::PostCaptureFailure => {
                assert_eq!(state.append_calls, [(1, 0)], "{path:?} {case:?}");
            }
            TransactionCase::ZeroDraft
            | TransactionCase::SchemaFailure
            | TransactionCase::PartialDriverFailure => {
                assert!(state.append_calls.is_empty(), "{path:?} {case:?}");
            }
        }
        assert_eq!(state.steps, 1, "{path:?} {case:?}");
        assert_eq!(
            state.anchors,
            [pos_runtime::SnapshotAnchor::new(
                timeline,
                pos_core::clock::Seq::from_u64(1)
            )],
            "{path:?} {case:?}"
        );
        assert!(!state.staged, "{path:?} {case:?}");

        match case {
            TransactionCase::NonEmpty | TransactionCase::ZeroDraft => {
                assert!(result.is_ok(), "{path:?} {case:?}: {result:?}");
                assert_eq!(state.commits, 1, "{path:?} {case:?}");
                assert_eq!(state.committed_tick, 1, "{path:?} {case:?}");
                assert_eq!(state.aborts, 0, "{path:?} {case:?}");
                if case == TransactionCase::NonEmpty {
                    assert_eq!(state.capture_commits, [0, 1], "{path:?} {case:?}");
                } else {
                    assert_eq!(state.capture_commits, [1], "{path:?} {case:?}");
                }
            }
            TransactionCase::SchemaFailure | TransactionCase::PartialDriverFailure => {
                assert!(result.is_err(), "{path:?} {case:?}");
                assert_eq!(state.commits, 0, "{path:?} {case:?}");
                assert_eq!(state.committed_tick, 0, "{path:?} {case:?}");
                assert_eq!(state.aborts, 1, "{path:?} {case:?}");
                assert!(state.capture_commits.is_empty(), "{path:?} {case:?}");
            }
            TransactionCase::AppendFailure => {
                assert!(result.is_err(), "{path:?} {case:?}");
                assert_eq!(state.commits, 0, "{path:?} {case:?}");
                assert_eq!(state.committed_tick, 0, "{path:?} {case:?}");
                assert_eq!(state.aborts, 1, "{path:?} {case:?}");
                assert_eq!(state.capture_commits, [0], "{path:?} {case:?}");
            }
            TransactionCase::PostCaptureFailure => {
                assert!(result.is_err(), "{path:?} {case:?}");
                assert_eq!(state.commits, 1, "{path:?} {case:?}");
                assert_eq!(state.committed_tick, 1, "{path:?} {case:?}");
                assert_eq!(state.aborts, 0, "{path:?} {case:?}");
                assert_eq!(state.capture_commits, [0, 1], "{path:?} {case:?}");
            }
        }
        drop(state);

        let failing_state = failing_state.lock().test_ok();
        if case == TransactionCase::PartialDriverFailure {
            assert_eq!(failing_state.steps, 1, "{path:?} {case:?}");
            assert_eq!(failing_state.commits, 0, "{path:?} {case:?}");
            assert_eq!(failing_state.committed_tick, 0, "{path:?} {case:?}");
            assert_eq!(failing_state.aborts, 1, "{path:?} {case:?}");
            assert!(!failing_state.staged, "{path:?} {case:?}");
            assert_eq!(
                failing_state.anchors,
                [pos_runtime::SnapshotAnchor::new(
                    timeline,
                    pos_core::clock::Seq::from_u64(1)
                )],
                "{path:?} {case:?}"
            );
        }
        drop(failing_state);
    }

    #[test]
    fn both_host_paths_cover_the_complete_driver_transaction_matrix() {
        for path in [
            TransactionHostPath::AdvanceTick,
            TransactionHostPath::Session,
        ] {
            for case in [
                TransactionCase::NonEmpty,
                TransactionCase::ZeroDraft,
                TransactionCase::SchemaFailure,
                TransactionCase::AppendFailure,
                TransactionCase::PartialDriverFailure,
                TransactionCase::PostCaptureFailure,
            ] {
                assert_host_transaction_case(path, case);
            }
        }
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn captured_ranges_fail_before_fold_when_length_order_or_cursor_is_invalid() {
        let mut store = pos_store::memory::MemoryStore::new();
        let timeline = store.create_timeline("range-validation").test_ok();
        let mut event = store
            .append(
                timeline.id(),
                &[EventDraft::new(
                    EntityId::new(),
                    Kind::new("range.event"),
                    CanonicalBytes::from_vec(Vec::new()),
                )],
            )
            .test_ok()
            .pop()
            .test_ok();
        assert!(validate_captured_range(
            pos_core::clock::Seq::ZERO,
            pos_core::clock::Seq::from_u64(2),
            std::slice::from_ref(&event),
        )
        .is_err());
        event.seq = pos_core::clock::Seq::from_u64(2);
        assert!(validate_captured_range(
            pos_core::clock::Seq::ZERO,
            pos_core::clock::Seq::from_u64(1),
            std::slice::from_ref(&event),
        )
        .is_err());
        assert!(
            capture_pending_range(&store, timeline.id(), pos_core::clock::Seq::from_u64(2),)
                .is_err()
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn experiment_schema_rejects_unknown_type() {
        struct BadDriver {
            entity: EntityId,
        }
        impl Driver for BadDriver {
            fn name(&self) -> &'static str {
                "bad"
            }
            fn step(
                &mut self,
                _: pos_core::ids::TimelineId,
                _: ObservationView<'_>,
            ) -> Result<StepOutput, RuntimeError> {
                let draft = EventDraft::new(
                    self.entity,
                    Kind::new("unregistered.event"),
                    CanonicalBytes::from_vec(vec![]),
                );
                Ok(StepOutput::new(vec![draft]))
            }
        }

        let entity = EntityId::new();
        assert_eq!(BadDriver { entity }.name(), "bad");
        let plugin = make_plugin("bad-plugin", &["known.event"]); // does NOT own "unregistered.event"
        let mut exp = Experiment::new(ExperimentConfig {
            name: "schema-reject-test".to_owned(),
            stop: StopCondition::MaxTicks(5),
            store_config: StoreConfig::Memory,
        });
        exp.register(&plugin, None, Some(Box::new(BadDriver { entity })))
            .test_ok();

        let err = exp.run().test_err();
        assert!(matches!(err, ExperimentError::Runtime(_)));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn experiment_fold_projects_state() {
        let entity = EntityId::new();
        let plugin = make_plugin_with_reducer("state-plugin", &["state.event"]);
        let driver = FixedDriver::new(entity, "state.event", 1).with_max_ticks(3);

        let mut exp = Experiment::new(ExperimentConfig {
            name: "fold-state-test".to_owned(),
            stop: StopCondition::MaxTicks(3),
            store_config: StoreConfig::Memory,
        });
        exp.register(
            &plugin,
            Some(Box::new(CountReducer)),
            Some(Box::new(driver)),
        )
        .test_ok();

        let result = exp.run().test_ok();
        assert_eq!(result.ticks, 3);
        assert_eq!(result.total_events, 3);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn live_session_steps_and_forks_memory_timeline() {
        let entity = EntityId::new();
        let plugin = make_plugin_with_reducer("session-ticker", &["session.event"]);
        let plugin_id = plugin.id;
        let driver = FixedDriver::new(entity, "session.event", 1);
        let config = ExperimentConfig {
            name: "session-test".to_owned(),
            stop: StopCondition::MaxTicks(2),
            store_config: StoreConfig::Memory,
        };
        let mut experiment = Experiment::new(config).with_fork_registry_factory(move || {
            let plugin = TestPlugin {
                id: plugin_id,
                name: "session-ticker",
                event_types: vec![Kind::new("session.event")],
                has_driver: true,
                has_reducer: true,
            };
            let driver = FixedDriver::new(entity, "session.event", 1);
            let mut registry = PluginRegistry::new();
            registry
                .register(
                    &plugin,
                    Some(Box::new(CountReducer)),
                    Some(Box::new(driver)),
                )
                .test_ok();
            Ok(registry)
        });
        experiment
            .register(
                &plugin,
                Some(Box::new(CountReducer)),
                Some(Box::new(driver)),
            )
            .test_ok();

        let mut session = experiment.start().test_ok();
        assert!(session.step().test_ok());
        assert_eq!(session.timeline().head, pos_core::clock::Seq::from_u64(1));
        lock_store(&session.store)
            .test_ok()
            .append(
                session.timeline().id(),
                &[EventDraft::new(
                    entity,
                    Kind::new("session.event"),
                    CanonicalBytes::from_vec(b"pending".to_vec()),
                )],
            )
            .test_ok();

        let mut fork = session.fork("session-fork").test_ok();
        assert_eq!(
            fork.timeline().meta.fork_point,
            Some((session.timeline().id(), session.timeline().head))
        );
        assert!(fork.step().test_ok());
        assert!(session.step().test_ok());
        assert_ne!(fork.timeline().id(), session.timeline().id());
        assert_eq!(session.timeline().head, pos_core::clock::Seq::from_u64(3));

        let fork_result = fork.run_to_completion().test_ok();
        assert_eq!(fork_result.ticks, 2);
        assert_eq!(fork_result.total_events, 2);

        let result = session.run_to_completion().test_ok();
        assert_eq!(result.ticks, 2);
        assert_eq!(result.total_events, 3);
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn create_durable_revocation_fixture() -> (
        tempfile::NamedTempFile,
        StoreConfig,
        TimelineId,
        EntityId,
        PluginId,
    ) {
        let database = tempfile::NamedTempFile::new().test_ok();
        let path = database.path().to_str().test_ok().to_owned();
        let entity = EntityId::new();
        let plugin = make_plugin("consent-ticker", &["experiment.tick"]);
        let plugin_id = plugin.id;
        let store_config = StoreConfig::Sqlite { path };
        let config = ExperimentConfig {
            name: "durable-consent".to_owned(),
            stop: StopCondition::MaxTicks(8),
            store_config: store_config.clone(),
        };
        let mut experiment =
            Experiment::new(config).with_consent_authority(ConsentAuthority::new());
        experiment
            .register(
                &plugin,
                None,
                Some(Box::new(FixedDriver::new(entity, "experiment.tick", 1))),
            )
            .test_ok();
        let mut session = experiment.start().test_ok();
        let first_tick = session.step_tick();
        assert!(
            matches!(
                first_tick,
                Ok(TickOutcome::Advanced {
                    emitted_events: 1,
                    ..
                })
            ),
            "first driver boundary must advance: {first_tick:?}"
        );
        let timeline_id = session.timeline().id();
        session.revoke_consent_at_boundary();
        assert!(matches!(
            session.append_events(&[EventDraft::new(
                entity,
                Kind::new("experiment.tick"),
                CanonicalBytes::from_static(b"blocked"),
            )]),
            Err(ExperimentError::ConsentRevokedV1)
        ));
        let revocation_boundary = session.step_tick();
        assert!(
            matches!(
                revocation_boundary,
                Ok(TickOutcome::Advanced {
                    emitted_events: 1,
                    ..
                })
            ),
            "host revocation boundary must commit the experiment lifecycle marker: {revocation_boundary:?}"
        );
        assert_eq!(session.step_tick().test_ok(), TickOutcome::Stopped);
        drop(session);

        (database, store_config, timeline_id, entity, plugin_id)
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn consent_revocation_is_durable_across_resume() {
        let (_database, store_config, timeline_id, entity, plugin_id) =
            create_durable_revocation_fixture();

        let resumed_plugin = TestPlugin {
            id: plugin_id,
            name: "consent-ticker",
            event_types: vec![Kind::new("experiment.tick")],
            has_driver: true,
            has_reducer: false,
        };
        let mut recovery = Experiment::new(ExperimentConfig {
            name: "durable-consent-recovery".to_owned(),
            stop: StopCondition::MaxTicks(8),
            store_config,
        });
        recovery
            .register(
                &resumed_plugin,
                None,
                Some(Box::new(FixedDriver::new(entity, "experiment.tick", 1))),
            )
            .test_ok();
        let resumed_result = recovery.resume(timeline_id);
        let resume_error = resumed_result.as_ref().err().map(ToString::to_string);
        assert!(
            resumed_result.is_ok(),
            "durable resume must accept the experiment lifecycle marker: {resume_error:?}"
        );
        let mut resumed = resumed_result.test_ok();
        let resumed_outcome = resumed.step_tick();
        assert!(
            matches!(resumed_outcome, Ok(TickOutcome::Stopped)),
            "the durable revocation marker must close the resumed session: {resumed_outcome:?}"
        );
        assert!(matches!(
            resumed.append_events(&[EventDraft::new(
                entity,
                Kind::new("experiment.tick"),
                CanonicalBytes::from_static(b"still-blocked"),
            )]),
            Err(ExperimentError::ConsentRevokedV1)
        ));
        let resumed_events = resumed.source_events_with_control().test_ok();
        assert!(resumed_events
            .iter()
            .any(|event| event.event_type.as_str() == EXPERIMENT_CONSENT_CLOSED_EVENT_TYPE));
        let marker = resumed_events
            .iter()
            .find(|event| event.event_type.as_str() == EXPERIMENT_CONSENT_CLOSED_EVENT_TYPE)
            .test_ok();
        assert_eq!(
            marker.payload.as_slice(),
            EXPERIMENT_CONSENT_TIMELINE_MARKER
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn live_session_fork_rejects_plugin_identity_mismatch_before_store_work() {
        let parent = CompositionPluginSpec {
            id: PluginId::new(),
            name: "composition",
            version: "1.0.0",
            event_type: "composition.event",
        };
        let child = CompositionPluginSpec {
            id: PluginId::new(),
            ..parent
        };
        let mut experiment = Experiment::new(ExperimentConfig {
            name: "identity-mismatch".to_owned(),
            stop: StopCondition::MaxTicks(1),
            store_config: StoreConfig::Memory,
        })
        .with_fork_registry_factory(move || Ok(composition_registry(&[child])));
        experiment
            .register(&CompositionPlugin(parent), None, None)
            .test_ok();
        assert_incompatible_fork(experiment.start().test_ok());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn live_session_fork_rejects_plugin_version_mismatch() {
        let parent = CompositionPluginSpec {
            id: PluginId::new(),
            name: "composition",
            version: "1.0.0",
            event_type: "composition.event",
        };
        let child = CompositionPluginSpec {
            version: "2.0.0",
            ..parent
        };
        let mut experiment = Experiment::new(ExperimentConfig {
            name: "version-mismatch".to_owned(),
            stop: StopCondition::MaxTicks(1),
            store_config: StoreConfig::Memory,
        })
        .with_fork_registry_factory(move || Ok(composition_registry(&[child])));
        experiment
            .register(&CompositionPlugin(parent), None, None)
            .test_ok();
        assert_incompatible_fork(experiment.start().test_ok());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn live_session_fork_rejects_plugin_registration_order_mismatch() {
        let first = CompositionPluginSpec {
            id: PluginId::new(),
            name: "first",
            version: "1.0.0",
            event_type: "first.event",
        };
        let second = CompositionPluginSpec {
            id: PluginId::new(),
            name: "second",
            version: "1.0.0",
            event_type: "second.event",
        };
        let mut experiment = Experiment::new(ExperimentConfig {
            name: "order-mismatch".to_owned(),
            stop: StopCondition::MaxTicks(1),
            store_config: StoreConfig::Memory,
        })
        .with_fork_registry_factory(move || Ok(composition_registry(&[second, first])));
        experiment
            .register(&CompositionPlugin(first), None, None)
            .test_ok();
        experiment
            .register(&CompositionPlugin(second), None, None)
            .test_ok();
        assert_incompatible_fork(experiment.start().test_ok());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn live_session_fork_rejects_effective_schema_mismatch() {
        let parent = CompositionPluginSpec {
            id: PluginId::new(),
            name: "composition",
            version: "1.0.0",
            event_type: "parent.event",
        };
        let child = CompositionPluginSpec {
            event_type: "child.event",
            ..parent
        };
        let mut experiment = Experiment::new(ExperimentConfig {
            name: "schema-mismatch".to_owned(),
            stop: StopCondition::MaxTicks(1),
            store_config: StoreConfig::Memory,
        })
        .with_fork_registry_factory(move || Ok(composition_registry(&[child])));
        experiment
            .register(&CompositionPlugin(parent), None, None)
            .test_ok();
        assert_incompatible_fork(experiment.start().test_ok());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn live_session_fork_builds_compatible_runtime_outside_the_store_lock() {
        let plugin = CompositionPluginSpec {
            id: PluginId::new(),
            name: "composition",
            version: "1.0.0",
            event_type: "composition.event",
        };
        let store: Arc<Mutex<Option<SharedEventStore>>> = Arc::new(Mutex::new(None));
        let saw_unlocked_store = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let factory_store = Arc::clone(&store);
        let factory_saw_unlocked_store = Arc::clone(&saw_unlocked_store);
        let mut experiment = Experiment::new(ExperimentConfig {
            name: "factory-outside-store-lock".to_owned(),
            stop: StopCondition::MaxTicks(1),
            store_config: StoreConfig::Memory,
        })
        .with_fork_registry_factory(move || {
            let store = factory_store.lock().test_ok().clone();
            let is_unlocked = store.is_some_and(|store| store.try_lock().is_ok());
            factory_saw_unlocked_store.store(is_unlocked, std::sync::atomic::Ordering::SeqCst);
            Ok(composition_registry(&[plugin]))
        });
        experiment
            .register(&CompositionPlugin(plugin), None, None)
            .test_ok();
        let mut session = experiment.start().test_ok();
        *store.lock().test_ok() = Some(Arc::clone(&session.store));
        let child = session.fork("compatible-child").test_ok();
        assert!(saw_unlocked_store.load(std::sync::atomic::Ordering::SeqCst));
        assert_eq!(
            child.timeline().meta.fork_point,
            Some((session.timeline().id(), session.timeline().head))
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn live_session_releases_the_store_lock_before_folding_projections() {
        let entity = EntityId::new();
        let plugin = make_plugin_with_reducer("lock-inspection", &["lock.inspection"]);
        let store = Arc::new(Mutex::new(None));
        let saw_unlocked_store = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut experiment = Experiment::new(ExperimentConfig {
            name: "lock-inspection".to_owned(),
            stop: StopCondition::MaxTicks(1),
            store_config: StoreConfig::Memory,
        });
        experiment
            .register(
                &plugin,
                Some(Box::new(LockInspectingReducer {
                    store: Arc::clone(&store),
                    saw_unlocked_store: Arc::clone(&saw_unlocked_store),
                })),
                Some(Box::new(FixedDriver::new(entity, "lock.inspection", 1))),
            )
            .test_ok();

        let mut session = experiment.start().test_ok();
        *store.lock().test_ok() = Some(Arc::clone(&session.store));
        assert!(session.step().test_ok());
        assert!(saw_unlocked_store.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn live_session_fork_requires_fresh_runtime_factory() {
        let mut session = Experiment::new(ExperimentConfig {
            name: "missing-factory".to_owned(),
            stop: StopCondition::MaxTicks(1),
            store_config: StoreConfig::Memory,
        })
        .start()
        .test_ok();

        assert!(matches!(
            session.fork("child"),
            Err(ExperimentError::MissingForkRegistryFactory)
        ));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn live_session_fork_propagates_runtime_factory_failure() {
        let mut session = Experiment::new(ExperimentConfig {
            name: "factory-failure".to_owned(),
            stop: StopCondition::MaxTicks(1),
            store_config: StoreConfig::Memory,
        })
        .with_fork_registry_factory(|| {
            Err(RuntimeError::NoDriver {
                name: "unavailable".to_owned(),
            })
        })
        .start()
        .test_ok();

        assert!(matches!(
            session.fork("child"),
            Err(ExperimentError::Runtime(RuntimeError::NoDriver { .. }))
        ));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn live_session_returns_a_stable_error_for_a_poisoned_shared_store() {
        let mut session = Experiment::new(ExperimentConfig {
            name: "poisoned-store".to_owned(),
            stop: StopCondition::MaxTicks(1),
            store_config: StoreConfig::Memory,
        })
        .with_fork_registry_factory(|| Ok(PluginRegistry::new()))
        .start()
        .test_ok();
        let store = Arc::clone(&session.store);
        drop(
            std::thread::spawn(move || {
                let _guard = store.lock().test_ok();
                std::panic::resume_unwind(Box::new("poison the shared store for this test"));
            })
            .join(),
        );

        let error = session.step().test_err();
        assert_eq!(
            error.to_string(),
            "the shared experiment EventStore lock is poisoned"
        );
        assert!(matches!(
            session.fork("child"),
            Err(ExperimentError::SharedStoreLockPoisoned)
        ));
        assert!(matches!(
            session.run_to_completion(),
            Err(ExperimentError::SharedStoreLockPoisoned)
        ));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn fixed_driver_name_is_fixed() {
        let entity = EntityId::new();
        let driver = FixedDriver::new(entity, "tick.event", 1);
        assert_eq!(driver.name(), "fixed");
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn experiment_branch_creates_fork() {
        let entity = EntityId::new();
        let plugin = make_plugin("branch-ticker", &["branch.event"]);
        let driver = FixedDriver::new(entity, "branch.event", 1);

        let mut exp = Experiment::new(ExperimentConfig {
            name: "branch-test".to_owned(),
            stop: StopCondition::MaxTicks(2),
            store_config: StoreConfig::Memory,
        });
        exp.register(&plugin, None, Some(Box::new(driver)))
            .test_ok();
        let result = exp.run().test_ok();
        assert_eq!(result.ticks, 2);

        // Re-open the same in-memory store is not possible after run() consumes it,
        // so we create a fresh store, seed a timeline, then call branch().
        let exp2 = Experiment::new(ExperimentConfig {
            name: "branch-seed".to_owned(),
            stop: StopCondition::MaxTicks(2),
            store_config: StoreConfig::Memory,
        });
        let plugin2 = make_plugin("branch-ticker2", &["branch2.event"]);
        let driver2 = FixedDriver::new(entity, "branch2.event", 1);
        let mut exp2_mut = exp2;
        exp2_mut
            .register(&plugin2, None, Some(Box::new(driver2)))
            .test_ok();

        // Consume the experiment and get a store back via run, then re-use the
        // branch logic through a manual store path.
        let mut store2 = pos_store::open_store(StoreConfig::Memory).test_ok();
        store2.create_timeline("branch-seed").test_ok();
        let forked = exp2_mut.branch("branch-seed", store2.as_mut()).test_ok();
        assert!(!forked.id().to_string().is_empty());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn experiment_branch_missing_timeline_returns_err() {
        let exp = Experiment::new(ExperimentConfig {
            name: "nonexistent".to_owned(),
            stop: StopCondition::MaxTicks(1),
            store_config: StoreConfig::Memory,
        });
        let mut store = pos_store::open_store(StoreConfig::Memory).test_ok();
        let err = exp.branch("nonexistent", store.as_mut());
        assert!(err.is_err());
    }

    #[test]
    fn public_branch_rejects_protected_history_and_capability_branch_is_explicit() {
        let subject = EntityId::new();
        let experiment = Experiment::new(ExperimentConfig {
            name: "protected-branch".to_owned(),
            stop: StopCondition::MaxTicks(1),
            store_config: StoreConfig::Memory,
        });
        let mut store = pos_store::open_store(StoreConfig::Memory).test_ok();
        let timeline = store.create_timeline("protected-branch").test_ok();
        store
            .append(
                timeline.id(),
                &[EventDraft::new(
                    subject,
                    Kind::new("persona.profile.v1"),
                    CanonicalBytes::from_static(b"protected"),
                )],
            )
            .test_ok();
        assert!(matches!(
            experiment.branch("public-child", store.as_mut()),
            Err(ExperimentError::Runtime(
                pos_runtime::RuntimeError::ConsentOperationUnavailable
            ))
        ));

        let authority = ConsentAuthority::new();
        let token = authority.record_grant_on_timeline(
            timeline.id(),
            &ConsentGrantedV1 {
                subject_id: subject,
                grantee_id: EntityId::new(),
                purpose: "branch-public-boundary".to_owned(),
                modalities: 0,
                min_geo_resolution: 0,
                fork_permitted: true,
                export_permitted: false,
                retention_days: 0,
                expiry_secs: 0,
                grant_seq: 1,
            },
        );
        let gated_experiment = Experiment::new(ExperimentConfig {
            name: "protected-branch".to_owned(),
            stop: StopCondition::MaxTicks(1),
            store_config: StoreConfig::Memory,
        })
        .with_consent_authority(authority);
        assert!(gated_experiment
            .branch_with_token("gated-child", store.as_mut(), &token, 0)
            .is_ok());

        let denied_authority = ConsentAuthority::new();
        let denied_token = denied_authority.record_grant_on_timeline(
            timeline.id(),
            &ConsentGrantedV1 {
                subject_id: subject,
                grantee_id: EntityId::new(),
                purpose: "branch-public-denied".to_owned(),
                modalities: 0,
                min_geo_resolution: 0,
                fork_permitted: false,
                export_permitted: false,
                retention_days: 0,
                expiry_secs: 0,
                grant_seq: 1,
            },
        );
        let denied_experiment = Experiment::new(ExperimentConfig {
            name: "protected-branch".to_owned(),
            stop: StopCondition::MaxTicks(1),
            store_config: StoreConfig::Memory,
        })
        .with_consent_authority(denied_authority);
        assert!(matches!(
            denied_experiment.branch_with_token("denied-child", store.as_mut(), &denied_token, 0),
            Err(ExperimentError::Runtime(
                pos_runtime::RuntimeError::Consent(pos_core::ConsentError::ForkNotPermitted)
            ))
        ));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn idle_driver_name_is_idle() {
        // Exercises the fn name() on the IdleDriver struct defined below — which is
        // a local struct and its name() is never called in experiment_empty_driver_terminates.
        struct IdleDriver2;
        impl Driver for IdleDriver2 {
            fn name(&self) -> &'static str {
                "idle2"
            }
            fn step(
                &mut self,
                _: pos_core::ids::TimelineId,
                _: ObservationView<'_>,
            ) -> Result<StepOutput, RuntimeError> {
                Ok(StepOutput::empty())
            }
        }
        let mut store = pos_store::open_store(StoreConfig::Memory).test_ok();
        let tl = store.create_timeline("idle2-test").test_ok();
        let mut d = IdleDriver2;
        assert_eq!(d.name(), "idle2");
        // Also call step to cover those lines
        let out = d.step(tl.id(), ObservationView::empty()).test_ok();
        assert!(out.drafts.is_empty());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn bad_driver_name_is_bad() {
        struct BadDriver2 {
            entity: EntityId,
        }
        impl Driver for BadDriver2 {
            fn name(&self) -> &'static str {
                "bad2"
            }
            fn step(
                &mut self,
                _: pos_core::ids::TimelineId,
                _: ObservationView<'_>,
            ) -> Result<StepOutput, RuntimeError> {
                let draft = EventDraft::new(
                    self.entity,
                    Kind::new("known.event"),
                    CanonicalBytes::from_vec(vec![]),
                );
                Ok(StepOutput::new(vec![draft]))
            }
        }
        let mut store = pos_store::open_store(StoreConfig::Memory).test_ok();
        let tl = store.create_timeline("bad2-test").test_ok();
        let entity = EntityId::new();
        let mut d = BadDriver2 { entity };
        assert_eq!(d.name(), "bad2");
        // Also call step to cover those lines
        let out = d.step(tl.id(), ObservationView::empty()).test_ok();
        assert_eq!(out.drafts.len(), 1);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn fixed_driver_exhaust_remaining_ticks() {
        // Drive FixedDriver.with_max_ticks(1) for 2 ticks — second tick hits the
        // `*remaining == 0` branch (line 259) and returns empty.
        let entity = EntityId::new();
        let plugin = make_plugin("exhaust-plugin", &["exhaust.event"]);
        let driver = FixedDriver::new(entity, "exhaust.event", 1).with_max_ticks(1);

        let mut exp = Experiment::new(ExperimentConfig {
            name: "exhaust-test".to_owned(),
            stop: StopCondition::MaxTicks(5),
            store_config: StoreConfig::Memory,
        });
        exp.register(&plugin, None, Some(Box::new(driver)))
            .test_ok();
        let result = exp.run().test_ok();
        // One emitting boundary plus one resumable quiescent boundary.
        assert_eq!(result.ticks, 2);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn run_result_has_manifest() {
        let entity = EntityId::new();
        let plugin = make_plugin("manifest-plugin", &["manifest.event"]);
        let driver = FixedDriver::new(entity, "manifest.event", 1);

        let mut exp = Experiment::new(ExperimentConfig {
            name: "manifest-test".to_owned(),
            stop: StopCondition::MaxTicks(2),
            store_config: StoreConfig::Memory,
        });
        exp.register(&plugin, None, Some(Box::new(driver)))
            .test_ok();

        let result = exp.run().test_ok();
        // The manifest should have the same timeline_id as the result
        assert_eq!(result.manifest.timeline_id, result.timeline_id);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn run_result_has_real_head_hash_after_events() {
        let entity = EntityId::new();
        let plugin = make_plugin("hash-plugin", &["hash.event"]);
        let driver = FixedDriver::new(entity, "hash.event", 1);

        let mut exp = Experiment::new(ExperimentConfig {
            name: "hash-test".to_owned(),
            stop: StopCondition::MaxTicks(3),
            store_config: StoreConfig::Memory,
        });
        exp.register(&plugin, None, Some(Box::new(driver)))
            .test_ok();

        let result = exp.run().test_ok();
        // head_hash should not be zero since events were committed
        assert_ne!(result.manifest.head_hash, pos_core::crypto::Hash::zero());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn run_result_head_hash_is_zero_when_no_events() {
        let exp = Experiment::new(ExperimentConfig {
            name: "zero-hash-test".to_owned(),
            stop: StopCondition::MaxTicks(5),
            store_config: StoreConfig::Memory,
        });
        // No plugins registered → no events → head_hash stays zero
        let result = exp.run().test_ok();
        assert_eq!(result.manifest.head_hash, pos_core::crypto::Hash::zero());
        assert_eq!(result.total_events, 0);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn run_result_has_projections() {
        let entity = EntityId::new();
        let plugin = make_plugin_with_reducer("proj-plugin", &["proj.event"]);
        let driver = FixedDriver::new(entity, "proj.event", 1).with_max_ticks(3);

        let mut exp = Experiment::new(ExperimentConfig {
            name: "proj-result-test".to_owned(),
            stop: StopCondition::MaxTicks(3),
            store_config: StoreConfig::Memory,
        });
        exp.register(
            &plugin,
            Some(Box::new(CountReducer)),
            Some(Box::new(driver)),
        )
        .test_ok();

        let result = exp.run().test_ok();
        // state_for returns from the first reducer ("proj-plugin")
        let n = result
            .projections
            .state_for(&entity)
            .and_then(|s| s.get("n"))
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        assert_eq!(n, 3);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn run_result_branch_creates_fork() {
        let entity = EntityId::new();
        let plugin = make_plugin("branch-result", &["branch.event"]);
        let driver = FixedDriver::new(entity, "branch.event", 1);

        // Use SQLite for persistence so branch() can reopen the store
        let tmp =
            std::env::temp_dir().join(format!("pos-test-{}.db", pos_core::ids::EntityId::new()));
        let path = tmp.to_str().test_ok().to_owned();

        let mut exp = Experiment::new(ExperimentConfig {
            name: "branch-result-test".to_owned(),
            stop: StopCondition::MaxTicks(2),
            store_config: StoreConfig::Sqlite { path },
        });
        exp.register(&plugin, None, Some(Box::new(driver)))
            .test_ok();
        let result = exp.run().test_ok();
        assert_eq!(result.ticks, 2);

        // Branch from the result without needing the original store
        let forked = result.branch("fork-from-result").test_ok();
        assert!(!forked.id().to_string().is_empty());
        assert_ne!(forked.id(), result.timeline_id);

        // Clean up
        drop(std::fs::remove_file(&tmp));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn fork_backed_run_result_branches_at_its_logical_head() {
        fn registry() -> PluginRegistry {
            let plugin = make_plugin("nested-result", &["nested.result.event"]);
            let mut registry = PluginRegistry::new();
            registry
                .register(
                    &plugin,
                    None,
                    Some(Box::new(FixedDriver::new(
                        EntityId::new(),
                        "nested.result.event",
                        1,
                    ))),
                )
                .test_ok();
            registry
        }

        let database = tempfile::NamedTempFile::new().test_ok();
        let path = database.path().to_str().test_ok().to_owned();
        let result = BacktestRunner::new(
            BacktestConfig {
                experiment_name: "nested-result-branch".to_owned(),
                train_ticks: 2,
                eval_ticks: 1,
                store_config: StoreConfig::Sqlite { path: path.clone() },
            },
            registry,
        )
        .run()
        .test_ok();

        let branch = result.eval_result.branch("nested-result-child").test_ok();
        assert_eq!(
            branch.meta.fork_point,
            Some((
                result.eval_result.timeline_id,
                pos_core::clock::Seq::from_u64(3)
            ))
        );
        let store = pos_store::sqlite::SqliteStore::open(&path).test_ok();
        assert_eq!(store.logical_head(branch.id()).test_ok().as_u64(), 3);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn run_result_branch_missing_timeline_returns_err() {
        // Create a result with Memory store, but timeline won't persist
        let result = RunResult {
            timeline_id: pos_core::ids::TimelineId::new(),
            ticks: 0,
            total_events: 0,
            timeline_head: 0,
            manifest: ReproManifest::new(
                pos_core::ids::TimelineId::new(),
                pos_core::crypto::Hash::zero(),
                pos_core::clock::WallTime::from_micros(0),
            ),
            projections: pos_state::ProjectionRegistry::new(),
            consent_gate: None,
            protected_token: None,
            store_config: Some(StoreConfig::Memory),
        };
        // Branching will fail because the timeline doesn't exist in a fresh Memory store
        let err = result.branch("nonexistent");
        assert!(err.is_err());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn run_result_has_store_config() {
        let entity = EntityId::new();
        let plugin = make_plugin("config-plugin", &["config.event"]);
        let driver = FixedDriver::new(entity, "config.event", 1);

        let mut exp = Experiment::new(ExperimentConfig {
            name: "config-test".to_owned(),
            stop: StopCondition::MaxTicks(1),
            store_config: StoreConfig::Memory,
        });
        exp.register(&plugin, None, Some(Box::new(driver)))
            .test_ok();
        let result = exp.run().test_ok();

        // store_config should be set to Memory
        assert!(matches!(result.store_config, Some(StoreConfig::Memory)));
    }

    #[test]
    fn host_supplied_store_result_has_no_reopen_recipe() {
        let experiment = Experiment::new(ExperimentConfig {
            name: "host-store-recipe".to_owned(),
            stop: StopCondition::MaxTicks(1),
            store_config: StoreConfig::Memory,
        });
        let session = experiment
            .start_with_store(Box::new(pos_store::memory::MemoryStore::new()))
            .test_ok();
        assert!(session.source_events().test_ok().is_empty());
        let result = session.run_to_completion().test_ok();
        assert!(result.store_config.is_none());
        assert!(matches!(
            result.branch("host-store-child"),
            Err(ExperimentError::MissingStoreRecoveryRecipe)
        ));
    }

    #[test]
    fn source_events_hides_control_and_sensitive_event_families() {
        let experiment = Experiment::new(ExperimentConfig {
            name: "source-filter".to_owned(),
            stop: StopCondition::MaxTicks(1),
            store_config: StoreConfig::Memory,
        });
        let mut session = experiment.start().test_ok();
        let entity = EntityId::new();
        lock_store(&session.store)
            .test_ok()
            .append(
                session.timeline().id(),
                &[
                    EventDraft::new(
                        entity,
                        Kind::new("public.event.v1"),
                        CanonicalBytes::from_static(b"public"),
                    ),
                    EventDraft::new(
                        entity,
                        Kind::new("persona.profile.v1"),
                        CanonicalBytes::from_static(b"sensitive"),
                    ),
                    EventDraft::new(
                        entity,
                        Kind::new(EXPERIMENT_CONSENT_CLOSED_EVENT_TYPE),
                        CanonicalBytes::from_static(EXPERIMENT_CONSENT_TIMELINE_MARKER),
                    ),
                ],
            )
            .test_ok();
        session.step_tick().test_ok();
        let events = session.source_events().test_ok();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type.as_str(), "public.event.v1");
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn run_result_manifest_has_plugin_versions() {
        let entity = EntityId::new();
        let plugin = make_plugin("manifest-plugin", &["manifest.event"]);
        let driver = FixedDriver::new(entity, "manifest.event", 1);

        let mut exp = Experiment::new(ExperimentConfig {
            name: "manifest-versions-test".to_owned(),
            stop: StopCondition::MaxTicks(1),
            store_config: StoreConfig::Memory,
        });
        exp.register(&plugin, None, Some(Box::new(driver)))
            .test_ok();
        let result = exp.run().test_ok();

        // Manifest should have plugin_versions populated
        assert!(!result.manifest.plugin_versions.is_empty());
        assert!(result
            .manifest
            .plugin_versions
            .contains_key("manifest-plugin"));
        assert_eq!(
            result.manifest.plugin_versions.get("manifest-plugin"),
            Some(&"0.1.0".to_owned())
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn run_result_manifest_has_adapter_records() {
        let entity = EntityId::new();
        let plugin = make_plugin("adapter-plugin", &["adapter.event"]);
        let driver = FixedDriver::new(entity, "adapter.event", 1);

        let mut exp = Experiment::new(ExperimentConfig {
            name: "adapter-test".to_owned(),
            stop: StopCondition::MaxTicks(1),
            store_config: StoreConfig::Memory,
        });
        exp.register(&plugin, None, Some(Box::new(driver)))
            .test_ok();
        let result = exp.run().test_ok();

        // Manifest should have adapter_records populated
        assert!(!result.manifest.adapter_records.is_empty());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn chain_head_hash_matches_manual_blake3() {
        // Verify that chain_head is actually BLAKE3 of all payload hashes concatenated.
        use pos_store::SeqRange;

        let entity = EntityId::new();
        let plugin = make_plugin("chain-plugin", &["chain.event"]);
        let driver = FixedDriver::new(entity, "chain.event", 2);
        let directory = tempfile::tempdir().test_ok();
        let path = directory.path().join("chain-head.db");

        let mut exp = Experiment::new(ExperimentConfig {
            name: "chain-hash-test".to_owned(),
            stop: StopCondition::MaxTicks(2),
            store_config: StoreConfig::Sqlite {
                path: path.to_str().test_ok().to_owned(),
            },
        });
        exp.register(&plugin, None, Some(Box::new(driver)))
            .test_ok();
        let result = exp.run().test_ok();

        let store = open_store(result.store_config.clone().test_ok()).test_ok();
        let events = store.read(result.timeline_id, SeqRange::all()).test_ok();
        assert!(!events.is_empty());
        let mut hasher = blake3::Hasher::new();
        for e in &events {
            hasher.update(e.payload_hash.as_bytes());
        }
        let expected = Hash::from_bytes(*hasher.finalize().as_bytes());
        assert_eq!(result.manifest.head_hash, expected);
        assert_ne!(result.manifest.head_hash, Hash::zero());
    }

    #[test]
    fn durable_result_branch_and_export_use_the_bound_capability() {
        let database = tempfile::NamedTempFile::new().test_ok();
        let store_config = StoreConfig::Sqlite {
            path: database.path().to_str().test_ok().to_owned(),
        };
        let mut store = open_store(store_config.clone()).test_ok();
        let timeline = store.create_timeline("unit-result-boundary").test_ok();
        let authority = ConsentAuthority::new();
        let token = authority.record_grant_on_timeline(
            timeline.id(),
            &ConsentGrantedV1 {
                subject_id: EntityId::new(),
                grantee_id: EntityId::new(),
                purpose: "unit-result-boundary".to_owned(),
                modalities: 0,
                min_geo_resolution: 0,
                fork_permitted: true,
                export_permitted: true,
                retention_days: 0,
                expiry_secs: 0,
                grant_seq: 1,
            },
        );
        let result = RunResult {
            timeline_id: timeline.id(),
            ticks: 0,
            total_events: 0,
            timeline_head: 0,
            manifest: ReproManifest::new(timeline.id(), Hash::zero(), WallTime::from_micros(0)),
            projections: pos_state::ProjectionRegistry::new(),
            consent_gate: Some(Arc::new(authority)),
            protected_token: Some(token),
            store_config: Some(store_config),
        };

        let child = result.branch("unit-result-child").test_ok();
        assert_eq!(child.meta.name.as_deref(), Some("unit-result-child"));
        let manifest = result
            .into_reproduction_manifest(ReproductionRecipe::new(
                "unit-result-host",
                1,
                serde_json::json!({"source": "unit"}),
            ))
            .test_ok();
        assert_eq!(manifest.recipe.host_id, "unit-result-host");
    }

    #[test]
    fn unit_token_branch_and_session_projection_use_durable_boundaries() {
        let experiment = Experiment::new(ExperimentConfig {
            name: "unit-token-branch".to_owned(),
            stop: StopCondition::MaxTicks(1),
            store_config: StoreConfig::Memory,
        });
        let mut store = open_store(StoreConfig::Memory).test_ok();
        let timeline = store.create_timeline("unit-token-branch").test_ok();
        let authority = ConsentAuthority::new();
        let token = authority.record_grant_on_timeline(
            timeline.id(),
            &ConsentGrantedV1 {
                subject_id: EntityId::new(),
                grantee_id: EntityId::new(),
                purpose: "unit-token-branch".to_owned(),
                modalities: 0,
                min_geo_resolution: 0,
                fork_permitted: true,
                export_permitted: false,
                retention_days: 0,
                expiry_secs: 0,
                grant_seq: 1,
            },
        );
        let gated = experiment.with_consent_authority(authority);
        let child = gated
            .branch_with_token("unit-token-child", store.as_mut(), &token, 0)
            .test_ok();
        assert_eq!(child.meta.name.as_deref(), Some("unit-token-child"));

        let mut session = Experiment::new(ExperimentConfig {
            name: "unit-session-projection".to_owned(),
            stop: StopCondition::MaxTicks(2),
            store_config: StoreConfig::Memory,
        })
        .start()
        .test_ok();
        let subject = EntityId::new();
        let authority = ConsentAuthority::new();
        let token = authority.record_grant_on_timeline(
            session.timeline().id(),
            &ConsentGrantedV1 {
                subject_id: subject,
                grantee_id: EntityId::new(),
                purpose: "unit-session-projection".to_owned(),
                modalities: 0,
                min_geo_resolution: 0,
                fork_permitted: false,
                export_permitted: false,
                retention_days: 0,
                expiry_secs: 0,
                grant_seq: 1,
            },
        );
        session = session
            .with_consent_authority(authority)
            .with_protected_token(token.clone(), 0);
        assert!(session
            .projection_state_for_reducer("missing", subject, &token, current_now_secs())
            .test_ok()
            .is_none());
    }

    #[test]
    fn durable_session_append_empty_boundary_and_subject_recovery_are_public() {
        let database = tempfile::NamedTempFile::new().test_ok();
        let store_config = StoreConfig::Sqlite {
            path: database.path().to_str().test_ok().to_owned(),
        };
        let plugin = TestPlugin {
            id: PluginId::new(),
            name: "unit-session-events",
            event_types: vec![Kind::new("unit.session.event")],
            has_driver: false,
            has_reducer: false,
        };
        let plugin_id = plugin.id;
        let mut experiment = Experiment::new(ExperimentConfig {
            name: "unit-session-events".to_owned(),
            stop: StopCondition::MaxTicks(2),
            store_config: store_config.clone(),
        });
        experiment.register(&plugin, None, None).test_ok();
        let session = experiment.start().test_ok();
        let timeline_id = session.timeline().id();
        let subject = EntityId::new();
        let authority = ConsentAuthority::new();
        let token = authority.record_grant_on_timeline(
            timeline_id,
            &ConsentGrantedV1 {
                subject_id: subject,
                grantee_id: EntityId::new(),
                purpose: "unit-session-events".to_owned(),
                modalities: 0,
                min_geo_resolution: 0,
                fork_permitted: false,
                export_permitted: false,
                retention_days: 0,
                expiry_secs: 0,
                grant_seq: 1,
            },
        );
        let mut session = session
            .with_consent_authority(authority.clone())
            .with_protected_token(token.clone(), 0);
        assert_eq!(session.append_events(&[]).test_ok(), 0);
        assert_eq!(
            session
                .append_events(&[EventDraft::new(
                    subject,
                    Kind::new("unit.session.event"),
                    CanonicalBytes::from_static(b"unit"),
                )])
                .test_ok(),
            1
        );
        assert_eq!(session.source_events().test_ok().len(), 1);
        assert!(session
            .projection_state_for_reducer("missing", subject, &token, current_now_secs())
            .test_ok()
            .is_none());

        session.revoke_consent_for_subject_at_boundary(subject);
        assert!(matches!(
            session.step_tick(),
            Ok(TickOutcome::Advanced {
                emitted_events: 1,
                ..
            })
        ));
        drop(session);

        let resumed_plugin = TestPlugin {
            id: plugin_id,
            name: "unit-session-events",
            event_types: vec![Kind::new("unit.session.event")],
            has_driver: false,
            has_reducer: false,
        };
        let mut resumed_experiment = Experiment::new(ExperimentConfig {
            name: "unit-session-events".to_owned(),
            stop: StopCondition::MaxTicks(2),
            store_config,
        });
        resumed_experiment
            .register(&resumed_plugin, None, None)
            .test_ok();
        let resumed = resumed_experiment
            .with_consent_authority(authority)
            .resume(timeline_id)
            .test_ok();
        assert!(matches!(
            resumed.projection_state_for_reducer("missing", subject, &token, current_now_secs()),
            Err(ExperimentError::ConsentRevokedV1)
        ));
    }

    #[test]
    fn protected_session_fork_hydrates_through_the_unit_seam() {
        let authority = ConsentAuthority::new();
        let experiment = Experiment::new(ExperimentConfig {
            name: "unit-protected-fork".to_owned(),
            stop: StopCondition::MaxTicks(1),
            store_config: StoreConfig::Memory,
        })
        .with_consent_authority(authority.clone())
        .with_fork_registry_factory(|| Ok(PluginRegistry::new()));
        let session = experiment.start().test_ok();
        let token = authority.record_grant_on_timeline(
            session.timeline().id(),
            &ConsentGrantedV1 {
                subject_id: EntityId::new(),
                grantee_id: EntityId::new(),
                purpose: "unit-protected-fork".to_owned(),
                modalities: 0,
                min_geo_resolution: 0,
                fork_permitted: true,
                export_permitted: false,
                retention_days: 0,
                expiry_secs: 0,
                grant_seq: 1,
            },
        );
        let mut session = session.with_protected_token(token, 0);
        let child = session.fork("unit-protected-child").test_ok();
        assert_eq!(
            child.timeline().meta.name.as_deref(),
            Some("unit-protected-child")
        );
    }

    #[test]
    fn nonempty_backtest_builds_durable_run_results_in_the_unit_seam() {
        let entity = EntityId::new();
        let runner = BacktestRunner::new(
            BacktestConfig {
                experiment_name: "unit-backtest".to_owned(),
                train_ticks: 1,
                eval_ticks: 1,
                store_config: StoreConfig::Memory,
            },
            move || {
                let plugin = make_plugin("unit-backtest-plugin", &["unit.backtest.event"]);
                let mut registry = PluginRegistry::new();
                registry
                    .register(
                        &plugin,
                        None,
                        Some(Box::new(FixedDriver::new(entity, "unit.backtest.event", 1))),
                    )
                    .test_ok();
                registry
            },
        );
        let result = runner.run().test_ok();
        assert_eq!(result.train_events, 1);
        assert_eq!(result.eval_events, 1);
        assert_eq!(result.train_result.timeline_head, 1);
        assert_eq!(result.eval_result.timeline_head, 2);
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod coverage_entrypoints {
    use super::*;
    use pos_core::store::EventStore;
    use pos_core::{Capability, ConsentGrantedV1, Plugin, PluginId};
    use pos_runtime::{Driver, ObservationView, RuntimeError, StepOutput};

    struct CoveragePlugin {
        id: PluginId,
    }

    impl Plugin for CoveragePlugin {
        fn id(&self) -> PluginId {
            self.id
        }

        fn name(&self) -> &'static str {
            "coverage-failing-plugin"
        }

        fn capability(&self) -> Capability {
            Capability {
                owned_event_types: vec![Kind::new("coverage.failure")],
                has_driver: true,
                ..Capability::default()
            }
        }
    }

    struct FailingDriver;

    impl Driver for FailingDriver {
        fn name(&self) -> &'static str {
            "coverage-failing-driver"
        }

        fn step(
            &mut self,
            _: pos_core::ids::TimelineId,
            _: ObservationView<'_>,
        ) -> Result<StepOutput, RuntimeError> {
            Err(RuntimeError::InvalidRecoveryEvidence {
                reason: "coverage driver failure",
            })
        }
    }

    struct SubjectDriver {
        subject: EntityId,
    }

    impl Driver for SubjectDriver {
        fn name(&self) -> &'static str {
            "coverage-subject-driver"
        }

        fn step(
            &mut self,
            _: pos_core::ids::TimelineId,
            _: ObservationView<'_>,
        ) -> Result<StepOutput, RuntimeError> {
            Ok(StepOutput {
                drafts: vec![EventDraft::new(
                    self.subject,
                    Kind::new("coverage.failure"),
                    pos_core::CanonicalBytes::from_static(b"coverage"),
                )],
            })
        }
    }

    struct RestoreFailDriver;

    impl Driver for RestoreFailDriver {
        fn name(&self) -> &'static str {
            "coverage-restore-failure"
        }

        fn step(
            &mut self,
            _: pos_core::ids::TimelineId,
            _: ObservationView<'_>,
        ) -> Result<StepOutput, RuntimeError> {
            Ok(StepOutput::empty())
        }

        fn needs_recovery_payload(&self, _: &pos_runtime::driver::RecoveryEventHeader) -> bool {
            true
        }

        fn stage_restore_from_history(
            &mut self,
            _: &pos_runtime::driver::DriverRecoveryEvidence,
        ) -> Result<(), RuntimeError> {
            Err(RuntimeError::InvalidRecoveryEvidence {
                reason: "coverage restore failure",
            })
        }
    }

    struct BacktestDriver {
        entity: EntityId,
    }

    impl Driver for BacktestDriver {
        fn name(&self) -> &'static str {
            "coverage-backtest-driver"
        }

        fn step(
            &mut self,
            _: pos_core::ids::TimelineId,
            _: ObservationView<'_>,
        ) -> Result<StepOutput, RuntimeError> {
            Ok(StepOutput {
                drafts: vec![EventDraft::new(
                    self.entity,
                    Kind::new("coverage.failure"),
                    pos_core::CanonicalBytes::from_static(b"backtest"),
                )],
            })
        }
    }

    #[test]
    fn consent_drafts_are_rejected_at_the_public_session_seam() {
        let experiment =
            Experiment::new(config("coverage-consent-draft", StopCondition::MaxTicks(1)));
        let mut session = ok(experiment.start());
        let result = session.append_events(&[EventDraft::new(
            EntityId::new(),
            Kind::new(pos_core::EVENT_TYPE_CONSENT_GRANTED_V1),
            pos_core::CanonicalBytes::from_static(b"coverage"),
        )]);
        assert!(matches!(result, Err(ExperimentError::ConsentRevokedV1)));
    }

    #[test]
    fn driver_runtime_errors_are_preserved_at_tick_boundary() {
        let plugin = CoveragePlugin {
            id: PluginId::new(),
        };
        let mut experiment =
            Experiment::new(config("coverage-driver-error", StopCondition::MaxTicks(1)));
        ok(experiment.register(&plugin, None, Some(Box::new(FailingDriver))));
        let mut session = ok(experiment.start());
        assert!(matches!(
            session.step_tick(),
            Err(ExperimentError::Runtime(_))
        ));
    }

    #[test]
    fn revoked_subject_drafts_and_faulted_projection_reads_fail_closed() {
        let subject = EntityId::new();
        let plugin = CoveragePlugin {
            id: PluginId::new(),
        };
        let mut experiment =
            Experiment::new(config("coverage-revoked-draft", StopCondition::MaxTicks(3)))
                .with_consent_authority(ConsentAuthority::new());
        ok(experiment.register(&plugin, None, Some(Box::new(SubjectDriver { subject }))));
        let mut session = ok(experiment.start());
        session.revoke_consent_for_subject_at_boundary(subject);
        let _ = ok(session.step_tick());
        assert!(matches!(
            session.step_tick(),
            Err(ExperimentError::ConsentRevokedV1)
        ));

        let failing_plugin = CoveragePlugin {
            id: PluginId::new(),
        };
        let mut failing = Experiment::new(config(
            "coverage-faulted-projection",
            StopCondition::MaxTicks(2),
        ))
        .with_consent_authority(ConsentAuthority::new());
        ok(failing.register(&failing_plugin, None, Some(Box::new(FailingDriver))));
        let mut faulted = ok(failing.start());
        let failed_step = faulted.step_tick();
        expect_err(&failed_step);
        let authority = ConsentAuthority::new();
        let token = authority.record_grant_on_timeline(
            faulted.timeline().id(),
            &ConsentGrantedV1 {
                subject_id: EntityId::new(),
                grantee_id: EntityId::new(),
                purpose: "coverage-faulted-projection".to_owned(),
                modalities: 0,
                min_geo_resolution: 0,
                fork_permitted: false,
                export_permitted: false,
                retention_days: 0,
                expiry_secs: 0,
                grant_seq: 1,
            },
        );
        expect_err(&faulted.projection_state_for_reducer("missing", EntityId::new(), &token, 0));
    }

    #[test]
    fn runtime_error_mapping_preserves_store_and_generic_variants() {
        let store = map_runtime_error(pos_runtime::RuntimeError::Store(
            pos_core::CoreError::Storage("coverage-store".to_owned()),
        ));
        assert!(matches!(
            store,
            ExperimentError::Store(pos_core::CoreError::Storage(message))
                if message == "coverage-store"
        ));

        let generic = map_runtime_error(pos_runtime::RuntimeError::InvalidRecoveryEvidence {
            reason: "coverage-runtime",
        });
        assert!(matches!(generic, ExperimentError::Runtime(_)));
    }

    #[test]
    fn resume_recovers_host_closure_through_the_default_gate() {
        let database = ok(tempfile::NamedTempFile::new());
        let path = ok(database
            .path()
            .to_str()
            .ok_or("coverage temp path is not utf8"))
        .to_owned();
        let config = StoreConfig::Sqlite { path };
        let timeline = {
            let mut store = ok(open_store(config.clone()));
            let timeline = ok(store.create_timeline("coverage-resume-closure"));
            ok(store.append(
                timeline.id(),
                &[EventDraft::new(
                    EntityId::new(),
                    Kind::new(EXPERIMENT_CONSENT_CLOSED_EVENT_TYPE),
                    pos_core::CanonicalBytes::from_static(EXPERIMENT_CONSENT_TIMELINE_MARKER),
                )],
            ));
            timeline.id()
        };
        let session = ok(Experiment::new(ExperimentConfig {
            name: "coverage-resume-closure".to_owned(),
            stop: StopCondition::MaxTicks(1),
            store_config: config,
        })
        .resume(timeline));
        assert!(session.consent_revoked);
    }

    #[test]
    fn resume_rejects_host_closure_when_the_gate_is_unavailable() {
        let database = ok(tempfile::NamedTempFile::new());
        let path = ok(database
            .path()
            .to_str()
            .ok_or("coverage missing-gate path is not utf8"))
        .to_owned();
        let config = StoreConfig::Sqlite { path };
        let timeline = {
            let mut store = ok(open_store(config.clone()));
            let timeline = ok(store.create_timeline("coverage-missing-gate-resume"));
            ok(store.append(
                timeline.id(),
                &[EventDraft::new(
                    EntityId::new(),
                    Kind::new(EXPERIMENT_CONSENT_CLOSED_EVENT_TYPE),
                    pos_core::CanonicalBytes::from_static(EXPERIMENT_CONSENT_TIMELINE_MARKER),
                )],
            ));
            timeline.id()
        };
        let experiment = Experiment::new(ExperimentConfig {
            name: "coverage-missing-gate-resume".to_owned(),
            stop: StopCondition::MaxTicks(1),
            store_config: config,
        })
        .without_consent_gate();
        assert!(matches!(
            experiment.resume(timeline),
            Err(ExperimentError::Runtime(
                RuntimeError::ConsentOperationUnavailable
            ))
        ));
    }

    #[test]
    fn resume_applies_host_closure_to_a_bound_gate() {
        let database = ok(tempfile::NamedTempFile::new());
        let path = ok(database
            .path()
            .to_str()
            .ok_or("coverage bound resume path is not utf8"))
        .to_owned();
        let store_config = StoreConfig::Sqlite { path };
        let timeline = {
            let mut store = ok(open_store(store_config.clone()));
            let timeline = ok(store.create_timeline("coverage-bound-resume"));
            ok(store.append(
                timeline.id(),
                &[EventDraft::new(
                    EntityId::new(),
                    Kind::new(EXPERIMENT_CONSENT_CLOSED_EVENT_TYPE),
                    pos_core::CanonicalBytes::from_static(EXPERIMENT_CONSENT_TIMELINE_MARKER),
                )],
            ));
            timeline.id()
        };
        let authority = ConsentAuthority::new();
        let session = ok(Experiment::new(ExperimentConfig {
            name: "coverage-bound-resume".to_owned(),
            stop: StopCondition::MaxTicks(1),
            store_config,
        })
        .with_consent_authority(authority)
        .resume(timeline));
        assert!(session.consent_revoked);
    }

    #[test]
    fn default_gate_revocation_boundary_commits_the_host_marker() {
        let mut session = ok(Experiment::new(config(
            "coverage-no-gate-revocation",
            StopCondition::MaxTicks(1),
        ))
        .start());
        session.revoke_consent_at_boundary();
        assert!(matches!(
            session.step_tick(),
            Ok(TickOutcome::Advanced {
                emitted_events: 1,
                ..
            })
        ));
    }

    #[test]
    fn revocation_boundary_rejects_missing_gate_before_append() {
        let experiment = Experiment::new(config(
            "coverage-missing-gate-revocation",
            StopCondition::MaxTicks(1),
        ))
        .without_consent_gate();
        let mut session = ok(experiment.start());
        session.revoke_consent_at_boundary();
        assert!(matches!(
            session.step_tick(),
            Err(ExperimentError::Runtime(
                RuntimeError::ConsentOperationUnavailable
            ))
        ));
    }

    #[test]
    fn backtest_builds_train_and_eval_results_through_public_runner() {
        let plugin_id = PluginId::new();
        let entity = EntityId::new();
        let runner = BacktestRunner::new(
            BacktestConfig {
                experiment_name: "coverage-nonempty-backtest".to_owned(),
                train_ticks: 1,
                eval_ticks: 1,
                store_config: StoreConfig::Memory,
            },
            move || {
                let mut registry = PluginRegistry::new();
                ok(registry.register(
                    &CoveragePlugin { id: plugin_id },
                    None,
                    Some(Box::new(BacktestDriver { entity })),
                ));
                registry
            },
        );
        let result = ok(runner.run());
        assert_eq!(result.train_events, 1);
        assert_eq!(result.eval_events, 1);
        assert_eq!(result.train_result.timeline_head, 1);
        assert_eq!(result.eval_result.timeline_head, 2);
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn ok<T, E: std::fmt::Debug>(value: Result<T, E>) -> T {
        value.unwrap_or_else(|error| {
            std::panic::resume_unwind(Box::new(format!("unexpected coverage error: {error:?}")))
        })
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn expect_err<T, E: std::fmt::Debug>(value: &Result<T, E>) {
        if value.is_ok() {
            std::panic::resume_unwind(Box::new("expected a rejected coverage value"));
        }
    }

    fn config(name: &str, stop: StopCondition) -> ExperimentConfig {
        ExperimentConfig {
            name: name.to_owned(),
            stop,
            store_config: StoreConfig::Memory,
        }
    }

    #[test]
    fn recovery_and_fork_entrypoints_fail_closed_without_state() {
        let result = RunResult {
            timeline_id: pos_core::ids::TimelineId::new(),
            ticks: 0,
            total_events: 0,
            timeline_head: 0,
            manifest: ReproManifest::new(
                pos_core::ids::TimelineId::new(),
                pos_core::crypto::Hash::from_bytes([0; 32]),
                pos_core::clock::WallTime::from_micros(0),
            ),
            projections: pos_state::ProjectionRegistry::new(),
            consent_gate: None,
            protected_token: None,
            store_config: None,
        };
        expect_err(&result.branch("missing-recipe"));

        let result = RunResult {
            store_config: Some(StoreConfig::Memory),
            ..result
        };
        expect_err(&result.branch("missing-timeline"));

        let store = pos_store::memory::MemoryStore::new();
        expect_err(&read_completed_prefix_at(
            &store,
            pos_core::ids::TimelineId::new(),
            pos_core::clock::Seq::ZERO,
        ));
        expect_err(&timeline_ancestry(
            &store,
            pos_core::ids::TimelineId::new(),
            pos_core::clock::Seq::ZERO,
        ));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn public_result_and_branch_error_boundaries_are_explicit() {
        let subject = EntityId::new();
        let authority = ConsentAuthority::new();
        let timeline = pos_core::ids::TimelineId::new();
        let grant = ConsentGrantedV1 {
            subject_id: subject,
            grantee_id: EntityId::new(),
            purpose: "coverage-result-errors".to_owned(),
            modalities: 0,
            min_geo_resolution: 0,
            fork_permitted: true,
            export_permitted: false,
            retention_days: 0,
            expiry_secs: 0,
            grant_seq: 1,
        };
        let token = authority.record_grant_on_timeline(timeline, &grant);
        let invalid_store_result = RunResult {
            timeline_id: timeline,
            ticks: 0,
            total_events: 0,
            timeline_head: 0,
            manifest: ReproManifest::new(timeline, Hash::zero(), WallTime::from_micros(0)),
            projections: pos_state::ProjectionRegistry::new(),
            consent_gate: Some(Arc::new(authority.clone())),
            protected_token: Some(token.clone()),
            store_config: Some(StoreConfig::Sqlite {
                path: "/dev/null/coverage-result-errors".to_owned(),
            }),
        };
        expect_err(
            &invalid_store_result.projection_state_for_reducer("missing", subject, &token, 0),
        );

        let database = ok(tempfile::NamedTempFile::new());
        let store_config = StoreConfig::Sqlite {
            path: ok(database
                .path()
                .to_str()
                .ok_or("coverage result path is not utf8"))
            .to_owned(),
        };
        let durable_timeline = {
            let mut store = ok(open_store(store_config.clone()));
            ok(store.create_timeline("coverage-result-errors")).id()
        };
        let durable_token = authority.record_grant_on_timeline(durable_timeline, &grant);
        let result = RunResult {
            timeline_id: durable_timeline,
            ticks: 0,
            total_events: 0,
            timeline_head: 0,
            manifest: ReproManifest::new(durable_timeline, Hash::zero(), WallTime::from_micros(0)),
            projections: pos_state::ProjectionRegistry::new(),
            consent_gate: Some(Arc::new(authority.clone())),
            protected_token: Some(durable_token.clone()),
            store_config: Some(store_config),
        };
        expect_err(&result.projection_state_for_reducer(
            "missing",
            EntityId::new(),
            &durable_token,
            0,
        ));
        ok(authority.fence_timeline_at(durable_timeline, 1));
        expect_err(&result.branch("coverage-revoked-branch"));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn public_branch_propagates_protected_history_read_failure() {
        let database = ok(tempfile::NamedTempFile::new());
        let path = ok(database
            .path()
            .to_str()
            .ok_or("coverage read path is not utf8"));
        let mut store = ok(open_store(StoreConfig::Sqlite {
            path: path.to_owned(),
        }));
        let timeline = ok(store.create_timeline("coverage-read-fault"));
        ok(store.append(
            timeline.id(),
            &[EventDraft::new(
                EntityId::new(),
                Kind::new("coverage.read.fault"),
                pos_core::CanonicalBytes::from_static(b"coverage"),
            )],
        ));
        drop(store);
        ok(rusqlite::Connection::open(path).and_then(|connection| {
            connection
                .execute("UPDATE events SET event_type = X'FF'", [])
                .map(|_| ())
        }));
        let mut reopened = ok(open_store(StoreConfig::Sqlite {
            path: path.to_owned(),
        }));
        assert!(
            Experiment::new(config("coverage-read-fault", StopCondition::MaxTicks(1),))
                .branch("coverage-read-fault-child", reopened.as_mut())
                .is_err()
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn append_driver_drafts_propagates_head_failure() {
        struct EmitDriver {
            entity: EntityId,
        }

        impl Driver for EmitDriver {
            fn name(&self) -> &'static str {
                "coverage-head-fault-driver"
            }

            fn step(
                &mut self,
                _: pos_core::ids::TimelineId,
                _: ObservationView<'_>,
            ) -> Result<StepOutput, RuntimeError> {
                Ok(StepOutput {
                    drafts: vec![EventDraft::new(
                        self.entity,
                        Kind::new("coverage.failure"),
                        pos_core::CanonicalBytes::from_static(b"head-fault"),
                    )],
                })
            }
        }

        let mut head_fault_store = pos_store::memory::MemoryStore::new();
        let entity = EntityId::new();
        let mut registry = PluginRegistry::new();
        ok(registry.register(
            &CoveragePlugin {
                id: PluginId::new(),
            },
            None,
            Some(Box::new(EmitDriver { entity })),
        ));
        assert!(append_driver_drafts(
            &mut head_fault_store,
            pos_core::ids::TimelineId::new(),
            &mut registry,
            pos_core::clock::Seq::ZERO,
        )
        .is_err());
    }

    #[test]
    fn public_session_fork_hydrates_at_the_completed_boundary() {
        let experiment =
            Experiment::new(config("coverage-session-fork", StopCondition::MaxTicks(1)))
                .with_fork_registry_factory(|| Ok(PluginRegistry::new()));
        let mut session = ok(experiment.start());
        let child = ok(session.fork("coverage-session-child"));
        assert_eq!(
            child.timeline().meta.name.as_deref(),
            Some("coverage-session-child")
        );
    }

    #[test]
    fn public_session_fork_rejects_protected_history() {
        let experiment = Experiment::new(config(
            "coverage-session-protected",
            StopCondition::MaxTicks(1),
        ))
        .with_fork_registry_factory(|| Ok(PluginRegistry::new()));
        let mut session = ok(experiment.start());
        let timeline_id = session.timeline().id();
        let mut store = ok(lock_store(&session.store));
        ok(store.append(
            timeline_id,
            &[EventDraft::new(
                EntityId::new(),
                Kind::new(pos_core::EVENT_TYPE_CONSENT_GRANTED_V1),
                pos_core::CanonicalBytes::from_static(b"protected"),
            )],
        ));
        drop(store);

        ok(session.step_tick());
        assert!(session.fork("coverage-session-protected-child").is_err());
    }

    #[test]
    fn protected_fork_hydration_propagates_driver_restore_errors() {
        let authority = ConsentAuthority::new();
        let plugin = CoveragePlugin {
            id: PluginId::new(),
        };
        let factory_id = plugin.id;
        let mut experiment =
            Experiment::new(config("coverage-restore-fork", StopCondition::MaxTicks(1)))
                .with_consent_authority(authority.clone())
                .with_fork_registry_factory(move || {
                    let mut registry = PluginRegistry::new();
                    registry.register(
                        &CoveragePlugin { id: factory_id },
                        None,
                        Some(Box::new(RestoreFailDriver)),
                    )?;
                    Ok(registry)
                });
        ok(experiment.register(&plugin, None, Some(Box::new(RestoreFailDriver))));
        let session = ok(experiment.start());
        let token = authority.record_grant_on_timeline(
            session.timeline().id(),
            &ConsentGrantedV1 {
                subject_id: EntityId::new(),
                grantee_id: EntityId::new(),
                purpose: "coverage-restore-fork".to_owned(),
                modalities: 0,
                min_geo_resolution: 0,
                fork_permitted: true,
                export_permitted: false,
                retention_days: 0,
                expiry_secs: 0,
                grant_seq: 1,
            },
        );
        let mut session = session.with_protected_token(token, 0);
        expect_err(&session.fork("coverage-restore-child"));
    }

    #[test]
    fn public_experiment_branch_uses_store_history_boundary() {
        let experiment = Experiment::new(config(
            "coverage-experiment-branch",
            StopCondition::MaxTicks(1),
        ));
        let mut store = pos_store::memory::MemoryStore::new();
        let timeline = ok(store.create_timeline("coverage-experiment-branch"));
        ok(store.append(
            timeline.id(),
            &[EventDraft::new(
                EntityId::new(),
                Kind::new("coverage.public.branch"),
                pos_core::CanonicalBytes::from_static(b"coverage"),
            )],
        ));
        let child = ok(experiment.branch("coverage-experiment-child", &mut store));
        assert_eq!(
            child.meta.name.as_deref(),
            Some("coverage-experiment-child")
        );
    }

    #[test]
    fn result_and_experiment_branch_seams_reopen_public_history() {
        let database = ok(tempfile::NamedTempFile::new());
        let store_config = StoreConfig::Sqlite {
            path: ok(database
                .path()
                .to_str()
                .ok_or("coverage temp path is not utf8"))
            .to_owned(),
        };
        let mut store = ok(open_store(store_config.clone()));
        let timeline = ok(store.create_timeline("coverage-result-branch"));
        ok(store.append(
            timeline.id(),
            &[EventDraft::new(
                EntityId::new(),
                Kind::new("coverage.public.event"),
                pos_core::CanonicalBytes::from_static(b"coverage"),
            )],
        ));
        let result = RunResult {
            timeline_id: timeline.id(),
            ticks: 0,
            total_events: 0,
            timeline_head: 0,
            manifest: ReproManifest::new(
                timeline.id(),
                pos_core::crypto::Hash::zero(),
                pos_core::clock::WallTime::from_micros(0),
            ),
            projections: pos_state::ProjectionRegistry::new(),
            consent_gate: None,
            protected_token: None,
            store_config: Some(store_config.clone()),
        };
        assert!(format!("{result:?}").contains("RunResult"));
        let child = ok(result.branch("coverage-result-child"));
        assert_eq!(child.meta.name.as_deref(), Some("coverage-result-child"));

        ok(store.append(
            timeline.id(),
            &[EventDraft::new(
                EntityId::new(),
                Kind::new(pos_core::EVENT_TYPE_CONSENT_GRANTED_V1),
                pos_core::CanonicalBytes::from_static(b"host-owned"),
            )],
        ));
        let rejected = RunResult {
            timeline_id: timeline.id(),
            ticks: 0,
            total_events: 0,
            timeline_head: 0,
            manifest: ReproManifest::new(
                timeline.id(),
                pos_core::crypto::Hash::zero(),
                pos_core::clock::WallTime::from_micros(0),
            ),
            projections: pos_state::ProjectionRegistry::new(),
            consent_gate: None,
            protected_token: None,
            store_config: Some(store_config),
        };
        expect_err(&rejected.branch("coverage-rejected-child"));
    }

    #[test]
    fn protected_result_branch_uses_the_token_fence() {
        let database = ok(tempfile::NamedTempFile::new());
        let store_config = StoreConfig::Sqlite {
            path: ok(database
                .path()
                .to_str()
                .ok_or("coverage temp path is not utf8"))
            .to_owned(),
        };
        let mut store = ok(open_store(store_config.clone()));
        let timeline = ok(store.create_timeline("coverage-protected-result"));
        let authority = ConsentAuthority::new();
        let protected_token = authority.record_grant_on_timeline(
            timeline.id(),
            &ConsentGrantedV1 {
                subject_id: EntityId::new(),
                grantee_id: EntityId::new(),
                purpose: "coverage-result-protected".to_owned(),
                modalities: 0,
                min_geo_resolution: 0,
                fork_permitted: true,
                export_permitted: false,
                retention_days: 0,
                expiry_secs: 0,
                grant_seq: 1,
            },
        );
        let protected_result = RunResult {
            timeline_id: timeline.id(),
            ticks: 0,
            total_events: 0,
            timeline_head: 0,
            manifest: ReproManifest::new(
                timeline.id(),
                pos_core::crypto::Hash::zero(),
                pos_core::clock::WallTime::from_micros(0),
            ),
            projections: pos_state::ProjectionRegistry::new(),
            consent_gate: Some(Arc::new(authority)),
            protected_token: Some(protected_token),
            store_config: Some(store_config),
        };
        let protected_child = ok(protected_result.branch("coverage-protected-child"));
        assert_eq!(
            protected_child.meta.name.as_deref(),
            Some("coverage-protected-child")
        );
    }

    #[test]
    fn experiment_token_branch_fails_closed_without_an_authority() {
        let experiment =
            Experiment::new(config("coverage-token-branch", StopCondition::MaxTicks(1)));
        let mut memory = pos_store::memory::MemoryStore::new();
        let timeline = ok(memory.create_timeline("coverage-token-branch"));
        let token = ConsentAuthority::new().record_grant_on_timeline(
            timeline.id(),
            &ConsentGrantedV1 {
                subject_id: EntityId::new(),
                grantee_id: EntityId::new(),
                purpose: "coverage-token-branch".to_owned(),
                modalities: 0,
                min_geo_resolution: 0,
                fork_permitted: true,
                export_permitted: false,
                retention_days: 0,
                expiry_secs: 0,
                grant_seq: 1,
            },
        );
        let mut missing = pos_store::memory::MemoryStore::new();
        expect_err(&experiment.branch_with_token("coverage-token-child", &mut missing, &token, 0));
        expect_err(&experiment.branch_with_token("coverage-token-child", &mut memory, &token, 0));
    }

    #[test]
    fn result_branch_and_export_require_matching_capability_state() {
        let database = ok(tempfile::NamedTempFile::new());
        let store_config = StoreConfig::Sqlite {
            path: ok(database
                .path()
                .to_str()
                .ok_or("coverage temp path is not utf8"))
            .to_owned(),
        };
        let mut store = ok(open_store(store_config.clone()));
        let timeline = ok(store.create_timeline("coverage-result-guards"));
        let authority = ConsentAuthority::new();
        let token = authority.record_grant_on_timeline(
            timeline.id(),
            &ConsentGrantedV1 {
                subject_id: EntityId::new(),
                grantee_id: EntityId::new(),
                purpose: "coverage-result-guards".to_owned(),
                modalities: 0,
                min_geo_resolution: 0,
                fork_permitted: false,
                export_permitted: false,
                retention_days: 0,
                expiry_secs: 0,
                grant_seq: 1,
            },
        );
        let gate: Arc<dyn ConsentGate> = Arc::new(authority);
        let mismatched = RunResult {
            timeline_id: timeline.id(),
            ticks: 0,
            total_events: 0,
            timeline_head: 0,
            manifest: ReproManifest::new(
                timeline.id(),
                pos_core::crypto::Hash::zero(),
                pos_core::clock::WallTime::from_micros(0),
            ),
            projections: pos_state::ProjectionRegistry::new(),
            consent_gate: Some(Arc::clone(&gate)),
            protected_token: None,
            store_config: Some(store_config.clone()),
        };
        expect_err(&mismatched.branch("coverage-mismatch"));
        let no_token_export = RunResult {
            timeline_id: timeline.id(),
            ticks: 0,
            total_events: 0,
            timeline_head: 0,
            manifest: ReproManifest::new(
                timeline.id(),
                pos_core::crypto::Hash::zero(),
                pos_core::clock::WallTime::from_micros(0),
            ),
            projections: pos_state::ProjectionRegistry::new(),
            consent_gate: Some(Arc::clone(&gate)),
            protected_token: None,
            store_config: None,
        };
        expect_err(
            &no_token_export.into_reproduction_manifest(ReproductionRecipe::new(
                "coverage-host",
                1,
                serde_json::json!({}),
            )),
        );
        let denied_export = RunResult {
            timeline_id: timeline.id(),
            ticks: 0,
            total_events: 0,
            timeline_head: 0,
            manifest: ReproManifest::new(
                timeline.id(),
                pos_core::crypto::Hash::zero(),
                pos_core::clock::WallTime::from_micros(0),
            ),
            projections: pos_state::ProjectionRegistry::new(),
            consent_gate: Some(Arc::clone(&gate)),
            protected_token: Some(token),
            store_config: Some(store_config),
        };
        expect_err(
            &denied_export.into_reproduction_manifest(ReproductionRecipe::new(
                "coverage-host",
                1,
                serde_json::json!({}),
            )),
        );
    }

    #[test]
    fn result_export_accepts_a_matching_export_capability() {
        let database = ok(tempfile::NamedTempFile::new());
        let store_config = StoreConfig::Sqlite {
            path: ok(database
                .path()
                .to_str()
                .ok_or("coverage export path is not utf8"))
            .to_owned(),
        };
        let mut store = ok(open_store(store_config.clone()));
        let timeline = ok(store.create_timeline("coverage-result-export"));
        let authority = ConsentAuthority::new();
        let token = authority.record_grant_on_timeline(
            timeline.id(),
            &ConsentGrantedV1 {
                subject_id: EntityId::new(),
                grantee_id: EntityId::new(),
                purpose: "coverage-result-export".to_owned(),
                modalities: 0,
                min_geo_resolution: 0,
                fork_permitted: false,
                export_permitted: true,
                retention_days: 0,
                expiry_secs: 0,
                grant_seq: 1,
            },
        );
        let export_result = RunResult {
            timeline_id: timeline.id(),
            ticks: 0,
            total_events: 0,
            timeline_head: 0,
            manifest: ReproManifest::new(
                timeline.id(),
                pos_core::crypto::Hash::zero(),
                pos_core::clock::WallTime::from_micros(0),
            ),
            projections: pos_state::ProjectionRegistry::new(),
            consent_gate: Some(Arc::new(authority)),
            protected_token: Some(token),
            store_config: Some(store_config),
        };
        let manifest = ok(
            export_result.into_reproduction_manifest(ReproductionRecipe::new(
                "coverage-export",
                1,
                serde_json::json!({}),
            )),
        );
        assert_eq!(manifest.recipe.host_id, "coverage-export");
    }

    #[test]
    fn protected_session_fork_revalidates_a_timeline_capability() {
        let authority = ConsentAuthority::new();
        let experiment = Experiment::new(config(
            "coverage-protected-session-fork",
            StopCondition::MaxTicks(1),
        ))
        .with_consent_authority(authority.clone())
        .with_fork_registry_factory(|| Ok(PluginRegistry::new()));
        let session = ok(experiment.start());
        let token = authority.record_grant_on_timeline(
            session.timeline().id(),
            &ConsentGrantedV1 {
                subject_id: EntityId::new(),
                grantee_id: EntityId::new(),
                purpose: "coverage-protected-fork".to_owned(),
                modalities: 0,
                min_geo_resolution: 0,
                fork_permitted: true,
                export_permitted: false,
                retention_days: 0,
                expiry_secs: 0,
                grant_seq: 1,
            },
        );
        let mut session = session.with_protected_token(token, 0);
        let child = ok(session.fork("coverage-child"));
        assert_eq!(
            child.timeline().meta.name.as_deref(),
            Some("coverage-child")
        );
    }

    #[test]
    fn protected_session_fork_rejects_a_token_without_fork_permission() {
        let authority = ConsentAuthority::new();
        let experiment = Experiment::new(config(
            "coverage-denied-session-fork",
            StopCondition::MaxTicks(1),
        ))
        .with_consent_authority(authority.clone())
        .with_fork_registry_factory(|| Ok(PluginRegistry::new()));
        let session = ok(experiment.start());
        let token = authority.record_grant_on_timeline(
            session.timeline().id(),
            &ConsentGrantedV1 {
                subject_id: EntityId::new(),
                grantee_id: EntityId::new(),
                purpose: "coverage-denied-fork".to_owned(),
                modalities: 0,
                min_geo_resolution: 0,
                fork_permitted: false,
                export_permitted: false,
                retention_days: 0,
                expiry_secs: 0,
                grant_seq: 1,
            },
        );
        let mut session = session.with_protected_token(token, 0);
        assert!(matches!(
            session.fork("coverage-denied-child"),
            Err(ExperimentError::Runtime(RuntimeError::Consent(
                pos_core::ConsentError::ForkNotPermitted
            )))
        ));
    }

    #[test]
    fn run_result_projection_and_public_export_fail_closed_or_succeed_explicitly() {
        let authority = ConsentAuthority::new();
        let subject = EntityId::new();
        let token = authority.record_grant_on_timeline(
            pos_core::ids::TimelineId::new(),
            &ConsentGrantedV1 {
                subject_id: subject,
                grantee_id: EntityId::new(),
                purpose: "coverage-result".to_owned(),
                modalities: 0,
                min_geo_resolution: 0,
                fork_permitted: false,
                export_permitted: true,
                retention_days: 0,
                expiry_secs: 0,
                grant_seq: 1,
            },
        );
        let result = RunResult {
            timeline_id: pos_core::ids::TimelineId::new(),
            ticks: 0,
            total_events: 0,
            timeline_head: 0,
            manifest: ReproManifest::new(
                pos_core::ids::TimelineId::new(),
                pos_core::crypto::Hash::zero(),
                pos_core::clock::WallTime::from_micros(0),
            ),
            projections: pos_state::ProjectionRegistry::new(),
            consent_gate: None,
            protected_token: None,
            store_config: None,
        };
        expect_err(&result.projection_state_for_reducer("coverage", subject, &token, 0));
        let manifest = ok(result.into_reproduction_manifest(ReproductionRecipe::new(
            "coverage-host",
            1,
            serde_json::json!({"case": "public"}),
        )));
        assert_eq!(manifest.recipe.host_id, "coverage-host");
    }

    #[test]
    fn consent_revocation_boundaries_filter_control_markers_and_continue_subjects() {
        let authority = ConsentAuthority::new();
        let experiment = Experiment::new(config(
            "coverage-consent-boundaries",
            StopCondition::MaxTicks(3),
        ))
        .with_consent_authority(authority.clone());
        let mut session = ok(experiment.start());
        let subject = EntityId::new();
        let revoked_subject = EntityId::new();
        let untrusted_authority = ConsentAuthority::new();
        let token = untrusted_authority.record_grant_on_timeline(
            session.timeline().id(),
            &ConsentGrantedV1 {
                subject_id: subject,
                grantee_id: EntityId::new(),
                purpose: "coverage-session-projection".to_owned(),
                modalities: 0,
                min_geo_resolution: 0,
                fork_permitted: false,
                export_permitted: false,
                retention_days: 0,
                expiry_secs: 0,
                grant_seq: 1,
            },
        );
        let _revoked_token = authority.record_grant_on_timeline(
            session.timeline().id(),
            &ConsentGrantedV1 {
                subject_id: revoked_subject,
                grantee_id: EntityId::new(),
                purpose: "coverage-session-revocation".to_owned(),
                modalities: 0,
                min_geo_resolution: 0,
                fork_permitted: false,
                export_permitted: false,
                retention_days: 0,
                expiry_secs: 0,
                grant_seq: 2,
            },
        );
        expect_err(&session.projection_state_for_reducer("missing", subject, &token, 0));
        session.revoke_consent_for_subject_at_boundary(revoked_subject);
        assert!(matches!(
            session.step_tick(),
            Ok(TickOutcome::Advanced { .. })
        ));
        assert!(session
            .source_events()
            .is_ok_and(|events| events.is_empty()));

        session.revoke_consent_at_boundary();
        assert!(matches!(
            session.step_tick(),
            Ok(TickOutcome::Advanced { .. })
        ));
        assert!(matches!(session.step_tick(), Ok(TickOutcome::Stopped)));
        session.revoke_consent_at_boundary();
        session.revoke_consent_for_subject_at_boundary(revoked_subject);
        assert!(matches!(session.step_tick(), Ok(TickOutcome::Stopped)));
    }

    #[test]
    fn empty_host_and_backtest_paths_are_exercised() {
        let experiment = Experiment::new(config("empty-start", StopCondition::MaxTicks(2)));
        let mut session = ok(experiment.start());
        let _ = ok(session.step_tick());
        let _ = ok(session.step());
        let _ = ok(session.source_events());
        expect_err(&session.fork("missing-factory"));

        let experiment = Experiment::new(config("supplied-store", StopCondition::MaxTicks(1)));
        let _ = ok(experiment.start_with_store(Box::new(pos_store::memory::MemoryStore::new())));

        let config = BacktestConfig {
            experiment_name: "empty-backtest".to_owned(),
            train_ticks: 1,
            eval_ticks: 1,
            store_config: StoreConfig::Memory,
        };
        let runner = BacktestRunner::new(config, pos_runtime::PluginRegistry::new);
        let _ = ok(runner.run());
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod integration_tests {
    trait TestValueExt<T> {
        fn test_ok(self) -> T;
    }

    impl<T, E: std::fmt::Debug> TestValueExt<T> for Result<T, E> {
        fn test_ok(self) -> T {
            self.unwrap_or_else(|error| {
                std::panic::resume_unwind(Box::new(format!("unexpected test error: {error:?}")))
            })
        }
    }

    impl<T> TestValueExt<T> for Option<T> {
        fn test_ok(self) -> T {
            self.unwrap_or_else(|| std::panic::resume_unwind(Box::new("expected test value")))
        }
    }

    use super::*;
    use pos_core::ids::EntityId;
    use pos_plugin_rule_agent::{RuleAgentDriver, RuleAgentPlugin, RuleAgentReducer};
    use pos_plugin_synthetic_obs::{SyntheticDriver, SyntheticObsPlugin, SyntheticReducer};

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn dual_plugin_compose_runs_and_projects_state() {
        let agent_entity = EntityId::new();
        let obs_entity = EntityId::new();

        let config = ExperimentConfig {
            name: "compose-test".to_owned(),
            stop: StopCondition::MaxTicks(5),
            store_config: pos_store::StoreConfig::Memory,
        };

        let mut exp = Experiment::new(config);

        // Register rule-agent plugin
        let agent_plugin = RuleAgentPlugin::new();
        let agent_driver = RuleAgentDriver::new(agent_entity, agent_plugin.actions().to_vec());
        let agent_reducer = RuleAgentReducer;
        exp.register(
            &agent_plugin,
            Some(Box::new(agent_reducer)),
            Some(Box::new(agent_driver)),
        )
        .test_ok();

        // Register synthetic-obs plugin
        let obs_plugin = SyntheticObsPlugin::new();
        let obs_driver = SyntheticDriver::new(obs_entity);
        let obs_reducer = SyntheticReducer;
        exp.register(
            &obs_plugin,
            Some(Box::new(obs_reducer)),
            Some(Box::new(obs_driver)),
        )
        .test_ok();

        let result = exp.run().test_ok();

        // 5 ticks × 2 plugins = 10 events minimum
        assert!(
            result.total_events >= 10,
            "expected at least 10 events, got {}",
            result.total_events
        );
        assert_eq!(result.ticks, 5);

        // Verify agent state was projected (decision count should be 5)
        // rule-agent is first registered reducer → state_for_reducer("rule-agent", ...)
        let decisions = result
            .projections
            .state_for_reducer("rule-agent", &agent_entity)
            .and_then(|s| s.get("decisions"))
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        assert_eq!(decisions, 5, "expected 5 decisions projected");

        // Verify obs state was projected (observation count should be 5)
        let obs_count = result
            .projections
            .state_for_reducer("synthetic-obs", &obs_entity)
            .and_then(|s| s.get("observations"))
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        assert_eq!(obs_count, 5, "expected 5 observations projected");
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod backtest_tests {
    trait TestValueExt<T> {
        fn test_ok(self) -> T;
    }

    impl<T, E: std::fmt::Debug> TestValueExt<T> for Result<T, E> {
        fn test_ok(self) -> T {
            self.unwrap_or_else(|error| {
                std::panic::resume_unwind(Box::new(format!("unexpected test error: {error:?}")))
            })
        }
    }

    impl<T> TestValueExt<T> for Option<T> {
        fn test_ok(self) -> T {
            self.unwrap_or_else(|| std::panic::resume_unwind(Box::new("expected test value")))
        }
    }

    use super::*;

    struct BtPlugin {
        id: pos_core::ids::PluginId,
    }

    impl pos_core::Plugin for BtPlugin {
        fn id(&self) -> pos_core::ids::PluginId {
            self.id
        }
        fn name(&self) -> &'static str {
            "bt-plugin"
        }
        fn capability(&self) -> pos_core::Capability {
            pos_core::Capability {
                owned_event_types: vec![pos_core::event::Kind::new("bt.tick")],
                owned_entity_kinds: vec![],
                has_driver: true,
                has_reducer: false,
            }
        }
    }

    struct BtDriver {
        entity: pos_core::ids::EntityId,
    }
    impl pos_runtime::Driver for BtDriver {
        fn name(&self) -> &'static str {
            "bt-driver"
        }
        fn step(
            &mut self,
            _: pos_core::ids::TimelineId,
            _: pos_runtime::ObservationView<'_>,
        ) -> Result<pos_runtime::StepOutput, pos_runtime::RuntimeError> {
            let draft = pos_core::event::EventDraft::new(
                self.entity,
                pos_core::event::Kind::new("bt.tick"),
                pos_core::event::CanonicalBytes::from_vec(vec![]),
            );
            Ok(pos_runtime::StepOutput::new(vec![draft]))
        }
    }

    fn make_registry() -> pos_runtime::PluginRegistry {
        use pos_runtime::Driver as _;
        let entity = pos_core::ids::EntityId::new();
        let plugin = BtPlugin {
            id: pos_core::ids::PluginId::new(),
        };
        let mut driver = BtDriver { entity };
        assert_eq!(driver.name(), "bt-driver"); // force coverage of fn name()
        let tl_id = pos_core::ids::TimelineId::new();
        drop(driver.step(tl_id, pos_runtime::ObservationView::empty()));
        let mut reg = pos_runtime::PluginRegistry::new();
        reg.register(&plugin, None, Some(Box::new(driver)))
            .test_ok();
        reg
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn backtest_runner_train_then_eval() {
        let config = BacktestConfig {
            experiment_name: "bt-test".to_owned(),
            train_ticks: 3,
            eval_ticks: 2,
            store_config: pos_store::StoreConfig::Memory,
        };

        let runner = BacktestRunner::new(config, make_registry);
        let result = runner.run().test_ok();

        assert_eq!(result.train_result.ticks, 3);
        assert_eq!(result.eval_result.ticks, 2);
        assert_eq!(result.train_events, 3);
        assert_eq!(result.eval_events, 2);
        // Train and eval timelines are independent (forked, so different IDs)
        assert_ne!(
            result.train_result.timeline_id,
            result.eval_result.timeline_id
        );
        // Lift metrics should be populated
        assert!(result.train_avg_events_per_tick > 0.0);
        assert!(result.eval_avg_events_per_tick > 0.0);
    }

    #[test]
    fn backtest_eval_hydrates_a_non_empty_training_history() {
        let result = BacktestRunner::new(
            BacktestConfig {
                experiment_name: "bt-coverage-history".to_owned(),
                train_ticks: 1,
                eval_ticks: 1,
                store_config: pos_store::StoreConfig::Memory,
            },
            make_registry,
        )
        .run()
        .test_ok();
        assert_eq!(result.train_events, 1);
        assert_eq!(result.eval_events, 1);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn backtest_runner_zero_eval_ticks() {
        let config = BacktestConfig {
            experiment_name: "bt-zero-eval".to_owned(),
            train_ticks: 2,
            eval_ticks: 0,
            store_config: pos_store::StoreConfig::Memory,
        };

        let runner = BacktestRunner::new(config, make_registry);
        let result = runner.run().test_ok();
        assert_eq!(result.train_events, 2);
        assert_eq!(result.eval_events, 0);
        // eval_avg_events_per_tick should be 0 when eval_ticks is 0
        assert!(result.eval_avg_events_per_tick.abs() < f64::EPSILON);
        // lift_vs_persistence = 0/train_avg - 1 = -1 (eval_avg=0, train_avg>0)
        assert!((result.lift_vs_persistence - (-1.0_f64)).abs() < f64::EPSILON);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn backtest_runner_stops_when_a_driver_emits_an_empty_batch() {
        let config = BacktestConfig {
            experiment_name: "bt-empty-driver".to_owned(),
            train_ticks: 1,
            eval_ticks: 1,
            store_config: pos_store::StoreConfig::Memory,
        };
        let runner = BacktestRunner::new(config, || {
            let plugin = BtPlugin {
                id: pos_core::ids::PluginId::new(),
            };
            let mut registry = pos_runtime::PluginRegistry::new();
            registry
                .register(&plugin, None, Some(Box::new(GoodBtDriver)))
                .test_ok();
            registry
        });

        let result = runner.run().test_ok();
        assert_eq!(result.train_result.ticks, 1);
        assert_eq!(result.eval_result.ticks, 1);
        assert_eq!(result.train_events, 0);
        assert_eq!(result.eval_events, 0);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn backtest_runner_zero_train_events_gives_zero_lift() {
        // When train produces no events (0 train_ticks), all lift metrics should be 0.
        struct EmptyPlugin {
            id: pos_core::ids::PluginId,
        }
        impl pos_core::Plugin for EmptyPlugin {
            fn id(&self) -> pos_core::ids::PluginId {
                self.id
            }
            fn name(&self) -> &'static str {
                "empty-plugin"
            }
            fn capability(&self) -> pos_core::Capability {
                pos_core::Capability {
                    owned_event_types: vec![],
                    owned_entity_kinds: vec![],
                    has_driver: false,
                    has_reducer: false,
                }
            }
        }

        let config = BacktestConfig {
            experiment_name: "bt-zero-train".to_owned(),
            train_ticks: 0,
            eval_ticks: 0,
            store_config: pos_store::StoreConfig::Memory,
        };
        let runner = BacktestRunner::new(config, || {
            let plugin = EmptyPlugin {
                id: pos_core::ids::PluginId::new(),
            };
            let mut reg = pos_runtime::PluginRegistry::new();
            reg.register(&plugin, None, None).test_ok();
            reg
        });
        let result = runner.run().test_ok();
        assert_eq!(result.train_events, 0);
        assert_eq!(result.eval_events, 0);
        assert!(result.persistence_lift.abs() < f64::EPSILON);
        assert!(result.train_avg_events_per_tick.abs() < f64::EPSILON);
        assert!(result.eval_avg_events_per_tick.abs() < f64::EPSILON);
        assert!(result.lift_vs_persistence.abs() < f64::EPSILON);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn backtest_runner_persistence_lift_computed() {
        // train=4 events over 4 ticks, eval=2 events over 2 ticks
        // persistence_lift = 2/4 = 0.5
        // train_avg = 4/4 = 1.0, eval_avg = 2/2 = 1.0, lift_vs_persistence = 0.0
        let config = BacktestConfig {
            experiment_name: "bt-lift".to_owned(),
            train_ticks: 4,
            eval_ticks: 2,
            store_config: pos_store::StoreConfig::Memory,
        };

        let runner = BacktestRunner::new(config, make_registry);
        let result = runner.run().test_ok();

        assert_eq!(result.train_events, 4);
        assert_eq!(result.eval_events, 2);
        let expected_persistence_lift = 2.0_f64 / 4.0_f64;
        let diff = (result.persistence_lift - expected_persistence_lift).abs();
        assert!(
            diff < 1e-10,
            "persistence_lift={}, expected={expected_persistence_lift}",
            result.persistence_lift
        );
        // train_avg = 1.0, eval_avg = 1.0 → lift_vs_persistence = 0.0
        let diff2 = result.lift_vs_persistence.abs();
        assert!(
            diff2 < 1e-10,
            "lift_vs_persistence should be ~0, got {}",
            result.lift_vs_persistence
        );

        let (_, _, _, unequal_average_lift) = backtest_metrics(2, 3, 4, 2);
        let expected_unequal_average_lift = (0.5_f64 / 1.5_f64) - 1.0_f64;
        assert!((unequal_average_lift - expected_unequal_average_lift).abs() < 1e-10);
    }

    // ---------- helper structs for error-propagation tests -------------------

    struct BadBtDriver {
        entity: pos_core::ids::EntityId,
    }
    impl pos_runtime::Driver for BadBtDriver {
        fn name(&self) -> &'static str {
            "bad-bt-driver"
        }
        fn step(
            &mut self,
            _: pos_core::ids::TimelineId,
            _: pos_runtime::ObservationView<'_>,
        ) -> Result<pos_runtime::StepOutput, pos_runtime::RuntimeError> {
            use pos_core::event::{CanonicalBytes, EventDraft, Kind};
            let draft = EventDraft::new(
                self.entity,
                Kind::new("bt.unknown.event"),
                CanonicalBytes::from_vec(vec![]),
            );
            Ok(pos_runtime::StepOutput::new(vec![draft]))
        }
    }

    struct GoodBtDriver;
    impl pos_runtime::Driver for GoodBtDriver {
        fn name(&self) -> &'static str {
            "good-bt-driver"
        }
        fn step(
            &mut self,
            _: pos_core::ids::TimelineId,
            _: pos_runtime::ObservationView<'_>,
        ) -> Result<pos_runtime::StepOutput, pos_runtime::RuntimeError> {
            Ok(pos_runtime::StepOutput::empty())
        }
    }

    struct BadEvalDriver {
        entity: pos_core::ids::EntityId,
    }
    impl pos_runtime::Driver for BadEvalDriver {
        fn name(&self) -> &'static str {
            "bad-eval-driver"
        }
        fn step(
            &mut self,
            _: pos_core::ids::TimelineId,
            _: pos_runtime::ObservationView<'_>,
        ) -> Result<pos_runtime::StepOutput, pos_runtime::RuntimeError> {
            use pos_core::event::{CanonicalBytes, EventDraft, Kind};
            let draft = EventDraft::new(
                self.entity,
                Kind::new("bt.bad.eval.event"),
                CanonicalBytes::from_vec(vec![]),
            );
            Ok(pos_runtime::StepOutput::new(vec![draft]))
        }
    }

    // --------------------------------------------------------------------------

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn helper_driver_names_are_correct() {
        use pos_runtime::Driver as _;
        // Cover fn name() on the helper drivers to get 100% line coverage.
        let entity = pos_core::ids::EntityId::new();
        assert_eq!(BadBtDriver { entity }.name(), "bad-bt-driver");
        assert_eq!(GoodBtDriver.name(), "good-bt-driver");
        assert_eq!(BadEvalDriver { entity }.name(), "bad-eval-driver");

        // Also cover GoodBtDriver::step by calling it directly.
        let mut store = pos_store::open_store(pos_store::StoreConfig::Memory).test_ok();
        let tl = store.create_timeline("good-step-test").test_ok();
        let out = GoodBtDriver
            .step(tl.id(), pos_runtime::ObservationView::empty())
            .test_ok();
        assert!(out.drafts.is_empty());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn backtest_runner_train_phase_error_propagates() {
        // Cover the `?` error branch on the train phase run_experiment_on_store call.
        // A driver that emits an unknown event type causes a schema validation error.
        let entity = pos_core::ids::EntityId::new();
        let config = BacktestConfig {
            experiment_name: "bt-err-train".to_owned(),
            train_ticks: 1,
            eval_ticks: 1,
            store_config: pos_store::StoreConfig::Memory,
        };
        let runner = BacktestRunner::new(config, move || {
            let plugin = BtPlugin {
                id: pos_core::ids::PluginId::new(),
            };
            let mut reg = pos_runtime::PluginRegistry::new();
            reg.register(&plugin, None, Some(Box::new(BadBtDriver { entity })))
                .test_ok();
            reg
        });
        let err = runner.run();
        assert!(
            err.is_err(),
            "expected error from bad driver in train phase"
        );
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn backtest_runner_eval_phase_error_propagates() {
        // Cover the `?` error branch on the eval phase run_experiment_on_store call.
        // Train phase has 0 ticks so no events → no error.
        // Eval phase uses a bad driver that emits an unregistered event type.
        use std::sync::{
            atomic::{AtomicU32, Ordering},
            Arc,
        };

        let entity = pos_core::ids::EntityId::new();
        let call_count = Arc::new(AtomicU32::new(0));
        let config = BacktestConfig {
            experiment_name: "bt-err-eval".to_owned(),
            train_ticks: 0,
            eval_ticks: 1,
            store_config: pos_store::StoreConfig::Memory,
        };
        let runner = BacktestRunner::new(config, move || {
            let n = call_count.fetch_add(1, Ordering::SeqCst);
            let plugin = BtPlugin {
                id: pos_core::ids::PluginId::new(),
            };
            let mut reg = pos_runtime::PluginRegistry::new();
            if n == 0 {
                reg.register(&plugin, None, Some(Box::new(GoodBtDriver)))
                    .test_ok();
            } else {
                reg.register(&plugin, None, Some(Box::new(BadEvalDriver { entity })))
                    .test_ok();
            }
            reg
        });
        let err = runner.run();
        assert!(err.is_err(), "expected error from bad driver in eval phase");
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod fault_injection_tests {
    trait TestValueExt<T> {
        fn test_ok(self) -> T;
    }

    impl<T, E: std::fmt::Debug> TestValueExt<T> for Result<T, E> {
        fn test_ok(self) -> T {
            self.unwrap_or_else(|error| {
                std::panic::resume_unwind(Box::new(format!("unexpected test error: {error:?}")))
            })
        }
    }

    impl<T> TestValueExt<T> for Option<T> {
        fn test_ok(self) -> T {
            self.unwrap_or_else(|| std::panic::resume_unwind(Box::new("expected test value")))
        }
    }

    use super::*;
    use pos_core::{
        event::{CanonicalBytes, EventDraft, Kind},
        ids::{EntityId, PluginId},
        store::EventStore,
        Capability, ConsentGrantedV1, CoreError, Plugin,
    };
    use pos_runtime::{Driver, ObservationView, RuntimeError, StepOutput};
    use pos_store::{open_store, StoreConfig};
    use rusqlite::Connection;
    use std::cell::Cell;

    fn config(name: &str, stop: StopCondition) -> ExperimentConfig {
        ExperimentConfig {
            name: name.to_owned(),
            stop,
            store_config: StoreConfig::Memory,
        }
    }

    struct FailLogicalHeadStore {
        inner: Box<dyn EventStore>,
        calls: Cell<u8>,
        fail_on_call: u8,
    }

    struct RejectingRevocationGate;

    impl ConsentGate for RejectingRevocationGate {
        fn check_consent(
            &self,
            _: pos_core::ids::TimelineId,
            _: EntityId,
            _: &Kind,
            _: u64,
            _: u64,
        ) -> Result<ConsentCapabilityToken, pos_core::ConsentError> {
            Err(pos_core::ConsentError::NoConsent)
        }
    }

    impl EventStore for FailLogicalHeadStore {
        fn create_timeline(&mut self, name: &str) -> Result<Timeline, CoreError> {
            self.inner.create_timeline(name)
        }

        fn append(
            &mut self,
            timeline: pos_core::ids::TimelineId,
            drafts: &[EventDraft],
        ) -> Result<Vec<pos_core::Event>, CoreError> {
            self.inner.append(timeline, drafts)
        }

        fn read(
            &self,
            timeline: pos_core::ids::TimelineId,
            range: pos_core::store::SeqRange,
        ) -> Result<Vec<pos_core::Event>, CoreError> {
            self.inner.read(timeline, range)
        }

        fn fork(
            &mut self,
            parent: pos_core::ids::TimelineId,
            at_seq: pos_core::clock::Seq,
            name: &str,
        ) -> Result<Timeline, CoreError> {
            self.inner.fork(parent, at_seq, name)
        }

        fn list_timelines(&self) -> Result<Vec<Timeline>, CoreError> {
            self.inner.list_timelines()
        }

        fn get_timeline(
            &self,
            id: pos_core::ids::TimelineId,
        ) -> Result<Option<Timeline>, CoreError> {
            self.inner.get_timeline(id)
        }

        fn logical_head(
            &self,
            id: pos_core::ids::TimelineId,
        ) -> Result<pos_core::clock::Seq, CoreError> {
            let call = self.calls.get().saturating_add(1);
            self.calls.set(call);
            if call == self.fail_on_call {
                Err(CoreError::Storage(
                    "injected boundary head failure".to_owned(),
                ))
            } else {
                self.inner.logical_head(id)
            }
        }
    }

    fn running_as_root() -> bool {
        std::fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|status| {
                status
                    .lines()
                    .find_map(|line| line.strip_prefix("Uid:\t"))
                    .and_then(|uids| uids.split_whitespace().next())
                    .and_then(|uid| uid.parse::<u32>().ok())
            })
            == Some(0)
    }

    fn drop_table(path: &str, table: &str) {
        let conn = Connection::open(path).test_ok();
        conn.execute(&format!("DROP TABLE {table}"), []).test_ok();
    }

    #[cfg(unix)]
    fn set_readonly(path: &std::path::Path) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o444)).test_ok();
    }

    #[cfg(unix)]
    fn set_writable(path: &std::path::Path) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644)).test_ok();
    }

    #[cfg(unix)]
    fn readonly_db(path: &std::path::Path) {
        let mut store = open_store(StoreConfig::Sqlite {
            path: path.to_str().test_ok().to_owned(),
        })
        .test_ok();
        store.create_timeline("seed").test_ok();
        drop(store);
        set_readonly(path);
    }

    struct FaultPlugin {
        id: PluginId,
        event_type: Kind,
    }

    impl Plugin for FaultPlugin {
        fn id(&self) -> PluginId {
            self.id
        }
        fn name(&self) -> &'static str {
            "fault-plugin"
        }
        fn capability(&self) -> Capability {
            Capability {
                owned_event_types: vec![self.event_type.clone()],
                owned_entity_kinds: vec![],
                has_driver: true,
                has_reducer: false,
            }
        }
    }

    struct EmitDriver {
        entity: EntityId,
        event_type: Kind,
    }

    impl Driver for EmitDriver {
        fn name(&self) -> &'static str {
            "emit"
        }
        fn step(
            &mut self,
            _: pos_core::ids::TimelineId,
            _: ObservationView<'_>,
        ) -> Result<StepOutput, RuntimeError> {
            let draft = EventDraft::new(
                self.entity,
                self.event_type.clone(),
                CanonicalBytes::from_vec(vec![]),
            );
            Ok(StepOutput::new(vec![draft]))
        }
    }

    struct BadEmitDriver {
        entity: EntityId,
    }

    struct FailStepDriver;

    impl Driver for FailStepDriver {
        fn name(&self) -> &'static str {
            "fail-step"
        }
        fn step(
            &mut self,
            _: pos_core::ids::TimelineId,
            _: ObservationView<'_>,
        ) -> Result<StepOutput, RuntimeError> {
            Err(RuntimeError::UnknownEventType(
                "driver.step.failed".to_owned(),
            ))
        }
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn fault_injection_driver_methods_are_exercised() {
        use pos_runtime::Driver as _;
        let entity = EntityId::new();
        let event_type = Kind::new("fault.tick");
        let mut emit = EmitDriver { entity, event_type };
        assert_eq!(emit.name(), "emit");
        let mut bad = BadEmitDriver { entity };
        assert_eq!(bad.name(), "bad-emit");
        let mut fail = FailStepDriver;
        assert_eq!(fail.name(), "fail-step");
        let mut store = open_store(StoreConfig::Memory).test_ok();
        let tl = store.create_timeline("driver-methods").test_ok();
        assert!(!emit
            .step(tl.id(), ObservationView::empty())
            .test_ok()
            .drafts
            .is_empty());
        assert!(!bad
            .step(tl.id(), ObservationView::empty())
            .test_ok()
            .drafts
            .is_empty());
        assert!(fail.step(tl.id(), ObservationView::empty()).is_err());
    }

    impl Driver for BadEmitDriver {
        fn name(&self) -> &'static str {
            "bad-emit"
        }
        fn step(
            &mut self,
            _: pos_core::ids::TimelineId,
            _: ObservationView<'_>,
        ) -> Result<StepOutput, RuntimeError> {
            let draft = EventDraft::new(
                self.entity,
                Kind::new("unregistered.event"),
                CanonicalBytes::from_vec(vec![]),
            );
            Ok(StepOutput::new(vec![draft]))
        }
    }

    fn registry_with_emit_driver() -> pos_runtime::PluginRegistry {
        let entity = EntityId::new();
        let event_type = Kind::new("fault.tick");
        let plugin = FaultPlugin {
            id: PluginId::new(),
            event_type: event_type.clone(),
        };
        let mut reg = pos_runtime::PluginRegistry::new();
        reg.register(
            &plugin,
            None,
            Some(Box::new(EmitDriver { entity, event_type })),
        )
        .test_ok();
        reg
    }

    #[test]
    fn backtest_result_build_errors_are_propagated_for_both_phases() {
        for fail_on_call in [2, 3, 4] {
            let mut store = FailLogicalHeadStore {
                inner: Box::new(pos_store::memory::MemoryStore::new()),
                calls: Cell::new(0),
                fail_on_call,
            };
            let runner = BacktestRunner::new(
                BacktestConfig {
                    experiment_name: format!("bt-result-error-{fail_on_call}"),
                    train_ticks: 0,
                    eval_ticks: 0,
                    store_config: StoreConfig::Memory,
                },
                registry_with_emit_driver,
            );
            assert!(matches!(
                runner.run_on_store(&mut store),
                Err(ExperimentError::Store(CoreError::Storage(_)))
            ));
        }
    }

    #[test]
    fn projection_step_and_revocation_error_boundaries_fault_closed() {
        let failing_store = FailLogicalHeadStore {
            inner: Box::new(pos_store::memory::MemoryStore::new()),
            calls: Cell::new(0),
            fail_on_call: 1,
        };
        let session = Experiment::new(config("projection-head-error", StopCondition::MaxTicks(1)))
            .start_with_store(Box::new(failing_store))
            .test_ok();
        let authority = ConsentAuthority::new();
        let token = authority.record_grant_on_timeline(session.timeline().id(), &export_grant(0));
        assert!(session
            .projection_state_for_reducer("missing", EntityId::new(), &token, 0)
            .is_err());

        let authority = ConsentAuthority::new();
        let session = Experiment::new(config("expired-step", StopCondition::MaxTicks(1)))
            .with_consent_authority(authority.clone())
            .start()
            .test_ok();
        let token = authority.record_grant_on_timeline(session.timeline().id(), &export_grant(1));
        let mut session = session.with_protected_token(token, 0);
        assert!(session.step_tick().is_err());

        let directory = tempfile::tempdir().test_ok();
        let path = directory.path().join("revocation-append-error.db");
        let authority = ConsentAuthority::new();
        let mut session = Experiment::new(ExperimentConfig {
            name: "revocation-append-error".to_owned(),
            stop: StopCondition::MaxTicks(1),
            store_config: StoreConfig::Sqlite {
                path: path.to_str().test_ok().to_owned(),
            },
        })
        .with_consent_authority(authority)
        .start()
        .test_ok();
        Connection::open(&path)
            .test_ok()
            .execute_batch(
                "CREATE TRIGGER fail_revocation_append
                 BEFORE INSERT ON events
                 BEGIN
                   SELECT RAISE(FAIL, 'injected revocation failure');
                 END;",
            )
            .test_ok();
        session.revoke_consent_at_boundary();
        assert!(session.step_tick().is_err());

        let mut session =
            Experiment::new(config("revocation-gate-error", StopCondition::MaxTicks(1)))
                .without_consent_gate()
                .start()
                .test_ok();
        session.registry = session
            .registry
            .with_consent_gate(Arc::new(RejectingRevocationGate));
        session.revoke_consent_at_boundary();
        assert!(session.step_tick().is_err());
    }

    #[test]
    fn durable_resume_propagates_gate_fence_failure() {
        let directory = tempfile::tempdir().test_ok();
        let path = directory.path().join("resume-gate-error.db");
        let store_config = StoreConfig::Sqlite {
            path: path.to_str().test_ok().to_owned(),
        };
        let timeline = {
            let mut store = open_store(store_config.clone()).test_ok();
            let timeline = store.create_timeline("resume-gate-error").test_ok();
            store
                .append(
                    timeline.id(),
                    &[EventDraft::new(
                        EntityId::new(),
                        Kind::new(EXPERIMENT_CONSENT_CLOSED_EVENT_TYPE),
                        pos_core::CanonicalBytes::from_static(EXPERIMENT_CONSENT_TIMELINE_MARKER),
                    )],
                )
                .test_ok();
            timeline.id()
        };
        let mut experiment = Experiment::new(ExperimentConfig {
            name: "resume-gate-error".to_owned(),
            stop: StopCondition::MaxTicks(1),
            store_config,
        })
        .without_consent_gate();
        experiment.registry = experiment
            .registry
            .with_consent_gate(Arc::new(RejectingRevocationGate));
        assert!(matches!(
            experiment.resume(timeline),
            Err(ExperimentError::Runtime(RuntimeError::Consent(
                pos_core::ConsentError::NoConsent
            )))
        ));
    }

    #[test]
    fn protected_fork_error_boundaries_reject_missing_and_expired_authority() {
        let authority = ConsentAuthority::new();
        let session = Experiment::new(config("fork-no-gate", StopCondition::MaxTicks(1)))
            .with_fork_registry_factory(|| Ok(PluginRegistry::new()))
            .start()
            .test_ok();
        let token =
            authority.record_grant_on_timeline(session.timeline().id(), &branch_grant(true, 0));
        let mut session = session.with_protected_token(token, 0);
        assert!(session.fork("child").is_err());

        let authority = ConsentAuthority::new();
        let session = Experiment::new(config("fork-expired", StopCondition::MaxTicks(1)))
            .with_consent_authority(authority.clone())
            .with_fork_registry_factory(|| Ok(PluginRegistry::new()))
            .start()
            .test_ok();
        let token =
            authority.record_grant_on_timeline(session.timeline().id(), &branch_grant(true, 1));
        let mut session = session.with_protected_token(token, 0);
        assert!(session.fork("child").is_err());

        let failing_store = FailLogicalHeadStore {
            inner: Box::new(pos_store::memory::MemoryStore::new()),
            calls: Cell::new(0),
            fail_on_call: 1,
        };
        let session = Experiment::new(config("fork-head-error", StopCondition::MaxTicks(1)))
            .start_with_store(Box::new(failing_store))
            .test_ok();
        assert!(session
            .fork_timeline_at("child", pos_core::clock::Seq::ZERO)
            .is_err());

        let failing_store = FailLogicalHeadStore {
            inner: Box::new(pos_store::memory::MemoryStore::new()),
            calls: Cell::new(0),
            fail_on_call: 1,
        };
        let mut session = Experiment::new(config(
            "fork-initial-head-error",
            StopCondition::MaxTicks(1),
        ))
        .with_fork_registry_factory(|| Ok(PluginRegistry::new()))
        .start_with_store(Box::new(failing_store))
        .test_ok();
        assert!(session.fork("child").is_err());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn run_result_branch_open_store_fails_on_directory_path() {
        let dir = tempfile::tempdir().test_ok();
        let result = RunResult {
            timeline_id: pos_core::ids::TimelineId::new(),
            ticks: 0,
            total_events: 0,
            timeline_head: 0,
            manifest: ReproManifest::new(
                pos_core::ids::TimelineId::new(),
                pos_core::crypto::Hash::zero(),
                pos_core::clock::WallTime::from_micros(0),
            ),
            projections: pos_state::ProjectionRegistry::new(),
            consent_gate: None,
            protected_token: None,
            store_config: Some(StoreConfig::Sqlite {
                path: dir.path().to_str().test_ok().to_owned(),
            }),
        };
        assert!(result.branch("fork").is_err());
    }

    fn export_result(
        timeline_id: pos_core::ids::TimelineId,
        authority: &ConsentAuthority,
        token: ConsentCapabilityToken,
        store_config: Option<StoreConfig>,
    ) -> RunResult {
        RunResult {
            timeline_id,
            ticks: 0,
            total_events: 0,
            timeline_head: 0,
            manifest: ReproManifest::new(
                timeline_id,
                pos_core::crypto::Hash::zero(),
                pos_core::clock::WallTime::from_micros(0),
            ),
            projections: pos_state::ProjectionRegistry::new(),
            consent_gate: Some(Arc::new(authority.clone())),
            protected_token: Some(token),
            store_config,
        }
    }

    fn export_grant(expiry_secs: u32) -> ConsentGrantedV1 {
        ConsentGrantedV1 {
            subject_id: EntityId::new(),
            grantee_id: EntityId::new(),
            purpose: "coverage-export-errors".to_owned(),
            modalities: 0,
            min_geo_resolution: 0,
            fork_permitted: true,
            export_permitted: true,
            retention_days: 0,
            expiry_secs,
            grant_seq: 1,
        }
    }

    fn branch_grant(fork_permitted: bool, expiry_secs: u32) -> ConsentGrantedV1 {
        ConsentGrantedV1 {
            fork_permitted,
            expiry_secs,
            ..export_grant(expiry_secs)
        }
    }

    #[test]
    fn protected_export_errors_are_closed_at_each_store_and_authority_boundary() {
        let authority = ConsentAuthority::new();
        let missing_recipe_timeline = pos_core::ids::TimelineId::new();
        let missing_recipe_token =
            authority.record_grant_on_timeline(missing_recipe_timeline, &export_grant(0));
        assert!(matches!(
            export_result(
                missing_recipe_timeline,
                &authority,
                missing_recipe_token,
                None,
            )
            .into_reproduction_manifest(ReproductionRecipe::new(
                "coverage-export-missing-recipe",
                1,
                serde_json::json!({}),
            )),
            Err(ExperimentError::MissingStoreRecoveryRecipe)
        ));

        let directory = tempfile::tempdir().test_ok();
        let directory_timeline = pos_core::ids::TimelineId::new();
        let directory_token =
            authority.record_grant_on_timeline(directory_timeline, &export_grant(0));
        assert!(export_result(
            directory_timeline,
            &authority,
            directory_token,
            Some(StoreConfig::Sqlite {
                path: directory.path().to_str().test_ok().to_owned(),
            }),
        )
        .into_reproduction_manifest(ReproductionRecipe::new(
            "coverage-export-open-error",
            1,
            serde_json::json!({}),
        ))
        .is_err());

        let database = tempfile::NamedTempFile::new().test_ok();
        let store_config = StoreConfig::Sqlite {
            path: database.path().to_str().test_ok().to_owned(),
        };
        let mut store = open_store(store_config.clone()).test_ok();
        let stored_timeline = store.create_timeline("coverage-export-head").test_ok();
        let missing_timeline = pos_core::ids::TimelineId::new();
        let missing_head_token =
            authority.record_grant_on_timeline(missing_timeline, &export_grant(0));
        drop(store);
        assert!(export_result(
            missing_timeline,
            &authority,
            missing_head_token,
            Some(store_config.clone()),
        )
        .into_reproduction_manifest(ReproductionRecipe::new(
            "coverage-export-head-error",
            1,
            serde_json::json!({}),
        ))
        .is_err());

        let expired_authority = ConsentAuthority::new();
        let expired_token =
            expired_authority.record_grant_on_timeline(stored_timeline.id(), &export_grant(1));
        assert!(export_result(
            stored_timeline.id(),
            &expired_authority,
            expired_token,
            Some(store_config),
        )
        .into_reproduction_manifest(ReproductionRecipe::new(
            "coverage-export-expired",
            1,
            serde_json::json!({}),
        ))
        .is_err());
    }

    #[test]
    fn protected_branch_errors_are_closed_at_each_authority_boundary() {
        let directory = tempfile::tempdir().test_ok();
        let path = directory.path().join("branch-token-corrupt.db");
        let authority = ConsentAuthority::new();
        let mut store = open_store(StoreConfig::Sqlite {
            path: path.to_str().test_ok().to_owned(),
        })
        .test_ok();
        let timeline = store.create_timeline("branch-token-corrupt").test_ok();
        let token = authority.record_grant_on_timeline(timeline.id(), &branch_grant(true, 0));
        Connection::open(&path)
            .test_ok()
            .execute("UPDATE timelines SET name = X'0102'", [])
            .test_ok();
        let experiment = Experiment::new(ExperimentConfig {
            name: "branch-token-corrupt".to_owned(),
            stop: StopCondition::MaxTicks(1),
            store_config: StoreConfig::Memory,
        })
        .with_consent_authority(authority);
        assert!(experiment
            .branch_with_token("child", store.as_mut(), &token, 0)
            .is_err());

        let authority = ConsentAuthority::new();
        let mut failing_head = pos_store::memory::MemoryStore::new();
        let timeline = failing_head.create_timeline("branch-token-head").test_ok();
        let token = authority.record_grant_on_timeline(timeline.id(), &branch_grant(true, 0));
        let mut failing_head = FailLogicalHeadStore {
            inner: Box::new(failing_head),
            calls: Cell::new(0),
            fail_on_call: 1,
        };
        let experiment = Experiment::new(config("branch-token-head", StopCondition::MaxTicks(1)))
            .with_consent_authority(authority);
        assert!(experiment
            .branch_with_token("child", &mut failing_head, &token, 0)
            .is_err());

        let authority = ConsentAuthority::new();
        let mut denied_store = pos_store::memory::MemoryStore::new();
        let timeline = denied_store
            .create_timeline("branch-token-denied")
            .test_ok();
        let token = authority.record_grant_on_timeline(timeline.id(), &branch_grant(false, 0));
        let experiment = Experiment::new(config("branch-token-denied", StopCondition::MaxTicks(1)))
            .with_consent_authority(authority);
        assert!(experiment
            .branch_with_token("child", &mut denied_store, &token, 0)
            .is_err());

        let mut ungated_store = pos_store::memory::MemoryStore::new();
        let timeline = ungated_store
            .create_timeline("branch-token-ungated")
            .test_ok();
        let token =
            ConsentAuthority::new().record_grant_on_timeline(timeline.id(), &branch_grant(true, 0));
        let experiment =
            Experiment::new(config("branch-token-ungated", StopCondition::MaxTicks(1)));
        assert!(experiment
            .branch_with_token("child", &mut ungated_store, &token, 0)
            .is_err());

        let authority = ConsentAuthority::new();
        let mut expired_store = pos_store::memory::MemoryStore::new();
        let timeline = expired_store
            .create_timeline("branch-token-expired")
            .test_ok();
        let token = authority.record_grant_on_timeline(timeline.id(), &branch_grant(true, 1));
        let experiment =
            Experiment::new(config("branch-token-expired", StopCondition::MaxTicks(1)))
                .with_consent_authority(authority);
        assert!(experiment
            .branch_with_token("child", &mut expired_store, &token, 2)
            .is_err());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn run_result_branch_list_timelines_fails_on_corrupt_row() {
        let dir = tempfile::tempdir().test_ok();
        let path = dir.path().join("branch.db");
        let entity = EntityId::new();
        let plugin = FaultPlugin {
            id: PluginId::new(),
            event_type: Kind::new("branch.tick"),
        };
        let mut exp = Experiment::new(ExperimentConfig {
            name: "branch-fault".to_owned(),
            stop: StopCondition::MaxTicks(1),
            store_config: StoreConfig::Sqlite {
                path: path.to_str().test_ok().to_owned(),
            },
        });
        exp.register(
            &plugin,
            None,
            Some(Box::new(EmitDriver {
                entity,
                event_type: Kind::new("branch.tick"),
            })),
        )
        .test_ok();
        let result = exp.run().test_ok();
        let conn = Connection::open(&path).test_ok();
        conn.execute("UPDATE timelines SET name = X'0102'", [])
            .test_ok();
        assert!(result.branch("child").is_err());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn live_session_propagates_driver_error() {
        let plugin = FaultPlugin {
            id: PluginId::new(),
            event_type: Kind::new("known.event"),
        };
        let mut experiment = Experiment::new(ExperimentConfig {
            name: "session-step-fault".to_owned(),
            stop: StopCondition::MaxTicks(1),
            store_config: StoreConfig::Memory,
        });
        experiment
            .register(&plugin, None, Some(Box::new(FailStepDriver)))
            .test_ok();

        assert!(matches!(
            experiment.start().test_ok().step(),
            Err(ExperimentError::Runtime(_))
        ));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn live_session_propagates_append_error() {
        let dir = tempfile::tempdir().test_ok();
        let path = dir.path().join("session-append.db");
        let plugin = FaultPlugin {
            id: PluginId::new(),
            event_type: Kind::new("session.append"),
        };
        let mut experiment = Experiment::new(ExperimentConfig {
            name: "session-append-fault".to_owned(),
            stop: StopCondition::MaxTicks(1),
            store_config: StoreConfig::Sqlite {
                path: path.to_str().test_ok().to_owned(),
            },
        });
        experiment
            .register(
                &plugin,
                None,
                Some(Box::new(EmitDriver {
                    entity: EntityId::new(),
                    event_type: Kind::new("session.append"),
                })),
            )
            .test_ok();
        let mut session = experiment.start().test_ok();
        assert_eq!(session.append_events(&[]).test_ok(), 0);
        Connection::open(&path)
            .test_ok()
            .execute_batch(
                "CREATE TRIGGER fail_session_append
                 BEFORE INSERT ON events
                 BEGIN
                   SELECT RAISE(FAIL, 'injected append failure');
                 END;",
            )
            .test_ok();

        assert!(matches!(session.step(), Err(ExperimentError::Store(_))));
        assert!(matches!(
            session.step_tick(),
            Err(ExperimentError::SessionFaulted)
        ));
    }

    #[test]
    fn default_consent_revocation_uses_the_session_subject() {
        let authority = ConsentAuthority::new();
        let mut session = Experiment::new(ExperimentConfig {
            name: "default-consent-revocation".to_owned(),
            stop: StopCondition::MaxTicks(1),
            store_config: StoreConfig::Memory,
        })
        .with_consent_authority(authority)
        .start()
        .test_ok();
        session.revoke_consent_at_boundary();
        assert!(matches!(
            session.step_tick(),
            Ok(TickOutcome::Advanced {
                emitted_events: 1,
                ..
            })
        ));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn revocation_boundary_faults_closed_when_its_fence_head_cannot_be_read() {
        let authority = ConsentAuthority::new();
        let mut session = Experiment::new(ExperimentConfig {
            name: "revocation-fence-fault".to_owned(),
            stop: StopCondition::MaxTicks(1),
            store_config: StoreConfig::Memory,
        })
        .with_consent_authority(authority)
        .start()
        .test_ok();
        {
            let mut store = lock_store(&session.store).test_ok();
            let inner =
                std::mem::replace(&mut *store, Box::new(pos_store::memory::MemoryStore::new()));
            *store = Box::new(FailLogicalHeadStore {
                inner,
                calls: std::cell::Cell::new(0),
                fail_on_call: 1,
            });
        }
        session.revoke_consent_at_boundary();
        assert!(matches!(
            session.step_tick(),
            Err(ExperimentError::Store(_))
        ));
        assert!(matches!(
            session.step_tick(),
            Err(ExperimentError::SessionFaulted)
        ));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn revocation_boundary_faults_closed_when_post_append_capture_fails() {
        let authority = ConsentAuthority::new();
        let mut session = Experiment::new(ExperimentConfig {
            name: "revocation-capture-fault".to_owned(),
            stop: StopCondition::MaxTicks(1),
            store_config: StoreConfig::Memory,
        })
        .with_consent_authority(authority)
        .start()
        .test_ok();
        {
            let mut store = lock_store(&session.store).test_ok();
            let inner =
                std::mem::replace(&mut *store, Box::new(pos_store::memory::MemoryStore::new()));
            *store = Box::new(FailLogicalHeadStore {
                inner,
                calls: std::cell::Cell::new(0),
                fail_on_call: 2,
            });
        }
        session.revoke_consent_at_boundary();
        assert!(matches!(
            session.step_tick(),
            Err(ExperimentError::Store(_))
        ));
        assert!(matches!(
            session.step_tick(),
            Err(ExperimentError::SessionFaulted)
        ));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn live_session_faults_when_post_append_capture_fails() {
        let dir = tempfile::tempdir().test_ok();
        let path = dir.path().join("session-post-capture.db");
        let event_type = Kind::new("session.post-capture");
        let plugin = FaultPlugin {
            id: PluginId::new(),
            event_type: event_type.clone(),
        };
        let mut experiment = Experiment::new(ExperimentConfig {
            name: "session-post-capture-fault".to_owned(),
            stop: StopCondition::MaxTicks(2),
            store_config: StoreConfig::Sqlite {
                path: path.to_str().test_ok().to_owned(),
            },
        });
        experiment
            .register(
                &plugin,
                None,
                Some(Box::new(EmitDriver {
                    entity: EntityId::new(),
                    event_type,
                })),
            )
            .test_ok();
        let mut session = experiment.start().test_ok();
        Connection::open(&path)
            .test_ok()
            .execute_batch(
                "CREATE TRIGGER corrupt_after_session_append
                 AFTER INSERT ON events
                 BEGIN
                   UPDATE timelines SET fork_seq = 0 WHERE id = NEW.timeline_id;
                 END;",
            )
            .test_ok();

        assert!(matches!(
            session.append_events(&[EventDraft::new(
                EntityId::new(),
                Kind::new("session.post-capture"),
                CanonicalBytes::from_static(b"append-fault"),
            )]),
            Err(ExperimentError::Store(_))
        ));
        assert!(matches!(
            session.step_tick(),
            Err(ExperimentError::SessionFaulted)
        ));
        assert!(matches!(
            session.append_events(&[]),
            Err(ExperimentError::SessionFaulted)
        ));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn live_session_propagates_final_read_error() {
        let dir = tempfile::tempdir().test_ok();
        let path = dir.path().join("session-read.db");
        let plugin = FaultPlugin {
            id: PluginId::new(),
            event_type: Kind::new("session.read"),
        };
        let mut experiment = Experiment::new(ExperimentConfig {
            name: "session-read-fault".to_owned(),
            stop: StopCondition::MaxTicks(1),
            store_config: StoreConfig::Sqlite {
                path: path.to_str().test_ok().to_owned(),
            },
        });
        experiment
            .register(
                &plugin,
                None,
                Some(Box::new(EmitDriver {
                    entity: EntityId::new(),
                    event_type: Kind::new("session.read"),
                })),
            )
            .test_ok();
        let mut session = experiment.start().test_ok();
        assert!(session.step().test_ok());
        drop_table(path.to_str().test_ok(), "events");

        assert!(matches!(
            session.run_to_completion(),
            Err(ExperimentError::Store(_))
        ));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn live_session_fork_hydration_error_does_not_create_a_child_timeline() {
        let dir = tempfile::tempdir().test_ok();
        let path = dir.path().join("session-fork-read.db");
        let mut session = Experiment::new(ExperimentConfig {
            name: "session-fork-read-fault".to_owned(),
            stop: StopCondition::MaxTicks(1),
            store_config: StoreConfig::Sqlite {
                path: path.to_str().test_ok().to_owned(),
            },
        })
        .with_fork_registry_factory(|| Ok(PluginRegistry::new()))
        .start()
        .test_ok();
        drop_table(path.to_str().test_ok(), "events");

        assert!(matches!(
            session.fork("child"),
            Err(ExperimentError::Store(_))
        ));
        let connection = rusqlite::Connection::open(&path).test_ok();
        let timeline_count: i64 = connection
            .query_row("SELECT COUNT(*) FROM timelines", [], |row| row.get(0))
            .test_ok();
        assert_eq!(timeline_count, 1);
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn experiment_run_open_store_fails_on_directory_path() {
        let dir = tempfile::tempdir().test_ok();
        let exp = Experiment::new(ExperimentConfig {
            name: "open-fault".to_owned(),
            stop: StopCondition::MaxTicks(1),
            store_config: StoreConfig::Sqlite {
                path: dir.path().to_str().test_ok().to_owned(),
            },
        });
        assert!(exp.run().is_err());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn experiment_run_create_timeline_fails_on_readonly_database() {
        if running_as_root() {
            return;
        }
        let dir = tempfile::tempdir().test_ok();
        let path = dir.path().join("create.db");
        readonly_db(&path);
        let entity = EntityId::new();
        let plugin = FaultPlugin {
            id: PluginId::new(),
            event_type: Kind::new("create.tick"),
        };
        let mut exp = Experiment::new(ExperimentConfig {
            name: "create-fault".to_owned(),
            stop: StopCondition::MaxTicks(1),
            store_config: StoreConfig::Sqlite {
                path: path.to_str().test_ok().to_owned(),
            },
        });
        exp.register(
            &plugin,
            None,
            Some(Box::new(EmitDriver {
                entity,
                event_type: Kind::new("create.tick"),
            })),
        )
        .test_ok();
        let result = exp.run();
        set_writable(&path);
        assert!(result.is_err());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn run_result_branch_fork_fails_on_readonly_database() {
        if running_as_root() {
            return;
        }
        let dir = tempfile::tempdir().test_ok();
        let path = dir.path().join("branch-fork.db");
        let entity = EntityId::new();
        let plugin = FaultPlugin {
            id: PluginId::new(),
            event_type: Kind::new("branch.tick"),
        };
        let mut exp = Experiment::new(ExperimentConfig {
            name: "branch-fault".to_owned(),
            stop: StopCondition::MaxTicks(1),
            store_config: StoreConfig::Sqlite {
                path: path.to_str().test_ok().to_owned(),
            },
        });
        exp.register(
            &plugin,
            None,
            Some(Box::new(EmitDriver {
                entity,
                event_type: Kind::new("branch.tick"),
            })),
        )
        .test_ok();
        let result = exp.run().test_ok();
        set_readonly(&path);
        let err = result.branch("child");
        set_writable(&path);
        assert!(err.is_err());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn experiment_branch_list_timelines_fails_on_corrupt_row() {
        let dir = tempfile::tempdir().test_ok();
        let path = dir.path().join("exp-branch-list.db");
        let entity = EntityId::new();
        let plugin = FaultPlugin {
            id: PluginId::new(),
            event_type: Kind::new("exp-branch.tick"),
        };
        let mut exp = Experiment::new(ExperimentConfig {
            name: "exp-branch-list".to_owned(),
            stop: StopCondition::MaxTicks(1),
            store_config: StoreConfig::Sqlite {
                path: path.to_str().test_ok().to_owned(),
            },
        });
        exp.register(
            &plugin,
            None,
            Some(Box::new(EmitDriver {
                entity,
                event_type: Kind::new("exp-branch.tick"),
            })),
        )
        .test_ok();
        let _ = exp.run().test_ok();
        let conn = Connection::open(&path).test_ok();
        conn.execute("UPDATE timelines SET name = X'0102'", [])
            .test_ok();
        let exp2 = Experiment::new(ExperimentConfig {
            name: "exp-branch-list".to_owned(),
            stop: StopCondition::MaxTicks(1),
            store_config: StoreConfig::Sqlite {
                path: path.to_str().test_ok().to_owned(),
            },
        });
        let mut store = open_store(StoreConfig::Sqlite {
            path: path.to_str().test_ok().to_owned(),
        })
        .test_ok();
        assert!(exp2.branch("child", store.as_mut()).is_err());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn experiment_branch_fork_fails_on_readonly_database() {
        if running_as_root() {
            return;
        }
        let dir = tempfile::tempdir().test_ok();
        let path = dir.path().join("exp-branch.db");
        let entity = EntityId::new();
        let plugin = FaultPlugin {
            id: PluginId::new(),
            event_type: Kind::new("exp-branch.tick"),
        };
        let mut exp = Experiment::new(ExperimentConfig {
            name: "exp-branch-fault".to_owned(),
            stop: StopCondition::MaxTicks(1),
            store_config: StoreConfig::Sqlite {
                path: path.to_str().test_ok().to_owned(),
            },
        });
        exp.register(
            &plugin,
            None,
            Some(Box::new(EmitDriver {
                entity,
                event_type: Kind::new("exp-branch.tick"),
            })),
        )
        .test_ok();
        let _ = exp.run().test_ok();
        set_readonly(&path);
        let exp2 = Experiment::new(ExperimentConfig {
            name: "exp-branch-fault".to_owned(),
            stop: StopCondition::MaxTicks(1),
            store_config: StoreConfig::Sqlite {
                path: path.to_str().test_ok().to_owned(),
            },
        });
        let mut store = open_store(StoreConfig::Sqlite {
            path: path.to_str().test_ok().to_owned(),
        })
        .test_ok();
        let err = exp2.branch("child", store.as_mut());
        set_writable(&path);
        assert!(err.is_err());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn backtest_runner_open_store_fails_on_directory_path() {
        let dir = tempfile::tempdir().test_ok();
        let config = BacktestConfig {
            experiment_name: "bt-open-fault".to_owned(),
            train_ticks: 1,
            eval_ticks: 1,
            store_config: StoreConfig::Sqlite {
                path: dir.path().to_str().test_ok().to_owned(),
            },
        };
        let runner = BacktestRunner::new(config, registry_with_emit_driver);
        assert!(runner.run().is_err());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn backtest_runner_create_timeline_fails_on_readonly_database() {
        if running_as_root() {
            return;
        }
        let dir = tempfile::tempdir().test_ok();
        let path = dir.path().join("bt-create.db");
        readonly_db(&path);
        let config = BacktestConfig {
            experiment_name: "bt-create-fault".to_owned(),
            train_ticks: 1,
            eval_ticks: 0,
            store_config: StoreConfig::Sqlite {
                path: path.to_str().test_ok().to_owned(),
            },
        };
        let runner = BacktestRunner::new(config, registry_with_emit_driver);
        let result = runner.run();
        set_writable(&path);
        assert!(result.is_err());
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn backtest_runner_ignores_unrelated_corrupt_timeline_metadata() {
        let dir = tempfile::tempdir().test_ok();
        let path = dir.path().join("bt-list.db");
        let path_str = path.to_str().test_ok().to_owned();
        let config = BacktestConfig {
            experiment_name: "bt-list-fault".to_owned(),
            train_ticks: 1,
            eval_ticks: 0,
            store_config: StoreConfig::Sqlite {
                path: path_str.clone(),
            },
        };
        let runner = BacktestRunner::new(config, registry_with_emit_driver);
        let _ = runner.run().test_ok();
        let conn = Connection::open(&path).test_ok();
        conn.execute(
            "UPDATE timelines SET name = X'0102' WHERE name LIKE '%-train'",
            [],
        )
        .test_ok();
        let config2 = BacktestConfig {
            experiment_name: "bt-list-fault-2".to_owned(),
            train_ticks: 1,
            eval_ticks: 0,
            store_config: StoreConfig::Sqlite { path: path_str },
        };
        let runner2 = BacktestRunner::new(config2, registry_with_emit_driver);
        assert!(runner2.run().is_ok());
    }

    /// Test that `BacktestRunner::run_on_store` fails when fork returns an error.
    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn backtest_runner_fork_eval_timeline_fails() {
        use pos_core::{
            clock::Seq,
            event::Event,
            ids::TimelineId,
            store::{EventStore, SeqRange},
            timeline::Timeline,
            CoreError,
        };

        struct FaultyForkerStore {
            base: pos_store::memory::MemoryStore,
        }

        impl EventStore for FaultyForkerStore {
            fn create_timeline(&mut self, name: &str) -> Result<Timeline, CoreError> {
                self.base.create_timeline(name)
            }

            fn append(
                &mut self,
                timeline: TimelineId,
                drafts: &[pos_core::event::EventDraft],
            ) -> Result<Vec<Event>, CoreError> {
                self.base.append(timeline, drafts)
            }

            fn fork(
                &mut self,
                _parent: TimelineId,
                _at_seq: Seq,
                _name: &str,
            ) -> Result<Timeline, CoreError> {
                Err(CoreError::Storage("fork failed for test".to_owned()))
            }

            fn list_timelines(&self) -> Result<Vec<Timeline>, CoreError> {
                self.base.list_timelines()
            }

            fn get_timeline(&self, id: TimelineId) -> Result<Option<Timeline>, CoreError> {
                self.base.get_timeline(id)
            }

            fn logical_head(&self, id: TimelineId) -> Result<Seq, CoreError> {
                self.base.logical_head(id)
            }

            fn read(&self, timeline: TimelineId, range: SeqRange) -> Result<Vec<Event>, CoreError> {
                self.base.read(timeline, range)
            }

            fn import_committed(
                &mut self,
                meta: pos_core::timeline::TimelineMeta,
                events: &[pos_core::Event],
            ) -> Result<pos_core::Timeline, pos_core::CoreError> {
                pos_core::store::import_committed_with_rollback(self, meta, events)
            }
        }

        let mut store = FaultyForkerStore {
            base: pos_store::memory::MemoryStore::new(),
        };
        let config = BacktestConfig {
            experiment_name: "bt-fork-fault".to_owned(),
            train_ticks: 0,
            eval_ticks: 0,
            store_config: StoreConfig::Memory,
        };
        let runner = BacktestRunner::new(config, registry_with_emit_driver);
        let result = runner.run_on_store(&mut store);
        assert!(matches!(
            result,
            Err(ExperimentError::Store(CoreError::Storage(_)))
        ));
    }

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn backtest_runner_compute_report_error_propagates() {
        let mut store = FailReadAfterStore {
            base: pos_store::memory::MemoryStore::new(),
            ok_reads_left: Cell::new(2),
        };
        let config = BacktestConfig {
            experiment_name: "bt-compute-report-fault".to_owned(),
            train_ticks: 0,
            eval_ticks: 0,
            store_config: StoreConfig::Memory,
        };
        let runner = BacktestRunner::new(config, registry_with_emit_driver);
        let result = runner.run_on_store(&mut store);
        assert!(matches!(
            result,
            Err(ExperimentError::Store(CoreError::Storage(_)))
        ));
    }

    // `run_experiment_on_store` reads once per phase for chain_head; allow those
    // two reads, then fail the `compute_report` read.
    struct FailReadAfterStore {
        base: pos_store::memory::MemoryStore,
        ok_reads_left: Cell<u32>,
    }

    impl pos_core::store::EventStore for FailReadAfterStore {
        fn create_timeline(
            &mut self,
            name: &str,
        ) -> Result<pos_core::timeline::Timeline, CoreError> {
            self.base.create_timeline(name)
        }

        fn append(
            &mut self,
            timeline: pos_core::ids::TimelineId,
            drafts: &[pos_core::event::EventDraft],
        ) -> Result<Vec<pos_core::event::Event>, CoreError> {
            self.base.append(timeline, drafts)
        }

        fn fork(
            &mut self,
            parent: pos_core::ids::TimelineId,
            at_seq: pos_core::clock::Seq,
            name: &str,
        ) -> Result<pos_core::timeline::Timeline, CoreError> {
            self.base.fork(parent, at_seq, name)
        }

        fn list_timelines(&self) -> Result<Vec<pos_core::timeline::Timeline>, CoreError> {
            self.base.list_timelines()
        }

        fn get_timeline(
            &self,
            id: pos_core::ids::TimelineId,
        ) -> Result<Option<pos_core::timeline::Timeline>, CoreError> {
            self.base.get_timeline(id)
        }

        fn logical_head(
            &self,
            id: pos_core::ids::TimelineId,
        ) -> Result<pos_core::clock::Seq, CoreError> {
            self.base.logical_head(id)
        }

        fn read(
            &self,
            timeline: pos_core::ids::TimelineId,
            range: pos_core::store::SeqRange,
        ) -> Result<Vec<pos_core::event::Event>, CoreError> {
            let left = self.ok_reads_left.get();
            if left == 0 {
                return Err(CoreError::Storage(
                    "read failed for compute_report".to_owned(),
                ));
            }
            self.ok_reads_left.set(left - 1);
            self.base.read(timeline, range)
        }

        fn create_timeline_with_meta(
            &mut self,
            meta: pos_core::timeline::TimelineMeta,
        ) -> Result<pos_core::timeline::Timeline, CoreError> {
            self.base.create_timeline_with_meta(meta)
        }

        fn append_committed(
            &mut self,
            timeline: pos_core::ids::TimelineId,
            events: &[pos_core::event::Event],
        ) -> Result<(), CoreError> {
            self.base.append_committed(timeline, events)
        }

        fn import_committed(
            &mut self,
            meta: pos_core::timeline::TimelineMeta,
            events: &[pos_core::Event],
        ) -> Result<pos_core::Timeline, CoreError> {
            pos_core::store::import_committed_with_rollback(self, meta, events)
        }
    }
}
