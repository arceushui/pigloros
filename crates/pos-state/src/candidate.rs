//! Detached protected projection candidates (ADR-094 §1, ADR-113 §1, §3 and
//! §4 E5).
//!
//! A [`ProtectedProjectionProviderV1`] opens a [`DetachedProjectionCandidateV1`]
//! for an exact recorded consumer set, from an initial State, bound to one
//! source. The candidate owns freshly built reducer instances and per-reducer
//! State maps; it holds no reference to any visible
//! [`crate::ProjectionRegistry`]. It folds Events with the same step the
//! visible registry uses, so a candidate fold equals the live fold, and it
//! accounts its staged size incrementally for the staged executor.

use std::{collections::HashMap, convert::Infallible, time::Duration};

use pos_core::{
    staged_install::ProjectionSourceV1, EntityId, Event, Hash, PluginId, Reducer, State,
    StateRegistry,
};

use crate::{staged::StagedSlotV1, ProjectionObservationPolicyV1, StagedProjectionV1};

/// Largest staged output of one fold, in staged-size bytes (ADR-093).
pub const MAX_STAGED_OUTPUT_BYTES_V1: u64 = 64 * 1024 * 1024;
/// Largest number of entities one consumer may hold (ADR-094 PSS1).
pub const MAX_STAGED_ENTITIES_PER_CONSUMER_V1: usize = 65_536;
/// Largest number of consumers in one protected plan (ADR-094 PSS1).
pub const MAX_STAGED_CONSUMERS_V1: usize = 64;

/// Staged-size bytes charged for each entity identifier.
const ENTITY_ID_BYTES: u64 = 16;

/// Exact recorded identity of one protected Reducer consumer.
///
/// The Plugin identity selects the consumer; the reducer identity digest
/// binds the admitted catalogue entry that the provider issued it for, so a
/// stale or substituted entry is rejected rather than reinterpreted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecordedConsumerV1 {
    plugin_id: PluginId,
    reducer_identity: Hash,
}

impl RecordedConsumerV1 {
    /// Record one consumer identity.
    #[must_use]
    pub const fn new(plugin_id: PluginId, reducer_identity: Hash) -> Self {
        Self {
            plugin_id,
            reducer_identity,
        }
    }

    /// The consumer's stable Plugin identity.
    #[must_use]
    pub const fn plugin_id(&self) -> PluginId {
        self.plugin_id
    }

    /// The admitted reducer identity digest.
    #[must_use]
    pub const fn reducer_identity(&self) -> Hash {
        self.reducer_identity
    }
}

/// Closed failures of opening a protected candidate, decided before any
/// reducer callback runs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProjectionCandidateErrorV1 {
    /// A recorded consumer has no admitted host-catalogue entry.
    NotAdmitted,
    /// The recorded consumer set is empty, names a consumer twice, or names
    /// an admitted Plugin with a different reducer identity.
    ConsumerSetMismatch,
    /// An admitted factory built no reducer, or built a Plugin other than
    /// the recorded one.
    PluginMismatch,
    /// The candidate source is not bound to one Timeline.
    SourceMismatch,
}

/// The State a candidate starts from.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InitialStateV1 {
    /// Every consumer starts with no entity State.
    Empty,
}

/// Host-installed source of detached protected projection candidates.
///
/// The provider is selected from the installed host composition, never from a
/// caller. Every candidate it opens owns fresh, independently built reducer
/// internals for exactly the recorded consumers, in recorded order.
pub trait ProtectedProjectionProviderV1 {
    /// Open a fresh candidate for exactly `recorded_consumers`, starting from
    /// `initial_state` and bound to `source`.
    ///
    /// # Errors
    /// Returns [`ProjectionCandidateErrorV1::NotAdmitted`] or
    /// [`ProjectionCandidateErrorV1::ConsumerSetMismatch`] before any reducer
    /// is built, [`ProjectionCandidateErrorV1::PluginMismatch`] when an
    /// admitted factory builds no reducer or another Plugin, or
    /// [`ProjectionCandidateErrorV1::SourceMismatch`] for an unbound source.
    fn open_candidate(
        &self,
        recorded_consumers: &[RecordedConsumerV1],
        initial_state: InitialStateV1,
        source: ProjectionSourceV1,
    ) -> Result<DetachedProjectionCandidateV1, ProjectionCandidateErrorV1>;
}

/// Admitted bounds of one candidate consumer (ADR-113 §4).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CandidateBoundsV1 {
    /// Admitted bound on the duration of one callback.
    pub callback_bound: Duration,
    /// Declared State growth per Event payload byte of one `apply`.
    pub growth_per_payload_byte: u64,
    /// Declared State growth of one `apply` regardless of payload.
    pub growth_constant_bytes: u64,
}

impl CandidateBoundsV1 {
    const fn growth(&self, event: &Event) -> u64 {
        self.growth_per_payload_byte
            .saturating_mul(event.payload.len() as u64)
            .saturating_add(self.growth_constant_bytes)
    }
}

/// One freshly built reducer for a candidate, with its recorded identity,
/// Plugin name, admitted bounds and copied observation policy.
pub struct CandidateReducerV1 {
    /// The recorded consumer the reducer was built for.
    pub consumer: RecordedConsumerV1,
    /// The built Plugin's name, matched against the visible slot name.
    pub name: &'static str,
    /// The freshly built reducer instance.
    pub reducer: Box<dyn Reducer>,
    /// The consumer's admitted bounds.
    pub bounds: CandidateBoundsV1,
    /// The observation policy copied at open, matched against the visible slot.
    pub observation_policy: Option<ProjectionObservationPolicyV1>,
}

/// Closed failures of the incremental staged-size accounting (ADR-113 §4 E5).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StagedLimitErrorV1 {
    /// The exact staged size exceeds [`MAX_STAGED_OUTPUT_BYTES_V1`].
    StagedOutputExceeded,
    /// A consumer holds more than [`MAX_STAGED_ENTITIES_PER_CONSUMER_V1`] entities.
    EntityLimitExceeded,
    /// An entity grew by more than the sum of its declared growth bounds.
    GrowthBoundExceeded,
}

#[derive(Clone, Copy, Debug, Default)]
struct EntityAccountV1 {
    measured: u64,
    declared: u64,
}

/// Incremental staged-size accounting of one candidate (ADR-113 §4 E5).
///
/// Each `apply` adds its declared growth bound to an upper bound, and each
/// new entity adds its exact staged size once. An exact pass re-measures
/// every entity only when the upper bound would exceed the staged limit, and
/// once at the end of the fold.
#[derive(Debug, Default)]
pub struct StagedAccountingV1 {
    upper: u64,
    exact: u64,
    exact_passes: u32,
    current: bool,
    entities: HashMap<(usize, EntityId), EntityAccountV1>,
}

impl StagedAccountingV1 {
    /// The current upper bound on the staged size.
    #[must_use]
    pub const fn upper_bound(&self) -> u64 {
        self.upper
    }

    /// The staged size measured by the last exact pass.
    #[must_use]
    pub const fn last_exact(&self) -> u64 {
        self.exact
    }

    /// Number of exact passes run so far.
    #[must_use]
    pub const fn exact_passes(&self) -> u32 {
        self.exact_passes
    }

    fn record(&mut self, key: (usize, EntityId), state: &State, growth: u64) {
        self.current = false;
        if let Some(account) = self.entities.get_mut(&key) {
            account.declared = account.declared.saturating_add(growth);
            self.upper = self.upper.saturating_add(growth);
        } else {
            let measured = staged_state_bytes(state);
            self.entities.insert(
                key,
                EntityAccountV1 {
                    measured,
                    declared: 0,
                },
            );
            self.upper = self.upper.saturating_add(measured);
        }
    }

    fn forget(&mut self, slots: usize, subject: EntityId) {
        for ordinal in 0..slots {
            self.entities.remove(&(ordinal, subject));
        }
        self.current = false;
    }

    fn exact_pass<'r>(
        &mut self,
        registries: impl Iterator<Item = &'r StateRegistry>,
    ) -> Result<(), StagedLimitErrorV1> {
        self.exact_passes = self.exact_passes.saturating_add(1);
        let mut total: u64 = 0;
        for (ordinal, registry) in registries.enumerate() {
            for (entity, state) in registry.entries() {
                let size = staged_state_bytes(state);
                let account = self.entities.entry((ordinal, *entity)).or_default();
                if size > account.measured.saturating_add(account.declared) {
                    return Err(StagedLimitErrorV1::GrowthBoundExceeded);
                }
                *account = EntityAccountV1 {
                    measured: size,
                    declared: 0,
                };
                total = total.saturating_add(size);
            }
        }
        self.exact = total;
        self.upper = total;
        if total > MAX_STAGED_OUTPUT_BYTES_V1 {
            return Err(StagedLimitErrorV1::StagedOutputExceeded);
        }
        self.current = true;
        Ok(())
    }
}

/// Staged size of one entity: its identifier plus every field name and the
/// canonical JSON text of every field value. It is independent of map order.
fn staged_state_bytes(state: &State) -> u64 {
    state
        .fields
        .iter()
        .map(|(key, value)| (key.len() + value.to_string().len()) as u64)
        .fold(ENTITY_ID_BYTES, u64::saturating_add)
}

/// One candidate-owned reducer instance and its private State map, held in
/// the same slot type the visible registry folds.
struct CandidateSlotV1 {
    consumer: RecordedConsumerV1,
    name: &'static str,
    bounds: CandidateBoundsV1,
    inner: crate::Slot,
}

/// One consumer's turn at one Event in the shared live fold step.
///
/// The staged executor runs [`Self::apply`] as one callback under its
/// enforcement points, then [`Self::account`] as host accounting.
pub struct CandidateTurnV1<'t> {
    ordinal: usize,
    event: &'t Event,
    slot: &'t mut CandidateSlotV1,
    accounting: &'t mut StagedAccountingV1,
}

impl CandidateTurnV1<'_> {
    /// The consumer's position in recorded order.
    #[must_use]
    pub const fn ordinal(&self) -> usize {
        self.ordinal
    }

    /// The consumer's admitted bounds.
    #[must_use]
    pub const fn bounds(&self) -> CandidateBoundsV1 {
        self.slot.bounds
    }

    /// Offer the Event to the consumer's reducer: its exclusion check,
    /// `projects_event`, `initial` for an absent entity, then `apply`.
    pub fn apply(&mut self) {
        self.slot.inner.fold(self.event);
    }

    /// Account the Event's effect on the consumer's staged size.
    ///
    /// # Errors
    /// Returns [`StagedLimitErrorV1::EntityLimitExceeded`] when the consumer
    /// holds more than [`MAX_STAGED_ENTITIES_PER_CONSUMER_V1`] entities.
    pub fn account(&mut self) -> Result<(), StagedLimitErrorV1> {
        if self.slot.inner.registry.len() > MAX_STAGED_ENTITIES_PER_CONSUMER_V1 {
            return Err(StagedLimitErrorV1::EntityLimitExceeded);
        }
        let entity = self.event.entity;
        if let Some(state) = self.slot.inner.registry.get(&entity) {
            let growth = self.slot.bounds.growth(self.event);
            self.accounting
                .record((self.ordinal, entity), state, growth);
        }
        Ok(())
    }
}

/// Private projection candidate: ordered, freshly built reducer instances
/// with their own State maps and no reference to a visible registry.
///
/// It also holds its bound source, its staged-size accounting and the
/// subjects it forgot. Its reducer instances are never exposed; only
/// bounded State reads are. A provider assembles it with
/// [`Self::from_reducers`] from one freshly built reducer per recorded
/// consumer.
///
/// # Trust boundary
/// [`Self::from_reducers`] is a public construction path for trusted
/// providers only. It is not an admission path: it checks no review,
/// conformance evidence or reducer identity. Admission happens only in the
/// host catalogue provider (`pos_runtime::HostProjectionProviderV1`), and
/// protected work must take its candidates from a
/// [`ProtectedProjectionProviderV1`], never build one directly.
pub struct DetachedProjectionCandidateV1 {
    slots: Vec<CandidateSlotV1>,
    source: ProjectionSourceV1,
    accounting: StagedAccountingV1,
    revocations: Vec<EntityId>,
}

impl DetachedProjectionCandidateV1 {
    /// Assemble a candidate from one freshly built reducer per recorded
    /// consumer, in recorded order, starting from `initial_state` and bound
    /// to `source`.
    ///
    /// For trusted providers only; this is not an admission path. The caller
    /// vouches that every reducer was freshly built from an admitted entry
    /// whose identity matches its consumer; admission is
    /// `pos_runtime::HostProjectionProviderV1`. See the type-level trust
    /// boundary.
    ///
    /// # Errors
    /// Returns [`ProjectionCandidateErrorV1::SourceMismatch`] for a source
    /// that is not bound to one Timeline, or
    /// [`ProjectionCandidateErrorV1::ConsumerSetMismatch`] when two entries
    /// name the same Plugin.
    pub fn from_reducers(
        reducers: Vec<CandidateReducerV1>,
        initial_state: InitialStateV1,
        source: ProjectionSourceV1,
    ) -> Result<Self, ProjectionCandidateErrorV1> {
        let InitialStateV1::Empty = initial_state;
        if source.timeline().is_none() {
            return Err(ProjectionCandidateErrorV1::SourceMismatch);
        }
        let slots: Vec<CandidateSlotV1> = reducers
            .into_iter()
            .map(|reducer| CandidateSlotV1 {
                consumer: reducer.consumer,
                name: reducer.name,
                bounds: reducer.bounds,
                inner: crate::Slot {
                    plugin_id: Some(reducer.consumer.plugin_id),
                    reducer: reducer.reducer,
                    registry: StateRegistry::new(),
                    observation_policy: reducer.observation_policy,
                },
            })
            .collect();
        let repeated = slots.iter().enumerate().any(|(index, slot)| {
            slots[..index]
                .iter()
                .any(|earlier| earlier.consumer.plugin_id == slot.consumer.plugin_id)
        });
        let candidate = Self {
            slots,
            source,
            accounting: StagedAccountingV1::default(),
            revocations: Vec::new(),
        };
        (!repeated)
            .then_some(candidate)
            .ok_or(ProjectionCandidateErrorV1::ConsumerSetMismatch)
    }

    /// The recorded consumers of this candidate, in fold order.
    #[must_use]
    pub fn consumers(&self) -> Vec<RecordedConsumerV1> {
        self.slots.iter().map(|slot| slot.consumer).collect()
    }

    /// The source the candidate is bound to.
    #[must_use]
    pub const fn source(&self) -> ProjectionSourceV1 {
        self.source
    }

    /// The candidate's staged-size accounting.
    #[must_use]
    pub const fn accounting(&self) -> &StagedAccountingV1 {
        &self.accounting
    }

    /// The subjects forgotten by `consent.revoked.v1` Events, in fold order.
    #[must_use]
    pub fn revocations(&self) -> &[EntityId] {
        &self.revocations
    }

    /// Fold host-filtered Events from the bound source into the candidate,
    /// without enforcement points or accounting.
    ///
    /// Each Event goes through the live fold step of
    /// [`crate::ProjectionRegistry`]: a well-formed `consent.revoked.v1`
    /// subject is forgotten from every candidate map, other consent and
    /// geographic Events are skipped, and every other Event is offered to
    /// every reducer in recorded order.
    pub fn fold_events(&mut self, events: &[Event]) {
        for event in events {
            let Ok(()) = self.fold_event_with(event, |mut turn| {
                turn.apply();
                Ok::<(), Infallible>(())
            });
        }
    }

    /// Fold one Event through the live fold step, handing each consumer's
    /// turn to `offer` in recorded order.
    ///
    /// # Errors
    /// Returns the first error of `offer`; the candidate must then be
    /// discarded.
    pub fn fold_event_with<E>(
        &mut self,
        event: &Event,
        mut offer: impl FnMut(CandidateTurnV1<'_>) -> Result<(), E>,
    ) -> Result<(), E> {
        let accounting = &mut self.accounting;
        let revocation = crate::fold_bound_event(
            self.slots.iter_mut().enumerate(),
            event,
            |(ordinal, slot)| {
                offer(CandidateTurnV1 {
                    ordinal,
                    event,
                    slot,
                    accounting: &mut *accounting,
                })
            },
        )?;
        if let Some(revocation) = revocation {
            for slot in &mut self.slots {
                slot.inner.registry.remove(&revocation.subject_id);
            }
            self.accounting
                .forget(self.slots.len(), revocation.subject_id);
            self.revocations.push(revocation.subject_id);
        }
        Ok(())
    }

    /// Whether the accounting upper bound exceeds the staged limit, so an
    /// exact pass is due before the next Event.
    #[must_use]
    pub const fn exact_pass_due(&self) -> bool {
        self.accounting.upper > MAX_STAGED_OUTPUT_BYTES_V1
    }

    /// Re-measure every entity exactly and reset the upper bound to it.
    ///
    /// # Errors
    /// Returns [`StagedLimitErrorV1::GrowthBoundExceeded`] for an entity that
    /// grew by more than its declared bounds since the previous pass, or
    /// [`StagedLimitErrorV1::StagedOutputExceeded`] when the exact staged size
    /// exceeds [`MAX_STAGED_OUTPUT_BYTES_V1`].
    pub fn exact_pass(&mut self) -> Result<(), StagedLimitErrorV1> {
        self.accounting
            .exact_pass(self.slots.iter().map(|slot| &slot.inner.registry))
    }

    /// Move the folded maps out as a [`StagedProjectionV1`], leaving the
    /// reducer instances for the caller to drop.
    ///
    /// Returns `None` unless an exact pass succeeded after the last change,
    /// so no staged result exists without a final exact pass.
    pub fn take_staged(&mut self) -> Option<StagedProjectionV1> {
        if !self.accounting.current {
            return None;
        }
        self.accounting.current = false;
        let consumers = self.consumers();
        let slots = self
            .slots
            .iter_mut()
            .map(|slot| StagedSlotV1 {
                plugin_id: slot.consumer.plugin_id,
                name: slot.name,
                observation_policy: slot.inner.observation_policy.take(),
                registry: std::mem::take(&mut slot.inner.registry),
            })
            .collect();
        Some(StagedProjectionV1::new(
            consumers,
            self.source,
            slots,
            std::mem::take(&mut self.revocations),
        ))
    }

    /// Candidate-owned State of one entity for one recorded consumer.
    #[must_use]
    pub fn state_for(&self, plugin_id: PluginId, entity: &EntityId) -> Option<&State> {
        self.slots
            .iter()
            .find(|slot| slot.consumer.plugin_id == plugin_id)
            .and_then(|slot| slot.inner.registry.get(entity))
    }
}
