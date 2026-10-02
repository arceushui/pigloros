//! Detached protected projection candidates (ADR-094 §1, ADR-113 §1).
//!
//! A [`ProtectedProjectionProviderV1`] opens a [`DetachedProjectionCandidateV1`]
//! for an exact recorded consumer set. The candidate owns freshly built
//! reducer instances and per-reducer State maps; it holds no reference to any
//! visible [`crate::ProjectionRegistry`]. It folds Events with the same step
//! the visible registry uses, so a candidate fold equals the live fold.

use pos_core::{EntityId, Event, Hash, PluginId, Reducer, State, StateRegistry};

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
    /// An admitted factory built no reducer for a candidate.
    PluginMismatch,
}

/// Host-installed source of detached protected projection candidates.
///
/// The provider is selected from the installed host composition, never from a
/// caller. Every candidate it opens owns fresh, independently built reducer
/// internals for exactly the recorded consumers, in recorded order.
pub trait ProtectedProjectionProviderV1 {
    /// Open a fresh candidate for exactly `recorded_consumers`.
    ///
    /// # Errors
    /// Returns [`ProjectionCandidateErrorV1::NotAdmitted`] or
    /// [`ProjectionCandidateErrorV1::ConsumerSetMismatch`] before any reducer
    /// is built, or [`ProjectionCandidateErrorV1::PluginMismatch`] when an
    /// admitted factory builds no reducer.
    fn open_candidate(
        &self,
        recorded_consumers: &[RecordedConsumerV1],
    ) -> Result<DetachedProjectionCandidateV1, ProjectionCandidateErrorV1>;
}

/// One candidate-owned reducer instance and its private State map.
struct CandidateSlotV1 {
    consumer: RecordedConsumerV1,
    reducer: Box<dyn Reducer>,
    registry: StateRegistry,
}

impl CandidateSlotV1 {
    fn fold_parts(&mut self) -> (&dyn Reducer, &mut StateRegistry) {
        (self.reducer.as_ref(), &mut self.registry)
    }
}

/// Private projection candidate: ordered, freshly built reducer instances
/// with their own State maps and no reference to a visible registry.
///
/// Its reducer instances are never exposed; only bounded State reads are.
/// A provider starts from [`Default`] and appends one freshly built reducer
/// per recorded consumer with [`Self::push_reducer`].
#[derive(Default)]
pub struct DetachedProjectionCandidateV1 {
    slots: Vec<CandidateSlotV1>,
}

impl DetachedProjectionCandidateV1 {
    /// Append the freshly built reducer of the next recorded consumer.
    ///
    /// # Errors
    /// Returns [`ProjectionCandidateErrorV1::ConsumerSetMismatch`] without
    /// changing the candidate when the consumer's Plugin is already present.
    pub fn push_reducer(
        &mut self,
        consumer: RecordedConsumerV1,
        reducer: Box<dyn Reducer>,
    ) -> Result<(), ProjectionCandidateErrorV1> {
        if self
            .slots
            .iter()
            .any(|slot| slot.consumer.plugin_id == consumer.plugin_id)
        {
            return Err(ProjectionCandidateErrorV1::ConsumerSetMismatch);
        }
        self.slots.push(CandidateSlotV1 {
            consumer,
            reducer,
            registry: StateRegistry::new(),
        });
        Ok(())
    }

    /// The recorded consumers of this candidate, in fold order.
    #[must_use]
    pub fn consumers(&self) -> Vec<RecordedConsumerV1> {
        self.slots.iter().map(|slot| slot.consumer).collect()
    }

    /// Fold host-filtered Events from one source into the candidate.
    ///
    /// Each Event goes through the live fold step of
    /// [`crate::ProjectionRegistry`]: a well-formed `consent.revoked.v1`
    /// subject is forgotten from every candidate map, other consent and
    /// geographic Events are skipped, and every other Event is offered to
    /// every reducer in recorded order.
    pub fn fold_events(&mut self, events: &[Event]) {
        for event in events {
            let revocation = crate::fold_bound_event(
                self.slots.iter_mut().map(CandidateSlotV1::fold_parts),
                event,
            );
            if let Some(revocation) = revocation {
                for slot in &mut self.slots {
                    slot.registry.remove(&revocation.subject_id);
                }
            }
        }
    }

    /// Candidate-owned State of one entity for one recorded consumer.
    #[must_use]
    pub fn state_for(&self, plugin_id: PluginId, entity: &EntityId) -> Option<&State> {
        self.slots
            .iter()
            .find(|slot| slot.consumer.plugin_id == plugin_id)
            .and_then(|slot| slot.registry.get(entity))
    }
}
