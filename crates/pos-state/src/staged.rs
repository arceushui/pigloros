//! Staged protected projection results and their install checks (ADR-113 §2).

use pos_core::{
    staged_install::ProjectionSourceV1, ConsentRevokedV1, EntityId, Event, PluginId, State,
    StateRegistry, EVENT_TYPE_CONSENT_REVOKED_V1,
};

use crate::{ProjectionCandidateErrorV1, ProjectionObservationPolicyV1, RecordedConsumerV1};

/// The complete result of one staged fold.
///
/// It holds no reducer instance and exposes no State; its maps reach a
/// visible registry only through
/// [`crate::ProjectionRegistry::prepare_install`] and ADR-112's checked
/// handoff. It cannot be cloned. Only a
/// [`crate::DetachedProjectionCandidateV1`] in this crate assembles one.
pub struct StagedProjectionV1 {
    pub(super) consumers: Vec<RecordedConsumerV1>,
    pub(super) source: ProjectionSourceV1,
    pub(super) slots: Vec<StagedSlotV1>,
    pub(super) revocations: Vec<EntityId>,
}

/// One staged consumer's private State map and the identity it must match.
pub(super) struct StagedSlotV1 {
    pub(super) plugin_id: PluginId,
    pub(super) name: &'static str,
    pub(super) observation_policy: Option<ProjectionObservationPolicyV1>,
    pub(super) registry: StateRegistry,
}

/// Closed failures of [`crate::ProjectionRegistry::prepare_install`]. The
/// visible registry is unchanged on every failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InstallErrorV1 {
    /// The registry has no host-bound erasure gate, or the staged source is
    /// not bound at its current inventory generation.
    SourceMismatch,
    /// A staged slot does not match the visible slot at its position:
    /// installed Plugin identity, name, observation policy or slot count.
    SlotMismatch,
}

impl StagedProjectionV1 {
    /// The recorded consumers, in fold order.
    #[must_use]
    pub fn consumers(&self) -> &[RecordedConsumerV1] {
        &self.consumers
    }

    /// The Timeline and generation the result was folded from.
    #[must_use]
    pub const fn source(&self) -> ProjectionSourceV1 {
        self.source
    }

    /// The revoked subjects the fold forgot, in fold order.
    #[must_use]
    pub fn revoked_subjects(&self) -> &[EntityId] {
        &self.revocations
    }

    /// The entities whose State differs between two staged results, matched
    /// consumer by consumer on their Plugin identity, over the union of their
    /// entity IDs, sorted by raw `EntityId` bytes. An absent entity counts as
    /// empty State. The result holds IDs only.
    ///
    /// # Errors
    /// Returns [`ProjectionCandidateErrorV1::ConsumerSetMismatch`] when the
    /// two results were folded for different consumer sets.
    pub fn diverged_entities(
        &self,
        other: &Self,
    ) -> Result<Vec<EntityId>, ProjectionCandidateErrorV1> {
        let pairs = self
            .slots
            .iter()
            .map(|mine| {
                other
                    .slots
                    .iter()
                    .find(|theirs| theirs.plugin_id == mine.plugin_id)
                    .map(|theirs| (&mine.registry, &theirs.registry))
            })
            .collect::<Option<Vec<_>>>()
            .filter(|pairs| pairs.len() == other.slots.len())
            .ok_or(ProjectionCandidateErrorV1::ConsumerSetMismatch)?;
        let empty = State::new();
        let mut diverged: Vec<EntityId> = pairs
            .into_iter()
            .flat_map(|(mine, theirs)| {
                let empty = &empty;
                mine.entity_ids()
                    .chain(theirs.entity_ids())
                    .filter(move |entity| {
                        mine.get(entity).unwrap_or(empty) != theirs.get(entity).unwrap_or(empty)
                    })
            })
            .collect();
        diverged.sort_unstable_by_key(|entity| entity.inner().to_bytes());
        diverged.dedup();
        Ok(diverged)
    }
}

/// Subject IDs of the `consent.revoked.v1` Events in one verified range.
///
/// The host collects them inside the guard and applies them after release
/// with [`crate::ProjectionRegistry::forget_revoked_subjects`]. They carry IDs
/// only, never Events.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RevokedSubjectsV1 {
    subjects: Vec<EntityId>,
}

impl RevokedSubjectsV1 {
    /// Decode the revoked subjects of a range that was read and verified
    /// complete. A malformed revocation names no subject, as in the live fold.
    #[must_use]
    pub fn from_verified_events(events: &[Event]) -> Self {
        let subjects = events
            .iter()
            .filter(|event| event.event_type.as_str() == EVENT_TYPE_CONSENT_REVOKED_V1)
            .filter_map(|event| ConsentRevokedV1::decode(&event.payload).ok())
            .map(|revocation| revocation.subject_id)
            .collect();
        Self { subjects }
    }

    /// The revoked subject IDs, in range order.
    #[must_use]
    pub fn subjects(&self) -> &[EntityId] {
        &self.subjects
    }
}
