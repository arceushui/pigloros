//! Staged protected projection results and their install checks (ADR-113 §2).

use pos_core::{
    staged_install::ProjectionSourceV1, ConsentRevokedV1, EntityId, Event, PluginId, StateRegistry,
    EVENT_TYPE_CONSENT_REVOKED_V1,
};

use crate::{ProjectionObservationPolicyV1, RecordedConsumerV1};

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

/// One staged consumer's private State map and the identity it must match.
pub(super) struct StagedSlotV1 {
    pub(super) plugin_id: PluginId,
    pub(super) name: &'static str,
    pub(super) observation_policy: Option<ProjectionObservationPolicyV1>,
    pub(super) registry: StateRegistry,
}

/// The complete result of one staged fold.
///
/// It holds no reducer instance and exposes no State; its maps reach a
/// visible registry only through [`crate::ProjectionRegistry::prepare_install`]
/// and ADR-112's checked handoff. It cannot be cloned.
pub struct StagedProjectionV1 {
    consumers: Vec<RecordedConsumerV1>,
    source: ProjectionSourceV1,
    slots: Vec<StagedSlotV1>,
    revocations: Vec<EntityId>,
}

impl StagedProjectionV1 {
    pub(super) const fn new(
        consumers: Vec<RecordedConsumerV1>,
        source: ProjectionSourceV1,
        slots: Vec<StagedSlotV1>,
        revocations: Vec<EntityId>,
    ) -> Self {
        Self {
            consumers,
            source,
            slots,
            revocations,
        }
    }

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

    /// The entities whose State differs between two staged results, slot by
    /// slot, over the union of their entity IDs, sorted by raw `EntityId`
    /// bytes. An absent entity or slot counts as default State. The result
    /// holds IDs only.
    #[must_use]
    pub fn diverged_entities(&self, other: &Self) -> Vec<EntityId> {
        let empty = &StateRegistry::new();
        let mut diverged: Vec<EntityId> = (0..self.slots.len().max(other.slots.len()))
            .flat_map(move |index| {
                let mine = slot_registry(&self.slots, index, empty);
                let theirs = slot_registry(&other.slots, index, empty);
                mine.entity_ids()
                    .chain(theirs.entity_ids())
                    .filter(move |entity| {
                        mine.get_or_default(entity) != theirs.get_or_default(entity)
                    })
            })
            .collect();
        diverged.sort_unstable_by_key(|entity| entity.inner().to_bytes());
        diverged.dedup();
        diverged
    }

    pub(super) fn slots(&self) -> &[StagedSlotV1] {
        &self.slots
    }

    pub(super) fn into_install_parts(self) -> (ProjectionSourceV1, Vec<StateRegistry>) {
        let maps = self.slots.into_iter().map(|slot| slot.registry).collect();
        (self.source, maps)
    }
}

fn slot_registry<'s>(
    slots: &'s [StagedSlotV1],
    index: usize,
    empty: &'s StateRegistry,
) -> &'s StateRegistry {
    slots.get(index).map_or(empty, |slot| &slot.registry)
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
