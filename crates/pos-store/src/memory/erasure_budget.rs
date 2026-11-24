//! The Memory counters behind the community erasure budget (ADR-129
//! revision 13, R13.1(1)-(2)).
//!
//! `targets(A)` is the ADR-136 closure size of a private-subject-data request
//! of actor A: 1 store target, 1 `timeline-payload` per affected Timeline,
//! A's role-0 subject keys, and 1 plus the role-7 key dependencies of each
//! distinct `PrivateSubjectData` row bound to an affected Timeline. `rows(U)`
//! is the number of catalogue rows of any class bound to U.
//!
//! The row terms are incremental counters, updated wherever a binding is
//! written, in the same store mutation: per Timeline its rows and the
//! targets of its private rows, and the rows bound to two or more
//! Timelines, which an actor whose scope holds several of them counts once.
//! The affected scope and the role-0 key count are derived under the guard
//! from the Timeline metadata and the key registry; nothing scans the
//! catalogue. Host Timelines are counted too, which can only over-count. Two
//! owners' rows of one artifact digest are two targets here and one in the
//! closure, which also only over-counts.

use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};

use pos_core::community_lifecycle::CommunityLifecycleErrorV1 as Error;
use pos_core::{
    ArtifactDataClassV1, ArtifactRegistrationCatalogRowV1, EntityId, Hash, KeyRegistryStateV1,
    KeyRoleV1, OwnerIdV1, TimelineId,
};

use super::MemoryStore;

/// One Timeline's counters.
#[derive(Clone, Copy, Default)]
struct TimelineCountV1 {
    rows: u64,
    private_targets: u64,
}

/// The incremental row counters of the catalogue's Timeline bindings.
#[derive(Default)]
pub(super) struct ErasureCountersV1 {
    timelines: BTreeMap<TimelineId, TimelineCountV1>,
    /// The first Timeline each row was bound to.
    first: BTreeMap<Hash, TimelineId>,
    /// Each row bound to two or more Timelines: its closure targets (none
    /// for another data class) and every Timeline it is bound to.
    shared: BTreeMap<Hash, (u64, BTreeSet<TimelineId>)>,
}

impl ErasureCountersV1 {
    /// Count one new `(timeline, address)` binding of a row whose closure
    /// cells are `targets`.
    fn bind(&mut self, timeline: TimelineId, address: Hash, targets: u64) {
        let count = self.timelines.entry(timeline).or_default();
        count.rows += 1;
        count.private_targets += targets;
        match self.first.entry(address) {
            Entry::Vacant(entry) => {
                entry.insert(timeline);
            }
            Entry::Occupied(entry) => {
                self.shared
                    .entry(address)
                    .or_insert_with(|| (targets, BTreeSet::from([*entry.get()])))
                    .1
                    .insert(timeline);
            }
        }
    }

    fn count(&self, timeline: TimelineId) -> TimelineCountV1 {
        self.timelines.get(&timeline).copied().unwrap_or_default()
    }
}

/// The closure targets of one catalogue row in a private-subject-data
/// request: its Artifact target and one key target per role-7 key
/// dependency; none for another data class.
fn row_targets(row: &ArtifactRegistrationCatalogRowV1) -> u64 {
    let fields = row.registration().fields();
    if fields.data_class == ArtifactDataClassV1::PrivateSubjectData {
        1 + fields
            .key_dependencies
            .iter()
            .filter(|dependency| dependency.identity.role == KeyRoleV1::CommunityArtifactEncryption)
            .count() as u64
    } else {
        0
    }
}

/// One actor of a Timeline's scope: A, `targets(A)` and `affected(A)`.
type ActorCount = (EntityId, u64, BTreeSet<TimelineId>);

/// A Timeline's scope: every actor whose affected scope contains it, and
/// `rows(U)` for every U of their affected scopes.
type ScopeCount = (Vec<ActorCount>, BTreeMap<TimelineId, u64>);

impl MemoryStore {
    /// Count the new `bindings` of `rows`, before they are written.
    pub(super) fn count_erasure_bindings<'a>(
        &mut self,
        bindings: &BTreeSet<(TimelineId, Hash)>,
        rows: impl Iterator<Item = &'a ArtifactRegistrationCatalogRowV1>,
    ) {
        let targets: BTreeMap<Hash, u64> = rows
            .map(|row| (row.registration_address(), row_targets(row)))
            .collect();
        for (timeline, address) in bindings {
            self.erasure_counters
                .bind(*timeline, *address, targets[address]);
        }
    }

    /// The scope of `timeline` with each actor's `targets(A)` and every
    /// `rows(U)` (R13.1(1)-(2)), committed store data only.
    ///
    /// # Errors
    /// `EvidenceUnavailable` when the Fork lineage of `timeline` names a
    /// Timeline the store does not hold or loops (a topology it cannot
    /// walk).
    pub(crate) fn community_erasure_scope(
        &self,
        timeline: TimelineId,
    ) -> Result<ScopeCount, Error> {
        self.scope_actors(timeline).map(|actors| {
            let children = self.fork_children();
            let actors: Vec<ActorCount> = actors
                .into_iter()
                .map(|actor| {
                    let affected = self.affected(actor, &children);
                    (actor, self.actor_targets(actor, &affected), affected)
                })
                .collect();
            let rows = actors
                .iter()
                .flat_map(|(_, _, affected)| affected.iter())
                .map(|affected| (*affected, self.erasure_counters.count(*affected).rows))
                .collect();
            (actors, rows)
        })
    }

    /// `affected(A)` (R13.1(1)) of `actor`, from the committed topology.
    pub(crate) fn community_affected_scope(&self, actor: EntityId) -> BTreeSet<TimelineId> {
        self.affected(actor, &self.fork_children())
    }

    /// The owners of `timeline` and of each of its `fork_point` ancestors.
    fn scope_actors(&self, timeline: TimelineId) -> Result<BTreeSet<EntityId>, Error> {
        let mut actors = BTreeSet::new();
        let mut walked = BTreeSet::new();
        let mut next = Some(timeline);
        while let Some(current) = next {
            let meta = self
                .timelines
                .get(&current)
                .filter(|_| walked.insert(current))
                .map(|state| &state.timeline.meta)
                .ok_or(Error::EvidenceUnavailable)?;
            actors.extend(meta.owner);
            next = meta.fork_point.map(|(parent, _)| parent);
        }
        Ok(actors)
    }

    /// Every Fork child of each Timeline, by `fork_point`.
    fn fork_children(&self) -> BTreeMap<TimelineId, Vec<TimelineId>> {
        let mut children = BTreeMap::<TimelineId, Vec<TimelineId>>::new();
        for state in self.timelines.values() {
            if let Some((parent, _)) = state.timeline.meta.fork_point {
                children
                    .entry(parent)
                    .or_default()
                    .push(state.timeline.meta.id);
            }
        }
        children
    }

    /// `affected(A)`: every Timeline `actor` owns and every Fork descendant.
    fn affected(
        &self,
        actor: EntityId,
        children: &BTreeMap<TimelineId, Vec<TimelineId>>,
    ) -> BTreeSet<TimelineId> {
        let mut affected: BTreeSet<TimelineId> = self
            .timelines
            .values()
            .filter(|state| state.timeline.meta.owner == Some(actor))
            .map(|state| state.timeline.meta.id)
            .collect();
        let mut pending: Vec<TimelineId> = affected.iter().copied().collect();
        while let Some(parent) = pending.pop() {
            for child in children.get(&parent).into_iter().flatten() {
                if affected.insert(*child) {
                    pending.push(*child);
                }
            }
        }
        affected
    }

    /// `targets(A)` over `affected`, each shared private row counted once.
    fn actor_targets(&self, actor: EntityId, affected: &BTreeSet<TimelineId>) -> u64 {
        let rows: u64 = affected
            .iter()
            .map(|timeline| self.erasure_counters.count(*timeline).private_targets)
            .sum();
        let repeated: u64 = self
            .erasure_counters
            .shared
            .values()
            .map(|(targets, timelines)| {
                targets * (timelines.intersection(affected).count() as u64).saturating_sub(1)
            })
            .sum();
        1 + affected.len() as u64 + self.subject_keys(actor) + rows - repeated
    }

    /// A's role-0 subject keys of every epoch in the key registry.
    fn subject_keys(&self, actor: EntityId) -> u64 {
        pos_crypto::subject_key::subject_owner_id(actor)
            .ok()
            .and_then(|owner| OwnerIdV1::new(owner).ok())
            .map_or(0, |owner| {
                self.key_registry
                    .iter()
                    .flat_map(KeyRegistryStateV1::key_records)
                    .filter(|record| {
                        record.identity.owner_id == owner
                            && record.identity.role == KeyRoleV1::SubjectDataEncryption
                    })
                    .count() as u64
            })
    }
}

#[cfg(any(test, feature = "test-support"))]
impl MemoryStore {
    /// Catalogue `rows` and bind each to `timeline` through the counted
    /// binding path, as a committed operation would. A row already
    /// catalogued keeps its first copy, and an existing binding is not
    /// counted again. Test seam for the R13 budget tests.
    pub fn bind_erasure_rows_for_test(
        &mut self,
        timeline: TimelineId,
        rows: Vec<ArtifactRegistrationCatalogRowV1>,
    ) {
        let fresh: BTreeSet<(TimelineId, Hash)> = rows
            .iter()
            .map(|row| (timeline, row.registration_address()))
            .filter(|binding| !self.artifact_registration_timelines.contains(binding))
            .collect();
        self.count_erasure_bindings(&fresh, rows.iter());
        self.artifact_registration_timelines.extend(fresh);
        for row in rows {
            let address = row.registration_address();
            self.artifact_registration_identities
                .entry((*row.owner_id(), row.artifact_class(), row.artifact_digest()))
                .or_insert(address);
            self.artifact_registrations.entry(address).or_insert(row);
        }
    }

    /// `targets(A)` of `actor` (R13.1(1)) from the counters, for the
    /// cross-crate parity test against the erasure closure.
    #[must_use]
    pub fn erasure_targets_for_test(&self, actor: EntityId) -> u64 {
        let affected = self.affected(actor, &self.fork_children());
        self.actor_targets(actor, &affected)
    }

    /// `(rows(U), the targets of U's private rows)` from the counters.
    #[must_use]
    pub fn erasure_counts_for_test(&self, timeline: TimelineId) -> (u64, u64) {
        let count = self.erasure_counters.count(timeline);
        (count.rows, count.private_targets)
    }
}

/// The test oracle of the counters: a full recount of the ADR-136 closure
/// over the store data, rebuilt as `freeze.rs` builds its target table.
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod oracle {
    use std::collections::{BTreeMap, BTreeSet};

    use pos_core::{
        ArtifactDataClassV1, EntityId, ErasureArtifactClassV1, Hash, KeyIdentityV1,
        KeyRegistryStateV1, KeyRoleV1, OwnerIdV1, TimelineId,
    };

    use super::MemoryStore;

    /// One closure target, by the components `freeze.rs` keys it with.
    #[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
    enum Target {
        Store,
        Payload(TimelineId),
        SubjectKey(KeyIdentityV1),
        Artifact(ErasureArtifactClassV1, Hash),
        ArtifactKey(ErasureArtifactClassV1, Hash, KeyIdentityV1),
    }

    impl MemoryStore {
        /// `affected(A)` by a fixpoint over every Timeline, not the
        /// production walk.
        fn recounted_affected(&self, actor: EntityId) -> BTreeSet<TimelineId> {
            let mut affected = BTreeSet::new();
            loop {
                let before = affected.len();
                for state in self.timelines.values() {
                    let meta = &state.timeline.meta;
                    let inherited = meta
                        .fork_point
                        .is_some_and(|(parent, _)| affected.contains(&parent));
                    if meta.owner == Some(actor) || inherited {
                        affected.insert(meta.id);
                    }
                }
                if affected.len() == before {
                    return affected;
                }
            }
        }

        /// The closure of a private-subject-data request of `actor`, as a
        /// target set, and the view-list length of every affected Timeline.
        pub(crate) fn erasure_recount_for_test(
            &self,
            actor: EntityId,
        ) -> (u64, BTreeMap<TimelineId, u64>) {
            let affected = self.recounted_affected(actor);
            let mut targets = BTreeSet::from([Target::Store]);
            targets.extend(affected.iter().copied().map(Target::Payload));
            let subject = pos_crypto::subject_key::subject_owner_id(actor)
                .ok()
                .and_then(|owner| OwnerIdV1::new(owner).ok());
            targets.extend(
                self.key_registry
                    .iter()
                    .flat_map(KeyRegistryStateV1::key_records)
                    .map(|record| record.identity)
                    .filter(|identity| {
                        Some(identity.owner_id) == subject
                            && identity.role == KeyRoleV1::SubjectDataEncryption
                    })
                    .map(Target::SubjectKey),
            );
            let mut rows = affected
                .iter()
                .map(|timeline| (*timeline, 0))
                .collect::<BTreeMap<_, _>>();
            for (timeline, address) in &self.artifact_registration_timelines {
                if let Some(count) = rows.get_mut(timeline) {
                    *count += 1;
                    let row = &self.artifact_registrations[address];
                    let fields = row.registration().fields();
                    if fields.data_class == ArtifactDataClassV1::PrivateSubjectData {
                        let class = row.artifact_class();
                        let digest = row.artifact_digest();
                        targets.insert(Target::Artifact(class, digest));
                        targets.extend(
                            fields
                                .key_dependencies
                                .iter()
                                .filter(|dependency| {
                                    dependency.identity.role
                                        == KeyRoleV1::CommunityArtifactEncryption
                                })
                                .map(|dependency| {
                                    Target::ArtifactKey(class, digest, dependency.identity)
                                }),
                        );
                    }
                }
            }
            (targets.len() as u64, rows)
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
