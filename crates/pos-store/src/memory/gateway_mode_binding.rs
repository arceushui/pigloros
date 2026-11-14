//! `MemoryStore` adapter for the persistent Gateway execution-mode binding
//! (ADR-134 §8).
//!
//! The binding is process-local: binding, attachment and the append
//! choke-point compare all apply to this one adapter instance. Commit-epoch
//! evidence lives in each Timeline's state, so a staged Timeline copy carries
//! its evidence and a discarded copy discards it with its Events.

use std::num::NonZeroU64;

use pos_core::{
    commit_epoch_for_append_v1, error::CoreError, AuthorityPersistenceStateV1,
    GatewayModeBindPermitV1, GatewayModeBindingErrorV1, GatewayModeBindingHistoryEntryV1,
    GatewayModeBindingKindV1, GatewayModeBindingPortV1, GatewayModeBindingRecordV1,
    GatewayModeMigrationPermitV1, GatewayModeProfileRefV1, GatewayModeRotationPermitV1,
    OwnTracksEnrollmentStateV1, Seq, TimelineId,
};

use super::{MemoryStore, TimelineState};

/// The current binding (the last history entry) and this instance's
/// attached epoch.
#[derive(Debug, Default)]
pub(super) struct MemoryGatewayModeStateV1 {
    history: Vec<GatewayModeBindingHistoryEntryV1>,
    attached: Option<NonZeroU64>,
}

/// The persisted and attached epochs one append compares.
#[derive(Clone, Copy, Debug)]
pub(super) struct MemoryModeAppendV1 {
    persisted: Option<NonZeroU64>,
    attached: Option<NonZeroU64>,
}

impl MemoryModeAppendV1 {
    /// The append choke point's compare: the epoch to record for an Event
    /// range, or [`CoreError::ModeBindingStale`] before any mutation.
    pub(super) fn commit_epoch(self) -> Result<Option<NonZeroU64>, CoreError> {
        commit_epoch_for_append_v1(self.persisted, self.attached)
    }
}

/// One committed Event range of a Timeline segment and its epoch.
#[derive(Clone, Copy, Debug)]
pub(super) struct CommitEpochRangeV1 {
    first_local_seq: u64,
    last_local_seq: u64,
    epoch: NonZeroU64,
}

/// Record the commit-epoch evidence of segment-local `first..=last` in the
/// Timeline state that receives those Events; an unbound store records none.
pub(super) fn record_commit_epoch_in_state(
    state: &mut TimelineState,
    epoch: Option<NonZeroU64>,
    first: Seq,
    last: Seq,
) {
    state
        .commit_epochs
        .extend(epoch.map(|epoch| CommitEpochRangeV1 {
            first_local_seq: first.as_u64(),
            last_local_seq: last.as_u64(),
            epoch,
        }));
}

/// The epoch recorded for the commit that wrote segment-local `local_seq`.
pub(super) fn commit_epoch_in_state(state: &TimelineState, local_seq: u64) -> Option<NonZeroU64> {
    state
        .commit_epochs
        .iter()
        .find(|range| (range.first_local_seq..=range.last_local_seq).contains(&local_seq))
        .map(|range| range.epoch)
}

impl MemoryGatewayModeStateV1 {
    fn current(&self) -> Option<&GatewayModeBindingRecordV1> {
        self.history
            .last()
            .map(GatewayModeBindingHistoryEntryV1::record)
    }

    /// The epochs the next append compares.
    pub(super) fn append_mode(&self) -> MemoryModeAppendV1 {
        MemoryModeAppendV1 {
            persisted: self
                .current()
                .map(GatewayModeBindingRecordV1::binding_epoch),
            attached: self.attached,
        }
    }

    fn record(
        &mut self,
        profile: GatewayModeProfileRefV1,
        epoch: NonZeroU64,
        kind: GatewayModeBindingKindV1,
    ) -> GatewayModeBindingRecordV1 {
        let record = GatewayModeBindingRecordV1::new(profile, epoch);
        self.history
            .push(GatewayModeBindingHistoryEntryV1::new(record.clone(), kind));
        self.attached = Some(epoch);
        record
    }

    fn change(
        &mut self,
        from: &GatewayModeProfileRefV1,
        to: &GatewayModeProfileRefV1,
        kind: GatewayModeBindingKindV1,
    ) -> Result<GatewayModeBindingRecordV1, GatewayModeBindingErrorV1> {
        match self
            .current()
            .map(|current| (current.profile() == from, current.binding_epoch()))
        {
            Some((true, epoch)) => Ok(self.record(to.clone(), epoch.saturating_add(1), kind)),
            Some((false, _)) => Err(GatewayModeBindingErrorV1::Mismatch),
            None => Err(GatewayModeBindingErrorV1::Unbound),
        }
    }

    /// Simulate another process changing the binding: replace this
    /// instance's attached epoch.
    #[cfg(test)]
    pub(super) const fn attach_epoch_for_test(&mut self, epoch: Option<NonZeroU64>) {
        self.attached = epoch;
    }
}

impl MemoryStore {
    /// Whether this store holds any record that makes it populated: a
    /// Timeline, authority or denial evidence, an `OwnTracks` enrollment, or
    /// Fork-admission authority, admissions or Principal-owner bindings.
    fn is_empty_for_mode_binding(&self) -> bool {
        [
            self.timelines.is_empty(),
            self.authority_state == AuthorityPersistenceStateV1::default(),
            self.authorization_denials.is_empty(),
            self.owntracks_enrollment == OwnTracksEnrollmentStateV1::absent(),
            self.fork_admission_authority.host.is_none(),
            self.fork_admissions.is_empty(),
            self.fork_principal_owner_bindings.is_empty(),
        ]
        .into_iter()
        .all(std::convert::identity)
    }
}

impl GatewayModeBindingPortV1 for MemoryStore {
    fn bind_empty_store_mode(
        &mut self,
        permit: GatewayModeBindPermitV1,
    ) -> Result<GatewayModeBindingRecordV1, GatewayModeBindingErrorV1> {
        match (
            self.mode_binding.current().is_some(),
            self.is_empty_for_mode_binding(),
        ) {
            (true, _) => Err(GatewayModeBindingErrorV1::AlreadyBound),
            (false, false) => Err(GatewayModeBindingErrorV1::PopulatedUnbound),
            (false, true) => Ok(self.mode_binding.record(
                permit.to().clone(),
                NonZeroU64::MIN,
                GatewayModeBindingKindV1::Bind,
            )),
        }
    }

    fn attach_mode_binding(
        &mut self,
        expected: &GatewayModeProfileRefV1,
    ) -> Result<GatewayModeBindingRecordV1, GatewayModeBindingErrorV1> {
        let current = crate::expected_mode_binding(self.mode_binding.current().cloned(), expected);
        current.inspect(|record| self.mode_binding.attached = Some(record.binding_epoch()))
    }

    fn rotate_mode(
        &mut self,
        permit: GatewayModeRotationPermitV1,
    ) -> Result<GatewayModeBindingRecordV1, GatewayModeBindingErrorV1> {
        self.mode_binding
            .change(permit.from(), permit.to(), GatewayModeBindingKindV1::Rotate)
    }

    fn migrate_mode(
        &mut self,
        permit: GatewayModeMigrationPermitV1,
    ) -> Result<GatewayModeBindingRecordV1, GatewayModeBindingErrorV1> {
        self.mode_binding.change(
            permit.from(),
            permit.to(),
            GatewayModeBindingKindV1::Migrate,
        )
    }

    fn load_mode_binding(
        &self,
    ) -> Result<Option<GatewayModeBindingRecordV1>, GatewayModeBindingErrorV1> {
        Ok(self.mode_binding.current().cloned())
    }

    fn load_mode_binding_history(
        &self,
    ) -> Result<Vec<GatewayModeBindingHistoryEntryV1>, GatewayModeBindingErrorV1> {
        Ok(self.mode_binding.history.clone())
    }

    fn load_commit_epoch(
        &self,
        timeline: TimelineId,
        local_seq: Seq,
    ) -> Result<Option<NonZeroU64>, GatewayModeBindingErrorV1> {
        Ok(self
            .timelines
            .get(&timeline)
            .and_then(|state| commit_epoch_in_state(state, local_seq.as_u64())))
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::sync::Arc;

    use pos_core::{
        CanonicalBytes, EntityId, ErasureContainmentGateV1, Event, EventDraft, EventStore,
        GatewayModeBindingHostV1, Kind, SeqRange,
    };

    use super::*;

    fn ok<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
        result.unwrap_or_else(|error| {
            std::panic::resume_unwind(Box::new(format!("unexpected test error: {error:?}")))
        })
    }

    fn store() -> MemoryStore {
        let mut store = MemoryStore::new();
        ok(store.bind_erasure_gate(Arc::new(ErasureContainmentGateV1::new_test_open())));
        store
    }

    fn draft() -> EventDraft {
        EventDraft::new(
            EntityId::new(),
            Kind::new("gateway.mode.test"),
            CanonicalBytes::from_vec(vec![1]),
        )
    }

    /// Two committed Events of another store, ready for `append_committed`.
    fn committed_events() -> Vec<Event> {
        let mut source = store();
        let timeline = ok(source.create_timeline("source")).id();
        ok(source.append(timeline, &[draft(), draft()]));
        // The importing Timeline assigns its own origins.
        ok(source.read(timeline, SeqRange::all()))
            .into_iter()
            .map(|event| Event {
                origin: None,
                ..event
            })
            .collect()
    }

    fn event_count(store: &MemoryStore, timeline: TimelineId) -> usize {
        ok(store.read(timeline, SeqRange::all())).len()
    }

    #[test]
    fn a_writer_attached_to_another_epoch_commits_nothing() {
        let mut store = store();
        let profile = ok(GatewayModeProfileRefV1::try_new(
            "gateway-mode-local-v1",
            [1; 32],
        ));
        ok(store.bind_empty_store_mode(
            GatewayModeBindingHostV1::new().authorize_bind(profile.clone()),
        ));
        let timeline = ok(store.create_timeline("bound")).id();
        let events = committed_events();
        for attached in [None, NonZeroU64::new(2)] {
            store.mode_binding.attach_epoch_for_test(attached);
            assert!(matches!(
                store.append(timeline, &[draft()]),
                Err(CoreError::ModeBindingStale)
            ));
            assert!(matches!(
                store.append_committed(timeline, &events),
                Err(CoreError::ModeBindingStale)
            ));
            assert!(matches!(
                store.append_committed(timeline, &[]),
                Err(CoreError::ModeBindingStale)
            ));
            assert_eq!(event_count(&store, timeline), 0);
            assert_eq!(
                ok(store.load_commit_epoch(timeline, Seq::from_u64(1))),
                None
            );
        }
        ok(store.attach_mode_binding(&profile));
        ok(store.append_committed(timeline, &[]));
        ok(store.append_committed(timeline, &events));
        ok(store.append(timeline, &[draft()]));
        for seq in 1..=3 {
            assert_eq!(
                ok(store.load_commit_epoch(timeline, Seq::from_u64(seq))),
                NonZeroU64::new(1)
            );
        }
        assert_eq!(
            ok(store.load_commit_epoch(timeline, Seq::from_u64(4))),
            None
        );
    }

    #[test]
    fn an_attached_writer_on_an_unbound_store_commits_nothing() {
        let mut store = store();
        let timeline = ok(store.create_timeline("unbound")).id();
        store.mode_binding.attach_epoch_for_test(NonZeroU64::new(1));
        assert!(matches!(
            store.append(timeline, &[draft()]),
            Err(CoreError::ModeBindingStale)
        ));
        assert_eq!(event_count(&store, timeline), 0);
    }
}
