//! The registry state a Timeline derives from its own Events (ADR-119 sections 4.3 and 4.6).
//!
//! A Fork has no row until its first operation, and its row is never copied from the parent:
//! the adapters initialise it from the fold of the Fork's inherited Events. A reader that needs
//! the Fork's state before that first operation, such as the composition boundary deriving the
//! effective composition at the Fork cut, folds the same Events here through the public port.

use pos_core::store::{EventStore, SeqRange};
use pos_core::{Event, Hash, Seq, TimelineId};

use super::error::CompositionFallbackRegistryErrorV1 as Error;
use super::logic::{fold_timeline, FallbackReadsV1, FallbackResult};
use super::port::CompositionFallbackRegistryV1;
use super::types::{FallbackLedgerRowV1, FallbackRegistryRowV1, FallbackRegistryStateV1};

/// The public reads of one store, as the fold takes them.
struct PortReadsV1<'s, S: ?Sized> {
    store: &'s S,
}

impl<S> FallbackReadsV1 for PortReadsV1<'_, S>
where
    S: EventStore + CompositionFallbackRegistryV1 + ?Sized,
{
    fn stored_row(
        &self,
        scope: &str,
        timeline: TimelineId,
    ) -> FallbackResult<Option<FallbackRegistryRowV1>> {
        self.store.registry_row(scope, timeline)
    }

    fn stored_policy(&self, policy_digest: Hash) -> FallbackResult<Option<Vec<u8>>> {
        self.store.retained_policy(policy_digest)
    }

    fn stored_ledger(
        &self,
        scope: &str,
        timeline: TimelineId,
    ) -> FallbackResult<Vec<FallbackLedgerRowV1>> {
        self.store.fallback_ledger(scope, timeline)
    }

    fn timeline_events(&self, timeline: TimelineId) -> FallbackResult<Vec<Event>> {
        let events = self.store.read(timeline, SeqRange::all());
        events.or(Err(Error::TimelineUnavailable))
    }

    fn timeline_head(&self, timeline: TimelineId) -> FallbackResult<Seq> {
        let head = self.store.logical_head(timeline);
        head.or(Err(Error::TimelineUnavailable))
    }
}

/// Fold the declaration and activation Events of `scope` on `timeline`, inherited ones included.
///
/// This is the state the Timeline's row holds, or is initialised to at its first operation.
/// On a Timeline with a row it equals the row's state, which every write checks. On a Fork
/// before its first operation it is the state inherited at the Fork cut. Before the first
/// declaration it is the empty state, with no policy.
///
/// # Errors
/// `TimelineUnavailable` when the Timeline cannot be read, `MissingState` before
/// provisioning, a storage error, or `CorruptState` for an Event that does not decode or does
/// not follow from the state before it.
pub fn derived_fallback_state_v1<S>(
    store: &S,
    scope: &str,
    timeline: TimelineId,
) -> Result<FallbackRegistryStateV1, Error>
where
    S: EventStore + CompositionFallbackRegistryV1 + ?Sized,
{
    let reads = PortReadsV1 { store };
    fold_timeline(&reads, scope, timeline).map(|fold| fold.state)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::sync::Arc;

    use pos_core::store::EventStore;
    use pos_core::{ErasureContainmentGateV1, Seq, TimelineId};

    use super::{derived_fallback_state_v1, PortReadsV1};
    use crate::composition_fallback_registry::logic::FallbackReadsV1;
    use crate::composition_fallback_registry::{
        CompositionFallbackRegistryErrorV1 as Error, CompositionFallbackRegistryV1,
    };
    use crate::memory::MemoryStore;

    /// A provisioned store with an open erasure gate and one empty Timeline.
    fn provisioned() -> Result<(MemoryStore, TimelineId), Error> {
        let mut store = MemoryStore::new();
        let gate = Arc::new(ErasureContainmentGateV1::new_test_open());
        store
            .bind_erasure_gate(gate)
            .or(Err(Error::StorageFailed))?;
        let timeline = store.create_timeline("derived");
        let timeline = timeline.or(Err(Error::StorageFailed))?.id();
        store.provision_fallback_registry()?;
        Ok((store, timeline))
    }

    /// The port reads pass through to the store: an empty Timeline has no row, no ledger, no
    /// Event and head 0, and an unknown Timeline is unavailable.
    #[test]
    fn the_port_reads_pass_through() -> Result<(), Error> {
        let (store, timeline) = provisioned()?;
        let reads = PortReadsV1 { store: &store };
        assert_eq!(reads.stored_row("scope", timeline)?, None);
        assert_eq!(reads.stored_ledger("scope", timeline)?, Vec::new());
        assert_eq!(reads.stored_policy(pos_core::Hash::zero())?, None);
        assert_eq!(reads.timeline_events(timeline)?, Vec::new());
        assert_eq!(reads.timeline_head(timeline)?, Seq::ZERO);
        let unknown = TimelineId::new();
        let unavailable = Some(Error::TimelineUnavailable);
        assert_eq!(reads.timeline_events(unknown).err(), unavailable);
        assert_eq!(reads.timeline_head(unknown).err(), unavailable);
        Ok(())
    }

    /// Before the first declaration the derived state is empty.
    #[test]
    fn an_undeclared_timeline_derives_the_empty_state() -> Result<(), Error> {
        let (store, timeline) = provisioned()?;
        let state = derived_fallback_state_v1(&store, "scope", timeline)?;
        assert_eq!(state.policy_digest(), None);
        assert_eq!(state.state_revision(), 0);
        Ok(())
    }
}
