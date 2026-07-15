//! Fork-comparison: diff two timelines that share a common ancestor.

use std::collections::HashSet;

use pos_core::{CoreError, EntityId, Event, Seq, TimelineId};
use pos_core::store::{EventStore, SeqRange};
use pos_state::ProjectionRegistry;

/// The result of comparing two diverged timelines.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ForkDiff {
    /// Seq of the common ancestor (the fork point).
    pub fork_seq: Seq,
    /// Events in timeline A after the fork point (not in B).
    pub only_in_a: Vec<Event>,
    /// Events in timeline B after the fork point (not in A).
    pub only_in_b: Vec<Event>,
    /// `EntityId`s whose state differs between A and B at their respective heads.
    pub diverged_entities: Vec<EntityId>,
}

/// Compare two timelines that share a common ancestor at `fork_seq`.
///
/// `fork_seq` is the last sequence number the two timelines share.
/// Events from `fork_seq + 1` onwards are read from each timeline and compared.
///
/// `registry_a` and `registry_b` are separate [`ProjectionRegistry`] instances —
/// one per fork arm — so that each arm's reducers accumulate state in isolation
/// and plugins on different forks never clobber each other's keys.
///
/// Steps:
/// 1. Read post-fork events from `a` and `b`.
/// 2. Collect `only_in_a` and `only_in_b`.
/// 3. Fold post-fork events through `registry_a` and `registry_b` respectively.
/// 4. Collect entity IDs that appear in either side and compare final state.
///
/// # Errors
/// Propagates [`CoreError`] from the underlying store.
pub fn compare(
    store: &dyn EventStore,
    a: TimelineId,
    b: TimelineId,
    fork_seq: Seq,
    registry_a: &mut ProjectionRegistry,
    registry_b: &mut ProjectionRegistry,
) -> Result<ForkDiff, CoreError> {
    let post_fork_range = SeqRange::from_seq(fork_seq.next());

    let events_a = store.read(a, post_fork_range)?;
    let events_b = store.read(b, post_fork_range)?;

    // Build state for A post-fork.
    registry_a.fold_events(&events_a);

    // Build state for B post-fork.
    registry_b.fold_events(&events_b);

    // Collect all entity IDs seen in either side.
    let all_entities: HashSet<EntityId> = events_a
        .iter()
        .chain(events_b.iter())
        .map(|e| e.entity)
        .collect();

    let snap_a = registry_a.state_snapshot();
    let snap_b = registry_b.state_snapshot();

    // Entities whose state differs across any registered reducer.
    let diverged_entities: Vec<EntityId> = all_entities
        .into_iter()
        .filter(|eid| {
            // Check all reducer names present in either snapshot.
            let names: HashSet<&String> = snap_a.keys().chain(snap_b.keys()).collect();
            names.iter().any(|name| {
                let reg_a = snap_a.get(*name).cloned().unwrap_or_default();
                let reg_b = snap_b.get(*name).cloned().unwrap_or_default();
                reg_a.get_or_default(eid) != reg_b.get_or_default(eid)
            })
        })
        .collect();

    Ok(ForkDiff {
        fork_seq,
        only_in_a: events_a,
        only_in_b: events_b,
        diverged_entities,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use pos_core::{
        event::{CanonicalBytes, EventDraft, Kind},
        ids::EntityId,
        Event, Reducer, State,
    };
    use pos_state::ProjectionRegistry;
    use pos_store::{open_store, StoreConfig};

    // ── helpers ──────────────────────────────────────────────────────────────

    struct CountReducer;

    impl Reducer for CountReducer {
        fn initial(&self) -> State {
            let mut s = State::new();
            s.set("n", serde_json::json!(0u64));
            s
        }

        fn apply(&self, state: &mut State, _event: &Event) {
            let n = state.get("n").and_then(serde_json::Value::as_u64).unwrap_or(0);
            state.set("n", serde_json::json!(n + 1));
        }
    }

    fn make_registry() -> ProjectionRegistry {
        let mut reg = ProjectionRegistry::new();
        reg.register("count", Box::new(CountReducer));
        reg
    }

    fn draft(entity: EntityId) -> EventDraft {
        EventDraft::new(entity, Kind::new("test.tick"), CanonicalBytes::from_vec(vec![]))
    }

    // ── tests ─────────────────────────────────────────────────────────────────

    #[test]
    fn compare_identical_timelines_no_diff() {
        // Fork a timeline, append nothing to either fork. Diff should be empty.
        let mut store = open_store(StoreConfig::Memory).unwrap();
        let parent = store.create_timeline("parent").unwrap();
        let entity = EntityId::new();

        // Append some shared events to the parent.
        let drafts: Vec<EventDraft> = (0..3).map(|_| draft(entity)).collect();
        let committed = store.append(parent.id(), &drafts).unwrap();
        let fork_seq = committed.last().unwrap().seq;

        // Fork twice at the same point.
        let fork_a = store.fork(parent.id(), fork_seq, "a").unwrap();
        let fork_b = store.fork(parent.id(), fork_seq, "b").unwrap();

        // No additional events on either fork.
        let diff = compare(
            store.as_ref(),
            fork_a.id(),
            fork_b.id(),
            fork_seq,
            &mut make_registry(),
            &mut make_registry(),
        )
        .unwrap();

        assert!(diff.only_in_a.is_empty());
        assert!(diff.only_in_b.is_empty());
        assert!(diff.diverged_entities.is_empty());
        assert_eq!(diff.fork_seq, fork_seq);
    }

    #[test]
    fn compare_diverged_timelines_detects_differences() {
        let mut store = open_store(StoreConfig::Memory).unwrap();
        let parent = store.create_timeline("parent").unwrap();
        let shared_entity = EntityId::new();

        // Append 2 shared events.
        let shared_drafts: Vec<EventDraft> = (0..2).map(|_| draft(shared_entity)).collect();
        let committed = store.append(parent.id(), &shared_drafts).unwrap();
        let fork_seq = committed.last().unwrap().seq;

        // Fork into A and B.
        let fork_a = store.fork(parent.id(), fork_seq, "branch-a").unwrap();
        let fork_b = store.fork(parent.id(), fork_seq, "branch-b").unwrap();

        // Append different counts to each fork for the same entity.
        let drafts_a: Vec<EventDraft> = (0..2).map(|_| draft(shared_entity)).collect();
        let drafts_b: Vec<EventDraft> = (0..3).map(|_| draft(shared_entity)).collect();

        store.append(fork_a.id(), &drafts_a).unwrap();
        store.append(fork_b.id(), &drafts_b).unwrap();

        let diff = compare(
            store.as_ref(),
            fork_a.id(),
            fork_b.id(),
            fork_seq,
            &mut make_registry(),
            &mut make_registry(),
        )
        .unwrap();

        // Each side should have its own post-fork events.
        assert_eq!(diff.only_in_a.len(), 2);
        assert_eq!(diff.only_in_b.len(), 3);

        // shared_entity has different counts on A (2) vs B (3) -> diverged.
        assert!(diff.diverged_entities.contains(&shared_entity));
    }

    #[test]
    fn compare_isolated_registries_no_clobber() {
        // Two registries must not share state even when both see events for the
        // same entity. This exercises the isolation guarantee that motivated the
        // fix from a single shared reducers slice.
        let mut store = open_store(StoreConfig::Memory).unwrap();
        let parent = store.create_timeline("parent").unwrap();
        let entity = EntityId::new();

        let shared: Vec<EventDraft> = (0..2).map(|_| draft(entity)).collect();
        let committed = store.append(parent.id(), &shared).unwrap();
        let fork_seq = committed.last().unwrap().seq;

        let fork_a = store.fork(parent.id(), fork_seq, "iso-a").unwrap();
        let fork_b = store.fork(parent.id(), fork_seq, "iso-b").unwrap();

        // Only A gets new events; B stays at the fork point.
        let new_a: Vec<EventDraft> = (0..3).map(|_| draft(entity)).collect();
        store.append(fork_a.id(), &new_a).unwrap();

        let mut reg_a = make_registry();
        let mut reg_b = make_registry();

        let diff = compare(
            store.as_ref(),
            fork_a.id(),
            fork_b.id(),
            fork_seq,
            &mut reg_a,
            &mut reg_b,
        )
        .unwrap();

        // B has no post-fork events.
        assert_eq!(diff.only_in_b.len(), 0);
        // A saw 3 events, B saw 0 → the entity state must diverge.
        assert!(diff.diverged_entities.contains(&entity));

        // Verify registry isolation: reg_a accumulated 3 events, reg_b accumulated 0.
        let count_a = reg_a
            .state_snapshot()
            .get("count")
            .and_then(|r| r.get(&entity))
            .and_then(|s| s.get("n"))
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        let count_b = reg_b
            .state_snapshot()
            .get("count")
            .and_then(|r| r.get(&entity))
            .and_then(|s| s.get("n"))
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);

        assert_eq!(count_a, 3, "reg_a should have folded 3 post-fork events");
        assert_eq!(count_b, 0, "reg_b should have seen no post-fork events");
    }
}
