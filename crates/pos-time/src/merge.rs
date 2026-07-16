//! Conflict-free (and strategy-guided) merge for divergent timelines.

use std::collections::HashSet;

use pos_core::{
    store::{EventStore, SeqRange},
    CoreError, EntityId, Event, Seq, Timeline, TimelineId,
};

/// Specification for how to merge two divergent timelines.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct MergeSpec {
    /// The common base timeline (the original before forking).
    pub base: TimelineId,
    /// First divergent fork.
    pub fork_a: TimelineId,
    /// Second divergent fork.
    pub fork_b: TimelineId,
    /// The seq at which the two forks diverged from the base.
    pub fork_seq: Seq,
    /// How conflicts should be resolved.
    pub strategy: MergeStrategy,
}

/// Strategy for resolving conflicts when merging divergent timelines.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum MergeStrategy {
    /// Accept both sides only when entity sets are disjoint; error otherwise.
    DisjointCrdt,
    /// On overlapping entities, keep fork A's post-fork events and drop B's.
    PreferA,
    /// On overlapping entities, keep fork B's post-fork events and drop A's.
    PreferB,
}

impl MergeStrategy {
    /// Parse a CLI/strategy name (`disjoint`, `prefer-a`, `prefer-b`).
    ///
    /// # Errors
    /// Returns an error string if the name is not recognized.
    pub fn parse(name: &str) -> Result<Self, String> {
        match name.to_ascii_lowercase().as_str() {
            "disjoint" | "disjoint-crdt" | "disjoint_crdt" => Ok(Self::DisjointCrdt),
            "prefer-a" | "prefer_a" | "a" => Ok(Self::PreferA),
            "prefer-b" | "prefer_b" | "b" => Ok(Self::PreferB),
            other => Err(format!(
                "unknown merge strategy '{other}' (expected disjoint|prefer-a|prefer-b)"
            )),
        }
    }
}

/// A conflict that could not be auto-resolved.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct MergeConflict {
    /// The entity whose state conflicts.
    pub entity: EntityId,
    /// Events from fork A that touch this entity after the fork point.
    pub in_a: Vec<Event>,
    /// Events from fork B that touch this entity after the fork point.
    pub in_b: Vec<Event>,
}

/// Structured merge outcome (ADR-008 contract type).
///
/// The live [`merge`] / [`merge_with_strategy`] APIs currently return
/// `Result<Timeline, CoreError>` and map disjoint conflicts to
/// [`CoreError::Storage`]. This enum remains for callers/tests that want an
/// explicit clean-vs-conflicts shape without going through the store.
#[derive(Clone, Debug)]
pub enum MergeResult {
    /// Clean merge — all events from both sides applied.
    Clean(Vec<Event>),
    /// Partial merge with unresolved conflicts.
    Conflicts(Vec<MergeConflict>),
}

/// Merge two divergent timelines using [`MergeStrategy::DisjointCrdt`].
///
/// Convenience wrapper around [`merge_with_strategy`].
///
/// # Errors
/// Returns [`CoreError::Storage`] if there are overlapping entities or store I/O fails.
/// Returns [`CoreError::TimelineNotFound`] if either timeline does not exist.
pub fn merge(
    store: &mut dyn EventStore,
    timeline_a: TimelineId,
    timeline_b: TimelineId,
    fork_seq: Seq,
    target_name: &str,
) -> Result<Timeline, CoreError> {
    merge_with_strategy(
        store,
        timeline_a,
        timeline_b,
        fork_seq,
        target_name,
        MergeStrategy::DisjointCrdt,
    )
}

/// Merge two divergent timelines according to `strategy`.
///
/// # Algorithm
/// 1. Read events from each timeline with seq > `fork_seq`
/// 2. Apply strategy:
///    - [`MergeStrategy::DisjointCrdt`]: error if any entity appears in both arms
///    - [`MergeStrategy::PreferA`]: drop B events for overlapping entities
///    - [`MergeStrategy::PreferB`]: drop A events for overlapping entities
/// 3. Fork the parent at `fork_seq`, append surviving events sorted by `wall_time`
///
/// # Errors
/// Returns [`CoreError::Storage`] on conflict ([`MergeStrategy::DisjointCrdt`]) or store I/O failure.
/// Returns [`CoreError::TimelineNotFound`] if either timeline does not exist.
pub fn merge_with_strategy(
    store: &mut dyn EventStore,
    timeline_a: TimelineId,
    timeline_b: TimelineId,
    fork_seq: Seq,
    target_name: &str,
    strategy: MergeStrategy,
) -> Result<Timeline, CoreError> {
    let next_seq = Seq::from_u64(fork_seq.as_u64() + 1);
    let events_a = store.read(timeline_a, SeqRange::from_seq(next_seq))?;
    let events_b = store.read(timeline_b, SeqRange::from_seq(next_seq))?;

    let entities_a: HashSet<EntityId> = events_a.iter().map(|e| e.entity).collect();
    let entities_b: HashSet<EntityId> = events_b.iter().map(|e| e.entity).collect();
    let overlap: HashSet<EntityId> = entities_a.intersection(&entities_b).copied().collect();

    let mut merged = match strategy {
        MergeStrategy::DisjointCrdt => {
            if let Some(entity) = overlap.iter().next() {
                return Err(CoreError::Storage(format!(
                    "merge conflict: overlapping entity {entity:?}"
                )));
            }
            let mut out = Vec::new();
            out.extend_from_slice(&events_a);
            out.extend_from_slice(&events_b);
            out
        }
        MergeStrategy::PreferA => {
            let mut out = Vec::new();
            out.extend_from_slice(&events_a);
            out.extend(events_b.into_iter().filter(|e| !overlap.contains(&e.entity)));
            out
        }
        MergeStrategy::PreferB => {
            let mut out = Vec::new();
            out.extend(events_a.into_iter().filter(|e| !overlap.contains(&e.entity)));
            out.extend_from_slice(&events_b);
            out
        }
    };

    merged.sort_by_key(|e| e.wall_time);

    let base_timeline = store
        .get_timeline(timeline_a)?
        .ok_or(CoreError::TimelineNotFound(timeline_a))?;
    let parent_id = if let Some((parent, _)) = base_timeline.meta.fork_point {
        parent
    } else {
        timeline_a
    };

    let result_timeline = store.fork(parent_id, fork_seq, target_name)?;

    if !merged.is_empty() {
        let drafts: Vec<pos_core::EventDraft> = merged
            .into_iter()
            .map(|e| {
                let mut draft = pos_core::EventDraft::new(e.entity, e.event_type, e.payload);
                draft.causation_id = e.causation_id;
                draft.correlation_id = e.correlation_id;
                draft.schema_version = e.schema_version;
                draft.wall_time = Some(e.wall_time);
                draft
            })
            .collect();
        store.append(result_timeline.id(), &drafts)?;
    }

    store
        .get_timeline(result_timeline.id())
        .and_then(|opt| opt.ok_or(CoreError::TimelineNotFound(result_timeline.id())))
}

/// Check if two divergent timelines can be merged without conflicts.
///
/// Returns `Ok(true)` if no entity appears in both post-fork arms,
/// `Ok(false)` if there are overlapping entities.
///
/// # Errors
/// Returns [`CoreError`] if either timeline does not exist or store I/O fails.
pub fn can_merge_conflict_free(
    store: &dyn EventStore,
    timeline_a: TimelineId,
    timeline_b: TimelineId,
    fork_seq: Seq,
) -> Result<bool, CoreError> {
    let next_seq = Seq::from_u64(fork_seq.as_u64() + 1);
    let events_a = store.read(timeline_a, SeqRange::from_seq(next_seq))?;
    let events_b = store.read(timeline_b, SeqRange::from_seq(next_seq))?;

    let entities_a: HashSet<EntityId> = events_a.iter().map(|e| e.entity).collect();
    let entities_b: HashSet<EntityId> = events_b.iter().map(|e| e.entity).collect();

    Ok(entities_a.is_disjoint(&entities_b))
}

#[cfg(test)]
mod tests {
    use super::*;
    use pos_core::{
        clock::WallTime,
        event::{CanonicalBytes, Kind},
        EventDraft,
    };
    use pos_store::memory::MemoryStore;

    fn setup_store() -> MemoryStore {
        MemoryStore::new()
    }

    fn make_draft(entity: EntityId, event_type: &str, payload: &[u8]) -> EventDraft {
        EventDraft::new(
            entity,
            Kind::new(event_type),
            CanonicalBytes::from_vec(payload.to_vec()),
        )
    }

    #[test]
    fn merge_spec_serializes_and_deserializes() {
        let spec = MergeSpec {
            base: TimelineId::new(),
            fork_a: TimelineId::new(),
            fork_b: TimelineId::new(),
            fork_seq: pos_core::clock::Seq::from_u64(42),
            strategy: MergeStrategy::DisjointCrdt,
        };
        let json = serde_json::to_string(&spec).unwrap();
        let back: MergeSpec = serde_json::from_str(&json).unwrap();
        assert_eq!(spec.fork_seq, back.fork_seq);
        assert_eq!(spec.base, back.base);
        assert_eq!(spec.fork_a, back.fork_a);
        assert_eq!(spec.fork_b, back.fork_b);

        for strategy in [
            MergeStrategy::DisjointCrdt,
            MergeStrategy::PreferA,
            MergeStrategy::PreferB,
        ] {
            let j = serde_json::to_string(&strategy).unwrap();
            let _back: MergeStrategy = serde_json::from_str(&j).unwrap();
        }
    }

    #[test]
    fn merge_strategy_parse() {
        assert_eq!(
            MergeStrategy::parse("disjoint").unwrap(),
            MergeStrategy::DisjointCrdt
        );
        assert_eq!(
            MergeStrategy::parse("prefer-a").unwrap(),
            MergeStrategy::PreferA
        );
        assert_eq!(
            MergeStrategy::parse("prefer-b").unwrap(),
            MergeStrategy::PreferB
        );
        assert!(MergeStrategy::parse("nope").is_err());
    }

    #[test]
    fn merge_disjoint_entities_succeeds() {
        let mut store = setup_store();

        let base = store.create_timeline("base").unwrap();
        let entity_base = EntityId::new();
        store
            .append(base.id(), &[make_draft(entity_base, "base.event", b"base")])
            .unwrap();

        let fork_a = store.fork(base.id(), Seq::from_u64(1), "fork_a").unwrap();
        let fork_b = store.fork(base.id(), Seq::from_u64(1), "fork_b").unwrap();

        let entity_a = EntityId::new();
        let entity_b = EntityId::new();

        store
            .append(fork_a.id(), &[make_draft(entity_a, "a.event", b"a1")])
            .unwrap();
        store
            .append(fork_b.id(), &[make_draft(entity_b, "b.event", b"b1")])
            .unwrap();

        let merged = merge(
            &mut store,
            fork_a.id(),
            fork_b.id(),
            Seq::from_u64(1),
            "merged",
        )
        .unwrap();

        let events = store.read(merged.id(), SeqRange::all()).unwrap();
        assert_eq!(events.len(), 3);

        let entities: HashSet<EntityId> = events.iter().map(|e| e.entity).collect();
        assert!(entities.contains(&entity_base));
        assert!(entities.contains(&entity_a));
        assert!(entities.contains(&entity_b));
    }

    #[test]
    fn merged_timeline_contains_events_from_both_arms() {
        let mut store = setup_store();

        let base = store.create_timeline("base").unwrap();
        store
            .append(
                base.id(),
                &[make_draft(EntityId::new(), "base.event", b"base")],
            )
            .unwrap();

        let fork_a = store.fork(base.id(), Seq::from_u64(1), "fork_a").unwrap();
        let fork_b = store.fork(base.id(), Seq::from_u64(1), "fork_b").unwrap();

        let entity_a1 = EntityId::new();
        let entity_a2 = EntityId::new();
        let entity_from_b = EntityId::new();

        store
            .append(
                fork_a.id(),
                &[
                    make_draft(entity_a1, "a.event1", b"a1"),
                    make_draft(entity_a2, "a.event2", b"a2"),
                ],
            )
            .unwrap();
        store
            .append(fork_b.id(), &[make_draft(entity_from_b, "b.event", b"b1")])
            .unwrap();

        let merged = merge(
            &mut store,
            fork_a.id(),
            fork_b.id(),
            Seq::from_u64(1),
            "merged",
        )
        .unwrap();

        let events = store.read(merged.id(), SeqRange::all()).unwrap();
        let post_fork_events: Vec<_> = events.iter().filter(|e| e.seq > Seq::from_u64(1)).collect();

        assert_eq!(post_fork_events.len(), 3);
    }

    #[test]
    fn merge_overlapping_entities_returns_error() {
        let mut store = setup_store();

        let base = store.create_timeline("base").unwrap();
        let shared_entity = EntityId::new();
        store
            .append(
                base.id(),
                &[make_draft(shared_entity, "base.event", b"base")],
            )
            .unwrap();

        let fork_a = store.fork(base.id(), Seq::from_u64(1), "fork_a").unwrap();
        let fork_b = store.fork(base.id(), Seq::from_u64(1), "fork_b").unwrap();

        store
            .append(fork_a.id(), &[make_draft(shared_entity, "a.event", b"a")])
            .unwrap();
        store
            .append(fork_b.id(), &[make_draft(shared_entity, "b.event", b"b")])
            .unwrap();

        let result = merge(
            &mut store,
            fork_a.id(),
            fork_b.id(),
            Seq::from_u64(1),
            "merged",
        );

        let err = result.unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("merge conflict"), "msg={msg}");
        assert!(msg.contains("overlapping entity"), "msg={msg}");
    }

    #[test]
    fn merge_prefer_a_keeps_a_on_overlap() {
        let mut store = setup_store();

        let base = store.create_timeline("base").unwrap();
        let shared = EntityId::new();
        store
            .append(base.id(), &[make_draft(shared, "base.event", b"base")])
            .unwrap();

        let fork_a = store.fork(base.id(), Seq::from_u64(1), "fork_a").unwrap();
        let fork_b = store.fork(base.id(), Seq::from_u64(1), "fork_b").unwrap();

        store
            .append(fork_a.id(), &[make_draft(shared, "a.event", b"a")])
            .unwrap();
        store
            .append(fork_b.id(), &[make_draft(shared, "b.event", b"b")])
            .unwrap();

        let merged = merge_with_strategy(
            &mut store,
            fork_a.id(),
            fork_b.id(),
            Seq::from_u64(1),
            "merged-a",
            MergeStrategy::PreferA,
        )
        .unwrap();

        let events = store.read(merged.id(), SeqRange::all()).unwrap();
        let post: Vec<_> = events.iter().filter(|e| e.seq > Seq::from_u64(1)).collect();
        assert_eq!(post.len(), 1);
        assert_eq!(post[0].event_type.as_str(), "a.event");
    }

    #[test]
    fn merge_prefer_b_keeps_b_on_overlap() {
        let mut store = setup_store();

        let base = store.create_timeline("base").unwrap();
        let shared = EntityId::new();
        store
            .append(base.id(), &[make_draft(shared, "base.event", b"base")])
            .unwrap();

        let fork_a = store.fork(base.id(), Seq::from_u64(1), "fork_a").unwrap();
        let fork_b = store.fork(base.id(), Seq::from_u64(1), "fork_b").unwrap();

        store
            .append(fork_a.id(), &[make_draft(shared, "a.event", b"a")])
            .unwrap();
        store
            .append(fork_b.id(), &[make_draft(shared, "b.event", b"b")])
            .unwrap();

        let merged = merge_with_strategy(
            &mut store,
            fork_a.id(),
            fork_b.id(),
            Seq::from_u64(1),
            "merged-b",
            MergeStrategy::PreferB,
        )
        .unwrap();

        let events = store.read(merged.id(), SeqRange::all()).unwrap();
        let post: Vec<_> = events.iter().filter(|e| e.seq > Seq::from_u64(1)).collect();
        assert_eq!(post.len(), 1);
        assert_eq!(post[0].event_type.as_str(), "b.event");
    }

    #[test]
    fn can_merge_conflict_free_returns_true_for_disjoint() {
        let mut store = setup_store();

        let base = store.create_timeline("base").unwrap();
        store
            .append(
                base.id(),
                &[make_draft(EntityId::new(), "base.event", b"base")],
            )
            .unwrap();

        let fork_a = store.fork(base.id(), Seq::from_u64(1), "fork_a").unwrap();
        let fork_b = store.fork(base.id(), Seq::from_u64(1), "fork_b").unwrap();

        store
            .append(
                fork_a.id(),
                &[make_draft(EntityId::new(), "a.event", b"a")],
            )
            .unwrap();
        store
            .append(
                fork_b.id(),
                &[make_draft(EntityId::new(), "b.event", b"b")],
            )
            .unwrap();

        let can_merge =
            can_merge_conflict_free(&store, fork_a.id(), fork_b.id(), Seq::from_u64(1)).unwrap();
        assert!(can_merge);
    }

    #[test]
    fn can_merge_conflict_free_returns_false_for_overlapping() {
        let mut store = setup_store();

        let base = store.create_timeline("base").unwrap();
        let shared_entity = EntityId::new();
        store
            .append(
                base.id(),
                &[make_draft(shared_entity, "base.event", b"base")],
            )
            .unwrap();

        let fork_a = store.fork(base.id(), Seq::from_u64(1), "fork_a").unwrap();
        let fork_b = store.fork(base.id(), Seq::from_u64(1), "fork_b").unwrap();

        store
            .append(fork_a.id(), &[make_draft(shared_entity, "a.event", b"a")])
            .unwrap();
        store
            .append(fork_b.id(), &[make_draft(shared_entity, "b.event", b"b")])
            .unwrap();

        let can_merge =
            can_merge_conflict_free(&store, fork_a.id(), fork_b.id(), Seq::from_u64(1)).unwrap();
        assert!(!can_merge);
    }

    #[test]
    fn empty_arms_merge_cleanly() {
        let mut store = setup_store();

        let base = store.create_timeline("base").unwrap();
        store
            .append(
                base.id(),
                &[make_draft(EntityId::new(), "base.event", b"base")],
            )
            .unwrap();

        let fork_a = store.fork(base.id(), Seq::from_u64(1), "fork_a").unwrap();
        let fork_b = store.fork(base.id(), Seq::from_u64(1), "fork_b").unwrap();

        let merged = merge(
            &mut store,
            fork_a.id(),
            fork_b.id(),
            Seq::from_u64(1),
            "merged",
        )
        .unwrap();

        let events = store.read(merged.id(), SeqRange::all()).unwrap();
        assert_eq!(events.len(), 1);
    }

    #[test]
    fn merge_sorts_events_by_wall_time() {
        let mut store = setup_store();

        let base = store.create_timeline("base").unwrap();
        let fork_a = store.fork(base.id(), Seq::ZERO, "fork_a").unwrap();
        let fork_b = store.fork(base.id(), Seq::ZERO, "fork_b").unwrap();

        let entity_a = EntityId::new();
        let entity_b = EntityId::new();

        let mut draft_a = make_draft(entity_a, "a.event", b"a");
        draft_a.wall_time = Some(WallTime::from_micros(2000));

        let mut draft_b = make_draft(entity_b, "b.event", b"b");
        draft_b.wall_time = Some(WallTime::from_micros(1000));

        store.append(fork_a.id(), &[draft_a]).unwrap();
        store.append(fork_b.id(), &[draft_b]).unwrap();

        let merged = merge(&mut store, fork_a.id(), fork_b.id(), Seq::ZERO, "merged").unwrap();

        let events = store.read(merged.id(), SeqRange::all()).unwrap();

        assert_eq!(events.len(), 2);
        assert_eq!(events[0].entity, entity_b);
        assert_eq!(events[1].entity, entity_a);
    }

    #[test]
    fn merge_conflict_single_overlap() {
        let mut store = setup_store();

        let base = store.create_timeline("base").unwrap();
        let fork_a = store.fork(base.id(), Seq::ZERO, "fork_a").unwrap();
        let fork_b = store.fork(base.id(), Seq::ZERO, "fork_b").unwrap();

        let shared = EntityId::new();
        let unique_a = EntityId::new();
        let unique_b = EntityId::new();

        store
            .append(
                fork_a.id(),
                &[
                    make_draft(shared, "a.event", b"a"),
                    make_draft(unique_a, "a.unique", b"a"),
                ],
            )
            .unwrap();
        store
            .append(
                fork_b.id(),
                &[
                    make_draft(shared, "b.event", b"b"),
                    make_draft(unique_b, "b.unique", b"b"),
                ],
            )
            .unwrap();

        let result = merge(&mut store, fork_a.id(), fork_b.id(), Seq::ZERO, "merged");

        assert!(result.is_err());
    }

    #[test]
    fn can_merge_with_empty_arm_a() {
        let mut store = setup_store();

        let base = store.create_timeline("base").unwrap();
        let fork_a = store.fork(base.id(), Seq::ZERO, "fork_a").unwrap();
        let fork_b = store.fork(base.id(), Seq::ZERO, "fork_b").unwrap();

        store
            .append(fork_b.id(), &[make_draft(EntityId::new(), "b.event", b"b")])
            .unwrap();

        let can_merge =
            can_merge_conflict_free(&store, fork_a.id(), fork_b.id(), Seq::ZERO).unwrap();
        assert!(can_merge);

        let merged = merge(&mut store, fork_a.id(), fork_b.id(), Seq::ZERO, "merged").unwrap();
        let events = store.read(merged.id(), SeqRange::all()).unwrap();
        assert_eq!(events.len(), 1);
    }

    #[test]
    fn can_merge_with_empty_arm_b() {
        let mut store = setup_store();

        let base = store.create_timeline("base").unwrap();
        let fork_a = store.fork(base.id(), Seq::ZERO, "fork_a").unwrap();
        let fork_b = store.fork(base.id(), Seq::ZERO, "fork_b").unwrap();

        store
            .append(fork_a.id(), &[make_draft(EntityId::new(), "a.event", b"a")])
            .unwrap();

        let can_merge =
            can_merge_conflict_free(&store, fork_a.id(), fork_b.id(), Seq::ZERO).unwrap();
        assert!(can_merge);

        let merged = merge(&mut store, fork_a.id(), fork_b.id(), Seq::ZERO, "merged").unwrap();
        let events = store.read(merged.id(), SeqRange::all()).unwrap();
        assert_eq!(events.len(), 1);
    }

    #[test]
    fn merge_result_clean_variant() {
        let events = vec![];
        let result = MergeResult::Clean(events);
        assert!(matches!(result, MergeResult::Clean(_)));
    }

    #[test]
    fn merge_result_conflicts_variant() {
        let conflicts = vec![];
        let result = MergeResult::Conflicts(conflicts);
        assert!(matches!(result, MergeResult::Conflicts(_)));
    }

    #[test]
    fn merge_conflict_structure() {
        let entity = EntityId::new();
        let conflict = MergeConflict {
            entity,
            in_a: vec![],
            in_b: vec![],
        };
        assert_eq!(conflict.entity, entity);
        assert!(conflict.in_a.is_empty());
        assert!(conflict.in_b.is_empty());
    }

    #[test]
    fn merge_root_timelines_without_fork() {
        let mut store = setup_store();

        let root_a = store.create_timeline("root_a").unwrap();
        let root_b = store.create_timeline("root_b").unwrap();

        let entity_a = EntityId::new();
        let entity_b = EntityId::new();

        store
            .append(root_a.id(), &[make_draft(entity_a, "a.event", b"a")])
            .unwrap();
        store
            .append(root_b.id(), &[make_draft(entity_b, "b.event", b"b")])
            .unwrap();

        let merged = merge(&mut store, root_a.id(), root_b.id(), Seq::ZERO, "merged").unwrap();

        let events = store.read(merged.id(), SeqRange::all()).unwrap();
        assert_eq!(events.len(), 2);
        let entities: HashSet<EntityId> = events.iter().map(|e| e.entity).collect();
        assert!(entities.contains(&entity_a));
        assert!(entities.contains(&entity_b));
    }
}
