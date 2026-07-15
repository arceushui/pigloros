//! Types for Wave-5 merge support.
//!
// #[allow(dead_code)] — impl in Wave 5

use pos_core::{EntityId, Event, Seq, TimelineId};

/// Specification for how to merge two divergent timelines.
/// Implementation lands in Wave 5. This type establishes the interface.
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
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub enum MergeStrategy {
    /// Accept both sides for disjoint entity sets; surface conflicts otherwise.
    DisjointCrdt,
    /// Always take A's version on conflict.
    PreferA,
    /// Always take B's version on conflict.
    PreferB,
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

/// Result of a merge attempt.
#[derive(Clone, Debug)]
pub enum MergeResult {
    /// Clean merge — all events from both sides applied.
    Clean(Vec<Event>),
    /// Partial merge with unresolved conflicts.
    Conflicts(Vec<MergeConflict>),
}

#[cfg(test)]
mod tests {
    use super::*;
    use pos_core::ids::TimelineId;

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

        // Also verify all strategy variants round-trip.
        for strategy in [MergeStrategy::DisjointCrdt, MergeStrategy::PreferA, MergeStrategy::PreferB] {
            let j = serde_json::to_string(&strategy).unwrap();
            let _back: MergeStrategy = serde_json::from_str(&j).unwrap();
        }
    }
}
