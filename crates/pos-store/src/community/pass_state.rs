//! The Memory domain's pass state and its pass read port (#560 A4c-1;
//! ADR-129 revisions 10, 11, 13 and 14).
//!
//! Everything here is domain-private and has no wire form. Initialization
//! creates T's state: the cumulative recorded-set counters (R10.3(6)) and
//! the selected CGR1 counts of the Initial frontier (R11.3(1)). The pass
//! writers ([`super::pass_writer`]: Reserve, and the Commit and Abort
//! transitions that A5 and A4e-2 call) add the rest; the retained-outcome,
//! control-operation, closure, observation, scope-row and
//! pending-reservation reads serve what the state holds. [`CommunityPassReadPortV1`] reads them all under the
//! caller's guard.

use std::collections::{BTreeMap, BTreeSet};

use pos_core::community_lifecycle::{
    CommunityGraphCountsV1, CommunityLifecycleErrorV1 as Error, CommunityNativeNodeReferenceV1,
    CommunityPassGraphTermsV1, CommunityScopeMemberV1, CommunitySharedCountsV1,
    CommunityTypedInputRefV1,
};
use pos_core::{EntityId, Hash, TimelineId};

use super::erasure_budget::CommunityPendingErasureV1;
use super::memory_domain::MemoryCommunityDomainV1;
use super::native_graph::{CommunityAssembledRecordV1, CommunityInitializationGraphV1};
use super::pass_planner::CommunityPassReadPortV1;

/// One generation's retained operation counts.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct CommunityGenerationCountsV1 {
    /// Passes holding a CPR1 whose detailed outcome is not disposed:
    /// Committed, Aborted and unresolved (R10.4(4)).
    pub(super) outcomes: u64,
    /// Committed observation materializations: +1 in their Reserve
    /// transaction, and counted for as long as their records are retained,
    /// an Aborted pass's too (R14, RN.1(1)).
    pub(super) materializations: u64,
    /// Committed Annotation CPN1s: +1 in the Commit transaction that binds
    /// each (R14, RN.1(1)).
    pub(super) annotations: u64,
}

impl CommunityGenerationCountsV1 {
    /// The retained control and protection operations: exactly the
    /// materializations and the Annotation CPN1s (R14, RN.1(1)). A pass
    /// Reserve, Seal, Commit or Abort, a `SetReason`, a reset, an
    /// initialization, a fork, a CGC1 and a `ProtectArtifacts`
    /// suboperation are never counted.
    pub(super) const fn control_operations(self) -> u64 {
        self.materializations.saturating_add(self.annotations)
    }
}

/// One Timeline's pass state.
pub(super) struct CommunityPassStateV1 {
    /// T's active generation G (R10.5).
    pub(super) generation: [u8; 16],
    /// `H(CSH1)`, T's selected head: the head and frontier a Reserve must
    /// still find (R10.7 step 5j).
    pub(super) head: Hash,
    /// The cumulative recorded-set counters (R10.3(6)).
    pub(super) counters: CommunitySharedCountsV1,
    /// The selected CGR1 `graph_counts` (R11.3(1)).
    pub(super) graph: CommunityGraphCountsV1,
    /// The logical digests of the CES1s in the selected closure (R11.3(3)).
    pub(super) closure: BTreeSet<Hash>,
    /// What a committed Observation CPN1 adds to the selected closure when
    /// its records are not in it yet; a missing entry adds nothing
    /// (R11.3(3)).
    pub(super) observations: BTreeMap<CommunityNativeNodeReferenceV1, CommunityPassGraphTermsV1>,
    /// The scope rows of a ref, by its digest (R11.4(3)).
    pub(super) scope_rows: BTreeMap<Hash, Vec<CommunityScopeMemberV1>>,
    /// The retained operation counts per generation.
    pub(super) generations: BTreeMap<[u8; 16], CommunityGenerationCountsV1>,
}

impl CommunityPassStateV1 {
    /// The state of a Timeline just initialized: the counters are the
    /// seed, the actual counts of its history, plus the initialization's
    /// own additions (R10.3(6)), and the graph is the initial CGR1's.
    ///
    /// The initialization adds one node per CPN1 of its graph (an
    /// `InitialState` and a `StateRevision` per member), each with one
    /// direct input, so as many edges, and its records' plaintext bytes.
    /// The store reports no byte count for the history, so the byte
    /// counter starts at the initialization's own bytes.
    pub(super) fn initialized(
        generation: [u8; 16],
        history: CommunitySharedCountsV1,
        graph: &CommunityInitializationGraphV1,
    ) -> Self {
        let records = graph.records();
        let nodes = records
            .iter()
            .filter(|record| record.record_magic() == CPN1)
            .count() as u64;
        let bytes = records
            .iter()
            .map(CommunityAssembledRecordV1::plaintext_length)
            .fold(0_u64, u64::saturating_add);
        Self {
            generation,
            head: graph.selected_head_digest(),
            counters: CommunitySharedCountsV1 {
                nodes: history.nodes.saturating_add(nodes),
                edges: history.edges.saturating_add(nodes),
                declared_inputs: history.declared_inputs,
                encoded_record_bytes: history.encoded_record_bytes.saturating_add(bytes),
            },
            graph: graph.graph_counts(),
            closure: BTreeSet::new(),
            observations: BTreeMap::new(),
            scope_rows: BTreeMap::new(),
            generations: BTreeMap::new(),
        }
    }
}

/// The magic of a native node record.
const CPN1: [u8; 4] = *b"CPN1";

/// One unresolved reservation's worst-case demand (R13.1(4)): the pass
/// rows and `F_p` it still holds, in targets and in rows bound to its
/// Timeline.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct CommunityPendingReservationV1 {
    pub(super) targets: u64,
    pub(super) rows: u64,
}

impl CommunityPassReadPortV1 for MemoryCommunityDomainV1 {
    fn recorded_set_counters(&self, timeline: TimelineId) -> CommunitySharedCountsV1 {
        self.pass_states
            .get(&timeline)
            .map(|state| state.counters)
            .unwrap_or_default()
    }

    fn retained_pass_outcomes(&self, timeline: TimelineId, generation: [u8; 16]) -> u64 {
        self.generation_counts(timeline, generation).outcomes
    }

    fn control_operations(&self, timeline: TimelineId, generation: [u8; 16]) -> u64 {
        self.generation_counts(timeline, generation)
            .control_operations()
    }

    /// Memory has no key destruction yet, so every vault key is live.
    fn live_keys(&self) -> u64 {
        self.keys.len() as u64
    }

    fn selected_graph(&self, timeline: TimelineId) -> CommunityGraphCountsV1 {
        self.pass_states
            .get(&timeline)
            .map_or(EMPTY_GRAPH, |state| state.graph)
    }

    fn event_source_in_closure(&self, timeline: TimelineId, event_source: Hash) -> bool {
        self.pass_states
            .get(&timeline)
            .is_some_and(|state| state.closure.contains(&event_source))
    }

    fn observation_graph(
        &self,
        timeline: TimelineId,
        observation: CommunityNativeNodeReferenceV1,
    ) -> CommunityPassGraphTermsV1 {
        self.pass_states
            .get(&timeline)
            .and_then(|state| state.observations.get(&observation))
            .copied()
            .unwrap_or_default()
    }

    fn scope_rows(
        &self,
        timeline: TimelineId,
        reference: CommunityTypedInputRefV1<'_>,
    ) -> Result<Vec<CommunityScopeMemberV1>, Error> {
        self.pass_states
            .get(&timeline)
            .and_then(|state| state.scope_rows.get(&reference.digest()))
            .cloned()
            .ok_or(Error::EvidenceUnavailable)
    }

    fn pending_erasure_demand(&self, actor: EntityId) -> CommunityPendingErasureV1 {
        let affected = self.store.community_affected_scope(actor);
        self.pending_reservations
            .iter()
            .filter(|((timeline, _), _)| affected.contains(timeline))
            .fold(
                CommunityPendingErasureV1::default(),
                |mut demand, ((timeline, _), entry)| {
                    demand.targets += entry.targets;
                    *demand.rows.entry(*timeline).or_default() += entry.rows;
                    demand
                },
            )
    }
}

/// The selected graph of a Timeline with no pass state.
const EMPTY_GRAPH: CommunityGraphCountsV1 = CommunityGraphCountsV1 {
    registrations: 0,
    edges: 0,
    keys: 0,
    maximum_depth: 0,
    registration_bytes: 0,
    artifact_bytes: 0,
};

impl MemoryCommunityDomainV1 {
    fn generation_counts(
        &self,
        timeline: TimelineId,
        generation: [u8; 16],
    ) -> CommunityGenerationCountsV1 {
        self.pass_states
            .get(&timeline)
            .and_then(|state| state.generations.get(&generation))
            .copied()
            .unwrap_or_default()
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests;
