//! Store-side checks of the factual Tick declaration an admission basis
//! carries (ADR-064 Revision 3, R3.7.2).
//!
//! Every function here is a predicate over the basis alone, or over the basis
//! and the payload hashes of the Events it binds. The adapter combines them
//! with the persisted prefix, in the order of R3.7.2, before any Event is
//! appended. The host is the trusted composition root: these checks recompute
//! what the store can recompute and are defence in depth for the rest.

use std::collections::{BTreeMap, BTreeSet};

use pos_core::{
    factual_artifact_digest, factual_ingress_content_digest, factual_output_content_digest,
    DependencyNodeCoordinateV1, DependencyNodeRecordV1, FactualHostOwnerV1, FactualNodeKeyV1,
    FactualRuleV1, Hash, PipelineAdmissionBasisV1, PipelineIngressV1, RecordedNodeOriginV1, Seq,
    TickDependencyRecordV1, TimelineId, FACTUAL_SNAPSHOT_SCHEMA_ID_V1,
};

/// The rule that fixes the class of the host nodes of each host owner: one
/// rule per owner (ADR-064 R4.3).
const HOST_RULES: [(FactualHostOwnerV1, FactualRuleV1); 6] = [
    (
        FactualHostOwnerV1::Observation,
        FactualRuleV1::ObservationSnapshot,
    ),
    (FactualHostOwnerV1::Prefix, FactualRuleV1::VerifiedPrefix),
    (FactualHostOwnerV1::History, FactualRuleV1::ConsumedHistory),
    (FactualHostOwnerV1::Ingress, FactualRuleV1::ExternalIngress),
    (FactualHostOwnerV1::Fold, FactualRuleV1::FoldCheckpoint),
    (FactualHostOwnerV1::FoldHistory, FactualRuleV1::FoldHistory),
];

/// The artifact digest the store recomputes for the node at `coordinate` from
/// the content digest of what the node stands for (R3.3.1).
fn recomputed(
    timeline: TimelineId,
    coordinate: &DependencyNodeCoordinateV1,
    content: Hash,
) -> Hash {
    let key = FactualNodeKeyV1 {
        tick: coordinate.tick(),
        scheduler_position: coordinate.scheduler_position(),
        owner: coordinate.owner_id(),
        output_ordinal: coordinate.output_ordinal(),
        schema_id: coordinate.schema_id(),
    };
    factual_artifact_digest(timeline, key, content)
}

/// Whether the node at `coordinate` is a node of `tick` whose artifact digest
/// is the one recomputed from `content`.
fn node_matches(
    timeline: TimelineId,
    tick: u64,
    coordinate: &DependencyNodeCoordinateV1,
    content: Hash,
) -> bool {
    coordinate.tick() == tick
        && coordinate.artifact_digest() == recomputed(timeline, coordinate, content)
}

/// Whether the coordinate is a host node of `owner`.
fn is_host_node(coordinate: &DependencyNodeCoordinateV1, owner: FactualHostOwnerV1) -> bool {
    coordinate.scheduler_position() == 0 && coordinate.owner_id() == owner.as_str()
}

/// The node of the record at `index`, if the record has one.
fn node_at(nodes: &[DependencyNodeRecordV1], index: u32) -> Option<&DependencyNodeRecordV1> {
    usize::try_from(index).ok().and_then(|at| nodes.get(at))
}

/// Whether the basis is that of a scheduled Driver Tick; the other ingress is
/// a human action.
const fn is_scheduled(basis: &PipelineAdmissionBasisV1) -> bool {
    matches!(
        basis.attempt().ingress(),
        PipelineIngressV1::ScheduledAiDriver
    )
}

/// R3.7.2 (i): every edge carries the persisted fence's authority grant. An
/// authorization that is no 32-byte digest carries no grant.
pub(crate) fn edges_carry_grant(basis: &PipelineAdmissionBasisV1, grant: Hash) -> bool {
    let edges = basis.dependencies().record().edges();
    edges
        .iter()
        .all(|edge| edge.authorization_digest() == Some(grant))
}

/// R3.7.2 (ii), the part that needs no store: the record is a committed one
/// at the asserted Tick.
pub(crate) fn declares_committed_tick(basis: &PipelineAdmissionBasisV1) -> bool {
    let dependencies = basis.dependencies();
    let record = dependencies.record();
    record.origin() == RecordedNodeOriginV1::Committed && record.tick() == dependencies.tick()
}

/// R3.7.2 (iii), outputs: one binding per draft in draft order, each naming a
/// distinct node of the Tick whose artifact digest is the one recomputed from
/// the draft and the node's coordinate.
///
/// Returns the `(seq, artifact digest)` Event binding of every draft, where
/// `first_seq` is the logical `seq` of the first draft.
pub(crate) fn output_event_nodes(
    timeline: TimelineId,
    basis: &PipelineAdmissionBasisV1,
    first_seq: Seq,
) -> Option<Vec<(Seq, Hash)>> {
    let dependencies = basis.dependencies();
    let nodes = dependencies.record().nodes();
    let bindings = dependencies.output_bindings();
    let drafts = basis.batch().drafts();
    let tick = dependencies.tick();
    let in_draft_order = bindings.len() == drafts.len()
        && (0_u32..)
            .zip(bindings)
            .all(|(index, binding)| binding.draft_index == index);
    let named: BTreeSet<u32> = bindings.iter().map(|binding| binding.node_index).collect();
    let bound = bindings
        .iter()
        .zip(drafts)
        .map(|(binding, draft)| {
            let content = factual_output_content_digest(draft);
            node_at(nodes, binding.node_index)
                .map(DependencyNodeRecordV1::coordinate)
                .filter(|coordinate| node_matches(timeline, tick, coordinate, content))
                .map(|coordinate| {
                    let offset = u64::from(binding.draft_index);
                    let seq = Seq::from_u64(first_seq.as_u64().saturating_add(offset));
                    (seq, coordinate.artifact_digest())
                })
        })
        .collect::<Option<Vec<_>>>();
    bound.filter(|_| in_draft_order && named.len() == bindings.len())
}

/// R3.7.2 (iii), snapshot: a scheduled record holds exactly one snapshot node,
/// whose artifact digest is the one recomputed from the observation anchor's
/// snapshot digest. A human record has none: every node of it is bound to a
/// draft.
pub(crate) fn snapshot_matches(timeline: TimelineId, basis: &PipelineAdmissionBasisV1) -> bool {
    let snapshot_digest = basis.attempt().observation().snapshot_digest();
    let snapshots: Vec<&DependencyNodeCoordinateV1> = basis
        .dependencies()
        .record()
        .nodes()
        .iter()
        .map(DependencyNodeRecordV1::coordinate)
        .filter(|coordinate| is_host_node(coordinate, FactualHostOwnerV1::Observation))
        .collect();
    !is_scheduled(basis)
        || matches!(
            snapshots.as_slice(),
            [only] if only.output_ordinal() == 0
                && only.schema_id() == FACTUAL_SNAPSHOT_SCHEMA_ID_V1
                && only.artifact_digest() == recomputed(timeline, only, snapshot_digest)
        )
}

/// R3.7.2 (iv), the part that needs the Events: the bindings are in strictly
/// ascending `seq` order, each names a committed Event at or below the
/// observation, and its node of this Tick carries the artifact digest
/// recomputed from the Event's payload hash and `seq`. `payloads` holds the
/// payload hash of every bound Event that exists at or below the observation:
/// a binding without an entry names no such Event.
///
/// Returns the `(seq, artifact digest)` Event binding of every ingress node.
pub(crate) fn ingress_event_nodes(
    timeline: TimelineId,
    basis: &PipelineAdmissionBasisV1,
    payloads: &BTreeMap<u64, Hash>,
) -> Option<Vec<(Seq, Hash)>> {
    let dependencies = basis.dependencies();
    let nodes = dependencies.record().nodes();
    let bindings = dependencies.event_nodes();
    let tick = dependencies.tick();
    let ascending = bindings.windows(2).all(|pair| pair[0].seq < pair[1].seq);
    let bound = bindings
        .iter()
        .map(|binding| {
            payloads
                .get(&binding.seq.as_u64())
                .map(|payload_hash| factual_ingress_content_digest(*payload_hash, binding.seq))
                .and_then(|content| {
                    node_at(nodes, binding.node_index)
                        .map(DependencyNodeRecordV1::coordinate)
                        .filter(|coordinate| node_matches(timeline, tick, coordinate, content))
                        .map(|coordinate| (binding.seq, coordinate.artifact_digest()))
                })
        })
        .collect::<Option<Vec<_>>>();
    bound.filter(|_| ascending)
}

/// The nodes of a record by artifact digest.
pub(crate) type DigestIndex<'a> = BTreeMap<Hash, &'a DependencyNodeRecordV1>;

/// Index the nodes of `record` by artifact digest, once for all the checks
/// that resolve a digest to a node.
pub(crate) fn digest_index(record: &TickDependencyRecordV1) -> DigestIndex<'_> {
    record
        .nodes()
        .iter()
        .map(|node| (node.coordinate().artifact_digest(), node))
        .collect()
}

/// R3.7.2 (viii): the structural shape of the record, over its `by_digest`
/// index.
///
/// Every output node inputs exactly one step node of its Tick, position and
/// owner; every step node inputs the snapshot node; every host node declares
/// no input and has the class of its host owner's rule; a human record holds
/// nothing but its draft nodes. The store cannot check Driver-output classes,
/// which need the output policy, nor the step-chain, carried-set, history or
/// verified-prefix content, which need registry state.
pub(crate) fn shape_holds(basis: &PipelineAdmissionBasisV1, by_digest: &DigestIndex<'_>) -> bool {
    let nodes = basis.dependencies().record().nodes();
    (is_scheduled(basis) || nodes.len() == basis.batch().drafts().len())
        && nodes.iter().all(|node| node_shape_holds(node, by_digest))
}

/// Whether one node has the shape its kind requires.
fn node_shape_holds(node: &DependencyNodeRecordV1, by_digest: &DigestIndex<'_>) -> bool {
    let coordinate = node.coordinate();
    if coordinate.scheduler_position() == 0 {
        host_node_shape_holds(node)
    } else if coordinate.output_ordinal() == 0 {
        step_inputs_snapshot(node, by_digest)
    } else {
        output_inputs_one_step(node, by_digest)
    }
}

/// A host node declares no input and has the class its owner's rule assigns.
fn host_node_shape_holds(node: &DependencyNodeRecordV1) -> bool {
    let owner = node.coordinate().owner_id();
    let rule = HOST_RULES
        .iter()
        .find(|(host, _)| host.as_str() == owner)
        .map(|(_, rule)| *rule);
    node.input_digests().is_empty() && rule.is_some_and(|found| node.class() == found.class())
}

/// A step node inputs the snapshot node of the record.
fn step_inputs_snapshot(node: &DependencyNodeRecordV1, by_digest: &DigestIndex<'_>) -> bool {
    node.input_digests().iter().any(|digest| {
        by_digest.get(digest).is_some_and(|source| {
            is_host_node(source.coordinate(), FactualHostOwnerV1::Observation)
        })
    })
}

/// An output node inputs exactly one step node of its Tick, position and owner.
fn output_inputs_one_step(node: &DependencyNodeRecordV1, by_digest: &DigestIndex<'_>) -> bool {
    let output = node.coordinate();
    let steps = node
        .input_digests()
        .iter()
        .filter(|digest| {
            by_digest.get(*digest).is_some_and(|source| {
                let step = source.coordinate();
                step.output_ordinal() == 0
                    && step.tick() == output.tick()
                    && step.scheduler_position() == output.scheduler_position()
                    && step.owner_id() == output.owner_id()
            })
        })
        .count();
    steps == 1
}
