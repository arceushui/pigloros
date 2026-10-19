//! Store-side checks of the factual Tick declaration an admission basis
//! carries (ADR-064 Revision 3, R3.7.2).
//!
//! Every function here is a predicate over the basis alone, or over the basis
//! and the payload hashes of the Events it binds. The adapter combines them
//! with the persisted prefix, in the order of R3.7.2, before any Event is
//! appended. The host is the trusted composition root: these checks recompute
//! what the store can recompute and are defence in depth for the rest. The
//! fold part of a scheduled record (ADR-064 R4.3, checks (ix) and (x)) is
//! recomputed in full from the store's own fold cursor and window.

use std::collections::{BTreeMap, BTreeSet};

use pos_core::{
    factual_artifact_digest, factual_fold_layout, factual_ingress_content_digest,
    factual_output_content_digest, DependencyNodeCoordinateV1, DependencyNodeRecordV1,
    FactualFoldBindingV1, FactualFoldChunkV1, FactualFoldLayoutV1, FactualFoldRestV1,
    FactualFoldSourceV1, FactualHostOwnerV1, FactualNodeKeyV1, FactualRuleV1,
    FactualTickDependenciesV1, Hash, PipelineAdmissionBasisV1, PipelineIngressV1,
    RecordedNodeOriginV1, Seq, TickDependencyRecordV1, TimelineId,
    FACTUAL_FOLD_HISTORY_SCHEMA_ID_V1, FACTUAL_FOLD_SCHEMA_ID_V1, FACTUAL_SNAPSHOT_SCHEMA_ID_V1,
    MAX_FACTUAL_FOLD_CHECKPOINTS_PER_TICK_V1,
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

/// The fold-history nodes one scheduled record may hold (ADR-064 R4.3: the
/// binding's `history` has zero or one entry).
const MAX_FOLD_HISTORY_NODES: usize = 1;

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
pub(crate) const fn is_scheduled(basis: &PipelineAdmissionBasisV1) -> bool {
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

/// R3.7.2 (viii), as amended by ADR-064 R4.3: the structural shape of the
/// record, over its `by_digest` index.
///
/// Every output node inputs exactly one step node of its Tick, position and
/// owner; every step node inputs the snapshot node; every host node has the
/// class of its host owner's rule and declares no input, except the snapshot
/// node and the fold checkpoint nodes; the fold binding names the fold nodes
/// (see [`fold_shape_holds`]); a human record holds nothing but its draft
/// nodes. The store cannot check Driver-output classes, which need the output
/// policy, nor the step-chain, carried-set, history or verified-prefix
/// content, which need registry state. The fold content and the fold inputs
/// are recomputed by [`fold_holds`].
pub(crate) fn shape_holds(basis: &PipelineAdmissionBasisV1, by_digest: &DigestIndex<'_>) -> bool {
    let nodes = basis.dependencies().record().nodes();
    (is_scheduled(basis) || nodes.len() == basis.batch().drafts().len())
        && nodes_and_fold_hold(basis, by_digest)
}

/// Every node has the shape its kind requires, and so has the fold part.
fn nodes_and_fold_hold(basis: &PipelineAdmissionBasisV1, by_digest: &DigestIndex<'_>) -> bool {
    let nodes = basis.dependencies().record().nodes();
    let each = nodes.iter().all(|node| node_shape_holds(node, by_digest));
    each && fold_shape_holds(basis, by_digest)
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

/// A host node has the class its owner's rule assigns, and declares no input
/// unless it is the snapshot node or a fold checkpoint node, whose inputs
/// [`fold_shape_holds`] checks.
fn host_node_shape_holds(node: &DependencyNodeRecordV1) -> bool {
    let owner = node.coordinate().owner_id();
    let rule = HOST_RULES
        .iter()
        .find(|(host, _)| host.as_str() == owner)
        .map(|(_, rule)| *rule);
    inputs_allowed(node, rule) && rule.is_some_and(|found| node.class() == found.class())
}

/// Whether the host node's inputs are allowed by its rule: only the snapshot
/// node and the fold checkpoint nodes may declare any (ADR-064 R4.3, (viii)).
fn inputs_allowed(node: &DependencyNodeRecordV1, rule: Option<FactualRuleV1>) -> bool {
    let may_input = matches!(
        rule,
        Some(FactualRuleV1::ObservationSnapshot | FactualRuleV1::FoldCheckpoint)
    );
    may_input || node.input_digests().is_empty()
}

/// The node at `index` if it is the host node of `owner` at the output
/// ordinal and schema ID `at`.
fn fold_node_at(
    nodes: &[DependencyNodeRecordV1],
    index: u32,
    owner: FactualHostOwnerV1,
    at: (u32, u32),
) -> Option<&DependencyNodeRecordV1> {
    let (ordinal, schema_id) = at;
    node_at(nodes, index).filter(|node| {
        let coordinate = node.coordinate();
        is_host_node(coordinate, owner)
            && coordinate.output_ordinal() == ordinal
            && coordinate.schema_id() == schema_id
    })
}

/// How many nodes of the record the host owner holds.
fn owned_count(nodes: &[DependencyNodeRecordV1], owner: FactualHostOwnerV1) -> usize {
    nodes
        .iter()
        .filter(|node| is_host_node(node.coordinate(), owner))
        .count()
}

/// The fold checkpoint nodes the binding names, in chain order, if each is
/// the fold node at its own ordinal.
fn bound_checkpoints<'a>(
    nodes: &'a [DependencyNodeRecordV1],
    fold: &FactualFoldBindingV1,
) -> Option<Vec<&'a DependencyNodeRecordV1>> {
    let named = (0_u32..).zip(&fold.checkpoints).map(|(ordinal, index)| {
        let at = (ordinal, FACTUAL_FOLD_SCHEMA_ID_V1);
        fold_node_at(nodes, *index, FactualHostOwnerV1::Fold, at)
    });
    named.collect()
}

/// The fold-history node the binding names, if it is the one at ordinal 0.
fn bound_history<'a>(
    nodes: &'a [DependencyNodeRecordV1],
    fold: &FactualFoldBindingV1,
) -> Option<Vec<&'a DependencyNodeRecordV1>> {
    let at = (0, FACTUAL_FOLD_HISTORY_SCHEMA_ID_V1);
    let named = fold
        .history
        .iter()
        .map(|index| fold_node_at(nodes, *index, FactualHostOwnerV1::FoldHistory, at));
    named.collect()
}

/// Whether `node` declares the artifact digest of `source`.
fn inputs_node(node: &DependencyNodeRecordV1, source: &DependencyNodeRecordV1) -> bool {
    let digest = source.coordinate().artifact_digest();
    node.input_digests().contains(&digest)
}

/// Whether each fold checkpoint node after the first inputs the one before
/// it, and the first inputs the fold-history node, if there is one.
fn chain_holds(
    checkpoints: &[&DependencyNodeRecordV1],
    history: &[&DependencyNodeRecordV1],
) -> bool {
    let linked = checkpoints
        .windows(2)
        .all(|pair| inputs_node(pair[1], pair[0]));
    let first = checkpoints.first();
    let behind = history
        .first()
        .is_none_or(|collapsed| first.is_some_and(|head| inputs_node(head, collapsed)));
    linked && behind
}

/// The ADR-064 R4.3 shape of the fold part (the structural half of checks
/// (ix) and (x); [`fold_holds`] recomputes the fold inputs and contents).
///
/// The binding names at most five fold checkpoint nodes, in ordinal order,
/// and at most one fold-history node, and they are every such node of the
/// record. The checkpoints chain, the first behind the fold-history node. The
/// snapshot node inputs exactly the last checkpoint; without one it inputs at
/// most one node, which is no node of the record: the head, a node of the
/// prefix that check (vii) resolves.
fn fold_shape_holds(basis: &PipelineAdmissionBasisV1, by_digest: &DigestIndex<'_>) -> bool {
    let dependencies = basis.dependencies();
    let nodes = dependencies.record().nodes();
    let fold = dependencies.fold();
    let bounded = fold.checkpoints.len() <= MAX_FACTUAL_FOLD_CHECKPOINTS_PER_TICK_V1
        && fold.history.len() <= MAX_FOLD_HISTORY_NODES;
    let named = bound_checkpoints(nodes, fold).zip(bound_history(nodes, fold));
    named.is_some_and(|(checkpoints, history)| {
        bounded
            && checkpoints.len() == owned_count(nodes, FactualHostOwnerV1::Fold)
            && history.len() == owned_count(nodes, FactualHostOwnerV1::FoldHistory)
            && chain_holds(&checkpoints, &history)
            && snapshot_input_holds(nodes, checkpoints.last().copied(), by_digest)
    })
}

/// The snapshot node inputs exactly the last fold checkpoint node, or, when
/// the record has none, at most one node outside the record.
fn snapshot_input_holds(
    nodes: &[DependencyNodeRecordV1],
    last: Option<&DependencyNodeRecordV1>,
    by_digest: &DigestIndex<'_>,
) -> bool {
    let outside = |declared: &[Hash]| {
        let foreign = declared
            .iter()
            .all(|digest| !by_digest.contains_key(digest));
        declared.len() <= 1 && foreign
    };
    nodes
        .iter()
        .filter(|node| is_host_node(node.coordinate(), FactualHostOwnerV1::Observation))
        .all(|snapshot| {
            let declared = snapshot.input_digests();
            last.map_or_else(
                || outside(declared),
                |checkpoint| declared == [checkpoint.coordinate().artifact_digest()],
            )
        })
}

/// The fold-head row a checked scheduled Tick writes (ADR-064 R4.3): the
/// anchor's `observed_through` and the artifact digest of the head after the
/// Tick, which is its last fold checkpoint node, else the head the snapshot
/// node inputs, else 32 zero bytes. A human Tick writes none.
///
/// The head is read from the record the checks accepted: check (x) requires
/// that a head without a fold node is the one the fold-head index names.
pub(crate) fn fold_head_row(basis: &PipelineAdmissionBasisV1) -> Option<(Seq, Hash)> {
    is_scheduled(basis).then(|| fold_head_of(basis))
}

/// The fold-head row of a scheduled basis: its anchor and head digest.
fn fold_head_of(basis: &PipelineAdmissionBasisV1) -> (Seq, Hash) {
    let observed = basis.attempt().observation().observed_through();
    let dependencies = basis.dependencies();
    let nodes = dependencies.record().nodes();
    let last = dependencies.fold().checkpoints.last();
    let checkpoint = last.and_then(|index| node_at(nodes, *index));
    let snapshot_input = || {
        nodes
            .iter()
            .find(|node| is_host_node(node.coordinate(), FactualHostOwnerV1::Observation))
            .and_then(|snapshot| snapshot.input_digests().first().copied())
    };
    let head = checkpoint
        .map(|node| node.coordinate().artifact_digest())
        .or_else(snapshot_input)
        .unwrap_or_else(Hash::zero);
    (observed, head)
}

/// What checks (ix) and (x) compare a scheduled record with: the store's own
/// fold source, read from the Events it holds, and the Tick's ingress nodes.
struct FoldCheckV1<'a> {
    timeline: TimelineId,
    tick: u64,
    source: &'a FactualFoldSourceV1,
    /// The artifact digest of the ingress node this Tick binds each `seq` to.
    ingress: BTreeMap<Seq, Hash>,
}

/// The ingress nodes of the Tick, by the `seq` each is bound to.
fn ingress_digests(dependencies: &FactualTickDependenciesV1) -> BTreeMap<Seq, Hash> {
    let nodes = dependencies.record().nodes();
    let bindings = dependencies.event_nodes();
    let bound = bindings.iter().filter_map(|binding| {
        let node = node_at(nodes, binding.node_index);
        node.map(|found| (binding.seq, found.coordinate().artifact_digest()))
    });
    bound.collect()
}

/// The inputs every node of `owner` declares, in node order.
fn owned_inputs(nodes: &[DependencyNodeRecordV1], owner: FactualHostOwnerV1) -> Vec<Hash> {
    let owned = nodes
        .iter()
        .filter(|node| is_host_node(node.coordinate(), owner));
    owned
        .flat_map(|node| node.input_digests().iter().copied())
        .collect()
}

/// The inputs the step and output nodes of the record declare.
fn driver_inputs(nodes: &[DependencyNodeRecordV1]) -> BTreeSet<Hash> {
    let drivers = nodes
        .iter()
        .filter(|node| node.coordinate().scheduler_position() != 0);
    drivers
        .flat_map(|node| node.input_digests().iter().copied())
        .collect()
}

/// The rest of a scheduled record beside its fold part (ADR-064 R4.2), as
/// the builder sized it: every node but the fold checkpoint, fold-history and
/// fold-only ingress nodes, and every edge but those into the fold checkpoint
/// nodes and the snapshot node. An ingress node is forwarded-needed iff a
/// step or output node inputs it; one that only a fold checkpoint node inputs
/// is counted in the fold part. The builder counts such an orphan ingress
/// node in the rest instead (`assemble_factual_tick` counts every ingress
/// node it already holds in the rest), so the two splits differ for an
/// orphan, but their totals agree for the kept set: the derived fold part is
/// the same.
fn fold_rest(dependencies: &FactualTickDependenciesV1) -> FactualFoldRestV1 {
    let record = dependencies.record();
    let nodes = record.nodes();
    let fed = driver_inputs(nodes);
    let fold_fed = owned_inputs(nodes, FactualHostOwnerV1::Fold);
    let folded: BTreeSet<Hash> = fold_fed.iter().copied().collect();
    let ingress = ingress_digests(dependencies);
    let forwarded = ingress
        .iter()
        .filter(|(_, digest)| fed.contains(*digest))
        .map(|(seq, _)| *seq)
        .collect();
    let fold_only = ingress
        .values()
        .filter(|digest| !fed.contains(*digest) && folded.contains(*digest))
        .count();
    let fold_nodes = owned_count(nodes, FactualHostOwnerV1::Fold);
    let history = owned_count(nodes, FactualHostOwnerV1::FoldHistory);
    let snapshot_fed = owned_inputs(nodes, FactualHostOwnerV1::Observation);
    let part = fold_nodes + history + fold_only;
    let fold_edges = fold_fed.len() + snapshot_fed.len();
    FactualFoldRestV1 {
        forwarded,
        nodes: nodes.len().saturating_sub(part),
        edges: record.edges().len().saturating_sub(fold_edges),
    }
}

/// ADR-064 R4.3, checks (ix) and (x), of a scheduled basis: the fold part
/// the store derives from its own fold `source` (the cursor `p` and head of
/// its fold-head index, and the window `(p, observed_through]` of the Events
/// it holds) and from the rest of the record is exactly the record's.
///
/// The derivation is `pos_core`'s own ([`factual_fold_layout`]): the fold
/// inputs and their exclusions, the fit to the record, the collapse, the
/// chunks and the content digests. It refuses an anchor below the cursor
/// and a rest beyond the reserved headroom, as the builder does. Each kept
/// fold input is resolved through its persisted node or the ingress node this
/// Tick binds it to; the head is the fold-head index's, never a node the
/// record names. A record without a fold node is checked the same way, so a
/// skipped range is verified, not trusted.
pub(crate) fn fold_holds(
    timeline: TimelineId,
    basis: &PipelineAdmissionBasisV1,
    source: &FactualFoldSourceV1,
) -> bool {
    let dependencies = basis.dependencies();
    let tick = dependencies.tick();
    let rest = fold_rest(dependencies);
    let check = FoldCheckV1 {
        timeline,
        tick,
        source,
        ingress: ingress_digests(dependencies),
    };
    let layout = factual_fold_layout((timeline, tick), source, &rest);
    layout.is_ok_and(|expected| fold_matches(&check, dependencies, &expected))
}

/// Whether the record's fold-history, fold checkpoint and snapshot nodes are
/// exactly those of the derived `expected` fold part.
fn fold_matches(
    check: &FoldCheckV1<'_>,
    dependencies: &FactualTickDependenciesV1,
    expected: &FactualFoldLayoutV1,
) -> bool {
    let nodes = dependencies.record().nodes();
    let fold = dependencies.fold();
    let checkpoints = bound_checkpoints(nodes, fold).unwrap_or_default();
    let history = bound_history(nodes, fold).unwrap_or_default();
    let found = check.source.head();
    let head = found.map(|node| node.coordinate().artifact_digest());
    let first = history.first();
    let collapsed = first.map(|node| node.coordinate().artifact_digest());
    let behind: Vec<Hash> = head.into_iter().chain(collapsed).collect();
    let bare = checkpoints.is_empty();
    history_matches(check, &history, expected.history)
        && chain_matches(check, &checkpoints, &expected.checkpoints, behind)
        && (!bare || snapshot_head_holds(nodes, head))
}

/// The record holds a fold-history node iff the derivation does, with the
/// artifact digest recomputed from the derived range.
fn history_matches(
    check: &FoldCheckV1<'_>,
    history: &[&DependencyNodeRecordV1],
    expected: Option<Hash>,
) -> bool {
    let present = history.len() == usize::from(expected.is_some());
    let mut pairs = history.iter().zip(expected);
    present && pairs.all(|(node, content)| node_has(check, node, content))
}

/// Whether `node` is a node of the checked Tick whose artifact digest is the
/// one recomputed from `content`.
fn node_has(check: &FoldCheckV1<'_>, node: &DependencyNodeRecordV1, content: Hash) -> bool {
    node_matches(check.timeline, check.tick, node.coordinate(), content)
}

/// The record's fold checkpoint nodes are the derived chain: as many, each
/// with the recomputed artifact digest, node 0 behind `first` (the head and
/// the fold-history node) and every later node behind the one before it.
fn chain_matches(
    check: &FoldCheckV1<'_>,
    checkpoints: &[&DependencyNodeRecordV1],
    chunks: &[FactualFoldChunkV1],
    first: Vec<Hash>,
) -> bool {
    let links = checkpoints
        .iter()
        .map(|node| vec![node.coordinate().artifact_digest()]);
    let behind = std::iter::once(first).chain(links);
    let mut paired = checkpoints.iter().zip(chunks).zip(behind);
    checkpoints.len() == chunks.len()
        && paired.all(|((node, chunk), before)| checkpoint_matches(check, node, chunk, &before))
}

/// One fold checkpoint node: its artifact digest is recomputed from the
/// derived content, and it inputs exactly what it chains onto and its chunk.
fn checkpoint_matches(
    check: &FoldCheckV1<'_>,
    node: &DependencyNodeRecordV1,
    chunk: &FactualFoldChunkV1,
    before: &[Hash],
) -> bool {
    let declared: BTreeSet<Hash> = node.input_digests().iter().copied().collect();
    let wanted = chunk_inputs(check, chunk, before);
    node_has(check, node, chunk.content) && wanted.is_some_and(|inputs| inputs == declared)
}

/// The inputs a fold checkpoint node must declare: `before` and the node of
/// every Event of its chunk, or `None` when an Event of the chunk has no
/// node, neither recorded nor bound by this Tick.
fn chunk_inputs(
    check: &FoldCheckV1<'_>,
    chunk: &FactualFoldChunkV1,
    before: &[Hash],
) -> Option<BTreeSet<Hash>> {
    let events = &check.source.window.events;
    let digests = chunk.events.iter().map(|index| {
        let event = &events[*index];
        let recorded = event.node.as_ref();
        let digest = recorded.map(|found| found.coordinate().artifact_digest());
        digest.or_else(|| check.ingress.get(&event.seq).copied())
    });
    let resolved: Option<Vec<Hash>> = digests.collect();
    let prefix = before.iter().copied();
    resolved.map(|found| prefix.chain(found).collect())
}

/// Check (x) of a record without a fold checkpoint node: the snapshot node
/// inputs exactly the fold-head index's head, or nothing without one. With a
/// fold checkpoint node, the shape check already requires the last.
fn snapshot_head_holds(nodes: &[DependencyNodeRecordV1], head: Option<Hash>) -> bool {
    let expected: Vec<Hash> = head.into_iter().collect();
    let observation = FactualHostOwnerV1::Observation;
    let mut snapshots = nodes
        .iter()
        .filter(|node| is_host_node(node.coordinate(), observation));
    snapshots.all(|snapshot| snapshot.input_digests() == expected.as_slice())
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
