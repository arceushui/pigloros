//! Store-independent check of the factual Tick declaration an admission basis
//! carries (ADR-064 Revision 3, R3.7.2).
//!
//! Both pipeline adapters plan a commit the same way: they check the
//! declaration against the Timeline's visible committed prefix before any
//! Event is appended, and install the checked rows with the Events. The
//! checks are written once here, over the `TickPrefixV1` each adapter
//! implements for its own storage. The order is the ADR's: the grant, the
//! Tick, the Event bindings, then the record. A refusal is the commit's
//! outcome; a store fault is an error.
//!
//! The adapters' fold reads (ADR-064 R4.3) share their assembly here too: the
//! cursor from the latest visible fold-head row and the window from the newest
//! Events of a range.

use std::collections::{BTreeMap, BTreeSet};

use pos_core::{
    CoreError, DependencyEdgeRecordV1, DependencyNodeRecordV1, Event, FactualFoldCursorV1,
    FactualFoldEventV1, FactualFoldWindowV1, Hash, Kind, PipelineAdmissionBasisV1,
    PipelineOutcomeV1, RecordedSetCountsV1, Seq, SeqRange, TickDependencyRecordV1, TimelineId,
    MAX_FACTUAL_FOLD_SCAN_PER_TICK_V1,
};

use crate::factual_declaration as declaration;

/// Why a Tick declaration is refused (R3.7.2).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TickRefusalV1 {
    /// The declaration breaks a structural rule.
    InvalidDeclaration,
    /// An edge names another authority grant than the persisted fence's.
    StaleGrant,
    /// The Timeline's recorded set takes no further Tick.
    SetExhausted,
}

impl TickRefusalV1 {
    /// The pipeline outcome that answers the refusal.
    pub(crate) const fn outcome(self) -> PipelineOutcomeV1 {
        match self {
            Self::InvalidDeclaration => PipelineOutcomeV1::InvalidDependencyDeclaration,
            Self::StaleGrant => PipelineOutcomeV1::AdmissionConflict,
            Self::SetExhausted => PipelineOutcomeV1::DependencySetExhausted,
        }
    }
}

/// The rows a checked factual Tick installs with its Events.
pub(crate) struct FactualInstallV1 {
    pub(crate) first_seq: Seq,
    pub(crate) last_seq: Seq,
    /// Every Event-backed node of the Tick: the draft nodes and the ingress
    /// nodes it records, by committed `seq` and artifact digest.
    pub(crate) event_nodes: Vec<(Seq, Hash)>,
}

/// What checking a Tick declaration decided.
pub(crate) enum PlannedTickV1 {
    /// The declaration holds: these rows are installed with the Events.
    Install(FactualInstallV1),
    /// The declaration is refused: nothing is appended or recorded.
    Refused(TickRefusalV1),
}

/// What an adapter reads of a Timeline's visible committed prefix: its own
/// committed set and every ancestor's through the ancestor's cut.
pub(crate) trait TickPrefixV1 {
    /// The Tick number of the visible head, or 0 while no Tick is visible.
    fn last_tick(&self) -> Result<u64, CoreError>;

    /// The committed Events of the Timeline's logical history in `range`.
    fn events_in(&self, range: SeqRange) -> Result<Vec<Event>, CoreError>;

    /// Whether a visible Tick binds any of the committed `seqs` to a node.
    fn any_bound(&self, seqs: &[Seq]) -> Result<bool, CoreError>;

    /// Whether the Timeline's own set already holds the position key or the
    /// artifact digest of a node of the record.
    fn records_any(&self, record: &TickDependencyRecordV1) -> Result<bool, CoreError>;

    /// The stored row counts of the Timeline's own set.
    fn counts(&self) -> Result<RecordedSetCountsV1, CoreError>;

    /// Whether every digest names a node of the visible prefix at a Tick
    /// below `tick`.
    fn sources_below(&self, digests: &[Hash], tick: u64) -> Result<bool, CoreError>;
}

/// Why planning stopped: the declaration is refused, or the store failed.
enum PlanHaltV1 {
    /// The declaration breaks a rule: the commit's outcome, not an error.
    Refused(TickRefusalV1),
    /// A read of the store failed: the commit is an error.
    Fault(CoreError),
}

impl From<TickRefusalV1> for PlanHaltV1 {
    fn from(refusal: TickRefusalV1) -> Self {
        Self::Refused(refusal)
    }
}

impl From<CoreError> for PlanHaltV1 {
    fn from(error: CoreError) -> Self {
        Self::Fault(error)
    }
}

/// `Ok` if `holds`, else the refusal of the declaration.
const fn demand(holds: bool, refusal: TickRefusalV1) -> Result<(), TickRefusalV1> {
    if holds {
        Ok(())
    } else {
        Err(refusal)
    }
}

/// R3.7.2 (i): every edge carries the persisted fence's authority grant. An
/// authorization that is no digest cannot equal it, so it is the same
/// conflict: a fence that has moved.
fn check_grant(basis: &PipelineAdmissionBasisV1, grant: Hash) -> Result<(), TickRefusalV1> {
    let carries = declaration::edges_carry_grant(basis, grant);
    demand(carries, TickRefusalV1::StaleGrant)
}

/// [`demand`] as a halt of the plan.
fn refuse_unless(holds: bool, refusal: TickRefusalV1) -> Result<(), PlanHaltV1> {
    demand(holds, refusal).map_err(PlanHaltV1::from)
}

/// Whether the basis declares a committed record at the Tick after `last`.
fn declares_next_tick(basis: &PipelineAdmissionBasisV1, last: u64) -> bool {
    let next = last.checked_add(1) == Some(basis.dependencies().tick());
    declaration::declares_committed_tick(basis) && next
}

/// R3.7.2 (ii): the record is a committed one at the next Tick of the prefix.
fn check_tick<P: TickPrefixV1>(
    prefix: &P,
    basis: &PipelineAdmissionBasisV1,
) -> Result<(), PlanHaltV1> {
    let invalid = TickRefusalV1::InvalidDeclaration;
    let judged = |last| refuse_unless(declares_next_tick(basis, last), invalid);
    prefix
        .last_tick()
        .map_err(PlanHaltV1::from)
        .and_then(judged)
}

/// The payload hash of every committed Event the ingress bindings of the
/// basis name, by logical `seq`. An Event that does not exist is absent, and
/// so is any binding past the observation: the read never reaches beyond
/// `observed_through`, whatever the bindings declare, and only the bound
/// Events are kept.
fn bound_payloads<P: TickPrefixV1>(
    prefix: &P,
    basis: &PipelineAdmissionBasisV1,
) -> Result<BTreeMap<u64, Hash>, CoreError> {
    let observed = basis.attempt().observation().observed_through();
    let seqs = basis.dependencies().event_nodes().iter().map(|b| b.seq);
    let within: BTreeSet<u64> = seqs
        .filter(|seq| *seq <= observed)
        .map(Seq::as_u64)
        .collect();
    let range = within.first().zip(within.last());
    range.map_or_else(
        || Ok(BTreeMap::new()),
        |(from, to)| {
            let wanted = SeqRange {
                from: Seq::from_u64(*from),
                to: Some(Seq::from_u64(*to)),
            };
            prefix.events_in(wanted).map(|events| {
                events
                    .iter()
                    .filter(|event| within.contains(&event.seq.as_u64()))
                    .map(|event| (event.seq.as_u64(), event.payload_hash))
                    .collect()
            })
        },
    )
}

/// The Event-backed nodes of a Tick: `(seq, artifact digest)` bindings.
type EventNodesV1 = Vec<(Seq, Hash)>;

/// The ingress nodes, if no visible Tick already binds one of their Events.
fn unbound_ingress<P: TickPrefixV1>(
    prefix: &P,
    ingress: Option<EventNodesV1>,
) -> Result<Option<EventNodesV1>, CoreError> {
    let seqs: Vec<Seq> = ingress.iter().flatten().map(|(seq, _)| *seq).collect();
    let bound = !seqs.is_empty() && prefix.any_bound(&seqs)?;
    Ok(ingress.filter(|_| !bound))
}

/// The output nodes followed by the ingress nodes, or the refusal of a
/// declaration that has either wrong.
fn joined_nodes(
    outputs: Option<EventNodesV1>,
    ingress: Option<EventNodesV1>,
) -> Result<EventNodesV1, PlanHaltV1> {
    outputs
        .zip(ingress)
        .map(|(first, second)| first.into_iter().chain(second).collect())
        .ok_or(PlanHaltV1::Refused(TickRefusalV1::InvalidDeclaration))
}

/// R3.7.2 (iii) and (iv): the Event bindings of the drafts and of the
/// ingress nodes, the snapshot node, and that no ingress Event is already
/// bound by a visible Tick. Returns every Event-backed node of the Tick.
fn bound_nodes<P: TickPrefixV1>(
    prefix: &P,
    timeline: TimelineId,
    basis: &PipelineAdmissionBasisV1,
    first_seq: Seq,
    payloads: &BTreeMap<u64, Hash>,
) -> Result<EventNodesV1, PlanHaltV1> {
    let outputs = declaration::output_event_nodes(timeline, basis, first_seq)
        .filter(|_| declaration::snapshot_matches(timeline, basis));
    let ingress = declaration::ingress_event_nodes(timeline, basis, payloads);
    unbound_ingress(prefix, ingress)
        .map_err(PlanHaltV1::from)
        .and_then(|unbound| joined_nodes(outputs, unbound))
}

/// The edge sources of the record that are no node of the record (`index`).
fn outside_sources(
    record: &TickDependencyRecordV1,
    index: &declaration::DigestIndex<'_>,
) -> Vec<Hash> {
    record
        .edges()
        .iter()
        .map(DependencyEdgeRecordV1::source_digest)
        .filter(|source| !index.contains_key(source))
        .collect()
}

/// Whether the `outside` sources are all nodes of the visible prefix at a
/// Tick below `tick`; there is nothing to look up for none.
fn outside_resolve<P: TickPrefixV1>(
    prefix: &P,
    outside: &[Hash],
    tick: u64,
) -> Result<bool, CoreError> {
    if outside.is_empty() {
        Ok(true)
    } else {
        prefix.sources_below(outside, tick)
    }
}

/// R3.7.2 (vii): no declared input is left without an edge, and every edge
/// source is a node of the record (`index`) or a node of the visible prefix at
/// a strictly lower Tick.
fn edge_sources_resolve<P: TickPrefixV1>(
    prefix: &P,
    record: &TickDependencyRecordV1,
    index: &declaration::DigestIndex<'_>,
) -> Result<bool, CoreError> {
    let covered = record.uncovered_input_count() == 0;
    let pending = covered.then(|| outside_sources(record, index));
    pending.map_or(Ok(false), |outside| {
        outside_resolve(prefix, &outside, record.tick())
    })
}

/// R3.7.2 (v) to (viii): the position keys are new, the set takes the record,
/// every edge source resolves, and the shape holds. Each check runs only if
/// the earlier ones passed.
fn check_rows<P: TickPrefixV1>(
    prefix: &P,
    basis: &PipelineAdmissionBasisV1,
) -> Result<(), PlanHaltV1> {
    let record = basis.dependencies().record();
    let index = declaration::digest_index(record);
    let invalid = TickRefusalV1::InvalidDeclaration;
    demand(!prefix.records_any(record)?, invalid)?;
    let capacity = record.ensure_set_capacity(prefix.counts()?);
    capacity.or(Err(TickRefusalV1::SetExhausted))?;
    demand(edge_sources_resolve(prefix, record, &index)?, invalid)?;
    demand(declaration::shape_holds(basis, &index), invalid).map_err(PlanHaltV1::from)
}

/// The rows the checked Tick installs, with its Event-backed nodes.
fn install_of(
    basis: &PipelineAdmissionBasisV1,
    first_seq: Seq,
    event_nodes: Vec<(Seq, Hash)>,
) -> FactualInstallV1 {
    let drafts = basis.batch().drafts().len() as u64;
    let spread = drafts.saturating_sub(1);
    FactualInstallV1 {
        first_seq,
        last_seq: Seq::from_u64(first_seq.as_u64().saturating_add(spread)),
        event_nodes,
    }
}

/// R3.7.2 (i) to (viii), in that order. The grant and the Tick are checked
/// first, from the basis and the prefix alone. Only then are the Events the
/// ingress bindings name read, so a store failure there follows those two
/// refusals and precedes the others.
fn judge<P: TickPrefixV1>(
    prefix: &P,
    timeline: TimelineId,
    basis: &PipelineAdmissionBasisV1,
    grant: Hash,
    first_seq: Seq,
) -> Result<FactualInstallV1, PlanHaltV1> {
    check_grant(basis, grant)?;
    check_tick(prefix, basis)?;
    let payloads = bound_payloads(prefix, basis)?;
    let nodes = bound_nodes(prefix, timeline, basis, first_seq, &payloads)?;
    check_rows(prefix, basis)?;
    Ok(install_of(basis, first_seq, nodes))
}

/// Check the factual Tick declaration of `basis` against the Timeline's
/// visible committed prefix (R3.7.2), before any Event is appended, and
/// prepare the rows the commit installs. Nothing is written. `first_seq` is
/// the logical `seq` the batch's first Event takes, and `grant` the authority
/// grant of the persisted admission fence.
pub(crate) fn plan_tick<P: TickPrefixV1>(
    prefix: &P,
    timeline: TimelineId,
    basis: &PipelineAdmissionBasisV1,
    grant: Hash,
    first_seq: Seq,
) -> Result<PlannedTickV1, CoreError> {
    match judge(prefix, timeline, basis, grant, first_seq) {
        Ok(install) => Ok(PlannedTickV1::Install(install)),
        Err(PlanHaltV1::Refused(refusal)) => Ok(PlannedTickV1::Refused(refusal)),
        Err(PlanHaltV1::Fault(error)) => Err(error),
    }
}

/// One Event of a fold read: its logical `seq`, its type, and its payload
/// hash, never its payload.
pub(crate) type FoldEntryV1 = (Seq, Kind, Hash);

/// At most one node, or the store's fault.
type FoldNodeV1 = Result<Option<DependencyNodeRecordV1>, CoreError>;

/// How many Events a fold read takes: one past the scan cap, so a read that
/// fills it shows that older Events of the range were left out.
pub(crate) const FOLD_READ_LIMIT: usize = MAX_FACTUAL_FOLD_SCAN_PER_TICK_V1 + 1;

/// The message of a fold-head row whose head digest names no visible node.
const DANGLING_FOLD_HEAD: &str = "fold head names no recorded node";

/// The node a fold-head row's head digest names: none for 32 zero bytes, else
/// the node `lookup` finds in the inherited prefix. A digest that names no
/// visible node is a storage fault.
fn fold_head_node(digest: Hash, lookup: impl FnOnce(&Hash) -> FoldNodeV1) -> FoldNodeV1 {
    if digest == Hash::zero() {
        return Ok(None);
    }
    let dangling = || CoreError::Storage(DANGLING_FOLD_HEAD.to_owned());
    let found = lookup(&digest);
    found.and_then(|held| held.map(Some).ok_or_else(dangling))
}

/// The fold cursor of the latest visible fold-head row, its scanned-through
/// `seq` and head digest, or `None` without a row (ADR-064 R4.2).
pub(crate) fn fold_cursor_of(
    row: Option<(Seq, Hash)>,
    lookup: impl FnOnce(&Hash) -> FoldNodeV1,
) -> Result<Option<FactualFoldCursorV1>, CoreError> {
    let cursor = row.map(|(scanned_through, digest)| {
        let head = fold_head_node(digest, lookup);
        head.map(|node| FactualFoldCursorV1 {
            scanned_through,
            head: node,
        })
    });
    cursor.transpose()
}

/// The fold window of the newest Events of a range, read newest first and at
/// most [`FOLD_READ_LIMIT`]: the last [`MAX_FACTUAL_FOLD_SCAN_PER_TICK_V1`]
/// of them in ascending `seq`, `truncated` when the read found more, and each
/// one's node and class from `nodes` (ADR-064 R4.3).
pub(crate) fn fold_window_of(
    mut newest: Vec<FoldEntryV1>,
    nodes: impl FnOnce(&[Seq]) -> Result<Vec<Option<DependencyNodeRecordV1>>, CoreError>,
) -> Result<FactualFoldWindowV1, CoreError> {
    let truncated = newest.len() > MAX_FACTUAL_FOLD_SCAN_PER_TICK_V1;
    newest.truncate(MAX_FACTUAL_FOLD_SCAN_PER_TICK_V1);
    newest.reverse();
    let seqs: Vec<Seq> = newest.iter().map(|entry| entry.0).collect();
    nodes(&seqs).map(|bound| {
        let events = newest.into_iter().zip(bound).map(fold_event).collect();
        FactualFoldWindowV1 { events, truncated }
    })
}

/// One window entry: the Event's `seq`, type, and payload hash, and its node.
fn fold_event(pair: (FoldEntryV1, Option<DependencyNodeRecordV1>)) -> FactualFoldEventV1 {
    let ((seq, event_type, payload_hash), node) = pair;
    FactualFoldEventV1 {
        seq,
        event_type,
        payload_hash,
        node_class: node.as_ref().map(DependencyNodeRecordV1::class),
        node,
    }
}
