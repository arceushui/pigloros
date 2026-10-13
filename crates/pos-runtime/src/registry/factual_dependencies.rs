//! The factual Tick declaration of a scheduled pass (ADR-064 Revision 3,
//! R3.4, R3.6 and R3.8.1-R3.8.2).
//!
//! The step phase keeps what each Driver declared and the digest of the
//! verified prefix a prefix Driver was handed. At admission the builder
//! resolves every host-derived and Driver-declared input against the
//! committed prefix with batched reads, records the ingress nodes the prefix
//! lacks, and has `assemble_factual_tick` turn the resolved inputs into the
//! declaration the admission basis binds. Every failure aborts the staged
//! Drivers before any store call.

use std::{
    collections::{BTreeMap, BTreeSet},
    ops::Range,
};

use indexmap::IndexMap;
use pos_core::output_policy::OutputAuthorityV1;
use pos_core::{
    assemble_factual_tick, factual_dependency::BoundFactualNodeV1, factual_event_schema_id,
    factual_verified_prefix_content_digest, CoreError, CounterfactualDependencyErrorV1,
    DependencyNodeRecordV1, Event, EventDraft, FactualDependencyErrorV1, FactualDriverStepV1,
    FactualEventRefV1, FactualHostOwnerV1, FactualIngressEventV1, FactualInputV1, FactualOutputV1,
    FactualPrefixReadPortV1, FactualPriorNodeV1, FactualScheduledTickV1, FactualTickContextV1,
    FactualTickDependenciesV1, FactualTickShapeV1, Hash, Kind, PluginId, Seq,
    TickDependencyRecordV1, MAX_OUTPUT_DIRECT_INPUTS_V1, MAX_STEP_INPUTS_PER_DRIVER_V1,
};

use super::{
    consent_visible_event, driver_visible_event,
    owner_id::entry_identity,
    pass_state::{CarriedSet, ForwardedPair, PassCut},
    subscribed_event_visible, HistoryInputV1, OperationContext, PendingStep, PluginEntry,
    PluginRegistry, ScheduledPassAdmissionV1, StepChainV1,
};
use crate::{
    driver::{DirectInputRefV1, StepOutput},
    error::RuntimeError,
};

/// What the pass knows of one committed Event it may declare or record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct EventFact {
    /// The Event type, which fixes the schema ID of an ingress node.
    pub(super) event_type: Kind,
    /// The Event's payload hash.
    pub(super) payload_hash: Hash,
    /// Whether the Event is Driver-visible and shown by the pass's consent.
    pub(super) shown: bool,
}

/// The inputs a Driver declared in one step.
pub(super) struct DriverDeclaration {
    step_inputs: Vec<DirectInputRefV1>,
    direct_inputs: Vec<Vec<DirectInputRefV1>>,
}

/// Split a Driver's output into its drafts and the inputs it declared.
pub(super) fn split_output(output: StepOutput) -> (Vec<EventDraft>, DriverDeclaration) {
    let StepOutput {
        step_inputs,
        outputs,
    } = output;
    let mut drafts = Vec::new();
    let mut direct_inputs = Vec::new();
    for declared in outputs {
        drafts.push(declared.draft);
        direct_inputs.push(declared.direct_inputs);
    }
    let declaration = DriverDeclaration {
        step_inputs,
        direct_inputs,
    };
    (drafts, declaration)
}

/// What a staged pass retains for the declaration of its Tick (R3.8.1).
///
/// The step phase writes everything up to `event_facts`; the builder writes
/// `step_nodes` and `history_recorded` before the store call, and
/// `commit_pending_step` reads them. They travel with the pass through an
/// in-doubt attempt, so a recovery settles the state exactly as a first
/// commit does.
#[derive(Default)]
pub(super) struct StagedFactual {
    /// The range of the staged drafts each stepped Driver staged.
    pub(super) draft_ranges: Vec<Range<usize>>,
    /// The digest of each stepped Driver's verified prefix, `None` for a
    /// Driver that has none.
    ///
    /// It is gathered in one pass by `gather_prefix_digests` and stays empty
    /// for a pass that stages no draft (which declares no Tick) and for an
    /// authorized pass (which gathers none): a missing position is `None`.
    pub(super) prefix_digests: Vec<Option<Hash>>,
    /// The step-level inputs each stepped Driver declared.
    pub(super) step_inputs: Vec<Vec<DirectInputRefV1>>,
    /// The draft-specific inputs of each staged draft.
    pub(super) direct_inputs: Vec<Vec<DirectInputRefV1>>,
    /// The Events the pass forwarded or a Driver declared, as the pass saw them.
    pub(super) event_facts: BTreeMap<Seq, EventFact>,
    /// The history nodes the pass's record creates, by content digest.
    pub(super) history_recorded: Vec<(Hash, FactualPriorNodeV1)>,
    /// The step node of every stepped Driver, in schedule order.
    pub(super) step_nodes: Vec<FactualPriorNodeV1>,
}

impl StagedFactual {
    /// Keep what one stepped Driver staged.
    pub(super) fn push_driver(
        &mut self,
        first_draft: usize,
        drafts: usize,
        declaration: DriverDeclaration,
    ) {
        self.draft_ranges.push(first_draft..first_draft + drafts);
        self.step_inputs.push(declaration.step_inputs);
        self.direct_inputs.extend(declaration.direct_inputs);
    }

    /// Keep the verified-prefix digest of every stepped Driver that has one.
    ///
    /// A pass that stages no draft records no Tick, so only a pass that staged
    /// a draft (`staged`) pays for the digests.
    pub(super) fn gather_prefix_digests(
        &mut self,
        staged: bool,
        plugins: &IndexMap<PluginId, PluginEntry>,
        driver_ids: &[PluginId],
        cut: PassCut<'_>,
        operation: &OperationContext,
    ) {
        if !staged {
            return;
        }
        self.prefix_digests = driver_ids
            .iter()
            .map(|id| verified_prefix_digest(&plugins[id], cut, operation))
            .collect();
    }

    /// Every input a Driver declared, step-level inputs first.
    pub(super) fn declared(&self) -> impl Iterator<Item = &DirectInputRefV1> {
        let step_level = self.step_inputs.iter().flatten();
        step_level.chain(self.direct_inputs.iter().flatten())
    }

    /// Keep what the pass saw of every Event it forwarded or a Driver declared.
    pub(super) fn gather_facts(
        &mut self,
        forwarded: &[Vec<ForwardedPair>],
        committed: &[Event],
        operation: &OperationContext,
    ) {
        let mut wanted: BTreeSet<Seq> = forwarded.iter().flatten().map(|pair| pair.0).collect();
        wanted.extend(self.declared().filter_map(committed_seq));
        for event in committed {
            if wanted.is_empty() {
                break;
            }
            if wanted.remove(&event.seq) {
                let fact = fact_of(event, operation);
                self.event_facts.insert(event.seq, fact);
            }
        }
    }

    /// Keep the step nodes and history nodes the pass's record creates.
    ///
    /// A step node is the node of a Driver position with output ordinal zero.
    /// The history nodes are the nodes of the host history owner, whose
    /// canonical order is the order of `history_contents`.
    pub(super) fn record_nodes(
        &mut self,
        record: &TickDependencyRecordV1,
        history_contents: &[Hash],
    ) {
        let history_owner = FactualHostOwnerV1::History.as_str();
        let nodes = record.nodes();
        self.step_nodes = nodes
            .iter()
            .filter(|node| node.coordinate().scheduler_position() > 0)
            .filter(|node| node.coordinate().output_ordinal() == 0)
            .map(FactualPriorNodeV1::from_record)
            .collect();
        let histories = nodes
            .iter()
            .filter(|node| node.coordinate().owner_id() == history_owner)
            .map(FactualPriorNodeV1::from_record);
        self.history_recorded = history_contents.iter().copied().zip(histories).collect();
    }
}

const fn committed_seq(input: &DirectInputRefV1) -> Option<Seq> {
    match input {
        DirectInputRefV1::CommittedEvent { seq } => Some(*seq),
        DirectInputRefV1::NodeDigest { .. } => None,
    }
}

fn fact_of(event: &Event, operation: &OperationContext) -> EventFact {
    EventFact {
        event_type: event.event_type.clone(),
        payload_hash: event.payload_hash,
        shown: driver_visible_event(event) && consent_visible_event(operation, event),
    }
}

/// The digest of the verified prefix a prefix Driver is handed this pass.
///
/// It covers the Events the Driver's subscriptions and this pass's consent
/// show, in ascending `seq` order (R3.3.1).
pub(super) fn verified_prefix_digest(
    entry: &PluginEntry,
    cut: PassCut<'_>,
    operation: &OperationContext,
) -> Option<Hash> {
    let PassCut {
        observed_through,
        events: committed,
    } = cut;
    entry.event_observation.verified_prefix_required.then(|| {
        let subscriptions = &entry.event_observation.event_subscriptions;
        let mut handed = Vec::new();
        for event in committed {
            if subscribed_event_visible(event, subscriptions, operation) {
                handed.push(FactualEventRefV1 {
                    seq: event.seq,
                    payload_hash: event.payload_hash,
                });
            }
        }
        // Nothing here relies on the order of `committed`, and the digest
        // covers ascending `seq` order, so the order is fixed explicitly.
        handed.sort_unstable_by_key(|event| event.seq);
        factual_verified_prefix_content_digest(observed_through, &handed)
    })
}

/// Settle the history and chain state of the Drivers when a commit recorded a
/// Tick (R3.4.10, R3.8.1).
///
/// Every stepped Driver's step node is now its latest, and its history is
/// consumed. Every other Driver whose pending history node this Tick recorded
/// declares that node from now on. A commit that recorded nothing leaves the
/// state untouched.
pub(super) fn settle_recorded_tick(
    plugins: &mut IndexMap<PluginId, PluginEntry>,
    driver_ids: &[PluginId],
    step_nodes: Vec<FactualPriorNodeV1>,
    history_recorded: &[(Hash, FactualPriorNodeV1)],
    recorded: bool,
) {
    if !recorded {
        return;
    }
    for entry in plugins.values_mut() {
        let pending = entry.pass_state.history.pending_content();
        if let Some((content, node)) = recorded_for(history_recorded, pending) {
            entry.pass_state.history = HistoryInputV1::Recorded { content, node };
        }
    }
    for (id, node) in driver_ids.iter().zip(step_nodes) {
        if let Some(entry) = plugins.get_mut(id) {
            entry.pass_state.history = HistoryInputV1::None;
            entry.chain = StepChainV1::Recorded { node };
        }
    }
}

/// The node this Tick recorded for a pending history digest, if any.
fn recorded_for(
    history_recorded: &[(Hash, FactualPriorNodeV1)],
    pending: Option<Hash>,
) -> Option<(Hash, FactualPriorNodeV1)> {
    let content = pending?;
    let found = history_recorded.iter().find(|(known, _)| *known == content);
    found.map(|(_, node)| (content, node.clone()))
}

/// Refuse a Driver that declared more inputs than a node may hold (R3.6.1).
fn ensure_declared_caps(staged: &StagedFactual) -> Result<(), FactualDependencyErrorV1> {
    let step_level = staged
        .step_inputs
        .iter()
        .any(|inputs| inputs.len() > MAX_STEP_INPUTS_PER_DRIVER_V1);
    let draft_level = staged
        .direct_inputs
        .iter()
        .any(|inputs| inputs.len() > MAX_OUTPUT_DIRECT_INPUTS_V1);
    if step_level || draft_level {
        Err(declared_too_many())
    } else {
        Ok(())
    }
}

/// The error of a Driver that declared more inputs than a node may hold.
const fn declared_too_many() -> FactualDependencyErrorV1 {
    FactualDependencyErrorV1::Record(CounterfactualDependencyErrorV1::FieldOutOfBounds)
}

/// The Events a step node declares individually: forwarded this pass plus
/// carried (R3.4.2(b)).
fn driver_event_seqs(fresh: &[ForwardedPair], carried: &CarriedSet) -> BTreeSet<Seq> {
    let new_seqs = fresh.iter().map(|pair| pair.0);
    new_seqs.chain(carried.keys().copied()).collect()
}

/// The Tick of a scheduled pass: one past the later of the store's head and
/// the highest Tick the stepped Drivers retain a prior node from.
///
/// While the stores hold factual rows the head is the last committed Tick and
/// every retained node is committed, so this is the ADR's "last committed
/// Tick plus one". Until slices 8-9 write rows the head stays zero. The Tick
/// is then strictly later than every prior node the stepped Drivers retain,
/// so a chain or history edge of those Drivers always points at an earlier
/// Tick (R3.4.1). That is not a registry-wide guarantee: passes over
/// different Driver subsets can repeat a Tick until the stores write rows.
/// A Tick that would pass `u64::MAX` exhausts the Timeline's set.
pub(super) fn next_factual_tick(head: u64, retained: u64) -> Result<u64, FactualDependencyErrorV1> {
    let latest = head.max(retained);
    let next = latest.checked_add(1);
    next.ok_or(FactualDependencyErrorV1::SetExhausted)
}

/// The Tick of the latest prior node a Driver's step node would declare from
/// its retained state; zero when it retains none.
fn retained_tick(entry: &PluginEntry) -> u64 {
    let chain = match &entry.chain {
        StepChainV1::Lookup => 0,
        StepChainV1::Recorded { node } => node.coordinate().tick(),
    };
    let history = match &entry.pass_state.history {
        HistoryInputV1::None | HistoryInputV1::Pending { .. } => 0,
        HistoryInputV1::Recorded { node, .. } => node.coordinate().tick(),
    };
    chain.max(history)
}

/// The class rule of each Event type an entry's admitted policy declares
/// (R3.5.1).
///
/// Output admission rejects a draft of an undeclared type, so every staged
/// draft of an entry has an entry here. A registration without an admission is
/// only the test-support `register_driver` Driver, which owns no Event type and
/// stages no draft.
fn output_authorities(entry: &PluginEntry) -> BTreeMap<&str, OutputAuthorityV1> {
    let declarations = entry
        .output_admission
        .iter()
        .flat_map(|admission| admission.policy().fields().output_declarations.iter());
    declarations
        .map(|found| (found.event_type(), found.authority()))
        .collect()
}

/// The distinct digests of one kind of node a Tick records, in first-use order.
///
/// Each stepped Driver adds at most one digest, so a list never outgrows the
/// number of registered Drivers and its positions fit a `u32`.
///
/// `next` always equals `order.len()`. It stays a counter so a position needs
/// no fallible `usize` to `u32` conversion, which would add a branch no
/// reachable input takes.
#[derive(Default)]
struct Interned {
    order: Vec<Hash>,
    index: BTreeMap<Hash, u32>,
    next: u32,
}

impl Interned {
    /// The position of `digest`, appending it when it is new.
    fn position(&mut self, digest: Hash) -> u32 {
        if let Some(found) = self.index.get(&digest) {
            return *found;
        }
        let next = self.next;
        self.next += 1;
        self.order.push(digest);
        self.index.insert(digest, next);
        next
    }
}

fn zip_found<K: Ord + Copy, V>(keys: &[K], found: Vec<Option<V>>) -> BTreeMap<K, V> {
    let mut map = BTreeMap::new();
    for (key, value) in keys.iter().zip(found) {
        if let Some(value) = value {
            map.insert(*key, value);
        }
    }
    map
}

/// What the port answered for one pass.
struct Lookups {
    /// The recorded node of each committed Event that has one.
    events: BTreeMap<Seq, DependencyNodeRecordV1>,
    /// The recorded node, and the Event it is bound to, of each named digest.
    digests: BTreeMap<Hash, BoundFactualNodeV1>,
    /// The latest step node of each stepped Driver whose chain is a lookup,
    /// by position in the pass.
    chains: BTreeMap<usize, DependencyNodeRecordV1>,
}

/// The Driver a declared input is checked against.
struct DriverScope<'a> {
    entry: &'a PluginEntry,
    schema_ids: Vec<u32>,
    authorities: BTreeMap<&'a str, OutputAuthorityV1>,
}

impl<'a> DriverScope<'a> {
    fn new(entry: &'a PluginEntry) -> Self {
        let subscriptions = &entry.event_observation.event_subscriptions;
        let schema_ids = subscriptions
            .iter()
            .filter(|kind| !pos_core::is_subject_controlled_event_type(kind))
            .map(|kind| factual_event_schema_id(kind.as_str()))
            .collect();
        Self {
            entry,
            schema_ids,
            authorities: output_authorities(entry),
        }
    }

    /// Whether the Driver subscribed to any Event type: a Driver with none
    /// observes no committed Event (R3.4.7).
    const fn subscribes(&self) -> bool {
        !self.subscriptions().is_empty()
    }

    /// The Event types the Driver subscribed to.
    const fn subscriptions(&self) -> &Vec<Kind> {
        &self.entry.event_observation.event_subscriptions
    }

    /// Whether the pass showed the Event and the Driver subscribed to its type.
    fn subscribed_and_shown(&self, fact: &EventFact) -> bool {
        fact.shown && self.subscriptions().contains(&fact.event_type)
    }

    /// Whether the recorded node of an Event the pass did not see is of a type
    /// the Driver subscribed to, judged by its schema ID.
    ///
    /// A schema ID cannot show whether the pass's consent hides the Event, so
    /// `schema_ids` leaves out the subject-controlled types: an unseen Event of
    /// such a type is undeclarable (R3.6.2), however it is named.
    fn subscribed_by_schema(&self, node: Option<&DependencyNodeRecordV1>) -> bool {
        node.is_some_and(|node| self.schema_ids.contains(&node.coordinate().schema_id()))
    }

    /// Whether the Driver could have read an Event (R3.6.2).
    fn declarable(&self, fact: Option<&EventFact>, node: Option<&DependencyNodeRecordV1>) -> bool {
        let shown = fact.map(|fact| self.subscribed_and_shown(fact));
        shown.unwrap_or_else(|| self.subscribed_by_schema(node))
    }
}

/// The Events the pass can record as ingress nodes: what it saw, and what the
/// stepped Drivers carry.
fn merged_facts(registry: &PluginRegistry, pending: &PendingStep) -> BTreeMap<Seq, EventFact> {
    let mut events = pending.factual.event_facts.clone();
    for id in &pending.driver_ids {
        let entry = &registry.plugins[id];
        for (seq, (payload_hash, event_type)) in &entry.pass_state.carried {
            let fact = EventFact {
                event_type: event_type.clone(),
                payload_hash: *payload_hash,
                shown: true,
            };
            events.entry(*seq).or_insert(fact);
        }
    }
    events
}

/// One scheduled pass being resolved into the inputs of the assembly.
struct PassBuild {
    through: Seq,
    lookups: Lookups,
    events: BTreeMap<Seq, EventFact>,
    ingress: BTreeMap<Seq, FactualIngressEventV1>,
    prefix_contents: Interned,
    history_contents: Interned,
}

impl PassBuild {
    fn new(
        registry: &PluginRegistry,
        pending: &PendingStep,
        lookups: Lookups,
        through: Seq,
    ) -> Self {
        Self {
            through,
            lookups,
            events: merged_facts(registry, pending),
            ingress: BTreeMap::new(),
            prefix_contents: Interned::default(),
            history_contents: Interned::default(),
        }
    }

    fn finish(
        self,
        snapshot_digest: Hash,
        drivers: Vec<FactualDriverStepV1>,
    ) -> FactualScheduledTickV1 {
        FactualScheduledTickV1 {
            snapshot_digest,
            prefix_contents: self.prefix_contents.order,
            history_contents: self.history_contents.order,
            ingress_events: self.ingress.into_values().collect(),
            drivers,
        }
    }

    /// The input for a committed Event: its recorded node, else an ingress
    /// node this Tick records (R3.4.4).
    fn event_input(&mut self, seq: Seq) -> Result<FactualInputV1, FactualDependencyErrorV1> {
        if let Some(node) = self.lookups.events.get(&seq) {
            return Ok(FactualInputV1::Prior(FactualPriorNodeV1::from_record(node)));
        }
        let fact = self
            .events
            .get(&seq)
            .ok_or(FactualDependencyErrorV1::UnresolvedInput)?;
        let ingress = FactualIngressEventV1 {
            seq,
            event_type: fact.event_type.as_str().to_owned(),
            payload_hash: fact.payload_hash,
        };
        self.ingress.insert(seq, ingress);
        Ok(FactualInputV1::IngressEvent(seq))
    }

    fn declared_inputs(
        &mut self,
        scope: &DriverScope<'_>,
        inputs: &[DirectInputRefV1],
    ) -> Result<Vec<FactualInputV1>, FactualDependencyErrorV1> {
        let mut resolved = Vec::with_capacity(inputs.len());
        for input in inputs {
            resolved.push(self.declared_input(scope, input)?);
        }
        Ok(resolved)
    }

    fn declared_input(
        &mut self,
        scope: &DriverScope<'_>,
        input: &DirectInputRefV1,
    ) -> Result<FactualInputV1, FactualDependencyErrorV1> {
        match input {
            DirectInputRefV1::CommittedEvent { seq } => self.declared_event(scope, *seq),
            DirectInputRefV1::NodeDigest { digest } => self.declared_digest(scope, *digest),
        }
    }

    /// Whether the Driver could not have read the Event at `seq`: it is above
    /// the cut, or the Driver subscribed to no Event type.
    fn unreadable(&self, scope: &DriverScope<'_>, seq: Seq) -> bool {
        seq > self.through || !scope.subscribes()
    }

    /// A declared Event: one the Driver could have read, and one the pass can
    /// resolve to a node or record as an ingress node (R3.6.2).
    fn declared_event(
        &mut self,
        scope: &DriverScope<'_>,
        seq: Seq,
    ) -> Result<FactualInputV1, FactualDependencyErrorV1> {
        if self.unreadable(scope, seq) {
            return Err(FactualDependencyErrorV1::UndeclarableInput);
        }
        let fact = self.events.get(&seq);
        let node = self.lookups.events.get(&seq);
        if fact.is_none() && node.is_none() {
            return Err(FactualDependencyErrorV1::UnresolvedInput);
        }
        if !scope.declarable(fact, node) {
            return Err(FactualDependencyErrorV1::UndeclarableInput);
        }
        self.event_input(seq)
    }

    /// A declared digest: a recorded node, and when it stands for an Event,
    /// one the Driver could have read (R3.6.2).
    fn declared_digest(
        &self,
        scope: &DriverScope<'_>,
        digest: Hash,
    ) -> Result<FactualInputV1, FactualDependencyErrorV1> {
        let (node, bound) = self
            .lookups
            .digests
            .get(&digest)
            .ok_or(FactualDependencyErrorV1::UnresolvedInput)?;
        // An Event the pass saw is judged by its fact, consent included; an
        // unseen one only by a schema ID that no subject-controlled type has.
        if let Some(seq) = bound {
            let fact = self.events.get(seq);
            if *seq > self.through || !scope.declarable(fact, Some(node)) {
                return Err(FactualDependencyErrorV1::UndeclarableInput);
            }
        }
        Ok(FactualInputV1::Prior(FactualPriorNodeV1::from_record(node)))
    }

    /// The inputs the host derives besides the Events (R3.4.2(c), (d), (f)).
    fn host_inputs(
        &mut self,
        index: usize,
        entry: &PluginEntry,
        prefix: Option<Hash>,
    ) -> Vec<FactualInputV1> {
        let chain = match &entry.chain {
            StepChainV1::Lookup => self.lookups.chains.get(&index).map(prior_input),
            StepChainV1::Recorded { node } => Some(FactualInputV1::Prior(node.clone())),
        };
        let history = match &entry.pass_state.history {
            HistoryInputV1::None => None,
            HistoryInputV1::Pending { content } => {
                let position = self.history_contents.position(*content);
                Some(FactualInputV1::HistoryNode(position))
            }
            HistoryInputV1::Recorded { node, .. } => Some(FactualInputV1::Prior(node.clone())),
        };
        let prefix = prefix.map(|digest| {
            let position = self.prefix_contents.position(digest);
            FactualInputV1::PrefixNode(position)
        });
        [chain, history, prefix].into_iter().flatten().collect()
    }

    fn output(
        &mut self,
        scope: &DriverScope<'_>,
        pending: &PendingStep,
        draft_index: usize,
    ) -> Result<FactualOutputV1, FactualDependencyErrorV1> {
        let draft = pending.staged_drafts[draft_index].clone();
        let declared = &pending.factual.direct_inputs[draft_index];
        let direct_inputs = self.declared_inputs(scope, declared)?;
        let authority = scope.authorities[draft.event_type.as_str()];
        Ok(FactualOutputV1 {
            draft,
            authority,
            direct_inputs,
        })
    }

    /// The step node of the Driver at `index` of the pass (R3.4.2).
    fn driver_step(
        &mut self,
        entry: &PluginEntry,
        index: usize,
        pending: &PendingStep,
    ) -> Result<FactualDriverStepV1, FactualDependencyErrorV1> {
        let scope = DriverScope::new(entry);
        let staged = &pending.factual;
        let prefix = staged.prefix_digests.get(index).copied().flatten();
        let mut step_inputs = self.host_inputs(index, entry, prefix);
        for seq in driver_event_seqs(&pending.forwarded[index], &entry.pass_state.carried) {
            step_inputs.push(self.event_input(seq)?);
        }
        let declared = self.declared_inputs(&scope, &staged.step_inputs[index])?;
        step_inputs.extend(declared);
        let mut outputs = Vec::new();
        for draft_index in staged.draft_ranges[index].clone() {
            outputs.push(self.output(&scope, pending, draft_index)?);
        }
        Ok(FactualDriverStepV1 {
            owner: entry.pass_state.owner_id.clone(),
            policy_identity: entry_identity(entry),
            step_inputs,
            outputs,
        })
    }
}

fn prior_input(node: &DependencyNodeRecordV1) -> FactualInputV1 {
    FactualInputV1::Prior(FactualPriorNodeV1::from_record(node))
}

impl PluginRegistry {
    /// Build the factual Tick declaration of a staged scheduled pass.
    ///
    /// It is the builder of ADR-064 R3.8.1: it runs after output admission and
    /// schema validation and before the admission basis, reads the prefix
    /// through the port, and writes the step nodes and history nodes of the
    /// record into `pending` for `commit_pending_step`.
    pub(super) fn scheduled_dependencies(
        &self,
        port: &dyn FactualPrefixReadPortV1,
        pending: &mut PendingStep,
        admission: &ScheduledPassAdmissionV1,
        anchor: (Seq, Hash),
    ) -> Result<FactualTickDependenciesV1, RuntimeError> {
        let (through, snapshot_digest) = anchor;
        ensure_declared_caps(&pending.factual).map_err(RuntimeError::DependencyDeclaration)?;
        let timeline = pending.timeline;
        let tick = self.declared_tick(port, pending)?;
        let lookups = self
            .read_lookups(port, pending)
            .map_err(RuntimeError::Store)?;
        let context = FactualTickContextV1 {
            timeline_id: timeline,
            tick,
            attempt_id: admission.attempt_id,
            evidence_digest: admission.provider_validation.digest(),
            authority_grant: admission.authority_grant,
        };
        let scheduled = self
            .scheduled_shape(pending, lookups, through, snapshot_digest)
            .map_err(RuntimeError::DependencyDeclaration)?;
        let history_contents = scheduled.history_contents.clone();
        let shape = FactualTickShapeV1::Scheduled(scheduled);
        let dependencies =
            assemble_factual_tick(&context, &shape).map_err(RuntimeError::DependencyDeclaration)?;
        let record = dependencies.record();
        pending.factual.record_nodes(record, &history_contents);
        Ok(dependencies)
    }

    /// The Tick a scheduled pass declares (R3.4.1, R3.8.1).
    ///
    /// The store's head is read through the port; the highest Tick among the
    /// prior nodes the stepped Drivers retain is read from the registry.
    fn declared_tick(
        &self,
        port: &dyn FactualPrefixReadPortV1,
        pending: &PendingStep,
    ) -> Result<u64, RuntimeError> {
        let head = port
            .last_committed_factual_tick(pending.timeline)
            .map_err(RuntimeError::Store)?;
        let retained = self.highest_retained_tick(pending);
        next_factual_tick(head.tick, retained).map_err(RuntimeError::DependencyDeclaration)
    }

    /// The highest Tick of the prior nodes the stepped Drivers retain.
    fn highest_retained_tick(&self, pending: &PendingStep) -> u64 {
        let mut highest = 0;
        for id in &pending.driver_ids {
            highest = highest.max(retained_tick(&self.plugins[id]));
        }
        highest
    }

    /// Resolve every input of the stepped Drivers into the assembly's shape.
    fn scheduled_shape(
        &self,
        pending: &PendingStep,
        lookups: Lookups,
        through: Seq,
        snapshot_digest: Hash,
    ) -> Result<FactualScheduledTickV1, FactualDependencyErrorV1> {
        let mut build = PassBuild::new(self, pending, lookups, through);
        let mut drivers = Vec::with_capacity(pending.driver_ids.len());
        for (index, id) in pending.driver_ids.iter().enumerate() {
            drivers.push(build.driver_step(&self.plugins[id], index, pending)?);
        }
        Ok(build.finish(snapshot_digest, drivers))
    }

    /// Read the recorded nodes the pass names, with one batched read per kind.
    ///
    /// The step chains are read per owner, one `last_step_node` call for each
    /// stepped Driver whose chain is a lookup: the port answers chains by
    /// design per owner, not in a batch.
    fn read_lookups(
        &self,
        port: &dyn FactualPrefixReadPortV1,
        pending: &PendingStep,
    ) -> Result<Lookups, CoreError> {
        let timeline = pending.timeline;
        let (seqs, digests) = self.lookup_keys(pending);
        let seqs: Vec<Seq> = seqs.into_iter().collect();
        let digests: Vec<Hash> = digests.into_iter().collect();
        let events = port.nodes_for_committed_events(timeline, &seqs)?;
        let by_digest = port.nodes_by_digest(timeline, &digests)?;
        Ok(Lookups {
            events: zip_found(&seqs, events),
            digests: zip_found(&digests, by_digest),
            chains: self.read_chains(port, pending)?,
        })
    }

    /// The Event `seq`s and node digests the pass needs the port to resolve.
    fn lookup_keys(&self, pending: &PendingStep) -> (BTreeSet<Seq>, BTreeSet<Hash>) {
        let mut seqs = BTreeSet::new();
        for (id, forwarded) in pending.driver_ids.iter().zip(&pending.forwarded) {
            seqs.extend(driver_event_seqs(
                forwarded,
                &self.plugins[id].pass_state.carried,
            ));
        }
        let mut digests = BTreeSet::new();
        for input in pending.factual.declared() {
            match input {
                DirectInputRefV1::CommittedEvent { seq } => {
                    seqs.insert(*seq);
                }
                DirectInputRefV1::NodeDigest { digest } => {
                    digests.insert(*digest);
                }
            }
        }
        (seqs, digests)
    }

    /// The latest step node of each stepped Driver whose chain is a lookup.
    fn read_chains(
        &self,
        port: &dyn FactualPrefixReadPortV1,
        pending: &PendingStep,
    ) -> Result<BTreeMap<usize, DependencyNodeRecordV1>, CoreError> {
        let mut chains = BTreeMap::new();
        for (index, id) in pending.driver_ids.iter().enumerate() {
            let entry = &self.plugins[id];
            if matches!(entry.chain, StepChainV1::Lookup) {
                if let Some(node) =
                    port.last_step_node(pending.timeline, &entry.pass_state.owner_id)?
                {
                    chains.insert(index, node);
                }
            }
        }
        Ok(chains)
    }
}
