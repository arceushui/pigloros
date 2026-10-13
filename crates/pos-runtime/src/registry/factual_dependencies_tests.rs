//! The factual Tick declaration of a scheduled pass, built from registry state
//! and a fake prefix (ADR-064 Revision 3, R3.4, R3.6 and R3.8.1-R3.8.2).

use std::{cell::Cell, num::NonZeroUsize, sync::Mutex, time::Duration};

use pos_core::clock::WallTime;
use pos_core::crypto::Hash;
use pos_core::event::{CanonicalBytes, SchemaVersion};
use pos_core::ids::{EntityId, EventId};
use pos_core::{
    factual_artifact_digest, factual_event_schema_id, factual_verified_prefix_content_digest,
    AppendDedupKey, AppendDedupScope, AppendIdentity, CoreError, DependencyNodeCoordinateV1,
    DependencyNodeRecordV1, FactualCutV1, FactualDependencyErrorV1, FactualEventRefV1,
    FactualHeadV1, FactualNodeKeyV1, FactualPrefixReadPortV1, FactualTickDependenciesV1,
    PipelineAdmissionBasisV1, PipelineAdmissionPortV1, PipelineAttemptIdV1,
    PipelineCommitReceiptV1, PipelineEvidenceRefV1, PipelineOutcomeV1, PipelineReceiptLookupV1,
    PipelineSecurityRevisionsDraftV1, PipelineSecurityRevisionsV1, RecordedDependencyClassV1,
    RecordedNodeOriginV1, RecordedSetCountsV1, FACTUAL_SNAPSHOT_SCHEMA_ID_V1,
    MAX_OUTPUT_DIRECT_INPUTS_V1, MAX_STEP_INPUTS_PER_DRIVER_V1,
};

use super::test_ext::{TestErrorExt, TestValueExt};
use super::*;

use super::factual_dependencies::{next_factual_tick, verified_prefix_digest};
use crate::driver::{DeclaredOutputV1, DirectInputRefV1, ObservationView};

const PLAIN: &str = "probe.plain";
const OTHER: &str = "probe.other";
const THROUGH: u64 = 3;
const ENDOGENOUS: RecordedDependencyClassV1 = RecordedDependencyClassV1::EndogenousRecomputed;
const PRESENTATION: RecordedDependencyClassV1 = RecordedDependencyClassV1::PresentationOnly;

const fn hash(value: u8) -> Hash {
    Hash::from_bytes([value; 32])
}

fn indexed_hash(index: usize) -> Hash {
    let mut bytes = [0_u8; 32];
    bytes[24..].copy_from_slice(&u64::try_from(index).test_ok().to_be_bytes());
    Hash::from_bytes(bytes)
}

fn payload_hash(seq: u64) -> Hash {
    let mut bytes = [0_u8; 32];
    bytes[..8].copy_from_slice(&seq.to_be_bytes());
    Hash::from_bytes(bytes)
}

fn event(seq: u64, event_type: &str) -> Event {
    Event {
        id: EventId::new(),
        entity: EntityId::new(),
        event_type: Kind::new(event_type),
        payload: CanonicalBytes::from_static(b"payload"),
        wall_time: WallTime::from_micros(1),
        seq: Seq::from_u64(seq),
        causation_id: None,
        correlation_id: None,
        schema_version: SchemaVersion::V1,
        signature: None,
        signature_identity: None,
        origin: None,
        payload_hash: payload_hash(seq),
    }
}

fn plain_events(last: u64) -> Vec<Event> {
    (1..=last).map(|seq| event(seq, PLAIN)).collect()
}

const fn committed_event(seq: u64) -> DirectInputRefV1 {
    DirectInputRefV1::CommittedEvent {
        seq: Seq::from_u64(seq),
    }
}

const fn named(digest: Hash) -> DirectInputRefV1 {
    DirectInputRefV1::NodeDigest { digest }
}

/// A recorded node of an earlier Tick.
fn node(owner: &str, ordinal: u32, schema_id: u32, digest: Hash) -> DependencyNodeRecordV1 {
    let coordinate =
        DependencyNodeCoordinateV1::try_new(1, 1, owner.to_owned(), ordinal, schema_id, digest)
            .test_ok();
    DependencyNodeRecordV1::try_new(
        coordinate,
        ENDOGENOUS,
        RecordedNodeOriginV1::Committed,
        Vec::new(),
        hash(9),
    )
    .test_ok()
}

fn presentation_node(digest: Hash) -> DependencyNodeRecordV1 {
    let coordinate =
        DependencyNodeCoordinateV1::try_new(1, 1, "plugin:old".to_owned(), 1, 7, digest).test_ok();
    DependencyNodeRecordV1::try_new(
        coordinate,
        PRESENTATION,
        RecordedNodeOriginV1::Committed,
        Vec::new(),
        hash(9),
    )
    .test_ok()
}

/// The prefix a Timeline is at: what the port answers.
#[derive(Default)]
struct FakePrefix {
    head: u64,
    events: BTreeMap<u64, DependencyNodeRecordV1>,
    digests: BTreeMap<Hash, (DependencyNodeRecordV1, Option<Seq>)>,
    chains: BTreeMap<String, DependencyNodeRecordV1>,
    chain_reads: Cell<usize>,
    /// The one read that fails: `head`, `events`, `digests` or `chain`.
    fail: &'static str,
}

impl FakePrefix {
    fn at(head: u64) -> Self {
        Self {
            head,
            ..Self::default()
        }
    }

    fn failing(read: &'static str) -> Self {
        Self {
            fail: read,
            ..Self::default()
        }
    }

    fn check(&self, read: &str) -> Result<(), CoreError> {
        if self.fail == read {
            Err(CoreError::Storage("injected read failure".to_owned()))
        } else {
            Ok(())
        }
    }
}

impl FactualPrefixReadPortV1 for FakePrefix {
    fn last_committed_factual_tick(&self, _: TimelineId) -> Result<FactualHeadV1, CoreError> {
        self.check("head")?;
        Ok(FactualHeadV1 {
            tick: self.head,
            last_seq: Seq::ZERO,
        })
    }

    fn cut_tick_at(&self, _: TimelineId, _: Seq) -> Result<FactualCutV1, CoreError> {
        Ok(FactualCutV1::Boundary {
            cut_tick: self.head,
        })
    }

    fn nodes_for_committed_events(
        &self,
        _: TimelineId,
        seqs: &[Seq],
    ) -> Result<Vec<Option<DependencyNodeRecordV1>>, CoreError> {
        self.check("events")?;
        Ok(seqs
            .iter()
            .map(|seq| self.events.get(&seq.as_u64()).cloned())
            .collect())
    }

    fn nodes_by_digest(
        &self,
        _: TimelineId,
        digests: &[Hash],
    ) -> Result<Vec<Option<pos_core::factual_dependency::BoundFactualNodeV1>>, CoreError> {
        self.check("digests")?;
        Ok(digests
            .iter()
            .map(|digest| self.digests.get(digest).cloned())
            .collect())
    }

    fn last_step_node(
        &self,
        _: TimelineId,
        owner: &FactualOwnerIdV1,
    ) -> Result<Option<DependencyNodeRecordV1>, CoreError> {
        self.check("chain")?;
        self.chain_reads.set(self.chain_reads.get() + 1);
        Ok(self.chains.get(owner.as_str()).cloned())
    }

    fn factual_set_counts(&self, _: TimelineId) -> Result<RecordedSetCountsV1, CoreError> {
        Ok(RecordedSetCountsV1::default())
    }
}

type Script = Arc<Mutex<Vec<&'static [u8]>>>;

/// A Driver that emits the payloads of its script and declares fixed inputs.
struct Scripted {
    name: &'static str,
    marker: u64,
    subscriptions: Vec<Kind>,
    owned: &'static str,
    script: Script,
    step_inputs: Vec<DirectInputRefV1>,
    direct_inputs: Vec<DirectInputRefV1>,
}

impl Driver for Scripted {
    fn name(&self) -> &'static str {
        self.name
    }

    fn tick_interval(&self) -> Duration {
        Duration::from_nanos(self.marker)
    }

    fn event_subscriptions(&self) -> &[Kind] {
        &self.subscriptions
    }

    fn step(&mut self, _: TimelineId, _: ObservationView<'_>) -> Result<StepOutput, RuntimeError> {
        let payloads = self
            .script
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let outputs = payloads
            .into_iter()
            .map(|payload| DeclaredOutputV1 {
                draft: EventDraft::new(
                    EntityId::new(),
                    Kind::new(self.owned),
                    CanonicalBytes::from_static(payload),
                ),
                direct_inputs: self.direct_inputs.clone(),
            })
            .collect();
        Ok(StepOutput::declared(self.step_inputs.clone(), outputs))
    }
}

struct OwnerPlugin {
    id: PluginId,
    name: &'static str,
    owned: &'static str,
}

impl Plugin for OwnerPlugin {
    fn id(&self) -> PluginId {
        self.id
    }

    fn name(&self) -> &'static str {
        self.name
    }

    fn capability(&self) -> Capability {
        Capability {
            owned_event_types: vec![Kind::new(self.owned)],
            owned_entity_kinds: Vec::new(),
            has_driver: true,
            has_reducer: false,
        }
    }
}

/// A Driver of `owned` Events that subscribes to `PLAIN`.
fn scripted(name: &'static str, marker: u64, owned: &'static str) -> (Scripted, Script) {
    let script = Script::default();
    let driver = Scripted {
        name,
        marker,
        subscriptions: vec![Kind::new(PLAIN)],
        owned,
        script: Arc::clone(&script),
        step_inputs: Vec::new(),
        direct_inputs: Vec::new(),
    };
    (driver, script)
}

fn set_script(script: &Script, payloads: &[&'static [u8]]) {
    let mut guard = script
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    *guard = payloads.to_vec();
}

fn registry_with(drivers: Vec<Scripted>) -> PluginRegistry {
    let gate = Arc::new(ErasureContainmentGateV1::new_test_open());
    let mut registry = PluginRegistry::new().with_erasure_gate(gate);
    for driver in drivers {
        let plugin = OwnerPlugin {
            id: PluginId::new(),
            name: driver.name,
            owned: driver.owned,
        };
        registry
            .register_generated(&plugin, None, Some(Box::new(driver)))
            .test_ok();
    }
    registry.compose_non_participant_drivers().test_ok();
    registry
}

/// One Driver of the given step-level and draft-level declared inputs, with
/// one draft.
fn declaring_registry(
    step_inputs: Vec<DirectInputRefV1>,
    direct_inputs: Vec<DirectInputRefV1>,
) -> PluginRegistry {
    let (mut driver, script) = scripted("declaring", 1, "probe.out.declaring");
    driver.step_inputs = step_inputs;
    driver.direct_inputs = direct_inputs;
    set_script(&script, &[b"a"]);
    registry_with(vec![driver])
}

fn ids(registry: &PluginRegistry) -> Vec<PluginId> {
    registry.plugins.keys().copied().collect()
}

fn owner_of(registry: &PluginRegistry, index: usize) -> String {
    let owners = registry.factual_owner_ids();
    owners[index].1.as_str().to_owned()
}

fn staged(
    registry: &mut PluginRegistry,
    timeline: TimelineId,
    through: u64,
    events: &[Event],
) -> PendingStep {
    let cut = Seq::from_u64(through);
    registry
        .step_all_anchored_with_events(timeline, &root_ancestry(timeline), cut, events)
        .test_ok();
    registry.pending_step.take().test_ok()
}

fn revisions() -> PipelineSecurityRevisionsV1 {
    PipelineSecurityRevisionsV1::try_from_draft(PipelineSecurityRevisionsDraftV1 {
        authority: hash(10),
        consent: hash(11),
        capability: hash(12),
        delegation: hash(13),
        policy: hash(14),
        execution_profile: hash(15),
        erasure: hash(16),
    })
    .test_ok()
}

fn admission() -> ScheduledPassAdmissionV1 {
    ScheduledPassAdmissionV1 {
        attempt_id: PipelineAttemptIdV1::try_new([7; 16]).test_ok(),
        idempotency: AppendIdentity::new(
            AppendDedupKey::from_keyed_hash([8; 32]),
            AppendDedupScope::from_keyed_hash([9; 32]),
        ),
        provider_validation: PipelineEvidenceRefV1::try_new(hash(60)).test_ok(),
        security_revisions: revisions(),
        authority_grant: hash(61),
        commit_head: Seq::ZERO,
        commit_now_secs: 1,
    }
}

fn build(
    registry: &PluginRegistry,
    port: &FakePrefix,
    pending: &mut PendingStep,
    through: u64,
) -> Result<FactualTickDependenciesV1, RuntimeError> {
    let anchor = (Seq::from_u64(through), hash(62));
    let built = registry.scheduled_dependencies(port, pending, &admission(), anchor);
    // The record's nodes are paired positionally with the stepped Drivers and
    // the interned history contents, so a length mismatch would truncate.
    if let Ok(dependencies) = &built {
        let staged = &pending.factual;
        assert_eq!(staged.step_nodes.len(), pending.driver_ids.len());
        let history = count_owned_by(dependencies, "host.history");
        assert_eq!(staged.history_recorded.len(), history);
    }
    built
}

fn declaration_error(error: RuntimeError) -> FactualDependencyErrorV1 {
    match error {
        RuntimeError::DependencyDeclaration(declaration) => declaration,
        other => std::panic::resume_unwind(Box::new(format!("unexpected error: {other}"))),
    }
}

fn find<'a>(
    deps: &'a FactualTickDependenciesV1,
    owner: &str,
    ordinal: u32,
) -> &'a DependencyNodeRecordV1 {
    let nodes = deps.record().nodes();
    let found = nodes.iter().find(|node| {
        node.coordinate().owner_id() == owner && node.coordinate().output_ordinal() == ordinal
    });
    found.test_ok()
}

fn count_owned_by(deps: &FactualTickDependenciesV1, owner: &str) -> usize {
    let nodes = deps.record().nodes();
    nodes
        .iter()
        .filter(|node| node.coordinate().owner_id() == owner)
        .count()
}

fn digest_of(deps: &FactualTickDependenciesV1, owner: &str, ordinal: u32) -> Hash {
    find(deps, owner, ordinal).coordinate().artifact_digest()
}

#[test]
fn a_pass_declares_a_snapshot_a_step_per_driver_and_an_output_per_draft() {
    let (first, first_script) = scripted("first", 1, "probe.out.first");
    let (second, _) = scripted("second", 2, "probe.out.second");
    set_script(&first_script, &[b"a", b"b"]);
    let mut registry = registry_with(vec![first, second]);
    let timeline = TimelineId::new();
    let mut pending = staged(&mut registry, timeline, 0, &[]);

    assert_eq!(pending.factual.draft_ranges, [0..2, 2..2]);
    assert_eq!(pending.factual.prefix_digests, [None, None]);
    assert_eq!(pending.factual.direct_inputs.len(), 2);
    let deps = build(&registry, &FakePrefix::at(4), &mut pending, 0).test_ok();

    assert_eq!(deps.tick(), 5);
    let record = deps.record();
    let positions: Vec<(u32, u32)> = record
        .nodes()
        .iter()
        .map(|node| {
            let coordinate = node.coordinate();
            (coordinate.scheduler_position(), coordinate.output_ordinal())
        })
        .collect();
    assert_eq!(positions, [(0, 0), (1, 0), (1, 1), (1, 2), (2, 0)]);
    let bound: Vec<(u32, u32)> = deps
        .output_bindings()
        .iter()
        .map(|binding| (binding.draft_index, binding.node_index))
        .collect();
    assert_eq!(bound, [(0, 2), (1, 3)]);
    assert!(deps.event_nodes().is_empty());

    // The snapshot node binds the anchor's digest at the Tick's coordinate.
    let key = FactualNodeKeyV1 {
        tick: 5,
        scheduler_position: 0,
        owner: "host.observation",
        output_ordinal: 0,
        schema_id: FACTUAL_SNAPSHOT_SCHEMA_ID_V1,
    };
    let snapshot = factual_artifact_digest(timeline, key, hash(62));
    assert_eq!(digest_of(&deps, "host.observation", 0), snapshot);

    // A step node declares the snapshot node; an output node its step node.
    let (first_owner, second_owner) = (owner_of(&registry, 0), owner_of(&registry, 1));
    let step = find(&deps, &first_owner, 0);
    assert_eq!(step.input_digests(), [snapshot]);
    let output = find(&deps, &first_owner, 2);
    assert_eq!(
        output.input_digests(),
        [step.coordinate().artifact_digest()]
    );
    // A zero-draft Driver still has a step node.
    assert_eq!(find(&deps, &second_owner, 0).input_digests(), [snapshot]);

    let nodes: Vec<u32> = pending
        .factual
        .step_nodes
        .iter()
        .map(|node| node.coordinate().scheduler_position())
        .collect();
    assert_eq!(nodes, [1, 2]);
    assert!(pending.factual.history_recorded.is_empty());
}

#[test]
fn a_zero_draft_driver_has_a_step_node_and_may_declare_step_inputs() {
    let (mut quiet, _) = scripted("quiet", 1, "probe.out.quiet");
    quiet.step_inputs = vec![named(hash(57))];
    let mut registry = registry_with(vec![quiet]);
    let mut port = FakePrefix::at(4);
    let named_node = node("plugin:old", 1, 7, hash(57));
    port.digests.insert(hash(57), (named_node, None));
    let mut pending = staged(&mut registry, TimelineId::new(), 0, &[]);
    assert!(pending.staged_drafts.is_empty());
    let deps = build(&registry, &port, &mut pending, 0).test_ok();

    let owner = owner_of(&registry, 0);
    assert!(find(&deps, &owner, 0).input_digests().contains(&hash(57)));
    assert!(deps.output_bindings().is_empty());
}

#[test]
fn a_forwarded_event_without_a_node_is_recorded_once_as_an_ingress_node() {
    let (first, first_script) = scripted("first", 1, "probe.out.first");
    let (second, _) = scripted("second", 2, "probe.out.second");
    set_script(&first_script, &[b"a"]);
    let mut registry = registry_with(vec![first, second]);
    let mut pending = staged(&mut registry, TimelineId::new(), THROUGH, &plain_events(3));
    let deps = build(&registry, &FakePrefix::at(0), &mut pending, THROUGH).test_ok();

    assert_eq!(deps.tick(), 1);
    let seqs: Vec<u64> = deps
        .event_nodes()
        .iter()
        .map(|binding| binding.seq.as_u64())
        .collect();
    assert_eq!(seqs, [1, 2, 3]);
    let schema = factual_event_schema_id(PLAIN);
    for ordinal in 0..3 {
        let ingress = find(&deps, "host.ingress", ordinal);
        assert_eq!(ingress.coordinate().schema_id(), schema);
        assert_eq!(ingress.class(), RecordedDependencyClassV1::ExogenousFrozen);
        assert!(ingress.input_digests().is_empty());
    }
    // Both Drivers declare the three ingress nodes once, beside the snapshot.
    for index in 0..2 {
        let owner = owner_of(&registry, index);
        assert_eq!(find(&deps, &owner, 0).input_digests().len(), 4);
    }
    assert_eq!(count_owned_by(&deps, "host.ingress"), 3);
}

#[test]
fn a_forwarded_event_with_a_recorded_node_is_declared_by_that_node() {
    let (first, first_script) = scripted("first", 1, "probe.out.first");
    set_script(&first_script, &[b"a"]);
    let mut registry = registry_with(vec![first]);
    let mut pending = staged(&mut registry, TimelineId::new(), THROUGH, &plain_events(3));
    let mut port = FakePrefix::at(4);
    let schema = factual_event_schema_id(PLAIN);
    port.events
        .insert(2, node("plugin:old", 1, schema, hash(40)));
    let deps = build(&registry, &port, &mut pending, THROUGH).test_ok();

    let seqs: Vec<u64> = deps
        .event_nodes()
        .iter()
        .map(|binding| binding.seq.as_u64())
        .collect();
    assert_eq!(seqs, [1, 3]);
    let owner = owner_of(&registry, 0);
    assert!(find(&deps, &owner, 0).input_digests().contains(&hash(40)));
}

#[test]
fn a_forwarded_event_resolving_to_a_presentation_only_node_is_refused() {
    let (first, first_script) = scripted("first", 1, "probe.out.first");
    set_script(&first_script, &[b"a"]);
    let mut registry = registry_with(vec![first]);
    let mut pending = staged(&mut registry, TimelineId::new(), THROUGH, &plain_events(3));
    let mut port = FakePrefix::at(4);
    port.events.insert(1, presentation_node(hash(41)));

    let error = declaration_error(build(&registry, &port, &mut pending, THROUGH).test_err());
    assert_eq!(error, FactualDependencyErrorV1::ClassRuleViolation);
}

/// Build the one Driver's pass over `events` and return the builder's answer.
fn declared(
    step_inputs: Vec<DirectInputRefV1>,
    port: &FakePrefix,
    events: &[Event],
    through: u64,
) -> Result<FactualTickDependenciesV1, FactualDependencyErrorV1> {
    let mut registry = declaring_registry(step_inputs, Vec::new());
    let mut pending = staged(&mut registry, TimelineId::new(), through, events);
    build(&registry, port, &mut pending, through).map_err(declaration_error)
}

#[test]
fn an_event_above_the_cut_is_undeclarable() {
    let port = FakePrefix::at(4);
    let result = declared(vec![committed_event(3)], &port, &plain_events(2), 2);
    assert_eq!(result.test_err(), FactualDependencyErrorV1::UndeclarableInput);
}

#[test]
fn an_event_of_a_type_the_driver_did_not_subscribe_to_is_undeclarable() {
    let events = [event(1, PLAIN), event(2, OTHER)];
    let result = declared(vec![committed_event(2)], &FakePrefix::at(4), &events, 2);
    assert_eq!(result.test_err(), FactualDependencyErrorV1::UndeclarableInput);
}

#[test]
fn an_event_the_pass_does_not_show_is_undeclarable() {
    let consent = pos_core::EVENT_TYPE_CONSENT_GRANTED_V1;
    let events = [event(1, PLAIN), event(2, consent)];
    let result = declared(vec![committed_event(2)], &FakePrefix::at(4), &events, 2);
    assert_eq!(result.test_err(), FactualDependencyErrorV1::UndeclarableInput);
}

#[test]
fn an_event_nobody_knows_is_unresolved_and_a_known_node_is_judged_by_its_schema() {
    let events = plain_events(1);
    let unknown = declared(vec![committed_event(2)], &FakePrefix::at(4), &events, 2);
    assert_eq!(unknown.test_err(), FactualDependencyErrorV1::UnresolvedInput);

    // The pass never saw Event 2, but the prefix records a node for it.
    let mut port = FakePrefix::at(4);
    let foreign = factual_event_schema_id(OTHER);
    let foreign_node = node("plugin:old", 1, foreign, hash(42));
    port.events.insert(2, foreign_node);
    let result = declared(vec![committed_event(2)], &port, &events, 2);
    assert_eq!(result.test_err(), FactualDependencyErrorV1::UndeclarableInput);

    let own = factual_event_schema_id(PLAIN);
    let own_node = node("plugin:old", 1, own, hash(42));
    port.events.insert(2, own_node);
    let deps = declared(vec![committed_event(2)], &port, &events, 2).test_ok();
    // Event 2 is declared by its recorded node; only Event 1 gets an ingress node.
    let seqs: Vec<u64> = deps
        .event_nodes()
        .iter()
        .map(|binding| binding.seq.as_u64())
        .collect();
    assert_eq!(seqs, [1]);
}

/// The owner of the only Driver step node of a pass.
fn owner_of_only_driver(deps: &FactualTickDependenciesV1) -> String {
    let nodes = deps.record().nodes();
    let steps = nodes
        .iter()
        .filter(|node| node.coordinate().scheduler_position() == 1);
    let mut owners = steps.map(|node| node.coordinate().owner_id().to_owned());
    owners.next().test_ok()
}

#[test]
fn a_declared_digest_must_resolve_and_an_event_node_must_be_readable() {
    let events = plain_events(2);
    let missing = declared(vec![named(hash(50))], &FakePrefix::at(4), &events, 6);
    assert_eq!(missing.test_err(), FactualDependencyErrorV1::UnresolvedInput);

    let own = factual_event_schema_id(PLAIN);
    let foreign = factual_event_schema_id(OTHER);
    let mut port = FakePrefix::at(4);
    // A node that stands for no Event is declarable by digest.
    port.digests
        .insert(hash(51), (node("plugin:old", 1, 7, hash(51)), None));
    assert!(declared(vec![named(hash(51))], &port, &events, 6).is_ok());
    // An Event node above the cut, or of a type the Driver did not subscribe
    // to, is not; Event 5 is below the cut and the pass never saw it.
    let beyond = (node("plugin:old", 2, own, hash(52)), Some(Seq::from_u64(9)));
    port.digests.insert(hash(52), beyond);
    let wrong = (
        node("plugin:old", 3, foreign, hash(53)),
        Some(Seq::from_u64(5)),
    );
    port.digests.insert(hash(53), wrong);
    let readable = (node("plugin:old", 4, own, hash(54)), Some(Seq::from_u64(5)));
    port.digests.insert(hash(54), readable);
    for refused in [hash(52), hash(53)] {
        let result = declared(vec![named(refused)], &port, &events, 6);
        assert_eq!(result.test_err(), FactualDependencyErrorV1::UndeclarableInput);
    }
    assert!(declared(vec![named(hash(54))], &port, &events, 6).is_ok());
}

#[test]
fn a_declared_presentation_only_node_breaks_the_class_rule() {
    let mut port = FakePrefix::at(4);
    port.digests
        .insert(hash(55), (presentation_node(hash(55)), None));
    let result = declared(vec![named(hash(55))], &port, &plain_events(1), 1);
    assert_eq!(result.test_err(), FactualDependencyErrorV1::ClassRuleViolation);
}

/// The failure of a pass whose one draft declares `inputs`, which must come
/// before the builder records any node for the commit.
fn draft_level_failure(
    inputs: Vec<DirectInputRefV1>,
    port: &FakePrefix,
    events: &[Event],
    through: u64,
) -> FactualDependencyErrorV1 {
    let mut registry = declaring_registry(Vec::new(), inputs);
    let mut pending = staged(&mut registry, TimelineId::new(), through, events);
    let result = build(&registry, port, &mut pending, through);
    assert!(pending.factual.step_nodes.is_empty());
    assert!(pending.factual.history_recorded.is_empty());
    declaration_error(err(result))
}

#[test]
fn a_draft_level_event_above_the_cut_is_undeclarable() {
    let inputs = vec![committed_event(3)];
    let error = draft_level_failure(inputs, &FakePrefix::at(4), &plain_events(2), 2);
    assert_eq!(error, FactualDependencyErrorV1::UndeclarableInput);
}

#[test]
fn a_draft_level_event_nobody_knows_is_unresolved() {
    let inputs = vec![committed_event(2)];
    let error = draft_level_failure(inputs, &FakePrefix::at(4), &plain_events(1), 2);
    assert_eq!(error, FactualDependencyErrorV1::UnresolvedInput);
}

#[test]
fn a_draft_level_presentation_only_node_breaks_the_class_rule() {
    let mut port = FakePrefix::at(4);
    port.digests
        .insert(hash(55), (presentation_node(hash(55)), None));
    let inputs = vec![named(hash(55))];
    let error = draft_level_failure(inputs, &port, &plain_events(1), 1);
    assert_eq!(error, FactualDependencyErrorV1::ClassRuleViolation);
}

/// The first `count` of `digests`, each declared by digest.
fn named_digests(digests: &[Hash], count: usize) -> Vec<DirectInputRefV1> {
    digests[..count].iter().copied().map(named).collect()
}

#[test]
fn declared_inputs_are_capped_per_step_node_and_per_output_before_any_read() {
    let digests: Vec<Hash> = (1..=4_096).map(indexed_hash).collect();
    let mut port = FakePrefix::at(4);
    for digest in &digests {
        port.digests
            .insert(*digest, (node("plugin:old", 1, 7, *digest), None));
    }
    let untouched = FakePrefix::at(4);

    // 255 step-level inputs fit: they and the snapshot node make 256.
    let at_cap = named_digests(&digests, MAX_STEP_INPUTS_PER_DRIVER_V1);
    let mut registry = declaring_registry(at_cap, Vec::new());
    let mut pending = staged(&mut registry, TimelineId::new(), 0, &[]);
    let deps = build(&registry, &port, &mut pending, 0).test_ok();
    let owner = owner_of(&registry, 0);
    assert_eq!(find(&deps, &owner, 0).input_digests().len(), 256);
    // One more is refused, and nothing is read.
    let over = named_digests(&digests, MAX_STEP_INPUTS_PER_DRIVER_V1 + 1);
    let mut registry = declaring_registry(over, Vec::new());
    let mut pending = staged(&mut registry, TimelineId::new(), 0, &[]);
    let result = build(&registry, &untouched, &mut pending, 0);
    assert_eq!(declaration_error(result.test_err()), bounds_error());

    // 4,095 draft-level inputs and the step node make a full output node.
    let at_cap = named_digests(&digests, MAX_OUTPUT_DIRECT_INPUTS_V1);
    let mut registry = declaring_registry(Vec::new(), at_cap);
    let mut pending = staged(&mut registry, TimelineId::new(), 0, &[]);
    let deps = build(&registry, &port, &mut pending, 0).test_ok();
    let owner = owner_of(&registry, 0);
    assert_eq!(find(&deps, &owner, 1).input_digests().len(), 4_096);
    let over = named_digests(&digests, MAX_OUTPUT_DIRECT_INPUTS_V1 + 1);
    let mut registry = declaring_registry(Vec::new(), over);
    let mut pending = staged(&mut registry, TimelineId::new(), 0, &[]);
    let result = build(&registry, &untouched, &mut pending, 0);
    assert_eq!(declaration_error(result.test_err()), bounds_error());
    assert_eq!(untouched.chain_reads.get(), 0);
}

const fn bounds_error() -> FactualDependencyErrorV1 {
    FactualDependencyErrorV1::Record(pos_core::CounterfactualDependencyErrorV1::FieldOutOfBounds)
}

#[test]
fn equal_inputs_declared_in_several_ways_are_declared_once() {
    let mut port = FakePrefix::at(4);
    port.digests
        .insert(hash(56), (node("plugin:old", 1, 7, hash(56)), None));
    // Event 1 is forwarded and declared; the digest is declared twice.
    let inputs = vec![named(hash(56)), named(hash(56)), committed_event(1)];
    let deps = declared(inputs, &port, &plain_events(1), 1).test_ok();
    let owner = owner_of_only_driver(&deps);
    // The snapshot node, the one ingress node and the one named node.
    assert_eq!(find(&deps, &owner, 0).input_digests().len(), 3);
}

#[test]
fn the_chain_edge_is_looked_up_once_and_then_retained_by_the_commit() {
    let (first, first_script) = scripted("first", 1, "probe.out.first");
    set_script(&first_script, &[b"a"]);
    let mut registry = registry_with(vec![first]);
    let owner = owner_of(&registry, 0);
    let mut port = FakePrefix::at(4);
    port.chains
        .insert(owner.clone(), node(&owner, 0, 1, hash(43)));
    let timeline = TimelineId::new();
    let mut pending = staged(&mut registry, timeline, 0, &[]);
    let deps = build(&registry, &port, &mut pending, 0).test_ok();

    assert_eq!(port.chain_reads.get(), 1);
    assert!(find(&deps, &owner, 0).input_digests().contains(&hash(43)));
    let step = digest_of(&deps, &owner, 0);
    registry.commit_pending_step(pending);
    let id = ids(&registry)[0];
    let recorded = match &registry.plugins[&id].chain {
        StepChainV1::Recorded { node } => node.coordinate().artifact_digest(),
        StepChainV1::Lookup => std::panic::resume_unwind(Box::new("chain not recorded")),
    };
    assert_eq!(recorded, step);

    // The next Tick declares the retained node and reads nothing.
    let later = FakePrefix::at(5);
    let mut pending = staged(&mut registry, timeline, 0, &[]);
    let deps = build(&registry, &later, &mut pending, 0).test_ok();
    assert_eq!(later.chain_reads.get(), 0);
    assert!(find(&deps, &owner, 0).input_digests().contains(&step));
}

#[test]
fn events_consumed_in_an_empty_pass_are_carried_into_the_next_recorded_step() {
    let (first, first_script) = scripted("first", 1, "probe.out.first");
    let mut registry = registry_with(vec![first]);
    let timeline = TimelineId::new();
    let events = plain_events(2);
    let pending = staged(&mut registry, timeline, 2, &events);
    assert!(pending.factual.step_nodes.is_empty());
    registry.commit_pending_step(pending);
    let id = ids(&registry)[0];
    let kinds: Vec<(u64, &str)> = registry.plugins[&id]
        .pass_state
        .carried
        .iter()
        .map(|(seq, (_, kind))| (seq.as_u64(), kind.as_str()))
        .collect();
    assert_eq!(kinds, [(1, PLAIN), (2, PLAIN)]);

    set_script(&first_script, &[b"a"]);
    let mut pending = staged(&mut registry, timeline, 2, &events);
    let deps = build(&registry, &FakePrefix::at(0), &mut pending, 2).test_ok();
    let seqs: Vec<u64> = deps
        .event_nodes()
        .iter()
        .map(|binding| binding.seq.as_u64())
        .collect();
    assert_eq!(seqs, [1, 2]);
    registry.commit_pending_step(pending);
    assert!(registry.plugins[&id].pass_state.carried.is_empty());
}

#[test]
fn a_carried_event_the_store_lacks_is_recorded_as_an_ingress_node_of_its_own_type() {
    let (first, first_script) = scripted("first", 1, "probe.out.first");
    set_script(&first_script, &[b"a"]);
    let mut registry = registry_with(vec![first]);
    let id = ids(&registry)[0];
    registry.plugins[&id]
        .pass_state
        .carried
        .insert(Seq::from_u64(1), (payload_hash(1), Kind::new(PLAIN)));
    let mut pending = staged(&mut registry, TimelineId::new(), 0, &[]);
    let deps = build(&registry, &FakePrefix::at(0), &mut pending, 0).test_ok();
    let seqs: Vec<u64> = deps
        .event_nodes()
        .iter()
        .map(|binding| binding.seq.as_u64())
        .collect();
    assert_eq!(seqs, [1]);
}

const fn restore_segment(timeline: TimelineId, through: u64) -> [TimelineHistorySegment; 1] {
    [TimelineHistorySegment::new(
        timeline,
        Seq::from_u64(through),
    )]
}

#[test]
fn a_restored_history_node_is_recorded_once_and_declared_by_the_driver_stepped_later() {
    let (first, first_script) = scripted("first", 1, "probe.out.first");
    let (second, second_script) = scripted("second", 1_000, "probe.out.second");
    set_script(&first_script, &[b"a"]);
    let mut registry = registry_with(vec![first, second]);
    let timeline = TimelineId::new();
    let events = plain_events(3);
    registry
        .restore_driver_state(&restore_segment(timeline, 3), &events)
        .test_ok();
    let (first_id, second_id) = (ids(&registry)[0], ids(&registry)[1]);
    let content = registry.plugins[&first_id]
        .pass_state
        .history
        .pending_content()
        .test_ok();
    assert_eq!(
        registry.plugins[&second_id]
            .pass_state
            .history
            .pending_content(),
        Some(content)
    );

    // Only the first Driver is due: the second stepped at 100 and waits 1,000.
    registry.plugins[&second_id].last_tick = Some(100);
    let ancestry = root_ancestry(timeline);
    let cut = Seq::from_u64(3);
    registry
        .tick_cadenced_anchored_with_events(timeline, &ancestry, 101, cut, &events)
        .test_ok();
    let mut pending = registry.pending_step.take().test_ok();
    let deps = build(&registry, &FakePrefix::at(0), &mut pending, 3).test_ok();

    assert_eq!(count_owned_by(&deps, "host.history"), 1);
    let recorded = digest_of(&deps, "host.history", 0);
    let first_owner = owner_of(&registry, 0);
    assert!(find(&deps, &first_owner, 0)
        .input_digests()
        .contains(&recorded));
    assert_eq!(pending.factual.history_recorded.len(), 1);
    assert_eq!(pending.factual.history_recorded[0].0, content);
    registry.commit_pending_step(pending);

    // The first Driver consumed its history; the second declares the node.
    assert_eq!(registry.plugins[&first_id].pass_state.history, HistoryInputV1::None);
    let kept = match &registry.plugins[&second_id].pass_state.history {
        HistoryInputV1::Recorded { content, node } => {
            (*content, node.coordinate().artifact_digest())
        }
        other => std::panic::resume_unwind(Box::new(format!("not recorded: {other:?}"))),
    };
    assert_eq!(kept, (content, recorded));

    // When the second Driver steps, no second history node is recorded.
    set_script(&second_script, &[b"b"]);
    let mut later = FakePrefix::at(1);
    let second_owner = owner_of(&registry, 1);
    let chain = node_at(&second_owner, hash(44));
    later.chains.insert(second_owner.clone(), chain);
    registry
        .tick_cadenced_anchored_with_events(timeline, &ancestry, 5_000, cut, &events)
        .test_ok();
    let mut pending = registry.pending_step.take().test_ok();
    let deps = build(&registry, &later, &mut pending, 3).test_ok();
    assert_eq!(count_owned_by(&deps, "host.history"), 0);
    assert!(find(&deps, &second_owner, 0)
        .input_digests()
        .contains(&recorded));
}

fn node_at(owner: &str, digest: Hash) -> DependencyNodeRecordV1 {
    node(owner, 0, 1, digest)
}

#[test]
fn an_empty_pass_leaves_history_and_chain_untouched() {
    let (first, _) = scripted("first", 1, "probe.out.first");
    let mut registry = registry_with(vec![first]);
    let timeline = TimelineId::new();
    let events = plain_events(3);
    registry
        .restore_driver_state(&restore_segment(timeline, 3), &events)
        .test_ok();
    let id = ids(&registry)[0];
    let before = registry.plugins[&id].pass_state.history.clone();

    let pending = staged(&mut registry, timeline, 3, &events);
    registry.commit_pending_step(pending);

    assert_eq!(registry.plugins[&id].pass_state.history, before);
    assert_eq!(registry.plugins[&id].chain, StepChainV1::Lookup);
}

#[test]
fn a_restore_resets_the_chain_and_the_carried_set() {
    let (first, _) = scripted("first", 1, "probe.out.first");
    let mut registry = registry_with(vec![first]);
    let timeline = TimelineId::new();
    let events = plain_events(2);
    let pending = staged(&mut registry, timeline, 2, &events);
    registry.commit_pending_step(pending);
    let id = ids(&registry)[0];
    let recorded = FactualPriorNodeV1::from_record(&node("plugin:old", 0, 1, hash(45)));
    registry.plugins[&id].chain = StepChainV1::Recorded { node: recorded };
    assert_eq!(registry.plugins[&id].pass_state.carried.len(), 2);

    registry
        .restore_driver_state(&restore_segment(timeline, 2), &events)
        .test_ok();
    assert_eq!(registry.plugins[&id].chain, StepChainV1::Lookup);
    assert!(registry.plugins[&id].pass_state.carried.is_empty());
}

#[test]
fn a_pending_history_node_is_recorded_by_the_next_recorded_step() {
    let (first, first_script) = scripted("first", 1, "probe.out.first");
    set_script(&first_script, &[b"a"]);
    let mut registry = registry_with(vec![first]);
    let id = ids(&registry)[0];
    registry.plugins[&id].pass_state.history = HistoryInputV1::Pending { content: hash(46) };
    let mut pending = staged(&mut registry, TimelineId::new(), 0, &[]);
    let deps = build(&registry, &FakePrefix::at(0), &mut pending, 0).test_ok();
    assert_eq!(count_owned_by(&deps, "host.history"), 1);
    assert_eq!(pending.factual.history_recorded[0].0, hash(46));
}

#[test]
fn a_verified_prefix_node_is_shared_by_equal_digests() {
    let (first, first_script) = scripted("first", 1, "probe.out.first");
    let (second, _) = scripted("second", 2, "probe.out.second");
    set_script(&first_script, &[b"a"]);
    let mut registry = registry_with(vec![first, second]);
    let mut pending = staged(&mut registry, TimelineId::new(), 0, &[]);
    pending.factual.prefix_digests = vec![Some(hash(47)), Some(hash(47))];
    let deps = build(&registry, &FakePrefix::at(0), &mut pending, 0).test_ok();
    assert_eq!(count_owned_by(&deps, "host.prefix"), 1);
    let prefix = digest_of(&deps, "host.prefix", 0);
    for index in 0..2 {
        let owner = owner_of(&registry, index);
        assert!(find(&deps, &owner, 0).input_digests().contains(&prefix));
    }

    pending.factual.prefix_digests = vec![Some(hash(47)), Some(hash(48))];
    let deps = build(&registry, &FakePrefix::at(0), &mut pending, 0).test_ok();
    assert_eq!(count_owned_by(&deps, "host.prefix"), 2);
}

#[test]
fn the_verified_prefix_digest_covers_the_events_the_driver_is_handed() {
    let (first, _) = scripted("first", 1, "probe.out.first");
    let mut registry = registry_with(vec![first]);
    let id = ids(&registry)[0];
    let events = [event(1, PLAIN), event(2, OTHER), event(3, PLAIN)];
    let cut = PassCut {
        observed_through: Seq::from_u64(3),
        events: &events,
    };
    let operation = OperationContext::Public;
    assert_eq!(
        verified_prefix_digest(&registry.plugins[&id], cut, &operation),
        None
    );

    registry.plugins[&id]
        .event_observation
        .verified_prefix_required = true;
    let handed = [
        FactualEventRefV1 {
            seq: Seq::from_u64(1),
            payload_hash: payload_hash(1),
        },
        FactualEventRefV1 {
            seq: Seq::from_u64(3),
            payload_hash: payload_hash(3),
        },
    ];
    let expected = factual_verified_prefix_content_digest(Seq::from_u64(3), &handed);
    let digest = verified_prefix_digest(&registry.plugins[&id], cut, &operation);
    assert_eq!(digest, Some(expected));
}

#[test]
fn a_closureless_driver_steps_with_the_zero_policy_identity() {
    let (staging, staging_script) = scripted("staging", 1, "probe.out.staging");
    set_script(&staging_script, &[b"a"]);
    let mut registry = registry_with(vec![staging]);
    let (bare, _) = scripted("bare", 2, "probe.out.bare");
    registry.register_driver(Box::new(bare)).test_ok();
    registry.compose_non_participant_drivers().test_ok();
    let timeline = TimelineId::new();
    let mut pending = staged(&mut registry, timeline, 0, &[]);
    let deps = build(&registry, &FakePrefix::at(0), &mut pending, 0).test_ok();

    let owner = owner_of(&registry, 1);
    let provenance = find(&deps, &owner, 0).provenance_digest();
    // The preimage of R3.3.3, written out independently of the helper.
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"PiglorOS.FactualNodeProvenance.v1");
    hasher.update(&[0]);
    hasher.update(&timeline.inner().to_bytes());
    hasher.update(&[7; 16]);
    hasher.update(&[2]);
    hasher.update(hash(60).as_bytes());
    hasher.update(hash(61).as_bytes());
    hasher.update(&u64::try_from(owner.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(owner.as_bytes());
    hasher.update(Hash::zero().as_bytes());
    let rule = b"pos.factual.driver-step";
    hasher.update(&u64::try_from(rule.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(rule);
    hasher.update(&1_u32.to_be_bytes());
    let expected = Hash::from_bytes(*hasher.finalize().as_bytes());
    assert_eq!(provenance, expected);
    // The draft-staging Driver carries its closure's identity instead.
    let staging_owner = owner_of(&registry, 0);
    assert_ne!(find(&deps, &staging_owner, 0).provenance_digest(), expected);
}

/// A port that records the bases offered to the store and answers from a
/// script.
struct RecordingPort {
    prefix: FakePrefix,
    bases: Vec<PipelineAdmissionBasisV1>,
    receipt_for: Option<PipelineAdmissionBasisV1>,
    lose_outcome: bool,
}

impl RecordingPort {
    fn new(lose_outcome: bool, receipt_for: Option<PipelineAdmissionBasisV1>) -> Self {
        Self {
            prefix: FakePrefix::at(2),
            bases: Vec::new(),
            receipt_for,
            lose_outcome,
        }
    }
}

fn committed_receipt(basis: &PipelineAdmissionBasisV1) -> PipelineCommitReceiptV1 {
    let events: Vec<Event> = (1_u64..)
        .zip(basis.batch().drafts())
        .map(|(seq, draft)| Event {
            id: EventId::new(),
            entity: draft.entity,
            event_type: draft.event_type.clone(),
            payload: draft.payload.clone(),
            wall_time: WallTime::from_micros(100 + seq),
            seq: Seq::from_u64(seq),
            causation_id: draft.causation_id,
            correlation_id: draft.correlation_id,
            schema_version: draft.schema_version,
            signature: None,
            signature_identity: None,
            origin: None,
            payload_hash: payload_hash(seq),
        })
        .collect();
    let timeline = basis.attempt().observation().timeline_id();
    let receipt = PipelineCommitReceiptV1::try_from_committed_events(basis, timeline, &events);
    receipt.test_ok()
}

impl PipelineAdmissionPortV1 for RecordingPort {
    fn admit_pipeline_batch(
        &mut self,
        basis: &PipelineAdmissionBasisV1,
    ) -> Result<PipelineOutcomeV1, CoreError> {
        self.bases.push(basis.clone());
        if self.lose_outcome {
            return Err(CoreError::StorageOutcomeUnknown("lost".to_owned()));
        }
        let receipt = committed_receipt(self.receipt_for.as_ref().test_ok());
        Ok(PipelineOutcomeV1::RecoveredDuplicate(receipt))
    }

    fn purge_expired_pipeline_receipts_bounded(
        &mut self,
        _: NonZeroUsize,
    ) -> Result<pos_core::store::PurgeOutcome, CoreError> {
        Err(CoreError::Storage("unused".to_owned()))
    }

    fn lookup_pipeline_receipt(
        &mut self,
        _: TimelineId,
        _: AppendDedupKey,
        _: PipelineAttemptIdV1,
    ) -> Result<PipelineReceiptLookupV1, CoreError> {
        Ok(PipelineReceiptLookupV1::Absent)
    }
}

impl FactualPrefixReadPortV1 for RecordingPort {
    fn last_committed_factual_tick(
        &self,
        timeline: TimelineId,
    ) -> Result<FactualHeadV1, CoreError> {
        self.prefix.last_committed_factual_tick(timeline)
    }

    fn cut_tick_at(&self, timeline: TimelineId, seq: Seq) -> Result<FactualCutV1, CoreError> {
        self.prefix.cut_tick_at(timeline, seq)
    }

    fn nodes_for_committed_events(
        &self,
        timeline: TimelineId,
        seqs: &[Seq],
    ) -> Result<Vec<Option<DependencyNodeRecordV1>>, CoreError> {
        self.prefix.nodes_for_committed_events(timeline, seqs)
    }

    fn nodes_by_digest(
        &self,
        timeline: TimelineId,
        digests: &[Hash],
    ) -> Result<Vec<Option<pos_core::factual_dependency::BoundFactualNodeV1>>, CoreError> {
        self.prefix.nodes_by_digest(timeline, digests)
    }

    fn last_step_node(
        &self,
        timeline: TimelineId,
        owner: &FactualOwnerIdV1,
    ) -> Result<Option<DependencyNodeRecordV1>, CoreError> {
        self.prefix.last_step_node(timeline, owner)
    }

    fn factual_set_counts(&self, timeline: TimelineId) -> Result<RecordedSetCountsV1, CoreError> {
        self.prefix.factual_set_counts(timeline)
    }
}

#[test]
fn an_in_doubt_pass_recovered_later_settles_the_state_like_a_first_commit() {
    let (first, first_script) = scripted("first", 1, "probe.out.first");
    let (second, _) = scripted("second", 1_000, "probe.out.second");
    set_script(&first_script, &[b"a"]);
    let mut registry = registry_with(vec![first, second]);
    let timeline = TimelineId::new();
    let events = plain_events(3);
    registry
        .restore_driver_state(&restore_segment(timeline, 3), &events)
        .test_ok();
    let (first_id, second_id) = (ids(&registry)[0], ids(&registry)[1]);
    registry.plugins[&second_id].last_tick = Some(100);
    let ancestry = root_ancestry(timeline);
    let cut = Seq::from_u64(3);
    registry
        .tick_cadenced_anchored_with_events(timeline, &ancestry, 101, cut, &events)
        .test_ok();

    // The first attempt loses its outcome: the pass stays in doubt, state intact.
    let mut lost = RecordingPort::new(true, None);
    let error = registry
        .admit_scheduled_pass(&mut lost, &admission())
        .test_err();
    assert!(matches!(
        error,
        RuntimeError::Store(CoreError::StorageOutcomeUnknown(_))
    ));
    assert_eq!(lost.bases.len(), 1);
    let basis = lost.bases[0].clone();
    assert_eq!(basis.dependencies().tick(), 3);
    assert!(registry.plugins[&second_id]
        .pass_state
        .history
        .pending_content()
        .is_some());
    assert_eq!(registry.plugins[&first_id].chain, StepChainV1::Lookup);

    // Recovery resubmits the retained basis and applies the retained lists.
    let mut admitting = RecordingPort::new(false, Some(basis.clone()));
    let receipt = registry.recover_scheduled_pass(&mut admitting).test_ok();
    assert!(receipt.is_some());
    assert_eq!(admitting.bases[0].digest(), basis.digest());
    assert_eq!(registry.plugins[&first_id].pass_state.history, HistoryInputV1::None);
    assert!(matches!(
        registry.plugins[&first_id].chain,
        StepChainV1::Recorded { .. }
    ));
    assert!(matches!(
        registry.plugins[&second_id].pass_state.history,
        HistoryInputV1::Recorded { .. }
    ));
}

#[test]
fn a_builder_failure_aborts_the_pass_before_any_store_call() {
    let steps: Vec<DirectInputRefV1> = (1..=256).map(indexed_hash).map(named).collect();
    let mut registry = declaring_registry(steps, Vec::new());
    let mut port = RecordingPort::new(false, None);
    let timeline = TimelineId::new();
    let ancestry = root_ancestry(timeline);
    registry
        .step_all_anchored_with_events(timeline, &ancestry, Seq::ZERO, &[])
        .test_ok();
    let error = registry
        .admit_scheduled_pass(&mut port, &admission())
        .test_err();
    assert_eq!(declaration_error(error), bounds_error());
    assert!(port.bases.is_empty());
    assert!(registry.pending_step.is_none());
}

#[test]
fn a_failing_read_of_the_prefix_is_the_stores_error() {
    for read in ["head", "events", "digests", "chain"] {
        let (first, first_script) = scripted("first", 1, "probe.out.first");
        set_script(&first_script, &[b"a"]);
        let mut registry = registry_with(vec![first]);
        let mut pending = staged(&mut registry, TimelineId::new(), 0, &[]);
        let result = build(&registry, &FakePrefix::failing(read), &mut pending, 0);
        let error = result.test_err();
        assert!(
            matches!(error, RuntimeError::Store(CoreError::Storage(_))),
            "{read}: {error}"
        );
    }
}

/// A prior node of the given Tick, as a Driver retains it.
fn prior_at_tick(tick: u64, digest: Hash) -> FactualPriorNodeV1 {
    let coordinate = ok(DependencyNodeCoordinateV1::try_new(
        tick,
        1,
        "plugin:old".to_owned(),
        0,
        1,
        digest,
    ));
    FactualPriorNodeV1::new(coordinate, ENDOGENOUS)
}

/// The Tick the next pass declares over a store whose head is `head`.
fn declared_tick_at(registry: &mut PluginRegistry, timeline: TimelineId, head: u64) -> u64 {
    let mut pending = staged(registry, timeline, 0, &[]);
    let port = FakePrefix::at(head);
    ok(build(registry, &port, &mut pending, 0)).tick()
}

#[test]
fn the_factual_tick_follows_the_later_of_the_head_and_the_retained_nodes() {
    assert_eq!(ok(next_factual_tick(0, 0)), 1);
    assert_eq!(ok(next_factual_tick(4, 0)), 5);
    assert_eq!(ok(next_factual_tick(0, 3)), 4);
    assert_eq!(ok(next_factual_tick(5, 3)), 6);
    let exhausted = err(next_factual_tick(u64::MAX, 0));
    assert_eq!(exhausted, FactualDependencyErrorV1::SetExhausted);
    let retained = err(next_factual_tick(0, u64::MAX));
    assert_eq!(retained, FactualDependencyErrorV1::SetExhausted);
}

#[test]
fn the_declared_tick_follows_the_prior_nodes_the_stepped_drivers_retain() {
    let (first, first_script) = scripted("first", 1, "probe.out.first");
    set_script(&first_script, &[b"a"]);
    let mut registry = registry_with(vec![first]);
    let id = ids(&registry)[0];
    let timeline = TimelineId::new();

    // Nothing retained and no rows: the first Tick.
    assert_eq!(declared_tick_at(&mut registry, timeline, 0), 1);

    // A retained step node of Tick 7 puts the next Tick after it, however
    // low the store's head is.
    let retained = prior_at_tick(7, hash(72));
    registry.plugins[&id].chain = StepChainV1::Recorded { node: retained };
    assert_eq!(declared_tick_at(&mut registry, timeline, 2), 8);
    // A head past the retained node wins.
    assert_eq!(declared_tick_at(&mut registry, timeline, 9), 10);

    // A recorded history node counts as well.
    let content = hash(73);
    let node = prior_at_tick(12, content);
    registry.plugins[&id].pass_state.history = HistoryInputV1::Recorded { content, node };
    assert_eq!(declared_tick_at(&mut registry, timeline, 2), 13);
}

#[test]
fn a_digest_of_an_unseen_subject_controlled_event_is_undeclarable() {
    // The pass never saw Event 5, and a schema ID cannot show whether this
    // pass's consent hides an Event of a consent-sensitive type.
    let sensitive = "model.fit";
    let schema = factual_event_schema_id(sensitive);
    let bound = (
        node("plugin:old", 1, schema, hash(71)),
        Some(Seq::from_u64(5)),
    );
    let mut port = FakePrefix::at(4);
    port.digests.insert(hash(71), bound);

    let mut registry = declaring_registry(vec![named(hash(71))], Vec::new());
    let id = ids(&registry)[0];
    let observation = &mut registry.plugins[&id].event_observation;
    observation.event_subscriptions.push(Kind::new(sensitive));
    let mut pending = staged(&mut registry, TimelineId::new(), 6, &plain_events(1));
    let result = build(&registry, &port, &mut pending, 6);
    let error = declaration_error(err(result));
    assert_eq!(error, FactualDependencyErrorV1::UndeclarableInput);
}

#[test]
fn a_driver_without_subscriptions_cannot_declare_an_event_it_never_saw() {
    let mut registry = declaring_registry(vec![committed_event(2)], Vec::new());
    let id = ids(&registry)[0];
    registry.plugins[&id]
        .event_observation
        .event_subscriptions
        .clear();
    let mut pending = staged(&mut registry, TimelineId::new(), 2, &plain_events(1));
    let result = build(&registry, &FakePrefix::at(0), &mut pending, 2);
    let error = declaration_error(err(result));
    assert_eq!(error, FactualDependencyErrorV1::UndeclarableInput);
}

/// An authorized view forwards no Event and `gather_facts` is not called, so
/// the pass holds no fact. A committed Event it declares is still refused as
/// undeclarable, not unresolved: an authorized Driver subscribes to nothing, and
/// the readability check runs before the lookup of facts (R3.4.7, R3.6.2).
#[test]
fn an_authorized_pass_refuses_a_declared_committed_event_as_undeclarable() {
    let mut registry = declaring_registry(vec![committed_event(1)], Vec::new());
    let id = ids(&registry)[0];
    registry.plugins[&id]
        .event_observation
        .event_subscriptions
        .clear();
    let mut pending = staged(&mut registry, TimelineId::new(), 0, &[]);
    assert!(pending.factual.event_facts.is_empty());
    let result = build(&registry, &FakePrefix::at(0), &mut pending, 2);
    let error = declaration_error(err(result));
    assert_eq!(error, FactualDependencyErrorV1::UndeclarableInput);
}

/// One Driver that reads the full verified prefix and emits `payloads`.
fn verified_prefix_registry(payloads: &[&'static [u8]]) -> PluginRegistry {
    let (driver, script) = scripted("first", 1, "probe.out.first");
    set_script(&script, payloads);
    let mut registry = registry_with(vec![driver]);
    let id = ids(&registry)[0];
    registry.plugins[&id]
        .event_observation
        .verified_prefix_required = true;
    registry
}

#[test]
fn the_verified_prefix_digest_is_gathered_only_for_a_pass_that_stages_a_draft() {
    let mut quiet = verified_prefix_registry(&[]);
    let pending = staged(&mut quiet, TimelineId::new(), 2, &plain_events(2));
    assert!(pending.factual.prefix_digests.is_empty());

    let mut busy = verified_prefix_registry(&[b"a"]);
    let pending = staged(&mut busy, TimelineId::new(), 2, &plain_events(2));
    assert!(pending.factual.prefix_digests[0].is_some());
}
