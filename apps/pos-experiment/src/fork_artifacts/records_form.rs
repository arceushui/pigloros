//! The records form of the ADR-064 provisional Ticks (owner answer Q7).
//!
//! Until the ADR-064 R7 steps form lands (#1201 to #1204), no Driver
//! declares its provisional Ticks. The host declares them instead: it builds
//! the provisional dependency graph of every recomputation Tick from the
//! first Tick through the plan horizon, and [`RecordsFormStagerV1`] stages,
//! for each Tick, one draft per Driver with the nodes and edges the graph
//! assigns to that Tick. Per Q7 a run staged this way is a genuine ADR-064
//! Fork execution; it is re-run when #1204 lands.
//!
//! # The provisional graph
//!
//! Every Driver lane declares, per Tick, a step node at
//! `(tick, position, owner, 0)` with the step schema and one output node at
//! `(tick, position, owner, 1)` with its Event schema. A step node consumes
//! the lane's previous step node (the last recorded one at the first Tick),
//! the nodes of the cut Tick's Events (first Tick only) and every output node
//! of the previous Tick. An output node consumes its step node and, for the
//! lead lane at the first Tick, the `InterventionAssigned` root of the
//! plan's Intervention. Every provisional node other than that root is
//! `EndogenousRecomputed` and stands for its lane's staged draft: its content
//! digest is the draft's output content digest.
//!
//! An edge from the Intervention root carries the Intervention's consent
//! decision digest; every other edge carries the host's authority grant.
//! The Intervention root carries the Intervention's provenance digest; every
//! other provisional node and every edge carries the run's provenance
//! digest.

use std::collections::BTreeMap;

use pos_conformance::counterfactual::dependency::{
    DependencyClassificationRuleV1, DependencyTickRangeV1, InputDependencyV1,
};
use pos_conformance::counterfactual::plan::CounterfactualPlanV1;
use pos_conformance::{DependencyClassV1, DependencyNodeV1};
use pos_core::{
    factual_artifact_digest, factual_event_schema_id, factual_output_content_digest,
    CanonicalBytes, DependencyEdgeRecordV1, DependencyNodeCoordinateV1, DependencyNodeRecordV1,
    EntityId, EventDraft, FactualNodeKeyV1, Hash, Kind, RecordedDependencyClassV1,
    RecordedNodeOriginV1, TimelineId, FACTUAL_STEP_SCHEMA_ID_V1,
};
use pos_runtime::counterfactual::coordinator::{
    CounterfactualDeclaringTickStagerV1, CounterfactualStagedTickV1, CounterfactualTickFailureV1,
    CounterfactualTickInputsV1,
};
use pos_time::counterfactual::dependency_graph::{
    DependencyGraphNodeOriginV1, DependencyGraphNodeV1,
};
use ulid::Ulid;

use super::history::{LaneV1, PrefixV1};

/// Owner of the `InterventionAssigned` root node.
const INTERVENTION_OWNER: &str = "intervention";
/// Classification rule of every provisional edge.
const CLASSIFICATION_RULE: &str = "classify.v1";

/// The provisional nodes and edges of one generation, in canonical order.
pub(super) struct ProvisionalGraphV1 {
    pub(super) nodes: Vec<DependencyGraphNodeV1>,
    pub(super) edges: Vec<InputDependencyV1>,
}

/// The identities every provisional record carries.
#[derive(Clone, Copy)]
pub(super) struct BindingsV1 {
    /// The authorization of every edge that leaves an endogenous node.
    pub(super) authorization: [u8; 32],
    /// The provenance of every provisional node and edge.
    pub(super) provenance: [u8; 32],
}

/// The draft of every lane at `tick`, in lane order.
fn staged_drafts(tick: u64, lanes: &[LaneV1]) -> Vec<EventDraft> {
    lanes
        .iter()
        .map(|lane| {
            EventDraft::new(
                EntityId::from_ulid(Ulid::from(0x09_u128)),
                Kind::new(lane.event_type),
                CanonicalBytes::from_vec(tick.to_be_bytes().to_vec()),
            )
        })
        .collect()
}

/// A node a provisional node can consume.
#[derive(Clone)]
struct SourceV1 {
    node: DependencyNodeV1,
    class: DependencyClassV1,
}

/// The source a recorded node row stands for. The two class enums share
/// one wire-code table.
fn committed_source(record: &DependencyNodeRecordV1) -> Option<SourceV1> {
    let coordinate = record.coordinate();
    DependencyClassV1::from_wire_code(u64::from(record.class().code())).map(|class| SourceV1 {
        node: DependencyNodeV1 {
            tick: coordinate.tick(),
            scheduler_position: coordinate.scheduler_position(),
            owner_id: coordinate.owner_id().to_owned(),
            output_ordinal: coordinate.output_ordinal(),
            schema_id: coordinate.schema_id(),
            artifact_digest: *coordinate.artifact_digest().as_bytes(),
        },
        class,
    })
}

/// The graph under construction.
struct BuilderV1<'a> {
    fork: TimelineId,
    bindings: BindingsV1,
    consent: [u8; 32],
    lanes: &'a [LaneV1],
    nodes: Vec<DependencyGraphNodeV1>,
    edges: Vec<InputDependencyV1>,
}

impl BuilderV1<'_> {
    fn edge(&self, consumer: &DependencyNodeV1, source: &SourceV1) -> InputDependencyV1 {
        let authorization_digest = if source.class == DependencyClassV1::InterventionAssigned {
            self.consent
        } else {
            self.bindings.authorization
        };
        InputDependencyV1 {
            consumer: consumer.clone(),
            source: source.node.clone(),
            dependency_class: source.class,
            tick_range: DependencyTickRangeV1 {
                first_tick: source.node.tick,
                last_tick: consumer.tick,
            },
            authorization_digest,
            classification_rule: DependencyClassificationRuleV1 {
                rule_id: CLASSIFICATION_RULE.to_owned(),
                rule_version: 1,
            },
            provenance_digest: self.bindings.provenance,
        }
    }

    /// Declare an `EndogenousRecomputed` node at `key` standing for `draft`
    /// and consuming `inputs`.
    fn endogenous(
        &mut self,
        key: FactualNodeKeyV1<'_>,
        draft: &EventDraft,
        inputs: &[SourceV1],
    ) -> SourceV1 {
        let content = factual_output_content_digest(draft);
        let node = DependencyNodeV1 {
            tick: key.tick,
            scheduler_position: key.scheduler_position,
            owner_id: key.owner.to_owned(),
            output_ordinal: key.output_ordinal,
            schema_id: key.schema_id,
            artifact_digest: *factual_artifact_digest(self.fork, key, content).as_bytes(),
        };
        let unique: BTreeMap<[u8; 32], &SourceV1> = inputs
            .iter()
            .map(|source| (source.node.artifact_digest, source))
            .collect();
        let edges: Vec<InputDependencyV1> = unique
            .values()
            .map(|source| self.edge(&node, source))
            .collect();
        self.edges.extend(edges);
        self.nodes.push(DependencyGraphNodeV1 {
            node: node.clone(),
            class: DependencyClassV1::EndogenousRecomputed,
            origin: DependencyGraphNodeOriginV1::Provisional,
            input_digests: unique.keys().copied().collect(),
            provenance_digest: self.bindings.provenance,
        });
        SourceV1 {
            node,
            class: DependencyClassV1::EndogenousRecomputed,
        }
    }

    /// Declare the step and output node of every lane at `tick`. Returns the
    /// step nodes and output nodes of the Tick.
    fn tick(
        &mut self,
        tick: u64,
        (steps, outputs): (&[SourceV1], &[SourceV1]),
        (forwarded, seed): (&[SourceV1], &[SourceV1]),
    ) -> (Vec<SourceV1>, Vec<SourceV1>) {
        let drafts = staged_drafts(tick, self.lanes);
        let lanes = self.lanes;
        lanes
            .iter()
            .zip(steps)
            .zip(&drafts)
            .enumerate()
            .map(|(index, ((lane, previous), draft))| {
                let key = FactualNodeKeyV1 {
                    tick,
                    scheduler_position: lane.position,
                    owner: &lane.owner,
                    output_ordinal: 0,
                    schema_id: FACTUAL_STEP_SCHEMA_ID_V1,
                };
                let mut consumed = vec![previous.clone()];
                consumed.extend_from_slice(forwarded);
                consumed.extend_from_slice(outputs);
                let step = self.endogenous(key, draft, &consumed);
                let mut consumed = vec![step.clone()];
                if index == 0 {
                    consumed.extend_from_slice(seed);
                }
                let key = FactualNodeKeyV1 {
                    tick,
                    scheduler_position: lane.position,
                    owner: &lane.owner,
                    output_ordinal: 1,
                    schema_id: factual_event_schema_id(lane.event_type),
                };
                (step, self.endogenous(key, draft, &consumed))
            })
            .unzip()
    }
}

/// The provisional graph of every Tick of `plan`, from its first Tick
/// through its horizon. `None` when the plan has no Intervention, its
/// Intervention has no digest, or a prefix node has no dependency class.
pub(super) fn provisional_graph(
    fork: TimelineId,
    lanes: &[LaneV1],
    prefix: &PrefixV1,
    plan: &CounterfactualPlanV1,
    bindings: BindingsV1,
) -> Option<ProvisionalGraphV1> {
    let forwarded: Option<Vec<SourceV1>> = prefix.forwarded.iter().map(committed_source).collect();
    let steps: Option<Vec<SourceV1>> = prefix.steps.iter().map(committed_source).collect();
    let intervention = plan.interventions.first();
    let digest = intervention.and_then(|intervention| intervention.digest().ok());
    let inputs = forwarded.zip(steps).zip(intervention.zip(digest));
    inputs.map(|((forwarded, steps), (intervention, digest))| {
        let root = DependencyNodeV1 {
            tick: intervention.effective_tick,
            scheduler_position: 0,
            owner_id: INTERVENTION_OWNER.to_owned(),
            output_ordinal: 0,
            schema_id: intervention.target_schema_id,
            artifact_digest: digest,
        };
        let mut builder = BuilderV1 {
            fork,
            bindings,
            consent: intervention.consent_decision_digest,
            lanes,
            nodes: vec![DependencyGraphNodeV1 {
                node: root.clone(),
                class: DependencyClassV1::InterventionAssigned,
                origin: DependencyGraphNodeOriginV1::Provisional,
                input_digests: Vec::new(),
                provenance_digest: intervention.provenance_digest,
            }],
            edges: Vec::new(),
        };
        let seed = [SourceV1 {
            node: root,
            class: DependencyClassV1::InterventionAssigned,
        }];
        let first = (steps, Vec::new());
        (plan.first_tick..=plan.horizon_tick).fold(first, |(steps, outputs), tick| {
            let given: (&[SourceV1], &[SourceV1]) = if tick == plan.first_tick {
                (&forwarded, &seed)
            } else {
                (&[], &[])
            };
            builder.tick(tick, (&steps, &outputs), given)
        });
        let BuilderV1 {
            mut nodes,
            mut edges,
            ..
        } = builder;
        nodes.sort_by(|left, right| left.node.coordinate_key().cmp(&right.node.coordinate_key()));
        edges.sort_by(InputDependencyV1::order_cmp);
        ProvisionalGraphV1 { nodes, edges }
    })
}

fn coordinate(node: &DependencyNodeV1) -> Option<DependencyNodeCoordinateV1> {
    DependencyNodeCoordinateV1::try_new(
        node.tick,
        node.scheduler_position,
        node.owner_id.clone(),
        node.output_ordinal,
        node.schema_id,
        Hash::from_bytes(node.artifact_digest),
    )
    .ok()
}

fn node_record(node: &DependencyGraphNodeV1) -> Option<DependencyNodeRecordV1> {
    let class = RecordedDependencyClassV1::from_code(u64::from(node.class.wire_code())).ok();
    coordinate(&node.node)
        .zip(class)
        .and_then(|(coordinate, class)| {
            let inputs = node.input_digests.iter().copied().map(Hash::from_bytes);
            DependencyNodeRecordV1::try_new(
                coordinate,
                class,
                RecordedNodeOriginV1::Provisional,
                inputs.collect(),
                Hash::from_bytes(node.provenance_digest),
            )
            .ok()
        })
}

fn edge_record(edge: &InputDependencyV1) -> Option<DependencyEdgeRecordV1> {
    let bytes = edge.to_canonical_cbor().ok();
    bytes
        .zip(coordinate(&edge.consumer))
        .and_then(|(bytes, consumer)| {
            let source = Hash::from_bytes(edge.source.artifact_digest);
            DependencyEdgeRecordV1::try_from_canonical(bytes, consumer, source).ok()
        })
}

/// The nodes and edges one Tick declares.
type DeclarationV1 = (Vec<DependencyNodeRecordV1>, Vec<DependencyEdgeRecordV1>);

/// The stager of the records form: for every Tick it stages one draft per
/// lane and declares the nodes and edges the provisional graph assigns to
/// the Tick.
pub(super) struct RecordsFormStagerV1 {
    declarations: BTreeMap<u64, DeclarationV1>,
    lanes: Vec<LaneV1>,
}

impl RecordsFormStagerV1 {
    /// Assign every node of `graph` to the record of its own Tick, the
    /// Intervention root included because it is effective at the first
    /// Tick, and every edge to its consumer's record, in canonical row
    /// order. `None` when a node or edge has no record.
    pub(super) fn new(graph: &ProvisionalGraphV1, lanes: Vec<LaneV1>) -> Option<Self> {
        let ticks: BTreeMap<[u8; 32], u64> = graph
            .nodes
            .iter()
            .map(|node| (node.node.artifact_digest, node.node.tick))
            .collect();
        let mut declarations: BTreeMap<u64, DeclarationV1> = BTreeMap::new();
        let nodes = graph.nodes.iter().try_for_each(|node| {
            node_record(node).map(|record| {
                declarations
                    .entry(node.node.tick)
                    .or_default()
                    .0
                    .push(record);
            })
        });
        let edges = nodes.and_then(|()| {
            graph.edges.iter().try_for_each(|edge| {
                let tick = ticks.get(&edge.consumer.artifact_digest).copied();
                tick.zip(edge_record(edge)).map(|(tick, record)| {
                    declarations.entry(tick).or_default().1.push(record);
                })
            })
        });
        edges.map(|()| {
            for (nodes, edges) in declarations.values_mut() {
                nodes.sort_by(|left, right| {
                    let left = left.coordinate().position_key();
                    left.cmp(&right.coordinate().position_key())
                });
                edges.sort_by(DependencyEdgeRecordV1::order_cmp);
            }
            Self {
                declarations,
                lanes,
            }
        })
    }
}

impl CounterfactualDeclaringTickStagerV1 for RecordsFormStagerV1 {
    fn stage_tick_with_dependencies(
        &mut self,
        inputs: &CounterfactualTickInputsV1<'_>,
    ) -> Result<CounterfactualStagedTickV1, CounterfactualTickFailureV1> {
        let tick = inputs.tick();
        let (nodes, edges) = self.declarations.get(&tick).cloned().unwrap_or_default();
        Ok(CounterfactualStagedTickV1 {
            drafts: staged_drafts(tick, &self.lanes),
            nodes,
            edges,
        })
    }
}
