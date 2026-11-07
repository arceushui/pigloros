//! The factual history of a Fork run and the Fork cut from it.
//!
//! Three Drivers, `alpha`, `beta` and `gamma`, commit every factual Tick
//! through scheduled admission on a fresh `MemoryStore`; each emits one draft
//! per Tick. The history also appends one external input before its first
//! Tick and before every Tick after the cut.
//!
//! The history is deterministic: the factual and Fork Timeline ids are
//! [`super::FACTUAL_TIMELINE_ID_V1`] and [`super::FORK_TIMELINE_ID_V1`], and
//! the pipeline attempt, idempotency and validation identities of each pass
//! are digests of the Timeline and the Tick instead of fresh ULIDs. Event ids
//! and wall times stay store-assigned; no recorded node and no exported
//! artifact covers them.

use std::sync::Arc;

use pos_core::{
    fork_ancestry, pipeline_draft_vector_digest_v1, AppendDedupKey, AppendDedupScope,
    AppendIdentity, CanonicalBytes, Capability, DependencyNodeRecordV1, EntityId,
    ErasureContainmentGateV1, EventDraft, EventStore, FactualHeadV1, FactualOwnerIdV1,
    FactualPrefixReadPortV1, Hash, Kind, PipelineAttemptIdV1, PipelineEvidenceRefV1, Plugin,
    PluginId, Seq, SeqRange, TimelineId, TimelineMeta,
};
use pos_runtime::{
    Driver, LocalScheduledAdmissionHostV1, ObservationView, PluginRegistry, RuntimeError,
    ScheduledPassAdmissionV1, StepOutput,
};
use pos_store::memory::MemoryStore;
use ulid::Ulid;

/// Event type of the external input the factual history appends.
const INPUT_EVENT_TYPE: &str = "agent.forkrun.input";
/// Event type of the lead Driver, the one the Intervention assigns.
pub(super) const LEAD_EVENT_TYPE: &str = "agent.forkrun.alpha";
const DOMAIN: &[u8] = b"PiglorOS.ForkArtifactsFactualPass.v1\0";

/// One Driver of the factual history and the Plugin that owns its Event type.
struct DriverSpecV1 {
    plugin: u128,
    name: &'static str,
    event_type: &'static str,
}

/// The Drivers in schedule order. None subscribes to anything.
const DRIVERS: [DriverSpecV1; 3] = [
    DriverSpecV1 {
        plugin: 0x6201,
        name: "alpha",
        event_type: LEAD_EVENT_TYPE,
    },
    DriverSpecV1 {
        plugin: 0x6202,
        name: "beta",
        event_type: "agent.forkrun.beta",
    },
    DriverSpecV1 {
        plugin: 0x6203,
        name: "gamma",
        event_type: "agent.forkrun.gamma",
    },
];

struct HistoryPlugin {
    id: PluginId,
    name: &'static str,
    event_type: &'static str,
}

impl Plugin for HistoryPlugin {
    fn id(&self) -> PluginId {
        self.id
    }

    fn name(&self) -> &'static str {
        self.name
    }

    fn capability(&self) -> Capability {
        Capability {
            owned_event_types: vec![Kind::new(self.event_type)],
            owned_entity_kinds: Vec::new(),
            has_driver: true,
            has_reducer: false,
        }
    }
}

/// A Driver that emits one draft of its Event type every Tick.
struct HistoryDriver {
    name: &'static str,
    event_type: &'static str,
}

impl Driver for HistoryDriver {
    fn name(&self) -> &'static str {
        self.name
    }

    fn step(&mut self, _: TimelineId, _: ObservationView<'_>) -> Result<StepOutput, RuntimeError> {
        Ok(StepOutput::new(vec![EventDraft::new(
            EntityId::from_ulid(Ulid::from(0x07_u128)),
            Kind::new(self.event_type),
            CanonicalBytes::from_static(b"factual"),
        )]))
    }
}

/// One Driver of the Fork: the names it was registered under, its owner,
/// scheduler position and Event type.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct LaneV1 {
    pub(super) plugin_name: &'static str,
    pub(super) driver_name: &'static str,
    pub(super) owner: String,
    pub(super) position: u32,
    pub(super) event_type: &'static str,
}

/// One registered Driver: its Plugin ID, the names its Plugin and Driver
/// report, and its Event type.
struct RegisteredV1 {
    plugin: PluginId,
    plugin_name: &'static str,
    driver_name: &'static str,
    event_type: &'static str,
}

/// What the Fork reads of the recorded prefix at its cut.
pub(super) struct PrefixV1 {
    /// The last step node of every Driver, in schedule order.
    pub(super) steps: Vec<DependencyNodeRecordV1>,
    /// The nodes of the cut Tick's Events, which the first provisional Tick
    /// is forwarded.
    pub(super) forwarded: Vec<DependencyNodeRecordV1>,
}

/// The recorded factual history, its cut and the Fork created at the cut.
pub(super) struct FactualV1 {
    pub(super) store: MemoryStore,
    pub(super) root: TimelineId,
    pub(super) fork: TimelineId,
    pub(super) cut: FactualHeadV1,
    /// The factual head after the suffix.
    pub(super) head: FactualHeadV1,
    pub(super) lanes: Vec<LaneV1>,
    pub(super) prefix: PrefixV1,
}

/// Record `cut_tick` factual Ticks, then one Tick per `factual_suffix` input
/// after the cut, and create the Fork at the cut. `None` when the host cannot
/// record the history or the cut has no recorded step of every Driver.
pub(super) fn record(
    root: TimelineId,
    fork: TimelineId,
    cut_tick: u64,
    factual_suffix: &[Vec<u8>],
) -> Option<FactualV1> {
    let gate = Arc::new(ErasureContainmentGateV1::new_test_open());
    let mut store = MemoryStore::new();
    let bound = store.bind_erasure_gate(Arc::clone(&gate)).ok();
    let created = bound.and_then(|()| {
        store
            .create_timeline_with_meta(TimelineMeta {
                id: root,
                ..TimelineMeta::root("factual")
            })
            .ok()
    });
    created
        .and_then(|_| registry(gate))
        .and_then(|(mut registry, registered)| {
            let input = append_input(&mut store, root, b"input");
            let prefix = input.and_then(|()| {
                (1..=cut_tick)
                    .try_for_each(|tick| commit_pass(&mut store, &mut registry, root, tick))
            });
            let cut = prefix.and_then(|()| store.last_committed_factual_tick(root).ok());
            let suffix = cut.and_then(|cut| {
                factual_suffix
                    .iter()
                    .zip(cut.tick + 1..)
                    .try_for_each(|(payload, tick)| {
                        append_input(&mut store, root, payload)
                            .and_then(|()| commit_pass(&mut store, &mut registry, root, tick))
                    })
                    .and_then(|()| store.last_committed_factual_tick(root).ok())
                    .map(|head| (cut, head))
            });
            suffix.zip(owners(&registry, registered))
        })
        .and_then(|((cut, head), owners)| {
            let meta = TimelineMeta {
                id: fork,
                ..TimelineMeta::forked_from(root, cut.last_seq, "fork")
            };
            let forked = store.create_timeline_with_meta(meta).ok();
            forked
                .and_then(|_| resolve_prefix(&store, fork, cut, owners))
                .map(|(lanes, prefix)| FactualV1 {
                    store,
                    root,
                    fork,
                    cut,
                    head,
                    lanes,
                    prefix,
                })
        })
}

/// A registry of the Drivers under their Plugin IDs, bound to `gate`, and
/// every registered Driver in schedule order.
fn registry(gate: Arc<ErasureContainmentGateV1>) -> Option<(PluginRegistry, Vec<RegisteredV1>)> {
    let mut registry = PluginRegistry::new().with_erasure_gate(gate);
    let registered: Option<Vec<RegisteredV1>> = DRIVERS
        .iter()
        .map(|spec| {
            let plugin = HistoryPlugin {
                id: PluginId::from_ulid(Ulid::from(spec.plugin)),
                name: spec.name,
                event_type: spec.event_type,
            };
            let driver = HistoryDriver {
                name: spec.name,
                event_type: spec.event_type,
            };
            let entry = RegisteredV1 {
                plugin: plugin.id(),
                plugin_name: plugin.name(),
                driver_name: driver.name(),
                event_type: spec.event_type,
            };
            registry
                .register_generated(&plugin, None, Some(Box::new(driver)))
                .ok()
                .map(|()| entry)
        })
        .collect();
    registered
        .filter(|_| registry.compose_non_participant_drivers().is_ok())
        .map(|registered| (registry, registered))
}

/// The factual owner ID of every registered Driver, in schedule order.
fn owners(
    registry: &PluginRegistry,
    registered: Vec<RegisteredV1>,
) -> Option<Vec<(FactualOwnerIdV1, RegisteredV1)>> {
    let owners = registry.factual_owner_ids();
    registered
        .into_iter()
        .map(|entry| {
            owners
                .iter()
                .find(|(id, _)| *id == entry.plugin)
                .map(|(_, owner)| (owner.clone(), entry))
        })
        .collect()
}

fn append_input(store: &mut MemoryStore, timeline: TimelineId, payload: &[u8]) -> Option<()> {
    let draft = EventDraft::new(
        EntityId::from_ulid(Ulid::from(0x20_u128)),
        Kind::new(INPUT_EVENT_TYPE),
        CanonicalBytes::from_vec(payload.to_vec()),
    );
    store.append(timeline, &[draft]).ok().map(|_| ())
}

/// Step every Driver against the committed prefix and admit the pass as
/// factual Tick `tick`.
fn commit_pass(
    store: &mut MemoryStore,
    registry: &mut PluginRegistry,
    timeline: TimelineId,
    tick: u64,
) -> Option<()> {
    LocalScheduledAdmissionHostV1::shared()
        .ok()
        .and_then(|host| {
            let revisions = host.observe(registry, store, timeline).ok();
            let events = store.read(timeline, SeqRange::all()).ok();
            let ancestry = fork_ancestry(&*store, timeline).ok();
            let head = store.logical_head(timeline).ok();
            revisions.zip(events).zip(ancestry.zip(head)).and_then(
                |((revisions, events), (ancestry, head))| {
                    registry
                        .step_all_anchored_with_events(timeline, &ancestry, head, &events)
                        .ok()
                        .and_then(|drafts| {
                            admission(
                                host.authority_grant(),
                                revisions,
                                timeline,
                                tick,
                                head,
                                &drafts,
                            )
                        })
                },
            )
        })
        .and_then(|admission| registry.admit_scheduled_pass(store, &admission).ok())
        .map(|_| ())
}

/// The scheduled admission of factual Tick `tick`, whose attempt,
/// idempotency and validation identities are digests of the Timeline, the
/// Tick and the staged drafts.
fn admission(
    authority_grant: Hash,
    security_revisions: pos_core::PipelineSecurityRevisionsV1,
    timeline: TimelineId,
    tick: u64,
    commit_head: Seq,
    drafts: &[EventDraft],
) -> Option<ScheduledPassAdmissionV1> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(DOMAIN);
    hasher.update(&timeline.inner().to_bytes());
    hasher.update(&tick.to_be_bytes());
    let attempt = *hasher.finalize().as_bytes();
    let mut validation = blake3::Hasher::new();
    validation.update(DOMAIN);
    validation.update(&attempt);
    validation.update(pipeline_draft_vector_digest_v1(drafts).as_bytes());
    let validation = Hash::from_bytes(*validation.finalize().as_bytes());
    let scope = *blake3::Hasher::new()
        .update(DOMAIN)
        .update(&timeline.inner().to_bytes())
        .finalize()
        .as_bytes();
    let attempt_id = attempt[..16]
        .try_into()
        .ok()
        .and_then(|bytes| PipelineAttemptIdV1::try_new(bytes).ok());
    let provider_validation = PipelineEvidenceRefV1::try_new(validation).ok();
    attempt_id
        .zip(provider_validation)
        .map(
            |(attempt_id, provider_validation)| ScheduledPassAdmissionV1 {
                attempt_id,
                idempotency: AppendIdentity::new(
                    AppendDedupKey::from_keyed_hash(attempt),
                    AppendDedupScope::from_keyed_hash(scope),
                ),
                provider_validation,
                security_revisions,
                authority_grant,
                commit_head,
                commit_now_secs: 0,
            },
        )
}

/// The lanes of the Fork and what it reads of the recorded prefix: the last
/// step node of every Driver and the nodes of the cut Tick's Events, one per
/// Driver.
fn resolve_prefix(
    store: &MemoryStore,
    fork: TimelineId,
    cut: FactualHeadV1,
    owners: Vec<(FactualOwnerIdV1, RegisteredV1)>,
) -> Option<(Vec<LaneV1>, PrefixV1)> {
    let steps: Option<Vec<DependencyNodeRecordV1>> = owners
        .iter()
        .map(|(owner, _)| store.last_step_node(fork, owner).ok().flatten())
        .collect();
    steps.and_then(|steps| {
        let mut seqs: Vec<Seq> = (1..=cut.last_seq.as_u64())
            .rev()
            .take(steps.len())
            .map(Seq::from_u64)
            .collect();
        seqs.reverse();
        let forwarded = store
            .nodes_for_committed_events(fork, &seqs)
            .ok()
            .and_then(|nodes| nodes.into_iter().collect::<Option<Vec<_>>>());
        let lanes = owners
            .into_iter()
            .zip(&steps)
            .map(|((owner, entry), step)| LaneV1 {
                plugin_name: entry.plugin_name,
                driver_name: entry.driver_name,
                owner: owner.as_str().to_owned(),
                position: step.coordinate().scheduler_position(),
                event_type: entry.event_type,
            })
            .collect();
        forwarded.map(|forwarded| (lanes, PrefixV1 { steps, forwarded }))
    })
}
