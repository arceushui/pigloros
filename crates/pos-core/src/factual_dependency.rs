//! ADR-064 Revision 3 factual Tick dependency contract.
//!
//! One admitted pipeline batch is one factual Tick. This module is the
//! `pos-core` half of the factual producer: the declaration that travels in
//! the admission basis ([`FactualTickDependenciesV1`]), the pure assembly of
//! that declaration ([`assemble_factual_tick`]), every digest and identifier
//! the declaration binds, the closed classification rules, the budget
//! constants, the host-local errors, and the read port the host uses to
//! resolve a Timeline's recorded prefix ([`FactualPrefixReadPortV1`]).
//!
//! It names no backend type, reads no store, and changes no store behaviour: the
//! registry builder and the adapters that consume it land in later slices.
//!
//! The two `PipelineOutcomeV1` outcomes `InvalidDependencyDeclaration` and
//! `DependencySetExhausted` are produced by the store in a later slice (Redmine
//! #603 and the slices 7b, 8, and 9 tickets #604 and #605). Here they are
//! covered by direct tests of the outcome mappers.
//!
//! # Derivations
//!
//! Every domain-tagged preimage is a domain tag, a zero byte, and fixed-width
//! big-endian fields. Variable-length fields (owners, rule IDs) carry a
//! big-endian `u64` length prefix; the ADR amendment of R3.3.3 records this
//! prefix width. [`factual_step_content_digest`] and
//! [`factual_ingress_content_digest`] are deliberately untagged: the ADR
//! (R3.3.2) defines them as a plain digest of their fields.
//!
//! - Owner IDs ([`factual_owner_id`]) are `plugin:` and the lowercase hex of a
//!   BLAKE3 digest; a slotted and a slotless entry use different preimage tags
//!   so they never collide.
//! - Artifact digests ([`factual_artifact_digest`]) bind the recording
//!   Timeline and the full node coordinate to a content digest.
//! - Provenance digests ([`factual_provenance_digest`]) bind the attempt, the
//!   ingress, the evidence, the authority grant, the responsible owner, the
//!   policy identity, and the classification rule.
//! - Content digests cover the Event draft, the Driver step, the late-bound
//!   ingress Event, the verified prefix, and the chained consumed history.
//! - A Tick's edge provenance is the provenance digest of its consumer node;
//!   its authorization digest is the fence's authority grant.

use std::collections::BTreeMap;

use crate::output_policy::OutputAuthorityV1;
use crate::pipeline::ingress_tag;
use crate::{
    encode_bytes, encode_hash, encode_head, pipeline_draft_vector_digest_v1, CoreError,
    CounterfactualDependencyErrorV1, DependencyEdgeRecordV1, DependencyNodeCoordinateV1,
    DependencyNodeRecordV1, EventDraft, Hash, PipelineAdmissionPortV1, PipelineAttemptIdV1,
    PipelineIngressV1, RecordedDependencyClassV1, RecordedNodeOriginV1, RecordedSetCountsV1, Seq,
    TickDependencyRecordV1, TimelineId, MAX_RECORDED_DEPENDENCY_EDGES_V1,
    MAX_RECORDED_DEPENDENCY_NODES_V1, MAX_TICK_DEPENDENCY_EDGES_V1, MAX_TICK_DEPENDENCY_NODES_V1,
};

/// Maximum Event inputs of one step node: forwarded this pass plus carried.
pub const MAX_FORWARDED_EVENTS_PER_DRIVER_V1: usize = 3_837;
/// Maximum Driver-declared step-level inputs of one step node.
pub const MAX_STEP_INPUTS_PER_DRIVER_V1: usize = 255;
/// Maximum Driver-declared draft-specific inputs of one output node.
pub const MAX_OUTPUT_DIRECT_INPUTS_V1: usize = 4_095;
/// Maximum host-derived non-Event inputs of one step node: the snapshot,
/// step-chain, verified-prefix, and history nodes.
pub const MAX_HOST_DERIVED_STEP_INPUTS_V1: usize = 4;
/// Maximum distinct Events a pass declares individually on its step nodes.
pub const MAX_FACTUAL_FORWARDED_EVENTS_PER_TICK_V1: usize = 16_384;
/// Maximum Event edges, summed over the Drivers, one pass declares.
pub const MAX_FACTUAL_FORWARDED_EDGES_PER_TICK_V1: usize = 131_072;
/// Schema ID of a Driver step node.
pub const FACTUAL_STEP_SCHEMA_ID_V1: u32 = 1;
/// Schema ID of an observation-snapshot node.
pub const FACTUAL_SNAPSHOT_SCHEMA_ID_V1: u32 = 2;
/// Schema ID of a verified-prefix node.
pub const FACTUAL_PREFIX_SCHEMA_ID_V1: u32 = 3;
/// Schema ID of a consumed-history node.
pub const FACTUAL_HISTORY_SCHEMA_ID_V1: u32 = 4;

const OWNER_DOMAIN: &[u8] = b"PiglorOS.FactualOwner.v1";
const ARTIFACT_DOMAIN: &[u8] = b"PiglorOS.FactualDependencyNode.v1";
const SCHEMA_DOMAIN: &[u8] = b"PiglorOS.FactualEventSchema.v1";
const PROVENANCE_DOMAIN: &[u8] = b"PiglorOS.FactualNodeProvenance.v1";
const PREFIX_DOMAIN: &[u8] = b"PiglorOS.FactualVerifiedPrefix.v1";
const HISTORY_DOMAIN: &[u8] = b"PiglorOS.FactualConsumedHistory.v1";
const BUNDLE_DOMAIN: &[u8] = b"PiglorOS.DependencyClassificationBundle.v1";
const TICK_DEPENDENCIES_DOMAIN: &[u8] = b"PiglorOS.FactualTickDependencies.v1";
const RECORD_DOMAIN: &[u8] = b"PiglorOS.FactualTickRecord.v1";
const SLOTTED_OWNER_TAG: u8 = 1;
const SLOTLESS_OWNER_TAG: u8 = 2;
const CBOR_UNSIGNED: u8 = 0;
const CBOR_TEXT: u8 = 3;
const CBOR_ARRAY: u8 = 4;
const EDGE_ARRAY_HEAD: u8 = 0x89;
const NODE_ARRAY_HEAD: u8 = 0x86;
const EDGE_MAGIC: &[u8] = b"IDP1";

/// Closed host-local failures of building or checking a factual declaration.
///
/// These names sit outside the closed ADR-064 error set. They expose only a
/// safe code, never a payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum FactualDependencyErrorV1 {
    /// A declared input names something the Driver could not have read.
    ///
    /// The registry builder of a later slice (Redmine #603, slice 7b)
    /// produces it; this slice only defines the closed name.
    #[error("a declared dependency input is not one the Driver could have read")]
    UndeclarableInput,
    /// A declared input resolves to no recorded node.
    #[error("a declared dependency input resolves to no recorded node")]
    UnresolvedInput,
    /// An input would break a classification rule.
    #[error("a dependency input breaks a classification rule")]
    ClassRuleViolation,
    /// The Timeline's recorded set cannot take another worst-case Tick.
    #[error("the recorded dependency set of the Timeline is exhausted")]
    SetExhausted,
    /// The record contract refused the assembled rows.
    #[error(transparent)]
    Record(#[from] CounterfactualDependencyErrorV1),
}

/// One host-owned owner of the nodes at scheduler position zero.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FactualHostOwnerV1 {
    /// The observation-snapshot node.
    Observation,
    /// The verified-prefix nodes.
    Prefix,
    /// The consumed-history nodes.
    History,
    /// The ingress and human-ingress nodes.
    Ingress,
}

impl FactualHostOwnerV1 {
    /// Return the literal owner ID of this host owner.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Observation => "host.observation",
            Self::Prefix => "host.prefix",
            Self::History => "host.history",
            Self::Ingress => "host.ingress",
        }
    }
}

/// The owner ID of a node: 1 to 128 bytes of UTF-8.
///
/// The length is validated when a node coordinate is built.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct FactualOwnerIdV1(String);

impl FactualOwnerIdV1 {
    /// Wrap an owner ID; a node coordinate validates the length.
    ///
    /// Production derives IDs through [`factual_owner_id`] or
    /// [`FactualOwnerIdV1::host`]; this constructor exists for hosts and tests
    /// that already hold an ID. It adds no validation: the contract has no
    /// owner-identity error (R3.8.2).
    #[must_use]
    pub const fn new(owner: String) -> Self {
        Self(owner)
    }

    /// Return the literal owner ID of a host owner.
    #[must_use]
    pub fn host(owner: FactualHostOwnerV1) -> Self {
        Self(owner.as_str().to_owned())
    }

    /// Borrow the owner ID text.
    #[must_use]
    pub const fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

/// What a Driver's owner ID is derived from.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FactualOwnerSourceV1<'a> {
    /// The Driver was registered at a stable manifest slot.
    Slot(&'a str),
    /// The Driver has no slot: its closure identity, name, and rank.
    Slotless {
        /// The output-policy closure's replay identity, or zero.
        policy_identity: Hash,
        /// The registered Plugin name.
        name: &'a str,
        /// The rank among slotless entries with equal identity and name.
        rank: u32,
    },
}

/// Derive the owner ID of a Driver.
///
/// A slotted entry hashes only its slot, so a policy revision or a
/// composition change leaves the ID unchanged. A slotless entry hashes its
/// policy identity, name, and rank. The two preimages carry different tags.
#[must_use]
pub fn factual_owner_id(source: FactualOwnerSourceV1<'_>) -> FactualOwnerIdV1 {
    let mut hasher = domain_hasher(OWNER_DOMAIN);
    match source {
        FactualOwnerSourceV1::Slot(slot) => {
            hasher.update(&[SLOTTED_OWNER_TAG]);
            update_prefixed(&mut hasher, slot.as_bytes());
        }
        FactualOwnerSourceV1::Slotless {
            policy_identity,
            name,
            rank,
        } => {
            hasher.update(&[SLOTLESS_OWNER_TAG]);
            hasher.update(policy_identity.as_bytes());
            update_prefixed(&mut hasher, name.as_bytes());
            hasher.update(&rank.to_be_bytes());
        }
    }
    FactualOwnerIdV1(format!("plugin:{}", hasher.finalize().to_hex()))
}

/// The closed classification rules of a factual Tick.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FactualRuleV1 {
    /// An authoritative or reproducible output node.
    DriverOutput,
    /// An ephemeral output node.
    DriverOutputEphemeral,
    /// A Driver step node.
    DriverStep,
    /// The Tick's observation-snapshot node.
    ObservationSnapshot,
    /// A verified-prefix node.
    VerifiedPrefix,
    /// A consumed-history node.
    ConsumedHistory,
    /// An ingress or human-ingress node.
    ExternalIngress,
}

impl FactualRuleV1 {
    /// The version of every rule in the registry.
    pub const VERSION: u32 = 1;

    /// Every rule the host knows.
    pub const ALL: [Self; 7] = [
        Self::DriverOutput,
        Self::DriverOutputEphemeral,
        Self::DriverStep,
        Self::ObservationSnapshot,
        Self::VerifiedPrefix,
        Self::ConsumedHistory,
        Self::ExternalIngress,
    ];

    /// Return the lowercase rule identifier.
    #[must_use]
    pub const fn rule_id(self) -> &'static str {
        match self {
            Self::DriverOutput => "pos.factual.driver-output",
            Self::DriverOutputEphemeral => "pos.factual.driver-output.ephemeral",
            Self::DriverStep => "pos.factual.driver-step",
            Self::ObservationSnapshot => "pos.factual.observation-snapshot",
            Self::VerifiedPrefix => "pos.factual.verified-prefix",
            Self::ConsumedHistory => "pos.factual.consumed-history",
            Self::ExternalIngress => "pos.factual.external-ingress",
        }
    }

    /// Return the one class this rule assigns.
    #[must_use]
    pub const fn class(self) -> RecordedDependencyClassV1 {
        match self {
            Self::DriverOutput
            | Self::DriverStep
            | Self::ObservationSnapshot
            | Self::VerifiedPrefix
            | Self::ConsumedHistory => RecordedDependencyClassV1::EndogenousRecomputed,
            Self::DriverOutputEphemeral => RecordedDependencyClassV1::PresentationOnly,
            Self::ExternalIngress => RecordedDependencyClassV1::ExogenousFrozen,
        }
    }

    /// Return the output rule for an admitted output declaration authority.
    #[must_use]
    pub const fn for_authority(authority: OutputAuthorityV1) -> Self {
        match authority {
            OutputAuthorityV1::Authoritative | OutputAuthorityV1::ReproducibleDerived => {
                Self::DriverOutput
            }
            OutputAuthorityV1::Ephemeral => Self::DriverOutputEphemeral,
        }
    }
}

/// Encode the classification bundle: a deterministic CBOR array of
/// `[rule_id, rule_version, class_code]` entries, sorted by rule ID and
/// version.
///
/// The rule ID is a CBOR text string; the ADR amendment of R3.5.3 records
/// this encoding.
#[must_use]
pub fn factual_classification_bundle_bytes() -> Vec<u8> {
    let mut rules = FactualRuleV1::ALL;
    rules.sort_by_key(|rule| (rule.rule_id(), FactualRuleV1::VERSION));
    let mut out = Vec::new();
    encode_head(&mut out, CBOR_ARRAY, rules.len() as u64);
    for rule in rules {
        encode_head(&mut out, CBOR_ARRAY, 3);
        encode_bytes(&mut out, rule.rule_id().as_bytes(), CBOR_TEXT);
        encode_head(&mut out, CBOR_UNSIGNED, u64::from(FactualRuleV1::VERSION));
        encode_head(&mut out, CBOR_UNSIGNED, u64::from(rule.class().code()));
    }
    out
}

/// Return the digest of the classification bundle.
///
/// This is the `classification_bundle_digest` a plan binds. A new rule joins
/// the same bundle and so changes the digest.
#[must_use]
pub fn factual_classification_bundle_digest() -> Hash {
    let mut hasher = domain_hasher(BUNDLE_DOMAIN);
    hasher.update(&factual_classification_bundle_bytes());
    finish(&hasher)
}

/// Check that a Timeline's recorded set can take one more worst-case Tick.
///
/// The preflight reserves a full record: it fails when the nodes, edges, or
/// declared inputs already recorded, plus one Tick's maximum, pass the set
/// bound.
///
/// # Errors
/// Returns [`FactualDependencyErrorV1::SetExhausted`] at the threshold.
///
/// The bound is shared with `TickDependencyRecordV1::ensure_set_capacity`: a
/// change to the set bounds or their arithmetic must touch both functions.
pub const fn ensure_factual_set_headroom(
    counts: RecordedSetCountsV1,
) -> Result<(), FactualDependencyErrorV1> {
    if counts.nodes.saturating_add(MAX_TICK_DEPENDENCY_NODES_V1) > MAX_RECORDED_DEPENDENCY_NODES_V1
        || counts.edges.saturating_add(MAX_TICK_DEPENDENCY_EDGES_V1)
            > MAX_RECORDED_DEPENDENCY_EDGES_V1
        || counts.inputs.saturating_add(MAX_TICK_DEPENDENCY_EDGES_V1)
            > MAX_RECORDED_DEPENDENCY_EDGES_V1
    {
        Err(FactualDependencyErrorV1::SetExhausted)
    } else {
        Ok(())
    }
}

/// The identity a Tick's nodes share: who recorded them and under what
/// authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FactualTickContextV1 {
    /// The recording Timeline.
    pub timeline_id: TimelineId,
    /// The factual Tick.
    pub tick: u64,
    /// The pipeline attempt.
    pub attempt_id: PipelineAttemptIdV1,
    /// The tentative-result evidence digest of the basis.
    pub evidence_digest: Hash,
    /// The authority grant of the persisted admission fence.
    pub authority_grant: Hash,
}

/// The position part of a node coordinate, without the digest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FactualNodeKeyV1<'a> {
    /// The factual Tick.
    pub tick: u64,
    /// The scheduler position: zero for the host, then `1..=n` per Driver.
    pub scheduler_position: u32,
    /// The owner ID.
    pub owner: &'a str,
    /// The output ordinal: zero for a step node, then `1..=k` per output.
    pub output_ordinal: u32,
    /// The schema ID.
    pub schema_id: u32,
}

/// One `(seq, payload_hash)` pair of a digested Event list.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FactualEventRefV1 {
    /// The Event's Timeline Order.
    pub seq: Seq,
    /// The Event's payload hash.
    pub payload_hash: Hash,
}

fn domain_hasher(domain: &[u8]) -> blake3::Hasher {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(&[0]);
    hasher
}

fn update_prefixed(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    hasher.update(&(bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

fn finish(hasher: &blake3::Hasher) -> Hash {
    Hash::from_bytes(*hasher.finalize().as_bytes())
}

/// Derive the schema ID of an Event-backed node from its Event type.
///
/// It is the first four bytes, big-endian, of a domain-tagged digest of the
/// type, with zero replaced by one.
#[must_use]
pub fn factual_event_schema_id(event_type: &str) -> u32 {
    let mut hasher = domain_hasher(SCHEMA_DOMAIN);
    hasher.update(event_type.as_bytes());
    let digest = hasher.finalize();
    let bytes = digest.as_bytes();
    u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]).max(1)
}

/// Derive the artifact digest of a node.
///
/// It binds the recording Timeline and the node coordinate to a content
/// digest, so equal payloads at different coordinates are distinct nodes.
#[must_use]
pub fn factual_artifact_digest(
    timeline_id: TimelineId,
    key: FactualNodeKeyV1<'_>,
    content_digest: Hash,
) -> Hash {
    let mut hasher = domain_hasher(ARTIFACT_DOMAIN);
    hasher.update(&timeline_id.inner().to_bytes());
    hasher.update(&key.tick.to_be_bytes());
    hasher.update(&key.scheduler_position.to_be_bytes());
    update_prefixed(&mut hasher, key.owner.as_bytes());
    hasher.update(&key.output_ordinal.to_be_bytes());
    hasher.update(&key.schema_id.to_be_bytes());
    hasher.update(content_digest.as_bytes());
    finish(&hasher)
}

/// Derive the provenance digest of a node.
///
/// The length prefixes are big-endian `u64`s; the ADR amendment of R3.3.3
/// records this width.
///
/// `responsible_owner` is the Driver owner ID or the host owner literal, and
/// `policy_identity` the Driver's replay identity (zero for host nodes).
#[must_use]
pub fn factual_provenance_digest(
    context: &FactualTickContextV1,
    ingress: PipelineIngressV1,
    responsible_owner: &str,
    policy_identity: Hash,
    rule: FactualRuleV1,
) -> Hash {
    let mut hasher = domain_hasher(PROVENANCE_DOMAIN);
    hasher.update(&context.timeline_id.inner().to_bytes());
    hasher.update(&context.attempt_id.as_bytes());
    hasher.update(&[ingress_tag(ingress)]);
    hasher.update(context.evidence_digest.as_bytes());
    hasher.update(context.authority_grant.as_bytes());
    update_prefixed(&mut hasher, responsible_owner.as_bytes());
    hasher.update(policy_identity.as_bytes());
    update_prefixed(&mut hasher, rule.rule_id().as_bytes());
    hasher.update(&FactualRuleV1::VERSION.to_be_bytes());
    finish(&hasher)
}

fn without_wall_time(draft: &EventDraft) -> EventDraft {
    EventDraft {
        wall_time: None,
        ..draft.clone()
    }
}

/// Content digest of an output or human-ingress node: the draft vector digest
/// of the one draft with its wall time cleared.
#[must_use]
pub fn factual_output_content_digest(draft: &EventDraft) -> Hash {
    pipeline_draft_vector_digest_v1(&[without_wall_time(draft)])
}

/// Content digest of a step node: the Driver's replay identity and the digest
/// of its own output vector with wall times cleared.
///
/// The preimage is deliberately untagged, as the ADR defines it (R3.3.2).
#[must_use]
pub fn factual_step_content_digest(replay_identity: Hash, drafts: &[EventDraft]) -> Hash {
    let cleared: Vec<EventDraft> = drafts.iter().map(without_wall_time).collect();
    let mut hasher = blake3::Hasher::new();
    hasher.update(replay_identity.as_bytes());
    hasher.update(pipeline_draft_vector_digest_v1(&cleared).as_bytes());
    finish(&hasher)
}

/// Content digest of an ingress node: the payload hash and the Event's `seq`.
///
/// The preimage is deliberately untagged, as the ADR defines it (R3.3.2).
#[must_use]
pub fn factual_ingress_content_digest(payload_hash: Hash, seq: Seq) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(payload_hash.as_bytes());
    hasher.update(&seq.as_u64().to_be_bytes());
    finish(&hasher)
}

fn update_events(hasher: &mut blake3::Hasher, events: &[FactualEventRefV1]) {
    hasher.update(&(events.len() as u64).to_be_bytes());
    for event in events {
        hasher.update(&event.seq.as_u64().to_be_bytes());
        hasher.update(event.payload_hash.as_bytes());
    }
}

/// Content digest of a verified-prefix node over the filtered prefix the
/// Driver was handed, in ascending `seq` order.
#[must_use]
pub fn factual_verified_prefix_content_digest(
    observed_through: Seq,
    events: &[FactualEventRefV1],
) -> Hash {
    let mut hasher = domain_hasher(PREFIX_DOMAIN);
    hasher.update(&observed_through.as_u64().to_be_bytes());
    update_events(&mut hasher, events);
    finish(&hasher)
}

/// Content digest of a consumed-history node over the Events it stands for.
///
/// `previous_history` is the content digest of the node it chains onto, or
/// the zero digest for a node that does not chain.
#[must_use]
pub fn factual_history_content_digest(
    previous_history: Hash,
    from_seq: Seq,
    through_seq: Seq,
    events: &[FactualEventRefV1],
) -> Hash {
    let mut hasher = domain_hasher(HISTORY_DOMAIN);
    hasher.update(previous_history.as_bytes());
    hasher.update(&from_seq.as_u64().to_be_bytes());
    hasher.update(&through_seq.as_u64().to_be_bytes());
    update_events(&mut hasher, events);
    finish(&hasher)
}

/// Binds one draft to the output or human-ingress node that stands for it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OutputNodeBindingV1 {
    /// The draft's index in the batch.
    pub draft_index: u32,
    /// The node's index in the record's canonical node order.
    pub node_index: u32,
}

/// Binds one committed Event to the ingress node recorded for it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EventNodeBindingV1 {
    /// The committed Event's Timeline Order.
    pub seq: Seq,
    /// The node's index in the record's canonical node order.
    pub node_index: u32,
}

/// The declaration a factual Tick carries in its admission basis.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FactualTickDependenciesV1 {
    tick: u64,
    record: TickDependencyRecordV1,
    output_bindings: Vec<OutputNodeBindingV1>,
    event_nodes: Vec<EventNodeBindingV1>,
}

impl FactualTickDependenciesV1 {
    /// Gather an asserted Tick, its record, and the two binding lists.
    ///
    /// Nothing is checked here: the store checks the declaration inside the
    /// commit transaction, and [`assemble_factual_tick`] builds a consistent
    /// one.
    #[must_use]
    pub const fn new(
        tick: u64,
        record: TickDependencyRecordV1,
        output_bindings: Vec<OutputNodeBindingV1>,
        event_nodes: Vec<EventNodeBindingV1>,
    ) -> Self {
        Self {
            tick,
            record,
            output_bindings,
            event_nodes,
        }
    }

    /// Return the asserted Tick, rechecked as the last Tick plus one.
    #[must_use]
    pub const fn tick(&self) -> u64 {
        self.tick
    }

    /// Borrow the Tick's record.
    #[must_use]
    pub const fn record(&self) -> &TickDependencyRecordV1 {
        &self.record
    }

    /// Borrow one binding per draft, in draft order.
    #[must_use]
    pub fn output_bindings(&self) -> &[OutputNodeBindingV1] {
        &self.output_bindings
    }

    /// Borrow the ingress nodes this Tick records, in ascending `seq`.
    #[must_use]
    pub fn event_nodes(&self) -> &[EventNodeBindingV1] {
        &self.event_nodes
    }

    /// Return the digest the admission basis binds.
    #[must_use]
    pub fn digest(&self) -> Hash {
        let mut hasher = domain_hasher(TICK_DEPENDENCIES_DOMAIN);
        hasher.update(&self.tick.to_be_bytes());
        hasher.update(record_digest(&self.record).as_bytes());
        hasher.update(&(self.output_bindings.len() as u64).to_be_bytes());
        for binding in &self.output_bindings {
            hasher.update(&binding.draft_index.to_be_bytes());
            hasher.update(&binding.node_index.to_be_bytes());
        }
        hasher.update(&(self.event_nodes.len() as u64).to_be_bytes());
        for binding in &self.event_nodes {
            hasher.update(&binding.seq.as_u64().to_be_bytes());
            hasher.update(&binding.node_index.to_be_bytes());
        }
        finish(&hasher)
    }
}

fn update_node(hasher: &mut blake3::Hasher, node: &DependencyNodeRecordV1) {
    let coordinate = node.coordinate();
    hasher.update(&coordinate.tick().to_be_bytes());
    hasher.update(&coordinate.scheduler_position().to_be_bytes());
    update_prefixed(hasher, coordinate.owner_id().as_bytes());
    hasher.update(&coordinate.output_ordinal().to_be_bytes());
    hasher.update(&coordinate.schema_id().to_be_bytes());
    hasher.update(coordinate.artifact_digest().as_bytes());
    hasher.update(&[node.class().code(), node.origin().code()]);
    hasher.update(&(node.input_digests().len() as u64).to_be_bytes());
    for input in node.input_digests() {
        hasher.update(input.as_bytes());
    }
    hasher.update(node.provenance_digest().as_bytes());
}

fn record_digest(record: &TickDependencyRecordV1) -> Hash {
    let mut hasher = domain_hasher(RECORD_DOMAIN);
    hasher.update(&record.tick().to_be_bytes());
    hasher.update(&[record.origin().code()]);
    hasher.update(&(record.nodes().len() as u64).to_be_bytes());
    for node in record.nodes() {
        update_node(&mut hasher, node);
    }
    hasher.update(&(record.edges().len() as u64).to_be_bytes());
    for edge in record.edges() {
        hasher.update(edge.digest().as_bytes());
    }
    finish(&hasher)
}

/// A node of an earlier Tick, resolved by the host.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FactualPriorNodeV1 {
    coordinate: DependencyNodeCoordinateV1,
    class: RecordedDependencyClassV1,
}

impl FactualPriorNodeV1 {
    /// Gather the coordinate and class of a recorded node.
    #[must_use]
    pub const fn new(
        coordinate: DependencyNodeCoordinateV1,
        class: RecordedDependencyClassV1,
    ) -> Self {
        Self { coordinate, class }
    }

    /// Take the coordinate and class of a recorded node row.
    #[must_use]
    pub fn from_record(record: &DependencyNodeRecordV1) -> Self {
        Self {
            coordinate: record.coordinate().clone(),
            class: record.class(),
        }
    }

    /// Borrow the node coordinate.
    #[must_use]
    pub const fn coordinate(&self) -> &DependencyNodeCoordinateV1 {
        &self.coordinate
    }

    /// Return the node class.
    #[must_use]
    pub const fn class(&self) -> RecordedDependencyClassV1 {
        self.class
    }
}

/// One direct input of a step or output node.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FactualInputV1 {
    /// The verified-prefix node at this index of the Tick.
    PrefixNode(u32),
    /// The new consumed-history node at this index of the Tick.
    HistoryNode(u32),
    /// The ingress node this Tick records for the Event with this `seq`.
    IngressEvent(Seq),
    /// A node recorded by an earlier Tick: an Event's node, the previous step
    /// node, a recorded history node, or a node named by digest.
    Prior(FactualPriorNodeV1),
}

/// A late-bound Event this Tick records as an ingress node.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FactualIngressEventV1 {
    /// The Event's Timeline Order.
    pub seq: Seq,
    /// The Event type, which fixes the node's schema ID.
    pub event_type: String,
    /// The Event's payload hash.
    pub payload_hash: Hash,
}

/// One output draft of a Driver with its draft-specific inputs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FactualOutputV1 {
    /// The staged draft.
    pub draft: EventDraft,
    /// The authority of the output declaration of the draft's Event type.
    pub authority: OutputAuthorityV1,
    /// The inputs of the output node besides its step node.
    pub direct_inputs: Vec<FactualInputV1>,
}

/// One stepped Driver, in schedule order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FactualDriverStepV1 {
    /// The Driver's owner ID.
    pub owner: FactualOwnerIdV1,
    /// The closure's replay identity, or zero for a closureless entry.
    pub policy_identity: Hash,
    /// The inputs of the step node besides the snapshot node.
    pub step_inputs: Vec<FactualInputV1>,
    /// The Driver's outputs, in vector order.
    pub outputs: Vec<FactualOutputV1>,
}

/// The nodes of a scheduled Tick, resolved by the host.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FactualScheduledTickV1 {
    /// The snapshot digest the basis anchor binds.
    pub snapshot_digest: Hash,
    /// The content digest of each verified-prefix node this Tick records.
    pub prefix_contents: Vec<Hash>,
    /// The content digest of each new consumed-history node this Tick records.
    pub history_contents: Vec<Hash>,
    /// The ingress nodes this Tick records, in strictly ascending `seq`.
    pub ingress_events: Vec<FactualIngressEventV1>,
    /// The stepped Drivers; the Driver at index `i` holds position `i + 1`.
    pub drivers: Vec<FactualDriverStepV1>,
}

/// The shape of a factual Tick.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FactualTickShapeV1 {
    /// A scheduled Driver pass.
    Scheduled(FactualScheduledTickV1),
    /// A human action: every approved draft is a human-ingress node.
    Human(Vec<EventDraft>),
}

/// Where one input of a node comes from.
enum FactualSource {
    /// A node of this Tick, by index into the specs.
    Node(usize),
    /// A node of an earlier Tick.
    Prior(FactualPriorNodeV1),
}

/// A node before its coordinate exists.
struct FactualNodeSpec {
    scheduler_position: u32,
    owner: String,
    output_ordinal: u32,
    schema_id: u32,
    content: Hash,
    rule: FactualRuleV1,
    policy_identity: Hash,
    sources: Vec<FactualSource>,
}

fn host_spec(
    owner: FactualHostOwnerV1,
    output_ordinal: u32,
    schema_id: u32,
    content: Hash,
    rule: FactualRuleV1,
) -> FactualNodeSpec {
    FactualNodeSpec {
        scheduler_position: 0,
        owner: owner.as_str().to_owned(),
        output_ordinal,
        schema_id,
        content,
        rule,
        policy_identity: Hash::zero(),
        sources: Vec::new(),
    }
}

/// The host nodes of a scheduled Tick, as indexes into the specs.
struct HostNodes {
    snapshot: usize,
    prefix: Vec<usize>,
    history: Vec<usize>,
    ingress: BTreeMap<Seq, usize>,
}

impl HostNodes {
    fn resolve(
        &self,
        tick: u64,
        input: &FactualInputV1,
    ) -> Result<FactualSource, FactualDependencyErrorV1> {
        match input {
            FactualInputV1::PrefixNode(index) => lookup(&self.prefix, *index),
            FactualInputV1::HistoryNode(index) => lookup(&self.history, *index),
            FactualInputV1::IngressEvent(seq) => self
                .ingress
                .get(seq)
                .map(|index| FactualSource::Node(*index))
                .ok_or(FactualDependencyErrorV1::UnresolvedInput),
            FactualInputV1::Prior(prior) => {
                if prior.coordinate.tick() < tick {
                    Ok(FactualSource::Prior(prior.clone()))
                } else {
                    Err(FactualDependencyErrorV1::UnresolvedInput)
                }
            }
        }
    }

    fn resolve_all(
        &self,
        tick: u64,
        first: usize,
        inputs: &[FactualInputV1],
    ) -> Result<Vec<FactualSource>, FactualDependencyErrorV1> {
        inputs
            .iter()
            .map(|input| self.resolve(tick, input))
            .collect::<Result<Vec<_>, _>>()
            .map(|resolved| {
                std::iter::once(FactualSource::Node(first))
                    .chain(resolved)
                    .collect()
            })
    }
}

/// Resolve a node index of this Tick; `u32` to `usize` is lossless on every
/// supported target.
fn lookup(nodes: &[usize], index: u32) -> Result<FactualSource, FactualDependencyErrorV1> {
    nodes
        .get(index as usize)
        .map(|node| FactualSource::Node(*node))
        .ok_or(FactualDependencyErrorV1::UnresolvedInput)
}

fn ensure_ascending_events(
    events: &[FactualIngressEventV1],
) -> Result<(), FactualDependencyErrorV1> {
    events
        .windows(2)
        .try_for_each(|pair| match pair[0].seq.cmp(&pair[1].seq) {
            std::cmp::Ordering::Less => Ok(()),
            std::cmp::Ordering::Equal => Err(CounterfactualDependencyErrorV1::DuplicateIdentity),
            std::cmp::Ordering::Greater => Err(CounterfactualDependencyErrorV1::NonCanonicalOrder),
        })
        .map_err(FactualDependencyErrorV1::from)
}

/// A source's coordinate and class.
struct FactualResolved {
    coordinate: DependencyNodeCoordinateV1,
    class: RecordedDependencyClassV1,
}

/// One node and the edges it consumes.
struct FactualRow {
    node: DependencyNodeRecordV1,
    edges: Vec<DependencyEdgeRecordV1>,
}

struct FactualAssembly<'a> {
    context: &'a FactualTickContextV1,
    ingress: PipelineIngressV1,
    specs: Vec<FactualNodeSpec>,
    output_specs: Vec<usize>,
    event_specs: Vec<(Seq, usize)>,
}

impl<'a> FactualAssembly<'a> {
    const fn new(context: &'a FactualTickContextV1, ingress: PipelineIngressV1) -> Self {
        Self {
            context,
            ingress,
            specs: Vec::new(),
            output_specs: Vec::new(),
            event_specs: Vec::new(),
        }
    }

    fn push(&mut self, spec: FactualNodeSpec) -> usize {
        let index = self.specs.len();
        self.specs.push(spec);
        index
    }

    fn push_run(
        &mut self,
        owner: FactualHostOwnerV1,
        schema_id: u32,
        rule: FactualRuleV1,
        contents: &[Hash],
    ) -> Vec<usize> {
        (0_u32..)
            .zip(contents)
            .map(|(ordinal, content)| {
                self.push(host_spec(owner, ordinal, schema_id, *content, rule))
            })
            .collect()
    }

    fn human(&mut self, drafts: &[EventDraft]) {
        for (ordinal, draft) in (0_u32..).zip(drafts) {
            let index = self.push(host_spec(
                FactualHostOwnerV1::Ingress,
                ordinal,
                factual_event_schema_id(draft.event_type.as_str()),
                factual_output_content_digest(draft),
                FactualRuleV1::ExternalIngress,
            ));
            self.output_specs.push(index);
        }
    }

    fn scheduled(
        &mut self,
        scheduled: &FactualScheduledTickV1,
    ) -> Result<(), FactualDependencyErrorV1> {
        ensure_ascending_events(&scheduled.ingress_events)?;
        let host = self.host_nodes(scheduled);
        for (position, driver) in (1_u32..).zip(&scheduled.drivers) {
            self.driver(&host, position, driver)?;
        }
        Ok(())
    }

    fn host_nodes(&mut self, scheduled: &FactualScheduledTickV1) -> HostNodes {
        let snapshot = self.push(host_spec(
            FactualHostOwnerV1::Observation,
            0,
            FACTUAL_SNAPSHOT_SCHEMA_ID_V1,
            scheduled.snapshot_digest,
            FactualRuleV1::ObservationSnapshot,
        ));
        let prefix = self.push_run(
            FactualHostOwnerV1::Prefix,
            FACTUAL_PREFIX_SCHEMA_ID_V1,
            FactualRuleV1::VerifiedPrefix,
            &scheduled.prefix_contents,
        );
        let history = self.push_run(
            FactualHostOwnerV1::History,
            FACTUAL_HISTORY_SCHEMA_ID_V1,
            FactualRuleV1::ConsumedHistory,
            &scheduled.history_contents,
        );
        let mut ingress = BTreeMap::new();
        for (ordinal, event) in (0_u32..).zip(&scheduled.ingress_events) {
            let index = self.push(host_spec(
                FactualHostOwnerV1::Ingress,
                ordinal,
                factual_event_schema_id(&event.event_type),
                factual_ingress_content_digest(event.payload_hash, event.seq),
                FactualRuleV1::ExternalIngress,
            ));
            ingress.insert(event.seq, index);
            self.event_specs.push((event.seq, index));
        }
        HostNodes {
            snapshot,
            prefix,
            history,
            ingress,
        }
    }

    fn driver(
        &mut self,
        host: &HostNodes,
        position: u32,
        driver: &FactualDriverStepV1,
    ) -> Result<(), FactualDependencyErrorV1> {
        let tick = self.context.tick;
        let drafts: Vec<EventDraft> = driver
            .outputs
            .iter()
            .map(|output| output.draft.clone())
            .collect();
        let sources = host.resolve_all(tick, host.snapshot, &driver.step_inputs)?;
        let step = self.push(FactualNodeSpec {
            scheduler_position: position,
            owner: driver.owner.as_str().to_owned(),
            output_ordinal: 0,
            schema_id: FACTUAL_STEP_SCHEMA_ID_V1,
            content: factual_step_content_digest(driver.policy_identity, &drafts),
            rule: FactualRuleV1::DriverStep,
            policy_identity: driver.policy_identity,
            sources,
        });
        for (ordinal, output) in (1_u32..).zip(&driver.outputs) {
            let sources = host.resolve_all(tick, step, &output.direct_inputs)?;
            let index = self.push(FactualNodeSpec {
                scheduler_position: position,
                owner: driver.owner.as_str().to_owned(),
                output_ordinal: ordinal,
                schema_id: factual_event_schema_id(output.draft.event_type.as_str()),
                content: factual_output_content_digest(&output.draft),
                rule: FactualRuleV1::for_authority(output.authority),
                policy_identity: driver.policy_identity,
                sources,
            });
            self.output_specs.push(index);
        }
        Ok(())
    }

    fn coordinates(&self) -> Result<Vec<DependencyNodeCoordinateV1>, FactualDependencyErrorV1> {
        self.specs
            .iter()
            .map(|spec| {
                let key = FactualNodeKeyV1 {
                    tick: self.context.tick,
                    scheduler_position: spec.scheduler_position,
                    owner: spec.owner.as_str(),
                    output_ordinal: spec.output_ordinal,
                    schema_id: spec.schema_id,
                };
                let digest = factual_artifact_digest(self.context.timeline_id, key, spec.content);
                DependencyNodeCoordinateV1::try_new(
                    key.tick,
                    key.scheduler_position,
                    spec.owner.clone(),
                    key.output_ordinal,
                    key.schema_id,
                    digest,
                )
                .map_err(FactualDependencyErrorV1::from)
            })
            .collect()
    }

    fn resolved(
        &self,
        coordinates: &[DependencyNodeCoordinateV1],
        source: &FactualSource,
    ) -> FactualResolved {
        match source {
            FactualSource::Node(index) => FactualResolved {
                coordinate: coordinates[*index].clone(),
                class: self.specs[*index].rule.class(),
            },
            FactualSource::Prior(prior) => FactualResolved {
                coordinate: prior.coordinate.clone(),
                class: prior.class,
            },
        }
    }

    fn row(
        &self,
        coordinates: &[DependencyNodeCoordinateV1],
        index: usize,
    ) -> Result<FactualRow, FactualDependencyErrorV1> {
        let spec = &self.specs[index];
        let consumer = &coordinates[index];
        let class = spec.rule.class();
        let sources: BTreeMap<Hash, FactualResolved> = spec
            .sources
            .iter()
            .map(|input| self.resolved(coordinates, input))
            .map(|resolved| (resolved.coordinate.artifact_digest(), resolved))
            .collect();
        if sources
            .values()
            .any(|resolved| breaks_class_rule(resolved.class, class))
        {
            return Err(FactualDependencyErrorV1::ClassRuleViolation);
        }
        let provenance = factual_provenance_digest(
            self.context,
            self.ingress,
            &spec.owner,
            spec.policy_identity,
            spec.rule,
        );
        let edges = sources
            .values()
            .map(|input| {
                let parts = EdgeParts {
                    consumer,
                    source: input,
                    authorization: self.context.authority_grant,
                    rule: spec.rule,
                    provenance,
                };
                DependencyEdgeRecordV1::try_from_canonical(
                    edge_bytes(&parts),
                    consumer.clone(),
                    input.coordinate.artifact_digest(),
                )
            })
            .collect::<Result<Vec<_>, CounterfactualDependencyErrorV1>>()?;
        let node = DependencyNodeRecordV1::try_new(
            consumer.clone(),
            class,
            RecordedNodeOriginV1::Committed,
            sources.keys().copied().collect(),
            provenance,
        )?;
        Ok(FactualRow { node, edges })
    }

    fn build(&self) -> Result<FactualTickDependenciesV1, FactualDependencyErrorV1> {
        let coordinates = self.coordinates()?;
        let mut order: Vec<usize> = (0..self.specs.len()).collect();
        order.sort_by(|left, right| {
            coordinates[*left]
                .position_key()
                .cmp(&coordinates[*right].position_key())
        });
        let mut rank = vec![0_u32; order.len()];
        for (position, spec_index) in (0_u32..).zip(&order) {
            rank[*spec_index] = position;
        }
        let built = order
            .iter()
            .map(|index| self.row(&coordinates, *index))
            .collect::<Result<Vec<_>, _>>()?;
        let output_bindings: Vec<OutputNodeBindingV1> = (0_u32..)
            .zip(&self.output_specs)
            .map(|(draft_index, spec_index)| OutputNodeBindingV1 {
                draft_index,
                node_index: rank[*spec_index],
            })
            .collect();
        let event_nodes: Vec<EventNodeBindingV1> = self
            .event_specs
            .iter()
            .map(|(seq, spec_index)| EventNodeBindingV1 {
                seq: *seq,
                node_index: rank[*spec_index],
            })
            .collect();
        let tick = self.context.tick;
        let (nodes, edge_groups): (Vec<_>, Vec<Vec<_>>) =
            built.into_iter().map(|row| (row.node, row.edges)).unzip();
        TickDependencyRecordV1::try_new(
            tick,
            RecordedNodeOriginV1::Committed,
            nodes,
            edge_groups.into_iter().flatten().collect(),
        )
        .map_err(FactualDependencyErrorV1::from)
        .map(|record| FactualTickDependenciesV1::new(tick, record, output_bindings, event_nodes))
    }
}

/// Whether an edge from `source` into `consumer` breaks the class rule: a
/// presentation-only source may only feed a presentation-only consumer.
const fn breaks_class_rule(
    source: RecordedDependencyClassV1,
    consumer: RecordedDependencyClassV1,
) -> bool {
    matches!(source, RecordedDependencyClassV1::PresentationOnly)
        && !matches!(consumer, RecordedDependencyClassV1::PresentationOnly)
}

/// The fields of one `IDP1` edge that its two nodes do not carry.
struct EdgeParts<'a> {
    consumer: &'a DependencyNodeCoordinateV1,
    source: &'a FactualResolved,
    authorization: Hash,
    rule: FactualRuleV1,
    provenance: Hash,
}

fn push_node(out: &mut Vec<u8>, node: &DependencyNodeCoordinateV1) {
    out.push(NODE_ARRAY_HEAD);
    encode_head(out, CBOR_UNSIGNED, node.tick());
    encode_head(out, CBOR_UNSIGNED, u64::from(node.scheduler_position()));
    encode_bytes(out, node.owner_id().as_bytes(), CBOR_TEXT);
    encode_head(out, CBOR_UNSIGNED, u64::from(node.output_ordinal()));
    encode_head(out, CBOR_UNSIGNED, u64::from(node.schema_id()));
    encode_hash(out, node.artifact_digest());
}

fn edge_bytes(parts: &EdgeParts<'_>) -> Vec<u8> {
    let source = &parts.source.coordinate;
    let mut out = vec![EDGE_ARRAY_HEAD];
    encode_bytes(&mut out, EDGE_MAGIC, CBOR_TEXT);
    encode_head(&mut out, CBOR_UNSIGNED, 1);
    push_node(&mut out, parts.consumer);
    push_node(&mut out, source);
    encode_head(
        &mut out,
        CBOR_UNSIGNED,
        u64::from(parts.source.class.code()),
    );
    encode_head(&mut out, CBOR_ARRAY, 2);
    encode_head(&mut out, CBOR_UNSIGNED, source.tick());
    encode_head(&mut out, CBOR_UNSIGNED, parts.consumer.tick());
    encode_hash(&mut out, parts.authorization);
    encode_head(&mut out, CBOR_ARRAY, 2);
    encode_bytes(&mut out, parts.rule.rule_id().as_bytes(), CBOR_TEXT);
    encode_head(&mut out, CBOR_UNSIGNED, u64::from(FactualRuleV1::VERSION));
    encode_hash(&mut out, parts.provenance);
    out
}

/// Assemble the declaration of one factual Tick from resolved inputs.
///
/// The assembly is pure. It derives every artifact digest, schema ID, and
/// provenance digest, sorts the nodes into the canonical order, adds one edge
/// per distinct input of every node (a step node also consumes the snapshot
/// node and an output node its step node), classifies every node by its
/// rule, and binds drafts and ingress Events to node indexes.
///
/// # Errors
/// Returns `UnresolvedInput` for an index or `seq` this Tick does not
/// record, or a prior node not at a strictly lower Tick;
/// `ClassRuleViolation` for a presentation-only input of a node of another
/// class; and `Record(..)` for ingress Events not in strictly ascending
/// `seq` order and for any fault of the record contract.
///
/// The derivation of the host edges (b) to (f) of R3.4.2 and the 255 and
/// 4,095 caps on the declared input lists belong to the registry builder of
/// slice 7b, which resolves the inputs before this call. Host nodes that no
/// node consumes are not flagged here.
pub fn assemble_factual_tick(
    context: &FactualTickContextV1,
    shape: &FactualTickShapeV1,
) -> Result<FactualTickDependenciesV1, FactualDependencyErrorV1> {
    match shape {
        FactualTickShapeV1::Scheduled(scheduled) => {
            let mut assembly = FactualAssembly::new(context, PipelineIngressV1::ScheduledAiDriver);
            assembly.scheduled(scheduled)?;
            assembly.build()
        }
        FactualTickShapeV1::Human(drafts) => {
            let mut assembly =
                FactualAssembly::new(context, PipelineIngressV1::HumanProposedAction);
            assembly.human(drafts);
            assembly.build()
        }
    }
}

/// The head of a Timeline's factual history.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FactualHeadV1 {
    /// The highest factual Tick, or zero when there is none.
    pub tick: u64,
    /// The last `seq` of that Tick, or zero when there is none.
    pub last_seq: Seq,
}

/// Where a Fork's `seq` cuts the parent's factual Ticks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FactualCutV1 {
    /// The cut falls on a Tick boundary or in the unrecorded tail.
    Boundary {
        /// The highest visible Tick that ends at or before the cut.
        cut_tick: u64,
    },
    /// The cut falls inside a recorded Tick.
    MidTick {
        /// The highest visible Tick that ends before the cut.
        cut_tick: u64,
        /// The Tick the cut splits.
        split_tick: u64,
    },
}

/// A recorded node with the `seq` it is bound to, when it is an Event node.
pub type BoundFactualNodeV1 = (DependencyNodeRecordV1, Option<Seq>);

/// Host-only reads over a Timeline's recorded factual prefix.
///
/// Every method resolves through the Timeline's fork ancestry, stopping at
/// each ancestor's cut Tick, and under the same erasure read fences as the
/// dependency prefix reads. A store failure is the store's [`CoreError`].
pub trait FactualPrefixReadPortV1 {
    /// Return the head of the Timeline's factual history.
    ///
    /// The result is total and ancestry-inclusive: the highest Tick of the
    /// Timeline's own set with its last `seq`; while that set is empty, the
    /// inherited cut Tick with its last `seq`; `{ 0, Seq::ZERO }` when no
    /// Tick exists.
    ///
    /// # Errors
    /// Returns the store's error.
    fn last_committed_factual_tick(&self, timeline: TimelineId)
        -> Result<FactualHeadV1, CoreError>;

    /// Locate the cut a Fork at `seq` makes in the Timeline's factual Ticks.
    ///
    /// # Errors
    /// Returns the store's error.
    fn cut_tick_at(&self, timeline: TimelineId, seq: Seq) -> Result<FactualCutV1, CoreError>;

    /// Resolve committed Events to their recorded nodes, one entry per `seq`.
    ///
    /// # Errors
    /// Returns the store's error.
    fn nodes_for_committed_events(
        &self,
        timeline: TimelineId,
        seqs: &[Seq],
    ) -> Result<Vec<Option<DependencyNodeRecordV1>>, CoreError>;

    /// Resolve artifact digests to their recorded nodes and bound `seq`, one
    /// entry per digest.
    ///
    /// # Errors
    /// Returns the store's error.
    fn nodes_by_digest(
        &self,
        timeline: TimelineId,
        digests: &[Hash],
    ) -> Result<Vec<Option<BoundFactualNodeV1>>, CoreError>;

    /// Return the latest step node of an owner, if one is recorded.
    ///
    /// # Errors
    /// Returns the store's error.
    fn last_step_node(
        &self,
        timeline: TimelineId,
        owner: &FactualOwnerIdV1,
    ) -> Result<Option<DependencyNodeRecordV1>, CoreError>;

    /// Return the row counts of the Timeline's own recorded set.
    ///
    /// # Errors
    /// Returns the store's error.
    fn factual_set_counts(&self, timeline: TimelineId) -> Result<RecordedSetCountsV1, CoreError>;
}

/// The combined capability the registry's Tick-path admission needs: commit
/// pipeline batches and read the recorded prefix.
pub trait FactualAdmissionPortV1: PipelineAdmissionPortV1 + FactualPrefixReadPortV1 {}

impl<T: PipelineAdmissionPortV1 + FactualPrefixReadPortV1 + ?Sized> FactualAdmissionPortV1 for T {}
