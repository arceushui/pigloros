//! The guest contract of the community Plugin world (ADR-061).
//!
//! Host types for the `contract-v1` records that cross the Component
//! boundary, the V1 `output-digest`, and the report of one completed
//! invocation. Nothing here links a WebAssembly runtime: the supervisor and
//! the Tick-Boundary commit use these types, and only the in-worker engine
//! (`pos-plugin-host`) converts them to and from Canonical ABI values.
//!
//! The host builds a [`PluginInvocationV1`] and receives a validated
//! [`PluginOutputV1`], [`PluginDescriptorV1`] or [`GuestPluginErrorV1`]. Fixed
//! lengths are part of the types: every `digest32` is `[u8; 32]`, and every
//! `invocation-id`, `timeline-id` and `entity-id` is `[u8; 16]`.
//!
//! # Output digest (ADR-061 revision 6)
//!
//! The host recomputes `output-digest` over every prior `plugin-output` field
//! and rejects a mismatch. Revision 6 defines the hashed bytes as raw
//! BLAKE3-256 over:
//!
//! - the domain `PiglorOS.Plugin.Output.v1\0`;
//! - then fields 0-5 in WIT order, each encoded as follows:
//!   - `list<u8>` (including `digest32.value` and `bounded-text.utf8`):
//!     `u64be(length) || bytes`;
//!   - any other list: `u64be(count)`, then each element;
//!   - a record: its fields in WIT order;
//!   - `u32`: four big-endian bytes.

pub use pos_core::community_lifecycle::{
    ArtifactRefV1, FieldRefV1, GuestPluginErrorV1, MeteringV1, PluginErrorCodeV1,
    TimelinePositionV1,
};
use pos_crypto::plugin_execution::is_valid_id_v1;
use zeroize::Zeroize;

use super::error::CommunityPluginHostErrorV1;

/// WIT bound on observation bytes, in bytes (1 MiB).
pub const MAX_OBSERVATION_BYTES_V1: usize = 1_048_576;
/// WIT bound on prior and next state bytes, in bytes (1 MiB).
pub const MAX_STATE_BYTES_V1: usize = 1_048_576;
/// Bound on the summed `canonical-bytes` of one output's trace annotations,
/// in bytes (1 MiB; ADR-061 revision 6).
pub const MAX_TRACE_ANNOTATION_BYTES_V1: usize = 1_048_576;

/// `contract-v1.plugin-invocation`, without its `kind`.
///
/// The engine sets `kind` from the export it invokes, so an invocation can
/// never name the other export. The host verifies every referenced artifact
/// and digest before it builds one (ADR-061); the engine checks the bounds
/// WIT cannot express before any guest code runs.
/// Owners of private copies use [`Zeroize`] or a zeroizing guard before
/// releasing them; this plain contract value does not erase itself on drop.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PluginInvocationV1 {
    /// Invocation ID.
    pub invocation_id: [u8; 16],
    /// Timeline position of the invocation.
    pub timeline_position: TimelinePositionV1,
    /// First output ordinal of this invocation.
    pub output_base_ordinal: u32,
    /// Principal reference.
    pub principal_ref: ArtifactRefV1,
    /// Authorization decision reference.
    pub authorization_decision: ArtifactRefV1,
    /// `ObservationSnapshot` reference.
    pub observation_snapshot: ArtifactRefV1,
    /// Observation bytes, at most 1 MiB.
    pub observation_bytes: Vec<u8>,
    /// Prior state schema digest.
    pub prior_state_schema: [u8; 32],
    /// Prior state bytes, at most 1 MiB.
    pub prior_state_bytes: Vec<u8>,
    /// Execution profile digest.
    pub execution_profile_digest: [u8; 32],
    /// Trust policy snapshot digest.
    pub trust_policy_snapshot_digest: [u8; 32],
    /// Deterministic budget ID, an ADR-061 ID.
    pub deterministic_budget_id: String,
    /// Deterministic random domain.
    pub deterministic_random_domain: [u8; 32],
    /// Provenance root.
    pub provenance_root: [u8; 32],
}

impl Zeroize for PluginInvocationV1 {
    fn zeroize(&mut self) {
        self.invocation_id.zeroize();
        self.timeline_position.timeline_id.zeroize();
        self.timeline_position.seq.zeroize();
        self.timeline_position.tick.zeroize();
        self.timeline_position.scheduler_position.zeroize();
        self.output_base_ordinal.zeroize();
        for artifact in [
            &mut self.principal_ref,
            &mut self.authorization_decision,
            &mut self.observation_snapshot,
        ] {
            artifact.schema_id.zeroize();
            artifact.byte_length.zeroize();
            artifact.digest.zeroize();
        }
        self.observation_bytes.zeroize();
        self.prior_state_schema.zeroize();
        self.prior_state_bytes.zeroize();
        self.execution_profile_digest.zeroize();
        self.trust_policy_snapshot_digest.zeroize();
        self.deterministic_budget_id.zeroize();
        self.deterministic_random_domain.zeroize();
        self.provenance_root.zeroize();
    }
}

impl PluginInvocationV1 {
    /// Check the bounds WIT cannot express.
    ///
    /// # Errors
    ///
    /// Returns `InvalidInvocation` when the observation or the prior state
    /// exceeds 1 MiB, or the budget ID is not an ADR-061 ID.
    pub fn validate(&self) -> Result<(), CommunityPluginHostErrorV1> {
        let valid = self.observation_bytes.len() <= MAX_OBSERVATION_BYTES_V1
            && self.prior_state_bytes.len() <= MAX_STATE_BYTES_V1
            && is_valid_id_v1(&self.deterministic_budget_id);
        valid
            .then_some(())
            .ok_or(CommunityPluginHostErrorV1::InvalidInvocation)
    }
}

/// `contract-v1.event-draft`, validated.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventDraftV1 {
    /// Event schema ID.
    pub event_schema_id: u32,
    /// Entity ID.
    pub entity_id: [u8; 16],
    /// Event type, an ADR-061 ID.
    pub event_type: String,
    /// Canonical payload bytes.
    pub canonical_payload: Vec<u8>,
    /// Dependency digests, strictly increasing.
    pub dependency_digests: Vec<[u8; 32]>,
}

impl Zeroize for EventDraftV1 {
    fn zeroize(&mut self) {
        self.event_schema_id.zeroize();
        self.entity_id.zeroize();
        self.event_type.zeroize();
        self.canonical_payload.zeroize();
        self.dependency_digests.zeroize();
    }
}

/// `contract-v1.trace-annotation`, validated.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TraceAnnotationV1 {
    /// Annotation schema ID.
    pub annotation_schema_id: u32,
    /// Canonical annotation bytes.
    pub canonical_bytes: Vec<u8>,
    /// Dependency digests, strictly increasing.
    pub dependency_digests: Vec<[u8; 32]>,
}

impl Zeroize for TraceAnnotationV1 {
    fn zeroize(&mut self) {
        self.annotation_schema_id.zeroize();
        self.canonical_bytes.zeroize();
        self.dependency_digests.zeroize();
    }
}

/// `contract-v1.plugin-output`, fully validated against its invocation.
///
/// Nothing in it is committed by the engine: the supervisor approves and
/// commits it as one value at the Tick Boundary.
/// Dropping an owned output erases its retained payloads, State, annotations
/// and identities. A consumer transferring a field must own that copy's cleanup.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PluginOutputV1 {
    /// The invocation's ID, echoed.
    pub invocation_id: [u8; 16],
    /// `EventDrafts`, in the guest's order.
    pub event_drafts: Vec<EventDraftV1>,
    /// Next state schema digest.
    pub next_state_schema: [u8; 32],
    /// Next state bytes.
    pub next_state_bytes: Vec<u8>,
    /// Trace annotations, in the guest's order.
    pub trace_annotations: Vec<TraceAnnotationV1>,
    /// Consumed dependency digests, strictly increasing.
    pub consumed_dependencies: Vec<[u8; 32]>,
    /// The output digest, equal to [`plugin_output_digest_v1`].
    pub output_digest: [u8; 32],
}

impl Zeroize for PluginOutputV1 {
    fn zeroize(&mut self) {
        self.invocation_id.zeroize();
        self.event_drafts.zeroize();
        self.next_state_schema.zeroize();
        self.next_state_bytes.zeroize();
        self.trace_annotations.zeroize();
        self.consumed_dependencies.zeroize();
        self.output_digest.zeroize();
    }
}

impl Drop for PluginOutputV1 {
    fn drop(&mut self) {
        self.zeroize();
        #[cfg(test)]
        tests::observe_output_erasure(self);
    }
}

/// `contract-v1.plugin-descriptor`, checked against the negotiated release.
///
/// `capabilities` and `dependencies` are checked against their count bounds
/// only, because the manifest is their authority, and `migrations` must be
/// empty, so none of them is kept.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PluginDescriptorV1 {
    /// Plugin ID, equal to the negotiated PMF1 Plugin ID.
    pub plugin_id: String,
    /// Release semver text. The host lifts it as UTF-8 text without a length
    /// check: revision 6 does not list one, and the manifest is the authority.
    pub release_semver: String,
    /// World, equal to the negotiated world.
    pub world: String,
    /// ABI major, equal to the negotiated major.
    pub abi_major: u16,
    /// Lowest ABI minor, equal to the PMF1 declaration.
    pub min_abi_minor: u16,
    /// Highest ABI minor, equal to the PMF1 declaration.
    pub max_abi_minor: u16,
    /// Required features, equal to the negotiated ones.
    pub required_features: Vec<String>,
    /// Event schema digests, strictly increasing.
    pub event_schema_digests: Vec<[u8; 32]>,
    /// State schema digest.
    pub state_schema_digest: [u8; 32],
    /// Manifest digest: 32 zero bytes in V1 (ADR-061 revision 6).
    ///
    /// The real digest covers the Component's own digest, so no Component
    /// can declare it.
    pub manifest_digest: [u8; 32],
    /// Release digest: 32 zero bytes in V1, for the same reason.
    pub release_digest: [u8; 32],
}

/// Deterministic values that `host-v1` exposes to one invocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostInputs {
    /// Simulation Time returned by `simulation-time`.
    pub simulation_time: u64,
}

/// What the caller supplies to one invocation besides the guest's input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvocationOptionsV1 {
    /// Deterministic `host-v1` values.
    pub host_inputs: HostInputs,
    /// Engine epoch ticks before the operational watchdog stops the guest.
    ///
    /// Zero stops the guest at its first epoch check.
    pub watchdog_epochs: u32,
}

/// One accepted `record-operational-log` call.
///
/// Operational logs are never authoritative behaviour inputs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationalLogRecord {
    /// Category chosen by the guest.
    pub category: u16,
    /// UTF-8 message of at most 256 bytes.
    pub message: String,
}

/// The guest's validated return: its value, or its own `plugin-error`.
pub type GuestReturnV1<T> = Result<T, GuestPluginErrorV1>;

/// One completed invocation: the guest's validated return and its metering.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InvocationReportV1<T> {
    /// The guest's validated typed return.
    pub result: GuestReturnV1<T>,
    /// Fuel, memory and host calls the invocation used.
    pub metering: MeteringV1,
    /// Accepted `record-operational-log` calls, in call order.
    ///
    /// Operational only: never an authoritative input or output.
    pub operational_log: Vec<OperationalLogRecord>,
}

/// The domain separator of the V1 output digest, including its NUL.
pub const PLUGIN_OUTPUT_DIGEST_DOMAIN_V1: &[u8] = b"PiglorOS.Plugin.Output.v1\0";

/// The V1 `output-digest` over fields 0-5 of `output`.
///
/// `output.output_digest` itself is not hashed.
#[must_use]
pub fn plugin_output_digest_v1(output: &PluginOutputV1) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(PLUGIN_OUTPUT_DIGEST_DOMAIN_V1);
    put_bytes(&mut hasher, &output.invocation_id);
    put_count(&mut hasher, output.event_drafts.len());
    for draft in &output.event_drafts {
        hasher.update(&draft.event_schema_id.to_be_bytes());
        put_bytes(&mut hasher, &draft.entity_id);
        put_bytes(&mut hasher, draft.event_type.as_bytes());
        put_bytes(&mut hasher, &draft.canonical_payload);
        put_digests(&mut hasher, &draft.dependency_digests);
    }
    put_bytes(&mut hasher, &output.next_state_schema);
    put_bytes(&mut hasher, &output.next_state_bytes);
    put_count(&mut hasher, output.trace_annotations.len());
    for annotation in &output.trace_annotations {
        hasher.update(&annotation.annotation_schema_id.to_be_bytes());
        put_bytes(&mut hasher, &annotation.canonical_bytes);
        put_digests(&mut hasher, &annotation.dependency_digests);
    }
    put_digests(&mut hasher, &output.consumed_dependencies);
    *hasher.finalize().as_bytes()
}

// `usize` fits in a `u64` on every supported target, so the cast is lossless.
const _: () = assert!(usize::BITS <= u64::BITS);

fn put_count(hasher: &mut blake3::Hasher, count: usize) {
    hasher.update(&(count as u64).to_be_bytes());
}

fn put_bytes(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    put_count(hasher, bytes.len());
    hasher.update(bytes);
}

fn put_digests(hasher: &mut blake3::Hasher, digests: &[[u8; 32]]) {
    put_count(hasher, digests.len());
    for digest in digests {
        put_bytes(hasher, digest);
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    thread_local! {
        static OUTPUT_ERASURE: std::cell::Cell<Option<bool>> = const { std::cell::Cell::new(None) };
    }

    // Borrow only the still-live value after real drop cleanup. This records
    // logical erasure, without inspecting freed storage or claiming a wipe proof.
    pub(super) fn observe_output_erasure(output: &PluginOutputV1) {
        OUTPUT_ERASURE.set(Some(
            output.event_drafts.is_empty()
                && output.next_state_bytes.is_empty()
                && output.trace_annotations.is_empty()
                && output.consumed_dependencies.is_empty(),
        ));
    }

    const ARTIFACT: ArtifactRefV1 = ArtifactRefV1 {
        schema_id: 1,
        byte_length: 0,
        digest: [0; 32],
    };

    fn invocation() -> PluginInvocationV1 {
        PluginInvocationV1 {
            invocation_id: [1; 16],
            timeline_position: TimelinePositionV1 {
                timeline_id: [2; 16],
                seq: 3,
                tick: 4,
                scheduler_position: 5,
            },
            output_base_ordinal: 6,
            principal_ref: ARTIFACT,
            authorization_decision: ARTIFACT,
            observation_snapshot: ARTIFACT,
            observation_bytes: vec![0; MAX_OBSERVATION_BYTES_V1],
            prior_state_schema: [7; 32],
            prior_state_bytes: vec![0; MAX_STATE_BYTES_V1],
            execution_profile_digest: [8; 32],
            trust_policy_snapshot_digest: [9; 32],
            deterministic_budget_id: "budget".to_owned(),
            deterministic_random_domain: [10; 32],
            provenance_root: [11; 32],
        }
    }

    #[test]
    fn invocations_stay_within_the_wit_bounds() {
        let error = Err(CommunityPluginHostErrorV1::InvalidInvocation);
        assert_eq!(invocation().validate(), Ok(()));
        let mut large = invocation();
        large.observation_bytes.push(0);
        assert_eq!(large.validate(), error);
        let mut large = invocation();
        large.prior_state_bytes.push(0);
        assert_eq!(large.validate(), error);
        let mut unnamed = invocation();
        unnamed.deterministic_budget_id = "Budget".to_owned();
        assert_eq!(unnamed.validate(), error);
    }

    #[test]
    fn erasing_an_owned_invocation_invalidates_every_field_without_changing_its_source() {
        let mut source = invocation();
        source.observation_bytes = b"private observation".to_vec();
        source.prior_state_bytes = b"private State".to_vec();
        let artifact = ArtifactRefV1 {
            schema_id: 23,
            byte_length: 42,
            digest: [0xa5; 32],
        };
        source.principal_ref = artifact;
        source.authorization_decision = artifact;
        source.observation_snapshot = artifact;
        let mut owned = source.clone();
        owned.zeroize();
        let empty_artifact = ArtifactRefV1 {
            schema_id: 0,
            byte_length: 0,
            digest: [0; 32],
        };
        assert_eq!(
            owned,
            PluginInvocationV1 {
                invocation_id: [0; 16],
                timeline_position: TimelinePositionV1 {
                    timeline_id: [0; 16],
                    seq: 0,
                    tick: 0,
                    scheduler_position: 0,
                },
                output_base_ordinal: 0,
                principal_ref: empty_artifact,
                authorization_decision: empty_artifact,
                observation_snapshot: empty_artifact,
                observation_bytes: Vec::new(),
                prior_state_schema: [0; 32],
                prior_state_bytes: Vec::new(),
                execution_profile_digest: [0; 32],
                trust_policy_snapshot_digest: [0; 32],
                deterministic_budget_id: String::new(),
                deterministic_random_domain: [0; 32],
                provenance_root: [0; 32],
            }
        );
        assert_eq!(
            owned.validate(),
            Err(CommunityPluginHostErrorV1::InvalidInvocation)
        );
        assert_eq!(source.observation_bytes, b"private observation");
        assert_eq!(source.prior_state_bytes, b"private State");
        assert_eq!(source.principal_ref, artifact);
        assert_eq!(source.validate(), Ok(()));
    }

    fn output() -> PluginOutputV1 {
        PluginOutputV1 {
            invocation_id: [1; 16],
            event_drafts: vec![EventDraftV1 {
                event_schema_id: 0x0102_0304,
                entity_id: [2; 16],
                event_type: "t".to_owned(),
                canonical_payload: vec![3],
                dependency_digests: vec![[4; 32]],
            }],
            next_state_schema: [5; 32],
            next_state_bytes: vec![6, 7],
            trace_annotations: vec![TraceAnnotationV1 {
                annotation_schema_id: 9,
                canonical_bytes: vec![10],
                dependency_digests: Vec::new(),
            }],
            consumed_dependencies: vec![[11; 32]],
            output_digest: [0; 32],
        }
    }

    #[test]
    fn output_erasure_clears_nested_payloads_annotations_and_state() {
        let source = output();
        let mut draft = source.event_drafts[0].clone();
        draft.zeroize();
        assert_eq!(
            draft,
            EventDraftV1 {
                event_schema_id: 0,
                entity_id: [0; 16],
                event_type: String::new(),
                canonical_payload: Vec::new(),
                dependency_digests: Vec::new(),
            }
        );
        let mut annotation = source.trace_annotations[0].clone();
        annotation.dependency_digests = vec![[0x39; 32]];
        annotation.zeroize();
        assert_eq!(
            annotation,
            TraceAnnotationV1 {
                annotation_schema_id: 0,
                canonical_bytes: Vec::new(),
                dependency_digests: Vec::new(),
            }
        );
        let mut owned = source.clone();
        owned.output_digest = [0x7b; 32];
        owned.zeroize();
        assert_eq!(
            owned,
            PluginOutputV1 {
                invocation_id: [0; 16],
                event_drafts: Vec::new(),
                next_state_schema: [0; 32],
                next_state_bytes: Vec::new(),
                trace_annotations: Vec::new(),
                consumed_dependencies: Vec::new(),
                output_digest: [0; 32],
            }
        );
        assert_eq!(source.event_drafts[0].canonical_payload, [3]);
        assert_eq!(source.trace_annotations[0].canonical_bytes, [10]);
        assert_eq!(source.next_state_bytes, [6, 7]);
    }

    #[test]
    fn dropping_an_output_reaches_erasure_before_releasing_its_payloads() {
        let owned = output();
        OUTPUT_ERASURE.set(None);
        drop(owned);
        assert_eq!(OUTPUT_ERASURE.get(), Some(true));
    }

    const fn len(count: u64) -> [u8; 8] {
        count.to_be_bytes()
    }

    #[test]
    fn the_digest_hashes_the_documented_encoding_of_fields_0_to_5() {
        let mut expected = PLUGIN_OUTPUT_DIGEST_DOMAIN_V1.to_vec();
        let parts: [&[u8]; 25] = [
            &len(16),
            &[1; 16],
            &len(1),
            &[1, 2, 3, 4],
            &len(16),
            &[2; 16],
            &len(1),
            b"t",
            &len(1),
            &[3],
            &len(1),
            &len(32),
            &[4; 32],
            &len(32),
            &[5; 32],
            &len(2),
            &[6, 7],
            &len(1),
            &[0, 0, 0, 9],
            &len(1),
            &[10],
            &len(0),
            &len(1),
            &len(32),
            &[11; 32],
        ];
        for part in parts {
            expected.extend_from_slice(part);
        }
        let digest = plugin_output_digest_v1(&output());
        assert_eq!(digest, *blake3::hash(&expected).as_bytes());
        let mut moved = output();
        moved.output_digest = [0xff; 32];
        assert_eq!(plugin_output_digest_v1(&moved), digest);
    }
}
