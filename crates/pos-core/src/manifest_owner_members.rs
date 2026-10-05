//! ADR-081 Revision 2 scope members recorded by one owner admission.
//!
//! Every owned Timeline scope carries its exact RTP1/RLS1 bytes, the retained
//! native members reachable from each admitted OPC1, and the unavailable
//! audience and WCS1 consumer reference leaves. The request builder and the
//! owner check share one derivation, so an admission can only commit the
//! exact leaves, edges and bytes that the native records imply. Recording a
//! lease is an upper-bound record only; it never grants use or renews consent.

use std::collections::{BTreeMap, BTreeSet};

use crate::executable_budget::ExecutableBudgetPolicyV1;
use crate::manifest_owner_admission::{
    opc1_native_digest, ManifestOwnerAdmissionErrorV1, ManifestOwnerPolicyCopiesV1,
    OutputPolicyClosureEnvelopeV1,
};
use crate::output_policy::OutputPolicyV1;
use crate::retention::{WorldRetentionLeaseInputV1, WorldRetentionLeaseV1, WorldRetentionPolicyV1};
use crate::world_replay::WorldReplayClosureV1;
use crate::{
    ArtifactDataClassV1, ArtifactOptionalityV1, ArtifactTransitionRuleV1, Hash, PluginId,
    TimelineId, WorldArtifactKeyDependencyV1, WorldArtifactKindV1, WorldArtifactLeafInputV1,
    WorldArtifactLeafV1, WorldClosureReadLimitsV1, WorldConsumerSetV1,
};

/// Owner policy hook: classify one `(kind, native digest)` leaf, or `None`.
type Classifier<'a> =
    &'a dyn Fn(WorldArtifactKindV1, Hash) -> Option<ManifestOwnerLeafClassificationV1>;
/// One leaf's `(kind, native digest)` identity within a scope.
type LeafKey = (WorldArtifactKindV1, Hash);
/// One scope's EOP1/OPC1 copies and member leaves, as counted by the byte budget.
pub(crate) type ScopeBytes<'a> = (
    &'a [ManifestOwnerPolicyCopiesV1],
    &'a ManifestOwnerScopeMembersV1,
);

const BASE_CONFIGURATION_DOMAIN: &[u8] = b"pigloros.base-configuration.v1";
const IMPLEMENTATION_DOMAIN: &[u8] = b"pigloros.implementation-artifact.v1";
/// Inclusive WCB1 traversal-depth bound shared with `WorldClosureBindingV1`.
const MAX_COMBINED_DEPTH_V1: u8 = 32;
/// Retained native-byte bound of one scoped member leaf.
///
/// The `SQLite` `manifest_owner_member_leaves.native_bytes` CHECK enforces the
/// same 16 MiB bound, so both stores accept exactly the same members.
pub const MAX_MANIFEST_OWNER_MEMBER_NATIVE_BYTES_V1: usize = 16_777_216;

/// Owner-hook classification recorded in one scoped WAL1 leaf.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifestOwnerLeafClassificationV1 {
    /// Data class assigned by the installed owner policy hook.
    pub data_class: ArtifactDataClassV1,
    /// Erasure transition fixed before any erasure begins.
    pub transition: ArtifactTransitionRuleV1,
    /// Exact, strictly ordered key dependencies.
    pub key_dependencies: Vec<WorldArtifactKeyDependencyV1>,
}

/// One member leaf's identity with the classification the installed owner
/// hook returns for it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifestOwnerClassifiedLeafV1 {
    /// WAL1 kind of the classified member or reference leaf.
    pub kind: WorldArtifactKindV1,
    /// Native digest of the classified member or reference leaf.
    pub native_digest: Hash,
    /// Data class, transition and key dependencies for that leaf.
    pub classification: ManifestOwnerLeafClassificationV1,
}

impl ManifestOwnerClassifiedLeafV1 {
    /// Copy the identity and classification recorded in one leaf.
    #[must_use]
    pub fn of_leaf(leaf: &WorldArtifactLeafV1) -> Self {
        let fields = leaf.as_input();
        Self {
            kind: fields.kind,
            native_digest: fields.native_digest,
            classification: ManifestOwnerLeafClassificationV1 {
                data_class: fields.data_class,
                transition: fields.transition,
                key_dependencies: fields.key_dependencies.clone(),
            },
        }
    }
}

/// One scoped member or reference leaf with its retained native bytes.
///
/// Reference leaves (kinds 6-9) record no native bytes, so their content is
/// never retained.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifestOwnerMemberLeafV1 {
    /// Required scoped WAL1 leaf.
    pub leaf: WorldArtifactLeafV1,
    /// Exact retained native bytes; empty for a reference leaf.
    pub native_bytes: Vec<u8>,
}

/// Exact lease records and member leaves for one owned Timeline scope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifestOwnerScopeMembersV1 {
    /// Exact canonical RTP1 bytes referenced by the lease.
    pub rtp1_bytes: Vec<u8>,
    /// Exact canonical RLS1 bytes: an upper-bound record, never a use grant.
    pub rls1_bytes: Vec<u8>,
    /// Member and reference leaves, strictly ordered by kind then native digest.
    pub leaves: Vec<ManifestOwnerMemberLeafV1>,
}

/// Native digests behind one WCS1 consumer's kind7/8/9 reference leaves.
///
/// These are native digests; the WCS1 consumer row carries the WAL1 leaf
/// addresses of the reference leaves built from them.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ManifestOwnerConsumerReferenceV1 {
    /// Native schema digest (artifact kind7).
    pub schema: Hash,
    /// Native reducer digest (artifact kind8).
    pub reducer: Hash,
    /// Native runtime digest (artifact kind9).
    pub runtime: Hash,
}

/// One admitted Plugin's exact EOP1 and OPC1 bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifestOwnerPolicySourceV1 {
    /// Plugin identity from the complete MCA1 catalog.
    pub plugin_id: PluginId,
    /// Exact canonical EOP1 bytes.
    pub eop1_bytes: Vec<u8>,
    /// Exact canonical OPC1 bytes.
    pub opc1_bytes: Vec<u8>,
}

/// Native inputs from which one owned Timeline scope is derived.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifestOwnerScopeSourceV1 {
    /// Admission owner, recorded as every leaf's copy owner.
    pub owner_id: [u8; 32],
    /// Owned Timeline named by the RLS1 lease.
    pub timeline_id: TimelineId,
    /// Exact canonical RTP1 bytes.
    pub rtp1_bytes: Vec<u8>,
    /// Exact canonical RLS1 bytes referencing the RTP1 policy.
    pub rls1_bytes: Vec<u8>,
    /// Reference digests for every WCS1 consumer.
    pub consumer_references: Vec<ManifestOwnerConsumerReferenceV1>,
    /// Every admitted Plugin's policy bytes, sorted by `PluginId`.
    pub policy_sources: Vec<ManifestOwnerPolicySourceV1>,
}

/// Derived scope with populated EOP1/OPC1 copies and its member leaves.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifestOwnerScopeV1 {
    /// Exact ADR-081 Timeline/RLS1 scope.
    pub scope: Hash,
    /// EOP1/OPC1 copies whose leaves carry their exact child edges.
    pub policy_copies: Vec<ManifestOwnerPolicyCopiesV1>,
    /// Lease records and member leaves for the scope.
    pub members: ManifestOwnerScopeMembersV1,
}

/// Build one scope's populated policy copies and member leaves.
///
/// `classify` supplies the installed owner policy hook's data class,
/// transition and key dependencies for each `(kind, native digest)`.
///
/// # Errors
/// Returns `InvalidBatch` for malformed or mismatched RTP1/RLS1/EOP1/OPC1
/// members, a lease for another Timeline, an unclassified leaf, a
/// classification that does not form a valid WAL1 leaf, or a classifier that
/// answers one `(kind, native digest)` inconsistently.
pub fn build_manifest_owner_scope_v1(
    source: &ManifestOwnerScopeSourceV1,
    classify: Classifier<'_>,
) -> Result<ManifestOwnerScopeV1, ManifestOwnerAdmissionErrorV1> {
    let references = source.consumer_references.iter().flat_map(|reference| {
        [
            (WorldArtifactKindV1::Schema, reference.schema),
            (
                WorldArtifactKindV1::ReducerImplementation,
                reference.reducer,
            ),
            (WorldArtifactKindV1::RuntimeIdentity, reference.runtime),
        ]
    });
    let policies = source.policy_sources.iter().map(PolicyBytes::from);
    derive_scope(
        ScopeInputs {
            owner_id: source.owner_id,
            timeline_id: source.timeline_id,
            rtp1_bytes: &source.rtp1_bytes,
            rls1_bytes: &source.rls1_bytes,
        },
        references,
        policies,
        classify,
    )
}

/// Reject a replacement lease that extends a previously recorded lease.
///
/// Replacement never renews retention: neither the admission close nor the
/// retention deadline may move later than the recorded lease's.
///
/// # Errors
/// Returns `CorruptState` for an undecodable recorded lease, `InvalidBatch`
/// for an undecodable replacement lease, and `OwnerRejected` for a deadline
/// extension.
pub fn validate_manifest_owner_lease_replacement_v1(
    previous: &ManifestOwnerScopeMembersV1,
    next: &ManifestOwnerScopeMembersV1,
) -> Result<(), ManifestOwnerAdmissionErrorV1> {
    let previous = recorded_lease(previous).ok_or(ManifestOwnerAdmissionErrorV1::CorruptState)?;
    let next = recorded_lease(next).ok_or(ManifestOwnerAdmissionErrorV1::InvalidBatch)?;
    if next.admission_closes_at_micros > previous.admission_closes_at_micros
        || next.retention_deadline_micros > previous.retention_deadline_micros
    {
        return Err(ManifestOwnerAdmissionErrorV1::OwnerRejected);
    }
    Ok(())
}

/// Decode the RLS1 lease recorded with a scope, if its RTP1/RLS1 bytes decode.
pub(crate) fn recorded_lease(
    members: &ManifestOwnerScopeMembersV1,
) -> Option<WorldRetentionLeaseInputV1> {
    WorldRetentionPolicyV1::from_canonical_cbor(&members.rtp1_bytes)
        .ok()
        .and_then(|policy| {
            WorldRetentionLeaseV1::from_canonical_cbor(&members.rls1_bytes, &policy).ok()
        })
        .map(|lease| *lease.as_input())
}

/// Check read limits and every scope's retained native bytes.
///
/// Every read limit must be nonzero and the combined depth at most 32. Each
/// member leaf must fit [`MAX_MANIFEST_OWNER_MEMBER_NATIVE_BYTES_V1`]. The
/// aggregate covers member leaves and every EOP1/OPC1 copy, so it also bounds
/// each single retained member by `max_native_bytes`; OPC1 bytes embed their
/// members, which therefore count toward the aggregate more than once.
///
/// Admission only records `max_node_visits` and `max_combined_depth`. The
/// ADR-081 R2.3 traversal-bound rejection, which checks both against the
/// actual closure, is enforced at cut time by #523 through the WDB1 packer.
/// The rule that one generation keeps identical limits holds vacuously here:
/// every admission creates a new configuration generation, and reusing an
/// `(owner, generation, Timeline)` row returns `Conflict`.
pub(crate) fn validate_scope_budgets<'a>(
    limits: WorldClosureReadLimitsV1,
    scopes: impl IntoIterator<Item = ScopeBytes<'a>>,
) -> Result<(), ManifestOwnerAdmissionErrorV1> {
    if limits.max_node_visits == 0
        || limits.max_native_bytes == 0
        || !(1..=MAX_COMBINED_DEPTH_V1).contains(&limits.max_combined_depth)
    {
        return Err(ManifestOwnerAdmissionErrorV1::InvalidBatch);
    }
    for (copies, members) in scopes {
        if members.leaves.iter().any(exceeds_member_bound) {
            return Err(ManifestOwnerAdmissionErrorV1::BoundExceeded);
        }
        let retained = members
            .leaves
            .iter()
            .map(|member| member.native_bytes.len())
            .chain(
                copies
                    .iter()
                    .flat_map(|copy| [copy.eop1_bytes.len(), copy.opc1_bytes.len()]),
            )
            .fold(0_u64, |total, length| total.saturating_add(length as u64));
        if retained > limits.max_native_bytes {
            return Err(ManifestOwnerAdmissionErrorV1::BoundExceeded);
        }
    }
    Ok(())
}

const fn exceeds_member_bound(member: &ManifestOwnerMemberLeafV1) -> bool {
    member.native_bytes.len() > MAX_MANIFEST_OWNER_MEMBER_NATIVE_BYTES_V1
}

/// Require the exact member leaves derived from the scope's native bytes.
///
/// The recomputed scope is not compared on its own: every derived EOP1/OPC1
/// copy leaf carries it, and the supplied copies were already checked
/// against the request scope, so copy equality proves it. A separate check
/// could never fail on its own and so could not be tested.
pub(crate) fn validate_scope_members(
    owner_id: [u8; 32],
    timeline_id: TimelineId,
    wcs1: &WorldConsumerSetV1,
    copies: &[ManifestOwnerPolicyCopiesV1],
    members: &ManifestOwnerScopeMembersV1,
) -> Result<(), ManifestOwnerAdmissionErrorV1> {
    let recorded = members
        .leaves
        .iter()
        .map(|member| &member.leaf)
        .chain(
            copies
                .iter()
                .flat_map(|copy| [&copy.eop1_leaf, &copy.opc1_leaf]),
        )
        .map(|leaf| {
            let class = ManifestOwnerClassifiedLeafV1::of_leaf(leaf);
            ((class.kind, class.native_digest), class.classification)
        })
        .collect::<BTreeMap<_, _>>();
    let references = members
        .leaves
        .iter()
        .map(|member| member.leaf.as_input())
        .filter(|leaf| is_consumer_reference(leaf.kind))
        .map(|leaf| (leaf.kind, leaf.native_digest));
    let policies = copies.iter().map(PolicyBytes::from);
    let derived = derive_scope(
        ScopeInputs {
            owner_id,
            timeline_id,
            rtp1_bytes: &members.rtp1_bytes,
            rls1_bytes: &members.rls1_bytes,
        },
        references,
        policies,
        &|kind, digest| recorded.get(&(kind, digest)).cloned(),
    )?;
    if derived.policy_copies != copies
        || derived.members != *members
        || !wcs1.optional_view_roots().is_empty()
        || consumer_reference_set(wcs1) != reference_leaf_set(members)
    {
        return Err(ManifestOwnerAdmissionErrorV1::InvalidBatch);
    }
    Ok(())
}

/// Require the owner hook's classification of every member leaf, in order.
pub(crate) fn verify_member_classes(
    members: &ManifestOwnerScopeMembersV1,
    classes: &[ManifestOwnerClassifiedLeafV1],
) -> Result<(), ManifestOwnerAdmissionErrorV1> {
    let recorded = members
        .leaves
        .iter()
        .map(|member| ManifestOwnerClassifiedLeafV1::of_leaf(&member.leaf))
        .collect::<Vec<_>>();
    if classes == recorded.as_slice() {
        Ok(())
    } else {
        Err(ManifestOwnerAdmissionErrorV1::InvalidBatch)
    }
}

/// WCS1 consumer reference kinds: schema, reducer and runtime (kinds 7-9).
const CONSUMER_REFERENCE_KINDS: [WorldArtifactKindV1; 3] = [
    WorldArtifactKindV1::Schema,
    WorldArtifactKindV1::ReducerImplementation,
    WorldArtifactKindV1::RuntimeIdentity,
];

fn is_consumer_reference(kind: WorldArtifactKindV1) -> bool {
    CONSUMER_REFERENCE_KINDS.contains(&kind)
}

fn consumer_reference_set(wcs1: &WorldConsumerSetV1) -> BTreeSet<LeafKey> {
    wcs1.consumers()
        .iter()
        .flat_map(|consumer| {
            [
                (WorldArtifactKindV1::Schema, consumer.schema_hash()),
                (
                    WorldArtifactKindV1::ReducerImplementation,
                    consumer.reducer_hash(),
                ),
                (
                    WorldArtifactKindV1::RuntimeIdentity,
                    consumer.runtime_hash(),
                ),
            ]
        })
        .collect()
}

fn reference_leaf_set(members: &ManifestOwnerScopeMembersV1) -> BTreeSet<LeafKey> {
    members
        .leaves
        .iter()
        .filter(|member| is_consumer_reference(member.leaf.as_input().kind))
        .map(|member| (member.leaf.as_input().kind, member.leaf.digest()))
        .collect()
}

#[derive(Clone, Copy)]
struct ScopeInputs<'a> {
    owner_id: [u8; 32],
    timeline_id: TimelineId,
    rtp1_bytes: &'a [u8],
    rls1_bytes: &'a [u8],
}

fn derive_scope<'a>(
    inputs: ScopeInputs<'_>,
    references: impl Iterator<Item = LeafKey>,
    policies: impl Iterator<Item = PolicyBytes<'a>>,
    classify: Classifier<'_>,
) -> Result<ManifestOwnerScopeV1, ManifestOwnerAdmissionErrorV1> {
    let policy = WorldRetentionPolicyV1::from_canonical_cbor(inputs.rtp1_bytes)
        .map_err(|_| ManifestOwnerAdmissionErrorV1::InvalidBatch)?;
    let lease = WorldRetentionLeaseV1::from_canonical_cbor(inputs.rls1_bytes, &policy)
        .map_err(|_| ManifestOwnerAdmissionErrorV1::InvalidBatch)?;
    if lease.as_input().timeline_id != inputs.timeline_id {
        return Err(ManifestOwnerAdmissionErrorV1::InvalidBatch);
    }
    let scope = WorldReplayClosureV1::artifact_scope(inputs.timeline_id, lease.digest());
    let mut leaves = ScopeLeaves {
        owner_id: inputs.owner_id,
        scope,
        lease: lease.digest(),
        classify,
        members: BTreeMap::new(),
    };
    let audience = policy.as_input().audience_policy_hash;
    let audience_leaf = leaves.member(
        WorldArtifactKindV1::AudiencePolicy,
        audience,
        &[],
        Vec::new(),
    )?;
    let retention = RetentionMember {
        digest: policy.digest(),
        bytes: inputs.rtp1_bytes,
        leaf: leaves.member(
            WorldArtifactKindV1::RetentionPolicy,
            policy.digest(),
            inputs.rtp1_bytes,
            vec![audience_leaf],
        )?,
    };
    leaves.member(
        WorldArtifactKindV1::RetentionLease,
        lease.digest(),
        inputs.rls1_bytes,
        vec![retention.leaf],
    )?;
    for (kind, digest) in references {
        leaves.member(kind, digest, &[], Vec::new())?;
    }
    let policy_copies = policies
        .map(|source| derive_copy(&mut leaves, &retention, source))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ManifestOwnerScopeV1 {
        scope,
        policy_copies,
        members: ManifestOwnerScopeMembersV1 {
            rtp1_bytes: inputs.rtp1_bytes.to_vec(),
            rls1_bytes: inputs.rls1_bytes.to_vec(),
            leaves: leaves.members.into_values().collect(),
        },
    })
}

/// One Plugin's exact EOP1/OPC1 bytes borrowed from a source or request.
#[derive(Clone, Copy)]
struct PolicyBytes<'a> {
    plugin_id: PluginId,
    eop1_bytes: &'a [u8],
    opc1_bytes: &'a [u8],
}

impl<'a> From<&'a ManifestOwnerPolicySourceV1> for PolicyBytes<'a> {
    fn from(source: &'a ManifestOwnerPolicySourceV1) -> Self {
        Self {
            plugin_id: source.plugin_id,
            eop1_bytes: &source.eop1_bytes,
            opc1_bytes: &source.opc1_bytes,
        }
    }
}

impl<'a> From<&'a ManifestOwnerPolicyCopiesV1> for PolicyBytes<'a> {
    fn from(copy: &'a ManifestOwnerPolicyCopiesV1) -> Self {
        Self {
            plugin_id: copy.plugin_id,
            eop1_bytes: &copy.eop1_bytes,
            opc1_bytes: &copy.opc1_bytes,
        }
    }
}

struct RetentionMember<'a> {
    digest: Hash,
    bytes: &'a [u8],
    leaf: Hash,
}

struct PolicyMemberLeaves {
    budget: Hash,
    configuration: Hash,
    implementation: Hash,
    profile: Option<Hash>,
}

fn derive_copy(
    leaves: &mut ScopeLeaves<'_>,
    retention: &RetentionMember<'_>,
    source: PolicyBytes<'_>,
) -> Result<ManifestOwnerPolicyCopiesV1, ManifestOwnerAdmissionErrorV1> {
    let PolicyBytes {
        plugin_id,
        eop1_bytes,
        opc1_bytes,
    } = source;
    let policy = OutputPolicyV1::from_canonical_cbor(eop1_bytes)
        .map_err(|_| ManifestOwnerAdmissionErrorV1::InvalidBatch)?;
    let envelope = OutputPolicyClosureEnvelopeV1::from_canonical_bytes_v1(opc1_bytes, eop1_bytes)
        .map_err(|_| ManifestOwnerAdmissionErrorV1::InvalidBatch)?;
    let members = policy_member_leaves(leaves, &policy, &envelope, retention)?;
    let eop1_leaf = leaves.leaf(
        WorldArtifactKindV1::OutputPolicy,
        policy.digest(),
        eop1_bytes,
        vec![
            members.configuration,
            members.budget,
            retention.leaf,
            members.implementation,
        ],
    )?;
    let mut closure_children = vec![
        eop1_leaf.digest(),
        members.budget,
        retention.leaf,
        members.configuration,
        members.implementation,
    ];
    closure_children.extend(members.profile);
    let opc1_leaf = leaves.leaf(
        WorldArtifactKindV1::OutputPolicyClosure,
        opc1_native_digest(opc1_bytes),
        opc1_bytes,
        closure_children,
    )?;
    Ok(ManifestOwnerPolicyCopiesV1 {
        plugin_id,
        eop1_bytes: eop1_bytes.to_vec(),
        eop1_leaf,
        opc1_bytes: opc1_bytes.to_vec(),
        opc1_leaf,
    })
}

fn policy_member_leaves(
    leaves: &mut ScopeLeaves<'_>,
    policy: &OutputPolicyV1,
    envelope: &OutputPolicyClosureEnvelopeV1<'_>,
    retention: &RetentionMember<'_>,
) -> Result<PolicyMemberLeaves, ManifestOwnerAdmissionErrorV1> {
    let budget_bytes = envelope.executable_budget_bytes();
    let budget = ExecutableBudgetPolicyV1::from_canonical_cbor(budget_bytes)
        .map_err(|_| ManifestOwnerAdmissionErrorV1::InvalidBatch)?;
    let fields = policy.fields();
    let configuration = envelope.configuration_artifact();
    let implementation = envelope.implementation_artifact();
    let profile_bytes = envelope.execution_profile_artifact();
    let profile_digest = budget.fields().execution_profile_hash;
    if fields.retention_policy_hash != retention.digest
        || envelope.retention_policy_artifact() != retention.bytes
        || fields.base_configuration_digest
            != host_artifact_digest(BASE_CONFIGURATION_DOMAIN, configuration)
        || fields.implementation_hash != host_artifact_digest(IMPLEMENTATION_DOMAIN, implementation)
        || fields.executable_profile_hash != budget.digest()
        || profile_digest != Hash::from_bytes(*blake3::hash(profile_bytes).as_bytes())
    {
        return Err(ManifestOwnerAdmissionErrorV1::InvalidBatch);
    }
    // A Generated profile is empty and has no kind5 member or edge.
    let profile = if profile_bytes.is_empty() {
        None
    } else {
        Some(leaves.member(
            WorldArtifactKindV1::ExecutionProfile,
            profile_digest,
            profile_bytes,
            Vec::new(),
        )?)
    };
    Ok(PolicyMemberLeaves {
        budget: leaves.member(
            WorldArtifactKindV1::ExecutableBudgetPolicy,
            budget.digest(),
            budget_bytes,
            profile.into_iter().collect(),
        )?,
        configuration: leaves.member(
            WorldArtifactKindV1::BaseConfiguration,
            fields.base_configuration_digest,
            configuration,
            Vec::new(),
        )?,
        implementation: leaves.member(
            WorldArtifactKindV1::PluginImplementationIdentity,
            fields.implementation_hash,
            implementation,
            Vec::new(),
        )?,
        profile,
    })
}

fn host_artifact_digest(domain: &[u8], bytes: &[u8]) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(&[0]);
    hasher.update(bytes);
    Hash::from_bytes(*hasher.finalize().as_bytes())
}

struct ScopeLeaves<'a> {
    owner_id: [u8; 32],
    scope: Hash,
    lease: Hash,
    classify: Classifier<'a>,
    members: BTreeMap<LeafKey, ManifestOwnerMemberLeafV1>,
}

impl ScopeLeaves<'_> {
    fn leaf(
        &self,
        kind: WorldArtifactKindV1,
        native_digest: Hash,
        native_bytes: &[u8],
        mut children: Vec<Hash>,
    ) -> Result<WorldArtifactLeafV1, ManifestOwnerAdmissionErrorV1> {
        let classification = (self.classify)(kind, native_digest)
            .ok_or(ManifestOwnerAdmissionErrorV1::InvalidBatch)?;
        children.sort_unstable();
        WorldArtifactLeafV1::new(WorldArtifactLeafInputV1 {
            scope: self.scope,
            kind,
            native_digest,
            native_byte_length: native_bytes.len() as u64,
            owner: self.owner_id,
            data_class: classification.data_class,
            optionality: ArtifactOptionalityV1::Required,
            transition: classification.transition,
            source_lease_hash: self.lease,
            key_dependencies: classification.key_dependencies,
            child_node_hashes: children,
        })
        .map_err(|_| ManifestOwnerAdmissionErrorV1::InvalidBatch)
    }

    /// Register one member leaf under its `(kind, native digest)` key.
    ///
    /// An identical registration deduplicates. The native digest fixes the
    /// bytes and children, so a second, different leaf can only come from a
    /// classifier that answers one key inconsistently; that conflict rejects.
    fn member(
        &mut self,
        kind: WorldArtifactKindV1,
        native_digest: Hash,
        native_bytes: &[u8],
        children: Vec<Hash>,
    ) -> Result<Hash, ManifestOwnerAdmissionErrorV1> {
        let leaf = self.leaf(kind, native_digest, native_bytes, children)?;
        let recorded = self
            .members
            .entry((kind, native_digest))
            .or_insert_with(|| ManifestOwnerMemberLeafV1 {
                leaf: leaf.clone(),
                native_bytes: native_bytes.to_vec(),
            });
        if recorded.leaf == leaf {
            Ok(leaf.digest())
        } else {
            Err(ManifestOwnerAdmissionErrorV1::InvalidBatch)
        }
    }
}
