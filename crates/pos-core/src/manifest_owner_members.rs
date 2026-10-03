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
    ArtifactDataClassV1, ArtifactOptionalityV1, ArtifactStateV1, ArtifactTransitionRuleV1, Hash,
    PluginId, TimelineId, WorldArtifactKeyDependencyV1, WorldArtifactKindV1,
    WorldArtifactLeafInputV1, WorldArtifactLeafV1, WorldClosureReadLimitsV1, WorldConsumerSetV1,
};

type Kind = WorldArtifactKindV1;
type AdmissionError = ManifestOwnerAdmissionErrorV1;
type Classifier<'a> = &'a dyn Fn(Kind, Hash) -> Option<ManifestOwnerLeafClassificationV1>;
/// One scope's EOP1/OPC1 copies and member leaves, as counted by the byte budget.
pub(crate) type ScopeBytes<'a> = (
    &'a [ManifestOwnerPolicyCopiesV1],
    &'a ManifestOwnerScopeMembersV1,
);

const BASE_CONFIGURATION_DOMAIN: &[u8] = b"pigloros.base-configuration.v1";
const IMPLEMENTATION_DOMAIN: &[u8] = b"pigloros.implementation-artifact.v1";
/// Inclusive WCB1 traversal-depth bound shared with `WorldClosureBindingV1`.
const MAX_COMBINED_DEPTH_V1: u8 = 32;

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

/// Classification the installed owner hook returns for one member leaf.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifestOwnerMemberLeafClassV1 {
    /// WAL1 kind of the classified member or reference leaf.
    pub kind: WorldArtifactKindV1,
    /// Native digest of the classified member or reference leaf.
    pub native_digest: Hash,
    /// Data class, transition and key dependencies for that leaf.
    pub classification: ManifestOwnerLeafClassificationV1,
}

impl ManifestOwnerMemberLeafClassV1 {
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
/// Reference leaves (kinds 6-9) record no native bytes; their native-content
/// state is fixed by kind and can never be `Retained`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifestOwnerMemberLeafV1 {
    /// Required scoped WAL1 leaf.
    pub leaf: WorldArtifactLeafV1,
    /// Exact retained native bytes; empty for a reference leaf.
    pub native_bytes: Vec<u8>,
}

impl ManifestOwnerMemberLeafV1 {
    /// Native-content state fixed by the leaf kind.
    #[must_use]
    pub const fn state(&self) -> ArtifactStateV1 {
        match self.leaf.as_input().kind {
            Kind::AudiencePolicy => ArtifactStateV1::MissingFrozenInput,
            Kind::Schema => ArtifactStateV1::MissingSchema,
            Kind::ReducerImplementation => ArtifactStateV1::MissingPlugin,
            Kind::RuntimeIdentity => ArtifactStateV1::MissingRuntime,
            _ => ArtifactStateV1::Retained,
        }
    }
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
/// members, a lease for another Timeline, an unclassified leaf, or a
/// classification that does not form a valid WAL1 leaf.
pub fn build_manifest_owner_scope_v1(
    source: &ManifestOwnerScopeSourceV1,
    classify: &dyn Fn(WorldArtifactKindV1, Hash) -> Option<ManifestOwnerLeafClassificationV1>,
) -> Result<ManifestOwnerScopeV1, ManifestOwnerAdmissionErrorV1> {
    let references = source.consumer_references.iter().flat_map(|reference| {
        [
            (Kind::Schema, reference.schema),
            (Kind::ReducerImplementation, reference.reducer),
            (Kind::RuntimeIdentity, reference.runtime),
        ]
    });
    let policies = source.policy_sources.iter().map(|policy| PolicyBytes {
        plugin_id: policy.plugin_id,
        eop1_bytes: &policy.eop1_bytes,
        opc1_bytes: &policy.opc1_bytes,
    });
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
    let previous = recorded_lease(previous).ok_or(AdmissionError::CorruptState)?;
    let next = recorded_lease(next).ok_or(AdmissionError::InvalidBatch)?;
    if next.admission_closes_at_micros > previous.admission_closes_at_micros
        || next.retention_deadline_micros > previous.retention_deadline_micros
    {
        return Err(AdmissionError::OwnerRejected);
    }
    Ok(())
}

fn recorded_lease(members: &ManifestOwnerScopeMembersV1) -> Option<WorldRetentionLeaseInputV1> {
    WorldRetentionPolicyV1::from_canonical_cbor(&members.rtp1_bytes)
        .ok()
        .and_then(|policy| {
            WorldRetentionLeaseV1::from_canonical_cbor(&members.rls1_bytes, &policy).ok()
        })
        .map(|lease| *lease.as_input())
}

/// Check read limits and every scope's aggregate retained native bytes.
///
/// Every read limit must be nonzero. The aggregate covers member leaves and
/// every EOP1/OPC1 copy, so it also bounds each single retained member by
/// `max_native_bytes`; OPC1 bytes embed their members, which therefore count
/// toward the aggregate more than once.
pub(crate) fn validate_scope_budgets<'a>(
    limits: WorldClosureReadLimitsV1,
    scopes: impl IntoIterator<Item = ScopeBytes<'a>>,
) -> Result<(), ManifestOwnerAdmissionErrorV1> {
    if limits.max_node_visits == 0
        || limits.max_native_bytes == 0
        || !(1..=MAX_COMBINED_DEPTH_V1).contains(&limits.max_combined_depth)
    {
        return Err(AdmissionError::InvalidBatch);
    }
    for (copies, members) in scopes {
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
            return Err(AdmissionError::BoundExceeded);
        }
    }
    Ok(())
}

/// Require the exact member leaves derived from the scope's native bytes.
///
/// Derived EOP1/OPC1 leaves carry the request scope only when the supplied
/// copies (already checked against that scope) are equal to them, so copy
/// equality also proves the recomputed scope.
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
            let class = ManifestOwnerMemberLeafClassV1::of_leaf(leaf);
            ((class.kind, class.native_digest), class.classification)
        })
        .collect::<BTreeMap<_, _>>();
    let references = members
        .leaves
        .iter()
        .map(|member| member.leaf.as_input())
        .filter(|leaf| is_consumer_reference(leaf.kind))
        .map(|leaf| (leaf.kind, leaf.native_digest));
    let policies = copies.iter().map(|copy| PolicyBytes {
        plugin_id: copy.plugin_id,
        eop1_bytes: &copy.eop1_bytes,
        opc1_bytes: &copy.opc1_bytes,
    });
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
        return Err(AdmissionError::InvalidBatch);
    }
    Ok(())
}

/// Require the owner hook's classification of every member leaf, in order.
pub(crate) fn verify_member_classes(
    members: &ManifestOwnerScopeMembersV1,
    classes: &[ManifestOwnerMemberLeafClassV1],
) -> Result<(), ManifestOwnerAdmissionErrorV1> {
    let recorded = members
        .leaves
        .iter()
        .map(|member| ManifestOwnerMemberLeafClassV1::of_leaf(&member.leaf))
        .collect::<Vec<_>>();
    if classes == recorded.as_slice() {
        Ok(())
    } else {
        Err(AdmissionError::InvalidBatch)
    }
}

const fn is_consumer_reference(kind: Kind) -> bool {
    matches!(
        kind,
        Kind::Schema | Kind::ReducerImplementation | Kind::RuntimeIdentity
    )
}

fn consumer_reference_set(wcs1: &WorldConsumerSetV1) -> BTreeSet<(Kind, Hash)> {
    wcs1.consumers()
        .iter()
        .flat_map(|consumer| {
            [
                (Kind::Schema, consumer.schema_hash()),
                (Kind::ReducerImplementation, consumer.reducer_hash()),
                (Kind::RuntimeIdentity, consumer.runtime_hash()),
            ]
        })
        .collect()
}

fn reference_leaf_set(members: &ManifestOwnerScopeMembersV1) -> BTreeSet<(Kind, Hash)> {
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
    references: impl Iterator<Item = (Kind, Hash)>,
    policies: impl Iterator<Item = PolicyBytes<'a>>,
    classify: Classifier<'_>,
) -> Result<ManifestOwnerScopeV1, ManifestOwnerAdmissionErrorV1> {
    let policy = WorldRetentionPolicyV1::from_canonical_cbor(inputs.rtp1_bytes)
        .map_err(|_| AdmissionError::InvalidBatch)?;
    let lease = WorldRetentionLeaseV1::from_canonical_cbor(inputs.rls1_bytes, &policy)
        .map_err(|_| AdmissionError::InvalidBatch)?;
    if lease.as_input().timeline_id != inputs.timeline_id {
        return Err(AdmissionError::InvalidBatch);
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
    let audience_leaf = leaves.member(Kind::AudiencePolicy, audience, &[], Vec::new())?;
    let retention = RetentionMember {
        digest: policy.digest(),
        bytes: inputs.rtp1_bytes,
        leaf: leaves.member(
            Kind::RetentionPolicy,
            policy.digest(),
            inputs.rtp1_bytes,
            vec![audience_leaf],
        )?,
    };
    leaves.member(
        Kind::RetentionLease,
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
        .map_err(|_| AdmissionError::InvalidBatch)?;
    let envelope = OutputPolicyClosureEnvelopeV1::from_canonical_bytes_v1(opc1_bytes, eop1_bytes)
        .map_err(|_| AdmissionError::InvalidBatch)?;
    let members = policy_member_leaves(leaves, &policy, &envelope, retention)?;
    let eop1_leaf = leaves.leaf(
        Kind::OutputPolicy,
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
        Kind::OutputPolicyClosure,
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
        .map_err(|_| AdmissionError::InvalidBatch)?;
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
        return Err(AdmissionError::InvalidBatch);
    }
    // A Generated profile is empty and has no kind5 member or edge.
    let profile = if profile_bytes.is_empty() {
        None
    } else {
        Some(leaves.member(
            Kind::ExecutionProfile,
            profile_digest,
            profile_bytes,
            Vec::new(),
        )?)
    };
    Ok(PolicyMemberLeaves {
        budget: leaves.member(
            Kind::ExecutableBudgetPolicy,
            budget.digest(),
            budget_bytes,
            profile.into_iter().collect(),
        )?,
        configuration: leaves.member(
            Kind::BaseConfiguration,
            fields.base_configuration_digest,
            configuration,
            Vec::new(),
        )?,
        implementation: leaves.member(
            Kind::PluginImplementationIdentity,
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
    members: BTreeMap<(Kind, Hash), ManifestOwnerMemberLeafV1>,
}

impl ScopeLeaves<'_> {
    fn leaf(
        &self,
        kind: Kind,
        native_digest: Hash,
        native_bytes: &[u8],
        mut children: Vec<Hash>,
    ) -> Result<WorldArtifactLeafV1, ManifestOwnerAdmissionErrorV1> {
        let classification = (self.classify)(kind, native_digest)
            .ok_or(AdmissionError::InvalidBatch)?;
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
        .map_err(|_| AdmissionError::InvalidBatch)
    }

    /// Register one member leaf; an identical `(kind, digest)` deduplicates.
    fn member(
        &mut self,
        kind: Kind,
        native_digest: Hash,
        native_bytes: &[u8],
        children: Vec<Hash>,
    ) -> Result<Hash, ManifestOwnerAdmissionErrorV1> {
        let leaf = self.leaf(kind, native_digest, native_bytes, children)?;
        let address = leaf.digest();
        self.members
            .entry((kind, native_digest))
            .or_insert_with(|| ManifestOwnerMemberLeafV1 {
                leaf,
                native_bytes: native_bytes.to_vec(),
            });
        Ok(address)
    }
}
