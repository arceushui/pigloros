//! Canonical ADR-081 WDB1 directory packing with ADR-089 Required policy seeds.
//!
//! These pure functions check, order, deduplicate and pack structurally valid
//! WAL1 leaves. They do not read native bytes, extract native dependencies,
//! publish a WCB1 binding, consult an owner store or grant a Replay claim.

use crate::world_dependency_directory::{
    WorldDependencyBranchChildV1, WorldDependencyBranchV1, WorldDependencyKeyV1,
};
use crate::{
    ArtifactDataClassV1, ArtifactOptionalityV1, ArtifactTransitionRuleV1, Hash,
    ManifestSlotBindingV1, PluginId, WorldArtifactKindV1, WorldArtifactLeafV1,
    WorldClosureReadLimitsV1, MAX_WORLD_DEPENDENCY_DIRECTORY_CHILDREN_V1,
};

/// Closed failures from directory packing and Required policy seed checks.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum WorldDependencyDirectoryErrorV1 {
    /// No WAL1 leaf was supplied for the directory.
    #[error("WDB1 directory has no leaves")]
    Empty,
    /// A leaf is registered under a different ADR-081 scope.
    #[error("WAL1 leaf scope differs from the directory scope")]
    WrongScope,
    /// One `[kind, native_digest]` key carries differing leaf registrations.
    #[error("one WDB1 key has conflicting WAL1 registrations")]
    ConflictingRegistration,
    /// The packed directory exceeds a recorded visit, byte or depth limit.
    #[error("WDB1 directory exceeds its recorded read limits")]
    LimitExceeded,
    /// An admitted MSB1 row has no supplied EOP1/OPC1 seed pair.
    #[error("admitted policy row has no Required seed leaves")]
    MissingPolicyLeaf,
    /// A policy seed or policy-kind leaf belongs to no admitted MSB1 row.
    #[error("policy leaf is not admitted by the selected binding")]
    UnexpectedPolicyLeaf,
    /// A policy seed leaf has the wrong ADR-081 artifact kind.
    #[error("policy seed leaf has the wrong artifact kind")]
    WrongKind,
    /// A policy seed leaf names a different RLS1 source lease.
    #[error("policy seed leaf names the wrong source lease")]
    WrongLease,
    /// A policy seed leaf names a different native copy owner.
    #[error("policy seed leaf names the wrong copy owner")]
    WrongOwner,
    /// A policy seed leaf is not Required or has a different class or transition.
    #[error("policy seed leaf has the wrong registration policy")]
    WrongPolicy,
    /// A policy seed leaf does not match its MSB1 EOP1 WAL1 or closure hash.
    #[error("policy seed leaf does not match its admitted identity")]
    IdentityMismatch,
}

/// Native registration facts fixed by the owner for every MSB1 policy leaf.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ManifestPolicyLeafExpectationV1 {
    /// Exact native RLS1 lease hash of the selected scope.
    pub source_lease_hash: Hash,
    /// Exact native copy owner of the retained EOP1/OPC1 bytes.
    pub owner: [u8; 32],
    /// Data class fixed by the owner/purpose policy before first commit.
    pub data_class: ArtifactDataClassV1,
    /// Immutable erasure transition fixed before first commit.
    pub transition: ArtifactTransitionRuleV1,
}

/// The Required kind-0 EOP1 and kind-14 OPC1 leaves supplied for one MSB1 row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifestPolicySeedV1 {
    /// Admitted Plugin identity of the MSB1 row.
    pub plugin_id: PluginId,
    /// Required scoped kind-0 WAL1 leaf whose hash MSB1 names.
    pub eop1_leaf: WorldArtifactLeafV1,
    /// Required scoped kind-14 WAL1 leaf whose native digest is the closure hash.
    pub opc1_leaf: WorldArtifactLeafV1,
}

/// Prove one exact Required EOP1 and OPC1 leaf pair for every MSB1 row.
///
/// The check runs before any deduplication and covers every admitted row,
/// including reducer-only zero-output Plugins absent from WCS1. It returns the
/// checked leaves in MSB1 row order, EOP1 before OPC1.
///
/// # Errors
/// Rejects a missing, duplicate or unadmitted seed, a wrong kind, scope,
/// lease, owner, optionality, data class or transition, and a leaf whose
/// identity differs from the MSB1 row.
pub fn check_manifest_policy_seeds_v1(
    binding: &ManifestSlotBindingV1,
    policy_seeds: &[ManifestPolicySeedV1],
    expectation: ManifestPolicyLeafExpectationV1,
) -> Result<Vec<WorldArtifactLeafV1>, WorldDependencyDirectoryErrorV1> {
    let scope = binding.as_input().scope;
    let rows = &binding.as_input().rows;
    let mut admitted = Vec::with_capacity(rows.len() * 2);
    for row in rows {
        let seed = row_seed(row.plugin_id, policy_seeds)?;
        check_policy_leaf(
            &seed.eop1_leaf,
            WorldArtifactKindV1::OutputPolicy,
            scope,
            &expectation,
        )?;
        check_policy_leaf(
            &seed.opc1_leaf,
            WorldArtifactKindV1::OutputPolicyClosure,
            scope,
            &expectation,
        )?;
        let eop1_wal1_hash = seed.eop1_leaf.digest();
        let closure_hash = seed.opc1_leaf.as_input().native_digest;
        if eop1_wal1_hash != row.eop1_wal1_hash || closure_hash != row.closure_hash {
            return Err(WorldDependencyDirectoryErrorV1::IdentityMismatch);
        }
        admitted.push(seed.eop1_leaf.clone());
        admitted.push(seed.opc1_leaf.clone());
    }
    if policy_seeds.len() != rows.len() {
        return Err(WorldDependencyDirectoryErrorV1::UnexpectedPolicyLeaf);
    }
    Ok(admitted)
}

/// Exact packed WDB1 directory over one scope's deduplicated WAL1 leaves.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorldDependencyDirectoryV1 {
    scope: Hash,
    root_hash: Hash,
    leaves: Vec<WorldArtifactLeafV1>,
    branches: Vec<WorldDependencyBranchV1>,
}

impl WorldDependencyDirectoryV1 {
    /// Order, deduplicate and pack the given leaves into canonical WDB1 nodes.
    ///
    /// Leaves sort by `[kind, native_digest]`. Identical registrations of one
    /// key collapse to one leaf. Leaves are packed 256 per height-one branch
    /// and branches 256 per higher branch; a single leaf is its own root. The
    /// limits count every WAL1 and WDB1 node visit, the summed native bytes of
    /// unique leaves, and the depth including the WAL1 level.
    ///
    /// # Errors
    /// Rejects no leaves, a wrong scope, conflicting registrations of one key,
    /// and a directory exceeding a recorded read limit.
    pub fn pack(
        scope: Hash,
        mut leaves: Vec<WorldArtifactLeafV1>,
        limits: WorldClosureReadLimitsV1,
    ) -> Result<Self, WorldDependencyDirectoryErrorV1> {
        if leaves.is_empty() {
            return Err(WorldDependencyDirectoryErrorV1::Empty);
        }
        if leaves.iter().any(|leaf| leaf.as_input().scope != scope) {
            return Err(WorldDependencyDirectoryErrorV1::WrongScope);
        }
        leaves.sort_unstable_by_key(leaf_order);
        let leaves = deduplicate(leaves)?;
        check_limits(&leaves, limits)?;
        Ok(build(scope, leaves))
    }

    /// Check every MSB1 policy seed, then pack it with the other ADR-081 seeds.
    ///
    /// Row membership is proved before deduplication. Any other kind-0 or
    /// kind-14 seed must equal an admitted row leaf; it then deduplicates.
    ///
    /// # Errors
    /// Returns any [`check_manifest_policy_seeds_v1`] failure, rejects an
    /// unadmitted policy-kind leaf, and returns any [`Self::pack`] failure.
    pub fn pack_with_manifest_policy_seeds(
        binding: &ManifestSlotBindingV1,
        policy_seeds: &[ManifestPolicySeedV1],
        expectation: ManifestPolicyLeafExpectationV1,
        other_seeds: Vec<WorldArtifactLeafV1>,
        limits: WorldClosureReadLimitsV1,
    ) -> Result<Self, WorldDependencyDirectoryErrorV1> {
        let mut leaves = check_manifest_policy_seeds_v1(binding, policy_seeds, expectation)?;
        if other_seeds
            .iter()
            .any(|seed| is_policy_kind(seed) && !leaves.contains(seed))
        {
            return Err(WorldDependencyDirectoryErrorV1::UnexpectedPolicyLeaf);
        }
        leaves.extend(other_seeds);
        Self::pack(binding.as_input().scope, leaves, limits)
    }

    /// Return the ADR-081 scope shared by every leaf and branch.
    #[must_use]
    pub const fn scope(&self) -> Hash {
        self.scope
    }

    /// Return the WCB1 dependency root: the top WDB1 or the single WAL1 hash.
    #[must_use]
    pub const fn root_hash(&self) -> Hash {
        self.root_hash
    }

    /// Return the root height, zero when the single leaf is the root.
    #[must_use]
    pub fn height(&self) -> u8 {
        self.branches
            .last()
            .map_or(0, WorldDependencyBranchV1::height)
    }

    /// Borrow the unique leaves in canonical `[kind, native_digest]` order.
    #[must_use]
    pub fn leaves(&self) -> &[WorldArtifactLeafV1] {
        &self.leaves
    }

    /// Borrow every WDB1 branch, level by level from height one to the root.
    #[must_use]
    pub fn branches(&self) -> &[WorldDependencyBranchV1] {
        &self.branches
    }
}

fn row_seed(
    plugin_id: PluginId,
    policy_seeds: &[ManifestPolicySeedV1],
) -> Result<&ManifestPolicySeedV1, WorldDependencyDirectoryErrorV1> {
    let mut matching = policy_seeds
        .iter()
        .filter(|seed| seed.plugin_id == plugin_id);
    let seed = matching
        .next()
        .ok_or(WorldDependencyDirectoryErrorV1::MissingPolicyLeaf)?;
    if matching.next().is_some() {
        return Err(WorldDependencyDirectoryErrorV1::UnexpectedPolicyLeaf);
    }
    Ok(seed)
}

fn check_policy_leaf(
    leaf: &WorldArtifactLeafV1,
    kind: WorldArtifactKindV1,
    scope: Hash,
    expectation: &ManifestPolicyLeafExpectationV1,
) -> Result<(), WorldDependencyDirectoryErrorV1> {
    let input = leaf.as_input();
    if input.kind != kind {
        Err(WorldDependencyDirectoryErrorV1::WrongKind)
    } else if input.scope != scope {
        Err(WorldDependencyDirectoryErrorV1::WrongScope)
    } else if input.source_lease_hash != expectation.source_lease_hash {
        Err(WorldDependencyDirectoryErrorV1::WrongLease)
    } else if input.owner != expectation.owner {
        Err(WorldDependencyDirectoryErrorV1::WrongOwner)
    } else if input.optionality != ArtifactOptionalityV1::Required
        || input.data_class != expectation.data_class
        || input.transition != expectation.transition
    {
        Err(WorldDependencyDirectoryErrorV1::WrongPolicy)
    } else {
        Ok(())
    }
}

const fn is_policy_kind(leaf: &WorldArtifactLeafV1) -> bool {
    matches!(
        leaf.as_input().kind,
        WorldArtifactKindV1::OutputPolicy | WorldArtifactKindV1::OutputPolicyClosure
    )
}

const fn leaf_order(leaf: &WorldArtifactLeafV1) -> (WorldArtifactKindV1, Hash) {
    (leaf.as_input().kind, leaf.as_input().native_digest)
}

fn deduplicate(
    sorted: Vec<WorldArtifactLeafV1>,
) -> Result<Vec<WorldArtifactLeafV1>, WorldDependencyDirectoryErrorV1> {
    let mut unique: Vec<WorldArtifactLeafV1> = Vec::with_capacity(sorted.len());
    for leaf in sorted {
        let identical = unique
            .last()
            .filter(|previous| leaf_order(previous) == leaf_order(&leaf))
            .map(|previous| *previous == leaf);
        match identical {
            Some(true) => {}
            Some(false) => return Err(WorldDependencyDirectoryErrorV1::ConflictingRegistration),
            None => unique.push(leaf),
        }
    }
    Ok(unique)
}

fn check_limits(
    leaves: &[WorldArtifactLeafV1],
    limits: WorldClosureReadLimitsV1,
) -> Result<(), WorldDependencyDirectoryErrorV1> {
    let fanout = MAX_WORLD_DEPENDENCY_DIRECTORY_CHILDREN_V1 as u64;
    let mut width = leaves.len() as u64;
    let mut node_visits = width;
    let mut depth = 1_u8;
    while width > 1 {
        width = width.div_ceil(fanout);
        node_visits += width;
        depth += 1;
    }
    let native_bytes = leaves.iter().fold(0_u64, |total, leaf| {
        total.saturating_add(leaf.as_input().native_byte_length)
    });
    let max_node_visits = limits.max_node_visits;
    let max_native_bytes = limits.max_native_bytes;
    let max_depth = limits.max_combined_depth;
    if node_visits > max_node_visits || native_bytes > max_native_bytes || depth > max_depth {
        Err(WorldDependencyDirectoryErrorV1::LimitExceeded)
    } else {
        Ok(())
    }
}

fn build(scope: Hash, leaves: Vec<WorldArtifactLeafV1>) -> WorldDependencyDirectoryV1 {
    let mut level: Vec<WorldDependencyBranchChildV1> = leaves
        .iter()
        .map(|leaf| {
            let input = leaf.as_input();
            let key = WorldDependencyKeyV1::for_validated_leaf(input.kind, input.native_digest);
            WorldDependencyBranchChildV1::packed(key, key, 1, leaf.digest())
        })
        .collect();
    let mut branches = Vec::new();
    let mut height = 0_u8;
    while level.len() > 1 {
        height += 1;
        let mut next = Vec::with_capacity(level.len());
        for chunk in level.chunks(MAX_WORLD_DEPENDENCY_DIRECTORY_CHILDREN_V1) {
            let branch = WorldDependencyBranchV1::packed(scope, height, chunk.to_vec());
            next.push(WorldDependencyBranchChildV1::packed(
                branch.first_key(),
                branch.last_key(),
                branch.leaf_count(),
                branch.digest(),
            ));
            branches.push(branch);
        }
        level = next;
    }
    WorldDependencyDirectoryV1 {
        scope,
        root_hash: level[0].node_hash(),
        leaves,
        branches,
    }
}
