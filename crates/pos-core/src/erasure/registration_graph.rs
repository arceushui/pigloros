//! Bounded structural inspection of an ARD1 catalog graph.
//!
//! A caller-provided catalog is not proof that an artifact owner committed its
//! bytes or that a format-specific extractor found every dependency. This
//! inspection cannot authorize Replay or `ReproManifest` release.

use super::{ArtifactOptionalityV1, ArtifactRegistrationV1, ErasureArtifactClassV1};
use crate::{Hash, KeyIdentityV1, OwnerIdV1};
use std::collections::{BTreeMap, BTreeSet};

/// Maximum distinct registrations in one ARD1 closure.
pub const MAX_ARTIFACT_GRAPH_REGISTRATIONS_V1: usize = 4_096;
/// Maximum child edges in one ARD1 closure.
pub const MAX_ARTIFACT_GRAPH_EDGES_V1: usize = 8_192;
/// Maximum distinct key identities in one ARD1 closure.
pub const MAX_ARTIFACT_GRAPH_KEYS_V1: usize = 4_096;
/// Maximum root-to-leaf registration depth, counting the root as one.
pub const MAX_ARTIFACT_GRAPH_DEPTH_V1: usize = 64;
/// Maximum sum of canonical ARD1 byte lengths in one closure.
pub const MAX_ARTIFACT_GRAPH_REGISTRATION_BYTES_V1: usize = 64 * 1_048_576;

/// One untrusted catalog row paired with its exact ARD1 registration.
///
/// The authoritative byte owner must independently establish every field,
/// including the owner and accepted schema, before this row can be used for a
/// protected operation. An `address` may be wrong or aliased in corrupt input.
#[derive(Clone, Debug)]
pub struct ArtifactRegistrationGraphNodeV1 {
    pub address: Hash,
    pub owner_id: OwnerIdV1,
    pub artifact_class: ErasureArtifactClassV1,
    pub artifact_digest: Hash,
    pub registration: ArtifactRegistrationV1,
}

/// Non-authorizing counts from a fully traversed structural graph.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArtifactRegistrationGraphSummaryV1 {
    pub registrations: usize,
    pub edges: usize,
    pub keys: usize,
    pub registration_bytes: usize,
}

/// A closed structural graph failure, not an erasure or release disposition.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ArtifactRegistrationGraphErrorV1 {
    #[error("ARD1 root is absent or not required")]
    InvalidRoot,
    #[error("ARD1 catalog address is duplicated")]
    DuplicateAddress,
    #[error("ARD1 child registration is missing")]
    MissingChild,
    #[error("ARD1 catalog owner does not match its registration")]
    OwnerMismatch,
    #[error("ARD1 catalog identity or child edge does not match its registration")]
    IdentityMismatch,
    #[error("ARD1 child graph contains a cycle")]
    Cycle,
    #[error("ARD1 child graph exceeds its accepted bound")]
    BoundExceeded,
    #[error("ARD1 catalog includes a registration outside the root closure")]
    ExtraRegistration,
}

/// Inspect exact catalog identities, edges, cycles, and ADR-093 graph bounds.
///
/// This pure helper takes untrusted rows. It neither checks artifact bytes nor
/// proves complete format-specific extraction, committed catalog visibility,
/// same-store byte disposition, or current key facts. The host must perform
/// those checks under its accepted owner and release boundaries.
///
/// # Errors
/// Rejects a missing/optional root, duplicate or extraneous catalog row,
/// mismatched owner/identity/edge, missing child, cycle, or exceeded bound.
pub fn inspect_artifact_registration_graph_v1(
    root: Hash,
    nodes: &[ArtifactRegistrationGraphNodeV1],
) -> Result<ArtifactRegistrationGraphSummaryV1, ArtifactRegistrationGraphErrorV1> {
    if nodes.len() > MAX_ARTIFACT_GRAPH_REGISTRATIONS_V1 {
        return Err(ArtifactRegistrationGraphErrorV1::BoundExceeded);
    }
    let mut by_address = BTreeMap::new();
    let mut identities = BTreeSet::new();
    for node in nodes {
        if by_address.insert(node.address, node).is_some() {
            return Err(ArtifactRegistrationGraphErrorV1::DuplicateAddress);
        }
        let fields = node.registration.fields();
        if !identities.insert((
            fields.owner_reference,
            fields.artifact_class,
            fields.artifact_digest,
        )) {
            return Err(ArtifactRegistrationGraphErrorV1::IdentityMismatch);
        }
    }
    let root_node = *by_address
        .get(&root)
        .ok_or(ArtifactRegistrationGraphErrorV1::InvalidRoot)?;
    if root_node.registration.fields().optionality != ArtifactOptionalityV1::Required {
        return Err(ArtifactRegistrationGraphErrorV1::InvalidRoot);
    }
    let mut traversal = GraphTraversal {
        nodes: &by_address,
        visiting: BTreeSet::new(),
        subtree_heights: BTreeMap::new(),
        keys: BTreeSet::new(),
        edges: 0,
        registration_bytes: 0,
    };
    traversal.visit(root, root_node, 1)?;
    if traversal.subtree_heights.len() != nodes.len() {
        return Err(ArtifactRegistrationGraphErrorV1::ExtraRegistration);
    }
    Ok(ArtifactRegistrationGraphSummaryV1 {
        registrations: traversal.subtree_heights.len(),
        edges: traversal.edges,
        keys: traversal.keys.len(),
        registration_bytes: traversal.registration_bytes,
    })
}

struct GraphTraversal<'a> {
    nodes: &'a BTreeMap<Hash, &'a ArtifactRegistrationGraphNodeV1>,
    visiting: BTreeSet<Hash>,
    subtree_heights: BTreeMap<Hash, usize>,
    keys: BTreeSet<KeyIdentityV1>,
    edges: usize,
    registration_bytes: usize,
}

impl GraphTraversal<'_> {
    fn visit(
        &mut self,
        address: Hash,
        node: &ArtifactRegistrationGraphNodeV1,
        depth: usize,
    ) -> Result<usize, ArtifactRegistrationGraphErrorV1> {
        if self.visiting.contains(&address) {
            return Err(ArtifactRegistrationGraphErrorV1::Cycle);
        }
        if depth > MAX_ARTIFACT_GRAPH_DEPTH_V1 {
            return Err(ArtifactRegistrationGraphErrorV1::BoundExceeded);
        }
        if let Some(height) = self.subtree_heights.get(&address).copied() {
            if depth + height - 1 > MAX_ARTIFACT_GRAPH_DEPTH_V1 {
                return Err(ArtifactRegistrationGraphErrorV1::BoundExceeded);
            }
            return Ok(height);
        }
        let fields = node.registration.fields();
        if fields.owner_reference != ArtifactRegistrationV1::owner_reference(&node.owner_id) {
            return Err(ArtifactRegistrationGraphErrorV1::OwnerMismatch);
        }
        if fields.artifact_class != node.artifact_class
            || fields.artifact_digest != node.artifact_digest
        {
            return Err(ArtifactRegistrationGraphErrorV1::IdentityMismatch);
        }
        self.registration_bytes = self
            .registration_bytes
            .saturating_add(node.registration.canonical_cbor().len());
        // At most 4,096 records with at most 2,048 direct edges each fit in
        // usize even on a 32-bit target.
        self.edges += fields.child_artifacts.len();
        if self.registration_bytes > MAX_ARTIFACT_GRAPH_REGISTRATION_BYTES_V1
            || self.edges > MAX_ARTIFACT_GRAPH_EDGES_V1
        {
            return Err(ArtifactRegistrationGraphErrorV1::BoundExceeded);
        }
        for key in &fields.key_dependencies {
            if !self.keys.contains(&key.identity) && self.keys.len() == MAX_ARTIFACT_GRAPH_KEYS_V1 {
                return Err(ArtifactRegistrationGraphErrorV1::BoundExceeded);
            }
            self.keys.insert(key.identity);
        }
        self.visiting.insert(address);
        let mut height = 1;
        for edge in &fields.child_artifacts {
            let child = *self
                .nodes
                .get(&edge.registration_address)
                .ok_or(ArtifactRegistrationGraphErrorV1::MissingChild)?;
            if child.artifact_class != edge.artifact_class
                || child.artifact_digest != edge.artifact_digest
            {
                return Err(ArtifactRegistrationGraphErrorV1::IdentityMismatch);
            }
            height = height.max(1 + self.visit(edge.registration_address, child, depth + 1)?);
        }
        // Do this after traversal so a corrupt catalog alias cannot conceal a
        // cycle that the traversal must reject independently.
        if node.registration.address() != address {
            return Err(ArtifactRegistrationGraphErrorV1::IdentityMismatch);
        }
        self.visiting.remove(&address);
        self.subtree_heights.insert(address, height);
        Ok(height)
    }
}
