//! Manifest owner-admission fixtures shared by the in-crate store tests.
//!
//! The memory and `SQLite` coverage modules build the same two-Plugin catalog,
//! EOP1/OPC1 policy copies, and always-accepting owner verifier; each caller
//! passes its own owner id so the stores keep distinct fixture owners.

use pos_core::{
    output_policy::{OutputPolicyInputV1, OutputPolicyV1},
    ArtifactDataClassV1, ArtifactOptionalityV1, ArtifactTransitionRuleV1, Hash,
    ManifestAdmissionCatalogInputV1, ManifestAdmissionCatalogRowV1, ManifestAdmissionCatalogV1,
    ManifestOwnerAdmissionErrorV1, ManifestOwnerAdmissionOwnerStateV1,
    ManifestOwnerAdmissionRequestV1, ManifestOwnerAdmissionVerifierV1, ManifestOwnerPolicyCopiesV1,
    ManifestOwnerTimelineAdmissionRequestV1, ManifestSlotAdmissionReceiptDraftV1,
    ManifestSlotAdmissionReceiptV1, PluginId, TimelineId, WorldArtifactKindV1,
    WorldArtifactLeafInputV1, WorldArtifactLeafV1,
};

pub(crate) type Fallible<T> = Result<T, Box<dyn std::error::Error>>;
pub(crate) type PolicySource = (OutputPolicyV1, Vec<u8>);

pub(crate) const fn hash(byte: u8) -> Hash {
    Hash::from_bytes([byte; 32])
}

pub(crate) const fn plugin(byte: u8) -> PluginId {
    PluginId::from_ulid(ulid::Ulid::from_bytes([byte; 16]))
}

/// Accepts every owner check so store tests isolate the persistence port.
pub(crate) struct AcceptingOwner;

impl ManifestOwnerAdmissionVerifierV1 for AcceptingOwner {
    fn verify_complete_composition(
        &self,
        _catalog: &ManifestAdmissionCatalogV1,
    ) -> Result<(), ManifestOwnerAdmissionErrorV1> {
        Ok(())
    }

    fn verify_complete_owned_scope_set(
        &self,
        _owner_id: [u8; 32],
        _timelines: &[ManifestOwnerTimelineAdmissionRequestV1],
    ) -> Result<(), ManifestOwnerAdmissionErrorV1> {
        Ok(())
    }

    fn verify_coordinator_receipt(
        &self,
        _receipt: &ManifestSlotAdmissionReceiptV1,
    ) -> Result<(), ManifestOwnerAdmissionErrorV1> {
        Ok(())
    }

    fn verify_owner_prestate_and_allocation(
        &self,
        _request: &ManifestOwnerAdmissionRequestV1,
        _current_state: Option<&ManifestOwnerAdmissionOwnerStateV1>,
    ) -> Result<(), ManifestOwnerAdmissionErrorV1> {
        Ok(())
    }

    fn sign_coordinator_receipt(
        &self,
        draft: ManifestSlotAdmissionReceiptDraftV1,
    ) -> Result<ManifestSlotAdmissionReceiptV1, ManifestOwnerAdmissionErrorV1> {
        draft
            .with_evidence_and_signature(hash(90), [0x5a; 64])
            .map_err(|_| ManifestOwnerAdmissionErrorV1::OwnerRejected)
    }

    fn verify_native_policy_copies(
        &self,
        _timeline_id: TimelineId,
        _scope: Hash,
        _copies: &ManifestOwnerPolicyCopiesV1,
    ) -> Result<(), ManifestOwnerAdmissionErrorV1> {
        Ok(())
    }
}

pub(crate) fn policy_and_closure(plugin_id: PluginId, seed: u8) -> Fallible<PolicySource> {
    let policy = OutputPolicyV1::new(OutputPolicyInputV1 {
        plugin_id,
        plugin_version: "1.0.0".to_owned(),
        implementation_hash: hash(seed + 30),
        base_configuration_digest: hash(seed + 40),
        executable_profile_hash: hash(seed + 50),
        retention_policy_hash: hash(seed + 60),
        policy_revision: 1,
        output_declarations: Vec::new(),
    })?;
    let members = [
        policy.to_canonical_cbor(),
        b"EBP1-fixture".to_vec(),
        b"implementation-fixture".to_vec(),
        b"CFG1-fixture".to_vec(),
        Vec::new(),
        b"RTP1-fixture".to_vec(),
    ];
    let mut closure = b"OPC1".to_vec();
    for member in members {
        let length = u64::try_from(member.len()).unwrap_or(u64::MAX);
        closure.extend_from_slice(&length.to_be_bytes());
        closure.extend_from_slice(&member);
    }
    Ok((policy, closure))
}

pub(crate) fn opc1_digest(bytes: &[u8]) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"pigloros.manifest-plugin-closure.v1\0");
    hasher.update(bytes);
    Hash::from_bytes(*hasher.finalize().as_bytes())
}

/// Two-Plugin catalog for `owner` at `generation`, with its policy sources.
pub(crate) fn catalog(
    owner: [u8; 32],
    generation: u64,
) -> Fallible<(ManifestAdmissionCatalogV1, Vec<PolicySource>)> {
    let sources = vec![
        policy_and_closure(plugin(1), 1)?,
        policy_and_closure(plugin(2), 2)?,
    ];
    let rows = sources
        .iter()
        .enumerate()
        .map(|(index, (policy, closure))| ManifestAdmissionCatalogRowV1 {
            stable_slot: if index == 0 { "slot-a" } else { "slot-b" }.to_owned(),
            plugin_id: policy.fields().plugin_id,
            plugin_name: "same-name".to_owned(),
            plugin_version: policy.fields().plugin_version.clone(),
            implementation_hash: policy.fields().implementation_hash,
            eop1_native_digest: policy.digest(),
            closure_hash: opc1_digest(closure),
        })
        .collect();
    let catalog = ManifestAdmissionCatalogV1::new(ManifestAdmissionCatalogInputV1 {
        owner_id: owner,
        configuration_generation: generation,
        rows,
    })?;
    Ok((catalog, sources))
}

pub(crate) fn leaf(
    owner: [u8; 32],
    scope: Hash,
    kind: WorldArtifactKindV1,
    native: &[u8],
    native_digest: Hash,
    lease: Hash,
) -> Fallible<WorldArtifactLeafV1> {
    let leaf = WorldArtifactLeafV1::new(WorldArtifactLeafInputV1 {
        scope,
        kind,
        native_digest,
        native_byte_length: u64::try_from(native.len()).unwrap_or(u64::MAX),
        owner,
        data_class: ArtifactDataClassV1::StructuralAuditMetadata,
        optionality: ArtifactOptionalityV1::Required,
        transition: ArtifactTransitionRuleV1::PreserveExact,
        source_lease_hash: lease,
        key_dependencies: Vec::new(),
        child_node_hashes: Vec::new(),
    })?;
    Ok(leaf)
}

/// EOP1/OPC1 copies of every source, leased to `owner` within `scope`.
pub(crate) fn policy_copies(
    owner: [u8; 32],
    scope: Hash,
    sources: &[PolicySource],
    lease: Hash,
) -> Fallible<Vec<ManifestOwnerPolicyCopiesV1>> {
    sources
        .iter()
        .map(|(policy, closure)| {
            let eop1_bytes = policy.to_canonical_cbor();
            let eop1_leaf = leaf(
                owner,
                scope,
                WorldArtifactKindV1::OutputPolicy,
                &eop1_bytes,
                policy.digest(),
                lease,
            )?;
            let opc1_leaf = leaf(
                owner,
                scope,
                WorldArtifactKindV1::OutputPolicyClosure,
                closure,
                opc1_digest(closure),
                lease,
            )?;
            Ok(ManifestOwnerPolicyCopiesV1 {
                plugin_id: policy.fields().plugin_id,
                eop1_bytes,
                eop1_leaf,
                opc1_bytes: closure.clone(),
                opc1_leaf,
            })
        })
        .collect()
}
